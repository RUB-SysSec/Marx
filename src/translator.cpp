
#include "translator.h"

#include <sstream>
#include <algorithm>

using namespace std;

/*!
 * \brief Constructs a new `Translator` instance.
 *
 * Note that this requires the exported dump files `{BINARY_NAME}.dmp` and
 * `{BINARY_NAME}.dmp.no-return` in the same directory as the input file. Said
 * files can be obtained using the IDA scripts provided in the `ida_export`
 * directory.
 *
 * \param vex The global `Vex` instance.
 * \param file The (full path to the) file that should be operated on.
 * \param parse_on_demand `true`, if functions shall be translated once they
 * are queried; `false` to parse all known functions at once.
 */
Translator::Translator(Vex &vex, const string &file,
    FileFormatType file_format, bool parse_on_demand)
    : _vex(vex), _dump_file(file + ".dmp") {

    _file_format = file_format;
    switch(_file_format) {
        case FileFormatELF64:
            _memory = new MappedElf(file);
            break;
        case FileFormatPE64:
            _memory = new MappedPe(file);
            break;
        default:
            throw runtime_error("Format not supported.");
            break;
    }

    if(!parse_on_demand) {
        parse_known_functions();
    }
}

void Translator::finalize_block(Function &function,
                                const BlockDescriptor &block,
                                IRSB *block_pointer) {
    auto terminator = get_terminator(*block_pointer);
    const auto &non_returning = _dump_file.get_non_returning();

    switch(terminator.type) {
    case TerminatorCall:
    case TerminatorJump: {
        const auto &needle = non_returning.find(terminator.target);
        if(needle != non_returning.cend()) {
            terminator.type = TerminatorNoReturn;
        }
        break;
    }

    default:
        break;
    }

    function.add_block(block.block_start, block_pointer, terminator);
    _blocks[block.block_start] = block_pointer;
}

bool Translator::process_block(Function &function,
                               const BlockDescriptor &block) {
    if(block.block_start == block.block_end) {
        return true;
    }

    bool result = true;
    if(_seen_blocks.find(block.block_start) != _seen_blocks.cend()) {
        return true;
    }

    size_t real_end = 0;

    const auto &translated_block = _vex.translate((*_memory)[block.block_start],
            block.block_start, block.instruction_count, &real_end);

    _seen_blocks.insert(block.block_start);

    /* A regular deep copy won't work as memory returned by it is volatile and
     * only valid within a libVEX_Translate callback (allocation strategies
     * AllocModeTEMP/AllocModePERM).
     * We patched in another strategy using heap allocations directly.
     */

    auto *block_pointer = deepCopyIRSB_Heap(&translated_block);
    auto &vex_block = *block_pointer;

    /* The basic block was non-strict and has been split by VEX at a call
     * instruction.
     *
     * FIXME: This can be handled nicer, as we can only specify the number of
     * instructions VEX should translate but it replies with the number of
     * _bytes_ it translated until split. This bloats the dump file.
     *
     * Fixes: Split into strict BBs when exporting from IDA (time-consuming) or
     * split beforehand (LDE). We currently do the former.
     */

    auto head_instructions = 0u;
    for(auto i = 0; i < vex_block.stmts_used; ++i) {
        const auto &current = *vex_block.stmts[i];
        if(current.tag == Ist_IMark) {
            head_instructions++;
        }
    }

    if(head_instructions < block.instruction_count) {
        BlockDescriptor split;
        split.block_start = real_end;
        split.block_end = block.block_end;
        split.instruction_count = block.instruction_count - head_instructions;

        result &= process_block(function, split);
        finalize_block(function, block, block_pointer);
        return result;
    }

    /* The basic block ends before a control-flow instruction is encountered
     * (i.e., one of its instructions is a control-flow target). We need to
     * split the basic block here manually.
     *
     * Alternative: Resort to pyvex' approach of translating one instruction at
     * a time. However, blocks are more commonly terminated by a branch which
     * justifies splitting in these edge cases.
     */
    auto instr_counter = block.instruction_count + 1;
    for(auto i = 0; i< vex_block.stmts_used; ++i) {
        const auto &current = *vex_block.stmts[i];

        if(current.tag == Ist_IMark) {
            --instr_counter;
            if(!instr_counter) {
                vex_block.jumpkind = Ijk_NoDecode;
                vex_block.stmts_used = i;

                if(vex_block.next->tag == Iex_Const) {
                    vex_block.next->Iex.Const.con->Ico.U64 =
                            current.Ist.IMark.addr;
                } else {
                    // TODO: Trigger allocation callback here.
                    IRConst *constant =
                            static_cast<IRConst*>(malloc(sizeof(IRConst)));
                    constant->tag = Ico_U64;
                    constant->Ico.U64 = current.Ist.IMark.addr;

                    vex_block.next->tag = Iex_Const;
                    vex_block.next->Iex.Const.con = constant;
                }

                break;
            }
        }
    }

    finalize_block(function, block, block_pointer);
    return result;
}

void Translator::detect_tail_jumps(Function &function) {
    for(const auto &block : function.get_blocks()) {
        /* FIXME: We cannot really do this in finalize_block as we need to know
         * all other blocks in the function. Hence, we cheat "a little".
         */
        auto &terminator = const_cast<Terminator&>(
            block.second->get_terminator());
        terminator.is_tail = false;

        const auto &blocks = function.get_blocks();
        auto target = terminator.fall_through;

        /* Only consider resolvable tail jumps for now (is there anything else
         * possible?). Fall-throughs are _considered_ as last resort, but
         * should not really come up in practice -- the only exception being
         * calls to non-returning functions which already should have been
         * handled by finalize_block.
         */
        switch(terminator.type) {
        case TerminatorJump:
            target = terminator.target;
            break;

        default:
            // Only handle jumps, really.
            continue;
        }

        auto is_target = [&](const BlockMap::value_type &i) {
            return i.second->get_address() == target;
        };

        // Check if the terminator's target points into another function.
        auto needle = find_if(blocks.cbegin(), blocks.cend(), is_target);
        terminator.is_tail = needle == blocks.cend();
    }
}

Function *Translator::translate_function(const
    pair<uintptr_t, FunctionBlocks> &current) {

    const auto address = current.first;
    const auto &blocks = current.second;

    _functions[address] = Function(address);
    Function &function = _functions.at(address);

    for(auto i = blocks.cbegin(), e = blocks.cend(); i != e; ++i) {
        if(!process_block(function, *i)) {
            _functions.erase(address);
            return nullptr;
        }
    }

    detect_tail_jumps(function);
    return &function;
}

Function *Translator::maybe_translate_function(const uintptr_t address) {
    const auto &function = _functions.find(address);

    if(function != _functions.cend()) {
        return &function->second;
    }

    const ParsedFunctions &functions = _dump_file.get_functions();
    const auto &needle = functions.find(address);

    if(needle == functions.cend()) {
        return nullptr;
    }

    return translate_function(*needle);
}

/*!
 * \brief Returns the `Function` object corresponding to the function at address
 * `address`.
 *
 * If the function is not known to the `Translator` instance, an exception of
 * type `runtime_error` is raised.
 *
 * \param address The address the function lies at.
 * \return A (read-only) `Function` object.
 */
const Function &Translator::get_function(const uintptr_t address) {
    lock_guard<mutex> _(_mutex);

    const Function *function = maybe_translate_function(address);
    if(!function) {
        stringstream stream;
        stream << "Cannot translate function at address " << hex
               << address << "." << endl;
        throw runtime_error(stream.str());
    }

    return *function;
}

/*!
 * \brief Returns a pointer to the `Function` object corresponding to the
 * function at address `address`.
 *
 * If the function is not known to the `Translator` instance, the value
 * `nullptr` is returned. Make sure to operate on valid pointers only.
 *
 * \param address The address the function lies at.
 * \return A pointer to a `Function` object or `nullptr`, if the function is
 * not known.
 */
const Function *Translator::maybe_get_function(const uintptr_t address) {
    lock_guard<mutex> _(_mutex);
    return maybe_translate_function(address);
}

void Translator::parse_known_functions() {
    const auto &functions = _dump_file.get_functions();

    for(const auto &kv : functions) {
        translate_function(kv);
    }
}

Terminator Translator::get_terminator(const IRSB &block) const {
    Terminator result;

    uint64_t last_addr = 0;
    result.type = TerminatorUnresolved;
    result.target = 0;
    result.fall_through = 0;

    const IRStmt *last_mark = nullptr;
    for(signed i = block.stmts_used - 1; i >= 0; --i) {
        const auto &current = *block.stmts[i];

        if(current.tag == Ist_IMark) {
            last_mark = &current;
            break;
        }
    }

    if(last_mark) {
        const auto &mark = last_mark->Ist.IMark;
        result.fall_through = mark.addr + mark.len;
        last_addr = last_mark->Ist.IMark.addr;
    }

    uintptr_t jcc_target = 0;
    bool is_conditional = false;

    for(signed i = block.stmts_used - 1; !jcc_target && i >= 0; --i) {
        const IRStmt &current = *block.stmts[i];

        if(current.tag == Ist_Exit) {
            jcc_target = current.Ist.Exit.dst->Ico.U64;
            is_conditional = true;

            if(jcc_target == result.fall_through) {
                jcc_target = 0;
            }
        }
    }

    uintptr_t jmp_call_target = 0;
    switch(block.next->tag) {
    case Iex_Const:
        jmp_call_target = block.next->Iex.Const.con->Ico.U64;
        break;

    default:
        break;
    }

    if(is_conditional && !jcc_target) {
        jcc_target = jmp_call_target;
    }

    switch(block.jumpkind) {
    case Ijk_NoDecode:
        result.type = TerminatorFallthrough;
        result.fall_through = jmp_call_target;
        break;

    case Ijk_Ret:
        result.type = TerminatorReturn;
        result.fall_through = 0;
        break;

    case Ijk_Call:
        if(jmp_call_target) {
            result.type = TerminatorCall;
            result.target = jmp_call_target;

            // TODO: jmp_call_target is known function that does not return.
        } else {
            result.type = TerminatorCallUnresolved;
            result.target = 0;
        }
        break;

    case Ijk_Boring:
        if(jcc_target) {
            result.type = TerminatorJcc;
            result.target = jcc_target;
        } else {
            if(jmp_call_target) {
                result.type = TerminatorJump;

                // Check if the jmp call target is the same as the
                // last address of the block. This happens, if we have
                // a instruction like "rep stosd" (often emitted by MSVC
                // in DEBUG builds) => use fall through address as jump
                // target to ignore this loop.
                if(last_addr == jmp_call_target && jmp_call_target != 0) {
                    result.target = result.fall_through;
                }
                else {
                    result.target = jmp_call_target;
                }

                result.fall_through = 0;
            } else {
                result.type = TerminatorUnresolved;
                result.target = 0;
                result.fall_through = 0;
            }
        }
        break;

    default:
        result.fall_through = 0;
        break;
    }

    return result;
}
