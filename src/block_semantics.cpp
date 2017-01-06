
#include "block_semantics.h"
#include "block.h"

#include <string>
#include <memory>
#include <sstream>

#include <iostream>

using namespace std;

const map<IRExprTag, ExpressionParser> BlockSemantics::_expression_parser = {
    { Iex_Get,   ExpressionParser(&BlockSemantics::parse_get) },
    { Iex_GetI,  ExpressionParser(&BlockSemantics::parse_geti) },
    { Iex_RdTmp, ExpressionParser(&BlockSemantics::parse_rdtmp) },
    { Iex_Qop,   ExpressionParser(&BlockSemantics::parse_qop) },
    { Iex_Triop, ExpressionParser(&BlockSemantics::parse_triop) },
    { Iex_Binop, ExpressionParser(&BlockSemantics::parse_binop) },
    { Iex_Unop,  ExpressionParser(&BlockSemantics::parse_unop) },
    { Iex_Load,  ExpressionParser(&BlockSemantics::parse_load) },
    { Iex_Const, ExpressionParser(&BlockSemantics::parse_const) },
    { Iex_CCall, ExpressionParser(&BlockSemantics::parse_ccall) },
    { Iex_ITE,   ExpressionParser(&BlockSemantics::parse_ite) },
};

const map<IRStmtTag, StatementHandler> BlockSemantics::_statement_handler = {
    { Ist_NoOp,    StatementHandler(&BlockSemantics::handle_noop) },
    { Ist_IMark,   StatementHandler(&BlockSemantics::handle_noop) },
    { Ist_AbiHint, StatementHandler(&BlockSemantics::handle_abi_hint) },
    { Ist_WrTmp,   StatementHandler(&BlockSemantics::handle_wrtmp) },
    { Ist_Put,     StatementHandler(&BlockSemantics::handle_put) },
    { Ist_PutI,    StatementHandler(&BlockSemantics::handle_puti) },
    { Ist_Store,   StatementHandler(&BlockSemantics::handle_store) },
    { Ist_StoreG,  StatementHandler(&BlockSemantics::handle_storeg) },
    { Ist_LoadG,   StatementHandler(&BlockSemantics::handle_loadg) },
    { Ist_CAS,     StatementHandler(&BlockSemantics::handle_noop) },
    { Ist_LLSC,    StatementHandler(&BlockSemantics::handle_noop) },
    { Ist_Dirty,   StatementHandler(&BlockSemantics::handle_noop) },
    { Ist_MBE,     StatementHandler(&BlockSemantics::handle_noop) },
    { Ist_Exit,    StatementHandler(&BlockSemantics::handle_noop) },
};

/*!
 * \brief Constructs a new `BlockSemantics` object and immediately computes
 * semantics.
 *
 * If it fails at extracting the block's semantics, an exception of type
 * `runtime_error` is thrown.
 *
 * \param block The block whose semantics shall be extracted.
 * \param initial_state The initial state based on which semantics are computed.
 */
BlockSemantics::BlockSemantics(const Block &block, State &initial_state)
    : _state(initial_state), _block(block), _unknown(make_shared<Unknown>()) {

    if(!extract_semantics(block.get_vex_block())) {
        stringstream stream;
        stream << "Cannot extract semantics for block at "
               << hex << block.get_address() << "." << endl;
        throw runtime_error(stream.str());
    }
}

#define DEBUG_PRINT_STEPS 0

bool BlockSemantics::extract_semantics(const IRSB &block) {
    for(auto i = 0; i < block.stmts_used; ++i) {
        const auto &current = *block.stmts[i];

#if DEBUG_PRINT_STEPS
        cout << string(79, '=') << endl;
        ppIRStmt(&current);
        cout << endl;
#endif

        if(!handle_statement(current)) {
            return false;
        }

#if DEBUG_PRINT_STEPS
        cout << string(79, '-') << endl;
        cout << endl << _state << endl;
#endif
    }

    _state.optimize();
    return true;
}

ExpressionPtr BlockSemantics::parse_expression(const IRExpr &expression) {
    const auto &needle = _expression_parser.find(expression.tag);

    if(needle == _expression_parser.cend()) {
        stringstream stream;
        stream << "Cannot handle expression with tag " << expression.tag
               << "." << endl;
        throw runtime_error(stream.str());
    }

    const auto &f = needle->second;
    return (this->*f)(expression);
}

bool BlockSemantics::handle_statement(const IRStmt &statement) {
    const auto &needle = _statement_handler.find(statement.tag);

    if(needle == _statement_handler.cend()) {
        stringstream stream;
        stream << "Cannot handle statement with tag " << statement.tag
               << "." << endl;
        throw runtime_error(stream.str());
    }

    const auto &f = needle->second;
    return (this->*f)(statement);
}

// We do not really need this for now.
uint64_t BlockSemantics::get_mask(uint8_t size) const {
    if(size == 64) {
        return -1UL;
    }

    return (1 << size) - 1;
}

bool BlockSemantics::get_size(const IRType &type, arg_out uint8_t &size)
    const {
    switch(type) {
    case Ity_I1:
        size = 1;
        break;

    case Ity_I8:
    case Ity_I16:
    case Ity_I32:
    case Ity_I64: {
        auto index = type - Ity_I1 - 1;
        size = (1 << index) * 8;
        break;
    }

    default: // 128-bit, floating-point, SIMD or invalid.
        return false;
    }

    return true;
}

bool BlockSemantics::parse_type(const IRType &type, arg_out uint8_t &size,
                               arg_out uint64_t &mask) const {
    if(!get_size(type, size)) {
        return false;
    }

    mask = get_mask(size);
    return true;
}

ExpressionPtr BlockSemantics::parse_get(const IRExpr &expression) {
    const auto &target = expression.Iex.Get;

    uint64_t mask;
    uint8_t size;
    if(!parse_type(target.ty, size, mask) || size != 64) {
        return _unknown;
    }

    auto r = make_shared<Register>(target.offset);

    State::const_iterator needle;
    if(!_state.find(r, needle)) {
        return _unknown;
    }

    /* TODO: We should think about whether sharing pointers makes sense here
     * or if we are better off by creating a copy.
     */
    return needle->second;
}

ExpressionPtr BlockSemantics::parse_geti(const IRExpr&) {
    // TODO: We may be able to solve this if details are constant.
    return _unknown;
}

ExpressionPtr BlockSemantics::parse_rdtmp(const IRExpr &expression) {
    const auto &target = expression.Iex.RdTmp;

    State::const_iterator needle;
    if(!_state.find(make_shared<Temporary>(target.tmp), needle)) {
        return _unknown;
    }

    return needle->second;
}

ExpressionPtr BlockSemantics::parse_qop(const IRExpr&) {
    return _unknown;
}

ExpressionPtr BlockSemantics::parse_triop(const IRExpr&) {
    return _unknown;
}

ExpressionPtr BlockSemantics::parse_binop(const IRExpr &expression) {
    const auto &target = expression.Iex.Binop;
    OperationType operation;

    switch(target.op) {
    case Iop_Add8:
    case Iop_Add16:
    case Iop_Add32:
    case Iop_Add64:
        operation = OperationAdd;
        break;

    case Iop_Sub8:
    case Iop_Sub16:
    case Iop_Sub32:
    case Iop_Sub64:
        operation = OperationSub;
        break;

    default:
        return _unknown;
    }

    const auto lhs = parse_expression(*target.arg1);
    const auto rhs = parse_expression(*target.arg2);

    if(lhs->type() == ExpressionUnknown || rhs->type() == ExpressionUnknown) {
        return _unknown;
    }

    return make_shared<Operation>(lhs, operation, rhs);
}

ExpressionPtr BlockSemantics::parse_unop(const IRExpr&) {
    return _unknown;
}

ExpressionPtr BlockSemantics::parse_ccall(const IRExpr&) {
    return _unknown;
}

ExpressionPtr BlockSemantics::parse_ite(const IRExpr&) {
    return _unknown;
}

ExpressionPtr BlockSemantics::parse_load(const IRExpr &expression) {
    const auto &target = expression.Iex.Load;
    if(target.end != Iend_LE) {
        throw runtime_error("Cannot handle big-endian load instructions yet.");
    }

    uint64_t mask;
    uint8_t size;

    if(!parse_type(target.ty, size, mask) || size != 64) {
        return _unknown;
    }

    const auto e = parse_expression(*target.addr);
    if(e->type() == ExpressionUnknown) {
        return _unknown;
    }

    return make_shared<Indirection>(e);
}

ExpressionPtr BlockSemantics::parse_const(const IRExpr &expression) {
    const auto &target = *expression.Iex.Const.con;

    switch(target.tag) {
    case Ico_U1:
        return make_shared<Constant>(target.Ico.U1);

    case Ico_U8:
        return make_shared<Constant>(target.Ico.U8);

    case Ico_U16:
        return make_shared<Constant>(target.Ico.U16);

    case Ico_U32:
        return make_shared<Constant>(target.Ico.U32);

    case Ico_U64:
        return make_shared<Constant>(target.Ico.U64);

    default:
        break;
    }

    return _unknown;
}

bool BlockSemantics::handle_noop(const IRStmt&) {
    return true;
}

bool BlockSemantics::handle_wrtmp(const IRStmt &statement) {
    const auto &current = statement.Ist.WrTmp;

    const auto e = parse_expression(*current.data);
    const auto dst = make_shared<Temporary>(current.tmp);

    if(e->type() == ExpressionUnknown) {
        _state.erase(dst);
        return true;
    }

    _state.update(dst, e);
    return true;
}

bool BlockSemantics::handle_put(const IRStmt &statement) {
    const auto &current = statement.Ist.Put;

    const auto e = parse_expression(*current.data);
    const auto d = make_shared<Register>(current.offset);

    if(d->type() == ExpressionUnknown) {
        return true;
    }

    if(e->type() == ExpressionUnknown) {
        _state.erase(d);
        return true;
    }

    _state.update(d, e);
    return true;
}

bool BlockSemantics::handle_puti(const IRStmt&) {
    // TODO: We may be able to handle this if details are constant.
    // Possibly should invalidate all registers for correctness.
    return true;
}

bool BlockSemantics::handle_store(const IRStmt &statement) {
    const auto &current = statement.Ist.Store;

    if(current.end != Iend_LE) {
        throw runtime_error("Cannot handle big-endian store instructions"
                            " yet.");
    }

    const auto e = parse_expression(*current.data);
    const auto d = parse_expression(*current.addr);

    if(d->type() == ExpressionUnknown) {
        return true;
    }

    const auto dst = make_shared<Indirection>(d);
    if(e->type() == ExpressionUnknown) {
        _state.erase(dst);
        return true;
    }

    _state.update(dst, e);
    return true;
}

bool BlockSemantics::handle_storeg(const IRStmt&) {
    // TODO: How to handle guarded stores?
    return true;
}

bool BlockSemantics::handle_loadg(const IRStmt&) {
    // TODO: How to handle guarded stores?
    return true;
}

bool BlockSemantics::handle_abi_hint(const IRStmt &statement) {
    /* We assume AbiHints are only generated for call/ret instructions. VEX
     * emits IR that set ups the return address, we will revert this here.
     *
     * Additionally, we will take care of the effects introduced by the calling
     * convention. For now, we assume System V:
     *
     *   - rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11 are scratch registers.
     *     We will invalidate these after the call (before it they might be
     *     used as argument registers).
     *   - rbx, rsp, rbp, r12, r13, r14 are preserved.
     *   - rax will be assigned a placeholder which can be set to the
     *     appropriate return value (e.g., if later it is known that this
     *     return value holds an object pointer).
     */
    // FIXME: Calling convention handling has moved to traversal callback.

    /* FIXME: Outsource this part into another class handling all kinds of
     * calling conventions. We should not need to know the offset of RSP here
     * (or RSP at all). */

    const auto &current = statement.Ist.AbiHint;
    const auto &target = parse_expression(*current.nia);

    State::const_iterator needle;
    if(!_state.find(register_rsp, needle) ||
            needle->second->type() == ExpressionUnknown) {
        return false;
    }

    OperationType operation;

    switch(_block.get_terminator().type) {
    case TerminatorCall:
    case TerminatorNoReturn:
    case TerminatorCallUnresolved:
        operation = OperationAdd;
        break;

    case TerminatorReturn:
        operation = OperationSub;
        break;

    default:
        return false;
    }

    // Maybe also remove pushed return value here?
    const auto element_width = make_shared<Constant>(8);
    const auto rsp = make_shared<Operation>(needle->second, operation,
                                            element_width);

    _state.update(register_rsp, rsp);
    _state.update(register_rip, target);
    return true;
}
