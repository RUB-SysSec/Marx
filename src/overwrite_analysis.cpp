//
// Created by sqall on 16.12.15.
//

#include "overwrite_analysis.h"
#include "block_semantics.h"
#include <assert.h>

extern "C" {
#include <valgrind/libvex.h>
}

using namespace std;

OverwriteAnalysis::OverwriteAnalysis(Translator &translator,
    const Function &function,
    const unordered_set<uint64_t> &new_operators,
    const VTableFile &vtable_file,
    const ModulePlt &module_plt,
    const ExternalFunctions &external_funcs,
    const GotMap &got_map,
    const IDataMap &idata_map,
    const FctReturnValuesFile &fct_return_values,
    FctVTableUpdates &external_vtable_updates,
    VCallFile &vcall_file,
    const string &module_name,
    uint64_t memory_begin,
    uint64_t memory_end)

        : BaseAnalysis(function, translator.get_file_format()),
          _translator(translator),
          _file_format(_translator.get_file_format()),
          _new_operators(new_operators),
          _vtable_file(vtable_file),
          _module_plt(module_plt),
          _external_funcs(external_funcs),
          _got_map(got_map),
          _idata_map(idata_map),
          _fct_return_values(fct_return_values),
          _external_vtable_updates(external_vtable_updates),
          _vcall_file(vcall_file),
          _this_vtables(_vtable_file.get_this_vtables()),
          _module_name(module_name),
          _vtable_updates(_master_vtable_updates),
          _op_new_candidates(_master_op_new_candidates),
          _vtv_vcalls(_master_vtv_vcalls),
          _ret_value_mapping(_master_ret_value_mapping),
          _block_cache_true(_master_block_cache_true),
          _block_cache_false(_master_block_cache_false) {

    _call_depth = MAX_CALL_DEPTH;

    // List current function as "already processed" to avoid recursions
    // NOTE: can miss context-sensitve overwrites
    _functions_processed.insert(function.get_entry());

    _begin = memory_begin;
    _end = memory_end;

    // consider function to be a function of an object (either virtual or
    // normal)
    switch(_file_format) {
        case FileFormatELF64: // => set RDI to be a this ptr candidate
            add_this_candidate(State::initial_values().at(OFFB_RDI));
            break;
        case FileFormatPE64: // => set RCX to be a this ptr candidate
            add_this_candidate(State::initial_values().at(OFFB_RCX));
            break;
        default:
            throw runtime_error("Do not know how to handle file format.");
    }

    // Make sure that the vtable file is finalized.
    if(!_vtable_file.is_finalized()) {
        throw runtime_error("VTable file object was not initialized.");
    }
}


OverwriteAnalysis::OverwriteAnalysis(Translator &translator,
    const Function &function,
    const unordered_set<uint64_t> &new_operators,
    const VTableFile &vtable_file,
    const ModulePlt &module_plt,
    const ExternalFunctions &external_funcs,
    const GotMap &got_map,
    const IDataMap &idata_map,
    const FctReturnValuesFile &fct_return_values,
    FctVTableUpdates &external_vtable_updates,
    VCallFile &vcall_file,
    const string &module_name,
    uint64_t memory_begin,
    uint64_t memory_end,
    const State &initial_state,
    size_t call_depth,
    unordered_set<uint64_t> &functions_processed,
    VTableUpdates &vtable_updates,
    OperatorNewExprMap &op_new_candidates,
    VTVVcalls &vtv_vcalls,
    MultipleReturnValues &ret_value_mapping,
    unordered_set<uint64_t> &block_cache_true,
    unordered_set<uint64_t> &block_cache_false)

        : BaseAnalysis(function, translator.get_file_format()),
          _translator(translator),
          _file_format(_translator.get_file_format()),
          _new_operators(new_operators),
          _vtable_file(vtable_file),
          _module_plt(module_plt),
          _external_funcs(external_funcs),
          _got_map(got_map),
          _idata_map(idata_map),
          _fct_return_values(fct_return_values),
          _external_vtable_updates(external_vtable_updates),
          _vcall_file(vcall_file),
          _this_vtables(_vtable_file.get_this_vtables()),
          _module_name(module_name),
          _vtable_updates(vtable_updates),
          _op_new_candidates(op_new_candidates),
          _vtv_vcalls(vtv_vcalls),
          _ret_value_mapping(ret_value_mapping),
          _block_cache_true(block_cache_true),
          _block_cache_false(block_cache_false) {

    _initial_state = initial_state;
    _call_depth = call_depth;

    // List current function as "already processed" to avoid recursions
    // NOTE: can miss context-sensitve overwrites
    _functions_processed = functions_processed;
    _functions_processed.insert(function.get_entry());

    _begin = memory_begin;
    _end = memory_end;

    // Make sure that the object is initialized.
    if(!_vtable_file.is_finalized()) {
        throw runtime_error("VTable file object was not initialized.");
    }
}


void OverwriteAnalysis::pre_traversal() {
    return;
}


void OverwriteAnalysis::post_traversal() {
    return;
}


void OverwriteAnalysis::path_traversed(const Path &path) {

    // If the path ends with a return instruction, store the current
    // return value in a mapping.
    if(_last_block_ptr->get_terminator().type == TerminatorReturn) {
        State::const_iterator rax_value;
        if(_last_state_ptr->find(register_rax, rax_value)) {

            ReturnValue ret_value;
            ret_value.path = path;
            ret_value.content = rax_value->second;
            ret_value.func_addr = _function.get_entry();
            _return_values.push_back(ret_value);
        }
    }

    // Copy all active vtables on this path into the vector with
    // active vtables on all paths.
    for(const auto &new_it : _active_vtables) {

        // Skip all active vtable objects that we already have in the
        // vector that contains the active vtable objects on all paths.
        bool found = false;
        for(const auto &old_it : _all_paths_active_vtables) {

            // Check if both elements are on the same path.
            if(new_it.path.size() != old_it.path.size()) {
                continue;
            }
            bool is_same_path = true;
            for(uint32_t i = 0; i < new_it.path.size(); i++) {
                if(new_it.path.at(i) != old_it.path.at(i)) {
                    is_same_path = false;
                    break;
                }
            }
            if(!is_same_path) {
                continue;
            }

            // Check if both elements have the same location.
            if(*(new_it.vtbl_ptr_loc) != *(old_it.vtbl_ptr_loc)) {
                continue;
            }

            found = true;
            break;
        }
        if(found) {
            continue;
        }

        _all_paths_active_vtables.push_back(new_it);
    }

    return;
}


// Blocks are interesting that have an indirect call, or a vtable as a
// constant, or a call to a new operator.
bool OverwriteAnalysis::block_predicate(const Block &block) {

    // check if address of block is cached
    auto end_true  = _block_cache_true.cend();
    auto end_false = _block_cache_false.cend();

    if(_block_cache_true.find(block.get_address()) != end_true) {
        return true;
    }
    if(_block_cache_false.find(block.get_address()) != end_false) {
        return false;
    }

    switch(block.get_terminator().type) {

        // BBs with an indirect call are interesting.
        case TerminatorCallUnresolved:
            _block_cache_true.insert(block.get_address());
            return true;

        // Calls to new operators are interesting.
        case TerminatorCall: {
            uint64_t callee_address = block.get_terminator().target;

            if(_new_operators.find(callee_address) != _new_operators.end()) {
                _block_cache_true.insert(block.get_address());
                return true;
            }
            break;
        }

        default:
            break;
    }

    // BBs with a vtable as constant are interesting
    const IRSB &vex_block = block.get_vex_block();
    for(auto i = 0; i < vex_block.stmts_used; ++i) {
        const auto &curr_stmt = *vex_block.stmts[i];

        // extract expression ptr
        const IRExpr * curr_expr = nullptr;
        switch(curr_stmt.tag) {

            case Ist_Put:
                curr_expr = curr_stmt.Ist.Put.data;
                break;

            case Ist_Store:
                curr_expr = curr_stmt.Ist.Store.data;
                break;

            default:
                break;
        }

        // extract vtable candidate (if exists)
        if(curr_expr != nullptr && curr_expr->tag == Iex_Const) {

            const auto &curr_const = curr_expr->Iex.Const;

            uint64_t vtable_candidate = 0;
            switch(curr_const.con->tag) {
                case Ico_U32:
                    vtable_candidate = curr_const.con->Ico.U32;
                    break;
                case Ico_U64:
                    vtable_candidate = curr_const.con->Ico.U64;
                    break;
                default:
                    break;
            }

            // check if constant is a vtable candidate
            if(vtable_candidate != 0 && _this_vtables.find(vtable_candidate) !=
                    _this_vtables.cend()) {
                _block_cache_true.insert(block.get_address());
                return true;
            }
        }
    }

    _block_cache_false.insert(block.get_address());
    return false;
}


void OverwriteAnalysis::import_external_vtable_updates(
                                            const ExternalFunction *ext_func,
                                            State &state) {

    if(ext_func != nullptr) {
        // If external function makes vtable updates, import them
        // to the current made vtable updates.
        const VTableUpdates* ext_updates;
        ext_updates = _external_vtable_updates.get_vtable_updates(
                    ext_func->module_name,
                    ext_func->addr);
        if(ext_updates != nullptr) {
            for(const auto it : *ext_updates) {

                // Replace the base of the external vtable update
                // like "init_rdi" with the actual value that is inside
                // the register.
                VTableUpdate ext_update;
                bool found = false;
                switch(_file_format) {
                    case FileFormatELF64: {
                        for(uint32_t i = 0; i < NUMBER_SYSTEM_V_ARGS; i++) {
                            if(*it.base == *_system_v_arguments_init[i]) {
                                State::const_iterator arg_value;
                                if(state.find(system_v_arguments[i],
                                              arg_value)) {
                                    ext_update.base =
                                                     arg_value->second->clone();
                                    ext_update.index = it.index;
                                    ext_update.offset = it.offset;
                                    found = true;
                                    break;
                                }
                                else {
                                    throw runtime_error("External functions "\
                                                        "overwrites vtable in "\
                                                        "an object residing "\
                                                        "in a register which "\
                                                        "is not set by "\
                                                        "caller.");
                                }
                            }
                        }
                        break;
                    }
                    case FileFormatPE64: {
                        for(uint32_t i = 0; i < NUMBER_MSVC_ARGS; i++) {
                            if(*it.base == *_msvc_arguments_init[i]) {
                                State::const_iterator arg_value;
                                if(state.find(msvc_arguments[i], arg_value)) {
                                    ext_update.base =
                                                     arg_value->second->clone();
                                    ext_update.index = it.index;
                                    ext_update.offset = it.offset;
                                    found = true;
                                    break;
                                }
                                else {
                                    throw runtime_error("External functions "\
                                                        "overwrites vtable in "\
                                                        "an object residing "\
                                                        "in a register which "\
                                                        "is not set by "\
                                                        "caller.");
                                }
                            }
                        }
                        break;
                    }
                    default:
                        throw runtime_error("Do not know how to "\
                                            "handle file format.");
                }
                if(!found) {
                    throw runtime_error("Not able to import external "\
                                        "vtable overwrite.");
                }

                _vtable_updates.push_back(ext_update);
            }
        }
    }

}


void OverwriteAnalysis::import_external_return_values(const Path &path,
                                        State &state,
                                        const FctReturnValues* ext_ret_values) {

    if(ext_ret_values != nullptr) {

        for(const auto &it : ext_ret_values->active_vtables) {
            add_active_vtable(it.vtbl_ptr_loc,
                              path,
                              false,
                              true,
                              it.index);
        }

        // If only one return value is known from the external function
        // => copy it into the current state.
        if(ext_ret_values->return_values.size() == 1) {
#if DEBUG_PRINT_ICALL_RESOLUTION
            cout << "New return value from external function: "
                 << *(ext_ret_values->return_values.at(0).content)
                 << endl;
#endif
            // Check if external function was reached by a call
            // (we ignore other cases like a tail-jump for now).
            if(_current_return_value != nullptr) {
                state.update(_current_return_value,
                           ext_ret_values->return_values.at(0).content);
            }
        }
        else if(ext_ret_values->return_values.size() > 1) {
            // Check if external function was reached by a call
            // (we ignore other cases like a tail-jump for now).
            if(_current_return_value != nullptr) {
#if DEBUG_PRINT_ICALL_RESOLUTION
                for(const auto &it : ext_ret_values->return_values) {
                    cout << "New multiple return "
                         << "values from external function: "
                         << *(it.content)
                         << endl;
                }
#endif
                MultipleReturnValue mul_ret_values;
                mul_ret_values.location = _current_return_value;
                mul_ret_values.ret_values = ext_ret_values->return_values;
                _ret_value_mapping.push_back(mul_ret_values);
            }
        }
    }
}


inline void OverwriteAnalysis::handle_new_operator(const Block &block,
                                                   State &state) {

    // Note, current return value is the return value of the callee,
    // not the return value of the current function.
    add_this_candidate(_current_return_value);

    // Store the operator new candidate if we do not know it.
    if(_op_new_candidates.find(_current_return_value)
            == _op_new_candidates.cend()) {

        NewOperator temp;
        temp.addr = block.get_last_address();
        temp.expr = _current_return_value;

        // Extract size that is used for new operator.
        shared_ptr<Register> first_arg_reg_ptr;
        switch(_file_format) {
            case FileFormatELF64:
                first_arg_reg_ptr = system_v_arguments[0];
                break;
            case FileFormatPE64:
                first_arg_reg_ptr = msvc_arguments[0];
                break;
            default:
                throw runtime_error("Do not know how to "\
                                    "handle file format.");
        }
        const auto &first_arg_reg = first_arg_reg_ptr;

        State::const_iterator first_arg_value;
        if(state.find(first_arg_reg, first_arg_value)) {
            if(first_arg_value->second->type() != ExpressionConstant) {
                temp.size = 0;
            }
            else {
                Constant &size = static_cast<Constant&>(
                                                *first_arg_value->second);
                temp.size = size.value();
            }
        }
        else {
            temp.size = 0;
        }

        _op_new_candidates[_current_return_value] = temp;
    }
}


void OverwriteAnalysis::handle_jump(const Path &path,
                                    const Block &,
                                    State &state,
                                    uint64_t target_address,
                                    const string &target_module,
                                    bool external_module) {

    // Check if the target does not belong to the current module.
    if(external_module) {

        const ExternalFunction *ext_func;
        ext_func = _external_funcs.get_external_function(target_module,
                                                         target_address);
        if(ext_func == nullptr) {
            return;
        }

        // Import vtable updates made by the external function.
        import_external_vtable_updates(ext_func, state);

        // Import return values from the external function.
        const FctReturnValues* ext_ret_values;
        ext_ret_values = _fct_return_values.get_ext_return_values_ptr(
                                                            target_module,
                                                            target_address);
        import_external_return_values(path, state, ext_ret_values);

        return;
    }

    const auto *function = _translator.maybe_get_function(target_address);

    // check if function is valid and not yet processed
    if(_function.get_entry() == target_address ||
            _functions_processed.find(target_address) !=
            _functions_processed.cend()) {

        return;
    }

    // If the function is known, start a sub-analysis.
    if(function) {

        // Abort if we go too deep.
        if(_call_depth <= 0) {
            //cerr << "Call depth depleted." << endl;
            return;
        }

#if DEBUG_PRINT_ICALL_RESOLUTION
        cout << "Processing (sub-analysis) "
             << hex << target_address << "... "
             << endl;
#endif

        // Start a new sub-analysis of the found interesting function.
        OverwriteAnalysis sub_analysis(_translator,
                                       *function,
                                       _new_operators,
                                       _vtable_file,
                                       _module_plt,
                                       _external_funcs,
                                       _got_map,
                                       _idata_map,
                                       _fct_return_values,
                                       _external_vtable_updates,
                                       _vcall_file,
                                       _module_name,
                                       _begin,
                                       _end,
                                       state,
                                       _call_depth - 1,
                                       _functions_processed,
                                       _vtable_updates,
                                       _op_new_candidates,
                                       _vtv_vcalls,
                                       _ret_value_mapping,
                                       _block_cache_true,
                                       _block_cache_false);

        // copy the current this pointer candidates to the sub analysis
        for(const auto &it : _this_candidates) {
            sub_analysis.add_this_candidate(it);
        }

        // Copy all current active vtables into the sub analysis and set
        // it as coming from the caller.
        for(const auto &it : _active_vtables) {
            // Make a copy if the reference.
            VTableActive copied_active_vtable = it;
            copied_active_vtable.from_caller = true;
            copied_active_vtable.from_callee = false;

            // Clear path so the active vtable comes from the first basic block.
            copied_active_vtable.path.clear();
            sub_analysis.add_active_vtable(copied_active_vtable);
        }

        sub_analysis.obtain();

        // Copy all active vtables from the sub analysis and set it as
        // coming from the callee
        const vector<VTableActive> &active_vtables =
                                    sub_analysis.get_active_vtables();
        for(const auto &it : active_vtables) {
            // Ignore active vtable objects that come from the caller.
            if(!it.from_caller) {

#if DEBUG_PRINT_ICALL_RESOLUTION
                cout << "New active vtable from callee: "
                     << *(it.vtbl_ptr_loc)
                     << endl;
#endif

                // Copy current path to the object so the active vtable
                // comes from the callee of exactly this call.
                add_active_vtable(it.vtbl_ptr_loc, path, false, true, it.index);
            }
        }

        // Copy return values back
        const vector<ReturnValue> &ret_values = sub_analysis.get_return_values();
        // If only one return value is known from the sub-analysis
        // => copy it into the current state.
        if(ret_values.size() == 1) {
            // Check if sub-processed function was reached by a call
            // (we ignore other cases like a tail-jump for now).
            if(_current_return_value != nullptr) {
                state.update(_current_return_value, ret_values.at(0).content);
            }
        }
        else if(ret_values.size() > 1) {
            // Check if sub-processed function was reached by a call
            // (we ignore other cases like a tail-jump for now).
            if(_current_return_value != nullptr) {
#if DEBUG_PRINT_ICALL_RESOLUTION
                for(const auto &ret_it : ret_values) {
                    cout << "New multiple return values from callee: "
                         << *(ret_it.content)
                         << endl;
                }
#endif
                MultipleReturnValue mul_ret_values;
                mul_ret_values.location = _current_return_value;
                mul_ret_values.ret_values = ret_values;
                _ret_value_mapping.push_back(mul_ret_values);

#if ACTIVATE_RETURN_HEURISTIC
                // Simple heuristic that considers all vtables that are
                // returned by the analyzed function as dependent.
                // NOTE: This will break if the function uses a void pointer
                // as return type and will overestimate if vtables
                // (that are not dependent) reside
                // in the return register at the end and the function does not
                // return any value (is of type void).
                for(const auto &ret_it : ret_values) {
                    for(const auto &act_it : active_vtables) {
                        if(!act_it.vtbl_ptr_loc->contains(*(ret_it.content))) {
                            continue;
                        }

                        // TODO: This totally ignores the offset at the moment
                        // and will overestimated.
                        VTableUpdate temp;
                        temp.offset = 0;
                        temp.index = act_it.index;
                        stringstream stream;
                        stream << "func_return_" << hex << target_address;
                        Symbolic temp_sym(stream.str());
                        temp.base = make_shared<Symbolic>(temp_sym);
                        add_vtable_update(temp);
                    }
                }
#endif

            }
        }

#if DEBUG_PRINT_ICALL_RESOLUTION
        cout << "Done (sub-analysis) "
             << hex << target_address << "."
             << endl;
#endif

    }

    // If the function is not known, check if it is a plt entry and
    // resolve it.
    else {
        const PltEntry *plt_entry = _module_plt.get_plt_entry(target_address);
        if(plt_entry != nullptr) {

            const string &func_name = plt_entry->func_name;
            const ExternalFunction *ext_func;
            ext_func = _external_funcs.get_external_function(func_name);

            // Import vtable updates made by the external function.
            import_external_vtable_updates(ext_func, state);

            // If plt function has return values, import them.
            const FctReturnValues* plt_ret_values;
            plt_ret_values = _fct_return_values.get_plt_return_values_ptr(
                                                                target_address);
            import_external_return_values(path, state, plt_ret_values);
        }
    }

    return;
}


void OverwriteAnalysis::handle_call(const Path &path,
                                    const Block &block,
                                    State &state) {

    uint64_t callee_address = block.get_terminator().target;

    // TODO overwrite the return value of the VTV function
    // (used to generate ground truth with the help of VTV)
    // VTV stub to verify vtable looks like this:
    // https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/libsupc%2B%2B/vtv_stubs.cc
    // const void*
    // __VLTVerifyVtablePointer(void**, const void* vtable_ptr)
    // { return vtable_ptr; }
    //
    // => return value contains always vtable pointer
    /*
    if(callee_address == 0x6BC050) { // node+vtv
    //if(callee_address == 0x11A70) { // flac+vtv
    //if(callee_address == 0x8EB0A0) { // mongodb+vtv
        const auto &second_arg_reg = system_v_arguments[1];
        State::const_iterator ret_value;
        if(state.find(second_arg_reg, ret_value)) {
            if(_current_return_value != nullptr) {
                state.update(_current_return_value, ret_value->second);

                // Store call to vtv verifiy function to find vcalls that
                // use it.
                uint64_t vtv_verify_addr = block.get_last_address();
                if(_vtv_vcalls.find(vtv_verify_addr)
                        != _vtv_vcalls.cend()) {
                    _vtv_vcalls[vtv_verify_addr].vtbl_obj = ret_value->second;
                }
                else {
                    VTVVcall temp;
                    temp.addr_verify_call = vtv_verify_addr;
                    temp.vtbl_obj = ret_value->second;
                    _vtv_vcalls[temp.addr_verify_call] = temp;
                }
            }
        }
        return;
    }
    */

    // Check if callee is a call to new operator.
    if(_new_operators.find(callee_address) != _new_operators.end()) {
        handle_new_operator(block, state);
        return;
    }

#if FOLLOW_ONLY_INTERESTING_CALLS
    // Check if any arg register contains a this pointer candidate
    // => consider function as interesting.
    bool is_interesting = false;
    switch(_file_format) {
        case FileFormatELF64: {
            for(const auto &arg_reg : system_v_arguments) {

                State::const_iterator arg_value;
                if(state.find(arg_reg, arg_value)) {

                    // check if arg register contains any of the
                    // this pointer candidates
                    for(const auto &it : _this_candidates) {
                        if(arg_value->second->contains(*it)) {

                            is_interesting = true;
                            break;
                        }
                    }
                    if(is_interesting) {
                        break;
                    }
                }
            }
            break;
        }
        case FileFormatPE64: {
            for(const auto &arg_reg : msvc_arguments) {

                State::const_iterator arg_value;
                if(state.find(arg_reg, arg_value)) {

                    // check if arg register contains any of the
                    // this pointer candidates
                    for(const auto &it : _this_candidates) {
                        if(arg_value->second->contains(*it)) {

                            is_interesting = true;
                            break;
                        }
                    }
                    if(is_interesting) {
                        break;
                    }
                }
            }
            break;
        }
        default:
            throw runtime_error("Do not know how to handle file format.");
    }

    // Consider calls to a plt entry as interesting (since we only import
    // data into our analysis run).
    const PltEntry *plt_entry = _module_plt.get_plt_entry(callee_address);
    if(plt_entry != nullptr) {
        is_interesting = true;
    }

    // TODO: Concept of interesting is not good if we do not know if it could
    // return a vtable object. But it could explode if we do not use it.
    // Pre-processing and taint functions that are interesting for us?
    if(!is_interesting) {
        return;
    }
#endif

    handle_jump(path, block, state, callee_address, _module_name, false);
}


void OverwriteAnalysis::add_vtable_update(const ExpressionPtr &base,
                                          uint64_t new_vtable,
                                          size_t offset) {

    const VTable &vtable = _vtable_file.get_vtable(_module_name,
                                                   new_vtable);
    uint32_t index = vtable.index;

    // Check if vtable overwrite is already known.
    for(const auto &it : _vtable_updates) {
        if(*(it.base) == *base
           && it.offset == offset
           && it.index == index) {

            return;
        }
    }

    VTableUpdate vtable_update;
    vtable_update.offset = offset;
    vtable_update.base = base;
    vtable_update.index = index;

    _vtable_updates.push_back(vtable_update);

}


uint64_t OverwriteAnalysis::get_used_table_entry(const ExpressionPtr &exp) {

    switch(exp->type()) {
        case ExpressionConstant: {
            Constant &temp = static_cast<Constant&>(*exp);

            // TODO
            // first check range to make it more performant

            switch(_file_format) {
                case FileFormatELF64:
                    if(_got_map.find(temp.value()) != _got_map.cend()) {
                        return temp.value();
                    }
                    break;
                case FileFormatPE64:
                    if(_idata_map.find(temp.value()) != _idata_map.cend()) {
                        return temp.value();
                    }
                    break;
                default:
                    throw runtime_error("Do not know how to "\
                                        "handle file format.");
            }

            break;
        }

        case ExpressionOperation: {
            Operation &temp = static_cast<Operation&>(*exp);
            uint64_t result_lhs = get_used_table_entry(temp.lhs());
            uint64_t result_rhs = get_used_table_entry(temp.rhs());

            // Check that not both sides of the operation contain
            // an address to a .got entry.
            assert((result_lhs == 0
                   || result_rhs == 0)
                   && "Do not know how to handle an operation "
                   && "with two .got constants.");

            if(result_lhs != 0) {
                return result_lhs;
            }
            else {
                return result_rhs;
            }
        }

        case ExpressionIndirection: {
            Indirection &temp = static_cast<Indirection&>(*exp);
            return get_used_table_entry(temp.address());
        }

        default:
            break;
    }
    return 0;
}


bool OverwriteAnalysis::in_traversal(const Path &path,
                                     const Block &block,
                                     State &state) {

    const auto &memory = state.get_memory_accesses();

    // Replace indirections to .got entries with their content
    // (obviously only when we analyze ELF binaries).
    if(_file_format == FileFormatELF64) {
        bool state_changed = false;
        for(const auto &kv : memory) {
            // Ignore all constants.
            if(kv.second->type() == ExpressionConstant) {
                continue;
            }

            uint64_t got_entry_addr = get_used_table_entry(kv.second);
            if(got_entry_addr != 0) {

                Constant key_const(got_entry_addr);
                ExpressionPtr key_exp_ptr = make_shared<Constant>(key_const);
                Indirection key_ind(key_exp_ptr);
                key_exp_ptr = make_shared<Indirection>(key_ind);

                Constant value_const(_got_map.at(got_entry_addr));
                ExpressionPtr value_exp_ptr =
                                             make_shared<Constant>(value_const);

                kv.second->propagate(key_exp_ptr, value_exp_ptr);

                state_changed = true;
            }
        }
        if(state_changed) {
            state.optimize();
        }
    }

    for(const auto &kv : memory) {

        // Extract possible vtable.
        uint64_t vtable_addr = 0;

        // After .got entries were resolved and the state is optimized,
        // memory values can have the following form:
        // (0x8578d0 + 0x0)
        if(kv.second->type() == ExpressionOperation) {
            Operation &temp_op = static_cast<Operation&>(*(kv.second));
            if(temp_op.lhs()->type() != ExpressionConstant
                || temp_op.lhs()->type() != ExpressionConstant) {
                continue;
            }

            Constant &vtable_candidate =
                                    static_cast<Constant&>(*(temp_op.lhs()));
            vtable_addr = vtable_candidate.value();
        }

        // If memory value is a constant, consider it as a vtable.
        else if(kv.second->type() == ExpressionConstant) {
            Constant &vtable_candidate = static_cast<Constant&>(*(kv.second));
            vtable_addr = vtable_candidate.value();
        }

        // Ignore all memory indirections that do not point to constant.
        else {
            continue;
        }

        // check if constant value is a vtable
        if(_this_vtables.find(vtable_addr) == _this_vtables.cend()) {
            continue;
        }

        // check if the vtable is written into a this-pointer candidate
        for(const auto &it : _this_candidates) {

            bool result = kv.first->contains(*it);
            if(result) {

                size_t offset = 0;
                ExpressionPtr base;

                // Add vtable as active vtable for this path.
                add_active_vtable(kv.first, vtable_addr, path, false, false);

                // check that memory object is an indirection
                // => raise assertion if not
                assert(kv.first->type() == ExpressionIndirection
                       && "Expected indirection."
                       && "Do not know how to handle it.");

                Indirection &temp_ind = static_cast<Indirection&>(*(kv.first));

                // extract offset and base value
                switch(temp_ind.address()->type()) {

                    // case operation, get the outer offset
                    // (i.e., [rdi+0x8] => offset: 0x8 or
                    // [[rdi+0x8]+0x10] => offset: 0x10)
                    case ExpressionOperation: {

                        // get offset value
                        auto inner = temp_ind.address();
                        Operation &temp_op = static_cast<Operation&>(*inner);

                        assert(temp_op.rhs()->type() == ExpressionConstant
                               && "Expected constant."
                               && "Do not know how to handle it.");
                        offset = static_cast<Constant&>(*temp_op.rhs()).value();

                        // use complete left hand side as base
                        // (i.e., [rdi+0x8] => base: rdi or
                        // [[rdi+0x8]+0x10] => base: [rdi+0x8])
                        base = temp_op.lhs();

                        break;
                    }

                    // case symbolic, set offset 0 and get
                    // base (i.e., [rdi] => base: rdi)
                    case ExpressionSymbolic:
                    // case indirection, set offset 0 and get base
                    // (i.e., [[[([(init_rdi + 0x8)] + 0x188)]]]
                    // => base: [[([(init_rdi + 0x8)] + 0x188)]])
                    case ExpressionIndirection:
                        base = temp_ind.address();
                        offset = 0;
                        break;

                    // error case
                    default:
                        throw runtime_error("Unexpected Expression Type.");
                }

                // Only add vtable overwrite if it does not exist already.
                add_vtable_update(base, vtable_addr, offset);

                // Add vtable to the new operator object to which
                // it was written to (if it was written to any)
                for(auto &op_new : _op_new_candidates) {
                    if(*op_new.second.expr == *it) {

                        const VTable &vtable = _vtable_file.get_vtable(
                                                                _module_name,
                                                                vtable_addr);
                        uint32_t index = vtable.index;
                        op_new.second.vtbl_idxs.insert(index);
                        break;
                    }
                }
            }
        }
    }

    switch(block.get_terminator().type) {
        case TerminatorCall:
            handle_call(path, block, state);
            break;

        case TerminatorJump: {
            uint64_t target_address = block.get_terminator().target;
            if(target_address) {
                handle_jump(path,
                            block,
                            state,
                            target_address,
                            _module_name,
                            false);
            }
            break;
        }

        case TerminatorCallUnresolved:
            handle_indirect_call(path, block, state);
            break;

        default:
            break;
    }

    _last_state_ptr = make_shared<State>(state);
    _last_block_ptr = make_shared<Block>(block);
    return true;
}


void OverwriteAnalysis::add_this_candidate(const ExpressionPtr &expression) {
    _this_candidates.insert(expression);
}


void OverwriteAnalysis::add_vtable_update(const VTableUpdate &vtable_update) {
    _vtable_updates.push_back(vtable_update);
}


void OverwriteAnalysis::handle_indirect_call(const Path &path,
                                             const Block &block,
                                             State &state) {

    // Remove active vtables that do not belong to the current path.
    path_update_active_vtables(path);

#if DEBUG_PRINT_ICALL_RESOLUTION
    cout << "Currently active vtables:" << endl;
    for(const auto &it : _active_vtables) {
        cout << "Active vtable: "
             << "Idx: "
             << dec << it.index
             << " Location: "
             << *(it.vtbl_ptr_loc) << endl;
    }
#endif

    // Get RIP value (in which the target of the indirect call is stored).
    State::const_iterator rip_value;
    if(state.find(register_rip, rip_value)) {

        ExpressionPtr icall_target = rip_value->second;

        // On Windows binaries, calls to external new operators (such as the
        // default new operator) are often implemented via an indirect call in
        // the form of "call [0x2120]" where 0x2120 is part of the .idata
        // => extract indirect call address to .idata and check if it is
        // a new operator.
        if(_file_format == FileFormatPE64) {
            uint64_t idata_entry_addr = get_used_table_entry(icall_target);
            if(idata_entry_addr != 0) {

                // Check if callee is a call to new operator.
                if(_new_operators.find(idata_entry_addr)
                                                      != _new_operators.end()) {
                    handle_new_operator(block, state);
                    return;
                }

            }
        }

        // Check if this argument is used for call target
        // => possible vcall found.
        shared_ptr<Register> this_arg_ptr;
        switch(_file_format) {
            case FileFormatELF64:
                this_arg_ptr = system_v_arguments[0];
                break;
            case FileFormatPE64:
                this_arg_ptr = msvc_arguments[0];
                break;
            default:
                throw runtime_error("Do not know how to "\
                                    "handle file format.");
        }
        const auto &this_arg = this_arg_ptr;

        State::const_iterator this_value;
        if(state.find(this_arg, this_value)) {
            if(icall_target->contains(*this_value->second)) {
                uint64_t call_addr = block.get_last_address();
                _vcall_file.add_possible_vcall(call_addr);
            }
        }

        // Check if call target uses a value that comes from the
        // vtv verify function
        // => found a vcall for the ground truth
        for(auto &it : _vtv_vcalls) {
            if(icall_target->contains(*it.second.vtbl_obj)) {
                it.second.addr_vcalls.insert(block.get_last_address());
                break;
            }
        }

        switch(icall_target->type()) {

            // case indirection
            // i.e., [([init_rdi] + 0x798)]
            case ExpressionIndirection: {

                ExpressionPtr outer = static_cast<Indirection&>(
                                                       *icall_target).address();

                // Extract offset and base
                size_t entry_offset = 0;
                ExpressionPtr base = nullptr;
                switch(outer->type()) {

                    // case operation
                    // i.e., [init_rdi] + 0x798
                    case ExpressionOperation: {
                        Operation &temp_op = static_cast<Operation&>(*outer);

                        assert(temp_op.rhs()->type() == ExpressionConstant
                               && "Expected constant."
                               && "Do not know how to handle it.");
                        entry_offset = static_cast<Constant&>(
                                                        *temp_op.rhs()).value();

                        base = temp_op.lhs();
                        break;
                    }

                    // case indirection (means there is no offset)
                    // i.e., [return_400807]
                    case ExpressionIndirection: {
                        base = outer;
                        break;
                    }

                    // case constant (means there is no offset or
                    // no vtable is used)
                    // i.e., 0xab01c0
                    case ExpressionConstant: {
                        // Constant could be directly a vtable (which means
                        // there is no offset at all) but also a jump table
                        // which we can not resolve.
                        base = outer;
                        break;
                    }

                    // case symbolic (means we can not resolve the dynamic call)
                    // i.e., init_rcx
                    case ExpressionSymbolic:
                        return;

                    default:
                        throw runtime_error("Do not know how to handle type "\
                                            "of the content of PC indirection "\
                                            "in indirect call resolving.");
                }

#if DEBUG_PRINT_ICALL_RESOLUTION
                cout << "Indirect call resolving: " << endl;
                cout << "BB: " << hex << block.get_address() << endl;
                cout << "Before: " << *icall_target << endl;
                cout << "Base: " << *base << endl;
                cout << "Entry Offset: " << hex << entry_offset << endl;
#endif

                // Only works for x64 systems.
                size_t entry_index = entry_offset / 0x8;

                // The expression can be directly a vtable.
                // The icall target then looks like
                // [(0x821730 + 0x8)]
                // which is split into
                // base: 0x821730
                // entry offset: 0x8
                if(base->type() == ExpressionConstant) {

                    Constant &const_temp = static_cast<Constant&>(*base);

                    // Check if constant value is a vtable pointer.
                    uint64_t vtbl_cand = const_temp.value();
                    const VTable *vtbl_ptr = _vtable_file.get_vtable_ptr(
                                                            _module_name,
                                                            vtbl_cand);

                    // Ignore value if it is not a vtable pointer.
                    if(vtbl_ptr == nullptr) {
                        break;
                    }

                    uint64_t target_func = vtbl_ptr->entries.at(entry_index);

#if DEBUG_PRINT_ICALL_RESOLUTION
                    cout << "Target function: "
                         << hex << target_func
                         << endl;
#endif

                    handle_jump(path,
                                block,
                                state,
                                target_func,
                                _module_name,
                                false);
                }

                // If it is not directly a constant we can handle,
                // check if it is a symbol that has a known active vtable.
                else {

                    // Try to directly resolve the symbol with the currently
                    // active vtables.
                    bool found = false;

                    // Process a copy of the active vtables
                    // because the subanalysis steps can change
                    // the current active vtables vector.
                    const vector<VTableActive> copied_act_vtables =
                                                                _active_vtables;
                    for(const auto &it : copied_act_vtables) {
                        if(*(it.vtbl_ptr_loc) == *base) {
                            const VTable &vtable = _vtable_file.get_vtable(
                                                                  it.index);

#if DEBUG_PRINT_ICALL_RESOLUTION
                            cout << "Found usage of vtable "
                                 << vtable.module_name << ":"
                                 << hex << vtable.addr
                                 << " in virtual call."
                                 << endl;
#endif

                            if(vtable.entries.size() <= entry_index) {
                                cerr << "Index larger than vtable entries "
                                     << "while resolving indirect call."
                                     << endl;
                                return;
                            }

                            uint64_t target_func = vtable.entries.at(
                                                               entry_index);

                            // Store this vcall and the vtable that is
                            // used by it.
                            uint64_t call_addr = block.get_last_address();
#if ACTIVATE_CONSERVATIVE_VCALLS
                            // Check if first arg register contains any of
                            // the this pointer candidates before
                            // considering it as a vcall
                            bool is_vcall = false;
                            shared_ptr<Register> arg_ptr;
                            switch(_file_format) {
                                case FileFormatELF64:
                                    arg_ptr = system_v_arguments[0];
                                    break;
                                case FileFormatPE64:
                                    arg_ptr = msvc_arguments[0];
                                    break;
                                default:
                                    throw runtime_error("Do not know how to "\
                                                        "handle file format.");
                            }
                            const auto &arg_reg = arg_ptr;

                            State::const_iterator arg_value;
                            if(state.find(arg_reg, arg_value)) {

                                for(const auto &it_this : _this_candidates) {
                                    if(arg_value->second->contains(*it_this)) {

                                        is_vcall = true;
                                        break;
                                    }
                                }
                            }
                            if(is_vcall) {
                                _vcall_file.add_vcall(call_addr,
                                                      vtable.index,
                                                      entry_index);
                            }
#else
                            _vcall_file.add_vcall(call_addr,
                                                  vtable.index,
                                                  entry_index);
#endif

#if DEBUG_PRINT_ICALL_RESOLUTION
                            cout << "Target function: "
                                 << hex << target_func
                                 << endl;
#endif

                            if(vtable.module_name != _module_name) {
                                handle_jump(path,
                                            block,
                                            state,
                                            target_func,
                                            vtable.module_name,
                                            true);
                            }
                            else {
                                handle_jump(path,
                                            block,
                                            state,
                                            target_func,
                                            _module_name,
                                            false);
                            }

                            found = true;
                            break;
                        }
                    }

                    // If we could not resolve the indirect call directly,
                    // use the return value mapping for it.
                    if(!found) {

                        // NOTE: iterate over the vector via size because
                        // items can be pushed into the vector during the
                        // iteration (which do not matter during this loop,
                        // but will lead to memory leaks if we use an iterator)
                        uint32_t curr_size = _ret_value_mapping.size();
                        for(uint32_t i = 0; i < curr_size; i++) {

                            // Since we care about vtable pointer, the
                            // object has another indirection to get to the
                            // vtbl ptr. Example: stored in the return
                            // value mapping is "return_400807" but the base
                            // will look like this "[return_400807]".
                            // Skip if base does not contain the return value
                            // location.
                            if(!base->contains(
                                           *(_ret_value_mapping[i].location))) {
                                continue;
                            }

                            unordered_set<uint32_t> dependent_vtables;

                            bool jump_taken = false;

                            // NOTE: iterate over the vector via size because
                            // items can be pushed into the vector during the
                            // iteration
                            // (can lead to memory leaks if we use an iterator)
                            uint32_t curr_ret_size =
                                        _ret_value_mapping[i].ret_values.size();
                            for(uint32_t j = 0; j < curr_ret_size; j++) {
                                // Copy the base and replace the return value
                                // symbol with the one stored for it in
                                // the return value mapping.
                                // Example: "[return_400807]" replace
                                // "return_400807" with "return_4007a9" so
                                // we get "[return_4007a9]".
                                ExpressionPtr copied_base = nullptr;
                                switch(base->type()) {
                                    case ExpressionSymbolic:
                                    case ExpressionIndirection: {
                                        copied_base = base->clone();
                                        break;
                                    }

                                    default:
                                        throw runtime_error("Do not know "\
                                                            "how to handle "\
                                                            "type of base "\
                                                            "during copy "\
                                                            "in indirect call "\
                                                            "resolving.");
                                }
                                copied_base->propagate(
                                   _ret_value_mapping[i].location,
                                   _ret_value_mapping[i].ret_values[j].content);

                                // Process a copy of the active vtables
                                // because the subanalysis steps can change
                                // the current active vtables vector.
                                const vector<VTableActive> cpy_act_vtables =
                                                                _active_vtables;
                                for(const auto &act_it : cpy_act_vtables) {
                                    if(*copied_base == *(act_it.vtbl_ptr_loc)) {

                                        found = true;

                                        const VTable &vtable =
                                          _vtable_file.get_vtable(act_it.index);

#if DEBUG_PRINT_ICALL_RESOLUTION
                                        cout << "Found usage of vtable "
                                             << hex << vtable.addr
                                             << " in virtual call "
                                             << "(multiple possibilities)."
                                             << endl;
#endif

                                        // Consider all vtables that are used
                                        // by this indirect call as dependent.
                                        dependent_vtables.insert(vtable.index);

                                        // Only consider first target for
                                        // now.
                                        //
                                        // TODO: Can we somehow split the
                                        // analysis from here and make
                                        // multiple new ones? Will this
                                        // explode?
                                        if(!jump_taken) {

                                            // This case can happen if we
                                            // have a manual type check
                                            // in the code that calls functions
                                            // depending on the type
                                            if(vtable.entries.size()
                                                    <= entry_index) {
                                                continue;
                                            }

                                            uint64_t target_func =
                                                 vtable.entries.at(entry_index);

#if DEBUG_PRINT_ICALL_RESOLUTION
                                            cout << "Target function: "
                                                 << hex << target_func
                                                 << endl;
#endif

                                            jump_taken = true;
                                            if(vtable.module_name
                                                              != _module_name) {
                                                handle_jump(path,
                                                            block,
                                                            state,
                                                            target_func,
                                                            vtable.module_name,
                                                            true);
                                            }
                                            else {
                                                handle_jump(path,
                                                            block,
                                                            state,
                                                            target_func,
                                                            _module_name,
                                                            false);
                                            }
                                        }
                                    }
                                }
                            }

                            // Store this vcall and the vtables that were
                            // used by it.
                            uint64_t call_addr = block.get_last_address();
#if ACTIVATE_CONSERVATIVE_VCALLS
                            // Check if first arg register contains any of
                            // the this pointer candidates before
                            // considering it as a vcall
                            bool is_vcall = false;
                            shared_ptr<Register> arg_ptr;
                            switch(_file_format) {
                                case FileFormatELF64:
                                    arg_ptr = system_v_arguments[0];
                                    break;
                                case FileFormatPE64:
                                    arg_ptr = msvc_arguments[0];
                                    break;
                                default:
                                    throw runtime_error("Do not know how to "\
                                                        "handle file format.");
                            }
                            const auto &arg_reg = arg_ptr;
                            State::const_iterator arg_value;
                            if(state.find(arg_reg, arg_value)) {

                                for(const auto &it_this : _this_candidates) {
                                    if(arg_value->second->contains(*it_this)) {

                                        is_vcall = true;
                                        break;
                                    }
                                }
                            }
                            if(is_vcall) {
                                for(uint32_t idx : dependent_vtables) {
                                    _vcall_file.add_vcall(call_addr,
                                                          idx,
                                                          entry_index);
                                }
                            }
#else
                            for(uint32_t idx : dependent_vtables) {
                                _vcall_file.add_vcall(call_addr,
                                                      idx,
                                                      entry_index);
                            }
#endif
                        }
                    }
                }

                break;
            }

            // case constant
            case ExpressionConstant: {

                // Constant is mostly 0 because the path can not be taken
                // normally, like clearing a register and then
                // have somewhere a check if the register is 0. We do not
                // evaluate the checks and just take the branch. But in case
                // the constant is a valid target, just handle the value
                // as a target address.
                uint64_t target_addr =
                            static_cast<Constant&>(*icall_target).value();
                handle_jump(path,
                            block,
                            state,
                            target_addr,
                            _module_name,
                            false);

                break;
            }

            // Case symbolic expression.
            // This can happen for example if we can not resolve a argument
            // register at this point.
            case ExpressionSymbolic:
                break;

            // Case unkown expression.
            // This can happen for example if the current state can not be
            // defined correctly by the execution engine.
            case ExpressionUnknown:
                break;

            default:
                throw runtime_error("Do not know how to handle type "\
                                    "of the content of PC "\
                                    "in indirect call resolving.");
        }
    }

    return;
}


void OverwriteAnalysis::add_active_vtable(const VTableActive &active_vtable) {

    // TODO
    // check if active vtable already does exist and path

    _active_vtables.push_back(active_vtable);
}


void OverwriteAnalysis::add_active_vtable(const ExpressionPtr &vtbl_ptr_loc,
                                          uint64_t vtable_addr,
                                          const Path &path,
                                          bool from_caller,
                                          bool from_callee) {

    const VTable &vtable = _vtable_file.get_vtable(_module_name,
                                                   vtable_addr);
    uint32_t index = vtable.index;

    add_active_vtable(vtbl_ptr_loc, path, from_caller, from_callee, index);

}


void OverwriteAnalysis::add_active_vtable(const ExpressionPtr &vtbl_ptr_loc,
                                          const Path &path,
                                          bool from_caller,
                                          bool from_callee,
                                          uint32_t index) {
    // Remove active vtables that do not belong to the current path.
    path_update_active_vtables(path);


    bool found = false;
    for(auto &it : _active_vtables) {
        if(*(it.vtbl_ptr_loc) == *vtbl_ptr_loc) {
            it.index = index;
            it.path = path;
            it.from_caller = from_caller;
            it.from_callee = from_callee;
            found = true;
            break;
        }
    }
    if(!found) {
        VTableActive vtable_active;
        vtable_active.index = index;
        vtable_active.vtbl_ptr_loc = vtbl_ptr_loc;
        vtable_active.path = path;
        vtable_active.from_caller = from_caller;
        vtable_active.from_callee = from_callee;

        _active_vtables.push_back(vtable_active);
    }
}


const vector<VTableActive>& OverwriteAnalysis::get_active_vtables() const {
    return _all_paths_active_vtables;
}


const std::vector<ReturnValue>& OverwriteAnalysis::get_return_values() const {
    return _return_values;
}


void OverwriteAnalysis::path_update_active_vtables(const Path &path) {

    for(auto it = _active_vtables.begin(); it != _active_vtables.end();) {

        // Remove active vtable object if its path is longer
        // than our current path.
        if(it->path.size() > path.size()) {
            it = _active_vtables.erase(it);
            continue;
        }

        // Remove active vtable object if it does not lie on our current path.
        bool removed = false;
        for(uint32_t i = 0; i < it->path.size(); i++) {
            if(it->path.at(i) != path.at(i)) {
                it = _active_vtables.erase(it);
                removed = true;
                break;
            }
        }
        if(removed) {
            continue;
        }

        ++it;
    }
}
