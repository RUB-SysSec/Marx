//
// Created by sqall on 16.12.15.
//

#ifndef RANGR_OVERWRITE_ANALYSIS_H
#define RANGR_OVERWRITE_ANALYSIS_H

#include "base_analysis.h"
#include "expression.h"
#include "translator.h"
#include "state.h"
#include "block.h"
#include "vtable_file.h"
#include "expression.h"
#include "vtable_update.h"
#include "module_plt.h"
#include "external_functions.h"
#include "vcall.h"
#include "got.h"
#include "idata.h"
#include "return_value.h"
#include "new_operators.h"
#include "vtv_vcall_gt.h"

#include <map>
#include <set>
#include <memory>
#include <unordered_set>

#define NUMBER_SYSTEM_V_ARGS 6
#define NUMBER_MSVC_ARGS 4

#define DEBUG_PRINT_ICALL_RESOLUTION 0

#define FOLLOW_ONLY_INTERESTING_CALLS 0
#define ACTIVATE_RETURN_HEURISTIC 0
#define ACTIVATE_CONSERVATIVE_VCALLS 0

const auto MAX_CALL_DEPTH = 2;

struct MultipleReturnValue {
    ExpressionPtr location;
    std::vector<ReturnValue> ret_values;
};


typedef std::map<ExpressionPtr, NewOperator> OperatorNewExprMap;

typedef std::unordered_set<ExpressionPtr, std::hash<ExpressionPtr>,
        ExpressionPtrComparison> ExpressionPtrUnorderedSet;

typedef std::vector<MultipleReturnValue> MultipleReturnValues;


/*!
 * \brief Class for analyzing the given module for vtable overwrites.
 *
 * Creates a vector of `VTableUpdate` that can be collected after the
 * analysis has finished.
 */
class OverwriteAnalysis : public BaseAnalysis {
private:

    Translator &_translator;
    const FileFormatType _file_format;

    uint64_t _begin, _end;
    size_t _call_depth;

    const std::unordered_set<uint64_t> &_new_operators;

    std::unordered_set<uint64_t> _functions_processed;
    const VTableFile &_vtable_file;
    const ModulePlt &_module_plt;
    const ExternalFunctions &_external_funcs;
    const GotMap &_got_map;
    const IDataMap &_idata_map;
    const FctReturnValuesFile &_fct_return_values;
    FctVTableUpdates &_external_vtable_updates;
    VCallFile &_vcall_file;
    const VTableMap &_this_vtables;

    const std::string _module_name;

    const ExpressionPtr _system_v_arguments_init[NUMBER_SYSTEM_V_ARGS] = {
        State::initial_values().at(OFFB_RDI),
        State::initial_values().at(OFFB_RSI),
        State::initial_values().at(OFFB_RDX),
        State::initial_values().at(OFFB_RCX),
        State::initial_values().at(OFFB_R8),
        State::initial_values().at(OFFB_R9)
    };

    const ExpressionPtr _msvc_arguments_init[NUMBER_MSVC_ARGS] = {
        State::initial_values().at(OFFB_RCX),
        State::initial_values().at(OFFB_RDX),
        State::initial_values().at(OFFB_R8),
        State::initial_values().at(OFFB_R9)
    };

    VTableUpdates _master_vtable_updates;
    VTableUpdates &_vtable_updates;

    std::vector<VTableActive> _active_vtables;
    std::vector<VTableActive> _all_paths_active_vtables;

    ExpressionPtrUnorderedSet _this_candidates;

    OperatorNewExprMap _master_op_new_candidates;
    OperatorNewExprMap &_op_new_candidates;

    VTVVcalls _master_vtv_vcalls;
    VTVVcalls &_vtv_vcalls;

    ReturnValues _return_values;
    MultipleReturnValues _master_ret_value_mapping;
    MultipleReturnValues &_ret_value_mapping;

    std::unordered_set<uint64_t> _master_block_cache_true;
    std::unordered_set<uint64_t> &_block_cache_true;
    std::unordered_set<uint64_t> _master_block_cache_false;
    std::unordered_set<uint64_t> &_block_cache_false;

    std::shared_ptr<State> _last_state_ptr = nullptr;
    std::shared_ptr<Block> _last_block_ptr = nullptr;


    /*!
     * \brief Adds a new vtable update to the already found ones.
     */
    void add_vtable_update(const ExpressionPtr &base,
                           uint64_t new_vtable,
                           size_t offset);


    void path_update_active_vtables(const Path &path);


    /*!
     * \brief Checks if the expression uses a .got/.idata entry and returns it.
     * \return Returns the address of the used .got/.idata entry or 0.
     */
    uint64_t get_used_table_entry(const ExpressionPtr &exp);


    void import_external_vtable_updates(const ExternalFunction *ext_func,
                                        State &state);

    void import_external_return_values(const Path &path,
                                       State &state,
                                       const FctReturnValues* ext_ret_values);

    void handle_new_operator(const Block&, State&);

public:
    using BaseAnalysis::BaseAnalysis;


    /*!
     * \brief Constructor used for a new analysis.
     *
     * This constructor is used to start an analysis of a new function.
     */
    OverwriteAnalysis(Translator &translator,
                      const Function &function,
                      const std::unordered_set<uint64_t> &new_operators,
                      const VTableFile &vtable_file,
                      const ModulePlt &module_plt,
                      const ExternalFunctions &external_funcs,
                      const GotMap &got_map,
                      const IDataMap &idata_map,
                      const FctReturnValuesFile &fct_return_values,
                      FctVTableUpdates &external_vtable_updates,
                      VCallFile &vcall_file,
                      const std::string &module_name,
                      uint64_t memory_begin,
                      uint64_t memory_end);


    /*!
     * \brief Constructor used for a sub-analysis called by the analysis itself.
     *
     * This constructor is used to start a sub-analysis. It is used whenever
     * the analysis finds a new interesting function that was called in the
     * control flow of the function that is currently analyzed. Therefore,
     * the sub-analysis has to work on the same data structures as
     * the current analysis.
     */
    OverwriteAnalysis(Translator &translator,
                      const Function &function,
                      const std::unordered_set<uint64_t> &new_operators,
                      const VTableFile &vtable_file,
                      const ModulePlt &module_plt,
                      const ExternalFunctions &external_funcs,
                      const GotMap &got_map,
                      const IDataMap &idata_map,
                      const FctReturnValuesFile &fct_return_values,
                      FctVTableUpdates &external_vtable_updates,
                      VCallFile &vcall_file,
                      const std::string &module_name,
                      uint64_t memory_begin,
                      uint64_t memory_end,
                      const State &initial_state,
                      size_t call_depth,
                      std::unordered_set<uint64_t> &functions_processed,
                      VTableUpdates &vtable_updates,
                      OperatorNewExprMap &op_new_candidates,
                      VTVVcalls &vtv_vcalls,
                      MultipleReturnValues &ret_value_mapping,
                      std::unordered_set<uint64_t> &block_cache_true,
                      std::unordered_set<uint64_t> &block_cache_false);


    /*!
     * \brief Handles the basic block if it ends with a call.
     *
     * Function checks if the call is interesting and follows it depending
     * on the findings. If the call was done to a new operator, the return
     * value is added as a this-ptr candidate.
     */
    void handle_call(const Path &path, const Block&, State&);


    /*!
     * \brief Handles all jumps at the end of a basic block.
     *
     * Function handles all kind of jumps and starts a new sub-analysis
     * if the jump target is a function that was not processed yet.
     */
    void handle_jump(const Path &path,
                     const Block&,
                     State&,
                     uint64_t target_address,
                     const std::string &target_module,
                     bool external_module=false);


    void handle_indirect_call(const Path &path,
                              const Block&,
                              State&);


    /*!
     * \brief Function is called by the base analysis before the function to
     * analyze is traversed.
     *
     * Not used.
     */
    virtual void pre_traversal();


    /*!
     * \brief Function is called by the base analysis after the function to
     * analyze was traversed.
     *
     * Not used.
     */
    virtual void post_traversal();


    /*!
     * \brief Function is called by the base analysis for each basic block
     * that is visited during the traversal of the function to analyze.
     *
     * Main function of the overwrite analysis. Checks if a vtable was written
     * into a this-ptr candidate and handles all jumps.
     */
    virtual bool in_traversal(const Path&path, const Block&, State&);


    /*!
     * \brief Function that is used by the base analysis to determine if a
     * basic block is interesting enough to be traversed
     * (used for path finding).
     *
     * Overwrite analysis considers all basic blocks as interesting that
     * contain an indirect call or a vtable as a constant.
     */
    virtual bool block_predicate(const Block &block);


    /*!
     * \brief Function is called by the base analysis when a path to
     * analyze was traversed.
     *
     * Overwrite analysis stores return values and active overwrites
     * of each traversed path.
     */
    virtual void path_traversed(const Path &path);


    /*!
     * \brief Adds an expression to the this-ptr candidates.
     */
    void add_this_candidate(const ExpressionPtr &expression);


    /*!
     * \brief Adds a vtable update.
     */
    void add_vtable_update(const VTableUpdate &vtable_update);


    /*!
     * \brief Returns the found vtable overwrites.
     * \return Returns the found vtable overwrites.
     */
    VTableUpdates& get_vtable_updates() {
        return _vtable_updates;
    }


    /*!
     * \brief Returns the found virtual callsites.
     * \return Returns the found virtual callsites.
     */
    const VCalls& get_vcalls() const;


    /*!
     * \brief Returns the found operator new calls.
     * \return Returns the found operator new calls.
     */
    const OperatorNewExprMap& get_operator_new_calls() const {
        return _op_new_candidates;
    }


    /*!
     * \brief Returns the found vtv vcalls.
     * \return Returns the found vtv vcalls.
     */
    const VTVVcalls& get_vtv_vcalls() const {
        return _vtv_vcalls;
    }


    void add_active_vtable(const ExpressionPtr &vtbl_ptr_loc,
                           uint64_t vtable_addr,
                           const Path &path,
                           bool from_caller,
                           bool from_callee);


    void add_active_vtable(const ExpressionPtr &vtbl_ptr_loc,
                           const Path &path,
                           bool from_caller,
                           bool from_callee,
                           uint32_t index);


    void add_active_vtable(const VTableActive &active_vtable);

    /*!
     * \brief Returns the active vtables on all traversed paths through
     * this function.
     * \return Returns the active vtables on all traversed paths through
     * this function.
     */
    const std::vector<VTableActive>& get_active_vtables() const;


    const std::vector<ReturnValue>& get_return_values() const;

};

#endif //RANGR_OVERWRITE_ANALYSIS_H
