#ifndef BASE_ANALYSIS_H
#define BASE_ANALYSIS_H

#include "function.h"
#include "block.h"
#include "memory.h"

#include <map>
#include <set>
#include <vector>

typedef std::map<Path, State> PathStates;
typedef std::vector<State> States;

/*!
 * \brief (Abstract) base class for analyses run on a function.
 */
class BaseAnalysis {
protected:
    const Function &_function;

    const FileFormatType _file_format;

    PathStates _states;
    PathStates _side_effects;

    State _initial_state;
    States _semantics;

    /*! Set by `BaseAnalysis::on_traversal` if the current block's
     * terminator is a `call`; `nullptr` otherwise. If set, contains the
     * symbol corresponding to the (unique) formatted return value.
     */
    std::shared_ptr<Symbolic> _current_return_value;

public:
    BaseAnalysis(const Function &function,
                 FileFormatType file_format);
    BaseAnalysis(const Function &function,
                 const State &initial_state,
                 FileFormatType file_format);

    BaseAnalysis(const BaseAnalysis&) = delete;
    void operator=(const BaseAnalysis&) = delete;

    bool obtain();

protected:
    /*! Pure virtual (implemented by sub-class). This function is called before
     * the function is actually traversed and may be used for initialization
     * work.
     */
    virtual void pre_traversal() = 0;

    /*! Pure virtual (implemented by sub-class). This function is called after
     * the traversal and may be used for post-processing of the collected
     * results. */
    virtual void post_traversal() = 0;

    /*! Pure virtual (implemented by sub-class). This function is called on each
     * basic block on the given path. Accumulates the analysis results.
     */
    virtual bool in_traversal(const Path&, const Block&, State&) = 0;

    /*! Pure virtual (implemented by sub-class). This function is called on each
     * basic block during path construction (i.e., if the lightweight path
     * policy is active). Determines whether the given block is "interesting"
     * and should be traversed by the generated paths.
     */
    virtual bool block_predicate(const Block&) = 0;

    /*! Pure virtual (implemented by sub-class). This function is called after
     * a single path has been fully traversed.
     */
    virtual void path_traversed(const Path&) = 0;

private:
    bool on_traversal(const Path &path, const Block &block);
};

#endif // BASE_ANALYSIS_H
