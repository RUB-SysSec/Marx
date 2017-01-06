
#include "base_analysis.h"
#include "amd64.h"

#include <memory>
#include <sstream>
#include <iostream>
#include <iterator>
#include <algorithm>

using namespace std;

/*!
 * \brief Constructs a new analysis on function `function`.
 *
 * The state at function entry is initialized to default values.
 *
 * \param function The function on which the analysis is run.
 */
BaseAnalysis::BaseAnalysis(const Function &function,
                           FileFormatType file_format)
    : _function(function),
      _file_format(file_format),
      _current_return_value(nullptr) {

    _initial_state.set_initial_state();
}

/*!
 * \brief Constructs a new analysis on function `function`, setting the state
 * at function entry to the specified state `initial_state`.
 *
 * \param function The function on which the analysis is run.
 * \param initial_state The state that should be set on function entry.
 */
BaseAnalysis::BaseAnalysis(const Function &function,
                           const State &initial_state,
                           FileFormatType file_format)
    : BaseAnalysis(function, file_format) {
    _initial_state = initial_state;
}

/*!
 * \brief Runs the analysis.
 *
 * The traversal callback `BaseAnalysis::on_traversal` also handles
 * updates on the state across function calls. Currently, System V is assumed
 * per default.
 *
 * \see `BaseAnalysis::on_traversal`
 *
 * \return Always returns `true`.
 * \todo Better use for return value? Also generalize calling convention.
 */
bool BaseAnalysis::obtain() {
    auto block_callback = [&](void *self_pointer, const Path &path,
                              const Block &block) -> bool {

        BaseAnalysis &self = *reinterpret_cast<BaseAnalysis*>(self_pointer);
        return self.on_traversal(path, block);
    };

    auto block_predicate = [&](void *self_pointer, const Block &block) -> bool {
        BaseAnalysis &self = *reinterpret_cast<BaseAnalysis*>(self_pointer);
        return self.block_predicate(block);
    };

    auto path_callback = [&](void *self_pointer, const Path &path) {
        BaseAnalysis &self = *reinterpret_cast<BaseAnalysis*>(self_pointer);
        self.path_traversed(path);
    };

    pre_traversal();
    auto result = _function.traverse(block_callback, block_predicate,
                                     path_callback, this);
    post_traversal();

    _states.clear();
    return result;
}

bool BaseAnalysis::on_traversal(const Path &path, const Block &block) {
    State new_state;

    // Get hold of the previous state set on the path.
    if(path.empty()) {
        new_state = _initial_state;
    } else {
        Path preceding_path(path.cbegin(), path.cend() - 1);
        const auto &preceding_state = _states[preceding_path];
        new_state = preceding_state;

        // Handle side-effects as caused by the calling convention used.
        const auto &side_effect = _side_effects.find(preceding_path);
        if(side_effect != _side_effects.cend()) {
            new_state.purge_scratch_registers(_file_format);
            new_state.merge(side_effect->second);
        }
    }

    bool is_call = false;
    switch(block.get_terminator().type) {
    case TerminatorCall:
    case TerminatorCallUnresolved: {

        auto formatted = State::format_return_value(block.get_address());
        _current_return_value = make_shared<Symbolic>(formatted);

        is_call = true;
        break;
    }

    default:
        _current_return_value = nullptr;
        break;
    }

    // Actually compute the new semantics.
    block.retrieve_semantics(new_state);
    bool continue_path = in_traversal(path, block, new_state);

    // Handle calls specially as they introduce side-effects.
    if(is_call) {
        State::iterator needle;
        if(new_state.find(register_rip, needle)) {
            // Construct an empty state which will contain side-effects only.
            State side_effects(false);

            side_effects.update(register_rax, _current_return_value);
            _side_effects[path] = side_effects;
        }
    }

    // Keep the state when hitting either a return instruction or a tail jump.
    const auto &terminator = block.get_terminator();

    if(terminator.is_tail || terminator.type == TerminatorReturn) {
        new_state.erase(register_rip);
        new_state.purge_scratch_registers(_file_format);

        _semantics.push_back(new_state);
    } else {
        _states[path] = new_state;
    }

    return continue_path;
}
