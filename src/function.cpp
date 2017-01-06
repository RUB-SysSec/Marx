
#include "function.h"
#include "path_builder.h"

#include <map>
#include <set>
#include <deque>
#include <sstream>
#include <cstddef>
#include <cassert>
#include <iterator>
#include <algorithm>

using namespace std;

typedef set<uintptr_t> SeenBlocks;
typedef map<Path, SeenBlocks> PathBlocks;

/*!
 * \brief Creates a new instance of the class, explicitly setting its entry
 * address.
 * \param entry The (virtual) address where the function starts originally.
 * \param branch_threshold The number of branches inside a function that
 * trigger a switch to a more lightweight traversal method. Defaults to at
 * least 15.
 */
Function::Function(uintptr_t entry, uint8_t branch_threshold)
    : _entry(entry), _branch_threshold(branch_threshold) {
}

/*!
 * \brief Initial policy that checks feasibility of traversing all paths.
 *
 * This (initial) policy simply counts the number of indirect branches which
 * give a rough estimate of the number of paths through the function.
 *
 * \return `true`, if the function contains fewer than 15 branches; `false`
 * otherwise.
 */
bool Function::can_be_fully_traversed() const {
    auto branches = 0;
    for(const auto &kv : _function_blocks) {
        if(kv.second->get_terminator().type == TerminatorJcc) {
            branches++;
        }
    }

    return branches < _branch_threshold;
}

/*!
 * \brief Traverses all paths through the function.
 *
 * Traverses all possible paths through the function and calls the supplied
 * callback on each encountered basic block. If it is infeasible to traverse
 * all possible paths (as determined by `can_be_fully_traversed`), logic
 * switches to a lightweight path generation algorithm. For this to work
 * properly, `block_predicate` has to be set.
 *
 * The traversal callback is passed several parameters:
 *
 * 1. a user-defined parameter (which can be used, e.g., to pass an additional
 * structure with data associated with the traversal, like a this pointer),
 * 2. the path describing the position of the currently visited basic block,
 * 3. the currently visited basic block itself, a `Block` reference.
 *
 * \param callback The function that is to be called on each basic block visit.
 * \param block_predicate A callback which decides whether a basic block is
 * deemed "interesting" for the current analysis and should be visited during
 * the traversal.
 * \param user_defined A user-defined parameter that is passed to the callback.
 * \return Always `true`.
 *
 * \todo Decide if the return type still makes sense in the current setup.
 */
bool Function::traverse(const TraversalCallback &block_callback,
                        const BlockPredicate &block_predicate,
                        const PathCallback &path_callback,
                        void *user_defined)
    const {
    if(can_be_fully_traversed()) {
        throw runtime_error("Path callbacks are not yet implemented for full"
                            " traversals.");
        return traverser(block_callback, user_defined);
    }

    if(!block_predicate) {
        throw runtime_error("Cannot switch to lightweight policy without a "
                            "valid block predicate.");
    }

    PathBuilder builder(*this, user_defined);
    const auto paths = builder.build_paths(block_predicate);

    // FIXME: This duplicates code from below.
    for(const auto &path : paths) {

        Path current_path;
        const Terminator *previous_terminator = nullptr;

        for(const auto &block : path) {
            const auto &needle = _function_blocks.find(block);
            if(needle == _function_blocks.cend()) {
                break;
            }

            if(previous_terminator) {
                bool annotation = false;

                const auto &terminator = *previous_terminator;
                switch(terminator.type) {
                case TerminatorJump:
                    annotation = true;
                    break;

                case TerminatorJcc: {
                    const auto current = needle->second->get_address();
                    if(terminator.target == current) {
                        annotation = false;
                        break;
                    }

                    assert(terminator.fall_through == current &&
                           "Cannot reconstruct annotation.");
                    annotation = true;
                }

                case TerminatorFallthrough:
                case TerminatorCallUnresolved:
                case TerminatorCall:
                    annotation = true;
                    break;

                default:
                    throw runtime_error("Lightweight policy: This should not"
                                        " happen.");
                    break;
                }

                current_path.push_back(annotation);
            }

            previous_terminator = &needle->second->get_terminator();
            if(!block_callback(user_defined, current_path, *needle->second)) {
                /* The callback has decided not to follow this path any
                 * further. */
                break;
            }
        }

        if(path_callback) {
            path_callback(user_defined, current_path);
        }
    }

    return true;
}

bool Function::traverser(const TraversalCallback &callback,
                         void *user_defined) const {

    deque<pair<uintptr_t, Path>> work_list;

    PathBlocks path_seen_blocks;
    work_list.push_back(make_pair(_entry, Path()));

    while(!work_list.empty()) {
        const auto pair = work_list.back();
        work_list.pop_back();

        uintptr_t current_address = pair.first;
        const Path &path = pair.second;

        SeenBlocks &seen_blocks = path_seen_blocks[path];
        if(seen_blocks.find(current_address) != seen_blocks.cend()) {
            continue;
        }

        const auto &needle = _function_blocks.find(current_address);
        if(needle == _function_blocks.cend()) {
            /* We cannot find a block with the given address that lies within
             * the current function. This is most likely the case due to the
             * invocation of a non-returning call. We must not follow these
             * anyway. */
            continue;
        }

        seen_blocks.insert(current_address);
        if(!callback(user_defined, path, *needle->second)) {
            /* The callback has decided not to follow this path any further. */
            continue;
        }

        // The current path may be extended by a true or false annotation.
        Path path_false = path, path_true = path;

        path_false.push_back(false);
        path_true.push_back(true);

        const Terminator &terminator = needle->second->get_terminator();

        switch(terminator.type) {
        case TerminatorJump:
            work_list.push_back(make_pair(terminator.target, path_true));
            path_seen_blocks[path_true] = seen_blocks;
            break;

        case TerminatorJcc:
            work_list.push_back(make_pair(terminator.target, path_false));
            path_seen_blocks[path_false] = seen_blocks;

        case TerminatorFallthrough:
        case TerminatorCallUnresolved:
        case TerminatorCall:
            work_list.push_back(make_pair(terminator.fall_through, path_true));
            path_seen_blocks[path_true] = seen_blocks;
            break;

        default:
            break;
        }
    }

    return true;
}

void Function::add_block(uintptr_t address, IRSB *block,
                         const Terminator &terminator) {
    _function_blocks[address] = make_shared<Block>(address, block, terminator);
}
