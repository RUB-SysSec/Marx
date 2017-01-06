
#include "path_builder.h"

#include <array>
#include <queue>
#include <algorithm>

using namespace std;

/*!
 * \brief Creates a new instance of the class.
 * \param function The function for which paths should be constructed.
 * \param user_defined A user-defined parameter that is passed to the block
 * predicate. Defaults to `nullptr`.
 * \param node_threshold The number of interesting nodes a function has to
 * exceed such that simpler paths are generated. Defaults to 20.
 * \see `PathBuilder::build_paths`
 */
PathBuilder::PathBuilder(const Function &function, void *user_defined,
                         uint8_t node_threshold)
    : _function(function), _user_defined(user_defined),
      _node_threshold(node_threshold) {
}

using Successors = array<uintptr_t, 2>;

Successors get_successors(const Block &block) {
    Successors result = { 0, 0 };

    const Terminator &terminator = block.get_terminator();
    switch(terminator.type) {
    case TerminatorJump:
        result[0] = terminator.target;
        break;

    case TerminatorJcc:
        result[0] = terminator.target;

    case TerminatorFallthrough:
    case TerminatorCallUnresolved:
    case TerminatorCall:
        result[1] = terminator.fall_through;
        break;

    default:
        break;
    }

    return result;
}

bool is_exit_block(void*, const Block &block) {
    const auto &terminator = block.get_terminator();
    return terminator.is_tail || terminator.type == TerminatorReturn;
}

template<typename T>
bool contains_duplicates(const deque<T> &container) {
    set<T> witness(container.cbegin(), container.cend());
    return witness.size() != container.size();
}

deque<ConcretePath> paths(const PathsByNode &p) {
    deque<ConcretePath> collect;
    for(const auto &kv : p) {
        collect.push_back(kv.second);
    }

    return collect;
}

//!
//! \brief Constructs the paths.
//! \param predicate A predicate which decides whether the given basic block is
//! deemed "interesting" and should be visited by the generated paths.
//! \return A set of distinct concrete paths through the function which try to
//! visit as much of the interesting nodes as possible.
//!
//! The algorithms determines sub-paths from the root node to an interesting
//! block, from any interesting block to another and from an interesting block
//! to a return block. Then, it tries to combine them such that the number of
//! interesting blocks visited by the constructed path is maximized.
//!
//! If the number of interesting basic blocks exceeds `_node_threshold`, a
//! simpler algorithm is used. The algorithm falls back to merely yielding
//! paths that visit _one_ interesting block (being optimistic about other
//! interesting blocks lying on that very same path).
//!
set<ConcretePath> PathBuilder::build_paths(BlockPredicate predicate) const {
    const auto blocks = _function.get_blocks();
    const auto root = _function.get_entry();

    // Get paths from root to interesting nodes.
    auto root_to_interesting = breadth_first(blocks, root, predicate);

    // Get paths from interesting node to exit.
    map<uintptr_t, deque<ConcretePath>> interesting_to_exit;

    for(const auto &kv : root_to_interesting) {
        auto to_exit = breadth_first(blocks, kv.first, &is_exit_block);
        interesting_to_exit[kv.first] = paths(to_exit);
    }

    bool safety_threshold = root_to_interesting.size() > _node_threshold;

    /* Get paths from one interesting node to another (distinct) node; done
     * only if the safe threshold is not exceeded.
     */
    map<uintptr_t, PathsByNode> interesting_to_interesting;
    if(!safety_threshold) {
        for(const auto &kv : root_to_interesting) {
            const auto source = kv.first;

            for(const auto &kv_dst : root_to_interesting) {
                const auto destination = kv_dst.first;
                if(source == destination) {
                    continue;
                }

                auto to_other = breadth_first(blocks, source,
                    [&](void*, const Block &block) -> bool {
                        return block.get_address() == destination;
                }, true);

                interesting_to_interesting[source] = to_other;
            }
        }
    }

    // Stitch together possible paths.
    set<ConcretePath> paths;

    /* TODO: Constraint the number of interesting nodes to chain on a
     * single path. */
    struct Entry {
        ConcretePath path;
        set<uintptr_t> visited;
    };

    queue<Entry> work;
    for(const auto &kv : root_to_interesting) {
        Entry entry;
        entry.path = kv.second;
        entry.visited.insert(kv.first);

        work.push(entry);
    }

    while(!work.empty()) {
        auto current = work.front();
        work.pop();

        auto tails = interesting_to_exit[current.path.back()];
        for(const auto &tail : tails) {
            deque<uintptr_t> head = current.path;
            head.pop_back();

            for(const auto &t : tail) {
                head.push_back(t);
            }

            paths.insert(head);
        }

        /* Safety threshold: Only visit one interesting node and hope that
         * the others happen to lie on the same path.
         */
        if(safety_threshold) {
            continue;
        }

        for(const auto &kv : interesting_to_interesting[current.path.back()]) {
            const auto &next_node = kv.first;

            auto needle = current.visited.find(next_node);
            if(needle != current.visited.cend()) {
                continue;
            }

            Entry next;
            const auto &path_to_next = kv.second;

            next.path = current.path;
            next.path.pop_back();

            for(const auto &p : path_to_next) {
                next.path.push_back(p);
            }

            next.visited = current.visited;
            next.visited.insert(next_node);

            work.push(next);
        }
    }

    /* If there are no interesting blocks, collect all paths from the root
     * node to any exit block.
     */
    if(paths.empty()) {
        auto root_to_exit = breadth_first(blocks, root, &is_exit_block);
        for(const auto &kv : root_to_exit) {
            if(!contains_duplicates(kv.second)) {
                paths.insert(kv.second);
            }
        }
    }

    return paths;
}

struct Node {
    uintptr_t address;
    shared_ptr<Block> block;
    uint16_t distance;

    Node *parent;
};

PathsByNode PathBuilder::breadth_first(const BlockMap &blocks,
                                       uintptr_t root,
                                       BlockPredicate predicate,
                                       bool terminate_on_match) const {
    map<uintptr_t, Node> nodes;
    PathsByNode result;

    for(const auto &kv : blocks) {
        Node current;
        current.address  = kv.first;
        current.block    = kv.second;
        current.distance = static_cast<uint16_t>(-1);
        current.parent   = nullptr;

        nodes[kv.first] = current;
    }

    nodes[root].distance = 0;
    queue<Node*> q;

    // Explicitly check if the root node is interesting as well.
    if(predicate(_user_defined, *nodes[root].block)) {
        auto &path = result[root];
        path.push_front(root);
    }

    q.push(&nodes[root]);
    while(!q.empty()) {
        Node &current = *q.front();
        q.pop();

        const auto &adjacent = get_successors(*current.block);
        for(const auto &neighbor : adjacent) {
            if(!neighbor) {
                continue;
            }

            auto &n = nodes[neighbor];
            if(n.distance == static_cast<uint16_t>(-1)) {
                n.distance = current.distance + 1;
                n.parent = &current;

                if(predicate(_user_defined, *n.block)) {
                    auto &path = result[n.address];
                    path.push_front(n.address);

                    auto *parent = n.parent;
                    while(parent) {
                        path.push_front(parent->address);
                        parent = parent->parent;
                    }

                    if(terminate_on_match) {
                        return result;
                    }
                }

                q.push(&n);
            }
        }
    }

    return result;
}
