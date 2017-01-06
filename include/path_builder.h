#ifndef PATH_BUILDER_H
#define PATH_BUILDER_H

#include <map>
#include <set>
#include <deque>
#include <vector>
#include <cstdint>
#include <functional>

#include "block.h"
#include "function.h"

//! A concrete path that contains the full addresses of basic blocks to visit.
using ConcretePath = std::deque<uintptr_t>;

//! A map relating a node to a concrete path.
using PathsByNode = std::map<uintptr_t, ConcretePath>;

const uint8_t NODE_THRESHOLD = 20;

//!
//! \brief Class calculating viable paths through a given `Function` (the
//! "lightweight" policy used as a fallback in `Function::traverse`).
//!
class PathBuilder {
private:
    const Function &_function;
    void *_user_defined;
    const uint8_t _node_threshold;

public:
    PathBuilder(const Function &function, void *user_defined=nullptr,
                uint8_t node_threshold=NODE_THRESHOLD);
    std::set<ConcretePath> build_paths(BlockPredicate predicate) const;

private:
    PathsByNode breadth_first(const BlockMap &blocks, uintptr_t root,
                              BlockPredicate predicate,
                              bool terminate_on_match=false) const;
};

#endif // PATH_BUILDER_H
