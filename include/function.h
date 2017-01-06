#ifndef FUNCTION_H
#define FUNCTION_H

#include "block.h"
#include "expression.h"
#include "block_semantics.h"

#include <map>
#include <set>
#include <vector>
#include <cstddef>
#include <functional>

extern "C" {
#include <valgrind/libvex.h>
}

/*!
 * \brief A path describing how we reached a basic block in the function.
 *
 * A path is merely a vector of `bool`s. Each entry denotes how control flow
 * changed at each terminator/basic block, starting at the beginning of the
 * traversal (most commonly the function's entry point). Following a
 * fall-through or an unconditional jumps is recorded using `true`, whereas
 * the target of a conditional jump is recorded as `false`.
 */
typedef std::vector<bool> Path;
typedef std::map<uintptr_t, std::shared_ptr<Block>> BlockMap;

/*!
 * \brief A function called on each visited basic block in a traversal.
 *
 * \see `Function::traverse`
 */
typedef std::function<bool (void*, const Path&, const Block&)>
    TraversalCallback;

/*!
 * \brief A function called after a path has been fully traversed.
 *
 * \see `Function::traverse`
 */
typedef std::function<void (void*, const Path&)> PathCallback;

class Translator;
const uint8_t BRANCH_THRESHOLD = 0;

/*!
 * \brief Class representing a function translated to VEX.
 *
 * Objects of this class are to be instantiated by the `Translator` class (hence
 * the `friend` relationship).
 */
class Function {
private:
    uintptr_t _entry;
    uint8_t _branch_threshold = BRANCH_THRESHOLD;
    BlockMap _function_blocks;

public:
    Function() = default;
    Function(uintptr_t entry, uint8_t branch_threshold=BRANCH_THRESHOLD);

    /*!
     * \brief Returns the function's entry address.
     * \return Returns the first virtual address in the function.
     */
    uintptr_t get_entry() const {
        return _entry;
    }

    bool can_be_fully_traversed() const;

    // FIXME: Cache this.
    /*!
     * \brief Returns the addresses of all known blocks.
     * \return Returns a vector of addresses.
     */
    std::vector<uintptr_t> get_block_addresses() const {
        std::vector<uintptr_t> result;
        for(const auto &kv : _function_blocks) {
            result.push_back(kv.first);
        }

        return result;
    }

    // FIXME: Cache this.
    /*!
     * \brief Returns the addresses of block's returning from the function
     * (i.e., those with a terminator of type `TerminatorReturn`).
     * \return Returns a vector of addresses.
     */
    std::vector<uintptr_t> get_return_block_addresses() const {
        std::vector<uintptr_t> result;
        for(const auto &kv : _function_blocks) {
            if(kv.second->get_terminator().type == TerminatorReturn) {
                result.push_back(kv.first);
            }
        }

        return result;
    }

    /*!
     * \brief Returns all blocks.
     * \return Returns a map containing all blocks of the function (key is the
     * block's address).
     */
    const BlockMap &get_blocks() const {
        return _function_blocks;
    }

    bool traverse(const TraversalCallback &block_callback,
                  const BlockPredicate &block_predicate,
                  const PathCallback &path_callback,
                  void *user_defined=nullptr) const;

private:
    bool traverser(const TraversalCallback &callback,
                   void *user_defined=nullptr) const;

    void add_block(uintptr_t address, IRSB *block,
                   const Terminator &terminator);

    friend class Translator;
};

#endif // FUNCTION_H
