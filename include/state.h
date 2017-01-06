#ifndef STATE_H
#define STATE_H

#include "expression.h"
#include "amd64.h"
#include "memory.h"

#include <map>
#include <set>
#include <vector>
#include <memory>
#include <ostream>
#include <unordered_map>
#include <unordered_set>

#define arg_out

/*!
 * \brief Type that specifies how to `std::shared_ptr<Expression>` instances
 * shall be compared.
 *
 * As `State` uses a STL map to track the state of expressions, we want to
 * compare the stored objects by value in order to provide sane updates.
 */
struct ExpressionPtrComparison {
    bool operator()(const ExpressionPtr &lhs, const ExpressionPtr &rhs) const {
        return *lhs == *rhs;
    }
};

using InternalState = std::unordered_map<ExpressionPtr, ExpressionPtr,
        std::hash<ExpressionPtr>, ExpressionPtrComparison>;

using InitialValues = std::map<unsigned int, std::shared_ptr<Symbolic>>;
using Expressions = std::vector<std::pair<ExpressionPtr, ExpressionPtr>>;

using kill_results = std::unordered_set<ExpressionPtr, std::hash<ExpressionPtr>,
        ExpressionPtrComparison>;

/*!
 * \brief Class that represents a CPU state.
 *
 * Effectively, this class represents the side effects of a computation by
 * keeping track of the various entities modified during a symbolic run. It
 * basically wraps around a STL map and provides some convience functions for
 * modifying the state.
 *
 * Keys in the state are destinations (such as temporaries, registers and memory
 * indirections), whereas values are the (abstract) values that are written to
 * said destination. An assignment of the form `key -> value` is commonly called
 * a _binding_ (binding the value to the key expression).
 *
 * \see `InternalState`
 */
class State {
private:
    static InitialValues _initial_values;
    InternalState _state;

    std::shared_ptr<Unknown> _unknown;

public:
    using iterator = InternalState::iterator;
    using const_iterator = InternalState::const_iterator;

    State(bool initialize=true);
    State(const State&) = default;

    /*!
     * \brief Static function that returns the initial register assignment.
     * \return Returns a (read-only) map, with keys being register offsets and
     * values the corresponding `ExpressionPtr`s.
     *
     * \see `AMD64_REGISTERS`
     */
    static const InitialValues &initial_values() {
        return _initial_values;
    }

    void set_initial_state();
    void purge_scratch_registers(FileFormatType file_format);

    void merge(const State &other);
    void optimize(bool do_purge_unchanged=false);

    const Expressions get_memory_accesses() const;

    friend std::ostream &operator<<(std::ostream &stream, const State &state);
    static const std::string format_return_value(uintptr_t address);

    InternalState::iterator erase(const InternalState::iterator &iterator);
    size_t erase(const InternalState::key_type &key);

    bool find(const InternalState::key_type &key,
              arg_out InternalState::iterator &iterator);
    bool find(const InternalState::key_type &key,
              arg_out InternalState::const_iterator &iterator) const;

    void update(const InternalState::key_type &key,
                const InternalState::mapped_type &value);

private:
    static const std::string format_initial_value(size_t offset);

    bool optimizer(bool do_purge_unchanged=false);
    void optimize_entries();

    bool propagate();

    bool purge_unchanged();
    bool purge_uninteresting();

    kill_results kill_helper(const ExpressionPtr &key,
                             const ExpressionPtr &value);
    void kill(const ExpressionPtr &key, const ExpressionPtr &value);
};

#endif // STATE_H
