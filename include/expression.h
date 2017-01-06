#ifndef EXPRESSION_H
#define EXPRESSION_H

#include <string>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <memory>
#include <iostream>

#include "amd64_registers.h"

/*!
 * \brief Enumerates all possible `Expression` types.
 *
 * The types are sorted by precedence in order to define an ordering on them.
 * That ordering is used to sanitize `Expression` layout later on.
 *
 * \see Operation::optimizer
 */
enum ExpressionType {
    //! The type of the expression is unknown.
    ExpressionUnknown = 0,

    // Sorted by precedence, low to high (as used in Expression::operator<).
    //! A constant (64-bit) value.
    ExpressionConstant,

    //! A symbolic value, described using a `std::string`.
    ExpressionSymbolic,

    /*!
     * A temporary register, described using an integer. Mapped from VEX
     * temporaries.
     */
    ExpressionTemporary,

    //! A register, described by a positive offset. \see `AMD64_REGISTERS`
    ExpressionRegister,

    //! A memory indirection used to denote (full qword sized) memory access.
    ExpressionIndirection,

    //! A binary operation combining two `Expression`s. \see `OperationType`
    ExpressionOperation,

    ExpressionCount
};

/*!
 * \brief Enumerates the different (binary) operations supported by `Operation`.
 */
enum OperationType {
    OperationAdd = 0,
    OperationSub,

    OperationCount
};

//! \brief Maps an `OperationType` to a printable string.
static const char *OPERATION_MAPPING[OperationCount] = {
    "+", "-"
};

class Expression;

//! A shared pointer used to hold an `Expression`.
typedef std::shared_ptr<Expression> ExpressionPtr;

/*!
 * \brief (Abstract) base class for symbolic expressions.
 *
 * Provides functions common to all expressions such as formatting, equality,
 * ordering, containment and optimization. For now, most `Expression`s are
 * stored in `shared_ptr`s as to avoid object slicing when used in, e.g., STL
 * containers. \see `ExpressionPtr`
 *
 * \todo Move from our short-term _object slicing_ solution using
 * `std::shared_ptr<Expression>` to something more efficient. Maybe
 * `boost::variant`?
 */
class Expression {
protected:
    bool _changed = true;
    ExpressionType _type;

public:
    virtual ~Expression() = default;

    /*!
     * \brief Constructor for `Expression`.
     * \param type The type of the expression. Defaults to _unknown_.
     */
    Expression(ExpressionType type=ExpressionUnknown)
        : _type(type) {
    }

    /*!
     * \brief Returns the type of the expression.
     * \return One of the options in `ExpressionType`.
     */
    ExpressionType type() const {
        return _type;
    }

    /*!
     * \brief Prints the expression to the given output stream.
     *
     * Sub-classes can define this behaviour by overriding `Expression::print`.
     *
     * \param stream The output stream to which the expression is printed.
     * \param self The `Expression` itself.
     * \return The (modified) output stream `steam`.
     */
    friend std::ostream &operator<<(std::ostream &stream,
                                    const Expression &self) {
        return self.print(stream);
    }

    /*!
     * \brief Decides whether two `Expression`s are equal.
     *
     * Sub-classes can define this behaviour by overriding `Expression::equals`.
     * The function defines equality for expressions of the same `type()`.
     *
     * Two `Expression`s are equal if one of this applies:
     * 1. both instances point to the same memory location,
     * 2. both expressions have the same type and `equals` returns true, or
     * 3. equality as specified for `Operation`s holds (`(A + 0) == A` is
     * `true`).
     *
     * \param other The other `Expression` to which this one is compared to.
     * \return `true`, if equal; `false` otherwise.
     *
     * \todo Specify type-specific equality rules in a sane manner.
     */
    bool operator==(const Expression &other) const {
        bool equal = false;
        equal = equal || (this == &other);
        equal = equal || (_type == other._type && equals(other));

        // TODO: Operation-specific. Rather replace these in the state.
        if(_type == ExpressionOperation) {
            equal = equal || operation_equal(other);
        } else if(other._type == ExpressionOperation) {
            equal = equal || other.operation_equal(*this);
        }

        return equal;
    }

    /*!
     * \brief Decides whether two `Expression`s are different.
     * \see `Expression::operator==`
     * \param other The other `Expression` to compare to.
     * \return `true`, if different; `false` otherwise.
     */
    bool operator!=(const Expression &other) const {
        return !(*this == other);
    }

    /*!
     * \brief Decides whether the current `Expression` is lower than the
     * `other`.
     *
     * Sub-classes can define this behaviour by overriding
     * `Expression::lower_than`. The function defines the ordering for
     * expressions of the same `type()`.
     *
     * The ordering for equal types is decided based on `lower_than`. If the
     * types are not equal, ordering is based on precedence defined in
     * `ExpressionType`.
     *
     * The ordering is used to make comparison of two expressions possible,
     * since `my_symbol + 5 == 5 + my_symbol` shall yield `true`.
     *
     * \see `ExpressionType`
     *
     * \param other The other `Expression` to which this one is compared to.
     * \return `true`, if this is lower than `other`; `false` otherwise.
     */
    bool operator<(const Expression &other) const {
        if(_type == other._type) {
            return lower_than(other);
        }

        return _type < other._type;
    }

    /*!
     * \brief Optimizes an expression, if possible.
     */
    virtual void optimize() = 0;

    /*!
     * \brief Decides whether this expression contains the given expression.
     * \param expression The expression that is searched.
     * \param depth For nested expressions, stop the search after `depth`
     * levels. Defaults to -1 in the base class (i.e., searches the full
     * expression tree).
     * \return `true`, if it contains the expression; `false`, otherwise.
     */
    virtual bool contains(const Expression &expression, size_t depth=-1) = 0;

    /*!
     * \brief Replaces all occurrences of expression `key` with `value`.
     * \param key The expression which is targeted by expression propagation.
     * \param value The expression that is propagated.
     * \return `true`, if anything has been propagated; `false`, otherwise.
     */
    virtual bool propagate(const ExpressionPtr &key,
                           const ExpressionPtr &value) = 0;

    virtual size_t hash() const = 0;
    virtual bool has_changed() = 0;

    virtual ExpressionPtr clone() const = 0;


protected:
    bool operation_equal(const Expression &other) const;

    virtual bool equals(const Expression&) const = 0;
    virtual bool lower_than(const Expression&) const = 0;

    virtual std::ostream &print(std::ostream&) const = 0;
};

namespace std {
    static void hash_combine(size_t &hash, const size_t &other) {
        hash ^= other + 0x9e3779b9 + (other << 6) + (other >> 2);
    }

    /*!
     * \brief Type that specifies how `shared_ptr<Expression>` is hashed.
     * \todo This buckets by type. If necessary, improve hashing results by
     * providing specialized hash methods for sub-classes.
     */
    template<> struct hash<ExpressionPtr> {
        size_t operator()(const ExpressionPtr &e) const {
            return e->hash();
        }
    };
}

/*!
 * \brief Class depicting an `Expression` whose value is not known.
 */
class Unknown : public Expression {
public:
    Unknown(const Unknown&) = default;
    Unknown(ExpressionType type=ExpressionUnknown)
        : Expression(type) {
    }

    virtual void optimize() {
        _changed = false;
    }

    virtual bool contains(const Expression &other, size_t=0) {
        return *this == other;
    }

    virtual bool propagate(const ExpressionPtr&, const ExpressionPtr&) {
        return false;
    }

    virtual size_t hash() const {
        return _type;
    }

    virtual ExpressionPtr clone() const {
        auto result = std::make_shared<Unknown>();
        result->_changed = _changed;

        return result;
    }

private:
    virtual bool has_changed() {
        return _changed;
    }

    virtual std::ostream &print(std::ostream &stream) const {
        return stream << "<?>";
    }

    virtual bool equals(const Expression&) const {
        return true;
    }

    virtual bool lower_than(const Expression&) const {
        return true;
    }
};

/*!
 * \brief `Expression` sub-class depicting a symbolic value.
 *
 * Symbols are common strings.
 */
class Symbolic : public Expression {
private:
    std::string _name;

public:
    Symbolic(const std::string &name)
        : Expression(ExpressionSymbolic), _name(name) {
    }

    /*!
     * \brief Returns the name of the symbolic value.
     * \return A read-only string reference.
     */
    const std::string &name() const {
        return _name;
    }

    virtual void optimize() {
        _changed = false;
    }

    virtual bool contains(const Expression &other, size_t=0) {
        return *this == other;
    }

    virtual bool propagate(const ExpressionPtr&, const ExpressionPtr&) {
        return false;
    }

    virtual size_t hash() const {
        size_t h = _type;
        std::hash_combine(h, std::hash<std::string>()(_name));
        return h;
    }

    virtual ExpressionPtr clone() const {
        auto result = std::make_shared<Symbolic>(_name);
        result->_changed = _changed;

        return result;
    }

private:
    virtual bool has_changed() {
        return _changed;
    }

    virtual std::ostream &print(std::ostream &stream) const {
        return stream << _name;
    }

    virtual bool equals(const Expression &other) const {
        const auto &o = static_cast<const Symbolic&>(other);
        return _name == o._name;
    }

    virtual bool lower_than(const Expression &other) const {
        const auto &o = static_cast<const Symbolic&>(other);
        return _name < o._name;
    }
};

/*!
 * \brief `Expression` sub-class depicting an integer-indexed temporary value.
 *
 * This class is more or less directly mapped from VEX temporaries.
 *
 * \todo We might merge these with the `Symbolic` class.
 */
class Temporary : public Expression {
private:
    uint32_t _id;

public:
    Temporary(uint32_t id)
        : Expression(ExpressionTemporary), _id(id) {
    }

    virtual void optimize() {
        _changed = false;
    }

    virtual bool contains(const Expression &other, size_t=0) {
        return *this == other;
    }

    /*!
     * \brief Returns the underlying 32-bit id.
     */
    uint32_t id() const {
        return _id;
    }

    virtual bool propagate(const ExpressionPtr&, const ExpressionPtr&) {
        return false;
    }

    virtual size_t hash() const {
        size_t h = _type;
        std::hash_combine(h, _id);
        return h;
    }

    virtual ExpressionPtr clone() const {
        auto result = std::make_shared<Temporary>(_id);
        result->_changed = _changed;

        return result;
    }

private:
    virtual bool has_changed() {
        return _changed;
    }

    virtual std::ostream &print(std::ostream &stream) const {
        return stream << "t(" << std::dec << _id << ")";
    }

    virtual bool equals(const Expression &other) const {
        const auto &o = static_cast<const Temporary&>(other);
        return _id == o._id;
    }

    virtual bool lower_than(const Expression &other) const {
        const auto &o = static_cast<const Temporary&>(other);
        return _id < o._id;
    }

    friend struct std::hash<Temporary>;
};

/*!
 * \brief `Expression` sub-class depicting a CPU register.
 *
 * Registers are distinguished by offset values. These are equivalent to offsets
 * as used in VEX and are currently specific to x86_64. \see `AMD64_REGISTERS`
 *
 * \todo Generalize for other architectures.
 */
class Register : public Expression {
private:
    uint32_t _offset;

public:
    Register(uint32_t offset)
        : Expression(ExpressionRegister), _offset(offset) {
    }

    /*!
     * \brief Returns the offset of the register.
     * \return A positive offset into `VexGuestAMD64State`.
     */
    uint32_t offset() const {
        return _offset;
    }

    virtual void optimize() {
        _changed = false;
    }

    virtual bool contains(const Expression &other, size_t=0) {
        return *this == other;
    }

    virtual bool propagate(const ExpressionPtr&, const ExpressionPtr&) {
        return false;
    }

    virtual size_t hash() const {
        size_t h = _type;
        std::hash_combine(h, _offset);
        return h;
    }

    virtual ExpressionPtr clone() const {
        auto result = std::make_shared<Register>(_offset);
        result->_changed = _changed;

        return result;
    }

private:
    virtual bool has_changed() {
        return _changed;
    }

    virtual std::ostream &print(std::ostream &stream) const {
        // FIXME: Obviously abstract away from concrete architecture.
        const auto &needle = AMD64_DISPLAY_REGISTERS.find(_offset);

        if(needle == AMD64_DISPLAY_REGISTERS.cend()) {
            return stream << "r(" << std::dec << _offset << ")";
        }

        return stream << needle->second;
    }

    virtual bool equals(const Expression &other) const {
        const auto &o = static_cast<const Register&>(other);
        return _offset == o._offset;
    }

    virtual bool lower_than(const Expression &other) const {
        const auto &o = static_cast<const Register&>(other);
        return _offset < o._offset;
    }
};

/*!
 * \brief `Expression` sub-class depicting a constant value.
 */
class Constant : public Expression {
private:
    uint64_t _value;

public:
    Constant(uint64_t value)
        : Expression(ExpressionConstant), _value(value) {
    }

    /*!
     * \brief Returns the underlying 64-bit value.
     */
    uint64_t value() const {
        return _value;
    }

    /*!
     * \brief Sets the underlying 64-bit value.
     * \param value The value to be set.
     */
    void value(uint64_t value) {
        _changed = true;
        _value = value;
    }

    virtual void optimize() {
        _changed = false;
    }

    virtual bool contains(const Expression &other, size_t=0) {
        return *this == other;
    }

    virtual bool propagate(const ExpressionPtr&, const ExpressionPtr&) {
        return false;
    }

    virtual size_t hash() const {
        size_t h = _type;
        std::hash_combine(h, _value);
        return h;
    }

    virtual ExpressionPtr clone() const {
        auto result = std::make_shared<Constant>(_value);
        result->_changed = _changed;

        return result;
    }

private:
    virtual bool has_changed() {
        return _changed;
    }

    virtual std::ostream &print(std::ostream &stream) const {
        return stream << "0x" << std::hex << _value;
    }

    virtual bool equals(const Expression &other) const {
        const auto &o = static_cast<const Constant&>(other);
        return _value == o._value;
    }

    virtual bool lower_than(const Expression &other) const {
        const auto &o = static_cast<const Constant&>(other);
        return _value < o._value;
    }
};

/*!
 * \brief `Expression` sub-class depicting a memory indirection.
 *
 * \todo Indirections are currently assumed to read 64 bits.
 */
class Indirection : public Expression {
private:
    ExpressionPtr _address;

public:
    Indirection(const ExpressionPtr &address)
        : Expression(ExpressionIndirection), _address(address) {
        _address->optimize();
    }

    /*!
     * \brief Returns the address of the memory this indirection targets.
     * \return A reference to a `ExpressionPtr`.
     */
    const ExpressionPtr &address() const {
        return _address;
    }

    virtual void optimize() {
        _address->optimize();
        _changed = _address->has_changed();
    }

    virtual bool contains(const Expression &other, size_t depth=-1) {
        bool result = *this == other;
        if(!result && depth) {
            return _address->contains(other, depth - 1);
        }

        return result;
    }

    virtual bool propagate(const ExpressionPtr &key,
                           const ExpressionPtr &value) {
        if(value->contains(*this)) {
            return false;
        }

        if(*_address == *key) {
            _changed = true;
            _address = value;
            return true;

        } else {
            if(_address->propagate(key, value)) {
                _changed = true;
                return true;
            }

            return false;
        }
    }

    virtual size_t hash() const {
        size_t h = _type;
        std::hash_combine(h, std::hash<ExpressionPtr>()(_address));
        return h;
    }

    virtual ExpressionPtr clone() const {
        auto result = std::make_shared<Indirection>(_address->clone());
        result->_changed = _changed;

        return result;
    }

private:
    virtual bool has_changed() {
        _changed = _changed || _address->has_changed();
        return _changed;
    }

    virtual std::ostream &print(std::ostream &stream) const {
        return stream << "[" << *_address << "]";
    }

    virtual bool equals(const Expression &other) const {
        const auto &o = static_cast<const Indirection&>(other);
        return *_address == *o._address;
    }

    virtual bool lower_than(const Expression &other) const {
        const auto &o = static_cast<const Indirection&>(other);
        return *_address < *o._address;
    }
};

/*!
 * \brief `Expression` sub-class depicting a binary operation combining two
 * expressions.
 *
 * Supported operations are found in `OperationType`. \see `OperationType`
 */
class Operation : public Expression {
private:
    ExpressionPtr _lhs, _rhs;
    OperationType _operation;

public:
    Operation(const ExpressionPtr &lhs, OperationType operation,
              const ExpressionPtr &rhs)
        : Expression(ExpressionOperation), _lhs(lhs), _rhs(rhs),
          _operation(operation) {

        _lhs->optimize();
        _rhs->optimize();

        optimize();
    }

    //! \brief Returns the left-hand side operand.
    const ExpressionPtr &lhs() const {
        return _lhs;
    }

    //! \brief Returns the right-hand side operand.
    const ExpressionPtr &rhs() const {
        return _rhs;
    }

    /*!
     * \brief Returns the operation.
     */
    OperationType operation() const {
        return _operation;
    }

    virtual void optimize() {
        while(optimizer());
    }

    virtual bool contains(const Expression &other, size_t depth=-1) {
        bool result = *this == other;
        if(!result && depth) {
            result = result || _lhs->contains(other, depth - 1);
            result = result || _rhs->contains(other, depth - 1);
        }

        return result;
    }

    virtual bool propagate(const ExpressionPtr &key,
                           const ExpressionPtr &value) {
        /* TODO: Always propagate Temporary values though. Maybe we shall only
         * prevent propagation if the cyclic dependency is in the same expr?
         */
        if(value->contains(*this, 1)) {
            return false;
        }

        bool dirty = false;

        if(*_lhs == *key) {
            _lhs = value;
            dirty = true;
        } else {
            dirty |= _lhs->propagate(key, value);
        }

        if(*_rhs == *key) {
            _rhs = value;
            dirty = true;
        } else {
            dirty |= _rhs->propagate(key, value);
        }

        _changed = _changed || dirty;
        return dirty;
    }

    /*!
     * \brief Checks for equality if an operation is a semantic no-op.
     *
     * Necessary for assuring that `(expression + 0)` equals `expression`.
     *
     * \todo This should be handled in a better way.
     * \param other The other expression to compare against.
     * \return `true`, if both are semantically equal; `false`, otherwise.
     */
    bool equals_inner(const Expression &other) const {
        if(_rhs->type() != ExpressionConstant) {
            return false;
        }

        const auto &constant = static_cast<const Constant&>(*_rhs);
        if(constant.value()) {
            return false;
        }

        switch(_operation) {
        case OperationAdd:
        case OperationSub: {
            return *_lhs == other;
        }

        default:
            return false;
        }
    }

    virtual size_t hash() const {
        size_t h = _type;
        std::hash_combine(h, std::hash<ExpressionPtr>()(_lhs));
        std::hash_combine(h, std::hash<ExpressionPtr>()(_rhs));

        return h;
    }

    virtual ExpressionPtr clone() const {
        auto result = std::make_shared<Operation>(_lhs->clone(), _operation,
                                                  _rhs->clone());
        result->_changed = _changed;

        return result;
    }

private:
    bool optimizer();
    void sanitize();

    virtual bool has_changed() {
        _changed = _changed || _lhs->has_changed() || _rhs->has_changed();
        return _changed;
    }

    virtual std::ostream &print(std::ostream &stream) const {
        return stream << "(" << *_lhs << " " << OPERATION_MAPPING[_operation]
                      << " " << *_rhs << ")";
    }

    virtual bool equals(const Expression &other) const {
        const auto &o = static_cast<const Operation&>(other);
        return *_lhs == *o._lhs && *_rhs == *o._rhs &&
                _operation == o._operation;
    }

    virtual bool lower_than(const Expression &other) const {
        const auto &o = static_cast<const Operation&>(other);

        bool is_lower = _operation < o._operation;
        is_lower = is_lower || *_lhs < *o._lhs;
        is_lower = is_lower || *_rhs < *o._rhs;

        return is_lower;
    }
};

#endif // EXPRESSION_H
