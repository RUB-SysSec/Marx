
#include "expression.h"

using namespace std;

bool Operation::optimizer() {
    /* Operations are the only expressions that could possibly be
     * ambiguous. We need to make sure to sanitize and optimize it as for
     * the state updating logic to be reasonable. */

    /* This is done in-place (as to avoid having to return a new shared_ptr
     * everytime). If an operation can reduced to one argument (e.g., 1+2),
     * it should be transformed into (result + 0), such that it can be
     * pruned later (e.g., 3+0).
     *
     * Make sure that all destructive updates on sub-expressions are immutable,
     * i.e., yield new objects that reflect the changes. This is done in order
     * not to propagate changes to other expressions referencing the modified
     * expression.
     *
     * TODO: Verify that there are not any destructive expression updates on
     *       anything not covered here (optimizer?). Expression::propagate
     *       should not be affected.
     * TODO: Consider shared_ptr.reset.
     * TODO: Arithmetic simplifications do not care for signedness or
     *       operand size.
     */

    /* TODO: Do we want to allow basic sanitization first (i.e., without
     * optimization)?
     */
    _changed = has_changed();
    if(!_changed) {
        return false;
    }

    bool dirty = false;
    sanitize();

    if(_operation == OperationSub) {
        // (X - X) = (0 + 0).
        if(*_lhs == *_rhs) {
            _lhs = std::make_shared<Constant>(0);
            _rhs = std::make_shared<Constant>(0);

            _operation = OperationAdd;
            dirty = true;
        }

        // (const_a - const_b) = (const_c - 0).
        else if(_lhs->type() == _rhs->type() &&
                _lhs->type() == ExpressionConstant) {

            auto &lhs = static_cast<Constant&>(*_lhs);
            auto &rhs = static_cast<Constant&>(*_rhs);

            if(rhs.value()) {
                _lhs = make_shared<Constant>(lhs.value() - rhs.value());
                _rhs = make_shared<Constant>(0);

                dirty = true;
            }
        }
    } else if(_operation == OperationAdd) {
        // (const_a + const_b) = (const_c + 0).

        // TODO: Generalize this for other operators.
        if(_lhs->type() == _rhs->type() &&
                _lhs->type() == ExpressionConstant) {

            auto &lhs = static_cast<Constant&>(*_lhs);
            auto &rhs = static_cast<Constant&>(*_rhs);

            if(lhs.value() && rhs.value()) {
                _lhs = make_shared<Constant>(lhs.value() + rhs.value());
                _rhs = make_shared<Constant>(0);

                dirty = true;
            }
        }
    }

    auto is_add_or_sub = [&](const OperationType &op) {
        return op == OperationAdd || op == OperationSub;
    };

    if(is_add_or_sub(_operation)) {
        // (X +- const_a), const_a > UINT64_MAX = (X +- (-const_a)).
        if(_rhs->type() == ExpressionConstant &&
                static_cast<const Constant&>(*_rhs).value() >
                UINT64_MAX / 2 + 1) {

            switch(_operation) {
            case OperationAdd:
                _operation = OperationSub;
                break;

            case OperationSub:
                _operation = OperationAdd;
                break;

            default:
                __builtin_unreachable();
            }

            auto &rhs = static_cast<Constant&>(*_rhs);
            _rhs = make_shared<Constant>(-rhs.value());

            dirty = true;
        }

        // ((X +- const_1) +- const_2) = (X +- const_3).
        if(_lhs->type() == ExpressionOperation &&
                _rhs->type() == ExpressionConstant) {

            const auto &lhs = static_cast<const Operation&>(*_lhs);
            auto &rhs = static_cast<Constant&>(*_rhs);

            if(lhs._rhs->type() == ExpressionConstant) {
                _lhs = lhs._lhs; // TODO: Copy here?
                auto value = static_cast<Constant&>(*lhs._rhs).value();

                bool inner = lhs._operation == OperationAdd;
                bool outer = _operation == OperationAdd;

                if(inner != outer) {
                    value -= rhs.value();
                } else {
                    value += rhs.value();
                }

                _operation = lhs._operation;
                _rhs = make_shared<Constant>(value);

                dirty = true;
            }
        }
    }

    _changed = dirty;

    sanitize();
    return dirty;
}

void Operation::sanitize() {
    _lhs->optimize();
    _rhs->optimize();

    switch(_operation) {
    case OperationSub:
        // Non-commutative, nothing we can do about that.
        return;

    default:
        break;
    }

    // Highest precedence on LHS.
    if(_lhs->type() < _rhs->type()) {
        _lhs.swap(_rhs);
    }

    // On equal types, decide using operator<.
    if(_lhs->type() == _rhs->type()) {
        if(*_lhs < *_rhs) {
            _lhs.swap(_rhs);
        }
    }
}

bool Expression::operation_equal(const Expression &other) const {
    /* All we do here is assert that (x +- 0) == x remains true.
     * FIXME: Integrate this better. */

    const auto &operation = static_cast<const Operation&>(*this);
    return operation.equals_inner(other);
}
