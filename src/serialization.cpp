#include "serialization.h"


using namespace std;


void serialize(ExpressionPtr exp, ostream &output) {

    switch(exp->type()) {

        case ExpressionUnknown: {
            output.put(ExpressionUnknown);
            break;
        }

        case ExpressionConstant: {
            output.put(ExpressionConstant);
            Constant &temp = static_cast<Constant&>(*exp);
            uint64_t value = temp.value();
            output.write(reinterpret_cast<const char *>(&value),
                         sizeof(value));
            break;
        }

        case ExpressionSymbolic: {
            output.put(ExpressionSymbolic);
            Symbolic &temp = static_cast<Symbolic&>(*exp);
            // Length + 1 to have \0 at the end.
            output.write(temp.name().c_str(),
                         temp.name().length() + 1);
            break;
        }

        case ExpressionTemporary: {
            output.put(ExpressionTemporary);
            Temporary &temp = static_cast<Temporary&>(*exp);
            uint32_t id = temp.id();
            output.write(reinterpret_cast<const char *>(&id),
                         sizeof(id));
            break;
        }

        case ExpressionRegister: {
            output.put(ExpressionRegister);
            Register &temp = static_cast<Register&>(*exp);
            uint32_t offset = temp.offset();
            output.write(reinterpret_cast<const char *>(&offset),
                         sizeof(offset));
            break;
        }

        case ExpressionIndirection: {
            output.put(ExpressionIndirection);
            Indirection &temp = static_cast<Indirection&>(*exp);
            serialize(temp.address(), output);
            break;
        }

        case ExpressionOperation: {
            output.put(ExpressionOperation);
            Operation &temp = static_cast<Operation&>(*exp);
            output.put(temp.operation());
            serialize(temp.lhs(), output);
            serialize(temp.rhs(), output);
            break;
        }

        default:
            throw runtime_error("Do not know how to serialize "\
                                "expression type.");
    }
}


ExpressionPtr unserialize(istream &input) {

    switch(input.get()) {

        case ExpressionUnknown: {
            Unknown temp;
            return make_shared<Unknown>(temp);
            break;
        }

        case ExpressionConstant: {
            uint64_t value;
            input.read(reinterpret_cast<char *>(&value),
                       sizeof(value));
            Constant temp(value);
            return make_shared<Constant>(temp);
        }

        case ExpressionSymbolic: {
            string name;
            // Read C-like string.
            getline(input, name, '\0');
            Symbolic temp(name);
            return make_shared<Symbolic>(temp);
        }

        case ExpressionTemporary: {
            uint32_t id;
            input.read(reinterpret_cast<char *>(&id),
                       sizeof(id));
            Temporary temp(id);
            return make_shared<Temporary>(temp);
        }

        case ExpressionRegister: {
            uint32_t offset;
            input.read(reinterpret_cast<char *>(&offset),
                       sizeof(offset));
            Register temp(offset);
            return make_shared<Register>(temp);
        }

        case ExpressionIndirection: {
            Indirection temp(unserialize(input));
            return make_shared<Indirection>(temp);
            break;
        }

        case ExpressionOperation: {
            OperationType op_type = static_cast<OperationType>(input.get());
            Operation temp(unserialize(input),
                           op_type,
                           unserialize(input));
            return make_shared<Operation>(temp);
            break;
        }

        default:
            break;
    }

    throw runtime_error("Do not know how to unserialize "\
                        "expression type.");
}
