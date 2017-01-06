#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "expression.h"
#include "iostream"

void serialize(ExpressionPtr exp, std::ostream &output);
ExpressionPtr unserialize(std::istream &input);


#endif
