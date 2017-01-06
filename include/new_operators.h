#ifndef NEW_OPERATORS_H
#define NEW_OPERATORS_H

#include <map>
#include <unordered_set>

#include "expression.h"
#include "vtable_file.h"
#include "vtable_hierarchy.h"

struct NewOperator {
    uint64_t addr;
    uint64_t size;
    ExpressionPtr expr;
    std::unordered_set<uint32_t> vtbl_idxs;
};


typedef std::map<uint64_t, NewOperator> OperatorNewAddrMap;


class NewOperators {
private:

    const std::string &_module_name;
    const VTableFile &_vtable_file;
    const VTableHierarchies &_vtable_hierarchies;

    OperatorNewAddrMap _op_new_candidates;

public:

    NewOperators(const std::string &module_name,
                 const VTableFile &vtable_file,
                 const VTableHierarchies &vtable_hierarchies);


    void add_op_new_candidate(const NewOperator &new_op_candidate);


    void export_new_operators(const std::string &target_dir);


    const OperatorNewAddrMap& get_new_operators() const;


    void copy_new_operators(const OperatorNewAddrMap &new_ops);
};

#endif //NEW_OPERATORS_H
