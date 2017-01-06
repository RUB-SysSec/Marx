#include "new_operators.h"

using namespace std;


NewOperators::NewOperators(const string &module_name,
                           const VTableFile &vtable_file,
                           const VTableHierarchies &vtable_hierarchies)
    : _module_name(module_name),
      _vtable_file(vtable_file),
      _vtable_hierarchies(vtable_hierarchies) {}


void NewOperators::add_op_new_candidate(const NewOperator &new_op_candidate) {
    if(_op_new_candidates.find(new_op_candidate.addr)
            == _op_new_candidates.cend()) {

        _op_new_candidates[new_op_candidate.addr] = new_op_candidate;
    }
    else {
        for(uint32_t idx : new_op_candidate.vtbl_idxs) {
            _op_new_candidates[new_op_candidate.addr].vtbl_idxs.insert(idx);
        }
    }
}


void NewOperators::export_new_operators(const string &target_dir) {

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << ".new_operators";
    string target_file = temp_str.str();

    ofstream new_op_file;
    new_op_file.open(target_file);

    new_op_file << _module_name << endl;

    const HierarchiesVTable &vtbl_hierarchies =
                                        _vtable_hierarchies.get_hierarchies();

    for(const auto &new_op : _op_new_candidates) {
        unordered_set<uint32_t> possible_vtables;
        for(uint32_t idx : new_op.second.vtbl_idxs) {

            // Copy also the whole vtable hierarchy into the possible
            // vtable set.
            if(possible_vtables.find(idx) == possible_vtables.cend()) {
                for(const auto &dep_vtables : vtbl_hierarchies) {
                    if(dep_vtables.find(idx) != dep_vtables.cend()) {
                        for(uint32_t dep_vtbl_idx : dep_vtables) {
                            possible_vtables.insert(dep_vtbl_idx);
                        }
                        break;
                    }
                }
            }
            possible_vtables.insert(idx);
        }

        new_op_file << hex << new_op.second.addr
                    << " "
                    << hex << new_op.second.size
                    << " ";

        for(uint32_t idx : possible_vtables) {
            const auto &temp = _vtable_file.get_vtable(idx);
            new_op_file << temp.module_name
                        << ":"
                        << hex << temp.addr
                        << " ";
        }

        new_op_file << endl;
    }
    new_op_file.close();
}


const OperatorNewAddrMap& NewOperators::get_new_operators() const {
    return _op_new_candidates;
}


void NewOperators::copy_new_operators(const OperatorNewAddrMap &new_ops) {
    for(const auto &new_op : new_ops) {
        add_op_new_candidate(new_op.second);
    }
}
