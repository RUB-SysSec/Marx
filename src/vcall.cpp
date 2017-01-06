
#include "vcall.h"
#include "expression.h"

using namespace std;


VCallFile::VCallFile(const string &module_name,
                     const VTableHierarchies &vtable_hierarchies,
                     const VTableFile &vtable_file)
    : _module_name(module_name),
      _vtable_hierarchies(vtable_hierarchies),
      _vtable_file(vtable_file) {}


const VCalls &VCallFile::get_vcalls() const {
    lock_guard<mutex> _(_mtx);

    return _vcalls;
}


void VCallFile::add_possible_vcall(uint64_t addr) {
    lock_guard<mutex> _(_mtx);

    _possible_vcalls.insert(addr);
}


void VCallFile::add_vcall(uint64_t addr, uint32_t index, size_t entry_index) {
    lock_guard<mutex> _(_mtx);

    // Check if virtual callsite is already known.
    for(auto &it : _vcalls) {
        if(it.addr == addr) {
            it.indexes.insert(index);

            // Do a sanity check that the entry indexes have not changed.
            // (Intuition: Can never be different for the same vcall).
            if(it.entry_index != entry_index) {
                cerr << "Different entry index at vcall 0x"
                     << hex << addr << endl;
                cerr << "Old entry index: "
                     << dec << it.entry_index << endl;
                cerr << "New entry index: "
                     << dec << entry_index << endl;
                throw runtime_error("Different vtable entry indexes "\
                                    "for same vcall.");
            }

            return;
        }
    }

    VCall vcall;
    vcall.indexes.insert(index);
    vcall.addr = addr;
    vcall.entry_index = entry_index;
    _vcalls.push_back(vcall);
}


void VCallFile::export_vcalls(const string &target_dir) {
    lock_guard<mutex> _(_mtx);

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << ".vcalls";
    string target_file = temp_str.str();

    ofstream vcall_file;
    vcall_file.open(target_file);

    stringstream temp_str_ext;
    temp_str_ext << target_dir << "/" << _module_name << ".vcalls_extended";
    string target_file_ext = temp_str_ext.str();

    ofstream vcall_file_ext;
    vcall_file_ext.open(target_file_ext);

    vcall_file << _module_name << endl;
    vcall_file_ext << _module_name << endl;

    const HierarchiesVTable &hierarchies =
                            _vtable_hierarchies.get_hierarchies();
    for(const auto &it : _vcalls) {

        // Do not consider all vtables used in this vcall as in one hierarchy.
        unordered_set<uint32_t> allowed_vtables;
        for(const auto idx : it.indexes) {
            for(const auto dependent_vtbls : hierarchies) {
                if(dependent_vtbls.find(idx) != dependent_vtbls.cend()) {
                    for(uint32_t hier_idx : dependent_vtbls) {
                        allowed_vtables.insert(hier_idx);
                    }
                }
            }

            // Add vtable index manually afterwards in order to also export
            // vtables that do not belong to a hierarchy.
            allowed_vtables.insert(idx);
        }

        // Address of vcall in module.
        vcall_file << hex << it.addr;
        vcall_file_ext << hex << it.addr;

        // Index into vtable that is used by vcall.
        vcall_file_ext << " " << hex << it.entry_index;

        // Export the hierarchy in the following format:
        // <module_name:hex_addr_vtable> <module_name:hex_addr_function>
        for(const auto idx : allowed_vtables) {
            const VTable& temp = _vtable_file.get_vtable(idx);

            // Export vtable address.
            vcall_file << " "
                       << temp.module_name
                       << ":"
                       << hex << temp.addr;
            vcall_file_ext << " "
                           << temp.module_name
                           << ":"
                           << hex << temp.addr;

            // Export target function address.
            uint64_t target_func = 0;
            if(temp.entries.size() > it.entry_index) {
                target_func = temp.entries.at(it.entry_index);
            }
            vcall_file_ext << " "
                           << temp.module_name
                           << ":"
                           << hex << target_func;
        }

        vcall_file << endl;
        vcall_file_ext << endl;
    }

    vcall_file.close();
    vcall_file_ext.close();

    stringstream temp_str_poss;
    temp_str_poss << target_dir << "/" << _module_name << ".vcalls_possible";
    string target_file_poss = temp_str_poss.str();

    ofstream vcall_file_poss;
    vcall_file_poss.open(target_file_poss);

    vcall_file_poss << _module_name << endl;

    for(const auto &it : _possible_vcalls) {

        // Address of possible vcall in module.
        vcall_file_poss << hex << it << endl;
    }

    vcall_file_poss.close();
}
