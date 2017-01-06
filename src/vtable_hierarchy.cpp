//
// Created by sqall on 23.02.16.
//

#include <algorithm>
#include <fstream>
#include <sstream>

#include "vtable_hierarchy.h"

using namespace std;

VTableHierarchies::VTableHierarchies(const FileFormatType file_format,
                                     const VTableFile &vtable_file,
                                     const string &module_name,
                                     const ExternalFunctions &external_funcs,
                                     const ModulePlt &module_plt,
                                     const BlacklistFuncsSet &funcs_blacklist,
                                     const int thread_id)
    : _file_format(file_format),
      _vtable_file(vtable_file),
      _this_vtables(_vtable_file.get_this_vtables()),
      _module_name(module_name),
      _external_funcs(external_funcs),
      _module_plt(module_plt),
      _funcs_blacklist(funcs_blacklist),
      _thread_id(thread_id) {

    // Make sure that the object is initialized.
    if(!_vtable_file.is_finalized()) {
        throw runtime_error("VTable file object was not finalized.");
    }

#if DEBUG_WRITE_HIERARCHY_STEPS
    hierarchy_steps_file.open("/tmp/" + module_name + "_steps.txt");
#endif

}


// Adds both vtables to the hierarchy. Returns "true" if it is added
// to an existing hierarchy (does not merge hierarchies that could be
// dependent after that) and "false" if it creates a new hierarchy.
bool VTableHierarchies::add_to_hierarchy(uint32_t vtable_1_idx,
                                         uint32_t vtable_2_idx) {

    // Insert dependency into vtables hierarchy result.
    bool is_inserted = false;
    for(auto &hierarchy_it : _hierarchies) {
        if(hierarchy_it.find(vtable_1_idx) != hierarchy_it.cend()
            || hierarchy_it.find(vtable_2_idx) != hierarchy_it.cend()) {

            hierarchy_it.insert(vtable_1_idx);
            hierarchy_it.insert(vtable_2_idx);
            is_inserted = true;
            break;
        }
    }
    if(!is_inserted) {

        DependentVTables new_hierarchy;
        new_hierarchy.insert(vtable_2_idx);
        new_hierarchy.insert(vtable_1_idx);
        _hierarchies.push_back(new_hierarchy);
    }

    return is_inserted;
}


// Merges all sets that have at least one element in common until
// there is no merging possible anymore.
void VTableHierarchies::merge_hierarchies() {
    merge_hierarchies_priv();
}


// Merges all sets that have at least one element in common until
// there is no merging possible anymore.
void VTableHierarchies::merge_hierarchies_priv() {

    for(auto hier_it = _hierarchies.begin(); hier_it != _hierarchies.end();) {

        // Iterate over the _remaining_ sets in the vector.
        bool is_merged = false;
        for(auto search_it = hier_it+1;
            search_it != _hierarchies.end();
            ++search_it) {

            // Check if element in source set is also in destination set
            // => if it is then merge source set into destination set.
            for(auto vtable_it : *hier_it) {
                if(search_it->find(vtable_it) != search_it->end()) {

#if DEBUG_WRITE_HIERARCHY_STEPS
                    hierarchy_steps_file << "\nMerging hierarchy:" << endl;
                    for(auto it : *hier_it) {
                        const auto debug_temp = _vtable_file.get_vtable(it);
                        hierarchy_steps_file << debug_temp.module_name
                             << " - 0x"
                             << hex << debug_temp.addr
                             << endl;
                    }
                    hierarchy_steps_file << "\nwith hierarchy: " << endl;
                    for(auto it : *search_it) {
                        const auto debug_temp = _vtable_file.get_vtable(it);
                        hierarchy_steps_file << debug_temp.module_name
                             << " - 0x"
                             << hex << debug_temp.addr
                             << endl;
                    }
#endif

                    is_merged = true;
                    search_it->insert(hier_it->begin(), hier_it->end());

#if DEBUG_WRITE_HIERARCHY_STEPS
                    hierarchy_steps_file << "\nNew hierarchy: " << endl;
                    for(auto it : *search_it) {
                        const auto debug_temp = _vtable_file.get_vtable(it);
                        hierarchy_steps_file << debug_temp.module_name
                             << " - 0x"
                             << hex << debug_temp.addr
                             << endl;
                    }
                    hierarchy_steps_file << "\n###############################"
                                         << "#################################"
                                         << endl;
#endif
                    break;
                }
            }
            if(is_merged) {
                break;
            }
        }

        // Remove source set if it was merged into destination set.
        if(is_merged) {
            hier_it = _hierarchies.erase(hier_it);
        }
        else {
            ++hier_it;
        }
    }

#if DEBUG_SEARCH_MERGING_REASON
    // Search the moment two vtables are put together into the same hierarchy.
    for(const auto hier_it : _hierarchies) {
        bool first = false;
        bool second = false;
        for(const auto vtable_it : hier_it) {
            if(_vtable_file.get_vtable(vtable_it).addr
                    == DEBUG_SEARCH_MERGING_VTABLE_ADDR_1) {
                first = true;
            }
            else if(_vtable_file.get_vtable(vtable_it).addr
                    == DEBUG_SEARCH_MERGING_VTABLE_ADDR_2) {
                second = true;
            }
        }
        if(first && second) {
            cout << "VTable "
                 << hex << DEBUG_SEARCH_MERGING_VTABLE_ADDR_1
                 << " and "
                 << hex << DEBUG_SEARCH_MERGING_VTABLE_ADDR_2
                 << " are now in the same hierarchy (Thread: "
                 << dec << _thread_id
                 << ")"
                 << endl;
            // Kill the whole process if we found the reason
            // (obviously, this will through errors).
            exit(0);
        }
    }
#else
    // Use thread id in order to shut up the compiler with errors.
    (void)_thread_id;
#endif

}


// Get vtables that reside on the same offset in the same object.
bool VTableHierarchies::get_vtable_dependencies(
    const VTableUpdates &vtable_updates, const ExpressionPtr &base_base,
    uint32_t base_index, size_t base_offset) {

    bool found_new_dependencies = false;

    // Get vtable overwrite dependencies.
    for(const auto &sub_it : vtable_updates) {

        // Only consider overwrites to the same offset for the same object.
        if(sub_it.offset != base_offset) {
            continue;
        }
        if(!(*sub_it.base == *base_base)) {
            continue;
        }
        if(base_index == sub_it.index) {
            continue;
        }

#if DEBUG_PRINT_DEPENDENCIES
        const auto &temp1 = _vtable_file.get_vtable(base_index);
        const auto &temp2 = _vtable_file.get_vtable(sub_it.index);
        cout << "Vtable dependency: "
             << temp1.module_name
             << ":0x"
             << hex << temp1.addr
             << " -> "
             << temp2.module_name
             << ":0x"
             << hex << temp2.addr
             << endl;
#endif

        // Insert dependency into vtables hierarchy result.
        add_to_hierarchy(base_index, sub_it.index);
        found_new_dependencies = true;

    }

    return found_new_dependencies;
}


// Get vtable dependencies considering offset to top.
bool VTableHierarchies::get_sub_vtable_dependencies(
    const VTableUpdates &vtable_updates, const ExpressionPtr &sub_base,
    uint32_t sub_index, size_t sub_offset) {

    bool found_new_dependencies = false;
    const auto &vtable_entry = _vtable_file.get_vtable(sub_index);

    // Only consider sub vtables (base vtables have offset to top equal 0).
    if(vtable_entry.offset_to_top == 0) {
        return false;
    }

    // Search if sub vtable has a base vtable in the same object.
    // NOTE: base vtable not necessarily at offset 0, consider composition.
    size_t base_vtable_offset = vtable_entry.offset_to_top + sub_offset;
    for(const auto &base_it : vtable_updates) {

        // Check if vtable has the base vtable offset.
        if(base_it.offset != base_vtable_offset) {
            continue;
        }

        // Only consider overwrites to the same object.
        if(!(*base_it.base == *sub_base)) {
            continue;
        }

#if DEBUG_PRINT_DEPENDENCIES
        const auto &temp1 = _vtable_file.get_vtable(sub_index);
        const auto &temp2 = _vtable_file.get_vtable(base_it.index);
        cout << "(Sub)-Vtable dependency: "
             << temp1.module_name
             << ":0x"
             << hex << temp1.addr
             << " -> "
             << temp2.module_name
             << ":0x"
             << hex << temp2.addr
             << endl;
#endif

        // Insert dependency into vtables hierarchy result.
        add_to_hierarchy(sub_index, base_it.index);
        found_new_dependencies = true;
    }

    return found_new_dependencies;
}


// Extracts all vtable dependencies that were found in the analysis.
bool VTableHierarchies::extract_vtable_dependencies(
        const VTableUpdates &vtable_updates) {

#if DEBUG_PRINT_DEPENDENCIES
    cout << "VTable Updates:" << endl;
    cout << "-------------" << endl;
    for(auto &it : vtable_updates) {
        cout << "Base: "
             << *(it.base)
             << endl;
        const auto &temp = _vtable_file.get_vtable(it.index);
        cout << "Vtable: "
             << temp.module_name
             << ":0x"
             << hex << temp.addr
             << endl;
        cout << "Offset: 0x"
             << hex << it.offset
             << endl;
        cout << "-------------" << endl;
    }
#endif

    // Extract vtable dependencies of found vtables.
    bool found_new_dependencies = false;
    ExpressionPtr current_base;
    uint32_t current_index;

    for(const auto &it : vtable_updates) {

        current_base = it.base;
        current_index = it.index;
        size_t current_offset = it.offset;

        // Get vtables that reside on the same offset in the same object.
        found_new_dependencies |= get_vtable_dependencies(vtable_updates,
                                                          current_base,
                                                          current_index,
                                                          current_offset);

        // Get vtable dependencies considering offset to top.
        found_new_dependencies |= get_sub_vtable_dependencies(vtable_updates,
                                                              current_base,
                                                              current_index,
                                                              current_offset);
    }

    return found_new_dependencies;
}


const HierarchiesVTable &VTableHierarchies::get_hierarchies() const {
    return _hierarchies;
}


// Updates the current hierarchy structure with the two given dependent
// vtables (given by index).
void VTableHierarchies::update_hierarchy_priv(uint32_t vtable_1_idx,
                                              uint32_t vtable_2_idx,
                                              bool merge_hierarchy) {

    // When vtables were added to an existing hierarchy, it can happen
    // that two hierarchies can be merged to one.
    if(add_to_hierarchy(vtable_1_idx, vtable_2_idx) && merge_hierarchy) {
        merge_hierarchies_priv();
    }
}


// Updates the current hierarchy structure with the two given dependent
// vtables (given by index).
void VTableHierarchies::update_hierarchy(uint32_t vtable_1_idx,
                                         uint32_t vtable_2_idx,
                                         bool merge_hierarchy) {
    update_hierarchy_priv(vtable_1_idx, vtable_2_idx, merge_hierarchy);
}


// Updates the current hierarchy structure with the given hierarchies.
void VTableHierarchies::update_hierarchy(
                                    const HierarchiesVTable& vtable_hierarchies,
                                    bool merge_hierarchy) {
    for(const DependentVTables& it : vtable_hierarchies) {
        DependentVTables copy = it;
        _hierarchies.push_back(copy);
    }
    if(merge_hierarchy) {
        merge_hierarchies_priv();
    }
}


// Updates the current hierarchy structure with the found vtable updates
// and the information given by the module and function that was analyzed.
void VTableHierarchies::update_hierarchy(const VTableUpdates &vtable_updates,
                                         const string&,
                                         uint64_t func_addr,
                                         bool merge_hierarchy) {

    // Check if current function is a member of a vtable (or multiple)
    // and get all the vtables.
    // NOTE: Only vtables of this module are considered here.
    map<uint32_t, vector<VTableUpdate> > dependent_vtables;
    for(const auto &vtbl_kv : _this_vtables) {

        const vector<uint64_t> &entries = vtbl_kv.second->entries;

        const auto pos_it = find(entries.begin(), entries.end(), func_addr);
        if(pos_it != entries.end()) {

            int pos = distance(entries.begin(), pos_it);

            // Create artificial vtable overwrites for RDI/RCX for each
            // vtable that contains the current function.
            shared_ptr<Symbolic> reg_ptr;
            switch(_file_format) {
                // => set RDI to contain active vtable.
                case FileFormatELF64:
                    reg_ptr = State::initial_values().at(OFFB_RDI);
                    break;
                // => set RCX to contain active vtable.
                case FileFormatPE64:
                    reg_ptr = State::initial_values().at(OFFB_RCX);
                    break;
                default:
                    throw runtime_error("Do not know how to handle file format.");
            }
            ExpressionPtr this_ptr = reg_ptr;

            VTableUpdate vtable_update;
            vtable_update.offset = 0;
            vtable_update.base = this_ptr;

            const VTable &vtable = _vtable_file.get_vtable(
                                        vtbl_kv.second->module_name,
                                        vtbl_kv.first);
            vtable_update.index = vtable.index;

            // Divide vtable updates considering the position of the function
            // inside the vtable (consider vtables that have this function at
            // the same position as dependent).
            if(dependent_vtables.find(pos) == dependent_vtables.end()) {
                dependent_vtables[pos] = { vtable_update };
            }
            else {
                dependent_vtables[pos].push_back(vtable_update);
            }
        }
    }

    // Extract vtable dependencies of found vtables
    // (differentiate between virtual functions and normal functions).
    bool found_new_dependencies = false;
    if(dependent_vtables.empty()) { // normal function

        found_new_dependencies |= extract_vtable_dependencies(vtable_updates);
    }

    else { // virtual function

        // Add manually dependent vtables as vtable overwrite of RDI/RCX.
        for(const auto &vtbl_kv : dependent_vtables) {

            VTableUpdates temp_updates = vtable_updates;

            // Add dependent vtables manually as overwrite.
            for(const auto &it : vtbl_kv.second) {
                temp_updates.push_back(it);
            }

#if DEBUG_PRINT_DEPENDENCIES
            cout << "Analysis for vtables with function at position: "
                 << dec << vtbl_kv.first
                 << endl;
#endif

            found_new_dependencies |= extract_vtable_dependencies(temp_updates);
        }
    }

    // Merge hierarchies if they have at least one common element.
    if(found_new_dependencies && merge_hierarchy) {

#if DEBUG_WRITE_HIERARCHY_STEPS
    hierarchy_steps_file << "\nMerging hierarchies after processing function "
                         << hex << func_addr
                         << endl;
#endif

        merge_hierarchies_priv();
    }
}


// Exports local hierarchy data structure to a file.
void VTableHierarchies::export_hierarchy(const string &target_dir) {

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << ".hierarchy";
    string target_file = temp_str.str();

    ofstream hier_file;
    hier_file.open(target_file);

    hier_file << _module_name << endl;

    for(const auto &hier_it : _hierarchies) {
        for(const auto &vtable_idx : hier_it) {
            const auto &temp = _vtable_file.get_vtable(vtable_idx);
            hier_file << temp.module_name
                      << ":"
                      << hex << temp.addr
                      << " ";
        }
        hier_file << endl;
    }
    hier_file.close();
}


// Imports hierarchy files and adds them to the local hierarchy data structure.
void VTableHierarchies::import_hierarchy(const string &target_file) {

    ifstream file(target_file + ".hierarchy");
    if(!file) {
        throw runtime_error("Opening hierarchy file failed.");
    }

    string line;

    // Parse first line manually.
    getline(file, line);
    istringstream header_parser(line);

    // First entry of file is always the module name.
    string import_module_name;
    header_parser >> import_module_name;
    if(header_parser.fail()) {
        throw runtime_error("Parsing hierarchy file failed.");
    }

    while(getline(file, line)) {
        istringstream parser(line);
        string hierarchy_entry;

        DependentVTables new_hierarchy;
        // Parse each hierarchy entry which is given in the following form:
        // <module_name>:<vtable_addr_hex>
        while(parser >> hierarchy_entry) {
            if(parser.fail()) {
                throw runtime_error("Parsing hierarchy file failed.");
            }

            string module_name;
            string vtable_addr_str;
            uint64_t vtable_addr;

            istringstream parser_entry(hierarchy_entry);
            if(parser_entry.fail()) {
                throw runtime_error("Parsing hierarchy file failed.");
            }
            getline(parser_entry, module_name, ':');
            getline(parser_entry, vtable_addr_str, ':');

            istringstream parser_vtable_addr(vtable_addr_str);
            if(parser_vtable_addr.fail()) {
                throw runtime_error("Parsing hierarchy file failed.");
            }
            parser_vtable_addr >> hex >> vtable_addr;

            // Convert module name and vtable address to the index.
            const VTable &vtable = _vtable_file.get_vtable(module_name,
                                                           vtable_addr);
            new_hierarchy.insert(vtable.index);
        }

        _hierarchies.push_back(new_hierarchy);
    }

    // Optimize hierarchies in case they were not optimal before.
    merge_hierarchies_priv();
}


void VTableHierarchies::entry_heuristic_inter() {

    // Check if any vtable of this module has an entry that uses a plt entry.
    // If it has, resolve it and check if any vtable of that external module
    // has the same function at the same position. If it has, consider
    // both vtables as dependent.
    for(const auto &vtbl_kv : _this_vtables) {
        const vector<uint64_t> &this_entries = vtbl_kv.second->entries;
        int pos = 0;

        for(const uint64_t vfunc_addr : this_entries) {

            // Ignore blacklisted function entries (i.e., pure virtual).
            if(_funcs_blacklist.find(vfunc_addr) != _funcs_blacklist.cend()) {
                continue;
            }

            const PltEntry *plt_entry = _module_plt.get_plt_entry(vfunc_addr);
            if(plt_entry == nullptr) {
                continue;
            }

            const ExternalFunction *ext_func =
                    _external_funcs.get_external_function(plt_entry->func_name);
            if(ext_func == nullptr) {
                continue;
            }

            // Check all vtables of the external module if they have the same
            // function at the same position.
            const VTableMap& ext_vtables = _vtable_file.get_vtables(
                                                ext_func->module_name);

            for(const auto &ext_vtbl_kv : ext_vtables) {

                const auto ext_pos_it = find(ext_vtbl_kv.second->entries.begin(),
                                         ext_vtbl_kv.second->entries.end(),
                                         ext_func->addr);
                if(ext_pos_it != ext_vtbl_kv.second->entries.end()) {
                    int pos_ext_func = distance(ext_vtbl_kv.second->entries.begin(),
                                                ext_pos_it);

#if DEBUG_PRINT_DEPENDENCIES
                    cout << "VTable: "
                         << vtbl_kv.second->module_name
                         << ":"
                         << hex << vtbl_kv.second->addr
                         << endl;

                    cout << ext_vtbl_kv.second->module_name
                         << ":"
                         << hex << ext_vtbl_kv.second->addr
                         << " - "
                         << ext_func->name
                         << " ("
                         << hex << ext_func->addr
                         << ") - pos: "
                         << dec << pos_ext_func
                         << endl;
#endif

                    // If both entries are at the same position in the
                    // corresponding VTable, consider them as dependent.
                    if(pos == pos_ext_func) {
                        update_hierarchy_priv(vtbl_kv.second->index,
                                              ext_vtbl_kv.second->index,
                                              true);
                    }
                }
                else {
                    continue;
                }
            }
            pos++;
        }
    }

    merge_hierarchies_priv();

    return;
}


void VTableHierarchies::vcall_analysis(const VCalls &vcalls) {

    // Add all vtables as dependent that are used in the same vcall.
    for(const auto &vcall : vcalls) {
        bool first = true;
        uint32_t ref_idx;
        for(uint32_t idx : vcall.indexes) {
            if(first) {
                first = false;
                ref_idx = idx;
                continue;
            }
            update_hierarchy_priv(ref_idx, idx, false);
        }
    }

    // Since we do not merge the hierachies after each update, we have to do
    // it manually at the end.
    merge_hierarchies_priv();
}
