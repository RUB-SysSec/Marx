
#include "vtable_file.h"

using namespace std;

/*!
 * \brief Constructs a new `VtableFile` object.
 * \param vtable_file The filename of the `_vtables.txt` file (as produced
 * by the exporter script).
 */
VTableFile::VTableFile(const string &this_module_name) {
    _this_module_name = this_module_name;
    _vtables.clear();
    _index = 0;
}

bool VTableFile::parse(const string &vtables_file) {

    // Make sure that we parse files only if object was not finalized yet.
    if(_is_finalized) {
        throw runtime_error("Parse attempt after VTableFile object was"\
                            " finalized.");
    }

    ifstream file(vtables_file + "_vtables.txt");
    if(!file) {
        return false;
    }

    string line;

    // Parse first line manually.
    getline(file, line);
    istringstream header_parser(line);

    // First entry of file is always the module name.
    string module_name;
    header_parser >> module_name;
    if(header_parser.fail()) {
        return false;
    }

    // Check if we already parsed a vtables file for this module.
    if(_managed_modules.find(module_name) != _managed_modules.cend()) {
        throw runtime_error("A vtables file for this module was already "\
                            "parsed.");
    }

    bool has_vtables = false;
    while(getline(file, line)) {
        has_vtables = true;
        istringstream parser(line);
        uint64_t vtable_addr = 0;
        uint64_t vtable_entry = 0;
        int offset_to_top = 0;

        parser >> hex >> vtable_addr;
        if(parser.fail()) {
            return false;
        }

        parser >> dec >> offset_to_top;
        if(parser.fail()) {
            return false;
        }

        VTable vtable;
        vtable.addr = vtable_addr;
        vtable.offset_to_top = offset_to_top;
        vtable.module_name = module_name;

        // NOTE: Index is a unique identifier for all vtables in all modules.
        vtable.index = _index;

        while(parser >> hex >> vtable_entry) {
            if(parser.fail()) {
                return false;
            }

            vtable.entries.push_back(vtable_entry);
        }

        _vtables.push_back(vtable);
        assert(_vtables[_index].module_name == vtable.module_name
               && _vtables[_index].addr == vtable.addr
               && _vtables[_index].index == vtable.index
               && "Index of vtable and index in vector are not the same.");

        _index++;
    }

    // Only add module to managed modules if it has at least one vtable.
    if(has_vtables) {
        _managed_modules.insert(module_name);
    }

    return true;
}


const VTableMap& VTableFile::get_this_vtables() const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    return *(_module_vtables_map.at(_this_module_name));
}


const VTableMap& VTableFile::get_vtables(const string &module_name) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    if(_module_vtables_map.find(module_name) == _module_vtables_map.cend()) {
        throw runtime_error("VTableFile object does not know module name.");
    }

    return *(_module_vtables_map.at(module_name));
}


const VTableVector& VTableFile::get_all_vtables() const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    return _vtables;
}


void VTableFile::finalize() {

    // Make sure that we only finalize this object once.
    if(_is_finalized) {
        throw runtime_error("VTableFile object was already finalized.");
    }
    _is_finalized = true;

    if(_managed_modules.find(_this_module_name) == _managed_modules.cend()) {
        throw runtime_error("VTableFile object has no data for the "\
                            "module to analyze.");
    }

    // Build up a vector that contains a mapping for each module
    // that maps from vtable address to vtable object.
    uint32_t idx = 0;
    for(auto &module_it : _managed_modules) {
        for(auto &vtbl_it : _vtables) {
            if(vtbl_it.module_name != module_it) {
                continue;
            }

            if(_module_vtables.size() <= idx) {
                VTableMap temp;
                temp[vtbl_it.addr] = &vtbl_it;
                _module_vtables.push_back(temp);
            }
            else {
                _module_vtables[idx][vtbl_it.addr] = &vtbl_it;
            }
        }
        idx++;
    }

    // Build up a mapping that maps a module name to its vtable address
    // to vtable object map.
    idx = 0;
    for(auto &module_it : _managed_modules) {
        _module_vtables_map[module_it] = &_module_vtables[idx];
        idx++;
    }

    // Sanity check if module mapping is completely correct
    // (Added for now to exclude this as error source)
    for(auto &module_it : _managed_modules) {
        const auto &vtable_map = *(_module_vtables_map.at(module_it));
        for(const auto &vtbl_kv : vtable_map) {
            if(vtbl_kv.second->module_name != module_it) {
                throw runtime_error("Error while finalizing vtable mapping.");
            }
        }
    }

    return;
}


bool VTableFile::is_finalized() const {
    return _is_finalized;
}


const VTable* VTableFile::get_vtable_ptr(const std::string &module_name,
                                        uint64_t addr) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    if(_module_vtables_map.at(module_name)->find(addr)
            != _module_vtables_map.at(module_name)->cend()) {

        return (_module_vtables_map.at(module_name)->at(addr));
    }
    return nullptr;
}


const VTable& VTableFile::get_vtable(const std::string &module_name,
                                     uint64_t addr) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    return *(_module_vtables_map.at(module_name)->at(addr));

}


const VTable& VTableFile::get_vtable(uint32_t index) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("VTableFile object was not finalized.");
    }

    if(_vtables.size() <= index) {
        throw runtime_error("Vtable index is out of range.");
    }

    return _vtables[index];
}
