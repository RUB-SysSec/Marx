
#include "return_value.h"


using namespace std;


FctReturnValuesFile::FctReturnValuesFile(const string &module_name,
                                         const VTableFile &vtable_file,
                                         const ModulePlt &module_plt,
                                         const ExternalFunctions &external_funcs)
    : _module_name(module_name),
      _vtable_file(vtable_file),
      _module_plt(module_plt),
      _external_funcs(external_funcs) {

}


void FctReturnValuesFile::add_return_value(uint64_t func_addr,
                                           const ReturnValue &return_value) {
    lock_guard<mutex> _(_mtx);

    if(_return_values_map.find(func_addr) == _return_values_map.cend()) {
        FctReturnValues temp;
        temp.func_addr = func_addr;
        temp.return_values.push_back(return_value);
        _return_values_map[func_addr] = temp;
    }

    else {
        FctReturnValues &temp = _return_values_map[func_addr];

        for(const auto &it : temp.return_values) {
            if(it.func_addr == return_value.func_addr
                && *(it.content) == *(return_value.content)) {
                return;
            }
        }

        // TODO
        // Check if return value does already exist.
        temp.return_values.push_back(return_value);
    }
}


void FctReturnValuesFile::add_active_vtable(uint64_t func_addr,
                                            const VTableActive &active_vtable) {
    lock_guard<mutex> _(_mtx);

    if(_return_values_map.find(func_addr) == _return_values_map.cend()) {
        FctReturnValues temp;
        temp.func_addr = func_addr;
        temp.active_vtables.push_back(active_vtable);
        _return_values_map[func_addr] = temp;
    }

    else {
        FctReturnValues &temp = _return_values_map[func_addr];

        // TODO
        // Check if active vtable does already exist.
        temp.active_vtables.push_back(active_vtable);
    }
}


void FctReturnValuesFile::export_return_values(const string &target_dir) {
    lock_guard<mutex> _(_mtx);

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << ".ret_values";
    string target_file = temp_str.str();

    ofstream ret_file;
    ret_file.open(target_file, ios::out|ios::binary);

    // First entry of file is always the module name.
    ret_file.write(_module_name.c_str(), _module_name.length() + 1);

    for(const auto &kv : _return_values_map) {
        // Write function address.
        ret_file.write(reinterpret_cast<const char *>(&kv.first),
                       sizeof(kv.first));

        uint32_t number = kv.second.return_values.size();
        ret_file.write(reinterpret_cast<const char *>(&number),
                       sizeof(number));
        for(const auto &it : kv.second.return_values) {
            serialize(it.content, ret_file);
        }

        number = kv.second.active_vtables.size();
        ret_file.write(reinterpret_cast<const char *>(&number),
                       sizeof(number));
        for(const auto &it : kv.second.active_vtables) {

            serialize(it.vtbl_ptr_loc, ret_file);

            const VTable &vtable = _vtable_file.get_vtable(it.index);

            // Write actual vtable representation to file.
            // Length + 1 to have \0 at the end.
            ret_file.write(vtable.module_name.c_str(),
                         vtable.module_name.length() + 1);
            ret_file.write(reinterpret_cast<const char *>(&vtable.addr),
                         sizeof(vtable.addr));
        }
    }

    ret_file.close();
}


void FctReturnValuesFile::import_ext_return_values(const string &module_file) {
    lock_guard<mutex> _(_mtx);

    // Make sure that the object is finalized.
    if(_is_finalized) {
        throw runtime_error("FctReturnValuesFile object is finalized.");
    }

    ifstream ret_file(module_file + ".ret_values", ios::in|ios::binary);
    if(!ret_file) {
        throw runtime_error("Could not open return values file.");
    }

    // First entry of file is always the module name.
    string import_module_name;
    // Read C-like string.
    getline(ret_file, import_module_name, '\0');

    while(!ret_file.eof()) {

        uint64_t func_addr;
        ret_file.read(reinterpret_cast<char *>(&func_addr),
                       sizeof(func_addr));

        // EOF is only present after first read instruction that does
        // reach it.
        if(ret_file.eof()) {
            break;
        }

        FctReturnValues func_ret_values;

        uint32_t number;
        ret_file.read(reinterpret_cast<char *>(&number),
                       sizeof(number));

        for(uint32_t i = 0; i < number; i++) {
            ReturnValue ret_value;
            ret_value.content = unserialize(ret_file);
            ret_value.func_addr = 0;
            func_ret_values.return_values.push_back(ret_value);
        }

        ret_file.read(reinterpret_cast<char *>(&number),
                       sizeof(number));

        for(uint32_t i = 0; i < number; i++) {

            VTableActive act_vtable;
            act_vtable.from_callee = true;
            act_vtable.from_caller = false;
            act_vtable.vtbl_ptr_loc = unserialize(ret_file);

            string vtbl_module_name;
            // Read C-like string.
            getline(ret_file, vtbl_module_name, '\0');

            uint64_t vtable_addr;
            ret_file.read(reinterpret_cast<char *>(&vtable_addr),
                           sizeof(vtable_addr));
            const VTable &vtable = _vtable_file.get_vtable(vtbl_module_name,
                                                           vtable_addr);
            act_vtable.index = vtable.index;
            func_ret_values.active_vtables.push_back(act_vtable);
        }

        // Get corresponding function of return value.
        const ExternalFunction *ext_func;
        ext_func = _external_funcs.get_external_function(import_module_name,
                                                         func_addr);
        if(ext_func == nullptr) {
            throw runtime_error("Imported return value does not belong "\
                                "to a function.");
        }

        // Add external return value.
        ExternalFctReturnValues ext_ret_value;
        ext_ret_value.func_return_values = func_ret_values;
        ext_ret_value.ext_func = ext_func;
        _ext_return_values.push_back(ext_ret_value);
    }

    ret_file.close();
}


const FctReturnValues* FctReturnValuesFile::get_plt_return_values_ptr(
                                                        uint64_t addr) const {
    lock_guard<mutex> _(_mtx);
    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("FctReturnValuesFile object was not finalized.");
    }

    if(_plt_return_values_ptr_map.find(addr)
                                    != _plt_return_values_ptr_map.cend()) {
        return _plt_return_values_ptr_map.at(addr);
    }
    return nullptr;
}


const FctReturnValues* FctReturnValuesFile::get_ext_return_values_ptr(
                                                 const string &module_name,
                                                 uint64_t func_addr) const {
    lock_guard<mutex> _(_mtx);
    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("FctReturnValuesFile object was not finalized.");
    }

    for(const auto &it : _ext_return_values) {
        if(it.ext_func->addr == func_addr
            && it.ext_func->module_name == module_name) {
            return &(it.func_return_values);
        }
    }
    return nullptr;
}


ExtReturnValues FctReturnValuesFile::get_return_values() const {
    lock_guard<mutex> _(_mtx);

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("FctReturnValuesFile object was not finalized.");
    }

    return _ext_return_values;
}


bool FctReturnValuesFile::is_finalized_ext_return_values() const {
    lock_guard<mutex> _(_mtx);
    return _is_finalized;
}


void FctReturnValuesFile::finalize_ext_return_values() {
    lock_guard<mutex> _(_mtx);

    // Make sure that the object is finalized.
    if(_is_finalized) {
        throw runtime_error("FctReturnValuesFile object is finalized.");
    }

    // Set up a map that contains only pointer to .plt entry return values
    for(uint32_t i = 0; i < _ext_return_values.size(); i++) {
        ExternalFctReturnValues &ext_ret_value = _ext_return_values[i];

        const PltEntry *plt_entry;
        plt_entry = _module_plt.get_plt_entry(ext_ret_value.ext_func->name);
        if(plt_entry == nullptr) {
            continue;
        }

        // Use the plt address as function address for the return value.
        ext_ret_value.func_return_values.func_addr = plt_entry->addr;

        // Set all function addresses of the return values to the plt entry.
        for(auto &it : ext_ret_value.func_return_values.return_values) {
            it.func_addr = plt_entry->addr;
        }

        _plt_return_values_ptr_map[plt_entry->addr] =
                                            &(ext_ret_value.func_return_values);
    }

    _is_finalized = true;
}
