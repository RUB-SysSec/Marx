
#include "external_functions.h"


using namespace std;


bool ExternalFunctions::is_finalized() const {
    return _is_finalized;
}


bool ExternalFunctions::parse(const string &funcs_file) {

    // Make sure that we parse files only if object was not finalized yet.
    if(_is_finalized) {
        throw runtime_error("Parse attempt after ExternalFunctions object was"\
                            " finalized.");
    }

    ifstream file(funcs_file + "_funcs.txt");
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

    while(getline(file, line)) {
        istringstream parser(line);
        uint64_t func_addr = 0;
        string func_name;

        parser >> hex >> func_addr;
        if(parser.fail()) {
            return false;
        }

        parser >> func_name;
        if(parser.fail()) {
            return false;
        }

        ExternalFunction func;
        func.addr = func_addr;
        func.name = func_name;
        func.module_name = module_name;

        // NOTE: Index is a unique identifier for all functions in all
        // external modules.
        func.index = _index;

        _external_functions.push_back(func);
        assert(_external_functions[_index].module_name == func.module_name
               && _external_functions[_index].addr == func.addr
               && _external_functions[_index].name == func.name
               && _external_functions[_index].index == func.index
               && "Index of function and index in vector are not the same.");

        _index++;
    }

    return true;
}


void ExternalFunctions::finalize() {

    // Make sure that we only finalize this object once.
    if(_is_finalized) {
        throw runtime_error("ExternalFunctions object was already finalized.");
    }
    _is_finalized = true;

    // Build external functions map for this module.
    for(auto &it : _external_functions) {
        _external_functions_map[it.name] = &it;
    }

    return;
}


const ExternalFunction* ExternalFunctions::get_external_function(
        const string &name) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("ExternalFunctions object was not finalized.");
    }

    if(_external_functions_map.find(name) == _external_functions_map.cend()) {
        return nullptr;
    }
    return _external_functions_map.at(name);
}


const ExternalFunction* ExternalFunctions::get_external_function(
        const std::string &module_name,
        uint64_t func_addr) const {

    // Make sure that the object is finalized.
    if(!_is_finalized) {
        throw runtime_error("ExternalFunctions object was not finalized.");
    }

    for(const auto &it : _external_functions) {
        if(it.module_name == module_name
            && it.addr == func_addr) {
            return &it;
        }
    }
    return nullptr;
}
