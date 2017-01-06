
#include "module_plt.h"


using namespace std;


ModulePlt::ModulePlt(const string &module_name)
    : _module_name(module_name) {

}


bool ModulePlt::parse(const string &plt_file) {

    ifstream file(plt_file + "_plt.txt");
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

    // Only allow to parse a .plt file for this module.
    if(_module_name != module_name) {
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

        PltEntry plt_entry;
        plt_entry.addr = func_addr;
        plt_entry.func_name = func_name;

        _plt_entries[func_addr] = plt_entry;
    }

    return true;
}


const PltEntry* ModulePlt::get_plt_entry(uint64_t addr) const {
    if(_plt_entries.find(addr) == _plt_entries.cend()) {
        return nullptr;
    }
    return &(_plt_entries.at(addr));
}


const PltEntry* ModulePlt::get_plt_entry(const string func_name) const {
    for(const auto &kv : _plt_entries) {
        if(kv.second.func_name == func_name) {
            return &(kv.second);
        }
    }
    return nullptr;
}
