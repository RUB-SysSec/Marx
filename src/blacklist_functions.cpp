#include "blacklist_functions.h"

using namespace std;

const BlacklistFuncsSet import_blacklist_funcs(const string &target_file) {

    ifstream file(target_file + "_funcs_blacklist.txt");
    if(!file) {
        throw runtime_error("Opening function blacklist file failed.");
    }

    string line;

    // Parse first line manually.
    getline(file, line);
    istringstream header_parser(line);

    // First entry of file is always the module name.
    string import_module_name;
    header_parser >> import_module_name;
    if(header_parser.fail()) {
        throw runtime_error("Parsing function blacklist file failed.");
    }

    BlacklistFuncsSet blacklist_set;

    while(getline(file, line)) {
        istringstream parser(line);
        uint64_t func_addr = 0;

        parser >> hex >> func_addr;
        if(parser.fail()) {
            throw runtime_error("Parsing function blacklist file failed.");
        }

        blacklist_set.insert(func_addr);
    }

    return blacklist_set;
}
