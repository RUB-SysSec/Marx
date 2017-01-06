#include "got.h"

using namespace std;

GotMap import_got(const string &target_file) {

    ifstream file(target_file + "_got.txt");
    if(!file) {
        throw runtime_error("Opening .got file failed.");
    }

    string line;

    // Parse first line manually.
    getline(file, line);
    istringstream header_parser(line);

    // First entry of file is always the module name.
    string import_module_name;
    header_parser >> import_module_name;
    if(header_parser.fail()) {
        throw runtime_error("Parsing .got file failed.");
    }

    GotMap got_map;

    while(getline(file, line)) {
        istringstream parser(line);
        uint64_t got_entry_addr = 0;
        uint64_t got_entry_content = 0;

        parser >> hex >> got_entry_addr;
        if(parser.fail()) {
            throw runtime_error("Parsing .got file failed.");
        }

        parser >> hex >> got_entry_content;
        if(parser.fail()) {
            throw runtime_error("Parsing .got file failed.");
        }

        got_map[got_entry_addr] = got_entry_content;
    }

    return got_map;
}
