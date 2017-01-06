#include "idata.h"

using namespace std;

IDataMap import_idata(const string &target_file) {

    ifstream file(target_file + "_idata.txt");
    if(!file) {
        throw runtime_error("Opening .idata file failed.");
    }

    string line;

    // Parse first line manually.
    getline(file, line);
    istringstream header_parser(line);

    // First entry of file is always the module name.
    string import_module_name;
    header_parser >> import_module_name;
    if(header_parser.fail()) {
        throw runtime_error("Parsing .idata file failed.");
    }

    IDataMap idata_map;

    while(getline(file, line)) {
        istringstream parser(line);
        uint64_t idata_entry_addr = 0;
        string idata_entry_content;

        parser >> hex >> idata_entry_addr;
        if(parser.fail()) {
            throw runtime_error("Parsing .idata file failed.");
        }

        parser >> idata_entry_content;
        if(parser.fail()) {
            throw runtime_error("Parsing .idata file failed.");
        }

        idata_map[idata_entry_addr] = idata_entry_content;
    }

    return idata_map;
}
