
#include "vtable_update.h"


using namespace std;

#define DEBUG_PRINT_UPDATES 0

FctVTableUpdates::FctVTableUpdates(VTableFile &vtable_file,
                                   const string &module_name)
    : _vtable_file(vtable_file),
      _module_name(module_name) {

}


void FctVTableUpdates::add_vtable_updates(uint64_t fct_addr,
                                         const VTableUpdates &vtable_updates) {
    lock_guard<mutex> _(_mtx);

    if(_this_vtable_updates.find(fct_addr) == _this_vtable_updates.cend()) {
        _this_vtable_updates[fct_addr] = vtable_updates;
    }
    else {
        for(const auto &it : vtable_updates) {
            _this_vtable_updates[fct_addr].push_back(it);
        }
    }
}


void FctVTableUpdates::export_vtable_updates(const string &target_dir) {
    lock_guard<mutex> _(_mtx);

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << ".vtableupdates";
    string target_file = temp_str.str();

    ofstream update_file;
    update_file.open(target_file);

    update_file << _module_name << endl;

    for(const auto &it : _this_vtable_updates) {
        uint64_t fct_addr = it.first;

        // Get all vtable updates that can be exported.
        VTableUpdates exportable_vtable_updates;
        for(const auto &vtable_update : it.second) {

            // Convert base expression ptr to string for export.
            ExpressionPtr base = vtable_update.base;
            string base_str;
            if(!convert_expression_str(base, base_str)) {
                continue;
            }
            exportable_vtable_updates.push_back(vtable_update);
        }

        // Ignore functions that do not have any vtable updates.
        if(exportable_vtable_updates.size() == 0) {
            continue;
        }

        update_file << hex << fct_addr
                    << " ";

        // Export all vtable updates for this function.
        for(const auto &vtable_update : exportable_vtable_updates) {

            // Convert base expression ptr to string for export.
            ExpressionPtr base = vtable_update.base;
            string base_str;
            if(!convert_expression_str(base, base_str)) {
                throw runtime_error("Not able to convert vtable update base"\
                                    "to string.");
            }

            const VTable &vtable = _vtable_file.get_vtable(vtable_update.index);
            uint64_t vtable_addr = vtable.addr;
            const string module_name = vtable.module_name;
            size_t offset = vtable_update.offset;

            update_file << module_name
                        << ":"
                        << hex << vtable_addr
                        << ":"
                        << base_str
                        << ":"
                        << dec << offset
                        << " ";

#if DEBUG_PRINT_UPDATES
            cout << "Fct Addr: 0x" << hex << fct_addr << endl;
            cout << "Module Name: " << module_name << endl;
            cout << "VTable Addr: 0x" << hex << vtable_addr << endl;
            cout << "Base: " << base_str << endl;
            cout << "Offset: 0x" << hex << offset << endl;
#endif

        }
        update_file << endl;
    }
    update_file.close();
}


// Convert expression to string (only consider System V argument register
// for now).
bool FctVTableUpdates::convert_expression_str(ExpressionPtr base,
                                              string &base_str) {

    if(*_rdi == *base) {
        base_str = "RDI";
    }
    else if(*_rsi == *base) {
        base_str = "RSI";
    }
    else if(*_rdx == *base) {
        base_str = "RDX";
    }
    else if(*_rcx == *base) {
        base_str = "RCX";
    }
    else if(*_r8 == *base) {
        base_str = "R8";
    }
    else if(*_r9 == *base) {
        base_str = "R9";
    }
    else {
        return false;
    }

    return true;
}


// Convert string to expression (only consider System V argument register
// for now).
bool FctVTableUpdates::convert_str_expression(const string &base_str,
                                              ExpressionPtr &base) {

    if("RDI" == base_str) {
        base = _rdi;
    }
    else if("RSI" == base_str) {
        base = _rsi;
    }
    else if("RDX" == base_str) {
        base = _rdx;
    }
    else if("RCX" == base_str) {
        base = _rcx;
    }
    else if("R8" == base_str) {
        base = _r8;
    }
    else if("R9" == base_str) {
        base = _r9;
    }
    else {
        return false;
    }

    return true;
}


const VTableUpdates* FctVTableUpdates::get_vtable_updates(
                                        const string &module_name,
                                        uint64_t fct_addr) const {
    lock_guard<mutex> _(_mtx);

    // Differentiate between the module that is currently analyzed and
    // the imported modules.
    if(_module_name == module_name) {
        if(_this_vtable_updates.find(fct_addr) == _this_vtable_updates.cend()) {
            return nullptr;
        }
        const VTableUpdates *temp = &(_this_vtable_updates.at(fct_addr));
        return temp;
    }

    if(_external_vtable_updates.find(module_name) ==
            _external_vtable_updates.cend()) {
        return nullptr;
    }
    const VTableUpdatesMap &vtable_updates_map =
            _external_vtable_updates.at(module_name);

    if(vtable_updates_map.find(fct_addr) == vtable_updates_map.cend()) {
        return nullptr;
    }
    const VTableUpdates *temp = &(vtable_updates_map.at(fct_addr));
    return temp;
}


void FctVTableUpdates::import_updates(const string &target_file) {
    lock_guard<mutex> _(_mtx);

    ifstream file(target_file + ".vtableupdates");
    if(!file) {
        throw runtime_error("Opening vtable update file failed.");
    }

    VTableUpdatesMap vtable_updates_map;
    string line;

    // Parse first line manually.
    getline(file, line);
    istringstream header_parser(line);

    // First entry of file is always the module name.
    string import_module_name;
    header_parser >> import_module_name;
    if(header_parser.fail()) {
        throw runtime_error("Parsing vtable update file failed.");
    }

    // Parse each vtable update line which is given in the following form:
    // <fct_addr_hex> <vtable_update_entry_1> ... <vtable_update_entry_n>
    while(getline(file, line)) {
        istringstream parser(line);
        string update_entry;
        VTableUpdates imported_updates;

        uint64_t fct_addr;
        parser >> hex >> fct_addr;
        if(parser.fail()) {
            throw runtime_error("Parsing vtable update file failed.");
        }

        // Parse each vtable update entry which is given in the following form:
        // <module_name>:<vtable_addr_hex>:<arg_reg>:<offset_dec>
        while(parser >> update_entry) {
            if(parser.fail()) {
                throw runtime_error("Parsing vtable update file failed.");
            }

            string module_name;
            string vtable_addr_str;
            string arg_reg_str;
            string offset_str;
            uint64_t vtable_addr;
            size_t offset;

            istringstream parser_entry(update_entry);
            if(parser_entry.fail()) {
                throw runtime_error("Parsing vtable update file failed.");
            }
            getline(parser_entry, module_name, ':');
            getline(parser_entry, vtable_addr_str, ':');
            getline(parser_entry, arg_reg_str, ':');
            getline(parser_entry, offset_str, ':');

            istringstream parser_vtable_addr(vtable_addr_str);
            if(parser_vtable_addr.fail()) {
                throw runtime_error("Parsing vtable update file failed.");
            }
            parser_vtable_addr >> hex >> vtable_addr;

            istringstream parser_offset(offset_str);
            if(parser_offset.fail()) {
                throw runtime_error("Parsing vtable update file failed.");
            }
            parser_offset >> dec >> offset;

            // Convert read data into the local data structure.
            const VTable &vtable = _vtable_file.get_vtable(module_name,
                                                           vtable_addr);

            ExpressionPtr base;
            if(!convert_str_expression(arg_reg_str, base)) {
                throw runtime_error("Parsing vtable update file failed.");
            }

            VTableUpdate vtable_update;
            vtable_update.index = vtable.index;
            vtable_update.offset = offset;
            vtable_update.base = base;
            imported_updates.push_back(vtable_update);
        }
        vtable_updates_map[fct_addr] = imported_updates;
    }

    _external_vtable_updates[import_module_name] = vtable_updates_map;
}
