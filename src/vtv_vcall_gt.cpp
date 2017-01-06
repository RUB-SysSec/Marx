#include "vtv_vcall_gt.h"

using namespace std;


VTVVcallsFile::VTVVcallsFile(const string &module_name)
    : _module_name(module_name) {}


void VTVVcallsFile::add_vtv_vcalls(const VTVVcalls &vtv_vcalls) {

    for(const auto &it : vtv_vcalls) {
        uint64_t verify_addr = it.second.addr_verify_call;
        if(_vtv_vcalls.find(verify_addr) != _vtv_vcalls.cend()) {
            for(uint64_t it_addr : it.second.addr_vcalls) {
                _vtv_vcalls[verify_addr].addr_vcalls.insert(it_addr);
            }
        }
        else {
            VTVVcall temp;
            temp.addr_verify_call = verify_addr;
            temp.vtbl_obj = nullptr;
            temp.addr_vcalls = it.second.addr_vcalls;
            _vtv_vcalls[verify_addr] = temp;
        }
    }
}


void VTVVcallsFile::export_vtv_vcalls(const string &target_dir) {

    stringstream temp_str;
    temp_str << target_dir << "/" << _module_name << ".vtv_vcalls";
    string target_file = temp_str.str();

    ofstream vtv_file;
    vtv_file.open(target_file);

    vtv_file << _module_name << endl;

    for(const auto &it_vtv : _vtv_vcalls) {
        vtv_file << hex << it_vtv.second.addr_verify_call;

        for(uint64_t vcall_addr : it_vtv.second.addr_vcalls) {
            vtv_file << " " << hex << vcall_addr;
        }
        vtv_file << endl;
    }

    vtv_file.close();
}


const VTVVcalls& VTVVcallsFile::get_vtv_vcalls() const {
    return _vtv_vcalls;
}
