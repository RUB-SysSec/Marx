#ifndef VTV_VCALL_GT_H
#define VTV_VCALL_GT_H

#include <map>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <iostream>

#include "expression.h"

struct VTVVcall {
    uint64_t addr_verify_call;
    ExpressionPtr vtbl_obj;
    std::unordered_set<uint64_t> addr_vcalls;
};

typedef std::map<uint64_t, VTVVcall> VTVVcalls;


class VTVVcallsFile {
private:

    const std::string &_module_name;

    VTVVcalls _vtv_vcalls;

public:

    VTVVcallsFile(const std::string &module_name);

    void add_vtv_vcalls(const VTVVcalls &vtv_vcalls);

    void export_vtv_vcalls(const std::string &target_dir);

    /*!
     * \brief Returns the found vtv vcalls.
     * \return Returns the found vtv vcalls.
     */
    const VTVVcalls& get_vtv_vcalls() const;
};

#endif // VTV_VCALL_GT_H
