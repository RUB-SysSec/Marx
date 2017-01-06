#ifndef VCALL_H
#define VCALL_H

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>

#include "vcall_types.h"
#include "vtable_hierarchy.h"
#include "vtable_file.h"

class VCallFile {
private:
    VCalls _vcalls;
    PossibleVCalls _possible_vcalls;

    const std::string &_module_name;

    const VTableHierarchies &_vtable_hierarchies;
    const VTableFile &_vtable_file;

    mutable std::mutex _mtx;

public:

    VCallFile(const std::string &module_name,
              const VTableHierarchies &vtable_hierarchies,
              const VTableFile &vtable_file);

    /*!
     * \brief Returns the found virtual callsites.
     * \return Returns the found virtual callsites.
     */
    const VCalls& get_vcalls() const;


    void add_vcall(uint64_t addr, uint32_t index, size_t entry_index);


    void add_possible_vcall(uint64_t addr);


    void export_vcalls(const std::string &target_dir);
};




#endif
