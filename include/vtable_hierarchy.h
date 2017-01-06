#ifndef VTABLE_HIERARCHY_H
#define VTABLE_HIERARCHY_H

#include "vtable_file.h"
#include "vtable_update.h"
#include "external_functions.h"
#include "module_plt.h"
#include "state.h"
#include "vcall_types.h"
#include "blacklist_functions.h"

#include <set>
#include <cassert>
#include <cstring>
#include <vector>
#include <mutex>


typedef std::set<uint32_t> DependentVTables;
typedef std::vector<DependentVTables> HierarchiesVTable;


#define DEBUG_WRITE_HIERARCHY_STEPS 0
#define DEBUG_PRINT_DEPENDENCIES 0
#define DEBUG_SEARCH_MERGING_REASON 0
#define DEBUG_SEARCH_MERGING_VTABLE_ADDR_1 0xdb3148
#define DEBUG_SEARCH_MERGING_VTABLE_ADDR_2 0xf0a000


/*!
 * \brief Class holding the information about the extracted hierarchy.
 *
 * Holding the internal structure of the extracted hierarchy. Can import
 * already found hierarchies and add it to its structure (makes it possible
 * to analyze binaries in an iterative manner). Found hierarchy can be
 * exported into a `.hierarchy` file for further usage.
 */
class VTableHierarchies {
private:
    HierarchiesVTable _hierarchies;
    const FileFormatType _file_format;
    const VTableFile &_vtable_file;
    const VTableMap &_this_vtables;
    const std::string &_module_name;

    const ExternalFunctions &_external_funcs;
    const ModulePlt &_module_plt;

    const BlacklistFuncsSet &_funcs_blacklist;

    // Only needed for debugging.
    const int _thread_id;

#if DEBUG_WRITE_HIERARCHY_STEPS
    std::ofstream hierarchy_steps_file;
#endif

    void merge_hierarchies_priv();

    bool get_vtable_dependencies(const VTableUpdates &vtable_updates,
                                 const ExpressionPtr &base_base,
                                 uint32_t base_index,
                                 size_t base_offset);

    bool get_sub_vtable_dependencies(const VTableUpdates &vtable_updates,
                                     const ExpressionPtr &sub_base,
                                     uint32_t sub_index,
                                     size_t sub_offset);

    bool extract_vtable_dependencies(const VTableUpdates &vtable_updates);

    bool add_to_hierarchy(uint32_t vtable_1_idx,
                          uint32_t vtable_2_idx);

    void update_hierarchy_priv(uint32_t vtable_1_idx,
                               uint32_t vtable_2_idx,
                               bool merge_hierarchy);

public:
    VTableHierarchies(const FileFormatType file_format,
                      const VTableFile &vtable_file,
                      const std::string &module_name,
                      const ExternalFunctions &external_funcs,
                      const ModulePlt &module_plt,
                      const BlacklistFuncsSet &funcs_blacklist,
                      const int thread_id);


    /*!
     * \brief Merges the existing hierarchies if they can be merged.
     */
    void merge_hierarchies();


    /*!
     * \brief Returns the current extracted hierarchy structure.
     * \return Returns the current extracted hierarchy structure.
     */
    const HierarchiesVTable& get_hierarchies() const;


    /*!
     * \brief Updates the hierarchy structure with the new given information.
     *
     * This function uses the extracted vtable updates to update
     * the hierarchy structure. Note that it is also using the information
     * which function in which module was analyzed in order to gain
     * the vtable update information.
     */
    void update_hierarchy(const VTableUpdates &vtable_updates,
                          const std::string &module_name,
                          uint64_t func_addr,
                          bool merge_hierarchy=true);


    /*!
     * \brief Updates the hierarchy structure with the new given information.
     *
     * This function adds both vtables given by their index into a hierarchy
     * (either in a new one or existing one if a dependency is already known).
     */
    void update_hierarchy(uint32_t vtable_1_idx,
                          uint32_t vtable_2_idx,
                          bool merge_hierarchy=true);


    /*!
     * \brief Updates the hierarchy structure with the new given information.
     *
     * This function adds all vtable hierarchies into the existing hierarchies
     * (either in a new one or existing one if a dependency is already known).
     */
    void update_hierarchy(const HierarchiesVTable& vtable_hierarchies,
                          bool merge_hierarchy=true);


    /*!
     * \brief Exports the current hierarchy structure into a file.
     */
    void export_hierarchy(const std::string &target_dir);


    /*!
     * \brief Imports a hierarchy from file, adds it to the current hierarchy.
     */
    void import_hierarchy(const std::string &target_file);


    /*!
     * \brief Inter-modular check if the same function is at the same position.
     *
     * This function checks if an entry in a vtable of this module also exists
     * in a vtable of another module. If it does the vtables are considered
     * as dependent.
     */
    void entry_heuristic_inter();


    void vcall_analysis(const VCalls &vcalls);


};

#endif // VTABLE_HIERARCHY_H
