#ifndef VTABLE_FILE_H
#define VTABLE_FILE_H

#include <map>
#include <set>
#include <unordered_set>
#include <vector>
#include <string>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cassert>

/*!
 * \brief Structure containing information about a vtable stored in the
 * `_vtables.txt` file.
 */
struct VTable {
    uint32_t index;
    uint64_t addr;
    int offset_to_top;
    std::vector<uint64_t> entries;
    std::string module_name;
};


typedef std::map<uint64_t, VTable*> VTableMap;
typedef std::vector<VTable> VTableVector;
typedef std::map<std::string, VTableMap*> VTableModulesMap;
typedef std::vector<VTableMap> VTableModulesVector;


/*!
 * \brief Class collecting the information that was produced by the IDA
 * exporting script.
 *
 * For a given `_vtables.txt` file (produced by the exporter).
 */
class VTableFile {
private:
    VTableVector _vtables;
    VTableModulesVector _module_vtables;
    VTableModulesMap _module_vtables_map;
    std::set<std::string> _managed_modules;
    uint32_t _index;

    std::string _this_module_name;
    bool _is_finalized = false;

public:
    VTableFile(const std::string &this_module_name);


    /*!
     * \brief Returns all known vtables for this module.
     * \return Returns a `map` with all known vtables (address as key,
     * `Vtable` struct as value) for the current module.
     */
    const VTableMap& get_this_vtables() const;


    /*!
     * \brief Returns all known vtables for the given module.
     * \return Returns a `map` with all known vtables (address as key,
     * `Vtable` struct as value) for the given module.
     */
    const VTableMap& get_vtables(const std::string &module_name) const;


    /*!
     * \brief Returns all known vtables.
     * \return Returns a `vector` with all known vtables.
     */
    const VTableVector& get_all_vtables() const;


    /*!
     * \brief Parses a given vtable file and builds internal vtable structure.
     */
    bool parse(const std::string &vtables_file);


    /*!
     * \brief Finalizes the vtable structures.
     *
     * This function finalizes the vtable structures. It can only be used
     * once all vtable files are imported via the `parse` function.
     * After `finalize` was executed, no changes to the vtable structures
     * are possible.
     */
    void finalize();


    /*!
     * \brief Returns `true` if the vtable structure is finalized.
     * \return Returns `true` if the vtable structure is finalized.
     */
    bool is_finalized() const;


    /*!
     * \brief Returns a vtable object given by module name and address.
     * \return Returns a vtable object.
     */
    const VTable& get_vtable(const std::string &module_name, uint64_t addr)
        const;


    /*!
     * \brief Returns a vtable object given by its index.
     * \return Returns a vtable object.
     */
    const VTable& get_vtable(uint32_t index) const;


    /*!
     * \brief Returns a vtable object given by module name and address.
     * \return Returns a vtable object pointer or nullptr if object does
     * not exist.
     */
    const VTable* get_vtable_ptr(const std::string &module_name,
                                             uint64_t addr) const;

};

#endif // VTABLE_FILE_H
