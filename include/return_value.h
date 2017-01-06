
#ifndef RETURN_VALUE_H
#define RETURN_VALUE_H

#include <vector>
#include <string>
#include <mutex>

#include "serialization.h"
#include "external_functions.h"
#include "module_plt.h"
#include "vtable_file.h"
#include "function.h"


struct VTableActive {
    Path path;
    ExpressionPtr vtbl_ptr_loc;
    uint32_t index; // Index of vtable.
    bool from_caller;
    bool from_callee;
};


struct ReturnValue {
    Path path;
    uint64_t func_addr; // Set to 0 if function not in the current module.
    ExpressionPtr content;
};


struct FctReturnValues {
    uint64_t func_addr; // Set to 0 if function not in the current module.
    std::vector<ReturnValue> return_values;
    std::vector<VTableActive> active_vtables;
};


struct ExternalFctReturnValues {
    const ExternalFunction *ext_func;
    FctReturnValues func_return_values;
};


typedef std::map<uint64_t, FctReturnValues> FctReturnValuesMap;
typedef std::map<uint64_t, FctReturnValues*> FctReturnValuesPtrMap;
typedef std::vector<ReturnValue> ReturnValues;
typedef std::vector<ExternalFctReturnValues> ExtReturnValues;


class FctReturnValuesFile {
private:

    const std::string &_module_name;
    const VTableFile &_vtable_file;
    const ModulePlt &_module_plt;
    const ExternalFunctions &_external_funcs;

    FctReturnValuesMap _return_values_map;

    FctReturnValuesPtrMap _plt_return_values_ptr_map;

    ExtReturnValues _ext_return_values;

    mutable std::mutex _mtx;

    bool _is_finalized = false;

public:

    FctReturnValuesFile(const std::string &module_name,
                        const VTableFile &vtable_file,
                        const ModulePlt &module_plt,
                        const ExternalFunctions &external_funcs);


    void add_return_value(uint64_t func_addr,
                          const ReturnValue &return_value);


    void add_active_vtable(uint64_t func_addr,
                           const VTableActive &active_vtable);


    void export_return_values(const std::string &target_dir);


    void import_ext_return_values(const std::string &module_file);


    /*!
     * \brief Returns a function return values object given by .plt address.
     * \return Returns a function return values object pointer
     * or nullptr if object does not exist.
     */
    const FctReturnValues* get_plt_return_values_ptr(uint64_t addr) const;


    /*!
     * \brief Returns a function return values object given by module name and
     * function address.
     * \return Returns a function return values object pointer
     * or nullptr if object does not exist.
     */
    const FctReturnValues* get_ext_return_values_ptr(
                                        const std::string &module_name,
                                        uint64_t func_addr) const;


    /*!
     * \brief Returns a copy of all return values objects.
     * \return Returns a copy of all return values objects.
     */
    ExtReturnValues get_return_values() const;


    /*!
     * \brief Finalizes the external return values structures.
     *
     * This function finalizes the external return values structures.
     * It can only be used
     * once all external return values files are imported via the
     * `import_ext_return_values` function.
     * After `finalize` was executed, no changes to the external return values
     * structures are possible.
     */
    void finalize_ext_return_values();


    /*!
     * \brief Returns `true` if the external return values structure is
     * finalized.
     * \return Returns `true` if the external return values structure is
     * finalized.
     */
    bool is_finalized_ext_return_values() const;

};



#endif
