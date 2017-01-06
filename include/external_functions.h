#ifndef EXTERNAL_FUNCTIONS_H
#define EXTERNAL_FUNCTIONS_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cassert>
#include <vector>
#include <map>


struct ExternalFunction {
    uint32_t index;
    uint64_t addr;
    std::string name;
    std::string module_name;
};


typedef std::vector<ExternalFunction> ExternalFunctionVector;
typedef std::map<std::string, ExternalFunction*> ExternalFunctionMap;



class ExternalFunctions {
private:
    ExternalFunctionVector _external_functions;
    ExternalFunctionMap _external_functions_map;
    uint32_t _index = 0;

    bool _is_finalized = false;

public:

    /*!
     * \brief Returns `true` if the external functions structure is finalized.
     * \return Returns `true` the external functions structure is finalized.
     */
    bool is_finalized() const;


    /*!
     * \brief Parses a given functions file and builds internal
     * functions structure.
     */
    bool parse(const std::string &funcs_file);


    /*!
     * \brief Finalizes the external functions structures.
     *
     * This function finalizes the external functions structures. It can only
     * be used once all external functions files are imported via the `parse`
     * function. After `finalize` was executed, no changes to the
     * external functions structures are possible.
     */
    void finalize();


    /*!
     * \brief Returns a pointer to the external function given by the name.
     * \return Returns a pointer to the external function given by the name
     * or null if it was not found.
     */
    const ExternalFunction* get_external_function(
            const std::string &name) const;


    /*!
     * \brief Returns a pointer to the external function given by the module
     * name and address.
     * \return Returns a pointer to the external function given by the name
     * or null if it was not found.
     */
    const ExternalFunction* get_external_function(
            const std::string &module_name,
            uint64_t func_addr) const;
};
















#endif // EXTERNAL_FUNCTIONS_H
