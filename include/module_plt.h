#ifndef MODULE_PLT_H
#define MODULE_PLT_H

#include <fstream>
#include <sstream>
#include <iostream>
#include <map>


struct PltEntry {
    uint64_t addr;
    std::string func_name;
};


typedef std::map<uint64_t, PltEntry> PltMap;


class ModulePlt {

    const std::string &_module_name;
    PltMap _plt_entries;

private:

public:
    ModulePlt(const std::string &module_name);


    /*!
     * \brief Parses the .plt entries file for the given module.
     */
    bool parse(const std::string &plt_file);


    /*!
     * \brief Returns a pointer to the plt entry given by the address.
     * \return Returns a pointer to the plt entry given by the address
     * or null if it was not found.
     */
    const PltEntry* get_plt_entry(uint64_t addr) const;


    /*!
     * \brief Returns a pointer to the plt entry given by the function name.
     * \return Returns a pointer to the plt entry given by the address
     * or null if it was not found.
     */
    const PltEntry* get_plt_entry(const std::string func_name) const;

};

#endif // MODULE_PLT_H
