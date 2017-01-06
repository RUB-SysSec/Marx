#ifndef VTABLE_UPDATE_H
#define VTABLE_UPDATE_H

#include "expression.h"
#include "state.h"
#include "vtable_file.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>

#define arg_out

/*!
 * \brief Structure containing information about a vtable overwrite
 * found during the analysis.
 */
struct VTableUpdate {
    size_t offset;
    ExpressionPtr base;
    uint32_t index;
};


typedef std::vector<VTableUpdate> VTableUpdates;
typedef std::map<uint64_t, VTableUpdates> VTableUpdatesMap;
typedef std::map<std::string, VTableUpdatesMap> VTableUpdatesModuleMap;


class FctVTableUpdates {
private:

    // VTable updates made by functions of this module.
    VTableUpdatesMap _this_vtable_updates;
    VTableUpdatesModuleMap _external_vtable_updates;

    VTableFile &_vtable_file;
    const std::string &_module_name;

    mutable std::mutex _mtx;

    ExpressionPtr _rdi = State::initial_values().at(OFFB_RDI);
    ExpressionPtr _rsi = State::initial_values().at(OFFB_RSI);
    ExpressionPtr _rdx = State::initial_values().at(OFFB_RDX);
    ExpressionPtr _rcx = State::initial_values().at(OFFB_RCX);
    ExpressionPtr _r8 = State::initial_values().at(OFFB_R8);
    ExpressionPtr _r9 = State::initial_values().at(OFFB_R9);

    bool convert_expression_str(ExpressionPtr base,
                                arg_out std::string &base_str);

    bool convert_str_expression(const std::string &base_str,
                                arg_out ExpressionPtr &base);

public:

    FctVTableUpdates(VTableFile &vtable_file,
                     const std::string &module_name);


    /*!
     * \brief Adds vtable updates for the given function.
     */
    void add_vtable_updates(uint64_t fct_addr,
                           const VTableUpdates &vtable_updates);


    /*!
     * \brief Exports the vtable updates that are done by this module.
     */
    void export_vtable_updates(const std::string &target_dir);


    /*!
     * \brief Returns all vtable updates made by a function of a
     * specific module.
     * \return Returns all vtable updates made by a function of a
     * specific module.
     */
    const VTableUpdates* get_vtable_updates(const std::string &module_name,
                                            uint64_t fct_addr) const;


    /*!
     * \brief Imports a vtable update from file,
     * adds it to the current vtable updates.
     */
    void import_updates(const std::string &target_file);

};

#endif // VTABLE_UPDATE_H
