
#include <iostream>
#include <cstring>
#include <sstream>
#include <cstddef>
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include <cassert>
#include <future>
#include <condition_variable>
#include <mutex>
#include <algorithm>
#include <queue>

#include "vex.h"
#include "translator.h"

//#include "custom_analysis.h"
#include "vtable_file.h"
#include "overwrite_analysis.h"
#include "vtable_hierarchy.h"
#include "vtable_update.h"
#include "module_plt.h"
#include "external_functions.h"
#include "return_value.h"
#include "got.h"
#include "idata.h"
#include "blacklist_functions.h"
#include "new_operators.h"
#include "vtv_vcall_gt.h"

#define NUM_THREADS 4

using namespace std;
const bool on_demand = false;
queue<uint64_t> queue_func_address;
mutex queue_mtx;


struct AnalysisObjects {
    const FileFormatType file_format;
    const Memory &memory;
    const VTableFile &vtable_file;
    const VTableMap &this_vtables;
    const ModulePlt &module_plt;
    const ExternalFunctions &external_funcs;
    const unordered_set<uint64_t> &new_operators;
    const GotMap &got_map;
    const IDataMap &idata_map;
    Translator &translator;
    FctVTableUpdates &fct_vtable_updates;
    VCallFile &vcall_file;
    FctReturnValuesFile &fct_return_values;

    AnalysisObjects(const FileFormatType format,
                    const Memory &mem,
                    const VTableFile &vtbl_file,
                    const VTableMap &this_vtbls,
                    const ModulePlt &mod_plt,
                    const ExternalFunctions &ext_funcs,
                    const unordered_set<uint64_t> &new_ops,
                    const GotMap &got,
                    const IDataMap &idata,
                    Translator &trans,
                    FctVTableUpdates &fct_vtbl_updates,
                    VCallFile &vcalls,
                    FctReturnValuesFile &fct_ret_values)
                      : file_format(format),
                        memory(mem),
                        vtable_file(vtbl_file),
                        this_vtables(this_vtbls),
                        module_plt(mod_plt),
                        external_funcs(ext_funcs),
                        new_operators(new_ops),
                        got_map(got),
                        idata_map(idata),
                        translator(trans),
                        fct_vtable_updates(fct_vtbl_updates),
                        vcall_file(vcalls),
                        fct_return_values(fct_ret_values) {}
};


void analyze_fct(const string &module_name,
                 AnalysisObjects &analysis_obj,
                 VTableHierarchies *thread_vtable_hierarchies,
                 NewOperators *thread_new_operators,
                 VTVVcallsFile *thread_vtv_vcalls,
                 uint32_t thread_number) {

    while(true) {

        // Get next function that has to be analyzed.
        uint64_t func_addr;
        queue_mtx.lock();
        if(queue_func_address.empty()) {
            queue_mtx.unlock();
            break;
        }
        func_addr = queue_func_address.front();
        queue_func_address.pop();
        cout << "Remaining functions to analyze: "
             << dec << queue_func_address.size()
             << " (Thread: " << thread_number << ")"
             << endl;
        queue_mtx.unlock();

        const Function &func = analysis_obj.translator.get_function(func_addr);

        // Get a set of all vtables that have this function as virtual function.
        unordered_set<VTable*> related_vtables;
        for(const auto &vtbl_kv : analysis_obj.this_vtables) {
            const vector<uint64_t> &entries = vtbl_kv.second->entries;
            const auto pos_it = find(entries.begin(), entries.end(), func_addr);

            if(pos_it != entries.end()) {
                related_vtables.insert(vtbl_kv.second);
            }
        }

#if ACTIVATE_RETURN_HEURISTIC
        VTableUpdates return_value_heuristic;
#endif

        try {

            // If this is not a known virtual function then just
            // analyze it once.
            if(related_vtables.size() == 0) {

                cout << "Processing " << hex << func_addr << "... "
                     << " (Thread: " << thread_number << ")" << endl;

                OverwriteAnalysis overwriteAnalysis(analysis_obj.translator,
                                                    func,
                                                    analysis_obj.new_operators,
                                                    analysis_obj.vtable_file,
                                                    analysis_obj.module_plt,
                                                    analysis_obj.external_funcs,
                                                    analysis_obj.got_map,
                                                    analysis_obj.idata_map,
                                                    analysis_obj.fct_return_values,
                                                    analysis_obj.fct_vtable_updates,
                                                    analysis_obj.vcall_file,
                                                    module_name,
                                                    analysis_obj.memory.get_load_begin(),
                                                    analysis_obj.memory.get_load_end());

                overwriteAnalysis.obtain();

                // Store the vtable update results and process them after
                // all functions were analyzed.
                VTableUpdates &vtable_updates =
                        overwriteAnalysis.get_vtable_updates();

                cout << "Updating vtable hierarchy for function "
                     << hex << func_addr << "... "
                     << " (Thread: " << thread_number << ")" << endl;
                thread_vtable_hierarchies->update_hierarchy(vtable_updates,
                                                            module_name,
                                                            func_addr);

                analysis_obj.fct_vtable_updates.add_vtable_updates(func_addr,
                                                                vtable_updates);

                // Store active vtables and return values of the currently
                // analyzed function.
                const vector<ReturnValue> &ret_values = overwriteAnalysis.get_return_values();
                const vector<VTableActive> &active_vtables = overwriteAnalysis.get_active_vtables();
                for(const auto &ret_it : ret_values) {
                    for(const auto &act_it : active_vtables) {
                        if(!act_it.vtbl_ptr_loc->contains(*(ret_it.content))) {
                            continue;
                        }

                        analysis_obj.fct_return_values.add_return_value(
                                                                 func_addr, ret_it);
                        analysis_obj.fct_return_values.add_active_vtable(
                                                                 func_addr, act_it);

#if ACTIVATE_RETURN_HEURISTIC
                        // TODO: This totally ignores the offset at the moment
                        // and will overestimated.
                        VTableUpdate temp;
                        temp.offset = 0;
                        temp.index = act_it.index;
                        Symbolic temp_sym("func_return");
                        temp.base = make_shared<Symbolic>(temp_sym);
                        return_value_heuristic.push_back(temp);
#endif

                    }
                }

                // Store new operator candidates and which vtables are
                // written into the objects.
                const auto &new_op_candidates =
                                overwriteAnalysis.get_operator_new_calls();
                for(const auto &it : new_op_candidates) {
                    thread_new_operators->add_op_new_candidate(it.second);
                }

                // Store vtv vcall candidates.
                const auto &vtv_vcalls = overwriteAnalysis.get_vtv_vcalls();
                thread_vtv_vcalls->add_vtv_vcalls(vtv_vcalls);
            }

            // If function is a virtual function, set vtable as active vtable
            // in the beginning into RDI/RCX.
            // For each vtable, re-run the analysis to be context sensitive.
            else {
                uint32_t counter = 0;
                for(const auto vtable_it : related_vtables) {

                    counter++;
                    cout << "Processing " << hex << func_addr
                         << " for vtable "
                         << hex << vtable_it->addr
                         << " ("
                         << dec << counter
                         << "/"
                         << related_vtables.size()
                         << ")... "
                         << " (Thread: " << thread_number << ")" << endl;

                    OverwriteAnalysis overwriteAnalysis(analysis_obj.translator,
                                                        func,
                                                        analysis_obj.new_operators,
                                                        analysis_obj.vtable_file,
                                                        analysis_obj.module_plt,
                                                        analysis_obj.external_funcs,
                                                        analysis_obj.got_map,
                                                        analysis_obj.idata_map,
                                                        analysis_obj.fct_return_values,
                                                        analysis_obj.fct_vtable_updates,
                                                        analysis_obj.vcall_file,
                                                        module_name,
                                                        analysis_obj.memory.get_load_begin(),
                                                        analysis_obj.memory.get_load_end());

                    Path path;
                    path.clear();
                    shared_ptr<Symbolic> reg_ptr;
                    switch(analysis_obj.file_format) {
                        // => set RDI to contain active vtable.
                        case FileFormatELF64:
                            reg_ptr = State::initial_values().at(OFFB_RDI);
                            break;
                        // => set RCX to contain active vtable.
                        case FileFormatPE64:
                            reg_ptr = State::initial_values().at(OFFB_RCX);
                            break;
                        default:
                            throw runtime_error("Do not know how to handle file format.");
                    }
                    ExpressionPtr symbol_temp = reg_ptr;
                    Indirection ind_temp(symbol_temp);
                    ExpressionPtr final_temp = make_shared<Indirection>(ind_temp);
                    overwriteAnalysis.add_active_vtable(final_temp,
                                                        vtable_it->addr,
                                                        path,
                                                        true,
                                                        false);

                    overwriteAnalysis.obtain();

                    // Store the vtable update results and process them after
                    // all functions were analyzed.
                    VTableUpdates &vtable_updates =
                            overwriteAnalysis.get_vtable_updates();

                    cout << "Updating vtable hierarchy for function "
                         << hex << func_addr
                         << " ("
                         << dec << counter
                         << "/"
                         << related_vtables.size()
                         << ")... "
                         << " (Thread: " << thread_number << ")" << endl;
                    thread_vtable_hierarchies->update_hierarchy(vtable_updates,
                                                                module_name,
                                                                func_addr);

                    analysis_obj.fct_vtable_updates.add_vtable_updates(func_addr,
                                                                vtable_updates);

                    // Store active vtables and return values of the currently
                    // analyzed function.
                    const vector<ReturnValue> &ret_values = overwriteAnalysis.get_return_values();
                    const vector<VTableActive> &active_vtables = overwriteAnalysis.get_active_vtables();

                    for(const auto &ret_it : ret_values) {
                        for(const auto &act_it : active_vtables) {

                            if(!act_it.vtbl_ptr_loc->contains(*(ret_it.content))) {
                                continue;
                            }

                            analysis_obj.fct_return_values.add_return_value(
                                                                     func_addr, ret_it);
                            analysis_obj.fct_return_values.add_active_vtable(
                                                                     func_addr, act_it);

#if ACTIVATE_RETURN_HEURISTIC
                            // TODO: This totally ignores the offset at the moment
                            // and will overestimated.
                            VTableUpdate temp;
                            temp.offset = 0;
                            temp.index = act_it.index;
                            Symbolic temp_sym("func_return");
                            temp.base = make_shared<Symbolic>(temp_sym);
                            return_value_heuristic.push_back(temp);
#endif

                        }
                    }

                    // Store new operator candidates and which vtables are
                    // written into the objects.
                    const auto &new_op_candidates =
                                    overwriteAnalysis.get_operator_new_calls();
                    for(const auto &it : new_op_candidates) {
                        thread_new_operators->add_op_new_candidate(it.second);
                    }

                    // Store vtv vcall candidates.
                    const auto &vtv_vcalls = overwriteAnalysis.get_vtv_vcalls();
                    thread_vtv_vcalls->add_vtv_vcalls(vtv_vcalls);
                }
            }

#if ACTIVATE_RETURN_HEURISTIC
            // Simple heuristic that considers all vtables that are
            // returned by the analyzed function as dependent.
            // NOTE: This will break if the function uses a void pointer
            // as return type and will overestimate if vtables
            // (that are not dependent) reside
            // in the return register at the end and the function does not
            // return any value (is of type void).
            thread_vtable_hierarchies->update_hierarchy(return_value_heuristic,
                                                        module_name,
                                                        func_addr);
#endif

            cout << "Analyzing "
                 << hex << func_addr
                 << " finished. (Thread: " << thread_number << ")" << endl;

        } catch(const exception &e) {
                cerr << "Could not extract semantics from function at "
                << hex << func_addr << "."
                << " (Thread: " << thread_number << ")" << endl;
                cerr << e.what() << endl;
        }
    }

    cout << "Merging vtable hierarchies "
         << "(Thread: " << thread_number << ")" << endl;
    thread_vtable_hierarchies->merge_hierarchies();

    cout << "Terminating thread (Thread: " << thread_number << ")" << endl;
}


void playground(const string &config_file) {

    // Parse config file.
    ifstream file(config_file);
    if(!file) {
        throw runtime_error("Opening config file failed.");
    }

    string module_name; // File name == module name
    string target_dir;
    string file_format_str;
    FileFormatType file_format;
    unordered_set<uint64_t> new_operators;
    vector<string> ext_modules;

    string line;
    while(getline(file, line)) {
        istringstream parser(line);

        string option;
        parser >> option;
        if(parser.fail()) {
            throw runtime_error("Parsing config file failed.");
        }
        transform(option.begin(),
                  option.end(),
                  option.begin(),
                  ::toupper);

        if(option == "MODULENAME") {
            parser >> module_name;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
        }
        else if(option == "TARGETDIR") {
            parser >> target_dir;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
        }
        else if(option == "NEWOPERATORS") {
            uint32_t number;
            parser >> dec >> number;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
            for(uint32_t i = 0; i < number; i++) {
                uint64_t new_op_addr;
                parser >> hex >> new_op_addr;
                if(parser.fail()) {
                    throw runtime_error("Parsing config file failed.");
                }
                new_operators.insert(new_op_addr);
            }
        }
        else if(option == "EXTERNALMODULES") {
            uint32_t number;
            parser >> dec >> number;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
            for(uint32_t i = 0; i < number; i++) {
                string ext_module;
                parser >> ext_module;
                if(parser.fail()) {
                    throw runtime_error("Parsing config file failed.");
                }
                ext_modules.push_back(ext_module);
            }
        }
        else if(option == "FORMAT") {
            parser >> file_format_str;
            if(parser.fail()) {
                throw runtime_error("Parsing config file failed.");
            }
            transform(file_format_str.begin(),
                      file_format_str.end(),
                      file_format_str.begin(),
                      ::toupper);
            if(file_format_str == "PE64") {
                file_format = FileFormatPE64;
            }
            else if(file_format_str == "ELF64") {
                file_format = FileFormatELF64;
            }
            else {
                throw runtime_error("Format not known.");
            }
        }
        else {
            throw runtime_error("Config option not known.");
        }
    }

    stringstream temp_str;
    temp_str << target_dir << "/" << module_name;
    string target_file = temp_str.str();

    Vex &vex = Vex::get_instance();

    Translator translator(vex, target_file, file_format, on_demand);
    const auto &memory = translator.get_memory();

    // Import all vtable files.
    VTableFile vtable_file(module_name);
    if(!vtable_file.parse(target_file)) {
        throw runtime_error("Cannot parse vtables file " + target_file + ".");
    }
    for(const auto &it : ext_modules) {
        if(!vtable_file.parse(it)) {
            throw runtime_error("Cannot parse vtables file '" + it + "'.");
        }
    }
    vtable_file.finalize();

    // Import all plt entries.
    ModulePlt module_plt(module_name);
    switch(file_format) {
        case FileFormatELF64:
            // Import all plt entries.
            if(!module_plt.parse(target_file)) {
                throw runtime_error("Cannot parse module plt file "
                                    + target_file + ".");
            }
            break;
        case FileFormatPE64:
            break;
        default:
            throw runtime_error("Do not know how to "\
                                "handle file format.");
    }

    // Import all functions of other modules.
    ExternalFunctions external_funcs;
    for(const auto &it : ext_modules) {
        if(!external_funcs.parse(it)) {
            throw runtime_error("Cannot parse external functions file '" + it + "'.");
        }
    }
    external_funcs.finalize();

    // Import blacklisted functions (for example pure virtual function).
    // These functions are ignored during the main analysis iteration
    // (but a sub analysis on them is started)
    // and will be ignored as a function for the vtable contains
    // same virtual function heuristic.
    const BlacklistFuncsSet funcs_blacklist = import_blacklist_funcs(
                                                                   target_file);

    // Import all known hierarchies.
    VTableHierarchies vtable_hierarchies(file_format,
                                         vtable_file,
                                         module_name,
                                         external_funcs,
                                         module_plt,
                                         funcs_blacklist,
                                         -1);
    for(const auto &it : ext_modules) {
        vtable_hierarchies.import_hierarchy(it);
    }

    // Create vtable hierarchies used by the threads.
    vector<VTableHierarchies*> thread_vtbl_hierarchies;
    for(uint32_t i = 0; i < NUM_THREADS; i++) {
        VTableHierarchies *temp = new VTableHierarchies(file_format,
                                                        vtable_file,
                                                        module_name,
                                                        external_funcs,
                                                        module_plt,
                                                        funcs_blacklist,
                                                        i);
        thread_vtbl_hierarchies.push_back(temp);
    }

    NewOperators new_operators_candidates = NewOperators(module_name,
                                                         vtable_file,
                                                         vtable_hierarchies);

    // Create new operators used by the threads.
    vector<NewOperators*> thread_new_operators;
    for(uint32_t i = 0; i < NUM_THREADS; i++) {
        NewOperators *temp = new NewOperators(module_name,
                                              vtable_file,
                                              vtable_hierarchies);
        thread_new_operators.push_back(temp);
    }

    VTVVcallsFile vtv_vcalls_file = VTVVcallsFile(module_name);

    // Create vtv vcalls used by the threads.
    vector<VTVVcallsFile*> thread_vtv_vcalls;
    for(uint32_t i = 0; i < NUM_THREADS; i++) {
        VTVVcallsFile *temp = new VTVVcallsFile(module_name);
        thread_vtv_vcalls.push_back(temp);
    }

    // Import all vtable updates that are made in external functions.
    FctVTableUpdates fct_vtable_updates(vtable_file,
                                        module_name);
    for(const auto &it : ext_modules) {
        fct_vtable_updates.import_updates(it);
    }

    // Import .got / .data entries.
    GotMap got_map;
    IDataMap idata_map;
    switch(file_format) {
        case FileFormatELF64:
            got_map = import_got(target_file);
            break;
        case FileFormatPE64:
            idata_map = import_idata(target_file);
            break;
        default:
            throw runtime_error("Do not know how to "\
                                "handle file format.");
    }

    VCallFile vcall_file(module_name, vtable_hierarchies, vtable_file);

    // Import return values of this modules .plt functions.
    FctReturnValuesFile fct_return_values(module_name,
                                          vtable_file,
                                          module_plt,
                                          external_funcs);
    for(const auto &it : ext_modules) {
        fct_return_values.import_ext_return_values(it);
    }
    fct_return_values.finalize_ext_return_values();


    // Get vtable dependencies via inter-modular heuristic.
    vtable_hierarchies.entry_heuristic_inter();

    // DEBUG
    // Use this code if you only want to analyze specific functions
    // (remember to set on_demand to true).
    /*
    uint64_t target_fcts[] = { 0x11d5d0 };
    map<uint64_t, Function> temp;
    for(const auto temp_addr : target_fcts) {
        temp[temp_addr] =  translator.get_function(temp_addr);
    }
    */

    map<uint64_t, Function> temp = translator.get_functions();

    const VTableMap &this_vtables = vtable_file.get_this_vtables();
    AnalysisObjects analysis_obj(file_format,
                                 memory,
                                 vtable_file,
                                 this_vtables,
                                 module_plt,
                                 external_funcs,
                                 new_operators,
                                 got_map,
                                 idata_map,
                                 translator,
                                 fct_vtable_updates,
                                 vcall_file,
                                 fct_return_values);

    // Set up queue with all function addresses that have to be analyzed.
    queue_mtx.lock();
    for(const auto &kv : temp) {
        // Ignore blacklisted functions (i.e., pure virtual,
        // on Linux it is a .plt entry
        // but on Windows it is a normal function in .text).
        if(funcs_blacklist.find(kv.first) != funcs_blacklist.cend()) {
            continue;
        }
        queue_func_address.push(kv.first);
    }
    queue_mtx.unlock();

    // For debugging purposes do not spawn any thread.
    if(NUM_THREADS == 1) {
        analyze_fct(module_name,
                    analysis_obj,
                    thread_vtbl_hierarchies[0],
                    thread_new_operators[0],
                    thread_vtv_vcalls[0],
                    0);
    }
    else {
        thread all_threads[NUM_THREADS];
        for(uint32_t i = 0; i < NUM_THREADS; i++) {
            all_threads[i] = thread(analyze_fct,
                                    module_name,
                                    ref(analysis_obj),
                                    thread_vtbl_hierarchies[i],
                                    thread_new_operators[i],
                                    thread_vtv_vcalls[i],
                                    i);
        }
        for(uint32_t i = 0; i < NUM_THREADS; i++) {
            all_threads[i].join();
        }
    }

    cout << "Copying thread vtable hierarchies ... " << endl;
    uint32_t counter = 0;
    for(const auto vtbl_hierarchies : thread_vtbl_hierarchies) {
        counter++;
        cout << "Processing thread vtable hierarchies "
             << dec << counter
             << "/"
             << dec << NUM_THREADS
             << "." << endl;
        vtable_hierarchies.update_hierarchy(vtbl_hierarchies->get_hierarchies(),
                                            false);
    }
    cout << "Merging vtable hierarchies ... " << endl;
    vtable_hierarchies.merge_hierarchies();

    cout << "Copying thread new operators ... " << endl;
    counter = 0;
    for(const auto new_ops : thread_new_operators) {
        counter++;
        cout << "Processing thread new operators "
             << dec << counter
             << "/"
             << dec << NUM_THREADS
             << "." << endl;
        new_operators_candidates.copy_new_operators(
                                                new_ops->get_new_operators());
    }

    cout << "Copying thread vtv vcalls ... " << endl;
    counter = 0;
    for(const auto vtv_file : thread_vtv_vcalls) {
        counter++;
        cout << "Processing thread vtv vcalls "
             << dec << counter
             << "/"
             << dec << NUM_THREADS
             << "." << endl;
        vtv_vcalls_file.add_vtv_vcalls(vtv_file->get_vtv_vcalls());
    }

    // Export return values of this module (and active vtables)
    fct_return_values.export_return_values(target_dir);

    // Apply the results of the vcalls to the hierarchy.
    vtable_hierarchies.vcall_analysis(vcall_file.get_vcalls());

    // Export vtable updates.
    fct_vtable_updates.export_vtable_updates(target_dir);

    // Export vtable hierarchies.
    vtable_hierarchies.export_hierarchy(target_dir);

    // Export vcalls.
    vcall_file.export_vcalls(target_dir);

    // Export new operators.
    new_operators_candidates.export_new_operators(target_dir);

    // Export vtv vcalls.
    vtv_vcalls_file.export_vtv_vcalls(target_dir);

    cout << "Done." << endl;

    // DEBUG
    // Print vtable hierarchy.
    for(auto &hier_it : vtable_hierarchies.get_hierarchies()) {
        cout << "Hierarchy:" << endl;
        for(auto &vtable_idx : hier_it) {
            const auto debug_temp = vtable_file.get_vtable(vtable_idx);
            cout << debug_temp.module_name
                 << " - 0x"
                 << hex << debug_temp.addr
                 << endl;
        }
        cout << endl;
    }

    // Print vcalls.
    for(const auto &vcall_it : vcall_file.get_vcalls()) {
        cout << "VCall BB: " << hex << vcall_it.addr << endl;
        cout << "Number VTables: " << dec << vcall_it.indexes.size() << endl;
    }
}


void handle_exception(const char *message) {
    cerr << "Exception occurred: " << message << endl;
}


int main(int argc, char* argv[]) {

    if(argc != 2) {
        cerr << "Usage: "
             << argv[0]
             << " <path_to_config>"
             << endl;
        return 0;
    }

    try {
        playground(argv[1]);
    } catch(const exception &e) {
        handle_exception(e.what());
    }

    return 0;
}
