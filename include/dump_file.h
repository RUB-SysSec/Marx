#ifndef DUMP_FILE_H
#define DUMP_FILE_H

#include <map>
#include <set>
#include <vector>
#include <string>

/*!
 * \brief Structure containing information about a serialized block in the
 * `.dmp` file.
 */
struct BlockDescriptor {
    uintptr_t block_start;
    uintptr_t block_end;
    uintptr_t instruction_count;
};

typedef std::vector<BlockDescriptor> FunctionBlocks;
typedef std::map<uintptr_t, FunctionBlocks> ParsedFunctions;
typedef std::set<uintptr_t> NonReturningFunctions;

/*!
 * \brief Class collecting the information that was produced by the IDA
 * exporting script.
 *
 * For a given `.dmp` file (produced by the exporter), an optional
 * `.dmp.no-return` file is supported which contains information about
 * non-returning functions in the processed binary.
 *
 * \todo This can be handled in a better manner.
 */
class DumpFile {
private:
    ParsedFunctions _functions;
    NonReturningFunctions _functions_no_return;

public:
    DumpFile(const std::string &dump_file);

    /*!
     * \brief Returns all known functions.
     * \return Returns a `map` with all known functions (address as key,
     * `Function` object as value).
     */
    const ParsedFunctions &get_functions() const {
        return _functions;
    }

    /*!
     * \brief Returns known, non-returning functions.
     * \return Returns a `set` containing the addresses of all known,
     * non-returning functions.
     */
    const NonReturningFunctions &get_non_returning() const {
        return _functions_no_return;
    }

private:
    bool parse(const std::string &dump_file);
    bool parse_no_return(const std::string &no_return_file);
};

#endif // DUMP_FILE_H
