
#include "dump_file.h"

#include <fstream>
#include <sstream>

using namespace std;

/*!
 * \brief Constructs a new `DumpFile` object.
 * \param dump_file The filename of the `.dmp` file (as produced by the exporter
 * script).
 *
 * Optionally tries to parse `.dmp.no-return` as well.
 */
DumpFile::DumpFile(const string &dump_file) {
    if(!parse(dump_file)) {
        throw runtime_error("Cannot parse function dump file " + dump_file +
                            ".");
    }

    parse_no_return(dump_file + ".no-return");
}

bool DumpFile::parse(const string &dump_file) {
    // FIXME: Comment on dump file structure.
    _functions.clear();

    ifstream file(dump_file.c_str(), ios::binary);
    if(!file) {
        return false;
    }

    uint64_t image_base = 0;
    if(!file.read(reinterpret_cast<char*>(&image_base), sizeof(image_base))) {
        return false;
    }

    uint32_t function_count = 0;
    if(!file.read(reinterpret_cast<char*>(&function_count),
                  sizeof(function_count))) {
        return false;
    }

    for(auto i = 0u; i < function_count; ++i) {
        uint32_t function_rva = 0;
        if(!file.read(reinterpret_cast<char*>(&function_rva),
                      sizeof(function_rva))) {
            return false;
        }

        uint16_t block_count = 0;
        if(!file.read(reinterpret_cast<char*>(&block_count),
                      sizeof(block_count))) {
            return false;
        }

        uint64_t function_base = image_base + function_rva;
        _functions[function_base] = FunctionBlocks();

        FunctionBlocks &blocks = _functions[function_base];
        for(auto j = 0u; j < block_count; ++j) {

            uint32_t block_rva = 0;
            if(!file.read(reinterpret_cast<char*>(&block_rva),
                          sizeof(block_rva))) {
                return false;
            }

            uint32_t block_size = 0;
            if(!file.read(reinterpret_cast<char*>(&block_size),
                          sizeof(block_size))) {
                return false;
            }

            uint16_t instruction_count = 0;
            if(!file.read(reinterpret_cast<char*>(&instruction_count),
                          sizeof(instruction_count))) {
                return false;
            }

            BlockDescriptor block;
            block.block_start = image_base + block_rva;
            block.block_end = block.block_start + block_size;
            block.instruction_count = instruction_count;

            blocks.push_back(block);
        }
    }

    return true;
}

bool DumpFile::parse_no_return(const string &no_return_file) {
    _functions_no_return.clear();

    ifstream file(no_return_file.c_str());
    if(!file) {
        return false;
    }

    string line;
    while(getline(file, line)) {
        uintptr_t current;
        istringstream parser(line);

        parser >> hex >> current;
        if(parser.fail()) {
            return false;
        }

        _functions_no_return.insert(current);
    }

    return true;
}
