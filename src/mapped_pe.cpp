
#include "mapped_pe.h"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstring>

using namespace std;

/*!
 * \brief Constructs a new `MappedPe` instance from a given PE file.
 * \param pe_file The path to the PE file which is to be mapped.
 *
 * If the file cannot be found or seems to be malformed, a `runtime_error`
 * exception is thrown.
 */
MappedPe::MappedPe(const string &pe_file) {
    ifstream file(pe_file.c_str(), ios::binary);
    if(!file) {
        throw runtime_error("Cannot open file " + pe_file + ".");
    }

    _buffer = vector<char>(istreambuf_iterator<char>(file),
                           istreambuf_iterator<char>());


    _mz_header = reinterpret_cast<mz_hdr*>(_buffer.data());
    if(_mz_header->magic != MZ_MAGIC) {
        throw runtime_error("Malformed input file " + pe_file + ".");
    }

    _pe_header = reinterpret_cast<pe_hdr*>(_buffer.data() + _mz_header->peaddr);
    if(_pe_header->magic != PE_MAGIC) {
        throw runtime_error("Malformed input file " + pe_file + ".");
    }

    // Magic value for optional header lies directly behind PE header.
    uint16_t *opt_hdr_magic = reinterpret_cast<uint16_t*>(_buffer.data()
                                                          + _mz_header->peaddr
                                                          + sizeof(pe_hdr));

    if(*opt_hdr_magic == IMAGE_FILE_OPT_PE32_MAGIC) {
        _pe32_opt_header = reinterpret_cast<pe32_opt_hdr*>(_buffer.data()
                                                           + _mz_header->peaddr
                                                           + sizeof(pe_hdr));
    }
    else if(*opt_hdr_magic == IMAGE_FILE_OPT_PE32_PLUS_MAGIC) {
        _pe32_plus_opt_header = reinterpret_cast<pe32plus_opt_hdr*>(
                                                            _buffer.data()
                                                            + _mz_header->peaddr
                                                            + sizeof(pe_hdr));
    }
    else {
        throw runtime_error("Malformed input file " + pe_file + ".");
    }

    for(uint32_t i = 0; i < _pe_header->sections; i++) {
        _text_section_header = reinterpret_cast<section_header*>(
                                                  _buffer.data()
                                                  + _mz_header->peaddr
                                                  + sizeof(pe_hdr)
                                                  + _pe_header->opt_hdr_size
                                                  + (i*sizeof(section_header)));

        // FIXME: We rely on compilers a bit here, this can be generalized.
        if(strcmp(_text_section_header->name, ".text") == 0) {
            _base = _text_section_header->virtual_address;
            _size = _text_section_header->virtual_size;
            _file_addr = _text_section_header->data_addr;
            _file_size = _text_section_header->raw_data_size;
            break;
        }
    }

    if(!_size) {
        throw runtime_error("Malformed input file " + pe_file + ".");
    }
}


/*!
 * \brief Implements indexing access, effectively accessing the memory lieing
 * at the given virtual address.
 * \param address (Virtual) address of memory to access.
 * \return A pointer to the memory requested, if it lies at the given virtual
 * address. `nullptr` else.
 */
const uint8_t *MappedPe::operator[](const uintptr_t address) const {
    if(address < _base || address > _base + _size) {
        return nullptr;
    }

    const uint8_t *data = reinterpret_cast<const uint8_t*>(_buffer.data());

    return data + address - _base + _file_addr;
}
