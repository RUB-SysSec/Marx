
#include "mapped_elf.h"

#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace std;

/*!
 * \brief Constructs a new `MappedElf` instance from a given ELF file.
 * \param elf_file The path to the ELF file which is to be mapped.
 *
 * If the file cannot be found or seems to be malformed, a `runtime_error`
 * exception is thrown.
 */
MappedElf::MappedElf(const string &elf_file) {
    ifstream file(elf_file.c_str(), ios::binary);
    if(!file) {
        throw runtime_error("Cannot open file " + elf_file + ".");
    }

    _buffer = vector<char>(istreambuf_iterator<char>(file),
                           istreambuf_iterator<char>());
    _e_header = reinterpret_cast<ElfW(Ehdr)*>(_buffer.data());
    _p_header = reinterpret_cast<ElfW(Phdr)*>(_buffer.data() +
                                              _e_header->e_phoff);

    // FIXME: We rely on compilers a bit here, this can be generalized.
    for(auto i = 0; i < _e_header->e_phnum; ++i) {
        const auto &current = _p_header[i];
        if(current.p_type == PT_LOAD && current.p_flags & PF_X) {
            _base = current.p_vaddr;
            _size = current.p_memsz;
            break;
        }
    }

    if(!_size) {
        throw runtime_error("Malformed input file " + elf_file + ".");
    }
}

/*!
 * \brief Implements indexing access, effectively accessing the memory lieing
 * at the given virtual address.
 * \param address (Virtual) address of memory to access.
 * \return A pointer to the memory requested, if it lies at the given virtual
 * address. `nullptr` else.
 */
const uint8_t *MappedElf::operator[](const uintptr_t address) const {
    if(address < _base || address > _base + _size) {
        return nullptr;
    }

    const uint8_t *data = reinterpret_cast<const uint8_t*>(_buffer.data());
    return data + address - _base;
}
