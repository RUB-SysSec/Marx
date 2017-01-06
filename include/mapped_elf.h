#ifndef MAPPED_ELF_H
#define MAPPED_ELF_H

#include <string>
#include <vector>
#include <cstdint>

#include <elf.h>
#include <link.h>

#include "memory.h"

/*!
 * \brief Class holding information about a memory-mapped ELF file.
 */
class MappedElf : public Memory {
private:
    std::vector<char> _buffer;

    ElfW(Ehdr) *_e_header = nullptr;
    ElfW(Phdr) *_p_header = nullptr;

    uintptr_t _base = 0;
    size_t _size = 0;

public:
    MappedElf(const MappedElf&) = delete;
    virtual void operator=(const MappedElf&) = delete;

    MappedElf(const std::string &elf_file);
    virtual const uint8_t *operator[](const uintptr_t index) const;

    /*!
     * \brief Returns the begin of the executable `LOAD` segment.
     * \return Returns a pointer to the segment's begin.
     */
    virtual uintptr_t get_load_begin() const {
        return _base;
    }

    /*!
     * \brief Returns the end of the executable `LOAD` segment.
     * \return Returns a pointer to the segment's end.
     */
    virtual uintptr_t get_load_end() const {
        return _base + _size;
    }
};

#endif // MAPPED_ELF_H
