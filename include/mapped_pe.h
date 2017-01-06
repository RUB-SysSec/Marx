#ifndef MAPPED_PE_H
#define MAPPED_PE_H

#include <string>
#include <vector>
#include <cstdint>

#include "pe.h"

#include "memory.h"

/*!
 * \brief Class holding information about a memory-mapped PE file.
 */
class MappedPe : public Memory {
private:
    std::vector<char> _buffer;

    mz_hdr *_mz_header = nullptr;
    pe_hdr *_pe_header = nullptr;

    pe32_opt_hdr *_pe32_opt_header = nullptr;
    pe32plus_opt_hdr *_pe32_plus_opt_header = nullptr;

    section_header *_text_section_header = nullptr;

    uintptr_t _base = 0;
    size_t _size = 0;
    uintptr_t _file_addr = 0;
    size_t _file_size = 0;

public:
    MappedPe(const MappedPe&) = delete;
    virtual void operator=(const MappedPe&) = delete;

    MappedPe(const std::string &pe_file);
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

#endif // MAPPED_PE_H
