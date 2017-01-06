#ifndef MEMORY_H
#define MEMORY_H

/*!
 * \brief Enumerates all supported `File Format` types.
 */
enum FileFormatType {
    FileFormatELF64 = 0,
    FileFormatPE64 = 1,
    FileFormatCount
};


class Memory {

public:

    Memory() {};

    Memory(const Memory&) = delete;
    virtual void operator=(const Memory&) = delete;

    virtual const uint8_t *operator[](const uintptr_t index) const = 0;

    virtual uintptr_t get_load_begin() const = 0;

    virtual uintptr_t get_load_end() const = 0;
};

#endif // MEMORY_H
