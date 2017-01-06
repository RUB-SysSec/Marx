#ifndef VEX_H
#define VEX_H

extern "C" {
#include <valgrind/libvex.h>
#include <valgrind/libvex_ir.h>
}

#include <vector>
#include <string>
#include <cstdint>

enum CONFIGURATION : size_t {
    MAX_INSTRUCTIONS = 100
};

#define arg_out

/*!
 * \brief Main class which acts as an interface to the linked VEX library.
 *
 * A singleton class used to interface the (patched) library libVEX. This is
 * done as the library does not seem to support multiple initializations.
 *
 * \todo This class merely supports x86_64 for now.
 */
class Vex {
private:
    VexAbiInfo _abi_info;
    VexArchInfo _arch_info;
    VexGuestExtents _guest_extents;

    VexControl _control;
    VexTranslateArgs _args;

    IRSB *_block;

    // Consider std::set (tree size?).
    std::vector<void*> _allocations;

public:
    /*!
     * \brief `get_instance` returns the only instance of this singleton class.
     * \return An instance of class `Vex`.
     */
    static Vex &get_instance() {
        static Vex singleton;
        return singleton;
    }

    Vex(const Vex&) = delete;
    void operator=(const Vex&) = delete;

    ~Vex();

    const IRSB &translate(const uint8_t *bytes, uintptr_t guest_address,
                          size_t instruction_count=MAX_INSTRUCTIONS,
                          arg_out uintptr_t *vex_block_end=nullptr);

private:
    Vex();

    void initialize();
    void initialize_amd64();

    static void __attribute__((noreturn)) failure_exit() {
        throw std::string("Fatal exit from libVEX.");
    }

    static void *dispatch() {
        return nullptr;
    }

    static unsigned int needs_self_check(void*, VexRegisterUpdates*,
                                         const VexGuestExtents*) {
        return 0;
    }

    static unsigned char chase_into_ok(void*, Addr) {
        return false;
    }

    static void log_bytes(const char *bytes, size_t number_bytes);
    static IRSB *instrument(void *callback_opaque, IRSB *block,
                            const VexGuestLayout*, const VexGuestExtents*,
                            const VexArchInfo*, IRType, IRType);

    void manage_allocation(void *allocation);
    static void incoming_allocation(void *user, void *allocation);
};

#endif // VEX_H
