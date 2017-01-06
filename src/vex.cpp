
#include "vex.h"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <ostream>
#include <stdexcept>

using namespace std;

Vex::Vex()
    : _block(nullptr) {

    AllocationListener listener = &Vex::incoming_allocation;
    LibVEX_registerAllocationListener(this, listener);

    LibVEX_default_VexControl(&_control);

    _control.iropt_level = 2;
    _control.iropt_verbosity = 0;
    _control.iropt_unroll_thresh = 0;

    _control.guest_chase_thresh = 0;
    _control.guest_max_insns = MAX_INSTRUCTIONS;

    LibVEX_Init(&Vex::failure_exit, &Vex::log_bytes, 0, &_control);
}

Vex::~Vex() {
    for(auto allocation : _allocations) {
        free(allocation);
    }
}

void Vex::incoming_allocation(void *user, void *allocation) {
    auto self = reinterpret_cast<Vex*>(user);
    self->manage_allocation(allocation);
}

void Vex::manage_allocation(void *allocation) {
    _allocations.push_back(allocation);
}

// FIXME: This is specific to AMD-64.
void Vex::initialize() {
    memset(&_args, 0, sizeof(_args));
    memset(&_abi_info, 0, sizeof(_abi_info));
    memset(&_arch_info, 0, sizeof(_arch_info));

    LibVEX_default_VexAbiInfo(&_abi_info);
    LibVEX_default_VexArchInfo(&_arch_info);

    _abi_info.guest_amd64_assume_fs_is_const = true;
    _abi_info.guest_amd64_assume_gs_is_const = true;

    _args.callback_opaque = this;

    _args.instrument1 = &Vex::instrument;
    _args.chase_into_ok = &Vex::chase_into_ok;
    _args.needs_self_check = &Vex::needs_self_check;

    const auto dispatch = reinterpret_cast<void*>(&Vex::dispatch);
    _args.disp_cp_chain_me_to_fastEP = dispatch;
    _args.disp_cp_chain_me_to_slowEP = dispatch;
    _args.disp_cp_xassisted = dispatch;
    _args.disp_cp_xindir = dispatch;

    _args.guest_extents = &_guest_extents;
}

void Vex::initialize_amd64() {
    initialize();

    _arch_info.endness = VexEndnessLE;
    _arch_info.hwcaps =  VEX_HWCAPS_AMD64_SSE3 |
            VEX_HWCAPS_AMD64_CX16 |
            VEX_HWCAPS_AMD64_LZCNT |
            VEX_HWCAPS_AMD64_AVX |
            VEX_HWCAPS_AMD64_RDTSCP |
            VEX_HWCAPS_AMD64_BMI |
            VEX_HWCAPS_AMD64_AVX2;

    _abi_info.guest_stack_redzone_size = 128;

    _args.arch_host = VexArchAMD64;
    _args.arch_guest = VexArchAMD64;

    _args.archinfo_host = _arch_info;
    _args.archinfo_guest = _arch_info;

    _args.abiinfo_both = _abi_info;
}

void Vex::log_bytes(const char *bytes, size_t number_bytes) {
    for(auto i = 0u; i < number_bytes; ++i) {
        printf("%c", bytes[i]);
    }
}

IRSB *Vex::instrument(void *callback_opaque, IRSB *block,
                            const VexGuestLayout*, const VexGuestExtents*,
                            const VexArchInfo*, IRType, IRType) {

    Vex &self = *static_cast<Vex*>(callback_opaque);
    self._block = deepCopyIRSB(block);

    return block;
}

/*!
 * \brief Translates bytes at a certain address into a VEX block of type IRSB.
 *
 * Translates the bytes given by array `bytes` which is assumed to lie at
 * virtual address `guest_address`. Outputs the virtual address of the end of
 * the translated block in parameter `vex_block_end`.
 *
 * \param bytes The bytes that are to be processed.
 * \param guest_address The virtual address the bytes originally lie at.
 * \param instruction_count The number of instructions VEX shall translate.
 * \param[out] vex_block_end The virtual address of the end of the translated
 *  block.
 * \return A reference to the translated VEX block (of type IRSB). Due to the
 * way VEX works internally, this reference lives as long as no further
 * translation request is made and hence should be deep-copied immediately.
 *
 * \todo VEX may not respect `instruction_count` properly. This should be
 * handled by the `Translator` class though.
 */
const IRSB &Vex::translate(const uint8_t *bytes, uintptr_t guest_address,
                           size_t instruction_count,
                           arg_out uintptr_t *vex_block_end) {
    initialize_amd64();
    _control.guest_max_insns = instruction_count;

    _args.guest_bytes = bytes;
    _args.guest_bytes_addr = guest_address;

    const auto result = LibVEX_Translate(&_args);
    if(!(result.status & result.VexTransOK)) {
        stringstream stream;
        stream << "Cannot translate code at address "
               << hex << reinterpret_cast<uintptr_t>(bytes)
               << " (guest address " << hex << guest_address << ").";

        throw runtime_error(stream.str());
    }

    if(vex_block_end) {
        // FIXME: Assert only one guest extent was used.
        *vex_block_end = guest_address + _args.guest_extents->len[0];
    }

    return *_block;
}
