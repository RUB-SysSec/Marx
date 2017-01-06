#ifndef AMD64_REGISTERS_H
#define AMD64_REGISTERS_H

#include <map>
#include <string>
#include <memory>

extern "C" {
#include <valgrind/libvex.h>
#include <valgrind/libvex_guest_amd64.h>
}

#define OFFB_RAX offsetof(VexGuestAMD64State, guest_RAX)
#define OFFB_RBX offsetof(VexGuestAMD64State, guest_RBX)
#define OFFB_RCX offsetof(VexGuestAMD64State, guest_RCX)
#define OFFB_RDX offsetof(VexGuestAMD64State, guest_RDX)
#define OFFB_RSP offsetof(VexGuestAMD64State, guest_RSP)
#define OFFB_RBP offsetof(VexGuestAMD64State, guest_RBP)
#define OFFB_RSI offsetof(VexGuestAMD64State, guest_RSI)
#define OFFB_RDI offsetof(VexGuestAMD64State, guest_RDI)
#define OFFB_R8  offsetof(VexGuestAMD64State, guest_R8)
#define OFFB_R9  offsetof(VexGuestAMD64State, guest_R9)
#define OFFB_R10 offsetof(VexGuestAMD64State, guest_R10)
#define OFFB_R11 offsetof(VexGuestAMD64State, guest_R11)
#define OFFB_R12 offsetof(VexGuestAMD64State, guest_R12)
#define OFFB_R13 offsetof(VexGuestAMD64State, guest_R13)
#define OFFB_R14 offsetof(VexGuestAMD64State, guest_R14)
#define OFFB_R15 offsetof(VexGuestAMD64State, guest_R15)

#define OFFB_RIP offsetof(VexGuestAMD64State, guest_RIP)
#define OFFB_RSP offsetof(VexGuestAMD64State, guest_RSP)

//! Register offsets used to encode x86_64 registers by VEX.
static const unsigned int AMD64_REGISTERS[] = {
    OFFB_RAX, OFFB_RBX, OFFB_RCX, OFFB_RDX, OFFB_RSP, OFFB_RBP, OFFB_RSI,
    OFFB_RDI, OFFB_R8, OFFB_R9, OFFB_R10, OFFB_R11, OFFB_R12, OFFB_R13,
    OFFB_R14, OFFB_R15
};

static std::map<unsigned int, std::string> AMD64_DISPLAY_REGISTERS = []{
    std::map<unsigned int, std::string> result;

    result[OFFB_RAX] = "rax";
    result[OFFB_RBX] = "rbx";
    result[OFFB_RCX] = "rcx";
    result[OFFB_RDX] = "rdx";
    result[OFFB_RSP] = "rsp";
    result[OFFB_RBP] = "rbp";
    result[OFFB_RSI] = "rsi";
    result[OFFB_RDI] = "rdi";
    result[OFFB_R8]  = "r8";
    result[OFFB_R9]  = "r9";
    result[OFFB_R10] = "r10";
    result[OFFB_R11] = "r11";
    result[OFFB_R12] = "r12";
    result[OFFB_R13] = "r13";
    result[OFFB_R14] = "r14";
    result[OFFB_R15] = "r15";
    result[OFFB_RIP] = "rip";

    return result;
}();

#endif // AMD64_REGISTERS_H
