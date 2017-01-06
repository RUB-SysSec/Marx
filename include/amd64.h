#ifndef FOO_AMD64_H
#define FOO_AMD64_H

#include "expression.h"
#include "amd64_registers.h"

#include <memory>

static const auto register_rip = std::make_shared<Register>(OFFB_RIP);
static const auto register_rsp = std::make_shared<Register>(OFFB_RSP);

static const auto register_rax = std::make_shared<Register>(OFFB_RAX);
static const auto register_rbx = std::make_shared<Register>(OFFB_RBX);
static const auto register_rcx = std::make_shared<Register>(OFFB_RCX);
static const auto register_rdx = std::make_shared<Register>(OFFB_RDX);

static const auto register_rbp = std::make_shared<Register>(OFFB_RBP);
static const auto register_rsi = std::make_shared<Register>(OFFB_RSI);
static const auto register_rdi = std::make_shared<Register>(OFFB_RDI);

static const auto register_r8 = std::make_shared<Register>(OFFB_R8);
static const auto register_r9 = std::make_shared<Register>(OFFB_R9);
static const auto register_r10 = std::make_shared<Register>(OFFB_R10);
static const auto register_r11 = std::make_shared<Register>(OFFB_R11);
static const auto register_r12 = std::make_shared<Register>(OFFB_R12);
static const auto register_r13 = std::make_shared<Register>(OFFB_R13);
static const auto register_r14 = std::make_shared<Register>(OFFB_R14);
static const auto register_r15 = std::make_shared<Register>(OFFB_R15);

static const std::shared_ptr<Register> system_v_arguments[] = {
    register_rdi,
    register_rsi,
    register_rdx,
    register_rcx,
    register_r8,
    register_r9,
};

static const std::shared_ptr<Register> system_v_scratch[] = {
    register_rdi,
    register_rsi,
    register_rdx,
    register_rcx,
    register_r8,
    register_r9,
    register_r10,
    register_r11,
};

static const std::shared_ptr<Register> system_v_preserved[] = {
    register_rbx,
    register_rsp,
    register_rbp,
    register_r12,
    register_r13,
    register_r14,
    register_r15,
};

static const std::shared_ptr<Register> msvc_arguments[] = {
    register_rcx,
    register_rdx,
    register_r8,
    register_r9,
};

static const std::shared_ptr<Register> msvc_scratch[] = {
    register_rcx,
    register_rdx,
    register_r8,
    register_r9,
    register_r10,
    register_r11,
};

static const std::shared_ptr<Register> msvc_preserved[] = {
    register_rbx,
    register_rsp,
    register_rbp,
    register_rdi,
    register_rsi,
    register_r12,
    register_r13,
    register_r14,
    register_r15,
};

#endif // FOO_AMD64_H
