#!/usr/bin/env python2.7

import sys

from idc import *
from idaapi import *
from idautils import *

from struct import pack
from ctypes import c_uint32, c_uint64
import subprocess

base = get_imagebase()
plt_start, plt_end = 0, 0
segments = list(Segments())

# C++ configuration
dump_vtables = True
vtable_section_names = [".rodata",
    ".data.rel.ro",
    ".data.rel.ro.local",
    ".rdata"]

# global variables that are needed for multiple C++ algorithms
if dump_vtables:
    extern_seg = None
    extern_start = 0
    extern_end = 0
    text_seg = None
    text_start = 0
    text_end = 0
    plt_seg = None
    plt_start = 0
    plt_end = 0
    got_seg = None
    got_start = 0
    got_end = 0
    idata_seg = None
    idata_start = 0
    idata_end = 0
    vtable_sections = list()
    for segment in segments:
        if SegName(segment) == "extern":
            extern_seg = segment
            extern_start = SegStart(extern_seg)
            extern_end = SegEnd(extern_seg)
        elif SegName(segment) == ".text":
            text_seg = segment
            text_start = SegStart(text_seg)
            text_end = SegEnd(text_seg)
        elif SegName(segment) == ".plt":
            plt_seg = segment
            plt_start = SegStart(plt_seg)
            plt_end = SegEnd(plt_seg)
        elif SegName(segment) == ".got":
            got_seg = segment
            got_start = SegStart(got_seg)
            got_end = SegEnd(got_seg)
        elif SegName(segment) == ".idata":
            idata_seg = segment
            idata_start = SegStart(idata_seg)
            idata_end = SegEnd(idata_seg)
        elif SegName(segment) in vtable_section_names:
            vtable_sections.append(segment)

def main():

    for func in Functions():

        flow = list(FlowChart(get_func(func)))
        if len(flow) == 1:
            block = flow[0]
            block_start = block.startEA
            block_end = block.endEA

            address = block_start
            counter = 0
            is_zero_xor = False
            has_ret = False
            has_mov = False
            while address != BADADDR and address < block_end:

                mnem = GetMnem(address)
                if mnem == "xor":
                    if GetOpnd(address, 0) == GetOpnd(address, 1):
                        is_zero_xor = True
                elif mnem == "retn":
                    has_ret = True
                elif mnem == "mov":
                    # Check if second is constant
                    if GetOpType(address, 1) == 5:
                        has_mov = True

                counter += 1
                address = NextHead(address)

            if counter == 2 and is_zero_xor and has_ret:
                print "%x Ignore XOR func" % func

            elif counter == 1 and has_ret:
                print "%x Ignore RETN func" % func

            elif counter == 2 and has_mov and has_ret:
                print "%x Ignore MOV func" % func

if __name__ == '__main__':
    main()