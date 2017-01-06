#!/usr/bin/env python2.7

import sys

from idc import *
from idaapi import *
from idautils import *

'''
Generate a file with all indirect calls.
'''

counter = 0
segments = list(Segments())
icalls_set = set()

for segment in segments:
    permissions = getseg(segment).perm
    if not permissions & SEGPERM_EXEC:
        continue

    print('\nProcessing segment %s.' % SegName(segment))

    ea = SegStart(segment)
    end = SegEnd(segment)
    while ea < end:

        # Return values of GetOpType
        # https://www.hex-rays.com/products/ida/support/idadoc/276.shtml
        if (GetMnem(ea) == "call"
            and GetOpType(ea, 0) >= 1
            and GetOpType(ea, 0) <= 4):
            #print "0x%x - call %s" % (ea, GetOpnd(ea, 0))
            icalls_set.add(ea)
            counter += 1

        ea = idc.NextHead(ea)

print "Number of icalls found: %d" % counter

target_file = GetInputFile() + ".icalls"
with open(target_file, 'w') as fp:
    for icall_addr in icalls_set:
        fp.write("%x\n" % icall_addr)

print "File written to: %s" % target_file