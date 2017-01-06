#!/usr/bin/python2

from idc import *
from idaapi import *
from idautils import *

missing = [0x7dfa30]

def xrefs(m):
    return [x.frm for x in XrefsTo(m)]

print ""

for i, m in enumerate(missing):
    a = xrefs(m)
    print('%03i %08x %d %s' \
        % (i, m, len(a), ' '.join('%08x' % x for x in a)))
sum([int(len(xrefs(m)) == 0) for m in missing])