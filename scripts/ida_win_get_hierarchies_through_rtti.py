#!/usr/bin/python2

import sys
from idc import *
from idaapi import *
from idautils import *

'''
Generate ground truth from RTTI values.
'''

vtable_section_names = [".rdata"]

# Get all vtables through the symbols.
vtable_symbols = []
for name_tuple in Names():
    temp = Demangle(name_tuple[1], 8)
    if not temp:
        continue
    if "vftable" in temp:
        vtable_symbols.append(name_tuple)

vtables = []
for vtable_tuple in vtable_symbols:
    vtables.append(vtable_tuple[0])

with open(GetInputFile() + '.gt_vtables', 'w') as fp:
    for vtable_tuple in vtable_symbols:
        fp.write("%x %s\n" % (vtable_tuple[0], Demangle(vtable_tuple[1], 8)))

#vtables = [0xDD0148, 0x0DD0108]

DEBUG = False

class ClassObject:

    def __init__(self, name):
        self.name = name
        self.base_classes = list()


    def add_base_class(self, base_class):
        self.base_classes.append(base_class)


def parse_typeinfo(rtti_ptr):

    def get_name_type_descr(type_descr):
        # Extract name of vtable (skip *pVFTable, void *).
        name_ptr = type_descr + 0x10
        name = GetString(name_ptr)
        return name

    # Skip signature, offset, cdOffset (each 4 bytes).
    # NOTE: This only works if the idb is rebased to 0x0 as image base.
    type_descr_ptr = rtti_ptr + 0xc
    class_hier_descr_ptr = rtti_ptr + 0x10

    type_descr = Dword(type_descr_ptr)
    class_hier_descr = Dword(class_hier_descr_ptr)

    name = get_name_type_descr(type_descr)
    class_obj = ClassObject(name)

    num_bases_ptr = class_hier_descr + 0x8
    num_bases = Dword(num_bases_ptr)

    if num_bases > 100:
        print "Error? Class %s has more than 100 base classes." % name
        return None

    elif num_bases > 0:
        base_array_ptr = class_hier_descr + 0xc
        base_array = Dword(base_array_ptr)

        temp_ptr = base_array
        for i in range(num_bases):
            base_descr = Dword(temp_ptr)
            base_type_descr = Dword(base_descr)
            base_name = get_name_type_descr(base_type_descr)

            if base_name != name:
                base_class_obj = ClassObject(base_name)
                class_obj.add_base_class(base_class_obj)
            temp_ptr += 0x4

    return class_obj


def print_class_hierarchy(class_obj):

    def pretty_print(class_obj, depth):
        print "   "*depth,
        print class_obj.name
        for base_class in class_obj.base_classes:
            pretty_print(base_class, depth+1)

    pretty_print(class_obj, 0)


def convert_to_set(class_obj):
    hierarchy_set = set()
    hierarchy_set.add(class_obj.name)
    for base_obj in class_obj.base_classes:
        hierarchy_set |= convert_to_set(base_obj)
    return hierarchy_set


# Abort if image base is not 0
if get_imagebase() != 0x0:
    print "Image base has to be 0x0."

else:
    hierarchy_list = list()
    vtable_mapping = dict()
    vtable_addr_error = set()

    for vtable_addr in vtables:

        print "Processing vtable: 0x%x" % vtable_addr

        # We assume that RTTI is always available
        # since MSVC reuses this field otherwise if it is not added.
        rtti_ptr = Qword(vtable_addr - 0x8)

        class_obj = parse_typeinfo(rtti_ptr)
        if class_obj is None:
            print "Error for vtable: 0x%x" % vtable_addr
            print "Seems not to be a vtable."
            vtable_addr_error.add(vtable_addr)
            continue
        vtable_mapping[vtable_addr] = class_obj

        if DEBUG:
            print_class_hierarchy(class_obj)

        # Convert to hierarchy set and merge into hierarchies
        hierarchy_set = convert_to_set(class_obj)
        is_merged = False
        i = 0
        while i < len(hierarchy_list):
            if hierarchy_list[i].isdisjoint(hierarchy_set):
                i += 1
                continue

            hierarchy_list[i] |= hierarchy_set
            is_merged = True
            break
        if not is_merged:
            hierarchy_list.append(hierarchy_set)

    # Replace vtable names with vtable addresses.
    for hierarchy_set in hierarchy_list:
        for name in list(hierarchy_set):
            was_added = False
            for k,v in vtable_mapping.iteritems():
                if name == v.name:
                    was_added = True
                    hierarchy_set.add(k)
            if was_added:
                hierarchy_set.remove(name)

    # Merge hierarchies
    i = 0
    while i < len(hierarchy_list):

        is_merged = False
        j = i + 1
        while j < len(hierarchy_list):

            if hierarchy_list[i].isdisjoint(hierarchy_list[j]):
                j += 1
                continue

            hierarchy_list[j] |= hierarchy_list[i]
            is_merged = True
            break

        if is_merged:
            hierarchy_list.remove(hierarchy_list[i])
        else:
            i += 1

    # Sanity check if all vtable addresses are in the hierarchy.
    for k,v in vtable_mapping.iteritems():
        found = False
        for hierarchy_set in hierarchy_list:
            if k in hierarchy_set:
                found = True
                break
        if not found:
            print "Error: Can not find vtable address 0x%x in hierarchies." % k

    '''
    DEBUG
    print hierarchy_list
    sys.exit(0)
    #'''

    not_complete_hierarchies = list()
    with open(GetInputFile() + '.gt_hierarchy', 'w') as fp:
        for hierarchy_set in hierarchy_list:
            has_written = False
            is_complete = True
            for vtable in hierarchy_set:
                if isinstance(vtable, int) or isinstance(vtable, long):
                    fp.write("%x " % vtable)
                    has_written = True
                else:

                    '''
                    temp = Demangle(vtable, 0)
                    if temp:
                        fp.write("%s " % temp)
                    else:
                        fp.write("%s " % vtable)
                    '''

                    is_complete = False
            if has_written:
                fp.write("\n")
            if not is_complete:
                not_complete_hierarchies.append(hierarchy_set)

    if vtable_addr_error:
        print "The following vtable addresses created errors:"
        for vtable_addr in vtable_addr_error:
            print "0x%x" % vtable_addr
    else:
        print "No vtable errors."

    if not_complete_hierarchies:
        print "The following hierarchies are not complete:"
        for hierarchy_set in not_complete_hierarchies:
            print "Hierarchy:"
            for vtable in hierarchy_set:
                if isinstance(vtable, int) or isinstance(vtable, long):
                    print "0x%x" % vtable
                else:
                    temp = Demangle(vtable, 8)
                    if temp:
                        print temp
                    else:
                        print vtable
            print ""
    else:
        print "All hierarchies complete."