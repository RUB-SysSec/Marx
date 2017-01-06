#!/usr/bin/python2

import sys
from idc import *
from idaapi import *
from idautils import *

'''
Generate ground truth from RTTI values.
'''

vtable_section_names = [".rodata", ".data.rel.ro", ".data.rel.ro.local"]


vtables = [  ]


with open(GetInputFile() + '.gt_vtables', 'r') as fp:
    for line in fp:
        vtables.append(int(line.split(" ")[0], 16))



#vtables = [0x790810, 0x7a6df0, 0x7a9570, 0x7a9590, 0x7b9930, 0x7c76f0]

DEBUG = True

class ClassObject:

    def __init__(self, name):
        self.name = name
        self.base_classes = list()


    def add_base_class(self, base_class):
        self.base_classes.append(base_class)


def parse_typeinfo(rtti_ptr):

    in_vtable_section = False
    for vtable_sec in vtable_sections:
        if SegStart(vtable_sec) <= rtti_ptr <= SegEnd(vtable_sec):
            in_vtable_section = True
            break

    # Check if type info resides in extern.
    if not in_vtable_section:
        name = Name(rtti_ptr)
        if name == "":
            print "Error for type info: 0x%x" % rtti_ptr
            print "No name found for extern symbol."
            return None
        class_obj = ClassObject(name)
        return class_obj

    name_ptr = Qword(rtti_ptr + 0x8)
    name = GetString(name_ptr)

    if not name:
        print "Error for type info: 0x%x" % rtti_ptr
        print "No name found."
        return None
    '''
    # Try to demangle name to:
    # `typeinfo name for'ClassName
    if not Demangle("__ZTS" + name, 0):
        print "Error for type info: 0x%x" % rtti_ptr
        print "Not able to demangle name: %s." % name
        return None
    '''

    # Remove the number in the beginning of the name
    # (part of the mangled name).
    skip = 0
    for i in range(len(name)):
        if 48 <= ord(name[i]) <= 57:
            continue
        skip = i
        break
    name = name[skip:]


    class_obj = ClassObject(name)


    # Upper base ptr is 0 if we have multi-inheritance
    # (because then we have the number of base classes given in
    # the lower base ptr)
    upper_base_ptr = Dword(rtti_ptr + 0x10)
    if upper_base_ptr < 0x50: # multi-inheritance
        number_bases = Dword(rtti_ptr + 0x14)

        if DEBUG:
            print "multi"

        if number_bases > 100:
            print "Error for type info: 0x%x" % rtti_ptr
            print "Detected multi-inheritance but with over 100 base classes."
            return None

        for i in range(number_bases):
            base_ptr = Qword(rtti_ptr + 0x18 + (i*0x10))

            if DEBUG:
                print "multi 0x%x" % base_ptr

            base_class = parse_typeinfo(base_ptr)
            if base_class:
                class_obj.add_base_class(base_class)

    else: # single-inheritance or base-class
        base_ptr = Qword(rtti_ptr + 0x10)

        is_ptr = False
        for vtable_sec in vtable_sections:
            if SegStart(vtable_sec) <= base_ptr <= SegEnd(vtable_sec):
                is_ptr = True
                break

        is_extern = False
        if SegStart(extern_section) <= base_ptr <= SegEnd(extern_section):
            is_extern = True

        if is_ptr: # single-inheritance

            if DEBUG:
                print "single"
                print "0x%x" % base_ptr

            base_class = parse_typeinfo(base_ptr)
            if base_class:
                class_obj.add_base_class(base_class)

        elif is_extern: # has inheritance to external module

            if DEBUG:
                print "external"
                print "0x%x" % base_ptr

            name = Name(base_ptr)
            if name == "":
                print "Error for external type info: 0x%x" % base_ptr
                print "No name found for extern symbol."
                return None
            if (Demangle(name, 0) and
                (name[:4] == "_ZTI" or name[:5] == "__ZTI")):
                temp = ClassObject(name)
                if temp:
                    class_obj.add_base_class(temp)

        else: # base-class
            if DEBUG:
                print "base"
                print "0x%x" % base_ptr

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


segments = list(Segments())
vtable_sections = set()
extern_section = None
for segment in segments:
    if SegName(segment) in vtable_section_names:
        vtable_sections.add(segment)

    if SegName(segment) == "extern":
        extern_section = segment



hierarchy_list = list()
vtable_mapping = dict()
vtable_addr_error = set()

for vtable_addr in vtables:

    print "Processing vtable: 0x%x" % vtable_addr


    rtti_ptr = Qword(vtable_addr - 0x8)
    if rtti_ptr == 0:
        print "Error for vtable: 0x%x" % vtable_addr
        print "RTTI pointer 0. Seems not to be a vtable."
        vtable_addr_error.add(vtable_addr)
        continue

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
'''
for hierarchy_set in hierarchy_list:
    for k,v in vtable_mapping.iteritems():
        if v.name in hierarchy_set:
            hierarchy_set.remove(v.name)
            hierarchy_set.add(k)
'''

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
            if isinstance(vtable, int):
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
            if isinstance(vtable, int):
                print "0x%x" % vtable
            else:
                temp = Demangle(vtable, 0)
                if temp:
                    print temp
                else:
                    print vtable
        print ""
else:
    print "All hierarchies complete."

