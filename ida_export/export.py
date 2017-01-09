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
#pure_virtual_addr = 0x4006D0 # toy example
#pure_virtual_addr = 0x20106C # libtoy.so (toy example)
#pure_virtual_addr = None # main (toy example)
#pure_virtual_addr = None # libwx_baseu_xml-3.0.so.0
#pure_virtual_addr = 0x2F1A38 # libwx_gtk2u_html-3.0.so.0
#pure_virtual_addr = 0x3BBC6C # libwx_gtk2u_xrc-3.0.so.0
#pure_virtual_addr = 0x8DA460 # libwx_gtk2u_core-3.0.so.0
#pure_virtual_addr = 0x2A1208 # libwx_gtk2u_aui-3.0.so.0
#pure_virtual_addr = 0x41C91C # libwx_gtk2u_adv-3.0.so.0
#pure_virtual_addr = 0x24D7C0 # libwx_baseu_net-3.0.so.0
#pure_virtual_addr = 0x4AD3D8 # libwx_baseu-3.0.so.0
#pure_virtual_addr = 0x430B10 # filezilla x64
#pure_virtual_addr = 0x4B1CE70 # libxul x64
#pure_virtual_addr = 0x743BB0 # mysqld x64
#pure_virtual_addr = 0x6CF150 # node x64
#pure_virtual_addr = 0x219AB4 # libflac x64
#pure_virtual_addr = 0x28ED58 # libmusicbrainz x64
#pure_virtual_addr = 0x916B80 # mongod x64
#pure_virtual_addr = 0x224C74 # libebml x64
#pure_virtual_addr = 0x2AC924 # libmatroska x64
#pure_virtual_addr = 0x492F68 # libwx_baseu-3.1.so.0.0.0
#pure_virtual_addr = 0x24BB30 # libwx_baseu_net-3.1.so.0.0.0
#pure_virtual_addr = None # libwx_baseu_xml-3.1.so.0.0.0
#pure_virtual_addr = 0x3F62C0 # libwx_gtk2u_adv-3.1.so.0.0.0
#pure_virtual_addr = 0x2981FC # libwx_gtk2u_aui-3.1.so.0.0.0
#pure_virtual_addr = 0x7F8894 # libwx_gtk2u_core-3.1.so.0.0.0
#pure_virtual_addr = 0x2CCE04 # libwx_gtk2u_html-3.1.so.0.0.0
#pure_virtual_addr = 0x313090 # libwx_gtk2u_xrc-3.1.so.0.0.0
#pure_virtual_addr = 0x430DB0 # filezilla
#pure_virtual_addr = 0x5E3C0 # libstdc++
#pure_virtual_addr = 0x4D6F2F0 # libxul.so + debug
#pure_virtual_addr = 0x220404 # libflac + VTV
#pure_virtual_addr = 0x6BC8B0 # node + VTV
#pure_virtual_addr = 0x8EB4C0 # mongod + VTV
#pure_virtual_addr = 0x4363D0 # filezilla + VTV
#pure_virtual_addr = 0x4057D0 # vboxmanage + debug
#pure_virtual_addr = 0x44C824 # vboxrt.so + debug
#pure_virtual_addr = 0x311A38 # VBoxXPCOM.so + debug
#pure_virtual_addr = None # spec + astar
#pure_virtual_addr = 0x4027B0 # spec + omnetpp
#pure_virtual_addr = 0x402F40 # spec + xalancbmk
#pure_virtual_addr = 0x402340 # spec + povray
#pure_virtual_addr = 0x403E50 # spec + dealII
#pure_virtual_addr = None # spec + namd
#pure_virtual_addr = 0x401DC0 # spec + soplex
#pure_virtual_addr = 0x14CE # windows toy 1 DEBUG
#pure_virtual_addr = 0x19DC  # windows toy 1 RELEASE
#pure_virtual_addr = 0xB2D3D8  # windows mysqld
#pure_virtual_addr = 0xBFD160  # windows mongodb
pure_virtual_addr = 0x606C4C  # windows node


# gives the number of allowed zero entries in the beginning of
# a vtable candidate
number_allowed_zero_entries = 2

is_linux = None
is_windows = None

# extracts all relocation entries from the ELF file
# (needed for vtable location heuristics)
def get_relocation_entries_gcc64(elf_file):

    relocation_entries = set()

    try:
        result = subprocess.check_output(
            ['readelf', '--relocs', elf_file])
    except:
        raise Exception("Not able to extract relocation entries.")

    for line in result.split('\n')[3:]:
        line = line.split()

        try:
            rel_offset = int(line[0], 16)
            relocation_entries.add(rel_offset)
        except:
            continue

    return relocation_entries


def memory_accessible(addr):
    for segment in segments:
        if SegStart(segment) <= addr < SegEnd(segment):
            return True
    return False


# check the given vtable entry is valid
def check_entry_valid_gcc64(addr, qword):

    # is qword a pointer into the text section?
    ptr_to_text = (text_start <= qword < text_end)

    # is qword a pointer to the extern section?
    ptr_to_extern = (extern_start <= qword < extern_end)

    # is qword a pointer to the plt section?
    ptr_to_plt = (plt_start <= qword < plt_end)

    # is the current entry a relocation entry
    # (means the value is updated during startup)
    # But ignore relocation entries that point to a vtable section
    # (relocated RTTI entries do that).
    is_relocation_entry = ((addr in relocation_entries)
        and not any(map(
        lambda x: SegStart(x) <= qword <= SegEnd(x), vtable_sections)))

    if (ptr_to_text
        or ptr_to_extern
        or ptr_to_plt
        or qword == pure_virtual_addr
        or is_relocation_entry):
        return True
    return False


# returns a dict with key = vtable address and value = set of vtable entries
def get_vtable_entries_gcc64(vtables_offset_to_top):

    vtable_entries = dict()

    # get all vtable entries for each identified vtable
    for vtable_addr in vtables_offset_to_top.keys():

        curr_addr = vtable_addr
        curr_qword = Qword(curr_addr)
        entry_ctr = 0
        vtable_entries[vtable_addr] = list()

        # get all valid entries and add them as vtable entry
        # (ignore the first x zero entries)
        while (check_entry_valid_gcc64(curr_addr, curr_qword)
            or (entry_ctr < number_allowed_zero_entries and curr_qword == 0)):

            vtable_entries[vtable_addr].append(curr_qword)

            curr_addr += 8
            entry_ctr += 1
            curr_qword = Qword(curr_addr)

    return vtable_entries


# returns a dict with key = vtable address and value = offset to top
def get_vtables_gcc64():

    vtables_offset_to_top = dict()

    # is it preceded by a valid offset to top and rtti entry?
    # heuristic value for offset to top taken from vfguard paper
    def check_rtti_and_offset_to_top(rtti_candidate, ott_candidate, addr):
        ott_addr = addr - 16
        offset_to_top = ctypes.c_longlong(ott_candidate).value
        ott_valid = (-0xFFFFFF <= offset_to_top and offset_to_top <= 0xffffff)
        rtti_valid = (rtti_candidate == 0
            or (not text_start <= rtti_candidate < text_end
            and memory_accessible(rtti_candidate)))

        # offset to top can not be a relocation entry
        # (RTTI on the other hand can be a relocation entry)
        # => probably a vtable beginning
        ott_no_rel = (not ott_addr in relocation_entries)

        if ott_valid and rtti_valid and ott_no_rel:
            return True
        return False


    for vtable_section in vtable_sections:
        i = SegStart(vtable_section)
        qword = 0
        prevqword = 0

        while i <= SegEnd(vtable_section) - 8:

            pprevqword = prevqword
            prevqword = qword
            qword = Qword(i)

            # heuristic that we also find vtables that have a zero
            # entry as first entry (libxul.so has some of them which
            # are not abstract classes, so we have to find them)
            is_zero_entry = (qword == 0)

            # Could entry be a valid vtable entry?
            if check_entry_valid_gcc64(i, qword):

                # is it preceded by a valid offset to top and rtti entry?
                if check_rtti_and_offset_to_top(prevqword, pprevqword, i):

                    # extract offset to top value for this vtable
                    offset_to_top = ctypes.c_longlong(pprevqword).value
                    vtables_offset_to_top[i] = offset_to_top

                # skip succeeding function pointers of the vtable
                while (check_entry_valid_gcc64(i, qword)
                    and i < (SegEnd(vtable_section) - 8)):

                    i += 8
                    prevqword = qword
                    qword = Qword(i)

            # Allow the first x vtable entries to be a zero entry
            # and check if it is preceded by a valid
            # offset to top and RTTI entry
            elif (is_zero_entry
                and (i-16) >= SegStart(vtable_section)
                and check_rtti_and_offset_to_top(prevqword, pprevqword, i)):

                for j in range(1, number_allowed_zero_entries+1):

                    if (i+(j*8)) <= (SegEnd(vtable_section)-8):

                        nextqword = Qword(i+(j*8))

                        # skip if next entry is a zero entry
                        if nextqword == 0:
                            continue

                        # if entry is a valid vtable entry add it
                        if check_entry_valid_gcc64(i+(j*8), nextqword):

                            # extract offset to top value for this vtable
                            offset_to_top = ctypes.c_longlong(pprevqword).value
                            vtables_offset_to_top[i] = offset_to_top
                            break

                        # do not check further if it is an invalid vtable entry
                        else:
                            break

                    # break if we would check outside of the section
                    else:
                        break

            i += 8

    # Heuristic to filter out vtable candidates (like wrong candidates
    # because of the allowed 0 entries in the beginning):
    # If vtable + 8 or vtable + 16 is also considered a vtable,
    # check if they have Xrefs => remove candidates if they do not have Xrefs.
    # Same goes for wrongly detected vtables that reside before the actual
    # vtable.
    for vtable in list(vtables_offset_to_top.keys()):
        for i in range(1, number_allowed_zero_entries+1):
            if (vtable + i*8) in vtables_offset_to_top.keys():

                if not list(XrefsTo(vtable + i*8)):
                    if (vtable + i*8) in vtables_offset_to_top.keys():
                        del vtables_offset_to_top[(vtable + i*8)]
                    continue

                if not list(XrefsTo(vtable)):
                    if vtable in vtables_offset_to_top.keys():
                        del vtables_offset_to_top[vtable]
                    continue

    return vtables_offset_to_top


# check the given vtable entry is valid
def check_entry_valid_msvc64(addr, qword):

    # is qword a pointer into the text section?
    ptr_to_text = (text_start <= qword < text_end)

    if (ptr_to_text
        or qword == pure_virtual_addr):
        return True
    return False


# TODO: function only works if RTTI is enabled in windows binary.
def get_vtables_msvc64():

    vtables_offset_to_top = dict()

    # is it preceded by a valid rtti entry?
    def check_rtti_and_offset_to_top(rtti_candidate, addr):

        # rtti pointer points to this structure
        #
        # http://blog.quarkslab.com/visual-c-rtti-inspection.html
        #typedef const struct _s__RTTICompleteObjectLocator {
        #  unsigned long signature;
        #  unsigned long offset;
        #  unsigned long cdOffset;
        #  _TypeDescriptor *pTypeDescriptor;
        #  __RTTIClassHierarchyDescriptor *pClassDescriptor;
        #} __RTTICompleteObjectLocator;

        rtti_pointer_valid = False
        for vtable_section in vtable_sections:
            if (SegStart(vtable_section)
                <= rtti_candidate
                < SegEnd(vtable_section)):

                rtti_pointer_valid = True
                break

        ott_valid = False
        try:
            ott_candidate = Dword(rtti_candidate + 4)
            offset_to_top = ctypes.c_ulong(ott_candidate).value
            ott_valid = offset_to_top <= 0xffffff
        except:
            pass

        rtti_valid = (not text_start <= rtti_candidate < text_end
            and rtti_pointer_valid)

        if rtti_valid and ott_valid:
            return True
        return False


    for vtable_section in vtable_sections:
        i = SegStart(vtable_section)
        qword = 0
        prevqword = 0

        while i <= SegEnd(vtable_section) - 8:

            pprevqword = prevqword
            prevqword = qword
            qword = Qword(i)

            # Could entry be a valid vtable entry?
            if check_entry_valid_msvc64(i, qword):

                # is it preceded by a valid offset to top and rtti entry?
                if check_rtti_and_offset_to_top(prevqword, i):

                    ott_candidate = Dword(prevqword + 4)
                    # Offset To Top is stored as a positive value and not
                    # as negative one like gcc does
                    # => we assume negative values.
                    vtables_offset_to_top[i] = \
                        ctypes.c_ulong(ott_candidate).value * (-1)

                # skip succeeding function pointers of the vtable
                while (check_entry_valid_msvc64(i, qword)
                    and i < (SegEnd(vtable_section) - 8)):

                    i += 8
                    prevqword = qword
                    qword = Qword(i)

            i += 8

    return vtables_offset_to_top


# returns a dict with key = vtable address and value = set of vtable entries
def get_vtable_entries_msvc64(vtables_offset_to_top):

    vtable_entries = dict()

    # get all vtable entries for each identified vtable
    for vtable_addr in vtables_offset_to_top.keys():

        curr_addr = vtable_addr
        curr_qword = Qword(curr_addr)
        entry_ctr = 0
        vtable_entries[vtable_addr] = list()

        # get all valid entries and add them as vtable entry
        while check_entry_valid_msvc64(curr_addr, curr_qword):

            vtable_entries[vtable_addr].append(curr_qword)

            curr_addr += 8
            entry_ctr += 1
            curr_qword = Qword(curr_addr)

    return vtable_entries


def process_function(function):
    dump = pack('<I', function - base)
    flow = FlowChart(get_func(function))
    assert len(dump) == 4

    block_dump, block_count = '', 0
    for block in flow:
        block_start = block.startEA
        block_end = block.endEA

        if plt_start <= block_start < plt_end:
            continue

        address, instruction_count = block_start, 0
        while address != BADADDR and address < block_end:
            instruction_count += 1
            address = NextHead(address)

        block_dump += pack('<I', block_start - base)
        block_dump += pack('<I', block_end - block_start)
        block_dump += pack('<H', instruction_count)

        block_count += 1

    dump += pack('<H', block_count)
    dump += block_dump
    return dump


def main():

    # Windows does only work if the image base is set to 0x0.
    if is_windows and get_imagebase() != 0x0:
        print "Image base has to be 0x0."
        return

    global plt_start, plt_end, segments
    dump = pack('<Q', base)
    assert len(dump) == 8

    for segment in segments:
        if SegName(segment) == '.plt':
            plt_start = SegStart(segment)
            plt_end = SegEnd(segment)
            break

    functions_dump = ''
    function_count = 0

    funcs = set()
    for segment in segments:
        permissions = getseg(segment).perm
        if not permissions & SEGPERM_EXEC:
            continue

        if SegStart(segment) == plt_start:
            continue

        print('\nProcessing segment %s.' % SegName(segment))
        for i, function in enumerate(Functions(SegStart(segment),
            SegEnd(segment))):

            funcs.add(function)

            functions_dump += process_function(function)
            function_count += 1

            if i & (0x100 - 1) == 0 and i > 0:
                print('Function %d.' % i)

    packed_function_count = pack('<I', function_count)
    assert len(packed_function_count) == 4

    dump += packed_function_count
    dump += functions_dump

    with open(GetInputFile() + '.dmp', 'w') as f:
        f.write(dump)

    print('\nExported %d functions.' % function_count)

    # Export function names.
    counter = 0
    with open(GetInputFile() + '_funcs.txt', 'w') as f:

        # Write Module name to file.
        # NOTE: We consider the file name == module name.
        f.write("%s\n" % GetInputFile())

        for func in funcs:
            # Ignore functions that do not have a name.
            func_name = GetFunctionName(func)
            if not func_name:
                continue

            f.write("%x %s\n" % (func, func_name))
            counter += 1

    print('\nExported %d function names.' % counter)

    # Export function blacklist.
    counter = 0
    with open(GetInputFile() + '_funcs_blacklist.txt', 'w') as f:

        # Write Module name to file.
        # NOTE: We consider the file name == module name.
        f.write("%s\n" % GetInputFile())

        # Blacklist pure virtual function.
        if pure_virtual_addr:
            f.write("%x\n" % pure_virtual_addr)

        # TODO
        # Write logic that creates addresses of blacklisted functions.
        # (needed for Windows binaries)

    print('\nExported %d function blacklist.' % counter)

    # Export vtables.
    if dump_vtables:

        if is_linux:
            vtables_offset_to_top = get_vtables_gcc64()
            vtable_entries = get_vtable_entries_gcc64(vtables_offset_to_top)

        elif is_windows:
            vtables_offset_to_top = get_vtables_msvc64()
            vtable_entries = get_vtable_entries_msvc64(vtables_offset_to_top)

        else:
            raise Exception("Do not know underlying architecture.")

        with open(GetInputFile() + '_vtables.txt', 'w') as f:

            # Write Module name to file.
            # NOTE: We consider the file name == module name.
            f.write("%s\n" % GetInputFile())

            for k in vtables_offset_to_top:
                f.write("%x %d" % (k, vtables_offset_to_top[k]))

                # write vtable entries in the correct order
                for vtbl_entry in vtable_entries[k]:
                    f.write(" %x" % vtbl_entry)

                f.write("\n")

        print('\nExported %d vtables.' % len(vtables_offset_to_top))

    # Export .plt entries.
    if dump_vtables and is_linux:
        counter = 0
        with open(GetInputFile() + '_plt.txt', 'w') as f:

            # Write Module name to file.
            # NOTE: We consider the file name == module name.
            f.write("%s\n" % GetInputFile())

            for i, function in enumerate(Functions(plt_start, plt_end)):

                # Ignore functions that do not have a name.
                func_name = GetFunctionName(function)
                if not func_name:
                    continue

                # Names of .plt function start with an ".". Remove it.
                f.write("%x %s\n" % (function, func_name[1:]))
                counter += 1
        print('\nExported %d .plt entries.' % counter)

    # Export .got entries.
    if dump_vtables and is_linux:
        counter = 0
        with open(GetInputFile() + '_got.txt', 'w') as f:

            # Write Module name to file.
            # NOTE: We consider the file name == module name.
            f.write("%s\n" % GetInputFile())

            curr_addr = got_start
            while curr_addr <= got_end:
                f.write("%x %x\n" % (curr_addr, Qword(curr_addr)))
                curr_addr += 8
                counter += 1
        print('\nExported %d .got entries.' % counter)

    # Export .idata entries.
    if dump_vtables and is_windows:
        counter = 0
        with open(GetInputFile() + '_idata.txt', 'w') as f:

            # Write Module name to file.
            # NOTE: We consider the file name == module name.
            f.write("%s\n" % GetInputFile())

            addr = idata_start
            while addr <= idata_end:

                # Ignore imports that do not have a name.
                import_name = Name(addr)
                if not import_name:
                    addr += 8
                    continue

                f.write("%x %s\n" % (addr, import_name))
                counter += 1
                addr += 8

        print('\nExported %d .idata entries.' % counter)


info = get_inf_structure()
if not info.is_64bit():
    raise Exception("Only 64 bit architecture is supported.")

if info.ostype == idc.OSTYPE_WIN and info.filetype == 11:
    is_windows = True
    is_linux = False
elif info.ostype == 0 and info.filetype == 18:
    is_windows = False
    is_linux = True
else:
    raise Exception("OS type not supported.")

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

    if is_linux:
        relocation_entries = get_relocation_entries_gcc64(GetInputFilePath())

if __name__ == '__main__':
    if pure_virtual_addr:
        print("pure_virtual function at 0x%x" % pure_virtual_addr)
    main()