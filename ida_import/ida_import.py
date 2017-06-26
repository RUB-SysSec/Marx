
import marx
import os
import re
from sys import stdout

# IDA imports
from idaapi import add_dref, dr_O, Form
from idc import MakeComm, MakeQword, Comment
# from idautils import DataRefsFrom
# from idautils import Modules as ida_Modules

# Number of bytes of an address
WORD_BYTE_COUNT = 8


class MarxIDAImportForm(Form):
    def __init__(self):
        Form.__init__(self, r"""Marx IDA Import Script

<#Select a hierarchy file to open#    Hierarchy File:{iHierarchyFileOpen}>
<#Select a new operators file to open#New Operators File:{iNewOpFileOpen}>
<#Select a vcalls file to open#       Vcalls File:{iVcallFileOpen}>
<#Select a Vtables file to open#      Vtables File:{iVTablesFileOpen}>
Class hierarchies <Allow hierarchies with only one class:{rAllowSingleClassHierarchies}>{cHierarchies}>
""", {
            'iHierarchyFileOpen': Form.FileInput(open=True, value="*.hierarchy"),
            'iNewOpFileOpen': Form.FileInput(open=True, value="*.new_operators"),
            'iVcallFileOpen': Form.FileInput(open=True, value="*.vcalls_extended"),
            'iVTablesFileOpen': Form.FileInput(open=True, value="*_vtables.txt"),
            'cHierarchies': Form.ChkGroupControl(("rAllowSingleClassHierarchies",))
        })


def vtable_hierarchy_to_ida_db(marx_module):
    for hierarchy in marx_module.class_hierarchies:
        for vtable in hierarchy.vtables:
            new_comment = "Begin of vtable - Class_{:X}, part of ClassHierarchy_{:d}".format(vtable.address, hierarchy.number)
            comment = Comment(vtable.address) or ""
            # Check if there is already a comment (with the same content)
            if new_comment not in comment:
                MakeComm(vtable.address, new_comment + comment)
            MakeQword(vtable.address)


def new_operators_to_ida_db(marx_module):
    for new_op in marx_module.new_operators.itervalues():
        comment = Comment(new_op.address)
        if new_op.class_hierarchy:
            # Check if there is already a comment, do nothing if there is already a comment
            if not comment:
                MakeComm(new_op.address,
                         "New operator - Size: {:d}, ".format(new_op.size) +
                         "ClassHierarchy_{:d}".format(
                         new_op.class_hierarchy.number))

            # For each vtable of an object which could be constructed by this new operator
            for vtable in new_op.class_hierarchy.vtables:
                # Add references from new operator address to vtable address
                add_dref(new_op.address, vtable.address, dr_O)
        else:
            # Check if there is already a comment, do nothing if there is already a comment
            if not comment:
                MakeComm(new_op.address, "New operator - Size: {:d}, no class info available".format(new_op.size))


def vcalls_extended_to_ida_db(marx_module):
    target_addresses = set()
    for vcall in marx_module.vcalls.itervalues():
        comment = Comment(vcall.address)
        if vcall.class_hierarchy:
            # For each vtable of an object which is possible at this vcall
            for vtable in vcall.class_hierarchy.vtables:

                # Add reference from vcall address to target function address (resolves icall)
                target_function = vtable.functions.get(vcall.index, None)
                if target_function:
                    add_dref(vcall.address, target_function.address, dr_O)
                    target_addresses.add(target_function.address)

            # Check if there is already a comment, do nothing if there is already a comment
            if not comment:
                MakeComm(vcall.address,
                         "Vcall - vtable index: {:d}, ".format(vcall.index) + 
                         "ClassHierarchy_{:d}\n".format(
                         vcall.class_hierarchy.number) +
                         "\n".join(
                         map(lambda target_address: "Possible target: 0x{:X}".format(target_address), target_addresses)))
                target_addresses.clear()

        else:
            # Check if there is already a comment, do nothing if there is already a comment
            if not comment:
                MakeComm(vcall.address, "Vcall - vtable index: {:d}, no class info available".format(vcall.index))


def vtables_to_ida_db(marx_module):
    for vtable in marx_module.vtables.itervalues():
        vtable_entry_address = 0
        for index, target_function in vtable.functions.iteritems():
            vtable_entry_address = vtable.address + (index * WORD_BYTE_COUNT)
            MakeQword(vtable_entry_address)

            if target_function.address:
                # Add reference from vtable entry address to target function address
                add_dref(vtable_entry_address, target_function.address, dr_O)
            # else:
            #     MakeComm("Unknown target function.")

        # Add comment at the end of the vtable
        if vtable_entry_address and vtable.class_hierarchy:
            MakeComm(vtable_entry_address,
                     "End of vtable - Class_{:X}, ".format(vtable.address) +
                     "part of ClassHierarchy_{:d}".format(
                     vtable.class_hierarchy.number))


def ida_main():
    # # Get IDA's module representation
    # ida_modules_dict = {module.name : module for module in ida_Modules()}

    # Create form object
    form = MarxIDAImportForm()
    # Compile (in order to populate the controls)
    form.Compile()

    # Execute the form
    if form.Execute() == 1:
        # Get file paths set in form
        hierarchy_file_path = form.iHierarchyFileOpen.value
        new_operators_file_path = form.iNewOpFileOpen.value
        vcalls_extended_file_path = form.iVcallFileOpen.value
        vtables_file_path = form.iVTablesFileOpen.value
        marx_module = None

        try:
            # Parsing hierarchy file
            with open(hierarchy_file_path, "r") as f:
                marx_module = marx.parse_hierarchy(f)
        except IOError:
            print "Could not open hierarchy file: {:s}".format(hierarchy_file_path)

        try:
            # Parsing new_operators file
            with open(new_operators_file_path, "r") as f:
                marx_module = marx.parse_new_operators(f)
        except IOError:
            print "Could not open new_operators file: {:s}".format(new_operators_file_path)

        try:
            # Parsing vcalls_extended file
            with open(vcalls_extended_file_path, "r") as f:
                marx_module = marx.parse_vcalls_extended(f)
        except IOError:
            print "Could not open vcalls_extended file: {:s}".format(vcalls_extended_file_path)

        try:
            # Parsing vtables file
            with open(vtables_file_path, "r") as f:
                marx_module = marx.parse_vtables(f)
        except IOError:
            print "Could not open vtables file: {:s}".format(vtables_file_path)

        # Toggle allow_false_positives
        marx.allow_single_class_hierarchies = bool(form.cHierarchies.value)

        # Add comments to vtables
        vtable_hierarchy_to_ida_db(marx_module)
        # Add data references and comments to new operators
        new_operators_to_ida_db(marx_module)
        # Add data references and comments to vcalls and vtables
        vcalls_extended_to_ida_db(marx_module)
        # Add data references to vtables
        vtables_to_ida_db(marx_module)


ida_main()
