
import argparse
from collections import defaultdict
from itertools import izip
from sys import stdout

# Toggle if parsing new operators or vcall extended files can create new class hierarchies
allow_single_class_hierarchies = False


class Multiton(type):
    """
    Metaclass which implements an object registry. Every class of this meta type contains a dict object
    which associates each object of such a class with the object that is passed first to its init method.
    That first object is used as primary key to distinguish between two instances of such a class and
    prevent the exist of two instances bound to the same key (in other words each instance associated
    with a specific key exists only once).
    """
    def __init__(cls, name, bases, dct):
        super(Multiton, cls).__init__(name, bases, dct)
        cls._instances = {}

    def __call__(cls, *args, **kw):
        if args[0] not in cls._instances:
            cls._instances[args[0]] = super(Multiton, cls).__call__(*args)
        return cls._instances[args[0]]

    def __getitem__(self, key):
        return self(key)

    def __delitem__(self, key):
        self._instances.__delitem__(key)


class PatchedDefaultDict(defaultdict):
    def __missing__(self, key):
        """
        Does the same as __missing__ in defaultdict but calls the default_factory with key as parameter.
        This allows default_factory to process the key (e.g. use the key as parameter in the init method
        of the new constructed object).
        :param key: a key which is not in this dict
        :return: value corresponding to the given key
        :raises KeyError: if default_factory is None
        """
        if self.default_factory is None:
            raise KeyError((key,))
        self[key] = value = self.default_factory(key)
        return value


class Module(object):
    __metaclass__ = Multiton

    def __init__(self, name):
        self.name = name
        self.vtables = PatchedDefaultDict(lambda address: VTable(address, self))  # {vtable_address: vtable_object}
        self.class_hierarchies = []

        self.vcalls = {}  # {vcall_address: vcall_object}
        self.new_operators = {}  # {new_operator_address: new_operator_object}

    def __str__(self):
        return self.name


class ClassHierarchy(object):
    _hierarchy_count = 0

    def __init__(self, vtables=None):
        self.vtables = vtables if vtables else []
        self.number = ClassHierarchy._hierarchy_count
        ClassHierarchy._hierarchy_count += 1


class Addressable(object):
    def __init__(self, address, marx_module):
        self.address = address
        self.module = marx_module

    def __str__(self):
        return str.format("{:s}:{:x}", self.module.name, self.address)


class VTable(Addressable):
    def __init__(self, address, marx_module):
        super(VTable, self).__init__(address, marx_module)
        self.class_hierarchy = None
        self.offset_to_top = 0
        self.functions = {}  # {index: addressable_object}


class NewOperator(Addressable):
    def __init__(self, address, marx_module, size):
        super(NewOperator, self).__init__(address, marx_module)
        self.size = size
        self.class_hierarchy = None


class VCall(Addressable):
    def __init__(self, address, marx_module, index):
        super(VCall, self).__init__(address, marx_module)
        self.index = index
        self.class_hierarchy = None


def parse_hierarchy(f):
    """
    Parse a given file f and constructs or extend a representation of the module specified in f, this
    involves vtables, vtable hierarchies and associated modules found in that module. This function could
    only  process files which contain the same output format as produced by Marx's VTableHierarchies::export_hierarchy
    function.
    :param f: output file of VTableHierarchies::export_hierarchy function
    :return: the object representing the module specified in f
    """
    marx_module = Module(f.readline().strip())

    vtables = []
    for line in f:
        for token in line.split():
            module_name, address = token.split(":", 1)
            vtable = Module[module_name].vtables[int(address, 16)]
            # Check if vtable is already part of a class hierarchy
            if not vtable.class_hierarchy:
                vtables.append(vtable)

        # Check if a new class hierarchy is needed
        if vtables:
            new_class_hierarchy = ClassHierarchy(vtables)
            marx_module.class_hierarchies.append(new_class_hierarchy)
            for vtable in vtables:
                vtable.class_hierarchy = new_class_hierarchy
            # Reset vtables list
            vtables = []

    return marx_module


def parse_new_operators(f):
    """
    Parse a given file f and constructs or extend a representation of the module specified in f, this
    involves the new operators found in that module. This function could only process files which contain
    the same output format as produced by Marx's NewOperators::export_new_operators function.
    :param f: output file of NewOperators::export_new_operators function
    :return: the object representing the module specified in f
    """
    marx_module = Module(f.readline().strip())

    for line in f:
        tokens = line.split()
        new_op = NewOperator(int(tokens.pop(0), 16), marx_module, int(tokens.pop(0), 16))

        if tokens:
            vtable_module_name, vtable_address = tokens[0].split(":", 1)
            vtable = Module[vtable_module_name].vtables[int(vtable_address, 16)]

            # Check if class hierarchy exists already, if not create one
            if vtable.class_hierarchy or not allow_single_class_hierarchies:
                new_op.class_hierarchy = vtable.class_hierarchy
            else:
                new_op.class_hierarchy = new_class_hierarchy = ClassHierarchy()
                Module[vtable_module_name].class_hierarchies.append(new_class_hierarchy)
                for vtable_token in tokens:
                    vtable_module_name, vtable_address = vtable_token.split(":", 1)
                    vtable = Module[vtable_module_name].vtables[int(vtable_address, 16)]

                    new_class_hierarchy.vtables.append(vtable)
                    vtable.class_hierarchy = new_class_hierarchy

        marx_module.new_operators[new_op.address] = new_op

    return marx_module


def parse_vcalls_extended(f):
    """
    Parse a given file f and constructs or extend a representation of the module specified in f, this
    involves the vcalls, whose vtables, the target functions within these vtables and whose modules found
    in that module. This function could only process files which contain the same output format as
    produced by Marx's VCallFile::export_vcalls function.
    :param f: output file of VCallFile::export_vcalls function
    :return: the object representing the module specified in f
    """
    marx_module = Module(f.readline().strip())

    for line in f:
        tokens = line.split()
        vcall = VCall(int(tokens.pop(0), 16), marx_module, int(tokens.pop(0), 16))

        if tokens:
            vtable_module_name, vtable_address = tokens[0].split(":", 1)
            vtable_address = int(vtable_address, 16)
            vtable = Module[vtable_module_name].vtables[vtable_address]

            # Check if class hierarchy exists already (if single class hierarchies allowed, missing class hierarchies are added)
            if vtable.class_hierarchy or not allow_single_class_hierarchies:
                vcall.class_hierarchy = vtable.class_hierarchy
                new_class_hierarchy = None
            else:
                vcall.class_hierarchy = new_class_hierarchy = ClassHierarchy()
                Module[vtable_module_name].class_hierarchies.append(new_class_hierarchy)

            for vtable_token, target_token in izip(*[iter(tokens)]*2):
                vtable_module_name, vtable_address = vtable_token.split(":", 1)
                vtable_address = int(vtable_address, 16)
                target_module_name, target_address = target_token.split(":", 1)
                target_address = int(target_address, 16)

                vtable = Module[vtable_module_name].vtables[vtable_address]

                # Initialize new class hierarchy
                if new_class_hierarchy:
                    new_class_hierarchy.vtables.append(vtable)
                    vtable.class_hierarchy = new_class_hierarchy

                # Omit unresolved target functions
                if target_address:
                    vtable.functions[vcall.index] = Addressable(target_address, Module[target_module_name])

        marx_module.vcalls[vcall.address] = vcall

    return marx_module


def parse_vtables(f):
    """
    Parse a given file f and constructs or extend the vtable function dicts of the module specified in f.
    :param f: file containing a description of the vtables in a module (*_vtables.txt file)
    :return: the object representing the module specified in f
    """
    marx_module = Module(f.readline().strip())

    for line in f:
        tokens = line.split()
        vtable = marx_module.vtables[int(tokens.pop(0), 16)]
        vtable.offset_to_top = int(tokens.pop(0))

        index = 0
        for target_address in tokens:
            if index not in vtable.functions:
                vtable.functions[index] = Addressable(int(target_address, 16), marx_module)

            index += 1

    return marx_module


def print_hierarchy(f, marx_module):
    """
    Converts the vtable hierarchy list of the given module to string and prints it to the given output stream f.
    This function produces the same output as Marx's VTableHierarchies::export_hierarchy function.
    :param f: output stream to write the string to
    :param marx_module: module which contains the vtable hierarchy list to print
    """
    print >>f, marx_module.name + "\n" + "\n".join(
        map(lambda hierarchy: " ".join(map(str, hierarchy.vtables)), marx_module.class_hierarchies))


def print_new_operators(f, marx_module):
    """
    Converts the new operators list of the given module to string and prints it to the given output stream f.
    :param f: output stream to write the string to
    :param marx_module: module which contains the new operators list to print
    """
    print >> f, marx_module.name + "\n" + "\n".join(
        map(lambda new_op: "{:x} {:x}".format(new_op.address, new_op.size) + "".join(
            map(lambda vtable: " {:s}".format(vtable),
                new_op.class_hierarchy.vtables) if new_op.class_hierarchy else ""),
            marx_module.new_operators.itervalues()))


def print_vcalls_extended(f, marx_module):
    """
    Converts the vcalls list of the given module to string and prints it to the given output stream f.
    :param f: output stream to write the string to
    :param marx_module: module which contains the vcalls list to print
    """
    def format_vtable(vtable, vcall):
        func = vtable.functions.get(vcall.index, None)
        return " {:s} {:s}".format(vtable, func) if func else ""

    print >> f, marx_module.name + "\n" + "\n".join(
        map(lambda vcall: "{:x} {:x}".format(vcall.address, vcall.index) + "".join(
            (format_vtable(vtable, vcall) for vtable in vcall.class_hierarchy.vtables)
            if vcall.class_hierarchy else ""),
            marx_module.vcalls.itervalues()))


def print_vtables(f, marx_module):
    """
    Converts the vtables of the given module to string and prints it to the given output stream f.
    :param f: output stream to write the string to
    :param marx_module: module which contains the vtables to print
    """
    print >> f, marx_module.name + "\n" + "\n".join(
        map(lambda vtable: "{:x} {:d} ".format(vtable.address, vtable.offset_to_top) +
                           " ".join(map(lambda item: "{:x}".format(item[1].address), vtable.functions.iteritems())),
            marx_module.vtables.itervalues()))


# Standalone code, for debugging
def main(args):
    # Parsing hierarchy file
    with open(args.hierarchy_file_path, "r") as f:
        marx_module = parse_hierarchy(f)
        if args.verbose:
            print "Hierarchy file successful parsed"

    # Additional debug output
    if args.debug_hierarchy:
        print_hierarchy(stdout, marx_module)

    # Parsing new_operators file
    with open(args.new_operators_file_path, "r") as f:
        parse_new_operators(f)
        if args.verbose:
            print "New operators file successful parsed"

    # Additional debug output
    if args.debug_new_operators:
        print_new_operators(stdout, marx_module)

    # Parsing vcalls file
    with open(args.vcalls_extended_file_path, "r") as f:
        parse_vcalls_extended(f)
        if args.verbose:
            print "Vcalls extended file successful parsed"

    # Additional debug output
    if args.debug_vcalls:
        print_vcalls_extended(stdout, marx_module)

    # Parsing vcalls file
    with open(args.vtables_txt_file_path, "r") as f:
        parse_vtables(f)
        if args.verbose:
            print "Vtables file successful parsed"

    # Additional debug output
    if args.debug_vtables:
        print_vtables(stdout, marx_module)


if __name__ == '__main__':
    # Parsing arguments passed to this script
    parser = argparse.ArgumentParser()
    parser.add_argument("hierarchy_file_path", help="File path to a .hierarchy file generated by MARX")
    parser.add_argument("new_operators_file_path", help="File path to a .new_operators file generated by MARX")
    parser.add_argument("vcalls_extended_file_path", help="File path to a .vcalls_extended file generated by MARX")
    parser.add_argument("vtables_txt_file_path", help="File path to a _vtables.txt file generated by MARX")
    parser.add_argument("-v", "--verbose", help="increases program output", action="store_true")

    parser.add_argument("-dh", "--debug_hierarchy", help="prints hierarchy after parsing", action="store_true")
    parser.add_argument("-dn", "--debug_new_operators", help="prints new operators after parsing", action="store_true")
    parser.add_argument("-dv", "--debug_vcalls", help="prints vcalls after parsing", action="store_true")
    parser.add_argument("-dt", "--debug_vtables", help="prints vtables after parsing", action="store_true")
    main(parser.parse_args())
