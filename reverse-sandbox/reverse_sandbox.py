#!/usr/bin/env python

"""
iOS/OS X sandbox decompiler

Heavily inspired from Dion Blazakis' previous work
    https://github.com/dionthegod/XNUSandbox/tree/master/sbdis
Excellent information from Stefan Essers' slides and work
    http://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements
    https://github.com/sektioneins/sandbox_toolkit
"""

import sys
import struct
import logging.config
import argparse
import os
import operation_node
import sandbox_filter
import sandbox_regex
import subprocess
from filters import Filters

import tqdm

REGEX_TABLE_OFFSET = 2
REGEX_COUNT_OFFSET = 4
VARS_TABLE_OFFSET = 6
VARS_COUNT_OFFSET = 8
NUM_PROFILES_OFFSET = 10

logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

ios16_5_struct = struct.Struct('<HHBBBxHHH')
PROFILE_OPS_OFFSET = 4
OPERATION_NODE_SIZE = 8
INDEX_SIZE = 2

class SandboxData():
    def __init__(self, release, 
        ios16_struct_size, header, op_nodes_count, sb_ops_count, vars_count, states_count, num_profiles, regex_count, entitlements_count, instructions_count) -> None:

        self.release = release
        self.data_file = None

        self.header_size = ios16_struct_size
        self.type = header
        self.op_nodes_count = op_nodes_count
        self.sb_ops_count = sb_ops_count
        self.vars_count = vars_count
        self.states_count = states_count
        self.num_profiles = num_profiles
        self.regex_count = regex_count
        self.entitlements_count = entitlements_count

        # offsets
        header_addition = 0
        if release > 17:
            header_addition = 2
        self.regex_table_offset = self.header_size + header_addition
        self.vars_offset = self.regex_table_offset + (self.regex_count * INDEX_SIZE)
        ent_size = INDEX_SIZE

        self.states_offset = self.vars_offset + (self.vars_count * INDEX_SIZE)
        self.entitlements_offset = self.states_offset + (self.states_count * INDEX_SIZE)

        self.profiles_offset = self.entitlements_offset + (self.entitlements_count * INDEX_SIZE)
        profile_ops_offset_size = PROFILE_OPS_OFFSET
        if release > 17:
            profile_ops_offset_size = 8
        
        ### another patch
        if release > 17:
            if entitlements_count > 0:
                self.profiles_offset += 72
                if release > 18:
                    self.profiles_offset += 4
        self.profiles_end_offset = self.profiles_offset + (self.num_profiles * (self.sb_ops_count * INDEX_SIZE + profile_ops_offset_size))
        self.operation_nodes_size = self.op_nodes_count * OPERATION_NODE_SIZE
        self.operation_nodes_offset = self.profiles_end_offset

        if not self.type:
            self.operation_nodes_offset += self.sb_ops_count * INDEX_SIZE

        align_delta = self.operation_nodes_offset & 7
        if align_delta != 0:
            self.operation_nodes_offset += 8 - align_delta
        
        self.base_addr = self.operation_nodes_offset + self.operation_nodes_size


        # data
        self.regex_list = None
        self.global_vars = None
        self.policies = None
        self.sb_ops = None
        self.operation_nodes = None
        self.ops_to_reverse = None

    def __repr__(self) -> str:
        return f"""
                struct_size: {hex(self.header_size)}
                header: {hex(self.type)}
                op_nodes_count: {hex(self.op_nodes_count)}
                sb_ops_count: {hex(self.sb_ops_count)}
                vars_count: {hex(self.vars_count)}
                states_count: {hex(self.states_count)}
                num_profiles: {hex(self.num_profiles)}
                re_table_count: {hex(self.regex_count)}
                entitlements_count: {hex(self.entitlements_count)}

                regex_table_offset: {hex(self.regex_table_offset)}
                pattern_vars_offset: {hex(self.vars_offset)}
                states_offset: {hex(self.states_offset)}
                entitlements_offset: {hex(self.entitlements_offset)}
                profiles_offset: {hex(self.profiles_offset)}
                profiles_end_offset: {hex(self.profiles_end_offset)}
                operation_nodes_offset: {hex(self.operation_nodes_offset)}
                operation_nodes_size: {hex(self.operation_nodes_size)}
                base_adrr: {hex(self.base_addr)}
                """

def node_to_c(node):
    queue = [node]
    processed = []

    out = ""
    while len(queue):
        node = queue[0]
        del queue[0]

        out += "node_%x:; // %r\n" % (node.offset, node.raw)
        if node.terminal:
            out += node.c_repr() + "\n\n"
            continue

        out += "if (%s) goto node_%x;\nelse goto node_%x;\n\n" % (node.c_repr(), node.non_terminal.match_offset, node.non_terminal.unmatch_offset)

        if node.non_terminal.match not in processed:
            processed += [node.non_terminal.match]
            queue += [node.non_terminal.match]

        if node.non_terminal.unmatch not in processed:
            processed += [node.non_terminal.unmatch]
            queue += [node.non_terminal.unmatch]

    return out.strip()

def parse_profile(infile, args) -> SandboxData:
    infile.seek(0)

    # ios 16+
    header, \
    op_nodes_count, \
    sb_ops_count, \
    vars_count, \
    states_count, \
    num_profiles, \
    re_count, \
    entitlements_count, \
    instructions_count \
        = struct.unpack('<HHBBBxHHHH', infile.read(16))


    sandbox_data = None
    if int(args.release) == 17:
        sandbox_data = SandboxData(
            int(args.release), ios16_5_struct.size, header, op_nodes_count, sb_ops_count, vars_count,
            states_count, num_profiles, re_count, entitlements_count, instructions_count)
        
    else:
        if header == 0:
            sandbox_data = SandboxData(
                int(args.release), ios16_5_struct.size, header, op_nodes_count, sb_ops_count, vars_count,
                states_count, num_profiles, entitlements_count, re_count, instructions_count)
        elif header == 0x8000:
            sandbox_data = SandboxData(
                int(args.release), ios16_5_struct.size, header, op_nodes_count, sb_ops_count, vars_count,
                states_count, re_count, entitlements_count, num_profiles, instructions_count)
        else:
            print("ERRORRRR on header - unexpected value")
    


    sandbox_data.data_file = infile

    print(sandbox_data)

    return sandbox_data


def extract_string_from_offset(f, offset, base_addr) -> str:
    """Extract string (literal) from given offset."""
    f.seek(offset * 8 + base_addr)
    len = struct.unpack("<H", f.read(2))[0] - 1
    return '%s' % f.read(len).decode("utf-8")


def create_operation_nodes(infile, sandbox_data, keep_builtin_filters):
    # Read sandbox operations.
    sandbox_data.operation_nodes = operation_node.build_operation_nodes(infile, sandbox_data.op_nodes_count)
    logger.info("operation nodes")

    for op_node in sandbox_data.operation_nodes:
        op_node.convert_filter(sandbox_filter.convert_filter_callback, infile, sandbox_data, keep_builtin_filters)
    logger.info("operation nodes after filter conversion")


    return sandbox_data.operation_nodes

def process_profile(infile, outfname, sb_ops, ops_to_reverse, op_table, operation_nodes, c_output, macho):
    if macho:
        c_output = True
    if c_output:
        outfile = open(outfname.strip() + ".c", "wt")
    else:
        out_fname = os.path.join(outfname.strip() + ".sb")
        outfile = open(out_fname, "wt")

    # Extract node for 'default' operation (index 0).
    default_node = operation_node.find_operation_node_by_offset(operation_nodes, op_table[0])
    if not default_node.terminal:
        return

        
    if c_output:
        outfile.write("extern long allow(const char *);\n")
        outfile.write("extern long deny(const char *);\n")
        
        outfile.write("extern long unparsed_filter();\n")
        outfile.write("extern long subpath();\n")
        outfile.write("extern long subpath_prefix();\n")
        
        for f in Filters.filters.values():
            name = f["name"];
            if name == "":
                name = "literal"
            for suffix in ["", "_regex", "_literal", "_prefix"]:
                outfile.write("extern long %s%s();\n" % (name.replace("-", "_"), suffix))
    else:
        outfile.write("(version 1)\n")
        outfile.write("(%s default)\n" % (default_node.terminal))
    
    # For each operation expand operation node.
    for idx in range(1, len(op_table)):
        offset = op_table[idx]
        operation = sb_ops[idx]
        # Go past operations not in list, in case list is not empty.
        if ops_to_reverse:
            if operation not in ops_to_reverse:
                continue

        node = operation_node.find_operation_node_by_offset(operation_nodes, offset)

        if not node:
            continue

        if c_output:
            outfile.write("long %s()\n{\n" % (operation.replace("-", "_").replace("*", "$"),))
            outfile.write(node_to_c(node))
            outfile.write("\n}\n\n")
            continue

        g = operation_node.build_operation_node_graph(node, default_node)
        if g:
            rg = operation_node.reduce_operation_node_graph(g)
            rg.str_simple_with_metanodes()
            rg.print_vertices_with_operation_metanodes(operation, default_node.terminal.is_allow(), outfile)
        else:
            if node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    outfile.write("(%s %s)\n" % (node.terminal, operation))
                else:
                    modifiers_type = [key for key, val in node.terminal.db_modifiers.items() if len(val)]
                    if modifiers_type:
                        outfile.write("(%s %s)\n" % (node.terminal, operation))

    outfile.close()
    
    if macho:
        # -O > 0 generates a lot of variable assignments that hinder decompilation readability
        subprocess.run(["clang", outfname.strip() + ".c", "-g", "-O0", "-undefined", "dynamic_lookup", "-Wno-everything", "-o", outfname.strip()])

def display_sandbox_profiles(infile, profiles_offset, num_profiles, base_addr):
    logger.info("Printing sandbox profiles from bundle")

    names = ""
    for i in range(0, num_profiles):

        infile.seek(profiles_offset + 0x178 * i)
        name_offset = struct.unpack("<H", infile.read(2))[0]
        name = extract_string_from_offset(infile, name_offset, base_addr)

        names += "\n" + name

    logger.info("Found %d sandbox profiles." % num_profiles)


def get_global_vars(f, vars_offset, num_vars, base_address):
    global_vars = []

    #vars_offset += 72

    next_var_pointer = vars_offset
    for i in range(0, num_vars):
        f.seek(next_var_pointer)
        var_offset = struct.unpack("<H", f.read(2))[0]
        f.seek(base_address + (var_offset * 8))
        len = struct.unpack("H", f.read(2))[0]
        s = f.read(len-1)
        global_vars.append(s.decode('utf-8'))
        next_var_pointer += 2

    logger.info("global variables are {:s}".format(", ".join(s for s in global_vars)))
    return global_vars

def get_policies(f, offset, count):

    policies = []
    f.seek(offset)
    policies = struct.unpack("<%dH" % (count), f.read(2*count))
    return policies

def read_sandbox_operations(parser, args, sandbox_data) -> None:
    sb_ops = [l.strip() for l in open(args.operations_file)]
    sandbox_data.sb_ops = sb_ops

    num_sb_ops = len(sb_ops)
    logger.info("num_sb_ops: %d", num_sb_ops)

    ops_to_reverse = []
    if args.operation:
        for op in args.operation:
            if op not in sb_ops:
                parser.print_usage()
                print ("unavailable operation: {}".format(op))
                sys.exit(1)
            ops_to_reverse.append(op)
        sandbox_data.ops_to_reverse = ops_to_reverse

def parse_regex_list(infile, sandbox_data):
    logger.debug("\n\nregular expressions:\n")
    regex_list = []

    if sandbox_data.regex_count > 0:
        infile.seek(sandbox_data.regex_table_offset)
        re_offsets_table = struct.unpack("<%dH" % sandbox_data.regex_count, infile.read(2 * sandbox_data.regex_count))

        offset_addition = 0
      
        for offset in re_offsets_table:
            infile.seek(offset * 8 + sandbox_data.base_addr + offset_addition)
            re_length = struct.unpack("<H", infile.read(2))[0]
            re = struct.unpack("<%dB" % re_length, infile.read(re_length))
            re_debug_str = "re: [", ", ".join([hex(i) for i in re]), "]"
            logger.debug(re_debug_str)
            regex_list.append(sandbox_regex.parse_regex(re))

    logger.info(regex_list)
    sandbox_data.regex_list = regex_list

def main():
    """Reverse Apple binary sandbox file to SBPL (Sandbox Profile Language) format.

    Sample run:
        python reverse_sandbox.py -r 7.1.1 container.sb.bin
        python reverse_sandbox.py -r 7.1.1 -d out container.sb.bin
        python reverse_sandbox.py -r 7.1.1 -d out container.sb.bin -n network-inbound network-outbound
        python reverse_sandbox.py -r 9.0.2 -d out sandbox_bundle_iOS_9.0 -n network-inbound network-outbound -p container
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="path to the binary sandbox profile")
    parser.add_argument("-r", "--release", help="iOS release version for sandbox profile", required=True)
    parser.add_argument("-o", "--operations_file", help="file with list of operations", required=True)
    parser.add_argument("-p", "--profile", nargs='+', help="profile to reverse (for bundles) (default is to reverse all operations)")
    parser.add_argument("-n", "--operation", nargs='+', help="particular operation(s) to reverse (default is to reverse all operations)")
    parser.add_argument("-d", "--directory", help="directory where to write reversed profiles (default is current directory)")
    parser.add_argument("-psb", "--print_sandbox_profiles", action="store_true", help="print sandbox profiles of a given bundle (only for iOS versions 9+)")
    parser.add_argument("-kbf", "--keep_builtin_filters", help="keep builtin filters in output", action="store_true")
    parser.add_argument("-c", "--c_output", help="output a C file rather than Scheme", action="store_true")
    parser.add_argument("-m", "--macho", help="generate a reversible Mach-O file (implies --c_output)", action="store_true")
    

    args = parser.parse_args()

    if args.filename is None:
        parser.print_usage()
        print ("no sandbox profile/bundle file to reverse")
        sys.exit(1)

    if args.directory:
        out_dir = args.directory
    else:
        out_dir = os.getcwd()

    infile = open(args.filename, "rb")

    sandbox_data = parse_profile(infile, args)

    read_sandbox_operations(parser, args, sandbox_data)

    parse_regex_list(infile, sandbox_data)

    if args.print_sandbox_profiles:
        if sandbox_data.type == 0x8000:
            display_sandbox_profiles(infile, sandbox_data.profiles_offset, sandbox_data.num_profiles, sandbox_data.base_addr)
        else:
            print ("cannot print sandbox profiles list; filename {} is not a sandbox bundle".format(args.filename))
        sys.exit(0)

    ## parse common structure ##

    logger.info("{:d} global vars at offset {}".format(sandbox_data.vars_count, sandbox_data.vars_offset))
    sandbox_data.global_vars = get_global_vars(infile, sandbox_data.vars_offset, sandbox_data.vars_count, sandbox_data.base_addr)
    sandbox_data.policies = get_policies(infile, sandbox_data.entitlements_offset, sandbox_data.entitlements_count)
    # Place file pointer to start of operation nodes area.
    infile.seek(sandbox_data.operation_nodes_offset)
    logger.info("number of operation nodes: %u" % sandbox_data.op_nodes_count)

    infile.seek(sandbox_data.operation_nodes_offset)
    operation_nodes = create_operation_nodes(infile, sandbox_data, args.keep_builtin_filters)

    # In case of sandbox profile bundle, go through each profile.
    if sandbox_data.type == 0x8000:
        logger.info("using profile bundle")

        profile_size = (sandbox_data.sb_ops_count * 2) + 2 + 2 # + name + policy index
        if int(args.release) > 17:
            profile_size += 4

        profile_ops_offset_size = PROFILE_OPS_OFFSET
        if int(args.release) > 17:
            profile_ops_offset_size += 4

        # read profiles
        for i in range(0, sandbox_data.num_profiles):
            infile.seek(sandbox_data.profiles_offset + profile_size * i)
            name_offset = struct.unpack("<H", infile.read(2))[0]
            name = extract_string_from_offset(infile, name_offset, sandbox_data.base_addr)

            # Go past profiles not in list, in case list is defined.
            if args.profile:
                if name not in args.profile:
                    continue
            logger.info("profile name (offset 0x%x): %s" % (name_offset, name))

            infile.seek(sandbox_data.profiles_offset + profile_size * i + profile_ops_offset_size) # name + flags + policy index

            # operands to read for each profile
            op_table = struct.unpack("<%dH" % sandbox_data.sb_ops_count, infile.read(2 * sandbox_data.sb_ops_count))

            name = name.replace('/', '_')
            out_fname = os.path.join(out_dir, name)
            process_profile(infile, out_fname, sandbox_data.sb_ops, sandbox_data.ops_to_reverse, op_table, operation_nodes, args.c_output, args.macho)

    # global profile
    else:
        infile.seek(sandbox_data.profiles_offset)

        op_table = struct.unpack("<%dH" % sandbox_data.sb_ops_count, infile.read(2 * sandbox_data.sb_ops_count))
        infile.seek(sandbox_data.operation_nodes_offset)
        logger.info("number of operation nodes: %d" % sandbox_data.op_nodes_count)

        out_fname = os.path.join(out_dir, os.path.splitext(os.path.basename(args.filename))[0])
        process_profile(infile, out_fname, sandbox_data.sb_ops, sandbox_data.ops_to_reverse, op_table, operation_nodes, args.c_output, args.macho)

    infile.close()


if __name__ == "__main__":
    sys.exit(main())
