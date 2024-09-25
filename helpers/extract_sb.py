#!/usr/bin/env python3

import subprocess
import unicorn.arm64_const
from argparse import ArgumentParser
from pathlib import Path

def ipsw_get_out_path(output):
    path = None
    for l in output.split("\n"):
        if "Created" in l or "kernelcache already exists" in l:
            path = l.split(" ")[-1]
    return Path(path)

def dl_kernel(device, version):
    output = subprocess.check_output(["ipsw", "--no-color", "download", "appledb", "--os", "iOS", "--version", version, "--device", device, "--kernel", "-y"], text=True, stderr=subprocess.STDOUT)
    path = ipsw_get_out_path(output)
    if path is None:
        raise Exception(f"Couldn't dl kernel: {output}")
    return path

def disassemble(path):
    return subprocess.check_output(["ipsw", "--no-color", "macho", "disass", path, "-x", "__TEXT_EXEC.__text"], text=True, stderr=subprocess.STDOUT).split("\n")
    
def get_bytes(lines):
    base = 0
    b = b""
    for l in lines:
        addr, op, dis = l.split("  ")
        if base == 0:
            base = int(addr.replace(":", ""), 0x10)
        b += b"".fromhex(op)
    return base, b

class Emulator:
    def __init__(self, addr, code):
        self.addr = addr
        self.code = code

        base = addr & ~0x3fff
        self.emu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        self.emu.mem_map(base, 0x40000)
        self.emu.mem_write(addr, code)

    def hook_unmapped(self, write_hook=None, read_hook=None):
        if write_hook:
            self.emu.hook_add(unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, write_hook)

        if read_hook:
            self.emu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, read_hook)
            # def hook_code(uc, address, size, user_data):
            #     print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
            #     # read this instruction code from memory
            #     print(">>> Instruction code at [0x%x] =" %(address), end="")
            # self.emu.hook_add(unicorn.UC_HOOK_CODE, hook_code)


    def __enter__(self):
        self.emu.emu_start(self.addr, self.addr+len(self.code))
        return self

    def __exit__(self, *args):
        self.emu.emu_stop()

def macho_read_data(macho, addr, size):
    return subprocess.check_output(["ipsw", "--no-color", "macho", "dump", macho, f"{addr:#x}", "--size", f"{size}", "--bytes"])


class Sandbox:
    def __init__(self, kc, version):
        self.kc = kc
        self.macho = self.get_sb_kext()
        self.platform_base_addr = None
        self.version = version
        print(f"sb: {self.macho}")

        self.dis = disassemble(self.macho)

    def get_sb_kext(self):
        output = subprocess.check_output(["ipsw", "--no-color", "kernel", "extract", self.kc, "com.apple.security.sandbox"], text=True, stderr=subprocess.STDOUT)
        path = ipsw_get_out_path(output)
        if path is None:
            raise Exception(f"Couldn't extract sb kext: {output}")
        return path
    
    def _get_nop(self, line):
        addr, op, dis = line.split("  ")
        return f"{addr}  1f 20 03 d5   nop ; {dis.replace(' ', '_')}"
    
    def _get_lines(self, name):
        # try to catch all assembly lines from a label
        # through a ref to the profile name
        # and ends with a bl to the load profile function.
        found_name = False
        lines = []
        new_label_marks = ["; loc_", ' b\t', 'cbz\t']
        skip_insts = ["pacia\t", "pacibsp", "b.ne\t", "ldaddal\t"]
        for l in self.dis:
            new_label = any([True for m in new_label_marks if m in l])
            if new_label and not found_name:
                lines = []
                continue
            if f'"{name}"' in l:
                found_name = True
            elif any([True for m in skip_insts if m in l]):
                # replace with nop to preserve alignment
                l = self._get_nop(l)
            elif " bl\t" in l:
                if found_name:
                    break
                else:
                    l = self._get_nop(l)
            lines.append(l)

        if not lines:
            raise Exception(f"Couldn't find code to load {name} profile")
        print(f"load {name} code:\n{'\n'.join(lines)}")
        return lines
    
    def _get_load_platform_lines(self):
        lines = []
        found_builtin_collection_str = False
        found_bl_after_builtin = False
        for l in self.dis:
            if found_bl_after_builtin:
                lines.append(l)
                if 'stp' in l:
                    break
            if found_builtin_collection_str:
                if " bl\t" in l:
                    found_bl_after_builtin = True
                    continue

            if '"builtin collection"' in l:
                found_builtin_collection_str = True
                continue

        if not lines:
            raise Exception("Couldn't find code to load platform profile")
        print(f"load platform lines\n{'\n'.join(lines)}")

        return lines

    def get_platform_profile_bytes(self):
        lines = self._get_load_platform_lines()
        addr, code = get_bytes(lines)

        def hook_unmapped_write(emu, access, addr, *args):
            self.platform_base_addr = addr
            base = addr & ~0x3fff
            emu.mem_map(base, 0x4000)
            return True

        emu = Emulator(addr, code)
        emu.hook_unmapped(write_hook=hook_unmapped_write)
        with emu:
            # code is expected to write to an unmapped address, will be caught by the hook
            if self.platform_base_addr is None:
                raise Exception("load platform profile code didn't do the expected stp!")
            platform_base_bytes = emu.emu.mem_read(self.platform_base_addr, 0x10)

        ref, size = int.from_bytes(platform_base_bytes[:8], byteorder='little'), int.from_bytes(platform_base_bytes[8:], byteorder='little')

        print(f"platform profile: {ref:#x} size: {size:#x}")

        profile = macho_read_data(self.macho, ref, size)
        print(f"read platform profile {len(profile):#x} bytes! {profile[:0x20].hex()}...")

        return profile

    def get_profile_bytes(self, name):
        lines = self._get_lines(name)
        addr, code = get_bytes(lines)

        def hook_unmapped(emu, access, addr, *args):
            base = addr & ~0x3fff
            emu.mem_map(base, 0x4000)
            return True

        emu = Emulator(addr, code)
        emu.hook_unmapped(hook_unmapped, hook_unmapped)
        with emu:
            ref, size = emu.emu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X2), emu.emu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X3)
            # x2 == ref to const (builtin profile)
            # x3 == size
            if not ref or not size:
                raise Exception(f"Couldn't find ref/size to {name} profile")
            
        print(f"{name}: {ref:#x} size: {size:#x}")

        profile = macho_read_data(self.macho, ref, size)
        print(f"read {name} profile {len(profile):#x} bytes! {profile[:0x20].hex()}...")

        return profile
    

    def get_operations(self):
        found_default = False
        ops = []
        for l in subprocess.check_output(["strings", self.macho], text=True).split("\n"):
            if l == "default":
                found_default = True
            if found_default:
                if '"' in l or ' ' in l or '%' in l or ':' in l:
                    # stupid
                    break
                ops.append(l)
        if not ops:
            raise Exception("Couldn't find sandbox operations?")
        print(f"Found {len(ops)} operations. {','.join(ops[0:3])}...{ops[-1]}.")
        return ops
    
    def decompile_sb(self, name, sb_bin=None, skip_decompile=False):
        sb_bin = sb_bin or self.get_profile_bytes(name)

        filename = name.replace(" ", "_")
        out_dir = self.macho.parent / filename
        out_dir.mkdir(exist_ok=True)
        filepath = out_dir / (filename + ".bin")
        
        with open(filepath, "wb") as f:
            f.write(sb_bin)

        if skip_decompile:
            print(f"Skipping decompilation for {name}")
        else:
            args = ["python3", "./reverse_sandbox.py", "--release", str(self.version), "--operations", self.ops_file.absolute(), "--directory", out_dir.absolute(), filepath.absolute()]
            print(f"running: {args}")
            if subprocess.call(args, cwd=Path(__file__).parents[1] / "reverse-sandbox"):
                print(f"ERROR: failed to decompile {name} profile")

    def decompile_all(self, skip_decompile=False):
        self.ops_file = self.macho.parent / "operations.txt"
        ops = self.get_operations()
        with open(self.ops_file, "w") as f:
            f.write("\n".join(ops))

        self.decompile_sb("builtin collection", skip_decompile=skip_decompile)
        protobox_name = "autobox collection" if self.version >= 18  else "protobox collection"
        self.decompile_sb(protobox_name, skip_decompile=skip_decompile)
        
        platform_sb = self.get_platform_profile_bytes()
        self.decompile_sb("platform collection", platform_sb, skip_decompile=skip_decompile)

def main():
    parser = ArgumentParser("Sandbox Extractor Helper", description="Specify device+version, and this script will do the entire process: Download the kernel cache, extract the sandbox profiles, and run the decompiler.")
    parser.add_argument("--device", "-d", help="Device", default="iPhone16,1")
    parser.add_argument("--version", "-v", help="Version, can specify a beta like '18.0 beta 4'", default="17.6.1")
    parser.add_argument("--skip-decompile", "-s", help="Skip sandbox decompilation (currently unsupported on iOS 18)", default=False, action="store_true")

    args = parser.parse_args()

    print(f"Downloading kernel cache for {args.device} {args.version}.")
    k = dl_kernel(args.device, args.version)

    release = int(args.version.split(".")[0])

    sb = Sandbox(k, release)

    sb.decompile_all(skip_decompile=args.skip_decompile)

if __name__ == "__main__":
    main()
