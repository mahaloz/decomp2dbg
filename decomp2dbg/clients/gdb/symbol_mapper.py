from ...utils import *
from .utils import *
import tempfile
from elftools.elf.elffile import ELFFile
import shlex

import gdb


class SymbolMapper:
    """
    A binary search dict implementation for ranges. Symbols will map for a range and we need to
    be able to lookup addresses in the middle of the range fast
    """

    __slots__ = (
        'text_base_addr',
        '_elf_cache',
        '_objcopy',
        '_gcc',
        '_last_sym_files',
        '_sym_file_ctr'
    )

    def __init__(self):
        self.text_base_addr = None
        self._elf_cache = {}
        self._objcopy = None
        self._gcc = None
        self._last_sym_files = set()
        self._sym_file_ctr = 0


    #
    # Native Symbol Support (Linux Only)
    # Inspired by Bata24
    #

    def add_native_symbols(self, sym_info_list):
        """
        Adds a list of symbols to gdb's internal symbol listing. Only function and global symbols are supported.
        Symbol info looks like:
        (symbol_name: str, base_addr: int, sym_type: str, size: int)
        If you don't know the size, pass 0.

        Explanation of how this works:
        Adding symbols to GDB is non-trivial, it requires the use of an entire object file. Because of its
        difficulty, this is currently only supported on ELFs. When adding a symbol, we use two binutils,
        gcc and objcopy. After making a small ELF, we strip it of everything but needed sections. We then
        use objcopy to one-by-one add a symbol to the file. Objcopy does not support sizing, so we do a byte
        patch on the binary to allow for a real size. Finally, the whole object is read in with the default
        gdb command: add-symbol-file.
        """

        if not self.check_native_symbol_support():
            err("Native symbol support not supported on this platform.")
            info("If you are on Linux and want native symbol support make sure you have gcc and objcopy.")
            return False

        if self.text_base_addr is None:
            err("Base address of the binary has not been discovered yet, please run the binary and try again.")
            return False

        # info("{:d} symbols will be added".format(len(sym_info_list)))
        self._delete_old_sym_files()

        # add each symbol into a mass symbol commit
        max_commit_size = 1500
        supported_types = ["function", "object"]

        objcopy_cmds = []
        queued_sym_sizes = {}
        fname = self._construct_small_elf()
        for i, (name, addr, typ, size) in enumerate(sym_info_list):
            if typ not in supported_types:
                warn(f"Skipping symbol {name}, type is not supported: {typ}")
                continue

            # queue the sym for later use
            queued_sym_sizes[i % max_commit_size] = size

            # absolute addressing
            #if addr >= self.text_base_addr:
            #    addr_str = "{:#x}".format(addr)
            # relative addressing
            #else:

            # you always want relative adressing
            addr_str = ".text:{:#x}".format(addr)

            # clean name
            name = self._clean_string(name)

            # create a symbol command for the symbol
            objcopy_cmds.append(
                '--add-symbol {name}={addr_str},global,{type_flag}'.format(
                    name=name, addr_str=addr_str, type_flag=typ
                )
            )

            # batch commit
            if i > 1 and i % max_commit_size == 0:
                # add the queued symbols
                self._add_symbol_file(fname, objcopy_cmds, self.text_base_addr, queued_sym_sizes)

                # re-init queues and elf
                fname = self._construct_small_elf()
                objcopy_cmds = []
                queued_sym_sizes = {}

        # commit remaining symbol commands
        if objcopy_cmds:
            self._add_symbol_file(fname, objcopy_cmds, self.text_base_addr, queued_sym_sizes)

        return True

    def check_native_symbol_support(self):
        # validate binutils bins exist
        try:
            self._gcc = which("gcc")
            self._objcopy = which("objcopy")
        except FileNotFoundError as e:
            err(f"Binutils binaries not found: {e}")
            return False

        return True

    @staticmethod
    def _clean_string(string: str):
        return re.sub(r'[^\w_. -:]', '_', string)

    def _delete_old_sym_files(self):
        for sym_file in self._last_sym_files:
            try:
                gdb.execute(f"remove-symbol-file {sym_file}")
            except Exception as e:
                pass

        self._last_sym_files = set()
        self._sym_file_ctr = 0

    def _construct_small_elf(self):
        if self._elf_cache:
            new_name = self._elf_cache["fname"]+str(self._sym_file_ctr)
            open(new_name, "wb").write(self._elf_cache["data"])
            self._sym_file_ctr += 1
            self._last_sym_files.add(new_name)
            return new_name

        # compile a small elf for symbol loading
        fd, fname = tempfile.mkstemp(dir="/tmp", suffix=".c")
        os.fdopen(fd, "w").write("int main() {}")
        # os.system(f"{self._gcc} {fname} -no-pie -o {fname}.debug")
        os.system(f"{self._gcc} {fname} -o {fname}.debug")
        # destroy the source file
        os.unlink(f"{fname}")

        # delete unneeded sections from object file
        os.system(f"{self._objcopy} --only-keep-debug {fname}.debug")
        os.system(f"{self._objcopy} --strip-all {fname}.debug")

        elf = ELFFile(open(f'{fname}.debug', 'rb'))

        required_sections = [".text", ".interp", ".rela.dyn", ".dynamic", ".bss"]
        for s in elf.iter_sections():
            # keep some required sections
            if s.name in required_sections:
                continue
            os.system(f"{self._objcopy} --remove-section={s.name} {fname}.debug 2>/dev/null")

        # cache the small object file for use
        self._elf_cache["fname"] = fname + ".debug"

        # add it to known sym files
        self._last_sym_files.add(self._elf_cache["fname"])

        self._elf_cache["data"] = open(self._elf_cache["fname"], "rb").read()
        return self._elf_cache["fname"]

    def _force_update_text_size(self, stream, elf, elf_data, new_size):
        text_sect = elf.get_section_by_name('.text')

        for count in range(elf['e_shnum']):
            sect_off = elf['e_shoff'] + count * elf['e_shentsize']
            stream.seek(sect_off)
            section_header = elf.structs.Elf_Shdr.parse_stream(stream)
            if section_header['sh_name'] == text_sect['sh_name']:
                break

        patch = struct.pack("<Q", new_size)
        elf_data[sect_off+32: sect_off + 32 + len(patch)] = patch
        return elf_data

    def _force_update_sym_sizes(self, fname, queued_sym_sizes):
        # use pyelftools to obtain accurate offsets and assign symbol sizes

        stream = open(fname, 'rb')
        elf_data = bytearray(stream.read())
        stream.close()

        stream = open(fname, 'rb')
        elf = ELFFile(stream)

        # patch .text to seem large enough for any function
        elf_data = self._force_update_text_size(stream, elf, elf_data, 0xFFFFFF)

        # find the symbol table
        section = elf.get_section_by_name('.symtab')
        if not section:
            return

            # locate the location of the symbols size in the symtab
        tab_offset = section['sh_offset']

        # see if symbols already exist to skip
        for skip_off, sym in enumerate(section.iter_symbols()):
            if sym.name:
                break
        else:
            # this should never happen
            skip_off = 1
        skip_off -= 1

        # NOTE: 64-bit elf checks are redundant as of now because all debug files
        # generated are 64-bit regardless of the original binary. Does not seem to
        # have any big problems as of now. May consider removing it or generating 32-bit
        # debug binaries if necessary for this code to remain relevant.
        sym_data_size = 24 if elf.elfclass == 64 else 16
        sym_size_off = sym_data_size - 8

        for i, size in queued_sym_sizes.items():
            # skip sizes of 0
            if not size:
                continue

            # compute offset
            sym_size_loc = tab_offset + sym_data_size * (i + 1 + skip_off) + sym_size_off
            pack_str = "<Q" if elf.elfclass == 64 else "<I"
            # write the new size
            updated_size = struct.pack(pack_str, size)
            elf_data[sym_size_loc:sym_size_loc + len(updated_size)] = updated_size

        # write data back to elf
        open(fname, "wb").write(elf_data)

    def _add_symbol_file(self, fname, cmd_string_arr, text_base, queued_sym_sizes):
        # add the symbols through copying
        cmd_string = ' '.join(cmd_string_arr)
        os.system(f"{self._objcopy} {cmd_string} {fname}")

        # force update the size of each symbol
        self._force_update_sym_sizes(fname, queued_sym_sizes)

        gdb.execute(f"add-symbol-file {fname} {text_base:#x}", to_string=True)

        os.unlink(fname)
        return

