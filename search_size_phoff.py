#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Nicolas Iooss
#
# SPDX-License-Identifier: MIT

"""Search workable tuples (file size, program header offset) to craft a quinindrome"""

from __future__ import annotations


class ImpossibleConstraintError(Exception):
    """Error raised when constraints become impossible to solve"""

    def __init__(self, offset: int, message: str) -> None:
        self.offset = offset
        self.message = message


class Quinindrome:
    """Represent a possible quinindrome with possibilities at each byte"""

    def __init__(self, file_size: int, phdr_offset: int) -> None:
        assert 0 <= phdr_offset < file_size <= 0x100
        assert phdr_offset + 0x20 <= file_size

        self.file_size = file_size
        self.phdr_offset = phdr_offset

        self.half_size = (file_size + 1) // 2
        self.possible_bytes: list[set[int] | None] = [None] * self.half_size
        self.byte_descs: dict[int, list[str]] = {}

        # ELF header
        self.place_bytes(0, b"\x7fELF", "Elf32_Ehdr.e_ident magic")
        self.place_u16(0x10, 2, "Elf32_Ehdr.e_type = ET_EXEC")
        # Elf32_Ehdr.e_machine can be EM_386 = 3 or EM_486 = 6
        self.place_byte_values(0x12, {3, 6}, "Elf32_Ehdr.e_machine [0]")
        self.place_byte(0x13, 0, "Elf32_Ehdr.e_machine [1]")
        # self.place_u32(0x18, image_base + code_offset, "Elf32_Ehdr.e_entry")
        # Entrypoint needs to be such that Elf32_Ehdr.e_entry & 0xfff is between 0 and file_size-1
        self.place_byte_values(0x18, set(range(file_size)), "Elf32_Ehdr.e_entry [0]")
        self.place_byte_values(0x19, {i << 4 for i in range(16)}, "Elf32_Ehdr.e_entry [1]")
        self.place_u32(0x1c, phdr_offset, "Elf32_Ehdr.e_phoff")
        self.place_u16(0x2a, 0x20, "Elf32_Ehdr.e_phentsize")
        self.place_u16(0x2c, 1, "Elf32_Ehdr.e_phnum")

        # Program header
        self.place_u32(phdr_offset + 0x00, 1, "Elf32_Phdr.p_type = PT_LOAD")
        #self.place_u32(phdr_offset + 0x04, 0+42, "Elf32_Phdr.p_offset")  # can be != 0 so long as vaddr - p_offset is page-aligned
        self.place_byte_values(phdr_offset + 0x05, set(range(0x10)), "Elf32_Phdr.p_offset [1]")  # p_offset has to be < 0x1000
        self.place_byte(phdr_offset + 0x06, 0, "Elf32_Phdr.p_offset [2]")
        self.place_byte(phdr_offset + 0x07, 0, "Elf32_Phdr.p_offset [3]")
        #self.place_u32(phdr_offset + 0x08, image_base+42, "Elf32_Phdr.p_vaddr")
        #self.place_u32(phdr_offset + 0x10, final_file_size-42, "Elf32_Phdr.p_filesz")
        #self.place_u32(phdr_offset + 0x14, image_base + code_offset, "Elf32_Phdr.p_memsz")  # p_memsz = e_entry
        #self.place_u32(phdr_offset + 0x18, 4, "Elf32_Phdr.p_flags = PF_R")  # Adjusted for e_phoff

        self.propagage_ph_off_vaddr()
        self.propagage_ph_vaddr_entry()
        self.propagage_ph_off_vaddr()
        self.propagage_ph_vaddr_entry()

        self.validate_elf_headers()

    def propagage_ph_off_vaddr_lsb(self) -> None:
        # Elf32_Phdr.p_offset & 0xfff == Elf32_Phdr.p_vaddr & 0xfff
        # So compare the LSB
        p_offset_lsb_values = self.get_u8_values(self.phdr_offset + 0x04)
        p_vaddr_lsb_values = self.get_u8_values(self.phdr_offset + 0x08)
        common_values: set[int]
        if p_offset_lsb_values is not None:
            if p_vaddr_lsb_values is not None:
                common_values = p_offset_lsb_values & p_vaddr_lsb_values
            else:
                common_values = p_offset_lsb_values
        else:
            if p_vaddr_lsb_values is not None:
                common_values = p_vaddr_lsb_values
            else:
                # Nothing to do
                return

        if p_offset_lsb_values != common_values:
            self.place_byte_values(
                self.phdr_offset + 0x04,
                common_values,
                "Elf32_Phdr.p_offset [0] from Elf32_Phdr.p_vaddr [0]",
            )
        if p_vaddr_lsb_values != common_values:
            self.place_byte_values(
                self.phdr_offset + 0x08,
                common_values,
                "Elf32_Phdr.p_vaddr [0] from Elf32_Phdr.p_offset [0]",
            )

    def propagage_ph_off_vaddr_2lownibble(self) -> None:
        # Elf32_Phdr.p_offset & 0xfff == Elf32_Phdr.p_vaddr & 0xfff ; lower nibble of 2nd bytes
        p_offset_2_values = self.get_u8_values(self.phdr_offset + 0x05)
        p_vaddr_2_values = self.get_u8_values(self.phdr_offset + 0x09)

        if p_offset_2_values is not None:
            p_offset_2_nibbles = {v & 0xf for v in p_offset_2_values}
            if len(p_offset_2_nibbles) == 1:
                known_low_nibble = list(p_offset_2_nibbles)[0]
                if p_vaddr_2_values is None or any(v & 0xf != known_low_nibble for v in p_vaddr_2_values):
                    possible_vaddr_2_values = {(i << 4) | known_low_nibble for i in range(16)}
                    self.place_byte_values(
                        self.phdr_offset + 0x09,
                        possible_vaddr_2_values,
                        "Low nibble from Elf32_Phdr.p_offset [1]",
                    )
        if p_vaddr_2_values is not None:
            p_vaddr_2_nibbles = {v & 0xf for v in p_vaddr_2_values}
            if len(p_vaddr_2_nibbles) == 1:
                known_low_nibble = list(p_vaddr_2_nibbles)[0]
                self.place_byte(
                    self.phdr_offset + 0x05,
                    known_low_nibble,
                    "Low nibble from Elf32_Phdr.p_vaddr [1]",
                )

    def propagage_ph_off_vaddr(self) -> None:
        self.propagage_ph_off_vaddr_lsb()
        self.propagage_ph_off_vaddr_2lownibble()

    def propagage_p_vaddr_entry_2(self) -> None:
        e_entry_2_values = self.get_u8_values(0x1a)
        p_vaddr_2_values = self.get_u8_values(self.phdr_offset + 0x0a)
        common_values: set[int]
        if e_entry_2_values is not None:
            if p_vaddr_2_values is not None:
                common_values = e_entry_2_values & p_vaddr_2_values
            else:
                common_values = e_entry_2_values
        else:
            if p_vaddr_2_values is not None:
                common_values = p_vaddr_2_values
            else:
                # Nothing to do
                return

        if e_entry_2_values != common_values:
            self.place_byte_values(
                0x1a, common_values, "Elf32_Ehdr.e_entry [2] from Elf32_Phdr.p_vaddr [2]"
            )
        if p_vaddr_2_values != common_values:
            self.place_byte_values(
                self.phdr_offset + 0x0a,
                common_values,
                "Elf32_Phdr.p_vaddr [2] from Elf32_Ehdr.e_entry [2]",
            )

    def propagage_p_vaddr_entry_3(self) -> None:
        e_entry_3_values = self.get_u8_values(0x1b)
        p_vaddr_3_values = self.get_u8_values(self.phdr_offset + 0x0b)
        common_values: set[int]
        if e_entry_3_values is not None:
            if p_vaddr_3_values is not None:
                common_values = e_entry_3_values & p_vaddr_3_values
            else:
                common_values = e_entry_3_values
        else:
            if p_vaddr_3_values is not None:
                common_values = p_vaddr_3_values
            else:
                # Nothing to do
                return

        if e_entry_3_values != common_values:
            self.place_byte_values(
                0x1b, common_values, "Elf32_Ehdr.e_entry [3] from Elf32_Phdr.p_vaddr [3]"
            )
        if p_vaddr_3_values != common_values:
            self.place_byte_values(
                self.phdr_offset + 0x0b,
                common_values,
                "Elf32_Phdr.p_vaddr [3] from Elf32_Ehdr.e_entry [3]",
            )

    def propagage_ph_vaddr_entry(self) -> None:
        # Elf32_Ehdr.e_entry and Elf32_Phdr.p_vaddr needs to use the same page
        # So compare the 2 MSB
        self.propagage_p_vaddr_entry_2()
        self.propagage_p_vaddr_entry_3()

    def validate_elf_headers(self) -> None:
        if self.get_known_u16(0x1a) == 0:
            # 16 high bits of e_entry are known to be zero
            # Entrypoint needs to be above the first NULL page: e_entry >= 0x1000
            e_entry_b1_values = self.get_u8_values(0x19)
            if e_entry_b1_values is not None and all(val < 0x10 for val in e_entry_b1_values):
                raise ImpossibleConstraintError(
                    0x18,
                    f"ELF entrypoint is forced to be in NULL page: {[hex(v) for v in sorted(e_entry_b1_values)]}",
                )

        if (entry_offset := self.get_known_u8(0x18)) is not None:
            # The entry point offset is known
            if (entry_op0 := self.get_known_u8(entry_offset)) is not None:
                if (entry_op1 := self.get_known_u8(entry_offset + 1)) is not None:
                    entry_op = bytes((entry_op0, entry_op1))
                    if entry_op == b"\x01\x00":  # add %eax,(%eax)
                        raise ImpossibleConstraintError(
                            entry_offset,
                            f"ELF entrypoint {entry_offset:#x} targets faulting instruction",
                        )
                    # print(f"Known entry at {entry_offset:#04x} -> {entry_op0:02x}{entry_op1:02x}")

    def get_base_offset(self, offset: int) -> int:
        assert 0 <= offset < self.file_size
        if offset < self.half_size:
            return offset
        offset = self.file_size - 1 - offset
        assert offset < self.half_size
        return offset

    def place_byte_values(self, offset: int, values: set[int], source: str) -> None:
        """Place a byte with several values"""
        boff = self.get_base_offset(offset)
        if (existing_values := self.possible_bytes[boff]) is not None:
            new_values = existing_values & values
            if not new_values:
                raise ImpossibleConstraintError(
                    offset,
                    f"values {values!r} from {source} not compatible with existing {existing_values!r} from {self.byte_descs[offset]!r}",
                )
            self.possible_bytes[boff] = new_values
        else:
            self.possible_bytes[boff] = values
            assert offset not in self.byte_descs
            assert (self.file_size - 1 - offset) not in self.byte_descs
            self.byte_descs[offset] = []
            self.byte_descs[self.file_size - 1 - offset] = []

        self.byte_descs[offset].append(source)
        if 2 * offset + 1 != self.file_size:
            self.byte_descs[self.file_size - 1 - offset].append(f"Mirror of {source}")

    def place_byte(self, offset: int, value: int, source: str) -> None:
        self.place_byte_values(offset, {value}, source)

    def place_bytes(self, offset: int, data: bytes, source: str) -> None:
        """Place several bytes in the program"""
        for data_offset, value in enumerate(data):
            self.place_byte(offset + data_offset, value, f"{source} [{data_offset}]")

    def place_u16(self, offset: int, value: int, source: str) -> None:
        """Place a 16-bit integer in the program"""
        self.place_bytes(offset, value.to_bytes(2, "little"), source)

    def place_u32(self, offset: int, value: int, source: str) -> None:
        """Place a 32-bit integer in the program"""
        self.place_bytes(offset, value.to_bytes(4, "little"), source)

    def get_u8_values(self, offset: int) -> set[int] | None:
        """Get the known byte values"""
        boff = self.get_base_offset(offset)
        return self.possible_bytes[boff]

    def get_known_u8(self, offset: int) -> int | None:
        """Get a known byte value"""
        values = self.get_u8_values(offset)
        if values is not None and len(values) == 1:
            return list(values)[0]
        return None

    def get_known_u16(self, offset: int) -> int | None:
        """Get a known u16 value"""
        if (b0 := self.get_known_u8(offset)) is None:
            return None
        if (b1 := self.get_known_u8(offset + 1)) is None:
            return None
        return b0 | (b1 << 8)

    def get_known_u32(self, offset: int) -> int | None:
        """Get a known u32 value"""
        if (b0 := self.get_known_u8(offset)) is None:
            return None
        if (b1 := self.get_known_u8(offset + 1)) is None:
            return None
        if (b2 := self.get_known_u8(offset + 2)) is None:
            return None
        if (b3 := self.get_known_u8(offset + 3)) is None:
            return None
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

    def count_holes(self) -> list[int]:
        """Count the holes (unknown bytes)"""
        holes: list[int] = []
        current_hole = 0
        for offset in range(self.file_size):
            if self.get_u8_values(offset) is None:
                current_hole += 1
            else:
                if current_hole:
                    holes.append(current_hole)
                current_hole = 0
        return holes

    def print_hex(self, /, indent: str = "") -> None:
        """Dump the possible values"""
        current_variable_index = 0
        variables: dict[int, str] = {}
        var_by_pos: dict[int, int] = {}
        for iline in range(0, self.file_size, 16):
            hexline = ""
            for i in range(16):
                if iline + i >= self.file_size:
                    break
                boff = self.get_base_offset(iline + i)
                values = self.possible_bytes[boff]
                if values is None:
                    hexline += "\033[33m..\033[m"
                elif len(values) == 1:
                    val = list(values)[0]
                    hexline += f"{val:02x}"
                else:
                    if boff in var_by_pos:
                        hexline += f"\033[32mv{var_by_pos[boff]}\033[m"
                    else:
                        hexline += f"\033[32mv{current_variable_index}\033[m"
                        variables[current_variable_index] = (
                            "{" + ",".join(f"{val:02x}" for val in sorted(values)) + "}"
                        )
                        var_by_pos[boff] = current_variable_index
                        current_variable_index += 1
                if i % 2:
                    hexline += " "
            print(f"{indent}{iline:04x}:  {hexline.strip()}")
        for pos, i_var in sorted(var_by_pos.items()):
            print(f"{indent}- \033[32mv{i_var} at {pos:#x} in {variables[i_var]}\033[m")

        # Show fields
        def repr_u8(offset: int) -> str:
            boff = self.get_base_offset(offset)
            values = self.possible_bytes[boff]
            if values is None:
                return "\033[33m..\033[m"
            if len(values) == 1:
                val = list(values)[0]
                return f"{val:02x}"
            return f"\033[32mv{var_by_pos[boff]}\033[m"

        def repr_u32(offset: int) -> str:
            return repr_u8(offset + 3) + repr_u8(offset + 2) + repr_u8(offset + 1) + repr_u8(offset)

        print(f"{indent}- \033[36me_entry  at 0x18 is 0x{repr_u32(0x18)}\033[m")
        print(
            f"{indent}- \033[36mp_offset at {self.phdr_offset + 0x04:#04x} is 0x{repr_u32(self.phdr_offset + 0x04)}\033[m"
        )
        print(
            f"{indent}- \033[36mp_vaddr  at {self.phdr_offset + 0x08:#04x} is 0x{repr_u32(self.phdr_offset + 0x08)}\033[m"
        )
        print(
            f"{indent}- \033[36mp_filesz at {self.phdr_offset + 0x10:#04x} is 0x{repr_u32(self.phdr_offset + 0x10)}\033[m"
        )
        print(
            f"{indent}- \033[36mp_memsz  at {self.phdr_offset + 0x14:#04x} is 0x{repr_u32(self.phdr_offset + 0x14)}\033[m"
        )
        print(
            f"{indent}- \033[36mp_flags  at {self.phdr_offset + 0x18:#04x} is 0x{repr_u32(self.phdr_offset + 0x18)}\033[m"
        )


def check_96() -> None:
    # Ensure the 96-byte solution works
    q = Quinindrome(0x60, 4)
    # q.print_hex()
    assert q.get_known_u32(0) == 0x464c457f
    assert q.get_known_u32(4) == 1
    # print(q.count_holes())


def do_search() -> None:
    for file_size in range(0x2e, 0x52):
        for phdr_offset in range(0, file_size - 0x20 + 1):
            try:
                q = Quinindrome(file_size, phdr_offset)
            except ImpossibleConstraintError as e:  # noqa: F841
                # print(f"Q({file_size:#x}.{phdr_offset:02x}) impossible at offset {e.offset:#x}: {e.message}")
                continue
            try:
                q.validate_elf_headers()
            except ImpossibleConstraintError as e:
                print(f"Q({file_size:#x}.{phdr_offset:02x}) impossible at offset {e.offset:#x}: {e.message}")
                continue

            holes = q.count_holes()
            if max(holes) < 8:
                # Ignore solutions with tiny holes
                continue

            print(f"Q({file_size}={file_size:#x}.{phdr_offset:#04x}) possible with holes {holes}:")
            q.print_hex(indent="    ")


if __name__ == "__main__":
    check_96()
    do_search()
