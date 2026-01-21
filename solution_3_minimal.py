#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Nicolas Iooss
#
# SPDX-License-Identifier: MIT

"""Craft an quinindrome file using overlapping headers with program header at 4 bytes"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import tempfile

from pathlib import Path


image_base = 0x00030000
phdr_offset = 0x2c
code_offset = 0x39
final_file_size = 81

program_bytes = bytearray(final_file_size)
program_sources: dict[int, list[str]] = {}  # Sources of bytes, empty when undefined


def place_u8(offset: int, value: int, source: str) -> None:
    """Place a byte in the program"""
    assert 0 <= offset < len(program_bytes)
    if existing_sources := program_sources.get(offset):
        if program_bytes[offset] != value:
            print(
                f"Error while placing byte at {offset:#x}: old {program_bytes[offset]:#x} from {existing_sources!r}, new {value:#x} from {source!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        existing_sources.append(source)
    else:
        program_bytes[offset] = value
        program_sources[offset] = [source]


def place_bytes(offset: int, data: bytes | bytearray, source: str) -> None:
    """Place several bytes in the program"""
    for data_offset, value in enumerate(data):
        place_u8(offset + data_offset, value, f"{source} [{data_offset}]")


def place_u16(offset: int, value: int, source: str) -> None:
    """Place a 16-bit integer in the program"""
    place_bytes(offset, value.to_bytes(2, "little"), source)


def place_u32(offset: int, value: int, source: str) -> None:
    """Place a 32-bit integer in the program"""
    place_bytes(offset, value.to_bytes(4, "little"), source)


if "--random-elf" in sys.argv:
    # Test ELF parsing reliability using random bytes
    for i in range(len(program_bytes)):
        program_bytes[i] = random.randint(0, 255)


# ELF header
place_bytes(0, b"\x7fELF", "Elf32_Ehdr.e_ident = ELF magic")
place_u16(0x10, 2, "Elf32_Ehdr.e_type = ET_EXEC")
place_u16(0x12, 3, "Elf32_Ehdr.e_machine = EM_386")  # can also be EM_486 = 6
place_u32(0x18, image_base + code_offset, "Elf32_Ehdr.e_entry")
place_u32(0x1c, phdr_offset, "Elf32_Ehdr.e_phoff")
place_u16(0x2a, 0x20, "Elf32_Ehdr.e_phentsize")
place_u16(0x2c, 1, "Elf32_Ehdr.e_phnum")

# Program header
place_u32(phdr_offset + 0x00, 1, "Elf32_Phdr.p_type = PT_LOAD")
place_u32(phdr_offset + 0x04, 0x2c, "Elf32_Phdr.p_offset")
place_u32(phdr_offset + 0x08, image_base + 0x2c, "Elf32_Phdr.p_vaddr")

# write(eax=4, ebx=1, ecx=start, edx=size)
place_bytes(code_offset + 0x00, b"\x43", "inc %ebx")
place_bytes(code_offset + 0x01, b"\x04\x04", "add $4, %al")
place_bytes(code_offset + 0x03, b"\xb9\0\x03\0\x02", "mov $((image_base<<8)+2), %ecx")  # Adjust on Ehdr fields
place_bytes(code_offset + 0x08, b"\xc1\xe1\x08", "shl $8, %ecx")
place_bytes(code_offset + 0x0b, b"\x45", "inc %ebp")  # Set p_flags to RX
place_bytes(code_offset + 0x0c, bytes((0xb2, final_file_size)), "mov $file_size, %dl")
place_bytes(code_offset + 0x0e, b"\xcd\x80", "int $0x80")
# exit(eax=1, ebx=0)
place_bytes(code_offset + 0x10, b"\x4b", "dec %ebx")
place_bytes(code_offset + 0x11, b"\x58", "pop %eax")  # Pop argc = 1
place_bytes(code_offset + 0x12, b"\xcd\x80", "int $0x80")

# Smiley in the middle
place_bytes(0x27, b"^_^", "smiley")

# Make the palindromisation happen
for i, b in enumerate(program_bytes):
    if s := program_sources.get(i):
        place_u8(final_file_size - 1 - i, b, f"Mirror of {' ; '.join(s)}")

# Disassemble the file
with tempfile.NamedTemporaryFile() as tmp:
    print(f"Writing {tmp.name}")
    tmp.write(program_bytes)
    tmp.flush()
    subprocess.run(["objdump", "-D", "-bbinary", "-mi386", tmp.name], check=True)

print("Hexdump:")
for iline in range(0, len(program_bytes), 16):
    hexline = ""
    for i in range(16):
        if iline + i >= len(program_bytes):
            hexline += "  "
        elif program_sources.get(iline + i):
            hexline += f"{program_bytes[iline + i]:02x}"
        else:
            hexline += "??"
        if i % 2:
            hexline += " "
    print(f" {iline:06x}:  {hexline.strip()}")

# We built a quinindrome directly, there is no need to make it a palindrome
quinindrome = bytes(program_bytes)

quinindrome_path = Path(__file__[:-3] + ".bin")
print(f"Writing the quinindrome to {quinindrome_path}")
with open(quinindrome_path, "wb") as f:
    f.write(quinindrome)
os.chmod(quinindrome_path, 0o755)

# subprocess.run(["readelf", "-hl", quinindrome_path], check=False)
# subprocess.run(["objdump", "-D", "-bbinary", "-mi386", quinindrome_path], check=True)

print(f"Generated a solution with {len(program_bytes)} -> {len(quinindrome)} bytes")
if len(quinindrome) != final_file_size:
    print(
        f"Error: please modify final_file_size = {len(quinindrome)} instead of {final_file_size}",
        file=sys.stderr,
    )
    sys.exit(1)

if "--run" in sys.argv:
    # Run with strace
    print("strace:")
    output = subprocess.check_output(["strace", quinindrome_path])
    print(f"Received {len(output)} bytes: {output!r}")
    assert output == quinindrome

    print(f"Launching ./test_script.sh {quinindrome_path.name}")
    subprocess.run(
        ["./test_script.sh", quinindrome_path.name], check=True, cwd=quinindrome_path.parent
    )
