<!--
SPDX-FileCopyrightText: 2026 Nicolas Iooss

SPDX-License-Identifier: MIT
-->

# Write-up for Synacktiv's 2025 Winter Challenge: Quinindrome

- *Author: [IooNag](https://infosec.exchange/@IooNag) ([GitHub](https://github.com/fishilico))*
- *Date: 2026-01-21*

## :santa: 1. A new challenge appears!

Following the [2025 Summer Challenge](https://www.synacktiv.com/en/publications/2025-summer-challenge-ocinception), Synacktiv [published](https://x.com/Synacktiv/status/1995902622738374764) a new challenge in December 2025: [2025 Winter Challenge: Quinindrome](https://www.synacktiv.com/en/publications/2025-winter-challenge-quinindrome) ([French version](https://www.synacktiv.com/publications/2025-winter-challenge-quinindrome)).

> The idea is to design a quinindrome, which is an ELF binary that meets these two requirements:
>
> 1. be a palindrome, meaning it's totally symmetrical,
> 2. and be a byte-wise quine: print its own file on stdout when executed.
>
> Of course, the process must end without a segfault, and the return code has to be set to 0.
>
> [...]
>
> the winner will be the one who manages to obtain the lowest score

On a Linux system, it is quite easy to build a program which fits both constraints, thanks to [shebang interpreter directive](https://en.wikipedia.org/wiki/Shebang_%28Unix%29):

```sh
#!/bin/cat
tac/nib/!#
```

This 21-byte program is a palindrome and when it is executed, Linux launches [`cat`](https://man7.org/linux/man-pages/man1/cat.1.html) with the file name.
This displays the content of the file and exits normally.

However, this program fails the [test script](./test_script.sh) provided by Synacktiv.
This script actually creates a container (based on the [`scratch` image](https://hub.docker.com/_/scratch)) that only contains the program under test.
As `cat` is not included in the container, it cannot be executed.

Now that this easy solution is not possible, what can actually work?

## :truck: 2. Compiling a fat solution

One of the simplest way of building a Quine consists in opening the program file given in `argv[0]`, reading it to a buffer and writing the buffer to the standard output:

```c
#include <fcntl.h>
#include <unistd.h>

static unsigned char buffer[10000000];

int main(int argc, char **argv) {
    int fd = open(argv[0], 0);
    size_t size = read(fd, buffer, sizeof(buffer));
    write(1, buffer, size);
    return 0;
}
```

Compiling this C program in a Debian 13 virtual machine leads to a 737 KiB executable:

```console
$ gcc -Os -static -o quine quine.c
$ stat --format=%s quine
754208
```

To make this program a palindrome, the naive way would be to add a byte-reversed copy to its end.
A less naive way consists in omitting the last byte in the copy, as it can behave like a *pivot* between the original part and its mirror.

```console
$ cat quine > quinindrome
$ python3 -c 'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read()[:-1][::-1])' \
    < quine >> quinindrome
$ chmod +x quinindrome
$ ./test_script.sh quinindrome
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 1508415
```

After several minutes, the [test script](./test_script.sh) validated this program was a valid solution!

But the score is very large.
How can the score be reduced as much as possible?

## :golf: 3. Code-golfing the executable again

As the score of a program fitting the requirements is its size, the aim is to produce a program as small as possible.
This is a domain called "code golfing" and my write-up for the previous challenge included a whole section with some tips: [Write-up for Synacktiv's 2025 Summer Challenge: OCInception, 6. (Bonus) Code-golfing the executable](https://github.com/fishilico/synacktiv-summer-chall-2025-ocinception/blob/4221d73fa0ecb6cb5336329004034faa038fd6ff/writeup.md#6-bonus-code-golfing-the-executable)

Instead of going through the explanations of all the tricks, let's study a solution to the problem of printing `Hello world\n` that was given in 98 bytes in <https://codegolf.stackexchange.com/questions/5696/shortest-elf-for-hello-world-n>:

```text
7F 45 4C 46 01 01 01 00 00 00 00 00 00 00 00 00
02 00 03 00 01 00 00 00 35 40 B3 04 2C 00 00 00
00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00
00 00 00 00 00 40 B3 04 B2 0C EB 1C 62 00 00 00
62 00 00 00 05 00 00 00 00 10 00 00 48 65 6C 6C
6F 20 77 6F 72 6C 64 0A B9 4C 40 B3 04 93 CD 80
EB FB
```

This program is neither a quine nor a palindrome, so why is it interesting to study it?
A quine can be crafted by writing the content of the program out instead of the string `"Hello world"`.
This makes it possible to modify this program to a working solution for the quinindrome challenge.

This StackExchange answer also provided some kind of description of the bytes:

```text
            org     0x04B34000
            db      0x7F, "ELF", 1, 1, 1, 0 ; e_ident
            dd      0, 0
            dw      2                       ; e_type
            dw      3                       ; e_machine
            dd      1                       ; e_version
            dd      _start                  ; e_entry
            dd      phdr - $$               ; e_phoff
            dd      0                       ; e_shoff
            dd      0                       ; e_flags
            dw      0x34                    ; e_ehsize
            dw      0x20                    ; e_phentsize
phdr:       dd      1                       ; e_phnum       ; p_type
                                            ; e_shentsize
            dd      0                       ; e_shnum       ; p_offset
                                            ; e_shstrndx
            db      0                                       ; p_vaddr
_start:     inc     eax
            mov     bl, 4
            mov     dl, 12                                  ; p_paddr
            jmp     short part2
            dd      filesize                                ; p_filesz
            dd      filesize                                ; p_memsz
            dd      5                                       ; p_flags
            dd      0x1000                                  ; p_align
str:        db      'Hello world', 10
part2:      mov     ecx, str
again:      xchg    eax, ebx
            int     0x80
            jmp     short again
filesize    equ     $ - $$EM_486
```

This syntax is the one used by a well-known assembler named [NASM](https://www.nasm.us/).
It enables writing x86 assembler statements (such as `inc eax` or `mov ecx, str`) interleaved with some integers with statements `db` (for bytes), `dw` (for 16-bit integers, *"words"*) and `dd` (for 32-bit integers, *"double-words"*).
The comments in the description map the fields used by the ELF headers to the content of the answer.

Indeed ELF executable files usually contain several headers, documented in [`man 5 elf`](https://man7.org/linux/man-pages/man5/elf.5.html):

- an "ELF header" called `Ehdr`
- a "program header" called `Phdr`
- a "section header" called `Shdr`

To run a program, the section header is not used so it can be omitted.
The program header contains information describing how the program is loaded.
It has to contain at least one entry which tells how the file is mapped to memory.
Finally, the ELF header is mandatory and always appear in the first bytes of the file.

Here are the 32-bit versions of C structures defining the ELF header and the program header, with some comments:

```c
typedef struct {
    unsigned char e_ident[16];  // ELF identifier "\x7fELF"
    uint16_t      e_type;       // Type of ELF file, should be ET_EXEC = 2
    uint16_t      e_machine;    // Architecture, should be EM_386 = 3 or EM_486 = 6
    uint32_t      e_version;
    Elf32_Addr    e_entry;      // Address of the entrypoint of the program
    Elf32_Off     e_phoff;      // File offset of the program header
    Elf32_Off     e_shoff;      // File offset of the section headr
    uint32_t      e_flags;
    uint16_t      e_ehsize;     // Size of the ELF header, should be 0x34
    uint16_t      e_phentsize;  // Size of Elf32_Phdr, should be 0x20
    uint16_t      e_phnum;      // Number of entries in the program header table
    uint16_t      e_shentsize;  // Size of Elf32_Shdr
    uint16_t      e_shnum;      // Number of entries in the section header table
    uint16_t      e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    uint32_t   p_type;   // Kind of entry, should be PT_LOAD = 1 for a loadable segment
    Elf32_Off  p_offset; // File offset of the segment
    Elf32_Addr p_vaddr;  // Address where the segment gets loaded
    Elf32_Addr p_paddr;  // "Physical address", ignored in Linux
    uint32_t   p_filesz; // Number of bytes from the file in the segment
    uint32_t   p_memsz;  // Number of bytes in memory for the segment
    uint32_t   p_flags;  // Permissions of the segment. Should be PF_X | PF_R = 5
    uint32_t   p_align;
} Elf32_Phdr;
```

A well-known trick to craft small ELF files consists in making these two headers overlap, using the fact that bytes `01 00 00 00 00 00 00 00` can be used to represent both:

- `e_phnum = 1; e_shentsize = 0; e_shnum = 0; e_shstrndx = 0` in the ELF header
- and `p_type = PT_LOAD; p_offset = 0` in the program header.

This trick was used in the StackExchange solution.

Then comes the assembly code.
What is happening?
To invoke operating system functions through syscalls in x86 (in 32-bit mode) on Linux, a software interrupt can be triggered thanks to instruction `int 0x80`.
The parameters of the syscall are provided in registers: `eax` to identify which system function is actually called ; and `ebx`, `ecx`, `edx`, `esi`, `edi` and `ebp` to provide the arguments.
The program is using two syscalls:

- [`write(int fd, void *buf, size_t count)`](https://man7.org/linux/man-pages/man2/write.2.html) (`eax = 4`) to write data to the standard output (`ebx = 1`) ;
- [`_exit(int status)`](https://man7.org/linux/man-pages/man2/exit.2.html) (`eax = 1`) to exit with a successful status code (`ebx = 0`).

Let's modify the code to output the content of the program.
To do so, the address where the program is loaded in memory needs to be put in register `ecx`.
A `mov` instruction with a 32-bit immediate value usually requires 5 bytes.
Using some tricks, it is possible to go down to 3 bytes when the address is `0xffff0000`, using 2 instructions: `dec %ecx` to set the register to `0xffffffff` and `inc %cx` to increment the low 16 bits (by the way, this address needs to be at least `0x10000`, to be above `/proc/sys/vm/mmap_min_addr`, and when running on a 64-bit system, userspace addresses can be above `0xc0000000` as there is no space reserved for the kernel).

This enables crafting a 14-byte quine in assembly code (using [AT&T syntax](https://en.wikipedia.org/wiki/X86_assembly_language#Syntax)):

```text
49      dec %ecx
66 41   inc %cx         ; set ecx = 0xffff0000 (address)
b2 ab   mov $0xab,%dl   ; set edx = 171 (file size)
b0 04   mov $0x4,%al    ; set eax = 4
43      inc %ebx        ; set ebx = 1
cd 80   int $0x80       ; write(1, 0xffff0000, 171)

4b      dec %ebx        ; set ebx = 0
58      pop %eax        ; set eax = 1 by using argc from the stack
cd 80   int $0x80       ; exit(0)
```

When Linux launches a program, the stack is initialized with several values: the number of arguments, the arguments, the environment variables... (in C: `{argc, argv[0], argv[1], ..., argv[argc-1], NULL, envp[0], ..., NULL}`).
As the test program is always run without any command-line argument in [`test_script.sh`](./test_script.sh), `argc = 1` and this value can be `pop`-ed from the stack to set a register to 1.

To test such a solution more easily, I wrote a Python script: [`solution_1_headers_code.py`](/solution_1_headers_code.py).
This script defines some functions helping to define the content of the headers and the code while ensuring overlapping fields use the same values:

```python
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
place_u32(phdr_offset + 0x04, 0, "Elf32_Phdr.p_offset")
place_u32(phdr_offset + 0x08, image_base, "Elf32_Phdr.p_vaddr")
place_u32(phdr_offset + 0x10, final_file_size, "Elf32_Phdr.p_filesz")
place_u32(phdr_offset + 0x14, final_file_size, "Elf32_Phdr.p_memsz")
place_u32(phdr_offset + 0x18, 5, "Elf32_Phdr.p_flags = PF_R | PF_X")
```

Knowing which bytes are defined enables displaying a hexadecimal dump of the quine with `??` to represent the undefined ones:

```text
 000000:  7f45 4c46 ???? ???? ???? ???? ???? ????
 000010:  0200 0300 ???? ???? 4800 ffff 2c00 0000
 000020:  ???? ???? ???? ???? ???? 2000 0100 0000
 000030:  0000 0000 0000 ffff ???? ???? ab00 0000
 000040:  ab00 0000 0500 0000 4966 41b2 abb0 0443
 000050:  cd80 4b58 cd80
```

This first solution produces the following quinindrome ([`solution_1_headers_code.bin`](./solution_1_headers_code.bin)):

```console
$ xxd solution_1_headers_code.bin
00000000: 7f45 4c46 0000 0000 0000 0000 0000 0000  .ELF............
00000010: 0200 0300 0000 0000 4800 ffff 2c00 0000  ........H...,...
00000020: 0000 0000 0000 0000 0000 2000 0100 0000  .......... .....
00000030: 0000 0000 0000 ffff 0000 0000 ab00 0000  ................
00000040: ab00 0000 0500 0000 4966 41b2 abb0 0443  ........IfA....C
00000050: cd80 4b58 cd80 cd58 4b80 cd43 04b0 abb2  ..KX...XK..C....
00000060: 4166 4900 0000 0500 0000 ab00 0000 ab00  AfI.............
00000070: 0000 00ff ff00 0000 0000 0000 0000 0100  ................
00000080: 2000 0000 0000 0000 0000 0000 0000 2cff   .............,.
00000090: ff00 4800 0000 0000 0300 0200 0000 0000  ..H.............
000000a0: 0000 0000 0000 0046 4c45 7f              .......FLE.

$ ./test_script.sh solution_1_headers_code.bin
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 171
```

There are still several undefined bytes in this file.
Let's go further down!

## :computer: 4. A very lax kernel loader

When analyzing the produced solution, somethings feels weird: the ELF header actually is invalid.
[Command `file`](https://man7.org/linux/man-pages/man1/file.1.html) reports:

```console
$ file solution_1_headers_code.bin
solution_1_headers_code.bin: ELF invalid class invalid byte order (SYSV), unknown class 0
```

A 32-bit ELF file usually starts with `0x7f, "ELF", 1, 1, 1` to indicate:

- `e_ident[EI_CLASS] = ELFCLASS32` (32-bit instruction set architecture)
- `e_ident[EI_DATA] = ELFDATA2LSB` (data in little endian)
- `e_ident[EI_VERSION] = EV_CURRENT` (version of the ELF specification)

Nevertheless these 3 bytes are not verified by the piece of code in Linux kernel responsible for loading ELF programs.
Where is this code?

In Linux kernel, when a program is launched (through syscalls such as `execve` or `execveat`), several loaders may be used.
They are implemented in files `binfmt_....c` in [directory `fs/`](https://github.com/torvalds/linux/blob/v6.12/fs/):

```text
binfmt_elf.c            for ELF files
binfmt_elf_fdpic.c      for FDPIC ELF files
binfmt_flat.c           for Flat files
binfmt_misc.c           to use /proc/sys/fs/binfmt_misc to invoke helper loaders
binfmt_script.c         for script files with shebang
compat_binfmt_elf.c     for 32-bit ELF files on 64-bit systems
```

The kernel actually supports other formats than ELF!
But on x86-based systems, FDPIC ELF and Flat are not available (they are used on some ARM systems and some systems without MMU, according to [`Kconfig`](https://github.com/torvalds/linux/blob/v6.12/fs/Kconfig.binfmt#L61)).
This is confirmed in a Debian 13 virtual machine by inspecting the configuration of the kernel:

```console
$ grep BINFMT /boot/config-6.12.57+deb13-amd64
CONFIG_BINFMT_ELF=y
CONFIG_COMPAT_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_BINFMT_MISC=m
```

On a 64-bit system, loading 32-bit ELF programs is handled by [`fs/compat_binfmt_elf.c`](https://github.com/torvalds/linux/blob/v6.12/fs/compat_binfmt_elf.c), which mostly defines some C macros and includes the main parser (cf. [line 144](https://github.com/torvalds/linux/blob/v6.12/fs/compat_binfmt_elf.c#L144)):

```c
/*
 * We share all the actual code with the native (64-bit) version.
 */
#include "binfmt_elf.c"
```

This file implements [function `load_elf_binary`](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c#L819), starting with:

```c
    retval = -ENOEXEC;
    /* First of all, some simple consistency checks */
    if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0)
        goto out;

    if (elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN)
        goto out;
    if (!elf_check_arch(elf_ex))
        goto out;
```

Here is the code which checks the first 4 bytes of ELF programs, as well as fields `e_type` and `e_machine`!

In the same file, [function `load_elf_phdrs`](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c#L506) verifies some constraints related to fields `e_phentsize` and `e_phnum`:

```c
    /*
     * If the size of this structure has changed, then punt, since
     * we will be doing the wrong thing.
     */
    if (elf_ex->e_phentsize != sizeof(struct elf_phdr))
        goto out;

    /* Sanity check the number of program headers... */
    /* ...and their total size. */
    size = sizeof(struct elf_phdr) * elf_ex->e_phnum;
    if (size == 0 || size > 65536 || size > ELF_MIN_ALIGN)
        goto out;

/* ... */
    retval = elf_read(elf_file, elf_phdata, size, elf_ex->e_phoff);
```

So `e_phentsize` needs to be `0x20`, `e_phnum` needs to actually counts the number of entries in the program header and `e_phoff` is used to locate the program header.

Fields `e_entry` is used to define where the execution starts and hence needs to be a valid memory address containing valid x86 instructions.

Would there be other constraints?
To check, the Python script was modified to use random bytes where no constraints were defined:

```python
if "--random-elf" in sys.argv:
    for i in range(len(program_bytes)):
        program_bytes[i] = random.randint(0, 255)
```

Running `./solution_1_headers_code.py --random-elf --run` helps confirming other fields in the ELF header are not actually used.

What about the program header?

- Field `p_type` has to be `PT_LOAD = 1`.
- Field `p_paddr` is not used.
- Field `p_align` is only used when the program is getting relocated to another address. With fixed-position executable (`e_type = ET_EXEC` instead of `ET_DYN`), it is not used.
- Only the 3 lowest significant bits of `p_flags` are used, to define the permissions of the segment (`PF_X = 1 ; PF_W = 2 ; PF_R = 4`). The 29 other bits can have any value.

Moreover, fields `p_offset`, `p_vaddr`, `p_filesz` and `p_memsz` follow some complex constraints.
While the intuitive rules would be "`p_offset = 0` to map the start of the file ; `p_vaddr = base address` to map the file at a given address ; `p_filesz = p_memsz = size of file` to map the whole file", in practice the implementation of functions [`load_elf_binary`](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c#L1205) and [`elf_load`](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c#L400) is much more lenient:

- `p_filesz <= p_memsz`: this ensures the memory region contains at least enough content from the file (the remaining content is filled with zeros).
- `eppnt->p_filesz != 0`: this ensures the memory region is loaded from the file (with [`elf_map` on line 408](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c#L408)) instead of being filled with zeros.

This enables crafting an ELF program where the program header is located 4 bytes after the start of the file: [`solution_2_phdr4.py`](./solution_2_phdr4.py):

```python
place_u32(phdr_offset + 0x00, 1, "Elf32_Phdr.p_type = PT_LOAD")
place_u32(phdr_offset + 0x04, 0, "Elf32_Phdr.p_offset")
place_u32(phdr_offset + 0x08, image_base, "Elf32_Phdr.p_vaddr")
place_u32(phdr_offset + 0x10, final_file_size, "Elf32_Phdr.p_filesz")
# e_entry and p_memsz are located at the same place
place_u32(phdr_offset + 0x14, image_base + code_offset, "Elf32_Phdr.p_memsz")
# e_phoff and p_flags are located at the same place
place_u8(phdr_offset + 0x18, 4, "Elf32_Phdr.p_flags = PF_R")
```

But this forces `p_flags` to be `4`, so the file is no longer mapped with the execution bit set... or is it?
Actually, with 32-bit x86 programs, when there is no `PT_GNU_STACK` entry in the program header, all segments are loaded with the executable bit!
This is the magic of [`elf_read_implies_exec`](https://github.com/torvalds/linux/blob/v6.12/arch/x86/include/asm/elf.h#L265-L290).

The ELF header takes `0x2e` bytes and there is not much space to fit some code in it:

```text
Hexdump:
 000000:  7f45 4c46 0100 0000 0000 0000 <vaddr  >
 000010:  0200 0300 <filesz > <entry  > 0400 0000
 000020:  ???? ???? ???? ???? ???? 2000 0100
```

To craft a quinindrome, the assembly code can be added right after and mirrored.
Another way consists in directly considering the mirrored bytes and using them in the code.
Using this strategy, I crafted a solution with 96 bytes ([`solution_2_phdr4.bin`](./solution_2_phdr4.bin)), using this 16-byte code:

```text
04 04       add $4, %al           ; eax = 4
b9 00010020 mov $0x20000100, %ecx ; ecx = 0x20000100
b2 60       mov $0x60, %dl        ; edx = 96 (file size)
86 dd       xchg %bl, %ch         ; ebx = 1, ecx = 0x20000000
cd 80       int $0x80             ; write(1, 0x20000000, 96)
58          pop %eax              ; eax = 1
eb f9       jmp . - 5             ; jump to "xchg %bl, %ch"
            ; xchg %bl, %ch       ; ebx = 0
            ; int $0x80           ; exit(0)
```

This code involves several tricks, such as using `xchg` and `jmp` to reuse instructions to invoke syscalls (this saves one byte).
This trick is documented for example on [StackExchange](https://codegolf.stackexchange.com/a/5741).
Moreover, the first `mov` instruction uses the mirrored bytes of the ELF header, and constraints the address where the file is loaded to `0x20000000`.

```console
$ xxd solution_2_phdr4.bin
00000000: 7f45 4c46 0100 0000 0000 0000 0000 0020  .ELF...........
00000010: 0200 0300 6000 0000 2f00 0020 0400 0000  ....`.../.. ....
00000020: 00f9 eb58 80cd dd86 60b2 2000 0100 b904  ...X....`. .....
00000030: 04b9 0001 0020 b260 86dd cd80 58eb f900  ..... .`....X...
00000040: 0000 0004 2000 002f 0000 0060 0003 0002  .... ../...`....
00000050: 2000 0000 0000 0000 0000 0001 464c 457f   ...........FLE.

$ ./test_script.sh solution_2_phdr4.bin
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 96
```

This solution has a single byte without any constraint (the one at `0x20`, being `p_align` and `e_shoff`).
This does not leave much room for improvement.
How can the score be reduced even more?

## :page_with_curl: 5. Gaining more freedom through page alignment

The implementation of [function `elf_map`](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c#L356) reveals something very interesting:

```c
#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN    ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN    PAGE_SIZE
#endif
#define ELF_PAGESTART(_v) ((_v) & ~(int)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

static unsigned long elf_map(struct file *filep, unsigned long addr,
        const struct elf_phdr *eppnt, int prot, int type,
        unsigned long total_size)
{
    unsigned long map_addr;
    unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
    unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
    addr = ELF_PAGESTART(addr);
    size = ELF_PAGEALIGN(size);
/* ... */
    if (total_size) {
        total_size = ELF_PAGEALIGN(total_size);
        map_addr = vm_mmap(filep, addr, total_size, prot, type, off);
```

The call to `vm_mmap` does not use `addr` and `size` directly, but aligns values according to the size of a memory page, which is 4096 bytes on x86.
The reason to do so is likely related to the way the MMU (Memory Management Unit) works in pages and needs to operate on addresses multiple of 4096.

In practice, this means it is possible to craft an ELF program with:

- `p_offset = 0x123` (this value needs to be `0 <= p_offset <= 0xfff`)
- `p_vaddr = 0x20000123` (this value needs to be `image_base + p_offset`)
- `p_filesz = 1` (this value needs to be `1 <= p_filesz <= 0xfff` and `p_filesz <= p_memsz`)

This can be tested with `./solution_2_phdr4.py --123 --run`, which produced [`solution_2_phdr4_0x123.bin`](./solution_2_phdr4_0x123.bin).

```console
$ xxd solution_2_phdr4_0x123.bin
00000000: 7f45 4c46 0100 0000 2301 0000 2301 0020  .ELF....#...#..
00000010: 0200 0300 0100 0000 2f00 0020 0400 0000  ......../.. ....
00000020: 00f9 eb58 80cd dd86 60b2 2000 0100 b904  ...X....`. .....
00000030: 04b9 0001 0020 b260 86dd cd80 58eb f900  ..... .`....X...
00000040: 0000 0004 2000 002f 0000 0001 0003 0002  .... ../........
00000050: 2000 0123 0000 0123 0000 0001 464c 457f   ..#...#....FLE.

$ readelf --program-headers solution_2_phdr4_0x123.bin
readelf: Warning: The e_shentsize field in the ELF header is larger than the size of an ELF section header
readelf: Error: Reading 57263076 bytes extends past end of file for section headers

Elf file type is EXEC (Executable file)
Entry point 0x2000002f
There is 1 program header, starting at offset 4

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000123 0x20000123 0x00030002 0x00001 0x2000002f R   0x58ebf900

$ ./test_script.sh solution_2_phdr4_0x123.bin
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 96
```

Even though this program does not follow the ELF specification, it still managed to be loaded by Linux.

Attentive readers might wonder: even though `p_filesz = 1`, why was the whole file loaded in memory and not filled with zeros?
Indeed, in usual ELF files, a memory segment is loaded and if `p_filesz < p_memsz`, some bytes are set to zero.
This mechanism is used for example to define a single read-write segment with both sections `.data` and `.bss` and make the kernel initialize `.bss` with zeros.

However, [function `elf_load`](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c#L411-L422) only set bytes to zero after `p_vaddr + p_filesz`, so using a value of `p_vaddr` which comes after the actual content (like `0x20000123`, where the content stops at `0x20000060`) makes the kernel not perform any zeroing.
And even if `p_offset` and `p_vaddr` stayed reasonable (`p_offset = 0`, `p_vaddr = 0x20000000`), the actual logic of setting bytes to zero would have failed because the memory is mapped without the write permission (bit `PF_W = 2` is missing from `p_flags = 4`).
Therefore it is actually possible to use `p_filesz = 1`, or even any value between `1` and `0xfff`, and have the ELF program still be executed.

With these new degrees of freedom, is it possible to shrink the solution even further?
To answer this, I wrote a Python script which tried every file size (starting from `0x2e`, the size of the ELF header) and every possible offset of the program header: [`search_size_phoff.py`](search_size_phoff.py).
For each combination, it crafted an ELF program and tried to validate all constraints required by Linux.

This program found a quinindrome pattern with 65 bytes and `e_phoff = 4`, displaying the possible values of some bytes:

```text
Q(65=0x41.0x04) possible with holes [1, 4, 1, 2, 1, 2, 1, 4, 1]:
    0000:  7f45 4c46 0100 0000 ..v0 0000 .... ....
    0010:  0200 v100 0100 20.. v2v3 .... 0400 0000
    0020:  ..00 0000 04.. ..v3 v2.. 2000 0100 v100
    0030:  02.. .... ..00 00v0 ..00 0000 0146 4c45
    0040:  7f
    - v0 at 0x9 in {00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f}
    - v1 at 0x12 in {03,06}
    - v2 at 0x18 in {00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,16,17,18,19,1a,1b,1c,1d,1e,1f,20,21,22,23,24,25,26,27,28,29,2a,2b,2c,2d,2e,2f,30,31,32,33,34,35,36,37,38,39,3a,3b,3c,3d,3e,3f,40}
    - v3 at 0x19 in {00,10,20,30,40,50,60,70,80,90,a0,b0,c0,d0,e0,f0}
    - e_entry  at 0x18 is 0x....v3v2
    - p_offset at 0x08 is 0x0000v0..
    - p_vaddr  at 0x0c is 0x........
    - p_filesz at 0x14 is 0x..200001
    - p_memsz  at 0x18 is 0x....v3v2
    - p_flags  at 0x1c is 0x00000004
```

The assembly code has to fit all the holes marked with dots in this representation.
This seems impossible to achieve, as the largest hole is 4-byte wide.
A new constraint was therefore added: there must be at least 8 consecutive bytes not covered by any constraints from the headers.

This led to finding a pattern with 77 bytes and `e_phoff = 0x2c`:

```text
Q(77=0x4d.0x2c) possible with holes [12, 1, 1, 7, 1, 1, 12]:
    0000:  7f45 4c46 .... .... .... .... .... ....
    0010:  0200 v000 ..v1 00.. 2c00 00v2 2c00 0000
    0020:  0100 20.. .... .... .... 2000 0100 0000
    0030:  2cv2 0000 2c.. 00v1 ..00 v000 02.. ....
    0040:  .... .... .... .... ..46 4c45 7f
    - v0 at 0x12 in {03,06}
    - v1 at 0x15 in {00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f}
    - v2 at 0x1b in {00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f}
    - e_entry  at 0x18 is 0xv200002c
    - p_offset at 0x30 is 0x0000v22c
    - p_vaddr  at 0x34 is 0xv100..2c
    - p_filesz at 0x3c is 0x......02
    - p_memsz  at 0x40 is 0x........
    - p_flags  at 0x44 is 0x........
```

Having 12 bytes to craft some assembly code seems doable.
However `e_entry = 0x...002c`, which means the execution has to start executing the bytes `01 00 00 00 2c ...` (at file offset `0x2c`).
In 32-bit x86, `01 00` is decoded as instruction `add %eax,(%eax)`, which loads some value from the memory location targeted by register `eax`.
This register is initialized to zero, so the program starts by dereferencing a NULL pointer, which makes it crash.
This is not a good way towards finding a working quinindrome.

Once the constraint "`e_entry` must not target bytes required to be `01 00`" was added, the Python script identified a third pattern using 81 bytes:

```text
Q(81=0x51.0x2c) possible with holes [12, 4, 1, 3, 1, 4, 12]:
    0000:  7f45 4c46 .... .... .... .... .... ....
    0010:  0200 v000 .... .... v1v2 ..v3 2c00 0000
    0020:  2c00 0000 0100 20.. .... 2000 0100 0000
    0030:  2c00 0000 2cv3 ..v2 v1.. .... ..00 v000
    0040:  02.. .... .... .... .... .... ..46 4c45
    0050:  7f
    - v0 at 0x12 in {03,06}
    - v1 at 0x18 in {00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,16,17,18,19,1a,1b,1c,1d,1e,1f,20,21,22,23,24,25,26,27,28,29,2a,2b,2c,2d,2e,2f,30,31,32,33,34,35,36,37,38,39,3a,3b,3c,3d,3e,3f,40,41,42,43,44,45,46,47,48,49,4a,4b,4c,4d,4e,4f,50}
    - v2 at 0x19 in {00,10,20,30,40,50,60,70,80,90,a0,b0,c0,d0,e0,f0}
    - v3 at 0x1b in {00,10,20,30,40,50,60,70,80,90,a0,b0,c0,d0,e0,f0}
    - e_entry  at 0x18 is 0xv3..v2v1
    - p_offset at 0x30 is 0x0000002c
    - p_vaddr  at 0x34 is 0xv2..v32c
    - p_filesz at 0x3c is 0x00v000..
    - p_memsz  at 0x40 is 0x......02
    - p_flags  at 0x44 is 0x........
```

This time, `e_entry` no longer has any constraint and can target unconstrained bytes.
This pattern imposes some relationships between `e_entry` and `p_vaddr`, which seem manageable.
[`solution_3_minimal.py`](./solution_3_minimal.py) produces a quinindrome following this pattern and using this 20-byte code:

```text
43          inc %ebx              ; ebx = 1
04 04       add $4, %al           ; eax = 4
b9 00030002 mov $0x02000300, %ecx ; ecx = 0x02000300
c1 e1 08    shl $8, %ecx          ; ecx = 0x00030000
45          inc %ebp              ; Have p_flags&7 = PF_R | PF_X
b2 51       mov $0x51, %dl        ; edx = 81 (file size)
cd 80       int $0x80             ; write(1, 0x00030000, 81)
4b          dec %ebx              ; ebx = 0
58          pop %eax              ; eax = 1
cd 80       int $0x80             ; exit(0)
```

```text
Hexdump:
 000000:  7f45 4c46 80cd 584b 80cd 51b2 4508 e1c1
 000010:  0200 0300 b904 0443 3900 0300 2c00 0000
 000020:  2c00 0000 0100 20?? ???? 2000 0100 0000
 000030:  2c00 0000 2c00 0300 3943 0404 b900 0300
 000040:  02c1 e108 45b2 51cd 804b 58cd 8046 4c45
 000050:  7f
```

In this configuration, 3 bytes in the middle of the file do not have any constraint (because `e_flags` and `e_ehsize` are not used by the kernel).
To make the solution a bit fun, I wrote a smiley.

```console
$ xxd solution_3_minimal.bin
00000000: 7f45 4c46 80cd 584b 80cd 51b2 4508 e1c1  .ELF..XK..Q.E...
00000010: 0200 0300 b904 0443 3900 0300 2c00 0000  .......C9...,...
00000020: 2c00 0000 0100 205e 5f5e 2000 0100 0000  ,..... ^_^ .....
00000030: 2c00 0000 2c00 0300 3943 0404 b900 0300  ,...,...9C......
00000040: 02c1 e108 45b2 51cd 804b 58cd 8046 4c45  ....E.Q..KX..FLE
00000050: 7f                                       .

$ ./test_script.sh solution_3_minimal.bin
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 81
```

## :boom: 6. (Bonus) It works on my machine!

Before submitting any solution to the challenge organizers, I made sure the test script was successful in a virtual machine running Debian 13.
This should have prevented any situation where a solution worked for me but not on the organizers' side.

Unfortunately, this happened.

Here is a [solution](./solution_3_with_bug.bin) I sent which was problematic:

```console
$ xxd solution_3_with_bug.bin
00000000: 7f45 4c46 80cd 584b 80cd 4308 e1c1 51b2  .ELF..XK..C...Q.
00000010: 0200 0300 b904 0490 3900 0300 2c00 0000  ........9...,...
00000020: 2c00 0000 0100 2000 0000 2000 0100 0000  ,..... ... .....
00000030: 2c00 0000 2c00 0300 3990 0404 b900 0300  ,...,...9.......
00000040: 02b2 51c1 e108 43cd 804b 58cd 8046 4c45  ..Q...C..KX..FLE
00000050: 7f                                       .

$ ./test_script.sh solution_3_with_bug.bin
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 81
```

This uses similar code as the one presented as the [minimal solution](./solution_3_minimal.bin):

```text
90          nop
04 04       add $4, %al           ; eax = 4
b9 00030002 mov $0x02000300, %ecx ; ecx = 0x02000300
b2 51       mov $0x51, %dl        ; edx = 81 (file size)
c1 e1 08    shl $8, %ecx          ; ecx = 0x00030000
43          inc %ebx              ; ebx = 1
cd 80       int $0x80             ; write(1, 0x00030000, 81)
4b          dec %ebx              ; ebx = 0
58          pop %eax              ; eax = 1
cd 80       int $0x80             ; exit(0)
```

Why would this program not work?
`readelf` reports:

```console
$ readelf --program-headers solution_3_with_bug.bin
...
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x00002c 0x0003002c 0x04049039 0x300b9 0xc151b202   E 0xcd584b80
```

Field flags is displayed `E`, not `R E`.
Indeed, in this program, `p_flags = 0xe1` only has bit `PF_X = 1` set, not `PF_R = 4` (among the 3 least significant bits).
On x86 processors, the Memory Management Engine (MMU) historically only had 2 bits to define permissions in page tables: `W` to enable write access and `NX` to prevent execution.
The read access was always granted so long as the memory page was present in the page table of a process.
This means there was no mechanism to implement "Execute-Only" or "Write-Only" memory in programs: memory regions were either Read-Only, Read-Write, Read-Execute, Read-Write-Execute or inaccessible.

This changed a few years ago where Intel VT-x introduced the ability to define Execute-Only pages in Extended Page Tables (EPT).
However I was not aware of a mechanism enabling a mainline Linux kernel to use such a feature to mark userspace pages as Execute-Only.

Searching a bit what other feature could be involved, I stumbled upon PKU (Memory Protection Keys Userspace), documented on <https://docs.kernel.org/core-api/protection-keys.html>.

> Memory Protection Keys provide a mechanism for enforcing page-based protections, but without requiring modification of the page tables when an application changes protection domains.

This feature enables making two threads of the same process able to access a different set of memory regions (a restricted thread can be configured in such a way it cannot access some regions ; a privileged thread can be configured to be the only one allowed to access some sensitive regions).
It can also be used to disable the read permission of some memory regions.

In 2016, a feature was integrated in Linux 4.6 to make Execute-Only memory regions possible: <https://github.com/torvalds/linux/commit/62b5f7d013fc455b8db26cf01e421f4c0d264b92>

> Protection keys provide new page-based protection in hardware.
> But, they have an interesting attribute: they only affect data
> accesses and never affect instruction fetches.  That means that
> if we set up some memory which is set as "access-disabled" via
> protection keys, we can still execute from it.
>
> This patch uses protection keys to set up mappings to do just that.
> If a user calls:
> ```c
> mmap(..., PROT_EXEC);
> ```
> or
> ```c
> mprotect(ptr, sz, PROT_EXEC);
> ```
> (note `PROT_EXEC`-only without `PROT_READ`/`WRITE`), the kernel will
> notice this, and set a special protection key on the memory.  It
> also sets the appropriate bits in the Protection Keys User Rights
> (PKRU) register so that the memory becomes unreadable and
> unwritable.

Experimenting with [QEmu](https://www.qemu.org/) shows that PKU is actually the reason the solution worked for me (on a virtual machine without PKU) but not for the organizers.

Here are some steps showing how to experimentally reproduce the issue.

1. Download file `debian-live-13.2.0-amd64-standard.iso` from a Debian mirror server (for example <https://debian.obspm.fr/debian-cd/13.2.0-live/amd64/iso-hybrid/>)
2. Create a directory named `share` and put the [quinindrome](./solution_3_with_bug.bin) in it: `q.bin`.
3. Launch a QEMU virtual machine with a processor enabling every features (option `-cpu max`):

```sh
qemu-system-x86_64 -enable-kvm -m 8G -cpu max -smp cores=4 -boot d \
    -drive file=debian-live-13.2.0-amd64-standard.iso,media=cdrom \
    -drive file=fat:rw:share/,format=raw,media=disk
```

4. In the virtual machine, confirm that PKU is available:

```sh
grep ' pku' /proc/cpuinfo && echo 'PKU is available'
```

5. In the virtual machine, mount the shared directory and run the program with `strace`:

```sh
sudo mount /dev/sda1 /mnt
sudo apt install -y strace
strace /mnt/q.bin
```

6. Observe that syscall `write` fails with error `EFAULT` and that the program bytes are not actually written to the output:

```text
execve("/mnt/q.bin", ["/mnt/q.bin"], 0x7ffce8c1a540 /* 20 vars */) = 0
[ Process PID=1468 runs in 32 bit mode. ]
write(1, 0x30000, 81)                   = -1 EFAULT (Bad address)
exit(0)                                 = ?
+++ exited with 0 +++
```

7. Launch another virtual machine without PKU (option `-cpu max,-pku`):

```sh
qemu-system-x86_64 -enable-kvm -m 8G -cpu max,-pku -smp cores=4 -boot d \
    -drive file=debian-live-13.2.0-amd64-standard.iso,media=cdrom \
    -drive file=fat:rw:share/,format=raw,media=disk
```

8. Repeat instructions 4 and 5 and observe that syscall `write` now succeeds.

Moreover, using `-cpu kvm64` on my test machine did not enable PKU and using `-cpu kvm64,+pku` did.
Mystery solved! :mag:

## :checkered_flag: Conclusion

Crafting an ELF file as small as possible is a pleasant way to explore how lenient the Linux kernel is, when parsing ELF files.
This enabled discovering new tricks to craft programs which still get successfully loaded and executed but make usual tools fail:

```console
$ file ./solution_3_minimal.bin
./solution_3_minimal.bin: ELF, unknown class 128

$ objdump -x ./solution_3_minimal.bin
objdump: ./solution_3_minimal.bin: file format not recognized

$ gdb ./solution_3_minimal.bin
...
"/vagrant/./solution_3_minimal.bin": not in executable format: file format not recognized

$ ./solution_3_minimal.bin | base64
f0VMRoDNWEuAzVGyRQjhwQIAAwC5BARDOQADACwAAAAsAAAAAQAgXl9eIAABAAAALAAAACwAAwA5
QwQEuQADAALB4QhFslHNgEtYzYBGTEV/
```

Thanks to the challenge authors and organizers for having organized such a fun event!
