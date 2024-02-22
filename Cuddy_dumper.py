from pwn import *
from time import sleep

# #
#> Written during playing with Cuddy WR300
# #

r = remote("router.local",23)

firm_out = open(sys.argv[3],"wb")

r.recvuntil(":");r.sendline("admin")
r.recvuntil(":");r.sendline("admin")

r.sendline("os")
r.recvuntil("OS>")

address = int(sys.argv[1],16)
offset = sys.argv[2]

limit = 0x1ffffc

while address != limit:

        r.sendline("spi rd "+hex(address)+" "+offset)

        recvbuff = r.recvuntil("OS>").strip()

        if b"ACT" in recvbuff:
                r.sendline("spi rd "+hex(address)+" "+offset)
                recvbuff = r.recvuntil("OS>").strip()

        data = int(b"0x"+recvbuff.split()[0],16)
        sleep(0.1)
        print("Data at address {} = {}".format(hex(address),p32(data)))
        address += 4
        firm_out.write(p32(data))
