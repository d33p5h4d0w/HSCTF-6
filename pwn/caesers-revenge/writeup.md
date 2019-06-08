# Caesers-revenge

* This is a format string bug. It asks for an input string and a shift value. caesar cipher is run on it. Then the result is printed with printf.
* We get only one chance. So
```
- We need to loop the function
- We need to get a leak
- We need to overwrite a GOT with system to call /bin/sh.
```
### Loop
* We loop the function by overwriting `puts` GOT with the function pointer of `caeser`.
* Now we get to loop this function and thus multiple format string payloads can be submitted.

### Leak
* We leak some GOT pointers. Using these leaks we find the glibc using [Libc database](https://libc.blukat.me/)
* Using this we calculate libc base and then system address.

### System
* If we check the disassembly, the send string (shift) will be passed to `strtol`.
* So we overwrite `strtol` GOT with `system`. Now we can enter `/bin/sh` to the shift input and get a shell.
* We use `hn` format specifier to write 2 bytes twice at `strtol`s GOT. (Upper 4 bytes are same for strtol and system).
* [solve.py](./exp.py) is the solution

### Notes
...Our target address contains null bytes. Hence we need to put the address after the format string. Else printf will stop at a null byte and we cannot overwrite or leak.
...The pointers we write are large numbers hence we split into two 2 bytes (%hn)
...Careful. The pointer may contain ascii, hence if you use a shift, address might change due to caeser cipher
...I used %`number`c to increase number of byte written (used by n). Hence first we need to write `system`s zeroth byte or  second byte based on their value. If two bytes with lower value needs to be written first. (Check the if high < low:)
...I used 1 shift for caeser, hence %n is %m and others too.