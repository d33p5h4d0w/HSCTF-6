# Bit
* Here the binary lets you flip one bit of any address (writable). But it gives only 4 tries.
```
- We need to loop this so that we can flip multiple bits
- We need to leak (it is easy since binary prints the value after flip)
- Get a shell
```

## Loop
* Flipping 4 bits of `exit` to reach back to main. Hence we jump to `0x080487e7` which only differs by 4 bit to `exit` GOT entry at that point `0x080484f6`
* Now we can flip any number of bits

## Leak
* Double flip some GOT entry to get the leak without changing value. 
* Get libc base

## Getting shell
* Overwrite `setvbuf` GOT entry to a magic gadget.
* Use `one_gadget` tool to get that.
* This is needed since we cannot create a rop chain to pass arguments.
* Also, `setvbuf` is used because we won't inteact with a broken pointer in the middle.
* When overwrite is done, we flip the `exit` address to the main where `setvbuf` is called.
* [Solve.py](./exp.py) is the solution.
