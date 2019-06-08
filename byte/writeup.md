# Byte
* This is an format string exploit. It flips a byte in the given address starting from `f` (hex). Checking the memory map, only writeable address starting from `f` is stack.
* Also it checks for a variable at `$ebp-0x8e`, which is initialized to 1. If we make it 0, we get the flag.
* It gives 2 chances. On the first chance, we need to leak a stack address, and calculate the offset to the address we need to zero out the byte.
* On the second chance we enter the address and get the flag.
* 7th variable on the stack is a stack pointer. It is at an offset of `+314` from the target address. We leak that with `%7$x`.

![Screenshot][byte]

[byte]: ./byte.png