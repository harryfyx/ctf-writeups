# Description

- category: reverse
- link: https://play.duc.tf/challenges#All%20Father's%20Wisdom-52
- difficulty: beginner

```
All Father's Wisdom

We found this binary in the backroom, its been marked as "The All Fathers Wisdom" - See hex for further details. Not sure if its just old and hex should be text, or they mean the literal hex.

Anyway can you get this 'wisdom' out of the binary for us?

Author: pix
```

We are given a binary file. 

## Solve

Try to run the binary, nothing happens.

We open the binary with Ghidra, and see there is a `main.main` inside main function. This is likely not compiled with C. Maybe it's a golang binary?

We disassemble `main.main`, and find that it exits before printing flag.

```
void main.main(undefined8 param_1)

{
  os.exit(0);
  main.print_flag(param_1);
  return;
}
```

We want to print the flag, so let's skipp `os.exit`.

Run the binary with gdb, and break at `main.main`. Use gdb's disassemble

```
Breakpoint 1, 0x0000000000409930 in main.main ()
(gdb) disassemble
Dump of assembler code for function main.main:
=>  0x0000000000409930 <+0>:     sub    $0x18,%rsp
    0x0000000000409934 <+4>:     mov    %rdi,0x8(%rsp)
    0x0000000000409939 <+9>:     mov    0x8(%rsp),%rax
    0x000000000040993e <+14>:    mov    %rax,(%rsp)
    0x0000000000409942 <+18>:    movb   $0x1,0x17(%rsp)
    0x0000000000409947 <+23>:    cmpb   $0x0,0x17(%rsp)
    0x000000000040994c <+28>:    je     0x409957 <main.main+39>
    0x000000000040994e <+30>:    xor    %eax,%eax
    0x0000000000409950 <+32>:    mov    %eax,%edi
    0x0000000000409952 <+34>:    call   0x4357a0 <os.exit>
    0x0000000000409957 <+39>:    mov    (%rsp),%rdi
    0x000000000040995b <+43>:    call   0x4088c0 <main.print_flag>
    0x0000000000409960 <+48>:    add    $0x18,%rsp
    0x0000000000409964 <+52>:    ret
End of assembler dump. 
```

We want to skip the instruction at `main.main +28`. Let's step until that point, and set the zero flag so it does the jump.

```
(gdb) x $eflags
0x202:  Cannot access memory at address 0x202
(gdb) p 0x202 | (1<<6)
$3 = 578
(gdb) set $eflags = 578
(gdb) i r
...
eflags         0x246               [ ZF IF ] 
...
```

We see zero flag is set, and then continue. It then prints some hex.

`44 55 43 54 46 7b 4f 64 31 6e 5f 31 53 2d 4e 30 74 5f 43 7d`

Exit gdb. We use Python to convert it into string.

```bash
harryfyx@DESKTOP-QADD3OA:/mnt/d/ductf2023$ echo '44 55 43 54 46 7b 4f 64 31 6e 5f 31 53 2d 4e 30 74 5f 43 7d' | python3 -c "print(''.join([chr(int(i, 16)) for i in input().split(' ')]))"
DUCTF{Od1n_1S-N0t_C}
```