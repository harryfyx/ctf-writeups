## Description

- category: reverse
- link: https://app.hackthebox.com/challenges/498
- difficulty: 5 (Medium?)

```
ReRop

How is that even possible, I thought it was only an exploitation technique, but maybe it has other applications as well
```

We are given a elf binary.

## Solve

We see that it is a 64 bit elf binary. Run it, and see it asks for a flag, and checks it.

Try static analysis with Ghidra. The decompiler has nothing for the check function.

```
void check(void)

{
  return;
}
```

The disassembler has a ROP.

```
                        **************************************************************
                        *                          FUNCTION                          *
                        **************************************************************
                        undefined check()
        undefined         AL:1           <RETURN>
                        check                                           XREF[3]:     Entry Point(*), main:0040182d(c), 
                                                                                    004b4b58(*)  
004017b5 f3 0f 1e fa     ENDBR64
004017b9 48 8d 27        LEA        RSP,[RDI]
004017bc c3              RET
```

Brief description of return oriented programming (ROP). It is mainly used in pwn, when the attacker cannot inject shellcode to the stack (maybe due to non-executable stack protection), she can create a ROP chain buffer after overflow. The `ret` instruction sets the program counter (PC) to the value popped from the stack. So, by overflowing the buffer, the attacker now controls how the program is going to execute. When multiple ROP happens to execute something complex, it is called a ROP chain.

We see in the `check` function, RSP (stack top or stack pointer) is assgined to RDI, and it returns. The check function is done in a ROP chain.

How to analyze the program? I have a dumb idea. I am going to use gdb to print out what instructions it actually runs during the ROP chain.

Open the binary with GDB, and do some setups. After enntering `check`, I run `ni` multiple times until it writes `Nope`.

```
(gdb) set disassemble-next-line auto
(gdb) catch syscall ptrace
(gdb) b check
(gdb) run
Starting program: /mnt/d/htb/ReRop/rev_rerop/rerop
Enter the flag: aaaaaaaaaaaaaaaaaaaaaaaaaaa

    Breakpoint 2, 0x00000000004017b5 in check ()
  
=> 0x00000000004017b5 <check+0>:        f3 0f 1e fa     endbr64         
(gdb) ni
0x00000000004017b9 in check ()

=> 0x00000000004017b9 <check+4>:        48 8d 27        lea    (%rdi),%rsp        
(gdb)
0x00000000004017bc in check ()

=> 0x00000000004017bc <check+7>:        c3      ret 
(gdb)
0x0000000000450ec7 in __open_nocancel ()

=> 0x0000000000450ec7 <__open_nocancel+103>:    58      pop    %rax     
(gdb)
0x0000000000450ec8 in __open_nocancel ()

=> 0x0000000000450ec8 <__open_nocancel+104>:    c3      ret   
(gdb)
0x0000000000401eef in get_common_cache_info.constprop ()
      
=> 0x0000000000401eef <get_common_cache_info.constprop.0+175>:  5f      pop    %rdi       
(gdb)
0x0000000000401ef0 in get_common_cache_info.constprop ()
  
=> 0x0000000000401ef0 <get_common_cache_info.constprop.0+176>:  c3      ret       
(gdb)
0x0000000000409f1e in __gettext_extract_plural ()
  
=> 0x0000000000409f1e <__gettext_extract_plural+270>:   5e      pop    %rsi       
(gdb)
0x0000000000409f1f in __gettext_extract_plural ()
  
=> 0x0000000000409f1f <__gettext_extract_plural+271>:   c3      ret     
(gdb)
0x0000000000458142 in find_derivation ()

=> 0x0000000000458142 <find_derivation+3234>:   5a      pop    %rdx     
(gdb)
0x0000000000458143 in find_derivation ()

=> 0x0000000000458143 <find_derivation+3235>:   c3      ret   
(gdb)
0x000000000041aab6 in __lll_lock_wake_private ()
      
=> 0x000000000041aab6 <__lll_lock_wake_private+22>:     0f 05   syscall 
(gdb)
0x000000000041aab8 in __lll_lock_wake_private ()
   
=> 0x000000000041aab8 <__lll_lock_wake_private+24>:     c3      ret     
(gdb)
0x0000000000451fe0 in twalk ()

=> 0x0000000000451fe0 <twalk+0>:        48 89 c7        mov    %rax,%rdi
(gdb)
0x0000000000451fe3 in twalk ()

=> 0x0000000000451fe3 <twalk+3>:        c3      ret 
(gdb)
0x0000000000450ec7 in __open_nocancel ()

=> 0x0000000000450ec7 <__open_nocancel+103>:    58      pop    %rax     
(gdb)
0x0000000000450ec8 in __open_nocancel ()

=> 0x0000000000450ec8 <__open_nocancel+104>:    c3      ret   
(gdb)
0x0000000000452000 in twalk ()

=> 0x0000000000452000 <twalk+32>:       48 89 c6        mov    %rax,%rsi
(gdb)
0x0000000000452003 in twalk ()

=> 0x0000000000452003 <twalk+35>:       48 31 db        xor    %rbx,%rbx
(gdb)
0x0000000000452006 in twalk ()

=> 0x0000000000452006 <twalk+38>:       48 85 ff        test   %rdi,%rdi
(gdb)
0x0000000000452009 in twalk ()

=> 0x0000000000452009 <twalk+41>:       48 0f 48 de     cmovs  %rsi,%rbx
(gdb)
0x000000000045200d in twalk ()

=> 0x000000000045200d <twalk+45>:       48 01 dc        add    %rbx,%rsp
(gdb)
0x0000000000452010 in twalk ()

=> 0x0000000000452010 <twalk+48>:       c3      ret 
(gdb)
0x0000000000450ec7 in __open_nocancel ()

=> 0x0000000000450ec7 <__open_nocancel+103>:    58      pop    %rax     
(gdb)
0x0000000000450ec8 in __open_nocancel ()

=> 0x0000000000450ec8 <__open_nocancel+104>:    c3      ret   
(gdb)
0x0000000000458142 in find_derivation ()

=> 0x0000000000458142 <find_derivation+3234>:   5a      pop    %rdx     
(gdb)
0x0000000000458143 in find_derivation ()

=> 0x0000000000458143 <find_derivation+3235>:   c3      ret   
(gdb)
0x0000000000419ad8 in _IO_remove_marker ()
  
=> 0x0000000000419ad8 <_IO_remove_marker+56>:   48 89 02        mov    %rax,(%rdx)
(gdb)
0x0000000000419adb in _IO_remove_marker ()
         
=> 0x0000000000419adb <_IO_remove_marker+59>:   c3      ret   
(gdb)
0x0000000000450ec7 in __open_nocancel ()

=> 0x0000000000450ec7 <__open_nocancel+103>:    58      pop    %rax     
(gdb)
0x0000000000450ec8 in __open_nocancel ()

=> 0x0000000000450ec8 <__open_nocancel+104>:    c3      ret   
(gdb)
0x0000000000458142 in find_derivation ()

=> 0x0000000000458142 <find_derivation+3234>:   5a      pop    %rdx     
(gdb)
0x0000000000458143 in find_derivation ()

=> 0x0000000000458143 <find_derivation+3235>:   c3      ret   
(gdb)
0x0000000000419ad8 in _IO_remove_marker ()
  
=> 0x0000000000419ad8 <_IO_remove_marker+56>:   48 89 02        mov    %rax,(%rdx)
(gdb)
0x0000000000419adb in _IO_remove_marker ()
         
=> 0x0000000000419adb <_IO_remove_marker+59>:   c3      ret   
(gdb)
0x0000000000450ec7 in __open_nocancel ()

=> 0x0000000000450ec7 <__open_nocancel+103>:    58      pop    %rax     
(gdb)
0x0000000000450ec8 in __open_nocancel ()

=> 0x0000000000450ec8 <__open_nocancel+104>:    c3      ret   
(gdb)
0x0000000000401eef in get_common_cache_info.constprop ()
      
=> 0x0000000000401eef <get_common_cache_info.constprop.0+175>:  5f      pop    %rdi       
(gdb)
0x0000000000401ef0 in get_common_cache_info.constprop ()
  
=> 0x0000000000401ef0 <get_common_cache_info.constprop.0+176>:  c3      ret       
(gdb)
0x0000000000409f1e in __gettext_extract_plural ()
  
=> 0x0000000000409f1e <__gettext_extract_plural+270>:   5e      pop    %rsi       
(gdb)
0x0000000000409f1f in __gettext_extract_plural ()
  
=> 0x0000000000409f1f <__gettext_extract_plural+271>:   c3      ret     
(gdb)
0x0000000000458142 in find_derivation ()

=> 0x0000000000458142 <find_derivation+3234>:   5a      pop    %rdx     
(gdb)
0x0000000000458143 in find_derivation ()

=> 0x0000000000458143 <find_derivation+3235>:   c3      ret   
(gdb)
0x000000000041aab6 in __lll_lock_wake_private ()
      
=> 0x000000000041aab6 <__lll_lock_wake_private+22>:     0f 05   syscall 
(gdb)
 Nope   

(gdb) x $rax
0xffffffffffffffff:     Cannot access memory at address 0xffffffffffffffff
(gdb) set $rax = 0
```

We see the ROP chain, and the last syscall prints "Nope". You can delete all the `ret` to make this prettier, since it doesn't help the progrm logic. We try to narrow down the problem by finding out what make it print `Correct Flag!`. The last conditional instruction is `cmovs  %rsi,%rbx`. That means rbx (a register) either stays the same or set equal to rsi (note gdb uses the AT&T flavor). If we try to set it both ways, we see that the correct value of rbx will make it print correct.

Before going further, by checking the code we have seen so far, we see a syscall is returning -1 (eax register), and it makes the check fail. By learning how a syscall is called in assembly, we know this is `ptrace`. This is a common anti-GDB technique, we will bypass that, or the program always prints "Nope". The program uses ptrace to detect GDB. We need to bypass that by setting the return value of ptrace to 0.

Now, with further disassembling, we see more checks. There are 29 similar checks, reads an address from the stack (the user input), dereference it with an offset, does some calculations, and expect it to be 0. Each check will pop 18 registers * 8 bytes/register. `pop` and `ret` are all popping from the stack. So we now know what the program checks.

What we can do is to dump the stack and solve it by Python. We go to the beginning of the first check, and run `dump binary memory result.bin $rsp %rsp + 29 * 18 * 8` to save it as a file. Then we use this Python script to solve it.

```Py
buffer = [''] * 64
with open('result.bin', 'rb') as fp:
    for _ in range(29):
        addr = fp.read(8)
        fp.read(8)
        offset = int.from_bytes(fp.read(8), byteorder='little')
        fp.read(8); fp.read(8); fp.read(8); fp.read(8); fp.read(8)
        a = int.from_bytes(fp.read(8), byteorder='little')
        fp.read(8); fp.read(8)
        b = int.from_bytes(fp.read(8), byteorder='little')
        fp.read(8); fp.read(8)
        c = int.from_bytes(fp.read(8), byteorder='little')
        fp.read(8); fp.read(8); fp.read(8)

        # ((addr[offset] + a) ^ b) - c = 0
        # therefore => addr[offset] = (c ^ b) - a
        buffer[offset] = chr((c ^ b) - a)
print(''.join(buffer))
# HTB{W4iT_W4S_Th@t_PWN_0R_R3V}
```