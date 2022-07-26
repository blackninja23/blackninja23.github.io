## **0x41haz Tryhackme**
From description given in challenge <a href='https://tryhackme.com/room/0x41haz'>0x41haz</a>

  ```
  Task 1: Find the password!
  In this challenge, you are asked to solve a simple reversing solution. Download and analyze the binary to discover the password.

  There may be anti-reversing measures in place!
  ```
- Download binary given from challenge <a href='https://tryhackme.com/room/0x41haz'>0x41haz</a>
- Using file command to determine file type
  ```file
  file 0x41haz.0x41haz
  ```
- Result from file command
  ```
  0x41haz.0x41haz: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
  ```
  It seems weird by see this `unknown arch 0x3e00`
   we google around and found <a href='https://pentester.blog/?p=247'>article</a> that define

  ```
   - The 5th byte defines format 32 bits (1) or 64 bits (2)
   - The 6th byte defines endianness LSB (1)  MSB (1)
  ```
- using hexeditor to  check it
  ```
  hexeditor 0x41haz.0x41haz
  ```
    <img src='/assets/img/0x41haz/2022-07-20_09-44.png' alt=''>

  As you can see 6th byte is 02 and not 01 for LSB (little endianness).so we change it to 01 using same hexeditor

    <img src='/assets/img/0x41haz/changed.png' alt=''>

- And the header was changed
  ```file
  └─$ file 0x41haz.0x41haz 
  0x41haz.0x41haz: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
  BuildID[sha1]=6c9f2e85b64d4f12b91136ffb8e4c038f1dc6dcd, for GNU/Linux 3.2.0, stripped
  ```
- Starting basically
  ```strings
  strings 0x41haz.0x41haz
  ```
  Result from strings command

  ```
  [REMOVED]
  u/UH
  2@@25$gfH
  sT&@f
  []A\A]A^A_
  =======================
  Hey , Can You Crackme ?
  =======================
  It's jus a simple binary 
  Tell Me the Password :
  Is it correct , I don't think so.
  Nope
  Well Done !!
  ;*3$"

  [REMOVED]
  ```
- it require some password then let us use radare
  ```radare
  └─$ r2 -d ./0x41haz.0x41haz 
  [0x7f60dd9b0050]> aaa
  [REMOVED]
  [0x7f60dd9b0050]> afl
  0x55f410331080    1 43           entry0
  0x55f410333fe0    1 4124         reloc.__libc_start_main
  0x55f410331030    1 6            sym.imp.puts
  0x55f410331040    1 6            sym.imp.strlen
  0x55f410330000    2 40           loc.imp._ITM_deregisterTMCloneTable
  0x55f410331050    1 6            sym.imp.gets
  0x55f410331060    1 6            sym.imp.exit
  0x55f410331070    1 6            sym.imp.__cxa_finalize
  0x55f410331165    8 219          main
  0x55f410331160    5 133  -> 56   entry.init0
  0x55f410331120    5 57   -> 50   entry.fini0
  0x55f4103310b0    4 41   -> 34   fcn.55f4103310b0
  [0x7f60dd9b0050]> s main
  [0x55f410331165]> pdf
              ; DATA XREF from entry0 @ 0x55f41033109d
  ┌ 219: int main (int argc, char **argv, char **envp);
  │           ; var int64_t var_40h @ rbp-0x40
  │           ; var int64_t var_16h @ rbp-0x16
  │           ; var int64_t var_eh @ rbp-0xe
  │           ; var int64_t var_ah @ rbp-0xa
  │           ; var int64_t var_8h @ rbp-0x8
  │           ; var int64_t var_4h @ rbp-0x4
  │           0x55f410331165      55             push rbp
  │           0x55f410331166      4889e5         mov rbp, rsp
  │           0x55f410331169      4883ec40       sub rsp, 0x40
  │           0x55f41033116d      48b832404032.  movabs rax, 0x6667243532404032 ; '2@@25$gf'
  │           0x55f410331177      488945ea       mov qword [var_16h], rax
  │           0x55f41033117b      c745f2735426.  mov dword [var_eh], 0x40265473 ; 'sT&@'
  │           0x55f410331182      66c745f64c00   mov word [var_ah], 0x4c ; 'L' ; 76
  │           0x55f410331188      488d3d790e00.  lea rdi, str._nHey___Can_You_Crackme___n ; 0x55f410332008 ; "=======================\nHey , Can You Crackme ?\n======================="
  │           0x55f41033118f      e89cfeffff     call sym.imp.puts       ; int puts(const char *s)

  ```
- if you check the main function, you can see some strings passed
  ```
  2@@25$gfsT&@L
  ```
  suspected to be password then we will use it to run it with our binary

  ```
  └─$ ./0x41haz.0x41haz
  =======================
  Hey , Can You Crackme ?
  =======================
  It's jus a simple binary 

  Tell Me the Password :
  2@@25$gfsT&@L
  Well Done !!

  ```
  We are done 🙂



