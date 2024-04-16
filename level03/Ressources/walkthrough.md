Je commence par analyser mon environnement :

```
$ id && pwd && ls -la
uid=1003(level03) gid=1003(level03) groups=1003(level03),100(users)
/home/users/level03
total 17
dr-xr-x---+ 1 level03 level03   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level03 level03  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level03 level03 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level04 users   7677 Sep 10  2016 level03
-rw-r--r--+ 1 level03 level03   41 Oct 19  2016 .pass
-rw-r--r--  1 level03 level03  675 Sep 10  2016 .profile
```

Je trouve un binaire `level03`, que je tente d'éxecuter :

```
$ ./level03
***********************************
*               level03         **
***********************************
Password:dab
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
$ exit

level03@OverRide:~$ su level04
Password: kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf

level04@OverRide:~$
```

Je suis très confus, puisqu'en voulant écrire le prologue habituel de ce walkthrough, mon test à marché et j'ai eu accès au shell instantanément.

Par curiosité, je reviens sur la session du `level03` et tente un d'autres mot de passe aléatoire :

```
$ ./level03
***********************************
*               level03         **
***********************************
Password:hello

Invalid Password

$ ./level03
***********************************
*               level03         **
***********************************
Password:bad

Invalid Password

$ ./level03
***********************************
*               level03         **
***********************************
Password:da

Invalid Password
```

Mais le plus étonnant, c'est que le mot de passe de mon test d'origine ne marche plus également :

```
$ ./level03
***********************************
*               level03         **
***********************************
Password:dab

Invalid Password
```

Malgré ce coup de chance incompréhensible pour le moment, je décompile le binaire avec [Dogbolt](https://dogbolt.org/?id=5794bb2b-b8b6-4ff4-b1f8-61bab5dffc14#Hex-Rays=183) pour tenter d'y voir plus clair :

```c
int decrypt(char a1)
{
  unsigned int i; // [esp+20h] [ebp-28h]
  unsigned int len; // [esp+24h] [ebp-24h]
  char buffer[18]; // [esp+2Bh] [ebp-1Dh] BYREF

  strcpy(buffer, "Q}|u`sfg~sf{}|a3");

  len = strlen(buffer);

  for ( i = 0; i < len; ++i )
    buffer[i] ^= a1;

  if ( !strcmp(buffer, "Congratulations!") )
    return system("/bin/sh");
  else
    return puts("\nInvalid Password");
}

int test(int a1, int a2)
{
  int result; // eax

  switch ( a2 - a1 )
  {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 21:
      result = decrypt(a2 - a1);
      break;
    default:
      result = decrypt(rand());
      break;
  }
  return result;
}

int main(int argc, const char **argv)
{
  int savedregs; // [esp+20h] [ebp+0h] BYREF

  srand(time(0));

  puts("***********************************");
  puts("*\t\tlevel03\t\t**");
  puts("***********************************");

  printf("Password:");
  scanf("%d", &savedregs);
  test(savedregs, 322424845);

  return 0;
}
```

En regardant, et simplifiant le code décompilé, je détermine que dans la fonction `test()`, j'ai atteint le cas `default`.

Je me renseigne sur `rand()` et apprend que cette dernière génère une valeur entre 0 et 32767.

Etant donné que le code ne présente pas de vulnérabilité et semble s'attendre à ce que l'on atteigne les cas de 0 à 21, pour "imiter" un succès, cela implique que lorsque j'ai essayé mon mot de passe, la valeur aléatoire générée était entre 1 et 21, soit une chance sur 1560 environ !

Afin de "toujours" réussir, il me suffit que `a2 - a1` dans `test()` soit égal à 1.

Je peux par exemple donc tenter `322424845 - 1` soit `322424844`. 
Pour que :

```c
test(savedregs, 322424845);
// devienne
test(322424844, 322424845);
```

Et atteindre le `case 1:`. J'essaye cette hypothèse :

```
$ ./level03
***********************************
*               level03         **
***********************************
Password:322424844

Invalid Password
```

Mais sans succès, je me penche donc sur la dernière fonction `decrypt()` :

```c
  for ( i = 0; i < len; ++i )
    buffer[i] ^= a1;
```

Je vois qu'ici, une opération XOR est effectuée sur la string encryptée : "Q}|u\`sfg~sf{}|a3" à partir du chiffre reçu dans `test()`. Ensuite, une comparaison entre le résultat et la string "Congratulations!" est faite.

J'utilise ce site : https://xor.pw/ et passe comme input "Q" en ASCII, puis essaye les nombres de 1 a 21 jusqu'à que le résultat en ASCII soit "C" (première lettre de la comparaison).

Je trouve que le nombre 18 change "Q" en "C" et "}" en "o" et ainsi de suite...

Je tente donc d'atteindre le `case 18:` avec l'input suivant : `322424845 - 18 = 322424827`

J'essaye :

```
$ ./level03
***********************************
*               level03         **
***********************************
Password:322424827
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
$
```

J'en conclus donc que le nombre qui m'a été aléatoirement généré a mon tout premier essai était... 18 ?
J'avais [1 chance sur 32767](https://www.tutorialspoint.com/c_standard_library/c_function_rand.htm) lol