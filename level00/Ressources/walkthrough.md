Je commence par analyser mon environnement :

```bash
$ id && pwd && ls -la
uid=1000(level00) gid=1000(level00) groups=1000(level00),100(users)
/home/users/level00
total 13
dr-xr-x---+ 1 level01 level01   60 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level01 level01  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level00 level00 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level01 users   7280 Sep 10  2016 level00
-rw-r--r--  1 level01 level01  675 Sep 10  2016 .profile
```

Je trouve un binaire `level00`, que je tente d'éxecuter :

```bash
$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:valid password

Invalid Password!
```

Je tente de décompiler le binaire avec [Dogbolt](https://dogbolt.org/?id=d2ff384a-ea37-4370-9ae5-4814118e5725#Hex-Rays=118) :

```c
int main(int argc, const char **argv)
{
  int v4; // [esp+1Ch] [ebp-4h] BYREF

  puts("***********************************");
  puts("* \t     -Level00 -\t\t  *");
  puts("***********************************");
  printf("Password:");
  __isoc99_scanf("%d", &v4);
  if ( v4 == 5276 )
  {
    puts("\nAuthenticated!");
    system("/bin/sh");
    return 0;
  }
  else
  {
    puts("\nInvalid Password!");
    return 1;
  }
}
```

Je vois que l'accès au shell est derrière "v4 == 5276", je tente naturellement donc :

```bash
$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:5276

Authenticated!
$ cat /home/users/level01/.pass
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

Euh... bingo ?