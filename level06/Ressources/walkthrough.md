Je commence par analyser mon environnement :

```bash
$ id && pwd && ls -la
uid=1006(level06) gid=1006(level06) groups=1006(level06),100(users)
/home/users/level06
total 17
dr-xr-x---+ 1 level06 level06   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level06 level06  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level06 level06 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level07 users   7907 Sep 10  2016 level06
-rw-r--r--+ 1 level06 level06   41 Oct 19  2016 .pass
-rw-r--r--  1 level06 level06  675 Sep 10  2016 .profile
```

Je trouve un binaire `level06`, que je tente d'éxecuter :

```bash
$ ./level06
***********************************
*               level06           *
***********************************
-> Enter Login: dab
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: dab
$
```

Je décompile le binaire avec [Dogbolt](https://dogbolt.org/?id=9f72fea8-183c-4bdc-9620-b88449bc2ae1#Hex-Rays=168&Boomerang=19) :

```c
int auth(char *login, int serial)
{
  int i; 
  int pass; 
  int log_len;

  login[strcspn(s, "\n")] = 0;
  log_len = strnlen(login, 32);

  if ( log_len <= 5 )
    return 1;

  if ( ptrace(PTRACE_TRACEME, 0, 1, 0) == -1 )
  {
    puts("\x1B[32m.---------------------------.");
    puts("\x1B[31m| !! TAMPERING DETECTED !!  |");
    puts("\x1B[32m'---------------------------'");
    return 1;
  }
  else
  {
    pass = (login[3] ^ 0x1337) + 6221293; // <--2 python script is used to reverse the logic and find the serial matching any username
    for ( i = 0; i < log_len; ++i )
    {
      if ( login[i] <= 31 )
        return 1;
      pass += (pass ^ (unsigned int)s[i]) % 0x539;
    }
    return serial != pass;
  }
}

int main(int argc, const char **argv)
{
  int serial;
  char login[28];

  puts("***********************************");
  puts("*\t\tlevel06\t\t  *");
  puts("***********************************");

  printf("-> Enter Login: ");
  fgets(login, 32, stdin);

  puts("***********************************");
  puts("***** NEW ACCOUNT DETECTED ********");
  puts("***********************************");
  printf("-> Enter Serial: ");
  scanf("%u", &serial);

  if ( auth(login, serial) ) // <---------------1 user input for login and serial must pass auth to access /bin/sh further down
    return 1;

  puts("Authenticated!");
  system("/bin/sh");

  return 0;
}
```

Je n'observe pas de vulnérabilité particulière, et note qui plus est que le programme semble simplement nécessiter que le serial pour un username donné soit correct.

J'utilise la logique du programme dans un script Python afin de déterminer le serial du login `agoodwin` :

```python
import sys

input = sys.argv[1]
if len(input) <= 5:
    exit(1)
    
key = (ord(input[3]) ^ 4919) + 6221293

for i in range(len(input)):
    if ord(input[i]) < 32:
        exit(1) 
    key += (ord(input[i]) ^ key) % 1337
    
print(f"{key}")
```

Et le lance :

```bash
$ python3 test.py agoodwin
6234472
```

J'essaye cette solution :

```bash
$ ./level06
***********************************
*               level06           *
***********************************
-> Enter Login: agoodwin
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6234472
Authenticated!
$ whoami
level07
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

Et c'est un succès !

