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