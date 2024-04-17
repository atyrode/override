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