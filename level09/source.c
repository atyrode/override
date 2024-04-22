typedef struct s_msg
{
    char text[140];
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