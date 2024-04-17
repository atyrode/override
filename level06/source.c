int auth(char *login, int serial)
{
  int i; // [esp+14h] [ebp-14h]
  int pass; // [esp+18h] [ebp-10h]
  int log_len; // [esp+1Ch] [ebp-Ch]

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
    pass = (login[3] ^ 0x1337) + 6221293;
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
  int serial; // [esp+2Ch] [ebp-24h] BYREF
  char login[28]; // [esp+30h] [ebp-20h] BYREF

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

  if ( auth(login, serial) )
    return 1;

  puts("Authenticated!");
  system("/bin/sh");

  return 0;
}