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