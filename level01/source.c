char a_user_name[100]; // idb

int verify_user_name()
{
  puts("verifying username....\n");
  return memcmp(a_user_name, "dat_wil", 7u);
}

int verify_user_pass(const void *a1)
{
  return memcmp(a1, "admin", 5u);
}

int main(int argc, const char **argv)
{
  char string[64]; // [esp+1Ch] [ebp-4Ch] BYREF
  int boolean; // [esp+5Ch] [ebp-Ch]

  memset(string, 0, sizeof(s));
  boolean = 0;
  puts("********* ADMIN LOGIN PROMPT *********");
  printf("Enter Username: ");
  fgets(a_user_name, 256, stdin);
  boolean = verify_user_name();
  if ( boolean != 0 )
  {
    puts("nope, incorrect username...\n");
  }
  else
  {
    puts("Enter Password: ");
    fgets(string, 100, stdin);
    boolean = verify_user_pass(s);
    puts("nope, incorrect password...\n");
  }
  return 1;
}