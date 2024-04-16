int main(int argc, const char **argv)
{
  char buffer[100]; // [esp+28h] [ebp-70h] BYREF
  unsigned int i; // [esp+8Ch] [ebp-Ch]

  i = 0;
  fgets(buffer, 100, stdin);
  for ( i = 0; i < strlen(buffer); ++i )
  {
    if ( buffer[i] > 64 && buffer[i] <= 90 )
      buffer[i] ^= 32;
  }
  printf(buffer);
  exit(0);
}