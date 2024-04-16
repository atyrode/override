int main(int argc, const char **argv)
{
  int stat_loc; // [esp+1Ch] [ebp-9Ch] BYREF
  char buffer[128]; // [esp+20h] [ebp-98h] BYREF
  int ptrace_result; // [esp+A8h] [ebp-10h]
  pid_t pid; // [esp+ACh] [ebp-Ch]

  pid = fork();

  memset(buffer, 0, sizeof(buffer));
  ptrace_result = 0;
  stat_loc = 0;

  if ( pid )
  {
    do
    {
      wait(&stat_loc);

      if ( (stat_loc & 0x7F) == 0 || (stat_loc, (char)((stat_loc & 0x7F) + 1) >> 1 > 0) )
      {
        puts("child is exiting...");
        return 0;
      }
      ptrace_result = ptrace(PTRACE_PEEKUSER, pid, 44, 0);
    }
    while ( ptrace_result != 11 );
    puts("no exec() for you");
    kill(pid, 9);
  }
  else
  {
    prctl(1, 1);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    puts("Give me some shellcode, k");
    gets(buffer);
  }
  return 0;
}