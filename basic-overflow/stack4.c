#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("Hacked successfully\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
