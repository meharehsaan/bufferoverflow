// run program in gdb to check buffer overflow
// gcc -ggdb bof.c
// gdb ./a.out

#include <stdio.h>
#include <string.h>

void vulnerable_function(const char *input)
{
    char buffer[64];
    strcpy(buffer, input); // buffer overflow here
}

int main()
{
    char input[128];
    printf("Enter input: ");
    gets(input); // Unsafe input function
    vulnerable_function(input);
    return 0;
}
