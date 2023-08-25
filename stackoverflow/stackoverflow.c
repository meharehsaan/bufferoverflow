#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ./a.out AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// overflow occurs after some characters it smashes

void f1(char *str)
{
    char buff[10];
    strcpy(buff, str);   // copy buffer without bound check

    // strncpy(buff, str, 10); // copy only 10 characters only 
    
    printf("The command line received is: %s \n", buff);
}

int main(int argc, char *argv[])
{
    if (argc > 1)
        f1(argv[1]);
    else
        printf("No command line received.\n");
    exit(0);
}