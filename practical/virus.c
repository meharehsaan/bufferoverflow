#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int getinput()
{
    char buf[10];
    int rv = read(0, buf, 1000);
    printf("NUmber of bytes read are %d\n", rv);
    return 0;
}

int main()
{
    getinput();
    return 0;
}

int virus()
{
    printf("Hacking Earth");
    exit(0);
}