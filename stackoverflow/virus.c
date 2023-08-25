// gcc -ggdb virus.c when return line executes pass it the virus 
// function address in gdb instead of return it calls the function 
// virus without being called by the code.

#include <stdio.h>
#include <stdlib.h>
void f3() { return; }
void f2() { f3(); }
void f1() { f2(); }
int main()
{
    f1();
    return 0;
}

int virus()
{
    printf("Now I am controlling your terminal...\n");
    exit(0);
}