#include <stdio.h>
#include <string.h>

// adding gadgets manually 
__asm__("sub %rbp, (%rdi)\n\t"     // sub qword ptr [rdi], rbp ; ret
        "ret\n\t"
        "pop %rdi;"                 // pop rdi ; ret
	    "ret;");

char *dummy = "sh";    

void greet_me()
{
    char name[200];
    printf("Enter your name:");
    gets(name);
    printf("hi %s !\n",name);
  
}
int main(int argc, char *argv[])
{
    greet_me();
    return 0;  
}
