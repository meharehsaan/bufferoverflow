// gcc -fno-stack-protector -no-pie -D_FORTIFY_SOURCE=0 stack.c -o stack

#include <stdio.h>

void foo(){
	char buffer[16];
	puts("Give me your input :: ");
	gets(buffer);
}

int main(int argc, char **argv)
{
	foo();
}
