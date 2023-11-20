#include<stdio.h>
int main(void)
{
    char s[16];
    printf("Enter the name : ");
    fgets(s, 16, stdin);
    puts("hello");
    printf(s, 16);
    printf("Enter the sentence");
    fgets(s, 256, stdin);
}