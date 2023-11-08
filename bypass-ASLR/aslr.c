#include <stdio.h>
#include <string.h>
#include <unistd.h>

void getMessage(void){
    char msg[200];
    printf("Enter Message: ");
    scanf("%[^\n]s", msg);
    printf("Message received.\n");
}


int main(void)
{
    getMessage();
    return 0;
}
