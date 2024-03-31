#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

char win[] = "YAY!";
char lose[] = "Nope!";

void print_data( char* data, int len) {
    for( int x = 0; x <= len; x++ )
    {
        printf("%c", data[x]);
    }
}

char* check_value(int random) {
    char buffer[20];
    char *output = lose;
    int check;
    int input_length;

    printf("Location of the buffer %p\n", buffer);
    printf("\nWhat's your guess? \n> ");
    input_length = read(STDIN_FILENO, buffer, 1024);
    printf("Your input: ");
    print_data( buffer, input_length );
    check = atoi(buffer);
    if(check == random) {
        output = win;
    }
    return output;
}

void main()
{
    gid_t egid = getegid();
    setregid(egid, egid);

    int r = rand() % 10;   
    char* output;
    printf("Can you guess the number?\n");
    while(1) {
        output = check_value(r);
        printf("\n--- %s ---\n", output);
        if( output == win )
        {
            break;
        }
    }
}
