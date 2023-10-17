#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//getting environmental variable address

int main(int argc, char *argv[]) {
	if(argc != 2 ) {
		printf("Must give the env variable name\n");
		exit(0);
	}
	char* ptr = getenv(argv[1]); // get env var address on stack
	printf("Addr of %s is: %p\n", argv[1], ptr);
}