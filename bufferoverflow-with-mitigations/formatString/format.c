#include <stdio.h>
#include <stdlib.h>

// compile with -no-pie

int val = 0;

int main(void) {    
	printf("The secret is at %p\n", &val);
	char buf[100];

	printf("Enter you message\n");
	fgets(buf, 100, stdin);
	printf(buf);

	// printf("Modified val = %d\n", val);

	 if(val)
	     puts("\nYou are great\n");

	return 0;
}
