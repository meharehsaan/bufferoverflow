#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

char code[] = "\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05";

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
