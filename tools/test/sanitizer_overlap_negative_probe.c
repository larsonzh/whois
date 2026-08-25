// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__)
__attribute__((noinline))
#endif
static void copy_bytes(char* destination, const char* source, size_t length)
{
    memcpy(destination, source, length);
}

int main(int argc, char** argv)
{
    size_t offset = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 1;
    char* buffer = (char*)malloc(64);
    if (!buffer || offset == 0 || offset > 16) {
        free(buffer);
        return 2;
    }

    memset(buffer, 'x', 64);
    buffer[63] = '\0';
    copy_bytes(buffer, buffer + offset, 32);
    puts(buffer);
    free(buffer);
    return 0;
}