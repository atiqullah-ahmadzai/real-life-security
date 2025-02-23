#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    // strcpy() does not perform bounds checking.
    strcpy(buffer, input);
    printf("Buffer content: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}