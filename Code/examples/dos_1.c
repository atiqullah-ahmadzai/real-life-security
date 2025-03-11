#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 10

// Non-vulnerable function: uses strncpy safely
void safeFunction(const char* input) {
    char buffer[BUFFER_SIZE];
    // Avoid buffer overflow by copying up to BUFFER_SIZE - 1
    strncpy(buffer, input, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0'; // ensure null termination
    printf("Safe buffer contents: %s\n", buffer);
}

// Vulnerable function: uses strcpy without checking bounds
void vulnerableFunction(const char* input) {
    char buffer[BUFFER_SIZE];
    // BAD: strcpy can overflow buffer if input is too large
    strcpy(buffer, input);
    printf("Vulnerable buffer contents: %s\n", buffer);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    // Safe usage
    printf("Calling safeFunction with \"Hello\"\n");
    safeFunction("Hello");

    // Vulnerable usage
    printf("Calling vulnerableFunction with \"ThisIsAReallyLongInputThatWillOverflow\"\n");
    vulnerableFunction("ThisIsAReallyLongInputThatWillOverflow");

    // Another safe usage
    printf("Calling safeFunction with \"World\"\n");
    safeFunction("World");

    // Potentially vulnerable usage, depends on user input
    printf("Calling vulnerableFunction with user input: %s\n", argv[1]);
    vulnerableFunction(argv[1]);

    return 0;
}
