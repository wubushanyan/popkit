#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

extern const char* const syscalls[];

int main() {
    int i = 0;
    while (1) {
        const char* syscall_name = syscalls[i];
        if (syscall_name == NULL) {
            break;
        }
        printf("%d: %s\n", i, syscall_name);
        i++;
    }
    return 0;
}