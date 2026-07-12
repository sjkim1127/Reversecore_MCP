
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void vuln_function(char *str) {
    char buffer[16];
    strcpy(buffer, str);
}
int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "backdoor") == 0) {
            system("ls");
        } else {
            vuln_function(argv[1]);
        }
    }
    return 0;
}
