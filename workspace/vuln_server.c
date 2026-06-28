#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void secret_backdoor() {
    printf("Access Granted!\n");
    system("/bin/sh");
}

void process_request() {
    char buffer[64];

    printf("Enter firmware request data: ");
    fflush(stdout);

    // VULNERABLE: gets does not check bounds
    gets(buffer);

    printf("Processing: %s\n", buffer);
}

int main(int argc, char **argv) {
    printf("--- IoT Firmware Update Service ---\n");
    process_request();
    return 0;
}
