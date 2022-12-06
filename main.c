#include "sniffer.h"
#include "inject.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int opt, ret;
    if (argc == 1) {
        printf("Invalid number of arguments.\nUsage: %s [-si]\n", argv[0]);
        return -1;
    }
    if (strcmp(argv[1], "-s") == 0) {
        ret = initialize_sniffer();
    }
    else if (strcmp(argv[1], "-i") == 0) {
        ret = initialize_inject(argv[2], argv[3]);
    }
    else {
        printf("Invalid arguments. Usage: %s [-si]\n", argv[0]);
        return -1;
    }
    return 0;
}
