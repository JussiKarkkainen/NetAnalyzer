#include "sniffer.h"
#include "inject.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int opt, ret;
    if (argc == 1) {
        printf("Invalid number of arguments.\nUsage: %s [-si]\n", argv[0]);
        return -1;
    }
    while ((opt = getopt(argc, argv, "si")) != -1) {
        switch (opt) {
            case 's':
                ret = initialize_sniffer();
                break;
            case 'i':
                ret = initialize_inject();
                break;
            default:
                printf("Invalid arguments.\nUsage: %s [-si]\n", argv[0]);
                return -1;
        }
    return 0;
    }
}

