#include "sniffer.h"
#include "inject.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int opt, ret;
    if (argc < 2) {
        printf("Invalid number of arguments.\nUsage: %s [-si]\n", argv[0]);
        return -1;
    }
    if (strcmp(argv[1], "-s") == 0) {
        ret = initialize_sniffer();
    }
    else if (strcmp(argv[1], "-i") == 0) {
        if (argc != 7) {
            printf("Invalid number of arguments.\nUsage: %s -i [Own IP] [Own MAC] [Interface] [Target one IP] [Target two IP]\n", argv[0]);
            printf("Number of arguments given was: %d\n", argc);
            return -1;
        }
        ret = initialize_inject(argv[5], argv[6], argv[2], argv[3], argv[4]);
    }
    else {
        printf("Invalid arguments. Usage: %s [-si]\n", argv[0]);
        return -1;
    }
    return 0;
}
