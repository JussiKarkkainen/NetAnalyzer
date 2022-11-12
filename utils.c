#include "utils.h"
#include <stdint.h>
#include <stdlib.h>

struct ip_proto_dict {
    char *key;
    int value;
};

struct ip_proto_dict ip_table[4]; 

void fill_ip_table(void) {
    ip_table[0].key = "TCP";
    ip_table[0].value = 0x06;
    ip_table[1].key = "UDP";
    ip_table[1].value = 0x11;
    ip_table[2].key = "ICMP";
    ip_table[2].value = 0x01;
    ip_table[3].key = "IGMP";
    ip_table[3].value = 0x02;
}

char *get_ip_protocol(uint8_t protocol) {

    for (int i=0; i<sizeof(ip_table); i++) {
        if (ip_table[i].value == protocol)
            return ip_table[i].key;
    }
    return "Unknown Protocol";
}
