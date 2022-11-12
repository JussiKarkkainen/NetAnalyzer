#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

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

void print_data(uint8_t *data, ssize_t size) {
    int i, j;
    for (i=0; i<size; i++) {
        if (i!=0 && i%16==0) {
            printf("      ");
            for (j=i-16; j<i; j++) {
                if (data[j]>=32 && data[j]<=128)
                    printf("%c", data[j]);
                else printf(".");
            }
            printf("\n");
        }
        if (i%16==0) printf("    ");
            printf(" %02x", data[i]);

		if (i==size-1) {
			for (j=0;j<15-i%16;j++) {
			    printf("   "); 
            }
			printf("    ");
			for (j=i-i%16; j<=i; j++) {
				if (data[j]>=32 && data[j]<=128) {
				  printf("%c",(unsigned char)data[j]);
				}
				else {
				  printf(".");
				}
			}
            printf("\n");
        }
    }
}

