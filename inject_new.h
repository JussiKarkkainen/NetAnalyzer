#ifndef INJECT_NEW_H
#define INJECT_NEW_H

#include <stdint.h>
#include "headers.h"

void get_mac_addr(uint32_t, uint32_t, uint8_t *, char *, uint8_t *); 
int send_packet(uint32_t, uint32_t, uint8_t *, char *, uint8_t *, int, 
                struct arp_header *, struct ethernet_header *);

#endif
