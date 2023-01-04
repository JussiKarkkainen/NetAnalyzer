#ifndef INJECT_NEW_H
#define INJECT_NEW_H

#include <stdint.h>

#define ARP_REQUEST 1

uint8_t *get_mac_addr(uint32_t, uint32_t, uint8_t *, char *, uint8_t *); 
void arp_spoof(uint32_t, uint32_t);

#endif
