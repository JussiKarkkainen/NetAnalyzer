#ifndef INJECT_NEW_H
#define INJECT_NEW_H

#include <stdint.h>
#include "headers.h"

void get_mac_addr(uint32_t, uint32_t, uint8_t *, char *, struct arp_header *); 
void arp_spoof(uint8_t *, uint8_t *, uint8_t *, uint32_t, uint32_t, char *);
void set_ifr(struct ifreq *, char *)
#endif
