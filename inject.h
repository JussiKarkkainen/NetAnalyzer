#ifndef INJECT_NEW_H
#define INJECT_NEW_H

#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "headers.h"

int initialize_inject(const char *gateway_ip, char *target_ip, char *own_ip, const char *own_mac, char *ifname);
void get_mac_addr(uint32_t, uint32_t, uint8_t *, char *, struct arp_header *); 
void arp_spoof(uint8_t *, uint8_t *, uint32_t, uint32_t, char *);
void set_ifr(int, struct ifreq *, char *); 

#endif
