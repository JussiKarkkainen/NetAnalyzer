#ifndef INJECT_NEW_H
#define INJECT_NEW_H

#include <stdint.h>

void get_mac_addr(uint32_t, uint32_t, uint8_t *, char *, uint8_t *); 
void send_packet(uint32_t, uint32_t, uint8_t *, char *, uint8_t *, int);

#endif
