#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>
#include <stdlib.h>

void process_packet(uint8_t*, ssize_t);
void analyze_tcp_packet(uint8_t*, ssize_t);
void analyze_udp_packet(uint8_t*, ssize_t);
void analyze_arp_header(uint8_t*, ssize_t);
void analyze_icmp_packet(uint8_t*, ssize_t);
int analyze_ethernet_frame(uint8_t*, ssize_t);
void analyze_ip_header(uint8_t*, ssize_t);
int initialize_sniffer(void);

#endif
