#ifndef HEADERS_H
#define HEADERS_H

#include <stdint.h>

#define IP_LEN 4
#define MAC_LEN 6
#define ETH_HDR_LEN 14
#define ARP_HDR_LEN 28

struct ip_header {
    int version : 4;
    int ihl : 4;
    int dscp : 6;
    int ecn : 2;
    uint16_t len;
    uint16_t identification;
    int reserved_flag : 1;
    int df : 1;
    int mf : 1;
    int frag_offset : 13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t cksum;
    uint32_t src_addr;
    uint32_t dst_addr;
}__attribute__((packed));

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    int data_offset : 4;
    int reserved : 3;
    int ns : 1;
    int cwr : 1;
    int ece : 1;
    int urg : 1;
    int ack : 1;
    int psh : 1;
    int rst : 1;
    int syn : 1;
    int fin : 1;
    uint16_t window_size;
    uint16_t cksum;
    uint16_t urgent_pointer;
}__attribute__((packed));

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t lenght;
    uint16_t cksum;
}__attribute__((packed));

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint32_t rest;
}__attribute__((packed));

struct ethernet_header {
    uint8_t daddr[MAC_LEN];
    uint8_t saddr[MAC_LEN];
    uint16_t ether_type;
}__attribute__((packed));

struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sha[MAC_LEN];
    uint8_t spa[IP_LEN];
    uint8_t tha[MAC_LEN];
    uint8_t tpa[IP_LEN];
}__attribute__((packed));

#endif
