#ifndef HEADERS_H
#define HEADERS_H

#include <stdint.h>

struct ip_header {
    int version : 4;
    int ihl : 4;
    int dscp : 6;
    int ecn : 2;
    uint16_t len;
    uint16_t identification;
    int flags : 3;
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
    int flags : 9;
    uint16_t window_size;
    uint16_t cksum;
    uint16_t urgent_pointer;
};

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t lenght;
    uint16_t cksum;

};

struct ethernet_header {
    uint8_t saddr[6];
    uint8_t daddr[6];
    uint16_t ether_type;
}__attribute__((packed));

#endif
