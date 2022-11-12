#include "headers.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

void process_packet(uint8_t*, ssize_t);
void analyze_tcp_packet(uint8_t*, ssize_t);
void analyze_udp_packet(uint8_t*, ssize_t);
void analyze_icmp_packet(uint8_t*, ssize_t);
void analyze_ethernet_frame(uint8_t*, ssize_t);
void analyze_ip_header(struct ip_header*);

int main() {
    
    fill_ip_table();   

    uint8_t *buffer = malloc(65535); // Largest possible tcp packet
    memset(buffer, 0, 65536);
    struct sockaddr saddr;

    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (raw_sock < 0) {
        perror("Unable to make a raw socket: "); 
        return -1;
    }
    printf("Raw Socket succesfully created\n");

    while (1) {
        socklen_t addrlen = sizeof(saddr);
        ssize_t size = recvfrom(raw_sock, buffer, 65536, 0, &saddr, &addrlen);

        if (size < 0) {
            perror("Unable to receive packet");
            return 1;        
        }
        process_packet(buffer, size);
        return 0;   // remove soon
    }
    free(buffer);
    close(raw_sock);
    return 0;
}

void process_packet(uint8_t *buffer, ssize_t size) {
    printf("----------- Start of packet ----------- \n");
    analyze_ethernet_frame(buffer, size);
    struct ip_header *iphdr = (struct ip_header*)(buffer + sizeof(struct ethernet_header));
    analyze_ip_header(iphdr);
    switch (iphdr->protocol) {
        case 0x06:
            analyze_tcp_packet(buffer, size);
            break;
        case 0x11:
            analyze_udp_packet(buffer, size);
            break;
        case 0x01: 
            analyze_icmp_packet(buffer, size);
            break;
        default:
            printf("Unknown protocol type %x\n", iphdr->protocol);
    }
    printf("----------- End of packet ----------- \n");
}

void analyze_ethernet_frame(uint8_t *buffer, ssize_t size) {
    struct ethernet_header *ethhdr = (struct ethernet_header*)buffer;
    printf("\n");
    printf("----------- Ethernet header -----------\n");
    printf("|Source MAC address| -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", ethhdr->saddr[0], ethhdr->saddr[1], 
                                                                       ethhdr->saddr[2], ethhdr->saddr[3], 
                                                                       ethhdr->saddr[4], ethhdr->saddr[5]);
    printf("|Destination MAC address| -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", ethhdr->daddr[0], ethhdr->daddr[1], 
                                                                            ethhdr->daddr[2], ethhdr->daddr[3], 
                                                                            ethhdr->daddr[4], ethhdr->daddr[5]);
    printf("|Ethernet protocol| -> %u\n", ethhdr->ether_type);
    printf("----------- End of Ethernet header -----------\n");
    printf("\n");
}

void analyze_ip_header(struct ip_header *iphdr) {
    struct sockaddr_in src_addr, dst_addr;
    src_addr.sin_addr.s_addr = iphdr->src_addr;
    dst_addr.sin_addr.s_addr = iphdr->dst_addr;
    printf("\n");
    printf("----------- IP header -----------\n");
    printf("|Version|                -> %d\n", iphdr->version);
    printf("|IHL|                    -> %d Bytes\n", (iphdr->ihl)*4);
    printf("|DSCP|                   -> %d\n", iphdr->dscp);
    printf("|ECN|                    -> %d\n", iphdr->ecn);
    printf("|Lenght|                 -> %d\n", iphdr->len); 
    printf("|Identification|         -> %d\n", iphdr->identification);
    printf("|Reserved Flag|          -> %d\n", iphdr->reserved_flag);
    printf("|DF Flag|                -> %d\n", iphdr->df);
    printf("|MF Flag|                -> %d\n", iphdr->mf);
    printf("|Fragment Offset|        -> %d\n", iphdr->frag_offset);
    printf("|TTL|                    -> %d\n", iphdr->ttl);
    printf("|Protocol|               -> %d [%s]\n", iphdr->protocol, get_ip_protocol(iphdr->protocol));
    printf("|Checksum|               -> %d\n", ntohs(iphdr->cksum));
    printf("|Source IP Address|      -> %s\n", inet_ntoa(src_addr.sin_addr));
    printf("|Destination IP Address| -> %s\n", inet_ntoa(dst_addr.sin_addr));
    printf("----------- End of IP header -----------\n");
    printf("\n");
}

void analyze_tcp_packet(uint8_t *buffer, ssize_t size) {
    struct tcp_header *tcphdr = (struct tcp_header*)(buffer + sizeof(struct ethernet_header) + sizeof(struct ip_header));
    printf("\n");
    printf("----------- TCP header -----------\n");
    printf("|Source Port|            -> %u\n", ntohs(tcphdr->src_port));
    printf("|Destination Port|       -> %u\n", ntohs(tcphdr->dst_port));
    printf("|Sequence Number|        -> %u\n", ntohl(tcphdr->sequence_num));
    printf("|Acknowledgment Number|  -> %u\n", ntohl(tcphdr->ack_num));
    printf("|Data Offset|            -> %d Bytes\n", (unsigned int)(tcphdr->data_offset)*4); 
    printf("|Reserved|               -> %u\n", (unsigned int)tcphdr->reserved);
    printf("|NS|                     -> %u\n", (unsigned int)tcphdr->ns);
    printf("|CWR|                    -> %u\n", (unsigned int)tcphdr->cwr);
    printf("|ECE|                    -> %u\n", (unsigned int)tcphdr->ece);
    printf("|URG|                    -> %u\n", (unsigned int)tcphdr->urg);
    printf("|ACK|                    -> %u\n", (unsigned int)tcphdr->ack);
    printf("|PSH|                    -> %u\n", (unsigned int)tcphdr->psh);
    printf("|RST|                    -> %u\n", (unsigned int)tcphdr->rst);
    printf("|SYN|                    -> %u\n", (unsigned int)tcphdr->syn);
    printf("|FIN|                    -> %u\n", (unsigned int)tcphdr->fin);
    printf("|Window Size|            -> %u\n", ntohs(tcphdr->window_size));
    printf("|Checksum|               -> %u\n", ntohs(tcphdr->cksum));
    printf("|Urgent Pointer|         -> %u\n", tcphdr->urgent_pointer);
    printf("----------- End of TCP header -----------\n");
    printf("\n");
}

void analyze_udp_packet(uint8_t *buffer, ssize_t size) {
    struct udp_header *udphdr = (struct udp_header*)(buffer + sizeof(struct ethernet_header) + sizeof(struct ip_header));
    printf("\n");
    printf("----------- UDP header -----------\n");
    printf("|Source Port|            -> %u\n", ntohs(udphdr->src_port));
    printf("|Destination Port|       -> %u\n", ntohs(udphdr->dst_port));
    printf("|Lenght|                 -> %u\n", ntohs(udphdr->lenght));
    printf("|Checksum|               -> %u\n", ntohs(udphdr->cksum));
    printf("----------- End of UDP header -----------\n");
    printf("\n");
}

void analyze_icmp_packet(uint8_t *buffer, ssize_t size) {
    printf("\n");
    printf("----------- ICMP header -----------\n");
    printf("----------- End of ICMP header -----------\n");
    printf("\n");
}

