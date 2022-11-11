#include "headers.h"
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

// Create a raw socket and analyze packet
int main() {
   
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
    switch (iphdr->protocol) {
        case 0x06:
            analyze_tcp_packet(buffer, size);
        case 0x11:
            analyze_udp_packet(buffer, size);
        case 0x01: 
            analyze_icmp_packet(buffer, size);
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

void analyze_ip_packet(uint8_t *buffer, ssize_t size) {
    printf("\n");
    printf("----------- IP header -----------\n");
    printf("----------- End of IP header -----------\n");
    printf("\n");
}

void analyze_tcp_packet(uint8_t *buffer, ssize_t size) {
    struct tcp_header *tcphdr = (struct tcp_header*)(buffer + sizeof(struct ethernet_header) + sizeof(struct ip_header));
    printf("\n");
    printf("----------- TCP header -----------\n");
    printf("%d\n", ntohl(tcphdr->sequence_num));

    printf("----------- End of TCP header -----------\n");
    printf("\n");
}

void analyze_udp_packet(uint8_t *buffer, ssize_t size) {
    printf("\n");
    printf("----------- UDP header -----------\n");
    printf("----------- End of UDP header -----------\n");
    printf("\n");
}

void analyze_icmp_packet(uint8_t *buffer, ssize_t size) {
    printf("\n");
    printf("----------- ICMP header -----------\n");
    printf("----------- End of ICMP header -----------\n");
    printf("\n");
}

