#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include "headers.h"

struct ip_addrs {
    uint32_t ip_one;
    uint32_t ip_two;
};

int initialize_inject(char *gateway_ip, char *target_ip, uint8_t *own_mac) {
    
    printf("Initializing inject\n");

    // Convert IP address strings to numerical form
    struct ip_addrs *ip_num;
    ip_num->ip_one = inet_addr(gateway_ip);
    ip_num->ip_two = inet_addr(target_ip);

    if (ip_num->ip_one == -1 || ip_num->ip_two == -1) {
        perror("inet_addr() returned an error: ");
        exit(1);
    }

    // Given the two IP addresses, find out the MAC addresses   
    uint8_t *mac_addr = get_mac_addr(ip_num->ip_one, own_mac);
    uint8_t *mac_addr = get_mac_addr(ip_num->ip_one, own_mac);


    // Construct ARP Packets for spoofing
    


    // Start the spoofing and analyze packets    

    printf("Starting spoofing\n");

    while (1) {
        arp_spoof(target_one_ip, target_two_ip, mac_target_one, own_mac);
        arp_spoof(target_two_ip, target_one_ip, mac_target_two, own_mac);
        sleep(1);
    }    
    
    return 0;
}


uint8_t *get_mac_addr(uint32_t ip_addr, uint8_t *own_mac) {
    
    struct arp_header *arp_hdr;

    arp_hdr->hardware_type = htons(1);
    arp_hdr->protocol_type = htons(0x0800);
    arp_hdr->hardware_size = 6;
    arp_hdr->protocol_size = 4;
    arp_hdr->opcode = htons(1);         // ARP request = 1, ARP_REPLY = 2
    
    memcpy(arp_hdr->sha, own_mac, 6);
    memcpy(arp_hdr->spa, own_ip, 4);
    memcpy(arp_hdr->tha, 0, 6);
    memcpy(arp_hdr->tpa, ip_addr, 4);

    struct sockaddr_ll dest_addr = {0};
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ARP);
    dest_addr.sll_ifindex = if_nametoindex(ifname);
    dest_addr.sll_halen = 6;

    uint8_t broadcast_mac[MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(dest_addr.sll_addr, broadcast_mac, 6);
    
    int sock = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (sock == -1) {
        perror("Error: socket()");
        return 1;
    }

    
    if (bind(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("bind failed");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
        return -1;
    }

    int bytes_sent = sendto(sockfd, req, sizeof(struct arp_header), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent < 0) {
        perror("sendto failed");
        return -1;
    }
    
    int bytes_recvd = recvfrom(sockfd, res, sizeof(struct arp_header), 0, NULL, NULL);
    if (bytes_recvd < 0) {
        return -1;
    }
    return bytes_recvd;
}

