#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_arp.h>
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
    
    uint8_t mac_addr_one[6];
    uint8_t mac_addr_two[6];

    // Given the two IP addresses, find out the MAC addresses   
    get_mac_addr(target_ip_one, my_ip, my_mac, interface, mac_addr_one);
    get_mac_addr(target_ip_two, my_ip, my_mac, interface, mac_addr_two);
    
    
    printf("MAC addresses found: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            mac_addr_one[0], mac_addr_one[1], mac_addr_one[2], mac_addr_one[3],
            mac_addr_one[4], mac_addr_one[5]);
    printf("MAC addresses found: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            mac_addr_two[0], mac_addr_two[1], mac_addr_two[2], mac_addr_two[3],
            mac_addr_two[4], mac_addr_two[5]);

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


int get_mac_addr(uint32_t target_ip, uint32_t own_ip, uint8_t *own_mac, char *ifname, uint8_t *mac_addr) {
    
    struct arp_header arp_hdr;
    arp_hdr.hardware_type = htons(1);
    arp_hdr.protocol_type = htons(0x0800);
    arp_hdr.hardware_size = 6;
    arp_hdr.protocol_size = 4;
    arp_hdr.opcode = htons(ARP_REQUEST);         // ARP_REQUEST = 1, ARP_REPLY = 2
    
    memcpy(arp_hdr.sha, own_mac, 6);
    memcpy(arp_hdr.spa, &own_ip, 4);
    memset(arp_hdr.tha, 0, 6);
    memcpy(arp_hdr.tpa, &target_ip, 4);
    
    struct sockaddr_ll dest_addr = {0};
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ARP);
    dest_addr.sll_hatype = ARPHRD_ETHER;
    dest_addr.sll_pkttype = PACKET_HOST;
    dest_addr.sll_ifindex = if_nametoindex(ifname);
    dest_addr.sll_halen = 6;
    
    if (dest_addr.sll_ifindex == 0) {
        perror("Error in if_nametoindex()");
        exit(1);
    }
    
    
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(dest_addr.sll_addr, broadcast_mac, 6);
    
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock == -1) {
        perror("Error: socket()");
        exit(1);
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) {
        perror("Error: setsockopt()");
        exit(1);
    } 


    while (1) {
        int bytes_sent = sendto(sock, &arp_hdr, sizeof(struct arp_header), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (bytes_sent < 0) {
            perror("sendto() failed");
            exit(1);
        }

        struct arp_header res;
        int bytes_recvd = recvfrom(sock, &res, sizeof(struct arp_header), 0, NULL, NULL);
        if (bytes_recvd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            perror("recvfrom() failed");
            exit(1);
        }

        if (ntohs(res.opcode) == ARPOP_REPLY) {
            memcpy(mac_addr, res.sha, 6);
            close(sock);
            return 0;
        }
    }

    perror("Unable to find target MAC addresses");
    exit(1);
}


/*
    int bytes_sent = sendto(sock, &arp_hdr, sizeof(struct arp_header), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent < 0) {
        perror("sendto() failed");
        exit(1);
    }
    
    struct arp_header res;

    int bytes_recvd = recvfrom(sock, &res, sizeof(struct arp_header), 0, NULL, NULL);
    if (bytes_recvd < 0) {
        perror("recvfrom() failed");
        exit(1);
    }
    if (ntohs(res.opcode) == ARPOP_REPLY) { 
        memcpy(mac_addr, res.sha, 6);
        close(sock);
    }
    printf("Unable to find target MAC addresses\n");
    exit(1);
    
}
*/
void arp_spoof(uint32_t ip_target, uint32_t ip_spoof) { 
/*    
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
   
    if ((sendto(sd, ethernet_packet, sizeof(struct arp_header) + sizeof(struct ethernet_header), 0,
                    (const struct sockaddr *)device, sizeof(*device))) <= 0) {
        perror("Error in sendto(): ");
        exit(1);
    }
  */
    uint32_t ip_send = ip_target;

}


