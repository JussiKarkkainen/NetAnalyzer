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

struct ip_addrs {
    uint32_t ip_one;
    uint32_t ip_two;
};

int initialize_inject(char *gateway_ip, char *target_ip) {
    
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

