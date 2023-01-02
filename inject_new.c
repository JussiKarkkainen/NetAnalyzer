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


int initialize_inject(char *gateway_ip, char *target_ip) {
    
    printf("Initializing inject\n");

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

