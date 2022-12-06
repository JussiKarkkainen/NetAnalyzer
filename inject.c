#include "inject.h"
#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include <stdint.h>

libnet_t *l;

struct libnet_ether_addr get_mac_addr(uint32_t);

int initialize_inject(char *gateway_ip, char *target_ip) {
    printf("Initializing inject\n");

    char *device = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    uint32_t target_one_ip;
    uint32_t target_two_ip;
    struct libnet_ether_addr *own_mac;
    uint32_t ip; 

    if ((l = libnet_init(LIBNET_LINK, device, errbuf)) ==  0) {
        fprintf(stderr, "Error in libnet_init\n%s", errbuf);
        exit(1);
    }
    
    if ((target_one_ip = libnet_name2addr4(l, gateway_ip, LIBNET_RESOLVE)) == -1) {
		fprintf(stderr, "Error in libnet_name2addr4: %s.\n%s", gateway_ip, libnet_geterror(l));
		exit(1);
	}
	
    if ((target_two_ip = libnet_name2addr4(l, target_ip, LIBNET_RESOLVE)) == -1) {
		fprintf(stderr, "An error occurred while converting the IP: %s.\n%s", target_ip, libnet_geterror(l));
		exit(1);
	}

	if ((own_mac = libnet_get_hwaddr(l)) == NULL) {
		fprintf(stderr, "An error occurred while getting the MAC address of the iface.\n%s", libnet_geterror(l));
		exit(1);
	}

	if ((ip = libnet_get_ipaddr4(l)) == -1) {
		fprintf(stderr, "An error occurred while getting the IP address of the iface.\n%s", libnet_geterror(l));
		exit(1);
	}
    
    device = l->device;
    
    printf("Hello %s\n", device);
    
    
    // Get MAC address of both targets.
    struct libnet_ether_addr target_mac_1 = get_mac_addr(target_one_ip)
    struct libnet_ether_addr target_mac_2 = get_mac_addr(target_two_ip)


    return 0;
}

struct libnet_ether_addr get_mac_addr(uint32_t ip_addr) {
    // Send an ARP request to given IP address
    libnet_ptag_t arp = 0, eth = 0;
    
    uint8_t broadcast_mac[6];
    memset(broadcast_mac, 0xFF, ETHER_ADDR_LEN);

    arp = libnet_autobuild_arp(ARPOP_REQUEST, 
                               (uint8_t *) mac,
                               (uint8_t *) &ip,
                               (uint8_t *) broadcast_mac,
                               (uint8_t *) ip_addr,
                                           l);
    if (arp == -1) {
        fprintf(stderr, "Error in creating arp packet: %s\n", libnet_geterror(l));
        exit(1);
    }

    eth = libnet_build_ethernet((uint8_t *) broadcast_ether,
                               (uint8_t *) mac,
                               ETHERTYPE_ARP,
                               NULL,
                               0,
                               l,
                               0);
    if (eth == -1) {
        fprintf(stderr, "Error in creating eth packet: %s\n", libnet_geterror(l));
        exit(1);
    }

    if ((libnet_write(l)) == -1) {
        fprintf(stderr, "Error in sending ARP request: %s\n", libnet_geterror(l));
        exit(1);
    }
    
    


    return mac_addr
}
