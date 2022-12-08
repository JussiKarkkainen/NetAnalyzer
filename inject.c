#include "inject.h"
#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include <stdint.h>

libnet_t *l;

pcap_t *handle;
uint32_t ip_tmp;

void process_packet(void); 
void get_mac_addr(uint32_t, struct libnet_ether_addr*);

int initialize_inject(char *gateway_ip, char *target_ip) {
    printf("Initializing inject\n");

    char *device = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    uint32_t target_one_ip;
    uint32_t target_two_ip;
    struct libnet_ether_addr *own_mac;
    struct bpf_program fp;
    uint32_t ip; 
    char *filter = "arp";

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
    
	if ((handle = pcap_open_live(device, 1500, 0, 2000, errbuf)) == NULL) {
		fprintf(stderr, "An error occurred while opening the device.\n%s", errbuf);
		exit (1);
	}

	if (strlen(errbuf) > 0) {
		fprintf (stderr, "Warning: %s", errbuf);
		errbuf[0] = 0;
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf (stderr, "This program only supports Ethernet cards!\n");
		exit(1);
	}

	/* Compiling the filter for ARP packet only */
	if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf (stderr, "%s", pcap_geterr (handle));
		exit(1);
	}

	/* Setting the filter for the sniffing session */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf (stderr, "%s", pcap_geterr(handle));
		exit(1);
	}

	pcap_freecode(&fp);
    
    // Get MAC address of both targets.
    get_mac_addr(target_one_ip, own_mac);
    get_mac_addr(target_two_ip, own_mac);
    

    return 0;
}

void get_mac_addr(uint32_t ip_addr, struct libnet_ether_addr *mac) {
    // Send an ARP request to given IP address
    libnet_ptag_t arp = 0, eth = 0;
    int s;    
    uint8_t broadcast_mac[6];
    memset(broadcast_mac, 0xFF, ETHER_ADDR_LEN);

    arp = libnet_autobuild_arp(ARPOP_REQUEST, 
                               (uint8_t *) mac,
                               (uint8_t *) &ip_addr,
                               (uint8_t *) broadcast_mac,
                               (uint8_t *) &ip_tmp,
                                           l);
    if (arp == -1) {
        fprintf(stderr, "Error in creating arp packet: %s\n", libnet_geterror(l));
        exit(1);
    }

    eth = libnet_build_ethernet((uint8_t *) broadcast_mac,
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
    
    printf("Sent ARP request, analyzing replies\n");
    
    if ((s = pcap_loop(handle, -1, process_packet, NULL)) < 0) {
        if (s == -1) {
            fprintf(stderr, "%s", pcap_geterr(handle));
            exit(1);
        }
    }
    libnet_clear_packet(l);
}


void process_packet() {
}


void arp_spoof() {
}

