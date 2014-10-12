/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "icmp_handler.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
	
	/* Initialize reusable information */
	struct sr_if *this_if = sr_get_interface(sr, interface);

	if (ethertype(packet) == ethertype_arp) {			/* ARP packet */
		struct sr_arp_hdr *arpHeader = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

		if (is_broadcast_mac(packet) || this_if->ip == arpHeader->ar_tip) {
			/* TODO DO ARP REQUEST */

		}

	} else if (ethertype(packet) == ethertype_ip) { 	/* IP packet */
		struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

		if (this_if->ip == ipHeader->ip_dst) {
			/* We are destination */
			processIP(sr, packet, len, interface);			

		} else {
			/* We are not destination. Forward it. */
			processForward(sr, packet, len, interface);
		}
	}
	
}

void processIP(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface) {

	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

	if (ipHeader->ip_p == ip_protocol_icmp) {
		/* ICMP request */ 

		/* Ignore invalid packets */ 
		if (!is_sane_icmp_packet(packet, len)) {
			return;
		}			

		/* Process ICMP only if echo*/ 
		struct sr_icmp_hdr *icmpHeader = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
		if (icmpHeader->icmp_type == icmp_echo_req_type) {
			icmp_send_echo_reply(sr, packet, len, interface);
		}

	} else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp) {
		/* TCP or UDP Payload */
		icmp_send_port_unreachable(sr, packet, len, interface);

	}

}

void processForward(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface) {
/*	
	// Ignore invalid packets 
	if (!is_sane_ip_packet(packet, len)) {		
		return;
	}

	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
	// TODO 

*/
}
