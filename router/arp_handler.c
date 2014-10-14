/**********************************************************************
 * file: arp_handler.c
 *
 * Description:
 *
 * This file contains all functions used to send arp messages
 * 
 *
 **********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_if.h"
#include "arp_handler.h"
#include "sr_protocol.h"

void arp_send_reply(struct sr_instance *sr , uint8_t *packet, unsigned int len, char *interface) {

    int i;
    struct sr_if *sourceIf = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr *) packet;
	struct sr_arp_hdr *arpHeader = (struct sr_arp_hdr *) (packet + sizeof(struct sr_ethernet_hdr));
    
    /* Initialize reply packet */
    uint8_t *reply = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
    struct sr_ethernet_hdr *replyEth = (struct sr_ethernet_hdr *) reply;
    struct sr_arp_hdr *replyArp = (struct sr_arp_hdr *) (reply + sizeof(struct sr_ethernet_hdr));
    
    /* Construct ethernet header */        
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        replyEth->ether_dhost[i] = ethHeader->ether_shost[i];
        replyEth->ether_shost[i] = sourceIf->addr[i];
    }
    replyEth->ether_type = htons(ethertype_arp);

    /* Construct ARP header */
    replyArp->ar_hrd = arpHeader->ar_hrd;
    replyArp->ar_pro = arpHeader->ar_pro;
    replyArp->ar_hln = arpHeader->ar_hln;
    replyArp->ar_pln = arpHeader->ar_pln;
    replyArp->ar_op = htons(arp_op_reply);
    replyArp->ar_sip = htonl(sourceIf->ip);
    replyArp->ar_tip = arpHeader->ar_sip;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        replyArp->ar_sha[i] = sourceIf->addr[i];
        replyArp->ar_tha[i] = arpHeader->ar_sha[i];
    }

    sr_send_packet(sr, reply, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), interface);	

    free(reply);

}

void send_packet_to_dest(struct sr_instance *sr , uint8_t *packet, unsigned int len, char *interface, unsigned char *dest_mac, uint32_t dest_ip) {
    
    int i;
    struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr *) packet;
    struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

    /* send the given packet to the destination mac and ip */   
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        ethHeader->ether_dhost[i] = dest_mac[i];
    }
    ipHeader->ip_dst = htonl(dest_ip);

    sr_send_packet(sr, packet, len, interface);	

}

void arp_send_request(struct sr_instance *sr , struct sr_arpreq *arpReq) {

	int i;
	struct sr_packet *pkt = arpReq->packets;  

	while (pkt != NULL) {		
		struct sr_if *sourceIf = sr_get_interface(sr, pkt->iface);
		
		/* Initialize request packet */
		uint8_t *req = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
		struct sr_ethernet_hdr *reqEth = (struct sr_ethernet_hdr *) req;
		struct sr_arp_hdr *reqArp = (struct sr_arp_hdr *) (req + sizeof(struct sr_ethernet_hdr));
		
		/* Construct ethernet header */        
		for (i = 0; i < ETHER_ADDR_LEN; i++) {
		    reqEth->ether_dhost[i] = 0xff;
		    reqEth->ether_shost[i] = sourceIf->addr[i];
		}
		reqEth->ether_type = htons(ethertype_arp);

		/* Construct ARP header */
		reqArp->ar_hrd = htons(arp_hrd_ethernet);
		reqArp->ar_pro = htons(0x0800);				/*IPv4 protocol type*/
		reqArp->ar_hln = htons(6);					/*Ethernet addresses size*/
		reqArp->ar_pln = htons(4);					/*IPv4 address size*/
		reqArp->ar_op = htons(arp_op_request);
		reqArp->ar_sip = htonl(sourceIf->ip);
		reqArp->ar_tip = 0x0000;
		for (i = 0; i < ETHER_ADDR_LEN; i++) {
		    reqArp->ar_sha[i] = sourceIf->addr[i];
		    reqArp->ar_tha[i] = 0xff;
		}

		sr_send_packet(sr, req, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), pkt->iface);	
		free(req);

		pkt = pkt->next;
	}

}
