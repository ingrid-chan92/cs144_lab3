/**********************************************************************
 * file: icmp_handler.c
 *
 * Description:
 *
 * This file contains all functions used to send ICMP messages
 *
 *
 **********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "icmp_handler.h"
#include "sr_utils.h"


void icmp_set_ethernet_hdr(unsigned char *source, struct sr_ethernet_hdr *received, struct sr_ethernet_hdr *response) {
	int i;

	/* Recevier is now destination. We are source */
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		response->ether_dhost[i] = received->ether_shost[i];
		response->ether_shost[i] = source[i];
	}
	response->ether_type = htons(ethertype_ip);
}

void icmp_set_ip_hdr(uint32_t source, struct sr_ip_hdr *received, struct sr_ip_hdr *response) {
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		response->ip_hl = 4;
		response->ip_v = 4;
	#elif __BYTE_ORDER == __BIG_ENDIAN
		response->ip_v = 4;
		response->ip_hl = 4;
	#else
	#error "Byte ordering not specified " 
	#endif 

	response->ip_tos = 0;
	response->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr));
	response->ip_id = 0;
	response->ip_off = 0;
	response->ip_ttl = htons(255);
	response->ip_p = htons(ip_protocol_icmp);

	/* Recevier is now destination. We are source */
	response->ip_src = source;
	response->ip_dst = received->ip_src;

	response->ip_sum = 0;
	response->ip_sum = cksum(received, sizeof(struct sr_ip_hdr));

}

void icmp_set_icmp_hdr(struct sr_icmp_hdr *response, uint8_t type, uint8_t code) {
	response->icmp_type = htons(type);
	response->icmp_code = htons(code);
	response->icmp_sum = 0;
	response->icmp_sum = cksum(response, sizeof(struct sr_icmp_hdr));
}

void icmp_send_echo_reply(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* Modify and resend packet at echo reply */

	/* Ethernet header */
	int i;
	unsigned char *sourceEth = sr_get_interface(sr, interface)->addr;
	struct sr_ethernet_hdr *ethHeader = (struct sr_ethernet_hdr *) packet;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		ethHeader->ether_dhost[i] = ethHeader->ether_shost[i];
		ethHeader->ether_shost[i] = sourceEth[i];
	}

	/* IP header */
	uint32_t sourceIP = sr_get_interface(sr, interface)->ip;
	struct sr_ip_hdr *ipHeader = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));
	ipHeader->ip_dst = ipHeader->ip_src;
	ipHeader->ip_src = sourceIP;	
	ipHeader->ip_sum = 0;
	ipHeader->ip_sum = cksum(ipHeader, sizeof(struct sr_ip_hdr));

	/* ICMP header */
	struct sr_icmp_hdr *icmpHeader = (struct sr_icmp_hdr *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	icmpHeader->icmp_type = htons(icmp_echo_reply_type);
	icmpHeader->icmp_code = htons(0);

	sr_send_packet(sr, packet, len, interface);	
}

void icmp_send_net_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	icmp_send_generic(sr, packet, len, interface, icmp_unreachable_type, icmp_net_unreachable);
}

void icmp_send_host_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	icmp_send_generic(sr, packet, len, interface, icmp_unreachable_type, icmp_host_unreachable);
}

void icmp_send_port_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	icmp_send_generic(sr, packet, len, interface, icmp_unreachable_type, icmp_port_unreachable);
}

void icmp_send_time_exceeded(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	icmp_send_generic(sr, packet, len, interface, icmp_time_exceeded_type, 0);
}

void icmp_send_generic(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
	uint8_t type,
	uint8_t code) 
{

	uint8_t *response = malloc(PACKET_SIZE);

	/* Set contents of response */
	icmp_set_ethernet_hdr(sr_get_interface(sr, interface)->addr, (struct sr_ethernet_hdr *) packet, (struct sr_ethernet_hdr *) response);
	icmp_set_ip_hdr(	sr_get_interface(sr, interface)->ip,
						(struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr)), 
						(struct sr_ip_hdr *) (response + sizeof(struct sr_ethernet_hdr)));
	icmp_set_icmp_hdr(	(struct sr_icmp_hdr *) (response + sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)),
						type, code);
print_hdrs(response, PACKET_SIZE);

	sr_send_packet(sr, response, PACKET_SIZE, interface);	
	free(response);
}

