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

void icmp_set_ethernet_hdr(struct sr_ethernet_hdr *received, struct sr_ethernet_hdr *response) {

}

void icmp_set_ip_hdr(struct sr_ip_hdr *received, struct sr_ip_hdr *response) {

}

void icmp_set_icmp_hdr(struct sr_icmp_hdr *response, uint8_t type, uint8_t code) {
	response->icmp_type = type;
	response->icmp_code = code;
	response->icmp_sum = cksum(response, sizeof(struct sr_icmp_hdr));
}

void icmp_send_echo_reply(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

	uint8_t *response = malloc(sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr));
	
	/* Set contents of response */
	icmp_set_ethernet_hdr((struct sr_ethernet_hdr *) packet, (struct sr_ethernet_hdr *) response);
	icmp_set_ip_hdr(	(struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr)), 
						(struct sr_ip_hdr *) (response + sizeof(struct sr_ethernet_hdr)));
	icmp_set_icmp_hdr(	(struct sr_icmp_hdr *) (response + sizeof(struct sr_ip_hdr) + sizeof(struct sr_ethernet_hdr)),
						icmp_echo_reply_type, 0);
	

	sr_send_packet(sr, response, len, interface);	
	free(response);
}

void icmp_send_net_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

}

void icmp_send_host_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

}

void icmp_send_port_unreachable(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

}

void icmp_send_time_exceeded(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

}

