#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_router.h"

void icmp_set_ethernet_hdr(unsigned char *, struct sr_ethernet_hdr *, struct sr_ethernet_hdr *);
void icmp_set_ip_hdr(uint32_t, struct sr_ip_hdr *, struct sr_ip_hdr *, int len);
void icmp_set_icmp_hdr(struct sr_icmp_hdr *, uint8_t, uint8_t);


void icmp_send_echo_reply(struct sr_instance* , uint8_t * , unsigned int , char* );
void icmp_send_net_unreachable(struct sr_instance* , uint8_t * , unsigned int , char* );
void icmp_send_host_unreachable(struct sr_instance* , uint8_t * , unsigned int , char* );
void icmp_send_port_unreachable(struct sr_instance* , uint8_t * , unsigned int , char* );
void icmp_send_time_exceeded(struct sr_instance* , uint8_t * , unsigned int , char* );

void icmp_send_generic(struct sr_instance* , uint8_t * , unsigned int , char* , uint8_t, uint8_t);
