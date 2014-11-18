/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 * 90904102 
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
};

/* -----------------------------------------------------------------------

 * struct sr_icmphdr

 * Encapsulation of the icmp header of the packet
-------------------------------------------------------------------------*/

struct sr_icmphdr
{
	uint8_t type;
	uint8_t code; 
	uint16_t chksum;
	uint16_t id;
	uint16_t seq_n;
};

/*-------------------------------------------------------------------------

 * struct arp_cache

 * structure used to store the arp reply information
-------------------------------------------------------------------------*/

struct arp_cache
{
	uint32_t ip;
	unsigned char mac[ETHER_ADDR_LEN];
	double time_stamp;
	struct arp_cache* next;
};

struct packet_cache
{
	uint32_t ip;
	uint32_t* packet;
	struct sr_instance* sr;
	char* interface;
	int len;
	int is_for_gw;
	struct packet_cache* next;
};

struct packet_count
{
	uint32_t ip;
	int count_pkts;
	int is_arp_reply;
	struct packet_count* next;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
uint16_t calc_ip_checksum(struct ip* ip_hdr);
char* get_broadcast_interface(struct sr_rt* rtable, uint32_t dest_ip);
void forward_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void send_arp_request(struct sr_instance* sr, uint8_t* packet, unsigned int len, char * interface);
void arp_packet_handle(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface); 
/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
