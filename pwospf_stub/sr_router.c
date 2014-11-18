/*
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
//#include "arp.h"

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_pwospf.h"

struct arp_cache* head = NULL;
struct packet_cache* pkt_queue = NULL;
struct packet_count* pkt_count = NULL;
static int is_thread_alive = 0;
pthread_mutex_t lock;
/*------------------------------------------------------------------------ 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *-----------------------------------------------------------------------*/
void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    	assert(sr);
	if(pthread_mutex_init(&lock, NULL) != 0)
	{
		printf("\nmutex init failed");
		return 1;
	}
	pwospf_init(sr);
    /* Add initialization code here! */
} /* -- sr_init -- */



/*------------------------------------------------------------------------
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
 *-----------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    	assert(sr);
    	assert(packet);
    	assert(interface);
    
    //printf("Computation starts here");
    	sr_init(sr);

    //struct sr_if* iface = sr_get_interface(sr, interface);
    	struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
    	printf("Ether_type: %d", ntohs(e_hdr->ether_type));
    	if(ntohs(e_hdr->ether_type) == ETHERTYPE_ARP){
		printf("handle arp");
		arp_pkt_handle(sr, packet, len, interface);
    	}   
    	else if(ntohs(e_hdr->ether_type) == ETHERTYPE_IP){
		
		printf("handle ip packet");
		ip_pkt_handle(sr, packet, len, interface);
    	}
	
    
    printf("*** -> Received packet of length %d \n",len);
    //printf("%s %u", sr->if_list->name, &packet);
}/* end sr_ForwardPacket */


/*------------------------------------------------------------------------
 * Method: chk_iflist_interface(struct ip* ip_hdr, struct sr_instance * sr)
 * Scope: Global
 *-----------------------------------------------------------------------*/

struct sr_if* chk_iflist_interface(struct ip* ip_hdr, struct sr_instance* sr){
	struct sr_if* if_list = sr->if_list;
	while(if_list){
		if(ip_hdr->ip_dst.s_addr == if_list->ip){
			return if_list;
		}
		
		if_list = if_list->next;
	}
	return NULL;
}

/*------------------------------------------------------------------------
 * Method: calc_icmp_chksum(uint16_t* buf, int len)
 * Scope: Global
 *----------------------------------------------------------------------*/
void calc_icmp_chksum(struct sr_icmphdr* icmp_hdr, uint8_t* packet, int len){
	uint32_t sum = 0;
	icmp_hdr->chksum = 0;
	uint16_t* tmp = (uint16_t *)packet;
	int i; 
	for(i = 0; i < len / 2; i++){
		sum = sum + tmp[i];
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum = sum + (sum >> 16);
	
	icmp_hdr->chksum = ~sum;
}
/*------------------------------------------------------------------------- * Method: dump_packets(uint32_t ip_)
 * Scope: Global
 *-----------------------------------------------------------------------*/
void dump_packets(uint32_t ip){
	struct packet_cache* find_dump_packet = pkt_queue;
	struct packet_cache* packet_found = (struct packet_cache*)malloc(sizeof(struct packet_cache));
	struct packet_cache* prev = NULL;
	while(find_dump_packet){
		if(find_dump_packet->ip == ip){
			if(prev == NULL){
				packet_found = find_dump_packet;
				find_dump_packet = find_dump_packet->next;
				pkt_queue = find_dump_packet;
			}
			else{
				packet_found = find_dump_packet;
				prev->next = find_dump_packet->next;
				find_dump_packet = find_dump_packet->next;
			}
			sr_send_packet(find_dump_packet->sr, find_dump_packet->packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_icmphdr) + 28, find_dump_packet->interface);
			dequeue_pkt_count(ip);
			free(packet_found);
		}
		else{
			prev = find_dump_packet;
			find_dump_packet = find_dump_packet->next;
		}
		//find_dump_packet = find_dump_packet->next;
	}
}

/*------------------------------------------------------------------------
 * Method: send_icmp_error(struct sr_instance* sr, int len, char* interface, uint8_t* packet, uint_t type, uint8_t code)
 *----------------------------------------------------------------------*/
void send_icmp_error(struct sr_instance* sr, uint8_t* packet, int len, char* interface, uint8_t type, uint8_t code){
	uint8_t* new_packet = (uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_icmphdr) + 28);
	struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)new_packet;
	struct sr_ethernet_hdr* old_e_hdr = (struct sr_ethernet_hdr*)packet;
	struct ip* ip_hdr = (struct ip*)(new_packet + sizeof(struct sr_ethernet_hdr));
	struct ip* old_ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	struct sr_icmphdr* icmp_hdr = (struct sr_icmphdr*)(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	
	int i;

	e_hdr->ether_type = htons(ETHERTYPE_IP);
	//uint8_t* temp = e_hdr->ether_dhost;
	for(i = 0; i < 6; i++){
		e_hdr->ether_dhost[i] = old_e_hdr->ether_shost[i];

		e_hdr->ether_shost[i] = old_e_hdr->ether_dhost[i];
	}
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(56);
	ip_hdr->ip_id = old_ip_hdr->ip_id;
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = IPPROTO_ICMP;
	
	printf("\nIP Source before swap: %s", inet_ntoa(*(struct in_addr*)&(old_ip_hdr->ip_src.s_addr)));
	printf("\nIP Dest before swap: %s", inet_ntoa(*(struct in_addr*)&(old_ip_hdr->ip_dst.s_addr)));

	//ip_hdr->ip_src.s_addr = old_ip_hdr->ip_src.s_addr;
	struct sr_if* if_list = sr->if_list;
	while(if_list){
		if(strcmp(if_list->name, interface) == 0){
			printf("\nInterface ip: %s", inet_ntoa(*(struct in_addr*)&if_list->ip));
			break;
		}
		if_list = if_list->next;
	}
	ip_hdr->ip_src.s_addr = if_list->ip;
	ip_hdr->ip_dst.s_addr = old_ip_hdr->ip_src.s_addr;
	printf("\nDEST AFTER SWAP: %s", inet_ntoa(*(struct in_addr*)&ip_hdr->ip_dst.s_addr));
	icmp_hdr->code = code;
	icmp_hdr->type = type;
	icmp_hdr->id = 0;
	icmp_hdr->seq_n = 0;
	
	memcpy(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_icmphdr), old_ip_hdr, 28);
	
	//icmp_hdr->chksum = 0;
	calc_icmp_chksum(icmp_hdr , new_packet + sizeof(struct sr_ethernet_hdr) + 20, 36);
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = calc_ip_checksum(ip_hdr);	

	printf("\nEther size: %d", sizeof(struct sr_ethernet_hdr));
	printf("\nIP header: %d", sizeof(struct ip));
	printf("\nICMP size: %d", sizeof(struct sr_icmphdr));

	printf("\nEthernet source after swapping:");
	for(i = 0; i < 6; i++){
		printf("%x ", e_hdr->ether_shost[i]);
	}
	printf("\nEthernet dest after swapping:");
	for(i = 0 ; i < 6; i++){
		printf("%x ", e_hdr->ether_dhost[i]);
	}
	printf("\n IP source address after swapping: %s", inet_ntoa(*(struct in_addr*)&(ip_hdr->ip_src.s_addr)));
	printf("\nIP dest sddr after swapping: %s", inet_ntoa(*(struct in_addr*)&(ip_hdr->ip_dst.s_addr)));
	printf("\n Interface: %s", interface); 
	printf("Packet length : %d", sizeof(*(new_packet)));
	
	printf("ip_hdr source:%s", inet_ntoa(*(struct in_addr*)&ip_hdr->ip_src.s_addr));
	printf("ip_hdr dest:%s", inet_ntoa(*(struct in_addr*)&ip_hdr->ip_dst.s_addr));
	//dump_packets(ip_hdr->ip_dst.s_addr);
	sr_send_packet(sr, new_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_icmphdr) + 28, interface);

}


/*------------------------------------------------------------------------
 * Method: ip_pkt_handle(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
 * Scope: Global
-------------------------------------------------------------------------*/
void ip_pkt_handle(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface){
	struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
	struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	struct timeval tv;
	double time_stamp;
	
	int i;
	//struct sr_icmphdr* icmp_hdr = (struct sr_icmphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

	//uint32_t dest_ip = ip_hdr->ip_dst.s_addr;
	
	printf("\nInside ip_pkt_handle");
	struct sr_rt* rtable = sr->routing_table;;
	struct sr_if* if_list = sr->if_list;
	printf("\nCaching gateway");
	while(rtable){
		if(rtable->dest.s_addr == 0 && rtable->mask.s_addr == 0){
			printf("\nGateway found in rtable");
			while(if_list){
				printf("fdrgfrgr");
				if(strcmp(if_list->name,rtable->interface) == 0){
					int match = 1;
					for(i = 0; i < 6; i++)
					if(e_hdr->ether_dhost[i] != if_list->addr[i])
					match = 0;
					if(match == 1){
					printf("\nPacket from gateway");
					struct arp_cache* cache = (struct arp_cache*)malloc(sizeof(struct arp_cache));
					cache->ip = rtable->gw.s_addr;
					for(i = 0; i < 6; i++){
						cache->mac[i] = e_hdr->ether_shost[i];
					}
					gettimeofday(&tv, NULL);
					time_stamp = tv.tv_sec + (tv.tv_usec / 1000000.0);
					cache->time_stamp = time_stamp;
					cache->next = NULL;
					add_arp_cache(cache);
					printf("\nGaateway added to cache");
					}
				}
				if_list = if_list->next;
			}

			/*struct arp_cache* cache = (struct arp_cache*)malloc(sizeof(struct arp_cache));
			cache->ip = rtable->dest.s_addr;
			for(i = 0; i < 6; i++){
				cache->mac[i] = e_hdr->ether_shost[i];
			}
			gettimeofday(&tv, NULL);
			time_stamp = tv.tv_sec + (tv.tv_usec/1000000.0);
			cache->time_stamp = time_stamp;
			cache->next = NULL;
			add_arp_cache(cache);*/
		}
		rtable = rtable->next;
	}

	//check if the dest of the packet is one of the if list interface, then forward eth0, else to destination
	if(chk_iflist_interface(ip_hdr, sr) == NULL){
		if(ip_hdr->ip_ttl > 1){
			forward_ip_packet(sr, packet, len, interface);
			return;
		}
		else{
			printf("\nTime to live exceeded\n");
			int icmp_type = 11;	// time to live exceeded
			int icmp_code = 0;	// time to live exceeded in transit
			send_icmp_error(sr, packet, len, interface, icmp_type, icmp_code);
		}
		
	}	
	else{	//if router is pinged
		struct sr_icmphdr* icmp_hdr = (struct sr_icmphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
		printf("Recieved ICMP ECHO REQUEST!!");
	
		if(ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17){
			int icmp_type = 3;
			int icmp_code = 3;
			send_icmp_error(sr, packet, len, interface, icmp_type, icmp_code);
		}

		char mac[6];
		for(int i = 0; i < 6; i++){
			mac[i] = e_hdr->ether_shost[i];
		}
		for(int i = 0; i < 6; i++){
			e_hdr->ether_shost[i] = e_hdr->ether_dhost[i];
		}
		for(int i = 0; i < 6; i++){
			e_hdr->ether_dhost[i] = mac[i];
		}	
		uint32_t ip; 
		ip = ip_hdr->ip_src.s_addr;
		ip_hdr->ip_src.s_addr = ip_hdr->ip_dst.s_addr;
		ip_hdr->ip_dst.s_addr = ip;
		printf("\nIP TTL: %d", ip_hdr->ip_ttl);
		icmp_hdr->type = 0;
		icmp_hdr->code = 0;
		icmp_hdr->chksum = 0;
		calc_icmp_chksum(icmp_hdr, packet + sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4, len - sizeof(struct sr_ethernet_hdr) - ip_hdr->ip_hl * 4);

		sr_send_packet(sr, packet, len, interface);
	}
}


void printPacket(uint8_t* packet){
	struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
	struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	struct sr_icmphdr* icmp_hdr = (struct sr_icmphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

	struct sr_arphdr* a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));

	printf("\nDest IP: %s", inet_ntoa(*(struct in_addr*)&(ip_hdr->ip_dst.s_addr)));
	printf("\nSource ip: %s", inet_ntoa(*(struct in_addr*)&(ip_hdr->ip_src.s_addr)));

	printf("\nSource eth_shost: ");
	for(int i = 0; i < 6; i++){
		printf("%x ", e_hdr->ether_shost[i]);
	}
	printf("\nDest eth_dhost: ");
	for(int i = 0; i < 6; i++){
		printf("%x " , e_hdr->ether_dhost[i]);
	}
	//printf("Source IP: %s", inet_ntoa()
}

/*----------------------------------------------------------------------------------------------------------------------------------------------------------
 * Method: increment_packet_count(uint32_t ip)
 * Scope: Global
 *--------------------------------------------------------------------------------------------------------------------------------------------------------*/
void increment_packet_count(uint32_t ip){
	//printf("\n inside pkt count incrementter");
	struct packet_count* local_pkt_count = pkt_count;
	struct packet_count* new_pkt_count = (struct packet_count*)malloc(sizeof(struct packet_count));
	struct packet_count* prev = NULL;
	int packet_found = 0;
	printf("\n Incrementing pkt count");
	if(local_pkt_count == NULL){
		//printf("Fegfrgtgh");
		new_pkt_count->ip = ip;
		new_pkt_count->count_pkts = 1;
		new_pkt_count->is_arp_reply = 0;		
		new_pkt_count->next = NULL;
		local_pkt_count = new_pkt_count;
		pkt_count = local_pkt_count;
		//printf("\nPacket count for %s: %d", inet_ntoa(*(struct in_addr*)&ip), local_pkt_count->count_pkts);
	}
	else{
		//printf("Defeferg");
		while(local_pkt_count != NULL){
			if(local_pkt_count->ip == ip){
				local_pkt_count->count_pkts = local_pkt_count->count_pkts + 1;
				packet_found = 1;
				//printf("\nPacket count for %s: %d", inet_ntoa(*(struct in_addr*)&ip), local_pkt_count->count_pkts);
				break;
			}
			prev = local_pkt_count;
			local_pkt_count = local_pkt_count->next;
		}
		if(packet_found == 0){
			new_pkt_count->ip = ip;
			new_pkt_count->count_pkts = 1;
			new_pkt_count->is_arp_reply = 0;
			new_pkt_count->next = NULL;
			prev->next = new_pkt_count;
			//printf("\nPacket count for %s: %d", inet_ntoa(*(struct in_addr*)&ip), local_pkt_count->count_pkts);
		}
		
	}
	local_pkt_count = pkt_count;
	printf("\nEntries in pkt count cache:\n");
	while(local_pkt_count){
		printf("\nIP addre: %s", inet_ntoa(*(struct in_addr*)&local_pkt_count->ip));
		printf("\tpacket count: %d", local_pkt_count->count_pkts);
		local_pkt_count = local_pkt_count->next;
	}

}

/*----------------------------------------------------------------------------------------------------------------------------------------------------------
 * Method: cache_this_packet(uint32_t ip, uint8_t* packet, int len, struct sr_instance* sr, char* interface)
 * Scope: Global
 *--------------------------------------------------------------------------------------------------------------------------------------------------------*/
void cache_this_packet(uint32_t ip, uint8_t* packet, int len, struct sr_instance* sr, char* interface, int is_for_gw){
	struct packet_cache* temp = pkt_queue;
	struct packet_count* prev = NULL;
	struct packet_cache* new_packet = (struct packet_cache*)malloc(sizeof(struct packet_cache));
	struct packet_count* local_pkt_count = pkt_count;
	struct packet_count* new_pkt_count = (struct packet_count*)malloc(sizeof(struct packet_count));

	new_packet->ip = ip;
	new_packet->packet = (uint8_t*)malloc(sizeof(uint8_t) * len);
	memcpy(new_packet->packet, packet, (sizeof(uint8_t) * len));
	new_packet->len = len;
	new_packet->sr = sr;
	new_packet->interface = interface;
	new_packet->is_for_gw = is_for_gw;
	new_packet->next = NULL;

	if(temp == NULL){
		temp = new_packet;
		pkt_queue = temp;
		printf("\nFirst IP packet cached\n");

		//add counter for ip packet
	}
	else{
		while(temp->next != NULL){
			//prev = temp;
			temp = temp->next;
		}
		temp->next = new_packet;
		printf("\n New packet cached\n");
	}
	printf("\nCache entries exist for:\n");
	temp = pkt_queue;
	while(temp){
		printf("\nIP : %s", inet_ntoa(*(struct in_addr*)&temp->ip));
		temp = temp->next;
	}

	//printf("\nCalling COUNTER INCREMENT");
	increment_packet_count(ip);
	
}

/*----------------------------------------------------------------------------------------------------------------------------------------------------------
 * Method: chk_reply_for_gw(uint32_t ip)
 * Scope: Global
 *--------------------------------------------------------------------------------------------------------------------------------------------------------*/
int chk_reply_for_gw(uint32_t ip, struct sr_instance* sr){
	struct sr_rt* rtable = sr->routing_table;
	while(rtable){
		if(rtable->gw.s_addr == ip){
			return 1;
		}
		rtable = rtable->next;
	}
	return 0;
}

void dequeue_pkt_count(uint32_t ip){
	printf("\n Inside pkt count dequeue: ");
	struct packet_count* temp = pkt_count;
	struct packet_count* prev = NULL;
	struct packet_count* packet_found = NULL;
	
	while(temp){
		if(temp->ip == ip){
			temp->count_pkts = temp->count_pkts - 1;
			if(temp->count_pkts < 1){
				if(prev == NULL){
					//printf("\ndelete entry found!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
					packet_found = temp;
					temp = temp->next;
					pkt_count = temp;
				}
				else{
					//printf("\ndelete entry found 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
					packet_found = temp;	
					prev->next = temp->next;
					temp = temp->next;
				}
				free(packet_found);
			}	
		}
		else{
			prev = temp;
			temp = temp->next;			
		}
	}	
	temp = pkt_count;
	while(temp){
		printf("\nIP : %s", inet_ntoa(*(struct in_addr*)&temp->ip));
		printf("\tPacket count: %d", temp->count_pkts);
		temp = temp->next;
	}
}

/*----------------------------------------------------------------------------------------------------------------------------------------------------------
 * Method: dequeue_packet(uint32_t)
 * Scope: Global
 *--------------------------------------------------------------------------------------------------------------------------------------------------------*/
void dequeue_packet(uint32_t ip){
	printf("\nI am dequeueing you");
	struct packet_cache* temp = pkt_queue;
	struct packet_cache* prev = NULL;
	struct packet_cache* packet_found = NULL;
	int is_reply_for_gw = 0;
	int pkt_dequeued = 0;

	
	while(temp){
		is_reply_for_gw = chk_reply_for_gw(ip, temp->sr);

		if(temp->ip == ip || (temp->is_for_gw == 1 && is_reply_for_gw == 1)){
			if(prev == NULL){
				packet_found = temp;
				temp = temp->next;
				pkt_queue = temp;
			}
			else{
				packet_found = temp;
				prev->next = temp->next;
				temp = temp->next;
			}
			forward_ip_packet(packet_found->sr, packet_found->packet, packet_found->len, packet_found->interface);
			free(packet_found);
			dequeue_pkt_count(ip);
			
		}
		else{
			prev = temp;
			temp = temp->next;
		}
	}
	
	printf("\nDequeue complete");
	temp = pkt_queue;
	while(temp){
		printf("ip :%s", inet_ntoa(*(struct in_addr*)&temp->ip));
		temp = temp->next;
	}
	/*printf("Removing entry from pkt count queue");
	if(packet_found == 1)
		dequeue_pkt_count(ip);*/
}

/*------------------------------------------------------------------------
 * Method: worker(void * arg)
 * Scope: Global
 *-----------------------------------------------------------------------*/
void *worker(void *arg){
	uint32_t dest_ip = *((uint32_t *)arg);
	int i = 0;
	struct packet_cache* find_arp = pkt_queue;
	struct packet_count* find_arp_recvd = pkt_count;
	char* interface;
	int is_arp_reply = 0;
/*	if(pthread_mutex_init(&lock, NULL) != 0){
		printf("\nNo able to locak.. Spin!!");
	}*/
	//pthread_mutex_lock(&lock);
	is_thread_alive = 1;
	while(find_arp){
		if(find_arp->ip == dest_ip){
			break;
		}
		find_arp = find_arp->next;
	}
	while(find_arp_recvd){
		if(find_arp_recvd->ip == dest_ip){
			is_arp_reply = find_arp_recvd->is_arp_reply;
			break;
		}
		find_arp_recvd = find_arp_recvd->next;
	}
	while(i < 5 && is_arp_reply != 1 && is_thread_alive == 1){
		printf("\nSpawning thread#%d for %s\n", i, inet_ntoa(*(struct in_addr*)&dest_ip));
		pthread_mutex_lock(&lock);
		send_arp_request(find_arp->sr, find_arp->packet, find_arp->len, find_arp->interface);
		pthread_mutex_unlock(&lock);
		find_arp_recvd = pkt_count;
		while(find_arp_recvd){
			if(find_arp_recvd->ip == dest_ip){
				is_arp_reply = find_arp_recvd->is_arp_reply;
				break;
			}
			find_arp_recvd = find_arp_recvd->next;
		}
		sleep(1);
		i++;
	}
	if(i >= 5){
		//is_thread_alive = 0;
		printf("\nDestinastion host unreachable");
		struct sr_rt* rtable = find_arp->sr->routing_table;
		while(rtable){
			if(rtable->dest.s_addr == 0 && rtable->mask.s_addr == 0){
				interface = rtable->interface;
			}
			rtable = rtable->next;
		}
		send_icmp_error(find_arp->sr, find_arp->packet, find_arp->len, interface, 3, 1);
		printf("\nInterface; %s", interface);

	}
	//pthread_mutex_unlock(&lock);
	is_thread_alive = 0;
	//pthread_mutex_unlock(&lock);
	//pthread_exit(0);
	return NULL;
}


/*-------------------------------------------------------------------------
 * Method: forward_ip_packet()
 *-----------------------------------------------------------------------*/
void forward_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface){
	int is_for_gw = 0;
	struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
	struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	uint32_t dest_ip = ip_hdr->ip_dst.s_addr;
	printf("\nInside forward_ip_packet\n");
	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = calc_ip_checksum(ip_hdr);
	struct sr_if* send_interface;
	struct sr_rt* rtable = sr->routing_table;
	char* send_on_route = NULL;
	struct sr_icmphdr* icmphdr = (struct sr_icmphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	
	//if(icmphdr->type != 0){
	
	while(rtable){
		//printf("\nmask addr: %s\n",inet_ntoa(*(struct in_addr*)&rtable->mask.s_addr));
		if((rtable->dest.s_addr == (ip_hdr->ip_dst.s_addr & rtable->mask.s_addr)) & rtable->mask.s_addr != 0){
		//	printf("Find an interface");
			send_on_route = rtable->interface;
			break;
		}
		else if((rtable->dest.s_addr == 0) && (rtable->mask.s_addr == 0)){
			send_on_route = rtable->interface;
			//dest_ip = rtable->gw.s_addr;
		}
		rtable = rtable->next; 
	}

	rtable = sr->routing_table;
	while(rtable){
		if(strcmp(rtable->interface, send_on_route) == 0){
			if(rtable->dest.s_addr == 0 && rtable->mask.s_addr == 0){
				dest_ip = rtable->gw.s_addr;
				is_for_gw = 1;
			}
		}
		rtable = rtable->next;
	}
	printf("Destn Adres: %s\n", inet_ntoa(*(struct in_addr*)&dest_ip));
	//struct in_addr ip_addr;
	/*if(send_on_route != NULL){
		if(send_on_route->mask.s_addr = 0 && send_on_route->dest.s_addr == 0)
			dest_ip = send_on_route->gw.s_addr;
		send_interface = sr_get_interface(sr, send_on_route->interface);
		//ip_addr = send_on_route->gw;
	}*/

	if(send_on_route != NULL){
		printf("\nSend Interface: %s\n", send_on_route);
		struct arp_cache* cache = head;
		struct arp_cache* cache_found = NULL;
		struct timeval tv;
		double now;
		gettimeofday(&tv, NULL);
		now = tv.tv_sec + (tv.tv_usec / 1000000.0);
		if(is_thread_alive == 0){
			while(cache){
			//printf("\nNow: %lf", now);
			//printf("\nTime stamp: %lf", cache->time_stamp);
				if(cache->ip == dest_ip && is_for_gw != 1){
				printf("\nTime elapsed in cache : %lf", (now - cache->time_stamp));
				//now = (double)(now - cache->time_stamp);
					if((now - cache->time_stamp) >= 15.0){
						delete_arp_cache(dest_ip);
						printf("\nEntry deleted from cache");
						break;
					}
				}
				cache = cache->next;
			}
		}
		cache = head;
		while(cache){
			printf("\nIP Address to be checked in cache: %s", inet_ntoa(*(struct in_addr*)&(dest_ip)));
			if(cache->ip == dest_ip)
			{
				cache_found = cache;
				printf("\nCache entry found!!\n");
				break;
			}
			cache = cache->next;
		}
	
		if(cache_found == NULL){
			printf("\nARP cache entry not found!!\n");
			if(send_on_route != NULL){
				cache_this_packet(dest_ip, packet, len, sr, send_on_route, is_for_gw);
			
				//if(is_for_gw != 1){
				//spawning thread from here since it was a arp cache miss
					uint32_t* p;
					pthread_t thread;
				
					thread = (pthread_t *)malloc(sizeof(pthread_t));
					p = (uint32_t *)malloc(sizeof(uint32_t));
					*p = dest_ip;
					
					pthread_create(&thread, NULL, worker, (void *)(p));
					//pthread_join(thread, NULL); 
				/*}
				else{
					send_arp_request(sr, packet, len, send_on_route);	
				}*/
			}
		}
		else{
			printf("\nARP cache entry found\n");
			printf("\nInterface to forward on: %s", send_on_route);
			struct sr_if* if_list = sr->if_list;
			struct sr_icmphdr* icmphdr_send = (struct sr_icmphdr*)malloc(sizeof(struct sr_icmphdr));
 			
			while(if_list){
				if(strcmp(if_list->name,send_on_route)== 0){
					//ip_hdr->ip_src.s_addr = if_list->ip;
					for(int i = 0; i < 6; i++){
						e_hdr->ether_shost[i] = (uint8_t)(if_list->addr[i]);
					}
				}
				if_list = if_list->next;
			
			}
			//ip_hdr->ip_src.s_addr = ip_hdr->ip_dst.s_addr;
			//ip_hdr->ip_dst.s_addr = dest_ip;
			for(int i = 0; i < 6; i++){
				e_hdr->ether_dhost[i] = (uint8_t)(cache_found->mac[i]);
			}
			printf("\nEthernet destination address:");
			for(int i = 0; i < 6; i++){
				printf("%x ", e_hdr->ether_dhost[i]);
			}
			printf("\nEthernet source address:");
			for(int i = 0; i < 6; i++){
				printf("%x ", e_hdr->ether_shost[i]);
			}
			//printPacket(packet);
			printf("\nForwarding IP packet\n");
			//icmphdr_send->
			sr_send_packet(sr, packet, len, send_on_route);
		}		
	}
}

/*-------------------------------------------------------------------------* Method: calc_ip_checksum()
*-----------------------------------------------------------------------*/
uint16_t calc_ip_checksum(struct ip* ip_hdr){
	uint32_t sum = 0;
	//printf("\nlength of packet: %d\n", len);
	uint16_t* word = (uint16_t *)ip_hdr;
	printf("Inside calc_ip_checksum\n");
	int i;
	for(i = 0; i < ip_hdr->ip_hl * 2; i++){
		sum = sum + word[i];
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum = sum + (sum >> 16);
	sum = ~sum;

	printf("\nip checksum: %d",sum);
	return (uint16_t)(sum);
}




/*------------------------------------------------------------------------
* Method: get_braodcast_interface
*------------------------------------------------------------------------*/
char* get_broadcast_interface(struct sr_rt* rtable, uint32_t dest_ip){
	while(rtable){
		struct in_addr mask;
		inet_aton("255.255.255.248", &mask);
		if((dest_ip|~mask.s_addr) == (rtable->dest.s_addr|~mask.s_addr)){
			printf("\nInterface to broadcast: %s\n", rtable->interface);
			return rtable->interface; 
}
		rtable = rtable->next;
	}
	return 0;
} 

/*------------------------------------------------------------------------
 * Method: send_arp_packet
 *-----------------------------------------------------------------------*/
void send_arp_request(struct sr_instance* sr, uint8_t* packet, unsigned int len, char * interface){
	//struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
	//struct sr_arphdr* a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
	struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	uint32_t dest_ip = ip_hdr->ip_dst.s_addr;

	struct sr_if* iface;
	uint8_t* packet1 = (uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
	struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet1;
	struct sr_arphdr* a_hdr = (struct sr_arphdr*)(packet1 + sizeof(struct sr_ethernet_hdr));
	struct sr_icmphdr* icmphdr = (struct sr_icmphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	int i;
	
	printf("Creating an arp req");
	e_hdr->ether_type = ntohs(ETHERTYPE_ARP);
	for(i = 0; i < 6; i++){
		e_hdr->ether_dhost[i] = 255;
	}
	a_hdr->ar_hrd = ntohs(1);
	a_hdr->ar_op = ntohs(ARP_REQUEST);
	a_hdr->ar_pro = ntohs(ETHERTYPE_IP);
	a_hdr->ar_hln = 6;
	a_hdr->ar_pln = 4;
	
	
	a_hdr->ar_tip = dest_ip;

	struct sr_if* if_list = sr->if_list;
	while(if_list){
		if(strcmp(if_list->name, interface) == 0){
			if(icmphdr->type == 0){
			struct sr_rt* rtable = sr->routing_table;
			while(rtable){
				if(rtable->dest.s_addr == 0 && rtable->mask.s_addr == 0){
					a_hdr->ar_tip = rtable->gw.s_addr;		
					break;
				}
				rtable = rtable->next;
			}
			//a_hdr->ar_tip = rtable->gw.s_addr;
			}
			for(i = 0; i < 6; i++){
				a_hdr->ar_sha[i] = if_list->addr[i];
				e_hdr->ether_shost[i] = a_hdr->ar_sha[i];
				a_hdr->ar_tha[i] = 255;
			}
			a_hdr->ar_sip = if_list->ip;
			printf("\nIP Source: %s\n", inet_ntoa(*(struct in_addr*)&a_hdr->ar_sip));
			printf("\nIP Target: %s\n", inet_ntoa(*(struct in_addr*)&a_hdr->ar_tip));
			printf("\narp  Source: ");
			for(i = 0; i < 6; i++){
				printf("%x ", a_hdr->ar_sha[i]);
			}
			printf("\narp Dest: ");
			for(i = 0; i < 6; i++){
				printf("%x ", a_hdr->ar_tha[i]);
			}
			printf("\nethernet source host: ");
			for(i = 0; i < 6; i++){
				printf("%x ", e_hdr->ether_shost[i]);
			}
			printf("\nEthernet dest host: ");
			for(i = 0; i < 6; i++){
				printf("%x ", e_hdr->ether_dhost[i]);
			}
			printf("\nInterface for arp request: %s\n", if_list->name);
			sr_send_packet(sr, packet1, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), if_list->name);
		}
		if_list = if_list->next;
	}
}

/*--------------------------------------------------------------------- 
 * Method: arp_pkt_handle(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
   Scope: Global
 *
 *---------------------------------------------------------------------*/
void arp_pkt_handle(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface){
	
	struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
	struct sr_arphdr* a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
	struct timeval tv;
	double now;

	if(a_hdr->ar_op == ntohs(ARP_REQUEST)){
		printf("Received ARP Request\n");
		
		struct sr_if* iface = sr_get_interface(sr, interface);
		struct sr_arphdr* a_reply = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
		memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, sizeof(e_hdr->ether_dhost));
		int i;
		for(i = 0; i < 6; i++){
			e_hdr->ether_shost[i] = ((uint8_t)iface->addr[i]);
		}
		a_reply->ar_hrd = htons(ARPHDR_ETHER);
		a_reply->ar_pro = htons(ETHERTYPE_IP);
		a_reply->ar_hln = 6;
		a_reply->ar_pln = 4;
		a_reply->ar_op = htons(ARP_REPLY);
		memcpy(a_reply->ar_sha, e_hdr->ether_shost, sizeof(e_hdr->ether_dhost));
		memcpy(a_reply->ar_tha, e_hdr->ether_dhost, sizeof(e_hdr->ether_shost));
		uint32_t temp = a_reply->ar_tip;
		a_reply->ar_tip = a_reply->ar_sip;
		a_reply->ar_sip= temp;
		
		struct arp_cache* new_entry = (struct arp_cache*)malloc(sizeof(struct arp_cache));
		new_entry->ip = a_reply->ar_tip;
		for(int i = 0; i < ETHER_ADDR_LEN; i++){
			new_entry->mac[i] = a_reply->ar_tha[i];
		}
		gettimeofday(&tv, NULL);
		now = tv.tv_sec + (tv.tv_usec/1000000.0);
		new_entry->time_stamp = now;
		new_entry->next = NULL;
		add_arp_cache(new_entry);
		//printf("Gateway cached");
		print_cache();
		//memcpy(packet + sizeof(struct sr_ethernet_hdr*), a_reply, sizeof(struct sr_arphdr*));
		printf("sending reply");
		sr_send_packet(sr, packet, len, interface);
	}
	else if(a_hdr->ar_op == ntohs(ARP_REPLY))
	{
		struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
		uint32_t dest_ip = ip_hdr->ip_dst.s_addr;
		
		printf("Received ARP Reply\n");
		is_thread_alive = 0;
		struct sr_arphdr* a_reply = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
		
		struct arp_cache* new_entry = (struct arp_cache*)malloc(sizeof(struct arp_cache));
		new_entry->ip = a_reply->ar_sip;
		printf("\nDestination IP from arp reply: %s", inet_ntoa(*(struct in_addr*)&(a_reply->ar_sip)));
		printf("\nMac entry into arpcache:");
		for(int i = 0; i < ETHER_ADDR_LEN; i++){
			printf("%x ", a_reply->ar_sha[i]);
			new_entry->mac[i] = a_reply->ar_sha[i];
		}
		gettimeofday(&tv, NULL);
		now = tv.tv_sec + (tv.tv_usec/1000000.0);
		new_entry->time_stamp = now;
		new_entry->next = NULL;
		if(is_thread_alive == 0){
			add_arp_cache(new_entry);
			printf("Entry added into cache");
			printf("\nARP Cache: \n");
			print_cache();
			printf("dfjfgergtrhrytyhtyhty");
			struct packet_count* update_pkt = pkt_count;
			while(update_pkt){
				if(update_pkt->ip == new_entry->ip){
					update_pkt->is_arp_reply = 1;
				}
				update_pkt = update_pkt->next;
			}
		
			//is_thread_alive = 0;
			printf("Dequeuing packets for : ");
			dequeue_packet(new_entry->ip);
		}
		//sr_send_packet(sr, packet, len, interface);
	}
}

void print_cache(){	
	printf("\nPrinting cache");
	struct arp_cache* temp = head;
	while(temp){
		printf("\nIP Addr: %s\t", inet_ntoa(*(struct in_addr*)&temp->ip));
		printf("Mac Addr: \t");
		for(int i = 0; i < 6; i++)	
			printf("%x ", temp->mac[i]);
		temp = temp->next;
	}	
}

void add_arp_cache(struct arp_cache* new_entry){
	struct arp_cache* temp = head;
	struct arp_cache* prev = NULL;
	int already_Exists = 0;
	
	if(temp == NULL){
		temp = (struct arp_cache*)malloc(sizeof(struct arp_cache));
		temp = new_entry;
		temp->next = NULL;
		head = temp;
		printf("\nFirst cache entry created\n");
	}
	else{
		
		while(temp != NULL){
			printf("Temp is not null");
			if(temp->ip == new_entry->ip)
				already_Exists = 1;
			prev = temp;
			temp = temp->next;
		}
		printf("\nEnd of cache\n");
		//temp = (struct arp_cache*)malloc(sizeof(struct arp_cache));
		//temp = new_entry;
		if(already_Exists != 1){
			prev->next = new_entry;
			printf("\nNew cache entry created\n");
		}
	}
	print_cache();
}

void delete_arp_cache(uint32_t delete_ip){
	struct arp_cache* prev = NULL;
	struct arp_cache* temp = head;
	struct arp_cache* del_pkt;
	prev = NULL;
	//temp = (struct arp_cache*)malloc(sizeof(struct arp_cache));
	temp = head;
	while(temp != NULL){
		if(temp->ip == delete_ip){
			if(prev == NULL){
				del_pkt = temp;
				temp = temp->next;
				head = temp;
			}
			else{
				del_pkt = temp;
				prev->next = temp->next;
				temp = temp->next;
			}
			free(del_pkt);
		}
		else{
			prev = temp;
			temp = temp->next;
		}
	}
}

/*void refresh_cache(){
	
}*/
