#ifndef ARP_H
#define ARP_H

#include "tcpdump.h"
#define ARP_ETHERNET 1
#define ARP_IP 2048

struct my_arp_header
{
	unsigned char ar_sha[6];  /* Sender Mac address */
    unsigned char ar_sip[4];  /* Sender IP address       */
    unsigned char ar_tha[6];  /* Target Mac address */
	unsigned char ar_tip[4];  /* Target IP address       */
    //struct ether_addr   ar_sha; /* Sender Mac address       */
	//struct in_addr      ar_sip; /* Sender IP                */
	//struct ether_addr   ar_tha; /* Targer Mac address       */
	//struct in_addr      ar_tip; /* Target IP                */
	unsigned short int  ar_hdr; /* Hardware Type            */
	unsigned short int  ar_pro; /* Protocol Type            */
	unsigned char       ar_hln; /* Hardware Length Address  */
	unsigned char       ar_pln; /* Protocol Length Address  */
	unsigned short int  ar_op;  /* Operation Code           */

};

#endif