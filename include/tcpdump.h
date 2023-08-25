#ifndef TCPDUMP_H
#define TCPDUMP_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include "bootp.h"
#include "data_link.h"
#include "application.h"
#include "network.h"
#include "arp.h"
#include "dns.h"
#include "data_link.h" 
#include "transport.h"


#define MAX_LEN_PACKET      1500
#define MAX_STRING_SIZE     1024

/******************** PORT *************/
#define HTTP_PORT           80
#define DHCP_CLIENT_PORT    68
#define DHCP_SERVER_PORT    67
#define HTTPS_PORT          443
#define SMTP_PORT           25
#define IMAP_PORT           143
#define POP_PORT            110
#define TELNET_PORT         23
#define DNS_PORT            53
#define FTP_CONTROL_PORT    21
#define FTP_DATA_PORT       20
/******************** PORT *************/

#define UNUSED(x) (void)(x)

extern char *optarg;

void panic(char * file, char * function);
void got_packet(unsigned char * args, const struct pcap_pkthdr * header, const unsigned char * packet);

#endif