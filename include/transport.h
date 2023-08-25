#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include "tcpdump.h"

#define BUFFER_OPTION_TCP 50
# define TCPOPT_EOL		        0
# define TCPOPT_NOP		        1
# define TCPOPT_MAXSEG		    2
# define TCPOPT_WINDOW		    3
# define TCPOPT_SACK_PERMITTED	4
# define TCPOPT_SACK		    5
# define TCPOPT_TIMESTAMP	    8
# define TCPOLEN_TIMESTAMP	    10
# define TCPOLEN_TSTAMP_APPA	(TCPOLEN_TIMESTAMP+2)




int udp(const unsigned char * packet, int * portSrc, int * portDest, int verbosite);
int tcp(const unsigned char * packet, int * portSrc, int * portDest, int size_ip, int verbosite);
void flag_tcp(struct tcphdr* my_tcp);
void option_tcp(const unsigned char * packet, int size);
int sctp(const unsigned char * packet, int * portSrc, int * portDest, int size_payload, int verbosite);
int icmp(const unsigned char * packet, int verbosite);
#endif