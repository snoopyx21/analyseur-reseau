#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include "tcpdump.h"
#include "arp.h"

int ip(const unsigned char * packet,  unsigned short * protocol, int verbosite);
void arp(const unsigned char * packet, int verbosite);

#endif