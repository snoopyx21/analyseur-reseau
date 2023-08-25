#ifndef DATA_LINK_H
#define DATA_LINK_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include "tcpdump.h"

int ethernet(const unsigned char * packet, unsigned short * protocol, int verbosite);

#endif
