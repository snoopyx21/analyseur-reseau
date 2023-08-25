#ifndef APPLICATION_H
#define APPLICATION_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <ctype.h>
#include <locale.h>
#include "bootp.h"
#include "tcpdump.h"


/************************** TELNET ***************************/
#define IAC         255/* interpret as command - TELNET */
#define DONT        254
#define DO          253
#define WONT        252
#define WILL        251
#define SB          250
#define GA          249
#define DONT        254
#define EL          248
#define EC          247
#define AYT         246
#define AO          245
#define IP          244
#define DM          242
#define NOP         241
#define SE          240

#define ECHO            1
#define SUPPR_GO_AHEAD  3
#define TERMINAL_TYPE   24
#define WINDOW_SIZE     31
#define TERM_SPEED      32
#define LINE_MODE       34
#define ENV_VAR         36
#define NEW_ENV_VAR     39
/************************** TELNET ***************************/

/************************** DHCP / BOOTP ***************************/
#define MAGIC_COOKIE_BIT_1 0x63
#define MAGIC_COOKIE_BIT_2 0x82
#define MAGIC_COOKIE_BIT_3 0x53
#define MAGIC_COOKIE_BIT_4 0x63
#define VENDOR_SIZE_BOOTP  64
#define VENDOR_SIZE_DHCP   60
/************************** DHCP / BOOTP ***************************/

int printable(char c);
void smtp(const unsigned char * packet, int size, int verbosite);
void pop(const unsigned char * packet, int size, int verbosite);
void http(const unsigned char * packet, int size, int verbosite);
void https(const unsigned char * packet, int size, int verbosite);
void imap(const unsigned char * packet, int size, int verbosite);
void ftp(const unsigned char * packet, int size, int port_source, int verbosite);
void telnet(const unsigned char * packet, int size, int verbosite);
void option_negocies_telnet(const unsigned char* tmp);
void dns(const unsigned char * packet, int size, int verbosite);
void udp_protocol(const unsigned char * packet, int size, int verbosite);
void action_vendor(unsigned char * packet, int size);


#endif