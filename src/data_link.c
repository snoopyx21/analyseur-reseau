#include "../include/data_link.h"

int ethernet(const unsigned char * packet, unsigned short * protocol, int verbosite)
{
    struct ether_header   *header;
	struct ether_addr     *mac_src;
	struct ether_addr     *mac_dest;
	header      = (struct ether_header*)( packet );
	mac_dest    = (struct ether_addr*) header->ether_dhost;
	mac_src     = (struct ether_addr*) header->ether_shost;
    *protocol   =  ntohs(header->ether_type);
    //printf("ntohs %06x %06x", protocol,ntohs(header->ether_type));
    UNUSED(packet);

    fprintf(stdout, "\n[ Ethernet ] :\n");

    switch(verbosite)
    {
        case 1 : /* verbosite faible */
            fprintf(stdout, "├─ Src : %s\n", ether_ntoa(mac_src));
		    fprintf(stdout, "└─ Dst : %s\n", ether_ntoa(mac_dest));
            break;
        case 2 : /* verbosite moyenne */
            fprintf(stdout, "├─ Source      : %s\n", ether_ntoa(mac_src)); 
            fprintf(stdout, "├─ Destination : %s\n", ether_ntoa(mac_dest));
            fprintf(stdout, "└─ Type        :");

            if(*protocol == ETHERTYPE_IP)
            {
                fprintf(stdout, "IP");
            }
            else if(*protocol == ETHERTYPE_ARP)
            {
                fprintf(stdout, "ARP");
            }
            else
            {
                fprintf(stdout, "?");
            }
            fprintf(stdout, "\n");
            break;
        case 3 : /* verbosite forte */
            fprintf(stdout, "├─ Source         : %02x:%02x:%02x:%02x:%02x:%02x\n", 
                header->ether_dhost[0],
                header->ether_dhost[1],
                header->ether_dhost[2],
                header->ether_dhost[3],
                header->ether_dhost[4],
                header->ether_dhost[5]);
            fprintf(stdout, "├─ Destination    : %02x:%02x:%02x:%02x:%02x:%02x\n", 
                header->ether_shost[0],
                header->ether_shost[1],
                header->ether_shost[2],
                header->ether_shost[3],
                header->ether_shost[4],
                header->ether_shost[5]);
            fprintf(stdout, "└─ Type           :");

            if(*protocol == ETHERTYPE_IP)
            {
                fprintf(stdout, " IP");
            }
            else if(*protocol == ETHERTYPE_ARP)
            {
                fprintf(stdout, " ARP");
            }
            else
            {
                fprintf(stdout, " ?");
            }
            fprintf(stdout, "\n");
            break;
        default :
            panic("data_link", "ethernet");
            break;
    }
	return sizeof(struct ether_header);
}