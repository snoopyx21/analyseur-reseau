#include "../include/network.h"

/* on renvoit la taille en OCTET */
int ip(const unsigned char * packet, unsigned short * protocol, int verbosite)
{
	int version_ip;
    struct iphdr * my_ip;
    struct in_addr src;
    struct in_addr dst;

    version_ip  = packet[0];
    version_ip  = version_ip >> 4;
    my_ip       = (struct iphdr*)( packet );
    src.s_addr  = my_ip->saddr;
    dst.s_addr  = my_ip->daddr;
    *protocol   = my_ip->protocol;

    fprintf(stdout, "\t[ IP ] :\n");
	
    if(version_ip == 4)
    {
        switch(verbosite)
        {
            case 1 : /* verbosite faible */
                fprintf(stdout, "\t├─ Src : %s\n", inet_ntoa(src));
                fprintf(stdout, "\t└─  Dst : %s\n", inet_ntoa(dst));
                break;
            case 2 : /* verbosite moyenne */
                fprintf(stdout, "\t├─ Source      : %s\n", inet_ntoa(src));
                fprintf(stdout, "\t├─ Destination : %s\n", inet_ntoa(dst));
                fprintf(stdout, "\t└─  Length      : %d\n", ntohs(my_ip->tot_len));
                break;
            case 3 : /* verbosite forte */
                fprintf(stdout, "\t├─ Header length   : %d\n", my_ip->ihl);
                fprintf(stdout, "\t├─ Version         : %d\n", my_ip->version);
                fprintf(stdout, "\t├─ Type of service : %d\n", my_ip->tos);
                fprintf(stdout, "\t├─ Length          : %d\n", ntohs(my_ip->tot_len));
                fprintf(stdout, "\t├─ Source          : %s\n", inet_ntoa(src));
                fprintf(stdout, "\t├─ Destination     : %s\n", inet_ntoa(dst));
                fprintf(stdout, "\t├─ Identification  : %d\n", ntohs(my_ip->id));
                fprintf(stdout, "\t├─ Offset          : %d\n", my_ip->frag_off);
                fprintf(stdout, "\t├─ Time to Live    : %d\n", my_ip->ttl);
                fprintf(stdout, "\t├─ Protocol        : %d\n", *protocol);
                fprintf(stdout, "\t└─ Header checksum : %d\n", my_ip->check);
                break;
            default:
                panic("network", "ip");
                break;
        }
	}
    else if(version_ip == 6)
    {
		fprintf(stdout, "\tVersion         : %d\n", my_ip->version);
	}
    else
    {
		panic("network", "ip");
	}
	return  my_ip->ihl*4;
}

void arp(const unsigned char * packet, int verbosite)
{
    /* structure dans .h - impossibilité d'utiliser la structure dans le header */
	struct my_arp_header * my_arp;
	
    fprintf(stdout, "\t[ ARP ] :\n");

    my_arp = (struct my_arp_header*)( packet );
	
    switch(verbosite)
    {
        case 1 :
        case 2 :
            fprintf(stdout,"\t├─ Hardware type           : ");
            if(ntohs(my_arp->ar_hdr) == ARPHRD_ETHER )
            {
                fprintf(stdout, "Ethernet (%d)\n", ntohs(my_arp->ar_hdr));
            }
            else
            {
                fprintf(stdout, "Unknown (%d)\n", ntohs(my_arp->ar_hdr));
            }
            /* requete ARP */
        	if(ntohs(my_arp->ar_op) == ARPOP_REQUEST)
            {
			    fprintf(stdout, "\t└─ Request : Who has  %d.%d.%d.%d ? Tell  %d.%d.%d.%d ...\n", 
                    my_arp->ar_tip[0],
                    my_arp->ar_tip[1],
                    my_arp->ar_tip[2],
                    my_arp->ar_tip[3],
                    my_arp->ar_sip[0],
                    my_arp->ar_sip[1],
                    my_arp->ar_sip[2],
                    my_arp->ar_sip[3]);
		    }
            /* reponse ARP */
            else if(ntohs(my_arp->ar_op) == ARPOP_REPLY)
            {
			    fprintf(stdout, "\t└─ Answer : %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x.\n", 
                    my_arp->ar_sip[0],
                    my_arp->ar_sip[1],
                    my_arp->ar_sip[2],
                    my_arp->ar_sip[3], 
                    my_arp->ar_sha[0],
                    my_arp->ar_sha[1],
                    my_arp->ar_sha[2],
                    my_arp->ar_sha[3],
                    my_arp->ar_sha[4],
                    my_arp->ar_sha[5] );
            }
            else 
            {
                fprintf(stdout, "\t└─ Unknown Operation       : (%d)\n", my_arp->ar_op);
            }
            break;
        case 3 :
        	fprintf(stdout,"\t├─ Hardware type           : ");
            if(ntohs(my_arp->ar_hdr) == ARPHRD_ETHER )
            {
                fprintf(stdout, "Ethernet (%d)\n", ntohs(my_arp->ar_hdr));
            }else
            {
                fprintf(stdout, "Unknown (%d)\n", ntohs(my_arp->ar_hdr));
            }
            fprintf(stdout,"\t├─ Protocol type           : ");
            if(ntohs(my_arp->ar_pro) == ETH_P_IP)
            {
                fprintf(stdout, "IP (%d)\n", ntohs(my_arp->ar_pro));
            }else
            {
                fprintf(stdout, "? (%d)\n", ntohs(my_arp->ar_pro));
            }
            fprintf(stdout,"\t├─ Hardware Address Length : %d\n",my_arp->ar_hln);
            fprintf(stdout,"\t├─ Protocol Address Length : %d\n",my_arp->ar_pln);
            switch(ntohs(my_arp->ar_op)) 
            {
                case ARPOP_REQUEST:
                        fprintf(stdout, "\t├─ Operation               : ARP request (%d)\n",
                            ntohs(my_arp->ar_op));
                        break;
                case ARPOP_REPLY:
                        fprintf(stdout, "\t├─ Operation               : ARP reply (%d)\n",
                            ntohs(my_arp->ar_op));
                        break;
                case ARPOP_RREQUEST:
                        fprintf(stdout, "\t├─ Operation               : RARP request (%d)\n",
                            ntohs(my_arp->ar_op));
                        break;
                case ARPOP_RREPLY:
                        fprintf(stdout, "\t├─ Operation               : RARP reply (%d)\n",
                            ntohs(my_arp->ar_op));
                        break;
                case ARPOP_InREQUEST:
                        fprintf(stdout, "\t├─ Operation               : InARP request (%d)\n",
                            ntohs(my_arp->ar_op));
                        break;
                case ARPOP_InREPLY:
                        fprintf(stdout, "\t├─ Operation               : InARP reply (%d)\n",
                            ntohs(my_arp->ar_op));
                        break;
                case ARPOP_NAK:
                        fprintf(stdout, "\t├─ Operation               : ARP NAK (%d)\n",
                            ntohs(my_arp->ar_op));
                        break;
                default:
                        fprintf(stdout, "\t├─ Operation               : Unknown \n");
                        break;
            }
            fprintf(stdout,"\t├─ Source Mac              : %02x:%02x:%02x:%02x:%02x:%02x\n",
                my_arp->ar_sha[0],
                my_arp->ar_sha[1],
                my_arp->ar_sha[2],
                my_arp->ar_sha[3],
                my_arp->ar_sha[4],
                my_arp->ar_sha[5]);
            fprintf(stdout,"\t├─ Source IP               : %d.%d.%d.%d\n",
                my_arp->ar_sip[0],
                my_arp->ar_sip[1],
                my_arp->ar_sip[2],
                my_arp->ar_sip[3]);
            fprintf(stdout,"\t├─ Target Mac              : %02x:%02x:%02x:%02x:%02x:%02x\n",
                my_arp->ar_tha[0],
                my_arp->ar_tha[1],
                my_arp->ar_tha[2],
                my_arp->ar_tha[3],
                my_arp->ar_tha[4],
                my_arp->ar_tha[5]);
            fprintf(stdout,"\t└─ Target IP               : %d.%d.%d.%d\n",
                my_arp->ar_tip[0],
                my_arp->ar_tip[1],
                my_arp->ar_tip[2],
                my_arp->ar_tip[3]);
            break;
        default :
            panic("network", "arp");
            break;
	}
}




