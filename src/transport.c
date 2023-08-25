#include "../include/transport.h"
#include "../include/sctp.h"

int udp(const unsigned char * packet, int * portSrc, int * portDest, int verbosite)
{
	struct udphdr * my_udp;

    my_udp      = (struct udphdr*) packet;
	*portSrc    = ntohs(my_udp->source);
	*portDest   = ntohs(my_udp->dest);

    fprintf(stdout, "\t\t[ UDP ] :\n");

	switch(verbosite)
    {
		case 1 :
        case 2 :
			fprintf(stdout, "\t\t├─ Src : %d\n", *portSrc);
            fprintf(stdout, "\t\t└─ Dst : %d\n", *portDest);
			break;
		case 3 :
			fprintf(stdout, "\t\t├─ Port source        : %d\n", *portSrc);
			fprintf(stdout, "\t\t├─ Port destination   : %d\n", *portDest);
			fprintf(stdout, "\t\t├─ Length             : %d\n", ntohs(my_udp->len));
			fprintf(stdout, "\t\t└─ Checksum           : %d\n", ntohs(my_udp->check));
			break;
		default:
            panic("transport", "udp");
			break;
	}
    /* return size */
	return 8;
}

int tcp(const unsigned char * packet, int * portSrc, int * portDest, int size_payload, int verbosite)
{
	struct tcphdr * my_tcp;
    int size_tcp;

    my_tcp      = (struct tcphdr*)( packet );
	size_tcp    = my_tcp->th_off*4;
	*portSrc    = ntohs(my_tcp->th_sport);
	*portDest   = ntohs(my_tcp->th_dport);

	fprintf(stdout, "\t\t[ TCP ] :\n");
	
	switch(verbosite)
    {
		case 1 : /* verbosite faible */
			fprintf(stdout, "\t\t├─ Src : %d\n", *portSrc);
            fprintf(stdout, "\t\t├─ Dst : %d\n", *portDest);
			if(size_payload - size_tcp == 0)
            {
				fprintf(stdout, "\t\t├─ Seq    : %d\n", ntohs(my_tcp->th_seq));
				fprintf(stdout, "\t\t├─ Ack    : %d\n", ntohs(my_tcp->th_ack));
				fprintf(stdout, "\t\t└─ Window : %d\n", ntohs(my_tcp->th_win));
			}
			break;
		case 2 : /* verbosite moyenne */
			fprintf(stdout, "\t\t├─ Src      : %d\n", *portSrc);
            fprintf(stdout, "\t\t├─ Dst      : %d\n", *portDest);
			if(size_payload - size_tcp == 0)
            {
				fprintf(stdout, "\t\t├─ Seq      : %d\n", ntohs(my_tcp->th_seq));
				fprintf(stdout, "\t\t├─ Ack      : %d\n", ntohs(my_tcp->th_ack));
				fprintf(stdout, "\t\t├─ Window   : %d\n", ntohs(my_tcp->th_win));
			}
            fprintf(stdout, "\t\t└─ Flag TCP : ");
			flag_tcp(my_tcp);
			break;
		case 3 : /* verbosite forte */
			fprintf(stdout, "\t\t├─ Source Port        	   : %d\n", *portSrc);
			fprintf(stdout, "\t\t├─ Destination Port   	   	: %d\n", *portDest);
			fprintf(stdout, "\t\t├─ Sequence number         : %d\n", ntohs(my_tcp->th_seq));
			fprintf(stdout, "\t\t├─ Acknowledgement Number  : %d\n", ntohs(my_tcp->th_ack));
			fprintf(stdout, "\t\t├─ Data offset        	   : %d octets\n", size_tcp);
            fprintf(stdout, "\t\t├─ Flag TCP           	   : ");
			flag_tcp(my_tcp);
			fprintf(stdout, "\t\t├─ Window size value       : %d\n", ntohs(my_tcp->th_win));
			fprintf(stdout, "\t\t├─ Checksum                : %d\n", ntohs(my_tcp->th_sum));
			if(size_tcp > 20)
            {
				option_tcp(packet + 20, size_tcp - 20);
			}
			break;
		default:
            panic("transport", "tcp");
			break;
	}
	return size_tcp;
}

void flag_tcp(struct tcphdr* my_tcp)
{
	if (my_tcp->th_flags & 0x01) /* TH_FIN */
    {
		fprintf(stdout, "FIN ");
	}
	if (my_tcp->th_flags & 0x02) /* TH_SYN */
    {
		fprintf(stdout, "SYN ");
	}
	if (my_tcp->th_flags & 0x10) /* TH_ACK */
    {
		fprintf(stdout, "ACK ");
	}
	if (my_tcp->th_flags & 0x08) /* TH_PSH */
    {
		fprintf(stdout, "PSH ");
	}
	if (my_tcp->th_flags & 0x04) /* TH_RST */
    {
		fprintf(stdout, "RST ");
	}
	if (my_tcp->th_flags & 0x20) /* TH_URG */
    {
		fprintf(stdout, "URG ");
	}
    fprintf(stdout, "\n");
}

void option_tcp(const unsigned char * packet, int size)
{
	unsigned char * option = (unsigned char *)packet;
	int i, len, end = 0;
	if (size < 0)
		panic("transport", "option_tcp");

	fprintf(stdout, "\t\t└─ Option                  : %d\n\t\t   └─", size);

	option = (unsigned char *)packet;
	for(i = 0 ; i < size ; i++)
    {
		switch(*option)
        {
			case TCPOPT_EOL : 
				fprintf(stdout, "End of option list\n"); 
				break;
            case TCPOPT_NOP: 
				fprintf(stdout, " No operation (NOP)");
				end = 1;
				break;
            case TCPOPT_MAXSEG: 
				fprintf(stdout, " Maximum segment size"); 
				break;
            case TCPOPT_WINDOW: 
				fprintf(stdout, " Window Scale"); 
				break;
            case TCPOPT_SACK_PERMITTED: 
				fprintf(stdout, " SACK Permitted"); 
				break;
            case TCPOPT_TIMESTAMP: 
				fprintf(stdout, " Timestamps"); 
				break;
            case TCPOLEN_TIMESTAMP: 
				fprintf(stdout, " Timestamps"); 
				break;
			case TCPOLEN_TSTAMP_APPA: 
				fprintf(stdout, "   IP "); 
				break;
			default:
				fprintf(stdout, "(Unknow) " );
				break;
		}
		if ( end == 0)
		{
			option++;
			len = (u_int8_t)*option;
			len = len - 2;
			option++;
			i++;
			for ( int j = 0; j < len; j++)
			{
					i++;
					option++;
			}
			option--;
		}
		end = 0;
		option++;
	}
	fprintf(stdout, "\n");
}

int sctp(const unsigned char * packet, int * portSrc, int * portDest, int size_payload, int verbosite)
{
	struct sctphdr * my_sctp;
	struct sctp_chunkhdr * my_sctp_chunkhdr;
    int size_sctp;

    my_sctp     = (struct sctphdr*)( packet );
	size_sctp	= size_payload;
	*portSrc    = ntohs(my_sctp->src_port);
	*portDest   = ntohs(my_sctp->dest_port);

	fprintf(stdout, "\t\t[ SCTP ] :\n");
	switch(verbosite)
    {
		case 1 : /* verbosite faible */
			fprintf(stdout, "\t\t├─ Src : %d\n", *portSrc);
            fprintf(stdout, "\t\t└─ Dst : %d\n", *portDest);
			break;
		case 2 : /* verbosite moyenne */
			fprintf(stdout, "\t\t├─ Src      			: %d\n", *portSrc);
            fprintf(stdout, "\t\t├─ Dst      			: %d\n", *portDest);
			fprintf(stdout, "\t\t├─ Verification Tag		: %u\n", ntohl(my_sctp->v_tag));
			fprintf(stdout, "\t\t└─ Checksum 			: %u\n", ntohl(my_sctp->checksum));
			break;
		case 3 : /* verbosite forte */
			fprintf(stdout, "\t\t├─ Port Source			: %d\n", *portSrc);
            fprintf(stdout, "\t\t├─ Port Destination		: %d\n", *portDest);
			fprintf(stdout, "\t\t├─ Verification Tag		: %u\n", ntohl(my_sctp->v_tag));
			fprintf(stdout, "\t\t├─ Checksum 			: %u\n", ntohl(my_sctp->checksum));
			size_sctp += SIZE_EN_TETE_SCTP;
			my_sctp_chunkhdr = (struct sctp_chunkhdr *) (my_sctp + size_sctp);
			/* pas fini - boucle nécessaire + affichage data chunk */
			fprintf(stdout, "\t\t├─ Type Chunk			: %d\n", ntohs(my_sctp_chunkhdr->chunk_type));
			fprintf(stdout, "\t\t├─ Flag Chunk 			: %u\n", ntohs(my_sctp_chunkhdr->chunk_flags));
			fprintf(stdout, "\t\t└─ Longueur Chunk		: %u\n", ntohs(my_sctp_chunkhdr->chunk_length));
			break;
		default:
            panic("transport", "sctp");
			break;
	}
	return 0;
}
int icmp(const unsigned char * packet, int verbosite)
{
	struct icmphdr * my_icmp;
	my_icmp     = (struct icmphdr*)( packet );
	
	fprintf(stdout, "\t\t[ ICMP ] :\n");
	switch(verbosite)
    {
		case 1 : /* verbosite faible */
		case 2 : /* verbosite moyenne */
		case 3 : /* verbosite forte */
			fprintf(stdout, "\t\t├─ Type : %d\n", ntohs(my_icmp->type));
            fprintf(stdout, "\t\t├─ Code : %d\n", ntohs(my_icmp->code));
			fprintf(stdout, "\t\t└─ Checksum : %d\n", ntohs(my_icmp->checksum));
			break;
		default:
            panic("transport", "icmp");
			break;
	}
	return 0;
}