#include "../include/application.h"
#include "../include/dns.h"

int printable(char c)
{
    setlocale(LC_ALL, "C");
    if ( iscntrl(c) )
    {
        if(c == '\n')
        {
            /* nouvelle ligne */
            fprintf(stdout, "\n\t\t\t└─ ");
        }
        if(c == '\t')
        {
            fprintf(stdout, "\t");
        }
        if(c == '\r')
        {
            /* nouvelle ligne */
            fprintf(stdout, "\r\t\t\t└─ ");
        }
    }
    /* on verifie si le caractère peut être printée */
	else if( isprint(c) )
    {
		fprintf(stdout, "%c", c);
	}
    else
    {
        fprintf(stdout, ".");
		//fprintf(stdout, "%02x", c);
	}
	return c;
}

void smtp(const unsigned char * packet, int size, int verbosite)
{
	int i;

    if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ SMTP ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
	if(size < 0)
        panic("application", "smtp");

	fprintf(stdout, "\t\t\t[ SMTP ] :\n\t\t\t└─ ");

	switch(verbosite)
    {
        case 1 :
        case 2 :
        	for (i = 0; i < size && packet[i] != '\n'; i++)
            {
			    printable(packet[i]);
		    }
            break;
        case 3 :
            for (i = 0; i < size; i++)
            {
                printable(packet[i]);
            }
            break;		
	}
    fprintf(stdout, "\n");
}

void pop(const unsigned char * packet, int size, int verbosite)
{
	int i;

    if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ POP ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
	if(size < 0)
        panic("application", "pop");

	fprintf(stdout, "\t\t\t[ POP ] :\n\t\t\t└─ ");

	switch(verbosite)
    {
        case 1 :
        case 2 :
        	for (i = 0; i < size && packet[i] != '\n'; i++)
            {
			    printable(packet[i]);
		    }
            break;
        case 3 :
            for (i = 0; i < size; i++)
            {
                printable(packet[i]);
            }
            break;		
	}
    fprintf(stdout, "\n");
}
void http(const unsigned char * packet, int size, int verbosite)
{
	int i;

    if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ HTTP ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
	if(size < 0)
        panic("application", "http");

	fprintf(stdout, "\t\t\t[ HTTP ] :\n\t\t\t└─ ");

	switch(verbosite)
    {
        case 1 :
        case 2 :
        	for (i = 0; i < size && packet[i] != '\n'; i++)
            {
			    printable(packet[i]);
		    }
            break;
        case 3 :
            for (i = 0; i < size; i++)
            {
                printable(packet[i]);
            }
            break;		
	}
    fprintf(stdout, "\n");
}

void https(const unsigned char * packet, int size, int verbosite)
{
	int i;
    //fprintf(stdout, "%d",size);
	if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ HTTPS ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
    if(size < 0)
    {
        panic("application", "https");
    }
	fprintf(stdout, "\t\t\t[ HTTPS ] :\n\t\t\t└─ ");

	switch(verbosite)
    {
        case 1 :
        case 2 :
        	for (i = 0; i < size && packet[i] != '\n'; i++)
            {
			    printable(packet[i]);
		    }
            break;
        case 3 :
            for (i = 0; i < size; i++)
            {
                printable(packet[i]);
            }
            break;		
	}
    fprintf(stdout, "\n");
}

void imap(const unsigned char * packet, int size, int verbosite)
{
	int i;

    if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ IMAP ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
	if(size < 0)
        panic("application", "imap");

	fprintf(stdout, "\t\t\t[ IMAP ] :\n\t\t\t└─ ");

	switch(verbosite)
    {
        case 1 :
        case 2 :
			if(packet[0] == '*')
            {
				fprintf(stdout, "\t\t\tResponse : ");
			}
            else
            {
				fprintf(stdout, "\t\t\tRequest : ");
			}
        	for (i = 0; i < size && packet[i] != '\n'; i++)
            {
			    printable(packet[i]);
		    }
            break;
        case 3 :
            for (i = 0; i < size; i++)
            {
                printable(packet[i]);
            }
            break;		
	}
    fprintf(stdout, "\n");
}
void ftp(const unsigned char * packet, int size, int port_source, int verbosite)
{
	int i;

    if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ FTP ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
	if(size < 0)
        panic("application", "ftp");

	fprintf(stdout, "\t\t\t[ FTP ] :\n");

	switch(verbosite)
    {
        case 1 :
        case 2 :
            if(port_source == FTP_CONTROL_PORT)
            {
                fprintf(stdout, "\t\t\t└─ Response : ");
            }
		    else
            { 
                fprintf(stdout, "\t\t\t└─ Request : ");
            }
        	for (i = 0; i < size && packet[i] != '\n'; i++)
            {
			    printable(packet[i]);
		    }
            break;
        case 3 :
            for (i = 0; i < size; i++)
            {
                printable(packet[i]);
            }
            break;		
	}
    fprintf(stdout, "\n");
}

void telnet(const unsigned char * packet, int size, int verbosite)
{
	int i;

    if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ TELNET ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
	if(size < 0)
        panic("application", "telnet");

	fprintf(stdout, "\t\t\t[ TELNET ] :\n\t\t\t└─ ");

	switch(verbosite)
    {
        case 1 :
        case 2 :
            for (i = 0; i < size && packet[i] != '\n'; i++)
            {
                printable(packet[i]);
            }
            break;
        case 3 :
            if(packet[0] == IAC ) /* interpret as command */
            {
                int rc;
                unsigned char* tmp;
                
                tmp = (unsigned char*) ( packet );
                rc = 0;

                while(*tmp == IAC && rc < size)
                {
                    tmp++;
                    rc++;
                    switch(*packet)
                    {
                        case DONT:
                            fprintf(stdout, "\t\t\tDON'T ");
                            tmp++; 
                            rc++;
                            option_negocies_telnet(tmp);
                            break;
                		case DO:
                            fprintf(stdout, "\t\t\tDO ");
                            tmp++; 
                            rc++;
                            option_negocies_telnet(tmp);
                            break;
                        case WONT:
                            fprintf(stdout, "\t\t\tWON'T ");
                            tmp++; 
                            rc++;
                            option_negocies_telnet(tmp);	
                            break;
                        case WILL:
                            fprintf(stdout, "\t\t\tWILL ");
                            tmp++; 
                            rc++;
                            option_negocies_telnet(tmp);
                            break;
                        /* erase character : supprime le caractere */
                        case EC:
                            fprintf(stdout, "\t\t\tErase Character ");
                            break;
                        /* erase line : supprime la ligne */
                        case EL:
                            fprintf(stdout, "\t\t\tErase Line ");
                            break;
                        /* Go Ahead : inverser le contrôle, pour les liaisons half-duplex */
                        case GA:
                            fprintf(stdout, "\t\t\tGo Ahead ");
                            break;
                        /* No Operation */
                        case NOP:
                            fprintf(stdout, "\t\t\tNOP ");
                            break;
                        /*  Abort Output: suspendre, interrompre ou abandonner l’affichage du processus distant */ 
                        case AO:
                            fprintf(stdout, "\t\t\tAbort Output ");
                            break;
                        /* Data Mark: vide l’ensemble des tampons entre le terminal virtuel et l'hôte distant */
                        case DM:
                            fprintf(stdout, "\t\t\tData mark ");
                            break;
                        /* Interrupt Process: suspendre, interrompre ou abandonner le processus distant */
                        case IP:
                            fprintf(stdout, "\t\t\tInterrupt Process ");
                            break;
                        /* Are You There : vérifier que le système distant est toujours "en vie" */
                        case AYT:
                            fprintf(stdout, "\t\t\tAre You There ");
                            break;
                        /* Sub Option : les données qui suivent sont une négociation de l’option précédente */
                        case SB:
                            fprintf(stdout, "\t\t\tSub Option ");
                            tmp++;
                            rc++;
                            option_negocies_telnet(tmp);

                            unsigned char* tmp2;
                            tmp2 = ( tmp ) - 1;

                            while(rc < size && *tmp != SE && *tmp2 != SE)
                            {
                                fprintf(stdout, "%02hhX ", *tmp);
                                tmp2 = tmp;
                                tmp++;
                                rc++;
                            }
                            fprintf(stdout, "%02hhX ", *tmp);
                            break;
                        default:
                            fprintf(stdout, "\t\t\tUnknow Control Character ");
                            break;
                    }
                    tmp++;
                    rc++;
                    fprintf(stdout, "\n");
                }
            }
            else /* on affiche les caracteres si IAC n'est pas présent */
            {
                    for (i = 0; i < size; i++)
                {
                    printable(packet[i]);
                }
            }
            break;		
	}
    fprintf(stdout, "\n");
}

void option_negocies_telnet(const unsigned char* tmp)
{
	switch(*tmp)
    {
        /* renvoie un echo des caractères reçus */
		case ECHO:
			fprintf(stdout, "echo ");
			break;
        /* non utilisation du caractère de contrôle go ahead(full duplex) */
		case SUPPR_GO_AHEAD:
			fprintf(stdout, "suppress go ahead ");
			break;
        /* permet de spécifier le type de terminal utilisé (avec sous-option) */
		case TERMINAL_TYPE:
			fprintf(stdout, "terminal type ");
			break;
        /* spécifie la taille de la fenêtre du terminal (avec sous-option) */
		case WINDOW_SIZE:
			fprintf(stdout, "window size ");
			break;
        /* négocie la vitesse de connexion (avec sous-option) */
		case TERM_SPEED:
			fprintf(stdout, "terminal speed speed ");
			break;
        /* les émissions client>serveur se font ligne par ligne et non caractère par caractère*/
		case LINE_MODE:
			fprintf(stdout, "line mode ");
			break;
        /* négociation de variables d’environnement */
		case ENV_VAR:
			fprintf(stdout, "environment variables ");
			break;
        /* même but que environment variables */
		case NEW_ENV_VAR:
			fprintf(stdout, "new environment variables ");
			break;
		default:
			fprintf(stdout, "Unknow option ( %d )", *tmp);
			break;
	}
}

void dns(const unsigned char * packet, int size, int verbosite)
{
    struct dns_header* header;
    int i;

    if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ DNS ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
    if(size < 0)
        panic("application", "dns");

    fprintf(stdout, "\t\t\t[ DNS ] :\n");

    header = (struct dns_header*)packet;

    switch(verbosite)
    {
        case 1 :
        case 2 :
            fprintf(stdout, "\t\t\t├─ Transaction ID       : %d\n", ntohs(header->id));
            fprintf(stdout, "\t\t\t├─ Queries              :\n\t\t\t");
            for (i = 0; i < size && packet[i] != '\n'; i++)
            {
			    printable(packet[i]);
		    }
            break;
        case 3 :
        	fprintf(stdout, "\t\t\t├─ Transaction ID       : %d\n", ntohs(header->id));
            fprintf(stdout, "\t\t\t├─ Recursion Desired    : %d\n", ntohs(header->rd));
            fprintf(stdout, "\t\t\t├─ Truncated Message    : %d\n", ntohs(header->tc));
            fprintf(stdout, "\t\t\t├─ Authoritive Answer   : %d\n", ntohs(header->aa));
            fprintf(stdout, "\t\t\t├─ Operation Code       : %d\n", ntohs(header->opcode));
            fprintf(stdout, "\t\t\t├─ Query / Response Flag: %d\n", ntohs(header->qr));
            fprintf(stdout, "\t\t\t├─ Response Code        : %d\n", ntohs(header->rcode));
            fprintf(stdout, "\t\t\t├─ Checking Disabled    : %d\n", ntohs(header->cd));
            fprintf(stdout, "\t\t\t├─ Authenticated Data   : %d\n", ntohs(header->ad));
            fprintf(stdout, "\t\t\t├─ Reserved             : %d\n", ntohs(header->z));
            fprintf(stdout, "\t\t\t├─ Recursion Available  : %d\n", ntohs(header->ra));
            fprintf(stdout, "\t\t\t├─ Questions            : %d\n", ntohs(header->q_count));
            fprintf(stdout, "\t\t\t├─ Answer RRs           : %d\n", ntohs(header->ans_count));
            fprintf(stdout, "\t\t\t├─ Authority RRs        : %d\n", ntohs(header->auth_count));
            fprintf(stdout, "\t\t\t├─ Additional RRs       : %d\n", ntohs(header->add_count));
            fprintf(stdout, "\t\t\t├─ Queries              :\n\t\t\t");
            for (i = sizeof(struct dns_header); i < size; i++)
            {
                printable(packet[i]);
            }
            break;
        default : 
            panic("application", "dns");
            break;
    }
}
void udp_protocol(const unsigned char * packet, int size, int verbosite)
{
    struct bootp* header; 
	unsigned char* vendor;
    int my_boolean;

    if (size == 0)
    {
        fprintf(stdout, "\t\t\t[ BOOTP / DHCP ] :\n\t\t\t└─ NO DATA\n");
        return;
    }
	if(size < 0)
        panic("application", "udp_protocol");

    my_boolean  = 0;
    header      = (struct bootp*)( packet );
    vendor      =  header->bp_vend;

	if( vendor[0] == MAGIC_COOKIE_BIT_1 && 
        vendor[1] == MAGIC_COOKIE_BIT_2 && 
        vendor[2] == MAGIC_COOKIE_BIT_3 && 
        vendor[3] == MAGIC_COOKIE_BIT_4 )
    {
		fprintf(stdout, "\t\t\t[ DHCP ] :\n");
        my_boolean = 1;
	}
    else
    {
		fprintf(stdout, "\t\t\t[ BOOTP ] :\n");
        my_boolean = 2;
	}

    switch(verbosite)
    {
        case 1 :
        case 2 :
            if (my_boolean == 2)
            {
                if (header->bp_op == BOOTREQUEST)
                {
                    fprintf(stdout, "\t\t\t├─ Boot Request   :  %d\n", header->bp_op);
                }
                else if (header->bp_op == BOOTREPLY)
                {
                    fprintf(stdout, "\t\t\t├─ Boot Reply     :  %d\n", header->bp_op);
                }
                fprintf(stdout, "\t\t\t└─ Transaction ID : %d\n", header->bp_xid);
            }
            else if (my_boolean == 1)
            {
                vendor = vendor + 6;
                fprintf(stdout, "\t\t\t└─ Operation : ");
			    switch(vendor[0])
                {
                    case DHCPDISCOVER:
                        fprintf(stdout, "DISCOVER\n");
                        break;
                    case DHCPOFFER:
                        fprintf(stdout, "OFFER\n");
                        break;
                    case DHCPREQUEST:
                        fprintf(stdout, "REQUEST\n");
                        break;
                    case DHCPDECLINE:
                        fprintf(stdout, "DECLINE\n");
                        break;
                    case DHCPACK:
                        fprintf(stdout, "ACK\n");
                        break;
                    case DHCPNAK:
                        fprintf(stdout, "NACK\n");
                        break;
                    case DHCPRELEASE:
                        fprintf(stdout, "RELEASE\n");
                        break;
                    default:
                        fprintf(stdout, "Unknow Operation\n");
                        break;
                }
            }
            else 
            {
                panic("application", "udp_protocol");
            }
            break;
        case 3 :
            if (header->bp_op == BOOTREQUEST)
            {
                fprintf(stdout, "\t\t\t├─ Boot Request     :  %d\n", header->bp_op);
            }
            else if (header->bp_op == BOOTREPLY)
            {
                fprintf(stdout, "\t\t\t├─ Boot Reply       :  %d\n", header->bp_op);
            }
            switch (header->bp_htype)
            {
                case 1 : /* Ethernet */
                    fprintf(stdout, "\t\t\t├─ Hardware Type        : Ethernet (%d)\n", header->bp_htype);
                    break;
                case 2 : /* Experimental Ethernet */
                    fprintf(stdout, "\t\t\t├─ Hardware Type        : Experimental Ethernet (%d)\n", header->bp_htype);
                    break;
                case 3 : /* AX25 */
                    fprintf(stdout, "\t\t\t├─ Hardware Type        : AX25 (%d)\n", header->bp_htype);
                    break;
                case 4 : /* PRONET */
                    fprintf(stdout, "\t\t\t├─ Hardware Type        : PRONET (%d)\n", header->bp_htype);
                    break;
                case 5 : /* CHAOS */
                    fprintf(stdout, "\t\t\t├─ Hardware Type        : CHAOS (%d)\n", header->bp_htype);
                    break;
                case 6 : /* IEEE802 */
                    fprintf(stdout, "\t\t\t├─ Hardware Type        : IEEE802 (%d)\n", header->bp_htype);
                    break;
                case 7 : /* ARCNET */
                    fprintf(stdout, "\t\t\t├─ Hardware Type        : ARCNET (%d)\n", header->bp_htype);
                    break;
                default :
                    fprintf(stdout, "\t\t\t├─ Hardware Type        : Unknown (%d)\n", header->bp_htype);
                    break;
            }
            fprintf(stdout, "\t\t\t├─ Hardware address length  : %d\n", header->bp_hlen);
            fprintf(stdout, "\t\t\t├─ Hops                     : %d\n", header->bp_hops);
            fprintf(stdout, "\t\t\t├─ Transaction ID           : %d\n", header->bp_xid);
            fprintf(stdout, "\t\t\t├─ Seconds elapsed          : %d\n", header->bp_secs);
            fprintf(stdout, "\t\t\t├─ Bootp flags              : %d\n", header->bp_flags);
            fprintf(stdout, "\t\t\t├─ Destination IP address   : %s\n", inet_ntoa(header->bp_ciaddr));
            fprintf(stdout, "\t\t\t├─ Source IP address        : %s\n", inet_ntoa(header->bp_yiaddr));
            fprintf(stdout, "\t\t\t├─ Next server IP address   : %s\n", inet_ntoa(header->bp_siaddr));
            fprintf(stdout, "\t\t\t├─ Relay agent IP address   : %s\n", inet_ntoa(header->bp_giaddr));
            fprintf(stdout, "\t\t\t├─ Client MAC address       : %02x:%02x:%02x:%02x:%02x:%02x\n",
                header->bp_chaddr[0],
                header->bp_chaddr[1],
                header->bp_chaddr[2],
                header->bp_chaddr[3],
                header->bp_chaddr[4],
                header->bp_chaddr[5]);
            fprintf(stdout, "\t\t\t├─ Server name              : %s\n", header->bp_sname);
            fprintf(stdout, "\t\t\t├─ Boot file name           : %s\n", header->bp_file);
            fprintf(stdout, "\t\t\t├─ Magic Cookie             : (%02x%02x%02x%02x)\n", 
                header->bp_vend[0],
                header->bp_vend[1],
                header->bp_vend[2],
                header->bp_vend[3]);
            if (my_boolean == 1)
            {
			    vendor = vendor + 4;
                fprintf(stdout, "\t\t\t└─ Magic Cookie             : \n");
			    action_vendor(vendor, VENDOR_SIZE_DHCP);
            }
            else if (my_boolean == 2)
            {
                action_vendor(vendor, VENDOR_SIZE_BOOTP);
            }
            break;
        default :
            panic("application", "udp_protocol");
            break;
    }
}

void action_vendor(unsigned char * packet, int size)
{
    unsigned char * tmp;
	int len, end;

    if (size == 0)
        panic("application", "action_vendor");


    tmp = packet;
    end  = 0;

	while(size > 0)
    {
		packet++;
		size--;

        switch((int) *tmp)
        {
            case 50: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Requested IP address \n", *tmp); 
                break;
            case 51: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Ip Address Lease Time \n", *tmp); 
                break;
            case 52: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Option overload \n", *tmp); 
                break;
            case 53: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Message Type \n", *tmp); 
                break;
            case 54: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Server ID \n", *tmp); 
                break;
            case 55: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Parameter List \n", *tmp); 
                break;
            case 56: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Message \n", *tmp); 
                break;
            case 57: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Max Msg Size\n", *tmp); 
                break;
            case 58: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Renewal Time \n", *tmp); 
                break;
            case 59: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Rebinding Time \n", *tmp); 
                break;
            case 60: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Class ID \n", *tmp); 
                break;
            case 61: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Client ID \n", *tmp); 
                break;
            case 12: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Hostname \n", *tmp); 
                break;
            case 15: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Domain name \n", *tmp); 
                break;
            case 44: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Netbios over TCP/IP name server \n", *tmp); 
                break;
            case 47: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Netbios over TCP/IP scope \n", *tmp); 
                break;
            case 28: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Broadcast address \n", *tmp); 
                break;
            case 255: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) End \n", *tmp); 
                end = 1; 
                break;
            case 0: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Padding \n", *tmp); 
                end = 1; 
                break;
            case 1: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Subnet Mask \n", *tmp); 
                break;
            case 2: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Time offset \n", *tmp); 
                break;
            case 3: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Router\n", *tmp); 
                break;
            case 6: 
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) DNS\n", *tmp); 
                break;
            default:
                fprintf(stdout, "\t\t\t\t└─ Option: (%d) Unknown \n", *tmp);
                break;
        }
		if (end == 0)
        {
            tmp++;
            len = (int)*tmp;
            tmp++;
            for(int i = 0 ; i < len ; i++) tmp++;
            tmp--;
        }
        end = 0;
        tmp++;
	}
    fprintf(stdout, "\n");
}


