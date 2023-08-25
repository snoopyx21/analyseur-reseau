#include "../include/tcpdump.h"

/* sortie d'erreur */
void panic(char * file, char * function)
{
    fprintf(stderr, "%s.c : Unexpected error occurred - function '%s'\n", file, function);
    exit(EXIT_FAILURE);
}

/* fonction call back */
void got_packet(unsigned char *args, const struct pcap_pkthdr * header, const unsigned char *packet)
{
    int port_source,
        port_dest,
        verbosite,
        rc, 
        rc_ip,
        size_payload,
        size; 
    unsigned short network_protocol,
                   transport_protocol;
    static int packet_id = 0;

    size                = header->len;
    port_source         = 0;
    port_dest           = 0;
    network_protocol    = 0;
    transport_protocol  = 0;
    rc                  = 0;
    rc_ip               = 0;
    verbosite           = atoi((const char *)args);

    packet_id++;

    fprintf(stdout, "\n-------------------------------------\n");
    fprintf(stdout, "Packet number %d\n", packet_id);

	rc = ethernet(packet, &network_protocol, verbosite);
    switch(network_protocol)
    {
        case ETHERTYPE_IP :
            rc_ip = ip(packet + rc, &transport_protocol, verbosite);
            if (rc_ip > 0)
            {
                rc   += rc_ip;
                size_payload  = size - rc;
                switch(transport_protocol)
                {
                    case IPPROTO_TCP :
                        rc   += tcp(packet + rc, &port_source, &port_dest, size_payload, verbosite);
                        size_payload  = size - rc;

                        if(port_source == HTTP_PORT || port_dest == HTTP_PORT)
                        {
                            http(packet + rc, size_payload, verbosite);
                        }
                        else if(port_dest == HTTPS_PORT || port_source == HTTPS_PORT)
                        {
                            https(packet + rc, size_payload, verbosite);
                        }
                        else if(port_dest == SMTP_PORT || port_source == SMTP_PORT)
                        {
                            smtp(packet + rc, size_payload, verbosite);
                        }else if(port_dest == IMAP_PORT || port_source == IMAP_PORT)
                        {
                            imap(packet + rc, size_payload, verbosite);
                        }
                        else if(port_source == POP_PORT)
                        {
                            pop(packet + rc, size_payload, verbosite);
                        }
                        else if(port_dest == TELNET_PORT || port_source == TELNET_PORT)
                        {
                            telnet(packet + rc, size_payload, verbosite);
                        }
                        else if(port_dest == FTP_CONTROL_PORT   || 
                                port_source == FTP_CONTROL_PORT ||
                                port_dest == FTP_DATA_PORT      || 
                                port_source == FTP_DATA_PORT)
                        {
                            ftp(packet + rc, size_payload, port_source, verbosite);
                        }
                        else 
                        {
                            fprintf(stdout, "\t\t\t[ Unknown ]\n");
                        }
                        break;
                    case IPPROTO_UDP :
                        rc   += udp(packet + rc, &port_source, &port_dest, verbosite);
                        size_payload  = size - rc;
                        if( port_source  == DHCP_CLIENT_PORT || 
                            port_source  == DHCP_SERVER_PORT || 
                            port_dest    == DHCP_CLIENT_PORT || 
                            port_dest    == DHCP_SERVER_PORT )
                        {
                            udp_protocol(packet + rc, size_payload, verbosite);
                        }
                        else if(port_source == DNS_PORT || port_dest == DNS_PORT)
                        {
                            dns(packet + rc, size_payload, verbosite);
                        }
                        else 
                        {
                            fprintf(stdout, "\t\t\t[ Unknown ]\n");
                        }
                        break;
                    case IPPROTO_ICMP :
                        icmp(packet + rc, verbosite);
                        break;
                    case IPPROTO_SCTP :
                        sctp(packet + rc, &port_source, &port_dest, size_payload, verbosite);
                        break;
                    default :
                        fprintf(stdout, "\t\t[ Unknown ]\n");
                        break;
                }
            }
            
            break;
        case ETHERTYPE_ARP :
            arp(packet + rc, verbosite);
            break;
        case ETHERTYPE_REVARP :
            fprintf(stdout, "\t[ RARP ]\n");
            break;
        default : 
            if ( verbosite == 3 ) 
                fprintf(stdout, "\t[ Unknown ]\n");
            break;
    }
    fprintf(stdout, "\n");
}

/*************************************************************************************************/

/* main - utilisation de la librairie PCAP */
int main(int argc, char * argv[])
{
    int rc, 
        opt, 
        iflag, 
        oflag, 
        fflag, 
        vflag, 
        errflag, 
        nb_args,
        verbosite;
    char interface[MAX_STRING_SIZE], 
        fichier[MAX_STRING_SIZE], 
        filtre[MAX_STRING_SIZE], 
        errbuf[PCAP_ERRBUF_SIZE];
    unsigned char args[MAX_STRING_SIZE];
    pcap_t *capture;

    /* filtre BPF */
    struct bpf_program filtre_BPF_program;
    bpf_u_int32 filtre_BPF;

    rc          = 0;
    opt         = 0;
    iflag       = 0;
    oflag       = 0;
    fflag       = 0;
    vflag       = 0;
    errflag     = 0;
    nb_args     = 0;
    filtre_BPF  = 0;
    verbosite   = 1;
    capture     = NULL;

    /* utilisation de getopt pour gérer les arguments */
    while ( (opt = getopt(argc, argv, "i:o:f:v:") ) != -1)
    {
        switch (opt) 
        {
            case 'i':
                iflag = 1;
                strcpy(interface, optarg);
                nb_args+=2;
                break;
            case 'o':
                oflag = 1;
                strcpy(fichier,optarg);
                nb_args += 2;
                break;
            case 'f':
                fflag = 1;
                strcpy(filtre, optarg);
                nb_args += 2;
                break;
            case 'v':
                vflag = 1;
                verbosite = atoi(optarg);
                nb_args += 2;
                break;
            /* getopt ne reconnait pas un caractère */
            case '?':
                errflag++;
                break;
            }
    }

    if ( (verbosite < 0) && (verbosite > 3) )
    {
        fprintf(stderr, "usage : verbosite incorrecte %d - 0 < verbosite <= 3\n", verbosite);
        return ( -1 );
    }
    sprintf((char *)args, "%d", verbosite);

    /* on ne peut pas avoir -f et -i / impossible d'avoir un mode live et un mode off */
    if (errflag || argc != (nb_args+1) || vflag == 0 || (iflag == 1 && oflag == 1))
    {
        fprintf(stderr, "usage : erreur args - ./tcpdump -i <interface> -o <fichier> -f <filtre> -v <1..3>\n");
        return ( -1 );
    }

    /* interface live */
    if ( iflag == 1 )
    {
        capture = pcap_open_live(interface, MAX_LEN_PACKET, 1, 1000, errbuf);
        /* failure - errbuf contient le message d'erreur */
        if (capture == NULL) 
        {
            fprintf(stderr, "Erreur pcap_open_live interface %s: %s\n", interface, errbuf);
            return ( -1 );
        }

        /* renvoie le type d'en-tête de la couche liaison de la capture en direct */
        rc = pcap_datalink(capture);
        if (rc == PCAP_ERROR_NOT_ACTIVATED) 
        {
            fprintf(stderr, "Capture inactive sur l'interface %s\n", interface);
            return ( -1 );
        }
        if (rc == DLT_EN10MB) 
        {
            fprintf(stderr, "Interface %s - no ethernet\n", interface);
            return ( -1 );
        }

        /* application filtre */
        if ( fflag == 1 )
        {
            if (pcap_compile(capture, &filtre_BPF_program, filtre, 0, filtre_BPF) == -1) 
            {
                fprintf(stderr, "Erreur pcap_compile avec filtre %s : %s\n", filtre, pcap_geterr(capture));
                return ( -1 );
            }
        }
        else 
        {
            if (pcap_compile(capture, &filtre_BPF_program, NULL, 0, filtre_BPF) == -1) 
            {
                fprintf(stderr, "Erreur pcap_compile : %s\n", pcap_geterr(capture));
                return ( -1 );
            }
        }

        /* association du filtre compilé à la capture */
        if (pcap_setfilter(capture, &filtre_BPF_program) == -1) 
        {
            fprintf(stderr, "Erreur pcap_setfilter : %s\n", pcap_geterr(capture));
            return ( -1 );
        }

        /* analyse des paquets en boucle */
        pcap_loop(capture, -1, got_packet, args);

        pcap_freecode(&filtre_BPF_program);
        pcap_close(capture);
    }
    /* interface no live */
    else
    {
        /* capture offline */
        capture = pcap_open_offline(fichier, errbuf);

        if (capture == NULL) 
        {
                fprintf(stderr, "Error pcap_open_offline (file : %s ) : %s\n", fichier, errbuf);
                return ( -1 );
        }

        /* application filtre */
        if ( fflag == 1 )
        {
            if (pcap_compile(capture, &filtre_BPF_program, filtre, 0, filtre_BPF) == -1) 
            {
                fprintf(stderr, "Erreur pcap_compile avec filtre %s : %s\n", filtre, pcap_geterr(capture));
                return ( -1 );
            }
        }
        else 
        {
            if (pcap_compile(capture, &filtre_BPF_program, NULL, 0, filtre_BPF) == -1) 
            {
                fprintf(stderr, "Erreur pcap_setfilter sur filtre %s : %s\n", filtre, pcap_geterr(capture));
                return ( -1 );
            }
        }

        /* association du filtre compilé à la capture */
        if (pcap_setfilter(capture, &filtre_BPF_program) == -1) 
        {
            fprintf(stderr, "Erreur pcap_setfilter : %s\n", pcap_geterr(capture));
            return ( -1 );
        }

        /* analyse des paquets en boucle */
        pcap_loop(capture, -1, got_packet, args);

        pcap_freecode(&filtre_BPF_program);
        pcap_close(capture);

    }

    return ( 0 );
}