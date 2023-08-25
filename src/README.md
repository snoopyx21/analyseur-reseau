# Projet Pcap - Service Réseau

Le projet de l'UE Service Réseau a pour but de réaliser un analyseur réseau.

## Installation

Télécharger le projet, puis :

```bash
$make
src/transport.c
gcc -W -Wall -g  -c -o obj/transport.o src/transport.c
src/tcpdump.c
gcc -W -Wall -g  -c -o obj/tcpdump.o src/tcpdump.c
src/application.c
gcc -W -Wall -g  -c -o obj/application.o src/application.c
src/network.c
gcc -W -Wall -g  -c -o obj/network.o src/network.c
src/data_link.c
gcc -W -Wall -g  -c -o obj/data_link.o src/data_link.c
gcc -W -Wall -g  -o my_tcpdump obj/transport.o obj/tcpdump.o obj/application.o obj/network.o obj/data_link.o  -lpcap 
```

## Usage

-i <interface> : interface pour l’analyse live

-o <fichier> : fichier d’entrée pour l’analyse offline

-f <filtre> : filtre BPF (optionnel)

-v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)

```bash
sudo ./tcpdump -i <interface> -o <fichier> -f <filtre> -v <1..3>
```

Un dossier test est présent afin de pouvoir tester différents protocoles :

```bash
sudo ./my_tcpdump -o test/my_test.cap -v 3
```

