#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
	Permet d'afficher les en têtes ARP avec la structure contenue dans netinet/if_ether
*/
void PrintHeaderARP(int EtherSize, const u_char *packet);