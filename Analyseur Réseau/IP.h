#include "TCP.h"
#include "UDP.h"
#include <netinet/ip.h>


/*
	Les define correspondant aux protocoles sur les couches suivantes
*/
#define ICMP 1
#define IGMP 2
#define TCP 6
#define UDP 17 


/*
cette fonction va permettre d'afficher l'en tête IP, regarder si la couche 4 est en UDP 
ou TCP, et d'appeler la fonction correspondante 

*/
void PrintHeaderIP(int EtherSize, const u_char *packet, int Verbosite,const struct pcap_pkthdr *header);