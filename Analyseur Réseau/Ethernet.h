#include "IP.h"
#include "ARP.h"
#include <netinet/if_ether.h>


/*
Cette fonction permet d'afficher l'en tête ethernet, de voir si on a affaire à un type ARP, IPV4,  ou autre, et d'appeler 
une fonction pour l'entête suivante en conséquence
*/
void PrintHeaderEthernet(const u_char *packet,int Verbosite,const struct pcap_pkthdr *header);