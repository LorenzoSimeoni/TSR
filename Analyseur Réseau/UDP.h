#include "BOOTP.h"
#include "dns.h"


/*
	Voici les ports les plus connus pour UDP (trouvés dans le cour)
*/
#define ECHO 7
#define FTP 21
#define SSH 22
#define TELNET 23
#define SMTP 25
#define BOOTPS 67
#define BOOTPC 68
#define DNS 53
#define TFTP 69
#define HTTP 80
#define HTTPS 443
#define DHCP 546

/*
	Permet de print l'header UDP puis de trouver le protocol applicatif utilisé
*/
void PrintHeaderUDP(int EtherSize, int IpSize,const u_char *packet,int Verbosite,const struct pcap_pkthdr *header);

/*
	Permet d'afficher le paquet de longueur header->len - k en HEXA
*/
void printPaquetUDPHEXA(const struct pcap_pkthdr *header, const u_char *packet, int k);
/*
	Permet d'afficher le paquet de longueur header->len - k en ASCII
*/
void printPaquetUDPASCII(const struct pcap_pkthdr *header, const u_char *packet, int k);
/*
	Permet d'afficher le paquet de longueur header->len - k en HEXA puis en ASCII à côté
*/
void printPaquetUDPHA(const struct pcap_pkthdr *header, const u_char *packet, int k);