#include "BOOTP.h"
#include "Telnet.h"
#include "dns.h"

/*
	Les define pour les ports les plus connus
*/
#define FTPC 20
#define FTPS 21
#define SSH 22
#define TELNET 23
#define SMTP 25
#define DNS 53
#define HTTP 80
#define HTTPS 443
#define POP3 110
#define IMAP 143


/*
	Fonction permettant d'afficher le header TCP et d'appeler la fonction du protocol applicatif,
	si il y en a une.
*/
void PrintHeaderTCP(int EtherSize, int IpSize,const u_char *packet,int Verbosite,const struct pcap_pkthdr *header);

/*
	Permet d'afficher le paquet en hexa, on peut dire (grâce à k) où commencer l'affichage
*/
void printPaquetTCPHEXA(const struct pcap_pkthdr *header, const u_char *packet, int k);

/*
	Permet d'afficher le paquet en HEXA
*/
void printPaquetTCPASCII(const struct pcap_pkthdr *header, const u_char *packet, int k);

/*
	Permet d'afficher le paquet en HEXA et puis en ASCII à côté
*/
void printPaquetTCPHA(const struct pcap_pkthdr *header, const u_char *packet, int k);