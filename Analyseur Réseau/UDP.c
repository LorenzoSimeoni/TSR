#include "UDP.h"

/*
	Permet d'afficher le paquet en Hexa
*/
void printPaquetUDPHEXA(const struct pcap_pkthdr *header, const u_char *packet, int k) {

    printf("\n");
    printf("\033[4m\033[34m#DATA \n\n");
    printf("\033[35mHEXA:\n\t");
    int i = 0;
    int j = 0;
    int k2 = 0;
 	for(k2 = k; k2<header->len; k2++) {
 		printf("\033[0m%.2x",packet[k2]);
 		i++;
 		j++;
 		if(j==14) {
 			printf("\n\t");
 			j = 0;
 			i = 0;
 		}
 		if(i==2) {
 			printf("  ");
 			i = 0;
 		}
 	}	
 	printf("\n");
 }

/*
	Permet d'afficher le paquet de longueur header->len - k en ASCII
*/
 void printPaquetUDPASCII(const struct pcap_pkthdr *header, const u_char *packet, int k) {
 	int k2=0;
 	for(k2=k; k2<header->len; k2++) {
 		if(packet[k2]==13){
 			printf("\n");
 		}
 		else if(packet[k2]>31 && packet[k2]<=127){
 			printf("\033[0m%c", packet[k2]);
 		}
 		else if(packet[k2]==10){
 			printf(" ");
 		}
 		else {
 			printf("\033[0m.");
 		}
 	}	
 	printf("\n");
}


/*
	Fonction permettant d'afficher l'ASCII à Côté de l'hexa
*/
void printPaquetUDPHA(const struct pcap_pkthdr *header, const u_char *packet, int k2) {

    int i = 0;
    int j = 0;
    int compteur = k2;
    int valeurk = k2;
    int k = 0;
 	for(k=k2; k<header->len; k++) {
 		printf("%.2x",packet[k]);
 		i++;
 		j++;
 		if(j==14 || k == header->len-1) {
 			printf("    ");
 			if(k==header->len-1) {
 				int nbespace = 14-(header->len-valeurk)%14;
 				if(nbespace == 14){
 					nbespace = 0;
 				}
 				nbespace= nbespace + nbespace/2;
 				for(int espace=0;espace<nbespace;espace++){
 					printf("  ");
 				}
 			}
 			do
 			{
 				if(packet[compteur]>31 && packet[compteur]<=127){
		 			printf("%c", packet[compteur]);
		 		}
		 		else {
		 			printf(".");
		 		}
		 		compteur++;
 			}while(compteur != k+1);
 			printf("\n\t");
 			j = 0;
 			i = 0;
 		}
 		if(i==2) {
 			printf("  ");
 			i = 0;
 		}
 	}	
 	printf("\n");
 }

/*
Permet d'afficher l'en tête UDP
*/
void PrintHeaderUDP(int EtherSize, int IpSize,const u_char *packet,int Verbosite,const struct pcap_pkthdr *header) {
	
	/*
		Permet de mettre la structure à la bonne adresse
	*/
	struct udphdr *headerUDP;
	headerUDP = (struct udphdr*)(packet+EtherSize+IpSize);
	int UDPSize = sizeof(struct udphdr);

	if(Verbosite == 1) {
		/*
			Le switch permet de trouver le protocol applicatif, grâce aux define qui se trouvent dans le .h
			On affiche ensuite le protocol applicatif
		*/
		switch(ntohs(headerUDP->uh_sport)) {
			case BOOTPS:
				printf("BOOTPS" );
				break;
			case BOOTPC:
				printf("BOOTPC");
				break;
			case DNS:
				printf("DNS");
				break;
			case TFTP:
				printf("TFTP");
				break;
			case HTTP:
				printf("HTTP");
				break;
			case HTTPS:
				printf("HTTPS");
				break;
			case DHCP:
				printf("DHCP");
				break;
			case ECHO: 
				printf("echo");
			break;
			case FTP:
				printf("FTP");
			break;
			case SSH:
				printf("SSH");
			break;
			case TELNET:
				printf("Telnet");
			break;
			case SMTP:
				printf("SMTP");
			break;
			default:
				printf("%d",ntohs(headerUDP->uh_sport) );
			break;
		}

		/*
			Le switch permet de trouver le protocol applicatif, grâce aux define qui se trouvent dans le .h
			On affiche ensuite le protocol applicatif
		*/
		switch(ntohs(headerUDP->uh_dport)) {
			case BOOTPS:
				printf(" BOOTPS" );
				break;
			case BOOTPC:
				printf(" BOOTPC");
				break;
			case DNS:
				printf(" DNS");
				break;
			case TFTP:
				printf(" TFTP");
				break;
			case HTTP:
				printf(" HTTP");
				break;
			case HTTPS:
				printf(" HTTPS");
				break;
			case DHCP:
				printf(" DHCP ");
				break;
			case ECHO: 
				printf("echo");
			break;
			case FTP:
				printf("FTP");
			break;
			case SSH:
				printf("SSH");
			break;
			case TELNET:
				printf("Telnet");
			break;
			case SMTP:
				printf("SMTP");
			break;
			default:
				printf(" %d ", ntohs(headerUDP->uh_dport) );
				break;
		}
		if(ntohs(headerUDP->uh_sport) == BOOTPS || ntohs(headerUDP->uh_sport)==BOOTPC){
			PrintHeaderBOOTP(EtherSize, IpSize, UDPSize,packet, Verbosite,header);
		}
		printf("\n");
	}

	if(Verbosite == 2) {

		/*
			Le switch permet de trouver le protocol applicatif, grâce aux define qui se trouvent dans le .h
			On affiche ensuite le protocol applicatif
		*/
		switch(ntohs(headerUDP->uh_sport)) {
			case BOOTPS:
				printf("\033[0mSource Port: BOOTP Côté serveur" );
				break;
			case BOOTPC:
				printf("\033[0mSource Port: BOOTP Côté client");
				break;
			case DNS:
				printf("\033[0mSource Port: DNS");
				break;
			case TFTP:
				printf("\033[0mSource Port: TFTP");
				break;
			case HTTP:
				printf("\033[0mSource Port: HTTP");
				break;
			case HTTPS:
				printf("\033[0mSource Port: HTTPS");
				break;
			case DHCP:
				printf("\033[0mSource Port: DHCP");
				break;
			case ECHO: 
				printf("Source Port: echo");
			break;
			case FTP:
				printf("Source Port: FTP");
			break;
			case SSH:
				printf("Source Port: SSH");
			break;
			case TELNET:
				printf("Source Port: Telnet");
			break;
			case SMTP:
				printf("Source Port: SMTP");
			break;
			default:
				printf("\033[0mSource Port: %d ", ntohs(headerUDP->uh_sport) );
				break;
		}
		printf("\n");

		/*
			Le switch permet de trouver le protocol applicatif, grâce aux define qui se trouvent dans le .h
			On affiche ensuite le protocol applicatif
		*/
		switch(ntohs(headerUDP->uh_dport)) {
			case BOOTPS:
				printf("Destination Port: BOOTP Côté serveur" );
				break;
			case BOOTPC:
				printf("Destination Port: BOOTP Côté client");
				break;
			case DNS:
				printf("Destination Port: DNS");
				break;
			case TFTP:
				printf("Destination Port: TFTP");
				break;
			case HTTP:
				printf("Destination Port: HTTP");
				break;
			case HTTPS:
				printf("Destination Port: HTTPS");
				break;
			case DHCP:
				printf("Destination Port: DHCP");
				break;
			case ECHO: 
				printf("Destination Port: echo");
			break;
			case FTP:
				printf("Destination Port: FTP");
			break;
			case SSH:
				printf("Destination Port: SSH");
			break;
			case TELNET:
				printf("Destination Port: Telnet");
			break;
			case SMTP:
				printf("Destination Port: SMTP");
			break;
			default:
				printf("Destination Port: %d ", ntohs(headerUDP->uh_dport) );
				break;
		}
		printf("\n");
		if(UDPSize+EtherSize+IpSize != header->len){

			switch(ntohs(headerUDP->uh_sport)) {
				case BOOTPS:
					PrintHeaderBOOTP(EtherSize, IpSize, UDPSize,packet, Verbosite,header);
					break;
				case BOOTPC:
				   	PrintHeaderBOOTP(EtherSize, IpSize, UDPSize,packet, Verbosite,header);
					break;
			}
		}

	}

	if(Verbosite == 3) {

		/*
			Le switch permet de trouver le protocol applicatif, grâce aux define qui se trouvent dans le .h
			On affiche ensuite le protocol applicatif
		*/
		switch(ntohs(headerUDP->uh_sport)) {
			case BOOTPS:
				printf("\033[0mSource Port: BOOTP Côté serveur" );
				break;
			case BOOTPC:
				printf("\033[0mSource Port: BOOTP Côté client");
				break;
			case DNS:
				printf("\033[0mSource Port: DNS");
				break;
			case TFTP:
				printf("\033[0mSource Port: TFTP");
				break;
			case HTTP:
				printf("\033[0mSource Port: HTTP");
				break;
			case HTTPS:
				printf("\033[0mSource Port: HTTPS");
				break;
			case DHCP:
				printf("\033[0mSource Port: DHCP");
				break;
			case ECHO: 
				printf("Source Port: echo");
			break;
			case FTP:
				printf("Source Port: FTP");
			break;
			case SSH:
				printf("Source Port: SSH");
			break;
			case TELNET:
				printf("Source Port: Telnet");
			break;
			case SMTP:
				printf("Source Port: SMTP");
			break;
			default:
				printf("\033[0mSource Port: %d ", ntohs(headerUDP->uh_sport) );
				break;
		}
		printf("\n");

		/*
			Le switch permet de trouver le protocol applicatif, grâce aux define qui se trouvent dans le .h
			On affiche ensuite le protocol applicatif
		*/
		switch(ntohs(headerUDP->uh_dport)) {
			case BOOTPS:
				printf("Destination Port: BOOTP Côté serveur" );
				break;
			case BOOTPC:
				printf("Destination Port: BOOTP Côté client");
				break;
			case DNS:
				printf("Destination Port: DNS");
				break;
			case TFTP:
				printf("Destination Port: TFTP");
				break;
			case HTTP:
				printf("Destination Port: HTTP");
				break;
			case HTTPS:
				printf("Destination Port: HTTPS");
				break;
			case DHCP:
				printf("Destination Port: DHCP");
				break;
			case ECHO: 
				printf("Destination Port: echo");
			break;
			case FTP:
				printf("Destination Port: FTP");
			break;
			case SSH:
				printf("Destination Port: SSH");
			break;
			case TELNET:
				printf("Destination Port: Telnet");
			break;
			case SMTP:
				printf("Destination Port: SMTP");
			break;
			default:
				printf("Destination Port: %d ", ntohs(headerUDP->uh_dport) );
			break;
		}
		printf("\n");
		printf("Length %d\n", ntohs(headerUDP->uh_ulen) );
		printf("Checksum %x\n", ntohs(headerUDP->uh_sum) );
	
		/*
			Cette variable permet de ne pas afficher la data plusieurs fois
			Si j'avais mis un default, j'aurai eu 2 fois l'affichage du paquet
			J'ai donc mis un if à la fin et on rentre dans le if si on a eu aucun paquet
			applicatif
			Pour la plupart des protocols j'utilise une fonction qui affiche l'hexa et l'ASCII
			à côté, sauf pour BOOTP ou j'analyse le header et les options quand on est en DHCP
			pour Telnet ou je trouve les options aussi et en SMTP où j'affiche l'ASCII.
		*/
		int PrintPacketManyTimes = 0;
		if(UDPSize+EtherSize+IpSize != header->len){

			switch(ntohs(headerUDP->uh_sport)) {
				case BOOTPS:
				    printf("\n");
				    printf("\033[4m\033[36m#BOOTPS \033[0m\n\n");
					PrintHeaderBOOTP(EtherSize, IpSize, UDPSize,packet, Verbosite,header);
					PrintPacketManyTimes = 1;
					break;
				case BOOTPC:
				 	
				    printf("\n");
				    printf("\033[4m\033[36m#BOOTPC \033[0m\n\n");
				   	PrintHeaderBOOTP(EtherSize, IpSize, UDPSize,packet, Verbosite,header);
				   	PrintPacketManyTimes = 1;
					break;
				case DNS:
				 	
				    printf("\n");
				    printf("\033[4m\033[34m#DNS (response)\033[0m\n\n");
					//printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintHeaderDNS(EtherSize, IpSize, UDPSize,packet, Verbosite,header);
					PrintPacketManyTimes = 1;
					break;
				case TFTP:
					
				    printf("\n");
				    printf("\033[4m\033[34m#TFTP \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case HTTP:
					
				    printf("\n");
				    printf("\033[4m\033[34m#HTTP \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case HTTPS:
					
				    printf("\n");
				    printf("\033[4m\033[34m#HTTPS \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case ECHO: 
					
				    printf("\n");
				    printf("\033[4m\033[34m#echo \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case FTP:
					
				    printf("\n");
				    printf("\033[4m\033[34m#FTP \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case SSH:
					
				    printf("\n");
				    printf("\033[4m\033[34m#SSH \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case TELNET:
					
				    printf("\n");
				    printf("\033[4m\033[34m#Telnet \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case SMTP:
					
				    printf("\n");
				    printf("\033[4m\033[34m#SMTP \033[0m\n\n\t");
					printPaquetUDPASCII(header,packet,UDPSize+EtherSize+IpSize);
					//printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
				break;
			}
			switch(ntohs(headerUDP->uh_dport)) {
				case DNS:
				 	
				    printf("\n");
				    printf("\033[4m\033[34m#DNS (query)\033[0m\n\n");
					PrintHeaderDNS(EtherSize, IpSize, UDPSize,packet, Verbosite,header);
					PrintPacketManyTimes = 1;
					break;
				case TFTP:
					
				    printf("\n");
				    printf("\033[4m\033[34m#TFTP \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case HTTP:
					
				    printf("\n");
				    printf("\033[4m\033[34m#HTTP \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case HTTPS:
					
				    printf("\n");
				    printf("\033[4m\033[34m#HTTPS \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case ECHO: 
					
				    printf("\n");
				    printf("\033[4m\033[34m#echo \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case FTP:
					
				    printf("\n");
				    printf("\033[4m\033[34m#FTP \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case SSH:
					
				    printf("\n");
				    printf("\033[4m\033[34m#SSH \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case TELNET:
					
				    printf("\n");
				    printf("\033[4m\033[34m#Telnet \033[0m\n\n\t");
					printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case SMTP:
					
				    printf("\n");
				    printf("\033[4m\033[34m#SMTP \033[0m\n\n\t");
				    printPaquetUDPASCII(header,packet,UDPSize+EtherSize+IpSize);
					//printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
				break;
			}

			if(PrintPacketManyTimes == 0) {
				printf("\n");
			    printf("\033[4m\033[34m#DATA \033[0m\n\n\t");
				printPaquetUDPHA(header,packet,UDPSize+EtherSize+IpSize);
			}
		}
	}
}
