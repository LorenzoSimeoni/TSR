#include "TCP.h"

/*
 Permet d'afficher le paquet de longueur header->len - k en HEXA
*/
void printPaquetTCPHEXA(const struct pcap_pkthdr *header, const u_char *packet, int k) {

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
	On reconnait les /n
*/
 void printPaquetTCPASCII(const struct pcap_pkthdr *header, const u_char *packet, int k) {
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
void printPaquetTCPHA(const struct pcap_pkthdr *header, const u_char *packet, int k2) {

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
La fonction Permet d'afficher l'en tête TCP
*/
void PrintHeaderTCP(int EtherSize, int IpSize,const u_char *packet,int Verbosite,const struct pcap_pkthdr *header) {

	struct tcphdr *headerTCP;
	headerTCP = (struct tcphdr*)(packet+EtherSize+IpSize);
	//int TCPSize = sizeof(struct tcphdr);
	int TCPSize = 4*headerTCP->th_off;

	if(Verbosite == 1) {
		//printf("%d ",ntohs(headerTCP->th_sport) );
		switch(ntohs(headerTCP->th_sport)) {
			case FTPC:
				printf("FTP Côté client");
				break;
			case FTPS:
				printf("FTP Côté Serveur");
				break;
			case SSH:
				printf("SSH");
				break;
			case TELNET:
				printf("TELNET");
				break;
			case SMTP:
				printf("SMTP");
				break;
			case DNS:
				printf("DNS");
				break;
			case HTTP:
				printf("HTTP");
				break;
			case HTTPS:
				printf("HTTPS");
				break;
			case POP3:
				printf("POP3");
				break;
			case IMAP:
				printf("IMAP");
				break;
			default:
				printf(" %d",ntohs(headerTCP->th_sport) );
				break;
		}

		//printf(" %d ",ntohs(headerTCP->th_dport) );
		switch(ntohs(headerTCP->th_dport)) {
			case FTPC:
				printf(" FTPC");
				break;
			case FTPS:
				printf(" FTPS");
				break;
			case SSH:
				printf(" SSH");
				break;
			case TELNET:
				printf(" TELNET");
				break;
			case SMTP:
				printf(" SMTP");
				break;
			case DNS:
				printf(" DNS");
				break;
			case HTTP:
				printf(" HTTP");
				break;
			case HTTPS:
				printf(" HTTPS");
				break;
			case POP3:
				printf(" POP3");
				break;
			case IMAP:
				printf(" IMAP");
				break;
			default:
				printf(" %d ",ntohs(headerTCP->th_dport) );
				break;
		}
		//printf(" %u ",headerTCP->th_off );
		//printf("Flags %u\n",headerTCP->th_flags );
		if(headerTCP->th_flags & TH_FIN) {
			printf(" FIN ");
		}
		if(headerTCP->th_flags & TH_SYN) {
			printf(" SYN ");
		}
		if(headerTCP->th_flags & TH_RST) {
			printf(" RST ");
		}
		if(headerTCP->th_flags & TH_PUSH) {
			printf(" PUSH ");
		}
		if(headerTCP->th_flags & TH_ACK) {
			printf(" ACK ");
		}
		if(headerTCP->th_flags & TH_URG) {
			printf(" URG ");
		}
		printf("\n");
	}

	if(Verbosite == 2) {
		//printf("\033[0mSource Port %d ",ntohs(headerTCP->th_sport) );
		switch(ntohs(headerTCP->th_sport)) {
			case FTPC:
				printf("\033[0mSource Port: FTP Côté client");
				break;
			case FTPS:
				printf("\033[0mSource Port: FTP Côté Serveur");
				break;
			case SSH:
				printf("\033[0mSource Port: SSH");
				break;
			case TELNET:
				printf("\033[0mSource Port: TELNET");
				break;
			case SMTP:
				printf("\033[0mSource Port: SMTP");
				break;
			case DNS:
				printf("\033[0mSource Port: DNS");
				break;
			case HTTP:
				printf("\033[0mSource Port: HTTP");
				break;
			case HTTPS:
				printf("\033[0mSource Port: HTTPS");
				break;
			case POP3:
				printf("\033[0mSource Port: POP3");
				break;
			case IMAP:
				printf("\033[0mSource Port: IMAP");
				break;
			default:
				printf("\033[0mSource Port: %d ",ntohs(headerTCP->th_sport) );
				break;
		}
		printf("\n");


		//printf("Destination Port %d ",ntohs(headerTCP->th_dport) );
		switch(ntohs(headerTCP->th_dport)) {
			case FTPC:
				printf("Destination Port: FTP Côté client");
				break;
			case FTPS:
				printf("Destination Port: FTP Côté Serveur");
				break;
			case SSH:
				printf("Destination Port: SSH");
				break;
			case TELNET:
				printf("Destination Port: TELNET");
				break;
			case SMTP:
				printf("Destination Port: SMTP");
				break;
			case DNS:
				printf("Destination Port: DNS");
				break;
			case HTTP:
				printf("Destination Port: HTTP");
				break;
			case HTTPS:
				printf("Destination Port: HTTPS");
				break;
			case POP3:
				printf("Destination Port: POP3");
				break;
			case IMAP:
				printf("Destination Port: IMAP");
				break;
			default:
				printf("Destination Port: %d ",ntohs(headerTCP->th_dport) );
				break;
		}
		printf("\n");

		//printf("Flags %u\n",headerTCP->th_flags );
		printf("Flags: ");
		if(headerTCP->th_flags & TH_FIN) {
			printf("FIN ");
		}
		if(headerTCP->th_flags & TH_SYN) {
			printf("SYN ");
		}
		if(headerTCP->th_flags & TH_RST) {
			printf("RST ");
		}
		if(headerTCP->th_flags & TH_PUSH) {
			printf("PUSH ");
		}
		if(headerTCP->th_flags & TH_ACK) {
			printf("ACK ");
		}
		if(headerTCP->th_flags & TH_URG) {
			printf("URG ");
		}
		printf("\n");
	}

	if(Verbosite == 3) {
		//printf("\033[0mSource Port %d ",ntohs(headerTCP->th_sport) );
		switch(ntohs(headerTCP->th_sport)) {
			case FTPC:
				printf("\033[0mSource Port: FTP Côté client");
				break;
			case FTPS:
				printf("\033[0mSource Port: FTP Côté Serveur");
				break;
			case SSH:
				printf("\033[0mSource Port: SSH");
				break;
			case TELNET:
				printf("\033[0mSource Port: TELNET");
				break;
			case SMTP:
				printf("\033[0mSource Port: SMTP");
				break;
			case DNS:
				printf("\033[0mSource Port: DNS");
				break;
			case HTTP:
				printf("\033[0mSource Port: HTTP");
				break;
			case HTTPS:
				printf("\033[0mSource Port: HTTPS");
				break;
			case POP3:
				printf("\033[0mSource Port: POP3");
				break;
			case IMAP:
				printf("\033[0mSource Port: IMAP");
				break;
			default:
				printf("\033[0mSource Port: %d ",ntohs(headerTCP->th_sport) );
				break;
		}
		printf("\n");


		//printf("	 %d ",ntohs(headerTCP->th_dport) );
		switch(ntohs(headerTCP->th_dport)) {
			case FTPC:
				printf("Destination Port: FTP Côté client");
				break;
			case FTPS:
				printf("Destination Port: FTP Côté Serveur");
				break;
			case SSH:
				printf("Destination Port: SSH");
				break;
			case TELNET:
				printf("Destination Port: TELNET");
				break;
			case SMTP:
				printf("Destination Port: SMTP");
				break;
			case DNS:
				printf("Destination Port: DNS");
				break;
			case HTTP:
				printf("Destination Port: HTTP");
				break;
			case HTTPS:
				printf("Destination Port: HTTPS");
				break;
			case POP3:
				printf("Destination Port: POP3");
				break;
			case IMAP:
				printf("Destination Port: IMAP");
				break;
			default:
				printf("Destination Port: %d ",ntohs(headerTCP->th_dport) );
				break;
		}
		printf("\n");

		printf("Sequence Number: %x\n",ntohl(headerTCP->th_seq) );
		printf("Acknowledgment Number: %x\n",ntohl(headerTCP->th_ack) );
		printf("Data Offset: %u (Header lenght: %u)\n",headerTCP->th_off, 4*headerTCP->th_off );

		//printf("Flags %u\n",headerTCP->th_flags );
		printf("Flags: ");
		if(headerTCP->th_flags & TH_FIN) {
			printf("FIN ");
		}
		if(headerTCP->th_flags & TH_SYN) {
			printf("SYN ");
		}
		if(headerTCP->th_flags & TH_RST) {
			printf("RST ");
		}
		if(headerTCP->th_flags & TH_PUSH) {
			printf("PUSH ");
		}
		if(headerTCP->th_flags & TH_ACK) {
			printf("ACK ");
		}
		if(headerTCP->th_flags & TH_URG) {
			printf("URG ");
		}
		printf("\n");
		printf("Window: %d\n",ntohs(headerTCP->th_win) );
		printf("Checksum: 0x%x\n",ntohs(headerTCP->th_sum) );
		printf("Urgent Pointer: %d\n",ntohs(headerTCP->th_urp) );


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
		//On regarde si il y a de la data restante
		if(TCPSize+EtherSize+IpSize != header->len){

			switch(ntohs(headerTCP->th_dport)) {
				case FTPC:
					printf("\n");
				    printf("\033[4m\033[34m#FTPC \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case FTPS:
					printf("\n");
				    printf("\033[4m\033[34m#FTPS \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case SSH:
					printf("\n");
				    printf("\033[4m\033[34m#SSH \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case TELNET:
					PrintHeaderTelnet(TCPSize+EtherSize+IpSize, packet,header);
					PrintPacketManyTimes = 1;
					break;
				case SMTP:
					printf("\n");
				    printf("\033[4m\033[34m#SMTP \033[0m\n\n");
				    printPaquetTCPASCII(header,packet,TCPSize+EtherSize+IpSize);
					//printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case DNS:
					printf("\n");
				    printf("\033[4m\033[34m#DNS (query)\033[0m\n\n");
					PrintHeaderDNS(EtherSize, IpSize, TCPSize,packet, Verbosite,header);
					PrintPacketManyTimes = 1;
					break;
				case HTTP:
					printf("\n");
				    printf("\033[4m\033[34m#HTTP \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case HTTPS:
					printf("\n");
				    printf("\033[4m\033[34m#HTTPS \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case POP3:
					printf("\n");
				    printf("\033[4m\033[34m#POP3 \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case IMAP:
					printf("\n");
				    printf("\033[4m\033[34m#IMAP \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
			}
			switch(ntohs(headerTCP->th_sport)) {
				case FTPC:
					printf("\n");
				    printf("\033[4m\033[34m#FTPC \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case FTPS:
					printf("\n");
				    printf("\033[4m\033[34m#FTPS \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case SSH:
					printf("\n");
				    printf("\033[4m\033[34m#SSH \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case TELNET:
					PrintHeaderTelnet(TCPSize+EtherSize+IpSize, packet,header);
					PrintPacketManyTimes = 1;
					break;
				case SMTP:
					printf("\n");
				    printf("\033[4m\033[34m#SMTP \033[0m\n\n");
				    printPaquetTCPASCII(header,packet,TCPSize+EtherSize+IpSize);
					//printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case DNS:
					printf("\n");
				    printf("\033[4m\033[34m#DNS (response)\033[0m\n\n");
					PrintHeaderDNS(EtherSize, IpSize, TCPSize,packet, Verbosite,header);
					PrintPacketManyTimes = 1;
					break;
				case HTTP:
					printf("\n");
				    printf("\033[4m\033[34m#HTTP \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case HTTPS:
					printf("\n");
				    printf("\033[4m\033[34m#HTTPS \033[0m\n\n\t");

					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case POP3:
					printf("\n");
				    printf("\033[4m\033[34m#POP3 \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
				case IMAP:
					printf("\n");
				    printf("\033[4m\033[34m#IMAP \033[0m\n\n\t");
					printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
					PrintPacketManyTimes = 1;
					break;
			}
			if(PrintPacketManyTimes == 0){
				printPaquetTCPHA(header,packet,TCPSize+EtherSize+IpSize);
			}
			
		}
	}
	//return TCPSize;
}