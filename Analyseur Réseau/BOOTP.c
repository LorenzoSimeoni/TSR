#include "BOOTP.h"

/*
	Permet de print l'header BOOTP 
	Si on a DHCP, j'ai mis les options qu'on avait dans le cahier mais pas toutes
*/
void PrintHeaderBOOTP(int EtherSize, int IpSize,int Couche4Size,const u_char *packet,int Verbosite,const struct pcap_pkthdr *header) {
	

	struct bootp *headerBOOTP;
	headerBOOTP = (struct bootp*)(packet+EtherSize+IpSize+Couche4Size);

	if(Verbosite == 1){
		printf(" %d ", headerBOOTP->bp_op);
		if(headerBOOTP->bp_op==BOOTREPLY) {
			printf("(Reply)");
		}
		else if(headerBOOTP->bp_op==BOOTREQUEST) {
			printf("(Request)");
		}
	}
	if(Verbosite == 2 || Verbosite==3){
		printf("Packet opcode type: %d ", headerBOOTP->bp_op);
		if(headerBOOTP->bp_op==BOOTREPLY) {
			printf("(Reply)");
		}
		else if(headerBOOTP->bp_op==BOOTREQUEST) {
			printf("(Request)");
		}
		printf("\n");
	}
	if(Verbosite == 3){

	printf("Hardware addr type: %d\n", headerBOOTP->bp_htype);
	printf("Hardware addr length: %d\n", headerBOOTP->bp_hlen );
	printf("Gateway hops: %d\n", headerBOOTP->bp_hops);
	printf("Transaction ID: %.2x\n", ntohl(headerBOOTP->bp_xid) );
	printf("Second since boot began: %d\n", ntohs(headerBOOTP->bp_secs));
	printf("Flags: %d\n", ntohs(headerBOOTP->bp_flags));

	char *ipAdresse = inet_ntoa(headerBOOTP->bp_ciaddr);
	printf("Client IP Address %s \n", ipAdresse);
	ipAdresse = inet_ntoa(headerBOOTP->bp_yiaddr);
	printf("'Your' IP Address %s\n", ipAdresse);
	ipAdresse = inet_ntoa(headerBOOTP->bp_siaddr);
	printf("Server IP Address %s\n", ipAdresse);
	ipAdresse = inet_ntoa(headerBOOTP->bp_giaddr);
	printf("Gateway IP Address %s\n", ipAdresse);

	printf("Client Hardware Address:");
	int i = 6;
	u_char *ptr;
	ptr = headerBOOTP->bp_chaddr;
	do{
	    if(i==6) {
			printf(" ");
			printf("%.2x",*ptr++);
		}
	    else {
			printf(":");
			printf("%.2x",*ptr++);
	    }
	}while(--i>0);
	printf("\n");	


	//Affiche le Host Name en Hexa et en ASCII à côté, ressemble en tout points aux fonctions 
	//printPaquetUDPHA et printPaquetTCPHA
	printf("Server Host Name: \n\t");
	int k = 0;
	ptr = headerBOOTP->bp_sname;
 	int j = 0;
 	int compteur = 0;
 	for(k=0; k<64; k++) {
  		printf("%.2x",ptr[k]);
 		i++;
 		j++;
 		if(j==14 || k == 64-1) {
 			printf("      ");
 			if(k==64-1) {
 				int nbespace = 14-64%14;
 				if(nbespace%2!=0){
 					nbespace--;
 				}
 				nbespace= nbespace + nbespace/2;
 				for(int espace=0;espace<nbespace;espace++){
 					printf("  ");
 				}
 			}
 			do
 			{
 				if(ptr[compteur]>31 && ptr[compteur]<=127){
		 			printf("%c", ptr[compteur]);
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
 		if(j==14) {
 			printf("\n\t");
 			j = 0;
 		}
 	}	
 	printf("\n");

 	j=0;
 	i=0;

 	//Pareil qu'au dessus on affiche en hexa puis en ASCII à côté
 	printf("Boot File Name: \n\t");
 	ptr = headerBOOTP->bp_file;
 	compteur = 0;
 	for(k=0;k<128;k++) {
  		printf("%.2x",ptr[k]);
 		i++;
 		j++;
 		if(j==14 || k == 128-1) {
 			printf("      ");
 			if(k==128-1) {
 				int nbespace = 14-128%14;
 				if(nbespace%2!=0){
 					nbespace--;
 				}
 				nbespace= nbespace + nbespace/2;
 				for(int espace=0;espace<nbespace;espace++){
 					printf("  ");
 				}
 			}
 			do
 			{
 				if(ptr[compteur]>31 && ptr[compteur]<=127){
		 			printf("%c", ptr[compteur]);
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
 		if(j==14) {
 			printf("\n\t");
 			j = 0;
 		}
 	}
 	printf("\n");

 	j=0;
 	i=0;
 	int tailleTrame = 0;
 	printf("Vendor Area:    \n");
 	ptr = headerBOOTP->bp_vend;
 	
 	//On vérifie que le magic cookie est bon
 	int DHCP = 0;
 	if(ptr[0]==((u_int8_t)  99) && ptr[1]==((u_int8_t)  130) && ptr[2]==((u_int8_t)  83) && ptr[3]==((u_int8_t)  99)){
 		DHCP = 1;
 	}
 	
 	//Si le magic cookie est bon, alors on regarde les fonctions DHCP
 	if(DHCP == 1){
 	printf("Magic Cookie : ");
 	for(k=0;k<4;k++){
 		printf("%x ", ptr[k]);
 	}
 	printf("\n");

 	//Va permettre d'afficher les options, puis de ne plus rien faire jusqu'a ce que k rattrape ce compteur
 	int LenghtOption=4;
 	int boucle = 0;
 	int index = 0;

 	/*
		A chaque option trouvé on va se décalé de L (ptr[LenghtOption+1] = ptr[k+1])
		en incrémentant LenghtOption.
		Une fois L atteind, on va remettre k à la valeur de LenghtOption sans chercher si il y a des options
 	*/
 	for(k=4;k<64;k++) {
 		//printf("k= %d LenghtOption = %d\n",k,LenghtOption);
 		if(LenghtOption == k && tailleTrame==0) {
		 	switch(ptr[k]) {
		 		case TAG_DHCP_MESSAGE:
		 			printf("DHCP message type: ");
		 			switch(ptr[LenghtOption + 2]) {
		 				case DHCPDISCOVER:
		 					printf("DISCOVER \n");
		 				break;
		 				case DHCPOFFER:
		 					printf("OFFER \n");
		 				break;
		 				case DHCPREQUEST:
		 					printf("REQUEST\n");
		 				break;
		 				case DHCPDECLINE:
		 					printf("DECLINE\n");
		 				break;
		 				case DHCPACK:
		 					printf("ACK\n");
		 				break;
		 				case DHCPNAK:
		 					printf("NACK\n");
		 				break;
		 				case DHCPRELEASE:
		 					printf("RELEASE\n");
		 				break;
		 				case DHCPINFORM:
		 					printf("INFORM\n");
		 				break;
		 			}
		 			LenghtOption = LenghtOption +2;
		 		break;
		 		case TAG_SUBNET_MASK:
		 			printf("Subnet Mask: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			index = 0;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption = LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_TIME_OFFSET:
		 			printf("Time Offset: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_GATEWAY:
		 			printf("Router: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_DOMAIN_SERVER:
		 			printf("DNS: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_HOSTNAME:
		 			printf("Host Name: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_DOMAINNAME:
		 			printf("Domain Name: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_BROAD_ADDR:
		 			printf("Broadcast Address: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_NETBIOS_NS:
		 			printf("netbios over TCP/IP name server: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_NETBIOS_SCOPE:
		 			printf("netbios over TCP/IP scope: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_REQUESTED_IP:
		 			printf("Requested IP Address: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_IP_LEASE:
		 			printf("Lease Time: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_SERVER_ID:
		 			printf("Server Identifier: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_PARM_REQUEST:
		 			printf("Parameter Request List: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_CLIENT_ID:
		 			printf("Client Identifier: ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 		case TAG_PAD:
		 		break;
		 		case TAG_END:
		 			printf("END \n");
		 			tailleTrame = 1;
		 		break;
		 		default:
		 			printf("Option Pas encore traitée par l'analyseur : ");
		 			boucle = ptr[LenghtOption + 1];
		 			LenghtOption++;
		 			for(index = 1; index < boucle+1 ; index++) {
		 				printf("%.2x",ptr[LenghtOption+index]);
		 			}
		 			LenghtOption=LenghtOption+boucle;
		 			printf("\n");
		 		break;
		 	}
		 	LenghtOption++;
 		}

 	}
 	}
 	/*
		Si le magic cookie n'est pas vérifié, on print en ASCII
 	*/
 	else{
 		j = 0;
	 	int k2=0;
	 	for(k2=0; k2<header->len; k2++) {
	 		//sprintf(str,"%d",packet[k]);
	 		if(packet[k2]>31 && packet[k2]<=127){
	 			printf("\033[0m%c", packet[k2]);
	 		}
	 		else {
	 			printf("\033[0m.");
	 		}
	  		j++;
	 		if(j==14) {
	 			printf("\n\t");
	 			j = 0;
	 		}
	 	}
 	}
 	printf("\n");
 }
}
