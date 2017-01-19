#include "Telnet.h"


/*
	Permet d'afficher les options Telnet, On cherche d'abord un ff puis on affiche les options principales
	(celles vu en cour). Les sous options ne sont pas encore traitées...
*/
void PrintHeaderTelnet(int payload ,const u_char *packet,const struct pcap_pkthdr *header) {
	
    printf("\n");
    printf("\033[4m\033[36m#TELNET\033[0m \n\n");

    //int j = 0;

    int compteurPourSousOptions = payload;
 	for(payload = payload; payload < header->len; payload++) {
 		//printf("\033[0m%.2x",packet[k]);
 		if(compteurPourSousOptions == payload ){
 			compteurPourSousOptions++;
	 		if(packet[payload-1] == TCIAC || packet[payload-2] == TCIAC) {
		 		switch(packet[payload]) {
		 			case TCSB:
		 				printf("Start Subnegotiation ");
		 				break;
		 			case TCSE:
		 				printf("End of Subnegociation ");
		 				break;
		 			case TCNOP:
		 				printf("No Operation ");
		 				break;
		 			case TCDM:
		 				printf("Data Mark ");
		 				break;
		 			case TCBRK:
		 				printf("NVT Character BRK ");
		 				break;
		 			case TCIP:
		 				printf("Interrupt Process ");
		 				break;
		 			case TCAO:
		 				printf("Abort Output	");
		 				break;
		 			case TCAYT:
		 				printf("Are You There? ");
		 				break;
		 			case TCEC:
		 				printf("Erase Character ");
		 				break;
		 			case TCEL:
		 				printf("Erase Line ");
		 				break;
		 			case TCGA:
		 				printf("go ahead ");
		 				break;
		 			case TCWILL:
		 				printf("will ");
		 				break;
		 			case TCWONT:
		 				printf("won't ");
		 				break;
		 			case TCIAC:
		 				printf("IAC ");
		 				break;
		 			case TCDO:
		 				printf("do ");
		 				break;
		 			case TCDONT:
		 				printf("don't ");
		 				break;
		 			case TOTXBINARY:
		 				printf("binary transmission ");
		 				break;
		 			case TOECHO:
		 				printf("echo ");
		 				break;
		 			case TONOGA:
		 				printf("suppress go ahead ");
		 				break;
		 			case TOTERMTYPE:
		 				printf("terminal type ");
		 				break;
		 			case TOWINDOWSIZE:
		 				printf("window size ");
		 				break;
		 			case TOTERMINALSPEED:
		 				printf(" terminal speed ");
		 				break;
		  			case TOLINEMODE:
		  				printf("line mode ");
		 				break;
		  			case TONEWENVOPT:
		  				printf("New environment option");
		 				break;
		  			default:
		  				if(packet[payload]>31 && packet[payload]<=127){
				 			printf("\033[0m%c", packet[payload]);
				 		}
				 		else {
				 			printf("\033[0m.");
				 		}
		 				break;
		 		}
	 		}
		 		
	 		else {

		 		if(packet[payload] == TCIAC) {
		 			printf("IAC ");
		 		}
		 		else if(packet[payload]==13){
		 			printf("\n");
		 		}
		 		else if(packet[payload]==10){
		 			printf(" ");
		 		}
				else if(packet[payload]>31 && packet[payload]<=127){
		 			printf("\033[0m%c", packet[payload]);
		 		}

		 		else {
		 			printf("\033[0m.");
		 		}
	 		}
 		}
 		else {
 			//compteurPourSousOptions++;
 			//printf("Salut\n" );
 		}

 	}	
 	printf("\n");
	
}