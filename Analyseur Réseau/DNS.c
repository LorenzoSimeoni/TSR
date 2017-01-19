#include "dns.h"



/*
	Permet d'afficher l'en tête de Base de DNS
	Le reste est afficher en ASCII plus bas
*/
void PrintHeaderDNS(int EtherSize, int IpSize,int Couche4Size,const u_char *packet,int Verbosite,const struct pcap_pkthdr *header) {

	dns_header_t *headerDNS;
	headerDNS = (dns_header_t*)(packet+EtherSize+IpSize+Couche4Size);
	int SizeDNS = sizeof(dns_header_t);

	printf("Transaction ID: 0x%x\n", ntohs(headerDNS->xid));
	printf("Flags: 0x%x\n", ntohs(headerDNS->flags));

	/*
		Dans cette partie on va regarder les flags présents dans le 
		paquet DNS. Le design est clairement inspiré de celui de wireshark
		Tous les define sont dans dns.h
	*/
	if(ntohs(headerDNS->flags) & DNS_FLAGS_QR_REPLY) {
		printf("1... .... .... .... = Response: Message is a response\n");
	}
	else{
		printf("0... .... .... .... = Response: Message is a query\n");
	}

	if(ntohs(headerDNS->flags) & DNS_FLAGS_QUERY_INVERSE) {
		printf(".000 1... .... .... = Opcode: Reverse query(1)\n");
	}
	else if(ntohs(headerDNS->flags) & DNS_FLAGS_QUERY_STATUS) {
		printf(".001 0... .... .... = Opcode: Status of a server request(2)\n");
	}
	else if(ntohs(headerDNS->flags) & DNS_FLAGS_OPCODE_MASK && ntohs(headerDNS->flags) & DNS_FLAGS_QUERY_STATUS) {
		printf(".001 1... .... .... = Reserved\n");
	}
	else{
		printf(".000 0... .... .... = Opcode: Standart query(0)\n");
	}
	if(ntohs(headerDNS->flags) & DNS_FLAGS_AA) {
		printf(".... .1.. .... .... = Authoritative: Server is an authority for domain\n");
	}
	else{
		printf(".... .0.. .... .... = Authoritative: Server is not an authority for domain\n");
	}
	if(ntohs(headerDNS->flags) & DNS_FLAGS_TC) {
		printf(".... ..1. .... .... = Truncated: Message is truncated\n");
	}
	else{
		printf(".... ..0. .... .... = Truncated: Message is not truncated\n");
	}
	if(ntohs(headerDNS->flags) & DNS_FLAGS_RD) {
		printf(".... ...1 .... .... = Recursion desired: Do query recursively\n");
	}
	else{
		printf(".... ...0 .... .... = Recursion not desired: Do not query recursively\n");
	}

	if(ntohs(headerDNS->flags) & DNS_FLAGS_QR_REPLY){
		if(ntohs(headerDNS->flags) & DNS_FLAGS_RA) {
			printf(".... .... 1... .... = Recursion available: Server can do recursive queries\n");
		}
		else{
			printf(".... .... 0... .... = Recursion unavailable: Server can't do recursive queries\n");
		}

		if((ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_FORMAT_ERROR) && (ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_SERVER_FAILURE) 
			&& (ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_NOT_IMPLEMENTED) && (ntohs(headerDNS->flags) & DNS_FLAGS_M)) {
			printf(".... .... .... 1111 = reserved (6-15) \n ");
		}
		else if(ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_NOT_IMPLEMENTED && ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_FORMAT_ERROR) {
			printf(".... .... .... 0101 = Reply code: Refusal(5) \n");
		}
		else if(ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_SERVER_FAILURE && ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_FORMAT_ERROR) {
			printf(".... .... .... 0011 = Reply code: No such name(3) \n");
		}
		else if(ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_FORMAT_ERROR) {
			printf(".... .... .... 0001 = Reply code: No such format(1) \n");
		}
		else if(ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_SERVER_FAILURE) {
			printf(".... .... .... 0010 = Reply code: Server failure(2) \n");
		}

		else if(ntohs(headerDNS->flags) & DNS_FLAGS_RCODE_NOT_IMPLEMENTED) {
			printf(".... .... .... 0100 = Reply code: Not implemented(4) \n");
		}
		else {
			printf(".... .... .... 0000 = Reply code: No error(0) \n");
		}
	}

	printf("\n");
	printf("Questions: %d\n", ntohs(headerDNS->qdcount));
	printf("Answer RRs: %d\n", ntohs(headerDNS->ancount));
	printf("Authority RRs: %d\n", ntohs(headerDNS->nscount));
	printf("Additional RRs: %d\n", ntohs(headerDNS->arcount));

	int j = 0;
 	printf("\033[4m\033[35mASCII:\n\t");
 	int k = 0;
 	//On affiche le reste en ASCII
 	for(k=EtherSize+IpSize+Couche4Size+SizeDNS; k<header->len; k++) {
 		//sprintf(str,"%d",packet[k]);
 		if(packet[k]>31 && packet[k]<=127){
 			printf("\033[0m%c", packet[k]);
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
 	printf("\n");

}