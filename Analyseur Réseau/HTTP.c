#include "HTTP.h"

void PrintHeaderTCP(int EtherSize, int IpSize, int TCPSize,const u_char *packet,int Verbosite,const struct pcap_pkthdr *header) {

	struct tcphdr *headerTCP;
	headerTCP = (struct tcphdr*)(packet+EtherSize+IpSize);
	//int TCPSize = sizeof(struct tcphdr);
	int TCPSize = 4*headerTCP->th_off;

	if(Verbosite == 1) {
		printf("\n");
	}

	if(Verbosite == 2) {

	}

	if(Verbosite == 3) {

	}
}