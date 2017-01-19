all: AnalyseurReseau.o IP.o Ethernet.o TCP.o UDP.o ARP.o BOOTP.o Telnet.o DNS.o
	gcc -Wall AnalyseurReseau.o IP.o Ethernet.o TCP.o UDP.o ARP.o BOOTP.o Telnet.o DNS.o -o AnalyseurReseau -lpcap

AnalyseurReseau.o: AnalyseurReseau.c Ethernet.h
	gcc -Wall -c AnalyseurReseau.c -o AnalyseurReseau.o -lpcap

Ethernet.o: Ethernet.c IP.h ARP.h Ethernet.h
	gcc -Wall -c Ethernet.c -o Ethernet.o

IP.o: IP.c UDP.h TCP.h BOOTP.h IP.h
	gcc -Wall -c IP.c -o IP.o

UDP.o: UDP.c UDP.h BOOTP.h Telnet.h dns.h
	gcc -Wall -c UDP.c -o UDP.o

TCP.o: TCP.c TCP.h BOOTP.h Telnet.h
	gcc -Wall -c TCP.c -o TCP.o

ARP.o: ARP.c ARP.h
	gcc -Wall -c ARP.c -o ARP.o

BOOTP.o: BOOTP.c BOOTP.h
	gcc -Wall -c BOOTP.c -o BOOTP.o

Telnet.o: Telnet.c Telnet.h
	gcc -Wall -c Telnet.c -o Telnet.o

DNS.o: DNS.c dns.h
	gcc -Wall -c DNS.c -o DNS.o

# suppression des fichiers temporaires
clean:

	rm -rf *.o