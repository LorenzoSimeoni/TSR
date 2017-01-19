#include "Ethernet.h"


/*
Cette fonction permet d'afficher l'en tête ethernet, de voir si on a affaire à un type ARP, IPV4,  ou autre, et d'appeler 
une fonction pour l'entête suivante en conséquence
*/
void PrintHeaderEthernet(const u_char *packet,int Verbosite,const struct pcap_pkthdr *header) {

    printf("\n");
    printf("*************************************************************************************\n");
    printf("\n");

    /*
        On place le pointeur de la structure sur le début du packet
    */
    struct ether_header *headerEthernet;
    headerEthernet = (struct ether_header *) packet;
    int EtherSize = sizeof(struct ether_header);
    u_char *ptr;
    int i;

    /*
        Permet de compter le nombre de paquets qui passent pendant la simulation
    */
    static int count = 1;

    if(Verbosite == 1){
        /*
            On print le type de la couche supèrieur. ntohs permet de remttre les bits dans l'ordre.
        */
        if (ntohs (headerEthernet->ether_type) == ETHERTYPE_IP)
        {
            PrintHeaderIP(EtherSize,packet,Verbosite,header);
        }
        else if (ntohs(headerEthernet->ether_type) == ETHERTYPE_ARP) {
            PrintHeaderARP(EtherSize, packet);
        }
        else {
            printf("Paquet non traité par l'analyseur \n");
        }

    }
    if(Verbosite == 2){
        printf("Packet Number : %d\n",count);
        count++;
        //Permet de repérer si on a un paquet ipv4
        if (ntohs (headerEthernet->ether_type) == ETHERTYPE_IP)
        {
            printf("Ethernet type hex:%x dec:%d is an IPv4 packet\n",
                    ntohs(headerEthernet->ether_type),
                    ntohs(headerEthernet->ether_type));
            PrintHeaderIP(EtherSize,packet,Verbosite,header);


        }
        //Permet de repérer si on a une requète ARP
        else  if (ntohs (headerEthernet->ether_type) == ETHERTYPE_ARP)
        {
            printf("\033[0mEthernet type hex:%x dec:%d is an ARP packet\n",
                    ntohs(headerEthernet->ether_type),
                    ntohs(headerEthernet->ether_type));
            PrintHeaderARP(EtherSize, packet);
        }
        //Repère si on a un autre paquet, et quitte si c'est le cas
        else {
            printf("\033[0mEthernet type hex:%x dec:%d autre type de paquets\n", ntohs(headerEthernet->ether_type),ntohs(headerEthernet->ether_type));
            printf("Paquet non traité par l'analyseur \n");
        }

    }

    if(Verbosite == 3){
        printf("\033[4m\033[33m#EN TETE ETHERNET\n");

        //Donne le nombre de paquets qui sont passés
        printf("\033[0mPacket Number : %d\n",count);
        count++;
        //Permet de Repérer si c'est un paquet IP
        if (ntohs (headerEthernet->ether_type) == ETHERTYPE_IP)
        {
            printf("Ethernet type hex:%x dec:%d is an IPv4 packet\n",
                    ntohs(headerEthernet->ether_type),
                    ntohs(headerEthernet->ether_type));


        }
        //Permet de repérer si on a une requète ARP
        else  if (ntohs (headerEthernet->ether_type) == ETHERTYPE_ARP)
        {
            printf("\033[0mEthernet type hex:%x dec:%d is an ARP packet\n",
                    ntohs(headerEthernet->ether_type),
                    ntohs(headerEthernet->ether_type));
        }
        //Repère si on a un autre paquet, et quitte si c'est le cas
        else {
            printf("\033[0mEthernet type hex:%x dec:%d autre type de paquets\n", ntohs(headerEthernet->ether_type),ntohs(headerEthernet->ether_type));
        }

        /*
            Permet d'afficher l'adresse MAC de destination
            On fait une boucle while pour pouvoir rajouter les ":" entre les chiffres en hexa
        */
        ptr = headerEthernet->ether_dhost;
        i = ETHER_ADDR_LEN;
        printf(" Destination Address:  \n");
        do{
            if(i==ETHER_ADDR_LEN) {
                printf(" ");
                printf("%x",*ptr++);
            }
            else {
                printf(":");
                printf("%x",*ptr++);
            }
            //printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);
        printf("\n");

        //Permet d'afficher l'adresse MAC source
        ptr = headerEthernet->ether_shost;
        i = ETHER_ADDR_LEN;
        //printf("ETHER_ADDR_LEN %d\n",i);
        printf(" Source Address:  \n");
        do{
            if(i==ETHER_ADDR_LEN) {
                printf(" ");
                printf("%x",*ptr++);
            }
            else {
                printf(":");
                printf("%x",*ptr++);
            }
         //   printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
        }while(--i>0);
        printf("\n");

        /*
            Permet de savoir quelle fonction appeler ensuite, en fonction de l'ether type
            Si l'ether type n'est pas connu on le dit et et on passe donc au paquet suivant
        */
        if (ntohs (headerEthernet->ether_type) == ETHERTYPE_IP)
        {
            printf("\n");
            
            printf("\033[4m\033[31m#EN TETE IP\n");
            PrintHeaderIP(EtherSize,packet,Verbosite,header);
        }
        else if (ntohs(headerEthernet->ether_type) == ETHERTYPE_ARP) {
            printf("\n");
            
            printf("\033[4m\033[31m#EN TETE ARP\n");
            PrintHeaderARP(EtherSize, packet);
        }
        else {
            printf("Paquet non traité par l'analyseur \n");
        }
    }

}