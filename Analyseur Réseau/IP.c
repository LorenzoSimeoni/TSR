#include "IP.h"


/*
cette fonction va permettre d'afficher l'en tête IP, regarder si la couche 4 est en UDP 
ou TCP, et d'appeler la fonction correspondante 

*/
void PrintHeaderIP(int EtherSize, const u_char *packet, int Verbosite,const struct pcap_pkthdr *header) {


    /*
      On place le pointeur de la structure sur le début de l'en tête IP (grâce au +Ethersize)
    */
    struct ip *headerIP;
    headerIP = (struct ip*)(packet+EtherSize);
    //int IpSize = sizeof(struct ip);

    //La taille vaut 4 (octets) * le chiffre donné dans ip_hl
    int IpSize = 4*headerIP->ip_hl;

    if(Verbosite == 1){
      if(headerIP->ip_p == 17){
        printf("UDP ");
      }
      else if(headerIP->ip_p == 6){
        printf("TCP ");
      }
      else if(headerIP->ip_p == ICMP) {
         printf("ICMP ");
      }
      else if(headerIP->ip_p == IGMP) {
         printf("IGMP ");
      }
      else {
        printf("%x ",headerIP->ip_p);
      }
      //On print l'adresse IP source et destination (int_ntoa permet de transformer la valeur en adresse IP)
      char *ipAdresse = inet_ntoa(headerIP->ip_src);
      printf("%s ", ipAdresse);
      ipAdresse = inet_ntoa(headerIP->ip_dst);
      printf("%s ", ipAdresse);

      /*
        On trouve quel est le protocol de la couche suivante et on appelle la fonction
        correspondante (si il y en a une)
      */
      if(headerIP->ip_p == UDP){
        PrintHeaderUDP(EtherSize,IpSize,packet,Verbosite,header);
      }
      else if(headerIP->ip_p == TCP) {
        PrintHeaderTCP(EtherSize,IpSize,packet,Verbosite,header);
      }
    }


    else if(Verbosite == 2){

      if(headerIP->ip_p == 17){
        printf("Protocol : UDP \n");
      }
      else if(headerIP->ip_p == 6){
        printf("Protocol : TCP \n");
      }
      else if(headerIP->ip_p == ICMP) {
         printf("Protocol : ICMP\n");
      }
      else if(headerIP->ip_p == IGMP) {
         printf("Protocol : IGMP\n");
      }
      else {
        printf("Protocol : %u\n",headerIP->ip_p);
      }

      //On print l'adresse IP source et destination (int_ntoa permet de transformer la valeur en adresse IP)
      char *ipAdresse = inet_ntoa(headerIP->ip_src);
      printf("Source Address %s \n", ipAdresse);
      ipAdresse = inet_ntoa(headerIP->ip_dst);
      printf("Destination Address %s\n", ipAdresse);

      /*
        On trouve quel est le protocol de la couche suivante et on appelle la fonction
        correspondante (si il y en a une)
      */
      if(headerIP->ip_p == UDP){
        PrintHeaderUDP(EtherSize,IpSize,packet,Verbosite,header);
      }
      else if(headerIP->ip_p == TCP) {
        PrintHeaderTCP(EtherSize,IpSize,packet,Verbosite,header);
      }
    }


    else if(Verbosite == 3){

      /*
        On print tout ce que contient notre structure
      */
      printf("\033[0mVersion %u\n",headerIP->ip_v);
      printf("IHL %u\n",headerIP->ip_hl );
      printf("Type of service %u\n", headerIP->ip_tos);
      printf("Total lenght %d\n", ntohs(headerIP->ip_len));
      printf("Identification %x (%d)\n",ntohs(headerIP->ip_id), ntohs(headerIP->ip_id) );

      //Affiche les flags IP 
      if(ntohs(headerIP->ip_off) & IP_RF) {
        printf("Flag: Reserved Fragment \n");
      }
      else if(ntohs(headerIP->ip_off) & IP_DF) {
        printf("Flag: Don't Fragment \n");
      }
      else if(ntohs(headerIP->ip_off) & IP_MF) {
        printf("Flag: More Fragment \n");
      }
      else if(ntohs(headerIP->ip_off) & IP_OFFMASK) {
        printf("Flag: mask for fragmenting bits \n");
      }

      printf("Fragment Offset %.2x\n",ntohs(headerIP->ip_off) );
      printf("TTL %u\n",headerIP->ip_ttl );
      
      /*
        On print le protocol utilisé si il est connu
      */
      printf("Protocol %u",headerIP->ip_p );


      if(headerIP->ip_p == UDP) {
        printf(" UDP");
      }
      else if(headerIP->ip_p == TCP) {
        printf(" TCP");
      }
      else if(headerIP->ip_p == ICMP) {
         printf(" ICMP");
      }
      else if(headerIP->ip_p == IGMP) {
         printf(" IGMP");
      }

      printf("\n");
      printf("Header Checksum hex:%x dec:%d\n",ntohs(headerIP->ip_sum),ntohs(headerIP->ip_sum) );
      char *ipAdresse = inet_ntoa(headerIP->ip_src);
      printf("Source Address %s\n", ipAdresse);
      ipAdresse = inet_ntoa(headerIP->ip_dst);
      printf("Destination Address %s\n", ipAdresse);

      /*
        On trouve quel est le protocol de la couche suivante et on appelle la fonction
        correspondante (si il y en a une)
      */
      if(headerIP->ip_p == UDP){
        printf("\n");
        
        printf("\033[4m\033[32m#EN TETE UDP \033[0m \n");

        PrintHeaderUDP(EtherSize,IpSize,packet,Verbosite,header);
      }
      else if(headerIP->ip_p == TCP) {
        printf("\n");
      
        printf("\033[4m\033[32m#EN TETE TCP \033[0m\n");
        PrintHeaderTCP(EtherSize,IpSize,packet,Verbosite,header);

      }
    }

}