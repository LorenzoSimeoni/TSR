#include "ARP.h"


/*
  Cette fonction permet d'afficher l'en tête ARP
*/
void PrintHeaderARP(int EtherSize, const u_char *packet) {

  struct ether_arp *headerARP;
  headerARP = (struct ether_arp*)(packet+EtherSize);
  //int ARPSize = sizeof(struct ether_arp);
  struct arphdr hA;
  hA =  headerARP->ea_hdr;

  printf("\033[0mHardware type %.2x\n",ntohs(hA.ar_hrd));
  if(ntohs(hA.ar_pro) == 0x0800 ) {
    printf("Protocol type: IPV4 (%.2x)\n",ntohs(hA.ar_pro));
  }
  else {
    printf("Protocol type %.2x\n",ntohs(hA.ar_pro) );
  }
  printf("Hardware Address Length %u\n",hA.ar_hln );
  printf("Protocol Address Length %u\n",hA.ar_pln );
  printf("Operation %.2x\n",ntohs(hA.ar_op) );

  u_char *ptr;
  int i;

  //Permet d'afficher les adresse MAC sous la forme ..:..:..:..:..:..
  //J'ai découvert qu'une fonction éxistait faisant la même chose mais bon trop tard
  ptr = headerARP->arp_sha;
  i = ETH_ALEN;
  printf("Sender Hardware Address: ");
  do{
      if(i==ETH_ALEN) {
          printf(" ");
          printf("%x",*ptr++);
      }
      else {
          printf(":");
          printf("%x",*ptr++);
      }
  }while(--i>0);
  printf("\n");


  //Permet d'afficher les adresse IP sous la forme 111.111.111.111
  ptr = headerARP->arp_spa;
  i = 4;
  printf("Sender Protocol Adresse: ");
  do{
      if(i==4) {
          printf(" ");
          printf("%d",*ptr++);
      }
      else {
          printf(".");
          printf("%d",*ptr++);
      }
  }while(--i>0);
  printf("\n");

  //Pareil que plus haut, affichage de l'adresse mac de la Target
  ptr = headerARP->arp_tha;
  i = ETH_ALEN;
  printf("Target Hardware Adresse: ");
  do{
      if(i==ETH_ALEN) {
          printf(" ");
          printf("%x",*ptr++);
      }
      else {
          printf(":");
          printf("%x",*ptr++);
      }
  }while(--i>0);
  printf("\n");



  //Affichage de l'adresse IP de la target
  ptr = headerARP->arp_tpa;
  i = 4;
  printf("Target Protocol Adresse: ");
  do{
      if(i==4) {
          printf(" ");
          printf("%d",*ptr++);
      }
      else {
          printf(".");
          printf("%d",*ptr++);
      }
  }while(--i>0);
  printf("\n");

}