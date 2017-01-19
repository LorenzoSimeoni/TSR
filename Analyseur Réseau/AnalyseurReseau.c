/*
Pour compiler :
	Make
*/




#include "Ethernet.h"
#include <unistd.h>
#include <ctype.h>


#define TAILLE_LIGNE 100


void callbackFonction1(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void callbackFonction2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void callbackFonction3(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printPaquet(const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv)
{
	char *dev= NULL; 
	char *net; 
	char *mask;
	int ret;  
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp; 
	bpf_u_int32 maskp;
	struct in_addr addr;
	const u_char *packet;
	struct pcap_pkthdr header; 
	pcap_t *ReseauFillaire;
	struct bpf_program filter; 
	char *fichier=NULL;


	//Cette Partie jusqu'a la fin du while permet de gérer les arguments, -i -v...
	char *vvalue = NULL;
	char *ivalue = NULL;
	char *ovalue = NULL;
	char *fvalue = NULL;
	int option;
	opterr = 0;
	int Verbosite = 0;
	while((option = getopt(argc, argv, "f:o:i:v:"))!=-1)
		switch(option)
		{
			case 'v':
			vvalue = optarg;
			Verbosite = atoi(vvalue);
			break;
			case 'i':
				ivalue = optarg;
				dev = ivalue;
			break;
			case 'o':
				ovalue = optarg;
				fichier = ovalue;
			break;
			case 'f':
				fvalue = optarg;
			break;
			//Si il manque un argument ou si on met une mauvaise option
			case '?':
				if (optopt == 'v')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if(optopt == 'i')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if(optopt == 'o')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if(optopt == 'f')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
				return 1;
			default:
				abort ();
		}

	//Si on travaille sur un fichier contenant des trames
	if(fichier != NULL) {

		/*
			On vérifie qu'il n'y a pas de problème quand on regarde le fichier pour trouver les trames
		*/
		ReseauFillaire = pcap_open_offline(fichier, errbuf);
		if (ReseauFillaire == NULL) {
			fprintf(stderr, "Couldn't open file %s: %s\n", fichier, errbuf);
			exit(1);
		}
		/*
			On regarde le fichier tant qu'il n'est pas nul
			Utilisation de pcap_next au lieu de pcap_loop parce que pcap loop il faut préciser le nombre
			de paquets et que la on ne sait pas		
		*/
		while((packet = pcap_next(ReseauFillaire, &header)) != NULL) {

			/*
				Appel la première fonction d'analyse d'header avec le packet et la Verbosité voulue.
			*/
			PrintHeaderEthernet(packet,Verbosite,&header);

		}
		pcap_close(ReseauFillaire);
	}
	//Si on travaille sur une interface Réseau
	else if(fichier == NULL) {

		//Verifie qu'on a bien passé en argument une interface
		if(dev == NULL)
		{
			printf("Vous devez donner une interface!!\n");
			printf("Les liste des interfaces disponibles est la suivante: \n");
			pcap_if_t *interfaces,*temp;
		    int i=0;
		    /*
				Permet de donner toutes les interfaces disponibles sur l'ordinateur
		    */
		    if(pcap_findalldevs(&interfaces,errbuf)==-1)
		    {
		        printf("\nerror in pcap findall devs");
		        return -1;   
		    }

		    for(temp=interfaces;temp;temp=temp->next)
		    {
		        printf("%d  :  %s\n",i++,temp->name);
		       
		    }
		    pcap_freealldevs(interfaces);
		    pcap_freealldevs(temp);
			exit(1);
		}
		//affiche l'interface
		printf("DEV: %s\n",dev);

		//Permet d'avoir L'adresse ip et le netmask de l'interface
		ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);
		//Si on met une mauvaise interface il nous le dit ici
		if(ret == -1)
		{
			printf("%s\n",errbuf);
			exit(1);
		}
		//pour afficher l'adresse IP de l'interface :)
		addr.s_addr = netp;
		net = inet_ntoa(addr);
		if(net == NULL)
		{
			perror("inet_ntoa");
			exit(1);
		}
		printf("NET: %s\n",net);
		//Pour afficher le masque de sous réseau!
		addr.s_addr = maskp;
		mask = inet_ntoa(addr);
		if(mask == NULL)
		{
			perror("inet_ntoa");
			exit(1);
		}
		printf("MASK: %s\n",mask);



		ReseauFillaire=pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);//sniffe le nombre de bytes précisés dans le BUFSIZ
		if(ReseauFillaire==NULL){
			printf("pcap_open_live(): %s\n",errbuf);
			exit(1);
		}

		/*
			Si on a choisi de rajouter un filtre
		*/
		if(fvalue != NULL){
			pcap_compile(ReseauFillaire, &filter, fvalue, 1, netp);

			pcap_setfilter(ReseauFillaire, &filter);		
		}

		/*
			Permet de faire le choix de la verbosité, je crois qu'on aurait aussi pu le mettre en dernier 
			argument mais je n'étais pas sur donc j'ai fais ce if
		*/
		if(Verbosite == 1){
			if(pcap_loop(ReseauFillaire,-1, callbackFonction1, NULL)==-1){//Permet d'appeler la callback fonction de Cerbosité 1
				perror("pcap_loop");
				exit(1);
			}
		}
		else if(Verbosite == 2){
			if(pcap_loop(ReseauFillaire,-1, callbackFonction2, NULL)==-1){//Permet d'appeler la callback fonction de Verbosité 2
				perror("pcap_loop");
				exit(1);
			}
		}
		else if(Verbosite == 3){
			if(pcap_loop(ReseauFillaire,-1, callbackFonction3, NULL)==-1){//Permet d'appeler la callback fonction de Verbosité 3
				perror("pcap_loop");
				exit(1);
			}
		}
		else {
			printf("Cette verbosité n'existe pas \n");
		}



		//Fermeture de la capture
		pcap_close(ReseauFillaire);
	}

	return 0;
}


/*
	Les fonctions appellent la première fonction qui montre le headerEthernet
*/
void callbackFonction1(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	PrintHeaderEthernet(packet,1,header);
}
void callbackFonction2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	PrintHeaderEthernet(packet,2,header);
}
void callbackFonction3(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	//printPaquet(header, packet);
	PrintHeaderEthernet(packet,3,header);
}

/*
	Fonction permettant d'afficher un paquet en hexa,
	on met un espace tous les 4 chiffres en hexa, et on met
	à la ligne tous les 14 chiffres
*/
void printPaquet(const struct pcap_pkthdr *header, const u_char *packet) {
 	int k = 0;
	printf("\n");
	printf("*************************************************************************************\n");
	printf("\n");
	printf("\033[4m\033[34m#PACKET \n\t");
	int i = 0;
	int j = 0;
	for(k=0; k<header->len; k++) {
		printf("\033[0m%.2x",packet[k]);
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
