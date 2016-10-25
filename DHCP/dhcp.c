/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

  unsigned char buff1[BUFFSIZE]; // buffer de recepcao

  int sockd;
  int on;
  struct ifreq ifr;

int main(int argc,char *argv[])
{
    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "wlp7s0");
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);
	int next_p;
	int ip_h_size;
	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		
		if(buff1[12] == 0x08 && buff1[13] == 0x00){ //IP
			
			if(buff1[23] == 0x11){ //UDP
				ip_h_size =(int) (4*(buff1[14]-0x40)); //em bytes
				next_p = 14 + ip_h_size;

				if(buff1[next_p+3] == 0x43){
					if(buff1[next_p+250] == 0x01){
						printf("DHCP Discover \n",buff1[next_p+3],buff1[next_p+250]);

						printf("MAC Address: %x:%x:%x:%x:%x:%x \n",buff1[next_p+254],buff1[next_p+255],buff1[next_p+256],buff1[next_p+257],buff1[next_p+258],buff1[next_p+259]);
						
						printf("Host length: %x\n",buff1[next_p+261]);

						printf("Host name: ");
						int i;
						for(i=1;i<=buff1[next_p+261];i++){
							printf("%x:",buff1[next_p+261+i]);
						}
						printf("\n");
						
						/* NAO PODE SER ASSIM
						Deve ser feito uma leitura dos campos de opçoes dinamicamente
						pois eles possuem um identificador */

						printf("-------------------------------\n");
					}else{

						printf("DHCP Request  \n",buff1[next_p+3],buff1[next_p+250]);
					}
				}
			}
		}


	}
}
