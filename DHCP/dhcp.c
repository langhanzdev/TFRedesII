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

  struct dhcpmessage
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    char chaddr[16];
    char sname[64];
    char file[128];
    char magic[4];
    char opt[3];
} __attribute__((__packed__));

void sendDHCP(){

	printf("Sending offer");
	//Variaveis para envio dos pacotes
	int sockfd,listenfd,connfd;
	const int on=1;
	struct sockaddr_in servaddr,cliaddr,rservaddr;

	if((sockfd=socket(AF_INET,SOCK_DGRAM,0)) < 0)
		printf("socket\n");
	if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0)
		printf("setsockopt\n");  

	if(setsockopt(sockfd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on)) < 0)
		printf("setsockopt\n");
	bzero(&servaddr,sizeof(servaddr));
	bzero(&cliaddr,sizeof(cliaddr));
	cliaddr.sin_port = htons(68);
	cliaddr.sin_family = AF_INET;
	cliaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(sockfd,(struct sockaddr*)&cliaddr,sizeof(cliaddr)) < 0)
		printf("bind\n");

	servaddr.sin_port = htons(67);
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("255.255.255.255");
	struct dhcpmessage dhcpmsg;
	bzero(&dhcpmsg,sizeof(dhcpmsg));
	dhcpmsg.op = 1;
	dhcpmsg.htype = 1;
	dhcpmsg.hlen = 6;
	dhcpmsg.hops = 0;
	dhcpmsg.xid = htonl(1000);
	dhcpmsg.secs = htons(0);
	dhcpmsg.flags = htons(0x8000);
	dhcpmsg.chaddr[0] = 0x00;
	dhcpmsg.chaddr[1] = 0x1A;
	dhcpmsg.chaddr[2] = 0x80;
	dhcpmsg.chaddr[3] = 0x80;
	dhcpmsg.chaddr[4] = 0x2C;
	dhcpmsg.chaddr[5] = 0xC3;
	dhcpmsg.magic[0]=99;
	dhcpmsg.magic[1]=130;
	dhcpmsg.magic[2]=83;
	dhcpmsg.magic[3]=99;
	dhcpmsg.opt[0]=53;
	dhcpmsg.opt[1]=1;
	dhcpmsg.opt[2]=1;
	if(sendto(sockfd,&dhcpmsg,sizeof(dhcpmsg),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
		printf("sendto\n");
}


int main(int argc,char *argv[])
{

	printf("-------------------------------------------------");
	printf("\nIniciando servidor DHCP...\n");

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

	printf("Servidor DHCP iniciado. Recebendo pacotes...\n");

	sendDHCP();	

	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		
		if(buff1[12] == 0x08 && buff1[13] == 0x00){ //IP
			
			if(buff1[23] == 0x11){ //UDP
				ip_h_size =(int) (4*(buff1[14]-0x40)); //em bytes
				next_p = 14 + ip_h_size;

				if(buff1[next_p+3] == 0x43){
					if(buff1[next_p+250] == 0x01){
						printf("DHCP Discover \n"/*,buff1[next_p+3],buff1[next_p+250]*/);

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

						printf("DHCP Request  \n"/*,buff1[next_p+3],buff1[next_p+250]*/);
					}
				}
			}
		}


	}
}
