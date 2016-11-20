/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1518

typedef unsigned char MacAddress[MAC_ADDR_LEN];
extern int errno;



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
    char opt[28];
} __attribute__((__packed__));

void sendOffer(int acao, char *mac){

	printf("Sending offer\n");
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
	if(acao == 0)
		servaddr.sin_addr.s_addr = inet_addr("255.255.255.255");
	else
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

	dhcpmsg.ciaddr = 0;
	dhcpmsg.yiaddr = inet_addr("192.168.0.28");
	dhcpmsg.siaddr = 0;
	dhcpmsg.giaddr = 0;

	dhcpmsg.chaddr[0] = mac[0];//0x00;
	dhcpmsg.chaddr[1] = mac[1];//0x1A;
	dhcpmsg.chaddr[2] = mac[2];//0x80;
	dhcpmsg.chaddr[3] = mac[3];//0x80;
	dhcpmsg.chaddr[4] = mac[4];//0x2C;
	dhcpmsg.chaddr[5] = mac[5];//0xC3;
	dhcpmsg.magic[0]=99;
	dhcpmsg.magic[1]=130;
	dhcpmsg.magic[2]=83;
	dhcpmsg.magic[3]=99;
	
	//DHCP Message Type
	dhcpmsg.opt[0]=53;
	dhcpmsg.opt[1]=1;
	if(acao == 0)
		dhcpmsg.opt[2]=2;
	else
		dhcpmsg.opt[2]=5;

	//DHCP Server Identifier
	dhcpmsg.opt[3]=54;
	dhcpmsg.opt[4]=4;
	dhcpmsg.opt[5]=192;
	dhcpmsg.opt[6]=168;
	dhcpmsg.opt[7]=0;
	dhcpmsg.opt[8]=10;

	//Mascara
	dhcpmsg.opt[9]=1;
	dhcpmsg.opt[10]=4;
	dhcpmsg.opt[11]=255;
	dhcpmsg.opt[12]=255;
	dhcpmsg.opt[13]=255;
	dhcpmsg.opt[14]=0;

	//Router (GateWay)
	dhcpmsg.opt[15]=3;
	dhcpmsg.opt[16]=4;
	dhcpmsg.opt[17]=192;
	dhcpmsg.opt[18]=168;
	dhcpmsg.opt[19]=0;
	dhcpmsg.opt[20]=10;

	//Domain Name Server
	dhcpmsg.opt[21]=6;
	dhcpmsg.opt[22]=4;
	dhcpmsg.opt[23]=192;
	dhcpmsg.opt[24]=168;
	dhcpmsg.opt[25]=0;
	dhcpmsg.opt[26]=10;

	dhcpmsg.opt[27]=255;


	if(sendto(sockfd,&dhcpmsg,sizeof(dhcpmsg),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
		printf("sendto\n");
}

void sendMisto(int acao, char *mac){
	int sockFd = 0, retValue = 0;
	char buffer[BUFFER_LEN], dummyBuf[50];
	struct sockaddr_ll destAddr;
	short int etherTypeT = htons(0x8200);

	/* Configura MAC Origem e Destino */
	MacAddress localMac = {0xDC, 0x53, 0x60, 0x13, 0x99, 0x8A};
	//MacAddress destMac = {mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]};
	MacAddress destMac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	/* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
	/* De um "man" para ver os parametros.*/
	/* htons: converte um short (2-byte) integer para standard network byte order. */
	if((sockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		printf("Erro na criacao do socket.\n");
		exit(1);
	}

	/* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
	destAddr.sll_family = htons(PF_PACKET);
	destAddr.sll_protocol = htons(ETH_P_ALL);
	destAddr.sll_halen = 6;
	destAddr.sll_ifindex = 2;  /* indice da interface pela qual os pacotes serao enviados */
	memcpy(&(destAddr.sll_addr), destMac, MAC_ADDR_LEN);

	

	struct dhcpmessage dhcpmsg;
	bzero(&dhcpmsg,sizeof(dhcpmsg));
	dhcpmsg.op = 1;
	dhcpmsg.htype = 1;
	dhcpmsg.hlen = 6;
	dhcpmsg.hops = 0;
	dhcpmsg.xid = htonl(1000);
	dhcpmsg.secs = htons(0);
	dhcpmsg.flags = htons(0x8000);

	dhcpmsg.ciaddr = 0;
	dhcpmsg.yiaddr = inet_addr("192.168.0.28");
	dhcpmsg.siaddr = 0;
	dhcpmsg.giaddr = 0;

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
	
	//DHCP Message Type
	dhcpmsg.opt[0]=53;
	dhcpmsg.opt[1]=1;
	if(acao == 0)
		dhcpmsg.opt[2]=2;
	else
		dhcpmsg.opt[2]=5;

	//DHCP Server Identifier
	dhcpmsg.opt[3]=54;
	dhcpmsg.opt[4]=4;
	dhcpmsg.opt[5]=192;
	dhcpmsg.opt[6]=168;
	dhcpmsg.opt[7]=0;
	dhcpmsg.opt[8]=10;

	//Mascara
	dhcpmsg.opt[9]=1;
	dhcpmsg.opt[10]=4;
	dhcpmsg.opt[11]=255;
	dhcpmsg.opt[12]=255;
	dhcpmsg.opt[13]=255;
	dhcpmsg.opt[14]=0;

	//Router (GateWay)
	dhcpmsg.opt[15]=3;
	dhcpmsg.opt[16]=4;
	dhcpmsg.opt[17]=192;
	dhcpmsg.opt[18]=168;
	dhcpmsg.opt[19]=0;
	dhcpmsg.opt[20]=10;

	//Domain Name Server
	dhcpmsg.opt[21]=6;
	dhcpmsg.opt[22]=4;
	dhcpmsg.opt[23]=192;
	dhcpmsg.opt[24]=168;
	dhcpmsg.opt[25]=0;
	dhcpmsg.opt[26]=10;

	dhcpmsg.opt[27]=255;

	/* Cabecalho Ethernet */
	memcpy(buffer, destMac, MAC_ADDR_LEN);
	memcpy((buffer+MAC_ADDR_LEN), localMac, MAC_ADDR_LEN);
	memcpy((buffer+(2*MAC_ADDR_LEN)), &(etherTypeT), sizeof(etherTypeT));

	/* Add some data */
	memcpy((buffer+ETHERTYPE_LEN+(2*MAC_ADDR_LEN)), dummyBuf, 50);

	//while(1) {
		/* Envia pacotes de 64 bytes */
		if((retValue = sendto(sockFd, buffer, 64, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
			printf("ERROR! sendto() \n");
			exit(1);
		}
		printf("Send success (%d).\n", retValue);
	//}
}


void sendDHCP2(){
	int sockFd = 0, retValue = 0;
  char buffer[BUFFER_LEN], dummyBuf[50];
  struct sockaddr_ll destAddr;
  short int etherTypeT = htons(0x8200);

  /* Configura MAC Origem e Destino */
  MacAddress localMac = {0xDC, 0x53, 0x60, 0x13, 0x99, 0x8A};
  MacAddress destMac = {0x00, 0x17, 0x9A, 0xB3, 0x9E, 0x16};
//   MacAddress destMac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
  /* De um "man" para ver os parametros.*/
  /* htons: converte um short (2-byte) integer para standard network byte order. */
  if((sockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    printf("Erro na criacao do socket.\n");
    exit(1);
  }

  /* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
  destAddr.sll_family = htons(PF_PACKET);
  destAddr.sll_protocol = htons(ETH_P_ALL);
  destAddr.sll_halen = 6;
  destAddr.sll_ifindex = 2;  /* indice da interface pela qual os pacotes serao enviados */
  memcpy(&(destAddr.sll_addr), destMac, MAC_ADDR_LEN);

  /* Cabecalho Ethernet */
  memcpy(buffer, destMac, MAC_ADDR_LEN);
  memcpy((buffer+MAC_ADDR_LEN), localMac, MAC_ADDR_LEN);
  memcpy((buffer+(2*MAC_ADDR_LEN)), &(etherTypeT), sizeof(etherTypeT));

  /* Add some data */
  memcpy((buffer+ETHERTYPE_LEN+(2*MAC_ADDR_LEN)), dummyBuf, 50);

  //while(1) {
    /* Envia pacotes de 64 bytes */
    if((retValue = sendto(sockFd, buffer, 64, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
       printf("ERROR! sendto() \n");
       exit(1);
    }
    printf("Send success (%d).\n", retValue);
  //}
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

	//sendOffer(1);	
	char mac[6];
	//recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		
		if(buff1[12] == 0x08 && buff1[13] == 0x00){ //IP
			
			if(buff1[23] == 0x11){ //UDP
				ip_h_size =(int) (4*(buff1[14]-0x40)); //em bytes
				next_p = 14 + ip_h_size;

				if(buff1[next_p+3] == 0x43){
					if(buff1[next_p+250] == 0x01){
						mac[0] = buff1[next_p+254];
						mac[1] = buff1[next_p+255];
						mac[2] = buff1[next_p+256];
						mac[3] = buff1[next_p+257];
						mac[4] = buff1[next_p+258];
						mac[5] = buff1[next_p+259];
						sendOffer(0,mac);
						printf("DHCP Discover \n"/*,buff1[next_p+3],buff1[next_p+250]*/);
						
						// printf("MAC Address: %x:%x:%x:%x:%x:%x \n",buff1[next_p+254],buff1[next_p+255],buff1[next_p+256],buff1[next_p+257],buff1[next_p+258],buff1[next_p+259]);
						
						// printf("Host length: %x\n",buff1[next_p+261]);

						// printf("Host name: ");
						// int i;
						// for(i=1;i<=buff1[next_p+261];i++){
						// 	printf("%x:",buff1[next_p+261+i]);
						// }
						printf("\n");
						
						/* NAO PODE SER ASSIM
						Deve ser feito uma leitura dos campos de opçoes dinamicamente
						pois eles possuem um identificador */

						printf("-------------------------------\n");
					}else{
						if(buff1[next_p+250] == 0x03){
							sendOffer(1,mac);
							//printf("MAC Address: %x:%x:%x:%x:%x:%x \n",buff1[next_p+254],buff1[next_p+255],buff1[next_p+256],buff1[next_p+257],buff1[next_p+258],buff1[next_p+259]);
							printf("DHCP Request  \n"/*,buff1[next_p+3],buff1[next_p+250]*/);
						}
					}
				}
			}
		}


	}
}


void sendRequest(){
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