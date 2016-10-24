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

  int qtd_total;
  int qtd_arp;
  int qtd_arp_rq;
  int qtd_arp_rp;
  int qtd_icmp;
  int qtd_icmp_rq;
  int qtd_icmp_rp;
  int qtd_udp;
  int qtd_tcp;
  int qtd_http;
  int qtd_smtp;
  int qtd_dns;

  int ip_h_size;
  int min_size;
  int max_size;
  int avg_size;

struct ip{
	unsigned char nr_ip;
	int count;
};
typedef struct ip ip;
ip list_ips[100];
int list_ip_size = 0;

int add(ip list[], unsigned char nrip, int n){
	int i;
	//encontra ip na lista
	for (i = 0 ; i < ( n - 1 ); i++){
		if(list[i].nr_ip == nrip){
			list[i].count = list[i].count + 1;
			return n;
		}
	}
	// novo ip
	if(n<100){
		ip x;
		x.count = 0;
		x.nr_ip = nrip;
		list[n+1] = x;
		n++;
		return n;
	}
	return -1;

}

void bubble_sort(ip list[], long n)
{
  long c, d;
  ip t;
 
  for (c = 0 ; c < ( n - 1 ); c++){
    for (d = 0 ; d < n - c - 1; d++){
      if (list[d].count > list[d+1].count){
        t         = list[d];
        list[d]   = list[d+1];
        list[d+1] = t;
      }
    }
  }
}


int main(int argc,char *argv[])
{
	qtd_total = 0;
	qtd_arp = 0;
	qtd_arp_rq = 0;
	qtd_arp_rp = 0;
	qtd_icmp = 0;
	qtd_icmp_rq = 0;
	qtd_icmp_rp = 0;
	qtd_udp = 0;
	qtd_tcp = 0;
	qtd_http = 0;
	min_size = 0;
	max_size = 0;
	avg_size = 0;

	
	

    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, argv[1]);
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	int next_p;
	float a;
	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
		qtd_total++;

		bubble_sort(list_ips,list_ip_size);

		// impressao do conteudo - exemplo Endereco Destino e Endereco Origem
		//char a = "06";
		if(buff1[12] == 0x08 && buff1[13] == 0x06){ //ARP
			 qtd_arp++; //ARP
			 if(buff1[21] == 0x01) qtd_arp_rq++; //ARP Request
			 else qtd_arp_rp++; //ARP Reply
		}
		if(buff1[12] == 0x08 && buff1[13] == 0x00){ //IP
			ip_h_size =(int) (4*(buff1[14]-0x40)); //em bytes
			next_p = 14 + ip_h_size;
			if(buff1[23] == 0x01){
				 qtd_icmp++; //ICMP
				 if(buff1[next_p] == 0x00) qtd_icmp_rp++; //ICMP Echo Reply
				 if(buff1[next_p] == 0x08) qtd_icmp_rq++; //ICMP Echo Request

			}
			/*unsigned char cip = buff1[30];
			strcat(cip,buff1[31]);
			strcat(cip,buff1[32]);
			strcat(cip,buff1[33]);
			*/
			//add(list_ips,cip,list_ip_size);

			if(buff1[23] == 0x06){ // TCP
				qtd_tcp++;
				
				if( buff1[next_p+3] == 0x50){ //HTTP
					qtd_http++;
				}

			}
			if(buff1[23] == 0x11){
				 qtd_udp++; //UDP
				 
			}
		}

		short int pck_size = (buff1[16] & 255);
		pck_size = (pck_size << 8);
		pck_size = (pck_size | buff1[17]);
		//printf("------ SIZE : %x%x\n",buff1[16],buff1[17]);
		//printf("------ SIZE : %d\n",byte1);
		
		//printf("ARG: %s",argv[1]);
		printf("-------------------------\n");
		printf("NIVEL DE ENLACE\n");
		printf("  ARP: %d : %1.2f\%\n", qtd_arp,(qtd_arp/(float)qtd_total)*100);
		if(qtd_arp != 0){
			printf("  ARP Request: %d : %1.2f\%\n",qtd_arp_rq,(qtd_arp_rq/(float)qtd_arp)*100);
			printf("  ARP Reply: %d : %1.2f\%\n",qtd_arp_rp,(qtd_arp_rp/(float)qtd_arp)*100);
		}
		printf("NIVEL DE REDE\n");
		printf("  ICMP: %d : %1.2f\%\n", qtd_icmp,(qtd_icmp/(float)qtd_total)*100);
		if(qtd_icmp != 0){
			printf("  ICMP Echo Request: %d : %1.2f\%\n",qtd_icmp_rq, (qtd_icmp_rq/(float)qtd_icmp)*100);
			printf("  ICMP Echo Reply: %d : %1.2f\%\n",qtd_icmp_rp, (qtd_icmp_rp/(float)qtd_icmp)*100);
		}
		printf("NIVEL DE TRANSPORTE\n");
		printf("  UDP: %d : %1.2f\%\n", qtd_udp,(qtd_udp/(float)qtd_total)*100);
		printf("  TCP: %d : %1.2f\%\n", qtd_tcp,(qtd_tcp/(float)qtd_total)*100);
		printf("NIVEL DE APLICACAO\n");
		printf("  HTTP: %d : %1.2f\%\n", qtd_http,(qtd_http/(float)qtd_total)*100);
		printf("DADOS\n");
		printf("  MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
		printf("  MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);
		printf("  Size:  %d \n\n", pck_size);
	}
}

