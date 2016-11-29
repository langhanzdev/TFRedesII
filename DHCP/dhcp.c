
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
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if.h>
#include <linux/if_packet.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/in_systm.h> 

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1518

typedef unsigned char MacAddress[MAC_ADDR_LEN];
extern int errno;

//Formata data e hora
char *format(int number){      
    char    *retorno,
        ret[100];
    int    i;

    if (number < 10){
        sprintf(ret,"0%d",number);
        retorno = ret;
        return retorno;
    }
    else{
        sprintf(ret,"%d",number);
        retorno = ret;
        return retorno;
    }
}      

//Funcao que retorna data
char *data(void){

    int dia,mes,ano;
    char   var1[100],
        var2[100],
        var3[100],
        var4[100],
        *dataPtr;
    struct tm *local;
    time_t t;

    t = time(NULL);
    local = localtime(&t);

    dia = local -> tm_mday;
    mes = local -> tm_mon + 1;
    ano = local -> tm_year + 1900;
      
    sprintf(var1,"%s",format(dia));
    sprintf(var2,"%s",format(mes));
    sprintf(var3,"%s",format(ano));      
    sprintf(var4,"%s/%s/%s",var1,var2,var3);

    dataPtr = var4;
    return dataPtr;
}

//Funcao que retorna hora
char *hora(void){
      
    int   hora,minuto,segundo;
    char   var1[100],
        var2[100],
        var3[100],
        var5[100],
        *retorno;
    struct tm *local;
    time_t t;

    t = time(NULL);
    local = localtime(&t);
    hora   =   local -> tm_hour;
    minuto   =    local -> tm_min;
    segundo =   local -> tm_sec;

    sprintf(var1,"%s",format(hora));
    sprintf(var2,"%s",format(minuto));
    sprintf(var3,"%s",format(segundo));
    sprintf(var5,"%s:%s:%s",var1,var2,var3);

    retorno = var5;
    return retorno;   
}

  unsigned char buff1[BUFFSIZE]; // buffer de recepcao

  int sockd;
  int on;
  struct ifreq ifr;

struct dhcp_packet {
    u_int8_t  op;       /* 0: Message opcode/type */
    u_int8_t  htype;    /* 1: Hardware addr type (net/if_types.h) */
    u_int8_t  hlen;     /* 2: Hardware addr length */
    u_int8_t  hops;     /* 3: Number of relay agent hops from client */
    u_int32_t xid;      /* 4: Transaction ID */
    u_int16_t secs;     /* 8: Seconds since client started looking */
    u_int16_t flags;    /* 10: Flag bits */
    struct in_addr ciaddr;  /* 12: Client IP address (if already in use) */
    struct in_addr yiaddr;  /* 16: Client IP address */
    struct in_addr siaddr;  /* 18: IP address of next server to talk to */
    struct in_addr giaddr;  /* 20: DHCP relay agent IP address */
    unsigned char chaddr [16];  /* 24: Client hardware address */
    char sname [64];    /* 40: Server name */
    char file [128];  /* 104: Boot filename */
    char magic[4];
unsigned char options [60];
};

void sendOffer(int acao, char *mac){
    int sock;
 
    unsigned int packetsize = (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dhcp_packet));
    unsigned char packet[packetsize];
 
    struct sockaddr_ll addr;
 
    struct ether_header *eth = (struct ether_header *) (packet);
    struct iphdr *ip = (struct iphdr *) (packet + sizeof(struct ether_header));
    struct udphdr *udp = (struct udphdr *) (packet + sizeof(struct iphdr) + sizeof(struct ether_header));
    struct dhcp_packet *dhcp =  (struct dhcp_packet *) (packet + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ether_header));
 
    struct ifreq ifreq;
 
    char SourceHwaddr[17];
    char DestHwaddr[17];
 
    //If other than one argument is giving error!
    // if (argc != 2)
    // {
    //     fprintf(stderr, "Usages: dhcpreq <INTERFACE>\n");
    //     exit(1);
    // }
 
    //Cria um socket UDP com IP
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1)
    {
        perror("creating socket");
        exit(0);
    }
    //Seta a interface
    strcpy(ifreq.ifr_name, "wlp7s0");//argv[1]);
    //Pega o MAC da maquina
    if (ioctl(sock, SIOCGIFHWADDR, &ifreq) != 0)
    {
        perror("ioctl get hwaddr");
        exit(0);
    }
 
    //Configura enderecos MAC
    sprintf(SourceHwaddr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char) ifreq.ifr_hwaddr.sa_data[0], (unsigned char) ifreq.ifr_hwaddr.sa_data[1],
            (unsigned char) ifreq.ifr_hwaddr.sa_data[2], (unsigned char) ifreq.ifr_hwaddr.sa_data[3], (unsigned char) ifreq.ifr_hwaddr.sa_data[4],
            (unsigned char) ifreq.ifr_hwaddr.sa_data[5]);

    sprintf(DestHwaddr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char) mac[0], (unsigned char) mac[1],
            (unsigned char) mac[2], (unsigned char) mac[3], (unsigned char) mac[4],
            (unsigned char) mac[5]);
 

    /*** Ethernet ***/
 
    //Mac destino
    memcpy(eth->ether_dhost, ether_aton("ff:ff:ff:ff:ff:ff"), ETH_ALEN);
    //MAC origem
    memcpy(eth->ether_shost, ether_aton(SourceHwaddr), ETH_ALEN);
    //Ethernet type
    eth->ether_type = htons(ETH_P_IP);
 
 
    /*** IP ***/
 
    //Tipo de servico
    ip->tos = 0;
    //Versao do IP
    ip->version = 4;
    //IP header length
    ip->ihl = sizeof(struct iphdr) >> 2;
    //Total length
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr)  + sizeof(struct dhcp_packet));
    //Id
    ip->id = htons((int) (rand() / (((double) RAND_MAX + 1) / 14095)));
    //Fragment offset
    ip->frag_off = 0;
    //Campo TTL
    ip->ttl = 128;
    //Campo protocol
    ip->protocol = IPPROTO_UDP; 
    //IP origem
    ip->saddr = inet_addr("10.32.143.204");
    //IP destino
    ip->daddr = inet_addr("255.255.255.255");
    
 
    /*** UDP ***/
 
    //Porta origem
    udp->source = htons(67);
    //Porta destino
    udp->dest = htons(68);
    //UDP length
    udp->len = htons(sizeof(struct udphdr) + sizeof(struct dhcp_packet));

 
    /*** DHCP  ***/

    dhcp->op = 2;
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000);
 
    //Endereço oferecido ao cliente
    inet_aton("0.0.0.0", (struct in_addr *) &dhcp->ciaddr);
    inet_aton("10.32.143.28", (struct in_addr *) &dhcp->yiaddr);
    inet_aton("0.0.0.0", (struct in_addr *) &dhcp->siaddr);
    inet_aton("0.0.0.0", (struct in_addr *) &dhcp->giaddr);
 
    //MAC do cliente
    dhcp->chaddr[0] = mac[0];
    dhcp->chaddr[1] = mac[1];
    dhcp->chaddr[2] = mac[2];
    dhcp->chaddr[3] = mac[3];
    dhcp->chaddr[4] = mac[4];
    dhcp->chaddr[5] = mac[5];

    //Servername preenchido com zeros
    bzero(dhcp->sname, sizeof(dhcp->sname));
    dhcp->sname[0] = 0xff;

    int i;
    for(i=1;i<129;i++){
        dhcp->sname[i] = 0x00;
    }
    i=1;
    
    //Filename preenchido com zeros
    bzero(dhcp->file, sizeof(dhcp->file));
    dhcp->file[0] = 0xff;
    for(i=1;i<65;i++){
        dhcp->file[i] = 0x00;
    }

    dhcp->magic[0]=99;
	dhcp->magic[1]=130;
	dhcp->magic[2]=83;
	dhcp->magic[3]=99;
 
    bzero(dhcp->options, sizeof(dhcp->options));
 
    //DHCP Message Type
	dhcp->options[0]=53;
	dhcp->options[1]=1;
	if(acao == 0)
		dhcp->options[2]=2;
	else
		dhcp->options[2]=5;

    //DHCP Server Identifier
	dhcp->options[3]=54;
	dhcp->options[4]=4;
	dhcp->options[5]=10;
	dhcp->options[6]=32;
	dhcp->options[7]=143;
	dhcp->options[8]=204;

	//IP address lease time
	dhcp->options[9]=51;
	dhcp->options[10]=4;
	dhcp->options[11]=00;
	dhcp->options[12]=00;
	dhcp->options[13]=28;
	dhcp->options[14]=32;

	//Mascara
	dhcp->options[15]=1;
	dhcp->options[16]=4;
	dhcp->options[17]=255;
	dhcp->options[18]=255;
	dhcp->options[19]=255;
	dhcp->options[20]=0;

	//Router (GateWay)
	dhcp->options[21]=3;
	dhcp->options[22]=4;
	dhcp->options[23]=10;
	dhcp->options[24]=32;
	dhcp->options[25]=143;
	dhcp->options[26]=204;

	//Domain Name Server
	dhcp->options[27]=6;
	dhcp->options[28]=4;
	dhcp->options[29]=10;
	dhcp->options[30]=32;
	dhcp->options[31]=143;
	dhcp->options[32]=204;

	//Domain name
	dhcp->options[33]=15;
	dhcp->options[34]=11;
	dhcp->options[35]=100;//64
	dhcp->options[36]=111;//6f
	dhcp->options[37]=109;//6d
	dhcp->options[38]=97;//61
	dhcp->options[39]=105;//69
	dhcp->options[40]=110;//6e
	dhcp->options[41]=46;//2e
	dhcp->options[42]=110;//6e
	dhcp->options[43]=97;//61
	dhcp->options[44]=109;//6d
	dhcp->options[45]=101;//65
	
    //Overload
    dhcp->options[46]=52;
    dhcp->options[47]=1;
    dhcp->options[48]=3;

    //broadcast address
    dhcp->options[49]=28;
    dhcp->options[50]=4;
    dhcp->options[51]=255;
    dhcp->options[52]=255;
    dhcp->options[53]=255;
    dhcp->options[54]=255;

    //Interface MTU
    dhcp->options[55]=26;
    dhcp->options[56]=2;
    dhcp->options[57]=02;
    dhcp->options[58]=64;

	dhcp->options[59]=255;
 
    //clear the addr and set the data in it
    memset(&addr, 0, sizeof(struct sockaddr_ll));
    addr.sll_family = PF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
 
    if (ioctl(sock, SIOCGIFINDEX, &ifreq) != 0)
    {
        perror("ioctl get index");
        exit(0);
    }
    addr.sll_ifindex = ifreq.ifr_ifindex;
 
    //Try to bind the socket on a address
    if (bind(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_ll)) != 0)
    {
        perror("Socket Binding error");
        exit(0);
    }
 
    //Write the packet to the socket
    int n = 0;
    if ((n = write(sock, packet, packetsize)) <= 0)
    {
        perror("Packet sending error");
        exit(0);
    }
 
    close(sock);
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

	char mac[6];

	//recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);      
		
		if(buff1[12] == 0x08 && buff1[13] == 0x00){ //IP

            int ipVersion=0;
            int ipLength;
            if(buff1[14] == 0x45){
                ipLength = (int) (4*(buff1[14]-0x40));
                ipVersion = 4;
            }else{
                ipLength = 64;
                ipVersion = 6;
            }

            int udp = 14 + ipLength;
			
            if(buff1[23] == 0x11){ //UDP
                
                int udpLength = udp+5;
                int pkgLenght = udpLength+ipLength+14;
				
				next_p = 14 + ipLength;
                
				if(buff1[udp+3] == 0x43){ //DHCP  - porta dest
                    
                    int dhcp = udp+8+1;
                    int macOrigem = dhcp + 245;
					
					if(buff1[dhcp + 241] == 0x01){
						mac[0] = buff1[6];
						mac[1] = buff1[6+1];
						mac[2] = buff1[6+2];
						mac[3] = buff1[6+3];
						mac[4] = buff1[6+4];
						mac[5] = buff1[6+5];
						
						sendOffer(0,mac);

						printf("DHCP Discover \n\n");
						printf("-------------------------------\n");

					}else{
						if(buff1[dhcp + 241] == 0x03){
							sendOffer(1,mac);
							printf("DHCP Request  \n\n");
                            printf("-------------------------------\n");
						}
					}
				}else{
                    
                    if(buff1[udp+3] == 0x35){ //DNS
                        int dns = udp+8+1;
                        char b[2] ;
                    }
                }
			}
            /// TCP
            if(buff1[23] == 0x06){//TCP
                
                int tcp = 14 + ipLength;
                int tcpLength = (int) (4*(buff1[tcp+12]/0x10));
                
                if(buff1[tcp+3] == 0x50){ //HTTP -- porta 80
                    
                    int http = 14 + ipLength + tcpLength;
                    int httpLength = tcp+8+1+buff1[http+12];
                    char b[2] ;
                    
                    if(buff1[http] == 0x47){ //GET
                        
                        int dom=0; 
                        int flag = 0;
                        FILE *arq;
                        arq = fopen("/home/langhanz/Desktop/novo.html", "a");
                        
                        if(arq == NULL){
                            printf("Erro, nao foi possivel abrir o arquivo\n");
                        }
                        
                        char aux[100];
                        sprintf(aux,"%s","<html>");
                        fputs(aux, arq);//html

                        while(flag==0){
                            dom=0;

                            sprintf(aux,"%s","<div style='background-color:#8FBC8F;margin:10px;padding:10px;'>");
                            fputs(aux, arq);//div   

                            for(dom=0;!(buff1[dom] == 0x48 && buff1[dom+1] == 0x6f && buff1[dom+2] == 0x73 && buff1[dom+3] == 0x74) && dom < 1500;dom++){
                                
                            }

                            if(ipVersion == 4){
                                
                                //Escreve IP
                                char hex_num[2];
                                sprintf(hex_num, "%x", (int)buff1[14+12]);
                                int a = strtol(hex_num, NULL, 16);
                                sprintf(hex_num, "%d", a);
                                fputs(hex_num,arq);
                                fputc(0x2e, arq);

                                sprintf(hex_num, "%x", (int)buff1[14+13]);
                                a = strtol(hex_num, NULL, 16);
                                sprintf(hex_num, "%d", a);
                                fputs(hex_num,arq);
                                fputc(0x2e, arq);

                                sprintf(hex_num, "%x", (int)buff1[14+14]);
                                a = strtol(hex_num, NULL, 16);
                                sprintf(hex_num, "%d", a);
                                fputs(hex_num,arq);
                                fputc(0x2e, arq);

                                sprintf(hex_num, "%x", (int)buff1[14+15]);
                                a = strtol(hex_num, NULL, 16);
                                sprintf(hex_num, "%d", a);
                                fputs(hex_num,arq);

                                fputc(0x20, arq);
                                fputc(0x2d, arq);
                                fputc(0x20, arq);
                                
                            }

                            //Escreve data e hora
                            char data_sistema[100],
                            hora_sistema[100];
                            sprintf(data_sistema,"%s%s",data()," ");
                            sprintf(hora_sistema,"%s",hora());
                            fputs(data_sistema, arq);
                            fputc(0x20, arq);
                            fputc(0x2d, arq);
                            fputc(0x20, arq);
                            fputs(hora_sistema, arq);

                            sprintf(aux,"%s","</br>");
                            fputs(aux, arq);

                            for(dom;!(buff1[dom] == 0x0d && buff1[dom+1] == 0x0a);dom++){                            
                                sprintf(b,"%c",buff1[dom]);
                                printf("%s",b);
                                fputc(buff1[dom], arq);
                            }  
                            
                            for(dom=0;!(buff1[dom] == 0x47 && buff1[dom+1] == 0x45 && buff1[dom+2] == 0x54) && dom < 1500;dom++){
                            
                            }
                            
                            dom = dom+4;
                            for(dom;!(buff1[dom] == 0x20);dom++){                            
                                sprintf(b,"%c",buff1[dom]);
                                printf("%s",b);
                                fputc(buff1[dom], arq);
                            }  

                            sprintf(aux,"%s","</div>");
                            fputs(aux, arq);//div 
                            flag = 1;   
                        }

                        sprintf(aux,"%s","</html>");
                        fputs(aux, arq);//html
                        fclose(arq);
                    
                        printf("\n");                        
                    }
                }
            }
		}
	}
}

