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
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if.h>
#include <linux/if_packet.h> 
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/in_systm.h> //tipos de dados



#define DHCP_UDP_OVERHEAD   (14 + /* Ethernet header */     \
                             20 + /* IP header */           \
                              8)   /* UDP header */
#define DHCP_SNAME_LEN      64
#define DHCP_FILE_LEN       128
#define DHCP_FIXED_NON_UDP  236
#define DHCP_FIXED_LEN      (DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
                        /* Everything but options. */
#define DHCP_MTU_MAX        1500
#define DHCP_OPTION_LEN     (DHCP_MTU_MAX - DHCP_FIXED_LEN)
 
#define BOOTP_MIN_LEN       300
#define DHCP_MIN_LEN            548
/* BOOTP (rfc951) message types */
#define BOOTREQUEST 1
#define BOOTREPLY   2
 
/* Possible values for flags field... */
#define BOOTP_BROADCAST 32768L
 
/* Possible values for hardware type (htype) field... */
#define HTYPE_ETHER 1               /* Ethernet 10Mbps              */
#define HTYPE_IEEE802   6               /* IEEE 802.2 Token Ring... */
#define HTYPE_FDDI  8       /* FDDI...          */
 
/* Magic cookie validating dhcp options field (and bootp vendor
   extensions field). */
#define DHCP_OPTIONS_COOKIE "\143\202\123\143"
 
/* DHCP Option codes: */
 
#define DHO_PAD             0
#define DHO_SUBNET_MASK         1
#define DHO_TIME_OFFSET         2
#define DHO_ROUTERS         3
#define DHO_TIME_SERVERS        4
#define DHO_NAME_SERVERS        5
#define DHO_DOMAIN_NAME_SERVERS     6
#define DHO_LOG_SERVERS         7
#define DHO_COOKIE_SERVERS      8
#define DHO_LPR_SERVERS         9
#define DHO_IMPRESS_SERVERS     10
#define DHO_RESOURCE_LOCATION_SERVERS   11
#define DHO_HOST_NAME           12
#define DHO_BOOT_SIZE           13
#define DHO_MERIT_DUMP          14
#define DHO_DOMAIN_NAME         15
#define DHO_SWAP_SERVER         16
#define DHO_ROOT_PATH           17
#define DHO_EXTENSIONS_PATH     18
#define DHO_IP_FORWARDING       19
#define DHO_NON_LOCAL_SOURCE_ROUTING    20
#define DHO_POLICY_FILTER       21
#define DHO_MAX_DGRAM_REASSEMBLY    22
#define DHO_DEFAULT_IP_TTL      23
#define DHO_PATH_MTU_AGING_TIMEOUT  24
#define DHO_PATH_MTU_PLATEAU_TABLE  25
#define DHO_INTERFACE_MTU       26
#define DHO_ALL_SUBNETS_LOCAL       27
#define DHO_BROADCAST_ADDRESS       28
#define DHO_PERFORM_MASK_DISCOVERY  29
#define DHO_MASK_SUPPLIER       30
#define DHO_ROUTER_DISCOVERY        31
#define DHO_ROUTER_SOLICITATION_ADDRESS 32
#define DHO_STATIC_ROUTES       33
#define DHO_TRAILER_ENCAPSULATION   34
#define DHO_ARP_CACHE_TIMEOUT       35
#define DHO_IEEE802_3_ENCAPSULATION 36
#define DHO_DEFAULT_TCP_TTL     37
#define DHO_TCP_KEEPALIVE_INTERVAL  38
#define DHO_TCP_KEEPALIVE_GARBAGE   39
#define DHO_NIS_DOMAIN          40
#define DHO_NIS_SERVERS         41
#define DHO_NTP_SERVERS         42
#define DHO_VENDOR_ENCAPSULATED_OPTIONS 43
#define DHO_NETBIOS_NAME_SERVERS    44
#define DHO_NETBIOS_DD_SERVER       45
#define DHO_NETBIOS_NODE_TYPE       46
#define DHO_NETBIOS_SCOPE       47
#define DHO_FONT_SERVERS        48
#define DHO_X_DISPLAY_MANAGER       49
#define DHO_DHCP_REQUESTED_ADDRESS  50
#define DHO_DHCP_LEASE_TIME     51
#define DHO_DHCP_OPTION_OVERLOAD    52
#define DHO_DHCP_MESSAGE_TYPE       53
#define DHO_DHCP_SERVER_IDENTIFIER  54
#define DHO_DHCP_PARAMETER_REQUEST_LIST 55
#define DHO_DHCP_MESSAGE        56
#define DHO_DHCP_MAX_MESSAGE_SIZE   57
#define DHO_DHCP_RENEWAL_TIME       58
#define DHO_DHCP_REBINDING_TIME     59
#define DHO_VENDOR_CLASS_IDENTIFIER 60
#define DHO_DHCP_CLIENT_IDENTIFIER  61
#define DHO_NWIP_DOMAIN_NAME        62
#define DHO_NWIP_SUBOPTIONS     63
#define DHO_USER_CLASS          77
#define DHO_FQDN            81
#define DHO_DHCP_AGENT_OPTIONS      82
#define DHO_SUBNET_SELECTION        118 /* RFC3011! */
/* The DHO_AUTHENTICATE option is not a standard yet, so I've
   allocated an option out of the "local" option space for it on a
   temporary basis.  Once an option code number is assigned, I will
   immediately and shamelessly break this, so don't count on it
   continuing to work. */
#define DHO_AUTHENTICATE        210
 
#define DHO_END             255
 
/* DHCP message types. */
#define DHCPDISCOVER    1
#define DHCPOFFER   2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK     5
#define DHCPNAK     6
#define DHCPRELEASE 7
#define DHCPINFORM  8
 
/* Relay Agent Information option subtypes: */
#define RAI_CIRCUIT_ID  1
#define RAI_REMOTE_ID   2
#define RAI_AGENT_ID    3
 
/* FQDN suboptions: */
#define FQDN_NO_CLIENT_UPDATE       1
#define FQDN_SERVER_UPDATE      2
#define FQDN_ENCODED            3
#define FQDN_RCODE1         4
#define FQDN_RCODE2         5
#define FQDN_HOSTNAME           6
#define FQDN_DOMAINNAME         7
#define FQDN_FQDN           8
#define FQDN_SUBOPTION_COUNT        8



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
    char opt[47];
} __attribute__((__packed__));


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
    char sname [64];  //DHCP_SNAME_LEN  /* 40: Server name */
    char file [128];  //DHCP_FILE_LEN/* 104: Boot filename */
    char magic[4];
    unsigned char options [60];//DHCP_OPTION_LEN
                /* 212: Optional parameters
                   (actual length dependent on MTU). */
};

void sendOffer(int acao, char *mac){
    int sock;
 
    unsigned int packetsize = (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dhcp_packet));
    unsigned char packet[packetsize];
 
    printf("Packetsize %d\n", packetsize);
    printf("DHCP_OPTION_LEN %d\n", DHCP_OPTION_LEN);
    printf("DHCP_FIXED_LEN %d\n", DHCP_FIXED_LEN);
 
    printf("Packet size min dhcp %lu\n", (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));
 
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
 
    //Create a UDP Socket with IP Protocol
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1)
    //if ((sock = socket(PF_PACKET, SOCK_DGRAM, IPPROTO_IP)) == -1)
    {
        perror("creating socket");
        exit(0);
    }
 
    //Set the interface name to argv[1] to define what interface we have
    strcpy(ifreq.ifr_name, "wlp7s0");//argv[1]);
 
    //Get the hardware address
    if (ioctl(sock, SIOCGIFHWADDR, &ifreq) != 0)
    {
        perror("ioctl get hwaddr");
        exit(0);
    }
 
    //Put the hardware address in a chararray
    sprintf(SourceHwaddr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char) ifreq.ifr_hwaddr.sa_data[0], (unsigned char) ifreq.ifr_hwaddr.sa_data[1],
            (unsigned char) ifreq.ifr_hwaddr.sa_data[2], (unsigned char) ifreq.ifr_hwaddr.sa_data[3], (unsigned char) ifreq.ifr_hwaddr.sa_data[4],
            (unsigned char) ifreq.ifr_hwaddr.sa_data[5]);

    sprintf(DestHwaddr, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char) mac[0], (unsigned char) mac[1],
            (unsigned char) mac[2], (unsigned char) mac[3], (unsigned char) mac[4],
            (unsigned char) mac[5]);
 
    /*
     * Begin Ethernet Header
     */
 
    //Destination ethernet address
    memcpy(eth->ether_dhost, ether_aton("a4:02:b9:05:2f:ad"), ETH_ALEN);
 
    //Source ethernet address
    memcpy(eth->ether_shost, ether_aton(SourceHwaddr), ETH_ALEN);
 
    //Ethernet type
    eth->ether_type = htons(ETH_P_IP);
 
    /*
     * End Ethernet Header
     */
 
    /*
     * Begin IP Header
     */
 
    //Set the type of service
    ip->tos = 0;
 
    //Set the IP version
    ip->version = 4;
 
    //Set the IP header length
    ip->ihl = sizeof(struct iphdr) >> 2;
 
    //Set the total length
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr)  + sizeof(struct dhcp_packet));
 
    //Set the id
    ip->id = htons((int) (rand() / (((double) RAND_MAX + 1) / 14095)));
 
    //Set the fragment offset
    ip->frag_off = 0;
 
    //Set the TTL
    ip->ttl = 128;
 
    //Set the protocol
    ip->protocol = IPPROTO_UDP;
 
    //Let IP set the checksum
 
    //Set the source IP
    ip->saddr = inet_addr("192.168.1.10");
    //Set the destenations IP
    ip->daddr = inet_addr("255.255.255.255");
    /*
     * End IP Header
     */
 
 
    /*
     * Begin UDP Header
     */
 
    //Set the source port
    udp->source = htons(67);
 
    //Set the desentation port
    udp->dest = htons(68);
 
    //Set the UDP length (incl dhcp packet)
    udp->len = htons(sizeof(struct udphdr) + sizeof(struct dhcp_packet));
 
    /*
     * End UDP Header
     */
 
    /*
     * Begin DHCP Packet
     */
    dhcp->op = 2;
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
 
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000);//BOOTP_BROADCAST
 
 
    inet_aton("0.0.0.0", (struct in_addr *) &dhcp->ciaddr);
    inet_aton("192.168.1.28", (struct in_addr *) &dhcp->yiaddr);
    inet_aton("0.0.0.0", (struct in_addr *) &dhcp->siaddr);
    inet_aton("0.0.0.0", (struct in_addr *) &dhcp->giaddr);
 
    //Copy the MAC address from ifreq
    //memcpy(dhcp->chaddr, &ifreq.ifr_addr, ETHER_ADDR_LEN);
    dhcp->chaddr[0] = 0xa4;//mac[0];//0x48;
    dhcp->chaddr[1] = 0x02;//mac[1];//0x50;
    dhcp->chaddr[2] = 0xb9;//mac[2];//0x73;
    dhcp->chaddr[3] = 0x05;//mac[3];//0x6e;
    dhcp->chaddr[4] = 0x2f;//mac[4];//0xb1;
    dhcp->chaddr[5] = 0xad;//mac[5];//0x64;
    //Servername must be null "a4:02:b9:05:2f:ad"
    bzero(dhcp->sname, sizeof(dhcp->sname));
    dhcp->sname[0] = 0xff;

    int i;
    for(i=1;i<129;i++){
        dhcp->sname[i] = 0x00;
    }
    i=1;
    //Filename must be null
    bzero(dhcp->file, sizeof(dhcp->file));
    dhcp->file[0] = 0xff;
    for(i=1;i<65;i++){
        dhcp->file[i] = 0x00;
    }

    dhcp->magic[0]=99;
	dhcp->magic[1]=130;
	dhcp->magic[2]=83;
	dhcp->magic[3]=99;
 
    //Must bu filled in
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
	dhcp->options[5]=192;
	dhcp->options[6]=168;
	dhcp->options[7]=1;
	dhcp->options[8]=10;

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
	dhcp->options[23]=192;
	dhcp->options[24]=168;
	dhcp->options[25]=1;
	dhcp->options[26]=10;

	//Domain Name Server
	dhcp->options[27]=6;
	dhcp->options[28]=4;
	dhcp->options[29]=192;
	dhcp->options[30]=168;
	dhcp->options[31]=1;
	dhcp->options[32]=10;

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

    /*
     * End DHCP Packet
     */
 
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
    printf("Interface index: %d\n", ifreq.ifr_ifindex);
 
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
    printf("%d bytes sent\n", n);
 
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
						//sendOffer(0,mac);
						printf("MAC Address Before: %x \n",buff1[next_p+258]);
						//printf("MAC Address: %x:%x:%x:%x:%x:%x \n",buff1[next_p+254],buff1[next_p+255],buff1[next_p+256],buff1[next_p+257],buff1[next_p+258],buff1[next_p+259]);
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
							//sendOffer(1,mac);
							sendOffer(1,mac);
							printf("MAC Address: %x:%x:%x:%x:%x:%x \n",buff1[next_p+254],buff1[next_p+255],buff1[next_p+256],buff1[next_p+257],buff1[next_p+258],buff1[next_p+259]);
							printf("DHCP Request  \n"/*,buff1[next_p+3],buff1[next_p+250]*/);
						}
					}
				}
			}
		}


	}
}

