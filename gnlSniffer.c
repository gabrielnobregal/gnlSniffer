#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<netinet/in.h>


/*************************************************************************************************************************                    
*								 gnlSniffer is developed by Gabriel Nobrega de Lima										 *
*					    This program is hosted at http://sourceforge.net/projects/gnlsniffer/							 *	
**************************************************************************************************************************/


enum BCODIFICACAO  {HEX, ASCII};
enum PROTOCOLO {TCP=1, UDP, TCP_UDP};
#define ALL_IP "255.255.255.255"

int pacoteUDP(unsigned char *p ,int sporta, int dporta, int tam)
{
	struct iphdr *c_ip;
	struct udphdr *c_udp;

	if(tam >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
			c_ip = (struct iphdr *)(p + sizeof(struct ethhdr));
			if(c_ip->protocol == IPPROTO_UDP)
			{//Lembrete ihl tras o tamanho exato do header em multiplo de 4
				c_udp = (struct udphdr*)(p + sizeof(struct ethhdr) + c_ip->ihl*4 );
				if(	(ntohs(c_udp->source) == sporta && dporta==-1) 
					   || (ntohs(c_udp->dest) ==dporta && sporta==-1)
					   || (dporta==-1 && sporta==-1) 
					   || (ntohs(c_udp->dest)==dporta && ntohs(c_udp->source) == sporta )){
						return 1;
				}else 
						return 0;
			}
			else
			{				
				return 0;
			}
		}
		

}
void cabecalhoUdp(unsigned char *p , int tam, int imp_tipo)
{
	struct ethhdr *c_ethernet;
	struct iphdr *c_ip;
	struct udphdr *c_udp;
	if(tam >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)))
	{
		c_ethernet = (struct ethhdr *)p;
		if(ntohs(c_ethernet->h_proto) == ETH_P_IP)
		{
			c_ip = (struct iphdr *)(p + sizeof(struct ethhdr));
			if(c_ip->protocol == IPPROTO_UDP)
			{  //Lembrete ihl tras o tamanho exato do header em multiplo de 4
				c_udp = (struct udphdr*)(p + sizeof(struct ethhdr) + c_ip->ihl*4 );
				printf("Protocolo: UDP \n");				
				printf("Porta destino: %d\n", ntohs(c_udp->dest));
				printf("Porta fonte: %d\n", ntohs(c_udp->source));
			}
			else
			{				
				printf("(UDP)Nao possui cabecalho TCP\n");
			}
		}
		
	}
	else
	{
		printf("Cabecalho TCP defeituoso!");

	} 
}

int criarSocket(int protocolo)
{
	int sock;
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(protocolo)))== -1)
	{
		printf("Erro ao criar Raw socket, você deve ser o root!\n");
		exit(-1);
	}

	return sock;
}

int associarSocketInterface(char *disp, int rawsock, int protocolo)
{
	struct sockaddr_ll sll;
	struct ifreq ifr;

	memset(&sll, 0, sizeof(sll));
	memset(&ifr, 0, sizeof(ifr));
	strncpy((char *)ifr.ifr_name, disp, IFNAMSIZ);///**********
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)///********
	{
		printf("Erro ao tentar obter interface especificada.\n");
		exit(-1);
	}
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocolo); 

	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		printf("Erro ao associar socket a interface.\n");
		exit(-1);
	}
	

	return 1;
	
}


void imprimirBytes(char *msg, unsigned char *p, int tam, int imp_tipo)
{
	printf(msg);

	if(imp_tipo == ASCII)
	{	
		while(tam--)
		{
		printf("%c ", *p);
		p++;
		}
	}else
	{
		while(tam--)
		{
		printf("%.2X ", *p);
		p++;
		}
		
	}

	printf("\n");
}


void cabecalhoEthernet(unsigned char *packet, int len, int imp_tipo)
{
	struct ethhdr *c_ethernet;

	if(len > sizeof(struct ethhdr))
	{
		c_ethernet = (struct ethhdr *)packet;

		//Aponta para o campo de MAC destino e imprime os proximos 6 bytes
		imprimirBytes("MAC destino: ", c_ethernet->h_dest, 6, imp_tipo );
				
		//Aponta para o campo de MAC origem e imprime os proximos 6 bytes
		imprimirBytes("MAC origem: ", c_ethernet->h_source, 6, imp_tipo);
			
	}
	else
	{
		printf("Cabecalho Ethernet defeituoso!\n");
	}
}

void cabecalhoIp(unsigned char *packet, int len, int imp_tipo)
{
	struct ethhdr *c_ethernet;
	struct iphdr *c_ip;

	                         

	c_ethernet = (struct ethhdr *)packet;

	if(ntohs(c_ethernet->h_proto) == ETH_P_IP)
	{
		
		
		if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
		{
			c_ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
			
			printf("IP destino: %s\n", inet_ntoa(c_ip->daddr));
			printf("IP fonte: %s\n", inet_ntoa(c_ip->saddr));
	

		}
		else
		{
			printf("Cabecalho IP defeituoso!\n");
		}

	}
	else
	{
		printf("Pacote nao possui cabecalho IP!\n");
	}

}



void cabecalhoTcp(unsigned char *p , int tam, int imp_tipo)
{
	struct ethhdr *c_ethernet;
	struct iphdr *c_ip;
	struct tcphdr *c_tcp;

	if(tam >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
		
		c_ethernet = (struct ethhdr *)p;

		if(ntohs(c_ethernet->h_proto) == ETH_P_IP)
		{
			c_ip = (struct iphdr *)(p + sizeof(struct ethhdr));

			if(c_ip->protocol == IPPROTO_TCP)
			{
				//Lembrete ihl tras o tamanho exato do header em multiplo de 4
				c_tcp = (struct tcphdr*)(p + sizeof(struct ethhdr) + c_ip->ihl*4 );
				printf("Protocolo: TCP \n");
				printf("Numero de sequencia: %d\n", ntohs(c_tcp->seq));
				printf("Porta fonte: %d\n", ntohs(c_tcp->source));
				printf("Porta destino: %d\n", ntohs(c_tcp->dest));

			}
			else
			{				
				printf("(UDP)Nao possui cabecalho TCP\n");
			}
		}
		
	}
	else
	{
		printf("Cabecalho TCP defeituoso!");

	} 
}

int pacoteIp(unsigned char *packet, int tam, char *sip, char *dip)
{
	struct ethhdr *c_ethernet;
	struct iphdr *c_ip;

	                         

	c_ethernet = (struct ethhdr *)packet;

	if(ntohs(c_ethernet->h_proto) == ETH_P_IP)
	{
		
		
			if(tam >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
			{
				c_ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
			
				if( (strcmp(inet_ntoa(c_ip->daddr),dip)==0 && strcmp(inet_ntoa(c_ip->saddr),sip)==0) ||
				   (strcmp(dip,ALL_IP)==0 && strcmp(inet_ntoa(c_ip->saddr),sip)==0)  ||
				   (	strcmp(inet_ntoa(c_ip->daddr),dip)==0 && strcmp(sip,ALL_IP)==0 ) ||
					(strcmp(dip,ALL_IP)==0 && strcmp(sip,ALL_IP)==0) )
					return 1;
	

			}
			else
			{
				return 0;
			}

	}else
	{
		return 0;
	}

return 0;

}


int protocoloTransporte(unsigned char *p, int tam, int protocolo)
{
	

	struct ethhdr *c_ethernet;
	struct iphdr *c_ip;
	
	if(tam >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
			c_ip = (struct iphdr *)(p + sizeof(struct ethhdr));
						
			if(c_ip->protocol == IPPROTO_TCP)
			{
				if(protocolo== TCP || protocolo== TCP_UDP)
				return TCP;else
				return -1;
			}else
			if(c_ip->protocol == IPPROTO_UDP || protocolo== TCP_UDP)
			{
				if(protocolo== UDP)
				return UDP;else
				return -1;
				
			}else
			return -1;
	}

}


int pacoteTCP(unsigned char *p ,int sporta, int dporta, int tam)
{
	struct ethhdr *c_ethernet;
	struct iphdr *c_ip;
	struct tcphdr *c_tcp;

	if(tam >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
			c_ip = (struct iphdr *)(p + sizeof(struct ethhdr));

			
			
				//Lembrete ihl tras o tamanho exato do header em multiplo de 4
				c_tcp = (struct tcphdr*)(p + sizeof(struct ethhdr) + c_ip->ihl*4 );
			
				
					if( 
					     ((ntohs(c_tcp->source)) == sporta && dporta==-1) 
					   || ((ntohs(c_tcp->dest))==dporta && sporta==-1)
					   || (dporta==-1 && sporta==-1) 
					   || (ntohs(c_tcp->dest)==dporta && ntohs(c_tcp->source) == sporta ))
					
						{
									
							
							return 1;

						}else 
						return 0;

				

		}
		
	

}




int cabecalhoDados (unsigned char *p, int tam, int imp_tipo)
{
	struct ethhdr *c_ethernet;
	struct iphdr *c_ip;
	struct tcphdr *c_tcp;
	unsigned char *c_dados;
	int tamanho_dados;

	if(tam > (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
		
		c_ip = (struct iphdr*)(p + sizeof(struct ethhdr));

		
		c_dados = (p + sizeof(struct ethhdr) + c_ip->ihl*4 +sizeof(struct tcphdr));
		//tot_len inclui o valor ip+tcp+dados (ihl utilizado pois ip possuí campos variaveis)
		tamanho_dados = ntohs(c_ip->tot_len) - c_ip->ihl*4 - sizeof(struct tcphdr);

		if(tamanho_dados!=0)
		{
			printf("Tamanho do cabecalho de dados: %d\n", tamanho_dados);
			imprimirBytes("Dados:", c_dados, tamanho_dados, imp_tipo);
			return 1;	
		}
		else
		{
			printf("Nao existe dados no pacote\n");
			return 0;
		}
	}
	else
	{
		printf("Nao existe dados no pacote\n");
		return 0;
	} 	

}

int aplicaFiltro(unsigned char *packet,int tam, int sporta, int dporta, char *sip, char *dip, int protocolo)
{	
	
		
		
		if(pacoteIp(packet, tam, sip, dip)) 
		{
			int tipo = protocoloTransporte(packet, tam, protocolo);// verifica consistencia do protocolo de transporte

			if(protocolo== TCP || protocolo == TCP_UDP)
			{
				

				if(tipo == TCP)
					if( pacoteTCP(packet, sporta, dporta,  tam)) 
						{
					
						return TCP;
						}
				
				
			}else
			if(protocolo== UDP || protocolo == TCP_UDP)
			{
				if(tipo == UDP)
					if( pacoteUDP(packet, sporta, dporta,  tam))
						return UDP;
				
			}	
		}

return -1;
}


void capturarPacotes(int sock, int n, int dado, int sporta, int dporta, char *sip, char *dip, int protocolo)
{

	int tam;
	unsigned char packet_buffer[2048]; 
	struct sockaddr_ll packet_info;
	int packet_info_size = sizeof(packet_info);
	int incpack=0;

	int tipo=-1;

	while(n>0  || n==-1)
	{
		if((tam = recvfrom(sock, packet_buffer, 2048, 0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1)
		{
			printf("Erro ao receber pacote!");
			exit(-1);
		}
		else
		{
			
			
			if((tipo=aplicaFiltro(packet_buffer, tam, sporta, dporta, sip, dip, protocolo))>=0)
			{
			
				incpack++;
				printf("\n\nPacote:%d\n\n",incpack);
				cabecalhoEthernet(packet_buffer, tam, HEX);			
				cabecalhoIp(packet_buffer, tam, HEX);
				
				if(tipo == UDP)
					cabecalhoUdp(packet_buffer, tam, dado);else
					cabecalhoTcp(packet_buffer, tam, dado);

			
				cabecalhoDados(packet_buffer, tam, dado);
			
				if(n!=-1)
				  n--;
			
			}
		
		}
	}
}


int main(int argc, char **argv)
{
	int raw;
	int len;
	    
	
	int sporta=-1;
	int dporta=-1;
	
	char sip[] = ALL_IP;
	char dip[] = ALL_IP;

	int npacotes = -1;
	
	int protocolo = TCP_UDP;
	
	int dados = HEX;
	
	char interface[] = "eth0";
	
	int i;
	
	if(geteuid() != 0)
	{
		printf("Para executar este programa voce deve ser root!\n");	
		exit(-1);	
	}	

	for(i=1; i<argc; i++)
	{
		if(strcmp(argv[i], "-i")==0)
		{	
			strcpy(interface, argv[++i]);
		}
		
		if(strcmp(argv[i], "-n")==0)
		{			
			npacotes = atoi(argv[++i]);
		}else
		
		if(strcmp(argv[i], "-sport")==0)
		{			
			sporta = atoi(argv[++i]);
			
		}else
		
		if(strcmp(argv[i], "-dport")==0)
		{			
			dporta = atoi(argv[++i]);
			
		}else
		
		if(strcmp(argv[i], "-p")==0)
		{			
			i++;
			if(strcmp(argv[i], "UDP")==0)
			{			
				protocolo = UDP;
				
			}else
			if(strcmp(argv[i], "TCP")==0)
			{
				protocolo = TCP;
				
			}else
			if(strcmp(argv[i], "TCP_UDP")==0)
			{
				protocolo = TCP_UDP;
				
			}else
			{
				printf("Erro de sintaxe, protocolo inadequado.\n");
				exit(-1);
			}		
		}else
		
		

		if(strcmp(argv[i], "-data")==0)
		{			
			i++;
			if(strcmp(argv[i], "HEX")==0)
			{
				dados = HEX;
			}else
			if(strcmp(argv[i], "ASCII")==0)
			{			
				dados = ASCII;
			}else
			{
			printf("Tipo -data incorreto. \n");			
			exit(-1);			
			}

		}else

		if(strcmp(argv[i], "-sip")==0)
		{			
			strcpy(sip,argv[++i]);
			
		}else
		
		if(strcmp(argv[i], "-dip")==0)
		{			
			strcpy(dip,argv[++i]);
		}else
		if(strcmp(argv[i], "-help")==0)
		{			
			printf("Parametros possiveis:\n-i (interface) \n-dport, -sport (porta) \n-sip, -dip (ip) \n-data (HEX, ASCII) \n-p (TCP, UDP, TCP_UDP) 					\n-n (numero de pacotes)\n-help (ajuda)");
			exit(-1);
		}
		
		
	}

		
		printf("Escutando a interface:%s\n", interface);

			
		raw = criarSocket(ETH_P_IP);
	

		associarSocketInterface(interface, raw, ETH_P_IP);

		
		capturarPacotes(raw, npacotes, dados, sporta, dporta, sip, dip, protocolo );

	
	
	
	return 0;
}



