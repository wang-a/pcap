
//#include <pcap.h>
//#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>	/* includes net/ethernet.h */


struct Ethernet_header
{
	u_int8_t dstMac[6]; //destination ethernet address
	u_int8_t srcMac[6]; //source ethernet address
	u_int16_t ethType; //packet type ID
}

struct IP_header
{
	u_int8_t ipver;		//version
	u_int8_t tos;		//type of service
	u_int16_t iplen;	//total length
	u_int16_t packId;	//identification
	u_int16_t ipFlag;	
	u_int8_t ttl;		//time to live
	u_int8_t protocol;	//protocol
	u_int16_t cheksum;	//scheck sum
	struct in_addr ip_src, dst_ip; //source and dest address
}

struct TCP_header
{
	u_int16_t sport;	//source port
	u_int16_t dport;	//destination port
	u_int32_t th_seq;	//sequence number
	u_int32_t th_ack;	//acknoledgement number
	u_int8_t offset;	//data offset
	u_int8_t flag;		//control flasgs
	u_int16_t th_win;	//window
	u_int16_t th_sum;	//checksum
	u_int16_t th_urp;	//urgent pointer
}



int main(int argc, char **argv)

{
	int i;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr hdr;			/* pcap.h */
	struct ether_header *eptr;	/* net/ethernet.h */
	struct Ethernet_header *ethernet;
	struct IP_header *ip;
	struct TCP_header *tcp;

	
	u_char *ptr;	//network-header-info

	dev=pcap_lookupdev(errbuf);	//device setting
	if (dev == NULL) 
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	printf("DEV: %s\n", dev);
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf);
		return(2);
	}
	while(1){
	packet = pcap_next(handle, &hdr);
	if (packet == NULL)
	{
		printf("Didn't grab packet\n");
		exit(1);
	}
	
	/*
	 *  struct pcap_pkthdr 
	   {
	 * 	struct timeval ts;	/time stamp
	 * 	bpf_u_int32 caplen;	/length of portion present
	 * 	bpf_u_int32;		/length this packet (off wire) 
	   }	 
	*/
	
	printf("Grabbed packet of length %d\n", hdr.len);
	printf("Received at ..... %d\n", ctime((const time_t*)&hdr.ts.tv_sec));
	printf("Ethernet address length is %d\n", ETHER_HDR_LEN);
	
	eptr = (struct ether_header *)packet;
	
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
	{
		printf("Ethernet type hex:%x dec:%d is an IP packet\n", ntohs(eptr->ether_type),ntohs(eptr->ether_type));
	}
	else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
	{
		printf("Ethernet type hex:%x dec:%d is an ARP packet\n",ntohs(eptr->ether_type),ntohs(eptr->ether_type));
	}
	else
	{
		printf("Ethernet type hex:%x not IP\n",	ntohs(eptr->ether_type));
		exit(1);
	}
}
	ptr = eptr->ether_dhost;
	i = ETHER_ADDR_LEN;
	printf(" Destination Address : ");
	do {
		printf("%s%x", ( i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
	} while(--i > 0);
	printf("\n");
	
	ptr = eptr->ether_shost;
	i = ETHER_ADDR_LEN;
	printf(" Source Address: ");
	do {
		printf("%s%x", ( i == ETHER_ADDR_LEN ) ? " " : ":", *ptr++);
	} while( --i > 0);
	printf("\n");

	return(0);
 }









	/* original code
	pcap_t *handle;			
	char *dev;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct bpf_program fp;		
	char filter_exp[] = "port 80";	
	bpf_u_int32 mask;		
	bpf_u_int32 net;		
	struct pcap_pkthdr header;	
	const u_char *packet;		


	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	int status = 0;
	while(1){
		status= pcap_next_ex(handle, &header, &packet);
		if(status == 0) {
			continue;
		}
		
		printf("destination Mac[%02x:%02x:%02x:%02x:%02x:%02x]\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
		printf("source Mac [%02x:%02x:%02x:%02x:%02x:%02x]\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
		puts("");
		if(packet[12]==0x08 && packet[13]==0x00){
			printf("IP:[%d.%d.%d.%d]\n",packet[26],packet[27],packet[28],packet[29]);
		}
		puts("");		
	}
	
	
	pcap_close(handle);
*/

/*other test(win)-> out!!
#include <winsock2.h>

#pragma comment(lib,"wsock32.lib") // pragma comment Used to include specific library files

SOCKET s; //socket descriptor(handle) similar FILE *fp, socket open data sending and receive, end
	WASDATA wsaData;
	struct sockaddr_in sin;
	struct 




	if(WSAStartup(WINSOCK_VERSION,&wasData)!=0)
	{
		printf("WSAStartup fail,error code = %d \n",WSAGetLastError());
		return ;
	}
	puts(wsaData.szDescription);
	puts(wsaData.szSystemStatus);

	s=socket(AF_INET,SOCK_STREAM,IPPOTO_TCP); //create TCP/IP socket*/

		/*if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		int status = 0;
		while(1){
			status= pcap_next_ex(handle, &header, &packet);
			if(status == 0) {
				continue;
			}
			printf("------------------------------------------------------------------------------\n");
			printf("destination Mac[%02x:%02x:%02x:%02x:%02x:%02x]\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
			printf("source Mac [%02x:%02x:%02x:%02x:%02x:%02x]\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
			puts("");
			if(packet[12]==0x08 && packet[13]==0x00){
				printf("source IP:[%d.%d.%d.%d]\n",packet[26],packet[27],packet[28],packet[29]);
				printf("destination IP:[%d.%d.%d.%d]\n",packet[30],packet[31],packet[32],packet[33]);
			}
			puts("");

			printf("Source Port : %d\n",packet[34]*256 + packet[35]);
			printf("Destination Port: %d\n",packet[36]*256 + packet[37]);
			puts("");
			int tcpnum = packet[46] >> 4;
			int tcplen = tcpnum*4;
			for(int i=34+tcplen;i<44+tcplen;i++)
				printf("%c",packet[i]);
			printf("\n");
										
		}	
		
		pcap_close(handle);
		return(0);
	 }*/
