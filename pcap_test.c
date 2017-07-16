#include <pcap.h>
#include <stdio.h>

	 int main(int argc, char *argv[])
	 {
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
		}
		pcap_close(handle);
		return(0);
	 }
