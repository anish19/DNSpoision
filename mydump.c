#include "mydump.h"

void print_tp(int num){
	switch(num){
		case 1:
			printf("ICMP" );
			break;
		case 6:
			printf("TCP");
			break;
		case 17:
			printf("UDP");
			break;
		case 132:
			printf("SCTP");
			break;
		default:
			printf("OTHER");
			break;
	}
}
int printable(char ch){
	if(ch >= 32 && ch <=126)return 1;
	return 0;
}

void readPackets(char* dev, pcap_t *handler, char* BPFfilters, char* strpattern){
	//The header that pcap gives us
	struct pcap_pkthdr *header;
	//header = (struct pcap_pkthdr*) malloc(sizeof(struct pcap_pkthdr));
	//The actual packet 
	const u_char *data;   
	//data = (u_char*) malloc(65535);
	int ret;
	struct ethernet_pack *ethernet;
	struct ip_pack *ip;
	struct tcp_pack *tcp;
	struct bpf_program fp;
	bpf_u_int32 net;		/* Our IP */
	bpf_u_int32 mask;		/* Our netmask */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	
	int filter_size = 0;
	if(BPFfilters != NULL)
		filter_size = strlen(BPFfilters);
	
	ethernet = (struct ethernet_pack*) malloc(sizeof(struct ethernet_pack));	
	ip = (struct ip_pack*) malloc(sizeof(struct ip_pack));
	tcp = (struct tcp_pack*) malloc(sizeof(struct tcp_pack));	

	if(filter_size > 0){	
		char filter_exp[filter_size];
		strncpy(filter_exp, BPFfilters, filter_size);
		filter_exp[filter_size] = '\0';
//		printf("filter is : %s\n", filter_exp);
		
		/* Find the properties for the device */
		if (dev!= NULL && pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		} 
		/* Compile and apply the filter */
		if (pcap_compile(handler, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handler));
			return;
		}
		if (pcap_setfilter(handler, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handler));
			return;
		}
	}
	while ((ret = pcap_next_ex(handler, &header, &data)) >= 0){
	
//		data = pcap_next(handler, header);
		if(header->len > 0){
			ethernet = (struct ethernet_pack*)(data);
			ip = (struct ip_pack*)(data + SIZE_ETHERNET);
		//	int size_ip = IP_HL(ip)*4;
			int size_ip = 20;
			if (size_ip < 20) {
			    printf("   * Invalid IP header length: %u bytes\n", size_ip);
			    return ;
			}
			tcp = (struct tcp_pack*)(data + SIZE_ETHERNET + size_ip);
			int size_th = TH_OFF(tcp);
			char *payload;
			payload = (char*)(data + SIZE_ETHERNET + size_ip + size_th);
			int payload_size = header->len - (SIZE_ETHERNET+size_ip + size_th);
			int i=0, ctr = 0;
			payload[payload_size] = '\0';
			char temp[payload_size];
			
			if(payload_size > 0 && strpattern != NULL){
				for(i = 0; i < payload_size; i++){
					if(printable(payload[i]) == 1){
						temp[ctr] = payload[i];
						ctr++;
					}
				}
				temp[ctr] = '\0';
				
				char str2[strlen(strpattern)];
				memcpy(str2, strpattern, strlen(strpattern));
				str2[strlen(strpattern)] = '\0';
				if(strstr(temp, str2) == NULL)continue;
			}
//			printf("\n");
			
			char buf[127];
			struct tm tmobj;
			tmobj = *localtime(&header->ts.tv_sec);
			strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmobj);
//    		printf("%s:", buf);
//  		printf("%d ", (int)header->ts.tv_usec);

// 		printf(" %s ->", ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
//  		printf(" %s", ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
    		int type = ntohs(ethernet->ether_type);
//    		printf(" type 0x%x ", type);
//    		printf(" len %d\n", header->len);


//        	printf("%s -> %s ",  inet_ntoa(ip->ip_src),  inet_ntoa(ip->ip_dst));
//        	print_tp(ip->ip_p);
//        	printf("\n");
//		printf("SRC PORT: %d DST PORT: %d \n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		if( (ntohs(tcp->th_sport) == 53 || ntohs(tcp->th_dport) == 53) && (payload[] )){
			printf("this is a DNS packet\n");
			unsigned char buf[65536],*qname,*reader;
			struct RES_RECORD answers[20],auth[20],addit[20];
			struct DNS_HEADER *dns = NULL;
			struct QUESTION *qinfo = NULL;

			dns = (struct DNS_HEADER)payload;
			if(dns->qr == 0){
				printf("this is a DNS query\n");
				
			}
		}

/*		if(ip->ip_p == 6){
				printf("SEQ: %u ACK: %u\n", ntohl(tcp->th_seq), ntohl(tcp->th_ack));
				printf("WINDOW SIZE: %d\n", ntohs(tcp->th_win));
			}
			
			printf("PAYLOAD SIZE: %d\n",payload_size );
			int offset = 0;
			while(offset<16  || offset + 16 < payload_size){
				for(i = 0 ; i < 16; i++){
					printf("%.2x ", payload[i+offset] & 0xff);
				}
				printf("\t\t");
				for(i = 0 ; i < 16; i++){
					if(printable(payload[i + offset]) == 1){
						printf("%c", payload[i+offset]);
					}
					else
						printf(".");
				}
				if(i%16==0)printf("\n");
				offset+=16;
			}
			 
			printf("\n\n");
*/
		}
   	} 
   	return;
}

void captureOnline(char* interface, char* BPFfilters, char* strpattern){
	//error buffer
	char errbuff[PCAP_ERRBUF_SIZE];
	
	if(interface == NULL){	
		//default device
	    interface = pcap_lookupdev(errbuff);
	    if(interface == NULL){
	    	fprintf(stderr,"%s\n",errbuff); 
	    	exit(1); 
	    }
	    // ask pcap for the network address and mask of the device 
	    // pcap_lookupnet(dev,&netp,&maskp,errbuf);
	}
	printf("Interface is : %s\n", interface);
	/*pcap handler
	* interface : interface to monitor 
	* BUFSIZE : max size of packet to capture
	* -1 : promiscuous mode
	* 0 : no timeout. listen endlessly
	* errbuff : error buffer
	*/
	pcap_t *handler = pcap_open_live(interface, BUFSIZE, 1, 1000, errbuff);
	if(handler == NULL){ 
		printf("pcap_open_live() failed: %s\n",errbuff); 
		exit(1); 
	
	}
	readPackets(interface, handler, BPFfilters, strpattern);
	
	return;
}

void captureOffline(char* filename, char* BPFfilters, char* strpattern){
	//error buffer
	char errbuff[PCAP_ERRBUF_SIZE];
	/*pcap handler
	* file : trace file
	* errbuff : error buffer
	*/
	pcap_t *handler = pcap_open_offline(filename, errbuff);
	if(handler == NULL){ 
		printf("pcap_open_live() failed: %s\n",errbuff); 
		exit(1); 
	}
	readPackets(NULL, handler, BPFfilters, strpattern);
	return;
}

int main(int argc, char **argv)
{
	int opt;	//for cmd arg
	int i;		//for loop
	char *interface, *filename, *strpattern=NULL;
	char *BPFfilters = NULL;
	int live = 0;

	while( (opt = getopt(argc, argv, "i:r:s:")) != -1){
		if(opt == -1)break;
		switch(opt){
			case 'i':
				live = 1;
				interface = (char*) malloc(16);
				strcpy(interface, optarg);
				printf("Interface filter is : %s\n", interface);
				break;
			case 'r':
				if(live == 1){
					printf("Can't read from file and interface at the same time.\n");
					printf("Please try again with only one argument set.\n");
					exit(1);
				}
				live = -1;
				filename = (char*) malloc(128);
				strcpy(filename, optarg);
				printf("File filter is : %s\n", filename);
				break;
			case 's':
				strpattern = (char*) malloc(1024);
				strcpy(strpattern, optarg);
				printf("String filter is : %s\n", strpattern);
				break;
			default:
				printf("in default\n");
				break;
		}
	}
	int filterSize = 0;
	if(abs(optind - argc) > 0){
		for(i = optind; i < argc; i++){
			filterSize += strlen(argv[i])+1;
		}
		BPFfilters = (char*)malloc(filterSize);
		int ctr = 0;
		for(i = optind; i < argc; i++){
			strncpy(BPFfilters+ctr, argv[i], strlen(argv[i]));
			ctr += strlen(argv[i]);
			BPFfilters[ctr] = ' ';
			ctr++;
		}
		BPFfilters[ctr] = '\0';
	}
	if(filterSize > 0){
		printf("filter is %s\n", BPFfilters);
	}
	if(live == 1){
		printf("Capturing Live\n");
		//capture packets from specified interface
		captureOnline(interface, BPFfilters, strpattern);

	}
	else if(live == -1){
		printf("Capturing Offline\n");
		//read packets from trace file
		captureOffline(filename, BPFfilters, strpattern);
	}
	else{
		printf("Capturing from Default Interface\n");
		//read packet from default interface
		captureOnline(NULL, BPFfilters, strpattern);
	}

	return 0;
}
