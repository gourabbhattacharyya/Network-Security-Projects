#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806



/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};



/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* UDP header */
struct sniff_udp {
    u_short sport;    /* source port */
    u_short dport;    /* destination port */
    u_short udp_length;
    u_short udp_sum;    /* checksum */
};


/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


//=====================ARP Reuqet and reply======================
#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
typedef struct arphdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
}arphdr_t;



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


void print_payload(const u_char *payload, int len);


void print_hex_ascii_line(const u_char *payload, int len, int offset);




/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}



/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}




// display info for each packet
void handle_packet(char *string, const struct pcap_pkthdr *header, const u_char *packet) {
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const struct sniff_udp *udp;
    const u_char *payload;
    arphdr_t *arpheader = NULL;       /* Pointer to the ARP header              */
    
    int size_ip;
    int size_tcp;
    int size_udp = 8; // fixed udp header length
    int size_icmp = 8; // fixed udp header length
    int size_payload;
    
    
    // print out time stamp. convert elapse time to date,
    // then remove new line symbol at the end
    char buf[30], timebuf[64];
    struct tm *sTm;
    time_t raw_time = (time_t)header->ts.tv_sec;
    time_t millisec = (time_t)header->ts.tv_usec;
    sTm = localtime(&raw_time);
    if (sTm != NULL) {
        strftime (buf, sizeof(buf), "%Y-%m-%d %H:%M:%S.%%06u", sTm);
        snprintf(timebuf, sizeof(timebuf), buf, millisec);
        printf("%s ", timebuf);
    }
    
    
    // extract ethernet header
    ethernet = (struct sniff_ethernet*)(packet);
    
    if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {
        printf("IPv4 ");
        // extract ip header
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("* Invalid IP header length: %u bytes\n", size_ip);
            return;
        }
        
        // for tcp packet
        if (ip->ip_p == IPPROTO_TCP) {
            
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                printf("* Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            printf("%02x:%02x:%02x:%02x:%02x:%02x -> ", (unsigned int)(ethernet->ether_shost)[0], (unsigned int)(ethernet->ether_shost)[1], (unsigned int)(ethernet->ether_shost)[2], (unsigned int)(ethernet->ether_shost)[3], (unsigned int)(ethernet->ether_shost)[4], (unsigned int)(ethernet->ether_shost)[5]);
            printf("%02x:%02x:%02x:%02x:%02x:%02x ", (unsigned int)(ethernet->ether_dhost)[0], (unsigned int)(ethernet->ether_dhost)[1], (unsigned int)(ethernet->ether_dhost)[2], (unsigned int)(ethernet->ether_dhost)[3], (unsigned int)(ethernet->ether_dhost)[4], (unsigned int)(ethernet->ether_dhost)[5]);
            
            printf("type %#x ", ntohs(ethernet->ether_type));
            printf("len %d ", ntohs(ip->ip_len));
            printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
            printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf("TCP ");
            
            // extract payload
            payload = (packet + SIZE_ETHERNET + size_ip + size_tcp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
            
            // print payload
            if (size_payload > 0) {
                printf("Payload (%d bytes):\n", size_payload);
                
                if (string != NULL) {
                    if (strstr((char *)payload, string) == NULL)
                        return;
                }
                
                print_payload(payload, size_payload);
            }
            printf("\n");
        } else if (ip->ip_p == IPPROTO_UDP) {
            
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            
            printf("%02x:%02x:%02x:%02x:%02x:%02x -> ", (unsigned int)(ethernet->ether_shost)[0], (unsigned int)(ethernet->ether_shost)[1], (unsigned int)(ethernet->ether_shost)[2], (unsigned int)(ethernet->ether_shost)[3], (unsigned int)(ethernet->ether_shost)[4], (unsigned int)(ethernet->ether_shost)[5]);
            printf("%02x:%02x:%02x:%02x:%02x:%02x ", (unsigned int)(ethernet->ether_dhost)[0], (unsigned int)(ethernet->ether_dhost)[1], (unsigned int)(ethernet->ether_dhost)[2], (unsigned int)(ethernet->ether_dhost)[3], (unsigned int)(ethernet->ether_dhost)[4], (unsigned int)(ethernet->ether_dhost)[5]);
            
            printf("type %#x ", ntohs(ethernet->ether_type));
            printf("len %d ", ntohs(ip->ip_len));
            printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
            printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
            printf("UDP ");
            
            // extract payload
            payload = (packet + SIZE_ETHERNET + size_ip + size_udp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
            
            // print payload
            if (size_payload > 0)
            {
                printf("Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
            }
            printf("\n");
        } else if (ip->ip_p == IPPROTO_ICMP) {
            
            printf("%02x:%02x:%02x:%02x:%02x:%02x -> ", (unsigned int)(ethernet->ether_shost)[0], (unsigned int)(ethernet->ether_shost)[1], (unsigned int)(ethernet->ether_shost)[2], (unsigned int)(ethernet->ether_shost)[3], (unsigned int)(ethernet->ether_shost)[4], (unsigned int)(ethernet->ether_shost)[5]);
            printf("%02x:%02x:%02x:%02x:%02x:%02x ", (unsigned int)(ethernet->ether_dhost)[0], (unsigned int)(ethernet->ether_dhost)[1], (unsigned int)(ethernet->ether_dhost)[2], (unsigned int)(ethernet->ether_dhost)[3], (unsigned int)(ethernet->ether_dhost)[4], (unsigned int)(ethernet->ether_dhost)[5]);
            
            printf("type %#x ", ntohs(ethernet->ether_type));
            printf("len %d ", ntohs(ip->ip_len));
            printf("%s -> ", inet_ntoa(ip->ip_src));
            printf("%s ", inet_ntoa(ip->ip_dst));
            printf("ICMP ");
            
            // extract payload
            payload = (packet + SIZE_ETHERNET + size_ip + size_icmp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
            
            // print payload
            if (size_payload > 0)
            {
                printf("Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
            }
            printf("\n");
        } else {
            
            printf("%02x:%02x:%02x:%02x:%02x:%02x -> ", (unsigned int)(ethernet->ether_shost)[0], (unsigned int)(ethernet->ether_shost)[1], (unsigned int)(ethernet->ether_shost)[2], (unsigned int)(ethernet->ether_shost)[3], (unsigned int)(ethernet->ether_shost)[4], (unsigned int)(ethernet->ether_shost)[5]);
            printf("%02x:%02x:%02x:%02x:%02x:%02x ", (unsigned int)(ethernet->ether_dhost)[0], (unsigned int)(ethernet->ether_dhost)[1], (unsigned int)(ethernet->ether_dhost)[2], (unsigned int)(ethernet->ether_dhost)[3], (unsigned int)(ethernet->ether_dhost)[4], (unsigned int)(ethernet->ether_dhost)[5]);
            
            printf("type %#x ", ntohs(ethernet->ether_type));
            printf("IP ");
            // extract payload
            payload = (packet + SIZE_ETHERNET + size_ip);
            size_payload = ntohs(ip->ip_len) - (size_ip);
            
            // print payload
            if (size_payload > 0)
            {
                printf("Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
            }
            printf("\n");
        }
    } else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
        
        arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */
        
        //printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
        printf("%s ", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
        
        
        /* If is Ethernet and IPv4, print packet contents */
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
            
            //Source MAC
            printf("%02X:%02X:%02X:%02X:%02X:%02X -> ", arpheader->sha[0], arpheader->sha[1], arpheader->sha[2], arpheader->sha[3], arpheader->sha[4], arpheader->sha[5]);
            
            //Target MAC
            printf("%02X:%02X:%02X:%02X:%02X:%02X ", arpheader->tha[0], arpheader->tha[1], arpheader->tha[2], arpheader->tha[3], arpheader->tha[4], arpheader->tha[5]);
            
            
            printf("type %#x ", ntohs(arpheader->ptype));
            printf("len %d ", header->len);
                   
           
            //Sender IP
            printf("%d.%d.%d.%d -> ", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]);

            //Target IP
            printf("%d.%d.%d.%d ", arpheader->tpa[0], arpheader->tpa[1], arpheader->tpa[2], arpheader->tpa[3]);
            
            printf("%s ", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");
            
            printf("\n");
            
        }
        //printf("ARP\n");
        
        
    } else {
        
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        
        printf("OtherType ");
        
        //Source MAC
        printf("%02x:%02x:%02x:%02x:%02x:%02x -> ", (unsigned int)(ethernet->ether_shost)[0], (unsigned int)(ethernet->ether_shost)[1], (unsigned int)(ethernet->ether_shost)[2], (unsigned int)(ethernet->ether_shost)[3], (unsigned int)(ethernet->ether_shost)[4], (unsigned int)(ethernet->ether_shost)[5]);
        
        //Target MAC
        printf("%02x:%02x:%02x:%02x:%02x:%02x ", (unsigned int)(ethernet->ether_dhost)[0], (unsigned int)(ethernet->ether_dhost)[1], (unsigned int)(ethernet->ether_dhost)[2], (unsigned int)(ethernet->ether_dhost)[3], (unsigned int)(ethernet->ether_dhost)[4], (unsigned int)(ethernet->ether_dhost)[5]);
        
        printf("type ");
        printf("OTHER ");
        
        printf("len %d ", ntohs(ip->ip_len));
        printf("%s -> ", inet_ntoa(ip->ip_src));
        printf("%s ", inet_ntoa(ip->ip_dst));
        printf("Unknown ");
        
        // extract payload
        payload = (packet + SIZE_ETHERNET + size_ip);
        size_payload = ntohs(ip->ip_len) - (size_ip);
        
        // print payload
        if (size_payload > 0)
        {
            printf("Payload (%d bytes):\n", size_payload);
            print_payload(payload, size_payload);
        }
        printf("\n");
        
    }
    
    return;
}




/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	char *string = NULL;
    
    if (args != NULL) {
        string = (char *)args;
    }
    
    
    if (string == NULL)
        handle_packet(string, header, packet);
    
    else {
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;
	const u_char *payload;                    /* Packet payload */
    arphdr_t *arpheader = NULL;       /* Pointer to the ARP header              */

	int size_ip;
	int size_tcp;
    int size_udp = 8; // fixed udp header length
    int size_icmp = 8; // fixed udp header length
	int size_payload;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
    
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print time with millisec*/
    char buf[30], timebuf[64];
    struct tm *sTm;
    time_t raw_time = (time_t)header->ts.tv_sec;
    time_t millisec = (time_t)header->ts.tv_usec;
    sTm = localtime(&raw_time);
    if (sTm != NULL) {
        strftime (buf, sizeof(buf), "%Y-%m-%d %H:%M:%S.%%06u", sTm);
        snprintf(timebuf, sizeof(timebuf), buf, millisec);
        printf("%s ", timebuf);
    }
    
    
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
            
            /* define/compute tcp header offset */
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                //printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            
            /* define/compute tcp payload (segment) offset */
            payload = (packet + SIZE_ETHERNET + size_ip + size_tcp);
            
            /* compute tcp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
            
			break;
            
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
            
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            payload = (packet + SIZE_ETHERNET + size_ip + size_udp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
			break;
            
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
            
            payload = (packet + SIZE_ETHERNET + size_ip + size_icmp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
            
			break;
            
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
            
            payload = (packet + SIZE_ETHERNET + size_ip);
            size_payload = ntohs(ip->ip_len) - (size_ip);
            
			break;
            
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		//printf("   Payload (%d bytes):\n", size_payload);
        //print_payload(payload, size_payload);
        
        char str_payload[size_payload];
        strncpy(str_payload, (char *)payload, size_payload);
        
        if (strstr(str_payload, string) == NULL)
        {
            return;
        }
        else
            handle_packet(string, header, packet);
    }
    return;
    }
}



int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
    char *file = NULL;
    char *string = NULL;
    char filter_exp[256] = "";        /* filter expression [3] */
    
    
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
    
    struct pcap_pkthdr header;
    const u_char *packet;
    
    arphdr_t *arpheader = NULL;       /* Pointer to the ARP header              */
    
	int num_packets = 10;			/* number of packets to capture */


	/* get the input values from command-line */
	if (argc > 2) {
        for (int i = 2; i <= argc; i++) {
            //if (i % 2 != 0) {
                /* determine commandline input */
                if(strcmp(argv[i-1], "-i") == 0){
                        //printf("   In i \n");
                        //printf("Value of Argc for filter for -i: %s\n", argv[(i - 1)]);
                        dev = argv[(i)];
                        i++;
                }else if (strcmp(argv[i-1], "-r") == 0){
                        //printf("   In r: UDP\n");
                        //printf("Value of Argc for filter for -r: %s\n", argv[(i - 1)]);
                        file = argv[(i)];
                        i++;
                }
                else if (strcmp(argv[i-1], "-s") == 0){
                        //printf("   In S: ICMP\n");
                        //printf("Value of Argc for filter for -s: %s\n", argv[(i - 1)]);
                        string = argv[(i)];
                        i++;
                }
                else {
                    strcat(filter_exp, argv[(i - 1)]);
                    //printf("Value of Argc for filter : %s\n", filter_exp);
                }
        //}
        }
        
        /*
        if ((strcmp(argv[argc-2], "-i") != 0) && (strcmp(argv[argc-2], "-r") != 0) && (strcmp(argv[argc-2], "-s") != 0)){
            strcat(filter_exp, argv[(argc - 1)]);
            printf("Value of Argc for filter : %s\n", filter_exp);
        }*/
	}
	else if (argc == 2) {
		fprintf(stderr, "error: unrecognized command-line options for interface name\n\n");
		exit(EXIT_FAILURE);
	}
    
    
    if ((dev == '\0' || dev == NULL) && file == NULL) {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }
    
    
    /*check if both interface and fileName provided */
    if (dev != NULL && file != NULL) {
        printf("You can only use interface OR pcapFile read options!\n");
        return 0;
    }
    
    
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

    
	/* print capture info */
    printf("\nInitializing mydump using following parameters for MyDump by Gourab Bhattacharyya_170048888:\n Device: %s\n pacpFile: %s\n Search String pattern: %s\n Filter Expression: %s\n\n\n", dev, file, string, filter_exp);
	//printf("Number of packets: %d\n", num_packets);

	
    /* capture traffic or read from PCAP file */
    if (dev != NULL && file == NULL) {
        /* open capture device */
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else if(dev == NULL && file != NULL) {
        handle = pcap_open_offline(file, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }
    }

    
    
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

    
	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, (u_char *)string);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

