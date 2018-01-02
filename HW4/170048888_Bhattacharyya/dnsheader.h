#ifndef _DNSHEADER
#define _DNSHEADER


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define MAX_FORGED_HOSTNAMES 100
#define IP_MAX_LENGTH 16
#define MAX_HOSTNAME_LENGTH 128

#define DNS_RESPONSES_MAX 1000
#define MAX_ANSWER_RECORDED 20

// USED ON BOTH dnsinject.c and dnsdetect.c programs
struct dnshdr   {
    unsigned    id:      16;
    unsigned    rd:       1;
    unsigned    tc:       1;
    unsigned    aa:       1;
    unsigned    opcode:   4;
    unsigned    qr:       1;
    unsigned    rcode:    4;
    unsigned    cd:       1;
    unsigned    ad:       1;
    unsigned    unused:   1;
    unsigned    ra:       1;
    unsigned    qdcount: 16;
    unsigned    ancount: 16;
    unsigned    nscount: 16;
    unsigned    arcount: 16;
};


/* IP header */
struct ip {
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


/* UDP header */
struct udp {
    u_short sport;    /* source port */
    u_short dport;    /* destination port */
    u_short udp_length;
    u_short udp_sum;    /* checksum */
};


struct udphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int16_t len;
    u_int16_t check;
};

// FOLLOWING STRUCTURS AND CONSTANS USED ONLY IN dnsdetect.c program

struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

struct DNSResponseInfo{
    int id;
    char hostName[MAX_HOSTNAME_LENGTH];
    int answerCount;
    char answers[MAX_ANSWER_RECORDED][IP_MAX_LENGTH];
};

#endif
