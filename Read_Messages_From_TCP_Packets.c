#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <pcap.h>

#define PCAP_BUF_SIZE 1024
#define PCAP_SRC_FILE 2

int synCount[PCAP_BUF_SIZE];
int synIdx = 0;
char synIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];
int httpCount[PCAP_BUF_SIZE];
int httpIdx = 0;
char httpIP[PCAP_BUF_SIZE][INET_ADDRSTRLEN];
int total_packet = 0;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int main(int argc, char **argv) {

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    int i;

    if(argc != 2) {
        printf("usage: %s filename\n", argv[0]);
        return -1;
    }

    fp = pcap_open_offline(argv[1], errbuf);
    if (fp == NULL) {
   fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
   return -1;
    }
   
    if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        return 0;
    }

    


    printf("Protocol Summary: %d TCP packets\n", total_packet);
    return 0;
   }
   void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    int i;

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header)+ sizeof(ipHeader));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
        
if (ipHeader->ip_p == IPPROTO_TCP) {
        printf("\n");
        printf("Source Address: %s\n",sourceIP);
        printf("Destination Address: %s\n",destIP);
        printf("%s\n",(packet + sizeof(struct ether_header)+ sizeof(ipHeader)+sizeof(tcpHeader)+36));
        total_packet++;
        }
    }
}
