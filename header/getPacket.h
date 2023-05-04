#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

void packetCapture(char* dev, char* filter);
void packetCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);