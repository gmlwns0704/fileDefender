#include "header/getPacket.h"
#include "header/getProc.h"
#include "header/tcpkiller.h"
#include "header/clientManage.h"
#include <time.h>

/*
struct pcap_pkthdr {
	struct timeval ts; // time stamp
	bpf_u_int32 caplen; // length of portion present
	bpf_u_int32 len; // length this packet (off wire)
};
*/

#define LOOPCNT 100
//https://www.tcpdump.org/pcap.html
void packetCapture(char* dev, char* filter){

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; // 필터 설정 저장
    bpf_u_int32 mask; // 서브넷 마스크
    bpf_u_int32 net; // 호스트 주소
    struct pcap_pkthdr hdr; // 패킷 헤더

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        perror("lookup_net");
        exit(1);
    }

    pcap_t* pcd = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if(pcd == NULL){
        perror("pcap_open_live");
        exit(1);
    }

    if(pcap_compile(pcd, &fp, filter, 0, net) < 0){
        perror("pcap_compile");
        exit(1);
    }
    if(pcap_setfilter(pcd, &fp) < 0) {
	    perror("pcap_setfilter");
	    exit(1);
    }


    // loop 시작
    struct clientList clHead;
    clHead.next = NULL;
    inet_aton("127.0.0.1", &(clHead.data.addr));
    clHead.data.lastTime = 0;
    //pcap_loop(pcd, 반복회수, 콜백, 콜백 args)
    pcap_loop(pcd, LOOPCNT, packetCallback, &clHead);
}

void packetCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header* etherHdr;
    struct ip* ipHdr;
    int offset = 0;

    // 패킷을 읽을 당시의 헤더
    time_t pcapTime = time(NULL);

    // 이더넷 헤더
    etherHdr = (struct ether_header*)(packet + offset);
    offset += sizeof(struct ether_header);

    // IP가 아닌 패킷
    if(ntohs(etherHdr->ether_type) != ETHERTYPE_IP){
        return;
    }

    ipHdr = (struct ip*)(packet + offset);
    offset += sizeof(struct ip);

    // tcp 패킷
    if(ipHdr->ip_p == IPPROTO_TCP){
        struct tcphdr* tcpHdr = (struct tcphdr*)(packet + offset);
        offset += sizeof(struct tcphdr);

        printf("pcap: dest port: %d\n", ntohs(tcpHdr->dest));
        struct procInfo info;

        // 프로세스를 발견하지 못함
        if(getProcInfoByPort(&info, ntohs(tcpHdr->dest)) == NULL){
            return;
        }
        
        printProcInfo(&info);
        /*
        printf("Src Address : %s\n", inet_ntoa(ipHdr->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(ipHdr->ip_dst));
        printf("Src Port : %d\n" , ntohs(tcpHdr->source));
        printf("Dst Port : %d\n" , ntohs(tcpHdr->dest));
        여기서 패킷의 정보, 프로세스 정보, 프로세스의 접근파일 목록을 조건과 비교, 
        */

        int childPids[10];
        int childsNum = getChildPids(info.pid, childPids, 10);
        if(childsNum == -1){
            perror("getChildsPids");
            return;
        }

        printf("printing %d child pids...\n", childsNum);
        for(int i = 0; i < childsNum; i++){
            printf("%d ", childPids[i]);
        }
        printf("\n");

        struct client clInfo;
        clInfo.addr = ipHdr->ip_src;
        clInfo.lastTime = pcapTime;

        // 정보조회 완료 후 클라이언트 정보를 리스트에 추가
        struct clientList* head = args;
        printf("client info: %s\n", inet_ntoa(clInfo.addr));
        if(newClient(head, &clInfo) == 0){
            printf("old client...\n");
        }
        else{
            printf("new client...\n");
        }

    }
}