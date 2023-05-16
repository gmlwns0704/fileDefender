#include "header/getPacket.h"
#include "header/getProc.h"
#include "header/tcpkiller.h"
#include "header/clientManage.h"
#include <time.h>


// pcap에 포함된 각 헤더의 구조

// 이더넷
/*
struct pcap_pkthdr {
	struct timeval ts; // time stamp
	bpf_u_int32 caplen; // length of portion present
	bpf_u_int32 len; // length this packet (off wire)
};
*/

// ip
/*
struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;       /* header length
    unsigned int ip_v:4;        /* version
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;        /* version
    unsigned int ip_hl:4;       /* header length
#endif
    u_int8_t ip_tos;            /* type of service
    u_short ip_len;         /* total length
    u_short ip_id;          /* identification
    u_short ip_off;         /* fragment offset field
#define IP_RF 0x8000            /* reserved fragment flag
#define IP_DF 0x4000            /* dont fragment flag
#define IP_MF 0x2000            /* more fragments flag
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits
    u_int8_t ip_ttl;            /* time to live
    u_int8_t ip_p;          /* protocol
    u_short ip_sum;         /* checksum
    struct in_addr ip_src, ip_dst;  /* source and dest address
  };
*/

// tcp
/*
struct tcphdr
  {
    u_int16_t th_sport;     // source port
    u_int16_t th_dport;     // destination port
    tcp_seq th_seq;     // sequence number
    tcp_seq th_ack;     // acknowledgement number
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;       // (unused)
    u_int8_t th_off:4;      // data offset
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;      // data offset
    u_int8_t th_x2:4;       // (unused)
#  endif
    u_int8_t th_flags;
#  define TH_FIN    0x01
#  define TH_SYN    0x02
#  define TH_RST    0x04
#  define TH_PUSH   0x08
#  define TH_ACK    0x10
#  define TH_URG    0x20
    u_int16_t th_win;       // window
    u_int16_t th_sum;       // checksum
    u_int16_t th_urp;       // urgent pointer
};
*/

/*
패킷 캡쳐 루프 시작
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
    inet_aton("127.0.0.1", &(clHead.clInfo.addr));
    clHead.clInfo.lastTime = 0;
    // pcap_loop(pcd, 반복회수, 콜백, 콜백 args)
    // clHead를 u_char* 로 컴파일한건 pcap_loop 형식때문, 실제론 (struct clientList*) 임
    pcap_loop(pcd, LOOPCNT, packetCallback, (u_char*)&clHead);
}

/*
패킷 캡쳐 콜백
*/
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
    offset += ipHdr->ip_hl * 4;

    // tcp 패킷
    if(ipHdr->ip_p == IPPROTO_TCP){
        struct tcphdr* tcpHdr = (struct tcphdr*)(packet + offset);
        // offset += sizeof(struct tcphdr);
        // tcp헤더의 크기 = data offset * 4 bytes
        offset += tcpHdr->th_off * 4;
        
        #ifdef DEBUG
        printf("pcap: tcp header size: %d\n", tcpHdr->th_off * 4);
        printf("pcap: dest port: %d\n", ntohs(tcpHdr->th_dport));
        #endif

        // tcp payload 포인트
        const u_char* payload = (packet + offset);
        // payload size = ip패킷 길이 - tcp헤더 길이 - ip헤더 길이
        // ipHdr는 ntohs을 씌워줘야함, 왜 얘만 그런지는 모르겠음
        u_short payloadLen = ntohs(ipHdr->ip_len) - (tcpHdr->th_off * 4) - (ipHdr->ip_hl * 4);

        #ifdef DEBUG
        printf("ip_len: %d bytes\nth_off: %d bytes\nip_hl: %d bytes\n",
        ntohs(ipHdr->ip_len),
        tcpHdr->th_off*4,
        ipHdr->ip_hl*4);
        printf("payload length: %d\n", payloadLen);
        printf("print payload:\n");
        for(int i = 0; i < payloadLen; i++)
            printf("0x%02x ", payload[i]);
        printf("\n");
        #endif

        struct procInfo info;

        // 프로세스를 발견하지 못함
        if(getProcInfoByPort(&info, ntohs(tcpHdr->dest)) == NULL){
            return;
        }
        
        #ifdef DEBUG
        printProcInfo(&info);
        #endif

        int childPids[10];
        int childsNum = getChildPids(info.pid, childPids, 10);
        if(childsNum == -1){
            perror("getChildsPids");
            return;
        }

        #ifdef DEBUG
        printf("printing %d child pids...\n", childsNum);
        for(int i = 0; i < childsNum; i++){
            printf("%d ", childPids[i]);
        }
        printf("\n");
        #endif

        struct client clInfo;
        clInfo.addr = ipHdr->ip_src;
        clInfo.lastTime = pcapTime;

        // args로 입력받은 client linked list head 받아오기
        struct clientList* head = (struct clientList*)args;
        printf("client info: %s\n", inet_ntoa(clInfo.addr));
        // 정보조회 완료 후 클라이언트 정보를 리스트에 추가
        if(newClient(head, &clInfo) == 0){
            printf("old client...\n");
        }
        else{
            printf("new client...\n");
        }

    }
}


/*
procInfo, clInfo를 기반으로 해당 패킷의 적합성 판단
적합하다면 1 리턴
부적합하다면 0 리턴
*/
int judgePacket(struct procInfo* procInfo, struct client clInfo){

}