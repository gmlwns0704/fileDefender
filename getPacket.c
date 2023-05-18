#include "header/getPacket.h"
#include "header/getProc.h"
#include "header/tcpkiller.h"
#include "header/clientManage.h"
#include <time.h>
#include <dirent.h>


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
    // head는 loopback
    inet_aton("127.0.0.1", &(clHead.clInfo.addr));
    clHead.clInfo.lastTime = 0;

    // pcap에서 쓸 매개변수 전달을 위한 버퍼 구성
    struct pcapLoopArgs args;
    args.clHeadPtr = &clHead;
    args.interface = dev;
    // pcap_loop(pcd, 반복회수, 콜백, 콜백 args)
    pcap_loop(pcd, LOOPCNT, packetCallback, (u_char*)&args);
}

/*
패킷 캡쳐 콜백
*/
void packetCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    // 코드 편의상 args로 받은 값들의 포인터 별도 생성
    struct clientList* head = ((struct pcapLoopArgs*)args)->clHeadPtr;
    const char* interface = ((struct pcapLoopArgs*)args)->interface;

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
        // tcp헤더의 크기 = data offset * 4 bytes
        offset += tcpHdr->th_off * 4;

        struct procInfo info;
        // 프로세스를 발견하지 못함
        if(getProcInfoByPort(&info, ntohs(tcpHdr->th_dport)) == NULL){
            return;
        }
        
        // 클라이언트 정보
        struct client clInfo;
        clInfo.addr = ipHdr->ip_src;
        clInfo.lastTime = pcapTime;

        // 커넥션 정보 (tcpkill.c 함수들에서 사용)
        struct connInfo connInfo;
        connInfo.interface = interface;
        connInfo.ip = ipHdr->ip_src;
        connInfo.port = ntohs(tcpHdr->th_dport);
        
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
        
        #ifdef DEBUG
        printProcInfo(&info);
        #endif

        int childPids[10];
        int childsNum = getChildPids(info.pid, childPids, 10);
        #ifdef DEBUG
        printf("printing %d child pids...\n", childsNum);
        for(int i = 0; i < childsNum; i++){
            printf("%d ", childPids[i]);
        }
        printf("\n");
        #endif

        printf("client info: %s\n", inet_ntoa(clInfo.addr));
        // 정보조회 완료 후 클라이언트 정보를 리스트에 추가
        if(newClient(head, &clInfo) == 0){
            printf("old client...\n");
        }
        else{
            printf("new client...\n");
        }

        if(judgePacket(&info, &clInfo)){
            // isDataInFile(payload, payloadLen, )
            /*
            메인함수에서 이미 initController를 수행했다는 가정
            tcpkill 명령
            */
            // connInfoCommand(t_blockIpAndPort, &connInfo);
        }
    }
}


/*
procInfo, clInfo를 기반으로 패킷의 적합성 판단
패킷이 통신하는 프로세스가 부적절한 파일에 접근했는지 확인
적합하다면 1 리턴
부적합하다면 0 리턴
*/
int judgePacket(struct procInfo* procInfo, struct client clInfo, const char* payload, size_t payloadLen){
    /*
    설정파일에서 clInfo가 접근하면 안되는 path 목록 얻어오기
    */

    /*
    이전에 getProcInfoByPort로 얻어온 프로세스 정보의 pid로 파일 접근여부 확인
    자식 프로세스들도 같이 조회할 예정
    */
   
    // 프로세스가 보호대상 파일에 접근하지 않음
    if(findfile(procInfo->pid, "/home/ubuntuhome/sftp/") == 0){
        return 0;
    }

    /*
    프로세스가 접근한 보호대상 파일들 중, 패킷의 데이터와 일치하는 것이 있는지 확인
    */
    /*
    // 각 path에 대하여
    for(int i = 0; i < 'path의 개수'; i++){
        // 데이터가 path파일의 일부인지 확인
        if(isDataInFile(payload, payloadLen, paths[i])){
            // 차단
            connInfoCommnad(t_blockIp, clInfo);
        }
    }
    */

    printf("this process tried to access file!\n");
    return 1;
}

/*
데이터가 대상 파일의 일부인지 확인
*/
int isDataInFile(const char* payload, size_t size, const char* path){
    FILE* f = fopen(path, "r");
    if(f == NULL){
        perror("fopen");
        return 0;
    }
    char fbyte;
    size_t byteCount = 0;

    // size만큼 일치하는 내용 발견 or 파일의 끝 도달시 종료
    while(byteCount < size && !feof(f)){
        // 1byte씩 읽음
        fread(&fbyte, 1, 1, f);
        #ifdef DEBUG
        printf("%02x vs %02x\n", fbyte, *(payload + byteCount));
        #endif
        // payload의 1byte를 fbyte와 비교
        if(*(payload + byteCount) == fbyte){
            // byteCount 1증가
            byteCount++;
        }
        else{
            // byteCount초기화
            byteCount = 0;
            // 파일포인터 다시 앞으로 한칸
            // fseek(f, -1, SEEK_CUR);
        }
    }

    fclose(f);
    // byteCount == size 라면 일치하는 것 발견, 아니라면 발견X
    return (byteCount == size);
}