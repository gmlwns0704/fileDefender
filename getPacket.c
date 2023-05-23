#include "header/getPacket.h"
#include "header/getProc.h"
#include "header/tcpkiller.h"
#include "header/clientManage.h"
#include "header/setting.h"
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
#define LOOPCNT -1
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
        pcap_perror(pcd, "pcap_compile");
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
    // 설정파일에 대한 정보도 전달
    parseConfigFile("config.json", &(args.rules), &(args.ruleCount));
    // pcap_loop(pcd, 반복회수, 콜백, 콜백 args)
    pcap_loop(pcd, LOOPCNT, packetCallback, (u_char*)&args);

    free(args.rules);
}

/*
패킷 캡쳐 콜백
*/
void packetCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    // 코드 편의상 args로 받은 값들의 포인터 or 복사값 별도 생성
    struct clientList* head = ((struct pcapLoopArgs*)args)->clHeadPtr;
    const char* interface = ((struct pcapLoopArgs*)args)->interface;
    const Rule* rules = ((struct pcapLoopArgs*)args)->rules;
    const int ruleCount = ((struct pcapLoopArgs*)args)->ruleCount;

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
        if(getProcInfoByPort(&info, ntohs(tcpHdr->th_dport)) == NULL && getProcInfoByPort(&info, ntohs(tcpHdr->th_sport)) == NULL){
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
        printf("client info: %s\n", inet_ntoa(clInfo.addr));
        #endif

        // 정보조회 완료 후 클라이언트 정보를 리스트에 추가
        if(newClient(head, &clInfo) == 0){
            #ifdef DEBUG
            printf("old client...\n");
            #endif
        }
        else{
            #ifdef DEBUG
            printf("new client...\n");
            #endif
        }

        /*
        해당 클라이언트가 접근하면 안되는 파일 목록 얻어오기
        char** 버퍼에 저장
        */
        char** inAccessibleFiles;
        // int inAccCount = getInaccessibleFiles(inet_ntoa(clInfo.addr), "config.json", (const char***)&inAccessibleFiles);
        int inAccCount = getInaccessibleFilesV2(inet_ntoa(clInfo.addr), rules, ruleCount, (const char***)&inAccessibleFiles);
        #ifdef DEBUG
        if(inAccCount == 0){
            printf("this client can access any file\n");
        }
        else{
            printf("this client cannot access to...\n");
            for(int i = 0; i < inAccCount; i++){
            printf("inAccFile[%d]: %s\n", i, inAccessibleFiles[i]);
        }
        }
        #endif

        /*
        lsof로 해당 파일 목록중 걸리는 파일이 있는지 확인
        char** 버퍼에 저장
        inAccessibleFiles 를 입력으로 사용
        */

        /*
        있다면 payload가 그 파일에 접근했는지 비교
        for문으로 isDataInFile()
        */

        // lsof가 완성될때까지 임시 파일로 테스트
        if(payloadLen > MINPAYLOADLEN && 
            isDataInFile(payload, payloadLen, "/home/ubuntuhome/nwProj/project/getPacket.c") > payloadLen * PAYLOADSAMERATE){
            if(!getSuspect(head, &clInfo)){
                #ifdef DEBUG
                printf("block this client...\n");
                #endif
                connInfoCommand(t_blockIp, &connInfo);
                setSuspect(head, &clInfo, 1);
            }
        }

        #ifdef DEBUG
        printf("ip_len: %d bytes\nth_off: %d bytes\nip_hl: %d bytes\n",
        ntohs(ipHdr->ip_len),
        tcpHdr->th_off*4,
        ipHdr->ip_hl*4);
        printf("payload length: %d\n", payloadLen);
        printf("print payload:\n");
        for(int i = 0; i < payloadLen; i++)
            printf("%c", payload[i]);
        printf("\n");
        #endif

        //free
        free(inAccessibleFiles);
    }
}

/*
데이터가 대상 파일의 일부인지 확인
diff 사용하기?
*/
int isDataInFile(const char* payload, size_t size, const char* path){
    FILE* f = fopen(path, "rb");
    if(f == NULL){
        perror("fopen");
        return 0;
    }
    unsigned char fbyte;
    size_t byteCount = 0;
    size_t maxByteCount = 0;

    // size만큼 일치하는 내용 발견 or 파일의 끝 도달시 종료
    for(int i = 0; byteCount < size && !feof(f) ; i++){
        
        // 1byte씩 읽음
        fread(&fbyte, 1, 1, f);

        // '\n', '\r'등 일부 문자는 스킵
        while((fbyte == '\r') && !feof(f))
            fread(&fbyte, 1, 1, f);
        while(byteCount < size && (payload[byteCount] == '\r'))
            byteCount++;
        // payload의 1byte를 fbyte와 비교
        if(*((unsigned char*)(payload + byteCount)) == (unsigned char)fbyte){
            #ifdef DEBUG
            printf("%c", *((char*)&fbyte));
            #endif
            // byteCount 1증가
            byteCount++;
        }
        else{
            #ifdef DEBUG2
            printf("\n!%02x(%c) != %02x(%c)!", fbyte, *((char*)&fbyte), *((unsigned char*)(payload + byteCount)), payload[byteCount]);
            #endif
            // byteCount초기화
            maxByteCount = (maxByteCount > byteCount) ? maxByteCount : byteCount;
            byteCount = 0;
        }
    }
    // 마지막에 한번 더 갱신 (한번도 틀린적이 없을 경우 대비)
    maxByteCount = (maxByteCount > byteCount) ? maxByteCount : byteCount;

    #ifdef DEBUG
    printf("maxByteCount: %ld\n", maxByteCount);
    #endif

    fclose(f);
    // byteCount >= size 라면 일치하는 것 발견, 아니라면 발견X
    return maxByteCount;
}