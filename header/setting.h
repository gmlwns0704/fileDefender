#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <jansson.h>

#define MAX_IP_LENGTH 16
#define MAX_PATH_LENGTH 256

typedef enum {
    WHITELIST, //화이트 리스트
    BLACKLIST  //블랙 리스트
} ListType;

typedef struct {
    char ip[MAX_IP_LENGTH]; //ip address
    char path[MAX_PATH_LENGTH]; //파일경로
    ListType listType; // 목록 유형 (화이트리스트 또는 블랙리스트)
} Rule;
// IP 주소와 파일 경로를 기반으로 액세스 권한을 확인하는 함수
int checkAccess(const char *ip, const char *path, const Rule *rules, int ruleCount);
// 설정 파일을 파싱하여 규칙을 읽어오는 함수
void parseConfigFile(const char *configFile, Rule **rules, int *ruleCount);
/*
 패킷을 처리하는 핸들러 함수
*/
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

