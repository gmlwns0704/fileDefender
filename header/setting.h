#pragma once
/*
jansson 라이브러리 설치
sudo apt-get install -y libjansson-dev
gcc 컴파일시 -ljansson 옵션
*/

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
    int alwaysCheck; 
    double sameRate;
} Rule;
// IP 주소와 파일 경로를 기반으로 액세스 권한을 확인하는 함수
int checkAccess(const char *ip, const char *path, const Rule *rules, int ruleCount);
// ip주소와 파일 경로를 기반으로 alwaysCheck값 리턴
double isAlwaysCheck(const char *ip, const char *path, const Rule *rules, int ruleCount);
// 설정 파일을 파싱하여 규칙을 읽어오는 함수
void parseConfigFile(const char *configFile, Rule **rules, int *ruleCount);
/*
 ip주소를 입력받아 파일목록 추출
 접근불가 파일목록 반환
*/
int getInaccessibleFiles(const char *ip, const char *configFile, const char ***inaccessibleFiles);
// 메모리문제 해결 버전
int getInaccessibleFilesV2(const char *ip, const Rule* rules, int ruleCount, const char ***inaccessibleFiles);