#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
각 명령별 고유번호
고유번호, //매개변수
*/
enum funcTable{
    t_blockPort = 1, //struct connInfo
    t_blockIp, //struct connInfo
    t_blockIpAndPort, //struct connInfo
    t_blockCustom, //size_t(strlen), string
    t_deleteTable, //pid_t
    t_deleteAll, //none
    t_stop //none
};
#define T_BLOCKPORT_SIZE (sizeof(struct connInfo))
#define T_BLOCKIP_SIZE (sizeof(struct connInfo))
#define T_BLOCKIPANDPORT_SIZE (sizeof(struct connInfo))
// #define T_BLOCKCUSTOM_SIZE (이건 따라오는 문자열 길이만큼)
#define T_DELETETABLE_SIZE (sizeof(pid_t))
#define T_DELETEALL_SIZE (0)

#ifdef DEBUG
// 해당 pid의 프로세스가 실행되고 있는지 확인 (디버깅용)
#define CHKPID(pid) {\
    char CHKPID_TMP[100];\
    sprintf(CHKPID_TMP, "ps aux | grep %u | grep -v grep", (pid));\
    system(CHKPID_TMP);}
#endif

/*
명령 전달을 위한 일정한 포맷
*/
struct command{
    enum funcTable func; // 명령
    size_t size; // 전달하는 데이터 크기
};

/*
커넥션에 대한 정보
*/
struct connInfo{
    const char* interface; // 인터페이스 이름
    int port; // 포트
    struct in_addr ip; // 대상 ip주소
};

int initController();
int endController();

int blockPort(struct connInfo* connInfo);
int blockIp(struct connInfo* connInfo);
int blockIpAndPort(struct connInfo* connInfo);
int blockCustom(char* command);

void blockController(int fdread, int fdwrite);
int _connInfoCommand(int pipeWrite, int pipeRead, enum funcTable func, struct connInfo* connInfo);
int connInfoCommand(enum funcTable func, struct connInfo* connInfo);
int _rmCommand(int pipeWrite, int pipeRead, pid_t pid);
int rmCommand(pid_t pid);