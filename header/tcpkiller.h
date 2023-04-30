#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum funcTable{
    t_blockPort = 1,
    t_blockIp,
    t_deleteTable
};

struct connInfo{
    char interface[32]; // 인터페이스 이름
    int port; // 포트
    struct in_addr ip; // 대상 ip주소
};

int blockPort(struct connInfo* connInfo);
int blockIp(struct connInfo* connInfo);

void blockController(int fdread, int fdwrite);