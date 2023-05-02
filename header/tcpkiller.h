#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum funcTable{
    t_blockPort = 1, //struct connInfo
    t_blockIp, //struct connInfo
    t_blockCustom, //size_t(strlen), string
    t_deleteTable //pid_t
};
#define T_BLOCKPORT_SIZE (sizeof(struct connInfo))
#define T_BLOCKIP_SIZE (sizeof(struct connInfo))
// #define T_BLOCKCUSTOM_SIZE (이건 따라오는 문자열 길이만큼)
#define T_DELETETABLE_SIZE (sizeof(pid_t))

struct command{
    enum funcTable func;
    size_t size;
};

struct connInfo{
    char interface[32]; // 인터페이스 이름
    int port; // 포트
    struct in_addr ip; // 대상 ip주소
};

int blockPort(struct connInfo* connInfo);
int blockIp(struct connInfo* connInfo);

void blockController(int fdread, int fdwrite);