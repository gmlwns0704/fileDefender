#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct procInfo{
    char protocol[16];
    int port;
    struct in_addr localAddress;
    struct in_addr foreignAddress;
    char state[32];
    int pid;
    char procName[128];
};

struct procInfo* getProcInfoByPort(struct procInfo* info, int port);
void printProcInfo(struct procInfo* info);