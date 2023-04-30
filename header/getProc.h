struct procInfo{
    char protocol[32];
    char localAddress[64];
    char foreignAddress[64];
    char state[32];
    int pid;
    char procName[128];
};

struct procInfo* getProcInfoByPort(struct procInfo* info, int port);