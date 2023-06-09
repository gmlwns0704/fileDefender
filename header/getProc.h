#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct procInfo{
    char protocol[16];
    int port;
    // struct in_addr localAddress;
    // struct in_addr foreignAddress;
    char state[32];
    int pid;
    char procName[128];
};

void printProcInfo(struct procInfo* info);

struct procInfo* getProcInfoByPort(struct procInfo* info, int port);
// int getMulProcInfoByPort(struct procInfo* infoArr, size_t num, int port);
int getChildPids(int ppid, int** childPids);

int findfile(int pid, int filecount, char*** filelist_buffer, char* path[]);