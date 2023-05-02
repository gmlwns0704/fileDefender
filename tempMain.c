#include "header/getProc.h"
#include "header/tcpkiller.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv){
    if(argc != 4){
        printf("usage: %s [interface] [ip] [port]\n", argv[0]);
        return -1;
    }
    struct connInfo ci;
    strcpy(ci.interface, argv[1]);
    inet_aton(argv[2], &(ci.ip));
    ci.port = atoi(argv[3]);

    struct procInfo procInfo;
    if(getProcInfoByPort(&procInfo, ci.port) == 0)
        printf("process not found\n");
    else
        printProcInfo(&procInfo);

    int pipeMainToSub[2];
    int pipeSubToMain[2];
    pipe(pipeMainToSub);
    pipe(pipeSubToMain);

    pid_t pid = fork();
    if(pid == 0){
        blockController(pipeMainToSub[0], pipeSubToMain[1]);
        exit(0);
    }

    enum funcTable func;
    func = t_blockPort;
    // func = t_blockIp;
    if(write(pipeMainToSub[1], &func, sizeof(func)) == -1)
        perror("write");
    if(write(pipeMainToSub[1], &ci, sizeof(struct connInfo)) == -1)
        perror("write");
    printf("worked?\n");

    sleep(10);
    
    printf("now remove it...\n");
    int targetPid;
    if(read(pipeSubToMain[0], &targetPid, sizeof(targetPid)) == -1){
        perror("read");
        exit(1);
    }
    
    func = t_deleteTable;
    if(write(pipeMainToSub[1], &func, sizeof(func)) == -1)
        perror("write");
    if(write(pipeMainToSub[1], &targetPid, sizeof(int)) == -1)
        perror("write");
    printf("worked?\n");
    
    wait(pid);    

    return 0;
}