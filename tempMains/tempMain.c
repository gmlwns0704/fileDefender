#include "../header/getProc.h"
#include "../header/tcpkiller.h"
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

    // 자식프로세스 생성
    pid_t pid = fork();
    if(pid == 0){
        blockController(pipeMainToSub[0], pipeSubToMain[1]);
        exit(0);
    }

    // 차단
    int targetPid = connInfoCommand(pipeMainToSub[1], pipeSubToMain[0], t_blockIpAndPort, &ci);
    printf("closed\n");
    // 대기
    sleep(10);
    // 차단 해제
    rmCommand(pipeMainToSub[1], pipeSubToMain[0], targetPid);
    printf("opened\n");
    
    wait(pid);

    return 0;
}