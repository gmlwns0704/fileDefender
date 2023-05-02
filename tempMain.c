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

    // 자식프로세스 생성
    pid_t pid = fork();
    if(pid == 0){
        blockController(pipeMainToSub[0], pipeSubToMain[1]);
        exit(0);
    }

    char buff[BUFSIZ];

    // 자식 프로세스에 내릴 명령 선택
    struct command input;
    input.func = t_blockPort;
    // input.func = t_blockIp;
    input.size = sizeof(struct connInfo);
    memcpy(buff, &input, sizeof(input));
    memcpy(buff+sizeof(input), &ci, input.size);
    
    // 명령 전달
    if(write(pipeMainToSub[1], buff, sizeof(input)+input.size) == -1)
        perror("write");
    printf("worked?\n");

    sleep(10);
    
    printf("now remove it...\n");
    // 자식 프로세스에서 반환한 pid값 받기
    int targetPid;
    if(read(pipeSubToMain[0], &targetPid, sizeof(targetPid)) == -1){
        perror("read");
        exit(1);
    }
    
    // 실행중인 차단 프로세스 종료하기
    input.func = t_deleteTable;
    input.size = sizeof(targetPid);
    memcpy(buff, &input, sizeof(input));
    memcpy(buff+sizeof(input), &ci, input.size);
    // 명령 전달
    if(write(pipeMainToSub[1], &input, sizeof(input)+input.size) == -1)
        perror("write");
    printf("worked?\n");
    
    wait(pid);    

    return 0;
}