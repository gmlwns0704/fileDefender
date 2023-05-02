#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "header/tcpkiller.h"

#define PLISTSIZE 256 // pidList의 개수

// 해당 pid의 프로세스가 실행되고 있는지 확인 (디버깅 체크용)
#define CHKPID(pid) {\
    char CHKPID_TMP[100];\
    sprintf(CHKPID_TMP, "ps aux | grep %u | grep -v grep", (pid));\
    system(CHKPID_TMP);\
}
    

int blockPort(struct connInfo* connInfo){ // 특정 인터페이스의 특정 포트를 tcpkill로 차단함
    char buff[10];
    pid_t pid = fork();
    if(pid < 0){
        perror("fork");
    }
    else if(pid == 0){
        sprintf(buff, "%d", connInfo->port);
        execlp("tcpkill", "tcpkill", "-i", connInfo->interface, "port", buff, NULL);

        perror("execlp, we must can not see it");
        exit(1);
    }
    
    CHKPID(pid);
    return pid; // subprocess의 pid 리턴
}

int blockIp(struct connInfo* connInfo){ //특정 인터페이스의 특정 src or dst ip 에 대한 통신을 차단함
    char* ipaddr;
    pid_t pid = fork();
    if(pid < 0){
        perror("fork");
    }
    else if(pid == 0){
        ipaddr = inet_ntoa(connInfo->ip);
        execlp("tcpkill", "tcpkill",
        "-i", connInfo->interface,
        "dst", ipaddr,
        "or",
        "src", ipaddr,
        NULL);

        perror("execlp, we must can not see it");
        exit(1);
    }

    CHKPID(pid);
    return pid; // subprocess의 pid 리턴
}

void blockController(int fdread, int fdwrite){
    int readLen;
    enum funcTable func;
    char buff[BUFSIZ];
    pid_t pidList[PLISTSIZE];
    memset(pidList, 0, sizeof(pidList));
    
    printf("start controller...\n");
    while(1){
        printf("read...\n");
        // 커맨드 읽기
        readLen = read(fdread, &func, sizeof(func));
        // 읽기 오류
        if(readLen < 0){
            perror("read");
            continue;
        }
        printf("readLen: %d\n", readLen);

        // 아직 NULL인 pidList의 인덱스 찾기
        int idx;
        for(idx = 0; idx < PLISTSIZE && pidList[idx]; idx++);
        printf("func: %d\nidx: %d\n", func, idx);
        pid_t newPid;
        switch(func){
            case t_blockPort:
                // 파이프에서 작업을 위한 데이터 읽어옴
                readLen = read(fdread, buff, sizeof(struct connInfo));
                if(readLen == 0){
                    perror("read");
                    continue;
                }
                newPid = blockPort((struct connInfo*)buff);
                pidList[idx] = newPid;
                if(write(fdwrite, &newPid, sizeof(pid_t)) == -1)
                    perror("write");
                break;
            
            case t_blockIp:
                // 파이프에서 작업을 위한 데이터 읽어옴
                readLen = read(fdread, buff, sizeof(struct connInfo));
                if(readLen == 0){
                    perror("read");
                    continue;
                }
                newPid = blockIp((struct connInfo*)buff);
                pidList[idx] = newPid;
                if(write(fdwrite, &newPid, sizeof(pid_t)) == -1)
                    perror("write");
                break;

            case t_deleteTable:
                // 파이프에서 작업을 위한 데이터 읽어옴
                readLen = read(fdread, buff, sizeof(int));
                if(readLen == 0){
                    fprintf(stderr, "E: readLen is 0\n");
                    continue;
                }
                // 삭제할 인덱스 탐색
                int targetIdx;
                for(targetIdx = 0; targetIdx < PLISTSIZE && pidList[targetIdx] != *((int*)buff); targetIdx++);
                kill(pidList[targetIdx], SIGINT);
                pidList[targetIdx] = 0;
                break;

        }

    }
}