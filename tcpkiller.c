#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "header/tcpkiller.h"

#define PLISTSIZE 256 // pidList의 개수

/*
특정 인터페이스 특정 포트 차단, pid 리턴
*/

static int pipein[2];
static int pipeout[2];
static int controllerPid;
/*
controller 자식 프로세스 실행
*/
int initController(){
    pipe(pipein);
    pipe(pipeout);
    controllerPid = fork();
    if(controllerPid == 0){
        blockController(pipein[0], pipeout[1]);
    }

    return controllerPid;
}

/*
자식 프로세스 종료와 관련 하위 프로세스 정리 등등
*/
int endController(){
    char commandBuff[BUFSIZ];
    // 자식 프로세스에 내릴 명령
    struct command input;
    input.func = t_deleteAll;
    input.size = T_DELETEALL_SIZE;
    // 하나의 버퍼에 병합
    memcpy(commandBuff, &input, sizeof(input));
    // 명령 전달
    if(write(pipein[1], commandBuff, sizeof(input)+input.size) == -1){
        perror("write");
        return 0;
    }
    return controllerPid;
}

int blockPort(struct connInfo* connInfo){
    char buff[10];
    pid_t pid = fork();
    if(pid < 0){
        perror("fork");
    }
    else if(pid == 0){
        sprintf(buff, "%d", connInfo->port);
        execlp("tcpkill", "tcpkill",
        "-i", connInfo->interface,
        "port", buff, NULL);

        perror("execlp, we must can not see it");
        exit(1);
    }

    return pid; // subprocess의 pid 리턴
}

/*
특정 인터페이스 특정 ip 차단
pid 리턴
*/
int blockIp(struct connInfo* connInfo){
    char* ipaddr;
    pid_t pid = fork();
    if(pid < 0){
        perror("fork");
    }
    else if(pid == 0){
        ipaddr = inet_ntoa(connInfo->ip);
        execlp("tcpkill", "tcpkill",
        "-i", connInfo->interface,
        "host", ipaddr,
        NULL);

        perror("execlp, we must can not see it");
        exit(1);
    }

    return pid; // subprocess의 pid 리턴
}

/*
특정 인터페이스의 특정 ip에 대한 특정 포트를 차단
*/
int blockIpAndPort(struct connInfo* connInfo){
    // 포트번호를 문자열로 바꾸기 위한 버퍼
    char buff[10];
    char* ipaddr;
    pid_t pid = fork();
    if(pid < 0){
        perror("fork");
    }
    else if(pid == 0){
        sprintf(buff, "%d", connInfo->port);
        ipaddr = inet_ntoa(connInfo->ip);
        execlp("tcpkill", "tcpkill",
        "-i", connInfo->interface,
        "host", ipaddr,
        "and",
        "port", buff,
        NULL);

        perror("execlp, we must can not see it");
        exit(1);
    }

    return pid; // subprocess의 pid 리턴
}
/*
직접 명령어 입력해서 block (ex: "tcpkill -i lo port 80")
*/
int blockCustom(char* command){ 
    // command를 ' '단위로 commands에 parsing
    char** commands;
    // 단어 개수 파악
    int count = 1;
    for(int i = 0; i < strlen(command); i++)
        if(command[i] == ' ')
            count++;
    
    // 단어단위로 각 commands 배열에 할당
    commands = calloc(count, sizeof(char*));
    for(int i = 0; i < count; i++){
        int len;
        int offset = 0;
        char buff[256] = "";
        sscanf(command + offset, "%s", buff);
        len = strlen(buff);
        commands[i] = calloc(len+1, sizeof(char));
        strncpy(commands[i], command + offset, len);
        offset += len+1;
        
    }

    pid_t pid = fork();
    if(pid < 0){
        perror("fork");
    }
    else if(pid == 0){
        // ex: "tcpkill -i lo port 9001"
        execvp("tcpkill", commands);

        perror("execvp, we must can not see it");
        exit(1);
    }

    return pid; // subprocess의 pid 리턴
}

/*
tcpkill child process들을 종합적으로 관리
*/
void blockController(int fdread, int fdwrite){
    int readLen;
    struct command input;
    char buff[BUFSIZ];
    // 컨트롤러에 의해 실행된 tcpkill 프로세스들의 pid 저장
    pid_t pidList[PLISTSIZE];
    memset(pidList, 0, sizeof(pidList));
    
    #ifdef DEBUG
    printf("start controller...\n");
    #endif
    while(1){

        #ifdef DEBUG
        printf("read...\n");
        #endif

        // 커맨드 읽기
        readLen = read(fdread, &input, sizeof(struct command));
        // 읽기 오류
        if(readLen <= 0){
            perror("read");
            continue;
        }
        // 파이프에서 작업을 위한 데이터 읽어옴
        readLen = read(fdread, buff, input.size);
        if(readLen <= 0){
            perror("read");
            continue;
        }

        // 아직 NULL인 pidList의 인덱스 찾기
        int idx;
        for(idx = 0; idx < PLISTSIZE && pidList[idx]; idx++);
        #ifdef DEBUG
        printf("func: %d\nidx: %d\n", input.func, idx);
        #endif
        pid_t newPid;
        int(*fptr) (struct connInfo*);

        switch(input.func){
            // connInfo를 받는 형식들
            // 함수포인터를 적절한 함수로 설정
            case t_blockPort:
                fptr = blockPort;
                break;
            case t_blockIp:
                fptr = blockIp;
                break;
            case t_blockIpAndPort:
                fptr = blockIpAndPort;
                break;
            
            /*
            connInfo 이외의 다른 형식을 받음
            case문 내에서 필요한 작업을 최대한 끝내야함
            case문의 마지막은 continue로 끝내야함
            */

            /*
            수동으로 문자열을 입력해서 tcpkill 실행
            */
            case t_blockCustom:
                newPid = blockCustom(buff);
                pidList[idx] = newPid;
                if(write(fdwrite, &newPid, sizeof(pid_t)) == -1)
                    perror("write");
                continue;

            /*
            원하는 pid를 입력하면 해당 프로세스 종료
            리턴 없음
            */
            case t_deleteTable: {
                // 삭제할 인덱스 탐색
                int targetIdx;
                for(targetIdx = 0; targetIdx < PLISTSIZE && pidList[targetIdx] != *((int*)buff); targetIdx++);
                // 해당 pid 프로세스 종료
                kill(pidList[targetIdx], SIGINT);
                // pidList에서 제거
                pidList[targetIdx] = 0;
            } // case t_deleteTable
                continue;
            /*
            모든 자식프로세스 종료
            */
            case t_deleteAll: {
                for(int i = 0; i < PLISTSIZE; i++){
                    if(pidList[i])
                        kill(pidList[i], SIGINT);
                    pidList[i] = 0;
                }
            } //case t_deleteAll
                continue;
            /*
            종료
            */
            case t_stop:
                exit(0);

        } //switch

        /*
        connInfo를 따르는 형식의 명령들의 공통된 작업
        connInfo 형식을 따르는 명령의 결과를 fdwrite에 write
        */
        newPid = fptr((struct connInfo*)buff);
        pidList[idx] = newPid;
        if(write(fdwrite, &newPid, sizeof(pid_t)) == -1)
            perror("write");

    } //while
} //blockController

/*
메인 프로세스에서 tcpkill 프로세스 관리 전용 프로세스에 명령내릴때 사용
*/
int _connInfoCommand(int pipeWrite, int pipeRead, enum funcTable func, struct connInfo* connInfo){
    char commandBuff[BUFSIZ];
    // 자식 프로세스에 내릴 명령
    struct command input;
    input.func = func;
    int inputSize;
    // connInfo를 사용하지 않는 명령은 거부
    switch(func){
        case t_blockCustom:
        case t_deleteTable:
            fprintf(stderr, "%d is not a command using connInfo\n", func);
            return 0;
        default:
            break;
    }
    input.size = sizeof(struct connInfo);
    // 하나의 버퍼에 병합
    memcpy(commandBuff, &input, sizeof(input));
    memcpy(commandBuff + sizeof(input), connInfo, input.size);
    
    // 명령 전달
    if(write(pipeWrite, commandBuff, sizeof(input)+input.size) == -1){
        perror("write");
        return 0;
    }
    // 생성된 pid 저장
    pid_t returnPid;
    if(read(pipeRead, &returnPid, sizeof(pid_t)) <= 0){
        perror("read");
        return 0;
    }
    #ifdef DEBUG
    CHKPID(returnPid);
    #endif
    // 생성된 tcpkill pid 리턴
    return returnPid;
}
int connInfoCommand(enum funcTable func, struct connInfo* connInfo){
    return _connInfoCommand(pipein[1], pipeout[0], func, connInfo);
}
/*
해당 pid에 해당하는 프로세스 kill
*/
int _rmCommand(int pipeWrite, int pipeRead, pid_t pid){
    char commandBuff[BUFSIZ];
    // 자식 프로세스에 내릴 명령
    struct command input;
    input.func = t_deleteTable;
    input.size = T_DELETETABLE_SIZE;
    // 하나의 버퍼에 병합
    memcpy(commandBuff, &input, sizeof(input));
    memcpy(commandBuff + sizeof(input), &pid, input.size);
    // 명령 전달
    if(write(pipeWrite, commandBuff, sizeof(input)+input.size) == -1){
        perror("write");
        return 0;
    }
    // 제거한 pid 리턴
    return pid;
}
int rmCommand(pid_t pid){
    return _rmCommand(pipein[1], pipein[0], pid);
}