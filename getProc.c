#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "header/getProc.h"

/*struct procInfo{
    char protocol[16];
    int port;
    struct in_addr localAddress;
    struct in_addr foreignAddress;
    char state[32];
    int pid;
    char procName[128];
};*/

/*
procInfo 구조체 내용 출력
*/
void printProcInfo(struct procInfo* info){
    printf("===printing process info===\n");
    printf("protocol: %s\n", info->protocol);
    printf("port: %d\n", info->port);
    // printf("local IP: %s\n", inet_ntoa(info->localAddress));
    // printf("foreign IP: %s\n", inet_ntoa(info->foreignAddress));
    printf("state: %s\n", info->state);
    printf("pid: %d\n", info->pid);
    printf("process name: %s\n", info->procName);
}

/*
해당 포트번호를 사용하는 프로세스의 정보를 취해서 procInfo 구조체에 저장
*/
struct procInfo* getProcInfoByPort(struct procInfo* info, int port){
    // 명령어 출력 결과 버퍼
    char buff[BUFSIZ];
    memset(buff, 0, sizeof(buff));

    // 명령어 설정
    char path[BUFSIZ];
    sprintf(path, "netstat -ntlp | grep -E [0-9]\\+.[0-9]\\+.[0-9]\\+.[0-9]*:%d\\+' '\\|:::%d\\+' '", port, port);
    #ifdef DEBUG
    printf("shell: %s\n", path);
    #endif
    //결과 버퍼
    memset(info, 0, sizeof(struct procInfo));
    
    FILE* f = popen(path, "r");
    if (f == NULL){
        perror("popen");
        pclose(f);
        return NULL;
    }
    fread(buff, sizeof(buff), 1, f);
    if (strlen(buff) < 0){
        perror("fread");
        pclose(f);
        return NULL;
    }
    else if(strlen(buff) == 0){
        // fprintf(stderr, "process not found\n");
        pclose(f);
        return NULL;
    }

    // printf(buff);
    char localAddrBuff[32];
    char foreignAddrBuff[32];
    char* format;
    sscanf(buff, "%s", info->protocol);
    // tcp6와 일반 tcp를 다르게 읽음
    if(strcmp(info->protocol, "tcp6") == 0){
        format = "%s %*d %*d :::%d :::%*s %s %d/%[^: ]\n";
    }
    else{
        format = "%s %*d %*d %*[^: ]:%d %*[^: ]:%*s %s %d/%[^: ]\n";
    }
    // Proto Recv-Q Send-Q Local_Address Foreign_Address State PID/Program name
    sscanf(buff, format,
        info->protocol,
        //localAddrBuff,
        &(info->port),
        //foreignAddrBuff,
        info->state,
        &(info->pid),
        info->procName);
    // 주소를 네트워크 바이트로 변환
    // inet_aton(localAddrBuff, &(info->localAddress));
    // inet_aton(foreignAddrBuff, &(info->foreignAddress));
    
    pclose(f);

    return info;
}

// int getMulProcInfoByPort(struct procInfo* infoArr, size_t num, int port){
//     // 명령어 출력 결과 버퍼
//     char buff[BUFSIZ];
//     memset(buff, 0, sizeof(buff));

//     // 명령어 설정
//     char command[BUFSIZ];
//     // netstat으로 읽고, 정규표현식으로 grep (양식: "XXX.XXX.XXX.XXX:[port] ")
//     sprintf(command, "netstat -ntlp | grep -E [0-9]\\+.[0-9]\\+.[0-9]\\+.[0-9]*:%d\\+' '", port);
    
//     //결과 버퍼
//     memset(infoArr, 0, sizeof(struct procInfo)*num);
    
//     FILE* f = popen(command, "r");
//     if (f == NULL){
//         perror("popen");
//         pclose(f);
//         return -1;
//     }
//     fread(buff, sizeof(buff), 1, f);
//     if (strlen(buff) < 0){
//         perror("fread");
//         pclose(f);
//         return -1;
//     }
//     else if(strlen(buff) == 0){
//         fprintf(stderr, "process not found\n");
//         pclose(f);
//         return -1;
//     }

//     // printf(buff);
//     int offset = 0;
//     int count;
//     for(count = 0; count < num; count++){
//         if(buff[offset] == '\0')
//             break;
        
//         char line[BUFSIZ];
//         struct procInfo* info;

//         // 한줄씩 읽음
//         sscanf(buff + offset, "%[^\n]\n", line);
//         // 읽은 만큼 buff offset
//         offset += strlen(line)+1;
//         // info = &(infoarr[count])
//         info = (struct procInfo*)((struct procInfo*)infoArr + count);

//         char localAddrBuff[32];
//         char foreignAddrBuff[32];
//         // Proto Recv-Q Send-Q Local_Address Foreign_Address State PID/Program name
//         sscanf(buff, "%s %*d %*d %[^: ]:%d %[^: ]:%*s %s %d/%[^: ]\n",
//         info->protocol,
//         localAddrBuff,
//         &(info->port),
//         foreignAddrBuff,
//         info->state,
//         &(info->pid),
//         info->procName);
//         // 주소를 네트워크 바이트로 변환
//         inet_aton(localAddrBuff, &(info->localAddress));
//         inet_aton(foreignAddrBuff, &(info->foreignAddress));
//     }
//     return count;
// }

/*
특정 프로세스의 자식 프로세스 목록 조회 후 childPids에 저장
오류 발생시 마이너스값 리턴
자식 프로세스의 개수 리턴
*/
int getChildPids(int ppid, int** childPids){

    int totalCount = 1;
    int pidStack[128];
    memset(pidStack, 0, sizeof(pidStack));
    pidStack[0] = ppid;

    for(int stackPtr = 0; stackPtr < totalCount; stackPtr++){
        ppid = pidStack[stackPtr];
        // 자식 프로세스들이 저장되는 파일 읽음
        char path[BUFSIZ];
        sprintf(path, "/proc/%d/task/%d/children", ppid, ppid);
    
        FILE* f = fopen(path, "r");
        if (f == NULL)
            continue;

        // 파일에서 %d단위로 읽어옴
        while(!feof(f)){
            fscanf(f, "%d ", &(pidStack[totalCount]));
            // 제대로된 정수값이 저장된게 아니면 탈출
            if(!(pidStack[totalCount]))
                break;
            // 스택에 발견한 child pid 추가, stackPtr이동
            totalCount++;
        }

        fclose(f);
    }

    *childPids = malloc(sizeof(int)*totalCount);
    memcpy(*childPids, pidStack, sizeof(int)*totalCount);

    return totalCount;
}

