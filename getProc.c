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
void printProcInfo(struct procInfo* info){
    printf("===printing process info===\n");
    printf("protocol: %s\n", info->protocol);
    printf("port: %d\n", info->port);
    printf("local IP: %s\n", inet_ntoa(info->localAddress));
    printf("foreign IP: %s\n", inet_ntoa(info->foreignAddress));
    printf("state: %s\n", info->state);
    printf("pid: %d\n", info->pid);
    printf("process name: %s\n", info->procName);
}

struct procInfo* getProcInfoByPort(struct procInfo* info, int port){
    // 명령어 출력 결과 버퍼
    char buff[BUFSIZ];
    memset(buff, 0, sizeof(buff));

    // 명령어 설정
    char path[BUFSIZ];
    sprintf(path, "netstat -ntlp | grep :%d", port);
    
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
        fprintf(stderr, "process not found\n");
        pclose(f);
        return NULL;
    }

    // printf(buff);
    char localAddrBuff[32];
    char foreignAddrBuff[32];
    // Proto Recv-Q Send-Q Local_Address Foreign_Address State PID/Program name
    sscanf(buff, "%s %*d %*d %[^: ]:%d %[^: ]:%*s %s %d/%[^: ]\n",
        info->protocol,
        localAddrBuff,
        &(info->port),
        foreignAddrBuff,
        info->state,
        &(info->pid),
        info->procName);
    // 주소를 네트워크 바이트로 변환
    inet_aton(localAddrBuff, &(info->localAddress));
    inet_aton(foreignAddrBuff, &(info->foreignAddress));
    
    pclose(f);

    return info;
}

int getMulProcInfoByPort(struct procInfo* infoArr, size_t num, int port){
    // 명령어 출력 결과 버퍼
    char buff[BUFSIZ];
    memset(buff, 0, sizeof(buff));

    // 명령어 설정
    char command[BUFSIZ];
    // netstat으로 읽고, 정규표현식으로 grep (양식: "XXX.XXX.XXX.XXX:[port] ")
    sprintf(command, "netstat -ntlp | grep -E [0-9]\\+.[0-9]\\+.[0-9]\\+.[0-9]*:%d\\+' '", port);
    
    //결과 버퍼
    memset(infoArr, 0, sizeof(struct procInfo)*num);
    
    FILE* f = popen(command, "r");
    if (f == NULL){
        perror("popen");
        pclose(f);
        return -1;
    }
    fread(buff, sizeof(buff), 1, f);
    if (strlen(buff) < 0){
        perror("fread");
        pclose(f);
        return -1;
    }
    else if(strlen(buff) == 0){
        fprintf(stderr, "process not found\n");
        pclose(f);
        return -1;
    }

    // printf(buff);
    int offset = 0;
    int count;
    for(count = 0; count < num; count++){
        if(buff[offset] == NULL)
            break;
        
        char line[BUFSIZ];
        struct procInfo* info;

        sscanf(buff + offset, "%[^\n]\n", line);
        offset += strlen(line)+1;
        info = (struct procInfo*)((struct procInfo*)infoArr + count);

        char localAddrBuff[32];
        char foreignAddrBuff[32];
        // Proto Recv-Q Send-Q Local_Address Foreign_Address State PID/Program name
        sscanf(line, "%s %*d %*d %*d.%*d.%*d.%*d:%d %*d.%*d.%*d.%*d:%*s %s %d/%s\n",
            info->protocol,
            localAddrBuff,
            &(info->port),
            foreignAddrBuff,
            info->state,
            &(info->pid),
            info->procName);
        // 주소를 네트워크 바이트로 변환
        inet_aton(localAddrBuff, &(info->localAddress));
        inet_aton(foreignAddrBuff, &(info->foreignAddress));
    }
    return count;
}

int getChildPids(int ppid, int* childPids, int maxCnt){
    // 자식 프로세스들이 저장되는 파일 읽음
    char path[BUFSIZ];
    sprintf(path, "/proc/%d/task/%d/children", ppid, ppid);
    
    FILE* f = fopen(path, "r");
    if (f == NULL){
        perror("fopen");
        pclose(f);
        return -1;
    }

    // 파일에서 %d단위로 읽어옴
    int count;
    for(count = 0; !feof(f) && count < maxCnt; count++){
        fscanf(f, "%d", childPids+count);
    }

    fclose(f);
    return count;
}