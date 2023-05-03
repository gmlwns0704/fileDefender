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
    char command[BUFSIZ];
    sprintf(command, "netstat -ntlp | grep :%d", port);
    
    //결과 버퍼
    memset(info, 0, sizeof(struct procInfo));
    
    FILE* f = popen(command, "r");
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

    printf(buff);
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
    sprintf(command, "netstat -ntlp | grep -E [0-9]\\+.[0-9]\\+.[0-9]\\+.[0-9]*:%d\\+' '", port);
    
    //결과 버퍼
    memset(info, 0, sizeof(struct procInfo));
    
    FILE* f = popen(command, "r");
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

    printf(buff);
    int offset = 0;
    int count = 0;
    for(count = 0; count < num; count++){
        char line[BUFSIZ];
        struct connInfo* info;

        sscanf(buff + offset, "%[^\n]\n", line);
        offset += strlen(line)+1;
        info = (struct connInfo*)infoArr + count;

        char localAddrBuff[32];
        char foreignAddrBuff[32];
        // Proto Recv-Q Send-Q Local_Address Foreign_Address State PID/Program name
        sscanf(line, "%s %*d %*d %[^: ]:%d %[^: ]:%*s %s %d/%[^: ]\n",
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