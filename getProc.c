#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "header/getProc.h"

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
        fprintf(stderr, "popen error\n");
        return NULL;
    }
    fread(buff, sizeof(buff), 1, f);
    if (strlen(buff) == 0){
        fprintf(stderr, "fread error\n");
        return NULL;
    }

    // Proto Recv-Q Send-Q Local_Address Foreign_Address State PID/Program name
    sscanf(buff, "%s %*d %*d %s %s %s %d/%[^\n]\n",
        info->protocol,
        info->localAddress,
        info->foreignAddress,
        info->state,
        &(info->pid),
        info->procName);
    
    pclose(f);

    return info;
}