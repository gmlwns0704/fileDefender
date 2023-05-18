#include <stdio.h>
#include <stdlib.h>
#include "header/getProc.h"
#include <string.h>
#include <stdbool.h>

bool findfile(int pid, char* path){
    FILE* fp;
    struct procInfo procIn;
    //파일 출력하는 버퍼
    char buff[BUFSIZ];
    //sprintf 임시 버퍼
    char buffer[BUFSIZ];

    sprintf(buffer, "lsof +p %d | tr -s ' ' | cut -d' ' -f9 ", pid);

    fp = popen(buffer, "r");
    if (fp == NULL)
    {
        perror("erro : ");
    }

    while (fgets(buff, 100, fp) != NULL)
    {
        if(strncmp(path, buff, strlen(path)) == 0)
        {
            printf("검색된 파일 이름 : %s\n", buff);
            return true;
        }
    }

    pclose(fp);

    return false;
}