#include <stdio.h>
#include <stdlib.h>
#include "header/getProc.h"
#include <string.h>
#include <stdbool.h>

bool findfile(char* path){
    FILE* fp;
    struct procInfo procIn;
    int PID;
    //파일 출력하는 버퍼
    char buff[BUFSIZ];
    //sprintf 임시 버퍼
    char buffer[BUFSIZ];

    //포트 번호로 프로세스 아이디 받아오기
    getProcInfoByPort(&procIn, 22);

    PID = procIn.pid;
    sprintf(buffer, "lsof +p %d | tr -s ' ' | cut -d' ' -f9 ", PID);

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


int main()
{
    char* filename;
    //file에 검색할 파일 경로 넣으면 됨
    char file[30] = "/home";
    bool flag;

    filename = file;
    flag = findfile(filename);
    if(flag == true)
        printf("파일 검색 완료\n");
    else
        printf("그런 파일은 없습니다.\n");
}
