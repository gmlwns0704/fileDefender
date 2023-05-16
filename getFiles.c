#include <stdio.h>
#include <stdlib.h>
#include "header/getProc.h"
#include <string.h>

int main()
{
     FILE* fp;
    struct procInfo procIn;
    int PID, i=0;
    //파일 출력하는 버퍼
    char buff[BUFSIZ];
    //sprintf 임시 버퍼
    char buffer[BUFSIZ];
    //파일 목록 저장 포인터 배열
    char *files[BUFSIZ];

    //포트 번호로 프로세스 아이디 받아오기
    getProcInfoByPort(&procIn, 22);

    PID = procIn.pid;

    sprintf(buffer, "lsof +p %d | tr -s ' ' | cut -d' ' -f9 ", PID);

    fp = popen(buffer, "r");
    if (fp == NULL)
    {
        perror("erro : ");
    }

    while (fgets(buff, 200, fp) != NULL)
    {
        //파일이름 하나씩 포인터 배열에 저장
        files[i] = buff;
        printf("%s", files[i]);
        i++;
    }

    pclose(fp);

}
