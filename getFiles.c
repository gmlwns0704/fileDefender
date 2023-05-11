#include <stdio.h>
#include "header/getProc.h"
#include <string.h>

int main()
{
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

    //lsof로 파일명만 가져오기
    sprintf(buffer, "lsof +p %d | tr -s ' ' | cut -d' ' -f9 ", PID);

    fp = popen(buffer, "r");
    if (fp == NULL)
    {
        perror("erro : ");
    }

    while (fgets(buff, 200, fp) != NULL)
    {
        printf("%s", buff);
    }

    pclose(fp);

}
