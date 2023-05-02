#include <stdio.h>
#include "header/getProc.h"

int main()
{
    FILE* fp;
    struct procInfo procIn;
    int PID, i;
    //파일 출력하는 버퍼
    char buff[200];
    //sprintf 임시 버퍼
    char buffer[200];

    //포트 번호로 프로세스 아이디 받아오기
    getProcInfoByPort(&procIn, 22);

    PID = procIn.pid;
    i = sprintf(buffer, "%s", "lsof -p ");
    i += sprintf(buffer + i, "%d", PID);

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