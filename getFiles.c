#include <stdio.h>
#include "header/getProc.h"

int main()
{
    FILE* fp;
    struct procInfo procIn;
    int PID, i;
    //���� ����ϴ� ����
    char buff[200];
    //sprintf �ӽ� ����
    char buffer[200];

    //��Ʈ ��ȣ�� ���μ��� ���̵� �޾ƿ���
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