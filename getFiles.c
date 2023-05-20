#include <stdio.h>
#include <stdlib.h>
#include "header/getProc.h"
#include <string.h>
#include <stdbool.h>

void protectfile(char* path){

}

bool findfile(int filecount, char* path[]){
    FILE* fp;
    struct procInfo procIn;
    int PID;
    //파일 출력하는 버퍼
    char buff[BUFSIZ];
    //sprintf 임시 버퍼
    char buffer[BUFSIZ];
    int cnt = 0;
    char* save[BUFSIZ];
    char temp[BUFSIZ];
    for(int i = 0 ; i < filecount ; i++)
    {
        //포트 번호로 프로세스 아이디 받아오기
        //getProcInfoByPort(&procIn, 22);

        //PID = procIn.pid;
        sprintf(buffer, "lsof +p %d | tr -s ' ' | cut -d' ' -f9 ", 3827);

        fp = popen(buffer, "r");
        if (fp == NULL)
        {
            perror("erro : ");
        }

        while (fgets(buff, 100, fp) != NULL)
        {
            if(strlen(path[i]) != 0)
            {
                if(strncmp(path[i], buff, strlen(path[i])) == 0)
                {
                    printf("Path%d -> 검색된 파일 이름 : %s\n", i+1, buff);
                    /*strcpy(temp, buff);
                    save[i] = temp;*/
                    cnt++;
                }
            }
        }
    }

    pclose(fp);
    if(cnt > 0)
        return true;
    else
        return false;
}


int main()
{
    //파일 경로들 저장할 포인터 배열
    char* filename[100];
    //검색할 파일들
    char path1[30] = "/usr/lib";
    char path2[30] = "/home";
    char path3[30] = "/ffd";
    bool flag;

    filename[0] = path1;
    filename[1] = path2;
    filename[2] = path3;
    //검색할 파일 개수, 파일 경로 저장한 포인터 배열 인자로 전달
    flag = findfile(3, filename);
    if(flag == true)
        printf("파일 검색 완료\n");
    else
        printf("그런 파일은 없습니다.\n");

}
