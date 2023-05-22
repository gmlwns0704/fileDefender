#include <stdio.h>
#include <stdlib.h>
#include "header/getProc.h"
#include <string.h>
#include <stdbool.h>

//파일 목록 저장 구조체
typedef struct {
    int check;
    char path[BUFSIZ];
}savefile;

//임시 파일 목록 저장
char* filebuffer[1024];

//파일 목록 리턴 함수
char** protectfile(savefile* files[]){
    for(int i = 0 ; i < sizeof(filebuffer) / sizeof(char *) ; i ++)
    {
        filebuffer[i] = malloc(sizeof(char *));
    }
    for(int i = 0 ; i < 1024 ; i++)
    {
        if(files[i]->check != 0)
            filebuffer[i] = files[i]->path;
    }

    return filebuffer;
}

//검색한 파일 존재 유무 찾는 함수
bool findfile(int filecount, char* path[]){
    char** temp;
    FILE* fp;
    savefile* files[1024];
    for(int j = 0 ; j < sizeof(files) / sizeof(savefile *) ; j++)
    {
        files[j] = malloc(sizeof(savefile)); 
        files[j]->check = 0;
    }
    struct procInfo procIn;
    int PID;
    //파일 출력하는 버퍼
    char buff[BUFSIZ];
    //sprintf 임시 버퍼
    char buffer[BUFSIZ];
    int cnt = 0;

    for(int i = 0 ; i < filecount ; i++)
    {
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
            if(strlen(path[i]) != 0)
            {
                if(strncmp(path[i], buff, strlen(path[i])) == 0)
                {
                    printf("Path%d -> 검색된 파일 이름 : %s\n", i+1, buff);
                    for(int j = 0 ; j < cnt+1 ; j++)
                    {
                        if(files[j]->check == 0)
                        {
                            strcpy(files[j]->path, buff);
                            files[j]->check = 1;
                            break;
                        } 
                    }
                    cnt++;
                }
            }
        }
    }

    //파일 목록 받아오는 함수 호출 (이 함수는 필요할 때 호출해서 쓰면 됨)
    temp = protectfile(files);
    //파일 목록 출력 가능
    /*for(int j = 0 ; j < cnt + 1 ; j++)
    {
        printf("%s", temp[j]);
    }*/

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
