#include <stdio.h>
#include <stdlib.h>
#include "header/getProc.h"
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

//검색한 파일 존재 유무 찾는 함수
int findfile(int pid, int filecount, char*** filelist_buffer, char* path[]){
    FILE* fp;
    int cnt = 0;
    int k = 0;
    int* pids;
    //자식 프로세스 pid가져오기
    int pid_cnt = getChildPids(pid, &pids);
    
    struct procInfo procIn;
    //파일 출력하는 버퍼
    char buff[200];
    //sprintf 임시 버퍼
    char buffer[100];
    
    for(int h = 0 ; h < pid_cnt ; h++)
    {
        for(int i = 0 ; i < filecount ; i++)
        {
            sprintf(buffer, "lsof +p %d | tr -s ' ' | cut -d' ' -f9 ", pids[h]);

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
                        //printf("Pid %d : Path%d -> 검색된 파일 이름 : %s\n", pids[h], i+1, buff);
                        cnt++;
                    }
                }
            }
        }
    }

    *filelist_buffer = (char **)malloc(sizeof(char *) * cnt);
    for(int j = 0 ; j < cnt ; j++)
    {
        (*filelist_buffer)[j] = (char*)malloc(sizeof(char) * 256); 
    }

    for(int h = 0 ; h < pid_cnt; h++)
    {
        for(int i = 0 ; i < filecount ; i++)
        {
            sprintf(buffer, "lsof +p %d | tr -s ' ' | cut -d' ' -f9 ", pids[h]);

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
                        strcpy((*filelist_buffer)[k], buff);
                        k++;
                    }
                }
            }
        }
        pclose(fp);
    }

    free(pids);
    if(cnt > 0)
        return cnt;
    else
        return 0;
}

/*
int main()
{
    //파일 경로들 저장할 포인터 배열
    char* filename[100];
    //검색할 파일들
    char path1[30] = "/usr/lib";
    char path2[30] = "/home";
    char path3[30] = "/";
    int pid = 1986, flag;
    //파일목록 저장 버퍼
    char** buffer;

    int testpid;
    filename[0] = path1;
    filename[1] = path2;
    filename[2] = path3;

    //fork();

    //검색할 파일경로 개수, 파일목록 저장할 버퍼, 파일 경로들 입력
    flag = findfile(pid, 3, &buffer, filename);
    if(flag > 0)
        printf("파일 %d개 검색 완료\n", flag);
    else
        printf("그런 파일은 없습니다.\n");

    for(int i = 0 ; i < flag; i++)
    {
        printf("%s", buffer[i]);
    }
}
*/
