#include "../header/getProc.h"
#include <stdio.h>

int main(int argc, char** argv){
    int* pids;
    int ppid = atoi(argv[1]);

    int childNum = getChildPids(ppid, &pids);
    if(childNum < 0){
        fprintf(stderr, "childNum is %d, child not exist or error\n", childNum);
        return 0;
    }
    for(int i = 0; i < childNum; i++){
        printf("%d ", pids[i]);
    }
    printf("\n");
}