#include "header/clientManage.h"
#include "header/getPacket.h"
#include "header/getProc.h"
#include "header/setting.h"
#include "header/tcpkiller.h"

int main(int argc, char** argv){
    if(argc == 1){
        printf("usage: %s [interfaces...]\n", argv[0]);
        return 0;
    }
    // tcpkill 관리 프로세스 생성
    int controllerPid = initController();
    printf("controller pid: %d\n", controllerPid);

    // 인터페이스별로 캡쳐 프로세스 생성
    int* pids = malloc(sizeof(int)*(argc-1));
    for(int i = 0; i < argc-1; i++){
        pids[i] = fork();
        if(pids[i] == 0){
            packetCapture(argv[i+1], "tcp");
            return 0;
        }
        else
            printf("%s capture pid: %d\n", argv[i+1], pids[i]);
    }

    for(int i = 0; i < argc-1; i++){
        wait(pids[i]);
    }
}
