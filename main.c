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
    initController();

    // 인터페이스별로 캡쳐 프로세스 생성
    int* pids = malloc(sizeof(int)*(argc-1));
    for(int i = 1; i < argc; i++){
        pid[i-1] = fork();
        if(pid[i-1] == 0){
            packetCapture(argv[i], "tcp");
            break;
        }
    }

    for(int i = 0; i < argc-1; i++){
        wait(pid[i-1]);
    }
}
