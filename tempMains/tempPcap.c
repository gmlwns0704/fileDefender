#include "../header/clientManage.h"
#include "../header/getPacket.h"
#include "../header/getProc.h"
#include "../header/tcpkiller.h"

int main(int argc, char** argv){
    // tcpkill 관리하는 프로세스 생성
    initController();
    /*
    각 인터페이스 별로 별도의 프로세스 만들어서 패킷 캡쳐 수행하기,
    initController로 만들어진 tcpkill프로세스와 파이프는 그대로 유지됨
    */
    int pid_lo = fork();
    if(pid_lo == 0){
        packetCapture("lo", argv[1]);
        return 0;
    }
    int pid_enp2s0 = fork();
    if(pid_enp2s0 == 0){
        packetCapture("enp2s0", argv[1]);
        return 0;
    }

    wait(pid_lo);
    wait(pid_enp2s0);
    
    return 0;
}