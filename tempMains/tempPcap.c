#include "../header/clientManage.h"
#include "../header/getPacket.h"
#include "../header/getProc.h"
#include "../header/tcpkiller.h"

int main(int argc, char** argv){
    // tcpkill 관리하는 프로세스 생성
    initController();
    packetCapture(argv[1], argv[2]);
    return 0;
}