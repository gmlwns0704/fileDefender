#include "../header/getPacket.h"
#include <stdio.h>

int main(int argc, char** argv){
    printf("%d\n", isDataInFile(argv[1], strlen(argv[1]), argv[2]));
    return 0;
}