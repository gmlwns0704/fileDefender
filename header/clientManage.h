#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <time.h>

struct client{
    struct in_addr addr; // ip주소
    time_t lastTime; // 마지막 통신 시간
};

struct clientList{
    struct client clInfo; // 클라이언트 정보
    struct clientList* next; // linked list 다음 노드
};

void printClientInfo(struct client* clInfo);
void printClientList(struct clientList* head);

int clIsSame(struct client* a, struct client* b);
int findClient(struct clientList* head, struct client* target);
int newClient(struct clientList* head, struct client* target);
int updateClient(struct clientList* head, struct client* target);
time_t getLastTime(struct clientList* head, struct client* target);