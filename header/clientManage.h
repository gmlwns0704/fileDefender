#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <time.h>

struct client{
    struct in_addr addr;
    time_t lastTime;
};

struct clientList{
    struct client data;
    struct clientList* next;
};

void printClientInfo(struct client* clInfo);
void printClientList(struct clientList* head);

int clIsSame(struct client* a, struct client* b);
int findClient(struct clientList* head, struct client* target);
int newClient(struct clientList* head, struct client* target);
time_t getLastTime(struct clientList* head, struct client* target);