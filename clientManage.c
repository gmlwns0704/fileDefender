#include "header/getPacket.h"
#include "header/getProc.h"
#include "header/tcpkiller.h"
#include "header/clientManage.h"

/*
해당 클라이언트의 정보 출력
*/
void printClientInfo(struct client* clInfo){
    printf("ip: %s\n", inet_ntoa(clInfo->addr));
    printf("last time: %ld\n", clInfo->lastTime);
}

/*
리스트의 노드들 순차적으로 출력
*/
void printClientList(struct clientList* head){
    struct clientList* tmp = head;
    if(tmp == NULL){
        printf("head is NULL\n");
        return;
    }
    while(tmp != NULL){
        printClientInfo(&(tmp->clInfo));
        printf("this: %p\n", tmp);
        printf("next: %p\n", tmp->next);
        tmp = tmp->next;
    }
}

/*
두 클라이언트가 같은 클라이언트인지 비교 후 1 or 0 리턴
*/
int clIsSame(struct client* a, struct client* b){
    // 둘중 하나라도 NULL
    if(!a || !b)
        return 0;
    // 값 비교
    int result = (ntohs(a->addr.s_addr) == ntohs(b->addr.s_addr));
    return result;
}

/*
해당 정보의 클라이언트가 존재한다면 1 아니면 0 리턴
*/
int findClient(struct clientList* head, struct client* target){
    for(struct clientList* tmp = head; tmp != NULL; tmp = tmp->next){
        if(clIsSame(&(tmp->clInfo), target)){
            return 1;
        }
    }
    // 존재하지 않음
    return 0;
}

/*
새로운 클라이언트를 리스트의 2번째 노드로 추가하고 1리턴 (1번째는 항상 head)
이미 존재한다면 추가하지 않고 0리턴
*/
int newClient(struct clientList* head, struct client* target){
    // 이미 존재하는 클라이언트임
    if(findClient(head, target))
        return 0;
    // 새로운 클라이언트임
    struct clientList* tmp = head;
    // tmp->next를 2번째 노드로
    tmp->next = head->next;
    // target내용 복사
    memcpy(&(tmp->clInfo), target, sizeof((tmp->clInfo)));
    // head->next를 새로운 노드로
    head->next = tmp;
    return 1;
}

/*
리스트에서 해당 클라이언트 탐색 후 정보 업데이트
존재하지 않으면 0 리턴
*/
int updateClient(struct clientList* head, struct client* target){
    for(struct clientList* tmp = head; tmp != NULL; tmp = tmp->next){
        if(clIsSame(&(tmp->clInfo), target)){
            memcpy(&(tmp->clInfo), target, sizeof((tmp->clInfo)));
            return 1;
        }
    }
    // 존재하지 않음
    return 0;
}

/*
해당 정보의 클라이언트와 마지막으로 통신한 시간 time_t 리턴
존재하지 않으면 0 리턴
*/
time_t getLastTime(struct clientList* head, struct client* target){
    for(struct clientList* tmp = head; tmp != NULL; tmp = tmp->next){
        if(clIsSame(&(tmp->clInfo), target)){
            return tmp->clInfo.lastTime;
        }
    }
    // 존재하지 않음
    return 0;
}