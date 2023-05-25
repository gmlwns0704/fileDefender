#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define GETSOCKETERRNO() (errno)

int main() {

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    //클라이언트 저장하기 위한 배열
    int usersave[5] = {-1, -1, -1, -1, -1};
    //임의로 사용하는 user변수
    int user;
    char buff[200];
    FILE* fp;

    struct addrinfo *bind_address;
    getaddrinfo(0, "8080", &hints, &bind_address);

    SOCKET socket_listen;
    socket_listen = socket(bind_address->ai_family,
            bind_address->ai_socktype, bind_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_listen)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    if (bind(socket_listen,
                bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }
    freeaddrinfo(bind_address);

    if (listen(socket_listen, 10) < 0) {
        fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

    fd_set master;
    FD_ZERO(&master);
    FD_SET(socket_listen, &master);
    SOCKET max_socket = socket_listen;

    //서버 시작
    printf("---Server Start---\n");

    while(1) {
        fd_set reads;
        reads = master;
        if (select(max_socket+1, &reads, 0, 0, 0) < 0) {
            fprintf(stderr, "select() failed. (%d)\n", GETSOCKETERRNO());
            return 1;
        }

        SOCKET i;
        for(i = 1; i <= max_socket; i++) {
            if (FD_ISSET(i, &reads)) {

                if (i == socket_listen) {
                    struct sockaddr_storage client_address;
                    socklen_t client_len = sizeof(client_address);
                    SOCKET socket_client = accept(socket_listen,
                            (struct sockaddr*) &client_address,
                            &client_len);
                    if (!ISVALIDSOCKET(socket_client)) {
                        fprintf(stderr, "accept() failed. (%d)\n",
                                GETSOCKETERRNO());
                        return 1;
                    }

                    FD_SET(socket_client, &master);
                    if (socket_client > max_socket)
                        max_socket = socket_client;

                    char address_buffer[100];
                    char port[100];
                    getnameinfo((struct sockaddr*)&client_address,
                            client_len,
                            address_buffer, sizeof(address_buffer), port, sizeof(port),
                            NI_NUMERICHOST);
                    //client 연결
                    printf("Accept connection from client\n");
                    
                    for(int n = 0 ; n < 5 ; n++){
                        if(usersave[n] == -1 && usersave[n] != -2)
                        {
                            usersave[n] = socket_client;
                            //임의의 user변수에 n값 저장 입장 알림 때 사용
                            user = n;
                            break;
                        }
                    }

                } else {
                    char read[1024];
                    int bytes_received = recv(i, read, 1024, 0);

                    if (bytes_received < 1) {
                        FD_CLR(i, &master);
                        CLOSESOCKET(i);

                        //감시하다가 어떤 사용자가 나가면 퇴장 알림
                        for(int n = 0 ; n < 5 ; n++){
                            if(usersave[n] == i)
                            {
                                //해당 client 퇴장 알림 서버에 출력
                                printf("client%d disconnected.\n",n+1);

                                usersave[n] = -2;
                                break;
                            }
                        }
                        continue;
                    } 

                    //어떤 client가 보낸 메세지인지 구분하기 위한 변수
                    int now_talking;
                    for(int n = 0 ; n < 5 ; n++){
                        //채팅 참여자 저장 배열인 usersave중 하나의 client 일시 now_talking에 값 저장후 break;
                        if(usersave[n] == i)
                        {
                            now_talking = n+1;
                            break;
                        }
                    }

                    //서버에 client, client가 보낸 메세지 출력
                    printf("client%d : %.*s", now_talking, bytes_received, read);

                    char *ptr = strtok(read, "\n");
                    
                    char catfile[100];
                    char en[1] = "\n";
                    sprintf(catfile, "cat %s\n", read);
                    printf("client%d request : %s", now_talking, catfile);

                    fp = popen(catfile, "r");

                    if (fp == NULL)
                    {
                        perror("erro : ");
                    }
                    while (fgets(buff, 200, fp) != NULL)
                    {
                        send(i, buff, strlen(buff), 0);
                    }

                    send(i, en, 1, 0);
                    printf("파일 전송 완료\n");
                    pclose(fp);
                    
                }         
            } 
        } 
    }

    printf("Closing listening socket...\n");
    CLOSESOCKET(socket_listen);

    printf("Finished.\n");

    return 0;
}
