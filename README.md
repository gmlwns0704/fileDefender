# fileDefender
외부와 이루어지는 통신에 대하여, 허가되지않은 외부 접속자가 특정 파일에 접근하려고 시도하면 통신을 차단함

# 구현할 내용
패킷캡쳐 (O)

포트번호로 프로세스 확인 (O)

tcpkill로 조건에 맞는 tcp차단 (O)

각종 tcpkill프로세스들 종합관리(프로세스B) (기본은 완성)

설정파일 읽고쓰는 기능

해당 프로세스와 자식프로세스들이 접근하는 파일 목록 추출

위에서 추출해낸 정보들로 설정파일에서 읽은 조건과 비교해서 차단여부 결정

# 해결할 내용
클라이언트-프로세스 통신 식별가능, 프로세스별 접근하는 파일 조회가능
=> 하지만 하나의 프로세스가 여러 클라이언트를 처리할때 어느 클라이언트가 어느 파일에 접근하는지 확인할 방법이 없음.
ex) A클라이언트가 A파일에 접근하는 것을 B가 A파일에 접근하는 것으로 오해하고 B를 차단해버릴 가능성 존재

# blockController (프로세스B) 에 명령내리는 법
tempMain.c 참고
  1. struct command 구조체 변수 생성
  2. command.func 값 설정 (tcpkiller.h의 enum functable참조)
  3. command.size 값 설정 (tcpkiller.h의 enum functable 주석 참조 or 그 아래의 #define 참조)
  4. func값에 따른 적절한 변수값 설정 (ex: func = t_blockPort 라면, struct connInfo)
  5. 둘을 하나의 버퍼에 통합
  6. 자식프로세스 readfd에 write