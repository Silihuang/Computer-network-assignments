#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <sys/time.h>

typedef int bool;

#define true 1
#define false 0
#define TIME_OUT 2 // 等不到ICMP reply, recv_icmp() return TIME_OUT
#define FIND_DST 3 // 找到目的地, terminated

static bool alarm_flag ;

// checksum
uint16_t checksum(uint16_t *addr, int len) {
        int nleft = len;
        uint32_t sum = 0;
        uint16_t *w = addr;
        uint16_t answer = 0;

        while (nleft > 1) {
            sum += *w++;
            nleft -= 2;
        } // while

        if (nleft == 1) {
            *(unsigned char *) (&answer) = *(unsigned char *) w;
            sum += answer;
        } // if 

        sum = (sum >> 16) + (sum & 0xffff) ;
        sum += (sum >> 16) ;
        return ~sum ;
} // checksum

// Timeout handler
void Timeout_handler( int signo ) { 

    alarm_flag = true ;

} // Timeout

// Receive封包
int recv_icmp( int sock_recv_send, char *argv[] ) { 

    char dst[16] = "" ; // 轉換完的IP address, Destiation ;
    char src[16] = "" ; // 轉換完的IP address, Source;
    char receivebuf[1024] ; // 封包buffer
    memset(receivebuf, 0, sizeof(receivebuf));
    int num ;

    // 設置alarm ; 
    alarm_flag = false ;
    struct sigaction sa ;
    sigemptyset( &sa.sa_mask ) ;
    sa.sa_handler = Timeout_handler ;
    sa.sa_flags = 0 ;
    sigaction( SIGALRM, &sa, NULL ) ;
    alarm(2) ;

    // 接收來自目標主機的 Echo Reply
    recv( sock_recv_send, receivebuf, sizeof( receivebuf ), 0 ) ;

    if (alarm_flag) { // 逾時Interrupt
        alarm(0) ;
        return TIME_OUT ;
    } // if

    // 取出 IP Header
    struct iphdr *ip_headrptr = (struct iphdr*)receivebuf ;
    // !!!IP轉換(uint32_t->string)!!!
    inet_ntop( AF_INET, &ip_headrptr->saddr, src, sizeof(src ) ) ; 
    printf( "%s\n", src ) ; // 印出資訊router的IP

    alarm(0) ;
    if ( strcmp(src, argv[2]) == 0 ) return FIND_DST ; // 收到目的地reply
    else return 0 ;

} // recv_icmp

int main(int argc, char *argv[]) {

    // ----------------輸入-----------------
    if ( argc != 3 ) {
        printf( "Error Command Type:./proc, TTLnum, IP\n" ) ;
        return 1 ;
    } // if
    else {
        printf("traceroute to %s, %d hops max (ICMP) \n", argv[argc-1], atoi(argv[1]) );
    } // else 
    // ----------------目的地socket設定-----------------
    struct sockaddr_in dst_socket ; // 目的地socket資訊
    bzero( &dst_socket, sizeof(dst_socket) ) ; 
    dst_socket.sin_family = AF_INET ; // Internet type
    dst_socket.sin_addr.s_addr = inet_addr( argv[argc-1] ) ; // 目的地IP

    // ----------------發送端socket設定-----------------
    // AF_INET與AF_PACKET的區別在於
    // 前者只能看到IP層以上的東西，而後者可以看到link層(ethernet)的信息
    // IPv4 , ICMP protocol socket
    int sock_recv_send ; 
    if ( (sock_recv_send = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP ) ) < 0) {
        perror( "socket error" ) ;
        exit(-1);
    } // if 

    // ----------------ICMP's send封包設定-----------------
    struct icmp *icmpsend ;  // 接收與發送的ICMP packet
    char sendbuf[1500] ;
    icmpsend = (struct icmp *) sendbuf;
    // set ICMP's Payload
    icmpsend->icmp_type = 8 ; // Echo Request 
    icmpsend->icmp_code = 0 ; 
    icmpsend->icmp_id = 0 ; 
    icmpsend->icmp_seq = htons(0) ; // sequence number
    // checksum
    icmpsend->icmp_cksum = checksum( ( u_short* ) icmpsend, 56 ) ;
    // ----------------發送並設定TTL-----------------
    for( int i = 0 ; i < atoi(argv[1]) ; i++ ) {

        int ttl = i + 1 ;
        setsockopt( sock_recv_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)); // 設定TTL
        // Echo request 
        if ( sendto( sock_recv_send, icmpsend, 56, 0, (struct sockaddr *) &dst_socket, sizeof( dst_socket ) ) < 0 ) {
            perror( "sendto error" ) ;
            exit(-1) ;
        } // if 

        printf( "%2d  ", i+1 ) ; // 第幾個封包
        int result = recv_icmp( sock_recv_send, argv ) ;
        if ( result == TIME_OUT ) printf("*\n"); // 接收ICMP, 如果ICMP reply逾時印*
        else if (result == FIND_DST ) break ;

    } // for

    return 0 ;
} // main