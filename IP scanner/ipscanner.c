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
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>

// ---------預設Code---------
#define PACKET_SIZE 92
#define IP_OPTION_SIZE 8
#define ICMP_PACKET_SIZE   PACKET_SIZE - (int)sizeof(struct ip) - IP_OPTION_SIZE
#define ICMP_DATA_SIZE     ICMP_PACKET_SIZE - (int)sizeof(struct icmphdr)
#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

typedef char u8;

typedef struct { // size = 92
	struct ip ip_hdr ; // 20bytes, struct ip: UNIX / struct iphdr: LINUX 
	struct icmphdr icmp_hdr ; // 與data加起來為72
	u8 studientID[10] ; // 學號
} myicmp ;

static struct in_addr Interface_ipaddress ; // Host的ip
static clock_t t1, t2; // timer
 

uint16_t Checksum( uint16_t *addr, int len ) {
        uint32_t sum = 0;
        uint16_t *w = addr;
        uint16_t answer = 0;

        while (len > 1) {
            sum += *w++;
            len -= 2;
        } // while

        if ( len == 1 ) {
            *(uint8_t*) (&answer) = *(uint8_t *) w;
            sum += answer;
        } // if 

        sum = (sum >> 16) + (sum & 0xffff) ;
        sum += (sum >> 16) ;
        return ~sum ;
} // checksum

int Get_Interface( char *InterfaceName, struct in_addr *interface_ipaddr ) {	

	int fd ;
	struct ifreq macreq ; // interface request structure
	fd = socket( AF_INET, SOCK_DGRAM, 0 ) ;
	strcpy( macreq.ifr_ifrn.ifrn_name, InterfaceName ) ; // 輸入網卡名

	if ( ioctl( fd, SIOCGIFINDEX, &macreq ) < 0 ) {
        // 獲取網卡index
        perror("ioctl error\n") ;
        return 1 ;
    } // if 
	if ( ioctl( fd, SIOCGIFADDR, &macreq ) < 0 ) {
	    // 取出自己的IP(send ip)
        perror("ioctl IP error\n") ;
        return 1 ;
    } // if 

	memcpy(interface_ipaddr, &((struct sockaddr_in *)(&macreq.ifr_addr))->sin_addr, 4);
	return 0 ;

} // Get_Interface

myicmp *Set_packet( myicmp *sendpacket, char Dstip[20], int i ) {

    sendpacket->icmp_hdr.checksum = 0 ; // initalize
    sendpacket->ip_hdr.ip_sum = 0 ;

    // ---IP header---
    sendpacket->ip_hdr.ip_hl = 5 ; // 五排
    sendpacket->ip_hdr.ip_v = 4 ; // ipv4
    sendpacket->ip_hdr.ip_tos = 0 ;
    sendpacket->ip_hdr.ip_len = htons(PACKET_SIZE) ;
    sendpacket->ip_hdr.ip_id = 0 ;
    sendpacket->ip_hdr.ip_off = htons( IP_DF ) ; // don't fragment
    sendpacket->ip_hdr.ip_ttl = 1 ; // hop 1 
    sendpacket->ip_hdr.ip_p = 1 ; // ICMP
    memcpy( &sendpacket->ip_hdr.ip_src, &Interface_ipaddress, 4 ) ; // src ip
    inet_pton( AF_INET, Dstip, &sendpacket->ip_hdr.ip_dst ) ;
    sendpacket->ip_hdr.ip_sum = Checksum( (uint16_t *)&sendpacket->ip_hdr, 20 ) ; // checksum

    // ---ICMP---
    sendpacket->icmp_hdr.type = 8 ; // echo_request
    sendpacket->icmp_hdr.code = 0 ;
    sendpacket->icmp_hdr.un.echo.id = htons( getpid() ) ; // process id
    sendpacket->icmp_hdr.un.echo.sequence = htons( i ) ; // 第幾個封包
    strcpy( sendpacket->studientID, "M103040053" ) ;
    sendpacket->icmp_hdr.checksum = Checksum( (uint16_t *)&sendpacket->icmp_hdr, 72 ) ; // checksum

    return sendpacket ;

} // Set_packet


// Receive封包
int recv_icmp( int sock_recv, struct timeval timeout, char Dstip[20], int sequence  ) { 

    int sock_recv_send ; 
    char receivebuf[4096] ; // 封包buffer
    char src[20] = "" ; // 轉換完的IP address, Source;
    struct iphdr *ip_headrptr = (struct iphdr*)receivebuf ; 
    int iphdrlen = ip_headrptr->ihl << 2 ; // header len
    struct icmphdr *icmp_header = (struct icmphdr*)( receivebuf + iphdrlen ) ; 

    if ( ( sock_recv_send = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP ) ) < 0) {
        perror( "socket error" ) ;
        exit(-1);
    } // if

    if ( setsockopt( sock_recv_send, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval) ) < 0 ) {
        // 設定timeout
        // SO_RCVTIMEO: 接收時間, SOL_SOCKET: 正在使用的socket選項
        perror( "setsockopt: timeout" ) ;
        exit(1);
    } // if 

    // 接收來自目標主機的 Echo Reply

    if ( recv( sock_recv_send, receivebuf, sizeof( receivebuf ), 0 ) > 0 ) {
        t2 = clock();
        inet_ntop( AF_INET, &ip_headrptr->saddr, src, sizeof(src ) ) ; // uint32_t->string
        // 確定是reply
        if ( strcmp( Dstip, src ) == 0 && icmp_header->type == 0  // net是little endian, host是big endian
            && (int)icmp_header->un.echo.id == htons(getpid()) && (int)icmp_header->un.echo.sequence == htons(sequence) ) {
            // Check : Source_ip, ICMP Type, ICMP Message ID, ICMP Sequence         
            printf( "\tReply from : %s , time : %.3lf ms\n", src, (t2-t1)/(double)(CLOCKS_PER_SEC)*1000 ) ; // 印出資訊router的IP   
            return 0 ;  
        } // if 

    } // if 

    printf( "\tDestination Unreachable\n" ) ;
    return 1 ;

} // recv_icmp 

int main(int argc, char *argv[]) {

    if ( getuid() != 0 || argc != 5 || strcmp( argv[1], "-i" ) != 0 || strcmp( argv[3], "-t" ) != 0 ) {
        printf( "Command Type: sudo ./ipscanner -i <interface>, -t <time(ms)>\n" ) ;
        return 1 ;
    } // if
    else if ( atoi(argv[4]) < 50  ) {
        printf( "Warning: Timeout時間太小, 結果可能有誤\n") ;
        return 1 ;
    } // else 

    int time_ms = atoi( argv[4] ) ; // timeout時間
	struct timeval timeout = { 0, time_ms*1000 } ; // 不知道為何要這樣寫才可以..... timeout.usec = xxx 不行？_?

    // ----------------獲取網卡資訊(IP address)-----------------
    if ( Get_Interface( argv[2], &Interface_ipaddress ) ) {
        perror("Interface") ;
        exit(1) ;
    } // if 

    // ----------------發送端socket設定(timeout, 主動編寫IPheader)-----------------
    int sock_send ; 
    if ( ( sock_send = socket( PF_INET, SOCK_RAW, IPPROTO_ICMP ) ) < 0) {
        // AF_INET只能看到IP層以上的東西，而AF_PACKET可以看到link層(ethernet)的信息
        perror( "socket" ) ;
        exit(1);
    } // if

    // !!!!!!此步非常重要, IP header為自定!!!!!!!!!
    int optval = 1 ;
	if( setsockopt( sock_send, IPPROTO_IP, IP_HDRINCL, &optval, sizeof( optval ) ) < 0 ) {
        // IP_HDRINCL: 主動編寫IP Header
        // optval: 指標，指向存放所獲得選項值的緩衝區，不可為0!!!!
		perror( "setsockopt" ) ;
		exit(1) ;
	} // if 

    for ( int i = 1 ; i < 255 ; i++ ) {
        // ----------------目的地socket設定(Destination_IP)-----------------
        struct sockaddr_in dst_socket ; // 目的地socket資訊
        bzero( &dst_socket, sizeof(dst_socket) ) ; 
        dst_socket.sin_family = PF_INET ; // Internet type

        char Hostid[10] ;
        struct in_addr dst ;
        sprintf( Hostid, "%d", i ) ; // 迴圈參數作為HostID
        char Dstip[20] = "140.117.171." ; // Subnet
        strcat( Dstip, Hostid ) ; // Subnet = "140.117.171." 
        inet_pton( AF_INET, Dstip,  &dst_socket.sin_addr.s_addr ) ; // IP: string to uint32_t

        // ----------------設定Packet(struct myicmp)-----------------
        myicmp *sendpacket = (myicmp*)malloc( PACKET_SIZE ) ;
        Set_packet( sendpacket, Dstip, i ) ;
    
        // ----------------Send-----------------
        t1 = clock();
        if ( sendto( sock_send, sendpacket, PACKET_SIZE, 0, (struct sockaddr *) &dst_socket, sizeof( dst_socket ) ) < 0 ) {
            // !!!!不存在的IP無法成功發送封包, 推測是arp無法找尋到目標mac, 但sendto並不會報錯QQ。!!!!
            // ip存在但沒收到回應, sendto可能會重送封包
            perror( "sendto error" ) ;
            exit(-1) ;
        } // if
        else { 
            printf( "PING %s(data size = 11, id=0x%x, seq = %d , timeout = %d ms)\n", 
                    Dstip, sendpacket->icmp_hdr.un.echo.id, i, time_ms ) ;
        } // else 

        // ----------------Receive-----------------
        int sock_recv = sock_send ; // 接收的格式一樣
        recv_icmp( sock_recv, timeout, Dstip, i ) ; // i 是sequence number
    
    } // for

    return 0 ;
} // main
