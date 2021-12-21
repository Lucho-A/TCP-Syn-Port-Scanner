/*
 ============================================================================
 Name        : TCP Syn Port Scanner.h
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Header file
 ============================================================================
*/

#ifndef HEADERS_TCP_SYN_PORT_SCANNER_H_
#define HEADERS_TCP_SYN_PORT_SCANNER_H_

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<errno.h>
#include<pthread.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<time.h>
#include<unistd.h>
#include<fcntl.h>
#include<curl/curl.h>
#include<sys/types.h>
#include<ctype.h>
#include<libcli.h>
#include <mysql/mysql.h>

#pragma GCC diagnostic ignored "-Wformat-truncation"

#define RETURN_ERROR 0
#define RETURN_OK 1

#define TRUE 1
#define FALSE 0

#define C_RED "\e[0;31m"
#define C_HRED "\e[0;91m"
#define C_HGREEN "\e[0;92m"
#define C_GREEN "\e[0;32m"
#define C_HBLUE "\e[0;94m"
#define C_HYELLOW "\e[0;93m"
#define C_BLUE "\e[0;34m"
#define C_CYAN "\e[0;36m"
#define C_WHITE "\e[0;37m"
#define C_DEFAULT "\e[0m"

#define CANT_PORTS 5000
#define PACKET_FORWARDING_LIMIT 5
#define BUFFER_RECV_MSG 10240
#define BRUTE_FORCE_DELAY 100000
#define BRUTE_FORCE_TIMEOUT 3
#define SECS_WAIT_BEFORE_CONTINUE_SCAN 5
#define PORT_FILTERED 0
#define PORT_OPENED 1
#define PORT_CLOSED 2
#define HEADER_GRABBING 1
#define SOCKET_GRABBING 2
#define METHODS_ALLOWED_GRABBING 3
#define SERVER_RESP_SPOOFED_HEADERS 4
#define GET_WEBPAGES 5
#define PATH_TO_RESOURCES "/home/lucho/git/TCP-Syn-Port-Scanner-Minimal/TCP-Syn-Port-Scanner-Minimal/Resources/"

#define USERNAMES 3
#define PASSWORDS 3

struct pseudo_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

typedef struct message{
	char descrip[128];
	char msg[128];
}Message;

struct in_addr dest_ip;

//int hack_port_53(in_addr_t ip, int port,int scanType);
int system_call(void);
int interactive_mode(in_addr_t ip, int port);
int hack_mysql(in_addr_t ip, int port);
int hack_web(in_addr_t ip, int port, int type);
int hack_ftp(in_addr_t ip, int port);
int hack_ssh(in_addr_t ip, int port);
int hack_telnet(in_addr_t ip, int port);
int hack_port(in_addr_t ip, int port);
int port_grabbing(in_addr_t ip, int port,int type);
void cert_grabbing(in_addr_t ip, int port, char *protocol);
void show_options(int port);
int open_file(char *fileName, FILE **f);
void show_error(char *errMsg, int errnum);
void * receive_ack( void *ptr );
void process_packet(unsigned char* , int);
unsigned short csum(unsigned short * , int );
char * hostname_to_ip(char * );
void get_local_ip (char *);
int start_sniffer();

#endif /* HEADERS_TCP_SYN_PORT_SCANNER_H_ */
