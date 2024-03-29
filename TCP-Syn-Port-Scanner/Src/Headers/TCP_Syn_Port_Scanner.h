/*
 ============================================================================
 Name        : TCP Syn Port Scanner.h
 Author      : L.
 Version     : 1.0.7
 Copyright   : GNU General Public License v3.0
 Description : Header file
 ============================================================================
*/

#ifndef HEADERS_TCP_SYN_PORT_SCANNER_H_
#define HEADERS_TCP_SYN_PORT_SCANNER_H_

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include<errno.h>
#include<pthread.h>
#include<netdb.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include<time.h>

#define VERSION 				"1.0.7"
#define RETURN_ERROR 			-1
#define RETURN_OK 				0
#define TRUE 					1
#define FALSE 					0
#define HRED 					"\e[0;91m"
#define RED 					"\e[0;31m"
#define HGREEN 					"\e[0;92m"
#define HYELLOW 				"\e[0;93m"
#define CYAN 					"\e[0;36m"
#define HCYAN 					"\e[0;96m"
#define WHITE 					"\e[0;37m"
#define GREEN 					"\e[0;32m"
#define HWHITE 					"\e[0;97m"
#define DEFAULT 				"\e[0m"
#define MAX_CANT_PORTS 			5000
#define MAX_SHOW_PORTS 			15
#define PACKET_FORWARDING_LIMIT 3
#define SEND_PACKETS_DELAY		200000
#define PATH_TO_RESOURCES 		"/home/lucho/git/TCP-Syn-Port-Scanner/TCP-Syn-Port-Scanner/Resources/"

enum portStatus{
	PORT_FILTERED=0,
	PORT_OPENED,
	PORT_CLOSED
};

static const long RETURN_THREAD_OK;

struct port{
	int portNumber;
	int portStatus;
	char ianaService[50];
};

struct pseudo_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

struct in_addr dest_ip;

void show_error(char *, int);
void *start_reading_packets(void *);
int reading_packets();
void process_packets(unsigned char*,int);
void get_local_ip (char *);
unsigned short csum(unsigned short *,int );
void ip_to_hostname(char *, char *);
void hostname_to_ip(char *, char **);

#endif /* HEADERS_TCP_SYN_PORT_SCANNER_H_ */
