/*
 ============================================================================
 Name        : TCP Syn Port Scanner.c
 Author      : L.
 Version     : 1.0.7
 Copyright   : GNU General Public License v3.0
 Description : TCP Syn Port Scanner developed in C, Ansi-style
 ============================================================================
 */

#include <TCP_Syn_Port_Scanner.h>

int contClosedPorts=0;
int contOpenedPorts=0;
int cantPortsToScan=0;
struct port *portsToScan=NULL;
int endProcess=FALSE;

int main(int argc, char *argv[]){
	system("clear");
	printf("%s",CYAN);
	printf("\n***********************************************************************************************************************************************************************\n");
	printf("* %sTCP Syn Port Scanner v%s by L.",HCYAN, VERSION);
	printf("\n*%s", CYAN);
	printf("\n* For a complete cybersecurity framework, as well, for others systems/plattforms assessments (Cybersecurity, Oracle, AIX, SAP HANA, among others), pls, contact me!");
	printf("\n*");
	printf("\n* Email: luis.alfie@gmail.com");
	printf("\n***********************************************************************************************************************************************************************");
	printf("%s",DEFAULT);
	if(getuid()!=0){
		show_error("\n\nYou must be root for running the program.\n\n",0);
		exit(EXIT_FAILURE);
	}
	char target[500]="", errorMsg[50]="";
	int argOK=FALSE;
	for(int i=1;i<argc;i++){
		if(strcmp(argv[1],"-h")==0) break;
		if(i==1){
			snprintf(target,sizeof(target),"%s",argv[i]);
			continue;
		}
		if(i==2){
			if(strtol(argv[2],NULL,10)>0 && strtol(argv[2],NULL,10)<5001){
				cantPortsToScan=strtol(argv[2],NULL,10);
				argOK=TRUE;
				continue;
			}
			snprintf(errorMsg,sizeof(errorMsg),"\n\nYou must enter a valid number (1-5000)");
			show_error(errorMsg, 0);
			argOK=FALSE;
			break;
		}
		snprintf(errorMsg,sizeof(errorMsg),"\n\nArgument %s not recognized", argv[i]);
		show_error(errorMsg, 0);
		argOK=FALSE;
		break;
	}
	if(!argOK){
		printf("%s",WHITE);
		printf("\n\nUsage (as root): 'TCP-Syn-Port-Scanner' ip|url cantPortToScan (1-5000) -h\n\n");
		printf("Options:\n");
		printf("-h: Show this.\n\n");
		printf("v.gr: sudo ./TCP-Syn-Port-Scanner scanme.org 500\n\n");
		exit(EXIT_FAILURE);
	}
	FILE *f=NULL;
	if((f=fopen(PATH_TO_RESOURCES "Ports.txt","r"))==NULL){
		show_error("Error opening Ports.txt", errno);
		exit(EXIT_FAILURE);
	}
	portsToScan= (struct port *) malloc(sizeof(struct port)*cantPortsToScan);
	for(int i=0;i<cantPortsToScan;i++){
		fscanf(f,"%d,",&portsToScan[i].portNumber);
		portsToScan[i].portStatus=PORT_FILTERED;
		struct servent *service_resp = getservbyport(ntohs(portsToScan[i].portNumber), "tcp");
		(service_resp==NULL)?(strcpy(portsToScan[i].ianaService,"???")):(strcpy(portsToScan[i].ianaService, service_resp->s_name));
	}
	struct timespec tInit, tEnd;
	clock_gettime(CLOCK_REALTIME, &tInit);
	time_t timestamp = time(NULL);
	struct tm tm = *localtime(&timestamp);
	printf("%s",WHITE);
	printf("\n\nStarting TCP Syn Port Scanning... (%d/%02d/%02d %02d:%02d:%02d UTC:%s)\n\n",tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,tm.tm_zone);
	printf("%s",DEFAULT);
	char *ip=hostname_to_ip(target);
	if(inet_addr(target)!=-1){
		printf("No need to resolve the URL (%s%s)\n\n",HWHITE,target);
		dest_ip.s_addr = inet_addr(target);
	}else{
		if(ip==NULL){
			printf("Unable to resolve the URL: %s%s\n\n",HWHITE, target);
			exit(EXIT_FAILURE);
		}
		printf("URL (%s) resolved to: %s%s\n\n" , target ,HWHITE, ip);
		dest_ip.s_addr = inet_addr( hostname_to_ip(target) );
	}
	printf("%s",DEFAULT);
	char hostname[128]="";
	ip_to_hostname(ip, hostname);
	printf("Hostname: %s%s%s \n",HWHITE,hostname,DEFAULT);
	int sk=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(sk<0){
		show_error("Error creating socket.", errno);
		exit(EXIT_FAILURE);
	}
	char datagram[4096];
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in dest;
	struct pseudo_header psh;
	int source_port = 65432;
	char source_ip[20];
	get_local_ip(source_ip);
	printf("\n%sLocal source IP is %s%s \n\n",DEFAULT, HWHITE,source_ip);
	memset(datagram,0,4096);
	//IP Header init
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons(54321);
	iph->frag_off = htons(16384);
	iph->ttl = 255; //spoofed
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = dest_ip.s_addr;
	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
	//TCP Header init
	tcph->source = htons(source_port);
	tcph->dest = htons(80);
	tcph->seq = htonl(1234567890);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr)/4;
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons(65535);
	tcph->check = 0;
	tcph->urg_ptr = 0;
	int one = 1;
	const int *val = &one;
	if (setsockopt (sk, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
		show_error("Error setting socket options.", errno);
		exit(EXIT_FAILURE);
	}
	char *threadMsg = "Reading packets thread";
	pthread_t reading_packets_thread;
	if(pthread_create(&reading_packets_thread,NULL,start_reading_packets,(void*) threadMsg)<0){
		show_error("Error creating thread.",errno);
		exit(EXIT_FAILURE);
	}
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	int contFilteredPortsChange=-1, endSendPackets=0, contFilteredPorts=0;
	while(endSendPackets!=PACKET_FORWARDING_LIMIT){
		for(int i=0;i<cantPortsToScan;i++){
			if(portsToScan[i].portStatus==PORT_FILTERED){
				contFilteredPorts++;
				tcph->dest=htons(portsToScan[i].portNumber);
				tcph->check=0;
				psh.source_address=inet_addr(source_ip);
				psh.dest_address=dest.sin_addr.s_addr;
				psh.placeholder=0;
				psh.protocol=IPPROTO_TCP;
				psh.tcp_length=htons(sizeof(struct tcphdr));
				memcpy(&psh.tcp,tcph,sizeof(struct tcphdr));
				tcph->check=csum((unsigned short*) &psh,sizeof(struct pseudo_header));
				if(sendto(sk,datagram,sizeof(struct iphdr)+sizeof(struct tcphdr),0,(struct sockaddr *) &dest,sizeof (dest))<0){
					show_error("Error sending syn packet.", errno);
					exit(EXIT_FAILURE);
				}
			}
		}
		usleep(SEND_PACKETS_DELAY);
		(contFilteredPortsChange==contFilteredPorts)?(endSendPackets++):(endSendPackets=0);
		contFilteredPortsChange=contFilteredPorts;
		contFilteredPorts=0;
	}
	endProcess=TRUE;
	contFilteredPorts=cantPortsToScan-contOpenedPorts-contClosedPorts;
	for(int i=0;i<cantPortsToScan;i++){
		if(portsToScan[i].portStatus==PORT_OPENED){
			printf("%s",HRED);
			printf("Port %d \topened \t\t(%s)\n",portsToScan[i].portNumber, portsToScan[i].ianaService);
		}
		if(portsToScan[i].portStatus==PORT_FILTERED){
			printf("%s",HYELLOW);
			if(contFilteredPorts<MAX_SHOW_PORTS) printf("Port %d \tfiltered \t(%s)\n",portsToScan[i].portNumber, portsToScan[i].ianaService);
		}
		if(portsToScan[i].portStatus==PORT_CLOSED){
			printf("%s",HGREEN);
			if(contClosedPorts<MAX_SHOW_PORTS) printf("Port %d \tclosed \t\t(%s)\n",portsToScan[i].portNumber, portsToScan[i].ianaService);
		}
	}
	clock_gettime(CLOCK_REALTIME, &tEnd);
	double elapsedTime=(tEnd.tv_sec-tInit.tv_sec) + (tEnd.tv_nsec-tInit.tv_nsec) / 1000000000.0;
	printf("%s",DEFAULT);
	printf("\nThe identified service names are the IANA standards ones and could differ in practice.\n");
	printf("\nScanned ports: %d in %.3lf secs\n\n",cantPortsToScan, elapsedTime);
	printf("%s",HGREEN);
	printf("\tClosed: %d\n", contClosedPorts);
	printf("%s",HYELLOW);
	printf("\tFiltered: %d\n",contFilteredPorts);
	printf("%s",HRED);
	printf("\tOpened: %d\n\n",contOpenedPorts);
	printf("%s",DEFAULT);
	return EXIT_SUCCESS;
}

void * start_reading_packets( void *ptr ){
	reading_packets();
	return (void*)&RETURN_THREAD_OK;
}

int reading_packets(){
	int sock_raw, data_size;
	socklen_t saddr_size;
	struct sockaddr saddr;
	unsigned char *buffer=(unsigned char *)malloc(65536);
	sock_raw = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
	if(sock_raw < 0){
		show_error("Error creating socket.", errno);
		exit(EXIT_FAILURE);
	}
	saddr_size = sizeof saddr;
	while(endProcess==FALSE){
		data_size=recvfrom(sock_raw,buffer,65536,0,&saddr,&saddr_size);
		if(data_size<0){
			show_error("Error reciving packets.", errno);
			exit(EXIT_FAILURE);
		}
		if(data_size>0)	process_packets(buffer, data_size);
	}
	close(sock_raw);
	return RETURN_OK;
}

void process_packets(unsigned char* buffer, int size){
	struct iphdr *iph=(struct iphdr*)buffer;
	struct sockaddr_in source,dest;
	unsigned short iphdrlen;
	if(iph->protocol==6){
		struct iphdr *iph=(struct iphdr *)buffer;
		iphdrlen=iph->ihl*4;
		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
		memset(&source,0,sizeof(source));
		source.sin_addr.s_addr=iph->saddr;
		memset(&dest,0,sizeof(dest));
		dest.sin_addr.s_addr=iph->daddr;
		for(int i=0;i<cantPortsToScan;i++){
			if(portsToScan[i].portNumber==ntohs(tcph->source) && source.sin_addr.s_addr==dest_ip.s_addr && portsToScan[i].portStatus==PORT_FILTERED){
				if(tcph->syn==1 && tcph->ack==1 ){
					portsToScan[i].portStatus=PORT_OPENED;
					contOpenedPorts++;
					break;
				}
				if(tcph->rst==1){
					portsToScan[i].portStatus=PORT_CLOSED;
					contClosedPorts++;
					break;
				}
				break;
			}
		}
	}
}

void ip_to_hostname(char *ip, char *hostname){
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &sa.sin_addr);
	char host[1024], service[20];
	int resp=getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof host, service, sizeof service, 0);
	(!resp)?(snprintf(hostname,sizeof(host),"%s",host)):(snprintf(hostname,sizeof(host),"%s",""));
}

char* hostname_to_ip(char * hostname){
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
	if((he=gethostbyname(hostname))==NULL) return NULL;
	addr_list=(struct in_addr **) he->h_addr_list;
	for(i=0;addr_list[i]!=NULL;i++) return inet_ntoa(*addr_list[i]);
	return NULL;
}

void get_local_ip(char * buffer){
	int sk=socket(AF_INET,SOCK_DGRAM,0);
	const char* kGoogleDnsIp="8.8.8.8";
	int dns_port=53;
	struct sockaddr_in serv;
	memset(&serv,0,sizeof(serv));
	serv.sin_family=AF_INET;
	serv.sin_addr.s_addr=inet_addr(kGoogleDnsIp);
	serv.sin_port=htons(dns_port);
	int resp=connect(sk,(const struct sockaddr*) &serv,sizeof(serv));
	if(resp!=0){
		show_error("Error connecting socket.", errno);
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in name;
	socklen_t namelen=sizeof(name);
	resp=getsockname(sk,(struct sockaddr*) &name, &namelen);
	if(resp!=0){
		show_error("Error getting socket name.",errno);
		exit(EXIT_FAILURE);
	}
	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
	if(p==NULL){
		show_error("Error converting Internet address.",errno);
		exit(EXIT_FAILURE);
	}
	close(sk);
}

unsigned short csum(unsigned short *ptr,int nbytes){
	register long sum;
	unsigned short oddbyte;
	register short r;
	sum=0;
	while(nbytes>1){
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1){
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
	sum=(sum>>16)+(sum & 0xffff);
	sum=sum+(sum>>16);
	r=(short)~sum;
	return(r);
}

void show_error(char *errMsg, int errnum){
	printf("%s",HRED);
	(errnum==0)?(printf("%s", errMsg)):(printf("%s Error %d (%s)\n", errMsg, errnum, strerror(errnum)));
	printf("%s",DEFAULT);
}









































