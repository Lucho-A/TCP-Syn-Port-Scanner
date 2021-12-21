/*
 ============================================================================
 Name        : Hack_Ssh.c
 Author      : L.
 Version     : 1.0.5
 Copyright   : GNU General Public License v3.0
 Description : Hack SSH
 ============================================================================
 */

#include "TCP_Syn_Port_Scanner_Minimal.h"

#define LIBSSH2_INIT_NO_CRYPTO 0x0001

int hack_ssh(in_addr_t ip, int port){
	show_error("Not implemented in this (minimal) version.", 0);
	return RETURN_OK;
}
