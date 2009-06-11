/*
 * Host Identity Protocol
 * Copyright (C) 2002-06 the Boeing Company
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  hip_umh_main.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *           Tom Henderson <thomas.r.henderson@boeing.com>
 * 
 * User-mode preparation for main_loop() and other functions that are common
 * to both Linux and win32 user-mode versions.
 *
 */

/*
 * Style:  KNF where possible, K&R style braces around control structures
 * Style:  indent using tabs-- multi-line continuation 4 spaces
 * Style:  no tabs in middle of lines
 * Style:  this code authored with tabstop=8
 */

#include <stdio.h>           /* stderr, etc                  */
#include <string.h>          /* memset()                     */
#include <time.h>            /* time()                       */
#ifdef __WIN32__
#include <win32/types.h>
#include <process.h>
#include <io.h>
#else
#include <sys/socket.h>      /* sock(), recvmsg(), etc       */
#include <sys/time.h>        /* gettimeofday()               */
#include <unistd.h>          /* fork(), getpid()             */
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#endif
#include <sys/types.h>       /* getpid() support, etc        */
#include <hip/hip_types.h>
#include <hip/hip_usermode.h>
#include <hip/hip_globals.h> /* g_state */
#include <hip/hip_funcs.h>

#ifdef __WIN32__
void hipd_main(void *args)
#else
void *hipd_main(void *args)
#endif
{
	char *argv[10];
	char *strargs;
	int argc, err;

	/* Convert the single void *args containing a string of program
	 * arguments into the standard argc with argv array. 
	 * Must be NULL-terminated, with arguments separated by a space. */
	memset(argv, 0, sizeof(argv));
	argc = 1;
	if (args) {
		strargs = (char *) args;
		argv[argc] = strargs;
		if (*strargs != '\0') {
			argc++;
			strargs++;
		}
		/* scan string until NULL */
		while(*strargs != '\0') {
			if (*strargs == ' ') {
				*strargs = '\0'; /* split into substrings by
						    adding NULL */
				strargs++; /* point to next item */
				argv[argc] = strargs;
				argc++;
				if (argc==10) /* stop at end of array */
					break;
			}
			strargs++;
		}
	}
	err = main_loop(argc, argv);
	if (err == -EINTR) { 
		/* wait for signal handler shutdown,
		 * otherwise program will hang */
		while (g_state==0)
#ifdef __WIN32__
			Sleep(1000);
	}
	return;
#else
			sleep(1);
	}
	pthread_exit((void *) 0);
	return(NULL);
#endif
}

/*
 * init_esp_input()
 *
 * Open and bind an ESP socket.
 */


int init_esp_input(int family, int proto)
{
	int s, err;
	struct sockaddr *local_addr;
	struct sockaddr_storage local_addr_s;
	local_addr = (struct sockaddr*) &local_addr_s;

	if ((family != AF_INET) && (family != AF_INET6))
		return(-1);
#ifdef __MACOSX__
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT)) < 0) {
		printf("init_esp_input(): socket() error\n");
		printf("error: (%d) %s\n", errno, strerror(errno));
		return(-1);
	}
#else
	if ((s = socket(family, SOCK_RAW, proto)) < 0) {
		printf("init_esp_input(): %s socket() error\n"
		       "error: (%d) %s\n", (proto==IPPROTO_UDP) ? "UDP" : "ESP",
		       errno, strerror(errno));
		return(-1);
	}
#endif
	memset(local_addr, 0, sizeof(struct sockaddr_storage));
#ifdef __MACOSX__
        ((struct sockaddr_in*)local_addr)->sin_family= AF_INET;
	/* XXX where does this 5150 come from? */
        ((struct sockaddr_in*)local_addr)->sin_port = htons(5150);
        ((struct sockaddr_in*)local_addr)->sin_addr.s_addr = 0;
#else
	local_addr->sa_family = family;
	if (family == AF_INET) {
		((struct sockaddr_in*)local_addr)->sin_port = \
			(proto==IPPROTO_UDP) ? htons(HIP_UDP_PORT) : 0;
		((struct sockaddr_in*)local_addr)->sin_addr.s_addr = INADDR_ANY;
	} else {
		str_to_addr((__u8*)"0::0", local_addr);
	}
#endif	
	/* XXX shouldn't this bind() to port 50500 only for UDP ?? */
	if ((err = bind(s, local_addr, SALEN(local_addr))) < 0) {
		/* XXX this is broken for IPv6; bind() doesn't accept
		 *     protocol 50, when using winsock2 or cygwin!
		 */
/*		if (family == AF_INET) { */
			printf("init_esp_input(): bind() error\n");
			printf("error: (%d) %s\n", errno, strerror(errno));
			return(-1);
/*		}*/
	}
	
	return(s);
}

