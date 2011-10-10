/*
 * Host Identity Protocol
 * Copyright (C) 2002-04 the Boeing Company
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
 *  hip_service.h
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * Definition of HIP Windows service thread functions.
 *
 */
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
#else
#include <sys/socket.h>	/* struct sockaddr */
#endif

/*
 * Globally-accessible functions
 */
/* Windows _beghinthread() uses different type than pthread_create() */
#ifdef __WIN32__
void hip_esp_output(void *arg);
void hip_esp_input(void *arg);
void tunreader(void *arg);
void hip_dns(void *arg);
void hipd_main(void *arg);
void hip_netlink(void *arg);
void hip_status(void *arg);
extern int socketpair(int, int, int, int sv[2]);
#define RETNULL ;
#else
void *hip_esp_output(void *arg);
void *hip_esp_input(void *arg);
void *tunreader(void *arg);
void *hip_dns(void *arg);
void *hipd_main(void *arg);
void *hip_netlink(void *arg);
void *hip_status(void *arg);
#define RETNULL NULL;
#endif

extern void hip_sleep(int seconds);

/*
 * Global definitions
 */
#ifdef __MACOSX__
#include <mac/mac_types.h>
#else
#ifndef __WIN32__
#include <asm/types.h>
#endif
#endif

#ifndef CONFIG_HIP
#define CONFIG_HIP
#endif

#define DNS_PORT 53
#define HIP_DNS_SUFFIX ".hip"
extern __u64 g_tap_mac;
extern int g_state;

#define KEEPALIVE_TIMEOUT 20

/* from linux/include/linux/kernel.h */
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])

#define TRUE 1
#define FALSE 0

