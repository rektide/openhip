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
void hip_pfkey(void *arg);
void tunreader(void *arg);
void hip_dns(void *arg);
void hipd_main(void *arg);
void hip_netlink(void *arg);
void hip_status(void *arg);
void hip_mobile_router(void *arg);
extern int socketpair(int, int, int, int sv[2]);
#define RETNULL ;
#else
void *hip_esp_output(void *arg);
void *hip_esp_input(void *arg);
void *hip_pfkey(void *arg);
void *tunreader(void *arg);
void *hip_dns(void *arg);
void *hipd_main(void *arg);
void *hip_netlink(void *arg);
void *hip_status(void *arg);
void *hip_mobile_router(void *arg);
#define RETNULL NULL;
#endif

int init_esp_input(int family, int proto);
int main_loop(int argc, char **argv);
int str_to_addr(unsigned char *data, struct sockaddr *addr);

int pfkey_send_acquire(struct sockaddr *target);

/*
 * Global definitions
 */
#ifndef CONFIG_HIP
#define CONFIG_HIP
#endif

#define DNS_PORT 53
#define HIP_DNS_SUFFIX ".hip"
extern __u64 g_tap_mac;
extern int g_state;

/*
 * Macros from hip.h and elsewhere
 */
#if 0
/* get pointer to IP from a sockaddr 
 *    useful for inet_ntop calls     */
#define SA2IP(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? \
	(void*)&((struct sockaddr_in*)x)->sin_addr : \
	(void*)&((struct sockaddr_in6*)x)->sin6_addr
/* get socket address length in bytes */
#define SALEN(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? \
	sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)
/* get IP address length in bytes */
#define SAIPLEN(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? 4 : 16
#endif
#define IS_LSI32(a) ((a & 0xFF) == 0x01)

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

