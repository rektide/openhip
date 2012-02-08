/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2002-2012 the Boeing Company
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *  \file  hip_usermode.h
 *
 *  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Definition of usermode thread functions.
 *
 */

#ifndef _HIP_USERMODE_H_
#define _HIP_USERMODE_H_

#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h> /* struct sockaddr */
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
void hip_mobile_router(void *arg);
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
void *hip_mobile_router(void *arg);
#define RETNULL NULL;
#endif

int init_esp_input(int family, int type, int proto, int port, char *msg);
int main_loop(int argc, char **argv);
int str_to_addr(unsigned char *data, struct sockaddr *addr);

/*
 * Global definitions
 */
#ifndef CONFIG_HIP
#define CONFIG_HIP
#endif

#ifdef HIP_VPLS
#define HIP_TAP_INTERFACE_MTU 1500
#else
#define HIP_TAP_INTERFACE_MTU 1400
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
#define SA2IP(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? \
  (void*)&((struct sockaddr_in*)x)->sin_addr : \
  (void*)&((struct sockaddr_in6*)x)->sin6_addr
/* get socket address length in bytes */
#define SALEN(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)
/* get IP address length in bytes */
#define SAIPLEN(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? 4 : 16
#endif
#define IS_LSI32(a) ((a & htonl(0xFF000000)) == htonl(0x01000000))


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

/*
 * Local data types
 */
struct ip_esp_hdr {
  __u32 spi;
  __u32 seq_no;
  __u8 enc_data[0];
};

struct ip_esp_padinfo {
  __u8 pad_length;
  __u8 next_hdr;
};

struct eth_hdr {
  __u8 dst[6];
  __u8 src[6];
  __u16 type;
} __attribute__((packed));

/* ARP header - RFC 826, STD 37 */
/*
 * Make our own ARP header struct, so we can add the
 * 'packed' attribute
 */
struct arp_hdr {
  __u16 ar_hrd;
  __u16 ar_pro;
  __u8 ar_hln;
  __u8 ar_pln;
  __u16 ar_op;
} __attribute__((packed));

/*
 * Make our own ARP data struct, so we can add the
 * 'packed' attribute
 */

struct arp_req_data {
  __u8 src_mac[6];
  __u32 src_ip;
  __u8 dst_mac[6];
  __u32 dst_ip;
} __attribute__((packed));

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

#endif
