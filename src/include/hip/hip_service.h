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
 *  \file  hip_service.h
 *
 *  \authors Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Definition of HIP Windows service thread functions.
 *
 */
#ifndef _HIP_SERVICE_H_
#define _HIP_SERVICE_H_

#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
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

#endif
