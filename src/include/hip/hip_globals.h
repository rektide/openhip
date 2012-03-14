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
 *  \file  hip_globals.h
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Global variable definitions.
 *
 */
#ifndef _HIP_GLOBALS_H_
#define _HIP_GLOBALS_H_

#include <openssl/dsa.h>        /* DSA support                  */
#include <openssl/dh.h>         /* Diffie-Hellman contexts      */
#include <math.h>               /* for exponential macros (reg life) */
#include <hip/hip_types.h>

/* global variables */

/* Array storing HIP association structs (this is the state machine state) */
extern hip_assoc hip_assoc_table[MAX_CONNECTIONS];
extern int max_hip_assoc;
extern const hip_hit zero_hit;

/* Linked list of my host identities */
extern hi_node *my_hi_head;

/* Linked list of my addresses */
extern sockaddr_list *my_addr_head;

/* Linked list of peer host identities */
extern hi_node *peer_hi_head;

/* Linked list of Diffie-Hellman contexts */
extern dh_cache_entry *dh_cache;

/* Diffie-Hellman constants */
extern const unsigned char *dhprime[DH_MAX];
extern const int dhprime_len[DH_MAX]; /* only used by new_dh_cache_entry()
                                       *    use DH_size() elsewhere */
extern unsigned char dhgen[DH_MAX];


extern int s_hip; /* RAW socket handle */
#undef s_net
extern int s_net; /* netlink socket */
extern int s6_hip; /* RAW IPv6 socket handle */
extern int s_stat; /* status socket */

/* Global options */
extern struct hip_opt OPT;

/* Global configuration data */
extern struct hip_conf HCNF;

extern int espsp[2]; /* ESP thread socket pair */
extern int g_state;
#ifdef __WIN32__
extern int netlsp[2];
#endif

const unsigned char khi_context_id[16];

#endif
