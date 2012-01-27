/*
 * Host Identity Protocol
 * Copyright (C) 2002-05 the Boeing Company
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
 *  hip_globals.h
 *
 *  Author:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *
 */
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

/* smartcard signing */
extern RSA *sc_rsa;
extern DSA *sc_dsa;
