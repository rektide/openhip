/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2005-2012 the Boeing Company
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
 *  \file  hip_sadb.h
 *
 *  \authors Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Definitions for the HIP Security Association database.
 *
 */

#ifndef _HIP_SADB_H_
#define _HIP_SADB_H_

#ifdef __MACOSX__
#include <sys/types.h>
#include <mac/mac_types.h>
#else
#ifdef __WIN32__
#include <win32/types.h>
#else
#include <asm/types.h>          /* __u16, __u32, etc */
#endif /* __WIN32__ */
#endif
#include <sys/types.h>          /* for socket.h */
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>         /* struct sockaddr */
#include <netinet/in.h>         /* struct sockaddr_in */
#endif /* __WIN32__ */
#include <openssl/des.h>        /* des_key_schedule */
#include <openssl/aes.h>        /* aes_key */
#include <openssl/blowfish.h>   /* bf_key */

/*
 * Algorithms
 */
#define SADB_AALG_NONE                  0
#define SADB_AALG_MD5HMAC               2
#define SADB_AALG_SHA1HMAC              3
#define SADB_X_AALG_SHA2_256HMAC        5
#define SADB_X_AALG_SHA2_384HMAC        6
#define SADB_X_AALG_SHA2_512HMAC        7
#define SADB_X_AALG_RIPEMD160HMAC       8
#define SADB_X_AALG_NULL                251

#define SADB_EALG_NONE                  0
#define SADB_EALG_DESCBC                2
#define SADB_EALG_3DESCBC               3
#define SADB_X_EALG_CASTCBC             6
#define SADB_X_EALG_BLOWFISHCBC         7
#define SADB_EALG_NULL                  11
#define SADB_X_EALG_AESCBC              12
#define SADB_X_EALG_SERPENTCBC          252
#define SADB_X_EALG_TWOFISHCBC          253


/*
 * definitions
 */
#define SADB_SIZE 512
#define LSI4(a) (((struct sockaddr_in*)a)->sin_addr.s_addr)
#define ESP_SEQNO_MAX (0xFFFFFFFF - 0x20)
#define check_esp_seqno_overflow(e) e && (e->sequence_hi == 0xFFFFFFFF) && \
  (e->sequence >= ESP_SEQNO_MAX)

/*
 * HIP Security Association entry
 *
 * Note that this is different than the hip_assoc/hip_assoc_table[] used by
 * the main hipd thread. The SADB is used primarily by the ESP input/output
 * threads (the data plane).
 */
typedef struct _hip_sadb_entry
{
  struct _hip_sadb_entry *next;
  __u32 spi;                            /* primary index into SADB */
  __u32 spinat;                         /* spinat for mobile router */
  __u32 mode;           /* ESP mode :  0-default 1-transport 2-tunnel 3-beet */
  int direction;                        /* 1-in/2-out */
  __u16 hit_magic;                      /* for quick checksum calculation */
  sockaddr_list *src_addrs;             /* source addresses             */
  sockaddr_list *dst_addrs;             /* destination addresses        */
  struct sockaddr_storage src_hit;       /* source HIT */
  struct sockaddr_storage dst_hit;       /* destination HIT */
  struct sockaddr_storage lsi;          /* peer's IPv4 1.x.x.x LSI */
  __u32 a_type;                         /* crypto parameters            */
  __u32 e_type;
  __u32 a_keylen;
  __u32 e_keylen;
  __u8 *a_key;                          /* raw crypto keys */
  __u8 *e_key;
  __u64 lifetime;                       /* seconds until expiration */
  struct timeval exptime;               /* expiration timestamp */
  __u64 bytes;                          /* bytes tx/rx */
  __u32 packets;                        /* number of packets tx/rx*/
  __u32 lost;                           /* number of packets lost */
  __u32 dropped;                        /* number of packets dropped */
  struct timeval usetime;               /* last used timestamp */
  __u32 sequence;                       /* outgoing or highest received seq no*/
  __u32 sequence_hi;                    /* high-order bits of 64-bit ESN */
  __u64 replay_win_max;                 /* right side of received window */
  __u64 replay_win_map;                 /* anti-replay bitmap */
  char iv[8];
  des_key_schedule ks[3];               /* 3-DES keys */
  AES_KEY *aes_key;                     /* AES key */
  BF_KEY *bf_key;                       /* BLOWFISH key */
  hip_mutex_t rw_lock;
} hip_sadb_entry;

/* HIP SADB desintation cache entry */
typedef struct _hip_sadb_dst_entry
{
  struct _hip_sadb_dst_entry *next;
  struct sockaddr_storage addr;
  hip_sadb_entry *sadb_entry;
  hip_mutex_t rw_lock;
} hip_sadb_dst_entry;

/* HIP LSI table entry */
#define LSI_PKT_BUFFER_SIZE 2000
/* number of seconds to keep LSI entries */
#define LSI_ENTRY_LIFETIME 120
typedef struct _hip_lsi_entry
{
  struct _hip_lsi_entry *next;
  struct sockaddr_storage addr;
  struct sockaddr_storage lsi4;
  struct sockaddr_storage lsi6;
  __u8 packet_buffer[LSI_PKT_BUFFER_SIZE];
  int num_packets;
  int next_packet;
  int send_packets;
  struct timeval creation_time;
} hip_lsi_entry;
/* protocol selector entry */
#define PROTO_SEL_SIZE 512
#define PROTO_SEL_ENTRY_LIFETIME 900
#define PROTO_SEL_DEFAULT_FAMILY AF_INET
#define hip_proto_sel_hash(a) (a % PROTO_SEL_SIZE)
typedef struct _hip_proto_sel_entry
{
  struct _hip_proto_sel_entry *next;
  __u32 selector;               /* upper layer protocol-specific selector */
  int family;                   /* guidance on which address family to use */
  struct timeval last_used;
} hip_proto_sel_entry;


/*
 * functions
 */
void hip_sadb_init();
void hip_sadb_deinit();
int hip_sadb_add(__u32 mode, int direction,
                 struct sockaddr *src_hit, struct sockaddr *dst_hit,
                 struct sockaddr *src, struct sockaddr *dst,
                 struct sockaddr *src_lsi, struct sockaddr *dst_lsi,
                 __u32 spi, __u32 spinat,
                 __u8 *e_key, __u32 e_type, __u32 e_keylen,
                 __u8 *a_key, __u32 a_type, __u32 a_keylen,
                 __u32 lifetime);
int hip_sadb_delete(__u32 spi);
int hip_sadb_add_del_addr(__u32 spi, struct sockaddr *addr, int flags);
void hip_remove_expired_lsi_entries(struct timeval *now);
void hip_add_lsi(struct sockaddr *addr, struct sockaddr *lsi4,
                 struct sockaddr *lsi6);
int buffer_packet(struct sockaddr *lsi, __u8 *data, int len);
void unbuffer_packets(hip_lsi_entry *entry);
hip_lsi_entry *hip_lookup_lsi(struct sockaddr *lsi);
hip_sadb_entry *hip_sadb_lookup_spi(__u32 spi);
hip_sadb_entry *hip_sadb_lookup_addr(struct sockaddr *addr);
hip_sadb_entry *hip_sadb_get_next(hip_sadb_entry *placemark);
void hip_sadb_expire(struct timeval *now);
int hip_sadb_get_usage(__u32 spi, __u64 *bytes, struct timeval *usetime);
int hip_sadb_get_lost(__u32 spi, __u32 *lost);
void hip_sadb_inc_bytes(hip_sadb_entry *entry, __u64 bytes, struct timeval *now,
                        int lock);
__u32 hip_sadb_inc_loss(hip_sadb_entry *entry, __u32 loss,
                        struct sockaddr *dst);
void hip_sadb_reset_loss(hip_sadb_entry *entry, struct sockaddr *dst);

int hip_select_family_by_proto(__u32 lsi, __u8 proto, __u8 *header,
                               struct timeval *now);
int hip_add_proto_sel_entry(__u32 lsi, __u8 proto, __u8 *header, int family,
                            int dir, struct timeval *now);
void hip_remove_expired_sel_entries(struct timeval *now);
void print_sadb();

#endif
