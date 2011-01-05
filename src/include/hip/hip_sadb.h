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
 *  hip_sadb.h
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * the HIP Security Association database
 *
 */
#ifdef __MACOSX__
#include <sys/types.h>
#include <mac/mac_types.h>
#else
#ifdef __WIN32__
#include <win32/types.h>
#else
#include <asm/types.h>		/* __u16, __u32, etc */
#endif /* __WIN32__ */
#endif
#include <sys/types.h>		/* for socket.h */
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>		/* struct sockaddr */
#include <netinet/in.h>		/* struct sockaddr_in */
#endif /* __WIN32__ */
#include <openssl/des.h>	/* des_key_schedule */
#include <openssl/aes.h>	/* aes_key */
#include <openssl/blowfish.h>	/* bf_key */

/*
 * definitions
 */
#define SADB_SIZE 512 
#define LSI4(a) (((struct sockaddr_in*)a)->sin_addr.s_addr)

/* HIP Security Association entry */
typedef struct _hip_sadb_entry 
{
	struct _hip_sadb_entry *next;
	__u32 spi;			/* primary index into SADB */
	__u32 spinat;			/* OTB -- spinat for mobile router */
	__u32 mode; 	/* ESP mode :  0-default 1-transport 2-tunnel 3-beet */
	int direction;			/* in/out */
	__u16 hit_magic;		/* for quick checksum calculation */
	sockaddr_list *src_addrs;	/* source addresses 		*/
	sockaddr_list *dst_addrs;	/* destination addresses 	*/
	struct sockaddr_storage src_hit; /* source HIT */
	struct sockaddr_storage dst_hit; /* destination HIT */
	struct sockaddr_storage lsi;	/* LSI 				*/
	struct sockaddr_storage lsi6;	/* IPv6 LSI (peer HIT)		*/
	__u32 a_type;			/* crypto parameters 		*/
	__u32 e_type;
	__u32 a_keylen;
	__u32 e_keylen;
	__u8 *a_key;			/* raw crypto keys */
	__u8 *e_key;
	__u64 lifetime;			/* seconds until expiration */
	__u64 bytes;			/* bytes transmitted */
	struct timeval usetime;		/* last used timestamp */
	__u32 sequence;			/* sequence number counter */
	__u32 replay_win;		/* anti-replay window */
	__u32 replay_map;		/* anti-replay bitmap */
	char iv[8];
	des_key_schedule ks[3];		/* 3-DES keys */
	AES_KEY *aes_key;		/* AES key */
	BF_KEY *bf_key;			/* BLOWFISH key */
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
        __u32 selector;         /* upper layer protocol-specific selector */
        int family;             /* guidance on which address family to use */
        struct timeval last_used;
} hip_proto_sel_entry;


/*
 * functions
 */
void hip_sadb_init();
void hip_sadb_deinit();
int hip_sadb_add(__u32 type, __u32 mode, struct sockaddr *src_hit,
    struct sockaddr *dst_hit, struct sockaddr *src, struct sockaddr *dst,
    __u16 port, __u32 spi, __u8 *e_key, __u32 e_type, __u32 e_keylen,
    __u8 *a_key, __u32 a_type, __u32 a_keylen, __u32 lifetime, __u16 hitmagic,
    __u32 spinat);
int hip_sadb_delete(__u32 type, struct sockaddr *src, struct sockaddr *dst,
    __u32 spi);
void hip_remove_expired_lsi_entries();
void hip_add_lsi(struct sockaddr *addr, struct sockaddr *lsi4, 
	struct sockaddr *lsi6);
int buffer_packet(struct sockaddr *lsi, __u8 *data, int len);
void unbuffer_packets(hip_lsi_entry *entry);
hip_lsi_entry *hip_lookup_lsi(struct sockaddr *lsi);
hip_sadb_entry *hip_sadb_lookup_spi(__u32 spi);
hip_sadb_entry *hip_sadb_lookup_addr(struct sockaddr *addr);
hip_sadb_entry *hip_sadb_get_next(hip_sadb_entry *placemark);

int hip_select_family_by_proto(__u32 lsi, __u8 proto, __u8 *header,
        struct timeval *now);
int hip_add_proto_sel_entry(__u32 lsi, __u8 proto, __u8 *header, int family,
        int dir, struct timeval *now);
void hip_remove_expired_sel_entries();
void print_sadb();
