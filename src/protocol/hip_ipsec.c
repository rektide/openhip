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
 *  hip_ipsec.c
 *
 *  Authors:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *  		Jeff Meegan, <jeff.r.meegan@boeing.com>
 *
 * Functions for communicating with the kernel IPSec implementation using
 * the PF_KEYv2 messaging interface.
 *
 */

#include <stdio.h>       	/* stderr, etc                  */
#include <stdlib.h>		/* rand()			*/
#include <errno.h>       	/* strerror(), errno            */
#include <string.h>      	/* memset()                     */
#include <time.h>		/* time()			*/
#include <ctype.h>		/* tolower()                    */
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>		/* sockaddrin_6 */
#include <io.h>				/* read() */
#include <win32/types.h>
#include <win32/ip.h>
#else
#ifndef __MACOSX__
#include <asm/types.h>
#endif
#include <unistd.h>		/* read()			*/
#include <arpa/inet.h>		/* inet_addr() 			*/
#include <sys/socket.h>  	/* sock(), recvmsg(), etc       */
#include <sys/time.h>  		/* gettimeofday()		*/
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>  	/* struct sockaddr_in, etc      */
#include <netinet/ip.h>  	/* struct iphdr                 */
#endif
#include <sys/types.h>		/* getpid() support, etc        */
#include <openssl/crypto.h>     /* OpenSSL's crypto library     */
#include <openssl/bn.h>		/* Big Numbers                  */
#include <openssl/dsa.h>	/* DSA support                  */
#include <openssl/dh.h>		/* Diffie-Hellman contexts      */
#include <openssl/sha.h>	/* SHA1 algorithms 		*/
#include <openssl/rand.h>	/* RAND_seed()                  */
#ifdef __MACOSX__
#include <sys/types.h>
#include <win32/pfkeyv2.h>
#else
#ifdef __UMH__
#include <win32/pfkeyv2.h>
#else
#include <linux/pfkeyv2.h> 	/* PF_KEY_V2 support */
#endif
#endif
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>

#define IPSEC_PFKEYv2_ALIGN (sizeof(uint64_t) / sizeof(uint8_t))
#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))

/* PF_KEY messages that have not been received yet */
static struct pfkey_buffer_entry {
	struct pfkey_buffer_entry *next;
	char *data;
} *pfkey_buffer = NULL;

#ifdef __UMH__
#define S_PFK_PROCESS "the PF_KEY thread"
#else
#define S_PFK_PROCESS "the Linux kernel"
#endif

/* XXX these are needed for Linux UML compilation
 * Should be instead handled by configure process
 */
#ifndef SADB_GETSEQ
#define SADB_GETSEQ		24
#define SADB_GETLSI		25
#define SADB_READDRESS		26
#define SADB_HIP_ACQUIRE	27
#define SADB_HIP_ADD		28
#define SADB_HIP_PACKET		29
#undef SADB_MAX
#define SADB_MAX		30
#endif


#ifdef DUMMY_FUNCTIONS
/* dummy prototypes for libipsec provided routines */
int pfkey_send_hip_x1 (int a, u_int b, u_int c, u_int d, struct sockaddr *e,
        struct sockaddr *f, struct sockaddr *fa, struct sockaddr *fb,
	u_int32_t g, u_int32_t h, u_int i, caddr_t j,
        u_int k, u_int l, u_int m, u_int n, u_int o, u_int32_t p, u_int32_t q,
        u_int32_t r, u_int32_t s, u_int32_t t,
        u_int8_t u, u_int16_t v, u_int16_t w, struct sockaddr *x, u_int16_t y)
{ return(0); }

int pfkey_send_rea (int a, u_int b, u_int c, struct sockaddr *d,
	struct sockaddr *e, u_int32_t f, u_int g, u_int h, u_int i, 
	u_int32_t j)
{ return(0); }
   
int pfkey_send_spdadd(int so, struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd, u_int proto,
	caddr_t policy, int policylen, u_int32_t seq)
{ return(0); }

int pfkey_send_spddelete(int so, struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd, u_int proto,
	caddr_t policy, int policylen, u_int32_t seq)
{ return(0); }

int pfkey_send_delete(int so, u_int satype, u_int mode, 
				struct sockaddr *src, struct sockaddr *dst,
				u_int32_t spi)
{ return(0); }
int pfkey_send_register(int so, u_int satype)
{ return(0); }

int pfkey_send_getspi(int so, u_int satype, u_int mode,
	struct sockaddr *src, struct sockaddr *dst, u_int32_t min, 
	u_int32_t max, u_int32_t reqid, u_int32_t seq)
{ return(0); }

int pfkey_send_get(int so, u_int satype, u_int mode, 
	struct sockaddr *src, struct sockaddr *dst, u_int32_t spi)
{ return(0); }

int __ipsec_errcode;

const char *ipsec_strerror (void)
{ return(0); }
int ipsec_get_policylen (caddr_t policy)
{ return(0); }
caddr_t ipsec_set_policy (char *msg, int msglen)
{ return(0); }
#else
/* prototypes for libipsec provided routines */
extern int pfkey_send_hip_x1 (int, u_int, u_int, u_int, struct sockaddr *,
        struct sockaddr *, struct sockaddr *, struct sockaddr *,
        u_int32_t, u_int32_t, u_int, caddr_t,
        u_int, u_int, u_int, u_int, u_int, u_int32_t, u_int32_t,
        u_int32_t, u_int32_t, u_int32_t,
        u_int8_t, u_int16_t, u_int16_t, struct sockaddr *, u_int16_t);

extern int pfkey_send_rea (int, u_int, u_int, struct sockaddr *,
	struct sockaddr *, u_int32_t, u_int , u_int, u_int, u_int32_t);
   
extern int pfkey_send_spdadd(int so, struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd, u_int proto,
	caddr_t policy, int policylen, u_int32_t seq);

extern int pfkey_send_spddelete(int so, struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd, u_int proto,
	caddr_t policy, int policylen, u_int32_t seq);

extern int pfkey_send_delete(int so, u_int satype, u_int mode, 
				struct sockaddr *src, struct sockaddr *dst,
				u_int32_t spi);
extern int pfkey_send_register(int so, u_int satype);

extern int pfkey_send_getspi(int so, u_int satype, u_int mode,
	struct sockaddr *src, struct sockaddr *dst, u_int32_t min, 
	u_int32_t max, u_int32_t reqid, u_int32_t seq);

extern int pfkey_send_get(int so, u_int satype, u_int mode, 
	struct sockaddr *src, struct sockaddr *dst, u_int32_t spi);

extern int __ipsec_errcode;
extern const char *ipsec_strerror (void);
extern int ipsec_get_policylen (caddr_t policy);
extern caddr_t ipsec_set_policy (char *msg, int msglen);
#endif
#ifdef __MACOSX__
extern void del_divert_rule(int);
#endif
/* from hip_main.c */
#ifdef __WIN32__
void hip_handle_packet(__u8* buff, int length, struct sockaddr *src);
#else
void hip_handle_packet(struct msghdr *msg, int length, __u16 family);
#endif

/* local functions */
int check_pfkey_response(int expected_type, __u32 seqno);
void hip_handle_acquire(struct sockaddr *src, struct sockaddr *dst);
int hip_convert_lsi_to_peer(struct sockaddr *lsi, hip_hit *hitp,
	struct sockaddr *src, struct sockaddr *dst);
void hip_handle_expire(__u32 spi);
void hip_pfkey_to_hip(char *buff);
void hip_add_pfkey_buffer(char *data, int len);

/*
 *
 * function get_next_spi()
 *
 * in:		hip_a = the src and dst addresses are needed from the
 * 			HIP association
 *
 * out:		returns next SPI value to use
 *
 * Obtains new random SPI, checks with kernel via SADB_GETSPI interface,
 * and then issues SADB_DELETE to remove the residual larval SA.
 */
__u32 get_next_spi(hip_assoc *hip_a) 
{
	int err;
	struct sockaddr *src, *dst;
	__u32 new_spi;

retry_getspi:
	/* randomly select a new SPI */
	new_spi = 0;
	while (new_spi <= SPI_RESERVED) {
		RAND_bytes((__u8*)&new_spi, 4);
	}

#ifndef DUMMY_FUNCTIONS
	/* we always choose incoming SPIs */
	src = HIPA_DST(hip_a);
	dst = HIPA_SRC(hip_a);

	/* send SADB_GETSPI */
	/* in RFC 2367, sadb_sa_spi must be in network byte order,
	 * but here the spirange extension is in host order. 
	 */
	err = pfkey_send_getspi(s_pfk,
				SADB_SATYPE_ESP,	/* satype */
				0, 		/* mode 3=BEET, 0=default */
				src,
				dst,
				new_spi,		/* min */
				new_spi,		/* max */
				0, 			/* reqid */
				++pfk_seqno);
	
	if (err < 1) {
		log_(NORM, "PF_KEY write() error: %s.\n", strerror(errno));
	}

	/* verify response */
	if ((err = check_pfkey_response(SADB_GETSPI, pfk_seqno)) < 0) {
		if (err == -EEXIST) {
			log_(WARN, "Randomly chosen SPI (0x%x) already used, ",
			    new_spi);
			log_(NORM, "retrying SADB_GETSPI.\n");
			goto retry_getspi;
		}
		log_(WARN, "Got invalid SADB_GETSPI back from %s! %s\n",
			S_PFK_PROCESS, ipsec_strerror());
		return(-1);
	}

	/* No larval SA is created with Windows version of GETSPI */
#ifndef __UMH__
	/* destroy the larval SA that has been created */
	if (sadb_delete(hip_a, src, dst, new_spi) < 0) {
		log_(WARN, "Error deleting LARVAL SA after SADB_GET!\n");
		return(0);
	}
#endif
#endif	
	return(new_spi);
}

/*    
 *    From pf_key rfc2367
 *    The basic unit of alignment and length in PF_KEY Version 2 is 64
 *    bits. Therefore:
 *
 *    * All extension headers, inclusive of the sadb_ext overlay fields,
 *      MUST be a multiple of 64 bits long.
 *
 *    * All variable length data MUST be padded appropriately such that
 *      its length in a message is a multiple of 64 bits.
 *
 *    * All length fields are, unless otherwise specified, in units of
 *      64 bits.
 *
 *    * Implementations may safely access quantities of between 8 and 64
 *      bits directly within a message without risk of alignment faults.
 *
 */

/*
 *
 * function sadb_register()
 *
 * in:		satype = type of SA to listen for
 *
 * out:		returns bytes sent on success, -1 on failure
 *
 * Sends a PF_KEYv2 SADB_REGISTER message to the kernel, to register
 * the types of SAs to handle, and validates the reponse.
 *
 */
int sadb_register(int satype)
{
	int err=0;

	/* send SADB_REGISTER message to the kernel */
	err = pfkey_send_register(s_pfk,satype);
	if (err < 1) {
		log_(NORM, "PF_KEY write() error: %s.\n", strerror(errno));
	}
		
	/* verify response */
	if (check_pfkey_response(SADB_REGISTER, pfk_seqno) < 0) {
		log_(WARN, "Got invalid SADB_REGISTER back from %s! %s\n",
			S_PFK_PROCESS, ipsec_strerror());
		return(-1);
	}

	return(err);
}


/*
 *
 * function sadb_add()
 *
 * in:		src = source IP address
 * 	        dst = destination IP address
 * 	        spi = SPI number of the SA to be added
 * 	        direction = 0 to add my keys      *outgoing*
 * 	                  = 1 to add peer keys    *incoming*
 *
 * out:		returns bytes sent or failure
 *
 * Sends PF_KEYv2 ADD message to the kernel to establish a unidirectional SA.
 *  skip the pfkey_send_add interface and use the pfkey_send_x1 directly
 *  as this is munged to look for a hit.
 * 
 */
int sadb_add(struct sockaddr *src, struct sockaddr *dst, hip_assoc *hip_a,
		__u32 spi, int direction)
{
	unsigned char *key, concat_key[256];
	int err=0;
	__u32 e_type, a_type, e_keylen, a_keylen;
	struct sockaddr_storage s_src_hit, s_dst_hit;

	/* 
	 * The libipsec code wants the two keys catentated together.  It 
	 * then reads them out based on a_keylen and e_keylen.  
	 */
	memset(concat_key, 0, sizeof(concat_key));

	/* first, prepare the encryption key */
	switch(hip_a->esp_transform) {
	case ESP_AES_CBC_HMAC_SHA1:		/* AES-CBC enc */
		e_type = SADB_X_EALG_AESCBC;
		break;
	case ESP_3DES_CBC_HMAC_SHA1:		/* 3DES-CBC enc */
	case ESP_3DES_CBC_HMAC_MD5:
		e_type = SADB_EALG_3DESCBC;
		break;
	case ESP_BLOWFISH_CBC_HMAC_SHA1:	/* BLOWFISH-CBC enc */
		e_type = SADB_X_EALG_BLOWFISHCBC;
		break;
	case ESP_NULL_HMAC_SHA1:		/* NULL enc */
	case ESP_NULL_HMAC_MD5:
		e_type = SADB_EALG_NULL;
		break;
	default:
		log_(WARN, "Unsupported ESP transform!\n");
		return(-1);
	}
	e_keylen = enc_key_len(hip_a->esp_transform);
	if (e_keylen) {
		key = get_key(hip_a, ESP_ENCRYPTION, direction);
		memcpy(&concat_key,key,e_keylen);
	}
	
	/* next, prepare authentication key */
	switch(hip_a->esp_transform) {
	case ESP_AES_CBC_HMAC_SHA1:		/* HMAC-SHA1 auth */
	case ESP_3DES_CBC_HMAC_SHA1:
	case ESP_BLOWFISH_CBC_HMAC_SHA1:
	case ESP_NULL_HMAC_SHA1:
		a_type = SADB_AALG_SHA1HMAC;
		break;
	case ESP_3DES_CBC_HMAC_MD5:		/* HMAC-MD5 auth */
	case ESP_NULL_HMAC_MD5:
		a_type = SADB_AALG_MD5HMAC;
		break;
	default:
		log_(WARN, "Unsupported ESP transform!\n");
		return(-1);
	}
	a_keylen = auth_key_len(hip_a->esp_transform);
	if (a_keylen) {
		key = get_key(hip_a, ESP_AUTH, direction);
		memcpy(&concat_key[e_keylen],key,a_keylen);
	}

	if (direction) { 	/* inbound */
		hit_to_sockaddr(SA(&s_src_hit), hip_a->peer_hi->hit);
		hit_to_sockaddr(SA(&s_dst_hit), hip_a->hi->hit);
	} else {		/* outbound */
		hit_to_sockaddr(SA(&s_src_hit), hip_a->hi->hit);
		hit_to_sockaddr(SA(&s_dst_hit), hip_a->peer_hi->hit);
	}

	log_(NORMT, "sadb_add(src=%s, ", logaddr(src));
	log_(NORM,  "dst=%s, ", logaddr(dst));
	log_(NORM,  "src HIT=%s, ", logaddr(SA(&s_src_hit)));
	log_(NORM,  "dst HIT=%s, ", logaddr(SA(&s_dst_hit)));
	log_(NORM,  "spi=0x%x, ", spi);
	log_(NORM,  "direction=%s)\n", direction ? "in":"out");
	log_(NORM, "spi=0x%x ekey: 0x", spi);
	print_hex(&concat_key,e_keylen);
	log_(NORM, "\nspi=0x%x akey: 0x", spi);
	print_hex(&concat_key[e_keylen],a_keylen);
	log_(NORM, "\n");

	err = pfkey_send_hip_x1(s_pfk,		/* my sock */
				SADB_ADD,       /* msg type */
				SADB_SATYPE_ESP,/* SATYPE always ESP*/
				hip_a->udp ? 3 : 0, /* mode 0=normal, 3=UDP */
				src,		/* src host */ 
				dst,		/* dst host */ 
				SA(&s_src_hit),	/* inner src : HIT */
				SA(&s_dst_hit),	/* inner dst : HIT */
				htonl(spi),	/* SPI */
				hip_a->spi_nat,	/* reqID -- unused (OTB) */
				0,		/* wsize=0*/
				(char*)concat_key, /* combined ekey&akey*/
				e_type,
				e_keylen,
				a_type,
				a_keylen,
				0,		/* flags=0 for sa ext */
				0,		/* l_alloc */
				0,		/* l_bytes */
				HCNF.sa_lifetime,/* l_addtime */
				0,  		/* l_usetime */
				++pfk_seqno, 	/* seq # */
				0, /* l_natt_type 2=UDP_ENCAP_ESPINUDP */
				0, /* l_natt_sport */
				0, /* l_natt_dport */
				NULL, 
				checksum_magic((const hip_hit*)hip_a->hi->hit,
					(const hip_hit*)hip_a->peer_hi->hit));

	if (err < 0) {
		log_(WARN, "PF_KEY write() error: %s.\n", strerror(errno));
		return(-1);
	}

	/* verify response */
	if (check_pfkey_response(SADB_ADD, pfk_seqno) < 0) {
		log_(WARN, "Got invalid SADB_ADD back from %s! %s\n",
			S_PFK_PROCESS, ipsec_strerror());
#ifdef __MACOSX__
                return(0);
#else
                return(-1);
#endif
	}
	return(err);
}


/*
 *
 * function sadb_readdress()
 *
 * in:		src = old IP address
 * 	        dst = new IP address
 * 	        spi = SPI number of the SA to be added
 *
 * out:		returns bytes sent or failure
 *
 * Sends PF_KEYv2 SADB_READDRESS message to the kernel to update change
 * an address used in a HIP association.
 *
 */
int sadb_readdress(struct sockaddr *src, struct sockaddr *dst, hip_assoc *hip_a,
		__u32 spi)
{
	int err=0;
	__u32 e_type, a_type;

	/* set encryption type */
	switch(hip_a->esp_transform) {
	case ESP_AES_CBC_HMAC_SHA1:		/* AES-CBC enc */
		e_type = SADB_X_EALG_AESCBC;
		break;
	case ESP_3DES_CBC_HMAC_SHA1:		/* 3DES-CBC enc */
	case ESP_3DES_CBC_HMAC_MD5:
		e_type = SADB_EALG_3DESCBC;
		break;
	case ESP_BLOWFISH_CBC_HMAC_SHA1:	/* BLOWFISH-CBC enc */
		e_type = SADB_X_EALG_BLOWFISHCBC;
		break;
	case ESP_NULL_HMAC_SHA1:		/* NULL enc */
	case ESP_NULL_HMAC_MD5:
		e_type = SADB_EALG_NULL;
		break;
	default:
		log_(WARN, "Unsupported ESP transform!\n");
		return(-1);
	}

	/* set authentication type */
	switch(hip_a->esp_transform) {
	case ESP_AES_CBC_HMAC_SHA1:		/* HMAC-SHA1 auth */
	case ESP_3DES_CBC_HMAC_SHA1:
	case ESP_BLOWFISH_CBC_HMAC_SHA1:
	case ESP_NULL_HMAC_SHA1:
		a_type = SADB_AALG_SHA1HMAC;
		break;
	case ESP_3DES_CBC_HMAC_MD5:		/* HMAC-MD5 auth */
	case ESP_NULL_HMAC_MD5:
		a_type = SADB_AALG_MD5HMAC;
		break;
	default:
		log_(WARN, "Unsupported ESP transform!\n");
		return(-1);
	}
	
	log_(NORM, "Readdressing SA with spi=0x%x old=%s, ", spi, logaddr(src));
	log_(NORM, "new=%s\n", logaddr(dst));

	err = pfkey_send_rea(	s_pfk,		/* my sock */
				SADB_READDRESS,       /* msg type */
				SADB_SATYPE_ESP,/* SATYPE always ESP*/
				src,		/* src host */ 
				dst,		/* dst host */ 
				htonl(spi),	/* SPI */
				e_type,
				a_type,
				0,		/* flags=0 for sa ext */
				++pfk_seqno); 	/* seq # */

	if (err < 0) {
		log_(WARN, "PF_KEY write() error: %s.\n", strerror(errno));
		return(-1);
	}

	/* verify response */
	if (check_pfkey_response(SADB_READDRESS, pfk_seqno) < 0) {
		log_(WARN, "Got invalid SADB_READDRESS back from %s! %s\n",
			S_PFK_PROCESS, ipsec_strerror());
		return(-1);
	}

	return(err);
}



/*
 *
 * function sadb_delete()
 *
 * in:		src   = source address present in SA 
 *              dst   = destination address present in SA
 *              spi   = SPI of SA to delete
 *
 * out:		returns bytes sent (>0) or failure (-1)
 *
 * Sends PF_KEYv2 SADB_DELETE message to the kernel to
 * remove a Security Association, between src and dst addresses.
 * 
 *
 */
int sadb_delete(hip_assoc *hip_a, struct sockaddr *src, struct sockaddr *dst, __u32 spi)
{
	int err=0;
	
	log_(NORMT, "sadb_delete(src=%s, dst=", logaddr(src));
	log_(NORM,  "%s, spi=0x%x)\n", logaddr(dst), spi);

	err = pfkey_send_delete(s_pfk,  		/* socket */
				SADB_SATYPE_ESP,	/* satype */
				0, 		/* mode 3=BEET, 0=default */
				src,			/* src */
				dst,			/* dest */
				htonl(spi));		/* SPI  */

	if (err < 0) {
		log_(WARN, "PF_KEY delete() error: %s.\n", strerror(errno));
		return(-1);
	}

	/* verify response */
	if (check_pfkey_response(SADB_DELETE, 0) < 0) {
		log_(WARN, "Got invalid SADB_DELETE back from %s! %s\n",
			S_PFK_PROCESS, ipsec_strerror());
		return(-1);
	}

	return(err);
}

/*
 * sadb_add_policy()
 *
 * in:		src = source address
 * 		dst = destination address
 * 		direction = 1 for incoming, 0 for outgoing SPD rule
 *
 * out:		Returns 1 if successful or if SPD rule already exists,
 * 		< 0 on error.
 *
 * Attempt to add a HIP IPSEC policy for the specific IP addresses of this
 * host and its peer (using 32-bit or 128-bit prefix length).
 */
int sadb_add_policy(hip_assoc *hip_a, struct sockaddr *src, 
		struct sockaddr *dst, int direction)
{
	int err=0;
	char pol1[100];
	char pol2[100];
	caddr_t policy;
	int policylen, src_plen, dst_plen;

	memset(pol1, 0, 100);
	memset(pol2, 0, 100);
	
	strcpy(pol1, "in ipsec hip/transport//require");
	strcpy(pol2, "out ipsec hip/transport//require");

	policy = direction ? 
		ipsec_set_policy(pol1, strlen(pol1)) :
		ipsec_set_policy(pol2, strlen(pol2));
	policylen = ipsec_get_policylen(policy);
	/* set prefix length to match specific host */
	src_plen = (src->sa_family == AF_INET) ? 32 : 128;
	dst_plen = (dst->sa_family == AF_INET) ? 32 : 128;

	log_(NORMT, "sadb_add_policy(src=%s, dst=", logaddr(src));
	log_(NORM,  "%s, direction=%s)\n", logaddr(dst), 
			direction ? "in":"out");

	/* PF_KEY message will have the format:
	 * < SADB_X_SPDADD >
	 * <base,address_S,address_D,lifeH,lifeS,lifeC,x_POLICY>
	 */
	err = pfkey_send_spdadd(s_pfk, src, src_plen, dst, dst_plen, 255,
				policy, policylen, ++pfk_seqno);
	free(policy);
	if (err < 0) {
		log_(WARN, "PF_KEY write() error: %s.\n", strerror(errno));
		return(-1);
	}
	
	/* verify response */
	if ((err = check_pfkey_response(SADB_X_SPDADD, pfk_seqno)) < 0) {
		if (err == -EEXIST)
			return(1);
		log_(WARN, "Got invalid SADB_X_SPDADD back from %s! %s\n",
			S_PFK_PROCESS, ipsec_strerror());
		return(-1);
	}

	return(1);
}

/*
 * sadb_delete_policy()
 *
 * in:		src = source address
 * 		dst = destination address
 * 		direction = 1 for incoming, 0 for outgoing SPD rule
 *
 * out:		Returns 1 if successful or if SPD rule already exists,
 * 		< 0 on error.
 *
 * Attempt to delete a HIP IPSEC policy for the specific IP addresses of this
 * host and its peer (using 32-bit or 128-bit prefix length).
 */
int sadb_delete_policy(struct sockaddr *src, struct sockaddr *dst,int direction)
{
	int err=0;
	int policylen, src_plen, dst_plen;
	struct sadb_x_policy policy;

	/* do not use ipsec_set_policy() here, it will not work */
	policylen = sizeof(struct sadb_x_policy);
	memset(&policy, 0, policylen);
	policy.sadb_x_policy_len = (policylen >> 3);
	policy.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy.sadb_x_policy_type = 2; 	/* IPSEC_POLICY_IPSEC */
	policy.sadb_x_policy_dir = direction ? 1:2; /* 1=in, 2=out */
	policy.sadb_x_policy_id = 0;
	
	/* set prefix length to match specific host */
	src_plen = (src->sa_family == AF_INET) ? 32 : 128;
	dst_plen = (dst->sa_family == AF_INET) ? 32 : 128;

	log_(NORMT, "sadb_delete_policy(src=%s, dst=", logaddr(src));
	log_(NORM,  "%s, direction=%s)\n", logaddr(dst),direction ? "in":"out");

	err = pfkey_send_spddelete(s_pfk, src, src_plen, dst, dst_plen, 255,
				(caddr_t)&policy, policylen, ++pfk_seqno);
	if (err < 0) {
		log_(WARN, "PF_KEY write() error: %s.\n", ipsec_strerror());
		return(-1);
	}

#ifndef __UMH__ /* User-mode pfkey_send_spddelete() doesn't do anything */
	/* verify response */
	/* XXX is the kernel responding with SADB_X_SPDDELETE or 
		SADB_X_SPDDELETE2? */
	if ((err = check_pfkey_response(SADB_X_SPDDELETE, pfk_seqno)) < 0) {
		if (err == -EEXIST)
			return(1);
		log_(WARN, "Got invalid SADB_X_SPDDELETE back from %s: %s\n",
			S_PFK_PROCESS, ipsec_strerror());
		return(-1);
	}
#endif /* __UMH__ */

	return(1);
}

/*
 * check_last_used()
 *
 * in:		hip_a = uses src, dst, and incoming SPI
 * out:		Returns 0 on error or if SA is unused, 1 if traffic detected
 * 		If SA has been used, store time in hip_a->use_time.
 *
 * Check the current use time of the SA using an SADB_GET message.
 */
int check_last_used(hip_assoc *hip_a, int incoming, struct timeval *now)
{
	int err=0, location;
	struct sadb_msg *pfkey_msg;
	struct sadb_ext *pfkey_ext;
	struct sadb_lifetime *l;
	struct sockaddr *src, *dst;
	__u32 spi;
	char buff[512];
	__u64 bytes=0;

	if (incoming) {
		src = HIPA_DST(hip_a);
		dst = HIPA_SRC(hip_a);
		spi = htonl(hip_a->spi_in);
	} else {
		src = HIPA_SRC(hip_a);
		dst = HIPA_DST(hip_a);
		spi = htonl(hip_a->spi_out);
	}
	
	err = pfkey_send_get(	s_pfk,
				SADB_SATYPE_ESP,	/* satype */
				0,	/* mode 3=BEET, 0=default */
				src,			/* src */
				dst,			/* dst */
				spi);

	if (err < 0) {
		log_(WARN, "PF_KEY write() error: %s.\n", ipsec_strerror());
		return(0);
	}

#ifdef __WIN32__
	err = recv(s_pfk, buff, sizeof(buff), 0);
#else
	err = read(s_pfk, buff, sizeof(buff));
#endif
	if (err < 0) {
		log_(WARN, "PF_KEY read() error: %s.\n", ipsec_strerror());
		return(0);
	}
		
	/* verify response */
	pfkey_msg = (struct sadb_msg*)buff;
	if ((pfkey_msg->sadb_msg_version == 2) &&
	    (pfkey_msg->sadb_msg_type == SADB_DUMP) &&
	    (pfkey_msg->sadb_msg_errno == 0)) {
		/* parse bytes from current lifetime extension*/
		location = sizeof(struct sadb_msg);
		while (location < err) {
			pfkey_ext = (struct sadb_ext*) &buff[location];
			if (pfkey_ext->sadb_ext_type == 
			    SADB_EXT_LIFETIME_CURRENT) {
				l = (struct sadb_lifetime *) pfkey_ext;
				bytes = l->sadb_lifetime_bytes;
				break;
			}
			location += (pfkey_ext->sadb_ext_len * 8);
		}
	} else if (pfkey_msg->sadb_msg_type == SADB_DUMP) {		
		log_(WARN, "Got invalid SADB_DUMP back from %s! errno=%d\n",
			S_PFK_PROCESS, pfkey_msg->sadb_msg_errno);
		return(0);
	} else {
		/* could be another waiting message */
		return(0);
	}

	/* no traffic detected */
	if (bytes == 0) {
		return(0);
	}

	/* update use_time if either direction has traffic
	 */
	if (incoming) {
		if (bytes > hip_a->used_bytes_in) {
			hip_a->used_bytes_in = bytes;
			hip_a->use_time.tv_sec = now->tv_sec;
			hip_a->use_time.tv_usec = now->tv_usec;
		}
	} else {
		if (bytes > hip_a->used_bytes_out) {
			hip_a->used_bytes_out = bytes;
			hip_a->use_time.tv_sec = now->tv_sec;
			hip_a->use_time.tv_usec = now->tv_usec;
		}
	}

	return(1);
}

/*
 * sadb_lsi()
 *
 * Echo the ACQUIRE message back to the kernel, with the SRC address
 * modified to provide the LSI -> IP mapping.
 */
int sadb_lsi(struct sockaddr *ip, struct sockaddr *lsi4, struct sockaddr *lsi6)
{
	char buff[256];
	struct sadb_msg *msg = (struct sadb_msg *)buff;
	struct sadb_address *addr;
	int len, plen, location, addr_len;

	len = sizeof(struct sadb_msg) + 2*sizeof(struct sadb_address);
	len += PFKEY_ALIGN8(SALEN(ip));
	len += PFKEY_ALIGN8(SALEN(lsi4));
	if (lsi6 && VALID_FAM(lsi6))
		len += sizeof(struct sadb_address) + PFKEY_ALIGN8(SALEN(lsi6));
	memset(buff, 0, len);
	
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_HIP_ACQUIRE;
	msg->sadb_msg_errno = 0;
	msg->sadb_msg_satype = SADB_SATYPE_ESP;
	msg->sadb_msg_len = len / sizeof(__u64);
	msg->sadb_msg_reserved = 0;
	msg->sadb_msg_seq = 0; /* this could match rcvd ACQUIRE's seqno */
	msg->sadb_msg_pid = 0;
	location = sizeof(struct sadb_msg);

	/* src address is IP */
	addr = (struct sadb_address*) &buff[location];
	addr_len = SALEN(ip);
	addr->sadb_address_len = PFKEY_ALIGN8(sizeof(struct sadb_address) +
					      addr_len) / IPSEC_PFKEYv2_ALIGN;
	addr->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	addr->sadb_address_proto = 0;
	plen = (ip->sa_family==AF_INET) ? (sizeof(struct in_addr) << 3) :
					  (sizeof(struct in6_addr) << 3);
	addr->sadb_address_prefixlen = plen;
	addr->sadb_address_reserved = 0;
	location += sizeof(struct sadb_address);
	memcpy(&buff[location], ip, addr_len);
	location += PFKEY_ALIGN8(SALEN(ip));

	/* dst address is LSI */
	addr = (struct sadb_address*) &buff[location];
	addr_len = SALEN(lsi4);
	addr->sadb_address_len = PFKEY_ALIGN8(sizeof(struct sadb_address) +
					      addr_len) / IPSEC_PFKEYv2_ALIGN;
	addr->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
	addr->sadb_address_proto = 0;
	plen = (lsi4->sa_family==AF_INET) ? (sizeof(struct in_addr) << 3) :
					  (sizeof(struct in6_addr) << 3);
	addr->sadb_address_prefixlen = plen;
	addr->sadb_address_reserved = 0;
	location += sizeof(struct sadb_address);
	memcpy(&buff[location], lsi4, addr_len);
	location += addr_len;
	
	/* another dst address for IPv6 LSI */
	if (lsi6 && VALID_FAM(lsi6)) {
		addr = (struct sadb_address*) &buff[location];
		addr_len = SALEN(lsi6);
		addr->sadb_address_len = PFKEY_ALIGN8(
			sizeof(struct sadb_address) +
			addr_len) / IPSEC_PFKEYv2_ALIGN;
		addr->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
		addr->sadb_address_proto = 0;
		plen = (lsi6->sa_family==AF_INET) ? 
			(sizeof(struct in_addr) << 3) :
			(sizeof(struct in6_addr) << 3);
		addr->sadb_address_prefixlen = plen;
		addr->sadb_address_reserved = 0;
		location += sizeof(struct sadb_address);
		memcpy(&buff[location], lsi6, addr_len);
	}
	if (send(s_pfk, (char *)msg, len, 0) < 0) {
		log_(WARN, "Error sending ACQUIRE response.\n");
		return(-1);
	}
	return(len);
}

/*
 * delete_associations()
 *
 * Remove associations from kernel by calling sadb_delete(), 
 * and sadb_delete_policy() for the incoming policy. (Outgoing policy is not
 * removed so further traffic will trigger a new exchange, if we are the
 * initiator) Called upon moving to CLOSING when no more packets may be sent.
 */
int delete_associations(hip_assoc *hip_a, __u32 old_spi_in, __u32 old_spi_out)
{
	int err;
	__u32 spi_in, spi_out;

	/* alternate SPIs may be passed in, but if zero use hip_a SPIs */
	spi_in = (old_spi_in) ? old_spi_in : hip_a->spi_in;
	spi_out = (old_spi_out) ? old_spi_out :	hip_a->spi_out;

	err = 0;
	if (sadb_delete(hip_a, HIPA_SRC(hip_a), HIPA_DST(hip_a), spi_out) < 0) {
		log_(WARN, "Error removing outgoing SA with SPI 0x%x\n",
		    spi_out);
		err = -1;
	}
	if (sadb_delete(hip_a, HIPA_DST(hip_a), HIPA_SRC(hip_a), spi_in) < 0) {
		log_(WARN, "Error removing incoming SA with SPI 0x%x\n", 
		    spi_in);
		err = -1;
	}
#ifndef __UMH__
	/* do not delete policy entry when we are only removing old SAs */
	if (!old_spi_in && !old_spi_out) {
		if (sadb_delete_policy(HIPA_DST(hip_a),HIPA_SRC(hip_a),1) < 0) {
			log_(WARN, "Error removing incoming policy \n");
			err = -1;
		}
		if ((!hip_a->preserve_outbound_policy) &&
		  (sadb_delete_policy(HIPA_SRC(hip_a),HIPA_DST(hip_a),0) < 0)) {
			log_(WARN, "Error removing outgoing policy \n");
			err = -1;
		}
	}
#endif
#ifdef __MACOSX__
        if(hip_a->ipfw_rule > 0)  {
                log_(WARN, "deleting divert rule...\n");
                del_divert_rule(hip_a->ipfw_rule);
                hip_a->ipfw_rule = 0;
        }
#endif
	return(err);
}

/*
 * flush_hip_associations()
 *
 * Called on exit to remove HIP associations from the SAD and SPD.
 */
int flush_hip_associations()
{
	int i, count=0;
	hip_assoc *hip_a;

	for (i=0; i < max_hip_assoc; i++) {
		hip_a = &hip_assoc_table[i];
		switch (hip_a->state) {
		case I2_SENT:
		case R2_SENT:
		case ESTABLISHED:
			count++;
			log_hipa_fromto(QOUT, "Close initiated (flush)", 
					hip_a, FALSE, TRUE);
			hip_send_close(hip_a, FALSE);
			set_state(hip_a, CLOSED);
#ifndef __UMH__		/* delete SAs from kernel; for UMH, all threads
			 * will be terminated anyway, and this hangs when
			 * called upon exit in Linux */
			delete_associations(hip_a, 0, 0);
#endif
			break;
		default:
			break;
		}
	}

	return(count);
}

/*
 * function parse_acquire()
 *
 * in:		data = message to parse
 * 		src, dst = pointers for storing addresses
 *
 * out:		returns 0 if successful, -1 otherwise
 * 
 * Parse SADB_ACQUIRE messages from kernel.
 */
int parse_acquire(char *data, struct sockaddr *src, struct sockaddr *dst)
{
	struct sadb_address *pfkey_addr;
	struct sockaddr *sa;

	pfkey_addr = (struct sadb_address*) &data[sizeof(struct sadb_msg)];
	if (pfkey_addr->sadb_address_exttype == SADB_EXT_ADDRESS_SRC) {
		sa = (struct sockaddr*)((char*)pfkey_addr +
			sizeof(struct sadb_address));
		switch (sa->sa_family) {
		 case AF_INET:
		 case AF_INET6:
			if (!is_my_address(sa)) {
				if (IS_LSI(sa))
					break;
				log_(WARN, "Not my IP: %s", logaddr(sa));
				return(-1);
			}
			memcpy(src, sa, SALEN(sa));
			break;
		 default: /* somebody else's ACQUIRE */
			return(-1);
		}
	}
	pfkey_addr = (struct sadb_address*) ((char*)pfkey_addr +
	    (pfkey_addr->sadb_address_len*IPSEC_PFKEYv2_ALIGN));
	if (pfkey_addr->sadb_address_exttype == SADB_EXT_ADDRESS_DST) {
		sa = (struct sockaddr*) ++pfkey_addr;
		switch (sa->sa_family) {
		 case AF_INET:
		 case AF_INET6:
			memcpy(dst, sa, SALEN(sa));
			break;
		 default: /* unsupported address family */
			 return(-1);
		}
	}
	else {
		/* no dst address */
		return(-1);
	}
	return(0);
}

/*
 * function parse_expire()
 *
 * in:		data = message to parse
 * 		spi = pointer for storing SPI
 *
 * out:		returns 0 on success, -1 on error
 *
 * Parse SADB_EXPIRE messages from kernel, 
 * retrieving the SPI of the expired SA.
 */
int parse_expire(char *data, __u32 *spi)
{
	int location, type, len, length;
	struct sadb_msg *msg;
	struct sadb_ext *ext;
	struct sadb_sa *sa;

	msg = (struct sadb_msg*) data;
	length = msg->sadb_msg_len * sizeof(__u64);
	location = sizeof(struct sadb_msg);
	
	while (location < length) {
		ext = (struct sadb_ext*) &data[location];
		len = ext->sadb_ext_len * sizeof(__u64);
		type = ext->sadb_ext_type;

		switch (type) {
		case SADB_EXT_SA:
			sa = (struct sadb_sa*) &data[location];
			*spi = ntohl(sa->sadb_sa_spi);
			return(0);
			break;
		default:
			break;
		}
	
		location += len;
	}

	return(-1);
}

/*
 * function pfkey_packet_type()
 *
 * in:		type = PFKEY packet type number
 * out:		Returns string containing PFKEY packet name
 * 		(r must have at least 25 bytes of storage space)
 *
 */
void pfkey_packet_type(int type, char *r)
{
	switch (type) {
	case SADB_RESERVED:
		sprintf(r, "SADB_RESERVED");
		break;
	case SADB_GETSPI:
		sprintf(r, "SADB_GETSPI");
		break;
	case SADB_UPDATE:
		sprintf(r, "SADB_UPDATE");
		break;
	case SADB_ADD:
		sprintf(r, "SADB_ADD");
		break;
	case SADB_DELETE:
		sprintf(r, "SADB_DELETE");
		break;
	case SADB_GET:
		sprintf(r, "SADB_GET");
		break;
	case SADB_ACQUIRE:
		sprintf(r, "SADB_ACQUIRE");
		break;
	case SADB_REGISTER:
		sprintf(r, "SADB_REGISTER");
		break;
	case SADB_EXPIRE:
		sprintf(r, "SADB_EXPIRE");
		break;
	case SADB_FLUSH:
		sprintf(r, "SADB_FLUSH");
		break;
	case SADB_DUMP:
		sprintf(r, "SADB_DUMP");
		break;
	case SADB_X_PROMISC:
		sprintf(r, "SADB_X_PROMISC");
		break;
	case SADB_X_PCHANGE:
		sprintf(r, "SADB_X_PCHANGE");
		break;
	case SADB_X_SPDUPDATE:
		sprintf(r, "SADB_X_SPDUPDATE");
		break;
	case SADB_X_SPDADD:
		sprintf(r, "SADB_X_SPDADD");
		break;
	case SADB_X_SPDDELETE:
		sprintf(r, "SADB_X_SPDDELETE");
		break;
	case SADB_X_SPDGET:
		sprintf(r, "SADB_X_SPDGET");
		break;
	case SADB_X_SPDACQUIRE:
		sprintf(r, "SADB_X_SPD_ACQUIRE");
		break;
	case SADB_X_SPDDUMP:
		sprintf(r, "SADB_X_SPDDUMP");
		break;
	case SADB_X_SPDFLUSH:
		sprintf(r, "SADB_X_SPDFLUSH");
		break;
	case SADB_X_SPDSETIDX:
		sprintf(r, "SADB_X_SPDSETIDX");
		break;
	case SADB_X_SPDEXPIRE:
		sprintf(r, "SADB_X_SPDEXPIRE");
		break;
	case SADB_X_SPDDELETE2:
		sprintf(r, "SADB_X_SPDDELETE2");
		break;
	case SADB_X_NAT_T_NEW_MAPPING:
		sprintf(r, "SADB_X_NAT_T_NEW_MAPPING");
		break;
	case SADB_GETSEQ:
		sprintf(r, "SADB_GETSEQ");
		break;
	case SADB_GETLSI:
		sprintf(r, "SADB_GETLSI");
		break;
	case SADB_READDRESS:
		sprintf(r, "SADB_READDRESS");
		break;
	case SADB_HIP_ACQUIRE:
		sprintf(r, "SADB_HIP_ACQUIRE");
		break;
	case SADB_HIP_ADD:
		sprintf(r, "SADB_HIP_ADD");
		break;
	case SADB_MAX:
		sprintf(r, "SADB_MAX");
		break;
	default:
		sprintf(r, "UNKNOWN");
		break;
	}
}


/*
 * function check_pfkey_response_header()
 *
 * out:		Returns 1 if this message was found with no error,
 * 		returns < 0 with PF_KEY errno if found with error,
 * 		and returns 0 if this message does not match.
 *
 * Helper function for check_pfkey_response()
 */
int check_pfkey_response_header(char *buff, int expected_type, __u32 seqno)
{
	struct sadb_msg *pfkey_msg;
	pfkey_msg = (struct sadb_msg*)buff;

	/* XXX extra check because kernel is returning both types */
	if ((expected_type == SADB_X_SPDDELETE) && 
	    (pfkey_msg->sadb_msg_type == SADB_X_SPDDELETE2))
		expected_type = SADB_X_SPDDELETE2;
	
	if ((pfkey_msg->sadb_msg_version == 2) &&
	    (pfkey_msg->sadb_msg_type == expected_type) &&
	    (pfkey_msg->sadb_msg_seq == seqno)) {
		if (pfkey_msg->sadb_msg_errno == 0) {
			return(1);
		} else {
			return(-pfkey_msg->sadb_msg_errno);
		}
	}
	return(0);
}

/*
 * function check_pfkey_response()
 *
 * in:		expected_type = PFKEYv2 message type to check for
 * 		
 * out:		Returns 0 if response message was found or -1 on error.
 * 
 * Check for a kernel response to a PFKEYv2 message. If there are
 * SADB_HIP_ACQUIRE messages awaiting, they are dispatched.
 * All other messages not matching the expected_type are dropped.
 *
 * NOTE: only call this after sending a message, otherwise will hang on read()
 */
int check_pfkey_response(int expected_type, __u32 seqno)
{
	int err, len, r, done;
	char buff[1024];
	struct pfkey_buffer_entry *entry, *prev;
	fd_set read_fdset;
	struct timeval timeout;

	/* First look in the PF_KEY message buffer to see if the
	 * expected message was already read.
	 */
	prev = NULL;
	for (entry = pfkey_buffer; entry; entry = entry->next) {
		r = check_pfkey_response_header(entry->data,
						expected_type, seqno);
		if (r != 0) { /* match found */
			/* remove from buffer and return 0 or error */
			if (prev)
				prev->next = entry->next;
			else
				pfkey_buffer = entry->next;
			free(entry->data);
			free(entry);
			return( (r==1) ? 0 : r);
		}
		prev = entry;
		
	}

	/* Next read from the PF_KEY socket to find the expected 
	 * message, putting all the others into the pfkey buffer.
	 */
	done = FALSE;
	while (!done) {
		FD_ZERO(&read_fdset);
		FD_SET((unsigned)s_pfk, &read_fdset);
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000; /* we expect a response soon */
		err = select(s_pfk + 1, &read_fdset, NULL, NULL, &timeout);
		if (err <  0) {
			log_(WARN, "PF_KEY select() error: %s.\n", 
				strerror(errno));
			return(-1);
		} else if (err == 0) { /* timeout */
			done = TRUE;
		} else if (FD_ISSET(s_pfk, &read_fdset)) {
		/* read in the message */
			memset(buff, 0, sizeof buff);
#ifdef __WIN32__
			if ((len = recv(s_pfk, buff, sizeof(buff), 0)) < 0) {
#else
			if ((len = read(s_pfk, buff, sizeof buff)) < 0) {
#endif /* __WIN32__ */
				log_(WARN, "PF_KEY read() error: %s.\n",
				    strerror(errno));
				return(-1);
			}
			r = check_pfkey_response_header(buff, expected_type, 
							seqno);
			if (r != 0){ /* match found */
				/* return 0 or error */
				return( (r==1) ? 0 : r);
			} else { /* match not found, continue reading... */
				hip_add_pfkey_buffer(buff, len);
			}
		} else {
			log_(WARN, "Unknown PF_KEY socket activity.\n");
		}
	}
	
	return(-1);
}


/*
 * PF_KEY processing
 */
void hip_handle_pfkey(char* buff)
{
	struct sadb_msg *pfkey_msg;
	int err;
	char typestr[30];
	struct sockaddr_storage ss_src, ss_dst; /* for ACQUIREs */
	struct sockaddr *src = (struct sockaddr *)&ss_src;
	struct sockaddr *dst = (struct sockaddr *)&ss_dst;
	__u32 spi;				/* for EXPIREs */

	pfkey_msg = (struct sadb_msg *)&buff[0];
	pfkey_packet_type(pfkey_msg->sadb_msg_type, typestr);
	if (pfkey_msg->sadb_msg_errno) {
		log_(NORMT, "%s PFKEY message has errno=%d!\n",
		    typestr, pfkey_msg->sadb_msg_errno);
	}
	   
	switch(pfkey_msg->sadb_msg_type) {
	/*
	 * SADB_HIP_ACQUIRE triggers HIP exchange
	 */
	case SADB_HIP_ACQUIRE:
		memset(src, 0, sizeof(struct sockaddr_storage));
		memset(dst, 0, sizeof(struct sockaddr_storage));
		if (parse_acquire(buff, src, dst) < 0) {
			log_(NORMT, "Invalid SADB_HIP_ACQUIRE.\n");
			break;
		}
		hip_handle_acquire(src, dst);
		break;
	/*
	 * SADB_ADD/DELETE echoed by kernel after sadb_add()/sadb_delete()
	 */
	case SADB_ADD:
		log_(NORMT, "SA added.\n");
		break;
	case SADB_DELETE:
		log_(NORMT, "SA deleted.\n");
		break;
	/* 
	 * SADB_EXPIRE - connection lifetime expires, send UPDATE
	 */
	case SADB_EXPIRE:
		if ((err = parse_expire(buff, &spi)) < 0) {
			log_(NORMT, "Invalid SADB_EXPIRE.\n");
			break;
		}
		log_(NORMT, "SADB_EXPIRE: SA with SPI=0x%x has expired.\n",spi);
		hip_handle_expire(spi);
		break;
	/*
	 * SADB_HIP_PACKET - HIP control packet received from the UDP socket in
	 *                   the usermode ESP thread.
	 */
	case SADB_HIP_PACKET:
		hip_pfkey_to_hip(buff);
		break;
	default:
		log_(NORMT, "Received %s (%d) message from %s, ignoring...\n",
		    typestr, pfkey_msg->sadb_msg_type,
		    (pfkey_msg->sadb_msg_pid==0) ? S_PFK_PROCESS :
		    				  "other process");
		print_hex(buff, 100);
		break;
	} /* end switch */
}


/*
 * hip_handle_acquire()
 *
 * Trigger the HIP exchange based on src and dst. For user-mode, src and dst
 * are LSIs instead of IP addresses. To send an I1, you need at least a
 * destination IP address (opportunistic) and a HIT (if not opportunstic).
 */
void hip_handle_acquire(struct sockaddr *src, struct sockaddr *dst)
{
	hip_hit *hitp = NULL;
	hip_assoc* hip_a = NULL;
	hi_node *mine;
	hiphdr hiph;

#ifdef __UMH__
	/*
	 * When running in user-mode, LSIs appear in the ACQUIRE message
	 * instead of IP addresses.
	 */
	struct sockaddr_storage lsi, lsi6;
	int do_lsi=0;
	hip_hit newhit;

	/* check for LSI, replace with IP address */
	if (IS_LSI(dst)) {
		do_lsi = 1;
		memset(&lsi, 0, sizeof(struct sockaddr_storage));
		memcpy(&lsi, dst, SALEN(dst));
		memset(&newhit, 0, HIT_SIZE);
		hitp = &newhit;
		log_(NORMT, "Received ACQUIRE for LSI %s ", logaddr(dst));
		/*if (IS_LSI(src))
			log_(WARN, "Source address in ACQUIRE is not a LSI.\n");
			*/ /* may need HIP checksum rewrite? */
		if (hip_convert_lsi_to_peer(SA(&lsi), hitp, src, dst) < 0)
			return;
		if (IS_LSI(dst)) {
			log_(WARN, "no suitable peer address, ignoring.\n");
			return;
		}
	} else { /* dst is not an LSI */
#else /* __UMH__ */
	/* For non user-mode Linux, the ACQUIRE message already contains the
	 * peer's IP address, so we don't need extra lookups here.
	 *
	 * XXX DNS reverse lookup IP to obtain name, 
	 *     then lookup HIP record for HIT? 
	 */
	{
#endif /* __UMH__ */
		/* get HIT from IP address instead of from LSI */
		log_(NORMT, "Received ACQUIRE for IP %s ", logaddr(dst));
		hitp = hit_lookup(dst);
	}

	/* Where do we send the I1? */
	if ((hitp == NULL) && (!OPT.opportunistic)) {
		log_(NORM, "HIT not found, unable to send I1\n");
		return;
	}
	/* Create pseudo-HIP header for lookup */
	if ((mine = get_preferred_hi(my_hi_head)) == NULL) {
		log_(WARN, "No local identities to use.\n");
		return;
	}
	memcpy(hiph.hit_rcvr, mine->hit, HIT_SIZE);
	if (hitp == NULL) { /* Look for existing assoc. using addrs and HITs */
		memcpy(hiph.hit_sndr, &zero_hit, sizeof(hip_hit));
		hip_a = find_hip_association(dst, src, &hiph);
	} else { /* Look for existing association using HITs */
		memcpy(hiph.hit_sndr, hitp, sizeof(hip_hit));
		hip_a = find_hip_association2(&hiph);
	}
	if (hip_a && (hip_a->state > UNASSOCIATED) && 
	    (hip_a->state != CLOSING) && (hip_a->state != CLOSED)) {
		/* already have a HIP association for this HIT */
		log_(NORM, "association exists -- ignoring.\n");
		return;
	} else if (hip_a && ((hip_a->state == CLOSING) ||
			     (hip_a->state == CLOSED)) ) {
		log_(NORM, "association exists, creating another.\n");
		/* Spec says to create another incarnation here;
		 * we need to free the data structures to reuse.
		 * Do not change state from CLOSED or CLOSING */
		if (hip_a->peer_hi->dsa) hip_dsa_free(hip_a->peer_hi->dsa);
		if (hip_a->peer_hi->rsa) hip_rsa_free(hip_a->peer_hi->rsa);
		if (hip_a->opaque) free(hip_a->opaque);
		if (hip_a->rekey) free(hip_a->rekey);
		if (hip_a->peer_rekey)	free(hip_a->peer_rekey);
		unuse_dh_entry(hip_a->dh);
		if (hip_a->dh_secret) free(hip_a->dh_secret);
		hip_a->peer_hi->dsa = NULL;
		hip_a->peer_hi->rsa = NULL;
		hip_a->opaque = NULL;
		hip_a->rekey = hip_a->peer_rekey = NULL;
		hip_a->dh = NULL;
		hip_a->dh_secret = NULL;
	} else if (!hip_a) {
		/* Create another HIP association */
		log_(NORM, "creating new association.\n");
		hip_a = init_hip_assoc(mine, (const hip_hit*) &hiph.hit_sndr);
		if (!hip_a) {
			log_(WARN, "Unable to create association triggered by "
				   "ACQUIRE.\n");
			return;
		}
		hip_a->preserve_outbound_policy = TRUE;
	}
#ifdef __UMH__
	/* XXX skip this when using RVS? */
	if (do_lsi) {
		/* update SADB with LSI mapping */
		hit_to_sockaddr(SA(&lsi6), *hitp);
		update_lsi_mapping(dst, SA(&lsi), *hitp);
	}
#endif

	/* fill in addresses */
	memcpy(HIPA_SRC(hip_a), src, SALEN(src));
	hip_a->hi->addrs.if_index = is_my_address(src);
	make_address_active(&hip_a->hi->addrs);
	add_other_addresses_to_hi(hip_a->hi, TRUE);
	memcpy(HIPA_DST(hip_a), dst, SALEN(dst));
	memcpy(&(hip_a->peer_hi->hit), hiph.hit_sndr, sizeof(hip_hit));
	add_other_addresses_to_hi(hip_a->peer_hi, FALSE);

	/* use HIP over UDP unless disabled in conf file */
	if (!HCNF.disable_udp && (dst->sa_family == AF_INET)) {
		hip_a->udp = TRUE;
		/* this signals to hip_send() to perform UDP encapsulation */
		((struct sockaddr_in*)HIPA_DST(hip_a))->sin_port = \
							htons(HIP_UDP_PORT);
		/* TODO: IPv6 over UDP here */
	}

	log_hipa_fromto(QOUT, "Base exchange initiated", hip_a, TRUE, TRUE);
	print_hex(hip_a->peer_hi->hit, HIT_SIZE);

	/* Send the I1 */
	if (hip_send_I1(hitp, hip_a) > 0) {
		if ((hip_a->state != CLOSING) && (hip_a->state != CLOSED))
			set_state(hip_a, I1_SENT);
	}
}

/*
 * hip_convert_lsi_to_peer()
 *
 * Given a peer's LSI, try and find the peer's HIT and IP address,
 * along with a matching source IP address.
 *
 */
int hip_convert_lsi_to_peer(struct sockaddr *lsi, hip_hit *hitp, 
	struct sockaddr *src, struct sockaddr *dst)
{
	hi_node *peer_hi = NULL;
	int err, want_family = 0, dns_ok = TRUE;
	struct sockaddr addr;
	struct sockaddr_storage lsi_save;

	memset(hitp, 0, HIT_SIZE);
	
	/* 
	 * For 1.x.x.x IPv4 LSIs, we need to find a HIT
	 */
	if (lsi->sa_family == AF_INET) {
		/* lookup LSI locally (preconfigured entries or
		 * those cached from HIP DNS lookups)
		 */
		peer_hi = lsi_lookup(lsi);
		if (!peer_hi || hits_equal(peer_hi->hit, zero_hit)) {
			/* Peer doesn't exist locally or has an empty HIT.
			 * Do DHT lookup and adopt if opportunistic is enabled.
			 */
			log_(NORM, "(Doing HIT lookup using the LSI %s "
				"in the DHT...)\n", logaddr(lsi));
			memcpy(&lsi_save, lsi, SALEN(lsi));
			/* XXX FIXME this line destroys the lsi on win32... */
			err = hip_dht_lookup_hit(lsi, hitp, FALSE);
			if ( !OPT.opportunistic && (err < 0)) {
				log_(NORM, "(Cannot determine HIT for this "
					"LSI)\n");
				return(-1);
			}
			memcpy(lsi, &lsi_save, SALEN(&lsi_save));
			if (err == 0) {
				log_(NORM, "(HIT for LSI (%s) found in DHT)\n",
					logaddr(lsi));
			}
			/* Now we have a HIT, */
			if (peer_hi) {
				memcpy(peer_hi->hit, hitp, HIT_SIZE);
			} else { /* create a new peer entry */
				memset(&addr, 0, sizeof(struct sockaddr));
				addr.sa_family = AF_INET;
				add_peer_hit(*hitp, &addr);
				peer_hi = find_host_identity(peer_hi_head,
						*hitp);
				if (!peer_hi)
					return(-1);
				memcpy(&peer_hi->lsi, lsi, SALEN(lsi));
				peer_hi->addrs.addr.ss_family = 0;
				dns_ok = FALSE;
			}
		} else { /* valid peer_hi with non-zero HIT */
			memcpy(hitp, peer_hi->hit, HIT_SIZE);
		}
	/* 
	 * For IPv6, the 2001:10::/28 LSI *is* the HIT 
	 */
	} else if (dst->sa_family == AF_INET6) {
		memcpy(hitp, SA2IP(dst), HIT_SIZE);
		/* look for a peer context */
		peer_hi = find_host_identity(peer_hi_head, *hitp);
		if (!peer_hi) {
			if (!OPT.allow_any) {
				log_(WARN, "Peer HIT in ACQUIRE has not been "
				    "configured, dropping (try -a option)\n");
				return(-1);
			}
			/* create a new peer entry */
			memset(&addr, 0, sizeof(struct sockaddr));
			addr.sa_family = AF_INET;
			add_peer_hit(*hitp, &addr);
			peer_hi = find_host_identity(peer_hi_head, *hitp);
			peer_hi->addrs.addr.ss_family = 0;
			dns_ok = FALSE;
		}
		/* store the 32-bit LSI in lsi */
		memset(lsi, 0, sizeof(struct sockaddr_storage));
		if (VALID_FAM(&peer_hi->lsi)) {
			memcpy(lsi, &peer_hi->lsi, SALEN(&peer_hi->lsi));
		} else {
			lsi->sa_family = AF_INET;
			((struct sockaddr_in*)lsi)->sin_addr.s_addr = 
				HIT2LSI(*hitp);
			memcpy(&peer_hi->lsi, lsi, SALEN(lsi));
		}
			
	}

	if (!peer_hi) /* should not be reached */
		return(-1);

	/* 
	 * Look for peer's destination address from:
	 * 1. local conf (known_host_identities)
	 * 2. DNS lookup of name
	 * 3. DHT lookup using HIT
	 */
	if (!VALID_FAM(&peer_hi->addrs.addr)) { 
	/* peer has no address, try to fill it in */
		if (dns_ok && 
		    (add_addresses_from_dns(peer_hi->name, peer_hi) < 0)) {
			if ((add_addresses_from_dht(peer_hi, FALSE) < 0)) {
				log_(NORM, "(Peer address not found for %s)\n",
					peer_hi->name);
				add_addresses_from_dns(NULL, NULL);
				return(-1);
			}
		} else if (!dns_ok &&
			   (add_addresses_from_dht(peer_hi, FALSE) < 0)) {
			log_(NORM, "(Peer address not found for ");
			print_hex(*hitp, HIT_SIZE);
			log_(NORM, ")\n");
			return(-1);
		}
	}

	/* copy from peer_hi address list into dst by matching the address
	 * family from our preferred address  */
	if (VALID_FAM(&peer_hi->addrs.addr)) { 
		want_family = 0;
		if (get_addr_from_list(my_addr_head, want_family, src) >= 0)
			want_family = src->sa_family;
		/* try to match address family of our preferred address  */
		if (get_addr_from_list(&peer_hi->addrs, want_family, dst) < 0) {
			/* use any address family */
			if (get_addr_from_list(&peer_hi->addrs, 0, dst) < 0) {
				log_(NORM,"(Peer address not found (2) %s)\n",
					dns_ok ? peer_hi->name : "");
			}
			/* XXX fix this for Windows -- IPv4 only
			 * could do BEX for IPv6 and update to v4 addr?
			 */
		}
	}

	/* my preferred address becomes src (instead of LSI) */
	if (get_addr_from_list(my_addr_head, dst->sa_family, src) < 0) {
		log_(NORM, "(Could not find a source address from the same "
			"address family (peer family=%d))\n", dst->sa_family);
		return(-1);
	}
	return(0);
}


/*
 * hip_handle_expire()
 *
 * Given the SPI of the expired SA, locate HIP association and perform
 * a rekey.
 */
void hip_handle_expire(__u32 spi)
{
	int i, err;
	hip_assoc* hip_a = NULL;

	/* Find an ESTABLISHED HIP association using the SPI */
	for (i=0; i < max_hip_assoc; i++) {
		hip_a = &hip_assoc_table[i];
		if ((hip_a->spi_in != spi) && (hip_a->spi_out != spi))
			continue;
		break;
	}
	if ((!hip_a) || (i >= max_hip_assoc))
		return; /* not found */

	if (hip_a->rekey) // XXX does this work for all cases?
		return; /* already rekeying */
	
	/*
	 * Initiate rekey
	 */
	log_(NORM, "Initiating rekey for association %d.\n", i);
	if (build_rekey(hip_a) < 0) {
		log_(WARN, "hip_handle_expire() had problem building rekey "
			"structure for rekey initiation.\n");
		return;
	}
	if ((err = hip_send_update(hip_a, NULL, NULL)) > 0) {
		log_(NORM, "Sent UPDATE (%d bytes)\n", err);
	} else {
		log_(NORM, "Failed to send UPDATE: %s.\n", strerror(errno));
	}
}

/*
 * hip_pfkey_to_hip()
 *
 * Convert HIP control packet from PFKEY message to a HIP packet and pass it
 * to the parser.
 *
 */
void hip_pfkey_to_hip(char *buff)
{
	struct sadb_msg *pfkey_msg = (struct sadb_msg *) buff;
	struct sockaddr_storage ss_addr_from;
	struct sockaddr *src = SA(&ss_addr_from);
	struct ip *iph;
	udphdr *udph;
	int length;
	int family = AF_INET; /* TODO: detect family from ip header to
				       support IPv6 */
#ifndef   __WIN32__
	struct msghdr msg;
	struct iovec iov;
#endif /* __WIN32__ */

	length = (pfkey_msg->sadb_msg_len * sizeof(__u64));
	length -= sizeof(struct sadb_msg);

	/* TODO: IPv6 over UDP here */
	iph = (struct ip *) &buff[sizeof(struct sadb_msg)];
	udph = (udphdr *) (iph + 1);

	memset(src, 0, sizeof(struct sockaddr_storage));
	src->sa_family = family;
	((struct sockaddr_in *)src)->sin_addr = iph->ip_src;
	((struct sockaddr_in *)src)->sin_port = udph->src_port;

#ifdef   __WIN32__
	hip_handle_packet(&buff[sizeof(struct sadb_msg)], length, src);
#else /* __WIN32__ */
	msg.msg_name = src;
	msg.msg_namelen = sizeof(struct sockaddr_storage);
	msg.msg_iov = &iov;
	msg.msg_iov->iov_base = &buff[sizeof(struct sadb_msg)];
	msg.msg_iovlen = length;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	hip_handle_packet(&msg, length, AF_INET);
#endif /* __WIN32__ */
}

/*
 * hip_check_pfkey_buffer()
 *
 * Look for PF_KEY messages that were skipped (in order to receive some other
 * PF_KEY response).
 */
void hip_check_pfkey_buffer()
{
	struct pfkey_buffer_entry *entry, *next;

	entry = pfkey_buffer; /* static variable */
	while (entry) {
		next = entry->next; /* allows us to free() entry */
		/* handle the PF_KEY message */
		if (entry->data)
			hip_handle_pfkey(entry->data);

		/* remove it from the buffer */
		if (entry == pfkey_buffer)
			pfkey_buffer = next;
		free(entry->data);
		entry->data = NULL;
		free(entry);
		
		entry = next;
		/* Or we could break here and allow processing during
		 * the next select() timeout.
		 */
	}

}


void hip_add_pfkey_buffer(char *data, int len)
{
	struct pfkey_buffer_entry *entry, *newentry;
	if (!data || !len)
		return;

	/* make a copy of data in a new entry */
	newentry = (struct pfkey_buffer_entry*)
			malloc(sizeof(struct pfkey_buffer_entry));
	if (!newentry) {
		log_(WARN, "hip_add_pfkey_buffer: malloc error!\n");
		return;
	}
	memset(newentry, 0, sizeof(struct pfkey_buffer_entry));
	newentry->data = (char*)malloc(len);
	if (!newentry->data) {
		log_(WARN, "hip_add_pfkey_buffer: malloc error (2)!\n");
		return;
	}
	memcpy(newentry->data, data, len);
	newentry->next = NULL;

	/* add the new entry to the buffer */
	if (!pfkey_buffer)
		pfkey_buffer = newentry;
	else {
		for (entry = pfkey_buffer; entry->next; entry = entry->next);
		entry->next = newentry;
	}	
}

