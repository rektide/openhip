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
 *  hip_ipsec_win32.c
 *
 *  Authors:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
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
#include <ws2tcpip.h>		/* for sockaddrin_6		*/
#include <io.h>			/* read() */
#include <win32/types.h>
#else
#include <sys/types.h>
#include <arpa/inet.h>		/* inet_addr() 			*/
#include <sys/socket.h>		/* sock(), recvmsg(), etc       */
#include <unistd.h>		/* write() 			*/
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#else
#include <asm/types.h>
#endif /* __MACOSX__ */
#include <netinet/in.h>  	/* struct sockaddr_in, etc      */
#include <netinet/ip.h>  	/* struct iphdr                 */
#endif /* __WIN32__ */
#include <openssl/crypto.h>     /* OpenSSL's crypto library     */
#include <openssl/bn.h>		/* Big Numbers                  */
#include <openssl/dsa.h>	/* DSA support                  */
#include <openssl/dh.h>		/* Diffie-Hellman contexts      */
#include <openssl/sha.h>	/* SHA1 algorithms 		*/
#include <openssl/rand.h>	/* RAND_seed()                  */
#ifdef __UMH__
#include <win32/pfkeyv2.h>
#else
#include "/usr/src/linux/include/linux/pfkeyv2.h" /* PF_KEY_V2 support */
#endif
#include <hip/hip_types.h>
#include <hip/hip_funcs.h> /* SALEN() */
#include <hip/hip_globals.h>


#define IPSEC_PFKEYv2_ALIGN (sizeof(uint64_t) / sizeof(uint8_t))
#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))

/* 
 * Local function declarations
 */
int build_sa_ext(char *data, __u32 spi, __u8 state, __u8 auth, __u8 encrypt, __u32 flags);
int build_sa2_ext(char *data, __u32 mode);
int build_nat_port_ext(char *data, int type, __u16 port);
int build_lifetime_ext(char *data, int type, __u32 lifetime);
int build_address_ext(char *data, int type, struct sockaddr *addr);
int build_ident_ext(char *data, int type, struct sockaddr *addr);
int build_hit_ext(char *data, int type, uint16_t val);



int pfkey_send_hip_x1 (int sock, u_int type, u_int satype, u_int mode, 
	struct sockaddr *src, struct sockaddr *dst, 
	struct sockaddr *isrc, struct sockaddr *idst,
	u_int32_t spi,
	u_int32_t regid, u_int wsize, caddr_t key,
        u_int e_type, u_int e_keylen, u_int a_type, u_int a_keylen,
	u_int flags, u_int32_t l_alloc, u_int32_t l_bytes,
        u_int32_t l_addtime, u_int32_t l_usetime, u_int32_t seqno,
        u_int8_t l_natt_type, u_int16_t l_natt_sport,
	u_int16_t l_natt_dport, struct sockaddr *l_natt_oa, 
	u_int16_t hitmagic)
{ 
	int err, location=0, len=0;
	struct sadb_key *pfkey_key;
	struct sadb_msg *pfkey_msg;
	char buff[SADB_MSG_SIZE_ADD]; 

	location = 0;

	/* message header */
	pfkey_msg = (struct sadb_msg*) &buff[0];
	pfkey_msg->sadb_msg_version = PF_KEY_V2;
	pfkey_msg->sadb_msg_type = type; 
	pfkey_msg->sadb_msg_errno = 0;
 	pfkey_msg->sadb_msg_satype = satype;
	pfkey_msg->sadb_msg_len = -1; /* Will fill in below */
  	pfkey_msg->sadb_msg_reserved = 0;
  	pfkey_msg->sadb_msg_seq = seqno; 
	pfkey_msg->sadb_msg_pid = regid; /* OTB -- spinat */
	len = sizeof(struct sadb_msg);	    
	location += len;
	
	/* SA extension */
	location += build_sa_ext(&buff[location], spi, 
			SADB_SASTATE_MATURE, (__u8)a_type, (__u8)e_type, 0);
	/* SA2 extension (for mode) */
	if (mode) {
		location += build_sa2_ext(&buff[location], mode);
	}
	/* NAT source/destination port */
	if (l_natt_sport > 0)
		location += build_nat_port_ext(&buff[location],
					SADB_X_EXT_NAT_T_SPORT, l_natt_sport);
	if (l_natt_dport > 0)
		location += build_nat_port_ext(&buff[location],
					SADB_X_EXT_NAT_T_DPORT, l_natt_dport);

	/* lifetime extension */
	location += build_lifetime_ext(&buff[location], 
		    SADB_EXT_LIFETIME_HARD, l_addtime);
	
	/* source address extension */
	location += build_address_ext(&buff[location], SADB_EXT_ADDRESS_SRC, 
	    src);
		
	/* destination address extension */
	location += build_address_ext(&buff[location], SADB_EXT_ADDRESS_DST, 
	    dst);

	/* inner source/destination address extensions */
	if (isrc && idst) {
		location += build_ident_ext(&buff[location], 
					    SADB_EXT_IDENTITY_SRC, isrc);
		location += build_ident_ext(&buff[location],
					    SADB_EXT_IDENTITY_DST, idst);
	}

	/* authentication key extension */
	pfkey_key = (struct sadb_key*) &buff[location];
	memset(pfkey_key, 0, sizeof(struct sadb_key));	
	location += sizeof(struct sadb_key); /* 8 bytes */
	/* 
	 * With 20 byte  auth key, need 8 + 20 + 4 (pad) to
	 * end up on an 8 byte boundary 
	 */
	pfkey_key->sadb_key_len = eight_byte_align(sizeof(struct sadb_key) + 
	    a_keylen) / IPSEC_PFKEYv2_ALIGN;
	pfkey_key->sadb_key_exttype = SADB_EXT_KEY_AUTH;
	pfkey_key->sadb_key_bits = a_keylen * 8; /* 160 bits */
	pfkey_key->sadb_key_reserved = 0;
	/* key[enc_key|auth_key] */
	memcpy(&buff[location], &key[e_keylen], a_keylen);
	location += a_keylen;
	memset(&buff[location], 0, 4); /* padding to 24 bytes */
	location += 4;

	/* encryption key extension */
	pfkey_key = (struct sadb_key*) &buff[location];
	memset(pfkey_key, 0, sizeof(struct sadb_key));	
	location += sizeof(struct sadb_key);
	pfkey_key->sadb_key_len = eight_byte_align(sizeof(struct sadb_key) + 
	    e_keylen) / IPSEC_PFKEYv2_ALIGN;
	pfkey_key->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
	pfkey_key->sadb_key_reserved = 0;
	pfkey_key->sadb_key_bits = e_keylen*8;
	/* key[enc_key|auth_key] */
	memcpy(&buff[location], &key[0], e_keylen);
	location += e_keylen;

	/* insert ext hdr for hip_hit */
	location += build_hit_ext(&buff[location], SADB_EXT_HIT, hitmagic);
	/* 
	   implementations that don't support the hit ext hdr SHOULD
           ignore it.
        */
	/* complete the header */
	len = location;
	pfkey_msg->sadb_msg_len = len / IPSEC_PFKEYv2_ALIGN;

	/* send the SADB_ADD message to the kernel */
#ifdef __WIN32__
	err = send(sock, (char *)pfkey_msg, len, 0);
#else
	err = write(sock, (char *)pfkey_msg, len);
#endif

	if (err < 1) {
		fprintf(stderr, "sadb_add: pfkey write() error: %s.\n", 
			strerror(errno));
	}
	
	return(err);	
}

int pfkey_send_rea (int sock, u_int type, u_int satype, 
	struct sockaddr *src, struct sockaddr *dst, u_int32_t spi, 
	u_int e_type, u_int a_type, u_int flags, u_int32_t seqno)
{ 
	struct sadb_msg *pfkey_msg;
	int len, err=0, location;
	char buff[512];

	location = 0;
	memset(buff, 0, sizeof(buff));
		
	/* message header */
	pfkey_msg = (struct sadb_msg*)&buff[0];
	pfkey_msg->sadb_msg_version = PF_KEY_V2;
	pfkey_msg->sadb_msg_type = type; 
	pfkey_msg->sadb_msg_errno = 0;
	pfkey_msg->sadb_msg_satype = satype;
	pfkey_msg->sadb_msg_len = -1; /* set later */
	pfkey_msg->sadb_msg_reserved = 0;
	pfkey_msg->sadb_msg_seq = seqno;
	pfkey_msg->sadb_msg_pid = 0;
	location = sizeof(struct sadb_msg);	    

	/* SA extension */
	location += build_sa_ext(&buff[location], spi, 
			SADB_SASTATE_MATURE, (__u8)a_type, (__u8)e_type, 0);
	
	/* src address extension */
	location += build_address_ext(&buff[location], 
	    SADB_EXT_ADDRESS_SRC, src);
	
	/* dst address extension */
	location += build_address_ext(&buff[location], 
	    SADB_EXT_ADDRESS_DST, dst);

	len = location; 
	pfkey_msg->sadb_msg_len = len / IPSEC_PFKEYv2_ALIGN;
	
#ifdef __WIN32__
	err = send(sock, (char *)pfkey_msg, len, 0);
#else
	err = write(sock, pfkey_msg, len);
#endif

	if (err < 1) {
		fprintf(stderr, "sadb_readdress: PF_KEY write() error: %s.\n", 
		    strerror(errno));
		return(err);
	}
   
	return(0);
}

/* used to establish direction */
int pfkey_send_spdadd(int so, struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd, u_int proto,
	caddr_t pol, int policylen, u_int32_t seq)
{

	struct sadb_msg pfkey_msgh;
	struct sadb_x_policy *policy;
	int len, err=0, location;
	char buff[1024];

	location = 0;
	len = sizeof(struct sadb_msg);
	len += sizeof(struct sadb_sa);
	len += 2*sizeof(struct sadb_address);
	len += 2*PFKEY_ALIGN8(SALEN(src));
	memset(buff, 0, len);
		
	/* message header */
	pfkey_msgh.sadb_msg_version = PF_KEY_V2;
	pfkey_msgh.sadb_msg_type = SADB_X_SPDADD; 
	pfkey_msgh.sadb_msg_errno = 0;
	pfkey_msgh.sadb_msg_satype = SADB_SATYPE_ESP;
	pfkey_msgh.sadb_msg_len = len / IPSEC_PFKEYv2_ALIGN;
	pfkey_msgh.sadb_msg_reserved = 0;
	pfkey_msgh.sadb_msg_seq = seq;
	pfkey_msgh.sadb_msg_pid = 0;
	len = sizeof(struct sadb_msg);	    
	memcpy(&buff[0], &pfkey_msgh, len);
	location += len;

	/* source flow extension */
	location += build_address_ext(	&buff[location], 
					SADB_EXT_ADDRESS_SRC, src);
	
	/* destination flow extension */
	location += build_address_ext(	&buff[location], 
					SADB_EXT_ADDRESS_DST, dst);

	/* policy extension - already built by ipsec_set_policy() */
	policy = (struct sadb_x_policy *)&buff[location];
	memcpy(policy, pol, sizeof(struct sadb_x_policy));
	location += sizeof(struct sadb_x_policy);

#ifdef __WIN32__
	err = send(so, buff, location, 0);
#else
	err = write(so, buff, location);
#endif

	if (err < 1){
		fprintf(stderr, "sadb_add_policy: pfkey write() error: %s.\n", 
		    strerror(errno));
	}
  
	return(err);
}

int pfkey_send_spddelete(int so, struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd, u_int proto,
	caddr_t policy, int policylen, u_int32_t seq)
{
	/* This is currently a no-op function. */
	return(0);
}

int pfkey_send_delete(int so, u_int satype, u_int mode, 
				struct sockaddr *src, struct sockaddr *dst,
				u_int32_t spi)
{
	struct sadb_msg pfkey_msgh;
	int len, err=0, location;
	char buff[SADB_MSG_SIZE_DELETE]; /* 80 */

	location = 0;
	len = sizeof(struct sadb_msg);
	len += sizeof(struct sadb_sa);
	len += 2*sizeof(struct sadb_address);
	len += 2*sizeof(struct sockaddr);
	memset(buff, 0, len);
		
	/* message header */
	pfkey_msgh.sadb_msg_version = PF_KEY_V2;
	pfkey_msgh.sadb_msg_type = SADB_DELETE; 
	pfkey_msgh.sadb_msg_errno = 0;
	pfkey_msgh.sadb_msg_satype = satype;
	pfkey_msgh.sadb_msg_len = len / IPSEC_PFKEYv2_ALIGN;
	pfkey_msgh.sadb_msg_reserved = 0;
	pfkey_msgh.sadb_msg_seq = 0;
	pfkey_msgh.sadb_msg_pid = 0;
	len = sizeof(struct sadb_msg);	    
	memcpy(&buff[0], &pfkey_msgh, len);
	location += len;

	/* SA extension */
	location += build_sa_ext(&buff[location], spi, 0, 0, 0, 0);

	/* source flow extension */
	location += build_address_ext(&buff[location], 
	    SADB_EXT_ADDRESS_SRC, src);
	
	/* destination flow extension */
	location += build_address_ext(&buff[location], 
	    SADB_EXT_ADDRESS_DST, dst);
	
	/* send SADB_DELETE message to the kernel */
#ifdef __WIN32__
	err = send(so, buff, location, 0);
#else
	err = write(so, buff, location);
#endif

	if (err < 1){
		fprintf(stderr, "sadb_delete: pfkey write() error: %s.\n", 
		    strerror(errno));
	}
  
	return(err);
}

int pfkey_send_register(int so, u_int satype)
{
	struct sadb_msg pfkey_msgh;
	int len, err=0;

	memset(&pfkey_msgh, 0, sizeof(struct sadb_msg));

	/* build the PF_KEY message */
	pfkey_msgh.sadb_msg_version = PF_KEY_V2;
	pfkey_msgh.sadb_msg_type = SADB_REGISTER; 
	pfkey_msgh.sadb_msg_errno = 0;
 	pfkey_msgh.sadb_msg_satype = satype;
	pfkey_msgh.sadb_msg_len = sizeof(struct sadb_msg) / IPSEC_PFKEYv2_ALIGN;
  	pfkey_msgh.sadb_msg_reserved = 0;
  	pfkey_msgh.sadb_msg_seq = 0;
	pfkey_msgh.sadb_msg_pid = 0;
	len = sizeof(pfkey_msgh);

	/* send SADB_REGISTER message to the kernel */
#ifdef __WIN32__
	err = send(so, (char *)&pfkey_msgh, len, 0);
#else
	err = write(so, &pfkey_msgh, len);
#endif
	if (err < 1) {
		fprintf(stderr, "sadb_register: pfkey write() error: %s.\n", 
		    strerror(errno));
	}
		
	return(err);
}

int pfkey_send_getspi(int so, u_int satype, u_int mode,
	struct sockaddr *src, struct sockaddr *dst, u_int32_t min, 
	u_int32_t max, u_int32_t reqid, u_int32_t seq)
{
	int err, location=0, len=0;
	struct sadb_msg *pfkey_msg;
	struct sadb_spirange *spirange;
	char buff[256]; 

	location = 0;
		
	/* message header */
	pfkey_msg = (struct sadb_msg*) &buff[0];
	pfkey_msg->sadb_msg_version = PF_KEY_V2;
	pfkey_msg->sadb_msg_type = SADB_GETSPI; 
	pfkey_msg->sadb_msg_errno = 0;
	pfkey_msg->sadb_msg_satype = satype;
	pfkey_msg->sadb_msg_len = -1;
	pfkey_msg->sadb_msg_reserved = 0;
	pfkey_msg->sadb_msg_seq = seq; 
	pfkey_msg->sadb_msg_pid = 0;
	len = sizeof(struct sadb_msg);	    
	location += len;

	/* spirange extension */
	spirange = (struct sadb_spirange*) &buff[location];
	spirange->sadb_spirange_len = \
		(sizeof(struct sadb_spirange) / IPSEC_PFKEYv2_ALIGN);
	spirange->sadb_spirange_exttype = SADB_EXT_SPIRANGE;
	spirange->sadb_spirange_min = min;
	spirange->sadb_spirange_max = max;
	spirange->sadb_spirange_reserved = 0;
	location += sizeof(struct sadb_spirange);
	
	/* complete the header */
	len = location;
	pfkey_msg->sadb_msg_len = len / IPSEC_PFKEYv2_ALIGN;
	
	/* send the SADB_GET message to the kernel */
#ifdef __WIN32__
	err = send(so, (char *)pfkey_msg, len, 0);
#else
	err = write(so, (char *)pfkey_msg, len);
#endif

	if (err < 1) {
		fprintf(stderr, "sadb_getspi: pfkey write() error: %s.\n", 
		    strerror(errno));
	}
   
	return(err);
}

int pfkey_send_get(int so, u_int satype, u_int mode, 
	struct sockaddr *src, struct sockaddr *dst, u_int32_t spi)
{
	int err, location=0, len=0;
	struct sadb_msg *pfkey_msg;
	char buff[256]; 

	location = 0;
		
	/* message header */
	pfkey_msg = (struct sadb_msg*) &buff[0];
	pfkey_msg->sadb_msg_version = PF_KEY_V2;
	pfkey_msg->sadb_msg_type = SADB_GET; 
	pfkey_msg->sadb_msg_errno = 0;
	pfkey_msg->sadb_msg_satype = satype;
	pfkey_msg->sadb_msg_len = -1;
	pfkey_msg->sadb_msg_reserved = 0;
	pfkey_msg->sadb_msg_seq = 0; 
	pfkey_msg->sadb_msg_pid = 0;
	len = sizeof(struct sadb_msg);	    
	location += len;
	
	/* SA extension */
	location += build_sa_ext(&buff[location], spi, 
	    SADB_SASTATE_MATURE, 0, 0, 0);

	/* source address extension */
	location += build_address_ext(&buff[location], 
	    SADB_EXT_ADDRESS_SRC, src);
	
	/* destination address extension */
	location += build_address_ext(&buff[location], 
	    SADB_EXT_ADDRESS_DST, dst);
	
	/* complete the header */
	len = location;
	pfkey_msg->sadb_msg_len = len / IPSEC_PFKEYv2_ALIGN;
	
	/* send the SADB_GET message to the kernel */
#ifdef __WIN32__
	err = send(so, (char *)pfkey_msg, len, 0);
#else
	err = write(so, (char *)pfkey_msg, len);
#endif

	if (err < 1) {
		fprintf(stderr, "sadb_get: pfkey write() error: %s.\n", 
		    strerror(errno));
	}
   
	return(err);
}

int __ipsec_errcode;

const char *ipsec_strerror (void)
{
	return(0);
}

int ipsec_get_policylen (caddr_t policy)
{
	return(sizeof(struct sadb_x_policy));
}

caddr_t ipsec_set_policy (char *msg, int msglen)
{
	struct sadb_x_policy *policy;
	int len = sizeof(struct sadb_x_policy);

	if (msglen < 2)
		return NULL;

	policy = (struct sadb_x_policy*) malloc(len);
	memset(policy, 0, len);
	policy->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy->sadb_x_policy_len = (len / IPSEC_PFKEYv2_ALIGN); 
	
	/* direction: 2 == outgoing, 1 == incoming */
	if (strncmp(msg, "in", 2)==0) {
		policy->sadb_x_policy_dir = 1;
	} else {
		policy->sadb_x_policy_dir = 2;
	}

	return((caddr_t)policy);
}

/*****************************************
 *      Message extension builders       *
 *****************************************/

/*
 * build an address extension
 */
int build_address_ext(char *data, int type, struct sockaddr *addr) 
{
	struct sadb_address *pfkey_addr;
	int addr_len, len, plen;
	
	plen = (addr->sa_family == AF_INET) ? (sizeof(struct in_addr) << 3) :
						(sizeof(struct in6_addr) << 3);
	addr_len = SALEN(addr);

	pfkey_addr = (struct sadb_address*) data;
	pfkey_addr->sadb_address_len = PFKEY_ALIGN8(sizeof(struct sadb_address)
					+ addr_len) / IPSEC_PFKEYv2_ALIGN; 
	pfkey_addr->sadb_address_exttype = type; 
	pfkey_addr->sadb_address_proto = IPPROTO_ESP;
	pfkey_addr->sadb_address_prefixlen = plen; 
	pfkey_addr->sadb_address_reserved = 0; 
	len = sizeof(struct sadb_address);	    
	memcpy(&data[len], addr, addr_len);
	len += addr_len;

	return(PFKEY_ALIGN8(len));
}

/*
 * build an identity extension
 */
int build_ident_ext(char *data, int type, struct sockaddr *addr) 
{
	struct sadb_ident *pfkey_ident;
	int addr_len, len;
	
	addr_len = SALEN(addr);
	pfkey_ident = (struct sadb_ident*) data;
	pfkey_ident->sadb_ident_len = PFKEY_ALIGN8(sizeof(struct sadb_ident) +
					addr_len) / IPSEC_PFKEYv2_ALIGN;
	pfkey_ident->sadb_ident_exttype = type; 
	pfkey_ident->sadb_ident_type = 0;
	pfkey_ident->sadb_ident_reserved = 0;
	pfkey_ident->sadb_ident_id = 0;
	len = sizeof(struct sadb_ident);
	memcpy(&data[len], addr, addr_len);
	len += addr_len;

	return(PFKEY_ALIGN8(len));
}

/*
 * build SA extension
 */
int build_sa_ext(char *data, __u32 spi, __u8 state, __u8 auth, __u8 encrypt, __u32 flags) 
{
	struct sadb_sa *pfkey_sa;

	pfkey_sa = (struct sadb_sa*) data;
	pfkey_sa->sadb_sa_len = sizeof(struct sadb_sa) / IPSEC_PFKEYv2_ALIGN;
	pfkey_sa->sadb_sa_exttype = SADB_EXT_SA;
	pfkey_sa->sadb_sa_spi = spi; /* SPI is already in network byte order */
	pfkey_sa->sadb_sa_replay = 0;
	pfkey_sa->sadb_sa_state = state;
	pfkey_sa->sadb_sa_auth = auth;
	pfkey_sa->sadb_sa_encrypt = encrypt;
	pfkey_sa->sadb_sa_flags = flags; 
	
	return(sizeof(struct sadb_sa));
}

/*
 * build SA2 extension
 */
int build_sa2_ext(char *data, __u32 mode) 
{
	struct sadb_x_sa2 *pfkey_sa2;

	pfkey_sa2 = (struct sadb_x_sa2*) data;
	pfkey_sa2->sadb_x_sa2_len = sizeof(struct sadb_x_sa2) \
					/ IPSEC_PFKEYv2_ALIGN;
	pfkey_sa2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	pfkey_sa2->sadb_x_sa2_mode = (__u8)mode; /* this is all we care about */
	pfkey_sa2->sadb_x_sa2_reserved1 = 0;
	pfkey_sa2->sadb_x_sa2_reserved2 = 0;
	pfkey_sa2->sadb_x_sa2_sequence = 0;
	pfkey_sa2->sadb_x_sa2_reqid = 0;
	
	return(sizeof(struct sadb_x_sa2));
}

/*
 * build nat port extension
 */
int build_nat_port_ext(char *data, int type, __u16 port) 
{
	struct sadb_x_nat_t_port *pfkey_nat;

	pfkey_nat = (struct sadb_x_nat_t_port*) data;
	pfkey_nat->sadb_x_nat_t_port_len = sizeof(struct sadb_x_nat_t_port) \
						/ IPSEC_PFKEYv2_ALIGN;
	pfkey_nat->sadb_x_nat_t_port_exttype = (__u16)type;
	pfkey_nat->sadb_x_nat_t_port_port = htons(port);
	pfkey_nat->sadb_x_nat_t_port_reserved = 0;
	
	return(sizeof(struct sadb_x_nat_t_port));
}

/*
 * build lifetime extension
 */
int build_lifetime_ext(char *data, int type, __u32 lifetime)
{
	struct sadb_lifetime *pfkey_lifetime;

	pfkey_lifetime = (struct sadb_lifetime*) data;
	pfkey_lifetime->sadb_lifetime_len = sizeof(struct sadb_lifetime) / 
	    IPSEC_PFKEYv2_ALIGN;
	pfkey_lifetime->sadb_lifetime_exttype = type;
	pfkey_lifetime->sadb_lifetime_allocations = 0;
	pfkey_lifetime->sadb_lifetime_bytes = 0;
	pfkey_lifetime->sadb_lifetime_addtime = lifetime; 
	pfkey_lifetime->sadb_lifetime_usetime = 0;

	return(sizeof(struct sadb_lifetime));
}

/*
 *  * build hit extension  HIT_BITSIZE / 8
 */
int build_hit_ext(char *data, int type, uint16_t val)
{
	struct sadb_hit *pfkey_hit;

	pfkey_hit = (struct sadb_hit*) data;
	pfkey_hit->sadb_hit_len =  sizeof(struct sadb_hit)/IPSEC_PFKEYv2_ALIGN;
	pfkey_hit->sadb_hit_exttype  =  type;
	pfkey_hit->sadb_hit = val;
	return(sizeof(struct sadb_hit));
}
