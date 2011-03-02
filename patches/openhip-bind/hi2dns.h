/*
Copyright (c) 2006-2011, The Boeing Company.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
    * Neither the name of The Boeing Company nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _NET_HIP_H_
#define _NET_HIP_H_

#include <asm/types.h>
#include <sys/socket.h> /* sockaddr */
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <time.h>


/* 
 * Implementation configuration options 
 */
#ifndef __UMH__
#define HIP_CONF_FILENAME	"/etc/hip/hip.conf"
#define HIP_MYID_FILENAME	"/etc/hip/my_host_identities.xml"
#define HIP_KNOWNID_FILENAME	"/etc/hip/known_host_identities.xml"
#define HIP_LOCK_FILENAME	"/var/run/hip.pid"
#define HIP_LOG_FILENAME	"/var/log/hipd.log"
#else
#define HIP_CONF_FILENAME	"hip.conf"
#define HIP_MYID_FILENAME	"my_host_identities.xml"
#define HIP_KNOWNID_FILENAME	"known_host_identities.xml"
#define HIP_LOCK_FILENAME	"hip.pid"
#define HIP_LOG_FILENAME	"hipd.log"
#endif

/*
 * Implementation limits
 */
#define MAX_HI_NAMESIZE 255 /* number of bytes for HI Domain Identifier */
#define MAX_HI_BITS 2048 /* number of bits of largest HI accepted - this
			  * may limit the time spent w/ DSA verification */

/*
 * IPsec-related constants
 */
#define DSA_PRIV 20 /* Size in bytes of DSA private key and Q value */

/* 
 * Miscellaneous constants and enums 
 */
#define TRUE 1
#define FALSE 0

/* 
 * Macros  
 */
#define DBG(x) x /* Debugging */
#define TDIFF(a, b) ((a).tv_sec - (b).tv_sec) /* Time diff in seconds */

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
/* cast to sockaddr */
#define SA(x) ((struct sockaddr*)x)

/* boolean to text yes/no */
#define yesno(x) x ? "yes" : "no"

/* convert lower 24-bits of HIT to LSI */
#define HIT_SIZE 16
#define HIT_PREFIX_TYPE1_SHA1	0x40
#define HIT2LSI(a) ( 0x01000000L | \
		     ((a[HIT_SIZE-3]<<16)+(a[HIT_SIZE-2]<<8)+(a[HIT_SIZE-1])))


#define IS_LSI32(a) ((a & 0xFF) == 0x01)
#define IS_LSI(a) ( ( ((struct sockaddr_in*)a)->sin_family == AF_INET) && \
	 	    (IS_LSI32(((struct sockaddr_in*)a)->sin_addr.s_addr)))
				     

#define VALID_FAM(a) ( (((struct sockaddr*)a)->sa_family == AF_INET) || \
		       (((struct sockaddr*)a)->sa_family == AF_INET6) )

/*
 * typedefs
 */
typedef __u8 hip_hit [HIT_SIZE];     /* 16-byte (128 bit) Host Identity Tag */

/*
 * list of struct sockaddrs
 */
typedef struct _sockaddr_list
{
	struct _sockaddr_list *next;
	struct sockaddr_storage addr; /* 128 bytes, enough to store any size */
	int if_index; 	/* link index */
	int lifetime;	/* address lifetime in seconds*/
	int status;	/* status from enum ADDRESS_STATES */
	int preferred;	/* set to TRUE if it's a new pending preferred addr */
	__u32 nonce;	/* random value for address verification */
	struct timeval creation_time;
} sockaddr_list;

/* For reference:  struct DSA definition from openssl/dsa.h */
/*
 * struct dsa_st {
 * 
 *      * This first variable is used to pick up errors where
 *      * a DSA is passed instead of of a EVP_PKEY *
        int pad; 
        int version;
        int write_params;
        BIGNUM *p;
        BIGNUM *q;      * == 20 *
        BIGNUM *g;

        BIGNUM *pub_key;  * y public key *
        BIGNUM *priv_key; * x private key *

	... (plus some other fields not used in HIP)
*/

typedef struct _hi_node {
	struct _hi_node *next;
	hip_hit hit;
	struct sockaddr_storage lsi;
	/* 
	 * IP address is needed to select a HIT corresponding to
	 * an IP address.  This value needs update upon readdress.
	 * Only the first entry of addrs is used for hip_assoc,
	 * while the list addrs->next is populated when building the
	 * HI tables.
	 */
	pthread_mutex_t addrs_mutex; /* provide DHT thread synchronization */
	struct _sockaddr_list addrs;
	/* Key data */
	int size; 		/* Size in bytes of the Host Identity	*/
	DSA *dsa; 		/* HI in DSA format			*/
	RSA *rsa;		/* HI in RSA format			*/
	__u64 r1_gen_count; 	/* R1 generation counter		*/
	__u32 update_id; 	/* this host's Update ID		*/
	/* Options */
	char algorithm_id;
	char anonymous;
	char allow_incoming;
	char skip_addrcheck;
	char name[MAX_HI_NAMESIZE];
	int name_len;		/* use this instead of strlen()		*/
} hi_node;

typedef struct _pseudo_header6
{
	unsigned char src_addr[16];
	unsigned char dst_addr[16];
	__u32 packet_length;
	char zero[3];
	__u8 next_hdr;
} pseudo_header6;

typedef struct _pseudo_header
{
	unsigned char src_addr[4];
	unsigned char dst_addr[4];
	__u8 zero;
	__u8 protocol;
	__u16 packet_length;
} pseudo_header;


/* HI (signature) algorithms  */
enum {
	HI_ALG_RESERVED,
	HI_ALG_DSA = 3,
	HI_ALG_RSA = 5,
} HI_ALGORITHMS;
#define HIP_RSA_DFT_EXP RSA_F4 /* 0x10001L = 65537; 3 and 17 are also common */
#define HI_TYPESTR(a)  ((a==HI_ALG_DSA) ? "DSA" : \
			(a==HI_ALG_RSA) ? "RSA" : "UNKNOWN")

/* HI Domain Identifier types */
enum {
	DIT_NONE,	/* none included */
	DIT_FQDN,	/* Fully Qualified Domain Name, in binary format */
	DIT_NAI,	/* Network Access Identifier, binary, login@FQDN */
} HI_DIT;

typedef enum {
	D_DEFAULT,
	D_VERBOSE,
	D_QUIET,
} DEBUG_MODES;

typedef enum {
	NORM,
	NORMT,
	WARN,
	ERR,
#ifndef OUT /* Windows */
	OUT,
#endif
} LOG_LEVELS;

#endif /* _NET_HIP_H_ */
