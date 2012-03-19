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
 *  \file  hip_types.h
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *		Tom Henderson, <thomas.r.henderson@boeing.com>
 *
 *  \brief  Data type definitions for the HIP protocol.
 *
 */

#ifndef _HIP_TYPES_H_
#define _HIP_TYPES_H_

/* XXX clean up type portability */
#if defined (__MACOSX__)
#include <mac/mac_types.h>
#elif defined (__WIN32__)
#include <win32/types.h>
#else /* Linux */
#include <asm/types.h>
#endif

#ifdef __MACOSX__
#include <sys/types.h>
#include <sys/time.h>
#endif
#ifdef __WIN32__
#include <winsock2.h>
#else
#include <sys/socket.h> /* sockaddr */
#include <netinet/in.h>
#endif
#include <sys/types.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <time.h>

#include <hip/hip_proto.h>

#ifdef HIP_VPLS
#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3]
#endif

/*
 * Implementation configuration options
 */
#define HIP_CONF_FILENAME       "hip.conf"
#define HIP_MYID_FILENAME       "my_host_identities.xml"
#define HIP_KNOWNID_FILENAME    "known_host_identities.xml"
#define HIP_REG_FILENAME        "registered_host_identities.xml"
#define HIP_PUB_PREFIX          ""
#define HIP_PUB_SUFFIX          "_host_identities.pub.xml"

#define HIP_LOCK_FILENAME       "hip.pid"
#define HIP_LOG_FILENAME        "hip.log"

/*
 * Implementation limits
 */
#define MAX_HITS 255
#define MAX_CONNECTIONS MAX_HITS
#define MAX_OPAQUE_SIZE 255 /* how many bytes we may echo in response */
#define MAX_HI_NAMESIZE 255 /* number of bytes for HI Domain Identifier */
#define MAX_HI_BITS 2048 /* number of bits of largest HI accepted - this
                          * may limit the time spent w/ DSA verification */
#define MAX_LOCATORS 8  /* number of LOCATORs accepted in an UPDATE message */

#define MAX_REGISTRATIONS 1024
#define MAX_REGISTRATION_TYPES 8 /* number of registration services */
#ifdef HIP_VPLS
#define MAX_LEGACY_HOSTS 255 /* how many legacy hosts can attached to endbox */
#endif /* HIP_VPLS */
#define MAX_MR_CLIENTS MAX_CONNECTIONS /* Number of mobile router clients */

/*
 * IPsec-related constants
 */
#define DSA_PRIV 20 /* Size in bytes of DSA private key and Q value */
#define HIP_KEY_SIZE 24 /* Must be large enough to hold largest possible key */
#define HIP_DSA_SIG_SIZE 41 /* T(1) + R(20) + S(20)  from RFC 2536 */
#define MAX_SIG_SIZE 512 /* RFC 3110 4096-bits max RSA length */
#define NUMKEYS 8 /* HIP, HMAC, HIP, HMAC, ESP, AUTH, ESP, AUTH */
#define KEYMAT_SIZE (4 * NUMKEYS * HIP_KEY_SIZE) /* 768 bytes, enough space for
                                                  *  32 ESP keys */
#define MAX_CERT_LEN 128 /* max lengh of a certificate URL */
/* 3DES keys = 192 bits, 24 bytes; SHA-1 keys = 160 bits, 20 bytes.
 * We need 4 3DES and 2 SHA for our 6 keys, 136 bytes, so 144 is enough.
 */

/*
 * Protocol constants
 */
#define HIP_RES_SHIM6_BITS 0x01


#define H_PROTO_UDP 17


/*
 * Miscellaneous constants and enums
 */
#define TRUE 1
#define FALSE 0
/*
 * #define UNKNOWN -1
 */
#define SPI_RESERVED 255
#define HIP_ALIGN 4
#define R1_CACHE_SIZE 8
#define ACCEPTABLE_R1_COUNT_RANGE 2
#ifndef HIP_UPDATE_BIND_CHECKS
#define HIP_UPDATE_BIND_CHECKS 5
#endif

/* Messages from the ESP input/output thread to hipd */
typedef enum {
  ESP_ACQUIRE_LSI = 1,
  ESP_EXPIRE_SPI,
  ESP_UDP_CTL,
  ESP_ADDR_LOSS,
} ESP_MESSAGES;

typedef struct _espmsg {
  __u8 message_type;
  __u32 message_data;
} espmsg;

/* Unoffical Registration states */

typedef enum {
  REG_OFFERED,
  REG_REQUESTED,
  REG_SEND_RESP,
  REG_GRANTED,
  REG_SEND_FAILED,
  REG_FAILED,
  REG_SEND_CANCELLED,
  REG_CANCELLED
} REG_STATES;

/* Official Failure Codes */

typedef enum {
  REG_FAIL_REQ_ADD_CRED = 0,
  REG_FAIL_TYPE_UNAVAIL
} REQ_FAILURE_CODES;

/*
 * Macros
 */
#define DBG(x) x /* Debugging */
#define TDIFF(a, b) ((a).tv_sec - (b).tv_sec) /* Time diff in seconds */

/* get pointer to IP from a sockaddr
 *    useful for inet_ntop calls     */
#define SA2IP(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? \
  (__u8*)&((struct sockaddr_in*)x)->sin_addr : \
  (__u8*)&((struct sockaddr_in6*)x)->sin6_addr
/* get socket address length in bytes */
#define SALEN(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)
/* get IP address length in bytes */
#define SAIPLEN(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? 4 : 16
/* get (__u16) port from socket address */
#define SA2PORT(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? \
  ((struct sockaddr_in*)x)->sin_port : \
  ((struct sockaddr_in6*)x)->sin6_port
/* cast to sockaddr */
#define SA(x) ((struct sockaddr*)x)

/* boolean to text yes/no */
#define yesno(x) x ? "yes" : "no"

/* Host Identity Tag is 128 bits long */
#define HIT_SIZE 16
/* The below prefix applies to the uppermost 28 bits only (RFC 4843) */
#define HIT_PREFIX_SHA1_32BITS 0x20010010
/* convert lower 24-bits of HIT to LSI */
#define HIT2LSI(a) (0x01000000L | \
                    ((a[HIT_SIZE - 3] << 16) + \
                     (a[HIT_SIZE - 2] << 8) + (a[HIT_SIZE - 1])))

/* compute the exponent of registration lifetime */
#define YLIFE(x) ((float)x - (float)64) / (float)8

/*
 * typedefs
 */
typedef __u8 hip_hit[HIT_SIZE];      /* 16-byte (128 bit) Host Identity Tag */


#ifdef __WIN32__
typedef HANDLE hip_mutex_t;
typedef HANDLE hip_cond_t; /* not implemented for WIN32 */
#else
typedef pthread_mutex_t hip_mutex_t;
typedef pthread_cond_t hip_cond_t;
#endif

#define HIP_KEEPALIVE_TIMEOUT 20

/*
 * UDP header, used for UDP encapsulation
 */
typedef struct _udphdr {
  __u16 src_port;
  __u16 dst_port;
  __u16 len;
  __u16 checksum;
} udphdr;

/*
 * HIP header
 * This HIP protocol header defines the structure of HIP packets.
 */
typedef struct _hiphdr {
  __u8 nxt_hdr;                /* payload protocol            */
  __u8 hdr_len;                 /* header length               */
  __u8 packet_type;             /* packet type                 */

#if defined(__MACOSX__) && defined(__BIG_ENDIAN__)
  __u8 version : 4,res : 4;       /* Endian - not OSX specific */
#else
  __u8 res : 4,version : 4;       /* version, reserved        */
#endif
  __u16 checksum;               /* checksum                    */
  __u16 control;                /* control                     */
  hip_hit hit_sndr;             /* Sender's Host Identity Tag  */
  hip_hit hit_rcvr;             /* Receiver's Host Identity Tag */
  /* HIP TLV parameters follow ...  */
} hiphdr;

/*
 * HIP Cookie
 */
typedef struct _hipcookie {
  __u8 k;
  __u8 lifetime;
  __u16 opaque;
  __u64 i __attribute__ ((packed));
} hipcookie;

struct key_entry {
  int type;
  int length;
  __u8 key[HIP_KEY_SIZE];
};

struct rekey_info {
  __u32 update_id;              /* to be ACKed                  */
  __u32 new_spi;                /* SPI that will be adopted	*/
  __u16 keymat_index;           /* keymat index			*/
  __u8 need_ack;       /* set to FALSE when update_id has been ACKed */
  __u8 dh_group_id;             /* new DH group given by peer	*/
  DH *dh;                       /* new DH given by the peer	*/
  struct timeval rk_time;       /* creation time, so struct can be freed */
};

/* timers for tracking loss multihoming state */
struct multihoming_info {
  struct timeval mh_time;               /* time since we are in multi-h. state*/
  struct timeval mh_last_loss;          /* time of last loss report */
  struct sockaddr_storage mh_addr;       /* address having reported loss */
};

/*
 * HIP Packet Entry
 */
struct hip_packet_entry {
  __u8 *packet;
  int len;
  struct timeval xmit_time;
  __u32 retransmits;
  struct sockaddr_storage dst;       /* for address checks */
};

/*
 * Registration types
 */
struct reg_info {
  __u8 type;
  int state;
  struct timeval state_time;
  __u8 failure_code;
  __u8 lifetime;
  struct reg_info *next;
};

struct reg_entry {
  int number;
  struct reg_info *reginfos;
  __u8 min_lifetime;
  __u8 max_lifetime;
};

/*
 * HIP association entry
 *
 */
typedef struct _hip_assoc {
  /* Identities */
  struct _hi_node *hi;
  struct _hi_node *peer_hi;
  /* Misc. state variables */
  int state;
  struct timeval state_time;
  struct timeval use_time;
  __u64 used_bytes_in;
  __u64 used_bytes_out;
  __u32 spi_in;
  __u32 spi_out;
  __u32 spi_nat;
  hipcookie cookie_r;
  __u64 cookie_j;
  struct hip_packet_entry rexmt_cache;
  struct opaque_entry *opaque;
  struct reg_entry *regs;         /* registrations with registrar or client */
  struct rekey_info *rekey;       /* new parameters to use after REKEY	*/
  struct rekey_info *peer_rekey;       /* peer's REKEY data from UPDATE */
  struct _tlv_from *from_via;       /* including FROM in I1 or VIA RVS in R1 */
  struct multihoming_info *mh;       /* state for loss multihoming */
  /* Other crypto */
  __u16 hip_transform;
  __u16 esp_transform;
  __u16 available_transforms;       /* bit mask used to flag available xfrms */
  __u8 dh_group_id;
  DH *dh;
  DH *peer_dh;          /* needed for rekeying */
  __u8 *dh_secret;       /* without packing, these cause memset segfaults! */
  __u16 keymat_index;
  __u16 mr_keymat_index;
  __u8 keymat[KEYMAT_SIZE];
  struct key_entry keys[NUMKEYS];
  struct key_entry mr_key;
  __u8 preserve_outbound_policy;
  __u8 udp;
#ifdef __MACOSX__
  __u16 ipfw_rule;
#endif
} hip_assoc;
#define HIPA_SRC(h) ((struct sockaddr*)&h->hi->addrs.addr)
#define HIPA_DST(h) ((struct sockaddr*)&h->peer_hi->addrs.addr)
#define HIPA_SRC_LSI(h) ((struct sockaddr*)&h->hi->lsi)
#define HIPA_DST_LSI(h) ((struct sockaddr*)&h->peer_hi->lsi)

/*
 * list of struct sockaddrs
 */
typedef struct _sockaddr_list
{
  struct _sockaddr_list *next;
  struct sockaddr_storage addr;       /* 128 bytes, enough to store any size */
  int if_index;         /* link index */
  int lifetime;         /* address lifetime in seconds*/
  int status;           /* status from enum ADDRESS_STATES */
  int preferred;        /* set to TRUE if it's a new pending preferred addr */
  __u32 nonce;          /* random value for address verification */
  struct timeval creation_time;
} sockaddr_list;

/*
 * R1 Cache
 */
typedef struct _r1_cache_entry
{
  /* the precomputed R1 packet */
  __u8 *packet;
  int len;
  /* stored cookie solutions */
  hipcookie *current_puzzle;        /* the cookie that is in packet */
  hipcookie *previous_puzzle;       /* old cookie */
  /* the DH context used in the R1 */
  struct _dh_cache_entry *dh_entry;
  /* time of entry creation */
  struct timeval creation_time;
} r1_cache_entry;

/* For reference:  struct DSA definition from openssl/dsa.h */
/*
 * struct dsa_st {
 *
 *      * This first variable is used to pick up errors where
 *      * a DSA is passed instead of of a EVP_PKEY *
 *       int pad;
 *       int version;
 *       int write_params;
 *       BIGNUM *p;
 *       BIGNUM *q;      * == 20 *
 *       BIGNUM *g;
 *
 *       BIGNUM *pub_key;  * y public key *
 *       BIGNUM *priv_key; * x private key *
 *
 *       ... (plus some other fields not used in HIP)
 */

typedef struct _hi_node {
  struct _hi_node *next;
  hip_hit hit;
  struct sockaddr_storage lsi;

  hip_mutex_t     *rvs_mutex;       /* Sync for DNS rvs resolving threads */

  /*
   * Do not try to contact the node until the
   * RVS servers are resolved.
   */
  hip_cond_t      *rvs_cond;
  int             *rvs_count;       /* Number of RVS DNS petitions still to
                                     * resolve */
  int             *copies;       /* Number of copies of the mutex structures */

  /*
   * List of hostnames of all RVS servers as received from the
   * DNS server.
   * (Double zero ended list)
   */
  char **rvs_hostnames;

  /*
   * List of IP addresses corresponding to the RVS hostnames.
   * Each hostname can be resolved to multiple addresses or
   * to none, so there cannot be direct 1-1 reationship between
   * RVS hostnames and addresses.
   */
  struct _sockaddr_list **rvs_addrs;

  /*
   * IP address is needed to select a HIT corresponding to
   * an IP address.  This value needs update upon readdress.
   * Only the first entry of addrs is used for hip_assoc,
   * while the list addrs->next is populated when building the
   * HI tables.
   */
  hip_mutex_t addrs_mutex;       /* provide DHT thread synchronization */
  struct _sockaddr_list addrs;
  /* Key data */
  int size;                     /* Size in bytes of the Host Identity	*/
  DSA *dsa;                     /* HI in DSA format			*/
  RSA *rsa;                     /* HI in RSA format			*/
  struct _r1_cache_entry r1_cache[R1_CACHE_SIZE];       /* the R1 cache	*/
  __u64 r1_gen_count;           /* R1 generation counter		*/
  __u32 update_id;              /* this host's Update ID		*/
  /* Options */
  char algorithm_id;
  char anonymous;
  char allow_incoming;
  char skip_addrcheck;
  char name[MAX_HI_NAMESIZE];
  int name_len;                 /* use this instead of strlen()		*/
} hi_node;

#ifdef HIP_VPLS
struct peer_node
{
  hip_hit hit;
  int size;       /* Size in bytes of the Host Identity   */
  __u64 r1_gen_count;
  char algorithm_id;
  char anonymous;
  char allow_incoming;
  char skip_addrcheck;
  char name[MAX_HI_NAMESIZE];
  struct _sockaddr_list **rvs_addrs;
};
#endif /* HIP_VPLS */

/* DH Cache
 */
typedef struct _dh_cache_entry
{
  struct _dh_cache_entry *next;         /* the cache is a linked-list   */
  __u8 group_id;                        /* can have various group_ids   */
  DH *dh;                               /* the Diffie-Hellman context	*/
  __u8 is_current;                      /* if this is the latest DH context
                                         *  for this group_id, then TRUE */
  int ref_count;        /* number of hip_assoc that point to this entry */
  struct timeval creation_time;         /* determines age */
} dh_cache_entry;

/* Opaque Data
 */
struct opaque_entry
{
  __u16 opaque_len;
  __u8 opaque_data[MAX_OPAQUE_SIZE];
  __u8 opaque_nosig;
};

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

/*
 * TLV parameters
 */

typedef struct _tlv_head
{
  __u16 type;
  __u16 length;
} tlv_head;

typedef struct _tlv_esp_info
{
  __u16 type;
  __u16 length;
  __u16 reserved;
  __u16 keymat_index;
  __u32 old_spi;
  __u32 new_spi;
} tlv_esp_info;

typedef struct _tlv_r1_counter
{
  __u16 type;
  __u16 length;
  __u32 reserved;
  __u64 r1_gen_counter;
} tlv_r1_counter;

typedef struct _tlv_puzzle
{
  __u16 type;
  __u16 length;
  hipcookie cookie;
} tlv_puzzle;

typedef struct _tlv_solution
{
  __u16 type;
  __u16 length;
  hipcookie cookie;
  __u64 j;
} tlv_solution;

typedef struct _tlv_diffie_hellman
{
  __u16 type;
  __u16 length;
  __u8 group_id;
  __u16 pub_len;
  __u8 pub[1];       /* variable length */
} __attribute__ ((packed)) tlv_diffie_hellman;

/* used for second DH public value */
typedef struct _tlv_diffie_hellman_pub_value
{
  __u8 group_id;
  __u16 pub_len;
  __u8 pub[1];       /* variable length */
} __attribute__ ((packed)) tlv_diffie_hellman_pub_value;

typedef struct _tlv_hip_transform
{
  __u16 type;
  __u16 length;
  __u16 transform_id;
} tlv_hip_transform;

typedef struct _tlv_esp_transform
{
  __u16 type;
  __u16 length;
  __u16 reserved;       /* LSB is E-bit */
  __u16 suite_id;
} tlv_esp_transform;

typedef struct _tlv_encrypted
{
  __u16 type;
  __u16 length;
  __u8 reserved[4];
  __u8 iv[8];             /* 64-bits for 3-DES and Blowfish */
  /* adjust for 128-bits if using AES */
  __u8 enc_data[1];       /* variable length */
} tlv_encrypted;

typedef struct _tlv_host_id
{
  __u16 type;
  __u16 length;
  __u16 hi_length;
  __u16 di_type_length;
  __u8 hi_hdr[4];
  /* for DSA:				for RSA:
   * __u8 hi_t;				__u8 e_len
   * __u8 hi_q[DSA_PRIV];			__u8 e[1] or __u8 e[3];
   * P, G, Y are here, variable		__u8 n[]; variable
   * length based on t (64 + 3*t)
   *
   * also DI is variable
   *
   */
} tlv_host_id;

typedef struct _tlv_cert
{
  __u16 type;
  __u16 length;
  __u8 cert_group;
  __u8 cert_count;
  __u8 cert_id;
  __u8 cert_type;
  __u8 certificate[1];          /* variable length */
} tlv_cert;

typedef struct _tlv_reg_info
{
  __u16 type;
  __u16 length;
  __u8 min_lifetime;
  __u8 max_lifetime;
  __u8 reg_type;
} tlv_reg_info;

typedef struct _tlv_reg_request
{
  __u16 type;
  __u16 length;
  __u8 lifetime;
  __u8 reg_type;
} tlv_reg_request;

typedef struct _tlv_reg_response
{
  __u16 type;
  __u16 length;
  __u8 lifetime;
  __u8 reg_type;
} tlv_reg_response;

typedef struct _tlv_reg_failed
{
  __u16 type;
  __u16 length;
  __u8 fail_type;               /* if 1, error in registration type */
  __u8 reg_type;
} tlv_reg_failed;


typedef struct _tlv_echo        /* response and request the same */
{
  __u16 type;
  __u16 length;
  __u8 opaque_data[1];          /* variable length */

} tlv_echo;

typedef struct _tlv_hmac
{
  __u16 type;
  __u16 length;
  __u8 hmac[20];
} tlv_hmac;

typedef struct _tlv_hip_sig
{
  __u16 type;
  __u16 length;
  __u8 algorithm;
  __u8 signature[0];       /* variable length */
} tlv_hip_sig;

typedef struct _tlv_seq
{
  __u16 type;
  __u16 length;
  __u32 update_id;
} tlv_seq;

typedef struct _tlv_ack
{
  __u16 type;
  __u16 length;
  __u32 peer_update_id;
} tlv_ack;

typedef struct _tlv_notify
{
  __u16 type;
  __u16 length;
  __u16 reserved;
  __u16 notify_type;
  __u8 notify_data[0];       /* variable length */
} tlv_notify;

typedef struct _locator
{
  __u8 traffic_type;
  __u8 locator_type;
  __u8 locator_length;
  __u8 reserved;
  __u32 locator_lifetime;
  __u8 locator[20];       /* 32-bit SPI + 128-bit IPv6/IPv4-in-IPv6 address */
} locator;
#define LOCATOR_PREFERRED 0x01
#define LOCATOR_TRAFFIC_TYPE_BOTH       0x00
#define LOCATOR_TRAFFIC_TYPE_SIGNALING  0x01
#define LOCATOR_TRAFFIC_TYPE_DATA       0x02
#define LOCATOR_TYPE_IPV6       0x00
#define LOCATOR_TYPE_SPI_IPV6   0x01

typedef struct _tlv_locator
{
  __u16 type;
  __u16 length;
  locator locator1[1];       /* one or more */
} tlv_locator;

typedef struct _tlv_from
{
  __u16 type;
  __u16 length;
  __u8 address[16];
} tlv_from;

typedef struct _tlv_via_rvs
{
  __u16 type;
  __u16 length;
  __u8 address[16];
} tlv_via_rvs;

typedef struct _tlv_proxy_ticket
{
  __u16 type;
  __u16 length;
  hip_hit mn_hit;
  hip_hit peer_hit;
  __u8 hmac_key[20];
  __u16 hmac_key_index;
  __u16 transform_type;
  __u16 action;
  __u16 lifetime;
  __u8 hmac[20];
} tlv_proxy_ticket;

typedef struct _tlv_auth_ticket
{
  __u16 type;
  __u16 length;
  __u16 hmac_key_index;
  __u16 transform_type;
  __u16 action;
  __u16 lifetime;
  __u8 hmac[20];
} tlv_auth_ticket;

/*
 * Struct to use in the set_lifetime_thread
 */
typedef struct _thread_arg {
  hiphdr hip_header;
  tlv_reg_response resp;
} thread_arg;


/*
 * Logging
 */
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
  QOUT,
} LOG_LEVELS;


/*
 * Global options
 */
struct hip_opt {
  int daemon;
  int debug;
  int debug_R1;
  int no_retransmit;
  int permissive;
  int opportunistic;
  int allow_any;
  struct sockaddr *trigger;
  int rvs;
  int mr;
  int mh;
};

struct name {
  char *name;
  struct name *next;
};

/*
 * Global configuration data
 */
struct hip_conf {
  __u32 cookie_difficulty;              /* 2 raised to this power	*/
  __u32 cookie_lifetime;                /* valid 2^(life-32) seconds	*/
  __u32 packet_timeout;                 /* seconds			*/
  __u32 max_retries;                    /* retransmissions		*/
  __u32 sa_lifetime;                    /* lifetime of SAs in seconds	*/
  __u32 loc_lifetime;                   /* lifetime of locators in seconds */
  char *preferred_hi;                   /* which HI to use		*/
  __u8 send_hi_name;                    /* flag to include DI (FQDN) in HI */
  __u8 dh_group;                        /* which DH group to propose in R1 */
  __u32 dh_lifetime;                    /* seconds until DH expires	*/
  __u32 r1_lifetime;                    /* seconds until an R1 is replaced */
  __u32 failure_timeout;                /* seconds to wait in state E_FAILED */
  __u32 msl;                            /* max segment lifetime */
  __u32 ual;                            /* seconds until unused SA expires */
  __u16 esp_transforms[SUITE_ID_MAX];       /* ESP transforms proposed in R1 */
  __u16 hip_transforms[SUITE_ID_MAX];       /* HIP transforms proposed in R1 */
  char *log_filename;                   /* non-default pathname for log	     */
  struct sockaddr_storage dht_server;       /* address+port of DHT server    */
  struct sockaddr_storage dns_server;       /* address of server w/HIP RRs   */
  __u8 disable_dns_lookups;             /* T/F disable DNS lookups	     */
  __u8 disable_notify;                  /* T/F disable sending NOTIFY packets */
  __u8 disable_dns_thread;              /* T/F disable DNS thread	     */
  __u8 disable_udp;                     /* T/F disable sending HIP over UDP */
  __u8 enable_bcast;                    /* T/F unicast packets from bcast LSI */
  char *master_interface;
  char *master_interface2;
  struct sockaddr_storage preferred;       /* preferred address */
  struct sockaddr_storage ignored_addr;       /* address to ignore */
  char *preferred_iface;                /* preferred interface name */
  struct name *outbound_ifaces;         /* if mobile router */
  __u8 save_known_identities;           /* save known_host_id's on exit */
  __u8 save_my_identities;              /* save my_host_id's on exit */
  __u8 reg_types[MAX_REGISTRATION_TYPES];       /* registration types offered */
  __u8 num_reg_types;                   /* number of registration types */
  __u8 min_reg_lifetime;                /* offered min registration lifetime */
  __u8 max_reg_lifetime;                /* offered max registration lifetime */
  __u8 peer_certificate_required;
#ifdef HIP_VPLS
  char *cfg_library;                    /* filename of configuration library */
  __u8 use_my_identities_file;          /* use my_host_identities file */
  __u32 endbox_hello_time;              /* frequency of endbox hellos on overlay
                                         */
  __u32 endbox_allow_core_dump;         /* whether or not to allow endbox to
                                         *core dump */
#endif /* HIP_VPLS */
  char conf_filename[255];
  char my_hi_filename[255];
  char known_hi_filename[255];
};

#endif /* _HIP_TYPES_H_*/


