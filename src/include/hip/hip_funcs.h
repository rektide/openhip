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
 * 		Definitions for the HIP protocol.
 *
 *  Version:	@(#)hip.h	1.5	08/12/04
 *
 *  Authors:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *		Tom Henderson, <thomas.r.henderson@boeing.com>
 *
 *
 */

#ifndef _HIP_FUNCS_H_
#define _HIP_FUNCS_H_

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


/* 
 * Macros  
 */
/* LSI functions */
#define IS_LSI32(a) ((a & 0xFF) == 0x01)
#ifdef __WIN32__
#define IN6_ARE_ADDR_EQUAL IN6_ADDR_EQUAL
#define IS_HIT(x) (( (ntohs(((struct in6_addr*)x)->s6_words[0]) & 0xFFFF) \
			== ((HIT_PREFIX_SHA1_32BITS >> 4) & 0xFFFF)) && \
		   ( (ntohs(((struct in6_addr*)x)->s6_words[1]) & 0xFFF0) \
		     	== ((HIT_PREFIX_SHA1_32BITS & 0xFFFF)) ) )
#elif defined (__MACOSX__)
#define IS_HIT(x) ( (ntohl(((struct in6_addr*)x)->__u6_addr.__u6_addr32[0]) \
                  & 0xFFFFFFF0L) == HIT_PREFIX_SHA1_32BITS )
#else /* Linux */
#define IS_HIT(x) ( (ntohl(((struct in6_addr*)x)->s6_addr32[0]) & 0xFFFFFFF0L) \
			== HIT_PREFIX_SHA1_32BITS )
#endif
#define SA2IP6(x) ( &((struct sockaddr_in6*)x)->sin6_addr )

#if defined(__MACOSX__) && defined(__BIG_ENDIAN__)
#define IS_LSI(a) ( ( ((struct sockaddr*)a)->sa_family == AF_INET) ? \
	 (IS_LSI32( ((struct sockaddr_in*)a)->sin_addr.s_addr >> 24)) : \
         (IS_HIT(  &((struct sockaddr_in6*)a)->sin6_addr) ) )
#else /* __MACOSX__ */
#define IS_LSI(a) ( (((struct sockaddr*)a)->sa_family == AF_INET) ? \
                   (IS_LSI32(((struct sockaddr_in*)a)->sin_addr.s_addr)) : \
                   (IS_HIT( &((struct sockaddr_in6*)a)->sin6_addr) )     )

#endif /* __MACOSX__ */
#define VALID_FAM(a) ( (((struct sockaddr*)a)->sa_family == AF_INET) || \
		       (((struct sockaddr*)a)->sa_family == AF_INET6) )


#define IN_LOOP(a) \
	(htonl(((struct sockaddr_in*)a)->sin_addr.s_addr) >> IN_CLASSA_NSHIFT \
	 ==  (INADDR_LOOPBACK >> IN_CLASSA_NSHIFT))
#define IN6_LOOP(a) \
	IN6_IS_ADDR_LOOPBACK( &((struct sockaddr_in6*)a)->sin6_addr )


/*
 *  Function prototypes
 */
/* hip_output.c */
int hip_send_I1(hip_hit* hit, hip_assoc *hip_a, int pos);
int hip_send_R1(struct sockaddr *src, struct sockaddr *dst, hip_hit *hiti,
			hi_node *hi, __u16 dst_port, int use_udp);
int hip_generate_R1(__u8 *data, hi_node *hi, hipcookie *cookie,
			dh_cache_entry *dh_entry);
int hip_send_I2(hip_assoc *hip_a);
int hip_send_R2(hip_assoc *hip_a);
int hip_send_update(hip_assoc *hip_a, struct sockaddr *newaddr,
			struct sockaddr *dstaddr, int use_udp);
int hip_send_update_proxy_ticket(hip_assoc *hip_mr, hip_assoc *hip_a,
			int use_udp);
int hip_send_close(hip_assoc *hip_a, int send_ack);
int hip_send_notify(hip_assoc *hip_a, int code, __u8 *data, int data_len);
int hip_send(__u8 *data, int len, struct sockaddr *src, struct sockaddr *dst,
			hip_assoc *hip_a, int retransmit, __u16 dst_port,
			int use_udp);
int hip_retransmit(hip_assoc *hip_a, __u8 *data, int len, struct sockaddr *src, 
			struct sockaddr *dst);
#ifdef __WIN32__
void udp_hip_keepalive (void *arg);
#else
void *udp_hip_keepalive (void *arg);
#endif
int build_tlv_hostid_len(hi_node *hi, int use_hi_name);
int build_tlv_hostid(__u8 *data, hi_node *hi, int use_hi_name);
int build_tlv_reg_info(__u8 *data, int location);
int build_tlv_reg_req(__u8 *data, int location, struct reg_entry *reg_offered);
int build_tlv_reg_resp(__u8 *data, int location,
			struct reg_entry *reg_requested);
int build_tlv_reg_failed(__u8 *data, int location,
			struct reg_entry *reg_requested);
int build_rekey(hip_assoc *hip_a);
int build_tlv_cert(__u8 *buff);

/* hip_input.c */
int hip_parse_hdr(__u8 *data, int len, struct sockaddr *src, 
			struct sockaddr *dst, __u16 family, hiphdr **hdr, int use_udp);
int hip_handle_I1(__u8 *data, hip_assoc *hip_a, struct sockaddr *src,
			struct sockaddr *dst, __u16 *dst_port, int use_udp);
int hip_handle_R1(__u8 *data, hip_assoc *hip_a, struct sockaddr *src,
			__u16 *dst_port, int use_udp);
int hip_handle_I2(__u8 *data, hip_assoc *hip_a, struct sockaddr *src,
			struct sockaddr *dst, __u16 *dst_port, int use_udp);
int hip_handle_R2(__u8 *data, hip_assoc *hip_a, __u16 *dst_port, int use_udp);
int hip_handle_update(__u8 *data, hip_assoc *hip_a, struct sockaddr *src, __u16 *dst_port, int use_udp);
int hip_handle_close(__u8 *data, hip_assoc *hip_a, __u16 *dst_port, int use_udp);
int hip_handle_notify(__u8 *buff, hip_assoc *hip_a, __u16 *dst_port, int use_udp);
int hip_finish_rekey(hip_assoc *hip_a, int rebuild, int use_udp);
int hip_handle_BOS(__u8 *data, struct sockaddr *src);
int hip_handle_CER(__u8 *data, hip_assoc *hip_a);
int rebuild_sa(hip_assoc *hip_a, struct sockaddr *newaddr, __u32 newspi, 
			int in, int peer, int use_udp);
int rebuild_sa_x2(hip_assoc *hip_a, struct sockaddr *newsrcaddr,
			struct sockaddr *newdstaddr, __u32 newspi, int in, int use_udp);
void handle_reg_info();
void handle_reg_request(char *data, int location);

/* hip_ipsec.c */
__u32 get_next_spi(hip_assoc *hip_a);
int sadb_add(struct sockaddr *src, struct sockaddr *dst, struct sockaddr *inner_src,
		struct sockaddr *inner_dst, hip_assoc *hip_a, __u32 spi, int direction);
/*int sadb_add(struct sockaddr *src, struct sockaddr *dst, hip_assoc *hip_a, 
			__u32 spi, int direction);*/
int sadb_readdress(struct sockaddr *src, struct sockaddr *dst, hip_assoc *hip_a,
			__u32 spi);
int sadb_add_policy(hip_assoc *hip_a, struct sockaddr *out_src, struct sockaddr *out_dst,
		struct sockaddr *in_src, struct sockaddr *in_dst, int direction);
/*int sadb_add_policy(struct sockaddr *src, struct sockaddr *dst, int direction);*/
int sadb_delete(hip_assoc *hip_a, struct sockaddr *src, struct sockaddr *dst, __u32 spi);
int sadb_delete_policy(struct sockaddr *src,struct sockaddr *dst,int direction);
int sadb_register(int satype);
int check_last_used(hip_assoc *hip_a, int direction, struct timeval *now);
int sadb_lsi(struct sockaddr *ip, struct sockaddr *lsi4, struct sockaddr *lsi6);
int delete_associations(hip_assoc *hip_a, __u32 old_spi_in, __u32 old_spi_out);
int flush_hip_associations();
int parse_acquire(char *data, struct sockaddr *src, struct sockaddr *dst);
int parse_expire(char *data, __u32 *spi);
void pfkey_packet_type(int type, char *r);
void hip_handle_pfkey(char *buff);
void hip_check_pfkey_buffer();
void update_lsi_mapping(struct sockaddr *dst, struct sockaddr *lsi,hip_hit hit);

/* hip_keymat.c */
int set_secret_key(unsigned char *key, hip_assoc *hip_a);
unsigned char *get_key(hip_assoc *hip_a, int type, int peer);
void compute_keys(hip_assoc *hip_a);
int compute_keymat(hip_assoc *hip_a);
int draw_keys(hip_assoc *hip_a, int draw_hip_keys, int keymat_index);
int draw_mr_key(hip_assoc *hip_a, int keymat_index);
int auth_key_len(int suite_id);
int enc_key_len(int suite_id);
int enc_iv_len(int suite_id);

/* hip_util.c */
int add_addresses_from_dns(char *name, hi_node *hi);
RSA *hip_rsa_new();
void hip_rsa_free(RSA *rsa);
DSA *hip_dsa_new();
void hip_dsa_free(DSA *dsa);
int save_identities_file(int);
int read_conf_file(char *);
int read_reg_file(void);
__u16 conf_transforms_to_mask();
hi_node *create_new_hi_node();
void append_hi_node(hi_node **head, hi_node *append);
int add_peer_hit(hip_hit peer_hit, struct sockaddr *peer_addr);
hi_node *find_host_identity(hi_node* hi_head, const hip_hit hitr);
int key_data_to_hi(const __u8 *data, __u8 alg, int hi_length, __u8 di_type, 
		   int di_length, hi_node **hi_p, int max_length);
hi_node *get_preferred_hi(hi_node *node);
int get_addr_from_list(sockaddr_list *list, int family,
		struct sockaddr *addr);
hip_assoc *init_hip_assoc(hi_node *my_host_id, const hip_hit *peer_hit);
void replace_hip_assoc(hip_assoc *a_old, hip_assoc *a_new);
int free_hip_assoc(hip_assoc *hip_a);
void free_hi_node(hi_node *hi);
void clear_retransmissions(hip_assoc *hip_a);
void set_state(hip_assoc *hip_a, int state);
hip_hit *hit_lookup(struct sockaddr*);
hi_node *lsi_lookup(struct sockaddr *lsi);
__u32 lsi_name_lookup(char *name, int name_len);
struct sockaddr *get_hip_dns_server();
__u32 receive_hip_dns_response(unsigned char *buff, int len);
int hits_equal(const hip_hit hit1, const hip_hit hit2);
void hit_to_sockaddr (struct sockaddr_in6 *sockad, hip_hit hit);
void print_cookie(hipcookie *cookie);
int str_to_addr(__u8 *data, struct sockaddr *addr);
int hit2hitstr(char *hit_str, const hip_hit hit);
int addr_to_str(struct sockaddr *addr, __u8 *data, int len);
int hex_to_bin(char *src, char *dst, int dst_len);
int solve_puzzle(hipcookie *cookie, __u64 *solution,
			hip_hit *hit_i, hip_hit *hit_r);
int validate_solution(const hipcookie *cookie_r, const hipcookie *cookie_i,
			hip_hit *hit_i, hip_hit *hit_r, __u64 solution);
int hi_to_hit(hi_node *hi, hip_hit hit);
int validate_hit(hip_hit hit, hi_node *hi);
void print_hex(const void *data, int len);
void print_binary(void *data, int len);
int compare_bits(const char *s1, int s1_len, const char *s2, int s2_len, 
			int numbits);
int compare_hits(hip_hit a, hip_hit b);
int compare_hits2(void const *s1, void const *s2);
int maxof(int num_args, ...);
int hip_header_offset(const __u8 *data);
int udp_header_offset(const __u8 *data);
__u16 checksum_udp_packet(__u8 *data, struct sockaddr *src, struct sockaddr *dst);
void hip_packet_type(int type, char *r);
void print_usage(void);
__u16 checksum_packet(__u8 *data, struct sockaddr *src, struct sockaddr *dst);
__u16 checksum_magic(const hip_hit *i, const hip_hit *r);
int tlv_length_to_parameter_length(int length);
int eight_byte_align(int length);
hip_assoc* find_hip_association(struct sockaddr *src, struct sockaddr *dst, 
			hiphdr* hiph);
hip_assoc* find_hip_association2(hiphdr* hiph);
hip_assoc* find_hip_association3(struct sockaddr *src, struct sockaddr *dst); 
hip_assoc* find_hip_association4(hip_hit hit);
void * binsert(const void *ky, const void *bs, size_t nel, size_t width, int (*compar)(const void *, const void *));
void log_registration(hip_reg *hip_r, int a);
void print_reg_table(hip_reg *hip_r);
int delete_reg_table(hip_reg key, hip_reg *hip_r);
int insert_reg_table(hip_reg key, hip_reg *hip_r);
returned *search_reg_table(hip_reg p, hip_reg *hip_r, returned *ret);
void cb(int p, int n, void *arg);
void init_crypto();
void deinit_crypto();
void pthread_locking_callback(int mode, int type, char *file, int line);
int init_log();
void fflush_log();
void log_(int level, char *fmt, ...);
char *logaddr(struct sockaddr *addr);
void logdsa(DSA *dsa);
void logrsa(RSA *rsa);
void logdh(DH *dh);
void logbn(BIGNUM *bn);
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len);
void log_hipa_fromto(int level, char *msg,  hip_assoc *hip_a,__u8 from,__u8 to);
void log_hipopts();
#ifdef __WIN32__
void log_WinError(int code);
#endif
#ifdef __UMH__
int do_bcast();
#endif
void hip_sleep(int seconds);
void hip_writelock();
void hip_exit(int signal);

/* hip_xml.c */
int locate_config_file(char *filename, int filename_size, char *default_name);
int read_identities_file(char *filename, int mine);
#ifdef SMA_CRAWLER
int read_peer_identities_from_hipcfg();
#endif /* SMA_CRAWLER */
void print_hi_to_buff(uint8_t **bufp, int *buf_len, hi_node *hi, int mine);
int save_identities_file(int);
int read_conf_file(char *);

/* hip_netlink.c */
int hip_netlink_open();
int get_my_addresses();
int select_preferred_address();
int is_my_address(struct sockaddr *addr);
int hip_handle_netlink(char *data, int length);
int add_address_to_iface(struct sockaddr *addr, int plen, int if_index);
int devname_to_index(char *dev, __u64 *mac);
sockaddr_list *add_address_to_list(sockaddr_list **list, struct sockaddr *addr,
    int ifi);
void delete_address_from_list(sockaddr_list **list, struct sockaddr *addr,
    int ifi);
void delete_address_entry_from_list(sockaddr_list **list, sockaddr_list *entry);
void make_address_active(sockaddr_list *item);
int update_peer_list_address(const hip_hit peer_hit, struct sockaddr *old_addr, struct sockaddr *new_addr);
int add_other_addresses_to_hi(hi_node *hi, int mine);

/* hip_cache.c */
void init_all_R1_caches();
void init_R1_cache(hi_node *hi);
hipcookie *generate_cookie();
void replace_next_R1();
int compute_R1_cache_index(hip_hit *hiti, __u8 current);
int calculate_r1_length(hi_node *hi);
void init_dh_cache();
dh_cache_entry *new_dh_cache_entry(__u8 group_id);
dh_cache_entry *get_dh_entry(__u8 group_id, int new);
void unuse_dh_entry(DH *dh);
void expire_old_dh_entries();

/* hip_status.c */
int hip_status_open();
void hip_handle_status_request(__u8 *buff, int len, struct sockaddr *addr);

/* hip_dht.c */
int hip_dht_lookup_hit(struct sockaddr *lsi, hip_hit *hit, int retry);
int hip_dht_lookup_address(hip_hit *hit, struct sockaddr *addr, int retry);
int hip_dht_publish(hip_hit *hit, struct sockaddr *addr, int retry);
int hip_dht_select_server(struct sockaddr *addr);
int add_addresses_from_dht(hi_node *hi, int retry);
void publish_my_hits();

#ifdef MOBILE_ROUTER
/* hip_mr.c */
int  hip_mr_set_external_if();
void hip_mr_handle_address_change(int add, struct sockaddr *newaddr, int ifi);
int  init_hip_mr_client(hip_hit peer_hit, struct sockaddr *src);
int  add_proxy_ticket(const __u8 *data);
#endif


/*
 * Miscellaneous
 */

static __inline __u64 __hton64( __u64 i )
{
#if defined(__MACOSX__) && defined(__BIG_ENDIAN__)
	return i;
#endif
	return ((__u64)(htonl((__u32)(i) & 0xffffffff)) << 32)
		| htonl((__u32)(((i) >> 32) & 0xffffffff ));
}
#define hton64(i)   __hton64( i )
#define ntoh64(i)   __hton64( i )

/* Unix replacements */
#ifdef __WIN32__
static __inline int gettimeofday(struct timeval *tv, void *tz) 
{
	if (!tv) return(-1);
	tv->tv_usec = 0;
	tv->tv_sec = time(NULL);
	return(0);
}

#define pthread_mutex_lock(mp) WaitForSingleObject(*mp, INFINITE)
#define pthread_mutex_unlock(mp) ReleaseMutex(*mp)
#define pthread_mutex_init(mp, mattr) *mp = CreateMutex(NULL, FALSE, NULL)
#define pthread_mutex_destroy(mp) CloseHandle(*mp)

#define snprintf _snprintf

#else
#define closesocket close
#endif /* __WIN32__ */

#endif 



