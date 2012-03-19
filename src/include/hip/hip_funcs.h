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
 *  \file  hip_funcs.h
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *		Tom Henderson, <thomas.r.henderson@boeing.com>
 *
 *  \brief  Function prototypes and inline definitions.
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
#define IS_LSI32(a) ((a & htonl(0xFF000000)) == htonl(0x01000000))
#ifdef __WIN32__
#define IN6_ARE_ADDR_EQUAL IN6_ADDR_EQUAL
#define IS_HIT(x) (((ntohs(((struct in6_addr*)x)->s6_words[0]) & 0xFFFF) \
                    == ((HIT_PREFIX_SHA1_32BITS >> 4) & 0xFFFF)) && \
                   ((ntohs(((struct in6_addr*)x)->s6_words[1]) & 0xFFF0) \
                    == ((HIT_PREFIX_SHA1_32BITS & 0xFFFF))))
#elif defined (__MACOSX__)
#define IS_HIT(x) ((ntohl(((struct in6_addr*)x)->__u6_addr.__u6_addr32[0]) \
                    & 0xFFFFFFF0L) == HIT_PREFIX_SHA1_32BITS)
#else /* Linux */
#define IS_HIT(x) ((ntohl(((struct in6_addr*)x)->s6_addr32[0]) & 0xFFFFFFF0L) \
                   == HIT_PREFIX_SHA1_32BITS)
#endif
#define SA2IP6(x) (&((struct sockaddr_in6*)x)->sin6_addr)

#define IS_LSI(a) ((((struct sockaddr*)a)->sa_family == AF_INET) ? \
                   (IS_LSI32(((struct sockaddr_in*)a)->sin_addr.s_addr)) : \
                   (IS_HIT( &((struct sockaddr_in6*)a)->sin6_addr)))

#define VALID_FAM(a) ((((struct sockaddr*)a)->sa_family == AF_INET) || \
                      (((struct sockaddr*)a)->sa_family == AF_INET6))


#define IN_LOOP(a) \
  (htonl(((struct sockaddr_in*)a)->sin_addr.s_addr) >> IN_CLASSA_NSHIFT \
   ==  (INADDR_LOOPBACK >> IN_CLASSA_NSHIFT))
#define IN6_LOOP(a) \
  IN6_IS_ADDR_LOOPBACK( &((struct sockaddr_in6*)a)->sin6_addr )
#define IN6_LL(a) \
  IN6_IS_ADDR_LINKLOCAL( &((struct sockaddr_in6*)a)->sin6_addr )


/*
 *  Function prototypes
 */
/* hip_output.c */
int hip_send_I1(hip_hit* hit, hip_assoc *hip_a);
int hip_send_R1(struct sockaddr *src, struct sockaddr *dst, hip_hit *hiti,
                hi_node *hi, hip_assoc *hip_rvs);
int hip_generate_R1(__u8 *data, hi_node *hi, hipcookie *cookie,
                    dh_cache_entry *dh_entry);
int hip_send_I2(hip_assoc *hip_a);
int hip_send_R2(hip_assoc *hip_a);
int hip_send_update(hip_assoc *hip_a, struct sockaddr *newaddr,
                    struct sockaddr *src, struct sockaddr *dstaddr);
int hip_send_update_relay(__u8 *data, hip_assoc *hip_a_client);
int hip_send_update_proxy_ticket(hip_assoc *hip_mr, hip_assoc *hip_a);
int hip_send_update_locators(hip_assoc *hip_a);
int hip_send_close(hip_assoc *hip_a, int send_ack);
int hip_send_notify(hip_assoc *hip_a, int code, __u8 *data, int data_len);
int hip_send(__u8 *data, int len, struct sockaddr *src, struct sockaddr *dst,
             hip_assoc *hip_a, int retransmit);
int hip_retransmit(hip_assoc *hip_a, __u8 *data, int len, struct sockaddr *src,
                   struct sockaddr *dst);
int build_tlv_hostid_len(hi_node *hi, int use_hi_name);
int build_tlv_hostid(__u8 *data, hi_node *hi, int use_hi_name);
int build_spi_locator(__u8 *data, __u32 spi, struct sockaddr *addr);
int build_tlv_signature(hi_node *hi, __u8 *data, int location, int R1);
int build_rekey(hip_assoc *hip_a);

/* hip_input.c */
int hip_parse_hdr(__u8 *data, int len, struct sockaddr *src,
                  struct sockaddr *dst, __u16 family, hiphdr **hdr);
int hip_handle_I1(__u8 *data, hip_assoc *hip_a, struct sockaddr *src,
                  struct sockaddr *dst);
int hip_handle_R1(__u8 *data, hip_assoc *hip_a, struct sockaddr *src);
int hip_handle_I2(__u8 *data, hip_assoc *hip_a, struct sockaddr *src,
                  struct sockaddr *dst);
int hip_handle_R2(__u8 *data, hip_assoc *hip_a);
int hip_handle_update(__u8 *data, hip_assoc *hip_a, struct sockaddr *src,
                      struct sockaddr *dst);
int hip_handle_close(__u8 *data, hip_assoc *hip_a);
int hip_handle_notify(__u8 *buff, hip_assoc *hip_a);
int hip_finish_rekey(hip_assoc *hip_a, int rebuild);
int hip_handle_BOS(__u8 *data, struct sockaddr *src);
int hip_handle_CER(__u8 *data, hip_assoc *hip_a);
int validate_signature(const __u8 *data, int data_len, tlv_head *tlv,
                       DSA *dsa, RSA *rsa);
int handle_hi(hi_node **hi_p, const __u8 *data);
int complete_base_exchange(hip_assoc *hip_a);
int rebuild_sa(hip_assoc *hip_a, struct sockaddr *newaddr, __u32 newspi,
               int in, int peer);
int rebuild_sa_x2(hip_assoc *hip_a, struct sockaddr *newsrcaddr,
                  struct sockaddr *newdstaddr, __u32 newspi, int in);

/* hip_ipsec.c */
__u32 get_next_spi();
int check_last_used(hip_assoc *hip_a, int direction, struct timeval *now);
int delete_associations(hip_assoc *hip_a, __u32 old_spi_in, __u32 old_spi_out);
int flush_hip_associations();
void hip_handle_esp(char *data, int length);
void start_base_exchange(struct sockaddr *dst);
void start_expire(__u32 spi);
void receive_udp_hip_packet(char *buff, int len);
void start_loss_multihoming(char *data, int len);
int handle_notify_loss(__u8 *data, int data_len);
void hip_handle_multihoming_timeouts(struct timeval *now);

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
int transform_to_ealg(int transform);
int transform_to_aalg(int transform);

/* hip_util.c */
int add_addresses_from_dns(char *name, hi_node *hi);
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
int get_other_addr_from_list(sockaddr_list *list, struct sockaddr *exclude,
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
void hit_to_sockaddr (struct sockaddr *sockad, const hip_hit hit);
void print_cookie(hipcookie *cookie);
int str_to_addr(__u8 *data, struct sockaddr *addr);
int hit_to_str(char *hit_str, const hip_hit hit);
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
__u16 checksum_udp_packet(__u8 *data,
                          struct sockaddr *src,
                          struct sockaddr *dst);
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
hip_assoc* find_hip_association_by_spi(__u32 spi, int dir);
hip_assoc *search_registrations(hip_hit hit, __u8 type);
hip_assoc *search_registrations2(__u8 type, int state);
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
int do_bcast();
void hip_sleep(int seconds);
void hip_writelock();
void hip_exit(int signal);
int regtype_to_string(__u8 type, char *str, int str_len);
void hex_print(register const char *indent,
               register const u_char *cp,
               register u_int length,
               register u_int oset);

/* hip_xml.c */
int locate_config_file(char *filename, int filename_size, char *default_name);
int read_identities_file(char *filename, int mine);
#ifdef HIP_VPLS
int read_peer_identities_from_hipcfg();
#endif /* HIP_VPLS */
void print_hi_to_buff(uint8_t **bufp, int *buf_len, hi_node *hi, int mine);
int save_identities_file(int);
int read_conf_file(char *);

/* hip_addr.c */
int hip_netlink_open();
int get_my_addresses();
int select_preferred_address();
int is_my_address(struct sockaddr *addr);
int hip_handle_netlink(char *data, int length);
void readdress_association(hip_assoc *hip_a, struct sockaddr *newaddr,
                           int if_index);
int add_address_to_iface(struct sockaddr *addr, int plen, int if_index);
int devname_to_index(char *dev, __u64 *mac);
sockaddr_list *add_address_to_list(sockaddr_list **list, struct sockaddr *addr,
                                   int ifi);
void delete_address_from_list(sockaddr_list **list, struct sockaddr *addr,
                              int ifi);
void delete_address_entry_from_list(sockaddr_list **list, sockaddr_list *entry);
void make_address_active(sockaddr_list *item);
int update_peer_list_address(const hip_hit peer_hit,
                             struct sockaddr *old_addr,
                             struct sockaddr *new_addr);
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
void hip_dht_update_my_entries(int flags);
int  hip_dht_resolve_hi(hi_node *hi, int retry);
/* int hip_dht_lookup_hit_by_name(char *name, hip_hit *hit, int retry);
 *  int hip_dht_lookup_address(hip_hit *hit, struct sockaddr *addr, int retry);
 *  int hip_dht_publish(hip_hit *hit, struct sockaddr *addr, int retry);
 *  int hip_dht_select_server(struct sockaddr *addr); */

/* hip_mr.c */
int  hip_mr_set_external_ifs();
void hip_mr_handle_address_change(int add, struct sockaddr *newaddr, int ifi);
int  hip_mr_retransmit(struct timeval *time1, hip_hit hit);
int  init_hip_mr_client(hip_hit peer_hit, struct sockaddr *src);
int  add_proxy_ticket(const __u8 *data);


/*
 * Miscellaneous
 */
static __inline __u64 __hton64( __u64 i )
{
#if defined(__BIG_ENDIAN__) || defined(__arm__)
  return(i);
#endif
  return(((__u64)(htonl((__u32)(i) & 0xffffffff)) << 32)
         | htonl((__u32)(((i) >> 32) & 0xffffffff)));
}

#define hton64(i)   __hton64( i )
#define ntoh64(i)   __hton64( i )

/* Unix replacements */
#ifdef __WIN32__
static __inline int gettimeofday(struct timeval *tv, void *tz)
{
  if (!tv)
    {
      return(-1);
    }
  tv->tv_usec = 0;
  tv->tv_sec = time(NULL);
  return(0);
}

#define pthread_mutex_lock(mp) WaitForSingleObject(*mp, INFINITE)
#define pthread_mutex_unlock(mp) ReleaseMutex(*mp)
#define pthread_mutex_init(mp, mattr) *mp = CreateMutex(NULL, FALSE, NULL)
#define pthread_mutex_destroy(mp) CloseHandle(*mp)
/* pthread conditionals not implmented for WIN32 */
#define pthread_cond_init(c, attr) { }
#define pthread_cond_wait(c, m) { }
#define pthread_cond_broadcast(c) { }
#define pthread_cond_destroy(c) { }

#define snprintf _snprintf
#define strnlen(s, l) strlen(s)

#else
#define closesocket close
#endif /* __WIN32__ */
#ifdef __MACOSX__
#define strnlen(s, l) strlen(s)
#endif /* __MACOSX__ */

#endif


