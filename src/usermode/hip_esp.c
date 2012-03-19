/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2004-2012 the Boeing Company
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
 *  \file  hip_esp.c
 *
 *  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  User-mode HIP ESP implementation.
 *
 */
#include <stdio.h>              /* printf() */
#ifdef __WIN32__
#include <win32/types.h>
#include <io.h>
#include <winsock2.h>
#include <win32/ip.h>
#else /* __WIN32__ */
#include <sys/stat.h>
#include <unistd.h>             /* write() */
#include <pthread.h>            /* pthread_exit() */
#include <sys/time.h>           /* gettimeofday() */
#include <sys/errno.h>          /* errno, etc */
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#include <netinet/in.h>
#endif /* __MACOSX__ */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/ip6.h>        /* struct ip6_hdr */
#include <netinet/icmp6.h>      /* struct icmp6_hdr */
#include <netinet/tcp.h>        /* struct tcphdr */
#include <netinet/udp.h>        /* struct udphdr */
#include <arpa/inet.h>
#ifndef __MACOSX__
#include <linux/types.h>
#endif /* __MACOSX__ */
#endif /* __WIN32__ */
#include <string.h>             /* memset, etc */
#include <openssl/hmac.h>       /* HMAC algorithms */
#include <openssl/sha.h>        /* SHA1 algorithms */
#include <openssl/des.h>        /* 3DES algorithms */
#include <openssl/rand.h>       /* RAND_bytes() */
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_usermode.h>
#include <hip/hip_sadb.h>
#include <hip/hip_globals.h>
#include <win32/checksum.h>

#ifdef HIP_VPLS
#include <utime.h>
#include <netinet/ether.h>
#include <hip/hip_cfg_api.h>
#include <hip/endbox_utils.h>
#endif /* HIP_VPLS */

/*
 * Globals
 */

#ifdef HIP_VPLS
int touchHeartbeat;
#endif

#ifdef __WIN32__
HANDLE tapfd;
#else
int tapfd;
#endif
int readsp[2] = { 0,0 };
int s_esp, s_esp_udp, s_esp_udp_dg, s_esp6;

#ifdef __MACOSX__
extern char *logaddr(struct sockaddr *addr);
#endif

__u32 g_tap_lsi;
__u64 g_tap_mac;
long g_read_usec;

#define BUFF_LEN 2000
#define HMAC_SHA_96_BITS 96 /* 12 bytes */
#define REPLAY_WIN_SIZE 64 /* 64 packets */

#define MULTIHOMING_LOSS_THRESHOLD 5

/* array of Ethernet addresses used by get_eth_addr() */
#define MAX_ETH_ADDRS 255
__u8 eth_addrs[6 * MAX_ETH_ADDRS]; /* must be initialized to random values */


/* Prototype of checksum function defined in hip_util.c */
__u16 checksum_udp_packet(__u8 *data,
                          struct sockaddr *src,
                          struct sockaddr *dst);

#ifdef __WIN32__
#define IS_EINTR_ERROR() (WSAGetLastError() == WSAEINTR)
#else
#define IS_EINTR_ERROR() (errno == EINTR)
#endif /* __WIN32__ */

/*
 * Local function declarations
 */
void tunreader_shutdown();
int handle_nsol(__u8 *in, int len, __u8 *out,int *outlen,struct sockaddr *addr);
int handle_arp(__u8 *in, int len, __u8 *out, int *outlen,struct sockaddr *addr);
int hip_esp_encrypt(__u8 *in, int len, __u8 *out, int *outlen,
                    hip_sadb_entry *entry, struct timeval *now);
int hip_esp_decrypt(__u8 *in, int len, __u8 *out, int *offset, int *outlen,
                    hip_sadb_entry *entry, struct ip *iph, struct timeval *now);

__u16 rewrite_checksum(__u8 *data, __u16 magic);
void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type);
void add_ipv4_header(__u8 *data, __u32 src, __u32 dst, struct ip *old,
                     __u16 len, __u8 proto);
void add_ipv6_pseudo_header(__u8 *data, struct sockaddr *src,
                            struct sockaddr *dst, __u32 len, __u8 proto);
void add_ipv6_header(__u8 *data,
                     struct sockaddr *src,
                     struct sockaddr *dst,
                     struct ip6_hdr *old,
                     struct ip *old4,
                     __u16 len,
                     __u8 proto);
__u16 in_cksum(struct ip *iph);
__u64 get_eth_addr(int family, __u8 *addr);

void esp_start_base_exchange(struct sockaddr *lsi);
void esp_start_expire(__u32 spi);
void esp_receive_udp_hip_packet(char *buff, int len);
void esp_signal_loss(__u32 spi, __u32 loss, struct sockaddr *dst);
__u32 get_next_seqno(hip_sadb_entry *entry);
int esp_anti_replay_check_initial(hip_sadb_entry *entry, __u32 seqno,
                                  __u32 *sequence_hi);
__u64 esp_update_anti_replay(hip_sadb_entry *entry, __u32 seqno, __u32 seqno_hi);

/* externals */
extern __u32 get_preferred_lsi(struct sockaddr *lsi);
extern int do_bcast();
extern int maxof(int num_args, ...);

#ifdef __MACOSX__
void add_outgoing_esp_header(__u8 *data, __u32 src, __u32 dst, __u16 len);
#endif

void init_readsp()
{
  if (readsp[0])
    {
      return;
    }

#ifdef __MACOSX__
  if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNSPEC, readsp))
    {
#else
  if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, readsp))
    {
#endif
      printf("sockpair() failed\n");
    }
  /* also initialize the Ethernet address table */
  RAND_bytes(eth_addrs, sizeof(eth_addrs));
}

/*
 * hip_esp_output()
 *
 * The ESP output thread. Reads ethernet packets from the socketpair
 * connected to the TAP-Win32 interface, and performs necessary ESP
 * encryption. Also handles ARP requests with artificial replies.
 */
#ifdef __WIN32__
void hip_esp_output(void *arg)
#else
void *hip_esp_output(void *arg)
#endif
{
  int len, err, flags, raw_len, is_broadcast, s, offset = 0;
  fd_set fd;
  struct timeval timeout, now;
  __u8 raw_buff[BUFF_LEN];
  __u8 data[BUFF_LEN];       /* encrypted data buffer */
  struct ip *iph;

#ifdef __WIN32__
  DWORD lenin;
  OVERLAPPED overlapped = { 0 };
#endif
  struct ip6_hdr *ip6h;
  static hip_sadb_entry *entry;
  struct sockaddr_storage ss_lsi;
  struct sockaddr *lsi = (struct sockaddr*)&ss_lsi;
  sockaddr_list *l;
#ifndef HIP_VPLS
  __u32 lsi_ip;
#else
  struct arp_hdr *arph;
  time_t last_time, now_time;
  int packet_count = 0;
#endif
#ifdef __MACOSX__
  __u32 saddr, daddr;
#endif
#ifdef RAW_IP_OUT
  int s_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (s_raw < 0)
    {
      printf("*** socket() error for raw socket in hip_esp_output\n");
    }
  flags = 1;
  if (setsockopt(s_raw, IPPROTO_IP, IP_HDRINCL, (char *)&flags,
                 sizeof(flags)) < 0)
    {
      printf("*** setsockopt() error for raw socket in "
             "hip_esp_output\n");
    }
#endif /* RAW_IP_OUT */

  init_readsp();
  lsi->sa_family = AF_INET;
  get_preferred_lsi(lsi);
  g_tap_lsi = LSI4(lsi);

#ifdef HIP_VPLS
  touchHeartbeat = 1;
  last_time = time(NULL);
  printf("hip_esp_output() thread (tid %u pid %d) started...\n",
         (unsigned)pthread_self(), getpid());
#else
  printf("hip_esp_output() thread started...\n");
#endif
  while (g_state == 0)
    {
      /* periodic select loop */
      gettimeofday(&now, NULL);
      FD_ZERO(&fd);
      FD_SET((unsigned)readsp[1], &fd);
#ifdef __MACOSX__
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
#else
      timeout.tv_sec = 0;
      timeout.tv_usec = g_read_usec;
#endif
#ifdef HIP_VPLS
      endbox_periodic_heartbeat(&now_time, &last_time, &packet_count,
                                "output", touchHeartbeat);
      endbox_check_hello_time(&now_time);
#endif

      if ((err =
             select(readsp[1] + 1, &fd, NULL, NULL,
                    &timeout)) < 0)
        {
          if (IS_EINTR_ERROR())
            {
              continue;
            }
          printf("hip_esp_output(): select() error\n");
        }
      else if (err == 0)
        {
          /* idle cycle */
          continue;
        }

      /* output data on socket */
      memset(raw_buff, 0, sizeof(raw_buff));
      memset(data, 0, sizeof(data));
      memset(lsi, 0, sizeof(struct sockaddr_storage));

#ifdef __WIN32__
      if ((len =
             recv(readsp[1], raw_buff, BUFF_LEN,
                  0)) == SOCKET_ERROR)
        {
#else
      if ((len = read(readsp[1], raw_buff, BUFF_LEN)) < 0)
        {
#endif
          if (IS_EINTR_ERROR())
            {
              continue;
            }
          printf("hip_esp_output(): read() failed: %s\n",
                 strerror(errno));
          exit(0);
        }
      /*
       * IPv4
       */
      if ((raw_buff[12] == 0x08) && (raw_buff[13] == 0x00))
        {
          iph = (struct ip*) &raw_buff[14];
          /* accept IPv4 traffic to 1.x.x.x here */
#ifdef HIP_VPLS
          if (endbox_ipv4_packet_check(iph, lsi,
                                       &packet_count) < 0)
            {
              continue;
            }
          is_broadcast = FALSE;
          /* Right now multicast only goes through currently
           * established tunnels.
           */
          if (IN_MULTICAST(ntohl(iph->ip_dst.s_addr)) ||
              (((ntohl(iph->ip_dst.s_addr)) & 0x000000FF) ==
               0x000000FF))
            {

#else /* HIP_VPLS */

#if defined(__BIG_ENDIAN__) || defined(__arm__)
          if (((iph->ip_v) == IPVERSION) &&
              ((iph->ip_dst.s_addr >> 24 & 0xFF) != 0x01))
#else /* BIG_ENDIAN */
          if (((iph->ip_v) == IPVERSION) &&
              ((iph->ip_dst.s_addr & 0xFF) != 0x01))
#endif /* BIG_ENDIAN */
            {
              continue;
            }
          lsi_ip = ntohl(iph->ip_dst.s_addr);
          lsi->sa_family = AF_INET;
          LSI4(lsi) = lsi_ip;
          is_broadcast = FALSE;
          /* broadcast packets */
          if ((lsi_ip & 0x00FFFFFF) == 0x00FFFFFF)
            {
              if (!do_bcast())
                {
                  continue;
                }
#endif /* HIP_VPLS */
              /* unicast the broadcast to each entry */
              entry = hip_sadb_get_next(NULL);
              is_broadcast = TRUE;
              /* unicast packets */
            }
          else if (!(entry = hip_sadb_lookup_addr(lsi)))
            {
#ifdef HIP_VPLS
              if (!endbox_check_cert(lsi))
                {
                  continue;
                }
#endif
              /* No SADB entry. Send ACQUIRE if we haven't
               * already, i.e. a new lsi_entry was created */
              if (buffer_packet(lsi, raw_buff,
                                len) == TRUE)
                {
                  esp_start_base_exchange(lsi);
                }
              continue;
            }
          raw_len = len;
          while (entry)
            {
              pthread_mutex_lock(&entry->rw_lock);
#ifdef RAW_IP_OUT
              offset = sizeof(struct ip);
#else
              offset = 0;
#endif
              if (check_esp_seqno_overflow(entry))
                {
                  esp_start_expire(entry->spi);
                }
              err = hip_esp_encrypt(raw_buff,
                                    raw_len,
                                    &data[offset],
                                    &len,
                                    entry,
                                    &now);
              if (err < 0)
                {
                  entry->dropped++;
                }
              pthread_mutex_unlock(&entry->rw_lock);
              if (err)
                {
                  if (!is_broadcast)
                    {
                      break;
                    }
                  entry = hip_sadb_get_next(entry);
                  continue;
                }
              flags = 0;
#ifdef RAW_IP_OUT
              /* Build IPv4 header and send out raw socket.
               * Use this to override OS source address
               * selection problems.
               */
              add_ipv4_header(data,
                              ntohl(LSI4(&entry->src_addrs->
                                         addr)),
                              ntohl(LSI4(
                                      &entry->dst_addrs
                                      ->
                                      addr)),
                              (struct ip*)
                              &raw_buff[sizeof(struct eth_hdr)
                              ],
                              sizeof(struct ip) + len,
                              IPPROTO_ESP);
              err = sendto(s_raw, data,
                           sizeof(struct ip) + len, flags,
                           SA(&entry->dst_addrs->addr),
                           SALEN(&entry->dst_addrs->addr));
#else
#ifdef __MACOSX__
/*I need to build an IP header and write it to a different address!*/
              /* TODO: use offset above, and LSI4 macro
               * instead
               *       of calls to inet_addr()
               */
              memmove(&data[20],&data,len);
              saddr =
                inet_addr(logaddr(SA(&entry->src_addrs->addr)));
              daddr =
                inet_addr(logaddr(SA(&entry->dst_addrs->addr)));

              add_outgoing_esp_header(data, saddr,daddr,len);

              err = sendto(s_esp,data, len + sizeof(struct ip),
                           flags, 0, 0);
              if (err < 0)
                {
                  perror("sendto()");
                }
#else /* __MACOSX__ */
              if (entry->mode == 3)
                {
                  s = s_esp_udp;
                }
              else if (entry->dst_addrs->addr.ss_family ==
                       AF_INET)
                {
                  s = s_esp;
                }
              else
                {
                  s = s_esp6;
                }
              err = sendto(s, data, len, flags,
                           SA(&entry->dst_addrs->addr),
                           SALEN(&entry->dst_addrs->addr));
#endif /* __MACOSX__ */
#endif /* RAW_IP_OUT */
              if (err < 0)
                {
                  printf("hip_esp_output(): sendto() "
                         "failed: %s\n", strerror(errno));
                }
              else
                {
                  hip_sadb_inc_bytes(
                    entry,
                    sizeof(struct ip) +
                    err,
                    &now,
                    1);
                }
              /* multihoming: duplicate packets to multiple
               * destination addresses */
              for (l = entry->dst_addrs->next; l;
                   l = l->next)
                {
                  err = sendto(s, data, len, flags,
                               SA(&l->addr),
                               SALEN(&l->addr));
                  if (err < 0)
                    {
                      printf(
                        "hip_esp_output(): sendto() "
                        "failed: %s\n",
                        strerror(errno));
                    }
                }
              /* broadcasts are unicast to each association */
              if (!is_broadcast)
                {
                  break;
                }
              entry = hip_sadb_get_next(entry);
            }             /* end while */
                          /*
                           * IPv6
                           */
        }
      else if ((raw_buff[12] == 0x86) && (raw_buff[13] == 0xdd))
        {
          ip6h = (struct ip6_hdr*) &raw_buff[14];
          /* accept IPv6 traffic to 2001:10::/28 here */
          if ((ip6h->ip6_vfc & 0xF0) != 0x60)
            {
              continue;
            }
          /* Look for all-nodes multicast address */
          if (IN6_IS_ADDR_MC_LINKLOCAL(&ip6h->ip6_dst) &&
              (ip6h->ip6_nxt == IPPROTO_ICMPV6))
            {
              err = handle_nsol(raw_buff, len, data,&len,lsi);
              if (err)
                {
                  continue;
                }
#ifdef __WIN32__
              if (!WriteFile(tapfd, data, len, &lenin,
                             &overlapped))
                {
                  printf( "hip_esp_output WriteFile() " \
                          "failed.\n");
                }
#else
              if (write(tapfd, data, len) < 0)
                {
                  printf( "hip_esp_output write() " \
                          "failed.\n");
                }
#endif
              continue;
            }
          else if (!IS_HIT(&ip6h->ip6_dst))
            {
              continue;
            }
          /* HIT prefix */
          lsi->sa_family = AF_INET6;
          memcpy(SA2IP(lsi), &ip6h->ip6_dst, SAIPLEN(lsi));
          if (!(entry = hip_sadb_lookup_addr(lsi)))
            {
              if (buffer_packet(lsi, raw_buff,
                                len) == TRUE)
                {
                  esp_start_base_exchange(lsi);
                }
              continue;
            }
          raw_len = len;
          pthread_mutex_lock(&entry->rw_lock);
          if (check_esp_seqno_overflow(entry))
            {
              esp_start_expire(entry->spi);
            }
          err = hip_esp_encrypt(raw_buff, raw_len,
                                data, &len, entry, &now);
          if (err < 0)
            {
              entry->dropped++;
            }
          pthread_mutex_unlock(&entry->rw_lock);
          if (err)
            {
              continue;
            }
          flags = 0;
          if (entry->mode == 3)
            {
              s = s_esp_udp;
            }
          else if (entry->dst_addrs->addr.ss_family ==
                   AF_INET)
            {
              s = s_esp;
            }
          else
            {
              s = s_esp6;
            }
          err = sendto(   s, data, len, flags,
                          SA(&entry->dst_addrs->addr),
                          SALEN(&entry->dst_addrs->addr));
          if (err < 0)
            {
              printf("hip_esp_output IPv6 sendto() failed:"
                     " %s\n",strerror(errno));
            }
          else
            {
              hip_sadb_inc_bytes(entry,
                                 sizeof(struct ip6_hdr) + err,
                                 &now, 1);
            }
          /*
           * ARP
           */
        }
      else if ((raw_buff[12] == 0x08) && (raw_buff[13] == 0x06))
        {
#ifndef HIP_VPLS
          /*
           *  printf("Raw buffer before handle_arp:\n");
           *  hex_print("\n\t", raw_buff, 60, 0);
           *  log_(NORM, "LSI into handle_arp: %0X\n",
           * lsi->sa_data);
           */
          err = handle_arp(raw_buff, len, data, &len, lsi);
          if (err)
            {
              continue;
            }
#ifdef __WIN32__
          if (!WriteFile(tapfd, data, len, &lenin,
                         &overlapped))
            {
              printf("hip_esp_output WriteFile() failed.\n");
            }
#else
          if (write(tapfd, data, len) < 0)
            {
              printf("hip_esp_output write() failed.\n");
            }
#endif /* __WIN32__ */
#else /* HIP_VPLS */
          /* Is the ARP for one of our legacy nodes? */
          arph = (struct arp_hdr*) &raw_buff[14];
          if (endbox_arp_packet_check(arph, lsi,
                                      &packet_count) < 0)
            {
              continue;
            }
          /* Why send an acquire during ARP? */
          /* Trying to do layer two */
          if (!(entry = hip_sadb_lookup_addr(lsi)))
            {
              if (!endbox_check_cert(lsi))
                {
                  continue;
                }
              if (buffer_packet(lsi, raw_buff,
                                len) == TRUE)
                {
                  esp_start_base_exchange(lsi);
                }
            }
          else                   /* Need to send packet */
            {
              raw_len = len;
              pthread_mutex_lock(&entry->rw_lock);
#ifdef RAW_IP_OUT
              offset = sizeof(struct ip);
#else
              offset = 0;
#endif
              err = hip_esp_encrypt(raw_buff,
                                    raw_len,
                                    &data[offset],
                                    &len,
                                    entry,
                                    &now);
              pthread_mutex_unlock(&entry->rw_lock);
              if (err)
                {
                  break;
                }
              flags = 0;
#ifdef RAW_IP_OUT
              /* Build IPv4 header and send out raw socket.
               * Use this to override OS source address
               * selection problems.
               */
              add_ipv4_header(data,
                              ntohl(LSI4(&entry->src_addrs->
                                         addr)),
                              ntohl(LSI4(
                                      &entry->dst_addrs
                                      ->
                                      addr)),
                              (struct ip*)
                              &raw_buff[sizeof(struct eth_hdr)
                              ],
                              sizeof(struct ip) + len,
                              IPPROTO_ESP);
              err = sendto(s_raw, data,
                           sizeof(struct ip) + len, flags,
                           SA(&entry->dst_addrs->addr),
                           SALEN(&entry->dst_addrs->addr));
#else
#ifdef __MACOSX__
/*I need to build an IP header and write it to a different address!*/
              /* TODO: use offset above, and LSI4 macro
               * instead
               *       of calls to inet_addr()
               */
              memmove(&data[20],&data,len);
              saddr =
                inet_addr(logaddr(SA(&entry->src_addrs
                                     ->addr)));
              daddr =
                inet_addr(logaddr(SA(&entry->dst_addrs
                                     ->addr)));

              add_outgoing_esp_header(data, saddr,daddr,len);

              err = sendto(s_esp,data, len + sizeof(struct ip),
                           flags, 0, 0);
              if (err < 0)
                {
                  perror("sendto()");
                }
#else /* __MACOSX__ */
              if (entry->mode == 3)
                {
                  s = s_esp_udp;
                }
              else if (entry->dst_addrs->addr.ss_family ==
                       AF_INET)
                {
                  s = s_esp;
                }
              else
                {
                  s = s_esp6;
                }
              err = sendto(s, data, len, flags,
                           SA(&entry->dst_addrs->addr),
                           SALEN(&entry->dst_addrs->addr));
#endif /* __MACOSX__ */
#endif /* RAW_IP_OUT */
              if (err < 0)
                {
                  printf("hip_esp_output(): sendto() "
                         "failed: %s\n", strerror(errno));
                }
              else
                {
                  pthread_mutex_lock(&entry->rw_lock);
                  entry->bytes += sizeof(struct ip) + err;
                  entry->usetime.tv_sec = now.tv_sec;
                  entry->usetime.tv_usec = now.tv_usec;
                  pthread_mutex_unlock(&entry->rw_lock);
                }
            }
#endif /* HIP_VPLS */
          continue;
          /*
           * Endbox hellos (uses protocol IEEE Std 802 - Local
           * Experimental Ethertype 1).
           */
#ifdef HIP_VPLS
        }
      else if ((raw_buff[12] == 0x88) && (raw_buff[13] == 0xB5))
        {
          if (HCNF.endbox_hello_time > 0)
            {
              endbox_hello_check(raw_buff);
            }
#endif
        }
      else
        {
          /* debug other eth headers here */
          /*int i;
           *  printf("<unknown traffic> (len=%d)\n", len);
           *  for (i = 0; i < len; i++)
           *       printf("%x", raw_buff[i] & 0xFF);
           *  printf("\n");*/

        }

    }
  /* write some data to flush waiting TAP threads, speed up exit */
  data[0] = 0;
  len = 1;
#ifdef __WIN32__
  WriteFile(tapfd, data, len, &lenin, &overlapped);
  CloseHandle(tapfd);
#else
  err = write(tapfd, data, len);
  close(tapfd);
#endif
  printf("hip_esp_output() thread shutdown.\n");
  fflush(stdout);
  tunreader_shutdown();
#ifndef __WIN32__
  pthread_exit((void *) 0);
  return(NULL);
#endif
}


/*
 * hip_esp_input()
 *
 * The ESP input thread. Reads ESP packets from the network and decrypts
 * them, adding HIT or LSI headers and sending them out the TAP-Win32 interface.
 * Also, expires temporary LSI entries and retransmits buffered packets.
 */
#ifdef __WIN32__
void hip_esp_input(void *arg)
#else
void *hip_esp_input(void *arg)
#endif
{
  int err, len, max_fd, offset;
  fd_set fd;
  struct timeval timeout, now;
  __u8 buff[BUFF_LEN];       /* raw, encrypted data buffer */
  __u8 data[BUFF_LEN];       /* decrypted data buffer */
  struct sockaddr_storage ss_lsi;
  struct sockaddr *lsi = (struct sockaddr*) &ss_lsi;
  struct ip *iph;
  struct ip_esp_hdr *esph;
  udphdr *udph;

  __u32 spi;
  hip_sadb_entry *entry;
#ifdef __WIN32__
  DWORD lenin;
  OVERLAPPED overlapped = { 0 };
#endif
#ifdef HIP_VPLS
  time_t last_time, now_time;
  int packet_count = 0;

  last_time = time(NULL);
  printf("hip_esp_input() thread (tid %d pid %d) started...\n",
         (unsigned)pthread_self(), getpid());
#else
  printf("hip_esp_input() thread started...\n");
#endif
  g_read_usec = 1000000;

  lsi->sa_family = AF_INET;
  get_preferred_lsi(lsi);
  g_tap_lsi = LSI4(lsi);

  while (g_state == 0)
    {
      gettimeofday(&now, NULL);
      FD_ZERO(&fd);
      FD_SET((unsigned)s_esp, &fd);
      FD_SET((unsigned)s_esp_udp, &fd);
#ifdef __WIN32__
      /* IPv6 ESP not available in Windows. Separate UDP datagram
       * socket not needed. */
      max_fd = (s_esp > s_esp_udp) ? s_esp : s_esp_udp;
#else
      FD_SET((unsigned)s_esp_udp_dg, &fd);
#ifdef __MACOSX__
      max_fd = maxof(3, s_esp, s_esp_udp, s_esp_udp_dg);
#else /* __MACOSX__ */
      FD_SET((unsigned)s_esp6, &fd);
      max_fd = maxof(4, s_esp, s_esp6, s_esp_udp, s_esp_udp_dg);
#endif /* __MACOSX__ */
#endif /* __WIN32__ */
#ifdef __MACOSX__
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
#else
      timeout.tv_sec = 0;
      timeout.tv_usec = g_read_usec;
#endif /* __MACOSX__ */
      memset(buff, 0, sizeof(buff));
      memset(data, 0, sizeof(data));

      /* periodic functions called every g_read_usec timeout */
#ifdef HIP_VPLS
      endbox_periodic_heartbeat(&now_time, &last_time, &packet_count,
                                "input", touchHeartbeat);
#endif
      hip_remove_expired_lsi_entries(&now);           /* unbuffer packets */
      hip_remove_expired_sel_entries(&now);           /* this is rate-limited */
      hip_sadb_expire(&now);

      if ((err =
             select(max_fd + 1, &fd, NULL, NULL,
                    &timeout)) < 0)
        {
          if (IS_EINTR_ERROR())
            {
              continue;
            }
          printf("hip_esp_input(): select() error %s\n",
                 strerror(errno));
        }
      else if (FD_ISSET(s_esp, &fd))
        {
#ifdef __WIN32__
          len = recv(s_esp, buff, sizeof(buff), 0);
#else
          len = read(s_esp, buff, sizeof(buff));
#endif
          iph = (struct ip *) &buff[0];
          esph = (struct ip_esp_hdr *) &buff[sizeof(struct ip)];
          spi     = ntohl(esph->spi);
          if (!(entry = hip_sadb_lookup_spi(spi)))
            {
              /*printf("Warning: SA not found for SPI 0x%x\n",
               *       spi);*/
              continue;
            }

          pthread_mutex_lock(&entry->rw_lock);
          err = hip_esp_decrypt(buff, len, data, &offset, &len,
                                entry, iph, &now);
          if (err < 0)
            {
              entry->dropped++;
            }
          pthread_mutex_unlock(&entry->rw_lock);
          if (err)
            {
              continue;
            }
#ifdef __WIN32__
          if (!WriteFile(tapfd, &data[offset], len, &lenin,
                         &overlapped))
            {
              printf("hip_esp_input() WriteFile() failed.\n");
              continue;
            }
#else /* __WIN32__ */
#ifdef HIP_VPLS
          packet_count++;
          iph =
            (struct ip*) &data[offset +
                               sizeof(struct eth_hdr)];
          endbox_ipv4_multicast_write(data, offset, len);
#else /* HIP_VPLS */
          if (write(tapfd, &data[offset], len) < 0)
            {
              printf("hip_esp_input() write() failed.\n");
            }
#endif /* HIP_VPLS */
#endif /* __WIN32__ */
        }
      else if (FD_ISSET(s_esp_udp, &fd))
        {
#ifdef __WIN32__
          len = recv(s_esp_udp, buff, sizeof(buff), 0);
#else
          len = read(s_esp_udp, buff, sizeof(buff));
#endif /* __WIN32__ */

          if (len < (sizeof(struct ip) + sizeof(udphdr)))
            {
              continue;                   /* packet too short */
            }
          iph = (struct ip*) &buff[0];
          udph = (udphdr*) &buff[sizeof(struct ip)];
          esph = (struct ip_esp_hdr *) \
                 &buff[sizeof(struct ip) + sizeof(udphdr)];
          spi     = ntohl(esph->spi);
          /*seq_no = ntohl(esph->seq_no);*/

          /* SOCK_RAW receives all UDP traffic, not just
           * HIP_UDP_PORT, even though we used bind(). */
          if (HIP_UDP_PORT != ntohs(udph->dst_port))
            {
              /*	printf("ignoring %d bytes from UDP port
               * %d\n",
               *               len, ntohs(udph->dst_port)); */
              continue;
            }

          /* UDP packet with SPI of zero is a HIP control packet,
           * send it to the hipd thread via ESP socketpair.
           */
          if (0x0 == spi)
            {
              esp_receive_udp_hip_packet((char *)buff, len);
              continue;
            }

          if (!(entry = hip_sadb_lookup_spi(spi)))
            {
              printf("Warning: SA not found for SPI 0x%x\n",
                     spi);
              continue;
            }

          pthread_mutex_lock(&entry->rw_lock);
          err = hip_esp_decrypt(buff, len, data, &offset, &len,
                                entry, iph, &now);
          if (err < 0)
            {
              entry->dropped++;
            }
          pthread_mutex_unlock(&entry->rw_lock);
          /* these two locks acquired by hip_sadb_lookup_addr */
          if (err)
            {
              continue;
            }

#ifdef __WIN32__
          if (!WriteFile(tapfd, &data[offset], len, &lenin,
                         &overlapped))
            {
              printf("hip_esp_input() WriteFile() failed.\n");
              continue;
            }
#else
          if (write(tapfd, &data[offset], len) < 0)
            {
              printf("hip_esp_input() write() failed.\n");
            }
#endif

#ifndef __WIN32__
        }
      else if (FD_ISSET(s_esp_udp_dg, &fd))
        {
          len = read(s_esp_udp_dg, buff, sizeof(buff));
          /* This data is ignored, it was already received by the
           * s_esp_udp RAW socket. This bound datagram socket
           * prevents ICMP port unreachable messages. */
          continue;
#ifndef __MACOSX__
        }
      else if (FD_ISSET(s_esp6, &fd))
        {
          len = read(s_esp6, buff, sizeof(buff));
          /* there is no IPv6 header supplied */
          esph = (struct ip_esp_hdr *) &buff[0];
          spi     = ntohl(esph->spi);
          /* seq_no = ntohl(esph->seq_no);*/
          if (!(entry = hip_sadb_lookup_spi(spi)))
            {
              printf("Warning: SA not found for SPI 0x%x\n",
                     spi);
              continue;
            }
          pthread_mutex_lock(&entry->rw_lock);
          err = hip_esp_decrypt(buff, len, data, &offset, &len,
                                entry, NULL, &now);
          if (err < 0)
            {
              entry->dropped++;
            }
          pthread_mutex_unlock(&entry->rw_lock);
          if (err)
            {
              continue;
            }
          if (write(tapfd, &data[offset], len) < 0)
            {
              printf("hip_esp_input() write() failed.\n");
            }
#endif /* !__MACOSX__ */
#endif /* !__WIN32__ */
        }
      else if (err == 0)
        {
          /* idle cycle */
        }
    }

  printf("hip_esp_input() thread shutdown.\n");
  fflush(stdout);
#ifndef __WIN32__
  pthread_exit((void *) 0);
  return(NULL);
#endif
}


#ifdef __WIN32__
/* For Windows, use overlapped event notification */
void tunreader(void *arg)
{
  DWORD len;
  char buf[BUFF_LEN];
  OVERLAPPED overlapped;
  int status;

  printf("tunreader() thread started...\n");

  init_readsp();
  overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

  while (g_state == 0)
    {
      overlapped.Offset = 0;
      overlapped.OffsetHigh = 0;
      ResetEvent(overlapped.hEvent);

      status = ReadFile(tapfd, buf, BUFF_LEN, &len, &overlapped);
      if (!status)
        {
          if (GetLastError() == ERROR_IO_PENDING)
            {
              /* WaitForSingleObject(overlapped.hEvent,2000);
               */
              WaitForSingleObject(overlapped.hEvent,INFINITE);
              if (!GetOverlappedResult(tapfd, &overlapped,
                                       &len, FALSE))
                {
                  /* there is nothing to send */
                  continue;
                }
            }
          else
            {
              /* other error, don't exit */
              printf("tunreader(): error (%d) reading from ",
                     (int)GetLastError());
              printf("tun device.\n");
              continue;
            }
        }
      send(readsp[0], buf, len, 0);
    }
  CloseHandle(tapfd);
  printf("tunreader() thread shutdown.\n");
  fflush(stdout);
}

#else /* __WIN32__ */

/* For Linux, use select. */
void *tunreader(void *arg)
{
  int len, err;
  char buf[BUFF_LEN];
  struct timeval timeout;
  fd_set read_fdset;

#ifdef HIP_VPLS
  time_t last_time, last_hello_time, now_time;

  last_time = time(NULL);
  last_hello_time = time(NULL);
  printf("tunreader() thread (tid %d pid %d) started (%d)...\n",
         (unsigned)pthread_self(), getpid(), tapfd);
#else
  printf("tunreader() thread started (%d)...\n", tapfd);
#endif

  init_readsp();
  while (g_state == 0)
    {
      FD_ZERO(&read_fdset);
      FD_SET((unsigned)tapfd, &read_fdset);
      timeout.tv_sec = 3;
      timeout.tv_usec = 0;
#ifdef HIP_VPLS
      now_time = time(NULL);
      if (now_time - last_time > 60)
        {
          printf("tunreader() heartbeat\n");
          last_time = now_time;
          utime("/usr/local/etc/hip/heartbeat_tunreader", NULL);
        }
      if ((HCNF.endbox_hello_time > 0) &&
          (now_time - last_hello_time > HCNF.endbox_hello_time))
        {
          last_hello_time = now_time;
          endbox_send_hello();
        }
#endif
      if ((err = select((tapfd + 1), &read_fdset,
                        NULL, NULL, &timeout) < 0))
        {
          if (err == EINTR)
            {
              continue;
            }
          printf("tunreader: error while reading from tun ");
          printf("device: %s\n", strerror(errno));
          fflush(stdout);
          return(0);
        }
      else if (FD_ISSET(tapfd, &read_fdset))
        {
          if ((len = read(tapfd, buf, BUFF_LEN)) > 0)
            {
              err = write(readsp[0], buf, len);
              if (err != len)
                {
                  printf("warning: tunreader: write(%d) "
                         "returned %d\n", len, err);
                }
            }
          else
            {
              printf("tunreader: read() error len=%d %s\n",
                     len, strerror(errno));
              continue;
            }
        }
      else if (err == 0)
        {
          /* idle cycle */
          continue;
        }
    }
  close(tapfd);
  printf("tunreader thread shutdown.\n");
  fflush(stdout);
  pthread_exit((void *) 0);
  return(NULL);
}

#endif /* __WIN32__ */

/*
 * tunreader_shutdown()
 *
 * Send dummy data to the tun device so that the tunreader() thread doesn't
 * hang waiting for a read event.
 */
void tunreader_shutdown()
{
  char data[8] = { 0,0,0,0,0,0,0,0 };
  struct sockaddr_in to;
  int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = htonl(g_tap_lsi);
  to.sin_port = htons(8000);

  sendto(s, data, sizeof(data), 0, (struct sockaddr*)&to, sizeof(to));
#ifdef __WIN32__
  closesocket(s);
#else
  close(s);
#endif
}

/*
 * handle_nsol()
 *
 * Handle ICMPv6 Neighbor Solicitations for HITs.
 * Right now this is called from the esp_output thread when an
 * application wants to send data to a HIT.
 */
int handle_nsol(__u8 *in, int len, __u8 *out, int *outlen,struct sockaddr *addr)
{
  struct eth_hdr *eth = (struct eth_hdr*)in;
  struct ip6_hdr *ip6h = (struct ip6_hdr*) &in[sizeof(struct eth_hdr)];
  __u64 esrc = 0, edst = 0;
  struct icmp6_hdr *nsol, *nadv;
  struct in6_addr *target, *adv_target;
  struct nd_opt_hdr *adv_target_opts;
  __u8 *p;
  __u16 payload_len;
  int location;
  struct sockaddr_storage src_ss;
  struct sockaddr_storage dst_ss;
  struct sockaddr *src = (struct sockaddr *) &src_ss;
  struct sockaddr *dst = (struct sockaddr *) &dst_ss;

  nsol = (struct icmp6_hdr *)&in[sizeof(struct eth_hdr) +
                                 sizeof(struct ip6_hdr)];

  /* Only allow ICMPv6 Neighbor Soliciations for HITs */
  if (nsol->icmp6_type != ND_NEIGHBOR_SOLICIT)
    {
      return(1);
    }
  target = (struct in6_addr*) (nsol + 1);
  if (!IS_HIT(target))         /* target must be HIT */
    {
      return(1);
    }
  /* don't answer requests for self */
  src->sa_family = AF_INET6;
  get_preferred_lsi(src);
  if (IN6_ARE_ADDR_EQUAL(target,
                         &((struct sockaddr_in6*)src)->sin6_addr))
    {
      return(1);
    }

  /* for now, replied MAC addr  */
  esrc = get_eth_addr(AF_INET6, &target->s6_addr[0]);
  memcpy(&edst, eth->src, 6);
  add_eth_header(out, esrc, edst, 0x86dd);
  location = sizeof(struct eth_hdr);

  /* IPv6 header added after length is calculated */
  memset(src, 0, sizeof(struct sockaddr_storage));
  memset(dst, 0, sizeof(struct sockaddr_storage));
  src->sa_family = AF_INET6;
  memcpy(SA2IP(src), &target->s6_addr[0], sizeof(struct in6_addr));
  dst->sa_family = AF_INET6;
  memcpy(SA2IP(dst), &ip6h->ip6_src.s6_addr[0], sizeof(struct in6_addr));
  location += sizeof(struct ip6_hdr);

  /* build neighbor advertisement reply */
  nadv = (struct icmp6_hdr *)&out[location];
  nadv->icmp6_type = ND_NEIGHBOR_ADVERT;
  nadv->icmp6_code = 0;
  nadv->icmp6_cksum = 0;
  nadv->icmp6_data32[0] = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
  location += sizeof(struct icmp6_hdr);
  adv_target = (struct in6_addr*) &out[location];
  memcpy(adv_target, target, sizeof(struct in6_addr));
  location += sizeof(struct in6_addr);
  adv_target_opts = (struct nd_opt_hdr*) &out[location];
  adv_target_opts->nd_opt_type = ND_OPT_TARGET_LINKADDR;
  adv_target_opts->nd_opt_len = 1;       /* 1x(8 octets) */
  location += sizeof(struct nd_opt_hdr);
  memcpy(&out[location], &esrc, 6);
  location += 6;

  /* return the HIT */
  if (addr)
    {
      memcpy(addr, src, sizeof(struct sockaddr_storage));
    }

  /* pseudo-header for upper-layer checksum calculation */
  p = (__u8*)nadv - 40;
  payload_len = &out[location] - (__u8*)nadv;
  add_ipv6_pseudo_header(p, src, dst, (__u32)payload_len, IPPROTO_ICMPV6);
  nadv->icmp6_cksum = ip_fast_csum(p, &out[location] - p);
  /* real IPv6 header */
  add_ipv6_header(&out[sizeof(struct eth_hdr)], src, dst, ip6h, NULL,
                  payload_len, IPPROTO_ICMPV6);

  *outlen = location;
  return(0);
}

/*
 * handle_arp()
 *
 * Handle ARP requests for 1.x.x.x addresses. Right now this is called
 * from the esp_output thread when an application wants to send data to
 * an LSI.
 */
int handle_arp(__u8 *in, int len, __u8 *out, int *outlen, struct sockaddr *addr)
{
  struct eth_hdr *eth = (struct eth_hdr*)in;
  struct arp_hdr *arp_req_hdr, *arp_reply_hdr;
  struct arp_req_data *arp_req, *arp_rply;
  __u64 src = 0, dst = 0;
  __u32 ip_dst;

  /* only handle ARP requests (opcode 1) here */
  arp_req_hdr = (struct arp_hdr*) &in[14];
  switch (ntohs(arp_req_hdr->ar_op))
    {
    case ARPOP_REQUEST:
      break;
    default:
      return(1);
    }

  if ((ntohs(arp_req_hdr->ar_hrd) == 0x01) &&           /* Ethernet */
      (ntohs(arp_req_hdr->ar_pro) == 0x0800) &&         /* IPv4 */
      (arp_req_hdr->ar_hln == 6) && (arp_req_hdr->ar_pln == 4))
    {
      /* skip sender MAC, sender IP, target MAC */
      arp_req = (struct arp_req_data*)(arp_req_hdr + 1);
      ip_dst = arp_req->dst_ip;
    }
  else
    {
      return(-1);
    }

  if (ip_dst == g_tap_lsi)         /* don't answer requests for self */
    {
      return(1);
    }


  /* repl with random MAC addr based on requested IP addr */
  src = get_eth_addr(AF_INET, (__u8*)&ip_dst);
  /* log_(NORM, "Source MAC for reply: %08X\n", src); */
  memcpy(&dst, eth->src, 6);
  /* log_(NORM, "Dest MAC for reply: %08X\n", dst); */
  add_eth_header(out, src, dst, 0x0806);

  /* build ARP reply */
  arp_reply_hdr = (struct arp_hdr*) &out[14];
  arp_reply_hdr->ar_hrd = htons(0x01);
  arp_reply_hdr->ar_pro = htons(0x0800);
  arp_reply_hdr->ar_hln = 6;
  arp_reply_hdr->ar_pln = 4;
  arp_reply_hdr->ar_op = htons(ARPOP_REPLY);
  arp_rply = (struct arp_req_data*)(arp_reply_hdr + 1);
  memcpy(arp_rply->src_mac, &src, 6);                   /* sender MAC */
  arp_rply->src_ip = arp_req->dst_ip;           /* sender address */
  memcpy(arp_rply->dst_mac, arp_req->src_mac, 6);       /* target MAC */
  arp_rply->dst_ip = arp_req->src_ip;         /* target IP */

  /*
   *  printf("Raw buffer arp_reply:\n");
   *  hex_print("\n\t", out, 60, 0);
   */
  /* return the address */
  if (addr)
    {
      addr->sa_family = AF_INET;
      ((struct sockaddr_in*)addr)->sin_addr.s_addr = ntohl(ip_dst);
    }

  *outlen = sizeof(struct eth_hdr) + sizeof(struct arp_hdr) + 20;
  return(0);
}

/*
 * hip_esp_encrypt()
 *
 * in:		in	pointer of data to encrypt
 *              len	length of data
 *              out	pointer of where to store encrypted data
 *              outlen	returned length of encrypted data
 *              entry   the SADB entry
 *
 * out:		Encrypted data in out, outlen. entry statistics are modified.
 *              Returns 0 on success, -1 otherwise.
 *
 * Perform actual ESP encryption and authentication of packets.
 */
int hip_esp_encrypt(__u8 *in, int len, __u8 *out, int *outlen,
                    hip_sadb_entry *entry, struct timeval *now)
{
  int alen = 0, elen = 0;
  unsigned int hmac_md_len;
  int i, iv_len = 0, padlen, location, hdr_len;
  struct ip *iph = NULL;
  struct ip6_hdr *ip6h = NULL;
  struct ip_esp_hdr *esp;
  udphdr *udph = NULL;

  struct ip_esp_padinfo *padinfo = 0;
  __u8 cbc_iv[16];
  __u8 hmac_md[EVP_MAX_MD_SIZE];
#ifndef HIP_VPLS
  __u16 checksum_fix = 0;
#endif
  int family, use_udp = FALSE;


#ifndef HIP_VPLS
  if ((in[12] == 0x86) && (in[13] == 0xdd))
    {
      family = AF_INET6;
    }
  else
    {
      family = AF_INET;
    }
#else
  family = AF_UNSPEC;
#endif

  switch (family)
    {
    case AF_INET:
      iph = (struct ip*) &in[sizeof(struct eth_hdr)];
      /* BEET mode uses transport mode encapsulation. IP header is
       * not included. */
      hdr_len = sizeof(struct eth_hdr) + sizeof(struct ip);
      /* rewrite upper-layer checksum, so it is based on HITs */
#ifndef HIP_VPLS
      checksum_fix =
#endif
      rewrite_checksum((__u8*)iph, entry->hit_magic);
      break;
    case AF_INET6:
      ip6h = (struct ip6_hdr*) &in[sizeof(struct eth_hdr)];
      hdr_len = sizeof(struct eth_hdr) + sizeof(struct ip6_hdr);
      /* assume HITs are used as v6 src/dst, no checksum rewrite */
      break;
#ifdef HIP_VPLS
    case AF_UNSPEC:
      hdr_len = 0;
      break;
#endif
    }

  /* elen is length of data to encrypt
   * for HIP_VPLS, this includes the IP header.
   */
  elen = len - hdr_len;


  /* setup ESP header, common to all algorithms */
  if (entry->mode == 3)         /*(HIP_ESP_OVER_UDP)*/
    {
      udph = (udphdr*) out;
      esp = (struct ip_esp_hdr*) &out[sizeof(udphdr)];
      use_udp = TRUE;
    }
  else
    {
      esp = (struct ip_esp_hdr*) out;
    }
  esp->spi = htonl(entry->spi);
  esp->seq_no = htonl(get_next_seqno(entry));
  padlen = 0;
  *outlen = sizeof(struct ip_esp_hdr);

  if (use_udp)         /* (HIP_ESP_OVER_UDP) */
    {
      *outlen += sizeof(udphdr);
    }

  /*
   * Encryption
   */

  /* Check keys and set IV length */
  switch (entry->e_type)
    {
    case SADB_EALG_3DESCBC:
      iv_len = 8;
      if (!entry->e_key || (entry->e_keylen == 0))
        {
          printf("hip_esp_encrypt: 3-DES key missing.\n");
          return(-1);
        }
      break;
    case SADB_X_EALG_BLOWFISHCBC:
      iv_len = 8;
      if (!entry->bf_key)
        {
          printf("hip_esp_encrypt: BLOWFISH key missing.\n");
          return(-1);
        }
      break;
    case SADB_EALG_NULL:
      iv_len = 0;
      break;
    case SADB_X_EALG_AESCBC:
      iv_len = 16;
      if (!entry->aes_key && entry->e_key)
        {
          entry->aes_key = malloc(sizeof(AES_KEY));
          if (AES_set_encrypt_key(entry->e_key, 8 *
                                  entry->e_keylen,
                                  entry->aes_key))
            {
              printf("hip_esp_encrypt: AES key problem!\n");
            }
        }
      else if (!entry->aes_key)
        {
          printf("hip_esp_encrypt: AES key missing.\n");
          return(-1);
        }
      break;
    default:
      printf("Unsupported encryption transform (%d).\n",
             entry->e_type);
#ifdef HIP_VPLS
      touchHeartbeat = 0;
#endif
      return(-1);
      break;
    }

  /* Add initialization vector (random value) */
  if (iv_len > 0)
    {
      RAND_bytes(cbc_iv, iv_len);
      memcpy(esp->enc_data, cbc_iv, iv_len);
      padlen = iv_len - ((elen + 2) % iv_len);
    }
  else
    {
      /* Padding with NULL not based on IV length */
      padlen = 4 - ((elen + 2) % 4);
    }
  /* add padding to input data, set padinfo */
  location = hdr_len + elen;
  for (i = 0; i < padlen; i++)
    {
      in[location + i] = i + 1;
    }
  padinfo = (struct ip_esp_padinfo*) &in[location + padlen];
  padinfo->pad_length = padlen;
  padinfo->next_hdr = (family == AF_INET) ? iph->ip_p : ip6h->ip6_nxt;
#ifdef HIP_VPLS
  if (family == AF_UNSPEC)
    {
      padinfo->next_hdr = 0;
    }
#endif
  /* padinfo is encrypted too */
  elen += padlen + 2;

  /* Apply the encryption cipher directly into out buffer
   * to avoid extra copying */
  switch (entry->e_type)
    {
    case SADB_EALG_3DESCBC:
      des_ede3_cbc_encrypt(&in[hdr_len],
                           &esp->enc_data[iv_len], elen,
                           entry->ks[0], entry->ks[1], entry->ks[2],
                           (des_cblock*)cbc_iv, DES_ENCRYPT);
      break;
    case SADB_X_EALG_BLOWFISHCBC:
      BF_cbc_encrypt(&in[hdr_len],
                     &esp->enc_data[iv_len], elen,
                     entry->bf_key, cbc_iv, BF_ENCRYPT);
      break;
    case SADB_EALG_NULL:
      memcpy(esp->enc_data, &in[hdr_len], elen);
      break;
    case SADB_X_EALG_AESCBC:
      AES_cbc_encrypt(&in[hdr_len],
                      &esp->enc_data[iv_len], elen,
                      entry->aes_key, cbc_iv, AES_ENCRYPT);
      break;
    default:
      break;
    }
  elen += iv_len;       /* auth will include IV */
  *outlen += elen;

  /*
   * Authentication
   */
  switch (entry->a_type)
    {
    case SADB_AALG_MD5HMAC:
      alen = HMAC_SHA_96_BITS / 8;           /* 12 bytes */
      if (!entry->a_key || (entry->a_keylen == 0))
        {
          printf("auth err: missing keys\n");
          return(-1);
        }
      elen += sizeof(struct ip_esp_hdr);
      HMAC(   EVP_md5(), entry->a_key, entry->a_keylen,
              (__u8*)esp, elen, hmac_md, &hmac_md_len);
      memcpy(&out[elen + (use_udp ? sizeof(udphdr) : 0)],
             hmac_md, alen);
      *outlen += alen;
      break;
    case SADB_AALG_SHA1HMAC:
      alen = HMAC_SHA_96_BITS / 8;           /* 12 bytes */
      if (!entry->a_key || (entry->a_keylen == 0))
        {
          printf("auth err: missing keys\n");
          return(-1);
        }
      elen += sizeof(struct ip_esp_hdr);
      HMAC(   EVP_sha1(), entry->a_key, entry->a_keylen,
              (__u8*)esp, elen, hmac_md, &hmac_md_len);
      memcpy(&out[elen + (use_udp ? sizeof(udphdr) : 0)],
             hmac_md, alen);
      *outlen += alen;
      break;
    default:
      break;
    }

#ifndef HIP_VPLS
  /* Record the address family of this packet, so incoming
   * replies of the same protocol/ports can be matched to
   * the same family.
   */
  if (hip_add_proto_sel_entry(LSI4(&entry->lsi),
                              (__u8)(iph ? iph->ip_p : ip6h->ip6_nxt),
                              iph ? (__u8*)(iph + 1) : (__u8*)(ip6h + 1),
                              family, 0, now  ) < 0)
    {
      printf("hip_esp_encrypt(): error adding sel entry.\n");
    }


  /* Restore the checksum in the input data, in case this is
   * a broadcast packet that needs to be re-sent to some other
   * destination.
   */
  if (checksum_fix > 0)
    {
#ifdef __MACOSX__
      if (iph->ip_p == IPPROTO_UDP)
        {
          ((struct udphdr*)(iph + 1))->uh_sum = checksum_fix;
        }
      else if (iph->ip_p == IPPROTO_TCP)
        {
          ((struct tcphdr*)(iph + 1))->th_sum = checksum_fix;
        }
#else
      if (iph->ip_p == IPPROTO_UDP)
        {
          ((struct udphdr*)(iph + 1))->check = checksum_fix;
        }
      else if (iph->ip_p == IPPROTO_TCP)
        {
          ((struct tcphdr*)(iph + 1))->check = checksum_fix;
        }
#endif
    }
#endif /* HIP_VPLS */

  /*
   * Build a UDP header at the beginning of out buffer.
   */
  if (use_udp)
    {
      memset(udph, 0, sizeof(udphdr));
      /* grab port numbers from sockaddr structures */
      if (entry->src_addrs->addr.ss_family == AF_INET)
        {
          udph->src_port = ((struct sockaddr_in*)
                            &entry->src_addrs->addr)->sin_port;
        }
      if (entry->dst_addrs->addr.ss_family == AF_INET)
        {
          udph->dst_port = ((struct sockaddr_in*)
                            &entry->dst_addrs->addr)->sin_port;
        }
      if (udph->src_port == 0)
        {
          printf("Warning: default to src HIP_UDP_PORT %d\n",
                 HIP_UDP_PORT);
          udph->src_port = htons(HIP_UDP_PORT);
        }
      if (udph->dst_port == 0)
        {
          printf("Warning: default to dst HIP_UDP_PORT %d\n",
                 HIP_UDP_PORT);
          udph->dst_port = htons(HIP_UDP_PORT);
        }
      udph->len = htons((__u16) * outlen);
      /* TODO: support IPv6 ESP over UDP here */
      udph->checksum = checksum_udp_packet (out,
                                            SA(&entry->src_addrs->
                                               addr),
                                            SA(&entry->dst_addrs->
                                               addr));
    }

  if (entry->spinat)
    {
#ifdef VERBOSE_MR_DEBUG
      printf("Rewriting outgoing ESP SPI from 0x%x to 0x%x.\n",
             ntohl(esp->spi), entry->spinat);
#endif /* VERBOSE_MR_DEBUG */
      esp->spi = htonl(entry->spinat);
    }
  return(0);
}

/*
 * hip_esp_decrypt()
 *
 * in:		in	pointer to IP header of ESP packet to decrypt
 *              len	packet length
 *              out	pointer of where to build decrypted packet
 *              offset	offset where decrypted packet is stored: &out[offset]
 *              outlen	length of new packet
 *              entry	the SADB entry
 *              iph     IPv4 header or NULL for IPv6
 *              now	pointer to current time (avoid extra gettimeofday call)
 *
 * out:		New packet is built in out, outlen.
 *              Returns 0 on success, -1 otherwise.
 *
 * Perform authentication and decryption of ESP packets.
 */
int hip_esp_decrypt(__u8 *in, int len, __u8 *out, int *offset, int *outlen,
                    hip_sadb_entry *entry, struct ip *iph, struct timeval *now)
{
  int alen = 0, elen = 0, iv_len = 0;
  unsigned int hmac_md_len;
  struct ip_esp_hdr *esp;
  /*udphdr *udph;*/

  struct ip_esp_padinfo *padinfo = 0;
  __u8 cbc_iv[16];
  __u8 hmac_md[EVP_MAX_MD_SIZE];
#ifndef HIP_VPLS
  __u64 dst_mac;
  __u16 sum;
  int family_out;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;
#endif /* HIP_VPLS */
  int use_udp = FALSE;
  __u32 new_seqno_hi = 0, loss;
  __u64 shift;
  struct sockaddr_storage dst;

  if (!in || !out || !entry)
    {
      return(-1);
    }


  if (entry->mode == 3)         /*(HIP_ESP_OVER_UDP) */
    {
      use_udp = TRUE;
      /*udph = (udphdr*) &in[sizeof(struct ip)];*/
      esp = (struct ip_esp_hdr*)&in[sizeof(struct ip) +
                                    sizeof(udphdr)];
      /* TODO: IPv6 UDP here */
    }
  else                          /* not UDP-encapsulated */
    {
      if (iph)                  /* IPv4 */
        {
          esp = (struct ip_esp_hdr*) &in[sizeof(struct ip)];
        }
      else                      /* IPv6 - header not included */
        {
          esp = (struct ip_esp_hdr*) &in[0];
        }
    }
  /* if (ntohl(esp->spi) != entry->spi)
   *       return(-1); *//* this check might be excessive */

  /* An IPv6 header is larger than an IPv4 header, so data
   * is decrypted into a buffer at the larger offset, since
   * we do not know the (inner) IP version before decryption. */
  *offset = sizeof(struct eth_hdr) + sizeof(struct ip6_hdr);       /* 54 */
#ifdef HIP_VPLS
  *offset = sizeof(struct eth_hdr);        /* Tunnel mode */
#endif

  /*
   *  Preliminary anti-replay check.
   */
  if (esp_anti_replay_check_initial(entry, ntohl(esp->seq_no),
                                    &new_seqno_hi))
    {
      printf("duplicate sequence number detected: %x\n",
             ntohl(esp->seq_no));
      return(-1);
    }

  /*
   *   Authentication
   */
  switch (entry->a_type)
    {
    case SADB_AALG_MD5HMAC:
      alen = HMAC_SHA_96_BITS / 8;           /* 12 bytes */
      elen = len - sizeof(struct ip_esp_hdr) - alen;
      if (iph)
        {
          elen -= sizeof(struct ip);
        }
      if (use_udp)             /* HIP_ESP_OVER_UDP */
        {
          elen -= sizeof(udphdr);
        }
      if (!entry->a_key || (entry->a_keylen == 0))
        {
          printf("auth err: missing keys\n");
          return(-1);
        }
      HMAC(   EVP_md5(), entry->a_key, entry->a_keylen,
              (__u8*)esp, elen + sizeof(struct ip_esp_hdr),
              hmac_md, &hmac_md_len);
      if (memcmp(&in[len - alen], hmac_md, alen) != 0)
        {
          printf("auth err: MD5 auth failure\n");
          return(-1);
        }
      break;
    case SADB_AALG_SHA1HMAC:
      alen = HMAC_SHA_96_BITS / 8;           /* 12 bytes */
      elen = len - sizeof(struct ip_esp_hdr) - alen;
      if (iph)
        {
          elen -= sizeof(struct ip);
        }
      if (use_udp)             /* HIP_ESP_OVER_UDP */
        {
          elen -= sizeof(udphdr);
        }
      if (!entry->a_key || (entry->a_keylen == 0))
        {
          printf("auth err: missing keys\n");
          return(-1);
        }
      HMAC(   EVP_sha1(), entry->a_key, entry->a_keylen,
              (__u8*)esp, elen + sizeof(struct ip_esp_hdr),
              hmac_md, &hmac_md_len);
      if (memcmp(&in[len - alen], hmac_md, alen) != 0)
        {
          printf("auth err: SHA1 auth failure SPI=0x%x\n",
                 entry->spi);
          return(-1);
        }
      break;
    default:
      break;
    }

  /* update anti-replay window now that integrity has been verified */
  shift = esp_update_anti_replay(entry, ntohl(esp->seq_no), new_seqno_hi);
  if (shift == 1)
    {
      /* normal case - in-order packet has next sequence number */
    }
  else if (shift == 0)
    {
      if (entry->lost > 0)             /* seqno within window, discount loss */
        {
          entry->lost--;
        }
    }
  else
    {
      /* window has shifted by loss number of packets */
      loss = (__u32)shift - 1;
      entry->lost += loss;
      /* track loss based on IPv4 destination locator */
      if (iph)
        {
          dst.ss_family = AF_INET;
          memcpy(SA2IP(&dst), &iph->ip_dst, SAIPLEN(&dst));
          loss = hip_sadb_inc_loss(entry, loss, SA(&dst));
          if (loss > MULTIHOMING_LOSS_THRESHOLD)
            {
              esp_signal_loss(entry->spi, loss, SA(&dst));
              hip_sadb_reset_loss(entry, SA(&dst));
            }
        }
    }

  /*
   *   Decryption
   */
  switch (entry->e_type)
    {
    case SADB_EALG_3DESCBC:
      iv_len = 8;
      if (!entry->e_key || (entry->e_keylen == 0))
        {
          printf("hip_esp_decrypt: 3-DES key missing.\n");
          return(-1);
        }
      break;
    case SADB_X_EALG_BLOWFISHCBC:
      iv_len = 8;
      if (!entry->bf_key)
        {
          printf("hip_esp_decrypt: BLOWFISH key missing.\n");
          return(-1);
        }
      break;
    case SADB_EALG_NULL:
      iv_len = 0;
      break;
    case SADB_X_EALG_AESCBC:
      iv_len = 16;
      if (!entry->aes_key && entry->e_key)
        {
          entry->aes_key = malloc(sizeof(AES_KEY));
          if (AES_set_decrypt_key(entry->e_key, 8 *
                                  entry->e_keylen,
                                  entry->aes_key))
            {
              printf("hip_esp_decrypt: AES key problem!\n");
            }
        }
      else if (!entry->aes_key)
        {
          printf("hip_esp_decrypt: AES key missing.\n");
          return(-1);
        }
      break;
    default:
      printf("Unsupported decryption algorithm (%d)\n",
             entry->e_type);
      break;
    }
  memcpy(cbc_iv, esp->enc_data, iv_len);
  elen -= iv_len;       /* don't include iv as part of ciphertext */

  switch (entry->e_type)
    {
    case SADB_EALG_3DESCBC:
      des_ede3_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset],elen,
                           entry->ks[0], entry->ks[1], entry->ks[2],
                           (des_cblock*)cbc_iv, DES_DECRYPT);
      break;
    case SADB_X_EALG_BLOWFISHCBC:
      BF_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset], elen,
                     entry->bf_key, cbc_iv, BF_DECRYPT);
      break;
    case SADB_EALG_NULL:
      memcpy(&out[*offset], esp->enc_data, elen);
      /* padinfo = (struct ip_esp_padinfo*) &in[len - alen - 2]; */
      break;
    case SADB_X_EALG_AESCBC:
      AES_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset], elen,
                      entry->aes_key, cbc_iv, AES_DECRYPT);
      break;
    default:
      return(-1);
    }

  /* remove padding */
  padinfo = (struct ip_esp_padinfo*) &out[*offset + elen - 2];
  elen -= 2 + padinfo->pad_length;

#ifndef HIP_VPLS
  /* determine address family for new packet based on
   * decrypted upper layer protocol header
   */
  family_out = hip_select_family_by_proto(LSI4(
                                            &entry->lsi),
                                          padinfo->next_hdr,
                                          &out[*offset], now);

  /* rewrite upper-layer checksum
   * checksum based on HITs --> based on LSIs */
  if (family_out == AF_INET)
    {
      switch (padinfo->next_hdr)
        {
#ifdef __MACOSX__
        case IPPROTO_TCP:
          tcp = (struct tcphdr*)&out[*offset];
          sum = htons(tcp->th_sum);
          sum =
            csum_hip_revert(  LSI4(&entry->lsi),
                              htonl(g_tap_lsi),
                              sum, htons(entry->hit_magic));
          tcp->th_sum = htons(sum);
          break;
        case IPPROTO_UDP:
          udp = (struct udphdr*)&out[*offset];
          sum = htons(udp->uh_sum);
          sum =
            csum_hip_revert(  LSI4(&entry->lsi),
                              htonl(g_tap_lsi),
                              sum, htons(entry->hit_magic));
          udp->uh_sum = htons(sum);
          break;
#else /* __MACOSX__ */
        case IPPROTO_TCP:
          tcp = (struct tcphdr*)&out[*offset];
          sum = htons(tcp->check);
          sum =
            csum_hip_revert(  LSI4(&entry->lsi),
                              htonl(g_tap_lsi),
                              sum, htons(entry->hit_magic));
          tcp->check = htons(sum);
          break;
        case IPPROTO_UDP:
          udp = (struct udphdr*)&out[*offset];
          sum = htons(udp->check);
          sum =
            csum_hip_revert(  LSI4(&entry->lsi),
                              htonl(g_tap_lsi),
                              sum, htons(entry->hit_magic));
          udp->check = htons(sum);
#endif /* __MACOSX__ */
        default:
          break;
        }
    }

  /* set offset to index the beginning of the packet */
  if (family_out == AF_INET)         /* offset = 20 */
    {
      *offset -= (sizeof(struct eth_hdr) + sizeof(struct ip));
    }
  else            /* offset = 0 */
    {
      *offset -= (sizeof(struct eth_hdr) + sizeof(struct ip6_hdr));
    }

  /* Ethernet header */
  dst_mac = get_eth_addr(family_out,
                         (family_out == AF_INET) ? SA2IP(&entry->lsi) :
                         SA2IP(&entry->dst_hit));
  add_eth_header(&out[*offset], dst_mac, g_tap_mac,
                 (family_out == AF_INET) ? 0x0800 : 0x86dd);

  /* IP header */
  if (family_out == AF_INET)
    {
      add_ipv4_header(&out[*offset + sizeof(struct eth_hdr)],
                      LSI4(&entry->lsi), htonl(g_tap_lsi), iph,
                      (__u16)(sizeof(struct ip) + elen),
                      padinfo->next_hdr);
      *outlen = sizeof(struct eth_hdr) + sizeof(struct ip) + elen;
    }
  else
    {
      add_ipv6_header(&out[*offset + sizeof(struct eth_hdr)],
                      SA(&entry->src_hit), SA(&entry->dst_hit),
                      NULL, iph, (__u16)elen, padinfo->next_hdr);
      *outlen = sizeof(struct eth_hdr) + sizeof(struct ip6_hdr) +
                elen;
    }
#else /* HIP_VPLS */
  *outlen = sizeof(struct eth_hdr) + elen;
#endif /* HIP_VPLS */

  /* previously, this happened after write(), but there
   * is some problem with using the entry ptr then */
  hip_sadb_inc_bytes(entry, *outlen - sizeof(struct eth_hdr), now, 0);
  return(0);
}

/*
 * rewrite_checksum()
 *
 * Rewrite the upper-later TCP/UDP checksum so it is based on the HITs
 * (which are summed and passed in as __u16 magic).
 * Returns the old checksum value, so it can be restored.
 */
__u16 rewrite_checksum(__u8 *data, __u16 magic)
{
  struct ip *iph = (struct ip *)data;
  struct tcphdr *tcp;
  struct udphdr *udp;
  __u16 ret = 0;


  /* rewrite upper-layer checksum, so it is based on HITs */
  switch (iph->ip_p)
    {
    case IPPROTO_TCP:
      tcp = (struct tcphdr*)(iph + 1);
#ifdef __MACOSX__
      ret = tcp->th_sum;
      tcp->th_sum = csum_tcpudp_hip_nofold(
        iph->ip_src.s_addr, iph->ip_dst.s_addr,
        tcp->th_sum, magic);
#else
      ret = tcp->check;
      tcp->check = csum_tcpudp_hip_nofold(
        iph->ip_src.s_addr, iph->ip_dst.s_addr,
        tcp->check, magic);
#endif
      break;
    case IPPROTO_UDP:
      udp = (struct udphdr*)(iph + 1);
#ifdef __MACOSX__
      ret = udp->uh_sum;
      udp->uh_sum = csum_tcpudp_hip_nofold(
        iph->ip_src.s_addr, iph->ip_dst.s_addr,
        udp->uh_sum, magic);
#else
      ret = udp->check;
      udp->check = csum_tcpudp_hip_nofold(
        iph->ip_src.s_addr, iph->ip_dst.s_addr,
        udp->check, magic);
#endif
      break;
    default:
      break;
    }
  return(ret);
}

/*
 * add_eth_header()
 *
 * Build an Ethernet header.
 */
void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type)
{
  struct eth_hdr *eth = (struct eth_hdr*)data;

  memcpy(eth->dst, &dst, 6);
  memcpy(eth->src, &src, 6);
  eth->type = htons((__u16)type);
}

/*
 * add_ipv4_header()
 *
 * Build an IPv4 header, copying some parameters from an old ip header (old),
 * src and dst in host byte order. old may be NULL.
 */
void add_ipv4_header(__u8 *data, __u32 src, __u32 dst, struct ip *old,
                     __u16 len, __u8 proto)
{
  struct ip *iph = (struct ip*)data;

  memset(iph, 0, sizeof(struct ip));
  iph->ip_v = 4;
  iph->ip_hl = 5;
  iph->ip_tos = old ? old->ip_tos : 0;       /* preserve TOS field */
  iph->ip_len = htons(len);
  iph->ip_id  = old ? old->ip_id : 0;        /* copy identification */
  iph->ip_off = old ? old->ip_off : 0;       /* copy fragmentation offset */
  iph->ip_ttl = old ? old->ip_ttl : 255;       /* preserve TTL */
  iph->ip_p = proto;
  iph->ip_sum = 0;
  iph->ip_src.s_addr = htonl(src);       /* assume host byte order */
  iph->ip_dst.s_addr = htonl(dst);

  /* add the header checksum */
#if defined(__MACOSX__) && defined(__BIG_ENDIAN__)
  iph->ip_sum = ip_fast_csum((__u8*)iph, 20);
#else
  iph->ip_sum = ip_fast_csum((__u8*)iph, iph->ip_hl);
#endif
}

/*
 * add_ipv6_pseudo_header()
 *
 * Build an IPv6 pseudo-header for upper-layer checksum calculation.
 */
void add_ipv6_pseudo_header(__u8 *data, struct sockaddr *src,
                            struct sockaddr *dst, __u32 len, __u8 proto)
{
  int l;
  struct _ph {
    __u32 ph_len;
    __u8 ph_zero[3];
    __u8 ph_next_header;
  } *ph;
  memset(data, 0, 40);

  /* 16 bytes source address, 16 bytes destination address */
  l = sizeof(struct in6_addr);
  memcpy(&data[0], SA2IP(src), l);
  memcpy(&data[l], SA2IP(dst), l);
  l += sizeof(struct in6_addr);
  /* upper-layer packet length, zero, next header */
  ph = (struct _ph*) &data[l];
  ph->ph_len = htonl(len);
  memset(ph->ph_zero, 0, 3);
  ph->ph_next_header = proto;
}

/*
 * add_ipv6_header()
 *
 * Build an IPv6 header, copying some parameters from an old header (old),
 * src and dst in network byte order.
 */
void add_ipv6_header(__u8 *data,
                     struct sockaddr *src,
                     struct sockaddr *dst,
                     struct ip6_hdr *old,
                     struct ip *old4,
                     __u16 len,
                     __u8 proto)
{
  struct ip6_hdr *ip6h = (struct ip6_hdr*)data;
  __u32 tc;

  memset(ip6h, 0, sizeof(struct ip6_hdr));
  ip6h->ip6_flow = 0;       /* zero the version (4), TC (8), flow-ID (20) */
  ip6h->ip6_vfc = 0x60;
  ip6h->ip6_plen = htons(len);
  ip6h->ip6_nxt = proto;
  ip6h->ip6_hlim = 255;
  memcpy(&ip6h->ip6_src, SA2IP(src), sizeof(struct in6_addr));
  memcpy(&ip6h->ip6_dst, SA2IP(dst), sizeof(struct in6_addr));

  /* Try to preserve flow label and hop limit where possible. */
  if (old)
    {
      ip6h->ip6_flow = old->ip6_flow;
      ip6h->ip6_hlim = old->ip6_hlim;
    }
  else if (old4)
    {
      tc = old4->ip_tos << 24;
      ip6h->ip6_flow |= tc;             /* 8 bits traffic class */
      ip6h->ip6_hlim = old4->ip_ttl;                    /* __u8 */
    }
}

#ifdef __MACOSX__

void add_outgoing_esp_header(__u8 *data, __u32 src, __u32 dst, __u16 len)
{
  struct ip *iph = (struct ip*)data;

  memset(iph, 0, sizeof(struct ip));
  iph->ip_v = 4;
  iph->ip_hl = 5;
  iph->ip_tos = 0;
  iph->ip_len = htons(len + sizeof(struct ip));
  iph->ip_id  = 1337;
  iph->ip_off = htons(0x4000);
  iph->ip_ttl = 64;
  iph->ip_p = IPPROTO_ESP;
  iph->ip_sum = 0;
  iph->ip_src.s_addr = src;
  iph->ip_dst.s_addr = dst;

  /* add the header checksum */
  iph->ip_sum = ip_fast_csum((__u8*)iph, iph->ip_hl);
}

#endif

/*
 * get_mac_addr()
 * Give a random 6-bit Ethernet address given an IPv4/IPv6 address.
 */
__u64 get_eth_addr(int family, __u8 *addr)
{
  __u32 index = 0, *p;
  int i, len;
  __u64 r = 0;

  if (!addr)
    {
      return(0);
    }

  /* sum the 32-bit words in address */
  p = (__u32*) addr;
  len = (family == AF_INET) ? 4 : 16;
  for (i = 0; i < len; i += 4)
    {
      index += *p++;
    }

  /* use sum as index into array of Ethernet addresses */
  index %= MAX_ETH_ADDRS;
  memcpy(&r, &eth_addrs[index], 6);
  ((char *)&r)[0] &= 0xFE;       /* clear the multicast bit */

  return(r);
}

/* helper for sending ESP message to hipd over the espsp socketpair */
void esp_send_to_hipd(char *data, int len, char *errmsg)
{
  /* int i;
   *  printf("sending this to hipd:\n");
   *  for (i = 0; i < len; i ++) {
   *   printf("%02x ", data[i] & 0xFF);
   *  } */
#ifdef __WIN32__
  if (send(espsp[0], data, len, 0) < 0)
    {
#else
  if (write(espsp[0], data, len) != len)
    {
#endif /* __WIN32__ */
      printf("%s write error: %s\n", errmsg, strerror(errno));
    }
}

/* send an ESP_ACQUIRE_LSI message, which results in a
 * call to start_base_exchange() in hipd */
void esp_start_base_exchange(struct sockaddr *lsi)
{
  struct sockaddr_storage dst;
  const int len = sizeof(espmsg) + sizeof(struct sockaddr_storage);
  char msgbuff[sizeof(espmsg) + sizeof(struct sockaddr_storage)] = {0};
  espmsg *msg = (espmsg*) &msgbuff[0];

  /* lsi is in host byte order, convert to network for ACQUIRE message */
  memcpy(&dst, lsi, sizeof(struct sockaddr_storage));
  if (dst.ss_family == AF_INET)
    {
      LSI4(&dst) = htonl(LSI4(lsi));
    }
  msg->message_type = ESP_ACQUIRE_LSI;
  msg->message_data = htonl(sizeof(struct sockaddr_storage));
  memcpy(&msgbuff[sizeof(espmsg)], &dst, sizeof(struct sockaddr_storage));
  esp_send_to_hipd((char*) msg, len, "esp_start_base_exchange()");
}

/* send an ESP_EXPIRE_SPI message, which results in a
 * call to start_expire() in hipd */
void esp_start_expire(__u32 spi)
{
  espmsg msg;
  msg.message_type = ESP_EXPIRE_SPI;
  msg.message_data = htonl(spi);
  esp_send_to_hipd((char*) &msg, sizeof(msg), "esp_start_expire()");
}

/* send an ESP_UDP_CTL message, which results in a
 * call to receive_udp_hip_packet() in hipd */
void esp_receive_udp_hip_packet(char *buff, int len)
{
  char msgbuff[sizeof(espmsg) + BUFF_LEN];
  espmsg *msg = (espmsg*) &msgbuff[0];
  msg->message_type = ESP_UDP_CTL;
  msg->message_data = htonl((__u32)len);
  memcpy(&msgbuff[sizeof(espmsg)], buff, len);
  esp_send_to_hipd( msgbuff, len + sizeof(espmsg),
                    "esp_receive_udp_hip_packet()");
}

/* send an ESP_ADDR_LOSS message to signal that lost ESP packets were detected
 */
void esp_signal_loss(__u32 spi, __u32 loss, struct sockaddr *dst)
{
  const int len = sizeof(espmsg) + 2 * sizeof(__u32) + \
                  sizeof(struct sockaddr_storage);
  char msgbuff[sizeof(espmsg) + 2 * sizeof(__u32) + \
               sizeof(struct sockaddr_storage)];
  struct _loss_data {
    __u32 spi;
    __u32 loss;
    struct sockaddr_storage dst;
  } *ld;
  espmsg *msg = (espmsg*) &msgbuff[0];

  memset(msgbuff, 0, len);
  msg->message_type = ESP_ADDR_LOSS;
  msg->message_data = htonl(len - sizeof(espmsg));

  ld = (struct _loss_data *) &msgbuff[sizeof(espmsg)];
  ld->spi = htonl(spi);
  ld->loss = htonl(loss);
  ld->dst.ss_family = dst->sa_family;
  memcpy(SA2IP(&ld->dst), SA2IP(dst), SAIPLEN(dst));
  /* printf("%s spi=0x%x loss=%u\n", __FUNCTION__, spi, loss); */
  esp_send_to_hipd((char*) msg, len, "esp_signal_loss()");
}

/*
 * update the sequence number counters in the sadb entry and return the next
 * sequence number
 */
__u32 get_next_seqno(hip_sadb_entry *entry)
{
  __u32 r = ++entry->sequence;
  /* overflow of lower 32 bits */
  if (r == 0)
    {
      r = ++entry->sequence;           /* don't use zero */
      entry->sequence_hi++;
    }
  return(r);
}

/*
 * Perform preliminary anti-replay verification on an ESP packet's sequence
 * number against the receive window of the SA; sadb entry is not modified.
 * Determine the high-order bits of a 64-bit ESN based on anti-replay packet
 * window and received lower bits.
 *
 * Returns 0 if the check passes, 1 if the check fails.
 * Returns value high-order ESN bits in  sequqnce_hi.
 */
int esp_anti_replay_check_initial(hip_sadb_entry *entry, __u32 seqno,
                                  __u32 *sequence_hi)
{
  /* T: top of window */
  __u32 replay_win_maxl = (__u32)(entry->replay_win_max & 0xFFFFFFFF);
  /* B: botttom of window */
  __u64 replay_win_min = entry->replay_win_max - REPLAY_WIN_SIZE + 1;
  __u32 replay_win_minl = (__u32)(replay_win_min & 0xFFFFFFFF);
  __u64 shift, esn;
  int do_replay_check;

  *sequence_hi = entry->sequence_hi;

  /* RFC 4303 Appendix A Case A: window within one subspace */
  if (replay_win_maxl >= REPLAY_WIN_SIZE - 1)
    {
      do_replay_check = 1;
      if (seqno >= replay_win_minl)
        {
          if (seqno > replay_win_maxl)
            {
              /* seq number to the right of the window */
              do_replay_check = 0;
            }
        }
      else
        {
          /* assume seq number wrap around to next subspace */
          (*sequence_hi)++;
          do_replay_check = 0;               /* new subspace */
        }
      /* RFC 4303 Appendix A Case B: window spans two seq no subspaces
       */
    }
  else
    {
      do_replay_check = 0;
      if (seqno >= replay_win_minl)
        {
          /* seq number from previous subspace;
           * don't wrap 64-bit ESN space */
          if (*sequence_hi > 0)
            {
              (*sequence_hi)--;
              do_replay_check = 1;
            }
        }
      else
        {
          /* seq number in current sequence_hi subspace */
          if (seqno <= replay_win_maxl)
            {
              do_replay_check = 1;
            }
          /* else seq number to the right of the window */
        }
    }

  /* check if this sequence number has already been seen in the
   * receive window bitmap
   */
  if (do_replay_check)
    {
      esn = ((__u64)(*sequence_hi) << 32) | seqno;
      shift = entry->replay_win_max - esn;
      if ((entry->replay_win_map >> (__u32)shift) & 0x1)
        {
          return(1);               /* drop packet - duplicate detected */
        }
    }
  return(0);       /* pass packet */
}

/*
 * Update the ESP anti-replay window using sequence number derived from
 * initial checks. Under normal conditions, returns 1 as the next received
 * packet is the next sequence number; return value > 1 indicates window
 * shifting, and 0 indicates received packet within window.
 */
__u64 esp_update_anti_replay(hip_sadb_entry *entry, __u32 seqno,
                             __u32 seqno_hi)
{
  __u64 esn = ((__u64)seqno_hi << 32) | seqno;
  __u64 shift;
  if (esn > entry->replay_win_max)
    {
      /* shift window to the left, new max seq no received */
      shift = esn - entry->replay_win_max;
      entry->replay_win_map = entry->replay_win_map << shift;
      entry->replay_win_max = esn;
      entry->replay_win_map |= 0x1;
      entry->sequence_hi = seqno_hi;
    }
  else
    {
      /* update bit corresponding to esn in window */
      shift = entry->replay_win_max - esn;
      entry->replay_win_map |= 0x1 << shift;
      return(0);
    }
  return(shift);
}

