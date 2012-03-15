/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2009-2012 the Boeing Company
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
 *  \file  hip_mr.c
 *
 *  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *            Orlie Brewer <orlie.t.brewer@boeing.com>
 *
 *  \brief  Mobile router SPINAT implemenation using netfilter queue
 *
 */

#include <unistd.h>
#include <pthread.h>            /* phread_exit() */
#include <netinet/in.h>         /* INET6_ADDRSTRLEN */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/ip6.h>        /* struct ip6_hdr */
#include <netinet/icmp6.h>      /* struct icmp6_hdr */
#include <netinet/tcp.h>        /* struct tcphdr */
#include <netinet/udp.h>        /* struct udphdr */
#include <arpa/inet.h>
#include <stdio.h>              /* printf() */
#include <string.h>             /* strerror() */
#include <errno.h>              /* errno */
#include <openssl/rand.h>       /* RAND_bytes() */
#include <sys/time.h>           /* gettimeofday() */
#include <hip/hip_service.h>
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_globals.h>
#include <hip/hip_mr.h>
#include <win32/checksum.h>     /* ip_fast_csum() */
#include <linux/types.h>
#ifndef aligned_be64
#define aligned_be64 u_int64_t __attribute__((aligned(8)))
#endif
#include <linux/netfilter.h>    /* NF_DROP */

#include <linux/version.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)
#include <linux/netfilter_ipv4.h>    /* NF_IP_PRE_ROUTING, etc. */
#define NF_INET_PRE_ROUTING  NF_IP_PRE_ROUTING
#define NF_INET_LOCAL_IN     NF_IP_LOCAL_IN
#define NF_INET_FORWARD      NF_IP_FORWARD
#define NF_INET_LOCAL_OUT    NF_IP_LOCAL_OUT
#define NF_INET_POST_ROUTING NF_IP_POST_ROUTING
#endif

#define BUFSIZE 2048
#define MR_TIMEOUT_US 500000 /* microsecond timeout for mobile_router select()*/
#define MAX_MR_CLIENTS MAX_CONNECTIONS
#define MAX_EIFACES 8

enum { EIF_UNAVAILABLE, EIF_AVAILABLE };

/*
 * local data
 */

struct if_data {
  char *name;
  int ifindex;
  int state;
  struct sockaddr_storage address;
};

static hip_mr_client hip_mr_client_table[MAX_MR_CLIENTS];
static hip_mutex_t hip_mr_client_mutex;
static int max_hip_mr_clients;

static int neifs = 0;
static struct if_data external_interfaces[MAX_EIFACES];

/*
 * local functions
 */
int  addr_match_payload(__u8 *payload, int family, struct sockaddr *src,
                        struct sockaddr *dst);
__u32 get_next_spinat(void);
hip_mr_client *mr_client_lookup(hip_hit hit);
void mr_process_I1(hip_mr_client *hip_mr_c, int family, int inbound,
                   struct if_data *ext_if, hiphdr *hiph,
                   unsigned char *payload);
void mr_process_R1(hip_mr_client *hip_mr_c, int family, int inbound,
                   struct if_data *ext_if, hiphdr *hiph,
                   unsigned char *payload);
__u32 mr_process_I2(hip_mr_client *hip_mr_c, int family, int inbound,
                    struct if_data *ext_if, hiphdr *hiph,
                    unsigned char *payload);
__u32 mr_process_R2(hip_mr_client *hip_mr_c, int family, int inbound,
                    struct if_data *ext_if, hiphdr *hiph,
                    unsigned char *payload);
__u32 mr_process_I1_or_R2(hip_mr_client *hip_mr_c, int family, int inbound,
                          struct if_data *ext_if, hiphdr *hiph,
                          unsigned char *payload);
void mr_process_CLOSE(hip_mr_client *hip_mr_c, int family, int inbound,
                      struct if_data *ext_if, hiphdr *hiph,
                      unsigned char *payload, int packet_type);
unsigned char *add_tlv_spi_nat(int family, unsigned char *payload,
                               size_t data_len, size_t *new_len, __u32 new_spi);
unsigned char *check_hip_packet(int family, int inbound,
                                struct if_data *ext_if, unsigned char *payload,
                                size_t data_len, size_t *new_len);
unsigned char *new_header(int family, unsigned char *payload);
unsigned char *check_esp_packet(int family, int inbound, struct if_data *ext_if,
                                unsigned char *payload);
void mr_clear_retransmissions(hip_spi_nat *spi_nats);
void *hip_mobile_router(void *arg);
int hip_send_proxy_update(struct sockaddr *newaddr, struct sockaddr *dstaddr,
                          hip_spi_nat *spi_nat, hip_hit *mn_hit);
int build_tlv_proxy_hmac(hip_proxy_ticket *ticket, __u8 *data, int location,
                         int type);
/* global functions defined in include/hip/hip_funcs.h
 *  int hip_mr_set_external_if();
 *  void hip_mr_handle_address_change(int add, struct sockaddr *newaddr, int
 * ifi);
 *  int init_hip_mr_client(hip_hit peer_hit, struct sockaddr *src);
 */
int free_hip_mr_client(hip_mr_client *hip_mr_c);
/* int add_proxy_ticket(const __u8 *data); */
int is_mobile_router();
int hip_mobile_router_add_remove_rules(int queue_num, int del);

int netfilter_queue_init(int queue_num);
int netfilter_queue_bind(int nlfd, int n, int af);
int netfilter_queue_unbind(int nlfd, int n, int af);
int netfilter_queue_config_command(int nlfd, int queue_num, int cmd, int af);
int netfilter_queue_config_param(int nlfd, int queue_num);
int netfilter_queue_sendmsg(int nlfd, __u8 *data, int len);
__u8* netfilter_queue_command_hdr(__u8 *buf, int queue_num, int type, int *len);
int netfilter_get_packet(int nlfd, __u8 *buf, int *buf_len, __u8 *family,
                         __u32 *id, __u8 *hook, int *ifi);
int netfilter_queue_set_verdict(int nlfd, int queue_num, __u32 id,
                                __u32 verdict, int data_len, __u8 *data);

/*
 * \fn addr_match_payload()
 *
 * \param payload	character pointer to packet payload
 * \param family	address family of the packet contained in payload
 * \param src		source address to check for in the packet
 * \param dst		desitnation address to check for in the packet
 *
 * \brief  Check if the given addresses are equal to the ones in the packet
 *         header.
 */
int addr_match_payload(__u8 *payload, int family, struct sockaddr *src,
                       struct sockaddr *dst)
{
  int ret = FALSE;
  struct ip *ip4h = NULL;
  struct ip6_hdr *ip6h = NULL;
  struct in_addr ip4_src, ip4_dst;
  struct in6_addr ip6_src, ip6_dst;

  if ((src->sa_family != family) || (dst->sa_family != family))
    {
      return(ret);
    }

  if (family == AF_INET)
    {
      ip4h = (struct ip *) payload;
      memcpy(&ip4_src, SA2IP(src), SAIPLEN(src));
      memcpy(&ip4_dst, SA2IP(dst), SAIPLEN(dst));
      if ((ip4_src.s_addr == ip4h->ip_src.s_addr) &&
          (ip4_dst.s_addr == ip4h->ip_dst.s_addr))
        {
          ret = TRUE;
        }
    }
  else
    {
      ip6h = (struct ip6_hdr *) payload;
      memcpy(&ip6_src, SA2IP(src), SAIPLEN(src));
      memcpy(&ip6_dst, SA2IP(dst), SAIPLEN(dst));
      if (IN6_ARE_ADDR_EQUAL(&ip6_src, &ip6h->ip6_src) &&
          IN6_ARE_ADDR_EQUAL(&ip6_dst, &ip6h->ip6_dst))
        {
          ret = TRUE;
        }
    }

  return(ret);
}

/*
 * \fn rewrite_addrs()
 *
 * \param payload	character pointer to packet payload
 * \param src		new source address to use in IP header
 * \param dst		new destination address to use in IP header
 *
 * Rewrite addresses in packet header
 */
void rewrite_addrs(__u8 *payload, struct sockaddr *src, struct sockaddr *dst)
{
  struct ip *ip4h = NULL;
  struct ip6_hdr *ip6h = NULL;

  if (src->sa_family != dst->sa_family)
    {
      return;
    }

  if (src->sa_family == PF_INET)
    {
      ip4h = (struct ip *) payload;
      memcpy(&ip4h->ip_src, SA2IP(src), SAIPLEN(src));
      memcpy(&ip4h->ip_dst, SA2IP(dst), SAIPLEN(dst));
      ip4h->ip_sum = 0;
      ip4h->ip_sum = ip_fast_csum((__u8*)ip4h, ip4h->ip_hl);
    }
  else
    {
      ip6h = (struct ip6_hdr *) payload;
      memcpy(&ip6h->ip6_src, SA2IP(src), SAIPLEN(src));
      memcpy(&ip6h->ip6_dst, SA2IP(dst), SAIPLEN(dst));
    }

}

/*
 *
 * \fn get_next_spinat()
 *
 * \param none
 *
 * \return	returns next SPI value to use for SPINAT
 *
 * \brief Obtains new random SPI for SPINAT, checks that it is not being used.
 * TODO: Should also check that it is not being used for mobile router SAs.
 */
__u32 get_next_spinat(void)
{
  int i;
  __u32 new_spi;
  hip_spi_nat *spi_nats;

retry_getspi:
  /* randomly select a new SPI */
  new_spi = 0;
  while (new_spi <= SPI_RESERVED)
    {
      RAND_bytes((__u8*)&new_spi, 4);
    }

  for (i = 0; i < max_hip_mr_clients; i++)
    {
      for (spi_nats = hip_mr_client_table[i].spi_nats; spi_nats;
           spi_nats = spi_nats->next)
        {
          if (new_spi == spi_nats->public_spi)
            {
              goto retry_getspi;
            }
        }
    }
  return(new_spi);
}

/*
 * \fn mr_client_lookup()
 *
 * \param hit	client HIT used to find mobile router client entry
 *
 * \brief Search for a mobile router client table entry using the given HIT
 */
hip_mr_client *mr_client_lookup(hip_hit hit)
{
  int i;
  for (i = 0; i < max_hip_mr_clients; i++)
    {
      if (hits_equal(hit, hip_mr_client_table[i].mn_hit))
        {
          return(&hip_mr_client_table[i]);
        }
    }
  return(NULL);
}

/*
 *
 * \fn mr_process_I1()
 *
 * \param hip_mr_c	pointer to the mobile node client structure
 * \param family	address family of packet, either AF_INET or AF_INET6
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param hiph		pointer to the HIP header in the packet
 * \param payload       pointer to a copy of the actual packet
 *
 * \brief Process the I1 from/to the mobile node, create SPINAT state.
 */
void mr_process_I1(hip_mr_client *hip_mr_c, int family, int inbound,
                   struct if_data *ext_if, hiphdr *hiph, unsigned char *payload)
{
  hip_hit *peer_hit;
  struct ip *ip4h = NULL;
  struct ip6_hdr *ip6h = NULL;
  __u8 *cp;

  hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

  if (inbound)
    {
      peer_hit = &(hiph->hit_sndr);
    }
  else
    {
      peer_hit = &(hiph->hit_rcvr);
    }

  log_(NORM, "mr_process_I1 %s\n", family == AF_INET ? "IPv4" : "IPv6");

  while (spi_nats)
    {
      if (hits_equal(*peer_hit, spi_nats->peer_hit))
        {
          break;
        }
      spi_nats = spi_nats->next;
    }

  if (!spi_nats)
    {
#ifdef VERBOSE_MR_DEBUG
      log_(NORM, "allocating new spi_nat structure\n");
#endif /* VERBOSE_MR_DEBUG */
      spi_nats = malloc(sizeof(hip_spi_nat));
      if (!spi_nats)
        {
          return;
        }
      memset(spi_nats, 0, sizeof(hip_spi_nat));
      spi_nats->next = hip_mr_c->spi_nats;
      hip_mr_c->spi_nats = spi_nats;
      memcpy(spi_nats->peer_hit, peer_hit, sizeof(hip_hit));
    }

  spi_nats->private_spi = 0;
  spi_nats->public_spi = 0;
  spi_nats->peer_addr.ss_family = family;
  ip4h = (struct ip *) payload;
  ip6h = (struct ip6_hdr *) payload;
  if (family == AF_INET)
    {
      cp = (inbound) ? (__u8*)&ip4h->ip_src : (__u8*)&ip4h->ip_dst;
      spi_nats->peer_ipv4_addr.ss_family = family;
      memcpy(SA2IP(&spi_nats->peer_ipv4_addr), cp,
             SAIPLEN(&spi_nats->peer_ipv4_addr));
    }
  else
    {
      cp = (inbound) ? (__u8*)&ip6h->ip6_src : (__u8 *)&ip6h->ip6_dst;
      spi_nats->peer_ipv6_addr.ss_family = family;
      memcpy(SA2IP(&spi_nats->peer_ipv6_addr), cp,
             SAIPLEN(&spi_nats->peer_ipv6_addr));
    }
  memcpy(SA2IP(&spi_nats->peer_addr), cp, SAIPLEN(&spi_nats->peer_addr));
#ifdef VERBOSE_MR_DEBUG
  struct sockaddr *dst = (struct sockaddr*)&spi_nats->peer_ipv4_addr;
  log_(NORM, "Current peer ipv4 address is %s\n", logaddr(dst));
  dst = (struct sockaddr*)&spi_nats->peer_addr;
  log_(NORM, "Current peer address is %s\n", logaddr(dst));
#endif /* VERBOSE_MR_DEBUG */
       /* XXX need to fix ext_if->address family != peer family here */
  if (inbound)
    {
      rewrite_addrs(payload, SA(&spi_nats->peer_addr),
                    SA(&hip_mr_c->mn_addr));
    }
  else
    {
      rewrite_addrs(payload, SA(&ext_if->address),
                    SA(&spi_nats->peer_addr));
    }
  return;
}

/*
 *
 * \fn mr_process_R1()
 *
 * \param hip_mr_c	pointer to the mobile node client structure
 * \param family	address family of packet, either AF_INET or AF_INET6
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param hiph		pointer to the HIP header in the packet
 * \param payload	pointer to a copy of the actual packet
 *
 * \return  Perform SPINAT on packet.
 *
 * \brief  Process the R1 from/to the peer node.
 */
void mr_process_R1(hip_mr_client *hip_mr_c, int family, int inbound,
                   struct if_data *ext_if, hiphdr *hiph, unsigned char *payload)
{
  hip_hit *peer_hit;
  struct ip *ip4h = NULL;
  struct ip6_hdr *ip6h = NULL;
  __u8 *cp;
  int location = 0;
  __u8 *data = (__u8 *)hiph;
  int data_len;
  int type, length;
  tlv_head *tlv;
  tlv_via_rvs *via;

  hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

  if (inbound)
    {
      peer_hit = &(hiph->hit_sndr);
    }
  else
    {
      peer_hit = &(hiph->hit_rcvr);
    }

  while (spi_nats)
    {
      if (hits_equal(*peer_hit, spi_nats->peer_hit))
        {
          break;
        }
      spi_nats = spi_nats->next;
    }

  if (!spi_nats)
    {
      return;
    }

  /* Look for VIA_RVS parameter from mobile node's peer */
  data_len = (hiph->hdr_len + 1) * 8;
  location += sizeof(hiphdr);

  while (location < data_len)
    {
      tlv = (tlv_head *) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      if (type == PARAM_VIA_RVS)
        {
          via = (tlv_via_rvs *) &data[location];
          if (inbound)
            {
              if (IN6_IS_ADDR_V4MAPPED(
                    (struct in6_addr*)via->address))
                {
                  spi_nats->rvs_addr.ss_family = AF_INET;
                  memcpy(SA2IP(&spi_nats->rvs_addr),
                         &via->address[12],
                         SAIPLEN(&spi_nats->rvs_addr));
                }
              else
                {
                  spi_nats->rvs_addr.ss_family = AF_INET;
                  memcpy(SA2IP(&spi_nats->rvs_addr),
                         via->address,
                         SAIPLEN(&spi_nats->rvs_addr));
                }
              log_(NORM,
                   "I1 packet relayed by the Rendezvous"
                   " Server address %s.\n",
                   logaddr(SA(&spi_nats->rvs_addr)));
            }
          /* Save the peer's real address */
          spi_nats->peer_addr.ss_family = family;
          ip4h = (struct ip *) payload;
          ip6h = (struct ip6_hdr *) payload;
          if (family == AF_INET)
            {
              cp = (inbound) ? (__u8*)&ip4h->ip_src :
                   (__u8*)&ip4h->ip_dst;
              spi_nats->peer_ipv4_addr.ss_family =
                family;
              memcpy(SA2IP(&spi_nats->peer_ipv4_addr),
                     cp,
                     SAIPLEN(&spi_nats->peer_ipv4_addr));
            }
          else
            {
              cp = (inbound) ? (__u8*)&ip6h->ip6_src :
                   (__u8 *)&ip6h->ip6_dst;
              spi_nats->peer_ipv6_addr.ss_family =
                family;
              memcpy(SA2IP(&spi_nats->peer_ipv6_addr),
                     cp,
                     SAIPLEN(&spi_nats->peer_ipv6_addr));
            }
          memcpy(SA2IP(&spi_nats->peer_addr), cp,
                 SAIPLEN(&spi_nats->peer_addr));
        }
      location += tlv_length_to_parameter_length(length);
    }

  if (inbound)
    {
      rewrite_addrs(payload, SA(&spi_nats->peer_addr),
                    SA(&hip_mr_c->mn_addr));
    }
  else
    {
      rewrite_addrs(payload, SA(&ext_if->address),
                    SA(&spi_nats->peer_addr));
    }
}

/*
 *
 * \fn mr_process_I2_or_R2()
 *
 * \param hip_mr_c      pointer to the mobile node client structure
 * \param family	address family of packet, either AF_INET or AF_INET6
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param hiph		pointer to the HIP header in the packet
 * \param payload	pointer to a copy of the actual packet
 *
 * Process the I2/R2 from/to the mobile node, get external SPI if from mobile
 * node and grab the SPI of the peer.
 */


__u32 mr_process_I2_or_R2(hip_mr_client *hip_mr_c,
                          int family,
                          int inbound,
                          struct if_data *ext_if,
                          hiphdr *hiph,
                          unsigned char *payload)
{
  hip_hit *peer_hit;
  __u32 new_spi = 0;
  int location = 0;
  __u8 *data = (__u8 *)hiph;
  int data_len;
  int type, length;
  tlv_head *tlv;
  tlv_esp_info *esp_info;

  hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

  if (inbound)
    {
      peer_hit = &(hiph->hit_sndr);
    }
  else
    {
      peer_hit = &(hiph->hit_rcvr);
    }

  while (spi_nats)
    {
      if (hits_equal(*peer_hit, spi_nats->peer_hit))
        {
          break;
        }
      spi_nats = spi_nats->next;
    }

  if (!spi_nats)
    {
      return(0);
    }

  data_len = (hiph->hdr_len + 1) * 8;
  location += sizeof(hiphdr);

  while (location < data_len)
    {
      tlv = (tlv_head *) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      if (type == PARAM_ESP_INFO)
        {
          esp_info = (tlv_esp_info *)tlv;
          if (inbound)
            {
              spi_nats->peer_spi = ntohl(esp_info->new_spi);
              log_(NORM, "Peer SPI 0x%x added\n",
                   spi_nats->peer_spi);
            }
          else
            {
              spi_nats->private_spi =
                ntohl(esp_info->new_spi);
              spi_nats->public_spi = get_next_spinat();
              log_(NORM, "Mobile node SPI 0x%x\n",
                   spi_nats->private_spi);
              log_(NORM, "External SPI 0x%x added\n",
                   spi_nats->public_spi);
              new_spi = spi_nats->public_spi;
              break;
            }
        }
      else if (type == PARAM_ESP_INFO_NOSIG)
        {
          esp_info = (tlv_esp_info *)tlv;
          if (inbound)
            {
              spi_nats->peer_spi = ntohl(esp_info->new_spi);
              log_(NORM, "Peer SPI 0x%x added\n",
                   spi_nats->peer_spi);
              break;
            }
        }
      location += tlv_length_to_parameter_length(length);
    }

  if (inbound)
    {
      rewrite_addrs(payload, SA(&spi_nats->peer_addr),
                    SA(&hip_mr_c->mn_addr));
    }
  else
    {
      rewrite_addrs(payload, SA(&ext_if->address),
                    SA(&spi_nats->peer_addr));
      spi_nats->last_out_addr.ss_family = family;
      memcpy(SA(&spi_nats->last_out_addr), SA(&ext_if->address),
             SALEN(&spi_nats->last_out_addr));
    }

  return(new_spi);
}

/*
 *
 * \fn mr_process_I2()
 *
 * \param hip_mr_c      pointer to the mobile node client structure
 * \param family	address family of packet, either AF_INET or AF_INET6
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param hiph		pointer to the HIP header in the packet
 * \param payload	pointer to a copy of the actual packet
 *
 * Process the I2 from/to the mobile node, get external SPI if from mobile node.
 */


__u32 mr_process_I2(hip_mr_client *hip_mr_c,
                    int family,
                    int inbound,
                    struct if_data *ext_if,
                    hiphdr *hiph,
                    unsigned char *payload)
{
  return(mr_process_I2_or_R2(hip_mr_c, family, inbound, ext_if, hiph,
                             payload));
}

/*
 *
 * \fn mr_process_R2()
 *
 * \param hip_mr_c	pointer to the mobile node client structure
 * \param family	address family of packet, either AF_INET or AF_INET6
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param hiph		pointer to the HIP header in the packet
 * \param payload	pointer to a copy of the actual packet
 *
 * \return  Perform SPINAT on packet.
 *
 * \brief  Process the R2 from the peer node, grab the SPI of the peer.
 */
__u32 mr_process_R2(hip_mr_client *hip_mr_c,
                    int family,
                    int inbound,
                    struct if_data *ext_if,
                    hiphdr *hiph,
                    unsigned char *payload)
{
  return(mr_process_I2_or_R2(hip_mr_c, family, inbound, ext_if, hiph,
                             payload));
}

/*
 *
 * \fn mr_process_update()
 *
 * \param hip_mr_c      pointer to the mobile node client structure
 * \param family        address family of packet, either AF_INET or AF_INET6
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param hiph          pointer to the HIP header in the packet
 * \param payload       pointer to a copy of the actual packet
 *
 * \return  Perform SPINAT on packet.
 *
 * \brief  Process the update from the peer node, grab the LOCATOR info of the
 *         peer from peer node.
 */
void mr_process_update(hip_mr_client *hip_mr_c, int family,
                       int inbound, struct if_data *ext_if, hiphdr *hiph,
                       unsigned char *payload)
{
  hip_hit *peer_hit;
  int location = 0;
  __u8 *data = (__u8 *)hiph;
  int data_len;
  int type, length;
  tlv_head *tlv;
  tlv_locator *loc;
  locator *loc1;
  __u8 *p_addr = NULL;

  hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

  if (inbound)
    {
      peer_hit = &(hiph->hit_sndr);
    }
  else
    {
      peer_hit = &(hiph->hit_rcvr);
    }

  while (spi_nats)
    {
      if (hits_equal(*peer_hit, spi_nats->peer_hit))
        {
          break;
        }
      spi_nats = spi_nats->next;
    }

  if (!spi_nats)
    {
      return;
    }

  data_len = (hiph->hdr_len + 1) * 8;
  location += sizeof(hiphdr);

  if (!inbound)
    {
      while (location < data_len)
        {
          tlv = (tlv_head *) &data[location];
          type = ntohs(tlv->type);
          length = ntohs(tlv->length);
          if (type == PARAM_VIA_RVS)
            {
              hip_send_proxy_update(SA(&ext_if->address),
                                    SA(
                                      &spi_nats->
                                      peer_addr),
                                    spi_nats,
                                    &hip_mr_c->mn_hit);
            }
          location += tlv_length_to_parameter_length(length);
        }
      if (spi_nats->use_rvs)
        {
          rewrite_addrs(payload, SA(&ext_if->address),
                        SA(&spi_nats->rvs_addr));
        }
      else
        {
          rewrite_addrs(payload, SA(&ext_if->address),
                        SA(&spi_nats->peer_addr));
        }
      return;
    }

  while (location < data_len)
    {
      tlv = (tlv_head *) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      p_addr = NULL;
      if (type == PARAM_SEQ)
        {
          mr_clear_retransmissions(spi_nats);
        }
      else if (type == PARAM_LOCATOR)
        {
          loc = (tlv_locator *)tlv;
          loc1 = &loc->locator1[0];
          if ((loc1->locator_type == LOCATOR_TYPE_IPV6) &&
              (loc1->locator_length == 4))
            {
              p_addr = &loc1->locator[0];
            }
          else if ((loc1->locator_type ==
                    LOCATOR_TYPE_SPI_IPV6) &&
                   (loc1->locator_length == 5))
            {
              p_addr = &loc1->locator[4];
            }
          else
            {
              log_(WARN,
                   "Invalid locator type %d / length %d.\n",
                   loc1->locator_type,
                   loc1->locator_length);
            }
        }
      if (p_addr)
        {
          /*
           * Read in address from LOCATOR
           */
          struct sockaddr *addr = NULL;

          if (IN6_IS_ADDR_V4MAPPED((struct in6_addr*)p_addr))
            {
              addr = SA(&spi_nats->peer_ipv4_addr);
              addr->sa_family = AF_INET;
              memcpy(SA2IP(addr), p_addr + 12, SAIPLEN(addr));
              if (IN_MULTICAST(*(SA2IP(addr))))
                {
                  memset(addr, 0,
                         sizeof(struct sockaddr_storage));
                }
              if (((struct sockaddr_in*)addr)->sin_addr.
                  s_addr == INADDR_BROADCAST)
                {
                  memset(addr, 0,
                         sizeof(struct sockaddr_storage));
                }
              memcpy(SA2IP(&spi_nats->peer_addr),
                     SA2IP(&spi_nats->peer_ipv4_addr),
                     SAIPLEN(&spi_nats->peer_addr));
            }
          else
            {
              addr = SA(&spi_nats->peer_ipv6_addr);
              addr->sa_family = AF_INET6;
              memcpy(SA2IP(addr), p_addr, SAIPLEN(addr));
              unsigned char *p = SA2IP(addr);
              if (IN6_IS_ADDR_MULTICAST((struct in6_addr*)p))
                {
                  memset(addr, 0,
                         sizeof(struct sockaddr_storage));
                }
              /* IPv6 doesn't have broadcast addresses */
              memcpy(SA2IP(&spi_nats->peer_addr),
                     SA2IP(&spi_nats->peer_ipv6_addr),
                     SAIPLEN(&spi_nats->peer_addr));
            }
        }
      location += tlv_length_to_parameter_length(length);
    }

  rewrite_addrs(payload, SA(&spi_nats->peer_addr),
                SA(&hip_mr_c->mn_addr));
}

/*
 *
 * \fn mr_process_CLOSE()
 *
 * \param hip_mr_c	pointer to the mobile node client structure
 * \param family	address family of packet, either AF_INET or AF_INET6
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param hiph		pointer to the HIP header in the packet
 * \param payload	pointer to a copy of the actual packet
 * \param packet_type	is either CLOSE or CLOSE_ACK.
 *
 * \return  Perform SPINAT on packet.
 *
 * \brief Process the CLOSE or CLOSE_ACK.
 */
void mr_process_CLOSE(hip_mr_client *hip_mr_c,
                      int family,
                      int inbound,
                      struct if_data *ext_if,
                      hiphdr *hiph,
                      unsigned char *payload,
                      int packet_type)
{
  hip_hit *peer_hit;

  hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

  if (inbound)
    {
      peer_hit = &(hiph->hit_sndr);
    }
  else
    {
      peer_hit = &(hiph->hit_rcvr);
    }

  while (spi_nats)
    {
      if (hits_equal(*peer_hit, spi_nats->peer_hit))
        {
          break;
        }
      spi_nats = spi_nats->next;
    }

  if (!spi_nats)
    {
      return;
    }

  if (inbound)
    {
      rewrite_addrs(payload, SA(&spi_nats->peer_addr),
                    SA(&hip_mr_c->mn_addr));
    }
  else
    {
      rewrite_addrs(payload, SA(&ext_if->address),
                    SA(&spi_nats->peer_addr));
    }

  /* TODO: Remove state for SA if CLOSE_ACK never received */

  if (packet_type == CLOSE_ACK)
    {
      if (spi_nats == hip_mr_c->spi_nats)
        {
          hip_mr_c->spi_nats = spi_nats->next;
          free(spi_nats);
        }
      else
        {
          hip_spi_nat *p;
          for (p = hip_mr_c->spi_nats; p; p = p->next)
            {
              if (spi_nats == p->next)
                {
                  p->next = spi_nats->next;
                  free(spi_nats);
                  break;
                }
            }
        }
    }

}

/*
 *
 * \fn add_tlv_spi_nat()
 *
 * \param hip_mr_c	pointer to the mobile node client structure
 * \param family	address family of packet, either AF_INET or AF_INET6
 * \param hiph		pointer to the HIP header in the packet
 * \param payload	pointer to a copy of the actual packet
 *
 * \returns  Create new packet adding PARAM_ESP_INFO_NOSIG TLV.
 *
 * \brief  Add a the external SPI of the mobile node to the I2.
 */
unsigned char *add_tlv_spi_nat(int family, unsigned char *payload,
                               size_t data_len, size_t *new_len, __u32 new_spi)
{
  hiphdr *hiph;
  struct ip *ip4h = NULL;
  struct ip6_hdr *ip6h = NULL;
  tlv_esp_info *esp_info;
  size_t len = data_len + sizeof(tlv_esp_info);
  int hiphdr_len;
  unsigned char *buff = malloc(len);

  if (!buff)
    {
      return(buff);
    }

  /* Copy original packet */
  memcpy(buff, payload, data_len);

  /* ESP INFO */
  esp_info = (tlv_esp_info*) &buff[data_len];
  esp_info->type = htons(PARAM_ESP_INFO_NOSIG);
  esp_info->length = htons(sizeof(tlv_esp_info) - 4);
  esp_info->reserved = 0;
  esp_info->keymat_index = 0;
  esp_info->old_spi = 0;
  esp_info->new_spi = htonl(new_spi);

  /* finish with new length */

  if (family == PF_INET)
    {
      ip4h = (struct ip *) buff;
      hiph = (hiphdr *)(buff + sizeof(struct ip));
    }
  else
    {
      ip6h = (struct ip6_hdr *) buff;
      hiph = (hiphdr *)(buff + sizeof(struct ip6_hdr));
    }
  hiphdr_len = (hiph->hdr_len + 1) * 8;
  hiphdr_len += sizeof(tlv_esp_info);
  hiph->hdr_len = (hiphdr_len / 8) - 1;
  if (family == PF_INET)
    {
      /* changing the packet length requires recalculating the
       * IPv4 header checksum */
      ip4h->ip_len = htons((unsigned short)hiphdr_len +
                           sizeof(struct ip));
      ip4h->ip_sum = 0;
      ip4h->ip_sum = ip_fast_csum((__u8*)ip4h, ip4h->ip_hl);
    }
  else
    {
      ip6h->ip6_plen = htons((unsigned short)hiphdr_len);
    }

#ifdef VERBOSE_MR_DEBUG
  log_(NORM, "Adding SPI_NAT of 0x%x\n", new_spi);
#endif /* VERBOSE_MR_DEBUG */
  *new_len = len;
  return(buff);
}

/*
 * \fn check_hip_packet()
 *
 * \param family	address family of packet
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param payload	packet
 * \param data_len	length of payload
 * \param new_len	new length if anything added to packet
 *
 * \brief  Perform SPINAT and Mobile Router service for HIP packets.
 */
unsigned char *check_hip_packet(int family,
                                int inbound,
                                struct if_data *ext_if,
                                unsigned char *payload,
                                size_t data_len,
                                size_t *new_len)
{
  struct sockaddr *src, *dst;
  struct sockaddr_storage src_addr, dst_addr;
  struct ip *ip4h = NULL;
  struct ip6_hdr *ip6h = NULL;
  hiphdr *hiph;
  hip_mr_client *client;
  __u32 new_spi;
  unsigned char *buff = payload;
  char ipstr[INET6_ADDRSTRLEN];

  *new_len = data_len;
  if (family == PF_INET)
    {
      ip4h = (struct ip *) payload;
      hiph = (hiphdr *) (payload + sizeof(struct ip));
    }
  else
    {
      ip6h = (struct ip6_hdr *) payload;
      hiph = (hiphdr *) (payload + sizeof(struct ip6_hdr));
    }
  /* TODO: consider using hip_parse_hdr() here */
  if ((hiph->hdr_len < 4) || ((hiph->hdr_len + 1) * 8 > data_len))
    {
      log_(WARN, "MR Packet error: hdr_len %u\n", hiph->hdr_len);
      return(NULL);
    }

  /*
   * check HITs in HIP header against client table
   */
  pthread_mutex_lock(&hip_mr_client_mutex);
  switch (hiph->packet_type)
    {
    case HIP_I1:
    case HIP_I2:
    case HIP_R1:
    case HIP_R2:
    case UPDATE:
    case CLOSE:
    case CLOSE_ACK:             /* source or destination HIT lookup */
      client = mr_client_lookup(hiph->hit_sndr);
      if (!client)
        {
          client = mr_client_lookup(hiph->hit_rcvr);
        }
      break;
    default:
      client = NULL;
    }

  /* not a client, no further processing */
  if (!client)
    {
      pthread_mutex_unlock(&hip_mr_client_mutex);
      return(buff);
    }


  /*
   * process HIP packets for clients
   */
  switch (hiph->packet_type)
    {
    case HIP_I1:
      mr_process_I1(client, family, inbound, ext_if, hiph,
                    payload);
      break;
    case HIP_R1:
      mr_process_R1(client, family, inbound, ext_if, hiph,
                    payload);
      break;
    case HIP_I2:
      new_spi = mr_process_I2(client, family, inbound, ext_if,
                              hiph, payload);
      if (new_spi)
        {
          buff = add_tlv_spi_nat(family, payload,
                                 data_len, new_len, new_spi);
        }
      break;
    case HIP_R2:
      new_spi = mr_process_R2(client, family, inbound, ext_if,
                              hiph, payload);
      if (new_spi)
        {
          buff = add_tlv_spi_nat(family, payload,
                                 data_len, new_len, new_spi);
        }
      break;
    case UPDATE:
      mr_process_update(client,
                        family,
                        inbound,
                        ext_if,
                        hiph,
                        payload);
      break;
    case CLOSE:
    case CLOSE_ACK:
      mr_process_CLOSE(client, family, inbound, ext_if, hiph,
                       payload, hiph->packet_type);
      break;
    }
  pthread_mutex_unlock(&hip_mr_client_mutex);

  /* finish with new checksum */

  if (buff != payload)
    {
      if (family == PF_INET)
        {
          ip4h = (struct ip *)buff;
          hiph = (hiphdr *)(buff + sizeof(struct ip));
        }
      else
        {
          ip6h = (struct ip6_hdr *)buff;
          hiph = (hiphdr *)(buff + sizeof(struct ip6_hdr));
        }
    }
  src = SA(&src_addr);
  dst = SA(&dst_addr);
  src->sa_family = family;
  dst->sa_family = family;
  if (family == PF_INET)
    {
      memcpy(SA2IP(src), &(ip4h->ip_src), SAIPLEN(src));
      memcpy(SA2IP(dst), &(ip4h->ip_dst), SAIPLEN(dst));
    }
  else
    {
      memcpy(SA2IP(src), &(ip6h->ip6_src), SAIPLEN(src));
      memcpy(SA2IP(dst), &(ip6h->ip6_dst), SAIPLEN(dst));
    }
  memset(ipstr, 0, sizeof(ipstr));
  inet_ntop(family, SA2IP(src), ipstr, sizeof(ipstr));
  log_(NORM, "mobile router SPINAT: rewriting addresses to (src,dst) = "
       "%s, ", ipstr);
  memset(ipstr, 0, sizeof(ipstr));
  inet_ntop(family, SA2IP(dst), ipstr, sizeof(ipstr));
  log_(NORM, "%s\n", ipstr);
  hiph->checksum = 0;
  hiph->checksum = checksum_packet((__u8 *)hiph, src, dst);

  return(buff);
}

/*
 * \fn new_header()
 *
 * \param family	new address family to use for the packet
 * \param payload	pointer to packet payload
 *
 * \return  Returns a pointer to the new packet buffer.
 *
 * \brief Translate packet between IPv4 and IPv6.
 */
unsigned char *new_header(int family, unsigned char *payload)
{
  __u32 tc;
  int data_len;
  unsigned char *data;
  struct ip_esp_hdr *esph;
  struct ip *ip4h;
  struct ip6_hdr *ip6h;

  if (family == AF_INET)
    {
      ip4h = (struct ip *)payload;
      esph = (struct ip_esp_hdr *) (payload + sizeof(struct ip));
      data_len = ntohs(ip4h->ip_len) - sizeof(struct ip);
      data = malloc(sizeof(struct ip6_hdr) + data_len);
      if (data)
        {
          ip6h = (struct ip6_hdr *)data;
          memset(ip6h, 0, sizeof(struct ip6_hdr));
          ip6h->ip6_flow = 0;               /* zero the version (4), TC (8),
                                             *flow-ID (20) */
          ip6h->ip6_vfc = 0x60;
          ip6h->ip6_plen = htons(data_len);
          ip6h->ip6_nxt = ip4h->ip_p;
          ip6h->ip6_hlim = ip4h->ip_ttl;
          tc = ip4h->ip_tos << 20;
          ip6h->ip6_flow |= tc;                 /* 8 bits traffic class */
          ip6h->ip6_hlim = ip4h->ip_ttl;                  /* __u8 */
          memcpy(data + sizeof(struct ip6_hdr), esph, data_len);
        }
    }
  else
    {
      ip6h = (struct ip6_hdr *)payload;
      esph = (struct ip_esp_hdr *) (payload + sizeof(struct ip6_hdr));
      data_len = ntohs(ip6h->ip6_plen);
      data = malloc(sizeof(struct ip) + data_len);
      if (data)
        {
          ip4h = (struct ip *)data;
          memset(ip4h, 0, sizeof(struct ip));
          ip4h->ip_v = 4;
          ip4h->ip_hl = 5;
          tc = ip6h->ip6_flow & 0x1100000;
          ip4h->ip_tos = tc >> 20;
          ip4h->ip_len = htons(data_len + sizeof(struct ip));
          ip4h->ip_id  = 0;
          ip4h->ip_off = htons(0x4000);
          ip4h->ip_ttl = ip6h->ip6_hlim;
          ip4h->ip_p = ip6h->ip6_nxt;
          ip4h->ip_sum = 0;
          memcpy(data + sizeof(struct ip), esph, data_len);
        }
    }

  return(data);
}

/*
 * \fn do_inbound_esp_packet()
 *
 * \param family	address family of packet
 * \param payload	packet
 * \param addr		local address of HIP MR client
 * \param spi_nat	pointer to spi_nat info for this association
 *
 * \brief process inbound ESP packets, rewriting SPIs.
 */
unsigned char *do_inbound_esp_packet(int family,
                                     unsigned char *payload,
                                     struct sockaddr *addr,
                                     hip_spi_nat *spi_nat)
{
  unsigned char *new_payload = NULL;
  struct ip_esp_hdr *esph;

  esph = (struct ip_esp_hdr *) (payload + ((family == AF_INET) ?
                                           sizeof(struct ip) : sizeof(
                                             struct ip6_hdr)));

#ifdef VERBOSE_MR_DEBUG
  log_(NORM, "Rewriting ESP SPI from 0x%x to 0x%x.\n",
       spi_nat->private_spi, ntohl(esph->spi));
#endif /* VERBOSE_MR_DEBUG */

  esph->spi = htonl(spi_nat->private_spi);
  if (family == addr->sa_family)
    {
      new_payload = payload;
    }
  else
    {
      new_payload = new_header(family, payload);
    }
  if (new_payload)
    {
      rewrite_addrs(new_payload, SA(&spi_nat->peer_addr), addr);
    }
  return(new_payload);
}

/*
 * \fn do_outbound_esp_packet()
 *
 * \param family	address family of packet
 * \param ext_if	pointer to the external interface info
 * \param payload	packet
 * \param client	point to the HIP MR client info
 * \param spi_nat	pointer to spi_nat info for this association
 *
 * \brief process outbound ESP packets.
 */
unsigned char *do_outbound_esp_packet(int family,
                                      struct if_data *ext_if,
                                      unsigned char *payload,
                                      hip_mr_client *client,
                                      hip_spi_nat *spi_nat)
{
  unsigned char *new_payload = NULL;
  struct sockaddr *client_addr, *dst, *out = SA(&ext_if->address);

  /* Determine destination and rewrite addresses */

  if (family == out->sa_family)
    {
      dst = NULL;
      if (family == AF_INET)
        {
          if (AF_INET == spi_nat->peer_ipv4_addr.ss_family)
            {
              dst = SA(&spi_nat->peer_ipv4_addr);
            }
        }
      else if (family == AF_INET6)
        {
          if (AF_INET6 == spi_nat->peer_ipv6_addr.ss_family)
            {
              dst = SA(&spi_nat->peer_ipv6_addr);
            }
        }
      if (dst)
        {
          rewrite_addrs(payload, out, dst);
        }
      new_payload = payload;
    }
  else
    {
      dst = NULL;
      if (family == AF_INET)
        {
          if (AF_INET6 == spi_nat->peer_ipv6_addr.ss_family)
            {
              dst = SA(&spi_nat->peer_ipv6_addr);
            }
        }
      else if (family == AF_INET6)
        {
          if (AF_INET == spi_nat->peer_ipv4_addr.ss_family)
            {
              dst = SA(&spi_nat->peer_ipv4_addr);
            }
        }
      if (dst)
        {
          /* Need to do IP family translation */
          new_payload = new_header(family, payload);
          if (new_payload)
            {
              rewrite_addrs(new_payload, out, dst);
            }
        }
    }

  /* Check to see if we need to send an UPDATE for this connection */

  if ((out->sa_family != spi_nat->last_out_addr.ss_family) ||
      (memcmp(SA2IP(&ext_if->address), SA2IP(&spi_nat->last_out_addr),
              SAIPLEN(&ext_if->address)) != 0))
    {
      if (dst)
        {
          client_addr = SA(&client->mn_addr);
          log_(NORM, "Sending UPDATE from %s to ", logaddr(out));
          log_(NORM, "%s for client ", logaddr(dst));
          log_(NORM, "%s\n", logaddr(client_addr));
          hip_send_proxy_update(out, dst, spi_nat,
                                &client->mn_hit);
          memcpy(SA(&spi_nat->last_out_addr), out,
                 SALEN(&spi_nat->last_out_addr));
        }
    }

  return(new_payload);
}

/*
 * \fn check_esp_packet()
 *
 * \param family	address family of packet
 * \param inbound	direction of packet (TRUE if inbound FALSE if outbound)
 * \param ext_if	pointer to the external interface info
 * \param payload	packet
 *
 * \brief  Perform SPINAT on ESP packets.
 */
unsigned char *check_esp_packet(int family, int inbound, struct if_data *ext_if,
                                unsigned char *payload)
{
  int i;
  unsigned char *new_payload = NULL;
  struct sockaddr *dst, *addr;
  struct ip_esp_hdr *esph;

  esph = (struct ip_esp_hdr *) (payload + ((family == AF_INET) ?
                                           sizeof(struct ip) : sizeof(
                                             struct ip6_hdr)));

#ifdef VERBOSE_MR_DEBUG
  log_(NORM, "ESP packet with SPI 0x%x\n", ntohl(esph->spi));
#endif /* VERBOSE_MR_DEBUG */

  pthread_mutex_lock(&hip_mr_client_mutex);
  for (i = 0; i < max_hip_mr_clients; i++)
    {
      addr = SA(&hip_mr_client_table[i].mn_addr);
      hip_spi_nat *spi_nats;
      for (spi_nats = hip_mr_client_table[i].spi_nats;
           spi_nats; spi_nats = spi_nats->next)
        {
          if (inbound)
            {
              if (spi_nats->public_spi != ntohl(esph->spi))
                {
                  continue;
                }
              new_payload = do_inbound_esp_packet(family,
                                                  payload,
                                                  addr,
                                                  spi_nats);
              pthread_mutex_unlock(&hip_mr_client_mutex);
              return(new_payload);
            }
          else
            {
              if (spi_nats->peer_spi != ntohl(esph->spi))
                {
                  continue;
                }
              dst = SA(&spi_nats->peer_addr);
              if (!addr_match_payload(payload, family,
                                      addr, dst))
                {
                  continue;
                }
              new_payload = do_outbound_esp_packet(
                family,
                ext_if,
                payload,
                &
                hip_mr_client_table[i],
                spi_nats);
              pthread_mutex_unlock(&hip_mr_client_mutex);
              return(new_payload);
            }
        }
    }

  pthread_mutex_unlock(&hip_mr_client_mutex);
  /* Need to determine is this packet is for this host */
  /* Right now just accept */
  return(payload);
}

/*
 * \fn hip_mobile_router()
 *
 * \brief Mobile Router thread that receives incoming packets from the
 *        netfilter QUEUE target that are HIP or ESP protocol
 *        packets, and performs SPINAT rewriting as necessary.
 */
void *hip_mobile_router(void *arg)
{
  int i, len, ifi;
  __u32 pkt_id, verdict;
  __u8 family, hook;
  int err, inbound, protocol;
  int write_raw, raw_ip4_socket, raw_ip6_socket, nlfd;
  unsigned char buf[BUFSIZE];
  unsigned char *output_buffer;
  size_t output_length;
  struct ip *ip4h = NULL;
  struct ip6_hdr *ip6h = NULL;
  int highest_descriptor = 0;
  struct timeval timeout;
  fd_set read_fdset;
  __u8 *cp;
  struct sockaddr_storage dst;
  struct if_data *ext_if;
  int qn = 0;

  printf("%s() thread started...\n", __FUNCTION__);

  pthread_mutex_init(&hip_mr_client_mutex, NULL);
  pthread_mutex_lock(&hip_mr_client_mutex);
  memset(hip_mr_client_table, 0, sizeof(hip_mr_client_table));
  pthread_mutex_unlock(&hip_mr_client_mutex);

  nlfd = netfilter_queue_init(qn);
  if (nlfd < 0)
    {
      printf("*** %s failed to initialize netfilter queue\n",
             __FUNCTION__);
      return(NULL);
    }

  printf("%s() initialized netfilter queue %d.\n", __FUNCTION__, qn);
  if (hip_mobile_router_add_remove_rules(qn, 0) < 0)
    {
      printf("%s() error adding iptables firewall rules!\n",
             __FUNCTION__);
    }

  /* Sockets used for change of address family */
  raw_ip4_socket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
  raw_ip6_socket = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
  if ((raw_ip4_socket < 0) || (raw_ip6_socket < 0))
    {
      printf("*** hip_mobile_router() error opening RAW %s socket: "
             "%s\n", (raw_ip4_socket < 0) ? "IPv4" : "IPv6",
             strerror(errno));
      return(NULL);
    }

  printf("Mobile router initialized.\n");
  fflush(stdout);

  /*
   * Main mobile router loop
   */
  while (g_state == 0)
    {

      /*
       * select() for socket activity
       */
      FD_ZERO(&read_fdset);
      FD_SET(nlfd, &read_fdset);
      timeout.tv_sec = 0;
      timeout.tv_usec = MR_TIMEOUT_US;
      highest_descriptor = nlfd;

      err = select(highest_descriptor + 1, &read_fdset,
                   NULL, NULL, &timeout);
      if (err < 0)             /* select() error */
        {
          if (EINTR == errno)
            {
              continue;
            }
          printf("hip_mobile_router(): select() error: %s.\n",
                 strerror(errno));
          continue;
        }
      else if (err == 0)               /* idle cycle - select() timeout  */
        {
          continue;
        }
      else if (FD_ISSET(nlfd, &read_fdset))
        {
          len = BUFSIZE;
          err = netfilter_get_packet(nlfd, buf, &len, &family,
                                     &pkt_id, &hook, &ifi);
#ifdef VERBOSE_MR_DEBUG
          /* printf("%s() received %s packet len = %d id=%d on "
           *       "hook=%d ifidx=%d\n", __FUNCTION__,
           *       family==AF_INET ? "IPv4" : "IPv6", len, pkt_id,
           *       hook, ifi); */
#endif /* VERBOSE_MR_DEBUG */
          if (err < 0)
            {
              printf("%s() error getting packet!\n",
                     __FUNCTION__);
              continue;
            }
          /* fall through */
        }
      else
        {
          printf("hip_mobile_router(): unknown socket "
                 "activity\n");
          continue;
        }

      output_buffer = buf;
      output_length = len;

      if (family == AF_INET)
        {
          ip4h = (struct ip *)buf;
        }
      else
        {
          ip6h = (struct ip6_hdr *)buf;
        }

      /* Determine if packet is from external side or not */
      if (hook == NF_INET_PRE_ROUTING)
        {
          inbound = TRUE;
        }
      else if (hook == NF_INET_POST_ROUTING)
        {
          inbound = FALSE;
        }
      else
        {
          /* packet is from some other hook we don't care about */
          /* printf("%s() passing packet from other hook...\n",
           *       __FUNCTION__); */
          netfilter_queue_set_verdict(nlfd, qn, pkt_id,
                                      NF_ACCEPT, 0, NULL);
          continue;
        }

      /* Find the external interface */
      for (i = 0; i < neifs; i++)
        {
          if (ifi == external_interfaces[i].ifindex)
            {
              break;
            }
        }
      if (i >= neifs)
        {
          /* printf("%s() packet %d not on external interface, "
           *       "pass through.\n", __FUNCTION__, pkt_id); */
          netfilter_queue_set_verdict(nlfd, qn, pkt_id,
                                      NF_ACCEPT, 0, NULL);
          continue;
        }

      ext_if = &external_interfaces[i];

      /*
       * Process HIP and ESP packets
       */
      verdict = NF_DROP;
      write_raw = 0;
      protocol = (family == PF_INET) ? ip4h->ip_p : ip6h->ip6_nxt;
#ifdef VERBOSE_MR_DEBUG
      printf("%s() received %d byte %s packet proto %d inbound %s\n",
             __FUNCTION__, len, (family == AF_INET) ? "IPv4" : "IPv6",
             protocol, inbound ? "yes" : "no");
#endif /* VERBOSE_MR_DEBUG */
      if (protocol == H_PROTO_HIP)
        {
          output_buffer = check_hip_packet(family,
                                           inbound,
                                           ext_if,
                                           buf,
                                           len,
                                           &output_length);
          verdict = NF_ACCEPT;
        }
      else if (protocol == IPPROTO_ESP)
        {
          output_buffer = check_esp_packet(family, inbound,
                                           ext_if, buf);
          if (output_buffer == buf)
            {
              verdict = NF_ACCEPT;
            }
          else
            {
              verdict = NF_DROP;
              if (output_buffer)                     /* address family change */
                {
                  write_raw = (family == PF_INET) ? \
                              PF_INET6 : PF_INET;
                }
            }
        }
#ifdef VERBOSE_MR_DEBUG
      printf("verdict %s write_raw %d\n",
             (verdict == NF_DROP) ? "drop" : "accept", write_raw);
#endif /* VERBOSE_MR_DEBUG */

      /*
       * Drop packets if their address family is translated or they
       * are not allowed. Accept packets as-is or with changes.
       */
      err = netfilter_queue_set_verdict(nlfd, qn, pkt_id, verdict,
                                        output_length, output_buffer);
      if (err < 0)
        {
          printf("%s - netfilter_queue_set_verdict(%d) "
                 "failed\n", __FUNCTION__, verdict);
        }

      /*
       * Change of address family, write new packet to raw socket
       */
      if (write_raw == PF_INET)
        {
          ip4h = (struct ip *)output_buffer;
          output_length = ntohs(ip4h->ip_len);
          cp = (__u8*) &ip4h->ip_dst;
        }
      else if (write_raw == PF_INET6)
        {
          ip6h = (struct ip6_hdr *)output_buffer;
          output_length = ntohs(ip6h->ip6_plen) +
                          sizeof(struct ip6_hdr);
          cp = (__u8*) &ip6h->ip6_dst;
        }
      else
        {
          err = output_length = 0;
        }
      if (output_length > 0)
        {
          memset(&dst, 0, sizeof(dst));
          dst.ss_family = write_raw;
          memcpy(SA2IP(&dst), cp, SAIPLEN(&dst));
          err = sendto((write_raw == AF_INET) ? raw_ip4_socket :
                       raw_ip6_socket,
                       output_buffer,
                       output_length,
                       0,
                       SA(&dst),
                       SALEN(&dst));
        }
      if (err < 0)
        {
          printf("hip_mobile_router() raw sendto() error: %s\n",
                 strerror(errno));
        }

      if (output_buffer && (output_buffer != buf))
        {
          free(output_buffer);
        }
    }

  printf("hip_mobile_router() thread shutdown.\n");

  if (hip_mobile_router_add_remove_rules(qn, 1) < 0)
    {
      printf("%s() error removing iptables firewall rules!\n",
             __FUNCTION__);
    }

  close(nlfd);
  close(raw_ip4_socket);
  close(raw_ip6_socket);
  fflush(stdout);
  pthread_exit((void *) 0);
  return(NULL);
}

/*
 *
 * \fn mr_clear_retransmissions()
 *
 * \param spi_nat	Pointer to SPINAT structure for this SPINAT
 *
 * \brief Clear the retransmission for this SPINAT
 *
 */
void mr_clear_retransmissions(hip_spi_nat *spi_nats)
{
  if (!spi_nats)
    {
      return;
    }
  if (spi_nats->rexmt_cache.packet != NULL)
    {
      free(spi_nats->rexmt_cache.packet);
    }
  spi_nats->rexmt_cache.packet = NULL;
  spi_nats->rexmt_cache.len = 0;
  memset(&spi_nats->rexmt_cache.xmit_time, 0, sizeof(struct timeval));
  spi_nats->rexmt_cache.retransmits = 0;
  memset(&spi_nats->rexmt_cache.dst, 0, sizeof(struct sockaddr_storage));
  spi_nats->use_rvs = FALSE;
}

/*
 *
 * \fn hip_mr_retransmit()
 *
 * \param time1	        current time
 * \param hit	        HIT of possible mobile router client
 *
 * \return              Returns 0 when successful, -1 on error.
 *
 * \brief Retransmit the UPDATE-PROXY packet on behalf of a mobile router client
 *
 */
int hip_mr_retransmit(struct timeval *time1, hip_hit hit)
{
  struct sockaddr *src, *dst;
  hip_spi_nat *spi_nats;
  hiphdr *hiph;
  hip_mr_client *client = mr_client_lookup(hit);

  if (!client)
    {
      return(-1);
    }

  for (spi_nats = client->spi_nats; spi_nats;
       spi_nats = spi_nats->next)
    {

      if ((spi_nats->rexmt_cache.len < 1) ||
          (TDIFF(*time1, spi_nats->rexmt_cache.xmit_time) <=
           (int)HCNF.packet_timeout))
        {
          continue;
        }

      if ((OPT.no_retransmit == FALSE) &&
          (spi_nats->rexmt_cache.retransmits <
           (int)HCNF.max_retries))
        {
          src = SA(&spi_nats->last_out_addr);
          dst = SA(&spi_nats->rexmt_cache.dst);
          log_(NORMT, "Mobile router retransmitted UPDATE "
               "from %s to ", logaddr(src));
          log_(NORM, "%s (attempt %d of %d)...\n", logaddr(dst),
               spi_nats->rexmt_cache.retransmits + 1,
               HCNF.max_retries);
          hip_retransmit(NULL, spi_nats->rexmt_cache.packet,
                         spi_nats->rexmt_cache.len, src, dst);
          gettimeofday(&spi_nats->rexmt_cache.xmit_time, NULL);
          spi_nats->rexmt_cache.retransmits++;
          if ((spi_nats->rexmt_cache.retransmits >=
               (int)HCNF.max_retries) &&
              VALID_FAM(&spi_nats->rvs_addr))
            {
              if (0 !=
                  memcmp(SA2IP(&spi_nats->rexmt_cache.dst),
                         SA2IP(&spi_nats->rvs_addr),
                         SAIPLEN(&spi_nats->rexmt_cache.dst)))
                {
                  memcpy(&spi_nats->rexmt_cache.dst,
                         &spi_nats->rvs_addr,
                         SALEN(&spi_nats->rvs_addr));
                  dst = SA(&spi_nats->rexmt_cache.dst);
                  hiph = (hiphdr *)
                         &spi_nats->rexmt_cache.packet[0];
                  hiph->checksum = 0;
                  hiph->checksum = checksum_packet(
                    (__u8 *)hiph, src, dst);
                  spi_nats->rexmt_cache.retransmits = 0;
                  spi_nats->use_rvs = TRUE;
                }
              else
                {
                  spi_nats->use_rvs = FALSE;
                }
            }
        }
      else
        {
          mr_clear_retransmissions(spi_nats);
        }
    }
  return(0);
}

/*
 *
 * \fn copy_for_retrans()
 *
 * \param data	        UPDATE-PROXY packet
 * \param len	        length of packet
 * \param dst		address of peer host
 * \param spi_nat	Pointer to SPINAT structure for this SPINAT
 *
 * \return              Returns 0 when successful, -1 on error.
 *
 * \brief Copy the UPDATE-PROXY packet on behalf of a mobile router client
 *        for possible retransmission.
 *
 */
int copy_for_retrans(__u8 *data,
                     int len,
                     struct sockaddr* dst,
                     hip_spi_nat *spi_nat)
{
  struct timeval time1;
  __u8 *out;

  if (!spi_nat)
    {
      return(-1);
    }
  mr_clear_retransmissions(spi_nat);

  out = malloc(len);
  if (!out)
    {
      log_(WARN, "hip_send() malloc error\n");
      return(-1);
    }
  memcpy(out, data, len);

  spi_nat->rexmt_cache.packet = out;
  spi_nat->rexmt_cache.len = len;
  gettimeofday(&time1, NULL);
  spi_nat->rexmt_cache.xmit_time.tv_sec = time1.tv_sec;
  spi_nat->rexmt_cache.xmit_time.tv_usec = time1.tv_usec;
  spi_nat->rexmt_cache.retransmits = 0;
  memcpy(&spi_nat->rexmt_cache.dst, dst, SALEN(dst));
  return(len);
}

/*
 *
 * \fn hip_send_proxy_update()
 *
 * \param newaddr       new preferred address to include in LOCATOR, or NULL
 * \param dstaddr       alternate destination address, if this is an address
 *                      check message, otherwise NULL
 * \param spi_nat	SPINAT structure for this SPINAT
 * \param mn_hit	HIT of the mobile node
 *
 * \return              Returns bytes sent when successful, -1 on error.
 *
 * \brief Opens a socket and sends the UPDATE-PROXY packet on behalf
 *        of a mobile router client. This is a modified version of
 *        hip_send_update().
 *
 */
int hip_send_proxy_update(struct sockaddr *newaddr, struct sockaddr *dstaddr,
                          hip_spi_nat *spi_nat, hip_hit *mn_hit)
{
  hip_hit *peer_hit = &spi_nat->peer_hit;
  hip_proxy_ticket *ticket = &spi_nat->ticket;
  __u32 spi_in = spi_nat->public_spi;
  struct sockaddr *src, *dst;
  hiphdr *hiph;
  __u8 buff[sizeof(hiphdr)             + 2 * sizeof(tlv_locator) +
            sizeof(tlv_auth_ticket)    +
            sizeof(tlv_hmac)           + sizeof(tlv_hip_sig) +
            MAX_SIG_SIZE + 2];
  int location = 0;

  tlv_locator *loc;
  tlv_auth_ticket *auth_ticket;
  locator *loc1;
  __u32 loc_spi;

  memset(buff, 0, sizeof(buff));

  src = newaddr;
  dst = dstaddr;

  /* build the HIP header */
  hiph = (hiphdr*) buff;
  hiph->nxt_hdr = IPPROTO_NONE;
  hiph->hdr_len = 0;
  hiph->packet_type = UPDATE;       /* TODO: use TBD UPDATE-PROXY packet type */
  hiph->version = HIP_PROTO_VER;
  hiph->res = HIP_RES_SHIM6_BITS;
  hiph->control = 0;
  hiph->checksum = 0;
  /* The HIT of the mobile node is used as sender's HIT, not the HIT of
   *   the mobile router. */
  memcpy(&hiph->hit_sndr, mn_hit, sizeof(hip_hit));
  memcpy(&hiph->hit_rcvr, peer_hit, sizeof(hip_hit));
  location = sizeof(hiphdr);

  /* set control bits */
  hiph->control = htons(hiph->control);

  /*
   * add LOCATOR parameter when supplied with readdressing info.
   */
  if (newaddr)
    {
      loc = (tlv_locator*) &buff[location];
      loc->type = htons(PARAM_LOCATOR);
      loc->length = htons(sizeof(tlv_locator) - 4);
      loc1 = &loc->locator1[0];
      loc1->traffic_type = LOCATOR_TRAFFIC_TYPE_BOTH;
      loc1->locator_type = LOCATOR_TYPE_SPI_IPV6;
      loc1->locator_length = 5;           /* (32 + 128 bits) / 4 */
      loc1->reserved = LOCATOR_PREFERRED;           /* set the P-bit */
      loc1->locator_lifetime = htonl(HCNF.loc_lifetime);
      memset(loc1->locator, 0, sizeof(loc1->locator));
      loc_spi = htonl(spi_in);
      memcpy(loc1->locator, &loc_spi, 4);
      if (newaddr->sa_family == AF_INET6)
        {
          memcpy(&loc1->locator[4], SA2IP(newaddr),
                 SAIPLEN(newaddr));
        }
      else               /* IPv4-in-IPv6 address format */
        {
          memset(&loc1->locator[14], 0xFF, 2);
          memcpy(&loc1->locator[16], SA2IP(newaddr),
                 SAIPLEN(newaddr));
        }
      location += sizeof(tlv_locator);
      location = eight_byte_align(location);
    }

  /*
   * add the authorization ticket parameter
   */
  auth_ticket = (tlv_auth_ticket *) &buff[location];
  auth_ticket->type = htons(PARAM_AUTH_TICKET);
  auth_ticket->length = htons(sizeof(tlv_auth_ticket) - 4);
  auth_ticket->hmac_key_index = htons(ticket->hmac_key_index);
  auth_ticket->transform_type = htons(ticket->transform_type);
  auth_ticket->action         = htons(ticket->action);
  auth_ticket->lifetime       = htons(ticket->lifetime);
  memcpy(auth_ticket->hmac, ticket->hmac, sizeof(auth_ticket->hmac));
  location += sizeof(tlv_auth_ticket);
  location = eight_byte_align(location);

  /* HMAC */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_proxy_hmac(ticket, buff, location, PARAM_HMAC);

  /* This UPDATE-PROXY is not signed */

  hiph->hdr_len = (location / 8) - 1;
  hiph->checksum = 0;
  hiph->checksum = checksum_packet(buff, src, dst);

  /* send the packet */
  copy_for_retrans(buff, location, dst, spi_nat);
  log_(NORMT, "Sending UPDATE packet (%d bytes) to dst : %s \n",
       location, logaddr(dst));
  return(hip_send(buff, location, src, dst, NULL, FALSE));
}

/*
 * \fn build_tlv_proxy_hmac()
 *
 * \param ticket	hip_proxy_ticket structure containing keys and transform
 *                      type
 * \param data		pointer to packet data for inserting the HMAC TLV
 * \param location	index for data, where to insert the HMAC TLV
 *
 * \brief Generate an HMAC TLV for the UPDATE-PROXY packet. This is a modified
 *        version of build_tlv_hmac(), the transform and keys come from the
 *        ticket data, not the HIP keymat.
 */
int build_tlv_proxy_hmac(hip_proxy_ticket *ticket, __u8 *data, int location,
                         int type)
{
  hiphdr *hiph;
  tlv_hmac *hmac;
  unsigned int hmac_md_len;
  unsigned char hmac_md[EVP_MAX_MD_SIZE];

  /* compute HMAC over message */
  hiph = (hiphdr*) data;
  memset(hmac_md, 0, sizeof(hmac_md));
  hmac_md_len = EVP_MAX_MD_SIZE;

  switch (ticket->transform_type)
    {
    case ESP_AES_CBC_HMAC_SHA1:
    case ESP_3DES_CBC_HMAC_SHA1:
    case ESP_BLOWFISH_CBC_HMAC_SHA1:
    case ESP_NULL_HMAC_SHA1:
      HMAC(   EVP_sha1(),
              ticket->hmac_key,
              auth_key_len(ticket->transform_type),
              data, location,
              hmac_md, &hmac_md_len  );
      break;
    case ESP_3DES_CBC_HMAC_MD5:
    case ESP_NULL_HMAC_MD5:
      HMAC(   EVP_md5(),
              ticket->hmac_key,
              auth_key_len(ticket->transform_type),
              data, location,
              hmac_md, &hmac_md_len  );
      break;
    default:
      return(0);
      break;
    }

  log_(NORM, "HMAC computed over %d bytes hdr length=%d\n ",
       location, hiph->hdr_len);

  /* build tlv header */
  hmac = (tlv_hmac*)  &data[location];
  hmac->type = htons((__u16)type);
  hmac->length = htons(sizeof(tlv_hmac) - 4);

  /* get lower 160-bits of HMAC computation */
  memcpy( hmac->hmac,
          &hmac_md[hmac_md_len - sizeof(hmac->hmac)],
          sizeof(hmac->hmac));

  return(eight_byte_align(sizeof(tlv_hmac)));
}

/*
 * \fn hip_mr_set_external_ifs()
 *
 * \brief If mobile router, set the outbound interface index. This is invoked
 *        from main_loop after the call to select_preferred_address().
 */
int hip_mr_set_external_ifs()
{
  struct name *iface;
  sockaddr_list *l, *l_new_external = NULL;

  if (!OPT.mr)
    {
      return(0);
    }

  for (iface = HCNF.outbound_ifaces; iface;
       iface = iface->next)
    {
      external_interfaces[neifs].ifindex =
        devname_to_index(iface->name, NULL);
      if (external_interfaces[neifs].ifindex == -1)
        {
          log_(ERR, "HIP started as mobile router but unable to "
               "get the outbound interface index of %s\n",
               iface->name);
          continue;
        }
      external_interfaces[neifs].name =
        malloc(strlen(iface->name) + 1);
      if (!external_interfaces[neifs].name)
        {
          log_(WARN, "hip_mr_set_external_ifs malloc error!\n");
          continue;
        }

      strcpy(external_interfaces[neifs].name, iface->name);
      log_(NORM, "Using %s (%d) as an outbound interface\n",
           external_interfaces[neifs].name,
           external_interfaces[neifs].ifindex);

      /* Use the preferred address if it is on the external interface,
       * otherwise use first non-local address on this interface */
      l_new_external = NULL;
      for (l = my_addr_head; l; l = l->next)
        {
          if (l->if_index !=
              external_interfaces[neifs].ifindex)
            {
              continue;
            }
          /* skip any ignored address from conf file */
          if (HCNF.ignored_addr.ss_family &&
              (l->addr.ss_family ==
               HCNF.ignored_addr.ss_family) &&
              (memcmp(SA2IP(&l->addr), SA2IP(&HCNF.ignored_addr),
                      SAIPLEN(&l->addr)) == 0))
            {
              continue;
            }
          if (TRUE == l->preferred)
            {
              l_new_external = l;
              break;
            }
          /* skip local and multicast addresses */
          if ((l->addr.ss_family == AF_INET6) &&
              (IN6_IS_ADDR_LINKLOCAL(SA2IP6(&l->addr)) ||
               IN6_IS_ADDR_SITELOCAL(SA2IP6(&l->addr)) ||
               IN6_IS_ADDR_MULTICAST(SA2IP6(&l->addr))))
            {
              continue;
            }
          if (!l_new_external)
            {
              l_new_external = l;
            }
        }
      if (l_new_external)
        {
          struct sockaddr *out =
            SA(&external_interfaces[neifs].address);
          pthread_mutex_lock(&hip_mr_client_mutex);
          out->sa_family = l_new_external->addr.ss_family;
          memcpy(SA2IP(out), SA2IP(&l_new_external->addr),
                 SAIPLEN(out));
          pthread_mutex_unlock(&hip_mr_client_mutex);
          external_interfaces[neifs].state = EIF_AVAILABLE;
          log_(NORM,"%s selected as the external address for "
               "%s.\n", logaddr(SA(&l_new_external->addr)),
               external_interfaces[neifs].name);
        }
      else
        {
          external_interfaces[neifs].state = EIF_UNAVAILABLE;
          log_(NORM, "Unable to find address on outbound "
               "interface %s\n",
               external_interfaces[neifs].name);
        }
      neifs++;
    }
  return(0);
}

/*
 * \fn send_updates()
 *
 * \param out		new external address for proxy UPDATE
 *
 * \brief This is invoked from hip_mr_handle_address_change() when an address
 *        has been added or removed from the mobile router. If a new address
 *        is the only available address on any external interface or if a
 *        deleted address was the current external address and another address
 *        is available, hip_mr_handle_address_change() will call this function.
 */
void send_updates(struct sockaddr *out)
{
  int i;
  hip_mr_client *client;
  hip_spi_nat *spi_nat;
  struct sockaddr *client_addr, *dst;

  /* Send a proxy UPDATE for each SPINAT connection */

  for (i = 0; i < max_hip_mr_clients; i++)
    {
      client = &hip_mr_client_table[i];
      client_addr = SA(&client->mn_addr);
      for (spi_nat = client->spi_nats; spi_nat;
           spi_nat = spi_nat->next)
        {
          dst = SA(&spi_nat->peer_addr);
          log_(NORM, "Sending UPDATE from %s to ", logaddr(out));
          log_(NORM, "%s for client ", logaddr(dst));
          log_(NORM, "%s\n", logaddr(client_addr));
          hip_send_proxy_update(out, dst, spi_nat,
                                &client->mn_hit);
          memcpy(SA(&spi_nat->last_out_addr), out,
                 SALEN(&spi_nat->last_out_addr));
        }
    }
}

/*
 * \fn hip_mr_handle_address_change()
 *
 * \param add		corresponds to add parameter of
 *                         handle_local_address_change()
 * \param newaddr       corresponds to newaddr parameter of
 *                         handle_local_address_change()
 * \param ifi		corresponds to ifi parameter of
 *                         handle_local_address_change()
 *
 * \brief This is invoked from handle_local_address_change() when an address
 *        has been added or removed from the mobile router. The mobile router
 *        may then select a new external address for that interface,
 *        which may trigger the UPDATE procedure.
 */
void hip_mr_handle_address_change(int add, struct sockaddr *newaddr, int ifi)
{
  int i, j;
  struct sockaddr *out, *update_addr = NULL;
  sockaddr_list *l, *l_new_external;

  if (!OPT.mr)
    {
      return;
    }

  for (i = 0; i < neifs; i++)
    {
      if (ifi == external_interfaces[i].ifindex)
        {
          break;
        }
    }
  if (i >= neifs)
    {
      return;
    }

  out = SA(&external_interfaces[i].address);
  pthread_mutex_lock(&hip_mr_client_mutex);

  /*
   * Address added to external interface
   */
  if (add && (external_interfaces[i].state == EIF_UNAVAILABLE))
    {
      /* There is no external address for this interface,
       * set the new address to be the external address */
      out->sa_family = newaddr->sa_family;
      memcpy(SA2IP(out), SA2IP(newaddr), SAIPLEN(out));
      external_interfaces[i].state = EIF_AVAILABLE;
      log_(NORM, "Using %s as new external address for %s\n",
           logaddr(out), external_interfaces[i].name);
      /*
       * If this is the only available interface, we need to send
       * a proxy UPDATE for each SPINAT connection for each client
       */
      for (j = 0; j < neifs; j++)
        {
          if ((ifi != external_interfaces[j].ifindex) &&
              (external_interfaces[j].state == EIF_AVAILABLE))
            {
              break;
            }
        }
      if (j >= neifs)
        {
          update_addr = out;
        }
      goto hip_mr_handle_address_change_exit;
    }

  /*
   * Address removed from external interface
   */
  /* Is the deleted address the external address? */
  if ((out->sa_family != newaddr->sa_family) ||
      (memcmp(SA2IP(out), SA2IP(newaddr), SAIPLEN(out))))
    {
      goto hip_mr_handle_address_change_exit;           /* other addr removed */
    }
  /* Try to find a new external address on the interface. Zero the
   * variable if none found.*/
  l_new_external = NULL;
  for (l = my_addr_head; l; l = l->next)
    {
      /* Try to use the same address family, otherwise use the first
       * non-local address on this interface */
      if (l->if_index != external_interfaces[i].ifindex)
        {
          continue;
        }
      /* skip any ignored address from conf file */
      if (HCNF.ignored_addr.ss_family &&
          (l->addr.ss_family == HCNF.ignored_addr.ss_family) &&
          (memcmp(SA2IP(&l->addr), SA2IP(&HCNF.ignored_addr),
                  SAIPLEN(&l->addr)) == 0))
        {
          continue;
        }
      /* skip local and multicast addresses */
      if ((l->addr.ss_family == AF_INET6) &&
          (IN6_IS_ADDR_LINKLOCAL(SA2IP6(&l->addr)) ||
           IN6_IS_ADDR_SITELOCAL(SA2IP6(&l->addr)) ||
           IN6_IS_ADDR_MULTICAST(SA2IP6(&l->addr))))
        {
          continue;
        }
      if (l->addr.ss_family == out->sa_family)
        {
          l_new_external = l;               /* prefer the same address family */
          break;
        }
      else if (!l_new_external)
        {
          l_new_external = l;
        }
    }
  if (l_new_external)
    {
      out->sa_family = l_new_external->addr.ss_family;
      memcpy(SA2IP(out), SA2IP(&l_new_external->addr), SAIPLEN(out));
      log_(NORM, "Using %s as new external address for %s\n",
           logaddr(out), external_interfaces[i].name);
    }
  else
    {
      log_(WARN, "No new external address found for %s\n",
           external_interfaces[i].name);
      external_interfaces[i].state = EIF_UNAVAILABLE;
      /* Is there an available interface? */
      for (j = 0; j < neifs; j++)
        {
          if (external_interfaces[j].state == EIF_AVAILABLE)
            {
              break;
            }
        }
      if (j >= neifs)
        {
          log_(WARN, "No external interfaces available\n");
        }
      else
        {
          log_(NORM, "Interface %s is available\n",
               external_interfaces[j].name);
          update_addr = SA(&external_interfaces[j].address);
        }
      memset(out, 0, sizeof(external_interfaces[i].address));
    }

hip_mr_handle_address_change_exit:

  if (update_addr)
    {
      send_updates(update_addr);
    }
  pthread_mutex_unlock(&hip_mr_client_mutex);
}

/*
 * \fn init_hip_mr_client()
 *
 * \param peer_hit	HIT of the mobile router client's peer. The mobile
 *                      router does not necessarily have an association with
 *                      this HIT.
 * \param src           source IP address of the mobile router client, which
 *                      is stored in the new entry.
 *
 * \brief Add a mobile router client entry to the table. Initialize the entry
 *        using the given peer HIT and client source address. Increase the
 *        max_hip_mr_clients count. Enforce a MAX_MR_CLIENTS limit.
 */
int init_hip_mr_client(hip_hit peer_hit, struct sockaddr *src)
{
  int i, num;
  hip_mr_client *hip_mr_c;

  /* Check to see if client already in the table */
  hip_mr_c = mr_client_lookup(peer_hit);
  if (hip_mr_c)
    {
      log_(WARN, "Mobile router client already exists.\n");
      return(-1);
      /* TODO: properly handle this case. update the source address
       *       in the client entry; assume old SAs with client will
       *       be handled by hip_parse_I2(), etc.
       */
    }

  /* Find an unused slot in the mr_client_table.
   */
  num = -1;
  pthread_mutex_lock(&hip_mr_client_mutex);
  for (i = 0; i < max_hip_mr_clients; i++)
    {
      if (hip_mr_client_table[i].state == CANCELLED)
        {
          num = i;
          free_hip_mr_client(&hip_mr_client_table[i]);
          if (num == max_hip_mr_clients)
            {
              max_hip_mr_clients++;
            }
          break;
        }
    }
  if (num < 0)
    {
      num = max_hip_mr_clients;
      if (num == MAX_MR_CLIENTS)
        {
          log_(WARN, "Max number of Mobile Router clients "
               "reached.\n");
          pthread_mutex_unlock(&hip_mr_client_mutex);
          return(-1);
        }
      else
        {
          max_hip_mr_clients++;
        }
    }

  hip_mr_c = &(hip_mr_client_table[num]);
  memcpy(hip_mr_c->mn_hit, peer_hit, sizeof(hip_hit));
  memcpy(SA(&hip_mr_c->mn_addr), src, SALEN(src));
  hip_mr_c->state = RESPONSE_SENT;
  pthread_mutex_unlock(&hip_mr_client_mutex);

  return(0);
}

/*
 * \fn free_hip_mr_client()
 *
 * \param hip_mr_c	mobile router client entry to free
 *
 * \brief  Removes a mobile router client entry from the mobile router client
 *         table. Frees its spi_nat linked list. Reduces the
 *         max_hip_mr_clients count.
 */
int free_hip_mr_client(hip_mr_client *hip_mr_c)
{
  int i;

  /* locate the client in the table */
  for (i = 0; i < max_hip_mr_clients; i++)
    {
      if (hip_mr_c == &hip_mr_client_table[i])
        {
          break;
        }
    }

  /* return error when the client was not found */
  if ((i > max_hip_mr_clients) || (i > MAX_MR_CLIENTS))
    {
      return(-1);
    }

  while (hip_mr_c->spi_nats)
    {
      hip_spi_nat *temp = hip_mr_c->spi_nats;
      hip_mr_c->spi_nats = temp->next;
      free(temp);
    }
  memset(hip_mr_c, 0, sizeof(hip_mr_client));
  hip_mr_c->state = CANCELLED;
  if (i == (max_hip_mr_clients - 1))
    {
      max_hip_mr_clients--;
    }

  return(i);

}

/*
 * \fn add_proxy_ticket()
 *
 * \param data		character pointer to the proxy ticket TLV in the
 *                      HIP packet
 *
 * \brief Add proxy ticket data to the mobile router client table.
 */
int add_proxy_ticket(const __u8 *data)
{
  int i, ret = -1;
  hip_mr_client *hip_mr_c;
  hip_spi_nat *spi_nats = NULL;
  tlv_proxy_ticket *ticket = (tlv_proxy_ticket *) data;
  char hit_str[INET6_ADDRSTRLEN];

  pthread_mutex_lock(&hip_mr_client_mutex);
  for (i = 0; i < max_hip_mr_clients; i++)
    {
      hip_mr_c = &(hip_mr_client_table[i]);
      if (hip_mr_c->state != RESPONSE_SENT)
        {
          continue;
        }
      if (!hits_equal(ticket->mn_hit, hip_mr_c->mn_hit))
        {
          continue;
        }
      for (spi_nats = hip_mr_c->spi_nats; spi_nats;
           spi_nats = spi_nats->next)
        {
          if (!hits_equal(ticket->peer_hit,
                          spi_nats->peer_hit))
            {
              continue;
            }
          spi_nats->ticket.hmac_key_index =
            ntohs(ticket->hmac_key_index);
          spi_nats->ticket.transform_type =
            ntohs(ticket->transform_type);
          spi_nats->ticket.action = ntohs(ticket->action);
          spi_nats->ticket.lifetime = ntohs(ticket->lifetime);
          memcpy(spi_nats->ticket.hmac_key, ticket->hmac_key,
                 sizeof(ticket->hmac_key));
          memcpy(spi_nats->ticket.hmac, ticket->hmac,
                 sizeof(ticket->hmac));
          ret = i;
          break;
        }
    }
  pthread_mutex_unlock(&hip_mr_client_mutex);
  /* status output */
  hit_to_str(hit_str, ticket->mn_hit);
  if (ret < 0)
    {
      log_(WARN, "Unable to find mobile router client %s to peer ",
           hit_str);
      hit_to_str(hit_str, ticket->peer_hit);
      log_(NORM, "%s\n", hit_str);
    }
  else
    {
      log_(NORM, "Added proxy ticket for mobile router client %s to ",
           hit_str);
      hit_to_str(hit_str, ticket->peer_hit);
      log_(NORM, "peer %s (keymat %d)\n", hit_str,
           spi_nats->ticket.hmac_key_index);
    }

  return(ret);
}

/*
 * \fn is_mobile_router()
 *
 * \return      Returns true if mobile router option was specified.
 *
 * \brief Return true if this HIP daemon is configured to serve as a HIP
 *        mobile router.
 */
int is_mobile_router()
{
  return(OPT.mr);
}

/*
 * \fn hip_mobile_router_add_remove_rules()
 *
 * \param queue_num	queue number
 * \param del		0 for add, 1 for delete
 *
 * \return      Returns -1 if any of the system() calls return an error.
 *
 * \brief  Add or remove iptables firewalls rules that send HIP (139) and
 *   ESP (50) packets to the netfilter queue.
 */
int hip_mobile_router_add_remove_rules(int queue_num, int del)
{
  const char adddel = del ? 'D' : 'A';
  const char pre[] = "PREROUTING";
  const char post[] = "POSTROUTING";
  const char *ipt, *hook = pre;
  int proto, i, j, err = 0;
  char cmd[255];

  for (i = 0, j = 0; i < 8; i++, j++)
    {
      proto = i % 2 ? 50 : 139;
      /* first 4 rules are for IPv4, then IPv6 */
      ipt = i > 3 ? "ip6tables" : "iptables";
      if (j > 1)             /* switch between pre/post routing hooks */
        {
          j = 0;
          hook = (hook == pre) ? post : pre;               /* toggle */
        }

      snprintf(cmd, sizeof(cmd),
               "%s -t mangle -%c %s -p %d -j NFQUEUE --queue-num %d",
               ipt, adddel, hook, proto, queue_num);
      if (system(cmd) < 0)
        {
          err--;
        }
    }
  return(err);
}

/*
 * \fn netfilter_queue_init()
 *
 * \param queue_num	queue number
 *
 * \brief Initialize a netlink netfilter socket at bind to the specified
 *        queue number. Returns the new socket number.
 */
int netfilter_queue_init(int queue_num)
{
  int nlfd;
  struct sockaddr_nl nladdr;
  socklen_t nladdr_len;

  /* set up a netlink netfilter socket */
  nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
  if (nlfd < 0)
    {
      printf("*** %s error opening Netlink socket: "
             "%s\n", __FUNCTION__, strerror(errno));
      return(-1);
    }

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_groups = 0;
  nladdr_len = sizeof(nladdr);

  if (getsockname(nlfd, SA(&nladdr), &nladdr_len) < 0)
    {
      printf("*** %s getsockname error: %s\n",
             __FUNCTION__, strerror(errno));
      return(-1);
    }
  /* initial bind with port/pid zero */
  if (bind(nlfd, SA(&nladdr), sizeof(nladdr)) < 0)
    {
      printf("*** %s error with init Netlink socket bind: "
             "%s\n", __FUNCTION__, strerror(errno));
      return(-1);
    }
  /* get netlink port/pid assigned by the kernel */
  nladdr_len = sizeof(nladdr);
  if (getsockname(nlfd, SA(&nladdr), &nladdr_len) < 0)
    {
      printf("*** %s getsockname error: %s\n",
             __FUNCTION__, strerror(errno));
      return(-1);
    }
  if (bind(nlfd, SA(&nladdr), sizeof(nladdr)) < 0)
    {
      printf("*** %s error binding Netlink socket: "
             "%s\n", __FUNCTION__, strerror(errno));
      return(-1);
    }

  /* disconnect any existing queue */
  if (netfilter_queue_unbind(nlfd, queue_num, AF_INET) < 0)
    {
      printf("*** %s error un-binding Netlink queue\n",
             __FUNCTION__);
      return(-1);
    }
  /* bind to address family */
  if (netfilter_queue_bind(nlfd, queue_num, AF_INET) < 0)
    {
      printf("*** %s error binding Netlink queue\n", __FUNCTION__);
      return(-1);
    }
  /* bind to queue number */
  if (netfilter_queue_bind(nlfd, queue_num, 0) < 0)
    {
      printf("*** %s error binding Netlink queue\n", __FUNCTION__);
      return(-1);
    }
  /* configure the queue */
  if (netfilter_queue_config_param(nlfd, queue_num) < 0)
    {
      printf("*** %s error setting queue mode\n", __FUNCTION__);
      return(-1);
    }
  return(nlfd);
}

/*
 * \fn netfilter_queue_bind()
 *
 * \param nlfd		netlink socket
 * \param n		queue number
 * \param af		address family
 *
 * \brief  Send a BIND or PF_BIND netfilter command message.
 */
int netfilter_queue_bind(int nlfd, int n, int af)
{
  int c = NFQNL_CFG_CMD_BIND;
  if (af > 0)
    {
      c = NFQNL_CFG_CMD_PF_BIND;
    }
  return(netfilter_queue_config_command(nlfd, n, c, af));
}

/*
 * \fn netfilter_queue_unbind()
 *
 * \param nlfd		netlink socket
 * \param n		queue number
 * \param af		address family
 *
 * \brief  Send an UNBIND or PF_UNBIND netfilter command message.
 */
int netfilter_queue_unbind(int nlfd, int n, int af)
{
  int c = NFQNL_CFG_CMD_UNBIND;
  if (af > 0)
    {
      c = NFQNL_CFG_CMD_PF_UNBIND;
    }
  return(netfilter_queue_config_command(nlfd, n, c, af));
}

/*
 * \fn netfilter_queue_config_command()
 *
 * \param nlfd		netlink socket
 * \param queue_num	queue number
 * \param cmd		configuration command type
 * \param af		address family
 *
 * \brief  Build and send a netfilter queue configuration command, which is
 *         used for bind and unbind commands.
 */
int netfilter_queue_config_command(int nlfd, int queue_num, int cmd, int af)
{
  __u8 buf[512];
  int len;
  struct nfqnl_msg_config_cmd *c;

  len = NLMSG_ALIGN(sizeof(struct nfqnl_msg_config_cmd));
  c = (struct nfqnl_msg_config_cmd *)
      netfilter_queue_command_hdr(buf, queue_num, NFQA_CFG_CMD, &len);
  c->command = cmd;
  c->pf = htons(af);

  return(netfilter_queue_sendmsg(nlfd, buf, len));
}

/*
 * \fn netfilter_queue_config_param()
 *
 * \param nlfd		netlink socket
 * \param queue_num	queue number
 *
 * \brief  Build and send a netfilter queue configuration parameters message.
 * This sets the given queue number to packet copy mode.
 */
int netfilter_queue_config_param(int nlfd, int queue_num)
{
  __u8 buf[512];
  int len;
  struct nfqnl_msg_config_params *p;

  len = NLMSG_ALIGN(sizeof(struct nfqnl_msg_config_params));
  p = (struct nfqnl_msg_config_params *)
      netfilter_queue_command_hdr(buf, queue_num, NFQA_CFG_PARAMS, &len);
  p->copy_range = 0xFFFF;
  p->copy_mode = NFQNL_COPY_PACKET;

  return(netfilter_queue_sendmsg(nlfd, buf, len));
}

/*
 * \fn netfilter_queue_command_hdr()
 *
 * \param buf		destination buffer
 * \param queue_num	queue number
 * \param type		netfilter attribute type
 * \param len		(in) attribute data length, (out) message length
 *
 * \brief Build a netfilter queue config message into buf; return a pointer to
 *	  the attribute data.
 */
__u8* netfilter_queue_command_hdr(__u8 *buf, int queue_num, int type, int *len)
{
  int msglen;
  struct nlmsghdr *n;
  struct nfgenmsg *g;
  struct nfattr *attr;

  msglen = sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg) +
           sizeof(struct nfattr) + *len;
  memset(buf, 0, msglen);

  n = (struct nlmsghdr*) buf;
  n->nlmsg_len = NLMSG_ALIGN(msglen);
  n->nlmsg_type = (NETLINK_FIREWALL << 8) | NFQNL_MSG_CONFIG;
  n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  n->nlmsg_pid = 0;
  n->nlmsg_seq = 0;

  g = (struct nfgenmsg *) ++n;
  g->nfgen_family = 0;
  g->version = 0;
  g->res_id = htons(queue_num);

  attr = (struct nfattr *) ++g;
  attr->nfa_type = type;
  attr->nfa_len = sizeof(struct nfattr) + *len;

  *len = msglen;
  return((__u8*) ++attr);
}

#define PRINT_NLMSGHDR(n) { \
    printf("nlmsg len=%d type=%d flags=%d seq=%d pid=%d\n", \
           n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags, \
           n->nlmsg_seq, n->nlmsg_pid); }


/*
 * \fn netfilter_queue_sendmsg()
 *
 * \param nlfd		netlink socket
 * \param data		ptr of data to send (struct nlmsghdr)
 * \param len		length of data to send
 *
 * \brief  Send data on the netlink socket and receive the kernel's reply.
 */
int netfilter_queue_sendmsg(int nlfd, __u8 *data, int len)
{
  struct sockaddr_nl nladdr;
  struct nlmsghdr *resp;
  int recv_len, expected_type;
  char buf[512];
  struct iovec iov = { buf, sizeof(buf) };
  struct msghdr msg = {
    (void*)&nladdr, sizeof(nladdr),
    &iov, 1, NULL, 0,0
  };
#if 0
  int i;
  printf("---- hex\n");
  for (i = 0; i < len; i++)
    {
      printf("%02x ", data[i] & 0xFF);
      if ((i > 0) && ((i % 16) == 0))
        {
          printf("\n");
        }
    }
  printf("\n---- end hex\n");
#endif
  expected_type = ((struct nlmsghdr*) data)->nlmsg_type & 0xFF;

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  if (sendto(nlfd, (void*)data, len, 0, SA(&nladdr),
             sizeof(nladdr)) < 0)
    {
      printf("netfilter_queue_sendmsg(): sendto error: %s\n",
             strerror(errno));
      return(-1);
    }

  if ((recv_len = recvmsg(nlfd, &msg, 0)) < 0)
    {
      printf("netfilter_queue_set(): recvmsg error: %s\n",
             strerror(errno));
      return(-1);
    }
  resp = (struct nlmsghdr*) buf;
  while (NLMSG_OK(resp, recv_len))
    {
      if (resp->nlmsg_type != expected_type)
        {
          return(-1);
        }
      resp = NLMSG_NEXT(resp, recv_len);
    }
  return(0);
}

/*
 * \fn netfilter_get_packet()
 *
 * \param nlfd		netlink socket
 * \param buf		destination packet buffer
 * \param buf_len	(in) size of buffer, (out) length of packet stored
 * \param family	ptr to store packet address family
 * \param id		ptr to store packet id (used with verdict)
 * \param hook		ptr to store netfilter hook number
 * \param ifi		ptr to store received interface index
 *
 * \brief  Receive packet from the kernel's netlink netfilter queue.
 */
int netfilter_get_packet(int nlfd, __u8 *buf, int *buf_len, __u8 *family,
                         __u32 *id, __u8 *hook, int *ifi)
{
  struct sockaddr_nl nladdr_from;
  socklen_t nladdr_len;
  struct nlmsghdr *n;
  struct nfgenmsg *nfmsg;
  struct nfattr *attr;
  struct nfqnl_msg_packet_hdr *pkt;
  int len, err = -1;
  __u32 *p32;

  nladdr_len = sizeof(nladdr_from);
  len = recvfrom(nlfd, buf, *buf_len, 0,
                 SA(&nladdr_from), &nladdr_len);
  if (len < 0)
    {
      printf("*** %s recvfrom error: %s\n",
             __FUNCTION__, strerror(errno));
      return(-1);
    }

  n = (struct nlmsghdr *) buf;

  /* PRINT_NLMSGHDR(n) */
  if (n->nlmsg_len != len)
    {
      printf("*** %s length mismatch %d != %d\n",
             __FUNCTION__, n->nlmsg_len, len);
      return(-1);
    }
  if ((n->nlmsg_type & 0xFF) != NFQNL_MSG_PACKET)
    {
      printf("ignoring netlink packet type %d\n", n->nlmsg_type);
      return(-1);
    }
  nfmsg = (struct nfgenmsg*) NLMSG_DATA(n);
  *family = nfmsg->nfgen_family;
  /* printf("family=%d ver=%d queuenum=%d\n", nfmsg->nfgen_family,
   *       nfmsg->version, ntohs(nfmsg->res_id)); */

  attr = (struct nfattr*) NFM_NFA(nfmsg);
  len = NFM_PAYLOAD(n);
  while (NFA_OK(attr, len))
    {
      /* printf(" attr: %d len=%d (remain %d)\n",
       *       NFA_TYPE(attr), attr->nfa_len, len); */
      switch (NFA_TYPE(attr))
        {
        case NFQA_PACKET_HDR:
          pkt = (struct nfqnl_msg_packet_hdr *) NFA_DATA(attr);
          *id = ntohl(pkt->packet_id);
          *hook = pkt->hook;
          /* printf("packet_id = %d, hwproto = %d, hook = %d\n",
           *id, pkt->hw_protocol, pkt->hook); */
          break;
        case NFQA_IFINDEX_INDEV:
        case NFQA_IFINDEX_OUTDEV:
          p32 = (__u32*) NFA_DATA(attr);
          *ifi = ntohl(*p32);
          break;
        case NFQA_HWADDR:
          break;
        case NFQA_PAYLOAD:
          if (*buf_len < attr->nfa_len)
            {
              printf("%s packet too large: %d < %d\n",
                     __FUNCTION__, *buf_len, attr->nfa_len);
              return(-1);
            }
          *buf_len = NFA_PAYLOAD(attr);
          memcpy(buf, NFA_DATA(attr), *buf_len);
          err = 0;
          break;
        }
      attr = NFA_NEXT(attr, len);
    }
  if (err < 0)
    {
      printf("*** %s did not receive packet payload data!\n",
             __FUNCTION__);
    }
  return(err);
}

/*
 * \fn netfilter_queue_set_verdict()
 *
 * \param nlfd		netlink socket
 * \param queue_num	queue number
 * \param id		packet id
 * \param verict	accept, drop, or steal packet
 * \param data_len	length of optional modified packet data
 * \param data		optional modified packet data
 *
 * \brief  Tell the kernel to accept or drop a queued packet via netlink.
 */
int netfilter_queue_set_verdict(int nlfd, int queue_num, __u32 id,
                                __u32 verdict, int data_len, __u8 *data)
{
  struct iovec iov[2];
  int msglen, nv;
  struct nlmsghdr *n;
  struct nfgenmsg *g;
  struct nfattr *attr;
  struct nfqnl_msg_verdict_hdr *v;
  __u8 buf[512];
  struct sockaddr_nl nladdr;
  struct msghdr msg;

  /* printf("%s() id=%d verdict=%d (data_len=%d)\n", __FUNCTION__,
   *       id, verdict, data_len); */

  msglen = sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg) +
           sizeof(struct nfattr) + sizeof(struct nfqnl_msg_verdict_hdr);
  if (data_len > 0)
    {
      msglen += sizeof(struct nfattr) + data_len;
    }
  memset(buf, 0, sizeof(buf));

  n = (struct nlmsghdr*) buf;
  n->nlmsg_len = NLMSG_ALIGN(msglen);
  n->nlmsg_type = (NETLINK_FIREWALL << 8) | NFQNL_MSG_VERDICT;
  n->nlmsg_flags = NLM_F_REQUEST;
  n->nlmsg_pid = 0;
  n->nlmsg_seq = 0;

  g = (struct nfgenmsg *) ++n;
  g->nfgen_family = 0;
  g->version = 0;
  g->res_id = htons(queue_num);

  attr = (struct nfattr *) ++g;
  attr->nfa_type = NFQA_VERDICT_HDR;
  attr->nfa_len = sizeof(struct nfattr) +
                  sizeof(struct nfqnl_msg_verdict_hdr);

  v = (struct nfqnl_msg_verdict_hdr *) ++attr;
  v->verdict = htonl(verdict);
  v->id = htonl(id);

  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = buf;

  /* IO vector used to avoid extra data copy for modified packets */
  if (data_len > 0)
    {
      attr = (struct nfattr *) ++v;
      attr->nfa_type = NFQA_PAYLOAD;
      attr->nfa_len = sizeof(struct nfattr) + data_len;
      iov[0].iov_len = msglen - data_len;
      iov[1].iov_base = data;
      iov[1].iov_len = data_len;
      nv = 2;
    }
  else
    {
      iov[0].iov_len = msglen;
      nv = 1;
    }

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;

  msg.msg_name = (void *)&nladdr;
  msg.msg_namelen = sizeof(nladdr);
  msg.msg_iov = iov;
  msg.msg_iovlen = nv;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  if (sendmsg(nlfd, &msg, 0) < 0)
    {
      printf("%s(): sendmsg error: %s\n",
             __FUNCTION__, strerror(errno));
      return(-1);
    }
  return(0);
}

