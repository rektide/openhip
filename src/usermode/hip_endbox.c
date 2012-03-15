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
 *  \file  hip_endbox.c
 *
 *  \authors Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *           Orlie Brewer <orlie.t.brewer@boeing.com>
 *           Jeff Meegan, <jeff.r.meegan@boeing.com>
 *
 *  \brief  HIP Virtual Private LAN Service (VPLS) specific functions.
 *          This file is included only if HIP is configured with enable-vpls.
 *
 */
#include <stdio.h>              /* printf() */
#include <string.h>             /* memset, etc */
#include <unistd.h>             /* write() */
#include <utime.h>
#include <sys/time.h>           /* gettimeofday() */
#include <sys/errno.h>          /* errno, etc */
#include <sys/resource.h>       /* getrlimit, setrlimit */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/ip6.h>        /* struct ip6_hdr */
#include <netinet/icmp6.h>      /* struct icmp6_hdr */
#include <netinet/tcp.h>        /* struct tcphdr */
#include <netinet/udp.h>        /* struct udphdr */
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_usermode.h>
#include <hip/hip_sadb.h>
#include <hip/hip_globals.h>
#include <hip/hip_cfg_api.h>
#include <hip/endbox_utils.h>

struct eb_hello {
  hip_hit hit;
  __u32 time;
};

extern int tapfd;

/* Functions from hip_util.c and hip_esp.c */

extern __u32 get_preferred_lsi(struct sockaddr *);
extern void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type);

/* File globals */

static int no_multicast = FALSE;
static int endbox_hello_time = 0;
static time_t last_hello_time = 0;

/* Functions */

void endbox_init()
{
  int ret;
  struct rlimit limits;

  log_(NORM,"Initializing VPLS bridge\n");
  ret = system("/usr/local/etc/hip/bridge_up.sh");
  log_(NORM, "bridge_up.sh returns %d\n", ret);

  if (HCNF.endbox_allow_core_dump)
    {
      log_(NORM, "Setting limit on core size to max\n");
      ret = getrlimit(RLIMIT_CORE, &limits);
      log_(NORM, "getrlimit returns %d\n", ret);
      log_(NORM, "Current is %u; max is %u\n",
           limits.rlim_cur, limits.rlim_max);
      limits.rlim_cur = limits.rlim_max;
      ret = setrlimit(RLIMIT_CORE, &limits);
      log_(NORM, "setrlimit returns %d\n", ret);
      ret = getrlimit(RLIMIT_CORE, &limits);
      log_(NORM, "getrlimit returns %d\n", ret);
      log_(NORM, "Current is %u; max is %u\n",
           limits.rlim_cur, limits.rlim_max);
    }

  return;
}

/* Determine if this packet is from one of our legacy nodes to an allowed
 * remote legacy node.
 */
static int is_valid_packet(__u32 src, __u32 dst, struct sockaddr *lsi)
{
  int rc;
  hip_hit hit1, hit2;
  hi_node *my_host_id;
  /* char ip[INET6_ADDRSTRLEN]; */

  struct sockaddr_storage default_ss;
  struct sockaddr_storage host_ss;
  struct sockaddr_storage eb_ss;
  struct sockaddr *default_p;
  struct sockaddr *host_p;
  struct sockaddr *dest_p;
  struct sockaddr *eb_p;

  if (!src)
    {
      return(FALSE);
    }

  memset(&default_ss, 0, sizeof(struct sockaddr_storage));
  memset(&host_ss, 0, sizeof(struct sockaddr_storage));
  memset(&eb_ss, 0, sizeof(struct sockaddr_storage));
  default_p = (struct sockaddr*)&default_ss;
  host_p = (struct sockaddr*)&host_ss;
  eb_p = (struct sockaddr*)&eb_ss;

  default_p->sa_family = AF_INET;
  ((struct sockaddr_in *)default_p)->sin_addr.s_addr = 0;

  /* Is this source address a legacy node or is there a default endbox? */

  host_p->sa_family = AF_INET;
  ((struct sockaddr_in *)host_p)->sin_addr.s_addr = src;
  eb_p->sa_family = AF_INET6;
  rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
  if (rc)
    {
      rc = hipcfg_getEndboxByLegacyNode(default_p, eb_p);
      if (rc)
        {
          return(FALSE);
        }
    }

  /* Is this legacy node one of mine or am I the default endbox? */

  memcpy(hit1, SA2IP(eb_p), HIT_SIZE);
  my_host_id = get_preferred_hi(my_hi_head);
  if (compare_hits(my_host_id->hit, hit1) != 0)
    {
      return(FALSE);
    }

  /* If destination is zero, it is a multicast packet */

  if (!dst)
    {
      return(TRUE);
    }

  /* Is this dest address a legacy node or is there a default endbox? */

  host_p->sa_family = AF_INET;
  ((struct sockaddr_in *)host_p)->sin_addr.s_addr = dst;
  eb_p->sa_family = AF_INET6;
  rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
  dest_p = host_p;
  if (rc)
    {
      dest_p = default_p;
      rc = hipcfg_getEndboxByLegacyNode(default_p, eb_p);
      if (rc)
        {
          return(FALSE);
        }
    }

  /* If the destination is also one of ours, ignore the packet */

  memcpy(hit2, SA2IP(eb_p), HIT_SIZE);
  if (compare_hits(my_host_id->hit, hit2) == 0)
    {
      return(FALSE);
    }

  /* Are we allowed to send to remote endbox? */

  if (!hipcfg_allowed_peers(hit1, hit2))
    {
      log_(NORM, "peer connection not allowed hit1: %02x%02x, hit2: "
           "%02x%02x\n", hit1[HIT_SIZE - 2], hit1[HIT_SIZE - 1],
           hit2[HIT_SIZE - 2], hit2[HIT_SIZE - 1]);
      return(FALSE);
    }
  else
    {
      /* Get the LSI of the destination endbox */
      eb_p->sa_family = AF_INET;
      hipcfg_getEndboxByLegacyNode(dest_p, eb_p);
      lsi->sa_family = AF_INET;
      LSI4(lsi) = ntohl(LSI4(eb_p));
      return(TRUE);
    }
}

/*
 * Called from tunreader()
 * Send a hello using protocol IEEE Std 802 - Local Experimental Ethertype 1.
 * This lets other HIP daemons know that you are on the same subnet segment.
 */
void endbox_send_hello()
{
  __u8 out[256];
  __u64 dst_mac = 0xffffffffffffffffLL;
  int outlen = 0;
  hi_node *my_host_id;
  struct eb_hello *endbox_hello;

  /* Is my host id set yet? */

  my_host_id = get_preferred_hi(my_hi_head);
  if (!my_host_id)
    {
      return;
    }

  add_eth_header(out, g_tap_mac, dst_mac, 0x88b5);

  endbox_hello = (struct eb_hello *) &out[14];
  memcpy(endbox_hello->hit, my_host_id->hit, sizeof(hip_hit));
  endbox_hello->time = htonl(HCNF.endbox_hello_time);

  outlen = sizeof(struct eth_hdr) + sizeof(struct arp_hdr) + 20;

  if (write(tapfd, out, outlen) < 0)
    {
      log_(WARN, "Sending endbox hello failed.\n");
    }
}

/*
 * Called from hip_esp_output()
 * If another HIP deamon with a smaller HIT is on the same subnet segment,
 * do not forward multicast to legacy nodes.  The other deamon will do it.
 */
void endbox_hello_check(__u8 *buffer)
{
  struct eb_hello *endbox_hello = (struct eb_hello *) (buffer + 14);
  hi_node *my_host_id = get_preferred_hi(my_hi_head);

  if (compare_hits(my_host_id->hit, endbox_hello->hit) > 0)
    {
      no_multicast = TRUE;
      endbox_hello_time = ntohl(endbox_hello->time);
      last_hello_time = time(NULL);
    }
}

/*
 * Called from hip_esp_output()
 * If another HIP deamon with a smaller HIT is no longer on the same subnet
 * segment, start forwarding multicast to legacy nodes.
 */
void endbox_check_hello_time(time_t *now_time)
{
  if (no_multicast &&
      (*now_time - last_hello_time > 2 * endbox_hello_time))
    {
      no_multicast = FALSE;
    }
}

/*
 * Called from hip_esp_output()
 */
int endbox_ipv4_packet_check(struct ip *iph, struct sockaddr *lsi,
                             int *packet_count)
{
  __u32 dst;

  if (!IN_MULTICAST(ntohl(iph->ip_dst.s_addr)) &&
      (((ntohl(iph->ip_dst.s_addr)) & 0x000000FF) != 0x000000FF))
    {
      dst = iph->ip_dst.s_addr;
    }
  else
    {
      dst = 0;
    }
  if (!is_valid_packet(iph->ip_src.s_addr, dst, lsi))
    {
      return(-1);
    }
  (*packet_count)++;
  return(0);
}

/*
 * Called from hip_esp_output()
 */
int endbox_arp_packet_check(struct arp_hdr *arph, struct sockaddr *lsi,
                            int *packet_count)
{
  struct arp_req_data *arp_req;

  if ((ntohs(arph->ar_hrd) == 0x01) &&           /* Ethernet */
      (ntohs(arph->ar_pro) == 0x0800) &&         /* IPv4 */
      (arph->ar_hln == 6) && (arph->ar_pln == 4))
    {
      arp_req = (struct arp_req_data*)(arph + 1);
      if (!is_valid_packet(arp_req->src_ip, arp_req->dst_ip, lsi))
        {
          return(-1);
        }
    }
  else
    {
      return(-1);
    }
  (*packet_count)++;
  return(0);
}

/*
 * Called from hip_esp_output()
 */
int endbox_check_cert(struct sockaddr *lsi)
{
  struct sockaddr_storage hit_ss;
  struct sockaddr *hit_p;
  hip_hit hit;

  /* Get the HIT of the destination from the LSI */

  LSI4(lsi) = ntohl(LSI4(lsi));
  memset(&hit_ss, 0, sizeof(struct sockaddr_storage));
  hit_p = (struct sockaddr*)&hit_ss;
  hit_p->sa_family = AF_INET6;
  if (hipcfg_getEndboxByLegacyNode(lsi, hit_p))
    {
      LSI4(lsi) = ntohl(LSI4(lsi));
      return(FALSE);
    }

  LSI4(lsi) = ntohl(LSI4(lsi));
  memcpy(hit, SA2IP(hit_p), HIT_SIZE);

  if (hipcfg_verifyCert(NULL, hit) > 0)
    {
      return(TRUE);
    }
  else
    {
      return(FALSE);
    }

}

/*
 * Called from hip_esp_input()/output() while loops
 */
void endbox_periodic_heartbeat(time_t *now_time,
                               time_t *last_time,
                               int *packet_count,
                               char *name,
                               int touchHeartbeat)
{
  char filename[255];
  *now_time = time(NULL);
  snprintf(filename, sizeof(filename),
           "/usr/local/etc/hip/heartbeat_hip_%s", name);

  if (*now_time - *last_time > 60)
    {
      printf("hip_esp_%s() heartbeat (%d packets)\n",
             name, *packet_count);
      *last_time = *now_time;
      *packet_count = 0;
      if (touchHeartbeat)
        {
          utime(filename, NULL);
        }
      else
        {
          printf("not touching heartbeat_hip_%s!\n", name);
        }
    }
}

/*
 * Called from hip_esp_input()
 * If multicast IP address, do not send if no_multicast is set.
 */
void endbox_ipv4_multicast_write(__u8 *data, int offset, int len)
{
  struct ip *iph = (struct ip *) &data[offset + sizeof(struct eth_hdr)];
  struct eth_hdr *eth;

  if (IN_MULTICAST((ntohl(iph->ip_dst.s_addr))) && no_multicast)
    {
      return;
    }
  else
    {
      /* This is an ugly hack to fix a problem too convoluted to
       * explain here when two endboxes are connected to
       * cross-connected switches.
       */
      if (IN_MULTICAST((ntohl(iph->ip_dst.s_addr))))
        {
          eth = (struct eth_hdr *) &data[offset];
          memcpy(eth->src, &g_tap_mac, 6);
        }
      if (write(tapfd, &data[offset], len) < 0)
        {
          printf("hip_esp_input() write() failed.\n");
        }
    }
}

