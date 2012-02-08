/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2005-2012 the Boeing Company
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
 *  \file  win32/ip.h
 *
 *  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Definitions for TCP/IP headers that are missing from Windows.
 *
 */

#ifndef _HIP_IP_H_
#define _HIP_IP_H_

#include <ws2tcpip.h> /* this is required for the struct in6_addr's in
                       *  struct ip6_hdr */

#define IPVERSION 4
struct ip {
  __u8 ip_hl : 4, ip_v : 4;         /* MSVC requires these are char */
  /*__u32 ip_hl:4;	   This will not work with MSVC.
   *  __u32 ip_v:4;*/
  __u8 ip_tos;
  __u16 ip_len;
  __u16 ip_id;
  __u16 ip_off;
  __u8 ip_ttl;
  __u8 ip_p;
  __u16 ip_sum;
  union {                       /* allows use of struct ip or iphdr*/
    struct in_addr ip_src;
    __u32 saddr;
  };
  union {
    struct in_addr ip_dst;
    __u32 daddr;
  };
};
/* allows use of struct ip or iphdr*/
#define iphdr ip
#define ihl ip_hl


struct udphdr {
/*	__u16 uh_sport;
 *       __u16 uh_dport; */
  __u16 source;
  __u16 dest;
  __u16 uh_ulen;
  __u16 check;
};

struct tcphdr {
/*	__u16 th_sport;
 *       __u16 th_dport; */
  __u16 source;
  __u16 dest;
  __u32 th_seq;
  __u32 th_ack;
  __u8 th_x2 : 4, th_off : 4;
  __u8 th_flags;
  __u16 th_win;
  __u16 check;
  __u16 th_urp;
};

/* from netinet/ip6.h */
struct ip6_hdr
{
  union
  {
    struct ip6_hdrctl
    {
      __u32 ip6_un1_flow;                   /* 4 bits version, 8 bits TC,
                                             *     20 bits flow-ID */
      __u16 ip6_un1_plen;                   /* payload length */
      __u8 ip6_un1_nxt;                   /* next header */
      __u8 ip6_un1_hlim;                   /* hop limit */
    } ip6_un1;
    __u8 ip6_un2_vfc;             /* 4 bits version, top 4 bits tclass */
  } ip6_ctlun;
  struct in6_addr ip6_src;        /* source address */
  struct in6_addr ip6_dst;        /* destination address */
};

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

/* from netinet/icmp6.h */
struct icmp6_hdr
{
  __u8 icmp6_type;         /* type field */
  __u8 icmp6_code;         /* code field */
  __u16 icmp6_cksum;       /* checksum field */
  union
  {
    __u32 icmp6_un_data32[1];             /* type-specific field */
    __u16 icmp6_un_data16[2];             /* type-specific field */
    __u8 icmp6_un_data8[4];             /* type-specific field */
  } icmp6_dataun;
};

#define icmp6_data32    icmp6_dataun.icmp6_un_data32
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_data8     icmp6_dataun.icmp6_un_data8
#define icmp6_pptr      icmp6_data32[0]  /* parameter prob */
#define icmp6_mtu       icmp6_data32[0]  /* packet too big */
#define icmp6_id        icmp6_data16[0]  /* echo request/reply */
#define icmp6_seq       icmp6_data16[1]  /* echo request/reply */
#define icmp6_maxdelay  icmp6_data16[0]  /* mcast group membership */

#define ICMP6_DST_UNREACH             1
#define ICMP6_PACKET_TOO_BIG          2
#define ICMP6_TIME_EXCEEDED           3
#define ICMP6_PARAM_PROB              4

#define ICMP6_INFOMSG_MASK  0x80    /* all informational messages */

#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129
#define ICMP6_MEMBERSHIP_QUERY      130
#define ICMP6_MEMBERSHIP_REPORT     131
#define ICMP6_MEMBERSHIP_REDUCTION  132
#define ND_ROUTER_SOLICIT           133
#define ND_ROUTER_ADVERT            134
#define ND_NEIGHBOR_SOLICIT         135
#define ND_NEIGHBOR_ADVERT          136
#define ND_REDIRECT                 137

#if     BYTE_ORDER == BIG_ENDIAN
#define ND_NA_FLAG_ROUTER        0x80000000
#define ND_NA_FLAG_SOLICITED     0x40000000
#define ND_NA_FLAG_OVERRIDE      0x20000000
#else   /* BYTE_ORDER == LITTLE_ENDIAN */
#define ND_NA_FLAG_ROUTER        0x00000080
#define ND_NA_FLAG_SOLICITED     0x00000040
#define ND_NA_FLAG_OVERRIDE      0x00000020
#endif

struct nd_opt_hdr             /* Neighbor discovery option header */
{
  uint8_t nd_opt_type;
  uint8_t nd_opt_len;           /* in units of 8 octets */
  /* followed by option specific data */
};

#define  ND_OPT_SOURCE_LINKADDR       1
#define  ND_OPT_TARGET_LINKADDR       2
#define  ND_OPT_PREFIX_INFORMATION    3
#define  ND_OPT_REDIRECTED_HEADER     4
#define  ND_OPT_MTU                   5
#define  ND_OPT_RTR_ADV_INTERVAL      7
#define  ND_OPT_HOME_AGENT_INFO       8

#endif /* _HIP_IP_H_ */
