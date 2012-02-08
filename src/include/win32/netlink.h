/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2012 the Boeing Company
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
 *  \file  win32/netlink.h
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Minimal netlink definitions for win32.
 *
 */
#ifndef _NETLINK_H_
#define _NETLINK_H_

#define AF_NETLINK 16

/* Netlink address */
struct sockaddr_nl {
  __u16 nl_family;
  __u16 nl_pad;
  __u32 nl_pid;
  __u32 nl_groups;
};

/* Common Netlink message header */
struct nlmsghdr {
  __u32 nlmsg_len;
  __u16 nlmsg_type;
  __u16 nlmsg_flags;
  __u32 nlmsg_seq;
  __u32 nlmsg_pid;
};

/* Interface address message */
struct ifaddrmsg {
  __u8 ifa_family;
  __u8 ifa_prefixlen;
  __u8 ifa_flags;
  __u8 ifa_scope;
  int ifa_index;
};

/* Interface info message */
struct ifinfomsg {
  __u8 ifi_family;
  __u8 ifi_pad;
  __u16 ifi_type;
  int ifi_index;
  __u32 ifi_flags;
  __u32 ifi_change;
};

/* Routing message attribute */
struct rtattr {
  __u16 rta_len;
  __u16 rta_type;
};

/* Generic message header */
struct rtgenmsg {
  __u8 rtgen_family;
};

#define NLMSG_ALIGNTO   4
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_LENGTH(len) ((len) + NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))

#define RTM_NEWLINK 0x10
#define RTM_DELLINK 0x11
#define RTM_NEWADDR 0x14
#define RTM_DELADDR 0x15
#define RTM_GETADDR 0x16

#define IFA_ADDRESS 1
#define IFA_LOCAL 2
#define IFA_MAX 6
#define IFA_F_PERMANENT 0x80

#define RTA_ALIGNTO     4
#define RTA_ALIGN(len) (((len) + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1))
#define RTA_OK(rta,len) ((len) > 0 && (rta)->rta_len >= \
                         sizeof(struct rtattr) && \
                         (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen)   ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                                 (struct rtattr*)(((char*)(rta)) + \
                                                  RTA_ALIGN((rta)->rta_len)))
#define RTA_LENGTH(len) (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))

#define IFA_RTA(r)  ((struct rtattr*)(((char*)(r)) + \
                                      NLMSG_ALIGN(sizeof(struct ifaddrmsg))))

#define NLMSG_NOOP 0x1
#define NLMSG_ERROR 0x2
#define NLMSG_DONE 0x3

#define NLMSG_ALIGNTO   4
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_NEXT(nlh,len)  ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                              (struct nlmsghdr*)(((char*)(nlh)) + \
                                                 NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len) ((len) > 0 && \
                           (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
                           (nlh)->nlmsg_len <= (len))

#define NLM_F_ROOT 0x100
#define NLM_F_MATCH 0x200
#define NLM_F_REQUEST 0x1

#endif /* _NETLINK_H_ */

