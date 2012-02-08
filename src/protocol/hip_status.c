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
 *  \file  hip_status.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief Status socket support, handles requests from an external status
 *         program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <win32/types.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/time.h>
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>         /* INADDR_NONE                  */
#include <netinet/ip.h>         /* INADDR_NONE                  */
#endif
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/asn1.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>              /* open()			*/
#ifdef __MACOSX__
#include <sys/types.h>
#else
#ifndef __WIN32__
#include <asm/types.h>
#endif
#endif
#ifndef __WIN32__
#include <netinet/ip6.h>
#endif
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#include <hip/hip_status.h>

/* Local definitions */
#ifndef IN_LOOPBACK
#define     IN_LOOPBACK(a)  ((((long int) (a)) & 0xff000000) == 0x7f000000)
#endif

/* Local functions */
int status_dump_hi_list(char *buff, hi_node *list, int do_addr);
int status_dump_addr_list(char *buff, sockaddr_list *addrs);
int status_dump_assoc(char *buff);
int status_dump_opts(char *buff);
void status_set_opts(__u8 *buff);


int hip_status_open()
{
  struct sockaddr_in addr;

  if (s_stat)
#ifdef __WIN32__
    { closesocket(s_stat); }

  if ((s_stat =
         socket(AF_INET, SOCK_DGRAM,
                IPPROTO_UDP)) == INVALID_SOCKET)
    {
      return(-1);
    }
#else
    { close(s_stat); }

  if ((s_stat = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
      return(-1);
    }
#endif
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(STATUS_PORT);

  if (bind(s_stat, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
      return(-1);
    }

  return(0);
}

void hip_handle_status_request(__u8 *buff, int len, struct sockaddr *addr)
{
  __u16 type;
  __u32 ip;
  char out[1500];
  int outlen = 0;
  struct status_tlv *tlv_end;

  /* For security purposes, only allow loopback connections
   * to status socket
   */
  if (!addr)
    {
      return;
    }
  if (addr->sa_family == AF_INET)
    {
      ip = ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
      if (!IN_LOOPBACK(ip))
        {
          return;
        }
    }
  else
    {
      if (!IN6_IS_ADDR_LOOPBACK(
            &((struct sockaddr_in6*)addr)->sin6_addr))
        {
          return;
        }
    }
  memcpy(&type, buff, 2);
  type = ntohs(type);

  if ((type < HIP_STATUS_REQ_MAX) && (len != 4))
    {
      return;
    }

  switch (type)
    {
    case HIP_STATUS_REQ_PEERS:
      outlen = status_dump_hi_list(out, peer_hi_head, TRUE);
      break;
    case HIP_STATUS_REQ_MYIDS:
      outlen = status_dump_hi_list(out, my_hi_head, FALSE);
      break;
    case HIP_STATUS_REQ_MYADDRS:
      outlen = status_dump_addr_list(out, my_addr_head);
      break;
    case HIP_STATUS_REQ_ASSOC:
      outlen = status_dump_assoc(out);
      break;
    case HIP_STATUS_REQ_OPTS:
      outlen = status_dump_opts(out);
      break;
    case HIP_STATUS_REQ_CONF:
      break;
    case HIP_STATUS_CONFIG_OPTS:
      status_set_opts(&buff[sizeof(struct status_tlv)]);
      outlen = 0;
      break;
    case HIP_STATUS_REQ_MIN:
    case HIP_STATUS_REQ_MAX:
    default:
      return;
    }

  if (outlen)
    {
      tlv_end = (struct status_tlv*) &out[outlen];
      tlv_end->tlv_type = htons(HIP_STATUS_REPLY_DONE);
      tlv_end->tlv_len =  0;
      outlen += sizeof(struct status_tlv);
      len = sendto(s_stat, out, outlen, 0, addr, SALEN(addr));
    }
}

/*
 * reply with:
 * hi
 * addrlist
 * hi
 * addrlist
 * ...
 */
int status_dump_hi_list(char *buff, hi_node *list, int do_addr)
{
  struct status_tlv *t = (struct status_tlv*) buff;
  char *p;
  hi_node *hi;
  int total_len = 0, len;
  __u32 lsi;

  for (hi = list; hi; hi = hi->next)
    {
      len = 0;
      p = (char *)(t + 1);
      /* HI node */
      t->tlv_type = htons(HIP_STATUS_REPLY_HI);
      ADD_ITEM(p, hi->hit, len);
      lsi = ((struct sockaddr_in*)&hi->lsi)->sin_addr.s_addr;
      ADD_ITEM(p, lsi, len);
      ADD_ITEM(p, hi->size, len);
      ADD_ITEM(p, hi->r1_gen_count, len);
      ADD_ITEM(p, hi->update_id, len);
      ADD_ITEM(p, hi->algorithm_id, len);
      strncpy(&p[len], hi->name, MAX_HI_NAMESIZE);
      len += strlen(hi->name);
      /* add anonymous, allow_incoming, skip_addrcheck here */
      t->tlv_len = htons((__u16)len);
      len += sizeof(struct status_tlv*);
      if (do_addr)             /* address list */
        {
          len += status_dump_addr_list(((char*)t) + len,
                                       &hi->addrs);
        }
      t = (struct status_tlv*) (((char*)t) + len);
      total_len += len;
    }
  return(total_len);
}

int status_dump_addr_list(char *buff, sockaddr_list *addrs)
{
  struct status_tlv *t = (struct status_tlv*) buff;
  sockaddr_list *a;
  char *p = (char*)(t + 1);
  int len = 0;

  t->tlv_type = htons(HIP_STATUS_REPLY_ADDR);

  for (a = addrs; a; a = a->next)
    {
      ADD_ITEM(p, a->addr, len)
    }

  t->tlv_len = htons((__u16)len);
  len += sizeof(struct status_tlv);
  return(len);
}

int status_dump_assoc(char *buff)
{
  struct status_tlv *t = (struct status_tlv*) buff;
  hip_assoc *a;
  char *p;
  int total_len = 0, len, i;

  for (i = 0; i < max_hip_assoc; i++)
    {
      a = &hip_assoc_table[i];
      /* skip empty entries */
      if (a->state == UNASSOCIATED)
        {
          continue;
        }
      len = 0;
      p = (char *)(t + 1);
      t->tlv_type = htons(HIP_STATUS_REPLY_ASSOC);
      ADD_ITEM(p, a->state, len);
      ADD_ITEM(p, a->state_time.tv_sec, len);
      ADD_ITEM(p, a->spi_in, len);
      ADD_ITEM(p, a->spi_out, len);
      ADD_ITEM(p, a->hip_transform, len);
      ADD_ITEM(p, a->esp_transform, len);
      ADD_ITEM(p, a->dh_group_id, len);
      t->tlv_len = htons((__u16)len);
      len += sizeof(struct status_tlv*);
      len += status_dump_hi_list(((char*)t) + len,
                                 a->hi, TRUE);
      len += status_dump_hi_list(((char*)t) + len,
                                 a->peer_hi, TRUE);
      /* These items not sent:
       *  cookie, rexmt_cache, opaque, rekey, peer_rekey, keys */
      t = (struct status_tlv*) (((char*)t) + len);
      total_len += len;
    }
  return(total_len);
}

int status_dump_opts(char *buff)
{
  struct status_tlv *t = (struct status_tlv*) buff;
  char *p = (char *)(t + 1);
  int len = 0;
  unsigned int opts;

  t->tlv_type = htons(HIP_STATUS_REPLY_OPTS);

  /* boolean options are encoded as bits in an 32-bit unsigned value */
  opts = (OPT.debug == D_VERBOSE);
  opts |= (OPT.debug_R1 == D_VERBOSE) << 1;
  opts |= (OPT.no_retransmit == TRUE) << 2;
  opts |= (OPT.opportunistic == TRUE) << 3;
  opts |= (OPT.permissive == TRUE) << 4;
  ADD_ITEM(p, opts, len);

  t->tlv_len = htons((__u16)len);

  return (len + sizeof(struct status_tlv*));
}

void status_set_opts(__u8 *buff)
{
  unsigned int opts;
  memcpy(&opts, buff, sizeof(unsigned int));

  if (opts & 0x0001)
    {
      OPT.debug = D_VERBOSE;
    }
  else
    {
      OPT.debug = D_DEFAULT;
    }
  if ((opts >> 1) & 0x0001)
    {
      OPT.debug_R1 = D_VERBOSE;
    }
  else
    {
      OPT.debug_R1 = D_QUIET;
    }
  if ((opts >> 2) & 0x0001)
    {
      OPT.no_retransmit = TRUE;
    }
  else
    {
      OPT.no_retransmit = FALSE;
    }
  if ((opts >> 3) & 0x0001)
    {
      OPT.opportunistic = TRUE;
    }
  else
    {
      OPT.opportunistic = FALSE;
    }
  if ((opts >> 4) & 0x0001)
    {
      OPT.permissive = TRUE;
    }
  else
    {
      OPT.permissive = FALSE;
    }

  log_hipopts();
}

