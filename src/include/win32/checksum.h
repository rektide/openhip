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
 *  \file  win32/checksum.h
 *
 *  \authors	Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Checksum routines.
 *
 */

#ifndef _CHECKSUM_H
#define _CHECKSUM_H

#ifndef __WIN32__
#include <asm/types.h>
#include <endian.h>
#include <netinet/in.h>
#else
#include <win32/types.h>
#include <ws2tcpip.h>
#endif /* __WIN32__ */

#ifdef __WIN32__
/* Windows' ws2tcpip.h has struct in6_addr with __u8 and __u16 members,
 * but no __u32 as we need here for accumulation.
 */
struct my_in6_addr {
  __u32 s6_addr32[4];
};
#endif

static __inline unsigned short ip_fast_csum(unsigned char * iph,
                                            unsigned int ihl)
{
  __u16 checksum;
  unsigned long sum = 0;
  int count = ihl * 4;
  unsigned short *p = (unsigned short *)iph;

  /*
   * this checksum algorithm can be found
   * in RFC 1071 section 4.1
   */

  /* one's complement sum 16-bit words of data */
  while (count > 1)
    {
      sum += *p++;
      count -= 2;
    }
  /* add left-over byte, if any */
  if (count > 0)
    {
      sum += (unsigned char)*p;
    }

  /*  Fold 32-bit sum to 16 bits */
  while (sum >> 16)
    {
      sum = (sum & 0xffff) + (sum >> 16);
    }
  /* take the one's complement of the sum */
  checksum = (__u16)(~sum);

  return(checksum);
}

static __inline unsigned int csum_fold(unsigned int sum)
{
  /*  Fold 32-bit sum to 16 bits */
  while (sum >> 16)
    {
      sum = (sum & 0xffff) + (sum >> 16);
    }
  /* take the one's complement of the sum */
  return((__u16) ~sum);
}

static __inline unsigned int csum_add(unsigned int csum, unsigned int addend);
static __inline unsigned long csum_tcpudp_nofold(unsigned long saddr,
                                                 unsigned long daddr,
                                                 unsigned short len,
                                                 unsigned short proto,
                                                 unsigned int sum)
{
  sum = csum_add(sum, saddr);
  sum = csum_add(sum, daddr);
  sum = csum_add(sum, (__u32)len);
  sum = csum_add(sum, (__u32)proto);
  return(sum);
}

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
#ifdef __WIN32__
static __inline unsigned short int csum_tcpudp_magic(unsigned long saddr,
                                                     unsigned long daddr,
                                                     unsigned short len,
                                                     unsigned short proto,
                                                     unsigned int sum)
#else
static inline unsigned short int csum_tcpudp_magic(unsigned long saddr,
                                                   unsigned long daddr,
                                                   unsigned short len,
                                                   unsigned short proto,
                                                   unsigned int sum)
#endif
{
  return(csum_fold(csum_tcpudp_nofold(saddr,daddr,len,proto,sum)));
}

/*
 * the following inlines are from linux/include/net/checksum.h
 */

static __inline unsigned int csum_add(unsigned int csum, unsigned int addend)
{
  csum += addend;
  return(csum + (csum < addend));
}

static __inline unsigned int csum_sub(unsigned int csum, unsigned int addend)
{
  return(csum_add(csum, ~addend));
}

/*
 * HIP checksum = tcp checksum + hitMagic - csum(saddr,daddr)
 */
static __inline unsigned short csum_tcpudp_hip_nofold(unsigned long saddr,
                                                      unsigned long daddr,
                                                      unsigned short sum,
                                                      unsigned short hitMagic)
{
  /* sum is assumed to be the folded complement, so get the sum back */
  unsigned short ret = ~sum;

  ret = ~csum_fold(csum_add(ret, hitMagic));
  ret = csum_fold(csum_sub(ret,~csum_fold(csum_add(saddr,daddr))));

  return(ret);
}

static __inline unsigned short csum_hip_revert(unsigned long saddr,
                                               unsigned long daddr,
                                               unsigned short sum,
                                               unsigned short hitMagic)
{
  /* sum is assumed to be the folded complement, so get the sum back */
  unsigned short ret = ~sum;

  ret = ~csum_fold(csum_sub(ret, hitMagic));
  ret = csum_fold(csum_add(ret,~csum_fold(csum_add(saddr,daddr))));
  return(ret);
}

/*
 * HIP checksum = tcp checksum + hitMagic - csum(saddr,daddr)
 */
#ifdef __WIN32__
static __inline unsigned short csum_tcpudp_hip_nofold6(struct in6_addr *saddr1,
                                                       struct in6_addr *daddr1,
                                                       unsigned short sum,
                                                       unsigned short hitMagic)
{
  int carry;
  unsigned int csum;
  /* sum is assumed to be the folded complement, so get the sum back */
  unsigned short ret = ~sum;

  /* Re-cast the struct since Windows has no 32-bit struct member. */
  struct my_in6_addr *saddr = (struct my_in6_addr*)saddr1;
  struct my_in6_addr *daddr = (struct my_in6_addr*)daddr1;

  /* First, sum saddr and daddr as done in csum_ipv6_magic() */
  csum = saddr->s6_addr32[0];
  carry = (csum < saddr->s6_addr32[0]);
  csum += carry;

  csum += saddr->s6_addr32[1];
  carry = (csum < saddr->s6_addr32[1]);
  csum += carry;

  csum += saddr->s6_addr32[2];
  carry = (csum < saddr->s6_addr32[2]);
  csum += carry;

  csum += saddr->s6_addr32[3];
  carry = (csum < saddr->s6_addr32[3]);
  csum += carry;

  csum += daddr->s6_addr32[0];
  carry = (csum < daddr->s6_addr32[0]);
  csum += carry;

  csum += daddr->s6_addr32[1];
  carry = (csum < daddr->s6_addr32[1]);
  csum += carry;

  csum += daddr->s6_addr32[2];
  carry = (csum < daddr->s6_addr32[2]);
  csum += carry;

  csum += daddr->s6_addr32[3];
  carry = (csum < daddr->s6_addr32[3]);
  csum += carry;

  /* Next, add in the hitMagic and subtract saddr+daddr */
  ret = ~csum_fold(csum_add(ret, hitMagic));
  ret = csum_fold(csum_sub(ret,~csum_fold(csum)));

  return(ret);

}

#else

static inline unsigned short csum_tcpudp_hip_nofold6(struct in6_addr *saddr,
                                                     struct in6_addr *daddr,
                                                     unsigned short sum,
                                                     unsigned short hitMagic)
{
  int carry;
  unsigned int csum;
  /* sum is assumed to be the folded complement, so get the sum back */
  unsigned short ret = ~sum;

  /* First, sum saddr and daddr as done in csum_ipv6_magic() */
  csum = saddr->s6_addr32[0];
  carry = (csum < saddr->s6_addr32[0]);
  csum += carry;

  csum += saddr->s6_addr32[1];
  carry = (csum < saddr->s6_addr32[1]);
  csum += carry;

  csum += saddr->s6_addr32[2];
  carry = (csum < saddr->s6_addr32[2]);
  csum += carry;

  csum += saddr->s6_addr32[3];
  carry = (csum < saddr->s6_addr32[3]);
  csum += carry;

  csum += daddr->s6_addr32[0];
  carry = (csum < daddr->s6_addr32[0]);
  csum += carry;

  csum += daddr->s6_addr32[1];
  carry = (csum < daddr->s6_addr32[1]);
  csum += carry;

  csum += daddr->s6_addr32[2];
  carry = (csum < daddr->s6_addr32[2]);
  csum += carry;

  csum += daddr->s6_addr32[3];
  carry = (csum < daddr->s6_addr32[3]);
  csum += carry;

  /* Next, add in the hitMagic and subtract saddr+daddr */
  ret = ~csum_fold(csum_add(ret, hitMagic));
  ret = csum_fold(csum_sub(ret,~csum_fold(csum)));

  return(ret);
}

#endif

#ifdef __WIN32__
static __inline unsigned short csum_hip_revert6(struct in6_addr *saddr1,
                                                struct in6_addr *daddr1,
                                                unsigned short sum,
                                                unsigned short hitMagic)
{
  int carry;
  unsigned int csum;
  /* sum is assumed to be the folded complement, so get the sum back */
  unsigned short ret = ~sum;

  /* Re-cast the struct since Windows has no 32-bit struct member. */
  struct my_in6_addr *saddr = (struct my_in6_addr*)saddr1;
  struct my_in6_addr *daddr = (struct my_in6_addr*)daddr1;

  /* First, sum saddr and daddr as done in csum_ipv6_magic() */
  csum = saddr->s6_addr32[0];
  carry = (csum < saddr->s6_addr32[0]);
  csum += carry;

  csum += saddr->s6_addr32[1];
  carry = (csum < saddr->s6_addr32[1]);
  csum += carry;

  csum += saddr->s6_addr32[2];
  carry = (csum < saddr->s6_addr32[2]);
  csum += carry;

  csum += saddr->s6_addr32[3];
  carry = (csum < saddr->s6_addr32[3]);
  csum += carry;

  csum += daddr->s6_addr32[0];
  carry = (csum < daddr->s6_addr32[0]);
  csum += carry;

  csum += daddr->s6_addr32[1];
  carry = (csum < daddr->s6_addr32[1]);
  csum += carry;

  csum += daddr->s6_addr32[2];
  carry = (csum < daddr->s6_addr32[2]);
  csum += carry;

  csum += daddr->s6_addr32[3];
  carry = (csum < daddr->s6_addr32[3]);
  csum += carry;

  /* Next, subtract hitMagic and add saddr+daddr */
  ret = ~csum_fold(csum_sub(ret, hitMagic));
  ret = csum_fold(csum_add(ret,~csum_fold(csum)));
  return(ret);
}

#else
static inline unsigned short csum_hip_revert6(struct in6_addr *saddr,
                                              struct in6_addr *daddr,
                                              unsigned short sum,
                                              unsigned short hitMagic)
{
  int carry;
  unsigned int csum;
  /* sum is assumed to be the folded complement, so get the sum back */
  unsigned short ret = ~sum;

  /* First, sum saddr and daddr as done in csum_ipv6_magic() */
  csum = saddr->s6_addr32[0];
  carry = (csum < saddr->s6_addr32[0]);
  csum += carry;

  csum += saddr->s6_addr32[1];
  carry = (csum < saddr->s6_addr32[1]);
  csum += carry;

  csum += saddr->s6_addr32[2];
  carry = (csum < saddr->s6_addr32[2]);
  csum += carry;

  csum += saddr->s6_addr32[3];
  carry = (csum < saddr->s6_addr32[3]);
  csum += carry;

  csum += daddr->s6_addr32[0];
  carry = (csum < daddr->s6_addr32[0]);
  csum += carry;

  csum += daddr->s6_addr32[1];
  carry = (csum < daddr->s6_addr32[1]);
  csum += carry;

  csum += daddr->s6_addr32[2];
  carry = (csum < daddr->s6_addr32[2]);
  csum += carry;

  csum += daddr->s6_addr32[3];
  carry = (csum < daddr->s6_addr32[3]);
  csum += carry;

  /* Next, subtract hitMagic and add saddr+daddr */
  ret = ~csum_fold(csum_sub(ret, hitMagic));
  ret = csum_fold(csum_add(ret,~csum_fold(csum)));
  return(ret);
}

#endif

#endif
