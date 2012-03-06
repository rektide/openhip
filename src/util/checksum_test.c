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
 *  \file  checksum_test.c
 *
 *  \authors	Tom Henderson (thomas.r.henderson@boeing.com)
 *
 *  \brief  Checksum test program.
 *
 * This file is outside of the normal build process and must be compiled
 * by hand using gcc.
 * 
 * By default, it will produce a checksum value of 446 corresponding to
 * RFC 5201, Appendix C.1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asm/types.h>

#define HIP_OVER_UDP 0  /* set to 1 to use alternate HIP/UDP format */
#define IPV6 1          /* set HIP_OVER_UDP to 0 */

#define IPPROTO_NONE 59 /* used in HIP next header */
#define H_PROTO_HIP 139
#define HIP_I1 1
#define HIP_VERSION 1
#define IPV4_PSEUDO_SIZE 12 /* HIP is 12 bytes into IPv4 pseudo structure */
#define IPV6_PSEUDO_SIZE 40
#define HIT_SIZE 16

#define HIT_SNDR "0x20010010000000000000000000000001"
#define HIT_RCVR "0x20010010000000000000000000000002"
#define IPV4_SRC "0xc0a80001" /* 192.168.0.1 */
#define IPV4_DST "0xc0a80002" /* 192.168.0.2 */

/*
 * IPv4 pseudoheader format
 *       0      7 8     15 16    23 24    31
 **+--------+--------+--------+--------+
 |          source address           |
 ||+--------+--------+--------+--------+
 |        destination address        |
 ||+--------+--------+--------+--------+
 |  zero  |protocol|       length    |
 ||+--------+--------+--------+--------+
 |                                   |
 |       /                                   /
 |  <transport layer header/data>    |
 \                                   \
 |                                   |
 ||+--------+--------+--------+--------+
 |
 |  length is defined as the length of the
 |  <transport layer header/data>; in this case,
 |  it is the length of the whole HIP I1, in bytes
 */
/*
 * IPv6 pseudoheader format
 **+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 +                                                               +
 |                                                               |
 +                         Source Address                        +
 |                                                               |
 +                                                               +
 |                                                               |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 +                                                               +
 |                                                               |
 +                      Destination Address                      +
 |                                                               |
 +                                                               +
 |                                                               |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                   Upper-Layer Packet Length                   |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      zero                     |  Next Header  |
 ||+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |
 |  The Upper-Layer Packet Length in the pseudo-header is the
 |  length of the upper-layer header and data (e.g., TCP header
 |  plus TCP data).  Some upper-layer protocols carry their own
 |  length information (e.g., the Length field in the UDP header);
 |  for such protocols, that is the length used in the pseudo-
 |  header.  Other protocols (such as TCP) do not carry their own
 |  length information, in which case the length used in the
 |  pseudo-header is the Payload Length from the IPv6 header, minus
 |  the length of any extension headers present between the IPv6
 |  header and the upper-layer header.
 */


#if (IPV6)
typedef struct _pseudo_header
{
  unsigned char src_addr[16];
  unsigned char dst_addr[16];
  __u32 packet_length;
  char zero[3];
  __u8 next_hdr;
} pseudo_header;
#else
typedef struct _pseudo_header
{
  unsigned char src_addr[4];
  unsigned char dst_addr[4];
  __u8 zero;
  __u8 protocol;
  __u16 packet_length;
} pseudo_header;
#endif

typedef unsigned char hip_hit[16];

#if (HIP_OVER_UDP)
#define HIP_UDP_PORT 272
typedef struct _hiphdr {
  __u16 src_port;
  __u16 dst_port;
  __u16 len;
  __u16 checksum;
  __u16 control;            /* control                     */
  __u8 packet_type;         /* packet type                 */
  __u8 res : 4,version : 4;       /* version, reserved        */
  hip_hit hit_sndr;         /* Sender's Host Identity Tag  */
  hip_hit hit_rcvr;         /* Receiver's Host Identity Tag*/
  /* HIP TLV parameters follow ...  */
} hiphdr;
#else
typedef struct _hiphdr {
  __u8 next_hdr;                /* payload protocol            */
  __u8 payload_len;             /* payload length              */
  __u8 packet_type;             /* packet type                 */
  __u8 res : 4,version : 4;        /* version, reserved           */
  __u16 checksum;               /* checksum                    */
  __u16 control;                /* control                     */
  hip_hit hit_sndr;             /* Sender's Host Identity Tag  */
  hip_hit hit_rcvr;             /* Receiver's Host Identity Tag */
  /* HIP TLV parameters follow ...  */
} hiphdr;
#endif

static __u16 checksum_packet(char *, __u32, __u32);
static int hex_to_bin(char *, char *, int);

int main(int argc, char *argv[])
{
  int i;
  int checksummed_size;
  hiphdr *hiph;
  unsigned char buff[512];

  hip_hit hit_sndr;
  hip_hit hit_rcvr;
  __u32 ip_src;
  __u32 ip_dst;

  char hit_sndr_char[] = HIT_SNDR;
  char hit_rcvr_char[] = HIT_RCVR;
  char ip_src_char[] = IPV4_SRC;
  char ip_dst_char[] = IPV4_DST;

  hex_to_bin(hit_sndr_char, hit_sndr, 16);
  hex_to_bin(hit_rcvr_char, hit_rcvr, 16);
  hex_to_bin(ip_src_char, (char*) &ip_src, 4);
  hex_to_bin(ip_dst_char, (char*) &ip_dst, 4);

#if (HIP_OVER_UDP)
  /* build the HIP header for I1*/
  /* Leave 12 bytes for pseudoheader */
  hiph = (hiphdr*) &buff[IPV4_PSEUDO_SIZE];
  hiph->src_port = htons(HIP_UDP_PORT);
  hiph->dst_port = htons(HIP_UDP_PORT);
  hiph->len = htons(sizeof(hiphdr));
  hiph->checksum = 0;
  hiph->control = 0;
  hiph->packet_type = HIP_I1;
  hiph->version = HIP_VERSION;
  hiph->res = 1;
#else
  /* build the HIP header for I1*/
  /* Leave 12 bytes up front for pseudoheader */
#if (IPV6)
  hiph = (hiphdr*) &buff[IPV6_PSEUDO_SIZE];
#else
  hiph = (hiphdr*) &buff[IPV4_PSEUDO_SIZE];
#endif
  hiph->next_hdr = IPPROTO_NONE;
  hiph->payload_len = 4;       /* 2*sizeof(hip_hit)/8 */
  hiph->packet_type = HIP_I1;
  hiph->version = HIP_VERSION;
  hiph->res = 1;
  hiph->control = 0;
  hiph->checksum = 0;
#endif

  memcpy(hiph->hit_sndr, hit_sndr, HIT_SIZE);
  memcpy(hiph->hit_rcvr, hit_rcvr, HIT_SIZE);

  hiph->checksum = checksum_packet(&buff[0], ip_src, ip_dst);
  printf ("Checksum is decimal %d, in network byte order 0x%04x\n", ntohs(hiph->checksum), ntohs(hiph->checksum));

  /* Print out results */
#if (HIP_OVER_UDP)
  checksummed_size = sizeof(hiphdr) + IPV4_PSEUDO_SIZE;
  printf("IPv4 UDP I1 with pseudoheader (first 12 bytes)");
#else
#if (IPV6)
  checksummed_size = IPV6_PSEUDO_SIZE + ((hiph->payload_len + 1) * 8);
  printf("IPv6 I1 with pseudoheader (first 40 bytes)");
#else
  checksummed_size = IPV4_PSEUDO_SIZE + ((hiph->payload_len + 1) * 8);
  printf("IPv4 I1 with pseudoheader (first 12 bytes)");
#endif
#endif
  printf(" and corresponding checksum:\n\t");
  for (i = 0; i < checksummed_size; i++)
    {
      if ((i % 4 == 0) && (i != 0))
        {
          printf("\n\t");
        }
      printf("%02x", buff[i]);
    }
  printf("\n");
}

/*
 * function checksum_packet()
 *
 * Calculates the checksum of a HIP packet with pseudo-header
 * src and dst are assumed to be in network byte order already
 * data is assumed to point to start of pseudoheader
 */
static
__u16 checksum_packet(char *data, __u32 src, __u32 dst)
{
  __u16 checksum;
  int length;
  long sum = 0;
  int count;
  unsigned short *p;       /* 16-bit */
  hiphdr* hiph;
  pseudo_header* pseudoh;

  pseudoh = (pseudo_header*) &data[0];
  hiph = (hiphdr*) &data[IPV4_PSEUDO_SIZE];

#if (IPV6)
  hiph = (hiphdr*) &data[IPV6_PSEUDO_SIZE];
  memset(pseudoh, 0, sizeof(pseudo_header));
  memset(pseudoh->src_addr + 10, 0x00, 2);
  memset(pseudoh->dst_addr + 10, 0x00, 2);
  memcpy(pseudoh->src_addr + 12, &src, 4);
  memcpy(pseudoh->dst_addr + 12, &dst, 4);
  length = (hiph->payload_len + 1) * 8;
  pseudoh->packet_length = htonl(length);
  pseudoh->next_hdr = H_PROTO_HIP;
#else
  hiph = (hiphdr*) &data[IPV4_PSEUDO_SIZE];
  /* fill the IPv4-style pseudo-header (RFC 768)*/
  memset(pseudoh, 0, sizeof(pseudo_header));
  memcpy(pseudoh->src_addr, &src, 4);
  memcpy(pseudoh->dst_addr, &dst, 4);
  pseudoh->protocol = H_PROTO_HIP;
#if (HIP_OVER_UDP)
  length = ntohs(hiph->len);
  pseudoh->packet_length = hiph->len;       /* Already in network order */
#else
  length = (hiph->payload_len + 1) * 8;
  pseudoh->packet_length = htons(length);
#endif
#endif

  /*
   * this checksum algorithm can be found
   * in RFC 1071 section 4.1
   */

  /* one's complement sum 16-bit words of data */
#if (IPV6)
  count = length + IPV6_PSEUDO_SIZE;
#else
  count = length + IPV4_PSEUDO_SIZE;
#endif
  p = (unsigned short*) data;
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
  checksum = ~sum;

  return(checksum);
}

/*
 * Convert character string found in src to binary dst
 * - leaves in network byte order
 */
static
int hex_to_bin(char *src, char *dst, int dst_len)
{
  char hex[] = "0123456789abcdef";
  char hexcap[] = "0123456789ABCDEF";
  char *p, c;
  int src_len, total, i;
  unsigned char o;

  if ((!src) || (!dst))
    {
      return(-1);
    }
  src_len = strlen(src);
  if (dst_len > src_len)
    {
      return(-1);
    }

  /* chop any '0x' prefix */
  if ((src[0] == '0') && (src[1] == 'x'))
    {
      src += 2;
      src_len -= 2;
    }

  /* convert requested number of bytes from hex to binary */
  total = 0;
  for (i = 0; (i < src_len) && (total < dst_len); i += 2)
    {
      /* most significant nibble */
      c = src[i];
      /*
       * Normally would use tolower(), but have found problems
       * with dynamic linking and different glibc versions
       */
      if ((p = strchr(hex, c)) == NULL)
        {
          if ((p = strchr(hexcap, c)) == NULL)
            {
              continue;
            }
        }
      if (((p - hex) < 0) || ((p - hex) > 15))
        {
          fprintf(stderr, "Binary conversion failed %c\n",c);
          return(-1);
        }
      o = (p - hex) << 4;
      /* least significant nibble */
      c = src[i + 1];
      if ((p = strchr(hex, c)) == NULL)
        {
          if ((p = strchr(hexcap, c)) == NULL)
            {
              continue;
            }
        }
      if (((p - hex) < 0) || ((p - hex) > 15))
        {
          fprintf(stderr, "Binary conversion failed 2 %c", c);
          return(-1);
        }
      o += (p - hex);
      dst[total] = o;
      total++;
      if (total >= src_len)
        {
          total = dst_len;
        }
    }
  return(total);
}

