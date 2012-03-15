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
 *  \file  hip_mr.h
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *		Orlie Brewer, <orlie.t.brewer@boeing.com>
 *
 *  \brief  Mobile router data types
 */

#ifndef _HIP_MR_H_
#define _HIP_MR_H_

/*
 * Mobile router registration extension
 */
typedef enum {
  CANCELLED = 0,
  RESPONSE_SENT,
  TIMED_OUT       /* XXX unused */
} MR_STATES;

typedef struct _hip_proxy_ticket {
  __u8 hmac_key[20];
  __u16 hmac_key_index;
  __u16 transform_type;
  __u16 action;
  __u16 lifetime;
  __u8 hmac[20];
} hip_proxy_ticket;

typedef struct _hip_spi_nat {
  hip_hit peer_hit;
  struct sockaddr_storage peer_addr;
  struct sockaddr_storage peer_ipv4_addr;
  struct sockaddr_storage peer_ipv6_addr;
  struct sockaddr_storage last_out_addr;
  struct sockaddr_storage rvs_addr;
  int use_rvs;
  __u32 private_spi;
  __u32 public_spi;
  __u32 peer_spi;
  hip_proxy_ticket ticket;
  struct hip_packet_entry rexmt_cache;
  struct _hip_spi_nat *next;
} hip_spi_nat;

typedef struct _hip_mr_client {
  hip_hit mn_hit;
  struct sockaddr_storage mn_addr;
  MR_STATES state;
  hip_spi_nat *spi_nats;
} hip_mr_client;

struct ip_esp_hdr {
  __u32 spi;
  __u32 seq_no;
  __u8 enc_data[0];
};

#endif /* _HIP_MR_H_*/


