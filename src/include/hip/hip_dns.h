/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2006-2012 the Boeing Company
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
 *  \file  hip_dns.h
 *
 *  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Definitions for DNS headers.
 *
 */
#ifndef _HIP_DNS_H_
#define _HIP_DNS_H_

/* DNS packet structures */
struct dns_hdr {
  __u16 transaction_id;
  __u16 flags;
  __u16 question_count;
  __u16 answer_count;
  __u16 namesrvr_count;
  __u16 additional_count;
#ifdef __WIN32__
};
#else
} __attribute__ ((packed));
#endif

#define HIP_RR_TYPE 55
#define HIP_RR_PKALG_DSA 1
#define HIP_RR_PKALG_RSA 2

#define DNS_FLAG_MASK_STDQUERY  0x0001
#define DNS_FLAG_AUTHORITATIVE  0x0400
#define DNS_FLAG_ANSWER         0x8000
#define DNS_FLAG_NXDOMAIN       0x03
#define DNS_QTYPE_CLASS_IN      1
#define DNS_DEFAULT_TTL         3600
#ifndef DNS_TYPE_A /* also defined in WinDNS.h */
#define DNS_TYPE_A              1
#define DNS_TYPE_PTR            12
#endif
#define DNS_TYPE_NXDOMAIN       -1 /* (not a real DNS answer type) */

struct dns_ans_hdr {
  __u16 ans_name;
  __u16 ans_type;
  __u16 ans_class;
  __u32 ans_ttl;
  __u16 ans_len;
#ifdef __WIN32__
};
#else
} __attribute__ ((packed));
#endif

#endif /* _HIP_DNS_H_ */

