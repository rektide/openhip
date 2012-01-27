/*
 * Host Identity Protocol
 * Copyright (C) 2006 the Boeing Company
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  dns.h
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 * Definitions for DNS headers.
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

