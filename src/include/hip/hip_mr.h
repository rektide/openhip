/*
 * Host Identity Protocol
 * Copyright (C) 2009-2012 the Boeing Company
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
 * \file hip_mr.h
 *
 *  Authors:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *		Orlie Brewer, <orlie.t.brewer@boeing.com>
 *
 * \brief Mobile router data types
 */

#ifndef _HIP_MR_H_
#define _HIP_MR_H_

/*
 * Mobile router registration extension
 */
typedef enum {
	CANCELLED = 0,
	RESPONSE_SENT,
	TIMED_OUT /* XXX unused */
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


