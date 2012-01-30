/*
 * Host Identity Protocol
 * Copyright (C) 2004-2009 the Boeing Company
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
 *  hip_endbox.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *           Orlie Brewer <orlie.t.brewer@boeing.com>
 *           Jeff Meegan, <jeff.r.meegan@boeing.com>
 *
 * HIP Virtual Private LAN Service (VPLS) specific functions.
 *
 */
#include <stdio.h>              /* printf() */
#include <sys/stat.h>
#include <unistd.h>             /* write() */
#include <pthread.h>            /* pthread_exit() */
#include <sys/time.h>           /* gettimeofday() */
#include <sys/errno.h>          /* errno, etc */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/ip6.h>        /* struct ip6_hdr */
#include <netinet/icmp6.h>      /* struct icmp6_hdr */
#include <netinet/tcp.h>        /* struct tcphdr */
#include <netinet/udp.h>        /* struct udphdr */
#include <arpa/inet.h>
#include <linux/types.h>
#include <string.h>             /* memset, etc */
#include <openssl/hmac.h>       /* HMAC algorithms */
#include <openssl/sha.h>        /* SHA1 algorithms */
#include <openssl/des.h>        /* 3DES algorithms */
#include <openssl/rand.h>       /* RAND_bytes() */
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_usermode.h>
#include <hip/hip_sadb.h>
#include <hip/hip_globals.h>
#include <win32/checksum.h>

#ifdef HIP_VPLS
#include <utime.h>
#include <netinet/ether.h>
#include <hip/hip_cfg_api.h>
#include <hip/endbox_utils.h>
#endif /* HIP_VPLS */

struct eb_hello {
	hip_hit hit;
	__u32 time;
};

extern int tapfd;

/* Functions from hip_esp.c */

void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type);

/* File globals */

static int no_multicast = FALSE;
static int endbox_hello_time = 0;
static time_t last_hello_time = 0;

/* Functions */

void endbox_init()
{
	return;
}

/* Determine if this packet is from one of our legacy nodes to an allowed
 * remote legacy node.
 */
int is_valid_packet(__u32 src, __u32 dst)
{
	int rc;
	struct sockaddr_storage host_ss;
	struct sockaddr_storage eb_ss;
	struct sockaddr *host_p;
	struct sockaddr *eb_p;
	hip_hit hit1, hit2;
	hi_node *my_host_id;
	char ip[INET6_ADDRSTRLEN];

	memset(&host_ss, 0, sizeof(struct sockaddr_storage));
	memset(&eb_ss, 0, sizeof(struct sockaddr_storage));
	host_p = (struct sockaddr*)&host_ss;
	eb_p = (struct sockaddr*)&eb_ss;

	/* Is this source address a legacy node? */

	host_p->sa_family = AF_INET;
	((struct sockaddr_in *)host_p)->sin_addr.s_addr = src;
	eb_p->sa_family = AF_INET6;
	rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
	if (rc) {
		addr_to_str(host_p, (__u8 *)ip, INET6_ADDRSTRLEN);
		log_(NORM, "is_valid_packet: invalid source addr %s\n", ip);
		return(0);
	}

	/* Is this legacy node one of ours? */

	memcpy(hit1, SA2IP(eb_p), HIT_SIZE);
	my_host_id = get_preferred_hi(my_hi_head);
	if (compare_hits(my_host_id->hit, hit1) != 0) {
		return(0);
	}

	/* If destination is zero, it is a multicast packet */

	if (!dst) {
		return(1);
	}

	/* Is this destination address a legacy node? */

	host_p->sa_family = AF_INET;
	((struct sockaddr_in *)host_p)->sin_addr.s_addr = dst;
	eb_p->sa_family = AF_INET6;
	rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
	if (rc) {
		addr_to_str(host_p, (__u8 *)ip, INET6_ADDRSTRLEN);
		log_(NORM, "is_valid_packet: invalid dest addr %s\n", ip);
		return(0);
	}

	/* If the destination is also one of ours, ignore the packet */

	memcpy(hit2, SA2IP(eb_p), HIT_SIZE);
	if (compare_hits(my_host_id->hit, hit2) == 0) {
		return(0);
	}

	/* Are we allowed to send to remote endbox? */

	rc = hipcfg_allowed_peers(hit1, hit2);
	if (!rc) {
		log_(NORM, "peer connection not allowed hit1: %02x%02x, hit2: "
		     "%02x%02x\n", hit1[HIT_SIZE - 2], hit1[HIT_SIZE - 1],
		     hit2[HIT_SIZE - 2], hit2[HIT_SIZE - 1]);
	}
	return(rc);
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
	__u64 src_mac;
	int outlen = 0;
	hi_node *my_host_id;
	struct eb_hello *endbox_hello;

	src_mac = (__u64)g_tap_lsi << 16;
	add_eth_header(out, src_mac, dst_mac, 0x88b5);

	endbox_hello = (struct eb_hello *) &out[14];
	my_host_id = get_preferred_hi(my_hi_head);
	memcpy(endbox_hello->hit, my_host_id->hit, sizeof(hip_hit));
	endbox_hello->time = htonl(HCNF.endbox_hello_time);

	outlen = sizeof(struct eth_hdr) + sizeof(struct arp_hdr) + 20;

	if (write(tapfd, out, outlen) < 0) {
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

	if (compare_hits(my_host_id->hit, endbox_hello->hit) > 0) {
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
	    (*now_time - last_hello_time > 2 * endbox_hello_time)) {
		no_multicast = FALSE;
	}
}

/*
 * Called from hip_esp_output()
 */
int endbox_ipv4_packet_check(struct ip *iph, struct sockaddr *lsi,
                             int *packet_count)
{
	struct sockaddr_storage legacy_host_ss, eb_ss;
	struct sockaddr *legacy_host_p, *eb_p;

	if (!IN_MULTICAST(ntohl(iph->ip_dst.s_addr)) &&
	    (((ntohl(iph->ip_dst.s_addr)) & 0x000000FF) != 0x000000FF)) {
		if (!is_valid_packet(iph->ip_src.s_addr, iph->ip_dst.s_addr)) {
			return(-1);
		}

		legacy_host_p = SA(&legacy_host_ss);
		eb_p = SA(&eb_ss);
		legacy_host_p->sa_family = AF_INET;
		LSI4(legacy_host_p) = iph->ip_dst.s_addr;
		eb_p->sa_family = AF_INET;
		if (!hipcfg_getEndboxByLegacyNode(legacy_host_p, eb_p)) {
			lsi->sa_family = AF_INET;
			LSI4(lsi) = ntohl(LSI4(eb_p));
		}
		(*packet_count)++;
	} else {
		if (!is_valid_packet(iph->ip_src.s_addr, 0)) {
			return(-1);
		}
		(*packet_count)++;
	}
	return(0);
}

/*
 * Called from hip_esp_output()
 */
int endbox_arp_packet_check(struct arp_hdr *arph, struct sockaddr *lsi,
                            int *packet_count)
{
	struct arp_req_data *arp_req;
	struct sockaddr_storage legacy_host_ss, eb_ss;
	struct sockaddr *legacy_host_p, *eb_p;

	if ((ntohs(arph->ar_hrd) == 0x01) &&     /* Ethernet */
	    (ntohs(arph->ar_pro) == 0x0800) &&   /* IPv4 */
	    (arph->ar_hln == 6) && (arph->ar_pln == 4)) {
		arp_req = (struct arp_req_data*)(arph + 1);
		if (!is_valid_packet(arp_req->src_ip, arp_req->dst_ip)) {
			return(-1);
		}
		legacy_host_p = SA(&legacy_host_ss);
		eb_p = SA(&eb_ss);
		legacy_host_p->sa_family = AF_INET;
		LSI4(legacy_host_p) = arp_req->dst_ip;
		eb_p->sa_family = AF_INET;
		if (!hipcfg_getEndboxByLegacyNode(legacy_host_p, eb_p)) {
			lsi->sa_family = AF_INET;
			LSI4(lsi) = ntohl(LSI4(eb_p));
		}
		(*packet_count)++;
		return(0);
	} else {
		return(-1);
	}
	return(0);
}

/*
 * Called from hip_esp_input()/output() while loop
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

	if (*now_time - *last_time > 60) {
		printf("hip_esp_%s() heartbeat (%d packets)\n",
		       name, *packet_count);
		*last_time = *now_time;
		*packet_count = 0;
		if (touchHeartbeat) {
			utime(filename, NULL);
		} else {
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
	struct ip* iph = (struct ip*) &data[offset + sizeof(struct eth_hdr)];

	if (IN_MULTICAST((ntohl(iph->ip_dst.s_addr))) && no_multicast) {
		return;
	} else if (write(tapfd, &data[offset], len) < 0) {
		printf("hip_esp_input() write() failed.\n");
	}
}

