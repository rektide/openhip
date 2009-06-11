/*
 * Host Identity Protocol
 * Copyright (C) 2005-08 the Boeing Company
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
 *  hip_mr.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *           Orlie Brewer <orlie.t.brewer@boeing.com>
 * 
 * Mobile router SPINAT implemenation
 *
 */

#ifdef __WIN32__
#include <win32/types.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <io.h>
#else
#include <unistd.h>
#include <pthread.h>            /* phread_exit() */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/ip6.h>        /* struct ip6_hdr */
#include <netinet/icmp6.h>      /* struct icmp6_hdr */
#include <netinet/tcp.h>        /* struct tcphdr */
#include <netinet/udp.h>        /* struct udphdr */
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libipq.h>
#endif /* WIN32 */
#include <stdio.h>              /* printf() */
#include <string.h>             /* strerror() */
#include <errno.h>              /* errno */
#include <hip/hip_service.h>
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_globals.h>
#include <openssl/rand.h>	/* RAND_bytes() */

#define INET6_ADDRSTRLEN 46
#define BUFSIZE 2048

struct ip_esp_hdr {
	__u32 spi;
	__u32 seq_no;
	__u8 enc_data[0];
};

extern hip_mr_client hip_mr_client_table[MAX_MR_CLIENTS];
extern int max_hip_mr_clients;
extern int external_if_index;
extern int new_external_address;
extern pthread_mutex_t hip_mr_client_mutex;

static struct sockaddr_storage out_addr;

struct spi_table {
	__u32 private_spi;
	__u32 public_spi;
	hip_hit mn_hit;
	hip_hit peer_hit;
	struct sockaddr_storage mn_addr;
	struct sockaddr_storage peer_addr;
	struct spi_table *next;
};

int hip_send_proxy_update(struct sockaddr *newaddr, struct sockaddr *dstaddr,
			hip_hit *mn_hit, hip_hit *peer_hit,
			hip_proxy_ticket *ticket, __u32 spi);
int build_tlv_proxy_hmac(hip_proxy_ticket *ticket, __u8 *data, int location,
			int type);

/*
 *
 * function get_next_spinat()
 *
 * in:          none
 *
 * out:         returns next SPI value to use for SPINAT
 *
 * Obtains new random SPI for SPINAT, checks that it is not being used.
 * TODO: Should also check that it is not being used for mobile router SAs.
 */

__u32 get_next_spinat(void)
{
	int i;
	__u32 new_spi;
	hip_spi_nat *spi_nats;

retry_getspi:
	/* randomly select a new SPI */
	new_spi = 0;
	while (new_spi <= SPI_RESERVED) {
		RAND_bytes((__u8*)&new_spi, 4);
	}

	for (i = 0; i < max_hip_mr_clients; i++) {
		for (spi_nats = hip_mr_client_table[i].spi_nats; spi_nats;
		     spi_nats = spi_nats->next) {
			if (new_spi == spi_nats->public_spi)
				goto retry_getspi;
		}
	}
	return new_spi;
}

hip_mr_client *check_hits(hip_hit the_hit)
{
	int i;
	for (i = 0; i < max_hip_mr_clients; i++) {
		if (hits_equal(the_hit, hip_mr_client_table[i].mn_hit)) {
struct sockaddr *src = (struct sockaddr*)&hip_mr_client_table[i].mn_addr;
printf("This is for Mobile Router client %s\n", logaddr(src));
			return &hip_mr_client_table[i];
		}
	}
	return NULL;
}

void adjust_addrs(struct sockaddr_storage *s, struct sockaddr_storage *d,
		struct ip6_hdr *ip6h)
{
	struct sockaddr *src, *dst;

	src = (struct sockaddr *)s;
	dst = (struct sockaddr *)d;
	src->sa_family = AF_INET6;
	dst->sa_family = AF_INET6;
	memcpy(&ip6h->ip6_src, SA2IP(src), sizeof(struct in6_addr));
	memcpy(&ip6h->ip6_dst, SA2IP(dst), sizeof(struct in6_addr));

}

void process_I1(hip_mr_client *hip_mr_c, hiphdr *hiph,
		struct ip6_hdr *ip6h)
{
	struct sockaddr *dst;
	hip_spi_nat *spi_nats = hip_mr_c->spi_nats;
	while (spi_nats) {
		if (hits_equal(hiph->hit_rcvr, spi_nats->peer_hit)) {
			break;
		}
		spi_nats = spi_nats->next;
	}

	if (!spi_nats) {
		spi_nats = malloc(sizeof(hip_spi_nat));
		if (!spi_nats)
			return;
		memset(spi_nats, 0, sizeof(hip_spi_nat));
		spi_nats->next = hip_mr_c->spi_nats;
		hip_mr_c->spi_nats = spi_nats;
        	memcpy(spi_nats->peer_hit, hiph->hit_rcvr, sizeof(hip_hit));
	}

	spi_nats->private_spi = 0;
	spi_nats->public_spi = 0;
	dst = (struct sockaddr *)&spi_nats->peer_addr;
	dst->sa_family = AF_INET6;
	memcpy(SA2IP(dst), &ip6h->ip6_dst, SAIPLEN(dst));

	adjust_addrs(&out_addr, &spi_nats->peer_addr, ip6h);

	return;
}

void process_R1(hip_mr_client *hip_mr_c, hiphdr *hiph,
		struct ip6_hdr *ip6h)
{
	hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

	while (spi_nats) {
		if (hits_equal(hiph->hit_sndr, spi_nats->peer_hit)) {
			break;
		}
		spi_nats = spi_nats->next;
	}

	if (!spi_nats)
		return;

	adjust_addrs(&spi_nats->peer_addr, &hip_mr_c->mn_addr, ip6h);
}

__u32 process_I2(hip_mr_client *hip_mr_c, hiphdr *hiph,
		struct ip6_hdr *ip6h)
{
	int location = 0;
	__u8 *data = (__u8 *)hiph;
	int data_len;
	int type, length;
	tlv_head *tlv;
	tlv_esp_info *esp_info;

	hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

	while (spi_nats) {
		if (hits_equal(hiph->hit_rcvr, spi_nats->peer_hit)) {
			break;
		}
		spi_nats = spi_nats->next;
	}

	if (!spi_nats)
		return 0;

	data_len = (hiph->hdr_len+1) * 8;
	location += sizeof(hiphdr);

	while (location < data_len) {
		tlv = (tlv_head *) &data[location];
		type = ntohs(tlv->type);
		length = ntohs(tlv->length);
		if (type == PARAM_ESP_INFO) {
			esp_info = (tlv_esp_info *)tlv;
			spi_nats->private_spi = ntohl(esp_info->new_spi);
			spi_nats->public_spi = get_next_spinat();
printf("Private SPI 0x%x added\n", spi_nats->private_spi);
printf("Public SPI 0x%x added\n", spi_nats->public_spi);
			break;
		}
                location += tlv_length_to_parameter_length(length);
	}

	adjust_addrs(&out_addr, &spi_nats->peer_addr, ip6h);
	return spi_nats->public_spi;
}

void process_R2(hip_mr_client *hip_mr_c, hiphdr *hiph,
		struct ip6_hdr *ip6h)
{
	int location = 0;
	__u8 *data = (__u8 *)hiph;
	int data_len;
	int type, length;
	tlv_head *tlv;
	tlv_esp_info *esp_info;

	hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

	while (spi_nats) {
		if (hits_equal(hiph->hit_sndr, spi_nats->peer_hit)) {
			break;
		}
		spi_nats = spi_nats->next;
	}

	if (!spi_nats)
		return;

	data_len = (hiph->hdr_len+1) * 8;
	location += sizeof(hiphdr);

	while (location < data_len) {
		tlv = (tlv_head *) &data[location];
		type = ntohs(tlv->type);
		length = ntohs(tlv->length);
		if (type == PARAM_ESP_INFO) {
			esp_info = (tlv_esp_info *)tlv;
			spi_nats->peer_spi = ntohl(esp_info->new_spi);
printf("Peer SPI 0x%x added\n", spi_nats->peer_spi);
			break;
		}
                location += tlv_length_to_parameter_length(length);
	}

	adjust_addrs(&spi_nats->peer_addr, &hip_mr_c->mn_addr, ip6h);
}

void process_CLOSE(hip_mr_client *hip_mr_c, hiphdr *hiph,
		struct ip6_hdr *ip6h, int packet_type)
{
	int in_bound;
	hip_hit *peer_hit;
	hip_spi_nat *spi_nats = hip_mr_c->spi_nats;

	if (hits_equal(hiph->hit_sndr, hip_mr_c->mn_hit)) {
		in_bound = 0;
		peer_hit = &(hiph->hit_rcvr);
	} else {
		in_bound = 1;
		peer_hit = &(hiph->hit_sndr);
	}

	while (spi_nats) {
		if (hits_equal(*peer_hit, spi_nats->peer_hit)) {
			break;
		}
		spi_nats = spi_nats->next;
	}

	if (!spi_nats)
		return;

	if (in_bound) {
		adjust_addrs(&spi_nats->peer_addr, &hip_mr_c->mn_addr, ip6h);
	} else { 
		adjust_addrs(&out_addr, &spi_nats->peer_addr, ip6h);
	}

	/* Remove state for SA */

	if (packet_type == CLOSE_ACK) {
		;
	}

}

unsigned char *add_tlv_spi_nat(unsigned char *payload, size_t data_len,
			size_t *new_len, __u32 new_spi)
{
	struct ip6_hdr *ip6h = (struct ip6_hdr*)payload;
	hiphdr *hiph = (hiphdr *)(payload + sizeof(struct ip6_hdr));
	tlv_esp_info *esp_info;
	size_t len = data_len + sizeof(tlv_esp_info);
	int hiphdr_len;
	unsigned char *buff = malloc(len);

	if (!buff) {
		return buff;
	}

	memcpy(buff, payload, data_len);
	ip6h = (struct ip6_hdr*)buff;
	hiph = (hiphdr *)(buff + sizeof(struct ip6_hdr));
	hiphdr_len = (hiph->hdr_len+1) * 8;

        /* ESP INFO */
        esp_info = (tlv_esp_info*) &buff[data_len];
        esp_info->type = htons(PARAM_ESP_INFO_NOSIG);
        esp_info->length = htons(sizeof(tlv_esp_info) - 4);
        esp_info->reserved = 0;
        esp_info->keymat_index = 0;
        esp_info->old_spi = 0;
        esp_info->new_spi = htonl(new_spi);

        /* finish with new length */

	hiphdr_len += sizeof(tlv_esp_info);
        ip6h->ip6_plen = htons((unsigned short)hiphdr_len);
        hiph->hdr_len = (hiphdr_len/8) - 1;

printf("Adding SPI_NAT of 0x%x\n", new_spi);
	*new_len = len;
	return buff;
}

void generate_hip_updates(struct sockaddr *out)
{
	int i;

	for (i = 0; i < max_hip_mr_clients; i++) {
		if (RESPONSE_SENT == hip_mr_client_table[i].state) {
			hip_spi_nat *spi_nats;

struct sockaddr *src = (struct sockaddr*)&hip_mr_client_table[i].mn_addr;
printf("Doing UPDATE for Mobile Router client %s\n", logaddr(src));

			for (spi_nats = hip_mr_client_table[i].spi_nats;
				spi_nats; spi_nats = spi_nats->next) {

				struct sockaddr *dst =
					(struct sockaddr*)&spi_nats->peer_addr;
				hip_send_proxy_update(out, dst,
					&hip_mr_client_table[i].mn_hit,
					&spi_nats->peer_hit,
					&spi_nats->ticket,
					spi_nats->public_spi);
			}
		}
	}
}

void check_address_change(void)
{
	sockaddr_list *l;
	struct sockaddr *out = (struct sockaddr *)&out_addr;

	if (!new_external_address)
		return;

	for (l = my_addr_head; l; l=l->next) {
		if (l->if_index == external_if_index  &&
		    l->addr.ss_family == AF_INET6) {
			struct in6_addr ip6_addr, ip6_old_addr;
			memcpy(&ip6_addr, SA2IP((struct sockaddr *)&l->addr),
				sizeof(struct in6_addr));
			if (!IN6_IS_ADDR_LINKLOCAL(&ip6_addr)  &&
			    !IN6_IS_ADDR_LOOPBACK(&ip6_addr)   &&
			    !IN6_IS_ADDR_SITELOCAL(&ip6_addr)) {
				memcpy(&ip6_old_addr, SA2IP(out),
					sizeof(struct in6_addr));
				if (IN6_ARE_ADDR_EQUAL(&ip6_addr,
					&ip6_old_addr))
						return;
				out->sa_family = AF_INET6;
				memcpy(SA2IP(out),
					SA2IP((struct sockaddr *)&l->addr),
					SAIPLEN(out));
				pthread_mutex_lock(&hip_mr_client_mutex);
				new_external_address = FALSE;
printf("Need to generate UPDATE packet for new address %s\n", logaddr(out));
				generate_hip_updates(out);
				pthread_mutex_unlock(&hip_mr_client_mutex);
				break;
			}

		}
	}

}

unsigned char *check_hip_packet(unsigned char *payload, size_t data_len,
			size_t *new_len)
{
	struct sockaddr *src, *dst;
	struct sockaddr_storage src_addr, dst_addr;
	struct ip6_hdr *ip6h = (struct ip6_hdr*)payload;
	hiphdr *hiph = (hiphdr *)(payload + sizeof(struct ip6_hdr));
	hip_mr_client *hip_mr_c;
	int length = (hiph->hdr_len+1) * 8;
	unsigned char *buff = NULL;

	switch(hiph->packet_type) {
		case HIP_I1:
			pthread_mutex_lock(&hip_mr_client_mutex);
			hip_mr_c = check_hits(hiph->hit_sndr);
			if (hip_mr_c) {
				process_I1(hip_mr_c, hiph, ip6h);
			}
			pthread_mutex_unlock(&hip_mr_client_mutex);
			printf("HIP I1 packet of length %d\n", length);
			break;
		case HIP_R1:
			pthread_mutex_lock(&hip_mr_client_mutex);
			hip_mr_c = check_hits(hiph->hit_rcvr);
			if (hip_mr_c) {
				process_R1(hip_mr_c, hiph, ip6h);
			}
			pthread_mutex_unlock(&hip_mr_client_mutex);
			printf("HIP R1 packet of length %d\n", length);
			break;
		case HIP_I2:
			pthread_mutex_lock(&hip_mr_client_mutex);
			hip_mr_c = check_hits(hiph->hit_sndr);
			if (hip_mr_c) {
				__u32 new_spi;
				new_spi = process_I2(hip_mr_c, hiph, ip6h);
				if (new_spi) {
					buff = add_tlv_spi_nat(payload,
						data_len, new_len, new_spi);
				}
			}
			pthread_mutex_unlock(&hip_mr_client_mutex);
			printf("HIP I2 packet of length %d\n", length);
			break;
		case HIP_R2:
			pthread_mutex_lock(&hip_mr_client_mutex);
			hip_mr_c = check_hits(hiph->hit_rcvr);
			if (hip_mr_c) {
				process_R2(hip_mr_c, hiph, ip6h);
			}
			pthread_mutex_unlock(&hip_mr_client_mutex);
			printf("HIP R2 packet of length %d\n", length);
			break;
		case CLOSE:
		case CLOSE_ACK:
			pthread_mutex_lock(&hip_mr_client_mutex);
			if ((hip_mr_c = check_hits(hiph->hit_rcvr))  ||
			    (hip_mr_c = check_hits(hiph->hit_sndr))) {
				process_CLOSE(hip_mr_c, hiph, ip6h,
					hiph->packet_type);
			}
			pthread_mutex_unlock(&hip_mr_client_mutex);
			if (hiph->packet_type == CLOSE)
				printf("HIP CLOSE ");
			else
				printf("HIP CLOSE ACK ");
			printf("packet of length %d\n", length);
			break;
	}

        /* finish with new checksum */

	if (buff) {
		ip6h = (struct ip6_hdr*)buff;
		hiph = (hiphdr *)(buff + sizeof(struct ip6_hdr));
	}
	src = (struct sockaddr *)&src_addr;
	src->sa_family = AF_INET6;
	dst = (struct sockaddr *)&dst_addr;
	dst->sa_family = AF_INET6;
	memcpy(SA2IP(src), &(ip6h->ip6_src), SAIPLEN(src));
	memcpy(SA2IP(dst), &(ip6h->ip6_dst), SAIPLEN(dst));
        hiph->checksum = 0;
        hiph->checksum = checksum_packet((__u8 *)hiph, src, dst);

	printf("  from HIT ");
	print_hex(hiph->hit_sndr, HIT_SIZE);
	printf("  to HIT ");
	print_hex(hiph->hit_rcvr, HIT_SIZE);
	printf("\n");
	return buff;
}

void check_esp_packet(struct ip6_hdr *ip6h, struct ip_esp_hdr *esph)
{
	int i, inbound = 0;
	struct sockaddr *out, *addr;
	struct in6_addr ip6_dst, ip6_src;

	printf("ESP packet with SPI 0x%x\n", ntohl(esph->spi));

	out = (struct sockaddr *)&out_addr;
	out->sa_family = AF_INET6;
	memcpy(&ip6_dst, SA2IP(out), sizeof(struct in6_addr));
	if (IN6_ARE_ADDR_EQUAL(&ip6h->ip6_dst, &ip6_dst)) {
		inbound = 1;
	}

	pthread_mutex_lock(&hip_mr_client_mutex);
	for (i = 0; i < max_hip_mr_clients; i++) {
		addr = (struct sockaddr *)&hip_mr_client_table[i].mn_addr;
		addr->sa_family = AF_INET6;
		memcpy(&ip6_src, SA2IP(addr), sizeof(struct in6_addr));
		hip_spi_nat *spi_nats = hip_mr_client_table[i].spi_nats;
		while (spi_nats) {
			if (inbound &&
			    (spi_nats->public_spi == ntohl(esph->spi))) {
				printf("Found the public SPI 0x%x\n", ntohl(esph->spi));
				printf("Changing to 0x%x\n", spi_nats->private_spi);
				esph->spi = htonl(spi_nats->private_spi);
				adjust_addrs(&spi_nats->peer_addr,
					     &hip_mr_client_table[i].mn_addr,
					     ip6h);
				pthread_mutex_unlock(&hip_mr_client_mutex);
				return;
			} else if (!inbound &&
			       (spi_nats->peer_spi == ntohl(esph->spi)) &&
			       IN6_ARE_ADDR_EQUAL(&ip6h->ip6_src, &ip6_src)) {
				adjust_addrs(&out_addr, &spi_nats->peer_addr,
					     ip6h);
			}
		spi_nats = spi_nats->next;
		}
	}
	pthread_mutex_unlock(&hip_mr_client_mutex);
}

#ifdef __WIN32__
void hip_mobile_router(void *arg)
#else
void *hip_mobile_router(void *arg)
#endif
{
	int status, type;
	unsigned char buf[BUFSIZE];
	unsigned char *new_buff;
	size_t new_len;
	struct ipq_handle *h;
        struct ip6_hdr *ip6h;
	struct ip_esp_hdr *esph;
	ipq_packet_msg_t *m;
	char buffer[INET6_ADDRSTRLEN];
	sockaddr_list *l;

	struct sockaddr *out = (struct sockaddr *)&out_addr;

	printf("hip_mobile_router() thread started...\n");

	/* TODO: get from interface name spec in config file to interface index
	Also, for an address/interface UPDATE change, how to get that info
	to this thread?
	external_if_index = devname_to_index("eth0", NULL);
	*/

	for (l = my_addr_head; l; l=l->next) {
		if (l->if_index == external_if_index  &&
		    l->addr.ss_family == AF_INET6) {
			struct in6_addr ip6_addr;
			memcpy(&ip6_addr, SA2IP((struct sockaddr *)&l->addr),
				sizeof(struct in6_addr));
			if (!IN6_IS_ADDR_LINKLOCAL(&ip6_addr)  &&
			    !IN6_IS_ADDR_LOOPBACK(&ip6_addr)   &&
			    !IN6_IS_ADDR_SITELOCAL(&ip6_addr)) {
				out->sa_family = AF_INET6;
				memcpy(SA2IP(out),
					SA2IP((struct sockaddr *)&l->addr),
					SAIPLEN(out));
				break;
			}

		}
	}

/*
	struct in6_addr ip6_out;
	out = (struct sockaddr *)&out_addr;
	out->sa_family = AF_INET6;
	inet_pton(AF_INET6, "2002:822a:20ec:1::3", &ip6_out);
	memcpy(SA2IP(out), &ip6_out, SAIPLEN(out));
*/
	h = ipq_create_handle(0, PF_INET6);
	if (!h) {
		printf("hip_mobile_router() - ipq_create_handle() "
			"failed: %s\n", ipq_errstr());
		fflush(stdout);
#ifdef __WIN32__
		return;
#else
		return NULL;
#endif
	}

	status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0) {
		printf("hip_mobile_router() - ipq_set_mode() failed: %s\n", 
			ipq_errstr());
		ipq_destroy_handle(h);
		fflush(stdout);
#ifdef __WIN32__
		return;
#else
		return NULL;
#endif
	}

	while(g_state == 0) {
		check_address_change();
		status = ipq_read(h, buf, BUFSIZE, 5);
		if (status < 0) {
			printf("hip_mobile_router() - ipq_read() failed: %s\n",
				ipq_errstr());
			continue;
		} else if (status == 0) { /* Timed out */
                        continue;
                }

		type = ipq_message_type(buf);
		if (NLMSG_ERROR == type) {
			printf("Received error message %d\n",
				ipq_get_msgerr(buf));
			continue;
		} else if (IPQM_PACKET != type) {
			printf("Received unexpected type %d\n", type);
			continue;
		}

		m = ipq_get_packet(buf);
		new_buff = m->payload;
		new_len = m->data_len;

		ip6h = (struct ip6_hdr*)m->payload;
		printf("\nPacket from %s",
			inet_ntop(AF_INET6, &(ip6h->ip6_src),
				buffer, sizeof(buffer)));
		printf(" to %s\n",
			inet_ntop(AF_INET6, &(ip6h->ip6_dst),
				buffer, sizeof(buffer)));

		if (m->indev_name[0] != 0  &&  m->outdev_name[0] == 0)
			printf("  INPUT from %s\n\n", m->indev_name);
		else if (m->indev_name[0] != 0  &&  m->outdev_name[0] != 0)
			printf("  FORWARD from %s to %s\n\n", m->indev_name,
				m->outdev_name);
		else if (m->indev_name[0] == 0  &&  m->outdev_name[0] != 0)
			printf("  OUTPUT to %s\n\n", m->outdev_name);

		if (ip6h->ip6_nxt == H_PROTO_HIP) {
			unsigned char *temp_buff;
			size_t len;
			temp_buff = check_hip_packet(m->payload, m->data_len,
					&len);
			if (temp_buff) {
				new_buff = temp_buff;
				new_len = len;
			}
		} else if (ip6h->ip6_nxt == IPPROTO_ESP) {
			esph = (struct ip_esp_hdr *)
				(m->payload + sizeof(struct ip6_hdr));
			check_esp_packet(ip6h, esph);
		}

		status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT,
			new_len, new_buff);
		if (status < 0) {
			printf("hip_mobile_router() - ipq_set_verdict() "
				"failed: %s\n", ipq_errstr());
			continue;
		}

	}

	printf("hip_mobile_router() thread shutdown.\n");
	ipq_destroy_handle(h);
	fflush(stdout);
#ifndef __WIN32__
	pthread_exit((void *) 0);
	return(NULL);
#endif

}

/*
 *
 * function hip_send_update()
 * 
 * in:		hip_a = HIP association containing valid source/destination
 * 			addresses, HITs, SPIs, key material, pub key
 * 		newaddr = new preferred address to include in LOCATOR, or NULL
 * 		dstaddr = alternate destination address, if this is an address
 * 			check message, otherwise NULL
 * 		
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Opens a socket and sends the UPDATE packet.
 * Packet will be scheduled for retransmission if it contains a SEQ (that
 * needs to be ACKed.)
 *
 */
int hip_send_proxy_update(struct sockaddr *newaddr, struct sockaddr *dstaddr,
			hip_hit *mn_hit, hip_hit *peer_hit,
			hip_proxy_ticket *ticket, __u32 spi_in)
{
	struct sockaddr *src, *dst;
	hiphdr *hiph;
	__u8   buff[sizeof(hiphdr)             + 2*sizeof(tlv_locator) +
		    sizeof(tlv_auth_ticket)    +
		    sizeof(tlv_hmac)           + sizeof(tlv_hip_sig) +
		    MAX_SIG_SIZE + 2 ];
	int location=0, retransmit=FALSE;

	tlv_locator *loc;
	tlv_auth_ticket *auth_ticket;
	locator *loc1;
	__u32 loc_spi;

	memset(buff, 0, sizeof(buff));

	src = newaddr;
	dst = dstaddr;

	/* build the HIP header */

	hiph = (hiphdr*) buff;
	hiph->nxt_hdr = IPPROTO_NONE;
	hiph->hdr_len = 0;
	hiph->packet_type = UPDATE;
	hiph->version = HIP_PROTO_VER;
	hiph->res = HIP_RES_SHIM6_BITS;
	hiph->control = 0;
	hiph->checksum = 0;
	memcpy(&hiph->hit_sndr, mn_hit, sizeof(hip_hit));
	memcpy(&hiph->hit_rcvr, peer_hit, sizeof(hip_hit));
	location = sizeof(hiphdr);

	/* set control bits */

	hiph->control = htons(hiph->control);

	/*
	 * Add LOCATOR parameter when supplied with readdressing info.
	 */
	if (newaddr) {
		loc = (tlv_locator*) &buff[location];
		loc->type = htons(PARAM_LOCATOR);
		loc->length = htons(sizeof(tlv_locator) - 4);
		loc1 = &loc->locator1[0];
		loc1->traffic_type = LOCATOR_TRAFFIC_TYPE_BOTH;
		loc1->locator_type = LOCATOR_TYPE_SPI_IPV6;
		loc1->locator_length = 5; /* (32 + 128 bits) / 4 */
		loc1->reserved = LOCATOR_PREFERRED; /* set the P-bit */
		loc1->locator_lifetime = htonl(HCNF.loc_lifetime);
		memset(loc1->locator, 0, sizeof(loc1->locator));
		loc_spi = htonl(spi_in);
		memcpy(loc1->locator, &loc_spi, 4);
		if (newaddr->sa_family == AF_INET6) {
			memcpy(&loc1->locator[4], SA2IP(newaddr),
			    SAIPLEN(newaddr));
		} else {/* IPv4-in-IPv6 address format */
			memset(&loc1->locator[14], 0xFF, 2);
			memcpy(&loc1->locator[16], SA2IP(newaddr),
			    SAIPLEN(newaddr));
		}
		location += sizeof(tlv_locator);
		location = eight_byte_align(location);
		add_reg_request = FALSE;
	}

	/* AUTH_TICKET */
	auth_ticket = (tlv_auth_ticket *) &buff[location];
	auth_ticket->type = htons(PARAM_AUTH_TICKET);
	auth_ticket->length = htons(sizeof(tlv_auth_ticket) - 4);
	auth_ticket->hmac_key_index = htons(ticket->hmac_key_index);
	auth_ticket->transform_type = htons(ticket->transform_type);
	auth_ticket->action         = htons(ticket->action);
	auth_ticket->lifetime       = htons(ticket->lifetime);
	memcpy(auth_ticket->hmac, ticket->hmac, sizeof(auth_ticket->hmac));
	location += sizeof(tlv_auth_ticket);
	location = eight_byte_align(location);

	/* HMAC */
	hiph->hdr_len = (location/8) - 1; 
	location += build_tlv_proxy_hmac(ticket, buff, location, PARAM_HMAC);

#ifdef NOT
	
	/* HIP signature */
	hiph->hdr_len = (location/8) - 1; 
	location += build_tlv_signature(hip_a->hi, buff, location, FALSE);

#endif
	hiph->hdr_len = (location/8) - 1;
	hiph->checksum = 0;
	hiph->checksum = checksum_packet(buff, src, dst);

	/* send the packet */
	log_(NORMT, "sending UPDATE packet (%d bytes)...\n", location);

	/* Retransmit UPDATEs unless it contains a LOCATOR or address check */
	log_(NORM, "Sending UPDATE packet to dst : %s \n", logaddr(dst));
/*
	hip_check_bind(src, use_udp, HIP_UPDATE_BIND_CHECKS);
*/
	return(hip_send(buff, location, src, dst, NULL, retransmit, 0, 0));
}

int build_tlv_proxy_hmac(hip_proxy_ticket *ticket, __u8 *data, int location,
			int type)
{
	hiphdr *hiph;
	tlv_hmac *hmac;
	unsigned int hmac_md_len;
	unsigned char hmac_md[EVP_MAX_MD_SIZE];
	
	/* compute HMAC over message */
	hiph = (hiphdr*) data;
	memset(hmac_md, 0, sizeof(hmac_md));
	hmac_md_len = EVP_MAX_MD_SIZE;
	
	switch (ticket->transform_type) {
	case ESP_AES_CBC_HMAC_SHA1:
	case ESP_3DES_CBC_HMAC_SHA1:
	case ESP_BLOWFISH_CBC_HMAC_SHA1:
	case ESP_NULL_HMAC_SHA1:
		HMAC(	EVP_sha1(), 
			ticket->hmac_key,
			auth_key_len(ticket->transform_type),
			data, location,
			hmac_md, &hmac_md_len  );
		break;		
	case ESP_3DES_CBC_HMAC_MD5:
	case ESP_NULL_HMAC_MD5:
		HMAC(	EVP_md5(), 
			ticket->hmac_key,
			auth_key_len(ticket->transform_type),
			data, location,
			hmac_md, &hmac_md_len  );
		break;
	default:
		return(0);
		break;
	}

	log_(NORM, "HMAC computed over %d bytes hdr length=%d\n ",
	    location, hiph->hdr_len);

	/* build tlv header */
	hmac = (tlv_hmac*)  &data[location];
	hmac->type = htons((__u16)type);
	hmac->length = htons(sizeof(tlv_hmac) - 4);
	
	/* get lower 160-bits of HMAC computation */
	memcpy( hmac->hmac, 
		&hmac_md[hmac_md_len-sizeof(hmac->hmac)],
		sizeof(hmac->hmac));

	return(eight_byte_align(sizeof(tlv_hmac)));
}

