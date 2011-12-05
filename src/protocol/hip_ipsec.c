/*
 * Host Identity Protocol
 * Copyright (C) 2002-06 the Boeing Company
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
 *  hip_ipsec.c
 *
 *  Authors:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *  		Jeff Meegan, <jeff.r.meegan@boeing.com>
 *
 * Functions for communicating with the usermode ESP implementation.
 *
 */

#include <stdio.h>       	/* stderr, etc                  */
#include <stdlib.h>		/* rand()			*/
#include <errno.h>       	/* strerror(), errno            */
#include <string.h>      	/* memset()                     */
#include <time.h>		/* time()			*/
#include <ctype.h>		/* tolower()                    */
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>		/* sockaddrin_6 */
#include <io.h>				/* read() */
#include <win32/types.h>
#include <win32/ip.h>
#else
#ifndef __MACOSX__
#include <asm/types.h>
#endif
#include <unistd.h>		/* read()			*/
#include <arpa/inet.h>		/* inet_addr() 			*/
#include <sys/socket.h>  	/* sock(), recvmsg(), etc       */
#include <sys/time.h>  		/* gettimeofday()		*/
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>  	/* struct sockaddr_in, etc      */
#include <netinet/ip.h>  	/* struct iphdr                 */
#endif
#include <sys/types.h>		/* getpid() support, etc        */
#include <openssl/crypto.h>     /* OpenSSL's crypto library     */
#include <openssl/bn.h>		/* Big Numbers                  */
#include <openssl/dsa.h>	/* DSA support                  */
#include <openssl/dh.h>		/* Diffie-Hellman contexts      */
#include <openssl/sha.h>	/* SHA1 algorithms 		*/
#include <openssl/rand.h>	/* RAND_seed()                  */
#ifdef __MACOSX__
#include <sys/types.h>
#endif
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#include <hip/hip_sadb.h>
#ifdef HIP_VPLS
#include <hip/hip_cfg_api.h>
#endif /* HIP_VPLS */


#ifdef __MACOSX__
extern void del_divert_rule(int);
#endif
/* from hip_main.c */
#ifdef __WIN32__
void hip_handle_packet(__u8* buff, int length, struct sockaddr *src);
#else
void hip_handle_packet(struct msghdr *msg, int length, __u16 family);
#endif

/* local functions */
int hip_convert_lsi_to_peer(struct sockaddr *lsi, hip_hit *hitp,
	struct sockaddr *src, struct sockaddr *dst);

/*
 *
 * function get_next_spi()
 *
 * out:		returns next SPI value to use
 *
 * Obtains new random SPI, checks with kernel via SADB_GETSPI interface,
 * and then issues SADB_DELETE to remove the residual larval SA.
 */
__u32 get_next_spi() 
{
	__u32 new_spi;

retry_getspi:
	/* randomly select a new SPI */
	new_spi = 0;
	while (new_spi <= SPI_RESERVED) {
		RAND_bytes((__u8*)&new_spi, 4);
	}

#ifndef DUMMY_FUNCTIONS
	if (hip_sadb_lookup_spi(new_spi) != NULL) {
		log_(WARN, "Randomly chosen SPI (0x%x) already used, ",
		    new_spi);
		log_(NORM, "generating another.\n");
		goto retry_getspi;
	}

#endif	
	return(new_spi);
}

/*
 * check_last_used()
 *
 * in:		hip_a = uses src, dst, and incoming SPI
 * out:		Returns 0 on error or if SA is unused, 1 if traffic detected
 * 		If SA has been used, store time in hip_a->use_time.
 *
 * Check the current use time of the SA using an SADB_GET message.
 */
int check_last_used(hip_assoc *hip_a, int incoming, struct timeval *now)
{
	__u32 spi;
	__u64 bytes=0, *pbytes;
	struct timeval usetime;

	spi = incoming ? hip_a->spi_in : hip_a->spi_out;
	if (hip_sadb_get_usage(spi, &bytes, &usetime) < 0) {
		log_(WARN, "%s: SA with SPI 0x%x not found in SADB.\n",
		     __FUNCTION__, spi);
		return(0);
	}
	
	/* no traffic detected */
	if (bytes == 0) {
		return(0);
	}

	/* update use_time if either direction has traffic
	 */
	pbytes = incoming ? &hip_a->used_bytes_in : &hip_a->used_bytes_out;
	if (bytes > *pbytes) {
		*pbytes = bytes;
		hip_a->use_time.tv_sec = usetime.tv_sec;
		hip_a->use_time.tv_usec = usetime.tv_usec;
	}
	return(1);
}


/*
 * delete_associations()
 *
 * Remove associations from kernel by calling sadb_delete(), 
 * and sadb_delete_policy() for the incoming policy. (Outgoing policy is not
 * removed so further traffic will trigger a new exchange, if we are the
 * initiator) Called upon moving to CLOSING when no more packets may be sent.
 */
int delete_associations(hip_assoc *hip_a, __u32 old_spi_in, __u32 old_spi_out)
{
	int err;
	__u32 spi_in, spi_out;

	/* alternate SPIs may be passed in, but if zero use hip_a SPIs */
	spi_in = (old_spi_in) ? old_spi_in : hip_a->spi_in;
	spi_out = (old_spi_out) ? old_spi_out :	hip_a->spi_out;

	err = 0;
	if (hip_sadb_delete(spi_out) < 0) {
		log_(WARN, "Error removing outgoing SA with SPI 0x%x\n",
		    spi_out);
		err = -1;
	}
	if (hip_sadb_delete(spi_in) < 0) {
		log_(WARN, "Error removing incoming SA with SPI 0x%x\n", 
		    spi_in);
		err = -1;
	}
#ifdef __MACOSX__
        if(hip_a->ipfw_rule > 0)  {
                log_(WARN, "deleting divert rule...\n");
                del_divert_rule(hip_a->ipfw_rule);
                hip_a->ipfw_rule = 0;
        }
#endif
	return(err);
}

/*
 * flush_hip_associations()
 *
 * Called on exit to remove HIP associations from the SAD and SPD.
 */
int flush_hip_associations()
{
	int i, count=0;
	hip_assoc *hip_a;

	for (i=0; i < max_hip_assoc; i++) {
		hip_a = &hip_assoc_table[i];
		switch (hip_a->state) {
		case I2_SENT:
		case R2_SENT:
		case ESTABLISHED:
			count++;
			log_hipa_fromto(QOUT, "Close initiated (flush)", 
					hip_a, FALSE, TRUE);
			hip_send_close(hip_a, FALSE);
			set_state(hip_a, CLOSED);
#ifndef __UMH__		/* delete SAs from kernel; for UMH, all threads
			 * will be terminated anyway, and this hangs when
			 * called upon exit in Linux */
			delete_associations(hip_a, 0, 0);
#endif
			break;
		default:
			break;
		}
	}

	return(count);
}


/*
 * function hip_handle_esp()
 *
 * Handles received messages from the ESP input/output threads. This can be
 * an acquire (start new association), expire (start rekey), or a HIP control
 * packet demuxed from the UDP receive thread.
 */
void hip_handle_esp(char *data, int length)
{
	espmsg *msg = (espmsg*)data;
	int len;

	switch (msg->message_type) {
	    case ESP_ACQUIRE_LSI:
		len = ntohl(msg->message_data);
		if (len != sizeof(struct sockaddr_storage)) {
		    log_(WARN, "mismatched LSI length received from ESP thread\n");
		    return;
		}
		start_base_exchange( SA(&data[sizeof(espmsg)]) );
		break;
	    case ESP_EXPIRE_SPI:
		start_expire(ntohl(msg->message_data));
		break;
	    case ESP_UDP_CTL:
		len = ntohl(msg->message_data);
		if (len != (length - sizeof(espmsg))) {
		    log_(WARN, "mismatched length received from ESP thread\n");
		    return;
		}
		receive_udp_hip_packet(&data[sizeof(espmsg)], len);
		break;
	    default:
		log_(WARN, "unknown data received from the ESP thread: %d\n",
			msg->message_type);
		break;
	}
}

/*
 * start_base_exchange()
 *
 * Trigger the HIP exchange based on dst LSI. 
 * To send an I1, you need at least a
 * destination IP address (opportunistic) and a HIT (if not opportunstic).
 */
void start_base_exchange(struct sockaddr *dst)
{
	hip_hit *hitp = NULL;
	hip_assoc* hip_a = NULL;
	hi_node *mine;
	hiphdr hiph;

	struct sockaddr_storage lsi, ss_src;
	struct sockaddr *src = SA(&ss_src);
	hip_hit newhit;
	int previous_state = UNASSOCIATED;

	/* replace LSI with IP address */
	memset(&lsi, 0, sizeof(struct sockaddr_storage));
	memcpy(&lsi, dst, SALEN(dst));
	memset(&newhit, 0, HIT_SIZE);
	hitp = &newhit;
	log_(NORMT, "Received ACQUIRE for LSI %s ", logaddr(dst));
	if (hip_convert_lsi_to_peer(SA(&lsi), hitp, src, dst) < 0)
		return;
	if (IS_LSI(dst)) {
		log_(WARN, "no suitable peer address, ignoring.\n");
		return;
	}

	/* Where do we send the I1? */
	if ((hitp == NULL) && (!OPT.opportunistic)) {
		log_(NORM, "HIT not found, unable to send I1\n");
		return;
	}
	/* Create pseudo-HIP header for lookup */
	if ((mine = get_preferred_hi(my_hi_head)) == NULL) {
		log_(WARN, "No local identities to use.\n");
		return;
	}
	memcpy(hiph.hit_rcvr, mine->hit, HIT_SIZE);
	if (hitp == NULL) { /* Look for existing assoc. using addrs and HITs */
		memcpy(hiph.hit_sndr, &zero_hit, sizeof(hip_hit));
		hip_a = find_hip_association(dst, src, &hiph);
	} else { /* Look for existing association using HITs */
		memcpy(hiph.hit_sndr, hitp, sizeof(hip_hit));
		hip_a = find_hip_association2(&hiph);
	}
	if (hip_a && (hip_a->state > UNASSOCIATED) && 
	    (hip_a->state != CLOSING) && (hip_a->state != CLOSED)) {
		/* already have a HIP association for this HIT */
		log_(NORM, "association exists -- ignoring.\n");
		return;
	} else if (hip_a && ((hip_a->state == CLOSING) ||
			     (hip_a->state == CLOSED)) ) {
		log_(NORM, "association exists, creating another.\n");
		/* Spec says to create another incarnation here;
		 * we need to free the data structures to reuse.
		 * Do not change state from CLOSED or CLOSING */
		previous_state = hip_a->state;
		free_hip_assoc(hip_a);
		hip_a = NULL;
	}
	if (!hip_a) {
		/* Create another HIP association */
		log_(NORM, "creating new association.\n");
		hip_a = init_hip_assoc(mine, (const hip_hit*) &hiph.hit_sndr);
		if (!hip_a) {
			log_(WARN, "Unable to create association triggered by "
				   "ACQUIRE.\n");
			return;
		}
		hip_a->preserve_outbound_policy = TRUE;
	}

	/* fill in addresses */
	memcpy(HIPA_SRC(hip_a), src, SALEN(src));
	hip_a->hi->addrs.if_index = is_my_address(src);
	make_address_active(&hip_a->hi->addrs);
	add_other_addresses_to_hi(hip_a->hi, TRUE);
	memcpy(HIPA_DST(hip_a), dst, SALEN(dst));
	memcpy(&(hip_a->peer_hi->hit), hiph.hit_sndr, sizeof(hip_hit));
	add_other_addresses_to_hi(hip_a->peer_hi, FALSE);

	/* use HIP over UDP unless disabled in conf file */
	if (!HCNF.disable_udp && (dst->sa_family == AF_INET)) {
		hip_a->udp = TRUE;
		/* this signals to hip_send() to perform UDP encapsulation */
		((struct sockaddr_in*)HIPA_DST(hip_a))->sin_port = \
							htons(HIP_UDP_PORT);
		/* TODO: IPv6 over UDP here */
	}

	log_hipa_fromto(QOUT, "Base exchange initiated", hip_a, TRUE, TRUE);
	print_hex(hip_a->peer_hi->hit, HIT_SIZE);

	/* Send the I1 */
	if (hip_send_I1(hitp, hip_a) > 0) {
		if (previous_state == CLOSING || previous_state == CLOSED) {
			set_state(hip_a, previous_state);
		} else {
			set_state(hip_a, I1_SENT);
		}
	}
}

/*
 * hip_convert_lsi_to_peer()
 *
 * Given a peer's LSI, try and find the peer's HIT and IP address,
 * along with a matching source IP address.
 *
 */
int hip_convert_lsi_to_peer(struct sockaddr *lsi, hip_hit *hitp, 
	struct sockaddr *src, struct sockaddr *dst)
{
	hi_node *peer_hi = NULL;
	int want_family = 0, dns_ok = TRUE;
	struct sockaddr addr;
#ifdef HIP_VPLS
	sockaddr_list *list;
	struct sockaddr *old_addr;
#endif
#if 0
	struct sockaddr_storage lsi_save;
#endif

	memset(hitp, 0, HIT_SIZE);
	
	/* 
	 * For 1.x.x.x IPv4 LSIs, we need to find a HIT
	 */
	if (lsi->sa_family == AF_INET) {
		/* lookup LSI locally (preconfigured entries or
		 * those cached from HIP DNS lookups)
		 */
		peer_hi = lsi_lookup(lsi);
#ifdef HIP_VPLS
		if (!peer_hi) {
			log_(NORM, "peer HI not found, "
			    "reloading from hipcfg\n");
			read_peer_identities_from_hipcfg();		        
			peer_hi = lsi_lookup(lsi);
		} else {
			list = &peer_hi->addrs;
			old_addr = SA(&list->addr);
			memset(&addr, 0, sizeof(struct sockaddr));
			if (hipcfg_getLlipByEndbox(lsi, &addr)) {
				log_(WARN, "Unable to update peer IP "
				    "from hipcfg; using stored value\n");
			} else if (!memcmp(SA2IP(old_addr), SA2IP(&addr),
					   SAIPLEN(&addr))) {
				log_(NORM, "Updating peer IP from hipcfg\n");
				memcpy(&list->addr, &addr, SALEN(&addr));
			} else {
				log_(NORM, "Peer IP is unchanged\n");
			}
		}
#endif /* HIP_VPLS */
		if (!peer_hi || hits_equal(peer_hi->hit, zero_hit)) {
			/* Peer doesn't exist locally or has an empty HIT.
			 * TODO: perform DHT lookup to retrieve HIT and adopt
			 * if opportunistic is enabled.
			 */
		} else { /* valid peer_hi with non-zero HIT */
			memcpy(hitp, peer_hi->hit, HIT_SIZE);
		}
	/* 
	 * For IPv6, the 2001:10::/28 LSI *is* the HIT 
	 */
	} else if (dst->sa_family == AF_INET6) {
		memcpy(hitp, SA2IP(dst), HIT_SIZE);
		/* look for a peer context */
		peer_hi = find_host_identity(peer_hi_head, *hitp);
		if (!peer_hi) {
			if (!OPT.allow_any) {
				log_(WARN, "Peer HIT in ACQUIRE has not been "
				    "configured, dropping (try -a option)\n");
				return(-1);
			}
			/* create a new peer entry */
			memset(&addr, 0, sizeof(struct sockaddr));
			addr.sa_family = AF_INET;
			add_peer_hit(*hitp, &addr);
			peer_hi = find_host_identity(peer_hi_head, *hitp);
			peer_hi->addrs.addr.ss_family = 0;
			dns_ok = FALSE;
		}
		/* store the 32-bit LSI in lsi */
		memset(lsi, 0, sizeof(struct sockaddr_storage));
		if (VALID_FAM(&peer_hi->lsi)) {
			memcpy(lsi, &peer_hi->lsi, SALEN(&peer_hi->lsi));
		} else {
			lsi->sa_family = AF_INET;
			((struct sockaddr_in*)lsi)->sin_addr.s_addr = 
				HIT2LSI(*hitp);
			memcpy(&peer_hi->lsi, lsi, SALEN(lsi));
		}
			
	}

	if (!peer_hi) { /* should not be reached */
		log_(WARN, "peer_hi is still null!\n");
		return(-1);
	}

	/* 
	 * Look for peer's destination address from:
	 * 1. local conf (known_host_identities)
	 * 2. DNS lookup of name
	 * 3. DHT lookup using HIT
	 */
	if (!VALID_FAM(&peer_hi->addrs.addr)) { 
	/* peer has no address, try to fill it in */
		if (dns_ok && 
		    (add_addresses_from_dns(peer_hi->name, peer_hi) < 0)) {
			/* note: this DHT lookup is blocking */
			if ((hip_dht_resolve_hi(peer_hi, FALSE) < 0)) {
				log_(NORM, "(Peer address not found for %s)\n",
					peer_hi->name);
				add_addresses_from_dns(NULL, NULL);
				return(-1);
			}
		} else if (!dns_ok &&
			   (hip_dht_resolve_hi(peer_hi, FALSE) < 0)) {
			log_(NORM, "(Peer address not found for ");
			print_hex(*hitp, HIT_SIZE);
			log_(NORM, ")\n");
			return(-1);
		}
	}

	/* return HIT from peer_hi if needed, which may come from DHT lookup */
	if (hits_equal(*hitp, zero_hit) && !hits_equal(peer_hi->hit, zero_hit)){
		memcpy(hitp, peer_hi->hit, HIT_SIZE);
	}

	/* copy from peer_hi address list into dst by matching the address
	 * family from our preferred address  */
	if (VALID_FAM(&peer_hi->addrs.addr)) { 
		want_family = 0;
		if (get_addr_from_list(my_addr_head, want_family, src) >= 0)
			want_family = src->sa_family;
		/* try to match address family of our preferred address  */
		if (get_addr_from_list(&peer_hi->addrs, want_family, dst) < 0) {
			/* use any address family */
			if (get_addr_from_list(&peer_hi->addrs, 0, dst) < 0) {
				log_(NORM,"(Peer address not found (2) %s)\n",
					dns_ok ? peer_hi->name : "");
			}
			/* XXX fix this for Windows -- IPv4 only
			 * could do BEX for IPv6 and update to v4 addr?
			 */
		}
	} else if ((*(peer_hi->rvs_addrs) != NULL) &&
	           (VALID_FAM(&(*(peer_hi->rvs_addrs))->addr))) {
		memcpy(SA(dst), SA(&(*(peer_hi->rvs_addrs))->addr),
		SALEN(&(*(peer_hi->rvs_addrs))->addr));
	}

	/* my preferred address becomes src (instead of LSI) */
	if (get_addr_from_list(my_addr_head, dst->sa_family, src) < 0) {
		log_(NORM, "(Could not find a source address from the same "
			"address family (peer family=%d))\n", dst->sa_family);
		return(-1);
	}
	return(0);
}


/*
 * start_expire()
 *
 * Given the SPI of the expired SA, locate HIP association and perform
 * a rekey.
 */
void start_expire(__u32 spi)
{
	int i, err;
	hip_assoc* hip_a = NULL;

	/* Find an ESTABLISHED HIP association using the SPI */
	for (i=0; i < max_hip_assoc; i++) {
		hip_a = &hip_assoc_table[i];
		if ((hip_a->spi_in != spi) && (hip_a->spi_out != spi))
			continue;
		break;
	}
	if ((!hip_a) || (i >= max_hip_assoc))
		return; /* not found */

	if (hip_a->rekey) // XXX does this work for all cases?
		return; /* already rekeying */
	
	/*
	 * Initiate rekey
	 */
	log_(NORM, "Initiating rekey for association %d.\n", i);
	if (build_rekey(hip_a) < 0) {
		log_(WARN, "hip_handle_expire() had problem building rekey "
			"structure for rekey initiation.\n");
		return;
	}
	if ((err = hip_send_update(hip_a, NULL, NULL, NULL)) > 0) {
		log_(NORM, "Sent UPDATE (%d bytes)\n", err);
	} else {
		log_(NORM, "Failed to send UPDATE: %s.\n", strerror(errno));
	}
}

/*
 * receive_udp_hip_packet
 *
 * Pass a HIP control packet from the UDP socket to the parser.
 *
 */
void receive_udp_hip_packet(char *buff, int len)
{
	struct sockaddr_storage ss_addr_from;
	struct sockaddr *src = SA(&ss_addr_from);
	struct ip *iph;
	udphdr *udph;
	int family = AF_INET; /* TODO: detect family from ip header to
				       support IPv6 */
#ifndef   __WIN32__
	struct msghdr msg;
	struct iovec iov;
#endif /* __WIN32__ */


	/* TODO: IPv6 over UDP here */
	iph = (struct ip *) buff;
	udph = (udphdr *) (iph + 1);

	memset(src, 0, sizeof(struct sockaddr_storage));
	src->sa_family = family;
	((struct sockaddr_in *)src)->sin_addr = iph->ip_src;
	((struct sockaddr_in *)src)->sin_port = udph->src_port;

#ifdef   __WIN32__
	hip_handle_packet(buff, len, src);
#else /* __WIN32__ */
	msg.msg_name = src;
	msg.msg_namelen = sizeof(struct sockaddr_storage);
	msg.msg_iov = &iov;
	msg.msg_iov->iov_base = buff;
	msg.msg_iovlen = len;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	hip_handle_packet(&msg, len, AF_INET);
#endif /* __WIN32__ */
}


