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
 *  hip_output.c
 *
 *  Author:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson,  <thomas.r.henderson@boeing.com>
 *
 * Routines for building and sending HIP packets.
 * 
 */

#include <stdio.h>       	/* stderr, etc                  */
#include <stdlib.h>		/* rand()			*/
#include <errno.h>       	/* strerror(), errno            */
#include <string.h>      	/* memset()                     */
#include <time.h>		/* time()			*/
#include <ctype.h>		/* tolower()                    */
#include <sys/types.h>		/* getpid() support, etc        */
#include <openssl/crypto.h>     /* OpenSSL's crypto library     */
#include <openssl/bn.h>		/* Big Numbers                  */
#include <openssl/des.h>	/* 3DES support			*/
#include <openssl/blowfish.h>	/* BLOWFISH support 		*/
#include <openssl/aes.h>	/* AES support			*/
#include <openssl/dsa.h>	/* DSA support                  */
#include <openssl/dh.h>		/* Diffie-Hellman contexts      */
#include <openssl/sha.h>	/* SHA1 algorithms 		*/
#include <openssl/rand.h>	/* RAND_seed()                  */
#include <openssl/err.h>	/* ERR_ functions		*/
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <crt/io.h>
#include <win32/types.h>
#else
#ifndef __MACOSX__
#include <asm/types.h>
#endif
#include <unistd.h>		/* close()			*/
#include <sys/time.h>           /* gettimeofday()               */
#include <sys/uio.h>		/* iovec */
#include <pthread.h>		/* pthread_exit() */
#ifdef __MACOSX__
#include <netinet/in_systm.h>   
#include <netinet/in.h>   
#endif
#include <netinet/ip.h>  	/* struct iphdr                 */
#endif
#if defined(__MACOSX__) || defined(__UMH__)
#include <win32/pfkeyv2.h>
#else
#include <linux/pfkeyv2.h> /* PF_KEY_V2 support */
#endif

#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>

#ifdef HIP_I3
#include "i3_hip.h"
#endif


/*
 * Forward declaration of local functions.
 */
int hip_check_bind(struct sockaddr *src, int use_udp, int num_attempts);
int build_tlv_dh(__u8 *data, __u8 group_id, DH *dh, int debug);
int build_tlv_transform(__u8 *data, int type, __u16 transforms[], __u16 single);
int build_tlv_echo_response(__u16 type, __u16 length, __u8 *buff, __u8 *data);
int build_tlv_signature(hi_node *hi, __u8 *data, int location, int R1);
int build_tlv_hmac(hip_assoc *hip_a, __u8 *data, int location, int type);
int build_tlv_reg_info(__u8 *data, int location);
int build_tlv_reg_req(__u8 *data, int location, struct reg_entry *reg_offered);
int build_tlv_reg_resp(__u8 *data, int location,
		struct reg_entry *reg_requested);
int build_tlv_reg_failed(__u8 *data, int location,
		struct reg_entry *reg_requested);
int build_tlv_rvs_hmac(hip_assoc *hip_a, __u8 *data, int location, int type, int pos);

#ifdef __MACOSX__
extern int next_divert_rule();
extern void add_divert_rule(int,int,char *);
extern void del_divert_rule(int);
#endif

/*
 * function hip_send_I1()
 * 
 * in:		hit  = Responder's HIT, who we want to start communications with
 * 		conn = Connection number to use for retransmission
 * 		
 * out:		Returns bytes sent when successful, -1 on failure.
 *
 * Opens a socket and sends the HIP Initiator packet.
 *
 */
int hip_send_I1(hip_hit *hit, hip_assoc *hip_a, int pos)
{
	struct sockaddr *src, *dst;
	hiphdr *hiph;
	tlv_from *ip_from;
	__u8 buff[sizeof(hiphdr) + sizeof(tlv_from) +
		   sizeof(tlv_rvs_hmac)];
	int location=0;

	memset(buff, 0, sizeof(buff));

	/* TODO: this can be cleaned up by collapsing the RVS case with
	 *       a few extra if's in the normal case
	 */

	/* in RVS mode, relay the I1 packet instead of triggering bex */
	if (OPT.rvs && fr.add_from && pos!=-1) {
		/* use RVS (global) & Responder (from reg_table) IP addresses */
		src = (struct sockaddr*) &fr.ip_rvs;
		dst = (struct sockaddr*) &hip_reg_table[pos].peer_addr;
	
		hiph = (hiphdr*) &buff[0];
	        hiph->nxt_hdr = IPPROTO_NONE;
	        hiph->hdr_len = 0; 
        	hiph->packet_type = HIP_I1;
	        hiph->version = HIP_PROTO_VER;
	        hiph->res = HIP_RES_SHIM6_BITS;
	        hiph->control = 0;
	        hiph->checksum = 0;

		memcpy(hiph->hit_sndr, fr.hit_from, sizeof(hip_hit));
		memcpy(hiph->hit_rcvr, hit, sizeof(hip_hit));
		location = sizeof(hiphdr);

		/* add the from parameter */
		ip_from	= (tlv_from*) &buff[location];
	 	ip_from->type = htons (PARAM_FROM);
		ip_from->length = htons(sizeof(tlv_from) - 4);
	 	memcpy(ip_from->addr, &fr.ip_from, sizeof(struct sockaddr));
		location = location + sizeof(tlv_from);
		location = eight_byte_align(location);

		/* RVS_HMAC */
		/* hip_a is now the pre-existing association between the 
		 * RVS server and the responder, to get the HMAC key */
		hip_a = hip_reg_table[pos].hip_a;
		hiph->hdr_len = (location/8) - 1; 
		location += build_tlv_rvs_hmac(hip_a, buff, location, 
				PARAM_RVS_HMAC, pos);

		hiph->hdr_len = (location/8) - 1;
		hiph->checksum = checksum_packet(&buff[0], src, dst);

		/* send the packet */
		log_(NORMT, "relaying HIP_I1 packet (%d bytes)...\n", location);
		
		return(hip_send(buff, location, src, dst, hip_a,
		     		TRUE, hip_a->peer_dst_port, hip_a->use_udp));
	} else { /* normal mode -- not an RVS relay */
		/* XXX this line seems extraneous */
		hip_a->peer_dst_port = HIP_UDP_PORT;
		src = HIPA_SRC(hip_a);
		dst = HIPA_DST(hip_a);
		if (VALID_FAM(&hip_a->peer_hi->rvs)) /* use RVS instead of DST*/
			dst = SA(&hip_a->peer_hi->rvs);

		/* NULL HITs only allowed for opportunistic I1s */
		if ((hit == NULL) && !OPT.opportunistic)
			return(-1);
		if (hit == NULL)
			log_(NORM, "Sending NULL HIT to %s.\n", logaddr(dst));
		else
			log_(NORM, "Sending HIT corresponding to %s.\n", 
				logaddr(dst));
    
		hiph = (hiphdr*) &buff[0];
		hiph->nxt_hdr = IPPROTO_NONE;
		hiph->hdr_len = 4; /* 2*sizeof(hip_hit)/8*/
		hiph->packet_type = HIP_I1;
		hiph->version = HIP_PROTO_VER;
		hiph->res = HIP_RES_SHIM6_BITS;
		hiph->control = 0;
		hiph->checksum = 0;
			
		memcpy(hiph->hit_sndr, hip_a->hi->hit, sizeof(hip_hit));
		if (hit == NULL) /* opportunistic */
			memset(hiph->hit_rcvr, 0, sizeof(hip_hit));
		else
			memcpy(hiph->hit_rcvr, hit, sizeof(hip_hit));

		location = sizeof(hiphdr);
		hiph->checksum = checksum_packet(&buff[0], src, dst);
#ifdef SMA_CRAWLER
                __u32 lsi_d;
                lsi_d = ntohl(HIT2LSI(hiph->hit_sndr));
                log_(WARN,"Initiator: %u.%u.%u.%u\n",NIPQUAD(lsi_d));
                lsi_d = ntohl(HIT2LSI(hiph->hit_rcvr));
                log_(WARN,"Responder: %u.%u.%u.%u\n",NIPQUAD(lsi_d));
#endif

	 	/* send the packet */
		log_(NORMT, "sending HIP_I1 packet (%d bytes)...\n", location);
#ifdef HIP_I3
		if (OPT.use_i3)
		     return(send_i3(buff, location, hit,
				    HIPA_SRC(hip_a),HIPA_DST(hip_a)));
		else
#endif
		return(hip_send(buff, location, src, dst, hip_a, TRUE,
        	                hip_a->peer_dst_port, hip_a->use_udp));
	}
}


/*
 *
 * function hip_send_R1()
 * 
 * in: 		hip_a = HIP association containing source/destination addresses,
 * 			response cookie, valid HITs
 * out:		Returns bytes sent when successful, -1 on error.
 * 		hip_a will have DH context and retransmission packets
 *
 * Opens a socket and sends the HIP Responder packet.
 *
 */
int hip_send_R1(struct sockaddr *src, struct sockaddr *dst, hip_hit *hiti, 
		hi_node *hi, __u16 dst_port, int use_udp)
{
	int err, i, location =0;
	hiphdr *hiph;
	r1_cache_entry *r1_entry;
	__u8 *data;
	tlv_via_rvs *via;

	/* make a copy of a pre-computed R1 from the cache */
	i = compute_R1_cache_index(hiti, TRUE);
	r1_entry = &hi->r1_cache[i];

	/* if received I1 with from parameter, add via_rvs parameter in R1 */
	if (fr2.add_via_rvs)
	{ 
		location = r1_entry->len;
		data = (__u8 *) malloc(location + sizeof(tlv_via_rvs));
		memcpy(data, r1_entry->packet, r1_entry->len);
		
		via = (tlv_via_rvs *) &data[location];
		via->type = htons(PARAM_VIA_RVS);
		via->length = htons(sizeof(tlv_via_rvs) - 4);
		memcpy(via->address, src, sizeof(struct sockaddr));	// RVS IP address
		location = location + sizeof(tlv_via_rvs);
	
		hiph = (hiphdr*) data;
		hiph->hdr_len = (location/8) -1;
	}else
	{
		data = (__u8 *) malloc(r1_entry->len);
		memcpy(data, r1_entry->packet, r1_entry->len);
		
		hiph = (hiphdr*) data;
	}
	log_(NORM,"Using premade R1 from %s cache slot %d.\n", hi->name, i);

	/* fill in receiver's HIT, checksum */
	memcpy(hiph->hit_rcvr, hiti, sizeof(hip_hit));
	hiph->checksum = 0;
	hiph->checksum = checksum_packet(data, src, dst);

	/* send the packet */
	if (fr2.add_via_rvs)
        {
                log_(NORMT, "sending HIP_R1 packet (%d bytes)...\n", r1_entry->len + sizeof(tlv_via_rvs));

/* If it is a RVS forwarding : which destination port ??? */
                err = hip_send(data, r1_entry->len + sizeof(tlv_via_rvs), src, dst, NULL, FALSE, dst_port, use_udp);
	}
#ifdef HIP_I3
        if (OPT.use_i3)
	{
		log_(NORMT, "sending HIP_R1 packet (%d bytes)...\n", r1_entry->len);
                err = send_i3(data, r1_entry->len, hiti, src, dst);
	}
#endif
	else
	{
		log_(NORMT, "sending HIP_R1 packet (%d bytes)...\n", r1_entry->len);

		err = hip_send(data, r1_entry->len, src, dst, NULL, FALSE, dst_port, use_udp);
	}

	free(data);
	return(err);
}

/*
 *
 * function hip_generate_R1()
 *
 * in:		data = ptr of where to store R1 (must have enough space)
 * 		hi = ptr to my Host Identity to use
 * 		cookie = the puzzle to insert into the R1
 * 		dh_entry = the DH cache entry to use
 *		
 */
int hip_generate_R1(__u8 *data, hi_node *hi, hipcookie *cookie, 
		    dh_cache_entry *dh_entry)
{
	hiphdr *hiph;
	int location=0, cookie_location=0;
	int len;

	tlv_r1_counter *r1cnt;
	tlv_puzzle *puzzle;

	memset(data, 0, sizeof(data));
	hiph = (hiphdr*) data;
   
	/* build the HIP header */
	hiph->nxt_hdr = IPPROTO_NONE;
	hiph->hdr_len = 0;
	hiph->packet_type = HIP_R1;
	hiph->version = HIP_PROTO_VER;
	hiph->res = HIP_RES_SHIM6_BITS;
	hiph->control = 0;
	hiph->checksum = 0; /* 0 for SIG, set later */
	memcpy(hiph->hit_sndr, hi->hit, sizeof(hip_hit));
	memset(hiph->hit_rcvr, 0, sizeof(hip_hit));
	location = sizeof(hiphdr);

	/* set control bits */
	if (hi->anonymous) {
		hiph->control |= CTL_ANON;
	}
	hiph->control = htons(hiph->control);

	/* optionally build R1 COUNTER TLV */
	if (hi->r1_gen_count > 0) {
		r1cnt = (tlv_r1_counter*) &data[location];
		r1cnt->type = htons(PARAM_R1_COUNTER);
		r1cnt->length = htons(sizeof(tlv_r1_counter) - 4);
		r1cnt->reserved = 0;
		r1cnt->r1_gen_counter = hton64(hi->r1_gen_count);
		location += sizeof(tlv_r1_counter);
		location = eight_byte_align(location);
	}
	
	/* build the PUZZLE TLV */
	puzzle = (tlv_puzzle*) &data[location];
	puzzle->type = htons(PARAM_PUZZLE);
	puzzle->length = htons(sizeof(tlv_puzzle) - 4);
	location += sizeof(tlv_puzzle);
	len = sizeof(hipcookie);
	memset(&puzzle->cookie, 0, len); /* zero OPAQUE and I fields for SIG */
	puzzle->cookie.k = cookie->k;
	puzzle->cookie.lifetime = cookie->lifetime;
	cookie_location = location - len;
	if (D_VERBOSE == OPT.debug_R1) {
		log_(NORM, "Cookie sent in R1: ");
		print_cookie(cookie);
	}
	location = eight_byte_align(location);
	
	/* Diffie Hellman */
	location += build_tlv_dh(&data[location], dh_entry->group_id,
				 dh_entry->dh, OPT.debug_R1);
		
	/* HIP transform */
	location += build_tlv_transform(&data[location],
		PARAM_HIP_TRANSFORM, HCNF.hip_transforms, 0);
	
	/* host_id */
	location += build_tlv_hostid(&data[location], hi, HCNF.send_hi_name);
	
	/* certificate */
	location += build_tlv_cert(&data[location]);

		/* reg_info */
		location += build_tlv_reg_info(data, location);

	/* if ECHO_REQUEST is needed, put it here */

	/* ESP transform */
	location += build_tlv_transform(&data[location],
		PARAM_ESP_TRANSFORM, HCNF.esp_transforms, 0);
	
	/* hip_signature_2 - receiver's HIT and checksum zeroed */
	hiph->hdr_len = (location/8) - 1;
	location += build_tlv_signature(hi, data, location, TRUE);

	hiph->hdr_len = (location/8) - 1;

	/* insert the cookie (OPAQUE and I) */
	memcpy(&data[cookie_location], cookie, sizeof(hipcookie));

	/* if ECHO_REQUEST_NOSIG is needed, put it here */
	

	return(location);
}


/*
 *
 * function hip_send_I2()
 * 
 * in:		hip_a = pointer to HIP connection instance
 * 		
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Opens a socket and sends the HIP Second Initiator packet.
 *
 */
int hip_send_I2(hip_assoc *hip_a)
{
	int err;
	struct sockaddr *src, *dst;
	hiphdr *hiph;
	__u8   buff[sizeof(hiphdr)            + sizeof(tlv_esp_info) +
		    sizeof(tlv_r1_counter)    +
		    sizeof(tlv_solution)      + sizeof(tlv_diffie_hellman) +
		    DH_MAX_LEN                + sizeof(tlv_hip_transform)+2 +
		    sizeof(tlv_esp_transform) + sizeof(tlv_encrypted) +
		    sizeof(tlv_host_id)       + 1 + DSA_PRIV +
		    3*(MAX_HI_BITS/8)         + MAX_HI_NAMESIZE +
				sizeof(tlv_echo)          + MAX_OPAQUE_SIZE +
				sizeof(tlv_reg_request)		+ MAX_REGISTRATION_TYPES +
		    sizeof(tlv_hmac)          +
		    sizeof(tlv_hip_sig)       + MAX_SIG_SIZE + 2];
	__u8 *unenc_data, *enc_data;
	__u16 zero16[1] = {0x0};
	int len, location=0;

	/* encrypted(host_id) */
	__u16 data_len, iv_len;
	des_key_schedule ks1, ks2, ks3;
	u_int8_t secret_key1[8], secret_key2[8], secret_key3[8];
	unsigned char *key;
	BF_KEY bfkey;
	AES_KEY aes_key;
	/* 
	 * initialization vector used as a randomizing block which is 
	 * XORed w/1st data block 
	 */
        unsigned char cbc_iv[16];

	__u64 solution;

	tlv_r1_counter *r1cnt;
	tlv_esp_info *esp_info;
	tlv_solution *sol;
	tlv_encrypted *enc;
	__u32 hi_location;
	
	hipcookie cookie;

	memset(buff, 0, sizeof(buff));
	memcpy(&cookie, &hip_a->cookie_r, sizeof(hipcookie));
	src = HIPA_SRC(hip_a);
	dst = HIPA_DST(hip_a);
/* destination port should already have been defined when I1 has been sent... anyway ... */
	hip_a->peer_dst_port = HIP_UDP_PORT ;

	if (!ENCR_NULL(hip_a->hip_transform))
		RAND_bytes(cbc_iv, sizeof(cbc_iv));
	
	/* build the HIP header */
	hiph = (hiphdr*) buff;
	hiph->nxt_hdr = IPPROTO_NONE;
	hiph->hdr_len = 0;
	hiph->packet_type = HIP_I2;
	hiph->version = HIP_PROTO_VER;
	hiph->res = HIP_RES_SHIM6_BITS;
	hiph->control = 0;
	hiph->checksum = 0;
	memcpy(hiph->hit_sndr, &(hip_a->hi->hit), sizeof(hip_hit));
	memcpy(hiph->hit_rcvr, &(hip_a->peer_hi->hit), sizeof(hip_hit));
	location = sizeof(hiphdr);
 
	/* set control bits */
	if (hip_a->hi->anonymous) {
		hiph->control |= CTL_ANON;
	}
	hiph->control = htons(hiph->control);
		
	/* ESP INFO */
	esp_info = (tlv_esp_info*) &buff[location];
	esp_info->type = htons(PARAM_ESP_INFO);
	esp_info->length = htons(sizeof(tlv_esp_info) - 4);
	esp_info->reserved = 0;
	esp_info->keymat_index = 0; /* this is set below, after compute_keys()*/
	esp_info->old_spi = 0;
	esp_info->new_spi = htonl(hip_a->spi_in);
	location += sizeof(tlv_esp_info);
	location = eight_byte_align(location);

	/* R1 counter - optional */
	if (hip_a->peer_hi->r1_gen_count > 0) {
		r1cnt = (tlv_r1_counter*) &buff[location];
		r1cnt->type = htons(PARAM_R1_COUNTER);
		r1cnt->length = htons(sizeof(tlv_r1_counter) - 4);
		r1cnt->reserved = 0;
		r1cnt->r1_gen_counter = hton64(hip_a->peer_hi->r1_gen_count);
		location += sizeof(tlv_r1_counter);
		location = eight_byte_align(location);
	}
    
	/* puzzle solution */
	sol = (tlv_solution*) &buff[location];
	sol->type = htons(PARAM_SOLUTION);
	sol->length = htons(sizeof(tlv_solution) - 4);
	memcpy(&sol->cookie, &cookie, sizeof(hipcookie));
	if ((err = solve_puzzle(&cookie, &solution, 
				&hip_a->hi->hit, &hip_a->peer_hi->hit))< 0)
		return(err);
	sol->j = solution; /* already in network byte order */
	hip_a->cookie_j = solution; /* saved for use with keying material */
	location += sizeof(tlv_solution);
	location = eight_byte_align(location);
	
	log_(NORM, "Sending the I2 cookie: ");
	print_cookie(&cookie);
	log_(NORM, "solution: 0x%llx\n",solution);

	/* now that we have the solution, we can compute the keymat */
	compute_keys(hip_a);
	esp_info->keymat_index = htons((__u16)hip_a->keymat_index);

	/* diffie_hellman */
	location += build_tlv_dh(&buff[location], hip_a->dh_group_id, 
				 hip_a->dh, OPT.debug);

	/* hip transform */
	location += build_tlv_transform(&buff[location],
	    PARAM_HIP_TRANSFORM, zero16, hip_a->hip_transform);

	/* encrypted(host_id) */
	enc = (tlv_encrypted*) &buff[location];
	enc->type = htons(PARAM_ENCRYPTED);
	memset(enc->reserved, 0, sizeof(enc->reserved));
	iv_len = enc_iv_len(hip_a->hip_transform);
	memcpy(enc->iv, cbc_iv, iv_len);

	/* inner padding is 8-byte aligned */
	data_len = build_tlv_hostid_len(hip_a->hi, HCNF.send_hi_name);

	/* AES has 128-bit IV/block size with which we need to align */
	if (iv_len > 8) 
		data_len = (iv_len-1) + data_len - (data_len-1) % iv_len;
	/* Set the encrypted TLV length. Encryption may require IV. */
	enc->length = htons((__u16)(data_len + sizeof(enc->reserved) + iv_len)); 
	if (iv_len)
	    memcpy(enc->iv, cbc_iv, iv_len);
	unenc_data = (__u8 *)malloc(data_len);
	enc_data = (__u8 *)malloc(data_len);
	if (!unenc_data || !enc_data) {
		log_(ERR, "hip_send_I2: malloc error building encrypted TLV\n");
		return(-1);
	}
	memset(unenc_data, 0, data_len);
	memset(enc_data, 0, data_len);
        /* host_id */
	hi_location = build_tlv_hostid(unenc_data, hip_a->hi,HCNF.send_hi_name);
	/* Pad the data using PKCS5 padding - for n bytes of padding, set
	 * those n bytes to 'n'. */
	memset( (unenc_data + hi_location), 
		(data_len - hi_location),  /* fill with pad length */
		(data_len - hi_location) );

	switch (hip_a->hip_transform) {
	case ESP_NULL_HMAC_SHA1:
	case ESP_NULL_HMAC_MD5:
		/* don't send an IV with NULL encryption, copy data */
		memcpy(enc->iv, unenc_data, data_len);
		break;
	case ESP_AES_CBC_HMAC_SHA1:
		/* do AES CBC encryption */
		key = get_key(hip_a, HIP_ENCRYPTION, FALSE);
		len = enc_key_len(hip_a->hip_transform);
		log_(NORM, "AES encryption key: 0x");
		print_hex(key, len);
		log_(NORM, "\n");
		/* AES key must be 128, 192, or 256 bits in length */
		if ((err = AES_set_encrypt_key(key, 8*len, &aes_key)) != 0) {
			log_(WARN, "Unable to use calculated DH secret for ");
			log_(NORM, "AES key (%d)\n", err);
			free(unenc_data);
			free(enc_data);
			return(-1);
		}
		log_(NORM, "Encrypting %d bytes using AES.\n", data_len);
		AES_cbc_encrypt(unenc_data, enc_data, data_len, &aes_key,
				cbc_iv, AES_ENCRYPT);
		memcpy(enc->iv + iv_len, enc_data, data_len);
		break;
	case ESP_3DES_CBC_HMAC_SHA1:
	case ESP_3DES_CBC_HMAC_MD5:
		/* do 3DES PCBC encryption */
		/* Get HIP Initiator key and draw out three keys from that */
		/* Assumes key is 24 bytes for now */
		key = get_key(hip_a, HIP_ENCRYPTION, FALSE);
		len = 8;
		if (len < DES_KEY_SZ)
			log_(WARN, "short key!");
		memcpy(&secret_key1, key, len);
		memcpy(&secret_key2, key+8, len);
		memcpy(&secret_key3, key+16, len);
		
		des_set_odd_parity((des_cblock *)&secret_key1);
		des_set_odd_parity((des_cblock *)&secret_key2);
		des_set_odd_parity((des_cblock *)&secret_key3);
		log_(NORM, "3-DES encryption key: 0x");
		print_hex(secret_key1, len);
		log_(NORM, "-");
		print_hex(secret_key2, len);
		log_(NORM, "-");
		print_hex(secret_key3, len);
		log_(NORM, "\n");

		if ( ((err = des_set_key_checked((
		    (des_cblock *)&secret_key1), ks1)) != 0) ||
		    ((err = des_set_key_checked((
		    (des_cblock *)&secret_key2), ks2)) != 0) ||
		    ((err = des_set_key_checked((
		    (des_cblock *)&secret_key3), ks3)) != 0)) {
			log_(WARN, "Unable to use calculated DH secret for ");
			log_(NORM, "3DES key (%d)\n", err);
			free(unenc_data);
			free(enc_data);
			return(-1);
		}
		log_(NORM, "Encrypting %d bytes using 3-DES.\n", data_len);
		des_ede3_cbc_encrypt(unenc_data, enc_data, data_len,
		    ks1, ks2, ks3, (des_cblock*)cbc_iv, DES_ENCRYPT);
		memcpy(enc->iv + iv_len, enc_data, data_len);
		break;
	case ESP_BLOWFISH_CBC_HMAC_SHA1:
		key = get_key(hip_a, HIP_ENCRYPTION, FALSE);
		len = enc_key_len(hip_a->hip_transform);
		log_(NORM, "BLOWFISH encryption key: 0x");
		print_hex(key, len);
		log_(NORM, "\n");
		BF_set_key(&bfkey, len, key);
		log_(NORM, "Encrypting %d bytes using BLOWFISH.\n", data_len);
		BF_cbc_encrypt(unenc_data, enc_data, data_len, 
		    &bfkey, cbc_iv, BF_ENCRYPT);
		memcpy(enc->enc_data, enc_data, data_len);
		break;
	}
	/* this is type + length + reserved + iv + data_len */
	location += 4 + 4 + iv_len + data_len;
	location = eight_byte_align(location); 
	free(unenc_data);
	free(enc_data);
	/* end HIP encryption */
	
	/* certificate */
	location += build_tlv_cert(&buff[location]);

	/* add requested registrations */
	if (hip_a->reg_offered)
		location += build_tlv_reg_req(buff,location,
				hip_a->reg_offered);

	/* add any echo response (included under signature) */
	if (hip_a->opaque && !hip_a->opaque->opaque_nosig) {
		location += build_tlv_echo_response(PARAM_ECHO_RESPONSE,
				hip_a->opaque->opaque_len,
				&buff[location],
				hip_a->opaque->opaque_data);
		location = eight_byte_align(location);
		free(hip_a->opaque); /* no longer needed */
		hip_a->opaque = NULL;
	}

	/* esp transform */
	location += build_tlv_transform(&buff[location],
	    PARAM_ESP_TRANSFORM, zero16, hip_a->esp_transform);

	/* add HMAC */
	hiph->hdr_len = (location/8) - 1; 
	location += build_tlv_hmac(hip_a, buff, location, PARAM_HMAC);
    
	/* build the HIP SIG in a SIG RR */
	hiph->hdr_len = (location/8) - 1;
	location +=  build_tlv_signature(hip_a->hi, buff, location, FALSE);
   
	/* add any echo response (after signature) */
	if (hip_a->opaque && (hip_a->opaque->opaque_nosig)) {
		location += build_tlv_echo_response(PARAM_ECHO_RESPONSE_NOSIG,
				hip_a->opaque->opaque_len,
				&buff[location],
				hip_a->opaque->opaque_data);
		location = eight_byte_align(location);
		free(hip_a->opaque); /* no longer needed */
		hip_a->opaque = NULL;
	}
    
	/* finish with checksum, length */
	hiph->hdr_len = (location/8) - 1;
	hiph->checksum = 0;
	hiph->checksum = checksum_packet(buff, src, dst);
 

	/* send the packet */
	log_(NORMT, "sending HIP_I2 packet (%d bytes)...\n", location);
#ifdef HIP_I3
	if (OPT.use_i3)
     		return(send_i3(buff, location, &hip_a->peer_hi->hit, HIPA_SRC(hip_a), HIPA_DST(hip_a)));
	else
#endif
     return(hip_send(buff, location, HIPA_SRC(hip_a), HIPA_DST(hip_a),
                        hip_a, TRUE, hip_a->peer_dst_port, hip_a->use_udp));
}


/*
 *
 * function hip_send_R2()
 * 
 * in:		hip_a = HIP association containing valid source/destination
 * 			addresses, HITs, SPIs, key material, pub key
 * 		
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Opens a socket and sends the Second Responder packet.
 *
 */
int hip_send_R2(hip_assoc *hip_a)
{
	struct sockaddr *src, *dst;
	hiphdr *hiph;
	__u8   buff[sizeof(hiphdr)            + sizeof(tlv_esp_info) +
		    sizeof(tlv_host_id)       + 1 + DSA_PRIV +
		    3*(MAX_HI_BITS/8)         + MAX_HI_NAMESIZE +
		    sizeof(tlv_hmac)          + sizeof(tlv_hip_sig) + 
		    MAX_SIG_SIZE + 2	      + sizeof(tlv_reg_response) ];
	int location=0, hi_location;
	tlv_esp_info *esp_info;

	memset(buff, 0, sizeof(buff));

	src = HIPA_SRC(hip_a);
	dst = HIPA_DST(hip_a);

	/* build the HIP header */
	hiph = (hiphdr*) buff;
	hiph->nxt_hdr = IPPROTO_NONE;
	hiph->hdr_len = 0;
	hiph->packet_type = HIP_R2;
	hiph->version = HIP_PROTO_VER;
	hiph->res = HIP_RES_SHIM6_BITS;
	hiph->control = 0;
	hiph->checksum = 0;
	memcpy(&hiph->hit_sndr, hip_a->hi->hit, sizeof(hip_hit));
	memcpy(&hiph->hit_rcvr, hip_a->peer_hi->hit, sizeof(hip_hit));
	location = sizeof(hiphdr);

	/* set control bits */
	hiph->control = htons(hiph->control);
	
	/* ESP INFO */
	esp_info = (tlv_esp_info*) &buff[location];
	esp_info->type = htons(PARAM_ESP_INFO);
	esp_info->length = htons(sizeof(tlv_esp_info) - 4);
	esp_info->reserved = 0;
	esp_info->keymat_index = htons((__u16)hip_a->keymat_index);
	esp_info->old_spi = 0;
	esp_info->new_spi = htonl(hip_a->spi_in);
	location += sizeof(tlv_esp_info);
	location = eight_byte_align(location);

	if (hip_a->reg_requested) {
		location += build_tlv_reg_resp(buff, location, hip_a->reg_requested);
		location += build_tlv_reg_failed(buff, location, hip_a->reg_requested);
        location = eight_byte_align(location);
	}

        /* reg_required */
        /* not defined yet */

	/* HMAC_2 */
	hi_location = location; /* temporarily add host_id parameter */
	location += build_tlv_hostid(&buff[location], hip_a->hi,
			HCNF.send_hi_name);
	location = eight_byte_align(location);
	hiph->hdr_len = (location/8) - 1; 
	build_tlv_hmac(hip_a, buff, location, PARAM_HMAC_2);
	/* memory areas overlap if sizeof(host_id) < sizeof(tlv_hmac) */
	memmove(&buff[hi_location], &buff[location], sizeof(tlv_hmac));
	location = hi_location + eight_byte_align(sizeof(tlv_hmac));
    
	/* HIP signature */
	hiph->hdr_len = (location/8) - 1; 
	location +=  build_tlv_signature(hip_a->hi, buff, location, FALSE);

	hiph->hdr_len = (location/8) - 1;
	hiph->checksum = 0;
	hiph->checksum = checksum_packet(buff, src, dst);

	/* send the packet */
	log_(NORMT, "sending HIP_R2 packet (%d bytes)...\n", location);
	/* R2 packet is not scheduled for retrans., but saved for retrans. */

#ifdef HIP_I3
	if (OPT.use_i3)
     		return(send_i3(buff, location, &hiph->hit_rcvr, HIPA_SRC(hip_a), HIPA_DST(hip_a)));
	else
#endif	
     return(hip_send(buff, location, HIPA_SRC(hip_a), HIPA_DST(hip_a),
                        hip_a, TRUE, hip_a->peer_dst_port, hip_a->use_udp));
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
int hip_send_update(hip_assoc *hip_a, struct sockaddr *newaddr,
    struct sockaddr *dstaddr, int use_udp)
{
	struct sockaddr *src, *dst;
	hiphdr *hiph;
	__u8   buff[sizeof(hiphdr)             + 2*sizeof(tlv_locator) +
		    sizeof(tlv_esp_info)       +
		    sizeof(tlv_seq)            + sizeof(tlv_ack) +
		    sizeof(tlv_diffie_hellman) + DH_MAX_LEN +
		    2*sizeof(tlv_echo)         + 3 + MAX_OPAQUE_SIZE +
		    sizeof(tlv_hmac)           + sizeof(tlv_hip_sig) +
		    sizeof(tlv_reg_request)    + sizeof (tlv_reg_response) +
		    MAX_SIG_SIZE + 2 ];
	int location=0, retransmit=FALSE;

	tlv_locator *loc;
	locator *loc1;
	tlv_esp_info *esp_info;
	tlv_seq *seq;
	tlv_ack *ack;
	tlv_echo *echo;
	__u32 *nonce, loc_spi;
	sockaddr_list *l, *l2;

	memset(buff, 0, sizeof(buff));

	/* for address verification, a new destination address will be given */
	src = HIPA_SRC(hip_a);
	dst = dstaddr ? dstaddr : HIPA_DST(hip_a);
	if (dst->sa_family != src->sa_family) {
		l2 = NULL;
		for (l = my_addr_head; l; l = l->next) {
			if (l->addr.ss_family != dst->sa_family)
				continue;
			if (!l2) l2 = l; /* save first address in same family */
			if (l->preferred)
				break;
		}
		/* use the preferred address or first one of this family */
		src = l ? SA(&l->addr) : ( l2 ? SA(&l2->addr) : src);
	}

	/* build the HIP header */
	hiph = (hiphdr*) buff;
	hiph->nxt_hdr = IPPROTO_NONE;
	hiph->hdr_len = 0;
	hiph->packet_type = UPDATE;
	hiph->version = HIP_PROTO_VER;
	hiph->res = HIP_RES_SHIM6_BITS;
	hiph->control = 0;
	hiph->checksum = 0;
	memcpy(&hiph->hit_sndr, hip_a->hi->hit, sizeof(hip_hit));
	memcpy(&hiph->hit_rcvr, hip_a->peer_hi->hit, sizeof(hip_hit));
	location = sizeof(hiphdr);

	/* set control bits */
	hiph->control = htons(hiph->control);

	/* 
	 * Add ESP_INFO and SEQ parameters when there is a new_spi in
	 * hip_a->rekey; also, rekey->keymat_index should be set.
	 */
	if (newaddr ||
	    (hip_a->rekey && hip_a->rekey->new_spi && !hip_a->rekey->acked)) {
		/* ESP_INFO */
		esp_info = (tlv_esp_info*) &buff[location];
		esp_info->type = htons(PARAM_ESP_INFO);
		esp_info->length = htons(sizeof(tlv_esp_info) - 4);
		esp_info->reserved = 0;
		esp_info->old_spi = htonl(hip_a->spi_in);
		if (hip_a->rekey) { /* rekeying */
			esp_info->keymat_index = 
					htons(hip_a->rekey->keymat_index);
			esp_info->new_spi = htonl(hip_a->rekey->new_spi);
		} else { /* gratuitous */
			esp_info->keymat_index = htons(hip_a->keymat_index);
			esp_info->new_spi = esp_info->old_spi;
		}
		location += sizeof(tlv_esp_info);
		location = eight_byte_align(location);
	}

	/* 
	 * add LOCATOR parameter when supplied with readdressing info
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
		loc_spi = htonl(hip_a->rekey ? 	hip_a->rekey->new_spi :
						hip_a->spi_in);
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

	if (hip_a->rekey && !hip_a->rekey->acked &&
	    (hip_a->rekey->update_id > 0)) {	
		/* SEQ */
		seq = (tlv_seq*) &buff[location];
		seq->type = htons(PARAM_SEQ);
		seq->length = htons(sizeof(tlv_seq) - 4);
		/*	increment this sometime before */
		seq->update_id = htonl(hip_a->rekey->update_id);
		location += sizeof(tlv_seq);
		location = eight_byte_align(location);
		/* for now we only retransmit if including a SEQ,
		 * which needs to be acked; retransmitted packet
		 * should be removed once ACK is received */
		retransmit = TRUE;
	}
	
	/* 
	 * Add an ACK parameter when there is an unacknowledged
	 * update_id in hip_a->peer_rekey
	 */
	if (hip_a->peer_rekey &&
	    (!hip_a->peer_rekey->acked) &&
	    (hip_a->peer_rekey->update_id > 0)) {
		ack = (tlv_ack*)  &buff[location];
		ack->type = htons(PARAM_ACK);
		ack->length = htons(sizeof(tlv_ack) - 4);
		ack->peer_update_id = htonl(hip_a->peer_rekey->update_id);
		hip_a->peer_rekey->acked = TRUE;
		location += sizeof(tlv_ack);
		location = eight_byte_align(location);
	}
	
	/* Add a Diffie-Hellman parameter when present
	 * in hip_a->rekey->dh
	 */
	if (hip_a->rekey && hip_a->rekey->dh) {
		location += build_tlv_dh(&buff[location],
		    hip_a->rekey->dh_group_id, hip_a->rekey->dh, OPT.debug);
	}

	/* Deal with registrations */
	
	if (add_reg_info) {
                        add_reg_info = FALSE;
                        location += build_tlv_reg_info(buff, location);
		}

	if (hip_a->reg_offered)
		location += build_tlv_reg_req(buff,location,
			hip_a->reg_offered);

	if (hip_a->reg_requested) {
		location += build_tlv_reg_resp(buff, location,
			hip_a->reg_requested);
		location += build_tlv_reg_failed(buff, location,
			hip_a->reg_requested);
	}

#ifdef UNUSED
	/* XXX this adds a non-critical echo request inside the signature
	 *     for IETF61 testing with HIPL, this was moved outside
	 */
	/* Add a nonce in an echo request parameter when
	 * doing address verification
	 */
	if (dstaddr) {
		echo = (tlv_echo*) &buff[location];
		echo->type = htons(PARAM_ECHO_REQUEST);
		echo->length = htons(4); /* 4-byte nonce */
		nonce = (__u32*) echo->opaque_data;
		for (l = &hip_a->peer_hi->addrs; l; l=l->next) {
			if ((l->addr.ss_family == dstaddr->sa_family) &&
			    (!memcmp(SA2IP(&l->addr), SA2IP(dstaddr),
				     SAIPLEN(dstaddr))) )
				break;
		}
		if (!l) {
			log_(WARN, "Could not find nonce for address %s.\n",
			    logaddr(dstaddr));
			return(-1);
		}
		*nonce = l->nonce;
		location += 8;
	}
#endif
	
	/* add any echo response (included under signature) */
	if (hip_a->opaque && !hip_a->opaque->opaque_nosig) {
		location += build_tlv_echo_response(PARAM_ECHO_RESPONSE,
				hip_a->opaque->opaque_len,
				&buff[location],
				hip_a->opaque->opaque_data);
		location = eight_byte_align(location);
		free(hip_a->opaque); /* no longer needed */
		hip_a->opaque = NULL;
	}
	
	hiph->hdr_len = (location/8) - 1;
	
	/* HMAC */
	hiph->hdr_len = (location/8) - 1; 
	location += build_tlv_hmac(hip_a, buff, location, PARAM_HMAC);

	/* HIP signature */
	hiph->hdr_len = (location/8) - 1; 
	location += build_tlv_signature(hip_a->hi, buff, location, FALSE);

	/* Add a nonce in an echo request parameter when
	 * doing address verification (after signature)
	 *  (for IETF61 testing with HIPL, this was moved outside of sig)
	 */
	if (dstaddr) {
		echo = (tlv_echo*) &buff[location];
		echo->type = htons(PARAM_ECHO_REQUEST_NOSIG);
		echo->length = htons(4); /* 4-byte nonce */
		nonce = (__u32*) echo->opaque_data;
		for (l = &hip_a->peer_hi->addrs; l; l=l->next) {
			if ((l->addr.ss_family == dstaddr->sa_family) &&
			    (!memcmp(SA2IP(&l->addr), SA2IP(dstaddr),
				     SAIPLEN(dstaddr))) )
				break;
		}
		if (!l) {
			log_(WARN, "Could not find nonce for address %s.\n",
			    logaddr(dstaddr));
			return(-1);
		}
		*nonce = l->nonce;
		location += 8;
		location = eight_byte_align(location);
	}
	
	/* add any echo response (after signature) */
	if (hip_a->opaque && hip_a->opaque->opaque_nosig) {
		location += build_tlv_echo_response(PARAM_ECHO_RESPONSE_NOSIG,
				hip_a->opaque->opaque_len,
				&buff[location],
				hip_a->opaque->opaque_data);
		location = eight_byte_align(location);
		free(hip_a->opaque);
		hip_a->opaque = NULL;
	}

	hiph->hdr_len = (location/8) - 1;
	hiph->checksum = 0;
	hiph->checksum = checksum_packet(buff, src, dst);

	/* send the packet */
	log_(NORMT, "sending UPDATE packet (%d bytes)...\n", location);

	/* Retransmit UPDATEs unless it contains a LOCATOR or address check */
	log_(NORM, "Sending UPDATE packet to dst : %s \n", logaddr(dst));
	hip_check_bind(src, use_udp, HIP_UPDATE_BIND_CHECKS);
	return(hip_send(buff, location, src, dst, hip_a, retransmit, hip_a->peer_dst_port, use_udp));
}



/*
 *
 * function hip_send_update_proxy_ticket()
 * 
 * in:		hip_mr = HIP association between mobile node and mobile router
 * 		hip_a = HIP association between mobile node and peer node
 * 		keymat_index = index to key material delagated from mobile
 *			node to mobile router
 *
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Opens a socket and sends the UPDATE packet.
 *
 */
int hip_send_update_proxy_ticket(hip_assoc *hip_mr, hip_assoc *hip_a,
				int use_udp)
{
	struct sockaddr *src, *dst;
	hiphdr *hiph;
	__u8   buff[sizeof(hiphdr)             + sizeof(tlv_proxy_ticket) +
		    sizeof(tlv_hmac)           + sizeof(tlv_hip_sig) +
		    MAX_SIG_SIZE + 2 ];
	int location=0, retransmit=FALSE;
	unsigned int hmac_md_len, length_to_hmac;
	unsigned char hmac_md[EVP_MAX_MD_SIZE];

	tlv_proxy_ticket *ticket;

	memset(buff, 0, sizeof(buff));

	src = HIPA_SRC(hip_mr);
	dst = HIPA_DST(hip_mr);

	/* build the HIP header */
	hiph = (hiphdr*) buff;
	hiph->nxt_hdr = IPPROTO_NONE;
	hiph->hdr_len = 0;
	hiph->packet_type = UPDATE;
	hiph->version = HIP_PROTO_VER;
	hiph->res = HIP_RES_SHIM6_BITS;
	hiph->control = 0;
	hiph->checksum = 0;
	memcpy(&hiph->hit_sndr, hip_mr->hi->hit, sizeof(hip_hit));
	memcpy(&hiph->hit_rcvr, hip_mr->peer_hi->hit, sizeof(hip_hit));
	location = sizeof(hiphdr);

	/* set control bits */
	hiph->control = htons(hiph->control);

	/* PROXY_TICKET */
	ticket = (tlv_proxy_ticket *) &buff[location];
	ticket->type = htons(PARAM_PROXY_TICKET);
	ticket->length = htons(sizeof(tlv_proxy_ticket) - 4);
	memcpy(&ticket->mn_hit, hip_a->hi->hit, sizeof(hip_hit));
	memcpy(&ticket->peer_hit, hip_a->peer_hi->hit, sizeof(hip_hit));
	ticket->hmac_key_index = htons(hip_a->mr_keymat_index);
	ticket->transform_type = htons((__u16)hip_a->mr_key.type);
	ticket->action = 0;
	ticket->lifetime = 0;
	memcpy(ticket->hmac_key, hip_a->mr_key.key, sizeof(ticket->hmac_key));

	/* compute HMAC over authenication part of ticket */
	memset(hmac_md, 0, sizeof(hmac_md));
	hmac_md_len = EVP_MAX_MD_SIZE;
	length_to_hmac = sizeof(ticket->hmac_key_index) +
			 sizeof(ticket->transform_type) +
			 sizeof(ticket->action) +
			 sizeof(ticket->lifetime);
	
	switch (hip_a->hip_transform) {
	case ESP_AES_CBC_HMAC_SHA1:
	case ESP_3DES_CBC_HMAC_SHA1:
	case ESP_BLOWFISH_CBC_HMAC_SHA1:
	case ESP_NULL_HMAC_SHA1:
		HMAC(	EVP_sha1(), 
			get_key(hip_a, HIP_INTEGRITY, FALSE),
			auth_key_len(hip_a->hip_transform),
			(__u8 *)&ticket->hmac_key_index, length_to_hmac,
			hmac_md, &hmac_md_len  );
		break;		
	case ESP_3DES_CBC_HMAC_MD5:
	case ESP_NULL_HMAC_MD5:
		HMAC(	EVP_md5(), 
			get_key(hip_a, HIP_INTEGRITY, FALSE),
			auth_key_len(hip_a->hip_transform),
			(__u8 *)&ticket->hmac_key_index, length_to_hmac,
			hmac_md, &hmac_md_len  );
		break;
	default:
		return(0);
		break;
	}

	/* get lower 160-bits of HMAC computation */
	memcpy( ticket->hmac, 
		&hmac_md[hmac_md_len-sizeof(ticket->hmac)],
		sizeof(ticket->hmac));

	location += sizeof(tlv_proxy_ticket);
	location = eight_byte_align(location);

	/* HMAC */
	hiph->hdr_len = (location/8) - 1; 
	location += build_tlv_hmac(hip_mr, buff, location, PARAM_HMAC);

	/* HIP signature */
	hiph->hdr_len = (location/8) - 1; 
	location += build_tlv_signature(hip_mr->hi, buff, location, FALSE);

	hiph->hdr_len = (location/8) - 1;
	hiph->checksum = 0;
	hiph->checksum = checksum_packet(buff, src, dst);

	/* send the packet */
	log_(NORMT, "sending UPDATE packet (%d bytes)...\n", location);

	/* Retransmit UPDATEs unless it contains a LOCATOR or address check */
	log_(NORM, "Sending UPDATE packet to mobile router : %s \n",
		logaddr(dst));
	hip_check_bind(src, use_udp, HIP_UPDATE_BIND_CHECKS);
	return(hip_send(buff, location, src, dst, hip_mr, retransmit,
			hip_mr->peer_dst_port, use_udp));
}


/*
 *
 * function hip_send_close()
 * 
 * in:		hip_a = HIP association containing valid source/destination
 * 			addresses, HITs, SPIs, key material, pub key
 * 		send_ack   = send CLOSE_ACK if true, CLOSE otherwise
 * 		
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Opens a socket and sends the Second Responder packet.
 *
 */
int hip_send_close(hip_assoc *hip_a, int send_ack)
{
	struct sockaddr *src, *dst;
	hiphdr *hiph;
	__u8   buff[sizeof(hiphdr)             + 
		    sizeof(tlv_echo)           + 3 + MAX_OPAQUE_SIZE +
		    sizeof(tlv_hmac)           + sizeof(tlv_hip_sig) + 
		    MAX_SIG_SIZE + 2 ];
	
	int location=0;
	tlv_echo *echo;
	__u16 nonce_len;

	memset(buff, 0, sizeof(buff));

	src = HIPA_SRC(hip_a);
	dst = HIPA_DST(hip_a);

	/* build the HIP header */
	hiph = (hiphdr*) buff;
	hiph->nxt_hdr = IPPROTO_NONE;
	hiph->hdr_len = 0;
	hiph->packet_type = (send_ack) ? CLOSE_ACK : CLOSE;
	hiph->version = HIP_PROTO_VER;
	hiph->res = HIP_RES_SHIM6_BITS;
	hiph->control = 0;
	hiph->checksum = 0;
	memcpy(&hiph->hit_sndr, hip_a->hi->hit, sizeof(hip_hit));
	memcpy(&hiph->hit_rcvr, hip_a->peer_hi->hit, sizeof(hip_hit));
	location = sizeof(hiphdr);

	/* set control bits */
	hiph->control = htons(hiph->control);

	if (send_ack && !hip_a->opaque) {
		log_(ERR, "CLOSE_ACK requested with no opaque data!\n");
		return(-1);
	}

	if (send_ack) { /* ECHO_RESPONSE */
		location += build_tlv_echo_response(PARAM_ECHO_RESPONSE,
				hip_a->opaque->opaque_len,
				&buff[location],
				hip_a->opaque->opaque_data);
		location = eight_byte_align(location);
		free(hip_a->opaque);
		hip_a->opaque = NULL;
	} else {	/* ECHO_REQUEST */
		/* generate a 4-byte nonce and save it to hip_a->opaque */
		if (hip_a->opaque) /* this should not be set */
			free(hip_a->opaque);
		hip_a->opaque = (struct opaque_entry*) 
			malloc(sizeof(struct opaque_entry));
		if (hip_a->opaque == NULL) {
			log_(WARN, "Malloc err: ECHO_REQUEST\n");
			return(-1);
		}
		nonce_len = sizeof(__u32);
		hip_a->opaque->opaque_len = nonce_len;
		RAND_bytes(hip_a->opaque->opaque_data, nonce_len);
		/* add the nonce to the packet */
		echo = (tlv_echo*) &buff[location];
		echo->type = htons(PARAM_ECHO_REQUEST);
		echo->length = htons(nonce_len);
		memcpy(echo->opaque_data, hip_a->opaque->opaque_data,nonce_len);
		location += 4 + nonce_len;
	}

	/* HMAC */
	hiph->hdr_len = (location/8) - 1; 
	location += build_tlv_hmac(hip_a, buff, location, PARAM_HMAC);
    
	/* HIP signature */
	hiph->hdr_len = (location/8) - 1; 
	location +=  build_tlv_signature(hip_a->hi, buff, location, FALSE);

	hiph->hdr_len = (location/8) - 1;
	hiph->checksum = 0;
	hiph->checksum = checksum_packet(buff, src, dst);

	/* send the packet */
	log_(NORMT, "sending CLOSE%s packet (%d bytes)...\n",
			send_ack ? "_ACK":"", location);
	/* CLOSE_ACK packet is not scheduled for retransmission */
#ifdef __MACOSX__
        if(hip_a->ipfw_rule > 0) {
                del_divert_rule(hip_a->ipfw_rule);
                hip_a->ipfw_rule = 0;
        }
#endif
	return(hip_send(buff, location, HIPA_SRC(hip_a), HIPA_DST(hip_a),
			hip_a, !send_ack, hip_a->peer_dst_port, hip_a->use_udp));
}


/*
 *
 * function hip_send_notify()
 * 
 * in:		hip_a = HIP association containing valid source/destination
 * 			addresses, HITs, SPIs, key material, pub key
 * 		
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Opens a socket and sends the HIP NOTIFY packet.
 *
 */
int hip_send_notify(hip_assoc *hip_a, int code, __u8 *data, int data_len)
{
	struct sockaddr *src, *dst;
	hiphdr *hiph;
	__u8   buff[sizeof(hiphdr)            + sizeof(tlv_notify) +
		    sizeof(tlv_host_id)       + 1 + DSA_PRIV +
		    3*(MAX_HI_BITS/8)         + MAX_HI_NAMESIZE +
		    sizeof(tlv_hip_sig)       + MAX_SIG_SIZE + 2 ];
	int location=0;
	tlv_notify *notify;
	char msg[32];

	/* silent NO-OP if NOTIFY has been disabled */
	if (HCNF.disable_notify)
		return(0);
	
	memset(buff, 0, sizeof(buff));

	src = HIPA_SRC(hip_a);
	dst = HIPA_DST(hip_a);

	/* build the HIP header */
	hiph = (hiphdr*) buff;
	hiph->nxt_hdr = IPPROTO_NONE;
	hiph->hdr_len = 0;
	hiph->packet_type = NOTIFY;
	hiph->version = HIP_PROTO_VER;
	hiph->res = HIP_RES_SHIM6_BITS;
	hiph->control = 0;
	hiph->checksum = 0;
	memcpy(&hiph->hit_sndr, hip_a->hi->hit, sizeof(hip_hit));
	memcpy(&hiph->hit_rcvr, hip_a->peer_hi->hit, sizeof(hip_hit));
	location = sizeof(hiphdr);

	/* set control bits */
	hiph->control = htons(hiph->control);
	
	/* NOTIFY */
	notify = (tlv_notify*) &buff[location];
	notify->type = htons(PARAM_NOTIFY);
	notify->length = htons(sizeof(tlv_notify) - 4);
	notify->reserved = 0;
	notify->notify_type = htons((__u16)code);
	location += sizeof(notify);
	if (data_len > 0) {
		memcpy(notify->notify_data, data, data_len);
		notify->length = htons((__u16)((sizeof(tlv_notify) - 4) + 
						data_len));
		location += data_len;
	}
	location = eight_byte_align(location);
    
	/* HIP signature */
	hiph->hdr_len = (location/8) - 1; 
	location +=  build_tlv_signature(hip_a->hi, buff, location, FALSE);

	hiph->hdr_len = (location/8) - 1;
	hiph->checksum = 0;
	hiph->checksum = checksum_packet(buff, src, dst);

	/* send the packet */
	sprintf(msg, "Sent NOTIFY (code %d)", code);
	log_hipa_fromto(QOUT, msg, hip_a, FALSE, TRUE);
	/* NOTIFY packet is not scheduled for retransmission */
	return(hip_send(buff, location, HIPA_SRC(hip_a), HIPA_DST(hip_a),
			NULL, FALSE, hip_a->peer_dst_port, hip_a->use_udp));
}

/*
 * function hip_send()
 * 
 * in:		data = pointer to data to send
 * 		len = length of data
 * 		hip_a = hip assoc for getting src, dst addresses and for
 * 		        storing packet for retransmission
 * 		retransmit = flag T/F to store packet in rexmt_cache
 * 
 * out:		returns bytes sent
 * 
 * Creates socket, binds, connects, and does sendmsg(); 
 * packets are saved when sent so they can be retransmitted.
 *
 */
int hip_send(__u8 *data, int len, struct sockaddr* src, struct sockaddr* dst,
	     hip_assoc *hip_a, int retransmit, __u16 dst_port, int use_udp)
{
	int s, flags, err=0;
	struct timeval time1;
	int out_len, do_retransmit=0;
	__u8 *out;
	udphdr *udph;
#ifndef __WIN32__
	/* on win32 we use send(), otherwise use sendmsg() */
	struct msghdr msg;
	struct iovec iov;
#endif /* __WIN32__ */
	
	if ((hip_a != NULL) && (!OPT.no_retransmit && retransmit))
		do_retransmit = 1;

	out_len = len;
	if (use_udp)
		out_len += sizeof(udphdr);

	/* malloc and memcpy the supplied data */
	if (use_udp || do_retransmit) {
		out = malloc(out_len);
		if (!out) {
			log_(WARN, "hip_send() malloc error\n");
			return(-1);
		}
		memset(out, 0, out_len);
		if (use_udp) {	/* add the UDP header */
			udph = (udphdr*) out;
			udph->src_port = htons(HIP_UDP_PORT);
			udph->dst_port = htons(dst_port);
			udph->len = htons((__u16)out_len);
			memcpy(&out[sizeof(udphdr)], data, len);
			udph->checksum = 0;
			udph->checksum = checksum_udp_packet(out, src, dst);
		} else {	/* use supplied data with no headers */
			memcpy(out, data, len);
		}
	/* no malloc and memcpy needed */
	} else {
		out = data;
	}

#ifndef __WIN32__
	/* initialize IP message header */
	msg.msg_name = 0L;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = 0L;
	msg.msg_controllen = 0;
	iov.iov_len = out_len;
	iov.iov_base = out;
#endif /* __WIN32__ */

	s = socket(src->sa_family, SOCK_RAW, 
		   use_udp ? H_PROTO_UDP : H_PROTO_HIP);
	if (s < 0) {
		log_(WARN, "hip_send() socket() error: %s.\n", strerror(errno));
		err = -1;
		goto queue_retrans;
	}

	if (bind(s, src, SALEN(src)) < 0) {
		log_(WARN, "bind(%s) error: %s.\n", 
			logaddr(src), strerror(errno));
		err = -1;
		goto queue_retrans;
	}
	
	if (connect(s, dst, SALEN(dst)) < 0) {
		log_(WARN, "connect(%s) error: %s.\n", 
			logaddr(dst), strerror(errno));
		err = -1;
		goto queue_retrans;
	}

	log_(NORMT, "Sending HIP packet on %s socket\n",
		use_udp ? "UDP" : "RAW");

	flags = 0;
#ifndef __WIN32__
	if ((len = sendmsg(s, &msg, flags)) != out_len) {
		log_(WARN, "Sent unexpected length: %d", len);
	}
#else
	if (sendto(s, data, len, 0, dst, SALEN(dst)) < 0) {
		log_(WARN, "sendto(%s) error: %s.\n", 
			logaddr(dst), strerror(errno));
		err = -1;
	}
#endif

	/* queue packet for retransmission, even if there are errors */
queue_retrans:
	if (hip_a != NULL) /* XXX incorrect for RVS relaying */
		clear_retransmissions(hip_a);
	if (do_retransmit) { /* out buffer freed by hip_retransmit_wait...() */
		hip_a->rexmt_cache.packet = out;
		hip_a->rexmt_cache.len = out_len;
		gettimeofday(&time1, NULL);
		hip_a->rexmt_cache.xmit_time.tv_sec = time1.tv_sec;
		hip_a->rexmt_cache.xmit_time.tv_usec = time1.tv_usec;
		hip_a->rexmt_cache.retransmits = 0;
		memcpy(&hip_a->rexmt_cache.dst, dst, SALEN(dst));
	} else if (use_udp) { /* out bufer must be freed */
		free(out);
	}
	
	closesocket(s);

	if (err >= 0 && hip_a != NULL) {
		gettimeofday(&time1, NULL);
		hip_a->use_time_ka.tv_sec = time1.tv_sec;
		hip_a->use_time_ka.tv_usec = time1.tv_usec;
	}

	return ((err < 0) ? err : out_len);
}

/*
 * function hip_retransmit()
 * 
 * in:		hip_a = hip association
 * 		data = packet data
 * 		len = data length
 * 		src = source address to bind to
 * 		dst = destination address to send to
 *
 * out:		returns bytes sent if successful, -1 otherwise
 *
 * Retransmit a saved packet.
 */
int hip_retransmit(hip_assoc *hip_a, __u8 *data, int len,
		struct sockaddr *src, struct sockaddr *dst)
{
	int s, err;
	struct timeval now;
#ifndef __WIN32__
	struct msghdr msg;
	struct iovec iov;

	msg.msg_name = 0L;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = 0L;
	msg.msg_controllen = 0;
	iov.iov_len = len;
	iov.iov_base = data;
#endif
	if (!hip_a)
		return(-1);

	s = socket(src->sa_family, SOCK_RAW, 
		   hip_a->use_udp ? H_PROTO_UDP : H_PROTO_HIP);
	if (s < 0) {
		log_(WARN, "hip_retransmit() socket() error: %s.\n",
			strerror(errno));
		return(-1);
	}

	if (bind(s, src, SALEN(src)) < 0) {
		log_(WARN, "hip_retransmit() bind(%s) error: %s.\n",
			logaddr(src), strerror(errno));
		return(-1);
	}
	if (connect(s, dst, SALEN(dst)) < 0) {
		log_(WARN, "hip_retransmit() connect(%s) error: %s.\n", 
			logaddr(dst), strerror(errno));
		return(-1);
	}

	/* send the packet */
#ifndef __WIN32__
	if ((err = sendmsg(s, &msg, 0)) < 0) {
		log_(WARN, "hip_retransmit() sendmsg() error: %s",
			strerror(errno));
	}
#else
	if ((err = sendto(s, data, len, 0, dst, SALEN(dst))) < 0) {
		log_(WARN, "hip_retransmit() sendto() error: %s",
			strerror(errno));
	}
#endif
	closesocket(s);

	if (err >= 0 && hip_a != NULL) {
		gettimeofday(&now, NULL);
		hip_a->use_time_ka.tv_sec = now.tv_sec;
		hip_a->use_time_ka.tv_usec = now.tv_usec;
	}

	return(err);
}


#ifdef __UMH__
#ifdef __WIN32__
void udp_hip_keepalive (void *arg) {
#else
void *udp_hip_keepalive (void *arg) {
#endif /* __WIN32__ */
	int i, err;
	__u8 buff;
/*	udphdr *udph;
	__u8 *data; */
	struct timeval now;
	hip_assoc *hip_a;
	struct sockaddr_storage addr;

	printf("udp_hip_keepalive() thread started...\n");

/*	memset(buff,0,sizeof(buff));
	udph = (udphdr*) buff;
	data = &buff[sizeof(udphdr)];
	udph->src_port = htons(HIP_UDP_PORT);
	udph->len = htons((__u16) 9);
	udph->checksum = 0;
	data[0]=0xFF; */
	buff = 0xFF;

/*	//debug
	int delay_print_maxhipassoc = 0; */
	while (g_state == 0) {
		gettimeofday(&now, NULL);

		for (i=0; i < max_hip_assoc; i++) {
			hip_a = &(hip_assoc_table[i]);
			if (!hip_a) {
				printf ("Keepalive test : bad hip_a.\n");
				continue;
			}
			if (!hip_a->use_udp) {
				/* direct hip association without UDP */
				continue;
			}
			if (hip_a->state != ESTABLISHED && hip_a->state != R2_SENT) {
				continue;
			}
			if (hip_a->peer_dst_port == 0) {
				printf ("Keepalive test : hip_a peer_dst_port not defined.\n");
				continue;
			}
			if (hip_a->use_time_ka.tv_sec + HIP_KEEPALIVE_TIMEOUT < now.tv_sec) {
				/*udph->dst_port = htons (hip_a->peer_dst_port);*/
				memset (&addr, 0, sizeof(struct sockaddr_storage));
				memcpy (&addr, (struct sockaddr*)&hip_a->peer_hi->addrs.addr,
					sizeof(struct sockaddr_storage));
				if (((struct sockaddr*)&addr)->sa_family==AF_INET) {
					((struct sockaddr_in*) &addr)->sin_port = htons (hip_a->peer_dst_port);
				} else {
					((struct sockaddr_in6*) &addr)->sin6_port = htons (hip_a->peer_dst_port);
				}
				err = sendto(s_hip_udp, &buff, sizeof(buff), 0,
					(struct sockaddr*)&addr, SALEN(&addr));
				if (err < 0) {
					printf("Keepalive sendto() failed: %s\n", strerror(errno));
				} else {
					printf("HIP keepalive sent.\n");
					hip_a->use_time_ka.tv_sec = now.tv_sec;
					hip_a->use_time_ka.tv_usec = now.tv_usec;
				}
				/*udph->dst_port = 0;*/
			}
		}
/* //debug
		delay_print_maxhipassoc++;
		if (delay_print_maxhipassoc>10){
			printf ("MAX_HIP_ASSOC value: %u\n",max_hip_assoc);
			delay_print_maxhipassoc = 0;
		}
*/
		hip_sleep(1);
	}

	printf("udp_hip_keepalive() thread shutdown.\n");
#ifndef __WIN32__
	pthread_exit((void *) 0);
	return (NULL);
#endif /* __WIN32__ */
}
#endif /* __UMH__ */



/*
 * function hip_check_bind()
 *
 * in:		addr = pointer to address to bind
 * 		use_udp = UDP flag
 * 		num_attempts = number of times to try the bind() call
 *
 * out:		returns 0 if bind is successful, -1 otherwise
 *
 * Check if it is possible to bind() to an address.
 */
int hip_check_bind(struct sockaddr *src, int use_udp, int num_attempts)
{
	int i, s, ret=0;

	if (num_attempts == 0)
		return 0;

	if (use_udp) {
		s = socket(src->sa_family, SOCK_RAW, H_PROTO_UDP);
	} else {
		s = socket(src->sa_family, SOCK_RAW, H_PROTO_HIP);
	}

	for (i=0; i < num_attempts; i++) {
		if (bind(s, src, SALEN(src)) < 0) {
			ret = -1;
#ifdef __WIN32__
			Sleep(25); /* wait for address to become avail. */
#else
			usleep(25000); /* wait for address to become avail. */
#endif
		} else {
			ret = 0; /* bind successful */
			break;
		}
	}

#ifdef __WIN32__
	closesocket(s);
#else
	close(s);
#endif
	return(ret);
}



/*****************************************
 *        Resource Record Builders       *
 *****************************************/

/*
 * Fill in Diffie Hellman public key tlv, using the
 * context stored in hip_a->dh. hip_a->dh is intialized
 * when building the R1 prior to calling this function,
 * and when parsing the R1 for the DH in I2.
 * Returns the number of bytes that it advances.
 */
int build_tlv_dh(__u8 *data, __u8 group_id, DH *dh, int debug)
{
	tlv_diffie_hellman *d;
	unsigned char *bin;
	int len;

	if (dh == NULL) {
		log_(WARN, "No Diffie Hellman context for DH tlv.\n");
		return(0);
	}
	
	d = (tlv_diffie_hellman*) data;
	d->type = htons(PARAM_DIFFIE_HELLMAN);
	d->group_id =  group_id;
	
	/* put dh->pub_key into tlv */
	len = dhprime_len[group_id];
	bin = (unsigned char*) malloc(len);
	if (!bin) {
		log_(WARN, "malloc error - generating Diffie Hellman\n");
		return(0);
	}
	len = bn2bin_safe(dh->pub_key, bin, len);
	memcpy(d->pub, bin, len);
	
	d->pub_len = ntohs((__u16)len);
	d->length = htons((__u16)(3 + len)); /* group_id + pub */
	
#ifndef SMA_CRAWLER
	if (D_VERBOSE == debug) {
		log_(NORM, "Using DH public value of len %d: 0x", len);
		print_hex(bin, len);
		log_(NORM, "\n");
	}
#endif
	free(bin);

	len += 5; /* tlv hdr + group_id + pub */
	len = eight_byte_align(len);
	return(len);
}

/*
 * Returns number of bytes that it advances
 * Transforms is a pointer to an array of transforms to include.
 * Single is for specifying a single transform to use (i.e., in I2).
 */
int build_tlv_transform(__u8 *data, int type, __u16 transforms[], __u16 single)
{
	int i, len = 0;
	tlv_head *tlv;
	tlv_hip_transform *hip_trans;
	tlv_esp_transform *esp_trans;
	__u16 *transform_id;
    
	tlv = (tlv_head*) data;
	tlv->type = htons((__u16)type);
	len += 4; /* advance for type, length */
	if (type == PARAM_HIP_TRANSFORM) {
		hip_trans = (tlv_hip_transform*) data;
		transform_id = &hip_trans->transform_id;
	} else { /* PARAM_ESP_TRANSFORM */
		esp_trans = (tlv_esp_transform*) data;
		/* set E-bit here if using 64-bit sequence numbers */
		esp_trans->reserved = 0x0000;
		transform_id = &esp_trans->suite_id;
		len += 2;
	}
	if (single > 0) {
		*transform_id = htons(single);
		len += 2; 
	} else {
		for (i=0; (transforms[i] > 0) && (i < SUITE_ID_MAX); i++) {
			len += 2;
			*transform_id = htons(transforms[i]);
			transform_id++;
		}
	}
	tlv->length = htons((__u16)(len - 4));
	len = eight_byte_align(len);
	return(len);
}

int build_tlv_hostid_len(hi_node *hi, int use_hi_name)
{
	int hi_len = 0;
	
	switch(hi->algorithm_id) {
	case HI_ALG_DSA: 	/*       tlv + T + Q + P,G,Y */
		if (!hi->dsa) {
			log_(WARN, "No DSA context when building length!\n");
			return(0);
		}
		hi_len = sizeof(tlv_host_id) + 1 + DSA_PRIV + 3*hi->size;
		break;
	case HI_ALG_RSA:	/*       tlv + e_len,e + N */
		if (!hi->rsa) {
			log_(WARN, "No RSA context when building length!\n");
			return(0);
		}
		hi_len = sizeof(tlv_host_id) + 1 + BN_num_bytes(hi->rsa->e)
			+ RSA_size(hi->rsa);
		if (BN_num_bytes(hi->rsa->e) > 255)
			hi_len += 2;
		break;
	default:
		break;
	}
	
	/* use stored length instead of strlen(hi->name), because other
	 * implementations may count a trailing NULL */
	if (use_hi_name && (hi->name_len > 0))
		hi_len += hi->name_len;
	
	return(eight_byte_align(hi_len));
}

int build_tlv_hostid(__u8 *data, hi_node *hi, int use_hi_name)
{
	int len, di_len=0;
	__u32 hi_hdr;
	__u16 e_len;
	tlv_host_id *hostid;
	
	hostid = (tlv_host_id*) data;
	hostid->type = htons(PARAM_HOST_ID);
	hostid->hi_length = 0; /* set this later */
	if (use_hi_name && (hi->name_len > 0)) {
		/* 4 bits type + 12 bits length */
		di_len = hi->name_len;/* preserves any trailing NULL */
		hostid->di_type_length =  htons((__u16)((DIT_FQDN << 12) | 
							 di_len));
	} else {
		hostid->di_type_length = 0;
	}
	
	/* RDATA word(32): flags(16), proto(8), alg(8) */
	/* flags = 0x..01 - key is associated with non-zone entity, or host */
	hi_hdr = htonl(0x0202ff00 | hi->algorithm_id);
	memcpy(hostid->hi_hdr, &hi_hdr, 4);
	len = sizeof(tlv_host_id); /* 12 */
	
	switch (hi->algorithm_id) {
	case HI_ALG_DSA: /* RDATA word: flags(16), proto(8), alg(8) */
		data[len] = (__u8) (hi->size - 64)/8; /* T value (1 byte) */
		len++;
		len += bn2bin_safe(hi->dsa->q, &data[len], DSA_PRIV);
		len += bn2bin_safe(hi->dsa->p, &data[len], hi->size);
		len += bn2bin_safe(hi->dsa->g, &data[len], hi->size);
		len += bn2bin_safe(hi->dsa->pub_key, &data[len], hi->size);
		break;
	case HI_ALG_RSA:
		e_len = BN_num_bytes(hi->rsa->e);
		/* exponent length */
		if (e_len <= 255) {
			data[len] = (__u8) e_len;
			len++;
		} else {
			__u16 *p;
			data[len] = 0x0;
			len++;
			p = (__u16*) &data[len];
			*p = htons(e_len);
			len += 2;
		}
		/* public exponent */
		len += bn2bin_safe(hi->rsa->e, &data[len], e_len);
		/* public modulus */
		len += bn2bin_safe(hi->rsa->n, &data[len], RSA_size(hi->rsa));
		break;
	default:
		break;
	}

	/* HI length includes RDATA header (4) */
	hostid->hi_length = htons((__u16)(len - sizeof(tlv_host_id) + 4));
	/* Add FQDN (only when use_hi_name==TRUE) */
	if (di_len > 0) {
		sprintf((char *)&data[len], "%s", hi->name);
		len += di_len;
	}
	/* Subtract off 4 for Type, Length in TLV */
	hostid->length = htons((__u16)(len - 4));
	return(eight_byte_align(len));
}


int build_tlv_echo_response(__u16 type, __u16 length, __u8 *buff, __u8 *data)
{
	tlv_echo *echo;
	
	echo = (tlv_echo*) buff;
	echo->type = htons(type);
	echo->length = htons(length);
	memcpy(echo->opaque_data, data, length);

	return(4 + length);
}

int build_tlv_cert(__u8 *buff)
{
#ifndef SMA_CRAWLER
	return 0;
#else
	tlv_cert *cert;
        char data[MAX_CERT_LEN];
	__u16 cert_len;

	if(!HCNF.use_smartcard)
	  return 0;

	if(hipcfg_getLocalCertUrl(data, sizeof(data))!=0){
	   log_(NORM, "local certificate is not available.\n");
	   return 0;
        }

        cert_len = strlen(data);
	cert = (tlv_cert*) buff;
	cert->type = htons(PARAM_CERT);
	cert->length = htons(cert_len+4);
	cert->cert_count = htons(1);
	cert->cert_group = htons(1);
	cert->cert_id = htons(1); //sequence number for this certificate
	cert->cert_type = htons(3); // X509v3 URL in LDAP
	memcpy(cert->certificate, data, cert_len); //certificate URL

	return(eight_byte_align(4 + 4 + cert_len ));
#endif /* SMA_CRAWLER */
}

int build_tlv_signature(hi_node *hi, __u8 *data, int location, int R1)
{
	/* HIP sig */
	SHA_CTX c;
	unsigned char md[SHA_DIGEST_LENGTH];
	DSA_SIG *dsa_sig;
	tlv_hip_sig *sig;
	unsigned int sig_len;
	int err;

	if ((hi->algorithm_id == HI_ALG_DSA) && !hi->dsa) {
		log_(WARN, "No DSA context for building signature TLV.\n");
		return(0);
	} else if ((hi->algorithm_id == HI_ALG_RSA) && !hi->rsa) {
		log_(WARN, "No RSA context for building signature TLV.\n");
		return(0);
	}
		
	/* calculate SHA1 hash of the HIP message */
	SHA1_Init(&c);
	SHA1_Update(&c, data, location);
	SHA1_Final(md, &c);

	/* build tlv header */
	sig = (tlv_hip_sig*) &data[location];
	sig->type = htons((__u16)(R1 ?  PARAM_HIP_SIGNATURE_2 : 
					PARAM_HIP_SIGNATURE));
	sig->length = 0; /* set this later */
	sig->algorithm = hi->algorithm_id;


	switch(hi->algorithm_id) {
	case HI_ALG_DSA:	
		memset(sig->signature, 0, HIP_DSA_SIG_SIZE);
		sig->signature[0] = 8;
		/* calculate the DSA signature of the message hash */	
		dsa_sig = DSA_do_sign(md, SHA_DIGEST_LENGTH, hi->dsa);
		/* build signature from DSA_SIG struct */
		bn2bin_safe(dsa_sig->r, &sig->signature[1], 20);
		bn2bin_safe(dsa_sig->s, &sig->signature[21], 20);
		sig_len = 1 + 20 + 20;
		DSA_SIG_free(dsa_sig);
		break;
	case HI_ALG_RSA:
		/* assuming RSA_sign() uses PKCS1 - RFC 3110/2437
		 * hash = SHA1 ( data )
		 * prefix = 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 
		 * signature = ( 00 | FF* | 00 | prefix | hash) ** e (mod n)
		 */
		sig_len = RSA_size(hi->rsa);
		memset(sig->signature, 0, sig_len);
		err = RSA_sign(NID_sha1, md, SHA_DIGEST_LENGTH, sig->signature,
				&sig_len, hi->rsa);
		if (!err) {
			log_(WARN, "RSA_sign() error: %s",
			    ERR_error_string(ERR_get_error(), NULL));
		}
		break;
	default:
		break;
	}

	/* signature debugging */
	if (!R1 || (D_VERBOSE==OPT.debug_R1)) {
		log_(NORM, "SHA1: ");
		print_hex(md, SHA_DIGEST_LENGTH);
		log_(NORM, "\nSignature: ");
		print_hex(sig->signature, sig_len);
		log_(NORM, "\n");
	}

	/* algorithm + computed signature */
	sig->length = htons((__u16)(1 + sig_len)); 

	/* total byte length is 5 + sig size (sizeof(tlv_hip_sig) == 6) */
	return(eight_byte_align(sizeof(tlv_hip_sig) + sig_len - 1));
}

int build_tlv_hmac(hip_assoc *hip_a, __u8 *data, int location, int type)
{
	hiphdr *hiph;
	tlv_hmac *hmac;
	unsigned int hmac_md_len;
	unsigned char hmac_md[EVP_MAX_MD_SIZE];
	
	/* compute HMAC over message */
	hiph = (hiphdr*) data;
	memset(hmac_md, 0, sizeof(hmac_md));
	hmac_md_len = EVP_MAX_MD_SIZE;
	
	switch (hip_a->hip_transform) {
	case ESP_AES_CBC_HMAC_SHA1:
	case ESP_3DES_CBC_HMAC_SHA1:
	case ESP_BLOWFISH_CBC_HMAC_SHA1:
	case ESP_NULL_HMAC_SHA1:
		HMAC(	EVP_sha1(), 
			get_key(hip_a, HIP_INTEGRITY, FALSE),
			auth_key_len(hip_a->hip_transform),
			data, location,
			hmac_md, &hmac_md_len  );
		break;		
	case ESP_3DES_CBC_HMAC_MD5:
	case ESP_NULL_HMAC_MD5:
		HMAC(	EVP_md5(), 
			get_key(hip_a, HIP_INTEGRITY, FALSE),
			auth_key_len(hip_a->hip_transform),
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

int build_tlv_reg_info(__u8 *data, int location)
{
        tlv_reg_info *info;
	__u8 *reg_typep;
	int len = 0, i;

	if(HCNF.n_reg_types == 0)
		return 0;

        info = (tlv_reg_info*) &data[location];
	len += 4;
        info->type = htons(PARAM_REG_INFO);
	info->length = htons((__u16)(2+HCNF.n_reg_types));
	len += 2 + HCNF.n_reg_types;
        info->min_lifetime = HCNF.min_lifetime;
        info->max_lifetime = HCNF.max_lifetime;
	reg_typep = &(info->reg_type);
	for (i=0; i<HCNF.n_reg_types; i++) {
		*reg_typep = HCNF.reg_types[i];
		reg_typep++;
	}
        
	return(eight_byte_align(len));
}

int build_tlv_reg_req(__u8 *data, int location, struct reg_entry *reg_offered)
{
        double tmp;
	tlv_reg_request *req = (tlv_reg_request*) &data[location];
	__u8 *reg_typep = &(req->reg_type);
	__u8 requested_lifetime = reg_offered->max_lifetime;
	__u16 num = 0;
	struct reg_info *reg = reg_offered->regs;

	while (reg) {
		if (reg->state != REG_OFFERED  &&  reg->state != REG_CANCELLED)
			continue;
		if (reg->type == REG_RVS  &&  !OPT.rvs  && add_reg_request)
		{
			/* if reg_info received, reg_request added to I2 */
			/* if finished lifetime, add reg_request in update packet */
			/* reg_request parameter from a normal update, not failed registration */
			if (!repeat_reg)
			{
				*reg_typep = HCNF.reg_type;
			}
			/* if there is an error in the registration with a rvs, */
			/* we send the reg_request parameter with the new values */
			else
			{	
				repeat_reg = FALSE;
				*reg_typep = repeat_type;
			}
			if (reg->state == REG_CANCELLED) {
				requested_lifetime = 0;
				log_(NORM, "Cancelled registration type = %d\n",
					*reg_typep);
			} else if (reg->state == REG_OFFERED) {
				reg->state = REG_REQUESTED;
				requested_lifetime = reg_offered->max_lifetime;
				log_(NORM, "Requested registration type = %d\n",
					*reg_typep);
			}
			reg->requested_lifetime = requested_lifetime;
			add_reg_request = FALSE;
			num++;
			reg_typep++;
		} else if (reg->type == REG_MR  &&  OPT.mn) {
			*reg_typep = REG_MR;
			if (reg->state == REG_CANCELLED) {
				requested_lifetime = 0;
				log_(NORM,"Cancelling registration with "
					"Mobile Router\n");
			} else if (reg->state == REG_OFFERED) {
				reg->state = REG_REQUESTED;
				requested_lifetime = reg_offered->max_lifetime;
				log_(NORM,"Requesting registration with "
					"Mobile Router\n");
			}
			reg->requested_lifetime = requested_lifetime;
			num++;
			reg_typep++;
		}
		reg = reg->next;
	}
        
	if (num) {
		req->type = htons(PARAM_REG_REQUEST);
		num++;
		req->length = htons(num); /* lifetime + reg_types */
		req->lifetime = requested_lifetime;

		tmp = YLIFE(req->lifetime);
		tmp = pow(2, tmp);
		log_(NORM, "Requested lifetime = %d (%f seconds)\n",\
			req->lifetime, tmp);

		return(eight_byte_align(sizeof(tlv_reg_request)-2+num));
	} else {
		return 0;
	}
}

int build_tlv_reg_resp(__u8 *data, int location, struct reg_entry *reg_requested)
{
	double tmp;
	tlv_reg_response *resp = (tlv_reg_response *) &data[location];
	__u8 *reg_typep = &(resp->reg_type);
	__u8 granted_lifetime = 0;
	__u16 num = 0;
	struct reg_info *reg = reg_requested->regs;

	while (reg) {
		if (reg->state == REG_SEND_RESP) {
			reg->state = REG_GRANTED;
			*reg_typep = reg->type;
			granted_lifetime = reg->granted_lifetime;
			log_(NORM, "Requested type = %d ok\n", *reg_typep);
			reg_typep++;
			num++;
		} else if (reg->state == REG_SEND_CANCELLED) {
			reg->state = REG_CANCELLED;
			*reg_typep = reg->type;
			granted_lifetime = 0;
			log_(NORM, "Cancelled type = %d ok\n", *reg_typep);
			reg_typep++;
			num++;
		}
		reg = reg->next;
	}

	if (num) {
		resp->type = htons(PARAM_REG_RESPONSE);
		num++;
		resp->length = htons(num); /* lifetime + reg_types */
		resp->lifetime = granted_lifetime;

		tmp = YLIFE(resp->lifetime);
		tmp = pow(2, tmp);
		log_(NORM, "Registered lifetime = %d (%f seconds)\n",
			resp->lifetime, tmp);

		return (eight_byte_align(sizeof(tlv_reg_response)-2+num));
	} else {
		return 0;
	}
}

/* TODO: Need to add possiblity of different fail types */

int build_tlv_reg_failed(__u8 *data, int location, struct reg_entry *reg_requested)
{
	tlv_reg_failed *fail = (tlv_reg_failed*) &data[location];
	__u8 *reg_typep = &(fail->reg_type);
	__u8 failure_code = 1;
	__u16 num = 0;
	struct reg_info *reg = reg_requested->regs;

	while (reg) {
		if (reg->state == REG_SEND_FAILED) {
			reg->state = REG_FAILED;
			*reg_typep = reg->type;
			failure_code = reg->failure_code;
			log_(NORM, "Failed Registered type = %d\n", *reg_typep);
			reg_typep++;
			num++;
		}
		reg = reg->next;
	}

	if (num) {
		fail->type = htons(PARAM_REG_FAILED);
		num++;
		fail->length = htons(num); /* fail_type +reg_types */
		fail->fail_type = failure_code;
		return (eight_byte_align(sizeof(tlv_reg_failed)));
	} else {
		return 0;
	}
}

int build_tlv_reg_required()
{
      /* TBD */
        return (eight_byte_align(sizeof(tlv_reg_failed)));
}

int build_tlv_rvs_hmac(hip_assoc *hip_a, __u8 *data, int location, int type, int pos)
{
	hiphdr *hiph;
	tlv_rvs_hmac *rvs_hmac;
	unsigned int rvs_hmac_md_len;
	unsigned char rvs_hmac_md[EVP_MAX_MD_SIZE];
	/* compute HMAC over message */
	hiph = (hiphdr*) data;
	memset(rvs_hmac_md, 0, sizeof(rvs_hmac_md));
	rvs_hmac_md_len = EVP_MAX_MD_SIZE;

	if (!hip_a) {
		log_(WARN, "State not found for building RVS HMAC.\n");
		return(0);
	}
	
	switch (hip_a->hip_transform) {
	case ESP_AES_CBC_HMAC_SHA1:
	case ESP_3DES_CBC_HMAC_SHA1:
	case ESP_BLOWFISH_CBC_HMAC_SHA1:
	case ESP_NULL_HMAC_SHA1:
		HMAC(	EVP_sha1(), 
			get_key(hip_a, HIP_INTEGRITY, FALSE),
			auth_key_len(hip_a->hip_transform),
			data, location,
			rvs_hmac_md, &rvs_hmac_md_len  );
		break;		
	case ESP_3DES_CBC_HMAC_MD5:
	case ESP_NULL_HMAC_MD5:
		HMAC(	EVP_md5(), 
			get_key(hip_a, HIP_INTEGRITY, FALSE),
			auth_key_len(hip_a->hip_transform),
			data, location,
			rvs_hmac_md, &rvs_hmac_md_len  );
		break;
	default:
		return(0);
		break;
	}

	log_(NORM, "HMAC computed over %d bytes hdr length=%d\n ",
	    location, hiph->hdr_len);

	/* build tlv header */
	rvs_hmac = (tlv_rvs_hmac*)  &data[location];
	rvs_hmac->type = htons((__u16)type);
	rvs_hmac->length = htons(sizeof(tlv_rvs_hmac) - 4);
	
	/* get lower 160-bits of HMAC computation */
	memcpy( rvs_hmac->hmac, 
		&rvs_hmac_md[rvs_hmac_md_len-sizeof(rvs_hmac->hmac)],
		sizeof(rvs_hmac->hmac));

	return(eight_byte_align(sizeof(tlv_rvs_hmac)));
}

/* Create a new rekey structure in hip_a, taking into account keymat size
 * and whether or not peer initiated a rekey.
 */
int build_rekey(hip_assoc *hip_a)
{
	__u8 new_group_id = 0;
	dh_cache_entry *dh_entry;

	if (!hip_a)
		return(-1);
	if (hip_a->rekey) {
		log_(WARN,"build_rekey called with existing rekey structure\n");
		return(-1);
	}

	/* hip_a->rekey will be used in a new UPDATE
	 * keymat_index = index to use in ESP_INFO
	 * dh_group_id, dh = new DH key to send
	 */
	hip_a->rekey = malloc(sizeof(struct rekey_info));
	if (!hip_a->rekey) {
		log_(WARN, "build_rekey malloc() error\n");
		return(-1);
	}
	memset(hip_a->rekey, 0, sizeof(struct rekey_info));
	/* Check for peer-initiated rekeying parameters */
	if (hip_a->peer_rekey) {
		if (hip_a->peer_rekey->dh) {
			/* use peer-suggested group ID */
			new_group_id = hip_a->rekey->dh_group_id;
			hip_a->rekey->keymat_index = 0;
		} else { /* use peer-suggested keymat index */
			hip_a->rekey->keymat_index = 
				hip_a->peer_rekey->keymat_index;
		}
	} else {
		hip_a->rekey->keymat_index = hip_a->keymat_index;
	}

	/* Generate new DH if we were to run out of keymat material when 
	 * drawing 4 new ESP keys or if the proposed DH group is different */
	if (((hip_a->rekey->keymat_index + (4*HIP_KEY_SIZE)) > KEYMAT_SIZE) ||
	    (new_group_id && (new_group_id != hip_a->dh_group_id))) {
		log_(NORM, "Including a new DH key in UPDATE.\n");
		if (new_group_id==0)
			new_group_id = hip_a->dh_group_id;
		dh_entry = get_dh_entry(new_group_id, TRUE);
		dh_entry->ref_count++;
		hip_a->rekey->keymat_index = 0;
		hip_a->rekey->dh_group_id = new_group_id;
		hip_a->rekey->dh = dh_entry->dh;
	}

	gettimeofday(&hip_a->rekey->rk_time, NULL);
	hip_a->rekey->new_spi = get_next_spi(hip_a);
	hip_a->rekey->acked = FALSE;
	hip_a->rekey->update_id = ++hip_a->hi->update_id;

	return(0);
}

