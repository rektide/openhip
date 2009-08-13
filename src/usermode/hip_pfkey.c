/*
 * Host Identity Protocol
 * Copyright (C) 2004-06 the Boeing Company
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
 *  hip_pfkey.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * User-mode minimal PFKEYv2 implementation.
 *
 */

#include <stdio.h>		/* printf() */
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <win32/types.h>
#else
#include <unistd.h>
#include <pthread.h>		/* phread_exit() */
#endif
#include <string.h>		/* strerror() */
#include <errno.h>		/* errno */
#include <hip/hip_types.h>
#include <hip/hip_service.h>
#include <hip/hip_sadb.h>		/* access to SADB */
#include <win32/pfkeyv2.h>
#ifdef SMA_CRAWLER
#include <utime.h>
#endif

/*
 * Globals
 */
int pfkeysp[2] = {-1, -1};
static int pfk_seqno=0;
#define PFKEY_UNIT64(a) ((a) >> 3)
#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))

/* 
 * Local function declarations
 */
#ifdef __WIN32__
void hip_pfkey(void *arg);
#else
void *hip_pfkey(void *arg);
#endif
int pfkey_handle_getspi(int sock, char *data, int len);
int pfkey_handle_add(int sock, char *data, int len);
int pfkey_handle_delete(int sock, char *data, int len);
int pfkey_handle_register(int sock, char *data, int len);
int pfkey_handle_get(int sock, char *data, int len);
int pfkey_handle_spdadd(int sock, char *data, int len);
int pfkey_handle_spddelete(int sock, char *data, int len);
int pfkey_handle_readdress(int sock, char *data, int len);
int pfkey_handle_acquire(char *data, int len);
int pfkey_send_acquire(struct sockaddr *target);
int pfkey_send_hip_packet(char *data, int len);
extern int get_preferred_lsi(struct sockaddr *lsi);

/*
 * hip_pfkey()
 *
 * The PFKEYv2 listener thread, that handles PF_KEY_V2 messages
 * in lieu of the Linux kernel.
 */
#ifdef __WIN32__
void hip_pfkey(void *arg)
#else
void *hip_pfkey(void *arg)
#endif
{
	int len, err;
	fd_set fd;
	struct timeval timeout;
	char buff[1024];
	struct sadb_msg *msg;

#ifdef SMA_CRAWLER
        time_t last_time, now_time;
 
        last_time = time(NULL);
        printf("hip_pfkey() thread (tid %d pid %d) started...\n",
                        (unsigned)pthread_self(), getpid());
#else
	printf("hip_pfkey() thread started...\n");
#endif
#ifdef __MACOSX__
	if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNSPEC, pfkeysp)) {
#else
	if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, pfkeysp)) {
#endif
		printf("hip_pfkey() - socketpair() failed: %s\n", 
		    strerror(errno));
		fflush(stdout);
#ifdef __WIN32__
		return;
#else
		return NULL;
#endif
	}

	while(g_state == 0) {
		/* periodic select loop */
		FD_ZERO(&fd);
		FD_SET((unsigned)pfkeysp[0], &fd);
#ifdef __MACOSX__
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
#else
		timeout.tv_sec = 0;
		timeout.tv_usec = 1000000;
#endif
#ifdef SMA_CRAWLER
                now_time = time(NULL);
                if (now_time - last_time > 60) {
                        printf("hip_pfkey() heartbeat\n");
                        last_time = now_time;
                        utime("/usr/local/etc/hip/heartbeat_hip_pfkey", NULL);
                }
#endif
		if ((err = select(pfkeysp[0]+1, &fd, NULL, NULL, &timeout))< 0){
			if (errno == EINTR)
				continue;
			printf("hip_pfkey(): select() error\n");
		} else if (err == 0) {
			/* idle cycle */
			continue;
		}

		/* pfkey data on socket */
#ifdef __WIN32__
		if ((len = recv(pfkeysp[0], buff, sizeof(buff), 0)) < 0) {
			if (errno == EINTR)
				continue;
			printf("hip_pfkey(): read() failed\n");
			fflush(stdout);
			return;
		}
#else
		if ((len = read(pfkeysp[0], buff, sizeof(buff))) < 0) {
			if (errno == EINTR)
				continue;
			printf("hip_pfkey(): read() failed\n");
			return NULL;
		}
#endif
		msg = (struct sadb_msg*) buff;
		if (msg->sadb_msg_version != PF_KEY_V2)
			continue;
		switch (msg->sadb_msg_type) {
		case SADB_GETSPI:
			pfkey_handle_getspi(pfkeysp[0], buff, len);
			break;
		case SADB_ADD:
			pfkey_handle_add(pfkeysp[0], buff, len);
			break;
		case SADB_DELETE:
			pfkey_handle_delete(pfkeysp[0], buff, len);
			break;
		case SADB_GET:
			pfkey_handle_get(pfkeysp[0], buff, len);
			break;
		case SADB_REGISTER:
			pfkey_handle_register(pfkeysp[0], buff, len);
			break;
		case SADB_X_SPDADD:
			pfkey_handle_spdadd(pfkeysp[0], buff, len);
			break;
		case SADB_X_SPDDELETE:
			pfkey_handle_spddelete(pfkeysp[0], buff, len);
			break;
		case SADB_READDRESS:
			pfkey_handle_readdress(pfkeysp[0], buff, len);
			break;
		case SADB_HIP_ACQUIRE:
			if (pfkey_handle_acquire(buff, len) < 0)
				printf("*** pfkey: Error with HIP acquire -- " \
					" ESP problems likely.\n");
			break;
		default:
			break;
		}
	}

	printf("hip_pfkey() thread shutdown.\n");
	fflush(stdout);
#ifndef __WIN32__
	pthread_exit((void *) 0);
	return(NULL);
#endif
}

/*
 * pfkey_handle_getspi()
 *
 * Expects a spirange with min == max, check if SPI is already in use.
 * Note that this differs from RFC 2367 in that no LARVAL security association
 * is generated, so do not follow this with a SADB_DELETE message.
 */
int pfkey_handle_getspi(int sock, char *data, int len)
{
	int msg_length, location, ext_len;
	struct sadb_msg *msg;
	struct sadb_ext *ext;
	struct sadb_spirange *spirange;
	__u32 spi = 0;
	
	msg = (struct sadb_msg*) data;
	
	msg_length = msg->sadb_msg_len * sizeof(__u64);
	location = sizeof(struct sadb_msg);
	while (location < msg_length) {
		ext = (struct sadb_ext*) &data[location];
		ext_len = ext->sadb_ext_len * sizeof(__u64);
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SPIRANGE:
			spirange = (struct sadb_spirange*) ext;
			spi = spirange->sadb_spirange_min;
			break;
		default:
			break;
		}
		location += ext_len;
	}

	if (!spi) {
		msg->sadb_msg_errno = -1;
	} else if (hip_sadb_lookup_spi(spi)) {
		msg->sadb_msg_errno = -EEXIST;
	} else {
		msg->sadb_msg_errno = 0;
	}

#ifdef __WIN32__
	send(sock, data, len, 0);
#else
	if (write(sock, data, len) != len)
		return(-1);
#endif
	return(0);
}

/*
 * pfkey_handle_add()
 *
 * Adds an SA to the SADB.
 */
int pfkey_handle_add(int sock, char *data, int len)
{
	__u32 type, spi, e_type, e_keylen, a_type, a_keylen, lifetime;
	int err, location, msg_length, ext_len;
	struct sockaddr *src, *dst;
	struct sockaddr *inner_src, *inner_dst;
	__u32 mode;
	__u16 dst_port;

	__u8 *a_key, *e_key;
	__u16 hitmagic;
	int is_src=0, addr_len=0;
	
	struct sadb_msg *msg;
	struct sadb_ext *ext;
	struct sadb_sa *sa;
	struct sadb_lifetime *life;
	struct sadb_address *addr;
	struct sadb_key *key;
	struct sadb_ident *ident;
	struct sadb_x_sa2 *x_sa2;
	struct sadb_x_nat_t_port *natt_port;

	type = spi = 0;
	e_type = e_keylen = 0;
	a_type = a_keylen = 0;
	lifetime = 0;
	hitmagic = 0;
	src = dst = NULL;
	inner_src = inner_dst = NULL;
	mode = 0;
	dst_port = 0;
	a_key = e_key = NULL;
	
	msg = (struct sadb_msg*) data;
	/* <base, SA, (lifetime(HS),) address(SD), (address(P),), 
			 	key(AE), (identity(SD),), (sensitivity)> */
	msg_length = msg->sadb_msg_len * sizeof(__u64);
	location = sizeof(struct sadb_msg);
	while (location < msg_length) {
		ext = (struct sadb_ext*) &data[location];
		ext_len = ext->sadb_ext_len * sizeof(__u64);
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			sa = (struct sadb_sa*) ext;
			spi = ntohl(sa->sadb_sa_spi);
			a_type = sa->sadb_sa_auth;
			e_type = sa->sadb_sa_encrypt;
			break;
		case SADB_EXT_LIFETIME_HARD:
			life = (struct sadb_lifetime*) ext;
			lifetime = (__u32)life->sadb_lifetime_addtime;
			break;
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_SOFT:
			break;
		case SADB_EXT_ADDRESS_SRC:
			is_src = 1;
		case SADB_EXT_ADDRESS_DST:
			addr = (struct sadb_address*) ext;
			addr_len = addr->sadb_address_prefixlen;
			addr++;
			if (is_src) src = (struct sockaddr*)addr;
			else dst = (struct sockaddr*)addr;
			is_src = 0;
			break;
		case SADB_EXT_IDENTITY_SRC:
			is_src = 1;
		case SADB_EXT_IDENTITY_DST:
			ident = (struct sadb_ident*) ext;
			addr_len = ident->sadb_ident_len;
			ident++;
			if (is_src) inner_src = (struct sockaddr*)ident;
			else inner_dst = (struct sockaddr*)ident;
			is_src = 0;
			break;
		case SADB_X_EXT_SA2:
			x_sa2 = (struct sadb_x_sa2*) ext;
			mode = (__u32) x_sa2->sadb_x_sa2_mode;
			break;
		case SADB_X_EXT_NAT_T_DPORT:
			natt_port = (struct sadb_x_nat_t_port*) ext;
			dst_port = ntohs (natt_port->sadb_x_nat_t_port_port);
			break;
		case SADB_X_EXT_NAT_T_SPORT:
			natt_port = (struct sadb_x_nat_t_port*) ext;
			/* src_port is ignored */
			break;
		case SADB_EXT_KEY_AUTH:
			key = (struct sadb_key*) ext;
			a_keylen = key->sadb_key_bits/8;
			if (a_keylen == 0)
				goto add_error;
			key++;
			a_key = (__u8*)key;
			break;
		case SADB_EXT_KEY_ENCRYPT:
			key = (struct sadb_key*) ext;
			e_keylen = key->sadb_key_bits/8;
			key++;
			e_key = (__u8*)key;
			break;
		case SADB_EXT_HIT:
			hitmagic = ((struct sadb_hit*)ext)->sadb_hit;
			break;
		default:
			printf("Warning: unknown TLV in PF_KEY message.\n ");
			goto add_error;
			break;
		}
		location += ext_len;
	}

	err = hip_sadb_add(type, mode, inner_src, inner_dst, src, 
			   dst, dst_port, spi, e_key, e_type, e_keylen,
			   a_key, a_type, a_keylen, lifetime, hitmagic,
			   msg->sadb_msg_pid);
	if (err < 0)
		msg->sadb_msg_errno = err;
	
	goto addsend;
add_error:
	msg->sadb_msg_errno = -1;
addsend:
#ifdef __WIN32__
	send(sock, data, len, 0);
#else
	if (write(sock, data, len) != len)
		return(-1);
#endif
	return(0);
}

/*
 * pfkey_handle_delete()
 *
 * Deletes an SA from the SADB.
 */
int pfkey_handle_delete(int sock, char *data, int len)
{
	__u32 type, spi;
	int err, location, msg_length, ext_len;
	struct sockaddr *src, *dst;
	int is_src=0, addr_len=0;
	
	struct sadb_msg *msg;
	struct sadb_ext *ext;
	struct sadb_sa *sa;
	struct sadb_address *addr;

	type = spi = 0;
	src = dst = NULL;
	
	msg = (struct sadb_msg*) data;
	msg_length = msg->sadb_msg_len * sizeof(__u64);
	location = sizeof(struct sadb_msg);
	while (location < msg_length) {
		ext = (struct sadb_ext*) &data[location];
		ext_len = ext->sadb_ext_len * sizeof(__u64);
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			sa = (struct sadb_sa*) ext;
			spi = ntohl(sa->sadb_sa_spi);
			break;
		case SADB_EXT_ADDRESS_SRC:
			is_src = 1;
		case SADB_EXT_ADDRESS_DST:
			addr = (struct sadb_address*) ext;
			addr_len = addr->sadb_address_prefixlen;
			addr++;
			if (is_src) src = (struct sockaddr*)addr;
			else dst = (struct sockaddr*)addr;
			is_src = 0;
			break;
		default:
			break;
		}
		location += ext_len;
	}
	
	err = hip_sadb_delete(type, src, dst, spi);
	if (err < 0)
		msg->sadb_msg_errno = err;
#ifdef __WIN32__
	send(sock, data, len, 0);
#else
	if (write(sock, data, len) != len)
		return(-1);
#endif
	return(0);
}

/*
 * pfkey_handle_get()
 *
 * Only the SPI is used from the SADB_GET to lookup the SA.
 * Reply with SADB_DUMP containing bytes used and usetime.
 * Note that, unlike RFC 2367, this does not dump everything.
 */
int pfkey_handle_get(int sock, char *data, int len)
{
	char buff[255];
	__u32 spi;
	int err, location, msg_length, ext_len;
	struct sockaddr *src, *dst;
	int is_src=0, addr_len=0;
	__u64 bytes, usetime;
	
	struct sadb_msg *msg, *reply_msg;
	struct sadb_ext *ext;
	struct sadb_sa *sa;
	struct sadb_address *addr;
	struct sadb_lifetime *life;
	hip_sadb_entry *entry;

	spi = 0;
	src = dst = NULL;
	bytes = 0;
	usetime = 0;
	err = 0;
	
	msg = (struct sadb_msg*) data;
	msg_length = msg->sadb_msg_len * sizeof(__u64);
	location = sizeof(struct sadb_msg);
	while (location < msg_length) {
		ext = (struct sadb_ext*) &data[location];
		ext_len = ext->sadb_ext_len * sizeof(__u64);
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			sa = (struct sadb_sa*) ext;
			spi = ntohl(sa->sadb_sa_spi);
			break;
		case SADB_EXT_ADDRESS_SRC:
			is_src = 1;
		case SADB_EXT_ADDRESS_DST:
			addr = (struct sadb_address*) ext;
			addr_len = addr->sadb_address_prefixlen;
			addr++;
			if (is_src) src = (struct sockaddr*)addr;
			else dst = (struct sockaddr*)addr;
			is_src = 0;
			break;
		default:
			break;
		}
		location += ext_len;
	}
	
	/* src, dst are ignored */
	/* get the bytes used from the SADB entry */
	if ((entry = hip_sadb_lookup_spi(spi))) {
		bytes = entry->bytes;
		usetime = entry->usetime.tv_sec;
	} else {
		err = -1;
	}

	/* build the SADB_DUMP reply */
	memset(buff, 0, sizeof(buff));
	msg_length = sizeof(struct sadb_msg) + sizeof(struct sadb_lifetime);
	reply_msg = (struct sadb_msg*)buff;
	reply_msg->sadb_msg_version = PF_KEY_V2;
	reply_msg->sadb_msg_type = SADB_DUMP;
	reply_msg->sadb_msg_errno = err;
	reply_msg->sadb_msg_satype = msg->sadb_msg_satype;
	reply_msg->sadb_msg_len = msg_length / sizeof(__u64);
	reply_msg->sadb_msg_reserved = 0;
	reply_msg->sadb_msg_seq = msg->sadb_msg_seq;
	reply_msg->sadb_msg_pid = 0;
	life = (struct sadb_lifetime*)&buff[sizeof(struct sadb_msg)];
	life->sadb_lifetime_len = sizeof(struct sadb_lifetime) / sizeof(__u64);
	life->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	life->sadb_lifetime_allocations = 0;
	life->sadb_lifetime_bytes = bytes;
	life->sadb_lifetime_addtime = 0;
	life->sadb_lifetime_usetime = usetime;
	
#ifdef __WIN32__
	send(sock, buff, msg_length, 0);
#else
	if (write(sock, buff, msg_length) != msg_length)
		return(-1);
#endif
	return(0);
}

/*
 * pfkey_handle_register()
 *
 * This is a no-op, since we're using a socketpair, only one process
 * can "register" communication with us. Echo back the SADB_REGISTER message.
 */
int pfkey_handle_register(int sock, char *data, int len)
{
	struct sadb_msg *msg;
	msg = (struct sadb_msg*) data;
	msg->sadb_msg_errno = 0;
	msg->sadb_msg_pid = 0;	
#ifdef __WIN32__
	send(sock, data, len, 0);
#else
	if (write(sock, data, len) != len)
		return(-1);
#endif
	return(0);
}

/*
 * pfkey_handle_spdadd()
 *
 * Another no-op function. No SPD is used.
 * However, direction of the SA is established based on this SPDADD input.
 */
int pfkey_handle_spdadd(int sock, char *data, int len)
{
	int location, msg_length, ext_len;
	struct sockaddr *src, *dst;
	int is_src=0, addr_len=0;
	__u8 direction;
	
	struct sadb_msg *msg;
	struct sadb_ext *ext;
	struct sadb_address *addr;
	struct sadb_x_policy *policy;

	hip_sadb_entry *entry;

	src = dst = NULL;
	direction = 0;
	
	msg = (struct sadb_msg*) data;
	msg_length = msg->sadb_msg_len * sizeof(__u64);
	location = sizeof(struct sadb_msg);
	while (location < msg_length) {
		ext = (struct sadb_ext*) &data[location];
		ext_len = ext->sadb_ext_len * sizeof(__u64);
		if (ext_len == 0) {
			dst = NULL;	/* error */
			break;
		}
		switch (ext->sadb_ext_type) {
		case SADB_EXT_ADDRESS_SRC:
			is_src = 1;
		case SADB_EXT_ADDRESS_DST:
			addr = (struct sadb_address*) ext;
			addr_len = addr->sadb_address_prefixlen;
			addr++;
			if (is_src) src = (struct sockaddr*)addr;
			else dst = (struct sockaddr*)addr;
			is_src = 0;
			break;
		case SADB_X_EXT_POLICY:
			/* direction: 2 == outgoing, 1 == incoming*/
			policy = (struct sadb_x_policy*) ext;
			direction = policy->sadb_x_policy_dir;
		default:
			break;
		}
		location += ext_len;
	}
	
	/* get the bytes used from the SADB entry */
	if (dst && (entry = hip_sadb_lookup_addr(dst))) {
		entry->direction = direction;
		msg->sadb_msg_errno = 0;
	} else {
		printf("Warning: SA not found using address in "
			"pfkey_handle_spadd(). dst=%p\n", dst);
		msg->sadb_msg_errno = -1;
	}
#ifdef __WIN32__
	send(sock, data, len, 0);
#else
	if (write(sock, data, len) != len)
		return(-1);
#endif
	return(0);
}

/*
 * pfkey_handle_spddelete()
 *
 * Another no-op function. No SPD is used.
 */
int pfkey_handle_spddelete(int sock, char *data, int len)
{
	struct sadb_msg *msg;
	msg = (struct sadb_msg*) data;
	msg->sadb_msg_errno = 0;
	msg->sadb_msg_pid = 0;	

#ifdef __WIN32__
	send(sock, data, len, 0);
#else
	if (write(sock, data, len) != len)
		return(-1);
#endif
	return(0);
}

/*
 * pfkey_handle_readdress()
 *
 * Currently, another no-op function. See comment below.
 */
int pfkey_handle_readdress(int sock, char *data, int len)
{
	struct sadb_msg *msg;
	msg = (struct sadb_msg*) data;
	/* TODO: 
	 * 	 perform any action here?
	 * 	 In the Linux kernel, we must walk the established sockets
	 * 	 list, but that is not necessary due to LSI usage here.
	 * 	 
	 *       Currently, the LSI mapping is updated via an extra
	 *       modified ACQUIRE message sent to pfkey, and that
	 *       could be moved here.
	 */
#ifdef __WIN32__
	send(sock, data, len, 0);
#else
	if (write(sock, data, len) != len)
		return(-1);
#endif
	return(0);
}

/*
 * pfkey_handle_acquire()
 *
 * Handle special ACQUIRE messages that come from the HIP daemon for updating
 * the LSI -> IP address mapping. This was done so that we could learn about
 * LSIs here without having to further modify libipsec.
 */
int pfkey_handle_acquire(char *data, int len)
{
	struct sadb_msg *msg;
	struct sadb_address *addr;
	struct sockaddr_storage ss_src, ss_lsi4, ss_lsi6;
	struct sockaddr *src = (struct sockaddr*)&ss_src;
	struct sockaddr *lsi4 = (struct sockaddr*)&ss_lsi4;
	struct sockaddr *lsi6 = (struct sockaddr*)&ss_lsi6;
	int location, addr_len;

	msg = (struct sadb_msg*) data;

	/* retrieve the new IP address */
	location = sizeof(struct sadb_msg);
	addr = (struct sadb_address*) &data[location];
	if (addr->sadb_address_exttype != SADB_EXT_ADDRESS_SRC)
		return(-1);
	addr_len = addr->sadb_address_len * sizeof(__u64);
	memcpy(src, addr+1, addr_len - sizeof(struct sadb_address));
	location += addr_len;

	/* retrieve the IPv4 LSI */
	addr = (struct sadb_address*) &data[location];
	if (addr->sadb_address_exttype != SADB_EXT_ADDRESS_DST)
		return(-1);
	addr_len = addr->sadb_address_len * sizeof(__u64);
	memcpy(lsi4, addr+1, addr_len - sizeof(struct sadb_address));
	location += addr_len;

	if (lsi4->sa_family == AF_INET)
		LSI4(lsi4) = ntohl(LSI4(lsi4));

	/* retrieve the IPv6 LSI */
	addr = (struct sadb_address*) &data[location];
	if (addr->sadb_address_exttype != SADB_EXT_ADDRESS_DST)
		return(-1);
	addr_len = addr->sadb_address_len * sizeof(__u64);
	memcpy(lsi6, addr+1, addr_len - sizeof(struct sadb_address));

	hip_add_lsi(src, lsi4, lsi6);
	return(0);
}


/*
 * pfkey_send_acquire()
 *
 * Sends a SADB_HIP_ACQUIRE message to the HIP daemon for triggering
 * a HIP exchange.
 */
int pfkey_send_acquire(struct sockaddr *target)
{
	char buff[256];
	struct sadb_msg *msg = (struct sadb_msg*) buff;
	struct sadb_address *addr;
	struct sadb_prop *proposal;
	struct sockaddr_storage ss_local;
	struct sockaddr *local = (struct sockaddr *)&ss_local;
	int len, extlen, plen, location;

	if (!target)
		return(-1);
	/* <base, address(SD), (address(P)), (identity(SD),) (sensitivity,)
	           proposal>                                                */
	len = sizeof(struct sadb_msg) + (2*sizeof(struct sadb_address)) +
	      (2*PFKEY_ALIGN8(SALEN(target))) + sizeof(struct sadb_prop);

	memset(buff, 0, len);
	
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_HIP_ACQUIRE;
	msg->sadb_msg_errno = 0;
	msg->sadb_msg_satype = SADB_SATYPE_ESP;
	msg->sadb_msg_len = PFKEY_UNIT64(len);
	msg->sadb_msg_reserved = 0;
	msg->sadb_msg_seq = ++pfk_seqno;
	msg->sadb_msg_pid = 0;

	memset(local, 0, sizeof(struct sockaddr_storage));
	switch (target->sa_family) {
	case AF_INET:
		plen = sizeof(struct in_addr) << 3;
		local->sa_family = AF_INET;
		get_preferred_lsi(local);
		LSI4(target) = htonl(LSI4(target));
		break;
	case AF_INET6:
		plen = sizeof(struct in6_addr) << 3;
		local->sa_family = AF_INET6;
		get_preferred_lsi(local);
		break;
	default:
		return(-1);
	}

	location = sizeof(struct sadb_msg);
	addr = (struct sadb_address*)&buff[location];
	extlen = sizeof(struct sadb_address);
	extlen += PFKEY_ALIGN8(SALEN(local));
	addr->sadb_address_len = PFKEY_UNIT64(extlen);
	addr->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	addr->sadb_address_proto = 0;
	addr->sadb_address_prefixlen = plen;
	addr->sadb_address_reserved = 0;
	addr++;
	memcpy(addr, local, SALEN(local));

	location += sizeof(struct sadb_address);
	location += PFKEY_ALIGN8(SALEN(local));
	addr = (struct sadb_address*)&buff[location];
	extlen = sizeof(struct sadb_address);
	extlen += PFKEY_ALIGN8(SALEN(target));
	addr->sadb_address_len = PFKEY_UNIT64(extlen);
	addr->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
	addr->sadb_address_proto = 0;
	addr->sadb_address_prefixlen = plen;
	addr->sadb_address_reserved = 0;
	addr++;
	memcpy(addr, target, SALEN(target));

	location += sizeof(struct sadb_address);
	location += PFKEY_ALIGN8(SALEN(target));
	proposal = (struct sadb_prop*) &buff[location];
	proposal->sadb_prop_len = PFKEY_UNIT64(sizeof(struct sadb_prop));
	proposal->sadb_prop_exttype = SADB_EXT_PROPOSAL;
	proposal->sadb_prop_replay = 0;
	memset(proposal->sadb_prop_reserved, 0, 3);
#ifdef __WIN32__
	if (send(pfkeysp[0], buff, len, 0) < 0) {
		printf("pfkey_send_acquire() write error: %s", strerror(errno));
		return(-1);
	}
#else
	if (write(pfkeysp[0], buff, len) != len) {
		printf("pfkey_send_acquire() write error: %s", strerror(errno));
		return(-1);
	}
#endif

	return(0);
}


/*
 * pfkey_send_hip_packet()
 *
 * Sends a SADB_HIP_PACKET message, which is simply a way to feed HIP control
 * packets to the hipd thread as they are demuxed from the single UDP port.
 */
int pfkey_send_hip_packet(char *data, int len)
{
	char buff[2048];
	struct sadb_msg *msg = (struct sadb_msg*) buff;
	int pf_len;

	pf_len = sizeof(struct sadb_msg) + len;
	if (pf_len > sizeof(buff))
		return(-1); /* TODO: dynamically allocate large HIP packets */

	memset(buff, 0, pf_len);

	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_HIP_PACKET;
	msg->sadb_msg_errno = 0;
	msg->sadb_msg_satype = 0;
	msg->sadb_msg_len = PFKEY_UNIT64(pf_len);
	msg->sadb_msg_reserved = 0;
	msg->sadb_msg_seq = ++pfk_seqno;
	msg->sadb_msg_pid = 0;

	memcpy(&buff[sizeof(struct sadb_msg)], data, len);

#ifdef __WIN32__
	if (send(pfkeysp[0], buff, pf_len, 0) < 0) {
		printf("pfkey_send_hip_packet() write error: %s\n",
			strerror(errno));
		return(-1);
	}
#else
	if (write(pfkeysp[0], buff, pf_len) != pf_len) {
		printf("pfkey_send_hip_packet() write error: %s\n",
			strerror(errno));
		return(-1);
	}
#endif
	return(0);
}

