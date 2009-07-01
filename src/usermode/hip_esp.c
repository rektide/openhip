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
 *  hip_esp.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * User-mode HIP ESP implementation.
 *
 * tunreader portions Copyright (C) 2004 UC Berkeley
 */
#include <stdio.h>		/* printf() */
#ifdef __WIN32__
#include <win32/types.h>
#include <io.h>
#include <winsock2.h>
#include <win32/ip.h>
#else /* __WIN32__ */
#include <sys/stat.h>
#include <unistd.h>		/* write() */
#include <pthread.h>		/* pthread_exit() */
#include <sys/time.h>		/* gettimeofday() */
#include <sys/errno.h>		/* errno, etc */
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#include <netinet/in.h>	
#endif /* __MACOSX__ */
#include <netinet/ip.h>		/* struct ip */
#include <netinet/ip6.h>	/* struct ip6_hdr */
#include <netinet/icmp6.h>	/* struct icmp6_hdr */
#include <netinet/tcp.h>	/* struct tcphdr */
#include <netinet/udp.h>	/* struct udphdr */
#include <arpa/inet.h>		
#ifndef __MACOSX__
#include <linux/types.h>	/* for pfkeyv2.h types */
#endif /* __MACOSX__ */
#endif /* __WIN32__ */
#include <string.h>		/* memset, etc */
#include <openssl/hmac.h>	/* HMAC algorithms */
#include <openssl/sha.h>	/* SHA1 algorithms */
#include <openssl/des.h>	/* 3DES algorithms */
#include <openssl/rand.h>	/* RAND_bytes() */
#include <win32/pfkeyv2.h>
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_usermode.h>
#include <hip/hip_sadb.h>

#if defined(__BIG_ENDIAN__) || defined( __MACOSX__)
#include <mac/checksum_mac.h>
#else
#include <win32/checksum.h>
#endif

#ifdef SMA_CRAWLER
#include <utime.h>
#include <netinet/ether.h>
#include <hip/hip_cfg_api.h>
#include <hip/endbox_utils.h>
#endif /* SMA_CRAWLER */

/* 
 * Globals
 */

#ifdef SMA_CRAWLER
int touchHeartbeat;
#endif

#ifdef __WIN32__
HANDLE tapfd;
#else
int tapfd;
#endif
int readsp[2] = {0,0};
int s_esp, s_esp_udp, s_esp6;
int s_udp;
#ifdef DEBUG_EVERY_PACKET
FILE *debugfp;
#endif

#ifdef __MACOSX__
extern char *logaddr(struct sockaddr *addr);
#endif

__u32 g_tap_lsi;
__u64 g_tap_mac;
long g_read_usec;

#define BUFF_LEN 2000
#define HMAC_SHA_96_BITS 96 /* 12 bytes */

/* array of Ethernet addresses used by get_eth_addr() */
#define MAX_ETH_ADDRS 255
__u8 eth_addrs[6 * MAX_ETH_ADDRS]; /* must be initialized to random values */


/* Prototype of checksum function defined in hip_util.c */
__u16 checksum_udp_packet(__u8 *data, struct sockaddr *src, struct sockaddr *dst);

/* 
 * Local data types 
 */
struct ip_esp_hdr {
	__u32 spi;
	__u32 seq_no;
	__u8 enc_data[0];
};

struct ip_esp_padinfo {
	__u8 pad_length;
	__u8 next_hdr;
};

struct eth_hdr {
	__u8 dst[6];
	__u8 src[6];
	__u16 type;
};

/* ARP header - RFC 826, STD 37 */
struct arp_hdr {
	__u16 ar_hrd;
	__u16 ar_pro;
	__u8 ar_hln;
	__u8 ar_pln;
	__u16 ar_op;
};


#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

/* 
 * Local function declarations
 */
void tunreader_shutdown();
int handle_nsol(__u8 *in, int len, __u8 *out,int *outlen,struct sockaddr *addr);
int handle_arp(__u8 *in, int len, __u8 *out, int *outlen,struct sockaddr *addr);
int hip_esp_encrypt(__u8 *in, int len, __u8 *out, int *outlen, 
	hip_sadb_entry *entry, struct timeval *now);
int hip_esp_decrypt(__u8 *in, int len, __u8 *out, int *offset, int *outlen,
    hip_sadb_entry *entry, struct ip *iph, struct timeval *now);

__u16 rewrite_checksum(__u8 *data, __u16 magic);
void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type);
void add_ipv4_header(__u8 *data, __u32 src, __u32 dst, struct ip *old, 
	__u16 len, __u8 proto);
void add_ipv6_pseudo_header(__u8 *data, struct sockaddr *src, 
	struct sockaddr *dst, __u32 len, __u8 proto);
void add_ipv6_header(__u8 *data, struct sockaddr *src, struct sockaddr *dst,
	struct ip6_hdr *old, struct ip *old4, __u16 len, __u8 proto);
__u16 in_cksum(struct ip *iph);
__u64 get_eth_addr(int family, __u8 *addr);

#ifdef SMA_CRAWLER
int build_host_mac_map();
#endif

/* void reset_sadbentry_udp_port (__u32 spi_out); */
int send_udp_esp_tunnel_activation (__u32 spi_out);

extern __u32 get_preferred_lsi(struct sockaddr *lsi);
extern int do_bcast();
extern int maxof(int num_args, ...);

#ifdef SMA_CRAWLER 
spiList *spiHead;
pList s[255];  /* local hosts */
int numHosts = 0;
int read_private_hosts() {
  FILE *fp;
  char str[255];
  char ip[16];
  char mac[32];
  int counter=0;

  fp = fopen("/tmp/private_hosts","r");
  if(!fp){
          fprintf(stderr,"error opening private host list\n");
          exit(-1);
  }
  while(!feof(fp)) {
          str[0] = 0;
          if (fgets(&str[0],255,fp) == NULL)
		  break;
          if(isalnum(str[0])) {
                  if(str[strlen(str)-1] == '\n')
                          str[strlen(str)-1] = '\0';

                  if(sscanf(&str[0], "%s\t%s", ip, mac) < 2) {
                          printf("parse error reading private host file\n");
                          return -1;
                          }
                  s[counter].ip = strdup(ip);
                  s[counter].mac = strdup(mac);
                  counter++;
          }
  }
  fclose(fp);
  numHosts = counter;
  return numHosts;
}

void save_private_hosts()
{
  FILE *fp;
  int i;
  if((fp=fopen("/tmp/private_hosts", "w"))==NULL){
     log_(WARN, "cannot open /tmp/private_hosts - MAC address will not be cached\n");
      return;
  }
 
  for(i=0;i<numHosts;i++)
    fprintf(fp,"%s %s\n",s[i].ip,s[i].mac);
  fclose(fp);
}

int find_host(char *host)
{
int i,retVal = 0;
	for(i=0;i< numHosts;i++) {
		if(!strcmp(s[i].ip,host)) {
			retVal =1;
			continue;
		}
	}
return retVal;
}


int find_host2(__u32 host)
{
int i;
__u32 r=0;
	for(i=0;i< numHosts;i++) {
	  r=inet_addr(s[i].ip);
	  if(host == r) {
		  return 1;
		}
	}
return 0;
}

pList *find_host3(__u32 host)
{
int i;
	for(i=0;i< numHosts;i++) {
	  if(host == inet_addr(s[i].ip)) {
			return &s[i];
		}
	}

return 0;
}

__u64 build_mac(char *mac)  {
  struct ether_addr *addr;
  __u64 ret=0;
  if(mac) {
    addr = ether_aton(mac);
    memcpy(&ret,&addr->ether_addr_octet,6);
  }
  return ret;
}
__u64 find_mac(__u32 host) 
{
  pList *p = find_host3(host);

  if(p)
    return build_mac(p->mac);

  /*
   *  check whether it is a multicast address...
   */

  if(IN_MULTICAST(ntohl(host))) {
     return build_mac("FF:FF:FF:FF:FF:FF");
  }
  return 0;
}

__u64 find_mac2(int index)
{
   if (index < numHosts)
     return build_mac(s[index].mac);
   else
     return 0;
 }

int find_mac3(__u8 *mac)
{
  int i;
  __u64 host_mac, mac2 = 0;

  for(i = 0; i < numHosts; i++) {
    host_mac = build_mac(s[i].mac);
    memcpy(&mac2,mac,6);
    if (host_mac == mac2)
      return 1;
  }
  printf("find_mac3 cannot find mac for MAC %02x%02x\n", mac[4], mac[5]);
  return 0;
}

void endbox_init()
{
	spiHead= (spiList *) malloc(sizeof(spiList));
	spiHead->next = 0;
}
#endif /* SMA_CRAWLER */

#ifdef __MACOSX__
void add_outgoing_esp_header(__u8 *data, __u32 src, __u32 dst, __u16 len);
#endif

void init_readsp()
{
	if (readsp[0])
		return;
	
#ifdef __MACOSX__
	if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNSPEC, readsp)) {
#else
	if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, readsp)) {
#endif
		printf("sockpair() failed\n");
	}
	/* also initialize the Ethernet address table */
	RAND_bytes(eth_addrs, sizeof(eth_addrs));
}

#ifdef SMA_CRAWLER
/* determine if to proxy a legacy node */
int ack_request(struct in_addr sa, struct in_addr da)
{
	int rc;
	struct sockaddr_storage host_ss;
	struct sockaddr_storage eb_ss;
	struct sockaddr *host_p;
	struct sockaddr *eb_p;
	hip_hit hit1, hit2;
	char *ip;

	host_p = (struct sockaddr*)&host_ss;
	eb_p = (struct sockaddr*)&eb_ss;

	host_p->sa_family = AF_INET;
	ip = inet_ntoa(sa);
	str_to_addr((unsigned char *)ip, host_p);

	//log_(NORM, "ack_request: sender ip addr %s\n", ip);
	if(!find_host2(sa.s_addr))
		return 0;
	/*
	  Not proxy it if no ACL permission between the source and
	  desitination endboxes, which takes care of the case where
	  the two endboxes are "behind" a bridge
	*/
	eb_p->sa_family=AF_INET6;
	rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
	if(rc){
		log_(WARN, "invalid source addr in arp %s", ip);
		return 0;
	}

	memcpy(hit1, SA2IP(eb_p), HIT_SIZE);

	host_p->sa_family = AF_INET;
	ip = inet_ntoa(da);
	str_to_addr((unsigned char *)ip, host_p);
	eb_p->sa_family=AF_INET6;
	rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
	if(rc){
		log_(WARN, "invalid dest addr in arp %s", ip);
		return 0;
	}
	memcpy(hit2, SA2IP(eb_p), HIT_SIZE);

	rc = hipcfg_allowed_peers(hit1, hit2);
	if(!rc)
	   log_(NORM, "peer connection not allowed hit1: %02x%02x, hit2: "
		"%02x%02x\n", hit1[HIT_SIZE-2], hit1[HIT_SIZE-1],
		hit2[HIT_SIZE-2], hit2[HIT_SIZE-1]);
	return rc;
}
#endif /* SMA_CRAWLER */
/*
 * hip_esp_output()
 *
 * The ESP output thread. Reads ethernet packets from the socketpair
 * connected to the TAP-Win32 interface, and performs necessary ESP
 * encryption. Also handles ARP requests with artificial replies.
 */
#ifdef __WIN32__
void hip_esp_output(void *arg)
#else
void *hip_esp_output(void *arg)
#endif
{
	int len, err, flags, raw_len, is_broadcast, s, offset=0;
	fd_set fd;
	struct timeval timeout, now;
	__u8 raw_buff[BUFF_LEN];
	__u8 data[BUFF_LEN]; /* encrypted data buffer */
	struct ip *iph;

#ifdef __WIN32__
	DWORD lenin;
	OVERLAPPED overlapped = {0};
#endif
	struct ip6_hdr *ip6h;
	static hip_sadb_entry *entry;
	struct sockaddr_storage ss_lsi;
	struct sockaddr *lsi = (struct sockaddr*)&ss_lsi;
#ifndef SMA_CRAWLER
	__u32 lsi_ip;
#else
	time_t last_time, now_time;
	int packet_count = 0;
#endif
#ifdef __MACOSX__
        __u32 saddr, daddr;
#endif
#ifdef RAW_IP_OUT
	int s_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s_raw < 0) {
		printf("*** socket() error for raw socket in hip_esp_output\n");
	}
	flags = 1;
	if (setsockopt(s_raw, IPPROTO_IP, IP_HDRINCL, (char *)&flags, 
				sizeof(flags)) < 0) {
		printf("*** setsockopt() error for raw socket in "
			"hip_esp_output\n");
	}
#endif /* RAW_IP_OUT */

#ifdef DEBUG_EVERY_PACKET
	if (!(debugfp = fopen("esp.log", "w"))) {
		printf("********* error opening debug log!\n");
	}
#endif
	init_readsp();
	lsi->sa_family = AF_INET;
	get_preferred_lsi(lsi);
	g_tap_lsi = LSI4(lsi);
	
#ifdef SMA_CRAWLER
	touchHeartbeat=1;
	last_time = time(NULL);
	printf("hip_esp_output() thread (tid %d pid %d) started...\n",
	       (unsigned)pthread_self(), getpid());
	build_host_mac_map();
#else
	printf("hip_esp_output() thread started...\n");
#endif
	while (g_state == 0) {
		/* periodic select loop */
		gettimeofday(&now, NULL); /* XXX does this cause perf. hit? */
		FD_ZERO(&fd);
		FD_SET((unsigned)readsp[1], &fd);
#ifdef __MACOSX__
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
#else
		timeout.tv_sec = 0;
		timeout.tv_usec = g_read_usec;
#endif
#ifdef SMA_CRAWLER
		now_time = time(NULL);
		if (now_time - last_time > 60) {
			printf("hip_esp_output() heartbeat (%d packets)\n",
				packet_count);
			last_time = now_time;
			packet_count = 0;
			if (touchHeartbeat)
				utime("/usr/local/etc/hip/heartbeat_hip_output",
					NULL);
			else
				printf("not touching heartbeat_hip_output!\n");
		}
#endif
		if ((err = select(readsp[1]+1, &fd, NULL, NULL, &timeout))< 0) {
#ifdef __WIN32__
			if (WSAGetLastError() == WSAEINTR)
#else
			if (errno == EINTR)
#endif
				continue;
			printf("hip_esp_output(): select() error\n");
		} else if (err == 0) {
			/* idle cycle */
			continue;
		}

		/* output data on socket */
		memset(raw_buff, 0, sizeof(raw_buff));
		memset(data, 0, sizeof(data));
		memset(lsi, 0, sizeof(struct sockaddr_storage));

#ifdef __WIN32__
		if ((len = recv(readsp[1], raw_buff, BUFF_LEN, 0)) == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEINTR)
#else
		if ((len = read(readsp[1], raw_buff, BUFF_LEN)) < 0) {
			if (errno == EINTR)
#endif
				continue;
			printf("hip_esp_output(): read() failed: %s\n",
				strerror(errno));
			exit(0);
		}
		/* 
		 * IPv4 
		 */
		if ((raw_buff[12] == 0x08) && (raw_buff[13] == 0x00)) {
			iph = (struct ip*) &raw_buff[14];
			/* accept IPv4 traffic to 1.x.x.x here */
#ifndef SMA_CRAWLER
			if (((iph->ip_v) == IPVERSION) &&
#if defined(__MACOSX__) && defined(__BIG_ENDIAN__)
				(iph->ip_dst.s_addr >> 24 & 0xFF)!=0x01)
#else
			    (iph->ip_dst.s_addr & 0xFF)!=0x01)
#endif
				continue;
#endif /* SMA_CRAWLER */
#ifdef SMA_CRAWLER
			if (!IN_MULTICAST(ntohl(iph->ip_dst.s_addr)) && 
			    ((ntohl(iph->ip_dst.s_addr)) & 0x000000FF) != 
			     0x000000FF) {
		          if(!ack_request(iph->ip_src, iph->ip_dst))
			    continue;

		          struct sockaddr_storage legacy_host_ss, eb_ss;
			  struct sockaddr *legacy_host_p = (struct sockaddr*)
				&legacy_host_ss;
			  struct sockaddr *eb_p = (struct sockaddr*)&eb_ss;
			  legacy_host_p->sa_family = AF_INET;
			  LSI4(legacy_host_p) = iph->ip_dst.s_addr;
			  eb_p->sa_family = AF_INET;
			  if(!hipcfg_getEndboxByLegacyNode(legacy_host_p,
				eb_p)){
				char endboxAddr[16];
				inet_ntop(eb_p->sa_family, SA2IP(eb_p),
					endboxAddr, sizeof(endboxAddr));
				struct sockaddr_in saddr;
				inet_pton(AF_INET,
					endboxAddr,&saddr.sin_addr.s_addr);
				LSI4(lsi) = ntohl(saddr.sin_addr.s_addr);
				lsi->sa_family = AF_INET;
			  }
			  packet_count++;
			} /* end if not multicast */
#else /* SMA_CRAWLER */
			lsi_ip = ntohl(iph->ip_dst.s_addr);
			lsi->sa_family = AF_INET;
			LSI4(lsi) = lsi_ip;
#endif /* SMA_CRAWLER */
			is_broadcast = FALSE;
			/* broadcast packets */
#ifndef SMA_CRAWLER
			if ((lsi_ip & 0x00FFFFFF)==0x00FFFFFF) {
				if (!do_bcast())
					continue;
#else
			if (IN_MULTICAST(ntohl(iph->ip_dst.s_addr)) ||
			    (((ntohl(iph->ip_dst.s_addr)) & 0x000000FF) ==
			     0x000000FF)) {
#endif /* !SMA_CRAWLER */
				/* unicast the broadcast to each entry */
				entry = hip_sadb_get_next(NULL);
				is_broadcast = TRUE;
			/* unicast packets */
			} else if (!(entry = hip_sadb_lookup_addr(lsi))){
				/* No SADB entry. Send ACQUIRE if we haven't
				 * already, i.e. a new lsi_entry was created */
				if (buffer_packet(lsi, raw_buff, len)==TRUE)
					pfkey_send_acquire(lsi);
				continue;
			}
			raw_len = len;
			while (entry) {
				pthread_mutex_lock(&entry->rw_lock);
#ifdef RAW_IP_OUT
				offset = sizeof(struct ip);
#else
				offset = 0;
#endif
				err = hip_esp_encrypt(raw_buff, raw_len,
					&data[offset], &len, entry, &now);
				pthread_mutex_unlock(&entry->rw_lock);
				if (err) {
					if (!is_broadcast)
						break;
					entry=hip_sadb_get_next(entry);
					continue;
				}
				flags = 0;
#ifdef RAW_IP_OUT
				/* Build IPv4 header and send out raw socket.
				 * Use this to override OS source address
				 * selection problems.
				 */
				add_ipv4_header(data,
					ntohl(LSI4(&entry->src_addrs->addr)), 
					ntohl(LSI4(&entry->dst_addrs->addr)), 
					(struct ip*)
					&raw_buff[sizeof(struct eth_hdr)],
					sizeof(struct ip) + len,
					IPPROTO_ESP);
				err = sendto(s_raw, data, 
					sizeof(struct ip) + len, flags,
					SA(&entry->dst_addrs->addr),
					SALEN(&entry->dst_addrs->addr));
#else
#ifdef __MACOSX__ 
/*I need to build an IP header and write it to a different address!*/
			/* TODO: use offset above, and LSI4 macro instead
			 *       of calls to inet_addr()
			 */
			memmove(&data[20],&data,len);
			saddr = inet_addr(
			    logaddr((struct sockaddr*)&entry->src_addrs->addr));
			daddr = inet_addr(
			    logaddr((struct sockaddr*)&entry->dst_addrs->addr));
                        
			add_outgoing_esp_header(data, saddr,daddr,len);
                        
			err=sendto(s_esp,data,len+sizeof(struct ip),flags,0,0);
			if (err < 0)
                                perror("sendto()");
#else /* __MACOSX__ */
				if (entry->mode == 3)
					s = s_esp_udp;
				else if (entry->dst_addrs->addr.ss_family ==
						AF_INET)
					s = s_esp;
				else
					s = s_esp6;
				err = sendto(s, data, len, flags,
						SA(&entry->dst_addrs->addr),
						SALEN(&entry->dst_addrs->addr));
#endif /* __MACOSX__ */
#endif /* RAW_IP_OUT */
				if (err < 0) {
					printf("hip_esp_output(): sendto() "
					       "failed: %s\n", strerror(errno));
				} else {
					pthread_mutex_lock(&entry->rw_lock);
					entry->bytes += sizeof(struct ip) + err;
					entry->usetime.tv_sec = now.tv_sec;
					entry->usetime.tv_usec = now.tv_usec;
					entry->usetime_ka.tv_sec = now.tv_sec;
					entry->usetime_ka.tv_usec = now.tv_usec;
					pthread_mutex_unlock(&entry->rw_lock);
				}
				/* broadcasts are unicast to each association */
				if (!is_broadcast)
					break;
				entry = hip_sadb_get_next(entry);
			} /* end while */
		/* 
		 * IPv6 
		 */
		} else if ((raw_buff[12] == 0x86) && (raw_buff[13] == 0xdd)) {
			ip6h = (struct ip6_hdr*) &raw_buff[14];
			/* accept IPv6 traffic to 2001:10::/28 here */
			if ((ip6h->ip6_vfc & 0xF0) != 0x60)
				continue;
			/* Look for all-nodes multicast address */
			if (IN6_IS_ADDR_MC_LINKLOCAL(&ip6h->ip6_dst) &&
			    (ip6h->ip6_nxt == IPPROTO_ICMPV6)) {
				err = handle_nsol(raw_buff, len, data,&len,lsi);
				if (err)
					continue;
#ifdef __WIN32__
				if (!WriteFile(tapfd, data, len, &lenin, 
							&overlapped)){
					printf( "hip_esp_output WriteFile() " \
						"failed.\n");
				}
#else
				if (write(tapfd, data, len) < 0) {
					printf( "hip_esp_output write() " \
						"failed.\n");
				}
#endif
				continue;
			} else if (!IS_HIT(&ip6h->ip6_dst)) {
				continue;
			}
			/* HIT prefix */
			lsi->sa_family = AF_INET6;
			memcpy(SA2IP(lsi), &ip6h->ip6_dst, SAIPLEN(lsi));
			if (!(entry = hip_sadb_lookup_addr(lsi))) {
				if (buffer_packet(lsi, raw_buff, len)==TRUE)
					pfkey_send_acquire(lsi);
				continue;
			} 
			raw_len = len;
			pthread_mutex_lock(&entry->rw_lock);
			err = hip_esp_encrypt(raw_buff, raw_len,
					      data, &len, entry, &now);
			pthread_mutex_unlock(&entry->rw_lock);
			flags = 0;
			if (entry->mode == 3)
				s = s_esp_udp;
			else if (entry->dst_addrs->addr.ss_family == AF_INET)
				s = s_esp;
			else
				s = s_esp6;
			err = sendto(	s, data, len, flags, 
					SA(&entry->dst_addrs->addr), 
					SALEN(&entry->dst_addrs->addr));
			if (err < 0) {
				printf("hip_esp_output IPv6 sendto() failed:"
					" %s\n",strerror(errno));
			} else {
				pthread_mutex_lock(&entry->rw_lock);
				entry->bytes += sizeof(struct ip6_hdr) + err;
				entry->usetime.tv_sec = now.tv_sec;
				entry->usetime.tv_usec = now.tv_usec;
				pthread_mutex_unlock(&entry->rw_lock);
			}
		/* 
		 * ARP 
		 */
		} else if ((raw_buff[12] == 0x08) && (raw_buff[13] == 0x06)) {
			err = handle_arp(raw_buff, len, data, &len, lsi);
			if (err)
				continue;
#ifdef __WIN32__
			if (!WriteFile(tapfd, data, len, &lenin, &overlapped)){
				printf("hip_esp_output WriteFile() failed.\n");
			}
#else
			if (write(tapfd, data, len) < 0) {
				printf("hip_esp_output write() failed.\n");
			}
#endif
			/* Why send acquire during ARP? */
			/*if (!hip_sadb_lookup_addr(lsi))
				pfkey_send_acquire(lsi);
			*/
			continue;
		} else {
			/* debug other eth headers here */
			/*int i;
			printf("<unknown traffic> (len=%d)\n", len);
			for (i = 0; i < len; i++)
				printf("%x", raw_buff[i] & 0xFF);
			printf("\n");*/
			
		}
	
	}
	/* write some data to flush waiting TAP threads, speed up exit */
	data[0] = 0;
	len = 1;
#ifdef __WIN32__
	WriteFile(tapfd, data, len, &lenin, &overlapped);
	CloseHandle(tapfd);
#else
	err = write(tapfd, data, len);
	close(tapfd);
#endif
	printf("hip_esp_output() thread shutdown.\n");
	fflush(stdout);
	tunreader_shutdown();
#ifndef __WIN32__
	pthread_exit((void *) 0);
	return(NULL);
#endif
}


/*
 * hip_esp_input()
 *
 * The ESP input thread. Reads ESP packets from the network and decrypts
 * them, adding HIT or LSI headers and sending them out the TAP-Win32 interface.
 * Also, expires temporary LSI entries and retransmits buffered packets.
 */
#ifdef __WIN32__
void hip_esp_input(void *arg)
#else
void *hip_esp_input(void *arg)
#endif
{
	int err, len, max_fd, offset;
	fd_set fd;
	struct timeval timeout, now;
	__u8 buff[BUFF_LEN]; /* raw, encrypted data buffer */
	__u8 data[BUFF_LEN]; /* decrypted data buffer */
	struct sockaddr_storage ss_lsi;
	struct sockaddr *lsi = (struct sockaddr*) &ss_lsi;
	struct ip *iph;
	struct ip_esp_hdr *esph;
	hip_sadb_entry *inverse_entry;
	udphdr *udph;

	__u32 spi, seq_no;
	hip_sadb_entry *entry;
#ifdef __WIN32__
	DWORD lenin;
	OVERLAPPED overlapped = {0};
#endif
#ifdef SMA_CRAWLER
	time_t last_time, now_time;
	int packet_count = 0;

	last_time = time(NULL);
	printf("hip_esp_input() thread (tid %d pid %d) started...\n",
	       (unsigned)pthread_self(), getpid());
#else
        printf("hip_esp_input() thread started...\n");
#endif
	g_read_usec = 1000000;
	
	lsi->sa_family = AF_INET;
	get_preferred_lsi(lsi);
	g_tap_lsi = LSI4(lsi);
	
	while (g_state == 0) {
		gettimeofday(&now, NULL); /* XXX does this cause perf. hit? */
		FD_ZERO(&fd);
		FD_SET((unsigned)s_esp, &fd);
		FD_SET((unsigned)s_esp_udp, &fd);
#ifndef __WIN32__
		/* IPv6 ESP not available in Windows */
		FD_SET((unsigned)s_esp6, &fd);
		max_fd = maxof(3, s_esp, s_esp6, s_esp_udp);
#else
		max_fd = (s_esp > s_esp_udp) ? s_esp : s_esp_udp;
#endif
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		memset(buff, 0, sizeof(buff));
		memset(data, 0, sizeof(data));

#ifdef SMA_CRAWLER
		now_time = time(NULL);
		if (now_time - last_time > 60) {
			printf("hip_esp_input() heartbeat (%d packets)\n", packet_count);
			last_time = now_time;
			packet_count = 0;
			utime("/usr/local/etc/hip/heartbeat_hip_input", NULL);
		}
#endif
		if ((err = select(max_fd+1, &fd, NULL, NULL, &timeout)) < 0 ) {
#ifdef __WIN32__
			if (WSAGetLastError() == WSAEINTR)
				continue;
			printf("hip_esp_input(): select() error %d\n",
			       WSAGetLastError());
#else
			if (errno == EINTR)
				continue;
			printf("hip_esp_input(): select() error %s\n",
			       strerror(errno));
#endif
		} else if (FD_ISSET(s_esp, &fd)) {
#ifdef __WIN32__
			len = recv(s_esp, buff, sizeof(buff), 0);
#else
			len = read(s_esp, buff, sizeof(buff));
#endif
			iph = (struct ip *) &buff[0];
			esph = (struct ip_esp_hdr *) &buff[sizeof(struct ip)];
			spi 	= ntohl(esph->spi);
			seq_no 	= ntohl(esph->seq_no);
			if (!(entry = hip_sadb_lookup_spi(spi))) {
				/*printf("Warning: SA not found for SPI 0x%x\n",
					spi);*/
				continue;
			}

			pthread_mutex_lock(&entry->rw_lock);
			err = hip_esp_decrypt(buff, len, data, &offset, &len,
						entry, iph, &now);
			pthread_mutex_unlock(&entry->rw_lock);
			if (err)
				continue;
#ifdef __WIN32__
			if (!WriteFile(tapfd, &data[offset], len, &lenin,
					&overlapped)) {
				printf("hip_esp_input() WriteFile() failed.\n");
				continue;
			}
#else /* __WIN32__ */
#ifdef SMA_CRAWLER
		      packet_count++;
		      iph = (struct ip*) &data[offset + sizeof(struct eth_hdr)];
		
		      // If multicast IP address, generate a MAC address for each host in the
		      // private host map.  OTB 20080414
		
		      if(IN_MULTICAST((ntohl(iph->ip_dst.s_addr)))) {
		        int i, n = numHosts;
		        for (i = 0; i < n; i++) {
		          __u64 dst_mac = find_mac2(i);
		          if(dst_mac) { //the endbox, entry with LSI, has dst_mac 0
		            add_eth_header(&data[offset], g_tap_mac, dst_mac, 0x0800);
		            if (write(tapfd, &data[offset], len) < 0) {
		              printf("hip_esp_input() write() failed.\n");
		            }
		          }
		        }
		      } else {
			if (write(tapfd, &data[offset], len) < 0)
        		   printf("hip_esp_input() write() failed.\n");
			}
#else /* SMA_CRAWLER */
			if (write(tapfd, &data[offset], len) < 0) {
				printf("hip_esp_input() write() failed.\n");
			}
#endif /* SMA_CRAWLER */
#endif /* __WIN32__ */
		} else if (FD_ISSET(s_esp_udp, &fd)) {
#ifdef __WIN32__
			len = recv(s_esp_udp, buff, sizeof(buff), 0);
#else
			len = read(s_esp_udp, buff, sizeof(buff));
#endif

			/* XXX clean this up XXX */
			iph = (struct ip*) &buff[0];
			udph = (udphdr*) &buff[sizeof(struct ip)];
			esph = (struct ip_esp_hdr *) \
				&buff[sizeof(struct ip)+sizeof(udphdr)];

			if (((int)(len - sizeof(struct ip) - sizeof(udphdr)) ==
				1) && (((__u8*)esph)[0] == 0xFF)) {
				printf ("Keepalive packet received.\n");
				continue;
			}
			spi 	= ntohl(esph->spi);
			seq_no 	= ntohl(esph->seq_no);
			if (!(entry = hip_sadb_lookup_spi(spi))) {
				/*printf("Warning: SA not found for SPI 0x%x\n",
					spi);*/
				continue;
			}

			if (!entry->inner_src_addrs)
				continue;

			if (!(inverse_entry = hip_sadb_lookup_addr(
				SA(&(entry->inner_src_addrs->addr))))) {
				printf ("Corresponding sadb entry for "
					"outgoing packets not found.\n");
				continue;
			}
			/*printf ( "DST_PORT = %u\n", 
			 * inverse_entry->dst_port);*/
			if (inverse_entry->dst_port == 0) {
				printf ("ESP channel - Setting dst_port "
					"to %u\n",ntohs(udph->src_port));
				pthread_mutex_lock(&inverse_entry->rw_lock);
				inverse_entry->dst_port = ntohs(udph->src_port);
				pthread_mutex_unlock(&inverse_entry->rw_lock);
			}

			pthread_mutex_lock(&entry->rw_lock);
			err = hip_esp_decrypt(buff, len, data, &offset, &len,
						entry, iph, &now);
			pthread_mutex_unlock(&entry->rw_lock);
			/* these two locks acquired by hip_sadb_lookup_addr */
			if (err)
				continue;

			if (len==35 && data[34]==0xFF) {
				printf ("Reception of udp-tunnel activation "
					"packet for spi:0x%x.\n",
					inverse_entry->spi);
				if (ntohs(udph->src_port) != 0) {
					printf ("ESP channel : Updating "
						"dst_port: %u=>%u.\n",
						inverse_entry->dst_port,
						ntohs(udph->src_port));
					pthread_mutex_lock(
						&inverse_entry->rw_lock);
					inverse_entry->dst_port = 
						ntohs( udph->src_port );
					pthread_mutex_unlock(
						&inverse_entry->rw_lock);
				}
				continue;
			}
			if (inverse_entry->dst_port != ntohs(udph->src_port)) {
				printf ("ESP channel : unexpected change of "
					"dst_port : %u=>%u\n",
					inverse_entry->dst_port,
					ntohs( udph->src_port ));
				pthread_mutex_lock(&inverse_entry->rw_lock);
				inverse_entry->dst_port = ntohs(udph->src_port);
				pthread_mutex_unlock(&inverse_entry->rw_lock);
			}
			 
#ifdef __WIN32__
			if (!WriteFile(tapfd, &data[offset], len, &lenin, 
				&overlapped)){
				printf("hip_esp_input() WriteFile() failed.\n");
				continue;
			}
#else
			if (write(tapfd, &data[offset], len) < 0) {
				printf("hip_esp_input() write() failed.\n");
			}
#endif

#ifndef __WIN32__
		} else if (FD_ISSET(s_esp6, &fd)) {
			len = read(s_esp6, buff, sizeof(buff));
			/* there is no IPv6 header supplied */
#ifdef DEBUG_EVERY_PACKET
			fprintf(debugfp, "read() %d bytes\n", len);
#endif
			esph = (struct ip_esp_hdr *) &buff[0];
			spi 	= ntohl(esph->spi);
			seq_no 	= ntohl(esph->seq_no);
			if (!(entry = hip_sadb_lookup_spi(spi))) {
				printf("Warning: SA not found for SPI 0x%x\n",
					spi);
				continue;
			}
			pthread_mutex_lock(&entry->rw_lock);
			err = hip_esp_decrypt(buff, len, data, &offset, &len,
						entry, NULL, &now);
			pthread_mutex_unlock(&entry->rw_lock);
			if (err)
				continue;
			if (write(tapfd, &data[offset], len) < 0) {
				printf("hip_esp_input() write() failed.\n");
			}
#endif /* !__WIN32__ */
		} else if (err == 0) {
			/* idle cycle */
			hip_remove_expired_lsi_entries();
			hip_remove_expired_sel_entries();
			/* TODO: implement SA timeout here */
		}
	}

	printf("hip_esp_input() thread shutdown.\n");
	fflush(stdout);
#ifndef __WIN32__
	pthread_exit((void *) 0);
	return(NULL);
#endif
}


#ifdef __WIN32__
void udp_esp_keepalive (void *arg) {
#else
void *udp_esp_keepalive (void *arg) {
#endif
	int len;
	hip_sadb_entry *entry;
	struct timeval now;
	__u8 buff[ sizeof(udphdr) + 1 ];
	udphdr *udph;
	__u8 *data;
	

	printf("udp_esp_keepalive() thread started...\n");

	/* prepare the UDP packet */
	memset(buff,0,sizeof(buff));
	udph = (udphdr*) buff;
	udph->src_port = htons(HIP_ESP_UDP_PORT);
	udph->len = htons((__u16) sizeof(buff));
	udph->checksum = 0;
	data = &buff[sizeof(udphdr)];
	data[0]=0xFF;

	/* 
	 * Loop forever, sending UDP ESP keepalives every 
	 * HIP_KEEPALIVE_TIMEOUT seconds for outgoing 
	 * BEET-mode SADB entries.
	 */
	while (g_state == 0) {
		gettimeofday(&now, NULL);
		/* get first outgoing entry from the hip_sadb[] */
		entry = hip_sadb_get_next(NULL);
		while (entry) {
			pthread_mutex_lock(&entry->rw_lock);
			/* BEET-mode only entries, must have dst_port */
			if ((entry->mode != 3) ||
			    (entry->dst_port == 0)) {
				goto udp_esp_keepalive_continue; 
			}
			/* not time yet */
			if (now.tv_sec < (entry->usetime_ka.tv_sec +
						HIP_KEEPALIVE_TIMEOUT)) {
				goto udp_esp_keepalive_continue; 
			}
			/* send a UDP ESP keepalive */
			udph->dst_port = htons(entry->dst_port);
			len = sendto(s_esp_udp, buff, sizeof(buff), 0,
				     (struct sockaddr*)&entry->dst_addrs->addr,
				     SALEN(&entry->dst_addrs->addr));
			if (len < 0) {
				printf("Keepalive sendto() failed for SPI=0x%x:"
				       " %s\n", entry->spi, strerror(errno));
			} else {
				/* printf("Keepalive sent for SPI=0x%x.\n",
					entry->spi); */
				entry->bytes += sizeof(struct ip) + len;
				entry->usetime_ka.tv_sec = now.tv_sec;
				entry->usetime_ka.tv_usec = now.tv_usec;
			}
			udph->dst_port = 0;
udp_esp_keepalive_continue:
			pthread_mutex_unlock(&entry->rw_lock);
			/* get next outgoing entry from the hip_sadb[] */
			entry = hip_sadb_get_next(entry);
		} /* end while */
		hip_sleep(1);
	}
	printf("udp_esp_keepalive() thread shutdown.\n");
#ifndef __WIN32__
	pthread_exit((void *) 0);
	return (NULL);
#endif /* __WIN32__ */
}

/*
void reset_sadbentry_udp_port (__u32 spi_out)
{
	hip_sadb_entry *entry;
	entry = hip_sadb_lookup_spi (spi_out);
	if (entry) {
		entry->dst_port = 0;
		printf ("SADB-entry dst_port reset for spi: 0x%x.\n",spi_out);
	}
}
*/

int send_udp_esp_tunnel_activation (__u32 spi_out)
{
	hip_sadb_entry *entry;
	struct timeval now;
	int err, len;
	int raw_len = 35 ;
	__u8 raw_buff[35];
	__u8 *payload;
	struct ip *iph;
	__u8 data[BUFF_LEN];

	memset(raw_buff,0,sizeof(raw_buff));
	iph = (struct ip*) &raw_buff[14];
	iph->ip_p = IPPROTO_RAW;
	payload = &raw_buff[34];
	payload[0]=0xFF;

/* ugly hack... 
 * since there is no "ACK" from the responder to signal that its SADB is 
 * uptodate, the "moving" initiator sends the activation packet directly
 * after its own SADB is updated... */
/* so this hack just add a small delay */
/* wait 0.2sec to give enough time to the peer for finishing the SADB update */
#ifdef __WIN32__
	Sleep(200);
#else
	struct timespec delay;
	delay.tv_sec = 0 ;
	delay.tv_nsec = 200000000;
	nanosleep (&delay, NULL);
#endif
/* end of ugly hack :-) */

	gettimeofday(&now, NULL);

	entry = hip_sadb_lookup_spi (spi_out);

	if (entry) {
		if (entry->mode != 3) {
			return(-1);
		}
		if (entry->direction != 2) {
			return(-1);
		}
		if (entry->dst_port == 0) {
			return(-1);
		}

		pthread_mutex_lock(&entry->rw_lock);
		err = hip_esp_encrypt(raw_buff, raw_len, data, 
					&len, entry, &now);
		pthread_mutex_unlock(&entry->rw_lock);
		if (err) {
			printf ("Error in send_udp_esp_tunnel_activation(). "
				"hip_esp_encrypt failed.\n");
			return (-1);
		}
		err = sendto(s_esp_udp, data, len, 0,
			(struct sockaddr*)&entry->dst_addrs->addr,
			SALEN(&entry->dst_addrs->addr));
		if (err < 0) {
			printf("send_udp_esp_tunnel_activation sendto() "
				"failed: %s\n",
				strerror(errno));
			return (-1);
		} else {
			printf("send_udp_esp_tunnel_activation packet sent.\n");
			entry->bytes += sizeof(struct ip) + err;
			entry->usetime_ka.tv_sec = now.tv_sec;
			entry->usetime_ka.tv_usec = now.tv_usec;
			return (0);
		}
	}
	return (-1);
}



#ifdef __WIN32__
/* For Windows, use overlapped event notification */
void tunreader(void *arg)
{
	DWORD len;
	char buf[BUFF_LEN];
	OVERLAPPED overlapped;
	int status;

	printf("tunreader() thread started...\n");

	init_readsp();
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	while (g_state == 0) {
		overlapped.Offset = 0;
		overlapped.OffsetHigh = 0;
		ResetEvent(overlapped.hEvent);

		status = ReadFile(tapfd, buf, BUFF_LEN, &len, &overlapped);
		if (!status) {
			if (GetLastError() == ERROR_IO_PENDING) {
				//WaitForSingleObject(overlapped.hEvent,2000);
				WaitForSingleObject(overlapped.hEvent,INFINITE);
				if (!GetOverlappedResult(tapfd, &overlapped,
				    &len, FALSE)) {
					/* there is nothing to send */
					continue;
				}
			} else {
				/* other error, don't exit */
				printf("tunreader(): error (%d) reading from ",
				    (int)GetLastError());
				printf("tun device.\n");
				continue;
			}
		}
		send(readsp[0], buf, len, 0);
	}
	CloseHandle(tapfd);
	printf("tunreader() thread shutdown.\n");
	fflush(stdout);
}

#else /* __WIN32__ */

/* For Linux, use select. */
void *tunreader(void *arg)
{
	int len, err;
	char buf[BUFF_LEN];
	struct timeval timeout;
	fd_set read_fdset;
	
#ifdef SMA_CRAWLER
	time_t last_time, now_time;

	last_time = time(NULL);
	printf("tunreader() thread (tid %d pid %d) started (%d)...\n",
	        (unsigned)pthread_self(), getpid(), tapfd);
#else
	printf("tunreader() thread started (%d)...\n", tapfd);
#endif

	init_readsp();
	while (g_state == 0) {
		FD_ZERO(&read_fdset);
		FD_SET((unsigned)tapfd, &read_fdset);
		timeout.tv_sec = 3;
		timeout.tv_usec = 0;
#ifdef SMA_CRAWLER
		now_time = time(NULL);
		if (now_time - last_time > 60) {
			printf("tunreader() heartbeat\n");
			last_time = now_time;
			utime("/usr/local/etc/hip/heartbeat_tunreader", NULL);
		}
#endif
		if ((err = select((tapfd+1), &read_fdset, 
				  NULL, NULL, &timeout) < 0)) {
			if (err == EINTR) 
				continue;
			printf("tunreader: error while reading from tun ");
			printf("device: %s\n", strerror(errno));
			fflush(stdout);
			return 0;
		} else if (FD_ISSET(tapfd, &read_fdset)) {
			if ((len = read(tapfd, buf, BUFF_LEN)) > 0) {
				err = write(readsp[0], buf, len);
				if (err != len)
					printf("warning: tunreader: write(%d) "
						"returned %d\n", len, err);
			} else {
				printf("tunreader: read() error len=%d %s\n",
					len, strerror(errno));
				continue;
			}
		} else if (err == 0) {
			/* idle cycle */
			continue;
		}
	}
	close(tapfd);
	printf("tunreader thread shutdown.\n");
	fflush(stdout);
	pthread_exit((void *) 0);
	return(NULL);
}
#endif /* __WIN32__ */

/*
 * tunreader_shutdown()
 *
 * Send dummy data to the tun device so that the tunreader() thread doesn't
 * hang waiting for a read event.
 */
void tunreader_shutdown()
{
	char data[8] = { 0,0,0,0,0,0,0,0 };
	struct sockaddr_in to;
	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = htonl(g_tap_lsi);
	to.sin_port = htons(8000);
	
	sendto(s, data, sizeof(data), 0, (struct sockaddr*)&to, sizeof(to));
#ifdef __WIN32__
	closesocket(s);
#else
	close(s);
#endif
}


/*
 * handle_nsol()
 * 
 * Handle ICMPv6 Neighbor Solicitations for HITs.
 * Right now this is called from the esp_output thread when an 
 * application wants to send data to a HIT.
 */
int handle_nsol(__u8 *in, int len, __u8 *out, int *outlen,struct sockaddr *addr)
{
	struct eth_hdr *eth = (struct eth_hdr*)in;
	struct ip6_hdr *ip6h = (struct ip6_hdr*) &in[sizeof(struct eth_hdr)];
	__u64 esrc=0, edst=0;
	struct icmp6_hdr *nsol, *nadv;
	struct in6_addr *target, *adv_target;
	struct nd_opt_hdr *adv_target_opts;
	__u8 *p;
	__u16 payload_len;
	int location;
	struct sockaddr_storage src_ss;
	struct sockaddr_storage dst_ss;
	struct sockaddr *src = (struct sockaddr *) &src_ss;
	struct sockaddr *dst = (struct sockaddr *) &dst_ss;

	nsol = (struct icmp6_hdr *)&in[ sizeof(struct eth_hdr) + 
					sizeof(struct ip6_hdr) ];

	/* Only allow ICMPv6 Neighbor Soliciations for HITs */
	if (nsol->icmp6_type != ND_NEIGHBOR_SOLICIT)
		return(1);
	target = (struct in6_addr*) (nsol + 1);
	if (!IS_HIT(target)) /* target must be HIT */
		return(1);
	/* don't answer requests for self */
	src->sa_family = AF_INET6;
	get_preferred_lsi(src);
	if (IN6_ARE_ADDR_EQUAL(target, &((struct sockaddr_in6*)src)->sin6_addr))
		return(1);

	/* for now, replied MAC addr  */
	esrc = get_eth_addr(AF_INET6, &target->s6_addr[0]);
	memcpy(&edst, eth->src, 6);
	add_eth_header(out, esrc, edst, 0x86dd);
	location = sizeof(struct eth_hdr);

	/* IPv6 header added after length is calculated */
	memset(src, 0, sizeof(struct sockaddr_storage));
	memset(dst, 0, sizeof(struct sockaddr_storage));
	src->sa_family = AF_INET6;
	memcpy(SA2IP(src), &target->s6_addr[0], sizeof(struct in6_addr));
	dst->sa_family = AF_INET6;
	memcpy(SA2IP(dst), &ip6h->ip6_src.s6_addr[0], sizeof(struct in6_addr));
	location += sizeof(struct ip6_hdr);
	
	/* build neighbor advertisement reply */
	nadv = (struct icmp6_hdr *)&out[location];
	nadv->icmp6_type = ND_NEIGHBOR_ADVERT;
	nadv->icmp6_code = 0;
	nadv->icmp6_cksum = 0;
	nadv->icmp6_data32[0] = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
	location += sizeof(struct icmp6_hdr);
	adv_target = (struct in6_addr*) &out[location];
	memcpy(adv_target, target, sizeof(struct in6_addr));
	location += sizeof(struct in6_addr);
	adv_target_opts = (struct nd_opt_hdr*) &out[location];
	adv_target_opts->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	adv_target_opts->nd_opt_len = 1; /* 1x(8 octets) */
	location += sizeof(struct nd_opt_hdr);
	memcpy(&out[location], &esrc, 6);
	location += 6;

	/* return the HIT */
	if (addr)
		memcpy(addr, src, sizeof(struct sockaddr_storage));
	
	/* pseudo-header for upper-layer checksum calculation */
	p = (__u8*)nadv - 40;
	payload_len = &out[location] - (__u8*)nadv;
	add_ipv6_pseudo_header(p, src, dst, (__u32)payload_len, IPPROTO_ICMPV6);
	nadv->icmp6_cksum = ip_fast_csum(p, &out[location] - p);
	/* real IPv6 header */
	add_ipv6_header(&out[sizeof(struct eth_hdr)], src, dst, ip6h, NULL,
			payload_len, IPPROTO_ICMPV6);

	*outlen = location;
	return(0);
}


/*
 * handle_arp()
 * 
 * Handle ARP requests for 1.x.x.x addresses. Right now this is called
 * from the esp_output thread when an application wants to send data to
 * an LSI.
 */
int handle_arp(__u8 *in, int len, __u8 *out, int *outlen, struct sockaddr *addr)
{
	struct eth_hdr *eth = (struct eth_hdr*)in;
	struct arp_hdr *arp_request, *arp_reply;
	char *p_sender, *p_target, *p;
	__u64 src=0, dst=0;
	__u32 ip_req, ip_sender;

	/* only handle ARP requests (opcode 1) here */
	arp_request = (struct arp_hdr*) &in[14];
	switch(ntohs(arp_request->ar_op)) {
		case ARPOP_REQUEST:
			break;
		default:
			return(1);
	}

	if ((ntohs(arp_request->ar_hrd) == 0x01) &&	/* Ethernet */
	    (ntohs(arp_request->ar_pro) == 0x0800) &&	/* IPv4 */
	    (arp_request->ar_hln == 6) && (arp_request->ar_pln == 4)) {
		/* skip sender MAC, sender IP, target MAC */
		arp_request++;
		p_sender = (char *)arp_request;
		ip_sender = *((__u32*)(p_sender + 6));
		p_target = p_sender + 6 + 4;
		ip_req = *((__u32*)(p_target + 6));
#ifdef SMA_CRAWLER
		struct in_addr sa, da;
	        sa.s_addr = ip_sender;
		da.s_addr = ip_req;
		if(!ack_request(sa, da)) //not proxy legacy node if both are behind the bridge
		  return -1;
#endif
	} else {
		return(-1);
	}

	if (ip_req == g_tap_lsi) /* don't answer requests for self */
		return(1);

#ifdef SMA_CRAWLER
	struct sockaddr_storage legacy_host_ss, eb_ss;
	struct sockaddr *legacy_host_p = (struct sockaddr*)&legacy_host_ss;
	struct sockaddr *eb_p = (struct sockaddr*)&eb_ss;
	legacy_host_p->sa_family = AF_INET;
	LSI4(legacy_host_p) = ip_req;
	eb_p->sa_family = AF_INET;
        if(!hipcfg_getEndboxByLegacyNode(legacy_host_p, eb_p)){
		if (IS_LSI32(ip_req)) {
			__u32 ip_src = *((__u32*)(p_sender + 6));
			if (ip_src == g_tap_lsi)
				src = g_tap_mac;
			else
				return (1);
		} else {
			if (find_mac3(eth->src))
				src = (__u64)g_tap_lsi << 16;
			else
				return (1);
		}
	}
	/* convert 32-bit lsi (1.a.b.c) to 48-bit MAC address (00-00-1-a-b-c) */
        src = (__u64)g_tap_lsi << 16;
#else
	/* repl with random MAC addr based on requested IP addr */
	src = get_eth_addr(AF_INET, (__u8*)&ip_req);
#endif
	memcpy(&dst, eth->src, 6);
	add_eth_header(out, src, dst, 0x0806);

	/* build ARP reply */
	arp_reply = (struct arp_hdr*) &out[14];
	arp_reply->ar_hrd = htons(0x01);
	arp_reply->ar_pro = htons(0x0800);
	arp_reply->ar_hln = 6;
	arp_reply->ar_pln = 4;
	arp_reply->ar_op = htons(ARPOP_REPLY);
	p = (char*)(arp_reply +1);
	memcpy(p, &src, 6);		/* sender MAC */
	memcpy(p+6, &ip_req, 4);	/* sender address */
	memcpy(p+10, p_sender, 10);	/* target MAC + address */

	/* return the address */
	if (addr) {
		addr->sa_family = AF_INET;
		((struct sockaddr_in*)addr)->sin_addr.s_addr = ntohl(ip_req);
	}
	
	*outlen = sizeof(struct eth_hdr) + sizeof(struct arp_hdr) + 20;
	return(0);
}

#ifdef SMA_CRAWLER
int build_host_mac_map()
{
  __u8 out[256], *p;
  int outlen = 0, i, j, rc;
  struct arp_hdr *arp_request, *arp_reply;
  __u64 dst_mac = 0xffffffffffffffffLL;
  __u64 src_mac;
  __u8 in[BUFF_LEN];
  struct timeval timeout;
  fd_set read_fdset;
  __u32 resp_ip;
  char *resp_ip_s;
  struct in_addr resp_ip_in;
  __u8 resp_mac[6];
  char resp_mac_s[32];
  struct in_addr eb_in, dst_in;
  char *eb_s, dst_s[32];
  int host_cnt;
  struct sockaddr_storage legacyHosts[5], eb_ss;
  struct sockaddr *dst_p, *eb_p = (struct sockaddr *)&eb_ss;
  struct stat stat_buf;

  if(stat("/tmp/private_hosts", &stat_buf)==0){
    log_(NORM, "loading legacy node MAC addresses from /tmp/private_hosts.\n");
    if(read_private_hosts()>0){
      printf("loaded %d entries from /tmp/private_hosts.\n", numHosts);
      return 0;
    }
  }
      
  log_(NORM, "Lookup MAC addresses for legacy hosts attached this endobx...\n");
  eb_in.s_addr = g_tap_lsi;
  eb_s = inet_ntoa(eb_in);
  
  s[numHosts].ip = strdup(eb_s);
  s[numHosts].mac = strdup("00:00:00:00:00:00");
  numHosts++; 

  if(eb_s == NULL)
    return -1;
  eb_p->sa_family=AF_INET;
  inet_pton(AF_INET, eb_s, SA2IP(eb_p));
 
  host_cnt=hipcfg_getLegacyNodesByEndbox(eb_p,
	legacyHosts, sizeof(legacyHosts)/sizeof(struct sockaddr_storage));
  if(host_cnt <0 )
    return -1;
  if(host_cnt == 0){
    log_(WARN, "no legacy hosts servied by endbox %s\n", eb_s);
    return 0;
  }
 
  hip_sleep(30); //HIP threads initialization complete
  for(i = 0; i<host_cnt; i++){
    dst_p = (struct sockaddr *)&legacyHosts[i];
    inet_ntop(dst_p->sa_family, SA2IP(dst_p), dst_s, sizeof(dst_s));
    log_(NORM, "finding MAC for legacy node %s...\n", dst_s);
    inet_aton(dst_s, &dst_in);
   
    src_mac = (__u64)g_tap_lsi << 16;
    add_eth_header(out, src_mac, dst_mac, 0x0806);

    arp_request = (struct arp_hdr*) &out[14];
    arp_reply = (struct arp_hdr*) &in[14];
    arp_request->ar_hrd = htons(0x01);
    arp_request->ar_pro = htons(0x0800);
    arp_request->ar_hln = 6;
    arp_request->ar_pln = 4;
    arp_request->ar_op = htons(ARPOP_REQUEST);
    p = (__u8 *)(arp_request +1);
    memcpy(p, &src_mac, 6);		/* sender MAC */
    memcpy(p+6, &g_tap_lsi, 4);	/* sender address */
    memcpy(p+10, &dst_mac, 6);		/* target MAC */
    memcpy(p+16, &dst_in.s_addr, 4);	/* target address */

    outlen = sizeof(struct eth_hdr) + sizeof(struct arp_hdr) + 20;

    FD_ZERO(&read_fdset);
    FD_SET((unsigned)readsp[1], &read_fdset);
    time_t poll_time, cur_time;
    time(&poll_time);
    while(1){
      time(&cur_time);
      if((cur_time-poll_time)>20){
	log_(WARN, "cannot get ARP response for legacy host %s\n", dst_s);
	break;
      }
      if(write(tapfd, out, outlen) < 0) {
          log_(WARN, "send ARP request failed while aquiring MAC addresses.\n");
          return -1;
      }
      fflush(stdout);
      timeout.tv_sec = 3;
      timeout.tv_usec = 0;
      rc=select(readsp[1]+1, &read_fdset, NULL, NULL, &timeout);
      if(rc == 0) {
	continue;
      }
      if(rc < 0 ){
        if(rc == EINTR)
          continue;
        log_(WARN, "error polling on socket to get MAC address, error: %s\n",
		strerror(errno));
        return -1;
      } 
      rc = read(readsp[1], in, BUFF_LEN);
      //printf("read readsp returned %d bytes", rc);
      if(rc <= 0) {
         log_(WARN, "error read on socket to get MAC address, error: %s\n",
		strerror(errno));
         return -1;
      }
      j=0; // supress compling error.
   /*
      printf("\n");
      for(j=0; j<14; j++)
        printf("%02x ", in[j]);
      printf("\n");
   */
      if(in[12]!=0x08 || in[13]!=0x06) {
        //printf("read readsp - not a ARP reply %02x %02x\n", in[12], in[13]);
        continue;
      }
    /*
      printf("ar_hrd %x\n", ntohs(arp_reply->ar_hrd));
      printf("ar_pro %x\n", ntohs(arp_reply->ar_pro));
      printf("ar_hln %x\n", arp_reply->ar_hln);
      printf("ar_pln %x\n", arp_reply->ar_pln);
      printf("ar_op %x\n", ntohs(arp_reply->ar_op));
    */
	     
      if(ntohs(arp_reply->ar_hrd)==0x01 &&     /* Ethernet */
         ntohs(arp_reply->ar_pro)==0x0800 && /* IPv4 */
         arp_reply->ar_hln==6 && arp_reply->ar_pln == 4 &&
         ntohs(arp_reply->ar_op)==0x0002){ /* ARP reply */
	/*
	   for(j=0; j<10; j++)
	    printf("%0x ", in[22+j]);
	   printf("\n");
	*/
           memcpy(resp_mac, &in[22], 6);
           resp_ip = ((__u32)in[28]<<24) + ((__u32)in[29]<<16) + ((__u32)in[30]<<8) + (__u32)in[31];
	   resp_ip_in.s_addr = htonl(resp_ip);
	 /*
	   printf("got ARP response - responder IP %s", inet_ntoa(resp_ip_in));
	   printf("dest IP %s\n", inet_ntoa(dst_in));
	 */
	   if(resp_ip_in.s_addr != dst_in.s_addr)
	      continue;
	   resp_ip_s = inet_ntoa(resp_ip_in);
	   sprintf(resp_mac_s, "%02x:%02x:%02x:%02x:%02x:%02x", 
		resp_mac[0],resp_mac[1], resp_mac[2],
		resp_mac[3],resp_mac[4], resp_mac[5]);
	   log_(NORM, "got MAC [%s] for legacy host [%s]\n",
		resp_mac_s, resp_ip_s);
	   s[numHosts].ip = strdup(resp_ip_s);
	   s[numHosts].mac = strdup(resp_mac_s);
	   numHosts++;
	   break;
      }
    }
  }
  log_(NORM, "complete aquiring legacy hosts MAC addresses on this endbox.\n");
  save_private_hosts();
  return(0);
}
#endif /* SMA_CRAWLER */

#ifdef CURRENTLY_UNUSED
extern __u32 get_preferred_addr();
/*
 * handle_broadcasts()
 *
 * This code leaks broadcast packets outside of the association.
 * Unfortunately, the receiving end will see a different source address
 * (not the source LSI) so the packet may be meaningless.
 */
void handle_broadcasts(__u8 *data, int len)
{
	struct ip iph_old;
	struct sockaddr_in to;
	int s, val;
	__u8 proto, mdata[32];
	__u16 magic;
	__u32 src_ip, dst_ip;
	__u64 sum;
	
	/* save IPv4 header before it is zeroed */
	memcpy(&iph_old, &data[14], sizeof(struct ip));
	proto = iph_old.ip_p;
	len -= 14; /* subtract eth header */

	/* 
	 * form a broadcast address, fixup TCP/UDP checksum
	 */
	src_ip = get_preferred_addr();
	if (!src_ip)	/* preferred address not found! */
		return;
	dst_ip = src_ip | 0xFF000000L;
	
	/* IP header */
	memset(mdata, 0, sizeof(mdata));
	memcpy(&mdata[0], &src_ip, sizeof(src_ip));
	memcpy(&mdata[16], &dst_ip, sizeof(dst_ip));
	sum = htonl(src_ip) + htonl(dst_ip);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	magic = (__u16)sum;
	magic = htons(magic+1);
	rewrite_checksum(&data[14], magic);

	/* 
	 * send it out on a raw socket 
	 */
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = dst_ip;

	s = socket(PF_INET, SOCK_RAW, proto);
	val = 1;
	setsockopt(s, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val));
	if (sendto(s, &data[34], len, 0, 
	    (struct sockaddr *)&to, sizeof(to)) < 0) {
		printf("broadcast sendto() failed: proto=%d len=%d err:%s\n",
			proto, len, strerror(errno));
	}
	close(s);
}
#endif


/*
 * hip_esp_encrypt()
 * 
 * in:		in	pointer of data to encrypt
 * 		len	length of data
 * 		out	pointer of where to store encrypted data
 * 		outlen	returned length of encrypted data
 * 		entry 	the SADB entry
 *
 * out:		Encrypted data in out, outlen. entry statistics are modified.
 * 		Returns 0 on success, -1 otherwise.
 * 
 * Perform actual ESP encryption and authentication of packets.
 */
int hip_esp_encrypt(__u8 *in, int len, __u8 *out, int *outlen, 
	hip_sadb_entry *entry, struct timeval *now)
{
	int alen=0, elen=0;
	unsigned int hmac_md_len;
	int i, iv_len=0, padlen, location, hdr_len;
	struct ip *iph=NULL;
	struct ip6_hdr *ip6h=NULL;
	struct ip_esp_hdr *esp;
	udphdr *udph = NULL;

	struct ip_esp_padinfo *padinfo=0;
	__u8 cbc_iv[16];
	__u8 hmac_md[EVP_MAX_MD_SIZE];
#ifndef SMA_CRAWLER
	__u16 checksum_fix = 0;
#endif
	int family, use_udp = FALSE;


	if ((in[12] == 0x86) && (in[13] == 0xdd))
		family = AF_INET6;
	else
		family = AF_INET;

	switch (family) {
	case AF_INET:
		iph = (struct ip*) &in[sizeof(struct eth_hdr)];
#ifndef SMA_CRAWLER
		/* BEET mode uses transport mode encapsulation. IP header is
		 * not included. */
		hdr_len = sizeof(struct eth_hdr) + sizeof(struct ip);
		/* rewrite upper-layer checksum, so it is based on HITs */
		checksum_fix = rewrite_checksum((__u8*)iph, entry->hit_magic);
#else
		/* SMA_CRAWLER uses tunnel mode encapsulation. IP header is
		 * included. */
		hdr_len = sizeof(struct eth_hdr);
#endif /* SMA_CRAWLER */
		break;
	case AF_INET6:
		ip6h = (struct ip6_hdr*) &in[sizeof(struct eth_hdr)];
#ifndef SMA_CRAWLER
		hdr_len = sizeof(struct eth_hdr) + sizeof(struct ip6_hdr);
#else
		hdr_len = sizeof(struct eth_hdr);
#endif /* SMA_CRAWLER */
		/* assume HITs are used as v6 src/dst, no checksum rewrite */
		break;
	}

	/* elen is length of data to encrypt
	 * for SMA_CRAWLER, this includes the IP header.
	 */
	elen = len - hdr_len;


	/* setup ESP header, common to all algorithms */
	if (entry->mode == 3) { /*(HIP_ESP_OVER_UDP)*/
		udph = (udphdr*) out;
		esp = (struct ip_esp_hdr*) &out[sizeof(udphdr)];
		use_udp = TRUE;
	} else {
		esp = (struct ip_esp_hdr*) out;
	}
	esp->spi = htonl(entry->spi);
	esp->seq_no = htonl(entry->sequence++);
	padlen = 0;
	*outlen = sizeof(struct ip_esp_hdr);
	
	if (use_udp) /* (HIP_ESP_OVER_UDP) */
		*outlen += sizeof(udphdr);

	/* 
	 * Encryption 
	 */

	/* Check keys and set IV length */
	switch (entry->e_type) {
	case SADB_EALG_3DESCBC:
		iv_len = 8;
		if (!entry->e_key || entry->e_keylen==0) {
			printf("hip_esp_encrypt: 3-DES key missing.\n");
			return(-1);
		}
		break;
	case SADB_X_EALG_BLOWFISHCBC:
		iv_len = 8;
		if (!entry->bf_key) {
			printf("hip_esp_encrypt: BLOWFISH key missing.\n");
			return(-1);
		}
		break;
	case SADB_EALG_NULL:
		iv_len = 0;
		break;
	case SADB_X_EALG_AESCBC:
		iv_len = 16;
		if (!entry->aes_key && entry->e_key) {
			entry->aes_key = malloc(sizeof(AES_KEY));
			if (AES_set_encrypt_key(entry->e_key, 8*entry->e_keylen,
						entry->aes_key)) {
				printf("hip_esp_encrypt: AES key problem!\n");
			}
		} else if (!entry->aes_key) {
			printf("hip_esp_encrypt: AES key missing.\n");
			return(-1);
		}
		break;
	case SADB_EALG_NONE:
	case SADB_EALG_DESCBC:
	case SADB_X_EALG_CASTCBC:
	case SADB_X_EALG_SERPENTCBC:
	case SADB_X_EALG_TWOFISHCBC:
	default:
		printf("Unsupported encryption transform (%d).\n",
			entry->e_type);
#ifdef SMA_CRAWLER
		touchHeartbeat = 0;
#endif
		return(-1);
		break;
	}

	/* Add initialization vector (random value) */
	if (iv_len > 0) {
		RAND_bytes(cbc_iv, iv_len);
		memcpy(esp->enc_data, cbc_iv, iv_len);
		padlen = iv_len - ((elen + 2) % iv_len);
	} else {
		/* Padding with NULL not based on IV length */
		padlen = 4 - ((elen + 2) % 4);
	}
	/* add padding to input data, set padinfo */
	location = hdr_len + elen;
	for (i=0; i<padlen; i++)
		in[location + i] = i+1;
	padinfo = (struct ip_esp_padinfo*) &in[location + padlen];
	padinfo->pad_length = padlen;
	padinfo->next_hdr = (family == AF_INET) ? iph->ip_p : ip6h->ip6_nxt;
	/* padinfo is encrypted too */
	elen += padlen + 2;
	
	/* Apply the encryption cipher directly into out buffer
	 * to avoid extra copying */
	switch (entry->e_type) {
	case SADB_EALG_3DESCBC:
		des_ede3_cbc_encrypt(&in[hdr_len],
				     &esp->enc_data[iv_len], elen,
				     entry->ks[0], entry->ks[1], entry->ks[2],
				     (des_cblock*)cbc_iv, DES_ENCRYPT);
		break;
	case SADB_X_EALG_BLOWFISHCBC:
		BF_cbc_encrypt(&in[hdr_len],
				&esp->enc_data[iv_len], elen,
				entry->bf_key, cbc_iv, BF_ENCRYPT);
		break;
	case SADB_EALG_NULL:
		memcpy(esp->enc_data, &in[hdr_len], elen);
		break;
	case SADB_X_EALG_AESCBC:
		AES_cbc_encrypt(&in[hdr_len],
				&esp->enc_data[iv_len], elen,
				entry->aes_key, cbc_iv, AES_ENCRYPT);
		break;
	default:
		break;
	}
	elen += iv_len; /* auth will include IV */
	*outlen += elen;
	
	/* 
	 * Authentication 
	 */
	switch (entry->a_type) {
	case SADB_AALG_NONE:
		break;
	case SADB_AALG_MD5HMAC:
		alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
		if (!entry->a_key || entry->a_keylen==0) {
			printf("auth err: missing keys\n");
			return(-1);
		}
		elen += sizeof(struct ip_esp_hdr);
		HMAC(	EVP_md5(), entry->a_key, entry->a_keylen,
			(__u8*)esp, elen, hmac_md, &hmac_md_len);
		memcpy(&out[elen + (use_udp ? sizeof(udphdr) : 0)], 
			hmac_md, alen);
		*outlen += alen;
		break;
	case SADB_AALG_SHA1HMAC:
		alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
		if (!entry->a_key || entry->a_keylen==0) {
			printf("auth err: missing keys\n");
			return(-1);
		}
		elen += sizeof(struct ip_esp_hdr);
#ifdef DEBUG_EVERY_PACKET
		fprintf(debugfp, "SPI=0x%x out a_key(%d): 0x",
			entry->spi, entry->a_keylen);
		for (i=0; i < entry->a_keylen; i++) {
			if (i%4==0) fprintf(debugfp, " ");
			fprintf(debugfp,"%.2x",entry->a_key[i] & 0xFF);
		}
		fprintf(debugfp, "\n");
#endif /* DEBUG_EVERY_PACKET */
		HMAC(	EVP_sha1(), entry->a_key, entry->a_keylen,
			(__u8*)esp, elen, hmac_md, &hmac_md_len);
		memcpy(&out[elen + (use_udp ? sizeof(udphdr) : 0)],
			hmac_md, alen);
		*outlen += alen;
#ifdef DEBUG_EVERY_PACKET
		fprintf(debugfp, "SHA1: (pkt %d) 0x", *outlen);
		for (i=0; i < alen; i++) {
			if (i%4==0) fprintf(debugfp, " ");
			fprintf(debugfp, "%.2x", hmac_md[i] & 0xFF);
		}
		fprintf(debugfp, "\n");
		fprintf(debugfp, "bytes(%d): ", elen);
		for (i=0; i < elen; i++) {
			if (i && i%8==0) fprintf(debugfp, " ");
			fprintf(debugfp, "%.2x",((__u8*)esp)[i] & 0xFF);
		}
		fprintf(debugfp, "\n\n");
#endif /* DEBUG_EVERY_PACKET */
		break;
	case SADB_X_AALG_SHA2_256HMAC:
	case SADB_X_AALG_SHA2_384HMAC:
	case SADB_X_AALG_SHA2_512HMAC:
	case SADB_X_AALG_RIPEMD160HMAC:
	case SADB_X_AALG_NULL:
		break;
	default:
		break;
	}

#ifndef SMA_CRAWLER
	/* Record the address family of this packet, so incoming
	 * replies of the same protocol/ports can be matched to
	 * the same family.
	 */
	if (hip_add_proto_sel_entry(LSI4(&entry->lsi), 
				(__u8)(iph ? iph->ip_p : ip6h->ip6_nxt), 
				iph ? (__u8*)(iph+1) : (__u8*)(ip6h+1),
				family, 0, now	) < 0)
		printf("hip_esp_encrypt(): error adding sel entry.\n");


	/* Restore the checksum in the input data, in case this is
	 * a broadcast packet that needs to be re-sent to some other
	 * destination.
	 */
	if (checksum_fix > 0) {
		if (iph->ip_p == IPPROTO_UDP)
#ifdef __MACOSX__
			((struct udphdr*)(iph + 1))->uh_sum = checksum_fix;
#else
			((struct udphdr*)(iph + 1))->check = checksum_fix;
#endif
		else if (iph->ip_p == IPPROTO_TCP)
#ifdef __MACOSX__
			((struct tcphdr*)(iph + 1))->th_sum = checksum_fix;
#else
			((struct tcphdr*)(iph + 1))->check = checksum_fix;
#endif
	}
#endif /* SMA_CRAWLER */

	if (use_udp) { /* (HIP_ESP_OVER_UDP) */
		/* Set up UDP header at the beginning of out */
		memset (udph, 0, sizeof(udphdr));
		udph->src_port = htons(HIP_ESP_UDP_PORT);
		if ( (udph->dst_port = htons(entry->dst_port))==0) {
			printf ("ESP encrypt : bad UDP dst port number (%u).\n",
				entry->dst_port);
		}
		udph->len = htons ((__u16)*outlen);
		udph->checksum = checksum_udp_packet (out, 
				    (struct sockaddr*)&entry->src_addrs->addr,
				    (struct sockaddr*)&entry->dst_addrs->addr);
	}

	if (entry->spinat) {
		printf("Entry has spinat of 0x%x\n", entry->spinat);
		printf("Changing 0x%x to 0x%x\n", ntohl(esp->spi),
			entry->spinat);
		esp->spi = htonl(entry->spinat);
	}
	return(0);
}


/*
 * hip_esp_decrypt()
 *
 * in:		in	pointer to IP header of ESP packet to decrypt
 * 		len	packet length
 * 		out	pointer of where to build decrypted packet
 * 		offset	offset where decrypted packet is stored: &out[offset]
 * 		outlen	length of new packet
 * 		entry	the SADB entry
 * 		iph     IPv4 header or NULL for IPv6
 * 		now	pointer to current time (avoid extra gettimeofday call)
 *
 * out:		New packet is built in out, outlen.
 * 		Returns 0 on success, -1 otherwise.
 * 
 * Perform authentication and decryption of ESP packets.
 */
int hip_esp_decrypt(__u8 *in, int len, __u8 *out, int *offset, int *outlen,
    hip_sadb_entry *entry, struct ip *iph, struct timeval *now)
{
	int alen=0, elen=0, iv_len=0;
	unsigned int hmac_md_len;
	struct ip_esp_hdr *esp;
	udphdr *udph;

	struct ip_esp_padinfo *padinfo=0;
#ifndef SMA_CRAWLER
	struct tcphdr *tcp=NULL;
	struct udphdr *udp=NULL;
#endif
	__u8 cbc_iv[16];
	__u8 hmac_md[EVP_MAX_MD_SIZE];
	__u64 dst_mac;
#ifdef SMA_CRAWLER
  __u64 src_mac;
#endif
#ifndef SMA_CRAWLER
	__u16 sum;
	int family_out;
	struct sockaddr_storage taplsi6;
#endif
	int use_udp = FALSE;
	
	if (!in || !out || !entry)
		return(-1);


	if (entry->mode == 3) {	/*(HIP_ESP_OVER_UDP) */
		use_udp = TRUE;
		udph = (udphdr*) &in[sizeof(struct ip)];
		esp = (struct ip_esp_hdr*)&in[sizeof(struct ip)+sizeof(udphdr)];
	} else { 		/* not UDP-encapsulated */
		if ( iph ) {	/* IPv4 */
			esp = (struct ip_esp_hdr*) &in[sizeof(struct ip)];
		} else { 	/* IPv6 - header not included */
			esp = (struct ip_esp_hdr*) &in[0];
		}
	}
	/* if (ntohl(esp->spi) != entry->spi)
		return(-1); *//* this check might be excessive */

	/* An IPv6 header is larger than an IPv4 header, so data
	 * is decrypted into a buffer at the larger offset, since
	 * we do not know the (inner) IP version before decryption. */
	*offset = sizeof(struct eth_hdr) + sizeof(struct ip6_hdr); /* 54 */
#ifdef SMA_CRAWLER
        *offset = sizeof(struct eth_hdr);  /* Tunnel mode */
#endif

	/* 
	 *   Authentication 
	 */
	switch (entry->a_type) {
	case SADB_AALG_NONE:
		break;
	case SADB_AALG_MD5HMAC:
		alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
		elen = len - sizeof(struct ip_esp_hdr) - alen;
		if (iph)
			elen -= sizeof(struct ip);
		if (use_udp) /* HIP_ESP_OVER_UDP */
			elen -= sizeof(udphdr);
		if (!entry->a_key || entry->a_keylen==0) {
			printf("auth err: missing keys\n");
			return(-1);
		}
		HMAC(	EVP_md5(), entry->a_key, entry->a_keylen, 
			(__u8*)esp, elen + sizeof(struct ip_esp_hdr),
			hmac_md, &hmac_md_len);
		if (memcmp(&in[len - alen], hmac_md, alen) != 0) {
			printf("auth err: MD5 auth failure\n");
			return(-1);
		}
		break;
	case SADB_AALG_SHA1HMAC:
		alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
		elen = len - sizeof(struct ip_esp_hdr) - alen;
		if (iph)
			elen -= sizeof(struct ip);
		if (use_udp) /* HIP_ESP_OVER_UDP */
			elen -= sizeof(udphdr);
		if (!entry->a_key || entry->a_keylen==0) {
			printf("auth err: missing keys\n");
			return(-1);
		}
#ifdef DEBUG_EVERY_PACKET
		{ 
			int i;
			fprintf(debugfp, "SPI=0x%x in a_key(%d): 0x",
				entry->spi, entry->a_keylen);
			for (i=0; i < entry->a_keylen; i++) {
				if (i%4==0) fprintf(debugfp, " ");
				fprintf(debugfp,"%.2x",entry->a_key[i] & 0xFF);
			}
			fprintf(debugfp, "\n");
			fprintf(debugfp, "len=%d elen=%d alen=%d iph=%p use_udp=%d \n", len, elen, alen, iph, use_udp);
		}
#endif /* DEBUG_EVERY_PACKET */
		HMAC(	EVP_sha1(), entry->a_key, entry->a_keylen, 
			(__u8*)esp, elen + sizeof(struct ip_esp_hdr),
			hmac_md, &hmac_md_len);
#ifdef DEBUG_EVERY_PACKET
		{
			int i;
			fprintf(debugfp, "SHA1: 0x");
			for (i=0; i < alen; i++) {
				if (i%4==0) fprintf(debugfp, " ");
				fprintf(debugfp, "%.2x", hmac_md[i] & 0xFF);
			}
			fprintf(debugfp, "\n");
			fprintf(debugfp, "(pkt(%d): 0x", len);
			for (i=0; i < alen; i++) {
				if (i%4==0) fprintf(debugfp, " ");
				fprintf(debugfp, "%.2x", in[i+len-alen] & 0xFF);
			}
			fprintf(debugfp, ")\n");
			fprintf(debugfp, "bytes(%d): ", elen);
			for (i=0; i < elen; i++) {
				if (i && i%8==0) fprintf(debugfp, " ");
				fprintf(debugfp, "%.2x",((__u8*)esp)[i] & 0xFF);
			}
			fprintf(debugfp, "\n\n");
		}
#endif /* DEBUG_EVERY_PACKET */
		if (memcmp(&in[len - alen], hmac_md, alen) !=0) {
			printf("auth err: SHA1 auth failure SPI=0x%x\n", 
				entry->spi);
			return(-1);
		}
		break;
	case SADB_X_AALG_SHA2_256HMAC:
	case SADB_X_AALG_SHA2_384HMAC:
	case SADB_X_AALG_SHA2_512HMAC:
	case SADB_X_AALG_RIPEMD160HMAC:
	case SADB_X_AALG_NULL:
		break;
	default:
		break;
	}
	
	/*
	 *   Decryption
	 */
	switch (entry->e_type) {
	case SADB_EALG_3DESCBC:
		iv_len = 8;
		if (!entry->e_key || entry->e_keylen==0) {
			printf("hip_esp_decrypt: 3-DES key missing.\n");
			return(-1);
		}
		break;
	case SADB_X_EALG_BLOWFISHCBC:
		iv_len = 8;
		if (!entry->bf_key) {
			printf("hip_esp_decrypt: BLOWFISH key missing.\n");
			return(-1);
		}
		break;
	case SADB_EALG_NULL:
		iv_len = 0;
		break;
	case SADB_X_EALG_AESCBC:
		iv_len = 16;
		if (!entry->aes_key && entry->e_key) {
			entry->aes_key = malloc(sizeof(AES_KEY));
			if (AES_set_decrypt_key(entry->e_key, 8*entry->e_keylen,
						entry->aes_key)) {
				printf("hip_esp_decrypt: AES key problem!\n");
			}
		} else if (!entry->aes_key) {
			printf("hip_esp_decrypt: AES key missing.\n");
			return(-1);
		}
		break;
	case SADB_EALG_NONE:
	case SADB_EALG_DESCBC:
	case SADB_X_EALG_CASTCBC:
	case SADB_X_EALG_SERPENTCBC:
	case SADB_X_EALG_TWOFISHCBC:
	default:
		printf("Unsupported decryption algorithm (%d)\n", 
			entry->e_type);
		break;
	}
	memcpy(cbc_iv, esp->enc_data, iv_len);
	elen -= iv_len; /* don't include iv as part of ciphertext */
	
	switch (entry->e_type) {
	case SADB_EALG_3DESCBC:
		des_ede3_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset],elen,
				     entry->ks[0], entry->ks[1], entry->ks[2],
				     (des_cblock*)cbc_iv, DES_DECRYPT);
		break;
	case SADB_X_EALG_BLOWFISHCBC:
		BF_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset], elen,
				entry->bf_key, cbc_iv, BF_DECRYPT);
		break;
	case SADB_EALG_NULL:
		memcpy(&out[*offset], esp->enc_data, elen);
		//padinfo = (struct ip_esp_padinfo*) &in[len - alen - 2];
		break;
	case SADB_X_EALG_AESCBC:
		AES_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset], elen,
				entry->aes_key, cbc_iv, AES_DECRYPT);
		break;
	default:
		return(-1);
	}

	/* remove padding */
	padinfo = (struct ip_esp_padinfo*) &out[*offset + elen - 2];
	elen -= 2 + padinfo->pad_length;

#ifndef SMA_CRAWLER
	/* determine address family for new packet based on 
	 * decrypted upper layer protocol header
	 */
	family_out = hip_select_family_by_proto(LSI4(&entry->lsi), 
					padinfo->next_hdr, &out[*offset], now);
	
	/* rewrite upper-layer checksum 
	 * checksum based on HITs --> based on LSIs */
	if (family_out == AF_INET) {
		switch (padinfo->next_hdr) {
#ifdef __MACOSX__
	case IPPROTO_TCP:
		tcp = (struct tcphdr*)&out[*offset];
		sum = htons(tcp->th_sum);
		sum = csum_hip_revert(	LSI4(&entry->lsi), htonl(g_tap_lsi),
					sum, htons(entry->hit_magic));
		tcp->th_sum = htons(sum);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr*)&out[*offset];
		sum = htons(udp->uh_sum);
		sum = csum_hip_revert(	LSI4(&entry->lsi), htonl(g_tap_lsi),
					sum, htons(entry->hit_magic));
		udp->uh_sum = htons(sum);
		break;
#else /* __MACOSX__ */
	case IPPROTO_TCP:
		tcp = (struct tcphdr*)&out[*offset];
		sum = htons(tcp->check);
		sum = csum_hip_revert(	LSI4(&entry->lsi), htonl(g_tap_lsi),
					sum, htons(entry->hit_magic));
		tcp->check = htons(sum);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr*)&out[*offset];
		sum = htons(udp->check);
		sum = csum_hip_revert(	LSI4(&entry->lsi), htonl(g_tap_lsi),
					sum, htons(entry->hit_magic));
		udp->check = htons(sum);
#endif /* __MACOSX__ */
	default:
		break;
		}
	}
	
	/* set offset to index the beginning of the packet */
	if (family_out == AF_INET) /* offset = 20 */
		*offset -= (sizeof(struct eth_hdr) + sizeof(struct ip));
	else	/* offset = 0 */
		*offset -= (sizeof(struct eth_hdr) + sizeof(struct ip6_hdr));
	
	/* Ethernet header */
	dst_mac = get_eth_addr(family_out, 
				(family_out==AF_INET) ? SA2IP(&entry->lsi) : 
							SA2IP(&entry->lsi6));
	add_eth_header(&out[*offset], dst_mac, g_tap_mac, 
			(family_out == AF_INET) ? 0x0800 : 0x86dd);
	
	/* IP header */
	if (family_out == AF_INET) {
		add_ipv4_header(&out[*offset+sizeof(struct eth_hdr)],
				LSI4(&entry->lsi), htonl(g_tap_lsi), iph,
				(__u16)(sizeof(struct ip) + elen),
				padinfo->next_hdr);
		*outlen = sizeof(struct eth_hdr) + sizeof(struct ip) + elen;
	} else {
		taplsi6.ss_family = AF_INET6;
		get_preferred_lsi(SA(&taplsi6));
		add_ipv6_header(&out[*offset+sizeof(struct eth_hdr)],
				SA(&entry->lsi6), SA(&taplsi6),
				NULL, iph, (__u16)elen, padinfo->next_hdr);
		*outlen = sizeof(struct eth_hdr) + sizeof(struct ip6_hdr)+ elen;
	}
#else /* SMA_CRAWLER */
	iph = (struct ip*) &out[*offset];    /* the inner IP hdr */
	*offset -= sizeof(struct eth_hdr);   /* where to put the eth hdr */
	dst_mac = 0;
 
	// generate a multicast MAC address
	// 0x01 0x00 0x5e + 23 bits from dest multicast addr

	if(IN_MULTICAST((ntohl(iph->ip_dst.s_addr)))) {
/*
 * If the FWDn and AFTn of a crawler have their switches connected,
 * then all nodes will receive a MAC multicast from both FWDn and AFTn,
 * which screws up their arp tables.
 * We know that it is for the HMI which is the second entry in the
 * private host table. OTB 20070907.
 * We are testing with additional checks and unique psuedo-MACs for the
 * ARP responses, if this works.  OTB 20070928
 * This does not work because each tool still gets two multicasts, but
 * responds to both through its own endbox.  OTB 20071012
 * I am putting code in hip_esp_input() to loop through all hosts in
 * private host table if it is a multicast ip address.  OTB 20080414
 */
	     ((u_char *)&dst_mac)[0] = 0x01;
	     ((u_char *)&dst_mac)[1] = 0x00;
	     ((u_char *)&dst_mac)[2] = 0x5e;
	     ((u_char *)&dst_mac)[3] = ((u_char *)&iph->ip_dst)[1]&0x7f;
	     ((u_char *)&dst_mac)[4] = ((u_char *)&iph->ip_dst)[2];
	     ((u_char *)&dst_mac)[5] = ((u_char *)&iph->ip_dst)[3];
	} else if(((ntohl(iph->ip_dst.s_addr)) & 0x000000FF)==0x000000FF) {
	     ((u_char *)&dst_mac)[0] = 0xff;
	     ((u_char *)&dst_mac)[1] = 0xff;
	     ((u_char *)&dst_mac)[2] = 0xff;
	     ((u_char *)&dst_mac)[3] = 0xff;
	     ((u_char *)&dst_mac)[4] = 0xff;
	     ((u_char *)&dst_mac)[5] = 0xff;
	} else if (iph->ip_dst.s_addr == g_tap_lsi) {
              src_mac = get_eth_addr(AF_INET, SA2IP(&entry->lsi));
              dst_mac = g_tap_mac;
	} else {
	     dst_mac = find_mac(iph->ip_dst.s_addr);
	}
        if(dst_mac == 0) {
                char name[16];
                inet_ntop(AF_INET, &iph->ip_dst.s_addr, name, 16);
                printf("error obtaining host mac address for %s.  ", name);
                inet_ntop(AF_INET, &iph->ip_src.s_addr, name, 16);
                printf("(src = %s)\n", name);
        }

        /* JEFFM JEFFM JEFFM 2/27/2007   */
        add_eth_header(&out[*offset], g_tap_mac, dst_mac, 0x0800);
	*outlen = sizeof(struct eth_hdr) + elen;
#endif /* SMA_CRAWLER */

	/* previously, this happened after write(), but there
	 * is some problem with using the entry ptr then */
	entry->bytes += *outlen - sizeof(struct eth_hdr);
	entry->usetime.tv_sec = now->tv_sec;
	entry->usetime.tv_usec = now->tv_usec;
	entry->usetime_ka.tv_sec = now->tv_sec;
	entry->usetime_ka.tv_usec = now->tv_usec;

	return(0);
}

/*
 * rewrite_checksum()
 * 
 * Rewrite the upper-later TCP/UDP checksum so it is based on the HITs
 * (which are summed and passed in as __u16 magic).
 * Returns the old checksum value, so it can be restored.
 */
__u16 rewrite_checksum(__u8 *data, __u16 magic)
{
	struct ip *iph = (struct ip *)data;
	struct tcphdr *tcp;
	struct udphdr *udp;
	__u16 ret=0;


	/* rewrite upper-layer checksum, so it is based on HITs */
	switch (iph->ip_p) {
	case IPPROTO_TCP:
		tcp = (struct tcphdr*)(iph + 1);
#ifdef __MACOSX__
		ret = tcp->th_sum;
		tcp->th_sum = csum_tcpudp_hip_nofold(
				iph->ip_src.s_addr, iph->ip_dst.s_addr,
				tcp->th_sum, magic);
#else
		ret = tcp->check;
		tcp->check = csum_tcpudp_hip_nofold(
				iph->ip_src.s_addr, iph->ip_dst.s_addr,
				tcp->check, magic);
#endif
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr*)(iph + 1);
#ifdef __MACOSX__
		ret = udp->uh_sum;
		udp->uh_sum = csum_tcpudp_hip_nofold(
				iph->ip_src.s_addr, iph->ip_dst.s_addr,
				udp->uh_sum, magic);
#else
		ret = udp->check;
		udp->check = csum_tcpudp_hip_nofold(
				iph->ip_src.s_addr, iph->ip_dst.s_addr,
				udp->check, magic);
#endif
		break;
	default:
		break;
	}
	return(ret);
}


/*
 * add_eth_header()
 *
 * Build an Ethernet header.
 */
void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type)
{
	struct eth_hdr *eth = (struct eth_hdr*)data;

	memcpy(eth->dst, &dst, 6);
	memcpy(eth->src, &src, 6);
	eth->type = htons((__u16)type);
}

/*
 * add_ipv4_header()
 *
 * Build an IPv4 header, copying some parameters from an old ip header (old),
 * src and dst in host byte order. old may be NULL.
 */
void add_ipv4_header(__u8 *data, __u32 src, __u32 dst, struct ip *old, 
	__u16 len, __u8 proto)
{
	struct ip *iph = (struct ip*)data;

	memset(iph, 0, sizeof(struct ip));
	iph->ip_v = 4;
	iph->ip_hl = 5;
	iph->ip_tos = old ? old->ip_tos : 0; /* preserve TOS field */
	iph->ip_len = htons(len);
	iph->ip_id  = old ? old->ip_id : 0;  /* copy identification */
	iph->ip_off = old ? old->ip_off : 0; /* copy fragmentation offset */
	iph->ip_ttl = old ? old->ip_ttl : 255; /* preserve TTL */
	iph->ip_p = proto;
	iph->ip_sum = 0;
	iph->ip_src.s_addr = htonl(src); /* assume host byte order */
	iph->ip_dst.s_addr = htonl(dst);

	/* add the header checksum */
#if defined(__MACOSX__) && defined(__BIG_ENDIAN__)
	iph->ip_sum = ip_fast_csum((__u8*)iph, 20);
#else
	iph->ip_sum = ip_fast_csum((__u8*)iph, iph->ip_hl);
#endif	
}

/*
 * add_ipv6_pseudo_header()
 *
 * Build an IPv6 pseudo-header for upper-layer checksum calculation.
 */
void add_ipv6_pseudo_header(__u8 *data, struct sockaddr *src, 
	struct sockaddr *dst, __u32 len, __u8 proto)
{
	int l;
	struct _ph {
		__u32 ph_len;
		__u8 ph_zero[3];
		__u8 ph_next_header;
	} *ph;
	memset(data, 0, 40);

	/* 16 bytes source address, 16 bytes destination address */
	l = sizeof(struct in6_addr);
	memcpy(&data[0], SA2IP(src), l);
	memcpy(&data[l], SA2IP(dst), l);
	l += sizeof(struct in6_addr);
	/* upper-layer packet length, zero, next header */
	ph = (struct _ph*) &data[l];
	ph->ph_len = htonl(len);
	memset(ph->ph_zero, 0, 3);
	ph->ph_next_header = proto;
}

/*
 * add_ipv6_header()
 *
 * Build an IPv6 header, copying some parameters from an old header (old),
 * src and dst in network byte order.
 */
void add_ipv6_header(__u8 *data, struct sockaddr *src, struct sockaddr *dst,
	struct ip6_hdr *old, struct ip *old4, __u16 len, __u8 proto)
{
	struct ip6_hdr *ip6h = (struct ip6_hdr*)data;
	__u32 tc;

	memset(ip6h, 0, sizeof(struct ip6_hdr));
	ip6h->ip6_flow = 0; /* zero the version (4), TC (8), flow-ID (20) */
	ip6h->ip6_vfc = 0x60;
	ip6h->ip6_plen = htons(len);
	ip6h->ip6_nxt = proto;
	ip6h->ip6_hlim = 255;
	memcpy(&ip6h->ip6_src, SA2IP(src), sizeof(struct in6_addr));
	memcpy(&ip6h->ip6_dst, SA2IP(dst), sizeof(struct in6_addr));

	/* Try to preserve flow label and hop limit where possible. */
	if (old) {
		ip6h->ip6_flow = old->ip6_flow;
		ip6h->ip6_hlim = old->ip6_hlim;
	} else if (old4) {
		tc = old4->ip_tos << 24;
		ip6h->ip6_flow |= tc; 	/* 8 bits traffic class */
		ip6h->ip6_hlim = old4->ip_ttl;		/* __u8 */
	}
}


#ifdef __MACOSX__

void add_outgoing_esp_header(__u8 *data, __u32 src, __u32 dst, __u16 len)
{
	struct ip *iph = (struct ip*)data;

	memset(iph, 0, sizeof(struct ip));
	iph->ip_v = 4;
	iph->ip_hl = 5;
	iph->ip_tos = 0;
	iph->ip_len = htons(len + sizeof(struct ip));
	iph->ip_id  = 1337;
	iph->ip_off = htons(0x4000);
	iph->ip_ttl = 64;
	iph->ip_p = IPPROTO_ESP;
	iph->ip_sum = 0;
	iph->ip_src.s_addr = src; 
	iph->ip_dst.s_addr = dst;

	/* add the header checksum */
	iph->ip_sum = ip_fast_csum((__u8*)iph, iph->ip_hl);
}



#endif

/*
 * get_mac_addr()
 * Give a random 6-bit Ethernet address given an IPv4/IPv6 address.
 */
__u64 get_eth_addr(int family, __u8 *addr)
{
	__u32 index=0, *p;
	int i, len;
	__u64 r=0;
	
	if (!addr)
		return 0;
	
	/* sum the 32-bit words in address */
	p = (__u32*) addr;
	len = (family == AF_INET) ? 4 : 16;
	for (i = 0; i < len; i+=4) {
		index += *p++;
	}

	/* use sum as index into array of Ethernet addresses */
	index %= MAX_ETH_ADDRS;
	memcpy(&r, &eth_addrs[index], 6);
	((char *)&r)[0] &= 0xFE; /* clear the multicast bit */
	
	return(r);
}


