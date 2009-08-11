/*
 * Host Identity Protocol
 * Copyright (C) 2005-06 the Boeing Company
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
 *  hip_dns.c
 *
 *  Author: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * DNS answering thread for user-mode HIP
 *
 */

#ifdef __MACOSX__
#include <sys/types.h>		/* __u32, etc */
#include <mac/mac_types.h>
#endif
#ifdef __WIN32__
#define _WIN32_WINNT 0x0500
#include <windows.h>		/* GetComputerNameEx */
#include <win32/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <io.h>
#include <time.h>
#include <WinDNS.h>
#define NS_MAXDNAME DNS_MAX_NAME_LENGTH
#define NS_PACKETSZ DNS_RFC_MAX_UDP_PACKET_LENGTH
#else
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#else
#include <asm/types.h>		/* __u32, etc */
#endif
#include <netinet/in.h>		/* struct sockaddr_in */
#include <netinet/udp.h>	/* struct sockaddr_in */
#include <arpa/inet.h>		/* inet_addr() */
#include <unistd.h>
#include <pthread.h>		/* phread_exit() */
#include <sys/time.h>		/* gettimeofday() */
#include <arpa/nameser.h>	/* NS_PACKETSZ */
#endif
#ifdef SMA_CRAWLER
#include <utime.h>
#endif
#include <stdio.h>		/* printf() */
#include <string.h>		/* strerror() */
#include <errno.h>		/* errno */
#include <openssl/rand.h>	/* RAND_bytes() */
#include <hip/hip_types.h>	/* dns structures */
#include <hip/hip_funcs.h>	/* dns structures */
#include <hip/hip_dns.h>	/* dns structures */
#include <hip/hip_usermode.h>
#include <hip/hip_sadb.h>	/* access to SADB */

/*
 * Globals
 */
int dnsfd;
__u16 g_txid;
#ifdef __WIN32__
char dns_domain[255]; /* name of this machine's domain */
#endif
extern __u32 lsi_name_lookup(char *name, int namelen);
extern __u32 get_preferred_lsi(struct sockaddr *);
extern __u32 receive_hip_dns_response(unsigned char *buff, int len);
extern struct sockaddr *get_hip_dns_server();

/* 
 * Local function declarations
 */
int init_dns_socket();
void handle_dns_request(char *buff, int len, struct sockaddr *from);
int parse_dns_name(char *name, char *dst, int *dst_len, int *type);
int send_dns_response(char *buff, int len, struct sockaddr *to, int anstype,
	char *ans);
int forward_dns_request(char *buff, int len, struct sockaddr *to);
__u16 send_hip_dns_lookup(char *name, int name_len);
__u32 get_current_dns_server();
int queue_request_info(__u16 xid, __u16 hip_request, struct sockaddr *addr);
int get_request_info(__u16 xid, __u16 hip_request, struct sockaddr *addr);
char **get_request_old_buff(__u16 xid);


/* internal data structure used to queue requests */
#define DNS_REQ_TABLE_SIZE 128
struct dns_request_info {
	__u16 xid;		/* DNS transaction ID */
	__u16 hip_request;	/* flag: 1=HIP RR lookup, 0=others */
	struct sockaddr addr;	/* request originator */
	char *old_buff;		/* for HIP RR queries, buff of non-HIP query */
};
struct dns_request_info dns_reqs[DNS_REQ_TABLE_SIZE];

/* SALEN() is not compiling correctly due to lack of IPv6 headers */
#define SALEN4(a) (sizeof struct sockaddr_in)
#define TDIFF(a, b) ((a).tv_sec - (b).tv_sec) /* Time diff in seconds */

#if 0
/* debugging code */
#define DUMP_WIDTH 16
void dns_hex_dump(char *data, int len)
{
	int i, idx=0;
	while (idx < (len-DUMP_WIDTH)) {
		for (i=0; i < DUMP_WIDTH; i++)
			printf("%2x ", data[idx + i] & 0xFF);
		printf("\n");
		idx += DUMP_WIDTH;	
	}
	for (i=idx; i<len; i++)
		printf("%x ", data[idx + i] & 0xFF);
	printf("\n");
}

void dump_dns_hdr(struct dns_hdr *hdr)
{
	if (!hdr) return;
	printf("transid=%x ", hdr->transaction_id);
	printf("flags=%x ", hdr->flags);
	printf("qcnt=%x ", hdr->question_count);
	printf("acnt=%x ", hdr->answer_count);
	printf("nscnt=%x ", hdr->namesrvr_count);
	printf("adcnt=%x\n", hdr->additional_count);
}
#endif

/*
 * hip_dns()
 *
 * A simple DNS thread, intercepts DNS requests from applications and
 * responds with an LSI. Forwards non-HIP DNS requests to the real DNS
 * server to avoid the 2 second timeout.
 *
 */
#ifdef __WIN32__
void hip_dns(void *arg)
#else
void *hip_dns(void *arg)
#endif
{
	int err, len;
	char buff[1024];
	fd_set read_fdset;
	struct timeval timeout;
	struct sockaddr from;
	socklen_t from_len;
#ifdef __WIN32__
	DWORD dw_size;
#endif


#ifdef SMA_CRAWLER
        time_t last_time, now_time;
        last_time = time(NULL);
        printf("hip_dns() thread (tid %d pid %d) started...\n",
                       (unsigned)pthread_self(), getpid());
#else
	printf("hip_dns() thread started...\n");
#endif
	/* initialize UDP port 53 socket */
	if (!(dnsfd = init_dns_socket())) {
		printf("Could not create DNS socket, aborting DNS thread.\n");
		fflush(stdout);
		return RETNULL
	}
#ifdef __WIN32__
	/* Windows optimization - get this machine's DNS domain name
	 * for later use
	 */
	dw_size = sizeof(dns_domain) - (sizeof(HIP_DNS_SUFFIX)+1);
	sprintf(dns_domain, "%s.", HIP_DNS_SUFFIX);
	if (!GetComputerNameEx(2, 
			&dns_domain[sizeof(HIP_DNS_SUFFIX)+1], &dw_size)) {
		printf("Warning: couldn't get this host's DNS domain name.\n");
		memset(dns_domain, 0, sizeof(dns_domain));
	}
#endif /* __WIN32__ */

	while(g_state == 0) {
		FD_ZERO(&read_fdset);
		FD_SET((unsigned)dnsfd, &read_fdset);
		timeout.tv_sec = 0;
		timeout.tv_usec = 500000;

#ifdef SMA_CRAWLER
                now_time = time(NULL);
                if (now_time - last_time > 60) {
                        printf("hip_dns() heartbeat\n");
                        last_time = now_time;
                        utime("/usr/local/etc/hip/heartbeat_hip_dns", NULL);
                }
#endif

		if ((err = select((dnsfd + 1), &read_fdset,
				  NULL, NULL, &timeout) < 0)) {
			if (errno == EINTR)
				continue;
			printf("hip_dns(): select() error: %s.\n",
				strerror(errno));
		} else if (FD_ISSET(dnsfd, &read_fdset)) {
			from_len = sizeof(struct sockaddr_in);
			if ((len = recvfrom(dnsfd, buff, sizeof(buff), 0, 
					    &from, &from_len)) < 0) {
				if (errno != EINTR)
					printf("DNS read error: %s\n",
						strerror(errno));
				continue;
			}
			handle_dns_request(buff, len, &from);
			
		} /* endif select() */

	}

	printf("hip_dns() thread shutdown.\n");
	fflush(stdout);
#ifndef __WIN32__
	pthread_exit((void *) 0);
#endif
	return RETNULL
}


/*
 * init_dns_socket()
 */
int init_dns_socket()
{
	int sockfd, retry_count=0;
	struct sockaddr_in saddr;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("Error creating DNS socket.\n");
		return(-1);
	}

retry_dns_bind:
	memset(&saddr, 0, sizeof(struct sockaddr_in));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (retry_count) /* upon retry, bind specifically to the LSI */
		get_preferred_lsi(SA(&saddr));
	saddr.sin_port = htons(DNS_PORT);

	if (bind(sockfd, (struct sockaddr *) &saddr, 
			sizeof(struct sockaddr_in) ) < 0) {
		printf("Error binding DNS socket: (%d) %s\n", errno,
			strerror(errno));
#ifdef __WIN32__
		errno = WSAGetLastError();
		if ((errno == WSAEADDRNOTAVAIL) && retry_count < 5) {
#else
		if (((errno == EADDRNOTAVAIL) || (errno==EADDRINUSE)) && 
		    (retry_count < 5)) {
#endif
			hip_sleep(1);
			/* retry after one second */
			printf("Retrying DNS bind...\n");
			retry_count++;
			goto retry_dns_bind;
		}
#ifdef __WIN32__
		closesocket(sockfd);
#else
		close(sockfd);
#endif
		return(0);
	}

	return(sockfd);
}


/*
 * handle_dns_request()
 *
 * in:		buff - buffer containing the raw DNS request
 * 		len  - length of the buffer data
 * 		from - address of the requester
 * out:		none
 *
 * Parse the DNS request and answer those ending with .hip suffix.
 * Forward normal (non .hip) requests to the real DNS server.
 * Optimize for speed here.
 */
void handle_dns_request(char *buff, int len, struct sockaddr *from)
{
	struct dns_hdr *dnsh = (struct dns_hdr *)buff;
	struct sockaddr to;
	struct sockaddr_in ntaplsi, *to4 = (struct sockaddr_in*) &to;
	char namebuff[255], s_tap[16], **old_buff;
	int ret, type, namelen, is_answer;
	__u32 lsi, taplsi;
	__u16 txid;

	if (!buff || !from || len < sizeof(struct dns_hdr))
		return;

	is_answer = (ntohs(dnsh->flags) & DNS_FLAG_ANSWER);
	ntaplsi.sin_family = AF_INET;
	get_preferred_lsi(SA(&ntaplsi)); /* this call may block */
	taplsi = ntohl(ntaplsi.sin_addr.s_addr);
	sprintf(s_tap, "%u.%u.%u.%u", NIPQUAD(taplsi));
	taplsi = ntohl(taplsi); 	/* recvfrom uses host order */

	/* only reply to local requests */
	if ( !is_answer && 
	     (((struct sockaddr_in *)from)->sin_addr.s_addr != taplsi))
		return;
	
	/* 
	 * Responses from the real DNS server are matched
	 * with their original request and forwarded back.
	 *
	 * Responses from the HIP DNS server are matched
	 * with their original request, parsed/validated,
	 * and the LSI is returned.
	 */
	if (is_answer) {
		if (get_request_info(dnsh->transaction_id, 0, from) < 0) {
			/* check for HIP answer */
			if (get_request_info(dnsh->transaction_id, 1, from) < 0)
				return; /* transaction not found */
			old_buff = get_request_old_buff(dnsh->transaction_id);
			if (!old_buff || !*old_buff)
				return; /* empty buffer */
			/* parse Host Identity from response and get LSI */
			lsi = receive_hip_dns_response((unsigned char *)buff, len);
			namelen = sizeof(namebuff); /* read namelen, type */
			parse_dns_name(*old_buff + sizeof(struct dns_hdr), 
					namebuff, &namelen, &type);
			/* send response back */
			if (lsi == 0)	/* send NXDOMAIN */
				send_dns_response(*old_buff, namelen, from,
						  DNS_TYPE_NXDOMAIN, NULL);
			else		/* send reply */
				send_dns_response(*old_buff, namelen, from,
						  type, (char*)&lsi);
			free(*old_buff); /* free after sendto() completed */
			*old_buff = NULL;
			return;
		}
		/* fast path */
		forward_dns_request(buff, len, from);
		return;
	/* 
	 * DNS queries are examined for a ".hip" suffix.
	 * Normal requests are forwarded to the real DNS
	 * server.
	 */
	} else if (ntohs((__u16)(dnsh->question_count > 0))) {
		/*
		 * Does name end with .hip suffix?
		 */
		namelen = sizeof(namebuff);
		ret = parse_dns_name((char*)(dnsh+1), namebuff, &namelen,&type);
		if (ret == 1) {
			/* Lookup DNS name in local peer list */
			if ((lsi = lsi_name_lookup(namebuff,
						   namelen-4))) {
				/* Name found in known_host_identities file,
				 * respond with LSI. */
				send_dns_response(buff, namelen, from, type,
						  (char*)&lsi);
			/* Name not found locally, look for HIP record in DNS.*/
			} else {
				/* We do not use res_query() here because that
				 * HIP request will end up back here in the DNS
				 * thread causing unnecessary delay.
				 */
				txid = send_hip_dns_lookup(namebuff, namelen-4);
				if (txid == 0)
					return;
				/* save original request in old_buff 
				 * we malloc(+16) so there's room to later
				 * append the IPv4 LSI answer
				 */
				queue_request_info(txid, 1, from);
				old_buff = get_request_old_buff(txid);
				*old_buff = malloc(len + 16);
				if (!*old_buff) {
					printf("hip_dns: malloc error\n");
					return;
				} /* XXX if we never receive a response, then
				   *      we need to somehow free old_buff 
				   */
				memcpy(*old_buff, buff, len);
			}
			return;
#ifdef __WIN32__
		/* reply to .hip suffix plus domain name to eliminate
		 * unnecessary 2 second timeout */
		} else if (ret == 2) {
			send_dns_response(buff, namelen, from,
					  DNS_TYPE_NXDOMAIN, NULL);
			return;
#endif /* __WIN32__ */
		/* reply to reverse lookups of self */
		} else if ((type == DNS_TYPE_PTR) &&
			   (strncmp(namebuff, s_tap, strlen(s_tap)) == 0)) {
			send_dns_response(buff, namelen, from, type,
					  "localhost");
			return;
		} /* end if ".hip" or type==DNS_TYPE_PTR */

		/* forward requests to real DNS server */
		queue_request_info(dnsh->transaction_id, 0, from);
		to4->sin_family = AF_INET;
		to4->sin_addr.s_addr = get_current_dns_server();
		to4->sin_port = htons(DNS_PORT);
		/* no server available */
		if (!to4->sin_addr.s_addr)
			return; /* respond w/NXDOMAN? */
		else
			forward_dns_request(buff, len, &to);
	}
}


/*
 * parse_dns_name()
 *
 * in:		name - pointer to name from question section of DNS request
 * 		dst - pointer to string for storing parsed name
 * 		dst_len - length of dst buffer
 *
 * out:		dst_len - number of bytes found in string
 * 		Returns 2 if name ends with HIP_DNS_SUFFIX + dns_domain
 * 		Returns 1 if name ends with HIP_DNS_SUFFIX
 * 
 * Read in a name from the DNS question section, storing it in the provided
 * string and placing '.' between each section. Returns 1 if the name ends
 * with the HIP_DNS_SUFFIX.
 */
int parse_dns_name(char *name, char *dst, int *dst_len, int *type)
{
	char *suffix_start=NULL;
	char *p, *start;
	int len, total=0;
	__u16 *tc;
#ifdef __WIN32__
	char *first_section;
#endif /* __WIN32__ */

	memset(dst, 0, *dst_len);

	/* DNS name consists of a series of sections
	 * that begin with their section length */
	len = name[0];
	start = &name[1];
	for (p = start; (*p != 0) && (total < *dst_len); p++) {
		/* read new section length, place "." between sections */
		if (len == 0) {
			len = *p;		/* get new length */
			dst[p - start] = '.';	/* replace length with '.' */
#ifdef __WIN32__
			if (!suffix_start) first_section = &dst[p - start];
#endif /* __WIN32__ */
			suffix_start = &dst[p - start]; /* save last '.' */
		/* copy to destination string as-is */
		} else {
			dst[p - &name[1]] = *p;
			len--;
		}
		total++;
	}

	/* return total bytes */
	*dst_len = total;
	tc = (__u16*) &name[total+2];
	*type = (int) ntohs(*tc);

#ifdef __WIN32__
	/* check for HIP suffix with appended domain 
	 * (i.e. host.hip.mydomain.com) - causes large speed-up for Windows
	 */
	len = strlen(dns_domain);
	if ((first_section) && (strncmp(first_section, dns_domain, len)==0))
		return(2);
#endif /* __WIN32__ */
	/* check for HIP suffix */
	len = sizeof(HIP_DNS_SUFFIX);
	if ((suffix_start) && (strncmp(suffix_start, HIP_DNS_SUFFIX, len)==0))
		return(1);

	return(0);
}

/*
 * build_dns_name()
 *
 * in:		name - pointer to string containing name
 * 		name_len - length of name
 * 		dst - pointer for storing name in DNS format
 *
 * out:		Returns number of bytes occupied by DNS name.
 * 
 * Convert a string into a DNS name for inclusion in a DNS question section.
 */
int build_dns_name(char *name, int name_len, char *dst)
{
	char *p, *plabel, *plabel_len;
	int total=0, label_len=0;

	/* DNS name consists of a series of sections
	 * that begin with their section length */
	plabel_len = &dst[0];
	plabel = &dst[1];
	for (p = name; (*p != 0) && (total < name_len); p++) {
		if (*p == '.') { /* go back to plabel_len and record length */
			*plabel_len = label_len;
			plabel_len = plabel;
			plabel++;
			*plabel_len = 0;
			label_len = 0;
		} else {	/* copy string character to label */
			label_len++;
			*plabel = *p;
			plabel++;
		}
		total++;
	}

	/* terminate with zero length label */
	*plabel_len = label_len;
	*plabel = '\0';
	total += 2;

	/* return total bytes */
	return(total);
}

/*
 * send_dns_response()
 *
 * in:		buff = pointer to original request buffer
 * 		namelen = length of domain name in question
 * 		to = where to send the DNS reply
 * 		anstype = type A or PTR answer?
 * 		ans = name to answer for reverse lookups
 *
 * Use the dns request to generate an answer.
 */
int send_dns_response(char *buff, int namelen, struct sockaddr *to, int anstype,
	char *ans)
{
	struct dns_hdr *dnsh;
	struct dns_ans_hdr *ansh;
	char *p;
	int err;

	dnsh = (struct dns_hdr*)buff;
	
	dnsh->flags |= htons(DNS_FLAG_ANSWER);
	dnsh->flags |= htons(DNS_FLAG_AUTHORITATIVE);
	/* answer section begins after DNS headers, plus length of
	 * domain name plus 4 bytes for type/class and 2 bytes for
	 * (start, end) name lengths */
	p = (char*)(dnsh+1);
	p += 6 + namelen;
	if (anstype == DNS_TYPE_NXDOMAIN) {
		dnsh->answer_count = 0;
		dnsh->flags |= htons(DNS_FLAG_NXDOMAIN);
	} else {
		/* add an answer - requires more buffer space */
		dnsh->answer_count = htons(1);
		ansh = (struct dns_ans_hdr*) p;
		ansh->ans_name = htons(0xC00C);
		ansh->ans_type = htons((__u16)anstype);
		ansh->ans_class = htons(DNS_QTYPE_CLASS_IN);
		ansh->ans_ttl = htonl(DNS_DEFAULT_TTL); /* default 1hr */
		switch (anstype) {
		case DNS_TYPE_A:
			ansh->ans_len = htons(sizeof(__u32));
			p = (char*)(ansh+1);
			memcpy(p, ans, sizeof(__u32));
			p += sizeof(__u32);
			break;
		case DNS_TYPE_PTR:
			ansh->ans_len = htons((__u16)(strlen(ans) + 2));
			p = (char*)(ansh+1);
			*p = strlen(ans);
			p++;
			p += sprintf(p, "%s", ans) + 1;
			break;
		default: /* unknown answer type */
			return(-1);
		}
	}
	
	/* 
	 * send response back to specified address/port
	 */
	if ((p - buff) > NS_PACKETSZ) {
		printf("send_dns_response(): name length error (len=%d)\n",
			(int)(p - buff));
		return(-1);
	}
	if ((err = sendto(dnsfd, buff, p - buff, 0, to, SALEN(to))) < 0) {
		printf("send_dns_response() sendto() error: %s\n", 
			strerror(errno));
		return(-1);
	}
	return(0);
}

#ifndef __WIN32__
#define USE_LINUX
#endif
/*
 * get_current_dns_server()
 *
 * Windows: use GetPerAdapterInfo() to return DNS server address
 * Linux: reads /etc/resolv.conf file to return DNS server address
 */
__u32 get_current_dns_server() {
#ifdef __WIN32__
	static struct timeval last = {0, 0};
#else
	static struct timeval last = {.tv_sec=0, .tv_usec=0};
#endif
	static __u32 addr=0;
	struct timeval now;
#ifdef USE_LINUX
	int len;
	char buff[4096], *p;
	FILE *f;
	memset(buff, 0, sizeof(buff));
#else
	ULONG len=0, len2;
	PIP_ADAPTER_INFO pAdapterInfo, pai;
	PIP_PER_ADAPTER_INFO pPerAdapterInfo=NULL;
#endif

	/* cache DNS server result for 5 minutes */
	gettimeofday(&now, NULL);
	if (TDIFF(now, last) < 300)
		return(addr);
	last.tv_sec = now.tv_sec;
	last.tv_usec = now.tv_sec;
#ifndef USE_LINUX
	GetAdaptersInfo(NULL, &len);
	pAdapterInfo = (PIP_ADAPTER_INFO)malloc(len);
	GetAdaptersInfo(pAdapterInfo, &len);

	for (pai = pAdapterInfo; pai; pai = pai->Next) {
		if (!pai->GatewayList.IpAddress.String[0])
			continue;
		len2 = 0;
		GetPerAdapterInfo(pai->Index, NULL, &len2);
		pPerAdapterInfo = (PIP_PER_ADAPTER_INFO)malloc(len2);
		GetPerAdapterInfo(pai->Index, pPerAdapterInfo, &len2);
		if (pPerAdapterInfo->DnsServerList.IpAddress.String[0]) {
			// XXX TODO: verify that addr is in network byte order
			addr = inet_addr(
			       pPerAdapterInfo->DnsServerList.IpAddress.String);
		}
		if (pPerAdapterInfo)
			free(pPerAdapterInfo);
		pPerAdapterInfo = NULL;
		break;
	}
	free(pAdapterInfo);
#else

	f = fopen("/etc/resolv.conf", "r");
	if (!f) return(0);
	while ((len = fread(buff, 1, sizeof(buff), f))) {
		for (p = buff; (p = strstr(p, "nameserver ")); p += 11) {
			/* position past "nameserver " (11 bytes) */
			addr = inet_addr(p + 11);
			if ((addr != INADDR_NONE) && (!IS_LSI32(addr)))
				break;
		}
	}
	fclose(f);
#endif
	if (IS_LSI32(addr))
		addr = 0;
	return(addr); /* return address in network byte order */
}

/* 
 * forward_dns_request()
 * 
 * Send the DNS request in buff to the specified address.
 */
int forward_dns_request(char *buff, int len, struct sockaddr *to) {
	int err;
	__u32 ip = ((struct sockaddr_in*)to)->sin_addr.s_addr;
	/* printf("forward_dns_request() to %u.%u.%u.%u\n", NIPQUAD(ip)); */

	/* check for empty address
	 */
	if ((to->sa_family == AF_INET) && (!ip))
		return(0);
	
	/* may want a separate forwarding socket here, if we are worried 
	 * about overloading the use of UDP port 53.
	 */
	if ((err = sendto(dnsfd, buff, len, 0, to, SALEN(to))) < 0) {
		printf("forward_dns_request(): sendto() error: %s\n",
			strerror(errno));
		return(-1);
	}
	return(0);
}


/*
 * send_hip_dns_lookup()
 *
 * Request a HIP record from the DNS server. Returns the transaction ID for
 * this request or zero on error.
 */
__u16 send_hip_dns_lookup(char *name, int name_len)
{
	int err, len;
	char buff[NS_PACKETSZ];
	struct dns_hdr *dnsh;
	__u16 u16;
	struct sockaddr_storage to;
	struct sockaddr *addr;

	/* initialize DNS transaction id */
	if (g_txid == 0)
		RAND_bytes((unsigned char*)&g_txid, 2);
	else
		g_txid++;
	
	/* DNS header */
	memset(buff, 0, sizeof(buff));
	dnsh = (struct dns_hdr*) buff;
	dnsh->transaction_id = htons(g_txid);
	dnsh->flags = htons(DNS_FLAG_MASK_STDQUERY);
	dnsh->question_count = htons(1);
	dnsh->answer_count = 0;
	dnsh->namesrvr_count = 0;
	dnsh->additional_count = 0;
	len = sizeof(struct dns_hdr);
	
	len += build_dns_name(name, name_len, &buff[len]); 	/* QNAME */
	u16 = htons(HIP_RR_TYPE);
	memcpy(&buff[len], &u16, 2);				/* QTYPE */
#ifdef __WIN32__
	u16 = htons(DNS_CLASS_INTERNET);
#else
	u16 = htons(ns_c_in);
#endif
	memcpy(&buff[len+2], &u16, 2);				/* QCLASS */
	len += 4;

	/* send HIP DNS request to a real name server */
	memset(&to, 0, sizeof(struct sockaddr_storage));
	if ((addr = get_hip_dns_server())) { /* use address from hip.conf */
		memcpy(&to, addr, SALEN(addr));
		if (addr->sa_family == AF_INET) {
			((struct sockaddr_in*)&to)->sin_port = htons(DNS_PORT);
		} else {
			((struct sockaddr_in6*)&to)->sin6_port =htons(DNS_PORT);
		}
	} else {			     /* use address from resolv.conf */
		((struct sockaddr_in*)&to)->sin_family = AF_INET;
		((struct sockaddr_in*)&to)->sin_addr.s_addr = 
						get_current_dns_server();
		if (!((struct sockaddr_in*)&to)->sin_addr.s_addr)
			return(0); /* no name server available */
		((struct sockaddr_in*)&to)->sin_port = htons(DNS_PORT);
		/* XXX get_current_dns_server() should
		 *      support IPv6 from resolv.conf */
	}
	err = forward_dns_request(buff, len, (struct sockaddr *)&to);
	if (err < 0)
		return(0);
	return(htons(g_txid));
}



/*
 * queue_request_info()
 *
 * Put the return address of a DNS request into the queue.
 */
int queue_request_info(__u16 xid, __u16 hip_request, struct sockaddr *addr) {
	int hash = (xid % DNS_REQ_TABLE_SIZE);
	dns_reqs[hash].xid = xid;
	dns_reqs[hash].hip_request = hip_request;
	memcpy(&dns_reqs[hash].addr, addr, SALEN(addr));
	if (dns_reqs[hash].old_buff) {
		free(dns_reqs[hash].old_buff);
		dns_reqs[hash].old_buff = NULL;
	}
	return(0);
}

/*
 * get_request_info()
 *
 * Get the return address of a DNS request from the queue.
 * Returns 0 if found, -1 if not found.
 */
int get_request_info(__u16 xid, __u16 hip_request, struct sockaddr *addr) {
	int hash = (xid % DNS_REQ_TABLE_SIZE);
	if (dns_reqs[hash].xid == xid) {
		if (dns_reqs[hash].hip_request != hip_request)
			return(-1);
		memcpy(addr, &dns_reqs[hash].addr, SALEN(&dns_reqs[hash].addr));
		return(0);
	} else {
		memset(addr, 0, sizeof(struct sockaddr));
		return(-1);
	}
}

/*
 * get_request_old_buff()
 *
 * Get a pointer to the old_buff element.
 */
char **get_request_old_buff(__u16 xid) {
	int hash = (xid % DNS_REQ_TABLE_SIZE);
	if (dns_reqs[hash].xid == xid) {
		return(&dns_reqs[hash].old_buff);
	}
	return NULL;
}

/*
 * add_local_hip_nameserver()
 *
 * Set the nameserver in Linux by adding 1.x.x.x to the beginning
 * of the /etc/resolv.conf file.
 */
void add_local_hip_nameserver(__u32 ip)
{
	size_t len;
	FILE *f;
	char buff[4096], tapstr[32]; /* buff holds all of resolv.conf */
	memset(buff, 0, sizeof(buff));
	memset(tapstr, 0, sizeof(tapstr));

	f = fopen("/etc/resolv.conf", "r+");
	if (!f) return;
	sprintf(tapstr, "nameserver %u.%u.%u.%u\n", NIPQUAD(ip));
	len = fread(buff, sizeof(char), sizeof(buff), f);
	if (len && (strstr(buff, tapstr))) { /* does 1.x.x.x already exist? */
		fclose(f);
		return;
	}
	rewind(f);
	if (fwrite(tapstr, sizeof(char), strlen(tapstr), f) != strlen(tapstr))
		printf("Warning: unable to write HIP DNS entry to "
			"/etc/resolv.conf\n");
	if (fwrite(buff, sizeof(char), len, f) != len)
		printf("Warning: unable to preserve %d bytes of data in "
			"/etc/resolv.conf\n", (int)len);
	fclose(f);
}

/*
 * delete_local_hip_nameserver()
 *
 * Remove 1.x.x.x from the /etc/resolv.conf file.
 */
void delete_local_hip_nameserver(__u32 ip)
{
	size_t len;
	FILE *f;
	char buff[4096], tapstr[32]; /* buff holds all of resolv.conf */
	memset(buff, 0, sizeof(buff));
	memset(tapstr, 0, sizeof(tapstr));

	f = fopen("/etc/resolv.conf", "r+");
	if (!f) return;

	sprintf(tapstr, "nameserver %u.%u.%u.%u\n", NIPQUAD(ip));
	len = fread(buff, sizeof(char), sizeof(buff), f);
	fclose(f);
	/* if 1.x.x.x LSI already exists, rewrite the file without it */
	if (len && (strstr(buff, tapstr))) { 
		f = fopen("/etc/resolv.conf", "w");
		len -= strlen(tapstr);
		if (fwrite(&buff[strlen(tapstr)], sizeof(char), len, f) != len)
			printf("Warning: unable to remove HIP DNS entry from "
				"/etc/resolv.conf\n");
		fclose(f);
	}
}
