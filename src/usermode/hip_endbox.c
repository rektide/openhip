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
#include <stdio.h>		/* printf() */
#include <sys/stat.h>
#include <unistd.h>		/* write() */
#include <pthread.h>		/* pthread_exit() */
#include <sys/time.h>		/* gettimeofday() */
#include <sys/errno.h>		/* errno, etc */
#include <netinet/ip.h>		/* struct ip */
#include <netinet/ip6.h>	/* struct ip6_hdr */
#include <netinet/icmp6.h>	/* struct icmp6_hdr */
#include <netinet/tcp.h>	/* struct tcphdr */
#include <netinet/udp.h>	/* struct udphdr */
#include <arpa/inet.h>		
#include <linux/types.h>	/* for pfkeyv2.h types */
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

#if defined(__BIG_ENDIAN__) && defined( __MACOSX__)
#include <mac/checksum_mac.h>
#else
#include <win32/checksum.h>
#endif

#ifdef HIP_VPLS
#include <utime.h>
#include <netinet/ether.h>
#include <hip/hip_cfg_api.h>
#include <hip/endbox_utils.h>
#endif /* HIP_VPLS */

#define BUFF_LEN 2000

/* functions from hip_esp.c */
void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type);

extern int tapfd;
extern int readsp[2];


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

/* determine if to proxy a legacy node */
int ack_request(__u32 src, __u32 dst)
{
	int rc;
	struct sockaddr_storage host_ss;
	struct sockaddr_storage eb_ss;
	struct sockaddr *host_p;
	struct sockaddr *eb_p;
	hip_hit hit1, hit2;
	char ip[INET6_ADDRSTRLEN];

	memset(&host_ss, 0, sizeof(struct sockaddr_storage));
	memset(&eb_ss, 0, sizeof(struct sockaddr_storage));
	host_p = (struct sockaddr*)&host_ss;
	eb_p = (struct sockaddr*)&eb_ss;

	host_p->sa_family = AF_INET;
	((struct sockaddr_in *)host_p)->sin_addr.s_addr = src;

	//log_(NORM, "ack_request: sender ip addr %s\n", ip);
	if(!find_host2(src))
		return 0;
	/*
	  Not proxy it if no ACL permission between the source and
	  desitination endboxes, which takes care of the case where
	  the two endboxes are "behind" a bridge
	*/
	eb_p->sa_family=AF_INET6;
	rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
	if(rc){
		addr_to_str(host_p, (__u8 *)ip, INET6_ADDRSTRLEN);
		log_(NORM, "invalid source addr in arp %s\n", ip);
		return 0;
	}

	if (!dst)
		return 1;

	memcpy(hit1, SA2IP(eb_p), HIT_SIZE);

	host_p->sa_family = AF_INET;
	((struct sockaddr_in *)host_p)->sin_addr.s_addr = dst;
	eb_p->sa_family=AF_INET6;
	rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
	if(rc){
		addr_to_str(host_p, (__u8 *)ip, INET6_ADDRSTRLEN);
		log_(NORM, "invalid dest addr in arp %s\n", ip);
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

/* Return value:
 * -1 => error
 *  0 => completed
 *  1 => not completed, need to call again
 */

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
  struct in_addr resp_ip_in;
  __u8 resp_mac[6];
  char resp_mac_s[32];
  char eb_s[32], dst_s[32], resp_ip_s[32];
  int host_cnt;
  struct sockaddr_storage legacyHosts[5], eb_ss;
  struct sockaddr *dst_p, *eb_p = (struct sockaddr *)&eb_ss;
  struct stat stat_buf;
  static time_t now_time, last_time;
  static int mac_table_full = FALSE;
  static unsigned call_count = 0;
  static unsigned cycle_time = 15, max_cycle_time = 60;;

  if (mac_table_full)
    return 0;

  if ((stat("/tmp/private_hosts", &stat_buf) == 0) && (numHosts == 0)) {
    log_(NORM, "Loading legacy node MAC addresses from /tmp/private_hosts.\n");
    if (read_private_hosts() > 0) {
      log_(NORM, "Loaded %d entries from /tmp/private_hosts.\n", numHosts);
      mac_table_full = TRUE;
      return 0;
    } else {
      log_(WARN, "Error reading /tmp/private_hosts; attempting discovery.\n");
    }
  }

  inet_ntop(AF_INET, &g_tap_lsi, eb_s, sizeof(eb_s));
 
  now_time = time(NULL);
  if (numHosts == 0) {
    s[numHosts].ip = strdup(eb_s);
    s[numHosts].mac = strdup("00:00:00:00:00:00");
    numHosts++; 
    last_time = time(NULL);
    return 1;
  } else if (now_time - last_time < cycle_time) {
    return 1;
  } else {
    last_time = now_time;
  }

  eb_p->sa_family = AF_INET;
  memcpy(SA2IP(eb_p), &g_tap_lsi, SAIPLEN(eb_p));
 
  host_cnt = hipcfg_getLegacyNodesByEndbox(eb_p,
	legacyHosts, sizeof(legacyHosts)/sizeof(struct sockaddr_storage));

  if(host_cnt < 0 ) {
    log_(WARN, "Error getting legacy hosts serviced by endbox %s\n", eb_s);
    return -1;
  } else if(host_cnt == 0) {
    log_(WARN, "No legacy hosts serviced by endbox %s\n", eb_s);
    return -1;
  } else if (numHosts == host_cnt + 1) { /* Already full */
    mac_table_full = TRUE;
    return 0;
  }
 
  log_(NORM, "Lookup MAC addresses for legacy hosts for endbox %s\n", eb_s);

  for(i = 0; i < host_cnt; i++) {
    dst_p = (struct sockaddr *)&legacyHosts[i];

    /* Only support IPv4 at present */

    if (dst_p->sa_family != AF_INET)
      continue;

    /* Is legacy host MAC already saved? */

    inet_ntop(dst_p->sa_family, SA2IP(dst_p), dst_s, sizeof(dst_s));
    for (j = 0; j < numHosts; j++)
      if (strcmp(s[j].ip, dst_s) == 0)
        break;
    if (j < numHosts)
      continue;

    log_(NORM, "Finding MAC for legacy node %s\n", dst_s);
   
    src_mac = (__u64)g_tap_lsi << 16;
    add_eth_header(out, src_mac, dst_mac, 0x0806);

    arp_request = (struct arp_hdr*) &out[14];
    arp_reply = (struct arp_hdr*) &in[14];
    arp_request->ar_hrd = htons(0x01);
    arp_request->ar_pro = htons(0x0800);
    arp_request->ar_hln = 6;
    arp_request->ar_pln = 4;
    arp_request->ar_op = htons(ARPOP_REQUEST);
    p = (__u8 *)(arp_request + 1);
    memcpy(p, &src_mac, 6);		/* sender MAC */
    memset(p+6, 0, 4);			/* sender (zero) address */
    memcpy(p+10, &dst_mac, 6);		/* target MAC */
    memcpy(p+16, SA2IP(dst_p), 4);	/* target address */

    outlen = sizeof(struct eth_hdr) + sizeof(struct arp_hdr) + 20;

    FD_ZERO(&read_fdset);
    FD_SET((unsigned)readsp[1], &read_fdset);

    if (write(tapfd, out, outlen) < 0) {
      log_(WARN, "Send ARP request failed while aquiring MAC addresses.\n");
      continue;
    }
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    rc = select(readsp[1]+1, &read_fdset, NULL, NULL, &timeout);
    if (rc == 0) {
      log_(WARN, "Cannot get ARP response for legacy host %s\n", dst_s);
      continue;
    } 
    if (rc < 0) {
      log_(WARN, "Error polling on socket to get MAC address, error: %s\n",
		strerror(errno));
      continue;
    }
    rc = read(readsp[1], in, BUFF_LEN);
    if (rc <= 0) {
      log_(WARN, "Error read on socket to get MAC address, error: %s\n",
		strerror(errno));
      continue;
    }
    if (in[12] != 0x08 || in[13] != 0x06) {
      log_(WARN, "Cannot get ARP response for legacy host %s\n", dst_s);
      continue;
    }

    /* Is this an ARP reply? */

    if (ntohs(arp_reply->ar_hrd)==0x01 &&     /* Ethernet */
        ntohs(arp_reply->ar_pro)==0x0800 &&   /* IPv4 */
        arp_reply->ar_hln==6 && arp_reply->ar_pln == 4 &&
        ntohs(arp_reply->ar_op)==0x0002) {    /* ARP reply */

      /* Is the reply from the legacy host? */

      resp_ip = ((__u32)in[28]<<24) + ((__u32)in[29]<<16) +
                ((__u32)in[30]<<8)  + ((__u32)in[31]);
      resp_ip_in.s_addr = htonl(resp_ip);
      inet_ntop(AF_INET, &resp_ip_in.s_addr, resp_ip_s, sizeof(resp_ip_s));
      if (strcmp(resp_ip_s, dst_s)) {
        log_(WARN, "Cannot get ARP response for legacy host %s\n", dst_s);
        continue;
      }

      /* Save result */

      memcpy(resp_mac, &in[22], 6);
      sprintf(resp_mac_s, "%02x:%02x:%02x:%02x:%02x:%02x", 
		resp_mac[0],resp_mac[1], resp_mac[2],
		resp_mac[3],resp_mac[4], resp_mac[5]);
      log_(NORM, "Got MAC [%s] for legacy host [%s]\n", resp_mac_s, resp_ip_s);
      s[numHosts].ip = strdup(resp_ip_s);
      s[numHosts].mac = strdup(resp_mac_s);
      numHosts++;
    } else {
      log_(WARN, "Cannot get ARP response for legacy host %s\n", dst_s);
    }
  }

  if (numHosts == host_cnt + 1) {
    log_(NORM, "Acquired all legacy hosts MAC addresses on this endbox.\n");
    mac_table_full = TRUE;
    return 0;
  } else {
    /* Gradually increase times between MAC discovery */
    if (numHosts > 1 && cycle_time < max_cycle_time) {
      call_count++;
      if (call_count == 3 || call_count == 6 || call_count == 9)
        cycle_time += 5;
      else if (call_count > 9 && call_count < 20)
        cycle_time += 2;
      else if (call_count >= 20)
        cycle_time++;
    }
    log_(WARN, "Did not acquire all legacy hosts MAC addresses.\n");
    return 1;
  }
}

/*
 * called from hip_esp_input()
 */
int endbox_ipv4_packet_check(struct ip *iph, struct sockaddr *lsi, 
	int *packet_count) 
{
	struct sockaddr_storage legacy_host_ss, eb_ss;
	struct sockaddr *legacy_host_p, *eb_p;

	if (!IN_MULTICAST(ntohl(iph->ip_dst.s_addr)) && 
	    ((ntohl(iph->ip_dst.s_addr)) & 0x000000FF) != 0x000000FF) {
	          if(!ack_request(iph->ip_src.s_addr, iph->ip_dst.s_addr))
			    return(-1);

		  legacy_host_p = SA(&legacy_host_ss);
		  eb_p = SA(&eb_ss);
		  legacy_host_p->sa_family = AF_INET;
		  LSI4(legacy_host_p) = iph->ip_dst.s_addr;
		  eb_p->sa_family = AF_INET;
		  if(!hipcfg_getEndboxByLegacyNode(legacy_host_p, eb_p)){
			lsi->sa_family = AF_INET;
			LSI4(lsi) = ntohl(LSI4(eb_p));
		  }
		  (*packet_count)++;
	} else {
		if(!ack_request(iph->ip_src.s_addr, 0))
			return(-1);
		  (*packet_count)++;
	}
	return(0);
}

/*
 * called from hip_esp_input()/output() while loop
 */
void endbox_periodic_heartbeat(time_t *now_time, time_t *last_time,
	int *packet_count, char *name, int touchHeartbeat)
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
		if (touchHeartbeat)
			utime(filename, NULL);
		else
			printf("not touching heartbeat_hip_%s!\n", name);
	}
}
		      
/*
 * If multicast IP address, generate a MAC address for each host in the
 * private host map.  OTB 20080414
 */
void endbox_ipv4_multicast_write(__u8 *data, int offset, int len) 
{
	struct ip* iph = (struct ip*) &data[offset + sizeof(struct eth_hdr)];
	int i, n;
	__u64 dst_mac;

	if (IN_MULTICAST((ntohl(iph->ip_dst.s_addr)))) {
		n = numHosts;
		for (i = 0; i < n; i++) {
			dst_mac = find_mac2(i);
			if (!dst_mac) /* the endbox,entry w/LSI, has dst_mac 0*/
				continue;
			add_eth_header(&data[offset], g_tap_mac,
					dst_mac, 0x0800);
			if (write(tapfd, &data[offset], len) < 0)
				printf("hip_esp_input() write() failed.\n");
		}
		      
	} else {
		if (write(tapfd, &data[offset], len) < 0)
			printf("hip_esp_input() write() failed.\n");
	}
}

void endbox_esp_decrypt(__u8 *out, int *offset)
{
	struct ip *iph = (struct ip*) &out[*offset];    /* the inner IP hdr */
	*offset -= sizeof(struct eth_hdr);   /* where to put the eth hdr */
	//__u64 src_mac;
	__u64 dst_mac = 0;
 
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
		/* jeffa: src_mac is never used below... */
              // src_mac = get_eth_addr(AF_INET, SA2IP(&entry->lsi));
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
}
