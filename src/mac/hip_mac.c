/*
 * Host Identity Protocol
 * Copyright (C) 2002-05 the Boeing Company
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
 *  Authors:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson <thomas.r.henderson@boeing.com>
 *              Jeff Meegan  jeff.r.meegan@boeing.com
 *
 *
 */

#ifdef __MACOSX__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/asn1.h>	
#include <openssl/rand.h>
#include <arpa/inet.h>		/* inet_addr() 			*/
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>		/* INADDR_NONE                  */
#include <netinet/ip.h>		/* INADDR_NONE                  */
#include <sys/types.h>
#include <sys/wait.h>		/* wait_pid() 			*/
#include <sys/uio.h>		/* iovec			*/
#include <errno.h>
#include <fcntl.h>		/* open()			*/
#include <netdb.h>		/* gethostbyname 		*/
#ifndef __MACOSX__
#include <asm/types.h>
#else
#include <sys/types.h>
#include <net/route.h>
#endif
#include <netinet/ip6.h>
#include <sys/ioctl.h>		/* set_link_params() support	*/
#include <sys/socket.h>		/* socket() */
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#include <hip/hip_stun.h>

/* Local functions */
/* int read_netlink_response();*/

void readdress_association(int add, struct sockaddr *newaddr, int if_index);
void association_add_address(hip_assoc *hip_a, struct sockaddr *newaddr,
    int if_index);
void association_del_address(hip_assoc *hip_a, struct sockaddr *newaddr,
    int if_index);
void handle_local_address_change(int add,struct sockaddr *newaddr,int if_index);

#ifdef __MACOSX__
int g_rulebase = 100;  /* starting IPFW ruleno */
int g_divertport = 5150;  /* divert port */
#endif

/* misnomer because Darwin/OSX doesn't have NETLINK sockets */
int hip_netlink_open()
{
	if(s_net) close(s_net);
	if ((s_net = socket(PF_ROUTE, SOCK_RAW, PF_UNSPEC)) < 0)
		return -1;
/* todo:  need to bind()??? */

return 0;

}

#ifndef __MACOSX__
extern int send_udp_esp_tunnel_activation (__u32 spi_out);
#endif

/*
 * function select_preferred_address()
 *
 * Choose one of this machine's IP addresses as preferred.
 * - any user preference should take priority, i.e. which interface to use
 * - first select an active address having a default gateway
 *
 */
int select_preferred_address()
{
	int preferred_selected;
	sockaddr_list *l;
	__u32 ip;
	/* Linux version */
	/* XXX TODO: dump routing table and choose addr w/default route. */
	preferred_selected = FALSE;
	/* when a preferred address has not been found yet, choose
	 * the first that is not a loopback address
	 */
	if (!preferred_selected) {
		for (l = my_addr_head; l; l=l->next) {
			if (l->addr.ss_family != AF_INET)
				continue;
			ip = ((struct sockaddr_in*)&l->addr)->sin_addr.s_addr;
			if ((ntohl(ip)==INADDR_LOOPBACK) || 
			    (ip == 0x01000001L) || ((ip & 0xFFFF) == 0xFEA9))

				continue;
			l->preferred = TRUE;
			log_(NORM, "%s selected as the ",logaddr(SA(&l->addr)));
			log_(NORM, "preferred address (2).\n");
			break;
		}
	}
	return(0);
}


/*
 * function devname_to_index()
 *
 * Convert device name to numeric index, and also return the MAC address.
 * Similar to librtnetlink ll_init_map() and ll_name_to_index(), but
 * no map is retained, no caching is performed (meant to be called only once).
 */

/*
 * function read_netlink_response()
 *
 * Called to parse the netlink response without checking for anything
 * but errors.
 */

/*
 * function add_address_to_list()
 *
 * Make a sockaddr and add it to a list.
 */
sockaddr_list *add_address_to_list(sockaddr_list **list, struct sockaddr *addr,
    int ifi)
{
	sockaddr_list *item, *l_p;

	/* make a new sockaddr_list element */
	item = (sockaddr_list*) malloc(sizeof(sockaddr_list));
	if (!item)
		return NULL;
	memset(item, 0, sizeof(sockaddr_list));
	memcpy(&item->addr, addr, SALEN(addr));
	item->if_index = ifi;
	item->next = NULL;
	
	/* append element to list */
	if (*list) {
		for(l_p = *list; l_p->next; l_p = l_p->next) /* skip... */;
		l_p->next = item;
	} else {
		*list = item;
	}
	return(item);
}

/*
 * function delete_address_from_list()
 *
 * Remove a given address from the list, or remove all addresses associated
 * with if_index (when len==0).
 */
void delete_address_from_list(sockaddr_list **list, struct sockaddr *addr,
    int ifi)
{
	sockaddr_list *item, *prev;
	int remove;

	if (!*list) /* no list */
		return;

	remove = FALSE;
	prev = NULL;
	item = *list;
	while (item) {
		/* remove from list if if_index matches */
		if (!addr) {
			if (item->if_index == ifi)
				remove = TRUE;
		/* remove from list if address matches */
		} else {
			if ((item->addr.ss_family == addr->sa_family) &&
			    (memcmp(SA2IP(&item->addr), SA2IP(addr),
				    SAIPLEN(addr))==0)) {
				/* address match */
				remove = TRUE;
			}
		}
		if (!remove) { /* nothing to delete, advance in list... */
			prev = item;
			item = item->next;
			continue;
		}
		remove = FALSE;
		if (prev) {
			prev->next = item->next;
			free(item);
			item = prev->next;
		} else { /* delete first item in list */
			*list = item->next;
			free(item);
			item = *list;
		}
	}
}


void delete_address_entry_from_list(sockaddr_list **list, sockaddr_list *entry)
{
	sockaddr_list *item, *prev;

	if (!*list) /* no list */
		return;
	
	prev = NULL;
	item = *list;
	while (item) {
		/* pointer match */
		if (item == entry) {
			if (prev) {
				prev->next = item->next;
				free(item);
				item = prev->next;
			} else {
				/* for hi_node->addrs, we cannot delete
				 * the first item in the list! */
				return;
			}
			break;
		} else {
			prev = item;
			item = item->next;
		}
	}
}

/*
 * function is_my_address()
 *
 * Returns the interface index if supplied address is found in my_addr_head, 
 * FALSE (0) otherwise. (The interface index is never zero.)
 */
int is_my_address(struct sockaddr *addr)
{
	sockaddr_list *l;
	for (l = my_addr_head; l; l=l->next) {
		if (addr->sa_family != l->addr.ss_family) {
			continue;
		}
		if (memcmp(SA2IP(&l->addr), SA2IP(addr), SAIPLEN(addr))==0) {
			/* address match */
			return(l->if_index);
		}
	}
	return FALSE;
}

void print_addr_list(sockaddr_list *list)
{
	sockaddr_list *l;
	log_(NORM, "Address list: [");
	for (l = my_addr_head; l; l=l->next) {
		log_(NORM, "(%d)%s, ", l->if_index,
		    logaddr((struct sockaddr*)&l->addr));
	}
	log_(NORM, "]\n");
}

/*
 * function hip_handle_netlink()
 *
 * Handles received netlink messages. Returns 1 if address change requires
 * selection/publishing new preferred address, 0 otherwise.
 */

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
 
int hip_handle_netlink(char *data, int len)
{
 struct rt_msghdr *hd = (struct rt_msghdr *)data; 
 struct if_msghdr *ifm; 
 struct ifa_msghdr *ifam; 

 struct sockaddr *packed; /* For decoding addresses */ 
 struct sockaddr unpacked[4096]; 
 int is_add, retval = 0,i=0,loc=0; 
 struct sockaddr_storage ss_addr;
 struct sockaddr *addr;
 sockaddr_list *l;
#ifndef __MACOSX__
 NatType nattype;
#endif

	addr = (struct sockaddr *) &ss_addr;
 
	switch (hd->rtm_type) { 

		case RTM_NEWADDR:
		case RTM_DELADDR:
                        ifam = (struct ifa_msghdr *)data; 
                        ifm = (struct if_msghdr *)data; 

                        packed=(struct sockaddr*)
				(data+sizeof(struct ifa_msghdr)); 

			memset(addr, 0, sizeof(struct sockaddr_storage));

			is_add = (hd->rtm_type ==RTM_NEWADDR);

			/* extract list of addresses from message */

			for( i = 0; i < RTAX_MAX; i++ ) { 
				bzero(&unpacked[i],sizeof(unpacked[i])); 
				if( ifam->ifam_addrs & (1<<i) ) { 
					memcpy(&(unpacked[i]), packed, 
							packed->sa_len); 
					packed=(struct sockaddr*)
					(((char*)packed)+ROUNDUP(packed->sa_len)); 
					if(i == RTAX_IFA) {
						loc = i;
						break;
					}
				} 
			} 


			addr->sa_family = unpacked[loc].sa_family;
			memcpy(	SA2IP(addr), SA2IP(&unpacked[loc]), 
					SALEN(&unpacked[loc]));
			log_(NORM, "Address %s: (%d)%s \n", (is_add) ? "added" :
			    "deleted", ifm->ifm_index, logaddr(addr));

#ifndef __MACOSX__
			/* NAT detection */
			if (OPT.stun && is_add) {
				log_(NORMT, "STUN: NAT detection with server ");
				printIPv4Addr (&STUN_server_addr);
				log_(NORM, "\n");
				nattype = stunNatType( &STUN_server_addr,FALSE, NULL, NULL, 0, NULL) ;          
				if (nattype == StunTypeOpen || nattype == StunTypeFirewall) {                           
					is_behind_nat = FALSE ;
					log_(NORM, "STUN: No NAT detected.\n");
				} else {
					is_behind_nat = TRUE ; 
					log_(NORM, "STUN: NAT detected, UDP encapsulation activated.\n");       
				}
			}
#endif

			handle_local_address_change(is_add, addr,
						    ifm->ifm_index);
			
			/* update our global address list */
			if (is_add) {
				l = add_address_to_list(&my_addr_head, addr,
							ifm->ifm_index);
				l->status = ACTIVE;
				/* Need to select_preferred_address() and
				 * publish_my_hits() here, but the address
				 * was just added and we may get no route to
				 * host errors, so handle later */
				retval = 1;
			} else {
				delete_address_from_list(&my_addr_head, addr,
				    ifm->ifm_index);
			}
			case RTM_IFINFO:
			/* TODO: no ADDLINK/DELLINK netlink messages, so we need
			   to parse IFINFO messages to discover link changes.

			ifm = (struct if_msghdr *)data; 
			if(!(ifm->ifm_flags & IFF_UP))  {
	                        delete_address_from_list(&my_addr_head, NULL,
       		                     ifm->ifm_index);
			}
			*/
			break;
	}
return retval;

}

/*
 * readdress_association()
 * 
 * 
 * Handle adding/deleting addresses to/from HIP associations, performing
 * readdress when needed. (readdress occurs after a delete + add)
 */
void readdress_association(int add, struct sockaddr *newaddr, int if_index)
{
	int i;
	hip_assoc *hip_a;


	if (!VALID_FAM(newaddr))
		return;

	/* lookup HIP association based on src interface index */
	for (i=0; i < max_hip_assoc; i++) {
		hip_a = &hip_assoc_table[i];
		if (hip_a->hi->addrs.if_index != if_index)
			continue;
		if (add) {
			association_add_address(hip_a, newaddr, if_index);
		} else {
			association_del_address(hip_a, newaddr, if_index);
		}
	}
}

/* An address has been added to this interface, so add it
 * to the list in hip_a->hi->addrs.
 * If the preferred address was deleted, make this the new
 * preferred address and perform readdressing procedures. */
void association_add_address(hip_assoc *hip_a, struct sockaddr *newaddr,
    int if_index)
{
	sockaddr_list *l;
	struct sockaddr *oldaddr;
#ifndef __MACOSX__
	int err=0;
#endif
	/* 
	 * If preferred address is deleted, do readdress and replace it
	 */
	if (hip_a->hi->addrs.status == DELETED) {
		oldaddr = HIPA_SRC(hip_a);
		if (!memcmp(oldaddr, newaddr, SALEN(newaddr))) {
			/* address is same, 'undelete' */
			make_address_active(&hip_a->hi->addrs);
			return;
		}

		/* perform readdress */
		rebuild_sa(hip_a, newaddr, 0, FALSE, FALSE, is_behind_nat);
		rebuild_sa(hip_a, newaddr, 0, TRUE, FALSE, is_behind_nat);
		sadb_readdress(oldaddr, newaddr, hip_a, hip_a->spi_in);
		/* replace the old preferred address */
		memcpy(&hip_a->hi->addrs.addr, newaddr, 
		    SALEN(newaddr));
		make_address_active(&hip_a->hi->addrs);
		if (!hip_a->rekey) {
			hip_a->rekey = malloc(sizeof(struct rekey_info));
			memset(hip_a->rekey, 0, sizeof(struct rekey_info));

			hip_a->rekey->update_id = ++hip_a->hi->update_id;
			hip_a->rekey->acked = FALSE;
		}

/* // hip_a->use_udp updated after rekeying is completely finished //
		if (OPT.stun) {
			hip_a->use_udp = is_behind_nat ;
		}
*/
		if (OPT.stun) {
			hip_a->next_use_udp = is_behind_nat;
		}

		if (is_behind_nat) { /* && hip_a->peer_dst_port==0) { */
			hip_a->peer_dst_port = HIP_UDP_PORT;
			hip_a->peer_esp_dst_port = HIP_ESP_UDP_PORT;
		}

		/* .next and .if_index should be already set */
		/* inform peer of new preferred address */
		if (hip_send_update(hip_a, newaddr, NULL, is_behind_nat) < 0)
			log_(WARN, "Problem sending UPDATE(REA) for %s!\n",
			    logaddr(newaddr));

#ifndef __MACOSX__
		if (hip_a->use_udp) { /* (HIP_ESP_OVER_UDP) */
		/* not necessary. it is just meant to update the port for incoming packets sent before 
			rekeying is completely finished */
			err = send_udp_esp_tunnel_activation (hip_a->spi_out);
			if (err<0) {
				printf("Activation of UDP-ESP channel failed.\n");
			} else {
				printf("Activation of UDP-ESP channel for spi:0x%x done.\n",
					 hip_a->spi_out);
			}
		}
#endif

	/* 
	 * Add the new address to the end of the list (or unmark deleted status)
	 */
	} else {
		for (l = &hip_a->hi->addrs; l->next; l=l->next){
			if (newaddr->sa_family != l->addr.ss_family)
				continue;
			if (!memcmp(SA2IP(&l->addr), SA2IP(newaddr),
			    SAIPLEN(&l->addr))) {
				/* entry already exists */
				make_address_active(l);
				return;
			}
		}
		/* add new entry to the end of the list */
		l->next = malloc(sizeof(sockaddr_list));
		memset(l->next, 0, sizeof(sockaddr_list));
		l->next->next = NULL;
		memcpy(&l->next->addr, newaddr, SALEN(newaddr));
		l->next->if_index = if_index;
	}
}

/* An address has been deleted from this interface, 
 * so mark its status as DELETED. 
 */
void association_del_address(hip_assoc *hip_a, struct sockaddr *newaddr,
    int if_index)
{
	sockaddr_list *l;
	for (l = &hip_a->hi->addrs; l; l=l->next) {
		if (newaddr->sa_family != l->addr.ss_family)
			continue;
		if (!memcmp(SA2IP(&l->addr), SA2IP(newaddr), SAIPLEN(&l->addr)))
			break;
	}
	
	if (l)
		l->status = DELETED;
}

void make_address_active(sockaddr_list *item)
{
	if (!item)
		return;
	item->status = ACTIVE;
	gettimeofday(&item->creation_time, NULL);
}


/*
 * function set_link_params()
 *
 * Uses ioctl(), not rtnetlink, just like ip command.
 * equivalent of:
 * 	"/sbin/ip link set hip0 mtu 1400"
 * 	"/sbin/ip link set hip0 up"
 * (see iproute2 source file ip/iplink.c)
 */
int set_link_params(char *dev, int mtu)
{
	int err=0;
	int fd;
	struct ifreq ifr;
	__u32 flags, mask;

	if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		log_(WARN, "set_link_up(): socket error: %s\n",
			strerror(errno));
		return(-1);
	}

	/* set link MTU */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ifr.ifr_mtu = mtu;
	
	err = ioctl(fd, SIOCSIFMTU, &ifr);
	if (err) {
		log_(WARN, "set_link_params(): SIOCSIFMTU error: %s\n",
			strerror(errno));
		/* non-fatal error */
	}
	
	/* set link to UP */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	err = ioctl(fd, SIOCGIFFLAGS, &ifr); /* get flags */
	if (err) {
		log_(WARN, "set_link_up(): SIOCGIFFLAGS error: %s\n",
			strerror(errno));
		close(fd);
		return(-1);
	}

	flags = mask = IFF_UP;
	if ((ifr.ifr_flags^flags)&mask) { /* modify flags */
		ifr.ifr_flags &= ~mask;
		ifr.ifr_flags |= mask&flags;
		err = ioctl(fd, SIOCSIFFLAGS, &ifr);
		if (err)
			log_(WARN, "set_link_up(): SIOCSIFFLAGS error: %s\n",
				strerror(errno));
	}
	
	close(fd);
	return(err);
}

/*

  OSX/Darwin version of devname_to_index - uses getifaddrs() instead
  of netlink.
  jeffm
*/

int devname_to_index( char *dev, __u64 *mac)
{
struct ifaddrs *ifap0, *ifap=0;
struct sockaddr_dl *sdl;
int retVal = -1;
char buf[BUFSIZ];

	memset(buf, 0, sizeof(buf));

	if (getifaddrs(&ifap0)) {
		freeifaddrs(ifap);
		return(-1);
	}

	for (ifap = ifap0; ifap; ifap=ifap->ifa_next) {

		if (ifap->ifa_addr == NULL)
			continue;

		if (strcmp(ifap->ifa_name,dev) != 0)
			continue;
		if(ifap->ifa_addr->sa_family == AF_LINK) {
			sdl = (struct sockaddr_dl*)ifap->ifa_addr;
			memcpy(mac,sdl->sdl_data+sdl->sdl_nlen,6);
			retVal = sdl->sdl_index;
		}
	}		

	freeifaddrs(ifap);
	return retVal;
}


/*
  retrieve set of addresses via getifaddrs() and add to hip address list

*/

int get_my_addresses()
{
	struct ifaddrs *ifap0=0, *ifap=0;
	int ix;
	char buf[BUFSIZ];

	memset(buf, 0, sizeof(buf));

	if (getifaddrs(&ifap0)) {
		freeifaddrs(ifap);
		return 0;
	}

	for (ifap = ifap0; ifap; ifap=ifap->ifa_next) {
		if (ifap->ifa_addr == NULL)
			continue;
		if (ifap->ifa_addr->sa_family == AF_INET ||
		    ifap->ifa_addr->sa_family == AF_INET6) {
			ix = if_nametoindex(ifap->ifa_name);
			add_address_to_list(&my_addr_head,ifap->ifa_addr,ix);
			log_(NORM, "(%d)%s ",ix,logaddr(ifap->ifa_addr));
		}
	}		

	freeifaddrs(ifap);
	return 1;
}


/*
  adds a new address to an interface - used to set address on tun device
  Note: This will most likely not support IPv6 as written :)

*/
int add_address_to_iface(struct sockaddr *addr, int plen, int if_index)
{
 int sock=0;
 int stat = 0;
 struct ifreq ifr;

 if((sock=socket(PF_INET,SOCK_DGRAM,0))<0)
 {
  return (-1);
 }

 memset(&ifr,0,sizeof( struct ifreq ) );

  /* convert name to interface index */
 if_indextoname(if_index,ifr.ifr_name);

 log_(WARN,"Adding new addres to interface %s\n",ifr.ifr_name);
 memcpy(&ifr.ifr_addr, addr, sizeof(struct sockaddr_in));


 /*if(ioctl(sock,SIOCSIFADDR, &ifr )!=0)*/
 stat = ioctl(sock,SIOCSIFADDR, &ifr);
 log_(WARN,"status = %d\n",stat);
 if(ioctl(sock,SIOCSIFADDR, &ifr )!=0)
 {
  close(sock);
  return (-1);
 }
 close(sock);
 return(0);
}

char *ip2dot(__u32 ip)
{
	static char buff[32];
	int	i;
	char *p= &buff[0];
	sprintf(p, "%u", ((char *)&ip)[0] & 0xff);
	p += strlen(p);
	for (i=1; i<4 ; ++i) {
		sprintf(p, ".%u", ((char *)&ip)[i] & 0xff);
		p += strlen(p);
	}
	*p = 0;
	return (char *) &buff[0];
}
/*
  return next rule ID 

*/
int next_divert_rule()
{
 return g_rulebase++;
}
/* 
	Add a IPFW divert rule.  Used during

*/
void add_divert_rule(int ruleno, int proto, char *src)
{
 char buf[1024];
	sprintf(buf,"/sbin/ipfw add %d divert %d %d from %s to any in",
		ruleno,g_divertport,proto,src);
 system(buf);
 log_(NORM,"Adding IPFW rule %d for dest %s\n",ruleno,src);
}


/*

  delete an IPFW divert rule.  Used during readdress
  as well as connection teardown

*/
void del_divert_rule(int ruleno)
{
 char buf[255];

	sprintf(buf,"/sbin/ipfw del %d",ruleno);
	system(buf);
 	log_(NORM,"Deleting IPFW rule %d\n",ruleno);
}

/*
 * handle_local_address_change()
 *
 * Handle adding/deleting addresses to/from HIP associations, performing
 * readdress when needed. (readdress occurs after a preferred has been deleted)
 */
void handle_local_address_change(int add, struct sockaddr *newaddr,int if_index)
{
        int i;
        hip_assoc *hip_a;

        if (!VALID_FAM(newaddr))
                return;

        /* lookup HIP association based on src interface index */
        for (i=0; i < max_hip_assoc; i++) {
                hip_a = &hip_assoc_table[i];
                if (hip_a->hi->addrs.if_index != if_index)
                        continue;
                if (add) {
                        association_add_address(hip_a, newaddr, if_index);
                } else {
                        association_del_address(hip_a, newaddr, if_index);
                }
        }
}

/*
 * update the address of a peer in the peer_hi_head list
 */
int update_peer_list_address(const hip_hit peer_hit, struct sockaddr *old_addr, struct sockaddr *new_addr)
{
	sockaddr_list *l;
	hi_node *peer_hi = find_host_identity(peer_hi_head, peer_hit);
	if (!peer_hi)
		return(-1);
	if (!new_addr)
		return(-1);

	l = &peer_hi->addrs;
	/* remove old address, if any specified */
	if (old_addr) /* or should we just flag deleted? */
		delete_address_from_list(&l, old_addr, 0);
	/* add the new address */
	l = add_address_to_list(&l, new_addr, 0);
	return ( l ? 0 : -1 );
}

#endif
