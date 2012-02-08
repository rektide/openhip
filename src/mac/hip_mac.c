/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2002-2012 the Boeing Company
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *  \file  hip_mac.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson <thomas.r.henderson@boeing.com>
 *              Jeff Meegan  jeff.r.meegan@boeing.com
 *
 *  \brief  Mac OS X specific functions.
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
#include <arpa/inet.h>          /* inet_addr()                  */
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>         /* INADDR_NONE                  */
#include <netinet/ip.h>         /* INADDR_NONE                  */
#include <sys/types.h>
#include <sys/wait.h>           /* wait_pid()                   */
#include <sys/uio.h>            /* iovec			*/
#include <errno.h>
#include <fcntl.h>              /* open()			*/
#include <netdb.h>              /* gethostbyname                */
#ifndef __MACOSX__
#include <asm/types.h>
#else
#include <sys/types.h>
#include <net/route.h>
#endif
#include <netinet/ip6.h>
#include <sys/ioctl.h>          /* set_link_params() support	*/
#include <sys/socket.h>         /* socket() */
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>

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
  if (s_net)
    {
      close(s_net);
    }
  if ((s_net = socket(PF_ROUTE, SOCK_RAW, PF_UNSPEC)) < 0)
    {
      return(-1);
    }
/* todo:  need to bind()??? */

  return(0);

}

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
  int preferred_selected, preferred_iface_index;
  sockaddr_list *l;
  __u32 ip;
  /* Linux version */
  /* XXX TODO: dump routing table and choose addr w/default route. */
  preferred_selected = FALSE;
  preferred_iface_index = -1;
  /* first check for preferred from conf file */
  if ((HCNF.preferred.ss_family) || (preferred_iface_index != -1))
    {
      for (l = my_addr_head; l; l = l->next)
        {
          /* preferred address takes priority */
          if ((l->addr.ss_family == HCNF.preferred.ss_family) &&
              (memcmp(SA2IP(&l->addr), SA2IP(&HCNF.preferred),
                      SAIPLEN(&l->addr)) == 0))
            {
              l->preferred = TRUE;
              log_(NORM, "%s selected as the",
                   logaddr(SA(&l->addr)));
              log_(NORM, " preferred address (conf).\n");
              preferred_selected = TRUE;
              break;
              /* preferred interface next priority */
            }
          else if ((preferred_iface_index > 0) &&
                   (preferred_iface_index == l->if_index))
            {
              if (l->addr.ss_family != AF_INET)
                {
                  continue;
                }
              ip =
                ((struct sockaddr_in*)&l->addr)->
                sin_addr.s_addr;
              if ((ntohl(ip) == INADDR_LOOPBACK) ||
                  (IS_LSI32(ip)))
                {
                  continue;
                }
              l->preferred = TRUE;
              log_(NORM, "%s selected as the",
                   logaddr(SA(&l->addr)));
              log_(NORM, " preferred address (conf iface).\n");
              preferred_selected = TRUE;
              break;
            }
        }
    }
  /* when a preferred address has not been found yet, choose
   * the first that is not a loopback address
   */
  if (!preferred_selected)
    {
      for (l = my_addr_head; l; l = l->next)
        {
          if (l->addr.ss_family != AF_INET)
            {
              continue;
            }
          ip = ((struct sockaddr_in*)&l->addr)->sin_addr.s_addr;
          if ((ntohl(ip) == INADDR_LOOPBACK) ||
              (ip == 0x01000001L) || ((ip & 0xFFFF) == 0xFEA9))
            {

              continue;
            }
          l->preferred = TRUE;
          log_(NORM, "%s selected as the ",logaddr(SA(&l->addr)));
          log_(NORM, "preferred address (2).\n");
          break;
        }
    }
  return(0);
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

  struct sockaddr *packed;       /* For decoding addresses */
  struct sockaddr unpacked[4096];
  int is_add, retval = 0,i = 0,loc = 0;
  struct sockaddr_storage ss_addr;
  struct sockaddr *addr;
  sockaddr_list *l;
#ifndef __MACOSX__
  NatType nattype;
#endif

  addr = (struct sockaddr *) &ss_addr;

  switch (hd->rtm_type)
    {

    case RTM_NEWADDR:
    case RTM_DELADDR:
      ifam = (struct ifa_msghdr *)data;
      ifm = (struct if_msghdr *)data;

      packed = (struct sockaddr*)
               (data + sizeof(struct ifa_msghdr));

      memset(addr, 0, sizeof(struct sockaddr_storage));

      is_add = (hd->rtm_type == RTM_NEWADDR);

      /* extract list of addresses from message */

      for (i = 0; i < RTAX_MAX; i++)
        {
          bzero(&unpacked[i],sizeof(unpacked[i]));
          if (ifam->ifam_addrs & (1 << i))
            {
              memcpy(&(unpacked[i]), packed,
                     packed->sa_len);
              packed = (struct sockaddr*)
                       (((char*)packed) +
                        ROUNDUP(packed->sa_len));
              if (i == RTAX_IFA)
                {
                  loc = i;
                  break;
                }
            }
        }


      addr->sa_family = unpacked[loc].sa_family;
      memcpy( SA2IP(addr), SA2IP(&unpacked[loc]),
              SALEN(&unpacked[loc]));
      log_(NORM, "Address %s: (%d)%s \n", (is_add) ? "added" :
           "deleted", ifm->ifm_index, logaddr(addr));

      handle_local_address_change(is_add, addr,
                                  ifm->ifm_index);

      /* update our global address list */
      if (is_add)
        {
          l = add_address_to_list(&my_addr_head, addr,
                                  ifm->ifm_index);
          l->status = ACTIVE;
          /* Need to select_preferred_address() and
           * publish_my_hits() here, but the address
           * was just added and we may get no route to
           * host errors, so handle later */
          retval = 1;
        }
      else
        {
          delete_address_from_list(&my_addr_head, addr,
                                   ifm->ifm_index);
        }
    case RTM_IFINFO:
      /* TODO: no ADDLINK/DELLINK netlink messages, so we need
       *  to parse IFINFO messages to discover link changes.
       *
       *  ifm = (struct if_msghdr *)data;
       *  if(!(ifm->ifm_flags & IFF_UP))  {
       *       delete_address_from_list(&my_addr_head, NULL,
       *            ifm->ifm_index);
       *  }
       */
      break;
    }
  return(retval);

}

/*
 * function set_link_params()
 *
 * Uses ioctl(), not rtnetlink, just like ip command.
 * equivalent of:
 *      "/sbin/ip link set hip0 mtu 1400"
 *      "/sbin/ip link set hip0 up"
 * (see iproute2 source file ip/iplink.c)
 */
int set_link_params(char *dev, int mtu)
{
  int err = 0;
  int fd;
  struct ifreq ifr;
  __u32 flags, mask;

  if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
      log_(WARN, "set_link_up(): socket error: %s\n",
           strerror(errno));
      return(-1);
    }

  /* set link MTU */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  ifr.ifr_mtu = mtu;

  err = ioctl(fd, SIOCSIFMTU, &ifr);
  if (err)
    {
      log_(WARN, "set_link_params(): SIOCSIFMTU error: %s\n",
           strerror(errno));
      /* non-fatal error */
    }

  /* set link to UP */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  err = ioctl(fd, SIOCGIFFLAGS, &ifr);       /* get flags */
  if (err)
    {
      log_(WARN, "set_link_up(): SIOCGIFFLAGS error: %s\n",
           strerror(errno));
      close(fd);
      return(-1);
    }

  flags = mask = IFF_UP;
  if ((ifr.ifr_flags ^ flags) & mask)         /* modify flags */
    {
      ifr.ifr_flags &= ~mask;
      ifr.ifr_flags |= mask & flags;
      err = ioctl(fd, SIOCSIFFLAGS, &ifr);
      if (err)
        {
          log_(WARN, "set_link_up(): SIOCSIFFLAGS error: %s\n",
               strerror(errno));
        }
    }

  close(fd);
  return(err);
}

/*
 *
 *  OSX/Darwin version of devname_to_index - uses getifaddrs() instead
 *  of netlink.
 *  jeffm
 */

int devname_to_index( char *dev, __u64 *mac)
{
  struct ifaddrs *ifap0, *ifap = 0;
  struct sockaddr_dl *sdl;
  int retVal = -1;
  char buf[BUFSIZ];

  memset(buf, 0, sizeof(buf));

  if (getifaddrs(&ifap0))
    {
      freeifaddrs(ifap);
      return(-1);
    }

  for (ifap = ifap0; ifap; ifap = ifap->ifa_next)
    {

      if (ifap->ifa_addr == NULL)
        {
          continue;
        }

      if (strcmp(ifap->ifa_name,dev) != 0)
        {
          continue;
        }
      if (ifap->ifa_addr->sa_family == AF_LINK)
        {
          sdl = (struct sockaddr_dl*)ifap->ifa_addr;
          memcpy(mac,sdl->sdl_data + sdl->sdl_nlen,6);
          retVal = sdl->sdl_index;
        }
    }

  freeifaddrs(ifap);
  return(retVal);
}

/*
 *  retrieve set of addresses via getifaddrs() and add to hip address list
 *
 */

int get_my_addresses()
{
  struct ifaddrs *ifap0 = 0, *ifap = 0;
  int ix;
  char buf[BUFSIZ];

  memset(buf, 0, sizeof(buf));

  if (getifaddrs(&ifap0))
    {
      freeifaddrs(ifap);
      return(0);
    }

  for (ifap = ifap0; ifap; ifap = ifap->ifa_next)
    {
      if (ifap->ifa_addr == NULL)
        {
          continue;
        }
      if ((ifap->ifa_addr->sa_family == AF_INET) ||
          (ifap->ifa_addr->sa_family == AF_INET6))
        {
          ix = if_nametoindex(ifap->ifa_name);
          add_address_to_list(&my_addr_head,ifap->ifa_addr,ix);
          log_(NORM, "(%d)%s ",ix,logaddr(ifap->ifa_addr));
        }
    }

  freeifaddrs(ifap);
  return(1);
}

/*
 *  adds a new address to an interface - used to set address on tun device
 *  Note: This will most likely not support IPv6 as written :)
 *
 */
int add_address_to_iface(struct sockaddr *addr, int plen, int if_index)
{
  int sock = 0;
  int stat = 0;
  struct ifreq ifr;

  if ((sock = socket(PF_INET,SOCK_DGRAM,0)) < 0)
    {
      return (-1);
    }

  memset(&ifr,0,sizeof(struct ifreq));

  /* convert name to interface index */
  if_indextoname(if_index,ifr.ifr_name);

  log_(WARN,"Adding new addres to interface %s\n",ifr.ifr_name);
  memcpy(&ifr.ifr_addr, addr, sizeof(struct sockaddr_in));


  /*if(ioctl(sock,SIOCSIFADDR, &ifr )!=0)*/
  stat = ioctl(sock,SIOCSIFADDR, &ifr);
  log_(WARN,"status = %d\n",stat);
  if (ioctl(sock,SIOCSIFADDR, &ifr ) != 0)
    {
      close(sock);
      return (-1);
    }
  close(sock);
  return(0);
}

/*
 *  return next rule ID
 *
 */
int next_divert_rule()
{
  return(g_rulebase++);
}

/*
 *       Add a IPFW divert rule.  Used during
 *
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
 *
 *  delete an IPFW divert rule.  Used during readdress
 *  as well as connection teardown
 *
 */
void del_divert_rule(int ruleno)
{
  char buf[255];

  sprintf(buf,"/sbin/ipfw del %d",ruleno);
  system(buf);
  log_(NORM,"Deleting IPFW rule %d\n",ruleno);
}

#endif
