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
 *  \file  hip_util.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson <thomas.r.henderson@boeing.com>
 *
 *  \brief  Miscellaneous helper functions for accessing HIP data structures,
 *          debugging, converting, validation, etc.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __WIN32__
#include <win32/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <crt/process.h>        /* getpid() */
#include <win32/ip.h>
#else
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>           /* waitpid()			*/
#include <arpa/inet.h>          /* inet_addr()                  */
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>         /* INADDR_NONE                  */
#include <netinet/ip.h>         /* INADDR_NONE                  */
#include <netinet/ip6.h>
#include <netdb.h>              /* gethostbyname                */
#include <sys/ioctl.h>          /* get_my_addresses() support	*/
#include <net/if.h>             /* get_my_addresses() support	*/
#include <pthread.h>            /* pthreads support		*/
#endif
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/asn1.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>              /* open()			*/
#include <signal.h>             /* SIGSEGV, etc definitions	*/
#include <hip/hip_version.h>    /* HIP_VERSION */
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#ifdef __WIN32__
#include <WinDNS.h>
#define NS_MAXDNAME DNS_MAX_NAME_LENGTH
#define NS_PACKETSZ DNS_RFC_MAX_UDP_PACKET_LENGTH
#else
#include <arpa/nameser.h>       /* res_search() support         */
#include <resolv.h>             /* res_search()			*/
#endif /* __WIN32__ */
#include <hip/hip_dns.h>        /* DNS headers			*/
#ifdef HIP_VPLS
#include <hip/hip_cfg_api.h>
#endif

#include <libxml/tree.h>

#ifndef HITGEN

/*
 * function add_addresses_from_dns()
 *
 * Given a name, perform a DNS lookup and store addresses in the hi_node.
 */
int add_addresses_from_dns(char *name, hi_node *hi)
{
  int first = TRUE;
  struct sockaddr_storage ss_addr;
  struct sockaddr *addr = (struct sockaddr*) &ss_addr;
  sockaddr_list *list, *l;
  int err = 0;
  struct addrinfo hints, *r;
  static struct addrinfo *res = NULL;
  /* cache last result */
  static char prev_name[255];

  /* is this enabled? */
  if (HCNF.disable_dns_lookups)
    {
      return(-1);
    }

  /* clear cached result */
  if (!hi)
    {
      if (res)
        {
          freeaddrinfo(res);
          res = NULL;
        }
      memset(prev_name, 0, sizeof(prev_name));
      return(0);
    }

  /* empty name lookup? */
  if (strlen(hi->name) == 0)
    {
      return(-1);
    }

  list = &hi->addrs;

  /* perform DNS lookup, if different name than last result */
  if (strncmp(prev_name, name, 255) != 0)
    {
      sprintf(prev_name, "%s", name);
      memset(&hints, 0, sizeof(struct addrinfo));
      if (res)
        {
          freeaddrinfo(res);
        }
      res = NULL;
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_RAW;
      err = getaddrinfo(name, NULL, &hints, &res);
    }

  if (err || !res)
    {
      /* address not found in DNS */
      res = NULL;
      return(-1);
    }

  /* process addrinfo result, may be cached from previous lookup */
  for (r = res; r; r = r->ai_next)
    {
      if ((r->ai_family != AF_INET) &&
          (r->ai_family != AF_INET6))
        {
          continue;
        }
      if (IS_LSI(r->ai_addr))             /* skip LSIs */
        {
          continue;
        }
      memcpy(addr, r->ai_addr, r->ai_addrlen);
      if (first)             /* start the address list in hi_node */
        {
          memset(list, 0, sizeof(sockaddr_list));
          memcpy(&list->addr, addr, SALEN(addr));
          list->status = UNVERIFIED;
          first = FALSE;
        }
      else
        {
          l = add_address_to_list(&list, addr, 0);
          if (l->status != ACTIVE)
            {
              l->status = UNVERIFIED;
            }
        }
    }
  return(0);
}

#endif /* HITGEN */

/*
 * conf_transforms_to_mask()
 *
 * Convert configured transforms to a mask.
 * The configured transforms are arrays ordered by preference; the mask is a
 * bitmask used to quickly determine whether or not a transform is supported.
 */
__u16 conf_transforms_to_mask()
{
  int i;
  __u16 transform, mask = 0;

  for (i = 0; i < SUITE_ID_MAX; i++)
    {
      transform = HCNF.hip_transforms[i];
      if (!transform)
        {
          break;
        }
      mask |= (1 << transform);
    }
  for (i = 0; i < SUITE_ID_MAX; i++)
    {
      transform = HCNF.esp_transforms[i];
      if (!transform)
        {
          break;
        }
      mask |= (1 << (ESP_OFFSET + transform));
    }
  return(mask);
}

/*
 * Create an hi_node
 */
hi_node *create_new_hi_node()
{
  hi_node *ret;

  ret = (hi_node *) malloc(sizeof(hi_node));
  if (ret == NULL)
    {
      log_(WARN, "Malloc error: creating new hi_node\n");
      return(NULL);
    }
  memset(ret, 0, sizeof(hi_node));
  pthread_mutex_init(&ret->addrs_mutex, NULL);
  ret->rvs_addrs = malloc(sizeof(struct _sockaddr_list *));
  if (ret->rvs_addrs == NULL)
    {
      log_(WARN, "Malloc error: creating new rvs_addr\n");
      return(NULL);
    }
  *(ret->rvs_addrs) = NULL;
  ret->rvs_count = malloc(sizeof(int));
  if (ret->rvs_count == NULL)
    {
      log_(WARN, "Malloc error: creating new rvs_count\n");
      return(NULL);
    }
  *(ret->rvs_count) = 0;
  ret->rvs_mutex = malloc(sizeof(hip_mutex_t));
  if (ret->rvs_mutex == NULL)
    {
      log_(WARN, "Malloc error: creating new rvs_mutex\n");
      return(NULL);
    }
  pthread_mutex_init(ret->rvs_mutex, NULL);
  ret->rvs_cond = malloc(sizeof(hip_cond_t));
  if (ret->rvs_cond == NULL)
    {
      log_(WARN, "Malloc error: creating new rvs_cond\n");
      return(NULL);
    }
  pthread_cond_init (ret->rvs_cond, NULL);

  return(ret);
}

/*
 * Append an hi_node to a list
 */
void append_hi_node(hi_node **head, hi_node *append)
{
  hi_node *hi_p;
  if (*head == NULL)
    {
      *head = append;
      return;
    }
  for (hi_p = *head; hi_p->next; hi_p = hi_p->next)
    {
      ;
    }
  hi_p->next = append;
}

/*
 * Create new entry in peer host identity list
 * both arguments in host byte order
 */
int add_peer_hit(hip_hit peer_hit, struct sockaddr *peer_addr)
{
  hi_node *hi_p = peer_hi_head;

  if (peer_hi_head == NULL)
    {
      /* Add first new peer node */
      if (!(peer_hi_head = create_new_hi_node()))
        {
          return(-1);
        }
      hi_p = peer_hi_head;
    }
  else
    {
      while (hi_p->next)
        {
          hi_p = hi_p->next;
        }
      if (!(hi_p->next = create_new_hi_node()))
        {
          return(-1);
        }
      hi_p = hi_p->next;
    }
  memcpy(hi_p->hit, peer_hit, sizeof(hip_hit));
#ifdef __WIN32__
  memcpy(&hi_p->addrs.addr, peer_addr, SALEN(peer_addr));
#else
  pthread_mutex_lock(&hi_p->addrs_mutex);
  memcpy(&hi_p->addrs.addr, peer_addr, SALEN(peer_addr));
  pthread_mutex_unlock(&hi_p->addrs_mutex);
#endif
  /* XXX set hi_p->size and other flags here */

  return(0);
}

/*
 * function key_data_to_hi()
 *
 * in:		data = data containing key RR (following RDATA header)
 *              alg = public key algorithm
 *              hi_length = public key length
 *              di_type   = domain identifier type
 *              di_length = domain idetnifier length (optional)
 *              **hi_p = pointer to pointer that will store new Host ID
 *              max_length = for length checking
 *
 * out:		Returns length of bytes used, -1 on error.
 *              hi_p is populated with new Host ID data.
 *
 * Parses algorithm-specific key RR data into a hi_node structure.
 */
int key_data_to_hi(const __u8 *data, __u8 alg, int hi_length, __u8 di_type,
                   int di_length, hi_node **hi_p, int max_length)
{
  int offset = 0, key_len = 0;
  char t;
  __u16 e_len = 0;
  hi_node *hi;

  /* for DSA:			for RSA:
   * T		1		E		1 or 3
   * Q		20		N (pub modulus) variable
   * P		64 + T*8
   * G		64 + T*8
   * Y (pub_key)	64 + T*8
   */
  switch (alg)
    {
    case HI_ALG_DSA:
      /* get T value from the 13th byte, do sanity check */
      t = (__u8) data[0];
      key_len = 64 + (t * 8);
      if (key_len > (MAX_HI_BITS / 8))
        {
          log_(WARN, "Maximum size for HI (%d bits) exceeded.\n",
               MAX_HI_BITS);
          if (!OPT.permissive)
            {
              return(-1);
            }
        }
      if (DSA_PRIV + (key_len * 3) > max_length)
        {
          log_(WARN, "Length too short for T value %u\n", t);
          if (!OPT.permissive)
            {
              return(-1);
            }
        }
      if (DSA_PRIV + (key_len * 3) > hi_length)
        {
          log_(WARN, "HI length too short for T value %u\n", t);
          if (!OPT.permissive)
            {
              return(-1);
            }
        }
      break;
    case HI_ALG_RSA:
      e_len = (__u8) data[0];
      if (e_len == 0)             /* 16-bit value */
        {
          e_len = (__u16) data[1];
          e_len = ntohs(e_len);
        }
      if (e_len > 512)             /* RFC 3110 limits this field to 4096 bits */
        {
          log_(WARN, "RSA HI has invalid exponent length of %u\n",
               e_len);
          return(-1);
        }
      key_len = hi_length - (e_len + ((e_len > 255) ? 3 : 1));
      if (key_len < 0)
        {
          log_(WARN, "RSA HI length too short: %u %u\n",
               hi_length, e_len);
          if (!OPT.permissive)
            {
              return(-1);
            }
        }
      if (key_len > max_length)
        {
          log_(WARN, "Length too short for E length %u\n",
               e_len);
          if (!OPT.permissive)
            {
              return(-1);
            }
        }
      break;
    default:
      log_(WARN, "Invalid HI type in RDATA: %u\n", alg);
      if (!OPT.permissive)
        {
          return(-1);
        }
    }

  /* prepare *hi_p */
  if (*hi_p == NULL)
    {
      *hi_p = create_new_hi_node();
      if (*hi_p == NULL)
        {
          log_(WARN, "Malloc error for storing HI\n");
          return(-1);
        }
    }
  hi = *hi_p;
  if ((alg == HI_ALG_DSA) && hi->dsa)
    {
      log_(WARN, "Parsing HI and DSA already exists.\n");
      return(-1);
    }
  else if ((alg == HI_ALG_RSA) && hi->rsa)
    {
      log_(WARN, "Parsing HI and RSA already exists.\n");
      return(-1);
    }
  hi->algorithm_id = alg;
  hi->size = key_len;

  /* read algorithm-specific key data */
  switch (alg)
    {
    case HI_ALG_DSA:
      hi->dsa = DSA_new();
      /* get Q, P, G, and Y */
      offset = 1;
      hi->dsa->q = BN_bin2bn(&data[offset], DSA_PRIV, 0);
      offset += DSA_PRIV;
      hi->dsa->p = BN_bin2bn(&data[offset], key_len, 0);
      offset += key_len;
      hi->dsa->g = BN_bin2bn(&data[offset], key_len, 0);
      offset += key_len;
      hi->dsa->pub_key = BN_bin2bn(&data[offset], key_len, 0);
#ifndef HIP_VPLS
      log_(NORM, "Found DSA HI with public key: 0x");
      print_hex((char *)&data[offset], key_len);
      log_(NORM, "\n");
#endif
      offset += key_len;
      break;
    case HI_ALG_RSA:
      hi->rsa = RSA_new();
      offset = ((e_len > 255) ? 3 : 1);
      hi->rsa->e = BN_bin2bn(&data[offset], e_len, 0);
      offset += e_len;
      hi->rsa->n = BN_bin2bn(&data[offset], key_len, 0);
#ifndef HIP_VPLS
      log_(NORM, "Found RSA HI with public modulus: 0x");
      print_hex((char *)&data[offset], key_len);
      log_(NORM, "\n");
#endif
      offset += key_len;
      break;
    default:
      break;
    }

  /* optional DI (FQDN or NAI) are saved to hi->name  */
  if ((di_type == DIT_FQDN) || (di_type == DIT_NAI))
    {
      if (di_length > MAX_HI_NAMESIZE)
        {
          di_length = MAX_HI_NAMESIZE;
        }
      memset(hi->name, 0, sizeof(hi->name));
      strncpy(hi->name, (char*)&data[offset], di_length);
      hi->name_len = di_length;
      offset += di_length;
      log_(NORM, "HI has name: %s length: %d\n",
           hi->name, hi->name_len);
    }
  else if (di_type == DIT_NONE)
    {
      if (di_length > 0)
        {
          log_(WARN, "warning: DI type of NONE with a ");
          log_(NORM, "non-zero length (type %d, length %d)\n",
               di_type, di_length);
        }
    }
  else
    {
      log_(WARN, "Unknown DI type (%d) in HI", di_type);
      return(-1);
    }

  hi->rvs_hostnames = malloc(sizeof(char *));
  hi->rvs_hostnames[0] = NULL;

  return(offset);
}

/*
 * function get_preferred_hi()
 *
 * Given an hi_node, traverse the list to find the HI that has the same name
 * as our preferred HI. If no preferred HI was specified or the preferred is
 * not found, return the first HI from the list.
 *
 */
hi_node *get_preferred_hi(hi_node *node)
{
  hi_node *first = node;
  if (HCNF.preferred_hi == NULL)
    {
      return(first);
    }
  for (; node; node = node->next)
    {
      if (strcmp((char *)node->name, HCNF.preferred_hi) == 0)
        {
          return(node);
        }
    }
  return(first);

}

/*
 * function get_preferred_lsi()
 *
 * Returns the LSI associated with the preferred HI. Blocks until HI is loaded
 * because this is used during initialization. Specify the address family
 * through lsi->sa_family.
 */
int get_preferred_lsi(struct sockaddr *lsi)
{
  hi_node *hi = NULL;
  __u32 lsi32;
#ifndef __WIN32__
  struct timeval timeout;
#endif
  if (!lsi)
    {
      return(-1);
    }

  /* block until XML file is parsed */
  while ((g_state == 0) && (!(hi = get_preferred_hi(my_hi_head))))
    {
#ifdef __WIN32__
      Sleep(250);
#else
      timeout.tv_sec = 0;
      timeout.tv_usec = 250000;
      select(0, NULL, NULL, NULL, &timeout);
#endif
    }
  if (!hi)
    {
      return(0);
    }

  switch (lsi->sa_family)
    {
    case AF_INET:       /* pre-configured value or bottom 24-bits of HIT */
      lsi32 = ((struct sockaddr_in*)&hi->lsi)->sin_addr.s_addr;
      if (!lsi32)
        {
          lsi32 = ntohl(HIT2LSI(hi->hit));
        }
      ((struct sockaddr_in*)lsi)->sin_addr.s_addr = lsi32;
      return(0);
    case AF_INET6:      /* 128-bits of HIT */
      memcpy(SA2IP(lsi), hi->hit, HIT_SIZE);
      return(0);
    default:
      return(-1);
    }
}

/* This was written to support handle_broadcasts() in UMH, */
/*
 * function get_preferred_addr()
 *
 * Returns the preferred IPv4 address for this machine.
 */
__u32 get_preferred_addr()
{
  sockaddr_list *l;
  __u32 ip = 0;

  for (l = my_addr_head; l; l = l->next)
    {
      if (AF_INET != l->addr.ss_family)
        {
          continue;
        }
      if (!l->preferred)
        {
          continue;
        }
      ip = (((struct sockaddr_in*)&l->addr)->sin_addr.s_addr);
      break;
    }

  return(ip);
}

/*
 * function get_addr_from_list()
 *
 * in:	list = sockaddr list to search
 *      family = AF_INET or AF_INET6, or zero if address can be from either
 *               family
 * out:	addr = pointer for storing address
 *
 * Finds the preferred address of the specified family from the specified
 * address list. If there is no preferred address, returns the first address
 * from the specified family. Returns 0 if found, -1 if no address was found.
 */
int get_addr_from_list(sockaddr_list *list, int family,
                       struct sockaddr *addr)
{
  sockaddr_list *l, *best = NULL;

  for (l = list; l; l = l->next)
    {
      if (family && (family != l->addr.ss_family))
        {
          continue;
        }
      /* Don't use LSI, loopback, or link-local addresses for HIP. */
      if (IS_LSI(&l->addr))
        {
          continue;
        }
      if ((l->addr.ss_family == AF_INET) && (IN_LOOP(&l->addr)))
        {
          continue;
        }
      if ((l->addr.ss_family == AF_INET6) && \
          (IN6_LOOP(&l->addr) || IN6_LL(&l->addr)))
        {
          continue;
        }

      /* return the first preferred address that is found */
      if (l->preferred)
        {
          best = l;
          break;
          /* otherwise, return the first address of the same
           *family */
        }
      else if (!best)
        {
          best = l;
        }
    }

  if (best)
    {
      memcpy(addr, &best->addr, SALEN(&best->addr));
      return(0);
    }
  else
    {
      return(-1);
    }
}

/*
 * function get_other_addr_from_list()
 *
 * in:	list = sockaddr list to search
 *      exclude = sockaddr in list to exclude from search
 * out:	addr = pointer for storing address
 *
 * Finds an address other than exclude in the given address list.
 * Returns 0 if found another address and exclude,
 *         1 if found another address but not exclude, and
 *         -1 if no other address was found.
 */
int get_other_addr_from_list(sockaddr_list *list, struct sockaddr *exclude,
                             struct sockaddr *addr)
{
  int r = 1;
  sockaddr_list *l, *best = NULL;

  for (l = list; l; l = l->next)
    {
      if (exclude->sa_family != l->addr.ss_family)
        {
          continue;
        }
      if (!memcmp(SA2IP(exclude), SA2IP(&l->addr),
                  SAIPLEN(&l->addr)))
        {
          r = 0;
          continue;               /* skip exclude addr */
        }
      if (l->preferred)
        {
          best = l;
        }
      else if (!best)
        {
          best = l;
        }
    }

  if (best)
    {
      memcpy(addr, &best->addr, SALEN(&best->addr));
      return(r);
    }
  else
    {
      return(-1);
    }
}

/*
 *
 * function find_host_identity()
 *
 * find a match to the provided HIT, and return pointer to the HI
 */
hi_node* find_host_identity(hi_node* hi_head, const hip_hit hitr)
{
  hi_node* temp = hi_head;

  if (temp == NULL)
    {
      return(NULL);
    }

  do
    {
      if (hits_equal(hitr, temp->hit))
        {
          return(temp);
        }
    }
  while ((temp = temp->next));
  return (NULL);
}

/*
 * function init_hip_assoc()
 *
 * in:		my_host_id = pointer to one of my HIs to copy into the assoc.
 *              peer_hit = pointer to peer's HIT, or NULL, for copying any
 *                              attributes from peer_hi_head
 * out:		Returns pointer to a new hip_assoc, or NULL if error.
 *
 * Initialize a hip_assoc by copying the given HI (mine) and allocating the
 * peer's HI.
 */
#ifndef HITGEN
hip_assoc *init_hip_assoc(hi_node *my_host_id, const hip_hit *peer_hit)
{
  hip_assoc *hip_a;
  hi_node *stored_hi;
  int i, num;

  /* Create another HIP association by finding
   * an unused slot in the hip_assoc_table.
   */
  num = -1;
  for (i = 0; i < max_hip_assoc; i++)
    {
      if (hip_assoc_table[i].state == UNASSOCIATED)
        {
          num = i;
          free_hip_assoc(&hip_assoc_table[i]);
          if (num == max_hip_assoc)
            {
              max_hip_assoc++;
            }
          break;
        }
    }
  if (num < 0)
    {
      num = max_hip_assoc;
      if (num == MAX_CONNECTIONS)
        {
          log_(WARN, "Max number of connections reached.\n");
          return(NULL);
        }
      else
        {
          max_hip_assoc++;
        }
    }

  hip_a = &(hip_assoc_table[num]);

  /* Create my Host Identity state */
  if (!(hip_a->hi = create_new_hi_node()))
    {
      return(NULL);
    }
  memcpy(hip_a->hi->hit, my_host_id->hit, sizeof(hip_hit));
  memcpy(&hip_a->hi->lsi, &my_host_id->lsi,
         sizeof(struct sockaddr_storage));
  hip_a->hi->size         = my_host_id->size;
  hip_a->hi->dsa          = my_host_id->dsa;
  hip_a->hi->rsa          = my_host_id->rsa;
  hip_a->hi->r1_gen_count = my_host_id->r1_gen_count;
  hip_a->hi->update_id    = my_host_id->update_id;
  hip_a->hi->algorithm_id = my_host_id->algorithm_id;
  hip_a->hi->anonymous    = my_host_id->anonymous;
  hip_a->hi->allow_incoming = my_host_id->allow_incoming;
  hip_a->hi->skip_addrcheck = my_host_id->skip_addrcheck;
  strncpy(hip_a->hi->name, my_host_id->name, sizeof(hip_a->hi->name));
  hip_a->hi->name_len = my_host_id->name_len;
  memset(&hip_a->hi->addrs, 0, sizeof(sockaddr_list));
  /* note that addrs is not set yet */

  /* Create the peer's HI */
  if (!(hip_a->peer_hi = create_new_hi_node()))
    {
      return(NULL);
    }
  if (peer_hit)
    {
      memcpy(hip_a->peer_hi->hit, peer_hit, sizeof(hip_hit));
      stored_hi = find_host_identity(peer_hi_head, *peer_hit);
      if (stored_hi)             /* transfer parameters from known_host_id...*/
        {
          hip_a->peer_hi->anonymous = stored_hi->anonymous;
          hip_a->peer_hi->allow_incoming =
            stored_hi->allow_incoming;
          hip_a->peer_hi->skip_addrcheck =
            stored_hi->skip_addrcheck;
          memcpy(&hip_a->peer_hi->lsi, &stored_hi->lsi,
                 SALEN(&stored_hi->lsi));
          memcpy(&hip_a->peer_hi->name, &stored_hi->name,
                 stored_hi->name_len);
          hip_a->peer_hi->rvs_mutex = stored_hi->rvs_mutex;
          hip_a->peer_hi->rvs_cond = stored_hi->rvs_cond;
          hip_a->peer_hi->rvs_count = stored_hi->rvs_count;
          hip_a->peer_hi->rvs_addrs = stored_hi->rvs_addrs;
          if (stored_hi->copies == NULL)
            {
              stored_hi->copies = malloc(sizeof(int));
              *(stored_hi->copies) = 1;
            }
          (*(stored_hi->copies))++;
          hip_a->peer_hi->copies = stored_hi->copies;
        }
    }
  memset(&hip_a->peer_hi->addrs, 0, sizeof(sockaddr_list));

  /* Misc state */
  set_state(hip_a, UNASSOCIATED);
  hip_a->use_time.tv_sec = 0;
  hip_a->use_time.tv_usec = 0;
  hip_a->used_bytes_in    = 0;
  hip_a->used_bytes_out   = 0;
  hip_a->spi_in           = 0;
  hip_a->spi_out          = 0;
  hip_a->opaque           = NULL;
  hip_a->regs             = NULL;
  hip_a->rekey            = NULL;
  hip_a->peer_rekey       = NULL;
  memset(&hip_a->rexmt_cache, 0, sizeof(hip_a->rexmt_cache));

  /* Crypto */
  hip_a->hip_transform    = 0;
  hip_a->esp_transform    = 0;
  hip_a->available_transforms = conf_transforms_to_mask();
  hip_a->dh_secret        = NULL;
  hip_a->dh_group_id      = HCNF.dh_group;
  hip_a->dh               = NULL;
  hip_a->peer_dh          = NULL;
  hip_a->keymat_index     = 0;
  memset(hip_a->keymat, 0, sizeof(hip_a->keymat));
  hip_a->preserve_outbound_policy = FALSE;
  hip_a->udp              = FALSE;

  return(hip_a);
}

#endif /* HITGEN */


/*
 * function free_hip_assoc()
 *
 * in:		hip_a = the HIP association to delete.
 * out:		Returns the index of the emptied entry in the hip_assoc_table,
 *              or -1 on error.
 *
 * Frees dynamic memory structures contained in a HIP association entry.
 */
#ifndef HITGEN
int free_hip_assoc(hip_assoc *hip_a)
{
  int i;

  /* locate the association in the table */
  for (i = 0; i < max_hip_assoc; i++)
    {
      if (hip_a == &hip_assoc_table[i])
        {
          break;
        }
    }
  /* return error if something went wrong */
  if ((i > max_hip_assoc) || (i > MAX_CONNECTIONS))
    {
      return(-1);
    }

  /* do not DSA_free(hip_a->hi->dsa), there is only one copy */
  if (hip_a->hi)
    {
      free(hip_a->hi);
    }
  /* if multiple addresses in hi->addrs->next, delete them */
  if (hip_a->peer_hi)
    {
      free_hi_node(hip_a->peer_hi);
    }
  if (hip_a->rexmt_cache.packet)
    {
      free(hip_a->rexmt_cache.packet);
    }
  if (hip_a->opaque)
    {
      free(hip_a->opaque);
    }
  if (hip_a->regs)
    {
      while (hip_a->regs->reginfos)
        {
          struct reg_info *reg = hip_a->regs->reginfos;
          hip_a->regs->reginfos = reg->next;
          free(reg);
        }
      free(hip_a->regs);
    }
  if (hip_a->rekey)
    {
      if (hip_a->rekey->dh)
        {
          unuse_dh_entry(hip_a->rekey->dh);
        }
      free(hip_a->rekey);
    }
  if (hip_a->peer_rekey)
    {
      if (hip_a->peer_rekey->dh)
        {
          DH_free(hip_a->peer_rekey->dh);
        }
      free(hip_a->peer_rekey);
    }
  if (hip_a->mh)
    {
      free(hip_a->mh);
    }
  unuse_dh_entry(hip_a->dh);
  if (hip_a->peer_dh)
    {
      DH_free(hip_a->peer_dh);
    }
  if (hip_a->dh_secret)
    {
      memset(hip_a->dh_secret, 0, sizeof(hip_a->dh_secret));
      free(hip_a->dh_secret);
    }
  /* erase any residual keying material, set ptrs to NULL  */
  memset(hip_a, 0, sizeof(hip_assoc));
  /* prevent the deleted entry from being used */
  hip_a->state = UNASSOCIATED;
  /* reduce maximum entry in table when necessary */
  if (i == (max_hip_assoc - 1))
    {
      max_hip_assoc--;
    }

  return(i);
}

/*
 * function free_hip_associations()
 *
 * Frees all associations in the association table by calling free_hip_assoc()
 * on them.
 */
void free_hip_associations()
{
  int i;
  for (i = 0; i < max_hip_assoc; i++)
    {
      if (hip_assoc_table[i].state != UNASSOCIATED)
        {
          free_hip_assoc(&hip_assoc_table[i]);
        }
    }
}
#endif /* HITGEN */

void free_hi_node(hi_node *hi)
{
  if (!hi)
    {
      return;
    }
  if (hi->dsa)
    {
      DSA_free(hi->dsa);
    }
  if (hi->rsa)
    {
      RSA_free(hi->rsa);
    }
  pthread_mutex_destroy(&hi->addrs_mutex);
  if (hi->copies != NULL)
    {
      (*(hi->copies))--;
      if (*(hi->copies) == 0)             /* Last instance of this node */
        {
          free(hi->rvs_count);
          free(hi->copies);
          free(hi->rvs_addrs);
          pthread_cond_destroy(hi->rvs_cond);
          pthread_mutex_destroy(hi->rvs_mutex);
          free(hi->rvs_cond);
          free(hi->rvs_mutex);
        }
    }
  else           /* Only instance of this node */
    {
      free(hi->rvs_count);
      free(hi->rvs_addrs);
      pthread_cond_destroy(hi->rvs_cond);
      pthread_mutex_destroy(hi->rvs_mutex);
      free(hi->rvs_cond);
      free(hi->rvs_mutex);
    }
  free(hi);
}

/*
 * function replace_hip_assoc()
 *
 * in:		a_old = the old HIP assocation entry to replace
 *              a_new = the new HIP assocation entry
 *
 * out:		None.
 *
 * Replace HIP association number i with the given entry.
 */
#ifndef HITGEN
void replace_hip_assoc(hip_assoc *a_old, hip_assoc *a_new)
{
  int i;

  /* out with the old */
  if ((i = free_hip_assoc(a_old)) < 0)
    {
      log_(WARN, "Error replacing HIP association.\n");
      return;
    }

  /* in with the new */
  a_old->hi = a_new->hi;
  a_old->peer_hi = a_new->peer_hi;
  a_old->state = a_new->state;
  a_old->state_time.tv_sec = a_new->state_time.tv_sec;
  a_old->state_time.tv_usec = a_new->state_time.tv_usec;
  a_old->use_time.tv_sec = a_new->use_time.tv_sec;
  a_old->use_time.tv_usec = a_new->use_time.tv_usec;
  a_old->spi_in = a_new->spi_in;
  a_old->spi_out = a_new->spi_out;
  memcpy(&a_old->cookie_r, &a_new->cookie_r, sizeof(hipcookie));
  memcpy(&a_old->rexmt_cache, &a_new->rexmt_cache,
         sizeof(struct hip_packet_entry));
  a_old->opaque = a_new->opaque;
  a_old->regs = a_new->regs;
  a_old->rekey = a_new->rekey;
  a_old->peer_rekey = a_new->peer_rekey;
  a_old->mh = a_new->mh;
  a_old->hip_transform = a_new->hip_transform;
  a_old->esp_transform = a_new->esp_transform;
  a_old->dh_group_id = a_new->dh_group_id;
  a_old->dh = a_new->dh;
  a_old->peer_dh = a_new->peer_dh;
  a_old->dh_secret = a_new->dh_secret;
  a_old->keymat_index = a_new->keymat_index;
  memcpy(a_old->keymat, a_new->keymat, KEYMAT_SIZE);
  memcpy(a_old->keys, a_new->keys, NUMKEYS * sizeof(struct key_entry));
  a_old->preserve_outbound_policy = a_new->preserve_outbound_policy;
  a_old->udp = a_new->udp;

  /* "free" the old entry (don't call free_hip_assoc) */
  memset(a_new, 0, sizeof(hip_assoc));
  /* reduce maximum entry in table when necessary */
  if (a_new == &hip_assoc_table[max_hip_assoc - 1])
    {
      max_hip_assoc--;
    }
}

#endif /* HITGEN */

void clear_retransmissions(hip_assoc *hip_a)
{
  if (!hip_a)
    {
      return;
    }
  if (hip_a->rexmt_cache.packet != NULL)
    {
      free(hip_a->rexmt_cache.packet);
    }
  hip_a->rexmt_cache.packet = NULL;
  hip_a->rexmt_cache.len = 0;
  memset(&hip_a->rexmt_cache.xmit_time, 0, sizeof(struct timeval));
  hip_a->rexmt_cache.retransmits = 0;
  memset(&hip_a->rexmt_cache.dst, 0, sizeof(struct sockaddr_storage));
}

/*
 * function set_state()
 *
 * in:		hip_a = the HIP association to modify
 *              state = the new state
 * out:		None.
 *
 * Set a new state for a HIP association, recording the current time for
 * state changes.
 */
void set_state(hip_assoc *hip_a, int state)
{
  if (hip_a == NULL)
    {
      return;
    }
  /* update state time on initialization or state change */
  if ((state == UNASSOCIATED) || (state != hip_a->state))
    {
      gettimeofday(&hip_a->state_time, NULL);
    }
  hip_a->state = state;
}

/*
 *
 * function hit_lookup()
 *
 * Look up and return HIT from a sockaddr that contains its IPv4 or
 * IPv6 address.
 * If there are several entries in the HI lists, will return the HIT
 * corresponding to the bit size that we prefer.
 *
 */
hip_hit *hit_lookup(struct sockaddr *addr)
{
  struct _sockaddr_list *a;
  hi_node *temp, *best = NULL;
  int preferred_bits;

  /* find the bit size of the preferred HI to use,
   * to resolve ambiguity when we have multiple HITs */
  if (HCNF.preferred_hi && strrchr(HCNF.preferred_hi, '-'))
    {
      sscanf(strrchr(HCNF.preferred_hi,
                     '-') + 1,"%d", &preferred_bits);
    }
  else
    {
      preferred_bits = 0;
    }

  temp = peer_hi_head;

  /* scan list of HIs */
  while (temp)
    {
      /* scan list of addresses */
      for (a = &temp->addrs; a; a = a->next)
        {
          if (a->addr.ss_family != addr->sa_family)
            {
              continue;
            }
          /* compare IP addresses */
          if (memcmp(SA2IP(&a->addr), SA2IP(addr),
                     SAIPLEN(&a->addr)) == 0)
            {
              if (temp->size * 8 == preferred_bits)
                {
                  return(&temp->hit);
                }
              best = temp;
            }
        }
      temp = temp->next;
    }     /* end while */

  return(best ? &(best->hit) : NULL);
}

/*
 * compare_hits2()
 * special case from memcmp()
 */
int compare_hits2(void const *s1, void const *s2)
{
  int n = 16;

  unsigned char *p1 = (unsigned char *)s1;
  unsigned char *p2 = (unsigned char *)s2;

  do
    {
      if (*p1++ != *p2++)
        {
          return (*--p1 - *--p2);
        }
    }
  while (--n != 0);

  return (0);
}

/*
 *
 * function lsi_lookup()
 *
 * Locate a Host Identity using the 1.x.x.x LSI.
 *
 */
hi_node *lsi_lookup(struct sockaddr *lsi)
{
  hi_node *hi;

  /* scan list of HIs */
  for (hi = peer_hi_head; hi; hi = hi->next)
    {
      if (hi->lsi.ss_family != lsi->sa_family)
        {
          continue;
        }
      /* compare LSIs as IP addresses */
      if (memcmp(SA2IP(&hi->lsi), SA2IP(lsi),
                 SAIPLEN(&hi->lsi)) == 0)
        {
          return(hi);
        }
    }
  return(NULL);
}

/*
 *
 * function lsi_name_lookup()
 *
 * Locate an 1.x.x.x LSI in the peer list using a host's DNS name.
 *
 */
__u32 lsi_name_lookup(char *name, int name_len)
{
  hi_node *hi;
  struct sockaddr_in *lsi4;
  __u32 lsi_ip;
  char *p;

  /* scan list of HIs */
  for (hi = peer_hi_head; hi; hi = hi->next)
    {
      /* check lengths, otherwise a short search string
       * will produce too many matches */
      if ((p = strrchr(hi->name, '-')))             /* ignore "-1024" */
        {
          if ((p - hi->name) > name_len)
            {
              continue;
            }
        }
      else if (strlen(hi->name) > (__u32)name_len)
        {
          continue;
        }
      /* case insensitive compare */
#ifdef __WIN32__
      if (_strnicmp(name, hi->name, name_len) == 0)
        {
#else
      if (strncasecmp(name, hi->name, name_len) == 0)
        {
#endif
          lsi4 = (struct sockaddr_in*)&hi->lsi;
          lsi_ip = lsi4->sin_addr.s_addr;
          if (!lsi_ip)
            {
              if (hits_equal(hi->hit, zero_hit))
                {
                  continue;
                }
              lsi_ip = ntohl(HIT2LSI(hi->hit));
            }
          return(lsi_ip);
        }
    }

  return(0);
}

/*
 * get_hip_dns_server()
 *
 * Return the configured address of the server that stores HIP RRs, if any.
 */
struct sockaddr *get_hip_dns_server()
{
  if (VALID_FAM(&HCNF.dns_server))
    {
      return(SA(&HCNF.dns_server));
    }
  else
    {
      return(NULL);
    }
}

int is_dns_thread_disabled()
{
  return(HCNF.disable_dns_thread);
}

int add_rvs_hostname_to_node(hi_node *hi, char *dnsName)
{
  int i = 0, len;

  /* Calculate current size of list */
  while (hi->rvs_hostnames[i] != NULL)
    {
      /*printf("     Pos %d: %s\n", i, hi->rvs_hostnames[i]);*/
      i++;
    }

  /* Alloc memory for current i + 1 new name + NULL  */
  hi->rvs_hostnames = realloc(hi->rvs_hostnames, (i + 2) * sizeof(char *));
  hi->rvs_hostnames[i + 1] = NULL;
  if (hi->rvs_hostnames == NULL)
    {
      return(-1);
    }
  len = strnlen(dnsName, 255) + 1;
  /* printf("     Adding %s (%d)\n", dnsName, len); */
  hi->rvs_hostnames[i] = malloc(len);
  memcpy(hi->rvs_hostnames[i], dnsName, len);
  return(0);
}

struct rvs_dns_request {
  char    *name;
  hi_node *node;
};

void print_rvs_addr_list(sockaddr_list *list)
{
  sockaddr_list *l;
  log_(NORM, "Address list: [");
  for (l = list; l; l = l->next)
    {
      log_(NORM, "(%d)%s, ", l->if_index,
           logaddr((struct sockaddr*)&l->addr));
    }
  log_(NORM, "]\n");
}

#ifndef HITGEN
void *background_resolve(void *arg)
{
  hi_node *hi;
  char    *name;
  struct addrinfo hints, *aux, *res = NULL;
  struct rvs_dns_request *req;

  req = (struct rvs_dns_request *) arg;
  name = req->name;
  hi = req->node;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_RAW;

  log_(NORM, "*** Trying resolve %s ***\n", name);
  getaddrinfo(name, NULL, &hints, &res);
  log_(NORM, "*** RESOLVE %s FINISHED!! ***\n", name);

  /* Start critical section */
  pthread_mutex_lock(hi->rvs_mutex);

  for (aux = res; aux != NULL; aux = aux->ai_next)
    {
      add_address_to_list(hi->rvs_addrs, aux->ai_addr, 0);
      print_rvs_addr_list(*(hi->rvs_addrs));
    }

  (*(hi->rvs_count))--;
  if (*(hi->rvs_count) == 0)
    {
      log_(NORM, "*** RESOLVE OF ALL RVS FINISHED!! ***\n");
      pthread_cond_broadcast(hi->rvs_cond);
    }
  else
    {
      log_(NORM, "*** Still %d to go... ***\n", *(hi->rvs_count));
    }

  pthread_mutex_unlock(hi->rvs_mutex);
  /* End critical section */

  freeaddrinfo(res);
  free(arg);
#ifdef WIN32
  return(NULL);
#else
  pthread_exit(NULL);
#endif /* WIN32 */
}

#endif /* HITGEN */

/*
 * receive_hip_dns_response()
 *
 * Parse the answer from a DNS server. Looks for the HIP record, validates
 * the HIT, stores the HI into the peer list, and returns the LSI.
 * Returns 0 on error or not found.
 */
__u32 receive_hip_dns_response(unsigned char *buff, int len)
{
  unsigned char *p, *phit = NULL;
  char name[NS_MAXDNAME], fn[25] = "receive_hip_dns_response";
  int i, qn_len, hi_len, name_len = 0;
  struct dns_hdr *r;
  struct dns_ans_hdr *dnsans;
  __u8 hit_len, pk_alg;
  __u16 pk_len;
  __u32 lsi;
  hi_node *hi;
  int pos, remainingBytes, rvsCount, dnsLen, j;
  char dnsName[255];
#ifndef HITGEN
  int k;
  struct rvs_dns_request *argument;
#ifndef WIN32
  pthread_t pt;
#endif /* !WIN32 */
#endif /* !HITGEN */

  /* Tried these resolver calls, but delay is too long and special
   * handling in hip_dns would be required:
   * err = res_query(stmp, ns_c_in, HIP_RR_TYPE, ans, sizeof(ans));
   * err = res_search(name, ns_c_in, HIP_RR_TYPE, ans, sizeof(ans));
   */
  r = (struct dns_hdr *)buff;
  p = (unsigned char *) (r + 1);

  /* question section */
  for (i = ntohs(r->question_count); i > 0; i--)
    {
      /* retrieve/advance through qname */
      name_len = 0;
      for (qn_len = p[0]; qn_len > 0; qn_len = p[0])
        {
          memcpy(&name[name_len], &p[1], qn_len);
          name_len += qn_len;
          name[name_len] = '.';
          name_len++;
          if (name_len > NS_MAXDNAME)
            {
              break;
            }
          p += qn_len + 1;
          if ((p - buff) > len)
            {
              break;
            }
        }
      name[name_len - 1] = '\0';
      p += 5;           /* 1 byte zero length,
                         *  2 bytes type, 2 bytes class */
      if ((p - buff) > len)
        {
          log_(WARN, "%s: Error with question section.\n", fn);
          return(0);
        }
    }
  /* answer section */
  for (i = ntohs(r->answer_count); i > 0; i--)
    {
      dnsans = (struct dns_ans_hdr *) p;
      p = (unsigned char*)(dnsans + 1);
      p += ntohs(dnsans->ans_len);
      if ((ntohs(dnsans->ans_len) == 0) || ((p - buff) > len))
        {
          log_(WARN, "%s: Error with answer section.\n", fn);
          return(0);
        }
      if (ntohs(dnsans->ans_type) != HIP_RR_TYPE)             /* not HIP record
                                                               */
        {
          continue;
        }
      /* parse the HIP record */
      p = (unsigned char*)(dnsans + 1);
      hit_len = p[0];
      pk_alg =  p[1];
      pk_len = (p[3] & 0xFF) + ((p[2] & 0xFF) << 8);           /* 16 bits */
      p += 4;
      /* convert algorithm from IPSECKEY RR to HIP algorithm type */
      pk_alg =  (pk_alg == HIP_RR_PKALG_DSA) ? HI_ALG_DSA : \
               ((pk_alg == HIP_RR_PKALG_RSA) ? HI_ALG_RSA : 0);

      /* ignore unknown algorithms and HIT sizes */
      hi = NULL;
      if ((hit_len == HIT_SIZE) && pk_alg)
        {
          phit = p;
          p += hit_len;
          log_(NORM, "HIP DNS RR: ");
          hi_len = key_data_to_hi(p, pk_alg, pk_len, DIT_NONE, 0,
                                  &hi, len - (p - buff));
          if (hi_len < 0)
            {
              log_(WARN, "invalid HI in HIP DNS RR\n");
            }
        }

      /* stop after the first valid Host Identity */
      if (hi)
        {
          memcpy(hi->hit, phit, hit_len);
          hi->lsi.ss_family = AF_INET;
          ((struct sockaddr_in*)&hi->lsi)->sin_addr.s_addr =
            ntohl(HIT2LSI(hi->hit));
          if (name_len > (MAX_HI_NAMESIZE - 1))
            {
              name_len = MAX_HI_NAMESIZE - 1;
            }
          strncpy(hi->name, name, name_len);
          hi->name_len = name_len;
          p += pk_len;
          if (!validate_hit(hi->hit, hi))
            {
              log_(WARN, "%s: HIT did not validate!\n", fn);
              free_hi_node(hi);
              continue;

            }
          else
            {
              /* printf("%s: HIT validated OK.\n", fn); */
            }

          pos = p -
                ((unsigned char*)&dnsans->ans_len +
                 sizeof(dnsans->ans_len));
          remainingBytes = ntohs(dnsans->ans_len) - pos;
          rvsCount = 0;
          while (remainingBytes > 0)
            {
              dnsLen = strnlen((char*) p, remainingBytes) + 1;
              memcpy(dnsName, p + 1, dnsLen - 1);                   /* First
                                                                     * char is
                                                                     * metadata
                                                                     */
              j = 0;
              for (; j < dnsLen - 2; j++)
                {
                  if (dnsName[j] < 22)
                    {
                      dnsName[j] = '.';
                    }
                }
              fprintf(stderr, "RVS: %s\n", dnsName);
              /* Add hostanmes to hi_node struct */
              add_rvs_hostname_to_node(hi, dnsName);
              rvsCount++;
              p += dnsLen;
              remainingBytes -= dnsLen;
            }

          /* TODO: handle pthread_t values correctly (IF NEEDED)
           *       Dynamic thread ID creation would need a
           *       non-blocking pthread_join
           *       to liberate the memory reserved for the IDs...
           *       Note: pthread_create does not accept NULL as a
           *       first argument,
           *       unlike other implementations found online (QNX)
           */

#ifndef HITGEN
          if (rvsCount > 0)
            {
              *(hi->rvs_count) += rvsCount;
              for (k = 0; hi->rvs_hostnames[k] != NULL;
                   k++)
                {
                  printf("  %d: %s\n",
                         k,
                         hi->rvs_hostnames[k]);
                  argument =
                    malloc(sizeof(struct
                                  rvs_dns_request));
                  argument->name = hi->rvs_hostnames[k];
                  argument->node = hi;
#ifdef WIN32
                  /* For WIN32, resolve serially since
                   * we don't have pthread conditionals */
                  background_resolve((void *)argument);
#else
                  /* Created thread will free allocated
                   *memory */
                  pthread_create(&pt,
                                 NULL,
                                 background_resolve,
                                 (void *)argument);
#endif /* WIN32 */
                }                 /* for */
            }             /* if */
#endif

          append_hi_node(&peer_hi_head, hi);
          lsi = ntohl(HIT2LSI(hi->hit));
          return(lsi);
        }

      /* advance ptr to next record */
      p += pk_len;
      if (p > &buff[NS_PACKETSZ])
        {
          break;
        }
    }     /* end for */

  return(0);
}

/*
 * function hits_equal()
 */
int hits_equal(const hip_hit hit1, const hip_hit hit2)
{
#ifdef __WIN32__
  return(IN6_ADDR_EQUAL((struct in6_addr*)hit1,
                        (struct in6_addr*)hit2));
#else
  return(IN6_ARE_ADDR_EQUAL((struct in6_addr*)hit1,
                            (struct in6_addr*)hit2));
#endif
}

/*
 * Create a struct sockaddr from HIT
 */
void hit_to_sockaddr (struct sockaddr *addr, const hip_hit hit)
{
  memset(addr, 0, sizeof(struct sockaddr_storage));
  addr->sa_family = AF_INET6;
  memcpy(SA2IP(addr), hit, HIT_SIZE);
}

/* generic callback function used by DSA_generate_parameters in hitgen.c */
void cb(int p, int n, void *arg)
{
  /* could do switch(p) here... */
  if (D_VERBOSE == OPT.debug)
    {
      fprintf(arg, ".");
      /* remove this line for lesser priority output */
      fflush(arg);
    }
}

void print_cookie(hipcookie *cookie)
{
  __u32 s =  1 << (cookie->lifetime - 32);
  log_(NORM, "(k=%u lifetime=%d (%u seconds) opaque=%d I=0x%llx)\n",
       cookie->k, cookie->lifetime, s, cookie->opaque, cookie->i);
}

/*
 * function str_to_addr()
 *
 * Returns 0 or negative number if not an address, positive value upon success.
 */
int str_to_addr(__u8 *data, struct sockaddr *addr)
{
  /* TODO: use platform-independent getaddrinfo() w/AI_NUMERICHOST */
#ifdef __WIN32__
  int len = SALEN(addr);
  return(WSAStringToAddress((LPSTR)data, addr->sa_family, NULL,
                            addr, &len) == 0);
#else
  return(inet_pton(addr->sa_family, (char*)data, SA2IP(addr)));
#endif
}

int addr_to_str(struct sockaddr *addr, __u8 *data, int len)
{
#ifdef __WIN32__
  DWORD dw = (DWORD)len;
  return(WSAAddressToString(addr, SALEN(addr), NULL, data, &dw) != 0);
#else
  return(inet_ntop(addr->sa_family, SA2IP(addr), (char*)data,
                   len) == NULL);
#endif
}

int hit_to_str(char *hit_str, const hip_hit hit)
{
  struct sockaddr_storage addr;
  hit_to_sockaddr(SA(&addr), hit);
  return (addr_to_str(SA(&addr), (__u8 *)hit_str, INET6_ADDRSTRLEN));
}

/*
 *
 * function hex_to_bin()
 *
 * in:		src = input hex data
 *		dst = output binary data
 *		dst_len = requested number of binary bytes
 *
 * out:		returns bytes converted if successful,
 *              -1 if error
 *
 */
int hex_to_bin(char *src, char *dst, int dst_len)
{
  char hex[] = "0123456789abcdef";
  char hexcap[] = "0123456789ABCDEF";
  char *p, c;
  int src_len, total, i, val;
  unsigned char o;

  if ((!src) || (!dst))
    {
      return(-1);
    }
  src_len = strlen(src);
  if (dst_len > src_len)
    {
      return(-1);
    }

  /* chop any '0x' prefix */
  if ((src[0] == '0') && (src[1] == 'x'))
    {
      src += 2;
      src_len -= 2;
    }

  /* convert requested number of bytes from hex to binary */
  total = 0;
  for (i = 0; (i < src_len) && (total < dst_len); i += 2)
    {
      /* most significant nibble */
      c = src[i];
      /*
       * Normally would use tolower(), but have found problems
       * with dynamic linking and different glibc versions
       */
      if ((p = strchr(hex, c)) == NULL)
        {
          if ((p = strchr(hexcap, c)) == NULL)
            {
              continue;
            }
          val = p - hexcap;
        }
      else
        {
          val = p - hex;
        }
      if ((val < 0) || (val > 15))
        {
          log_(WARN, "Binary conversion failed %c\n",c);
          return(-1);
        }
      o = val << 4;
      /* least significant nibble */
      c = src[i + 1];
      if ((p = strchr(hex, c)) == NULL)
        {
          if ((p = strchr(hexcap, c)) == NULL)
            {
              continue;
            }
          val = p - hexcap;
        }
      else
        {
          val = p - hex;
        }
      if ((val < 0) || (val > 15))
        {
          log_(WARN, "Binary conversion failed 2 %c", c);
          return(-1);
        }
      o += val;
      dst[total] = o;
      total++;
      if (total >= src_len)
        {
          total = dst_len;
        }
    }
  return(total);
}

/* solve_puzzle()
 *
 * in:		cookie = the cookie to solve (K, lifetime, random I, OPAQUE)
 *              solution = pointer to where to store the solution, if found
 *
 * out:		returns 0 if solved, -ERANGE if exceeds max_tries
 *
 * Solve the cookie puzzle in max_tries and store the solution, otherwise
 * return error.
 */
int solve_puzzle(hipcookie *cookie, __u64 *solution,
                 hip_hit *hit_i, hip_hit *hit_r)
{
  /* For birthday cookie */
  unsigned int i = 0, lifetime_sec;
  int done = 0;
  const char zero[8] = { 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0 };
  unsigned char ij[48] = {0};
  unsigned char ij_part1[40] = {0};
  unsigned char md[SHA_DIGEST_LENGTH] = {0};
  SHA_CTX c;
  int k;
  struct timeval time1, time2;

  /* create the first part of the hash material that doesn't change */
  memcpy(&ij_part1[0], &(cookie->i), 8);
  memcpy(&ij_part1[8], hit_i, sizeof(hip_hit));
  memcpy(&ij_part1[24], hit_r, sizeof(hip_hit));

  log_(NORM, "Using cookie from R1: ");
  print_cookie(cookie);
  log_(NORM, "Calculating Ltrunc(SHA1(I|Rand),K)...");

  k = cookie->k;
  if (k == 0)
    {
      log_(NORM, "Cookie has zero difficulty, using zero solution.\n");
      *solution = 0;
      return(0);
    }
  lifetime_sec = 1 << (cookie->lifetime - 32);
  gettimeofday(&time1, NULL);

  /* Solve cookie puzzle */
  while (!done && g_state == 0)
    {
      if ((++i) % 5000)             /* check progress every so often */
        {
          gettimeofday(&time2, NULL);
          if (TDIFF(time2, time1) > (int)lifetime_sec)
            {
              log_(WARN, "Couldn't solve puzzle within ");
              log_(NORM, "lifetime of %d (%d tries).\n",
                   lifetime_sec, i);
              return(-ERANGE);
            }
        }
      memcpy(ij, ij_part1, 40);
      RAND_bytes(&ij[40], 8);
      SHA1_Init(&c);
      SHA1_Update(&c, ij, 48);
      SHA1_Final(md, &c);

      if (!OPT.daemon && (D_VERBOSE == OPT.debug) &&
          ((i % 10000) == 0))
        {
          printf(".");
          fflush(stdout);
        }
      if (compare_bits((char*)md, SHA_DIGEST_LENGTH, zero, 8,
                       k) == 0)
        {
          gettimeofday(&time2, NULL);
          log_(NORM, "found match in %d tries (~%d seconds).\n",
               i, TDIFF(time2, time1));
          done = 1;
        }
    }

  memcpy(solution, &ij[40], 8);
  log_(NORM, "MD=");
  print_hex(md, sizeof(md));
  log_(NORM, "\nIJ=");
  print_hex(ij, sizeof(ij));
  log_(NORM, "\n");

  return(0);
}

/*
 * function validate_solution()
 *
 *  in:		cookie_r = the cookie from R1
 *              cookie_i = the cookie from I2
 *              hit_i = Initiator's HIT
 *              hit_r = Responder's HIT
 *              solution = J, the puzzle solution given in I2
 *
 *  out:	Returns 0 if cookie is valid, -1 if invalid or error.
 */
int validate_solution(const hipcookie *cookie_r, const hipcookie *cookie_i,
                      hip_hit* hit_i, hip_hit* hit_r, __u64 solution)
{
  unsigned char md[SHA_DIGEST_LENGTH];
  unsigned char ij[48];
  __u8 k;
  SHA_CTX c;
  const char zero[8] = { 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0 };

  /* R1 cache slots may be empty */
  if (cookie_r == NULL)
    {
      log_(WARN, "validate_solution(): cookie_r is NULL.\n");
      return(-1);
    }
  else if (cookie_i == NULL)
    {
      log_(WARN, "validate_solution(): cookie_i is NULL.\n");
      return(-1);
    }

  /* check that K, OPAQUE, I are equal */
  if (cookie_r->i != cookie_i->i)
    {
      log_(NORM, "Puzzle and solution have different I's: ");
      log_(NORM, "puzzle 0x%llx, solution 0x%llx\n",
           cookie_r->i, cookie_i->i);
      return(-1);
    }
  else if (cookie_r->k != cookie_i->k)
    {
      log_(NORM, "Puzzle and solution have different K's: ");
      log_(NORM, "puzzle %u, solution %u\n",
           cookie_r->k, cookie_i->k);
      return(-1);
    }
  else if (cookie_r->opaque != cookie_i->opaque)
    {
      log_(NORM, "Puzzle and solution have different opaque ");
      log_(NORM, "data: puzzle 0x%x, solution 0x%x\n",
           cookie_r->opaque, cookie_i->opaque);
      return(-1);
    }

  memcpy(&ij[0], &(cookie_r->i), 8);
  /* Initiator's HIT*/
  memcpy(&ij[8], hit_i, 16);
  /* Responder's HIT*/
  memcpy(&ij[24], hit_r, 16);
  memcpy(&ij[40], &solution, 8);
  k =  cookie_r->k;
  log_(NORM, "Verifying cookie to %u bits\n", k);

  SHA1_Init(&c);
  SHA1_Update(&c, ij, 48);
  SHA1_Final(md, &c);

  if (compare_bits((char *)md, SHA_DIGEST_LENGTH, zero, 8, k) == 0)
    {
      log_(NORM, "Cookie verified ok.\n");
      return(0);
    }
  else
    {
      log_(NORM, "ij given = ");
      print_hex(ij, 48);
      log_(NORM, " SHA1 = ");
      print_hex(md, SHA_DIGEST_LENGTH);
      log_(WARN, "Cookie did not pass verification.\n");
      if (OPT.permissive)
        {
          return(0);
        }
      else
        {
          return(-1);
        }
    }

  return(-1);
}

#if 0
/* Deprecated in khi-02 draft (base-06) */
/* KHI expansion function used by hi_to_hit()
 */
int khi_expand(__u8 *in, __u8 *out, int len)
{
  int i, j = 0;

  if (len < 12)         /* no expansion */
    {
      memcpy(out, in, len);
      return(0);
    }

  for (i = 0; i < (len - (len % 12)); i += 12)
    {
      memcpy(&out[j], &in[i], 12);              /* 12 bytes of input */
      j += 12;
      memset(&out[j], 0, 4);                    /* 4 bytes of zero */
      j += 4;
    }

  if (len % 12)                                 /* leftover bytes */
    {
      memcpy(&out[j], &in[i], len % 12);
    }

  return(0);
}

#endif

/* KHI encode n-bits from bitstring
 */
int khi_encode_n(__u8 *in, int len, __u8 *out, int n)
{
  BIGNUM *a;
  int m = ((SHA_DIGEST_LENGTH * 8) - n) / 2;
  /*
   * take middle n bits of a number:
   *
   * |-----+------------------+-----|
   *   m=30       n=100         m=30   = 160 bits
   */

  a = BN_bin2bn(in, len, NULL);
  BN_rshift(a, a, m);       /* shift a m-bits to the right */
  BN_mask_bits(a, n);       /* truncate a to an n-bit number */

  /* Round up one byte if indivisible by 8, since 100 bits = 12.5 bytes */
  bn2bin_safe(a, out, n / 8 + (n % 8 ? 1 : 0));
  BN_free(a);

  return(0);
}

/* generate KHI input from HI
 */
int khi_hi_input(hi_node *hi, __u8 *out)
{
  int location;
  __u16 e_len;

  switch (hi->algorithm_id)
    {
    case HI_ALG_DSA:     /* RFC 2536 */
      /* Encode T, Q, P, G, Y */
      location = 0;
      out[location] = (hi->size - 64) / 8;
      location++;
      bn2bin_safe(hi->dsa->q, &out[location], DSA_PRIV);
      bn2bin_safe(hi->dsa->p, &out[location + DSA_PRIV], hi->size);
      bn2bin_safe(hi->dsa->g, &out[location + DSA_PRIV + hi->size],
                  hi->size);
      bn2bin_safe(hi->dsa->pub_key,
                  &out[location + DSA_PRIV + (2 * hi->size)],
                  hi->size);
      break;
    case HI_ALG_RSA:     /* RFC 3110 */
      /* Encode e_len, exponent(e), modulus(n) */
      location = 0;
      e_len = BN_num_bytes(hi->rsa->e);
      if (e_len > 255)
        {
          __u16 *p =  (__u16*) &out[location + 1];
          out[location] = 0x0;
          *p = htons(e_len);
          location += 3;
        }
      else
        {
          out[location] = (__u8) e_len;
          location++;
        }
      location += bn2bin_safe(hi->rsa->e, &out[location], e_len);
      location += bn2bin_safe(hi->rsa->n, &out[location],
                              RSA_size(hi->rsa));
      break;
    default:
      return(-1);
    }
  return(0);
}

/*
 * function hi_to_hit()
 *
 * in:		hi = the Host Identity from which HIT is computed
 *              hit = ptr to destination HIT
 *
 * out:		Returns 0 if successful, -1 on error.
 *
 * Converts the Host Identity to a Type 1 SHA-1 HIT.
 *
 */
int hi_to_hit(hi_node *hi, hip_hit hit)
{
  int len;
  __u8 *data = NULL;
  SHA_CTX ctx;
  unsigned char hash[SHA_DIGEST_LENGTH];
  __u32 prefix;

  if (!hi)
    {
      log_(WARN, "hi_to_hit(): NULL hi\n");
      return(-1);
    }


  /* calculate lengths and validate HIs */
  switch (hi->algorithm_id)
    {
    case HI_ALG_DSA:     /* RFC 2536 */
      if (!hi->dsa)
        {
          log_(WARN, "hi_to_hit(): NULL dsa\n");
          return(-1);
        }
      len = sizeof(khi_context_id) + 1 + DSA_PRIV + (3 * hi->size);
      break;
    case HI_ALG_RSA:     /* RFC 3110 */
      if (!hi->rsa)
        {
          log_(WARN, "hi_to_hit(): NULL rsa\n");
          return(-1);
        }
      len = sizeof(khi_context_id);
      len += BN_num_bytes(hi->rsa->e) + RSA_size(hi->rsa);
      if (BN_num_bytes(hi->rsa->e) > 255)
        {
          len += 3;
        }
      else
        {
          len++;
        }
      break;
    default:
      log_(WARN, "hi_to_hit(): invalid algorithm (%d)\n",
           hi->algorithm_id);
      return(-1);
    }

  /*
   * Prepare hash input
   * input = context_id | input
   */
  data = malloc(len);
  if (!data)
    {
      log_(WARN, "hi_to_hit(): malloc(%d) error\n", len);
      return(-1);
    }
  memcpy(&data[0], khi_context_id, sizeof(khi_context_id));
  khi_hi_input(hi, &data[sizeof(khi_context_id)]);
  /* Compute the hash */
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data, len);
  SHA1_Final(hash, &ctx);

  /* KHI = Prefix | Encode_n( Hash)
   */
  prefix = htonl(HIT_PREFIX_SHA1_32BITS);
  memcpy(&hit[0], &prefix, 4);       /* 28-bit prefix */
  khi_encode_n(hash, SHA_DIGEST_LENGTH, &hit[3], 100 );
  /* lower 100 bits of HIT */
  hit[3] = (HIT_PREFIX_SHA1_32BITS & 0xFF) |
           (hit[3] & 0x0F);       /* fixup the 4th byte */
  free(data);
  return(0);
}

/*
 * function validate_hit()
 *
 * in:		hit = Host Identity Tag to validate
 *              hi = the Host Identity to check the HIT against
 *
 * out:		Returns TRUE (1) if HIT is valid, FALSE (0) otherwise
 */
int validate_hit(hip_hit hit, hi_node *hi)
{
  hip_hit computed_hit;

  if (!hi)
    {
      return(FALSE);
    }

  if (hi_to_hit(hi, computed_hit) < 0)
    {
      return(FALSE);
    }
#ifdef __MACOSX__
  return(IN6_ARE_ADDR_EQUAL((struct in6_addr*)computed_hit,
                            (struct in6_addr*)hit));
#else
  return(hits_equal(computed_hit, hit));
#endif
}

/* function ntoh64()
 *
 * Swap the byte order of an unsigned 64-byte integer; from Ericsson.
 */
#if defined(__arm__) || defined(__BIG_ENDIAN__)
#define ntoh64__(k) (k)
#else
#define ntoh64__(k) ((((uint64_t) ntohl((k) >> 32)) & 0x00000000ffffffffll) | \
                     (((uint64_t) ntohl((k)) << 32) & 0x00000000ffffffffll))
#endif
/*
 * compare_bits()
 *
 * in:		s1 = first string
 *              s2 = second string
 *              numbits = number of bits to compare
 *
 * out:		Returns 0 if equal, 1 if not equal, -1 on error.
 *
 * Compare the specified number of bits of two strings,
 * starting from the end of each string and moving left.
 *
 */
int compare_bits(const char *s1,
                 int s1_len,
                 const char *s2,
                 int s2_len,
                 int numbits)
{
  /*int bytenum, num_bytes, num_bits; */
  __u64 mask, a, b;

  if (numbits < 1)
    {
      return(-1);
    }
  /* requested to compare more bits than we have */
  if ((numbits > s1_len * 8) || (numbits > s2_len * 8))
    {
      return(-1);
    }

#ifdef __WIN32__
  mask = 0xFFFFFFFFFFFFFFFF;
#else
  mask = 0xFFFFFFFFFFFFFFFFll;
#endif
  mask = mask >> (64 - numbits);
  memcpy(&a, &s1[s1_len - 8], 8);       /* get the last 8 bytes (64 bits) */
  memcpy(&b, &s2[s2_len - 8], 8);
  a = ntoh64(a) & mask;       /* s1, s2 are coming from network */
  b = ntoh64(b) & mask;
  return(a != b);
}

/*
 * function compare_hits()
 *
 * in:		a, b = HITs to compare
 * out:		Returns > 0 if (a > b)
 *
 * Uses BN_ucmp to compare HITs.
 */
int compare_hits(hip_hit a, hip_hit b)
{
  BIGNUM *hit1, *hit2;
  int result;

  hit1 = BN_bin2bn((unsigned char*)a, HIT_SIZE, NULL);
  hit2 = BN_bin2bn((unsigned char*)b, HIT_SIZE, NULL);
  result = BN_ucmp(hit1, hit2);
  BN_free(hit1);
  BN_free(hit2);
  return(result);
}

/*
 * function maxof()
 *
 * in:		num_args = number of items
 *              ... = list of integers
 * out:		Returns the integer with the largest value from the
 *              list provided. Must have three or more values in the list.
 */
int maxof(int num_args, ...)
{
  int max, i, a;
  va_list ap;

  va_start(ap, num_args);
  max = va_arg(ap, int);
  for (i = 2; i < num_args; i++)
    {
      if ((a = va_arg(ap, int)) > max)
        {
          max = a;
        }
    }
  va_end(ap);
  return(max);
}

/*
 * function hip_packet_type()
 *
 * in:		type = HIP packet type number
 * out:		Returns string containing the HIP packet name
 *
 */
void hip_packet_type(int type, char *r)
{
  switch (type)
    {
    case HIP_I1:
      sprintf(r, "HIP_I1");
      break;
    case HIP_R1:
      sprintf(r, "HIP_R1");
      break;
    case HIP_I2:
      sprintf(r, "HIP_I2");
      break;
    case HIP_R2:
      sprintf(r, "HIP_R2");
      break;
    case CER:
      sprintf(r, "CER");
      break;
    case UPDATE:
      sprintf(r, "UPDATE");
      break;
    case NOTIFY:
      sprintf(r, "NOTIFY");
      break;
    case CLOSE:
      sprintf(r, "CLOSE");
      break;
    case CLOSE_ACK:
      sprintf(r, "CLOSE_ACK");
      break;
/*	case BOS:	// BOS and PAYLOAD were removed starting with base-01
 *               sprintf(r, "BOS");
 *               break;
 *       case PAYLOAD:
 *               sprintf(r, "PAYLOAD");
 *               break;
 */
    default:
      sprintf(r, "UNKNOWN");
    }
}

/*
 * function print_usage()
 *
 * Displays available program arguments.
 */
void print_usage()
{
  printf("%s v%s daemon\n", HIP_NAME, HIP_VERSION);
  printf("Usage: hip [debug] [options]\n\n");
  printf("Where debug is one of the following:\n");
  printf("  -v\t show verbose debugging information\n");
  printf("  -q\t quiet mode, only errors are shown\n");
  printf("and options are:\n");
  printf("  -d\t daemon mode, fork and write output to logfile\n");
  printf("  -r1\t show pre-calculated R1 generation\n");
  printf("  -o\t opportunistic -- send NULL destination HIT in I1\n");
  printf("  -a\t allow any -- allow HITs not listed in the known identities "
         "file\n");
  printf("  -conf\t <filename> absolute path to hip.conf file\n");
  printf("  -p\t permissive -- doesn't enforce sigs, checksums ");
  printf("(for debugging)\n");
  printf("  -nr\t no retransmit mode (for testing)\n");
  printf("  -t <addr>  manually trigger a HIP exchange with the ");
  printf("given address\n");
  printf("  -rvs\t rendezvous server mode\n");
#ifndef __WIN32__
  printf("  -mr\t mobile router mode\n");
#endif /* !__WIN32__ */
  printf("  -mh\t turn on loss-based multihoming\n");
  printf("With no options, simple output will be displayed.\n\n");
}

/*
 * function checksum_packet()
 *
 * Calculates the checksum of a HIP packet with pseudo-header
 * src and dst are IPv4 or IPv6 addresses in network byte order
 */
__u16 checksum_packet(__u8 *data, struct sockaddr *src, struct sockaddr *dst)
{
  __u16 checksum;
  unsigned long sum = 0;
  int count, length;
  unsigned short *p;       /* 16-bit */
  pseudo_header pseudoh;
  pseudo_header6 pseudoh6;
  __u32 src_network, dst_network;
  struct in6_addr *src6, *dst6;
  hiphdr* hiph = (hiphdr*) data;

  if (src->sa_family == AF_INET)
    {
      /* IPv4 checksum based on UDP-- Section 6.1.2 */
      src_network = ((struct sockaddr_in*)src)->sin_addr.s_addr;
      dst_network = ((struct sockaddr_in*)dst)->sin_addr.s_addr;

      memset(&pseudoh, 0, sizeof(pseudo_header));
      memcpy(&pseudoh.src_addr, &src_network, 4);
      memcpy(&pseudoh.dst_addr, &dst_network, 4);
      pseudoh.protocol = H_PROTO_HIP;
      length = (hiph->hdr_len + 1) * 8;
      pseudoh.packet_length = htons((__u16)length);

      count = sizeof(pseudo_header);           /* count always even number */
      p = (unsigned short*) &pseudoh;
    }
  else
    {
      /* IPv6 checksum based on IPv6 pseudo-header */
      src6 = &((struct sockaddr_in6*)src)->sin6_addr;
      dst6 = &((struct sockaddr_in6*)dst)->sin6_addr;

      memset(&pseudoh6, 0, sizeof(pseudo_header6));
      memcpy(&pseudoh6.src_addr[0], src6, 16);
      memcpy(&pseudoh6.dst_addr[0], dst6, 16);
      length = (hiph->hdr_len + 1) * 8;
      pseudoh6.packet_length = htonl(length);
      pseudoh6.next_hdr = H_PROTO_HIP;

      count = sizeof(pseudo_header6);           /* count always even number */
      p = (unsigned short*) &pseudoh6;
    }
  /*
   * this checksum algorithm can be found
   * in RFC 1071 section 4.1
   */

  /* sum the pseudo-header */
  /* count and p are initialized above per protocol */
  while (count > 1)
    {
      sum += *p++;
      count -= 2;
    }

  /* one's complement sum 16-bit words of data */
  /* log_(NORM, "checksumming %d bytes of data.\n", length); */
  count = length;
  p = (unsigned short*) data;
  while (count > 1)
    {
      sum += *p++;
      count -= 2;
    }
  /* add left-over byte, if any */
  if (count > 0)
    {
      sum += (unsigned char)*p;
    }

  /*  Fold 32-bit sum to 16 bits */
  while (sum >> 16)
    {
      sum = (sum & 0xffff) + (sum >> 16);
    }
  /* take the one's complement of the sum */
  checksum = (__u16)(~sum);

  return(checksum);
}

/*
 * function checksum_udp_packet()
 *
 * XXX TODO: combine with checksum_packet() function; the two functions differ
 *           by protocol number in pseudo-header and how the length is read
 *
 * Calculates the checksum of a UDP packet with pseudo-header
 * src and dst are IPv4 or IPv6 addresses in network byte order
 */
__u16 checksum_udp_packet(__u8 *data,
                          struct sockaddr *src,
                          struct sockaddr *dst)
{
  __u16 checksum;
  unsigned long sum = 0;
  int count, length;
  unsigned short *p;       /* 16-bit */
  pseudo_header pseudoh;
  pseudo_header6 pseudoh6;
  __u32 src_network, dst_network;
  struct in6_addr *src6, *dst6;
  udphdr* udph = (udphdr*) data;

  if (src->sa_family == AF_INET)
    {
      /* IPv4 checksum based on UDP-- Section 6.1.2 */
      src_network = ((struct sockaddr_in*)src)->sin_addr.s_addr;
      dst_network = ((struct sockaddr_in*)dst)->sin_addr.s_addr;

      memset(&pseudoh, 0, sizeof(pseudo_header));
      memcpy(&pseudoh.src_addr, &src_network, 4);
      memcpy(&pseudoh.dst_addr, &dst_network, 4);
      pseudoh.protocol = H_PROTO_UDP;
      length = ntohs(udph->len);
      pseudoh.packet_length = htons((__u16)length);

      count = sizeof(pseudo_header);           /* count always even number */
      p = (unsigned short*) &pseudoh;
    }
  else
    {
      /* IPv6 checksum based on IPv6 pseudo-header */
      src6 = &((struct sockaddr_in6*)src)->sin6_addr;
      dst6 = &((struct sockaddr_in6*)dst)->sin6_addr;

      memset(&pseudoh6, 0, sizeof(pseudo_header6));
      memcpy(&pseudoh6.src_addr[0], src6, 16);
      memcpy(&pseudoh6.dst_addr[0], dst6, 16);
      length = ntohs(udph->len);
      pseudoh6.next_hdr = H_PROTO_UDP;
      pseudoh6.packet_length = htonl(length);

      count = sizeof(pseudo_header6);           /* count always even number */
      p = (unsigned short*) &pseudoh6;
    }
  /*
   * this checksum algorithm can be found
   * in RFC 1071 section 4.1
   */

  /* sum the psuedo-header */
  /* count and p are initialized above per protocol */
  while (count > 1)
    {
      sum += *p++;
      count -= 2;
    }

  /* one's complement sum 16-bit words of data */
  /* log_(NORM, "checksumming %d bytes of data.\n", length); */
  count = length;
  p = (unsigned short*) data;
  while (count > 1)
    {
      sum += *p++;
      count -= 2;
    }
  /* add left-over byte, if any */
  if (count > 0)
    {
      sum += (unsigned char)*p;
    }

  /*  Fold 32-bit sum to 16 bits */
  while (sum >> 16)
    {
      sum = (sum & 0xffff) + (sum >> 16);
    }
  /* take the one's complement of the sum */
  checksum = (__u16)(~sum);

  return(checksum);
}

/*
 * function checksum_magic()
 *
 * Calculates the hitMagic value given two HITs.
 * Note that since this is simple addition, it doesn't matter
 * which HIT is given first, and the one's complement is not
 * taken.
 */
__u16 checksum_magic(const hip_hit *i, const hip_hit *r)
{
  int count;
  unsigned long sum = 0;
  unsigned short *p;       /* 16-bit */

  /*
   * this checksum algorithm can be found
   * in RFC 1071 section 4.1, pseudo-header
   * from RFC 2460
   */

  /* one's complement sum 16-bit words of data */
  /* sum initiator's HIT */
  count = HIT_SIZE;
  p = (unsigned short*) i;
  while (count > 1)
    {
      sum += *p++;
      count -= 2;
    }
  /* sum responder's HIT */
  count = HIT_SIZE;
  p = (unsigned short*) r;
  while (count > 1)
    {
      sum += *p++;
      count -= 2;
    }

  /*  Fold 32-bit sum to 16 bits */
  while (sum >> 16)
    {
      sum = (sum & 0xffff) + (sum >> 16);
    }

  /*log_(NORM, "hitMagic checksum over %d bytes: 0x%x\n",
   *   2*HIT_SIZE, (__u16)sum);*/

  /* don't take the one's complement of the sum */
  return((__u16)sum);
}

/*
 * Use ip header length to find start of HIP packet
 */
int hip_header_offset(const __u8 *data)
{
  struct ip *iph = (struct ip*) &data[0];
  int len =  ((iph->ip_hl & 0x0f) << 2);       /* IPv4 header length */

  /* Adjust for any UDP header plus zero marker */
  if (iph->ip_p == IPPROTO_UDP)
    {
      len += sizeof(udphdr) + sizeof(__u32);
    }

  return(len);
}

/*
 * Compute real parameter length using the length field in the TLV header;
 * from RFC 5201 section 5.2.1
 */
int tlv_length_to_parameter_length(int length)
{
  return (11 + length - (length + 3) % 8);
}

/*
 *  Makes sure we have moved a multiple of 8 bytes
 *  Takes input and returns next highest multiple of 8 bytes
 */
int eight_byte_align(int location)
{
  if (location <= 0)
    {
      return(0);
    }
  else
    {
      return (7 + location - (location - 1) % 8);
    }
}

/*
 * Return pointer to hip association (none if not found)
 */
hip_assoc* find_hip_association(struct sockaddr *src, struct sockaddr *dst,
                                hiphdr* hiph)
{
  int i;
  hip_assoc* hip_a;

  for (i = 0; i < max_hip_assoc; i++)
    {
      hip_a = &(hip_assoc_table[i]);
      /* state and identities must exist */
      if ((hip_a->state == 0) || !hip_a->hi || !hip_a->peer_hi)
        {
          continue;
        }
      /*
       * src must match peer_hi->addrs.addr
       * dst must match hi->addrs.addr
       * hit_send must match peer_hi->hit
       * hit_recv must match hi->hit
       */
      /* even though hi->addrs is a list, only consider
       * the first (preferred) address in the list */
      if (!(memcmp(SA2IP(HIPA_DST(hip_a)), SA2IP(src), SAIPLEN(src)))
          &&
          !(memcmp(SA2IP(HIPA_SRC(hip_a)), SA2IP(dst), SAIPLEN(dst)))
          &&
          (hits_equal(hip_a->peer_hi->hit, hiph->hit_sndr)) &&
          (hits_equal(hip_a->hi->hit, hiph->hit_rcvr)))
        {
          return (hip_a);
        }
    }
  return(NULL);
}

/*
 * Return pointer to hip association (none if not found)
 */
hip_assoc* find_hip_association2(hiphdr* hiph)
{
  int i;
  hip_assoc* hip_a;

  for (i = 0; i < max_hip_assoc; i++)
    {
      hip_a = &(hip_assoc_table[i]);
      if ((hip_a->state == 0) || !hip_a->hi || !hip_a->peer_hi)
        {
          continue;
        }
      if ((hits_equal(hip_a->peer_hi->hit, hiph->hit_sndr)) &&
          (hits_equal(hip_a->hi->hit, hiph->hit_rcvr)))
        {
          return (hip_a);
        }
    }
  return(NULL);
}

/*
 * Return pointer to hip association (none if not found)
 * Lookup based only on IPs
 */
hip_assoc* find_hip_association3(struct sockaddr *src, struct sockaddr *dst)
{
  int i;
  hip_assoc* hip_a;

  for (i = 0; i < max_hip_assoc; i++)
    {
      hip_a = &(hip_assoc_table[i]);
      if ((hip_a->state == 0) || !hip_a->hi || !hip_a->peer_hi)
        {
          continue;
        }
      /*
       * src must match peer_hi->addrs.addr
       * dst must match hi->addrs.addr
       * even though hi->addrs is a list, only consider
       * the first (preferred) address in the list */
      if (!(memcmp(SA2IP(HIPA_DST(hip_a)), SA2IP(src), SAIPLEN(src)))
          &&
          !(memcmp(SA2IP(HIPA_SRC(hip_a)), SA2IP(dst), SAIPLEN(dst))))
        {
          return (hip_a);
        }
    }
  return(NULL);
}

/*
 * Return pointer to hip association (none if not found)
 */
hip_assoc* find_hip_association4(hip_hit hit)
{
  int i;
  hip_assoc* hip_a;

  for (i = 0; i < max_hip_assoc; i++)
    {
      hip_a = &(hip_assoc_table[i]);
      if ((hip_a->state == 0) || !hip_a->hi || !hip_a->peer_hi)
        {
          continue;
        }
      if ((hits_equal(hip_a->peer_hi->hit, hit)))
        {
          return (hip_a);
        }
    }
  return(NULL);
}

/*
 * Return pointer to hip association for the given SPI (none if not found)
 * dir =  0 to check both incoming/outgoing SPIs,
 *        1 for incoming SPI,
 *        2 for outgoing SPI.
 */
hip_assoc* find_hip_association_by_spi(__u32 spi, int dir)
{
  int i;
  hip_assoc* hip_a;

  for (i = 0; i < max_hip_assoc; i++)
    {
      hip_a = &(hip_assoc_table[i]);
      if (hip_a->state == 0)
        {
          continue;
        }
      if (((dir == 0) || (dir == 1)) && (hip_a->spi_in == spi))
        {
          return(hip_a);
        }
      else if (((dir == 0) ||
                (dir == 2)) && (hip_a->spi_out == spi))
        {
          return(hip_a);
        }
    }
  return(NULL);
}

hip_assoc *search_registrations(hip_hit hit, __u8 type)
{
  hip_assoc *hip_a;
  struct reg_info *reg;

  hip_a = find_hip_association4(hit);
  if (!hip_a)         /* peer HIT not found */
    {
      return(NULL);
    }

  if (!hip_a->regs)
    {
      return(NULL);           /* did not offer registration to this peer */

    }
  for (reg = hip_a->regs->reginfos; reg; reg = reg->next)
    {
      if (type != reg->type)
        {
          continue;
        }
      if (reg->state == REG_GRANTED)
        {
          return(hip_a);               /* found, registration is valid */
        }
      else               /* registration type matches, but state is invalid */
        {
          return(NULL);
        }
    }
  return(NULL);       /* registration type not found */
}

hip_assoc *search_registrations2(__u8 type, int state)
{
  int i;
  hip_assoc* hip_a;
  struct reg_info *reg;

  for (i = 0; i < max_hip_assoc; i++)
    {
      hip_a = &(hip_assoc_table[i]);
      if ((hip_a->state == 0) || !hip_a->regs ||
          !hip_a->regs->reginfos)
        {
          continue;
        }
      /* currently there are only three supported reg types,
       * so we're assuming this double loop is not too bad.. */
      for (reg = hip_a->regs->reginfos; reg; reg = reg->next)
        {
          if (type != reg->type)
            {
              continue;
            }
          if (state != reg->state)
            {
              continue;
            }
          return(hip_a);
        }
    }
  return(NULL);
}

/*
 * Initialize OpenSSL crypto library.
 * thread code is adapted from openssl-0.9.8g/crypto/threads/mttest.c
 */
static hip_mutex_t *g_lock_cs;
void init_crypto()
{
  struct timeval time1;
  char rnd_seed[20] = {0};
  int i;

  CRYPTO_malloc_init();

  /* seed the random number generator */
#ifdef WIN32
  RAND_screen();
#endif /* WIN32 */
  /* According to RAND_add(3), /dev/urandom is used, if available,
   * to seed the PRNG transparently. */
  if (!RAND_status())
    {
      /* PRNG not seeded with enough data, include more data */
      gettimeofday(&time1, NULL);
      sprintf(rnd_seed, "%x%x", (unsigned int)time1.tv_usec,
              (unsigned int)time1.tv_sec);
      RAND_seed(rnd_seed, sizeof(rnd_seed));
    }

  if (!RAND_status())
    {
      /* fprintf is used because log not initialized yet */
      fprintf(stderr, "*** Failed to seed PRNG with enough data!\n");
    }

  /* make crypto library thread safe */
  g_lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(hip_mutex_t));
  if (!g_lock_cs)
    {
      fprintf(stderr, "*** Error with OPENSSL_malloc() in init_crypto()!\n");
      return;
    }
  for (i = 0; i < CRYPTO_num_locks(); i++)
    {
      pthread_mutex_init( &(g_lock_cs[i]), NULL);
    }
#ifdef WIN32
  /* CRYPTO_set_id_callback() already has default definition on win32 */
  CRYPTO_set_locking_callback((void (*)(int,int,const char*,int))
                              pthread_locking_callback );
#else
  CRYPTO_set_id_callback((unsigned long (*)())pthread_self );
  CRYPTO_set_locking_callback((void (*)())pthread_locking_callback );
#endif /* WIN32 */
}

/*
 * De-initialize OpenSSL crypto library.
 * thread code is adapted from openssl-0.9.8g/crypto/threads/mttest.c
 */
void deinit_crypto()
{
  int i;
  CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks(); i++)
    {
      pthread_mutex_destroy(&(g_lock_cs[i]));
    }
  OPENSSL_free(g_lock_cs);
}

/*
 * Thread locking callback used by OpenSSL crypto library
 * this is basically the code from openssl-0.9.8g/crypto/threads/mttest.c
 */
void pthread_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    {
      pthread_mutex_lock( &(g_lock_cs[type]));
    }
  else
    {
      pthread_mutex_unlock( &(g_lock_cs[type]));
    }
}

/*
 * Logging functions
 */
static FILE *logfp;

int init_log()
{
  char *name;
  char default_name[255];

  if (!OPT.daemon)
    {
      return(0);
    }

  if (HCNF.log_filename)
    {
      name = HCNF.log_filename;
    }
  else
    {
#ifdef __WIN32__
      snprintf(default_name, sizeof(default_name), "%s",
               HIP_LOG_FILENAME);
#else
      snprintf(default_name, sizeof(default_name), "%s/log/%s",
               LOCALSTATEDIR, HIP_LOG_FILENAME);
#endif
      name = default_name;
    }

  logfp = fopen(name, "a");

  if (!logfp)
    {
      fprintf(stderr,"Unable to open logfile (%s) for writing: %s\n",
              name, strerror(errno));
      return(-1);
    }

  return(0);
}

void close_log()
{
  if (OPT.daemon)
    {
      fflush(logfp);
      fclose(logfp);
    }
}

void fflush_log()
{
  if (D_QUIET != OPT.debug)
    {
      fflush(OPT.daemon ? logfp : stdout);
    }
}

/*
 * log_()
 *
 * in:		level = One of the following levels:
 *                NORM:  normal output (D_VERBOSE) to screen or file
 *                NORMT: timestamp + normal
 *                WARN:  errorstamp + normal
 *                ERR:   output to stderr only, use for fatal errors
 *                QOUT:   output to screen or file, even if D_QUIET, with time
 *              fmt, ... = arguments for printf(...)
 *
 * Output to stdout, stderr, file, or nothing.
 */
void log_(int level, char *fmt, ...)
{
  va_list ap;
  FILE *fp = NULL;
  char timestr[26];
  struct timeval now;

  switch (level)
    {
    case ERR:     /* print to stderr */
#ifdef __WIN32__ /* problem displaying stderr on win32 */
      fp = stdout;
#else
      fp = stderr;
#endif
      break;
    case QOUT:     /* log to file, or print when not D_QUIET */
      if (D_QUIET != OPT.debug)
        {
          fp = OPT.daemon ? logfp : stdout;
        }
      else
        {
          return;
        }
      break;
    case NORM:
    case NORMT:
    case WARN:
    default:     /* log to file, print when D_VERBOSE */
      if (D_VERBOSE == OPT.debug)
        {
          fp = OPT.daemon ? logfp : stdout;
        }
      else
        {
          return;
        }
      break;
    }

  /* include the current time at beginning of log line */
  if ((level == NORMT) || (level == QOUT))
    {
#ifdef __WIN32__
      now.tv_usec = 0;
      now.tv_sec = time(NULL);
      strncpy(timestr, ctime(&now.tv_sec), sizeof(timestr));
#else
      gettimeofday(&now, NULL);
      ctime_r(&now.tv_sec, timestr);
#endif
      timestr[strlen(timestr) - 1] = 0;
      fprintf(fp, "%s (%d) ", timestr, level);
      /* print warning symbol for errors */
    }
  else if ((level == WARN) || (level == ERR))
    {
      fprintf(fp, "*** ");
    }

  /* pass variable argument list to vfprintf() */
  va_start(ap, fmt);
  vfprintf(fp, fmt, ap);
  va_end(ap);
}

char *logaddr(struct sockaddr *addr)
{
  static char ip_string[INET6_ADDRSTRLEN];
  memset(ip_string, 0, INET6_ADDRSTRLEN);
  if (addr)
    {
      addr_to_str(addr, (__u8*)ip_string, INET6_ADDRSTRLEN);
    }
  else
    {
      sprintf(ip_string, "<null>");
    }
  return(ip_string);
}

void logdsa(DSA *dsa)
{
  BIO *bp;
  FILE *fp;

  if (D_VERBOSE == OPT.debug)
    {
      fp = OPT.daemon ? logfp : stdout;
    }
  else
    {
      return;
    }

  bp = BIO_new_fp(fp, BIO_NOCLOSE);
  DSAparams_print(bp, dsa);
  BIO_free(bp);
}

void logrsa(RSA *rsa)
{
  BIO *bp;
  FILE *fp;

  if (D_VERBOSE == OPT.debug)
    {
      fp = OPT.daemon ? logfp : stdout;
    }
  else
    {
      return;
    }

  bp = BIO_new_fp(fp, BIO_NOCLOSE);
  RSA_print(bp, rsa, 0);
  BIO_free(bp);
}

void logdh(DH *dh)
{
  BIO *bp;
  FILE *fp;

  if (D_VERBOSE == OPT.debug)
    {
      fp = OPT.daemon ? logfp : stdout;
    }
  else
    {
      return;
    }

  bp = BIO_new_fp(fp, BIO_NOCLOSE);
  DHparams_print(bp, dh);
  BIO_free(bp);
}

void logbn(BIGNUM *bn)
{
  BIO *bp;
  FILE *fp;

  if (D_VERBOSE == OPT.debug)
    {
      fp = OPT.daemon ? logfp : stdout;
    }
  else
    {
      return;
    }

  bp = BIO_new_fp(fp, BIO_NOCLOSE);
  BN_print(bp, bn);
  BIO_free(bp);
}

/*
 * function bn2bin_safe(BIGNUM *dest)
 *
 * BN_bin2bn() chops off the leading zero(es) of the BIGNUM,
 * so numbers end up being left shifted.
 * This fixes that by enforcing an expected destination length.
 */
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len)
{
  int padlen = len - BN_num_bytes(a);
  /* add leading zeroes when needed */
  if (padlen > 0)
    {
      memset(to, 0, padlen);
    }
  BN_bn2bin(a, &to[padlen]);
  /* return value from BN_bn2bin() may differ from length */
  return(len);
}

/*
 * function print_hex()
 *
 * Generic binary to hex printer.
 */
void print_hex(const void* data, int len)
{
  int i;
  unsigned char *p = (unsigned char*) data;
  FILE *fp;

  if (D_VERBOSE == OPT.debug)
    {
      fp = OPT.daemon ? logfp : stdout;
    }
  else
    {
      return;
    }

  for (i = 0; i < len; i++)
    {
      if ((2 * len > 60) && (i && (i % 16 == 0)))
        {
          fprintf(fp, "\n");
        }
      else if (i % 4 == 0)
        {
          fprintf(fp, " ");
        }
      fprintf(fp, "%.2x", p[i]);
    }
}

/*
 * function print_binary()
 *
 * Generic binary printer, len is number of bits to print.
 */
void print_binary(void* data, int len)
{
  int i, byte, bit;
  unsigned char *p = (unsigned char*) data;
  FILE *fp;

  if (D_VERBOSE == OPT.debug)
    {
      fp = OPT.daemon ? logfp : stdout;
    }
  else
    {
      return;
    }

  for (i = 0; i < len; i++)
    {
      byte = i / 8;           /* which byte to print (0-len/8)  */
      bit = i % 8;            /* which bit within the byte (0-7) */
#if 0
      if (byte && !bit && (byte % 4 == 0))             /*newline every 4th byte
                                                        */
        {
          fprintf(fp, "\n");
        }
      else if (i && (bit  == 0))             /* space between every byte */
        {
          fprintf(fp, " ");
        }
#endif
      fprintf(fp, "%c", ((p[byte] << bit) & 0x80) ? '1' : '0');
    }
}

void log_hipa_fromto(int level, char *msg, hip_assoc *hip_a, __u8 from, __u8 to)
{
  char logstr[1024];
  unsigned char addrstr[INET6_ADDRSTRLEN];
  struct sockaddr_storage hit;

  if (!hip_a)
    {
      return;
    }
  memset(logstr, 0, sizeof(logstr));
  /* from HIT/IP to HIT/IP occupies max 46*4 + 10 = 128  bytes */
  strncat(logstr, msg, 1024 - 130);
  if (from && hip_a->hi)         /* from HIT/src/LSI */
    {
      strcat(logstr, " from \n\t");
      hit_to_sockaddr(SA(&hit), hip_a->hi->hit);
      if (addr_to_str(SA(&hit), addrstr, INET6_ADDRSTRLEN))
        {
          strcat(logstr, "(none)");
        }
      else
        {
          strcat(logstr, (char *)addrstr);
        }
      strcat(logstr, " / ");
      if (addr_to_str(HIPA_SRC(hip_a), addrstr, INET6_ADDRSTRLEN))
        {
          strcat(logstr, "(none)");
        }
      else
        {
          strcat(logstr, (char *)addrstr);
        }
      strcat(logstr, " / ");
      if (addr_to_str(SA(&hip_a->hi->lsi), addrstr,
                      INET6_ADDRSTRLEN))
        {
          strcat(logstr, "(none)");
        }
      else
        {
          strcat(logstr, (char *)addrstr);
        }
    }
  if (to && hip_a->peer_hi)         /* to HIT/dst/LSI */
    {
      strcat(logstr, " to \n\t");
      hit_to_sockaddr(SA(&hit), hip_a->peer_hi->hit);
      if (addr_to_str(SA(&hit), addrstr, INET6_ADDRSTRLEN))
        {
          strcat(logstr, "(none)");
        }
      else
        {
          strcat(logstr, (char *)addrstr);
        }
      strcat(logstr, " / ");
      if (addr_to_str(HIPA_DST(hip_a), addrstr, INET6_ADDRSTRLEN))
        {
          strcat(logstr, "(none)");
        }
      else
        {
          strcat(logstr, (char *)addrstr);
        }
      strcat(logstr, " / ");
      if (addr_to_str(SA(&hip_a->peer_hi->lsi), addrstr,
                      INET6_ADDRSTRLEN))
        {
          strcat(logstr, "(none)");
        }
      else
        {
          strcat(logstr, (char *)addrstr);
        }
    }

  strcat(logstr, "\n");

  log_(level, logstr);
}

/*
 * function log_hipopts()
 *
 * Log current option settings.
 */
void log_hipopts()
{
  log_(NORM, "Setting options: daemon = %s  debug level = %d  ",
       yesno(OPT.daemon), OPT.debug);
  log_(NORM, "permissive = %s\n", yesno(OPT.permissive));
  log_(NORM, "     no_retransmit = %s  opportunistic = %s any = %s ",
       yesno(OPT.no_retransmit), yesno(OPT.opportunistic),
       yesno(OPT.allow_any));
  log_(NORM, "rvs = %s", yesno(OPT.rvs));
  log_(NORM, " mr = %s", yesno(OPT.mr));
  log_(NORM, "\n");
}

#ifdef __WIN32__
void log_WinError(int code)
{
  LPVOID lpMsgBuf;
  FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
                 FORMAT_MESSAGE_FROM_SYSTEM, NULL, code,
                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 (LPTSTR) &lpMsgBuf, 0, NULL);
  log_(NORM, "error %d: %s", code, lpMsgBuf);
  LocalFree(lpMsgBuf);
}
#endif

/*
 * Access HCNF.enable_bcast
 */
int do_bcast()
{
  return(HCNF.enable_bcast == TRUE);
}


/*
 * Platform-independent sleep function.
 */
void hip_sleep(int seconds)
{
#ifdef __WIN32__
  /* Microsoft requires at least one of the select() file sets
   * to contain a valid socket, so we use Sleep() instead. */
  Sleep(seconds * 1000);
#else
  /* usleep() and sleep() are not thread safe */
  struct timeval timeout;
  timeout.tv_sec = seconds;
  timeout.tv_usec = 0;
  select(0, NULL, NULL, NULL, &timeout);
#endif
}

/*
 * Check for existence of, otherwise create a lockfile containing the PID
 * of the running hipd (/var/run/hipd.pid). Exit if already running.
 */
void hip_writelock()
{
#ifndef __WIN32__
  FILE *lockfile;
  int pid;
  char lockname[255];

  snprintf(lockname, sizeof(lockname), "%s/run/%s",
           LOCALSTATEDIR, HIP_LOCK_FILENAME);

  if (!(lockfile = fopen(lockname, "r")))
    {
      /* Unable to open file for reading,
       * create file, write this program's PID, and continue.
       */
      if (!(lockfile = fopen(lockname, "w")))
        {
          log_(ERR, "Unable to create a lockfile (%s)\n",
               lockname);
        }
      else
        {
          pid = getpid();
          fprintf(lockfile, "%d\n", pid);
          fclose(lockfile);
        }
    }
  else
    {
      /* Writelock file opened for reading,
       * try to read PID of running process and exit.
       */
      if (fscanf(lockfile, "%d", &pid) != 1)
        {
          log_(ERR, "Warning: lock file exists but unable to "
               "read PID value.\n");
        }
      fclose(lockfile);
      log_(ERR, "hipd already running (PID %d)\n", pid);
      log_(ERR, "(may need to remove %s)\n", lockname);
      if (!OPT.permissive)
        {
          exit(1);
        }
    }
#endif /* __WIN32__ */
}

#ifndef HITGEN
extern void delete_local_hip_nameserver(__u32 ip);
/*
 * Catches the interrupt signal (CTRL+C) for quitting hipd.
 * Removes the lockfile.
 */
void hip_exit(int signal)
{
#ifndef __WIN32__
  int err;
  char lockname[255];
  struct sockaddr_storage lsi;
#endif
  static int been_here_before = 0;
  if (been_here_before)
    {
      return;
    }
  been_here_before = 1;
  if (signal == SIGSEGV)
    {
      log_(QOUT, "****** the HIP process has encountered a bug and "
           "needs to shutdown! ******\n");
    }
  else
    {
      if (HCNF.save_my_identities &&
          ((signal == SIGINT) || (signal == SIGTERM)))
        {
          save_identities_file(TRUE);               /* store my HIs with R1
                                                     * counters */
        }
      if (HCNF.save_known_identities &&
          ((signal == SIGINT) || (signal == SIGTERM)))
        {
          save_identities_file(FALSE);                  /* store peer HIs */
        }
    }
  hip_dht_update_my_entries(2);         /* DHT cleanup */
#ifndef __WIN32__
  snprintf(lockname, sizeof(lockname), "%s/run/%s",
           LOCALSTATEDIR, HIP_LOCK_FILENAME);
  unlink(lockname);                     /* remove PID file */
  killpg(getpid(), SIGINT);             /* signal INT to all children */
  waitpid(0, &err, WNOHANG);       /* cleanup zombie processes from fork() */
#endif
  flush_hip_associations();             /* delete from SDB and SPD */
  free_hip_associations();
  /*
   *  any other cleanup should be done here,
   *  such as closing sockets, files
   */
  log_(QOUT, "hipd caught signal %d%s, exiting.\n", signal,
       signal == SIGTERM ? " (SIGTERM)" :
       signal == SIGSEGV ? " (SIGSEGV)" :
       signal == SIGINT ? " (SIGINT)" : "");
  close_log();
  xmlCleanupParser();
  deinit_crypto();
#ifdef HIP_VPLS
  err = system("/usr/local/etc/hip/bridge_down.sh");
  /* Allow config library to perform any shutdown ops */
  hipcfg_close();
#endif
#ifndef __WIN32__
  /* in Linux UMH, remove /etc/resolv.conf entry */
  lsi.ss_family = AF_INET;
  get_preferred_lsi(SA(&lsi));
  delete_local_hip_nameserver( ((struct sockaddr_in *)&lsi)->sin_addr.s_addr );
#endif /* __WIN32__ */
  g_state = 2;
  printf("Shutting down threads...\n");
  /* do not pthread_exit() here because
   * this is just the signal handler
   */
}

#endif /* HITGEN */

/*
 * Prints out HIT for debugging
 */
void print_hit(const hip_hit *hit)
{
  int i;
  unsigned char *c;

  c = (unsigned char*) hit;
  printf("0x");
  for (i = 0; i < HIT_SIZE; i++)
    {
      printf("%.2x", c[i]);
    }
}

/*
 * regtype_to_string()
 *
 * Fill the provided string with text description of this registration type.
 * Return -1 if the type is unknown, 0 if it is a known registration type.
 */
int regtype_to_string(__u8 type, char *str, int str_len)
{
  int ret = 0;
  switch (type)
    {
    case REGTYPE_RESERVED:
      snprintf(str, str_len, "(reserved val=0)");
      ret = -1;
      break;
    case REGTYPE_RVS:
      snprintf(str, str_len, "Rendezvous Service");
      break;
    case REGTYPE_RELAY_UDP_HIP:
      snprintf(str, str_len, "UDP Relay Service");
      break;
    case REGTYPE_MR:
      snprintf(str, str_len, "Mobile Router Service");
      break;
    default:
      ret = -1;
    }
  return(ret);
}

/*
 * hex_print()
 * (From tcpdump)
 * Print a buffer in tcpdump -x format
 *
 * Example:
 *
 * hex_print("\n\t", raw_buff, 100, 0);
 *
 */

void hex_print(register const char *indent,
               register const u_char *cp,
               register u_int length,
               register u_int oset)
{
  register u_int i, s;
  register int nshorts;

  nshorts = (u_int) length / sizeof(u_short);
  i = 0;
  while (--nshorts >= 0)
    {
      if ((i++ % 8) == 0)
        {
          (void)printf("%s0x%04x: ", indent, oset);
          oset += 16;
        }
      s = *cp++;
      (void)printf(" %02x%02x", s, *cp++);
    }
  if (length & 1)
    {
      if ((i % 8) == 0)
        {
          (void)printf("%s0x%04x: ", indent, oset);
        }
      (void)printf(" %02x", *cp);
    }
  (void)printf("\n");
}

