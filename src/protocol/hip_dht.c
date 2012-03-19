/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2005-2012 the Boeing Company
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
 *  \file  hip_dht.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  DHT interface for publishing IP addresses using the HIT as the key.
 *          This was written to work with draft-ahrenholz-hiprg-dht-06.txt.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <win32/types.h>
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#include <sys/time.h>
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>         /* INADDR_NONE                  */
#include <netinet/ip.h>         /* INADDR_NONE                  */
#include <pthread.h>            /* pthreads support		*/
#endif
#include <openssl/evp.h>
#ifndef __CYGWIN__
#ifndef __WIN32__
#include <netinet/ip6.h>
#endif
#endif
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>              /* open()			*/
#include <libxml/tree.h>        /* XML support			*/
#ifndef __MACOSX__
#include <libxml/xmlwriter.h>
#endif
#include <openssl/sha.h>
#include <openssl/rand.h>       /* RAND_bytes() */
#include <hip/hip_version.h>    /* HIP_VERSION */
#include <hip/hip_types.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>

/* constants */
#define XMLRPC_MODE_GET         0x0001
#define XMLRPC_MODE_PUT         0x0002
#define XMLRPC_MODE_RM          0x0003
#define XMLRPC_MODE_RETRY_OFF   0x0010
#define XMLRPC_MODE_RETRY_ON    0x0020
#define XMLRPC_APP_HIT          "hip-name-hit"  /* HIT lookup service */
#define XMLRPC_APP_ADDR         "hip-addr"      /* addr lookup service */

#define DHT_KEY_SIZE            20      /* 160 bits maximum for OpenDHT */
#define DHT_VAL_SIZE            1024    /* 1kb maximum for OpenDHT */
#define DHT_DEF_TTL             604800

extern __u32 get_preferred_addr();

#ifdef __WIN32__
#define RETNULL ;
#define VOIDECL void
#else
#define RETNULL NULL;
#define VOIDECL void *
#endif

/* local functions */
int hip_dht_lookup_hit_by_name(char *name, hip_hit *hit, int retry);
int hip_dht_lookup_address(hip_hit *hit, struct sockaddr *addr, int retry);
int hip_dht_publish_addr(hi_node *hi, struct sockaddr *addr, int retry);
int hip_dht_publish_hit(hi_node *hi, char *name, int retry);
int hip_dht_select_server(struct sockaddr *addr);
VOIDECL hip_dht_resolve_hi_thread(void *void_hi);
VOIDECL publish_my_hits_thread(void *void_addr);
void hit2hit_key(hip_hit *hit, __u8 *hit_key);
int build_hdrr(__u8 *hdrr, int hdrr_size, hi_node *hi, struct sockaddr *addr);
int parse_hdrr(__u8 *hdrr, int len);
int hip_xmlrpc_getput(int mode, char *app, struct sockaddr *server,
                      char *key, int key_len, char *value, int *value_len,
                      char *secret, int secret_len, int ttl);
int hip_xmlrpc_parse_response(int mode, char *xmldata, int len,
                              char *value, int *value_len);
char *hip_xmlrpc_resp_to_str(int code);
xmlNodePtr xml_new_param(xmlNodePtr node_parent, char *type, char *value);
int build_http_post_header(char *buff, int content_len, struct sockaddr *addr);
struct dht_val *lookup_dht_val(char *key);
struct dht_val *insert_dht_val(char *key);
int hip_xmlrpc_rm(struct dht_val *v);

/* DHT client data */
struct dht_val {
  char app[255];
  __u8 key[DHT_KEY_SIZE];       /* DHT key */
  int value_hash_len;
  __u8 value_hash[SHA_DIGEST_LENGTH];       /* 20 bytes required for remove */
  int secret_len;
  __u8 secret[40];              /* secret value for remove, max 40 bytes */
  struct timeval expire_time;       /* now + ttl_sec */
  struct dht_val *next;
};

hip_mutex_t dht_vals_lock;
static struct dht_val *dht_vals = NULL;


/*******************************************************************************
 * These first two functions represent the public interface to the DHT resolver.
 *
 ******************************************************************************/

/*
 * \fn hip_dht_update_my_entries()
 *
 * \param flags		integer used to signal init and cleanup of DHT
 *                      0 = normal update, 1 = startup, 2 = shutdown
 *
 * Publish (HIT, IP) and (name, HIT) combinations to a DHT,
 * to support both type of lookups. This is called upon startup and periodically
 * after the preferred address has been selected. This maintains the timed
 * DHT records, removes old values, and publishes new records.
 */
void hip_dht_update_my_entries(int flags)
{
  struct sockaddr_storage ss_server;
  struct sockaddr *addr, *server = (struct sockaddr*)&ss_server;
  sockaddr_list *l;
  struct dht_val *v;
#ifndef __WIN32__
  pthread_attr_t attr;
  pthread_t thr;
#endif
  /* initialize DHT structures */
  if (flags == 1)
    {
      pthread_mutex_init(&dht_vals_lock, NULL);
      dht_vals = NULL;
      /* pass-through to publishing... */
      /* deinitialize */
    }
  else if (flags == 2)
    {
      /* remove all values from the DHT (during shutdown) */
      pthread_mutex_lock(&dht_vals_lock);
      v = dht_vals;
      while (dht_vals)
        {
          hip_xmlrpc_rm(v);               /* remove the value from the DHT */
          v = dht_vals->next;
          free(dht_vals);
          dht_vals = v;
        }
      pthread_mutex_unlock(&dht_vals_lock);
      return;
    }

  if (hip_dht_select_server(server) < 0)
    {
      return;           /* prevents unneccessary thread creation */

    }
  /* only publish our preferred address */
  addr = NULL;
  for (l = my_addr_head; l; l = l->next)
    {
      if (IS_LSI(&l->addr))             /* skip any LSIs */
        {
          continue;
        }
      if (!l->preferred)
        {
          continue;
        }
      addr = SA(&l->addr);
      break;
    }
  if (!addr)         /* no preferred address */
    {
      return;
    }

#ifdef __WIN32__
  _beginthread(publish_my_hits_thread, 0, (void *)addr);
#else
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&thr, &attr, publish_my_hits_thread, addr);
#endif /* __WIN32__ */
  return;
}

VOIDECL publish_my_hits_thread(void *void_addr)
{
  struct sockaddr *addr = SA(void_addr);
  hi_node *hi;

  /* send a publish request for each configured HIT */
  for (hi = my_hi_head; hi; hi = hi->next)
    {
      /* since retry is on, if there is an error returned, we will
       * give up all attempts (e.g. no server/server unreachable) */
      if (hip_dht_publish_addr(hi, addr, TRUE) < 0)
        {
          break;
        }
      if (hip_dht_publish_hit(hi, hi->name, TRUE) < 0)
        {
          break;
        }
    }
#ifndef __WIN32__
  pthread_exit((void *)0);
#endif
  return RETNULL;
}

/*
 * \fn hip_dht_resolve_hi()
 *
 * \param hi	pointer to host identity whose name, LSI, or HIT can be used
 *              for lookups, and the HIT and address may be updated
 * \param retry if TRUE, we'll spawn a new thread an retry multiple times
 *              without blocking
 *
 * \return	returns -1 if there is a problem, 0 otherwise
 *
 * \brief Given a Host Identity, perform a DHT lookup using its HIT and store
 * any resulting address in the hi_node. If the HIT is missing, perform a HIT
 * lookup in the DHT using the name and/or LSI.
 */
int hip_dht_resolve_hi(hi_node *hi, int retry)
{
  int err;
  struct sockaddr_storage ss_addr;
  struct sockaddr *addr = (struct sockaddr*) &ss_addr;
  sockaddr_list *list;
  char hit_str[INET6_ADDRSTRLEN];
#ifndef __WIN32__
  pthread_attr_t attr;
  pthread_t thr;
#endif
  if (hip_dht_select_server(addr) < 0)
    {
      return(0);           /* prevents unneccessary thread creation */

    }
  /* When retry is turned on, a separate thread will be forked that
   * will perform the DHT lookup(s), retry a certain number of times,
   * and exit */
  if (retry == TRUE)
    {
#ifdef __WIN32__
      _beginthread(hip_dht_resolve_hi_thread, 0, (void *)hi);
#else
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      pthread_create(&thr, &attr, hip_dht_resolve_hi_thread, hi);
#endif
      return(0);
      /* We have been recursively called from a thread */
    }
  else if (retry == 2)
    {
      retry = TRUE;           /* used for calls below... */
    }

  /*
   * First locate the HIT using the peer's name if this HIT is missing.
   */
  if (hits_equal(hi->hit, zero_hit))
    {
      if (hi->name_len == 0)
        {
          log_(NORM,
               "HIT and name not present, unable to perform"
               " DHT lookup.\n");
          return(-1);
        }
      log_(NORM,
           "HIT not present for peer %s, performing DHT lookup "
           "using the name '%s'.\n",
           logaddr(SA(&hi->lsi)),
           hi->name);
      if ((err = hip_dht_lookup_hit_by_name(hi->name, &hi->hit,
                                            retry)) < 0)
        {
          /* no HIT from name, so we cannot do address lookup */
          log_(WARN, "Unable to find HIT for %s in the DHT.\n",
               logaddr(SA(&hi->lsi)));
          return(err);
        }
      else
        {
          hit_to_str(hit_str, hi->hit);
          log_(NORM, "Discovered HIT for peer %s using the DHT: "
               "%s\n", hi->name, hit_str);
        }
    }

  /*
   * Look up current IP address using HIT as key
   */
  memset(addr, 0, sizeof(struct sockaddr_storage));
  addr->sa_family = AF_INET;
  if ((err = hip_dht_lookup_address(&hi->hit, addr, retry)) < 0)
    {
      return(err);
    }

  /* add address to list, checking if first item is empty */
  pthread_mutex_lock(&hi->addrs_mutex);
  if ((hi->addrs.status == DELETED) || !VALID_FAM(&hi->addrs.addr))
    {
      memcpy(&hi->addrs.addr, addr, SALEN(addr));
      hi->addrs.if_index = 0;
      hi->addrs.lifetime = 0;
      hi->addrs.status = UNVERIFIED;
      hi->addrs.nonce = 0;
      gettimeofday(&hi->addrs.creation_time, NULL);
    }
  else
    {
      list = &hi->addrs;
      add_address_to_list(&list, addr, 0);
    }
  pthread_mutex_unlock(&hi->addrs_mutex);

  return(0);
}

VOIDECL hip_dht_resolve_hi_thread(void *void_hi)
{
  hi_node *hi = (hi_node*)void_hi;
  hip_dht_resolve_hi(hi, 2);
#ifndef __WIN32__
  pthread_exit((void *) 0);
#endif
  return RETNULL;
}

/*******************************************************************************
 * Below are DHT-related helper functions
 *
 ******************************************************************************/

/*
 * \fn hip_dht_lookup_hit_by_name()
 *
 * \param name		text string name used for lookup
 * \param hit		pointer for storing HIT from response
 * \param retry		if TRUE we will retry failed connection attempts
 *
 * \return		Returns 0 on success, -1 on error.
 *
 * \brief Given a name, lookup the associated HIT using a DHT server.
 */
int hip_dht_lookup_hit_by_name(char *name, hip_hit *hit, int retry)
{
  int mode, value_len, err;
  struct sockaddr_storage ss_server;
  struct sockaddr *server = (struct sockaddr*)&ss_server;
  SHA_CTX c;
  char name_hash[SHA_DIGEST_LENGTH];
  __u8 value[DHT_VAL_SIZE];
  hiphdr *hiph;

  if (hip_dht_select_server(server) < 0)
    {
      return(-1);
    }
  if (!name)
    {
      return(-1);
    }

  /*
   * Prepare DHT key: SHA-1(name)
   */
  memset(name_hash, 0, SHA_DIGEST_LENGTH);
  SHA1_Init(&c);
  SHA1_Update(&c, name, strlen(name));
  SHA1_Final((__u8 *)name_hash, &c);

  memset(value, 0, DHT_VAL_SIZE);

  /*
   * For the Bamboo DHT (OpenDHT), this is tied
   * to an XML RPC "GET" call
   */
  value_len = DHT_VAL_SIZE;
  mode = XMLRPC_MODE_GET;
  mode |= (retry) ? XMLRPC_MODE_RETRY_ON : XMLRPC_MODE_RETRY_OFF;
  err = hip_xmlrpc_getput(mode, XMLRPC_APP_HIT, server,
                          name_hash, SHA_DIGEST_LENGTH,
                          (char *)value, &value_len,
                          NULL, 0, 0);
  if (err < 0)
    {
      return(err);
    }
  if (parse_hdrr(value, value_len) < 0)
    {
      return(-1);
    }
  hiph = (hiphdr *) &value[0];
  memcpy(hit, hiph->hit_sndr, HIT_SIZE);

  return(0);
}

/*
 * \fn hip_dht_lookup_address()
 *
 * \param hit		pointer to HIT for use with the lookup
 * \param addr		pointer to sockaddr_storage for storing the returned
 *                      LOCATOR
 * \param retry		if TRUE we will retry failed connection attempts
 *
 * \return              Returns 0 on success, -1 on error.
 *
 * \brief Given a HIT, lookup an address using a DHT server.
 */
int hip_dht_lookup_address(hip_hit *hit, struct sockaddr *addr, int retry)
{
  int mode, err, value_len;
  struct sockaddr_storage ss_server;
  struct sockaddr *server = (struct sockaddr*)&ss_server;
  __u8 dht_key[DHT_KEY_SIZE], hdrr[DHT_VAL_SIZE], *p_addr;
  int location, type, length, len, data_len, sig_verified = FALSE;
  hiphdr *hiph;
  tlv_head *tlv;
  locator *loc;
  hi_node *peer_hi = NULL;

  if (hip_dht_select_server(server) < 0)
    {
      return(-1);
    }

  /*
   * Prepare the DHT key: HIT_KEY (100 middle bits of HIT + padding)
   */
  hit2hit_key(hit, dht_key);

  /*
   * For the Bamboo DHT (OpenDHT), this is tied
   * to an XML RPC "GET" call
   */
  memset(hdrr, 0, DHT_VAL_SIZE);
  value_len = DHT_VAL_SIZE;
  mode = XMLRPC_MODE_GET;
  mode |= (retry) ? XMLRPC_MODE_RETRY_ON : XMLRPC_MODE_RETRY_OFF;
  err = hip_xmlrpc_getput(mode,
                          XMLRPC_APP_ADDR,
                          server,
                          (char *)dht_key,
                          DHT_KEY_SIZE,
                          (char *)hdrr,
                          &value_len,
                          NULL,
                          0,
                          0);
  if (err < 0)
    {
      return(err);
    }
  if (parse_hdrr(hdrr, value_len) < 0)
    {
      return(-1);
    }

  /*
   * Validate the signature and grab the LOCATOR that matches
   * the address family provided in addr.
   */
  location = 0;
  hiph = (hiphdr*) &hdrr[location];
  data_len = location + ((hiph->hdr_len + 1) * 8);
  location += sizeof(hiphdr);
  while (location < data_len)
    {
      tlv = (tlv_head*) &hdrr[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      /* first verify SIGNATURE */
      if (!sig_verified && peer_hi &&
          (type == PARAM_HIP_SIGNATURE))
        {
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          if (validate_signature(hdrr, len, tlv,
                                 peer_hi->dsa,
                                 peer_hi->rsa) < 0)
            {
              log_(WARN, "HDRR has invalid signature.\n");
              err = -1;
              break;
            }
          else
            {
              log_(NORM, "Signature in HDRR validated OK.\n");
            }
          sig_verified = TRUE;
          location = sizeof(hiphdr);
          continue;
        }
      else if (!sig_verified && (type == PARAM_HOST_ID))
        {
          if (handle_hi(&peer_hi, &hdrr[location]) < 0)
            {
              log_(WARN, "Error with HI from HDRR.\n");
              err = -1;
              break;
            }
          if (!validate_hit(hiph->hit_sndr, peer_hi))
            {
              log_(WARN, "HI in HDRR does not match the "
                   "sender's HIT\n");
              err = -1;
              break;
            }
          else
            {
              log_(NORM, "HI in HDRR validates the sender's "
                   "HIT.\n");
            }
        }
      if (type == PARAM_LOCATOR)
        {
          loc = ((tlv_locator*)tlv)->locator1;
          if ((loc->locator_type == LOCATOR_TYPE_IPV6) &&
              (loc->locator_length == 4))
            {
              p_addr = &loc->locator[0];
            }
          else if ((loc->locator_type == LOCATOR_TYPE_SPI_IPV6)
                   && (loc->locator_length == 5))
            {
              p_addr = &loc->locator[4];
            }
          else
            {
              log_(WARN, "HDRR has unknown LOCATOR type.\n");
              err = -1;
              break;
            }
          if (IN6_IS_ADDR_V4MAPPED(
                (struct in6_addr*)p_addr))
            {
              addr->sa_family = AF_INET;
              memcpy(SA2IP(addr), p_addr + 12, SAIPLEN(addr));
              if (IN_MULTICAST(*(SA2IP(addr))))
                {
                  err = -1;
                  break;
                }
              if (((struct sockaddr_in*)addr)->sin_addr.
                  s_addr
                  == INADDR_BROADCAST)
                {
                  err = -1;
                  break;
                }
            }
          else
            {
              unsigned char *p = SA2IP(addr);
              addr->sa_family = AF_INET6;
              memcpy(SA2IP(addr), p_addr, SAIPLEN(addr));
              if (IN6_IS_ADDR_MULTICAST((struct in6_addr*)p))
                {
                  err = -1;
                  break;
                }
            }
          log_(NORM, "Found peer address %s in HDRR\n",
               logaddr(addr));
          err = 0;
        }
      location += tlv_length_to_parameter_length(length);
    }     /* end while */

  if (err < 0)
    {
      memset(addr, 0, sizeof(struct sockaddr_storage));
    }
  if (peer_hi)
    {
      free_hi_node(peer_hi);
    }
  return(err);
}

/*
 * \fn hip_dht_publish_hit()
 *
 * \param hit		Host Identity having the HIT to use for the DHT value
 * \param name		name to use as the DHT key
 *
 * \return  Returns 0 on success, -1 on error.
 *
 * \brief  Store this HIT in the DHT using name.
 */
int hip_dht_publish_hit(hi_node *hi, char *name, int retry)
{
  int mode, len;
  struct sockaddr_storage ss_server;
  struct sockaddr *server = (struct sockaddr*)&ss_server;
  __u8 name_hash[SHA_DIGEST_LENGTH], secret[2 * SHA_DIGEST_LENGTH];
  hiphdr hdrr;
  SHA_CTX c;

  if (hip_dht_select_server(server) < 0)
    {
      return(-1);
    }

  /*
   * Prepare the DHT key: SHA-1(name)
   */
  memset(name_hash, 0, SHA_DIGEST_LENGTH);
  SHA1_Init(&c);
  SHA1_Update(&c, name, strlen(name));
  SHA1_Final(name_hash, &c);

  /*
   * Prepare the DHT value: HDRR([CERT])
   */
  memset(&hdrr, 0, sizeof(hdrr));
  hdrr.nxt_hdr = IPPROTO_NONE;
  hdrr.hdr_len = 4;       /* 4x8 = 32 = size of HIT fields */
  hdrr.packet_type = HIP_HDRR;
  hdrr.version = HIP_PROTO_VER;
  hdrr.res = HIP_RES_SHIM6_BITS;
  hdrr.control = 0;
  hdrr.checksum = 0;
  memcpy(hdrr.hit_sndr, hi->hit, HIT_SIZE);
  memcpy(hdrr.hit_rcvr, zero_hit, HIT_SIZE);
  len = sizeof(hiphdr);       /* 40 bytes */
  /* TODO: may add optional CERT parameter here;
   *       the name should then match the CERT
   */

  /*
   * For the Bamboo DHT (OpenDHT), this is tied
   * to an XML RPC "PUT" call
   */
  RAND_bytes(secret, 2 * SHA_DIGEST_LENGTH);
  mode = XMLRPC_MODE_PUT;
  mode |= (retry) ? XMLRPC_MODE_RETRY_ON : XMLRPC_MODE_RETRY_OFF;
  return(hip_xmlrpc_getput(mode, XMLRPC_APP_HIT, server,
                           (char *)name_hash, SHA_DIGEST_LENGTH,       /* key */
                           (char *)&hdrr, &len,                 /* value */
                           (char *)secret, 2 * SHA_DIGEST_LENGTH,
                           DHT_DEF_TTL));
}

/*
 * \fn hip_dht_publish_addr()
 *
 * \param hi	Host Identity containing HIT to use as the DHT key,
 *              and public key for the HOST_ID TLV and signature
 * \param addr	address to use for the DHT value
 * \param retry retry the put operation when TRUE
 * \return	Returns 0 on success, -1 on error.
 *
 * \brief Store this HIT and address on the DHT server.
 */
int hip_dht_publish_addr(hi_node *hi, struct sockaddr *addr, int retry)
{
  int mode;
  struct sockaddr_storage ss_server;
  struct sockaddr *server = (struct sockaddr*)&ss_server;
  __u8 dht_key[DHT_KEY_SIZE], hdrr[DHT_VAL_SIZE];
  __u8 secret[2 * SHA_DIGEST_LENGTH];
  int hdrr_len, secret_len;

  if (hip_dht_select_server(server) < 0)
    {
      return(-1);
    }

  /*
   * Prepare the DHT key: HIT_KEY (100 middle bits of HIT + padding)
   */
  hit2hit_key(&hi->hit, dht_key);
  /* log_(NORM, "Using HIT_KEY=");
   *  print_hex(dht_key, DHT_KEY_SIZE);
   *  log_(NORM, "\n"); */

  /*
   * Prepare the DHT value: HDRR(LOCATOR, SEQ, HOST_ID, [CERT], HIP_SIG)
   */
  hdrr_len = build_hdrr(hdrr, DHT_VAL_SIZE, hi, addr);
  if (hdrr_len < 0)
    {
      return(-1);
    }

  /*
   * For the Bamboo DHT (OpenDHT), this is tied
   * to an XML RPC "PUT" call
   */
  secret_len = 2 * SHA_DIGEST_LENGTH;
  RAND_bytes(secret, secret_len);
  mode = XMLRPC_MODE_PUT;
  mode |= (retry) ? XMLRPC_MODE_RETRY_ON : XMLRPC_MODE_RETRY_OFF;
  return(hip_xmlrpc_getput(mode, XMLRPC_APP_ADDR, server,
                           (char *)dht_key, DHT_KEY_SIZE,
                           (char *)hdrr, &hdrr_len,
                           (char *)secret, secret_len, DHT_DEF_TTL));
}

/*
 * \fn hip_dht_select_server()
 *
 * \param addr	pointer to store address of the server
 * \return      Returns 0 on success, -1 on error.
 *
 * \brief Select the address of the DHT server to use.
 */
int hip_dht_select_server(struct sockaddr *addr)
{
  /*
   * we leave room for more complex server selection schemes here
   *
   * for now, a single server+port is specified via the conf file
   *
   */
  if (VALID_FAM(&HCNF.dht_server))
    {
      memcpy(addr, &HCNF.dht_server, SALEN(&HCNF.dht_server));
      return(0);
    }
  return(-1);
}

/*
 * \fn hit2hit_key
 *
 * \param hit		128-bit Host Identity Tag
 * \param hit_key	buffer for storing HIT_KEY; should be DHT_VAL_SIZE long
 *
 * \brief Create a HIT_KEY from a HIT by taking the middle 100 bits and adding
 *        padding.
 */
void hit2hit_key(hip_hit *hit, __u8 *hit_key)
{
  BIGNUM *hk = BN_bin2bn((const unsigned char *)hit, HIT_SIZE, NULL);
  BN_lshift(hk, hk, 28);       /* truncate to 100-bit number */
  memset(hit_key, 0, DHT_KEY_SIZE);
  bn2bin_safe(hk, hit_key, 16);       /* lower 28-bits now zeroes */
  BN_free(hk);
}

/*
 * \fn build_hdrr()
 *
 * \param hdrr	pointer to buffer for storing a new HDRR
 * \param hdrr_size length of hdrr buffer
 * \param hi	Host Identity to use for building HOST_ID and HIP_SIG TLVs
 *              and HIT to use as Sender's HIT
 * \param addr	address to use for LOCATOR TLV
 *
 * \brief Build a HIP DHT Resource Record in the provided buffer.
 */
int build_hdrr(__u8 *hdrr, int hdrr_size, hi_node *hi, struct sockaddr *addr)
{
  int len;
  hiphdr *hiph;
  tlv_locator *loc;
  locator *loc1;
  tlv_seq *seq;

  /* header */
  memset(hdrr, 0, hdrr_size);
  if (hdrr_size < sizeof(hiph))
    {
      return(-1);
    }
  hiph = (hiphdr *) &hdrr[0];
  hiph->nxt_hdr = IPPROTO_NONE;
  hiph->hdr_len = 4;
  hiph->packet_type = HIP_HDRR;
  hiph->version = HIP_PROTO_VER;
  hiph->res = HIP_RES_SHIM6_BITS;
  hiph->control = 0;
  hiph->checksum = 0;
  memcpy(hiph->hit_sndr, hi->hit, HIT_SIZE);
  memcpy(hiph->hit_rcvr, zero_hit, HIT_SIZE);
  len = sizeof(hiphdr);

  /* LOCATOR */
  if (hdrr_size < sizeof(tlv_locator))
    {
      return(-1);
    }
  loc = (tlv_locator*) &hdrr[len];
  loc->type = htons(PARAM_LOCATOR);
  loc->length = htons(sizeof(tlv_locator) - 8);       /* minus type, len, SPI */
  loc1 = &loc->locator1[0];
  loc1->traffic_type = LOCATOR_TRAFFIC_TYPE_BOTH;
  loc1->locator_type = LOCATOR_TYPE_IPV6;
  loc1->locator_length = 4;       /* 128 bits / 4 */
  loc1->reserved = LOCATOR_PREFERRED;       /* set the P-bit */
  loc1->locator_lifetime = htonl(HCNF.loc_lifetime);
  memset(loc1->locator, 0, sizeof(loc1->locator));
  if (addr->sa_family == AF_INET6)
    {
      memcpy(&loc1->locator[0], SA2IP(addr), SAIPLEN(addr));
    }
  else           /* IPv4-in-IPv6 address format */
    {
      memset(&loc1->locator[10], 0xFF, 2);
      memcpy(&loc1->locator[12], SA2IP(addr), SAIPLEN(addr));
    }
  len += (sizeof(tlv_locator) - 4);       /* minus SPI */
  len = eight_byte_align(len);

  /* SEQ */
  if (hdrr_size < sizeof(tlv_seq))
    {
      return(-1);
    }
  seq = (tlv_seq *) &hdrr[len];
  seq->type = htons(PARAM_SEQ);
  seq->length = htons(sizeof(tlv_seq) - 4);
  seq->update_id = htonl(0);       /* TODO: implement counter that is saved
                                    *       across reboots
                                    */
  len += sizeof(tlv_seq);
  len = eight_byte_align(len);

  /* HOST_ID */
  if (hdrr_size < build_tlv_hostid_len(hi, HCNF.send_hi_name))
    {
      return(-1);
    }
  len += build_tlv_hostid(&hdrr[len], hi, HCNF.send_hi_name);

  /* CERT - currently none */

  /* HIP signature */
  hiph->hdr_len = (len / 8) - 1;
  len += build_tlv_signature(hi, hdrr, len, 2);
  hiph->hdr_len = (len / 8) - 1;
  return(len);
}

/*
 * \fn build_hdrr()
 *
 * \param hdrr	 pointer to buffer for storing a new HDRR
 * \param len	length of hdrr buffer
 */
int parse_hdrr(__u8 *hdrr, int len)
{
  hiphdr *hiph;

  if (len < sizeof(hiph))
    {
      return(-1);
    }
  if (hdrr == NULL)
    {
      return(-1);
    }
  hiph = (hiphdr *) &hdrr[0];
  /* sanity checking of header field values */
  if ((hiph->nxt_hdr != IPPROTO_NONE) ||
      (hiph->version != HIP_PROTO_VER) ||
      (hiph->packet_type != HIP_HDRR) ||
      (hiph->res != HIP_RES_SHIM6_BITS))
    {
      return(-1);
    }
  /* check for truncated packet, header length greater than received len*/
  if (((hiph->hdr_len + 1) * 8) > len)
    {
      return(-1);
    }
  /* header is OK */
  return(0);
}

/*******************************************************************************
 * Below are functions specific to different DHT implementations.
 *
 *
 ******************************************************************************/

/*
 * \fn hip_xmlrpc_getput()
 *
 * \param mode		determines get or put, app, retry on/off
 *		         If retry is off only one attempt should be made,
 *                       on means the connect() should keep retrying
 * \param app		string to use in the XML RPC application field
 * \param server	server address and port to connect to
 * \param key           DHT key used for get or put
 * \param key_len	length of DHT key in bytes
 * \param value		DHT value used for put, ptr for storing value for get
 * \param value_len	ptr to length of value buffer, length of get is returned
 * \param secret	secret value used to make put removable
 * \param secret_len	length of secret value
 * \param ttl		time to live in seconds
 *
 * \brief Perform the XML RPC GET, PUT, and RM operations.
 */
int hip_xmlrpc_getput(int mode, char *app, struct sockaddr *server,
                      char *key, int key_len, char *value, int *value_len,
                      char *secret, int secret_len, int ttl)
{
  xmlDocPtr doc = NULL;
  xmlNodePtr root_node = NULL, node;
  int len = 0, s, retval = 0;
  char buff[2048], oper[14];
  unsigned char key64[2 * DHT_KEY_SIZE], val64[2 * DHT_VAL_SIZE];
  unsigned char tmp[2 * DHT_VAL_SIZE], *xmlbuff = NULL;
  fd_set read_fdset;
  struct timeval timeout, now;
  char *p;
  unsigned int retry_attempts = 0;
  struct sockaddr_in src_addr;
  struct dht_val *dv, rm;
  SHA_CTX c;
  __u8 secret_hash[SHA_DIGEST_LENGTH], value_hash[SHA_DIGEST_LENGTH];
  int rm_ttl = 0, value_hash_len;

  int retry = ((mode & 0x00F0) == XMLRPC_MODE_RETRY_ON);

  if ((key_len > (2 * DHT_KEY_SIZE)) ||
      (*value_len > (2 * DHT_VAL_SIZE)))
    {
      return(-1);
    }

  /*
   * support for removable puts
   */
  memset(&rm, 0, sizeof(struct dht_val));
  if ((mode & 0x000F) == XMLRPC_MODE_PUT)
    {
      /*
       * produce hashes of the secret and the value, for later removal
       */
      SHA1_Init(&c);
      SHA1_Update(&c, value, *value_len);
      SHA1_Final(value_hash, &c);
      SHA1_Init(&c);
      SHA1_Update(&c, secret, secret_len);
      SHA1_Final(secret_hash, &c);

      /*
       * check if we already published a record with this key; record
       * this new secret value and value_hash
       */
      pthread_mutex_lock(&dht_vals_lock);
      gettimeofday(&now, NULL);
      dv = lookup_dht_val(key);
      if (dv)
        {
          /* save old secret so we can remove it later below */
          memcpy(&rm, &dv, sizeof(struct dht_val));
          /* any time left for removing the old record? */
          rm_ttl = TDIFF(rm.expire_time, now);
        }
      else
        {
          dv = insert_dht_val(key);
        }
      strncpy(dv->app, app, sizeof(dv->app));
      dv->value_hash_len = SHA_DIGEST_LENGTH;
      memcpy(dv->value_hash, value_hash, SHA_DIGEST_LENGTH);
      dv->secret_len = secret_len;
      memcpy(dv->secret, secret, secret_len);
      dv->expire_time.tv_usec = now.tv_usec;
      dv->expire_time.tv_sec = now.tv_sec + ttl;
      pthread_mutex_unlock(&dht_vals_lock);
    }

  switch (mode & 0x000F)
    {
    case XMLRPC_MODE_PUT:
      sprintf(oper, "put_removable");
      break;
    case XMLRPC_MODE_GET:
      sprintf(oper, "get");
      break;
    case XMLRPC_MODE_RM:
      sprintf(oper, "rm");
      break;
    default:
      log_(WARN, "Invalid XMLRPC mode given to DHT.\n");
      return(-1);
    }

  /*
   * create a new XML document
   */
  doc = xmlNewDoc(BAD_CAST "1.0");
  root_node = xmlNewNode(NULL, BAD_CAST "methodCall");
  xmlDocSetRootElement(doc, root_node);
  node = xmlNewChild(root_node, NULL, BAD_CAST "methodName",
                     BAD_CAST oper);
  node = xmlNewChild(root_node, NULL, BAD_CAST "params", NULL);
  memset(tmp, 0, sizeof(tmp));
  memcpy(tmp, key, key_len);
  EVP_EncodeBlock(key64, tmp, key_len);
  xml_new_param(node, "base64", (char *)key64);                 /* key */
  /* log_(NORM, "Doing %s using key(%d)=",
   *    ((mode & 0x000F)==XMLRPC_MODE_PUT) ? "PUT":"GET", key_len);
   *  print_hex(key, key_len);
   *  log_(NORM, " [%s]\n", key64); // */
  switch (mode & 0x000F)
    {
    case XMLRPC_MODE_PUT:
      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, value, *value_len);
      EVP_EncodeBlock(val64, tmp, *value_len);
      xml_new_param(node, "base64", (char *)val64);             /* value */
      xml_new_param(node, "string", "SHA");                     /* hash type */
      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, secret_hash, SHA_DIGEST_LENGTH);
      EVP_EncodeBlock(val64, tmp, SHA_DIGEST_LENGTH);
      xml_new_param(node, "base64", (char *)val64);            /* secret_hash */
      sprintf((char *)tmp, "%d", ttl);
      xml_new_param(node, "int", (char *)tmp);                  /* lifetime */
      break;
    case XMLRPC_MODE_GET:
      xml_new_param(node, "int", "10");                 /* maxvals */
      xml_new_param(node, "base64", "");                /* placemark */
      memset(value, 0, *value_len);
      break;
    case XMLRPC_MODE_RM:
      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, value_hash, SHA_DIGEST_LENGTH);
      EVP_EncodeBlock(val64, tmp, SHA_DIGEST_LENGTH);
      xml_new_param(node, "base64", (char *)val64);             /* value_hash */
      xml_new_param(node, "string", "SHA");                     /* hash type */
      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, secret, secret_len);
      EVP_EncodeBlock(val64, tmp, secret_len);
      xml_new_param(node, "base64", (char *)val64);             /* secret */
      sprintf((char *)tmp, "%d", ttl);
      xml_new_param(node, "int", (char *)tmp);                  /* lifetime */
    }
  xml_new_param(node, "string", app);                   /* app */
  xmlDocDumpFormatMemory(doc, &xmlbuff, &len, 0);

  /*
   * Build an HTTP POST and transmit to server
   */
  memset(buff, 0, sizeof(buff));
  build_http_post_header(buff, len, server);       /* len is XML length above */
  memcpy(&buff[strlen(buff)], xmlbuff, len);
  xmlFree(xmlbuff);
  len = strlen(buff) + 1;
connect_retry:
  /* Connect and send the XML RPC */
  if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      log_(WARN, "DHT connect - socket error: %s\n", strerror(errno));
      retval = -1;
      goto putget_exit;
    }
  /* Use the preferred address as source */
  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.sin_family = AF_INET;
  src_addr.sin_addr.s_addr = get_preferred_addr();
  if (!src_addr.sin_addr.s_addr)
    {
      log_(NORM, "No preferred address, deferring DHT!\n");
      return(-1);
    }
  log_(NORM, "Using source address of %s for DHT %s.\n",
       logaddr(SA(&src_addr)), oper);
  fflush(stdout);
  if (bind(s, SA(&src_addr), SALEN(&src_addr)) < 0)
    {
      log_(WARN, "DHT connect - bind error: %s\n", strerror(errno));
    }

  if (g_state != 0)
    {
      return(-1);
    }
  if (retry && (retry_attempts > 0))
    {
      /* quit after a certain number of retries */
      if (retry_attempts >= HCNF.max_retries)
        {
          retval = -2;
          goto putget_exit;
        }
      /* wait packet_timeout seconds before retrying */
      hip_sleep(HCNF.packet_timeout);
    }
  retry_attempts++;

  if (connect(s, server, SALEN(server)) < 0)
    {
      log_(WARN, "DHT server connect error: %s\n", strerror(errno));
      closesocket(s);
#ifdef __WIN32__
      errno = WSAGetLastError();
      if (retry && ((errno == WSAETIMEDOUT) ||
                    (errno == WSAENETUNREACH)))
        {
          goto connect_retry;
        }
#else
      if (retry &&
          ((errno == ETIMEDOUT) || (errno == EHOSTUNREACH)))
        {
          goto connect_retry;
        }
#endif
      retval = -3;
      goto putget_exit;
    }

  if (send(s, buff, len, 0) != len)
    {
      log_(WARN, "DHT sent incorrect number of bytes\n");
      retval = -4;
      goto putget_exit;
    }
  xmlFreeDoc(doc);
  doc = NULL;

  /*
   * Receive XML RPC response from server
   */
  FD_ZERO(&read_fdset);
  FD_SET((unsigned int)s, &read_fdset);
  /* use longer timeout when retry==TRUE, because we have own thread */
  if (retry)
    {
      timeout.tv_sec = 3;
      timeout.tv_usec = 0;
    }
  else
    {
      timeout.tv_sec = 0;
      timeout.tv_usec = 300000;           /* 300ms */
    }
  if (select(s + 1, &read_fdset, NULL, NULL, &timeout) < 0)
    {
      log_(WARN, "DHT select error: %s\n", strerror(errno));
      retval = -5;
      goto putget_exit;
    }
  else if (FD_ISSET(s, &read_fdset))
    {
      if ((len = recv(s, buff, sizeof(buff) - 1, 0)) <= 0)
        {
          log_(WARN, "DHT error receiving from server: %s\n",
               strerror(errno));
          retval = -6;
          goto putget_exit;
        }
      if (strncmp(buff, "HTTP", 4) != 0)
        {
          return(-7);
        }
      if ((p = strstr(buff, "Content-Length: ")) == NULL)
        {
          return(-8);
        }
      else               /* advance ptr to Content-Length */
        {
          p += 16;
        }
      sscanf(p, "%d", &len);
      p = strchr(p, '\n') + 3;           /* advance to end of line */
      retval = hip_xmlrpc_parse_response(mode, p, len,
                                         value, value_len);
      log_(NORM, "DHT server responded with return code %d (%s).\n",
           retval, hip_xmlrpc_resp_to_str(retval));
    }
  else
    {
      /* select timeout */
      if (retry)             /* XXX testme: retry select instead? */
        {
          goto connect_retry;
        }
      retval = -9;
    }

putget_exit:
#ifdef __WIN32__
  closesocket(s);
#else
  close(s);
#endif
  if (doc != NULL)
    {
      xmlFreeDoc(doc);
    }
  if (rm_ttl > 0)
    {
      value_hash_len = sizeof(rm.value_hash);
      hip_xmlrpc_getput(((mode & 0x00F0) | XMLRPC_MODE_RM),
                        app, server, key, key_len,
                        (char *)rm.value_hash, &value_hash_len,
                        (char *)rm.secret, secret_len, rm_ttl);
    }
  return(retval);
}

/*
 * \fn xml_new_param()
 *
 * \param node_parent	XML node object that will be parent of the new child
 *                      created here
 * \param type		type tag embedded in XML
 * \param value		value tag embedded in XML
 *
 * \return Returns the new XML child object.
 *
 * \brief insert a value embedded in XML in the format
 *	  <param><value><type>value</type></value></param>
 */
xmlNodePtr xml_new_param(xmlNodePtr node_parent, char *type, char *value)
{
  xmlNodePtr node_param, node_value;
  node_param = xmlNewChild(node_parent, NULL, BAD_CAST "param", NULL);
  node_value = xmlNewChild(node_param, NULL, BAD_CAST "value", NULL);
  return(xmlNewChild(node_value, NULL, BAD_CAST type, BAD_CAST value));
}

/*
 * \fn build_http_post_header()
 *
 * \param buff		buffer for storing the new header
 * \param content_len	value to use for the Content-length field
 * \param addr		value to use in the Host field
 *
 * \return Returns the length of the newly created HTTP string.
 *
 * \brief Builds an HTTP POST string in the specified buffer.
 */
int build_http_post_header(char *buff, int content_len, struct sockaddr *addr)
{
  unsigned short port = 0;
  char addrstr[INET6_ADDRSTRLEN];

  addr_to_str(addr, (__u8*)addrstr, INET6_ADDRSTRLEN);
  if (AF_INET == addr->sa_family)
    {
      port = ntohs(((struct sockaddr_in*)addr)->sin_port);
    }
  else if (AF_INET6 == addr->sa_family)
    {
      port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
    }

  sprintf(
    buff,
    "POST /RPC2 HTTP/1.0\r\nUser-Agent: %s %s\r\nHost: %s:%d\r\nContent-Type: text/xml\r\nContent-length: %d\r\n\r\n",
    HIP_NAME,
    HIP_VERSION,
    addrstr,
    port,
    content_len);
  return(strlen(buff));
}

/*
 * \fn hip_xmlrpc_parse_response()
 *
 * \param mode		is this an XML RPC GET/PUT? store response in hit/addr?
 * \param xmldata       pointer to XML character data
 * \param len		length of XML data
 * \param value		ptr for storing response value
 * \param value_len	ptr to the length of the value buffer and for
 *                      storing response value length
 *
 * \return		For GETs, the address or HIT is returned in addr or hit,
 *	                and 0 is returned for success.
 *	                For PUTs, the XML RPC return code is returned,
 *                      which is 0 for success, or 1 or 2.
 *                      -1 is returned on error.
 */
int hip_xmlrpc_parse_response(int mode, char *xmldata, int len,
                              char *value, int *value_len)
{
  xmlDocPtr doc = NULL;
  xmlNodePtr node, node_val;
  int retval = -10, i;
  xmlChar *data;
  EVP_ENCODE_CTX ctx;

  /* log_(NORM, "Got the DHT response (content-length=%d):\n%s\n",
   *    len, xmldata); // */
  if ((doc = xmlParseMemory(xmldata, len)) == NULL)
    {
      goto parse_response_exit;
    }
  node = xmlDocGetRootElement(doc);                     /* <methodResponse> */
  if (node->children)
    {
      node = node->children;                              /* <params> */
    }
  node = node->children;
  if (!node)                                            /* <param> */
    {
      goto parse_response_exit;
    }
  node_val = NULL;
  if (!strcmp((char *)node->name, "param") && node->children &&
      !strcmp((char *)node->children->name, "value"))
    {
      node_val = node->children->children;
    }
  if (!node_val)
    {
      goto parse_response_exit;
    }

  switch (mode & 0x000F)
    {
    case XMLRPC_MODE_PUT:       /* retrieve status code only */
    case XMLRPC_MODE_RM:
      data = xmlNodeGetContent(node_val);
      /* status code is first int that we encounter */
      if (strcmp((char *)node_val->name, "int") == 0)
        {
          sscanf((const char *)data, "%d", &retval);
          xmlFree(data);
          goto parse_response_exit;
        }
      break;
    case XMLRPC_MODE_GET:        /* retrieve address or HIT */
      /* <?xml version="1.0" encoding="ISO-8859-1"?>
       *   <methodResponse>
       *     <params><param><value><array><data>
       *        <value><array><data>
       *           <value><base64>AgAAAMCoAQAAAAAAA==</base64></value>
       *           <value><base64>AgAAAMCoAgcAAAAAA==</base64></value>
       *        </data></array></value>
       *        <value><base64></base64></value>
       *     </data></array></value></param></params>
       *   </methodResponse>
       */
      if (!strcmp((char *)node_val->name, "array") &&
          node_val->children &&
          !strcmp((char *)node_val->children->name, "data"))
        {
          node = node_val->children->children;
        }

      if (!strcmp((char *)node->name, "value") && node->children &&
          !strcmp((char *)node->children->name, "array"))
        {
          node = node->children->children;               /* <data> */

        }
      /* step through array of responses */
      for (node = node->children; node; node = node->next)
        {
          node_val = node->children;               /* <value><base64> */
          if ((!node_val) ||
              (strcmp((char *)node_val->name, "base64")))
            {
              continue;
            }
          data = xmlNodeGetContent(node_val);
          /* protect against unusually large values */
          if (strlen((char *)data) >
              ((unsigned)(((*value_len + 2) / 3) * 4) + 1))
            {
              xmlFree(data);
              continue;
            }
          /* log_(NORM, "XMLRPC GET: got the value:\n%s\n",
           *               data); */
          /* decode base64 into value pointer */
          /* *value_len = EVP_DecodeBlock((unsigned char *)value, */
          /*			data, strlen((char *)data)); */
          EVP_DecodeInit(&ctx);
          retval = EVP_DecodeUpdate(&ctx, (__u8 *)value, &i,
                                    (__u8 *)data,
                                    strlen((char *)data));
          if (retval < 0)
            {
              xmlFree(data);
              continue;
            }
          *value_len = i;
          EVP_DecodeFinal(&ctx, data, &i);
          retval = 0;
          xmlFree(data);
          /* the last value encountered will be returned */
        }         /* end for */
                  /* placemark and other tags are ignored */
      break;
    }

parse_response_exit:
  if (doc != NULL)
    {
      xmlFreeDoc(doc);
    }
  return(retval);
}

char *hip_xmlrpc_resp_to_str(int code)
{
  static char ret[16];
  switch (code)
    {
    case 0:
      sprintf(ret, "success");
      break;
    case 1:
      sprintf(ret, "over capacity");
      break;
    case 2:
      sprintf(ret, "try again");
      break;
    case 3:
      sprintf(ret, "failure");
      break;
    default:
      sprintf(ret, "undefined");
      break;
    }
  return(ret);
}

struct dht_val *lookup_dht_val(char *key)
{
  struct dht_val *v;

  for (v = dht_vals; v; v = v->next)
    {
      /* look for matching key */
      if (memcmp(key, v->key, sizeof(v->key)) == 0)
        {
          return(v);
        }
    }
  return(NULL);
}

struct dht_val *insert_dht_val(char *key)
{
  struct dht_val *r = (struct dht_val*) malloc(sizeof(struct dht_val));
  if (r == NULL)
    {
      log_(WARN, "insert_dht_val() malloc error\n");
      return(NULL);
    }
  memset(r, 0, sizeof(struct dht_val));
  memcpy(r->key, key, sizeof(r->key));
  r->next = dht_vals;
  dht_vals = r;
  return(r);
}

int hip_xmlrpc_rm(struct dht_val *v)
{
  struct timeval now;
  struct sockaddr_storage server;
  int mode = XMLRPC_MODE_RM | XMLRPC_MODE_RETRY_OFF;
  int err, key_len, value_len, secret_len, rm_ttl;

  if (!v)
    {
      return(-1);
    }
  if (hip_dht_select_server(SA(&server)) < 0)
    {
      return(-1);
    }

  gettimeofday(&now, NULL);
  rm_ttl = TDIFF(v->expire_time, now);
  if (rm_ttl <= 0)
    {
      return(0);
    }

  key_len = sizeof(v->key);
  value_len = v->value_hash_len;
  secret_len = v->secret_len;

  err = hip_xmlrpc_getput(mode, v->app, SA(&server),
                          (char *)v->key, key_len,
                          (char *)v->value_hash,  &value_len,
                          (char *)v->secret, secret_len, rm_ttl);
  if (err == 0)
    {
      log_(NORM, "Removed a %s value from the DHT.\n", v->app);
    }
  return(err);
}

/* Testing code -- compile with:
 * gcc -g -Wall -o hip_dht hip_dht.c hip_globals.o hip_util.o -lcrypto
 **-L/usr/lib -lxml2 -lz -liconv -lm -I/usr/include/libxml2 -DTEST_XMLRPC
 * gcc -g -Wall -o hip_dht hip_dht.c ../hip-hip_globals.o ../hip-hip_util.o
 **-lcrypto -L/usr/lib -lxml2 -lz -liconv -lm -I../include
 *-I/usr/include/libxml2
 **-DTEST_XMLRPC
 */
#ifdef TEST_XMLRPC
sockaddr_list *add_address_to_list(sockaddr_list **list, struct sockaddr *addr,
                                   int ifi)
{
  return(NULL);
}

void delete_address_from_list(sockaddr_list **list, struct sockaddr *addr,
                              int ifi)
{
  return;
}

void unuse_dh_entry(DH *dh)
{
  return;
}

int flush_hip_associations()
{
  return(0);
}

int g_state;

int main(int argc, char **argv)
{
  int err, publish;
  hip_hit hit;
  struct sockaddr_storage addr;
  struct sockaddr_in *addr4 = (struct sockaddr_in*)&addr;

  /*
   * Load hip.conf configuration file
   * user may have provided path using command line, or search defaults
   */
  memset(HCNF, 0, sizeof(HCNF));
  if ((locate_config_file(HCNF.conf_filename, sizeof(HCNF.conf_filename),
                          HIP_CONF_FILENAME) < 0) ||
      (read_conf_file(HCNF.conf_filename) < 0))
    {
      log_(ERR, "Problem with configuration file, using defaults.\n");
    }
  else
    {
      log_(NORM, "Using configuration file:\t%s\n",
           HCNF.conf_filename);
    }


  memset(&addr, 0, sizeof(addr));
  addr4->sin_family = AF_INET;
  addr4->sin_addr.s_addr = inet_addr("192.168.1.2");
  hex_to_bin("7BE901B3AF2679C8C580619535641713", hit, HIT_SIZE);

  printf("Doing XML RPC put 1...\n");
  err = hip_dht_publish(&hit, (struct sockaddr*)&addr);
  printf("return value = %d\n", err);

  addr4->sin_addr.s_addr = inet_addr("192.168.2.7");

  printf("Doing XML RPC put 2...\n");
  err = hip_dht_publish(&hit, (struct sockaddr*)&addr);
  printf("return value = %d\n", err);

  memset(&addr, 0, sizeof(addr));
  addr4->sin_family = AF_INET;

  printf("addr is at: %p\n", &addr);
  printf("Doing XML RPC get...\n");
  err = hip_dht_lookup_address(&hit, (struct sockaddr*)&addr);
  printf("return value = %d\n", err);
  printf("Address = %s\n", logaddr((struct sockaddr*)&addr));
  return(0);
}

#endif /* TEST_XMLRPC */

