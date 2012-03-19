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
 *  \file  hip_input.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson, <thomas.r.henderson@boeing.com>
 *
 *  \brief Receving functions for handling HIP control packets.
 *
 */

#include <stdio.h>              /* stderr, etc                  */
#include <stdlib.h>             /* rand()			*/
#include <errno.h>              /* strerror(), errno            */
#include <string.h>             /* memset()                     */
#include <time.h>               /* time()			*/
#include <ctype.h>              /* tolower()                    */
#include <sys/types.h>          /* getpid() support, etc        */
#ifdef __WIN32__
#include <process.h>            /* _beginthread()		*/
#include <winsock2.h>
#include <ws2tcpip.h>
#include <win32/types.h>
#include <win32/ip.h>
#else
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#include <netinet/in.h>
#else
#include <asm/types.h>
#endif /* __MACOSX__ */
#include <netinet/ip.h>         /* struct iphdr                 */
#include <sys/time.h>           /* gettimeofday()               */
#include <pthread.h>            /* for RVS lifetime thread	*/
#include <unistd.h>             /* sleep()			*/
#endif /* __WIN32__ */
#include <openssl/crypto.h>     /* OpenSSL's crypto library     */
#include <openssl/bn.h>         /* Big Numbers                  */
#include <openssl/des.h>        /* 3DES support			*/
#include <openssl/blowfish.h>   /* BLOWFISH support		*/
#include <openssl/aes.h>        /* AES support			*/
#include <openssl/dsa.h>        /* DSA support                  */
#include <openssl/asn1.h>       /* DSAparams_dup()              */
#include <openssl/dh.h>         /* Diffie-Hellman contexts      */
#include <openssl/sha.h>        /* SHA1 algorithms              */
#include <openssl/rand.h>       /* RAND_bytes()                 */
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#include <hip/hip_sadb.h>
#ifdef HIP_VPLS
#include <hip/hip_cfg_api.h>
#endif /* HIP_VPLS */

/*
 * Local function declarations
 */
int hip_parse_I1(hip_assoc *hip_a, const __u8 *data, hip_hit *hiti,
                 hip_hit *hitr);
int hip_parse_R1(const __u8 *data, hip_assoc *hip_a);
int hip_parse_I2(const __u8 *data, hip_assoc **hip_ar, hi_node *my_host_id,
                 struct sockaddr *src, struct sockaddr *dst);
int hip_parse_R2(__u8 *data, hip_assoc *hip_a);
int hip_parse_close(const __u8 *data, hip_assoc *hip_a, __u32 *nonce);
int validate_hmac(const __u8 *data, int data_len, __u8 *hmac, int hmac_len,
                  __u8 *key, int type);
hi_node *check_if_my_hit(hip_hit *hit);
int handle_transforms(hip_assoc *hip_a, __u16 *transforms, int length, int esp);
int handle_cert(hip_assoc *hip_a, const __u8 *data);
int handle_dh(hip_assoc *hip_a, const __u8 *data, __u8 *g, DH *dh);
int handle_acks(hip_assoc *hip_a, tlv_ack *ack);
int handle_esp_info(tlv_esp_info *ei, __u32 spi_out, struct rekey_info *rk);
int handle_locators(hip_assoc *hip_a, locator **locators,
                    int num, struct sockaddr *src,
                    __u32 new_spi);
void finish_address_check(hip_assoc *hip_a, __u32 nonce, struct sockaddr *src);
int handle_update_rekey(hip_assoc *hip_a);
int handle_update_readdress(hip_assoc *hip_a, struct sockaddr **addrcheck);
void update_peer_list(hip_assoc *hip_a);
void log_sa_info(hip_assoc *hip_a);
int check_tlv_type_length(int type, int length, int last_type, char *p);
int check_tlv_length(int type, int length);
int check_tlv_unknown_critical(int type, int length);
#ifdef __MACOSX__
extern int next_divert_rule();
extern void add_divert_rule(int,int,char *);
extern void del_divert_rule(int);
#endif
int handle_reg_info(hip_assoc *hip_a, const __u8 *data);
int handle_reg_request(hip_assoc *hip_a, const __u8 *data);
int handle_reg_response(hip_assoc *hip_a, const __u8 *data);
int handle_reg_failed(hip_assoc *hip_a, const __u8 *data);
int add_reg_info(struct reg_entry *regs, __u8 type, int state, __u8 lifetime);
int delete_reg_info(struct reg_entry *regs, __u8 type);
int add_from_via(hip_assoc *hip_a, __u16 type, struct sockaddr *addr,
                 __u8* address);

/*
 *
 * function hip_parse_hdr()
 *
 * in:		data = raw socket bytes
 *              len  = length of data
 *              src, dst = pointer for storing addresses for IPv4,
 *                         or supplying them for IPv6, in network byte order
 *              family = address family, AF_INET or AF_INET6
 *
 * - parse raw socket data to get a HIP packet
 * - sanity check the HIP header
 * - checksum the packet
 * - return addresses (for IPv4) and a pointer to the HIP header
 *
 */
int hip_parse_hdr(__u8 *data, int len, struct sockaddr *src,
                  struct sockaddr *dst, __u16 family, hiphdr **hdr)
{
  hiphdr* hiph;
  __u16 checksum;
  struct sockaddr_in addr;
  struct ip *iph;
  udphdr *udph = NULL;
  char typestr[12];

  /* IPv4 - get source and destination addresses */
  if (family == AF_INET)
    {
      iph = (struct ip*) &data[0];
      hiph = (hiphdr*) &data[hip_header_offset(data)];
      *hdr = hiph;
      memset(&addr, 0, sizeof(struct sockaddr_in));
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = iph->ip_src.s_addr;
      if (iph->ip_p == IPPROTO_UDP)
        {
          udph = (udphdr*)&data[sizeof(struct ip)];
          addr.sin_port = udph->src_port;
        }
      memcpy(src, &addr, sizeof(struct sockaddr_in));
      addr.sin_addr.s_addr = iph->ip_dst.s_addr;
      if (udph)
        {
          addr.sin_port = udph->dst_port;
        }
      memcpy(dst, &addr, sizeof(struct sockaddr_in));
      /* IPv6 - source and destination addresses already supplied */
    }
  else if (family == AF_INET6)
    {
      iph = NULL;
      hiph = (hiphdr*) &data[0];
      *hdr = hiph;
      /* TODO: detect HIP over UDP as with the IPv4 case */
    }
  else
    {
      return(-1);
    }

  if ((hiph->nxt_hdr != 0) &&
      (hiph->nxt_hdr != IPPROTO_NONE))
    {
      log_(WARN, "Packet warning: nxt_hdr %u, ", hiph->nxt_hdr);
      log_(NORM, "trailing data will be ignored!\n");
    }
  if ((hiph->hdr_len < 4) || ((hiph->hdr_len + 1) * 8 > len))
    {
      log_(WARN, "Packet error: hdr_len %u\n", hiph->hdr_len);
      return(-2);
    }
  if ((hiph->packet_type < HIP_I1) || (hiph->packet_type > CLOSE_ACK))
    {
      log_(WARN, "Packet error: type %u\n", hiph->packet_type);
      return(-2);
    }
  if (hiph->version != HIP_PROTO_VER)
    {
      log_(WARN, "Packet error: version %u res %u\n",
           hiph->version, hiph->res);
      return(-2);
    }
  if (hiph->res != HIP_RES_SHIM6_BITS)
    {
      log_(WARN, "Packet warning: version %u res %u, ",
           hiph->version, hiph->res);
      log_(NORM, "unknown reserved bits set in HIP header!\n");
    }

  if (hiph->control != 0)
    {
      /* Parse control bits */
      /* TODO: check (hiph->control & CTL_ANON) against global
       *       policy for allowing ANONYMOUS HIs */
      log_(WARN, "Ignoring control bits 0x%x in the HIP header.\n",
           hiph->control);
    }

  /* HIP encapsulated in UDP, skip checksum verification */
  if (iph && (iph->ip_p == IPPROTO_UDP))
    {
      /* assume RAW socket has already enforced the UDP checksum */
      if (hiph->checksum != 0)             /* checksum MUST be zero */
        {
          log_(WARN, "HIP header encapsulated in UDP contains a "
               "non-zero checksum 0x%x\n", hiph->checksum);
          return(-4);
        }
      return(0);
    }

  checksum = checksum_packet((__u8*)hiph, src, dst);
  if (checksum != 0)
    {
      hip_packet_type(hiph->packet_type, typestr);
      log_(WARN, "HIP %s packet has bad checksum: sum=0x%x, should"
           " be 0.\n", typestr, checksum);
      return(-3);
    }
  return(0);
}

/*
 *
 * function hip_parse_I1()
 *
 * in:		hip_a = pointer to any pre-existing association with RVS for
 *                      verifying the RVS_HMAC parameter
 *              data = pointer to hip header in received data
 *              hiti = pointer to Initiator's HIT to extract
 *              hitr = pointer to Responder's HIT to extract
 *
 * out:		returns 0 if successful, -1 otherwise
 *
 * parse HIP Initiator packet-- has already passed initial just
 *
 */
int hip_parse_I1(hip_assoc *hip_a, const __u8 *data, hip_hit *hiti,
                 hip_hit *hitr)
{
  int location = 0, data_len = 0, rec_num = 0;
  int last_type, type, length, len;
  tlv_head *tlv;
  tlv_from *from;
  unsigned char *rvs_hmac;

  hiphdr *hiph = (hiphdr*) data;
  memcpy(hiti, hiph->hit_sndr, sizeof(hip_hit));       /* Initiator's HIT */
  memcpy(hitr, hiph->hit_rcvr, sizeof(hip_hit));       /* Responder's HIT */
  data_len = location + ((hiph->hdr_len + 1) * 8);
  location += sizeof(hiphdr);
  last_type = 0;

  if (hits_equal(*hiti, zero_hit))
    {
      return(-1);
    }

  while (location < data_len)
    {
      tlv = (tlv_head*) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      rec_num++;
      log_(NORM, " I1 TLV type = %d length = %d \n", type, length);
      if (last_type > type)
        {
          log_(WARN, "Out of order TLV parameter, (%d > %d) ",
               last_type, type);
          log_(NORM, "malformed packet.\n");
          return(-1);
        }
      else
        {
          last_type = type;
        }

      if (type == PARAM_FROM)
        {
          from = (tlv_from*) &data[location];
          if (!hip_a)
            {
              log_(WARN, "I1 contains FROM but there " \
                   "is no association.\n");
              return(-1);
            }
          if (length > (sizeof(tlv_from) - 4))
            {
              log_(NORM, "Ignoring extra address data.\n");
            }
          add_from_via(hip_a, PARAM_FROM, NULL, from->address);
        }
      else if (type == PARAM_RVS_HMAC)
        {
          if (!hip_a)
            {
              log_(WARN, "I1 contains RVS_HMAC but there " \
                   "is no association.\n");
              return(-1);
            }
          rvs_hmac = ((tlv_hmac*)tlv)->hmac;
          /* reset the length and checksum for the HMAC */
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          log_(NORM, "RVS_HMAC verify over %d bytes. ",len);
          log_(NORM, "hdr length=%d \n", hiph->hdr_len);
          if (validate_hmac(data, len, rvs_hmac, length,
                            get_key(hip_a, HIP_INTEGRITY, TRUE),
                            hip_a->hip_transform))
            {
              log_(WARN, "Invalid RVS_HMAC.\n");
              if (hip_a->from_via)
                {
                  free(hip_a->from_via);
                  hip_a->from_via = NULL;
                }
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          else
            {
              log_(NORM, "RVS_HMAC verified OK.\n");
            }
        }
      else
        {
          if (check_tlv_unknown_critical(type, length) < 0)
            {
              return(-1);
            }
        }
      location += tlv_length_to_parameter_length(length);
    }
  return(0);
}

/*
 * Parse received I1. Look for HIT in local table.  If in table,
 * or if opportunistic, accept it if we have not reached MAX_CONNECTIONS.
 */
int hip_handle_I1(__u8 *buff, hip_assoc* hip_a, struct sockaddr *src,
                  struct sockaddr *dst)
{
  hip_hit hiti, hitr;
  struct sockaddr_storage addr;
  hi_node* my_host_id = NULL;
  hi_node* peer_host_id = NULL;
  int err = 0;
  int state = UNASSOCIATED;
  hiphdr *hiph;
  __u8 *addrp;
  hip_assoc *hip_a_rvs = NULL, *hip_a_client = NULL;

  hiph = (hiphdr*) buff;

  if (hip_a)
    {
      state = hip_a->state;
    }

  /* send R1 in any state, except E_FAILED */
  if (state < E_FAILED)
    {
      /* Find hip_assoc between RVS and Responder for RVS_HMAC
       * verification if this is a relayed I1 */
      hip_a_rvs = find_hip_association3(src, dst);
      if (hip_parse_I1(hip_a_rvs, buff, &hiti, &hitr) < 0)
        {
          log_(WARN, "Error while processing I1, dropping.\n");
          return(-1);
        }
      /*
       * Is this my HIT?  If so, get corresponding HI.
       * If not and this is an RVS, check for the hit in the reg_table
       */
      my_host_id = check_if_my_hit(&hitr);
      if (!my_host_id  && OPT.rvs)
        {
          hip_a_client = search_registrations(hitr, REGTYPE_RVS);
          if (!hip_a_client)
            {
              log_ (NORMT, "Received I1 with a receiver "
                    "HIT that does not have a current"
                    "registration with this RVS.\n");
              return(-1);
            }
          if (add_from_via(hip_a_client, PARAM_FROM, src,
                           NULL) < 0)
            {
              return(-1);
            }
          /* relay the I1 packet, and don't send any R1  */
          hip_send_I1(&hiph->hit_sndr, hip_a_client);
          return(0);
        }
      else if (!my_host_id)               /* not in RVS mode, drop I1 */
        {
          log_(NORMT, "Received I1 with unknown receiver HIT:\n");
          memset(&addr, 0, sizeof(addr));
          addr.ss_family = AF_INET6;
          memcpy(SA2IP(&addr), &hiph->hit_rcvr, HIT_SIZE);
          log_(NORM, "  Receiver HIT = %s\n", logaddr(SA(&addr)));
          return(-1);
        }

      /* Find peer HIT */
      peer_host_id = find_host_identity(peer_hi_head, hiti);
#ifdef HIP_VPLS
      if (!hipcfg_allowed_peers(hitr, hiti))
        {
          log_(NORMT,"ACL denied for HIP peer\n");
          return(-1);
        }
      if (hipcfg_verifyCert(NULL, hiti) <= 0)
        {
          log_(NORMT,"Cert verification failed for HIP peer\n");
          return(-1);
        }
      log_(NORMT,"Accepted an allowed peer Endbox HIT in I1\n");
      if (!peer_host_id)
        {
          /* Read in initiator's HIT to table */
          add_peer_hit(hiti, src);
        }
#else
      if (!peer_host_id)
        {
          /* could be opportunistic */
          if (!OPT.allow_any)
            {
              log_(NORMT, "Received I1 with unknown sender's"
                   " HIT, dropping (Try turning on allow any"
                   " option or adding peer's HIT to the %s "
                   "file.)\n", HIP_KNOWNID_FILENAME);
              return(-1);
            }
          else
            {
              /* We accept opportunistic HIT */
              log_(NORMT,"Accepted an unknown HIT in I1\n");
              /* Read in initiator's HIT to table */
              add_peer_hit(hiti, src);
            }
        }
#endif
    }
  else
    {
      log_(NORMT, "Out of order HIP_I1 packet, state %d\n", state);
      return(0);
    }
  if (state == I1_SENT)
    {
      /* peer HIT larger than my HIT */
      if (compare_hits(hiti, hitr) > 0)
        {
          log_(NORMT, "Dropping I1 in state I1_SENT because ");
          log_(NORM, "local HIT is smaller than peer HIT.\n");
          return(0);
        }
      /* local HIT is greater than peer HIT, send R1... */
    }
  /*
   * Relayed I1 from RVS, send to address in FROM parameter and fill
   * in address for VIA_RVS parameter.
   */
  if (hip_a_rvs && hip_a_rvs->from_via)
    {
      /* get address from FROM parameter */
      memset(&addr, 0, sizeof(addr));
      if (IN6_IS_ADDR_V4MAPPED((struct in6_addr*)
                               hip_a_rvs->from_via->address))
        {
          addr.ss_family = AF_INET;
          addrp = &hip_a_rvs->from_via->address[12];
        }
      else
        {
          addr.ss_family = AF_INET6;
          addrp = &hip_a_rvs->from_via->address[0];
        }
      memcpy(SA2IP(&addr), addrp, SAIPLEN(&addr));
      src = SA(&addr);
      if (HIPA_DST(hip_a_rvs)->sa_family == AF_INET)
        {
          ((struct sockaddr_in *)src)->sin_port =
            ((struct sockaddr_in *)HIPA_DST(hip_a_rvs))->
            sin_port;
        }
      log_(NORM, "Relayed I1 from RVS %s, ",
           logaddr(HIPA_DST(hip_a_rvs)));
      log_(NORM, "using %s as new destination address.\n",
           logaddr(src));
      /* store RVS address for VIA_RVS parameter */
      add_from_via(hip_a_rvs, PARAM_VIA_RVS,
                   HIPA_DST(hip_a_rvs), NULL);
    }

  /*
   * Send a pre-computed R1
   */
  if ((err = hip_send_R1(dst, src, &hiti, my_host_id, hip_a_rvs)) > 0)
    {
      log_(NORMT, "Sent R1 (%d bytes)\n", err);
    }
  else
    {
      log_(NORMT, "Failed to send R1: %s.\n", strerror(errno));
      return(-1);
    }
  return(0);
}

/*
 *
 * function hip_parse_R1()
 *
 * in:		data = raw socket bytes
 *              hip_a = contains storage for cookie, peer_hi, dh, transforms,
 *                      opaque data, etc.
 *
 * out:		returns 0 if successful, -1 otherwise
 *
 * parse HIP Responder packet
 *
 */
int hip_parse_R1(const __u8 *data, hip_assoc *hip_a)
{
  hiphdr *hiph;
  tlv_head *tlv;
  int location, data_len;
  int len, type, length;
  unsigned char *dh_secret_key;
  int last_type = 0, status = -1, sig_verified = FALSE;
  __u8 g_id = 0;
  __u16 *p;
  tlv_puzzle *tlv_pz = NULL;
  dh_cache_entry *dh_entry;
  hi_node saved_peer_hi;
  hipcookie cookie_tmp = { 0, 0, 0, 0 };
  __u64 gen;
  __u8 valid_cert = FALSE;
  tlv_via_rvs *via;
  struct sockaddr_storage rvs_addr;

  location = 0;
  hiph = (hiphdr*) &data[location];
  data_len = location + ((hiph->hdr_len + 1) * 8);
  location += sizeof(hiphdr);
  memset(&saved_peer_hi, 0, sizeof(saved_peer_hi));

  while (location < data_len)
    {
      tlv = (tlv_head*) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      if (check_tlv_type_length(type, length, last_type, "R1") < 0)
        {
          return(-1);
        }
      else
        {
          last_type = type;
        }

      /* First retrieve the HOST_ID and SIGNATURE before accepting
       * the rest of the R1 packet */
      if (!sig_verified && (type == PARAM_PUZZLE))
        {
          /* save the cookie, then zero fields for signature */
          tlv_pz = (tlv_puzzle*) tlv;
          memcpy(&cookie_tmp, &tlv_pz->cookie, sizeof(hipcookie));
          memset(&tlv_pz->cookie, 0, sizeof(hipcookie));
          tlv_pz->cookie.k = cookie_tmp.k;
          tlv_pz->cookie.lifetime = cookie_tmp.lifetime;
        }
      else if (!sig_verified && (type == PARAM_HOST_ID))
        {
          if (hip_a->peer_hi)                 /* save HI in case of error */
            {
              memcpy(&saved_peer_hi, hip_a->peer_hi,
                     sizeof(saved_peer_hi));
            }
          if (handle_hi(&hip_a->peer_hi, &data[location]) < 0)
            {
              log_(WARN, "Error with HI from R1.\n");
              /* no error yet, check HIT and R1 counter */
            }
          if (!validate_hit(hiph->hit_sndr, hip_a->peer_hi))
            {
              log_(WARN, "HI in R1 does not match the "
                   "sender's HIT\n");
              hip_send_notify(hip_a, NOTIFY_INVALID_HIT,
                              NULL, 0);
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          else
            {
              log_(NORM, "HI in R1 validates the sender's "
                   "HIT.\n");
            }
        }
      else if (!sig_verified && (type == PARAM_HIP_SIGNATURE_2))
        {
          if ((hip_a == NULL) || (hip_a->peer_hi == NULL))
            {
              log_(WARN, "Received signature parameter "
                   "without any Host Identity context for "
                   "verification.\n");
              return(-1);
            }
          len = eight_byte_align(location);
          memset(hiph->hit_rcvr, 0, sizeof(hip_hit));
          /* cookie has already been zeroed */
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          if (validate_signature(data, len, tlv,
                                 hip_a->peer_hi->dsa,
                                 hip_a->peer_hi->rsa) < 0)
            {
              log_(WARN, "Invalid signature.\n");
              hip_send_notify(hip_a,
                              NOTIFY_AUTHENTICATION_FAILED,
                              NULL, 0);
              if (!OPT.permissive)
                {
                  /* restore HI as if nothing happened */
                  goto restore_saved_peer_hi;
                }
            }
          /* rewind, now accept packet parameters */
          sig_verified = TRUE;
          status = 0;
          last_type = 0;
          location = sizeof(hiphdr);
          continue;
        }
      if (!sig_verified)             /* skip all parameters until sig verified
                                      */
        {
          location += tlv_length_to_parameter_length(length);
          continue;
        }

      if (type == PARAM_R1_COUNTER)
        {
          gen = ntoh64(((tlv_r1_counter*)tlv)->r1_gen_counter);
          if (hip_a->state == I2_SENT)
            {
              /* generation counter too small */
              if ((saved_peer_hi.r1_gen_count > 0) &&
                  (saved_peer_hi.r1_gen_count <= gen))
                {
                  log_(WARN, "R1 generation counter too "
                       "small, dropping packet.\n");
                  /* restore HI as if nothing happened */
                  goto restore_saved_peer_hi;
                }
              /* generation counter OK, discard old state */
              log_(NORM, "R1 generation counter "
                   "accepted, removing old state.\n");
              if (hip_a->peer_dh)
                {
                  DH_free(hip_a->peer_dh);
                  hip_a->peer_dh = NULL;
                }
              if (hip_a->dh_secret)
                {
                  free(hip_a->dh_secret);
                  hip_a->dh_secret = NULL;
                }
              if (saved_peer_hi.rsa &&
                  (saved_peer_hi.rsa !=
                   hip_a->peer_hi->rsa))
                {
                  RSA_free(saved_peer_hi.rsa);
                }
              if (saved_peer_hi.dsa &&
                  (saved_peer_hi.dsa !=
                   hip_a->peer_hi->dsa))
                {
                  DSA_free(saved_peer_hi.dsa);
                }
              memset(hip_a->keymat, 0, KEYMAT_SIZE);
              hip_a->keymat_index = 0;
            }
          else                   /* state I1_SENT or CLOSED */
            {
              hip_a->peer_hi->r1_gen_count = gen;
            }
        }
      else if (type == PARAM_PUZZLE)
        {
          memcpy(&hip_a->cookie_r, &cookie_tmp,sizeof(hipcookie));
          log_(NORM, "Got the R1 cookie: ");
          print_cookie(&hip_a->cookie_r);
        }
      else if (type == PARAM_DIFFIE_HELLMAN)
        {
          if (handle_dh(hip_a, &data[location], &g_id,
                        NULL) < 0)
            {
              hip_send_notify(hip_a,
                              NOTIFY_NO_DH_PROPOSAL_CHOSEN,
                              NULL, 0);
              return(-1);
            }

          /* group ID chosen by responder
           * get a DH entry from cache or generate a new one */
          dh_entry = get_dh_entry(g_id, FALSE);
          dh_entry->ref_count++;
          hip_a->dh_group_id = g_id;
          hip_a->dh = dh_entry->dh;

          /* compute key from our dh and peer's pub_key and
           * store in dh_secret_key */
          dh_secret_key = malloc(DH_size(hip_a->dh));
          if (!dh_secret_key)
            {
              log_(WARN, "hip_parse_R1() malloc() error");
              return(-1);
            }
          memset(dh_secret_key, 0, DH_size(hip_a->dh));
          len = DH_compute_key(dh_secret_key,
                               hip_a->peer_dh->pub_key,
                               hip_a->dh);
          logdh(hip_a->dh);
          if (len != DH_size(hip_a->dh))
            {
              log_(NORM, "Warning: secret key len = %d,",len);
              log_(NORM, " expected %d\n",DH_size(hip_a->dh));
            }
          set_secret_key(dh_secret_key, hip_a);
          /* Do not free(dh_secret_key), which is now
           * dh->dh_secret  */
        }
      else if (type == PARAM_HIP_TRANSFORM)
        {
          p = &((tlv_hip_transform*)tlv)->transform_id;
          if ((handle_transforms(hip_a, p, length, FALSE)) < 0)
            {
              hip_send_notify(hip_a,
                              NOTIFY_NO_HIP_PROPOSAL_CHOSEN,
                              NULL, 0);
              return(-1);
            }
        }
      else if (type == PARAM_ESP_TRANSFORM)
        {
          /* first check E bit */
          if (((tlv_esp_transform*)tlv)->reserved && 0x01)
            {
              log_(NORM, "64-bit ESP sequence numbers reques");
              log_(NORM, "ted but unsupported by kernel!\n");
              if (OPT.permissive)
                {
                  return(-1);
                }
            }
          p = &((tlv_esp_transform*)tlv)->suite_id;
          if ((handle_transforms(hip_a, p, length - 2,
                                 TRUE)) < 0)
            {
              hip_send_notify(hip_a,
                              NOTIFY_NO_ESP_PROPOSAL_CHOSEN,
                              NULL, 0);
              return(-1);
            }
        }
      else if ((type == PARAM_ECHO_REQUEST) ||
               (type == PARAM_ECHO_REQUEST_NOSIG))
        {
          /* prevent excessive memory consumption */
          if (length > MAX_OPAQUE_SIZE)
            {
              log_(WARN,"ECHO_REQUEST in R1 is too large.\n");
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          else
            {
              hip_a->opaque = (struct opaque_entry*)
                              malloc(sizeof(struct
                                            opaque_entry));
              if (hip_a->opaque == NULL)
                {
                  log_(NORM,"Malloc err: ECHO_REQUEST\n");
                  return(-1);
                }
              hip_a->opaque->opaque_len = (__u16)length;
              memcpy(hip_a->opaque->opaque_data,
                     ((tlv_echo*)tlv)->opaque_data, length);
              hip_a->opaque->opaque_nosig =
                (type == PARAM_ECHO_REQUEST_NOSIG);
            }
        }
      else if (type == PARAM_REG_INFO)                  /* R1 packet */
        {
          log_(NORM,
               "Peer is a registrar providing registration "
               "info in its R1 packet.\n");
          if (handle_reg_info(hip_a, &data[location]) < 0)
            {
              log_(WARN, "Problem with registration info.\n");
            }
        }
      else if (type == PARAM_VIA_RVS)
        {
          via = (tlv_via_rvs *) &data[location];
          if (IN6_IS_ADDR_V4MAPPED(
                (struct in6_addr*)via->address))
            {
              rvs_addr.ss_family = AF_INET;
              memcpy(SA2IP(&rvs_addr), &via->address[12],
                     SAIPLEN(&rvs_addr));
            }
          else
            {
              rvs_addr.ss_family = AF_INET;
              memcpy(SA2IP(&rvs_addr), via->address,
                     SAIPLEN(&rvs_addr));
            }
          log_(NORM,
               "R1 packet relayed by the Rendezvous Server "
               "address %s.\n",
               logaddr(SA(&rvs_addr)));
          /* we could check if the VIA RVS address is the same one
           * that we used for the relay */
        }
      else if ((type == PARAM_HOST_ID) ||
               (type == PARAM_HIP_SIGNATURE_2))
        {
          /* these parameters already processed */
        }
      else if (type == PARAM_CERT)
        {
          if (HCNF.peer_certificate_required &&
              (handle_cert(hip_a, &data[location]) < 0))
            {
              hip_send_notify(hip_a,
                              NOTIFY_AUTHENTICATION_FAILED,
                              NULL, 0);
              return(-1);
            }
          valid_cert = TRUE;
          /* validate certificate */
        }
      else if (type == PARAM_LOCATOR)
        {
          ;
        }
      else
        {
          if (check_tlv_unknown_critical(type, length) < 0)
            {
              return(-1);
            }
        }
      location += tlv_length_to_parameter_length(length);
    }
  if (HCNF.peer_certificate_required && !valid_cert)
    {
      hip_send_notify(hip_a, NOTIFY_AUTHENTICATION_FAILED, NULL, 0);
      return(-1);
    }

  return(status);
restore_saved_peer_hi:
  if (hip_a->peer_hi->dsa &&
      (hip_a->peer_hi->dsa != saved_peer_hi.dsa))
    {
      DSA_free(hip_a->peer_hi->dsa);
    }
  if (hip_a->peer_hi->rsa &&
      (hip_a->peer_hi->rsa != saved_peer_hi.rsa))
    {
      RSA_free(hip_a->peer_hi->rsa);
    }
  memcpy(hip_a->peer_hi, &saved_peer_hi, sizeof(saved_peer_hi));
  return(-1);
}

int hip_handle_R1(__u8 *buff, hip_assoc *hip_a, struct sockaddr *src)
{
  int err = 0;

  /* R1 only accepted in these states */
  if ((hip_a->state != I1_SENT) && (hip_a->state != I2_SENT) &&
      (hip_a->state != CLOSING) && (hip_a->state != CLOSED))
    {
      log_(NORMT,"HIP_R1 packet not accepted in state=%d.\n",
           hip_a->state);
      return(-1);
    }
  /* Assert hip_a->peer_hi was created in HIP_ACQUIRE */
  if (!hip_a->peer_hi)
    {
      log_(NORMT, "HIP_ACQUIRE failed to make peer_hi.\n");
      return(-1);
    }
  /* may want to set hip_a->available_transforms bitmask here,
   * to control which suites are used with which host */
  /* Parse R1 */
  if (hip_parse_R1(buff, hip_a) < 0)
    {
      log_(NORMT, "Error while processing R1, dropping.\n");
      if (hip_a->state == I1_SENT)
        {
          clear_retransmissions(hip_a);
          set_state(hip_a, E_FAILED);
        }
      return(-1);
    }
  /* Set ip, hit, size, hi_t of peer_hi */
  if (hip_a->dh == NULL)
    {
      log_(WARN, "Error: after parsing R1, DH is null.\n");
    }
  /* Need to send an SPI to peer */
  hip_a->spi_in = get_next_spi();
  /* Fill in the destination address for when an RVS was used, */
  if (VALID_FAM(&hip_a->peer_hi->lsi))
    {
      memcpy(HIPA_DST(hip_a), src, SALEN(src));
    }
  /* Update peer_hi_head and fill in LSI*/
  update_peer_list(hip_a);
  /* hip_send_I2 takes cookie from R1 */
  if ((err = hip_send_I2(hip_a)) > 0)
    {
      log_(NORMT, "Sent I2 (%d bytes)\n", err);
      set_state(hip_a, I2_SENT);
    }
  else if (err == -ERANGE)
    {
      log_(NORMT, "Couldn't solve R1 cookie, ");
      if (OPT.no_retransmit)
        {
          log_(NORM,"retransmission off, aborting exchange.\n");
        }
      else if (hip_a->rexmt_cache.retransmits < HCNF.max_retries)
        {
          log_(NORM, "retransmitting I1.\n");
        }
      else
        {
          log_(NORM, "maximum retransmissions reached.\n");
        }
      return(0);
    }
  else
    {
      log_(NORMT, "Failed to send I2: %s.\n", strerror(errno));
      return(-1);
    }
  return(0);
}

/*
 *
 * function hip_parse_I2()
 *
 * in:		data = raw socket bytes
 *              hip_a is pointer to HIP connection instance
 *              cookie = pointer to store extracted cookie
 *
 * out:		Returns -1 if failure, packet length otherwise.
 *
 * parse HIP Second Initiator packet
 *
 */
int hip_parse_I2(const __u8 *data, hip_assoc **hip_ar, hi_node *my_host_id,
                 struct sockaddr *src, struct sockaddr *dst)
{
  hiphdr *hiph;
  int location, data_len;
  int i, j, len, key_len, iv_len, last_type = 0, err = 0;
  int type, length;
  hip_assoc *hip_a = NULL, *hip_a_existing;
  __u16 proposed_keymat_index = 0;
  __u32 proposed_spi_out = 0;
  tlv_head *tlv;
  tlv_esp_info *esp_info;
  unsigned char *hmac;
  hipcookie cookie;
  __u64 solution = 0, r1count = 0;
  __u16 *p;
  __u8 g_id = 0;
  unsigned char *dh_secret_key;
  dh_cache_entry *dh_entry = NULL;
  unsigned char *key, *enc_data = NULL, *unenc_data = NULL;
  des_key_schedule ks1, ks2, ks3;
  BF_KEY bfkey;
  AES_KEY aes_key;
  u_int8_t secret_key1[8], secret_key2[8], secret_key3[8];
  unsigned char cbc_iv[16];
  int got_dh = 0, comp_keys = 0, status;
  __u8 valid_cert = FALSE;

  hip_a_existing = *hip_ar;

  /* Find hip header */
  location = 0;
  hiph = (hiphdr*) &data[location];
  data_len = location + ((hiph->hdr_len + 1) * 8);
  location += sizeof(hiphdr);

  status = -1;
  /* Parse TLVs */
  while (location < data_len)
    {
      tlv = (tlv_head*) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      /* check if hip_a has been initalized*/
      if ((type > PARAM_SOLUTION) && !hip_a)
        {
          log_(NORM,
               "I2 packet does not contain puzzle solution.\n");
          return(-1);
        }
      if (check_tlv_type_length(type, length, last_type, "I2") < 0)
        {
          return(-1);
        }
      else
        {
          last_type = type;
        }

      if (type == PARAM_ESP_INFO)
        {
          esp_info = (tlv_esp_info*)tlv;
          proposed_keymat_index = ntohs(esp_info->keymat_index);
          proposed_spi_out = ntohl(esp_info->new_spi);
        }
      else if (type == PARAM_R1_COUNTER)
        {
          r1count = ntoh64(((tlv_r1_counter*)tlv)->r1_gen_counter);
          if ((my_host_id->r1_gen_count - r1count) >
              ACCEPTABLE_R1_COUNT_RANGE)
            {
              log_(NORM, "Got R1 count of %llu, my R1 count",
                   r1count);
              log_(NORM, "er is %llu, outside range (%d), ",
                   my_host_id->r1_gen_count,
                   ACCEPTABLE_R1_COUNT_RANGE);
              if (!OPT.permissive)
                {
                  log_(NORM, "dropping.\n");
                  return(-1);
                }
            }
          log_(NORM,"R1 counter %llu (%llu) acceptable.\n",
               r1count, my_host_id->r1_gen_count);
        }
      else if (type == PARAM_SOLUTION)
        {
          memcpy(&cookie, &((tlv_solution*)tlv)->cookie,
                 sizeof(hipcookie));
          /* integers remain in network byte order */
          solution = ((tlv_solution*)tlv)->j;
          log_(NORM, "Got the I2 cookie: ");
          print_cookie(&cookie);
          log_(NORM, "solution: 0x%llx\n",solution);
          i = compute_R1_cache_index(&hiph->hit_sndr, TRUE);
          j = compute_R1_cache_index(&hiph->hit_sndr, FALSE);
          /* locate cookie using current random number */
          if ((validate_solution(
                 my_host_id->r1_cache[i].current_puzzle,
                 &cookie,
                 &hiph->hit_sndr, &hiph->hit_rcvr,
                 solution) == 0) ||
              (validate_solution(
                 my_host_id->r1_cache[i].previous_puzzle,
                 &cookie,
                 &hiph->hit_sndr, &hiph->hit_rcvr,
                 solution) == 0))
            {
              dh_entry = my_host_id->r1_cache[i].dh_entry;
              /* locate cookie using previous random number */
            }
          else if ((validate_solution(
                      my_host_id->r1_cache[j].
                      current_puzzle,
                      &cookie,
                      &hiph->hit_sndr, &hiph->hit_rcvr,
                      solution) == 0) ||
                   (validate_solution(
                      my_host_id->r1_cache[j].
                      previous_puzzle,
                      &cookie,
                      &hiph->hit_sndr, &hiph->hit_rcvr,
                      solution) == 0))
            {
              dh_entry = my_host_id->r1_cache[j].dh_entry;
            }
          else
            {
              log_(WARN,"Invalid solution received in I2.\n");
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          /* create HIP association state here */
          hip_a = init_hip_assoc(my_host_id,
                                 (const hip_hit *)&hiph->hit_sndr);
          if (!hip_a)
            {
              log_(WARN,
                   "Unable to create a HIP association "
                   "while receiving I2.\n");
              return(-1);
            }
          hip_a->dh_group_id = dh_entry->group_id;
          hip_a->dh = dh_entry->dh;
          dh_entry->ref_count++;
          dh_entry->is_current = FALSE;               /* mark the entry so it
                                                       *  will not be used again
                                                       * */
          hip_a->spi_out = proposed_spi_out;
          memcpy(&hip_a->cookie_r, &cookie, sizeof(hipcookie));
          hip_a->cookie_j = solution;
          /* fill in the addresses */
          memcpy(HIPA_SRC(hip_a), dst, SALEN(dst));
          hip_a->hi->addrs.if_index = is_my_address(dst);
          make_address_active(&hip_a->hi->addrs);
          memcpy(HIPA_DST(hip_a), src, SALEN(src));
          if ((src->sa_family == AF_INET) &&
              (((struct sockaddr_in*)src)->sin_port > 0))
            {
              hip_a->udp = TRUE;
            }
        }
      else if (type == PARAM_DIFFIE_HELLMAN)
        {
          if (handle_dh(hip_a, &data[location], &g_id,
                        NULL) < 0)
            {
              hip_send_notify(hip_a, NOTIFY_INVALID_DH_CHOSEN,
                              NULL, 0);
              return(-1);
            }
          /* We chose g_id in R1, so I2 should match */
          if (g_id != hip_a->dh_group_id)
            {
              log_(NORM, "Got DH group %d, expected %d.",
                   g_id, hip_a->dh_group_id);
              hip_send_notify(hip_a, NOTIFY_INVALID_DH_CHOSEN,
                              NULL, 0);
              return(-1);
            }
          /* compute key from our dh and peer's pub_key and
           * store in dh_secret_key */
          dh_secret_key = malloc(DH_size(hip_a->dh));
          if (!dh_secret_key)
            {
              log_(WARN, "hip_parse_I2() malloc() error");
              return(-1);
            }
          memset(dh_secret_key, 0, DH_size(hip_a->dh));
          len = DH_compute_key(dh_secret_key,
                               hip_a->peer_dh->pub_key,
                               hip_a->dh);
          if (len != DH_size(hip_a->dh))
            {
              log_(NORM,"Warning: secret key len = %d,", len);
              log_(NORM,"expected %d\n", DH_size(hip_a->dh));
            }
          set_secret_key(dh_secret_key, hip_a);
          got_dh = 1;
          /* Do not free(dh_secret_key), which is now
           * dh->dh_secret  */
        }
      else if (type == PARAM_HIP_TRANSFORM)
        {
          p = &((tlv_hip_transform*)tlv)->transform_id;
          if ((handle_transforms(hip_a, p, length, FALSE)) < 0)
            {
              hip_send_notify(
                hip_a,
                NOTIFY_INVALID_HIP_TRANSFORM_CHOSEN,
                NULL,
                0);
              return(-1);
            }
          /* Must compute keys here so we can use them below. */
          if (got_dh)
            {
              compute_keys(hip_a);
              if (proposed_keymat_index >
                  hip_a->keymat_index)
                {
                  hip_a->keymat_index =
                    proposed_keymat_index;
                }
              comp_keys = 1;
            }
          else
            {
              log_(NORM, "Couldn't do compute_keys() ");
              log_(NORM, "because DH is not set yet.\n");
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
        }
      else if (type == PARAM_ESP_TRANSFORM)
        {
          /* check E bit */
          if (((tlv_esp_transform*)tlv)->reserved && 0x01)
            {
              log_(NORM, "64-bit ESP sequence numbers reque");
              log_(NORM, "sted but unsupported by kernel!\n");
              if (OPT.permissive)
                {
                  return(-1);
                }
            }
          p = &((tlv_esp_transform*)tlv)->suite_id;
          if ((handle_transforms(hip_a, p, length - 2,
                                 TRUE)) < 0)
            {
              hip_send_notify(
                hip_a,
                NOTIFY_INVALID_ESP_TRANSFORM_CHOSEN,
                NULL,
                0);
              return(-1);
            }
        }
      else if (type == PARAM_ENCRYPTED)
        {
          err = 0;
          /* NULL encryption */
          if (ENCR_NULL(hip_a->hip_transform))
            {
              len = length - 8;                   /* tlv - type,length,reserv */
              len = eight_byte_align(len);
              enc_data = NULL;
              unenc_data = malloc(len);
              memset(unenc_data, 0, len);
              memcpy(unenc_data, ((tlv_encrypted*)tlv)->iv,
                     len);
              /* Cipher decryption */
            }
          else
            {
              if (!comp_keys)
                {
                  log_(NORM, "Got ENCRYPTED TLV, but ");
                  log_(NORM, "keys not computed yet.\n");
                  err = NOTIFY_ENCRYPTION_FAILED;
                  goto I2_ERROR;
                }
              /* prepare the data */
              /* tlv length - reserved,iv */
              iv_len = enc_iv_len(hip_a->hip_transform);
              len = length - (4 + iv_len);
              len = eight_byte_align(len);
              enc_data = malloc(len);
              unenc_data = malloc(len);
              memset(enc_data, 0, len);
              memset(unenc_data, 0, len);
              /* AES uses a 128-bit IV, 3-DES and Blowfish
               * use 64-bits. */
              memcpy(enc_data,
                     ((tlv_encrypted*)tlv)->iv + iv_len, len);
              memcpy(cbc_iv, ((tlv_encrypted*)tlv)->iv,
                     iv_len);
              key = get_key(hip_a, HIP_ENCRYPTION, TRUE);
              key_len = enc_key_len(hip_a->hip_transform);

              /* prepare keys and decrypt based on cipher */
              switch (hip_a->hip_transform)
                {
                case ESP_AES_CBC_HMAC_SHA1:
                  log_(NORM, "AES decryption key: 0x");
                  print_hex(key, key_len);
                  log_(NORM, "\n");
                  if (AES_set_decrypt_key(key, 8 *
                                          key_len,
                                          &aes_key))
                    {
                      log_(WARN, "Unable to use cal");
                      log_(NORM, "ulated DH secret ");
                      log_(NORM, "for AES key.\n");
                      err = NOTIFY_ENCRYPTION_FAILED;
                      goto I2_ERROR;
                    }
                  log_(NORM, "Decrypting %d bytes ", len);
                  log_(NORM, "using AES.\n");
                  AES_cbc_encrypt(enc_data,
                                  unenc_data,
                                  len,
                                  &aes_key,
                                  cbc_iv,
                                  AES_DECRYPT);
                  break;
                case ESP_3DES_CBC_HMAC_SHA1:
                case ESP_3DES_CBC_HMAC_MD5:
                  memcpy(&secret_key1, key, key_len / 3);
                  memcpy(&secret_key2,
                         key + 8,
                         key_len / 3);
                  memcpy(&secret_key3,
                         key + 16,
                         key_len / 3);
                  des_set_odd_parity((des_cblock*)
                                     (&secret_key1));
                  des_set_odd_parity((des_cblock*)
                                     (&secret_key2));
                  des_set_odd_parity((des_cblock*)
                                     (&secret_key3));
                  log_(NORM, "decryption key: 0x");
                  print_hex(secret_key1, key_len);
                  log_(NORM, "-");
                  print_hex(secret_key2, key_len);
                  log_(NORM, "-");
                  print_hex(secret_key3, key_len);
                  log_(NORM, "\n");

                  if (des_set_key_checked((des_cblock*)
                                          &secret_key1,
                                          ks1) ||
                      des_set_key_checked((des_cblock*)
                                          &secret_key2,
                                          ks2) ||
                      des_set_key_checked((des_cblock*)
                                          &secret_key3,
                                          ks3))
                    {
                      log_(NORM, "Unable to use cal");
                      log_(NORM, "culated DH secret");
                      log_(NORM, " for 3DES key.\n");
                      err = NOTIFY_ENCRYPTION_FAILED;
                      goto I2_ERROR;
                    }
                  log_(NORM, "Decrypting %d bytes ", len);
                  log_(NORM, "using 3-DES.\n");
                  des_ede3_cbc_encrypt(
                    enc_data,
                    unenc_data,
                    len,
                    ks1,
                    ks2,
                    ks3,
                    (des_cblock*)
                    cbc_iv,
                    DES_DECRYPT);
                  break;
                case ESP_BLOWFISH_CBC_HMAC_SHA1:
                  log_(NORM, "BLOWFISH decryption key: ");
                  log_(NORM, "0x");
                  print_hex(key, key_len);
                  log_(NORM, "\n");
                  BF_set_key(&bfkey, key_len, key);
                  log_(NORM, "Decrypting %d bytes ", len);
                  log_(NORM, "using BLOWFISH.\n");
                  BF_cbc_encrypt(enc_data,
                                 unenc_data,
                                 len,
                                 &bfkey,
                                 cbc_iv,
                                 BF_DECRYPT);
                  break;
                default:
                  log_(WARN, "Unsupported transform ");
                  log_(NORM, "for decryption\n");
                  err = NOTIFY_ENCRYPTION_FAILED;
                  goto I2_ERROR;
                  break;
                }                 /* end switch(hip_a->hip_transform) */
            }             /* end if */
                          /* parse HIi */
          tlv = (tlv_head*) unenc_data;
          if (ntohs(tlv->type) == PARAM_HOST_ID)
            {
              if (handle_hi(&hip_a->peer_hi,
                            unenc_data) < 0)
                {
                  log_(WARN, "Error with I2 HI.\n");
                  err = NOTIFY_ENCRYPTION_FAILED;
                  goto I2_ERROR;
                }
              if (!validate_hit(hiph->hit_sndr,
                                hip_a->peer_hi))
                {
                  log_(WARN, "HI in I2 does not match ");
                  log_(NORM, "the sender's HIT\n");
                  err = NOTIFY_INVALID_HIT;
                  goto I2_ERROR;
                }
              else
                {
                  log_(NORM, "HI in I2 validates the ");
                  log_(NORM, "sender's HIT.\n");
                }
            }
          else
            {
              log_(WARN, "Invalid HI decrypted type: %x.\n",
                   ntohs(tlv->type));
              err = NOTIFY_ENCRYPTION_FAILED;
              goto I2_ERROR;
            }
I2_ERROR:
          if (enc_data)                 /* NULL encryption doesn't use this */
            {
              free(enc_data);
            }
          free(unenc_data);
          if ((err) && (!OPT.permissive))
            {
              hip_send_notify(hip_a, err, NULL, 0);
              return(-1);
            }
        }
      else if (type == PARAM_HOST_ID)
        {
          if (handle_hi(&hip_a->peer_hi, &data[location]) < 0)
            {
              log_(WARN, "Error with I2 HI.\n");
              hip_send_notify(hip_a, NOTIFY_INVALID_SYNTAX,
                              NULL, 0);
              return(-1);
            }
          if (!validate_hit(hiph->hit_sndr,
                            hip_a->peer_hi))
            {
              log_(WARN, "HI in I2 does not match ");
              log_(NORM, "the sender's HIT\n");
              hip_send_notify(hip_a, NOTIFY_INVALID_HIT,
                              NULL, 0);
              return(-1);
            }
          else
            {
              log_(NORM, "HI in I2 validates the ");
              log_(NORM, "sender's HIT.\n");
            }
        }
      else if (type == PARAM_CERT)
        {
          if (HCNF.peer_certificate_required &&
              (handle_cert(hip_a, &data[location]) < 0))
            {
              hip_send_notify(hip_a,
                              NOTIFY_AUTHENTICATION_FAILED,
                              NULL, 0);
              return(-1);
            }
          valid_cert = TRUE;
        }
      else if ((type == PARAM_ECHO_RESPONSE) ||
               (type == PARAM_ECHO_RESPONSE_NOSIG))
        {
          log_(NORM, "Warning: received unrequested ECHO_RESPON");
          log_(NORM, "SE from I2 packet.\n");
        }
      else if (type == PARAM_HMAC)
        {
          hmac = ((tlv_hmac*)tlv)->hmac;
          /* reset the length and checksum for the HMAC */
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          log_(NORM, "HMAC verify over %d bytes. ",len);
          log_(NORM, "hdr length=%d \n", hiph->hdr_len);
          if (validate_hmac(data, len,
                            hmac, length,
                            get_key(hip_a, HIP_INTEGRITY, TRUE),
                            hip_a->hip_transform))
            {
              log_(WARN, "Invalid HMAC.\n");
              hip_send_notify(hip_a,
                              NOTIFY_HMAC_FAILED,
                              NULL, 0);
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          else
            {
              log_(NORM, "HMAC verified OK.\n");
            }
        }
      else if (type == PARAM_HIP_SIGNATURE)
        {
          if ((hip_a == NULL) || (hip_a->peer_hi == NULL))
            {
              log_(WARN, "Received signature parameter "
                   "without any Host Identity context for "
                   "verification.\n");
              return(-1);
            }
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          if (validate_signature(data, len, tlv,
                                 hip_a->peer_hi->dsa,
                                 hip_a->peer_hi->rsa) < 0)
            {
              log_(WARN, "Invalid signature.\n");
              hip_send_notify(hip_a,
                              NOTIFY_AUTHENTICATION_FAILED,
                              NULL, 0);
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          /* adopt the new hip_assoc now */
          if (hip_a_existing)
            {
              log_(NORM, "Replacing old association.\n");
              replace_hip_assoc(hip_a_existing, hip_a);
              *hip_ar = hip_a_existing;
            }
          else
            {
              *hip_ar = hip_a;
            }
          /* exit w/OK */
          status = 0;
        }
      else if (type == PARAM_REG_REQUEST)               /* I2 packet */
        {
          log_(NORM, "Peer has requested registration(s) in its"
               " I2 packet.\n");
          if (handle_reg_request(hip_a, &data[location]) < 0)
            {
              log_(WARN, "Problem with registration "
                   "request.\n");
            }
        }
      else if (type == PARAM_ESP_INFO_NOSIG)
        {
          esp_info = (tlv_esp_info*)tlv;
          hip_a->spi_nat = ntohl(esp_info->new_spi);
          log_(NORMT, "Adding SPI NAT 0x%x\n", hip_a->spi_nat);
        }
      else
        {
          if (check_tlv_unknown_critical(type, length) < 0)
            {
              /* cookie has been solved, send NOTIFY */
              if (hip_a)
                {
                  __u16 t;
                  t = (__u16)type;
                  hip_send_notify(
                    hip_a,
                    NOTIFY_UNSUPPORTED_CRITICAL_PARAMETER_TYPE,
                    (__u8*)&t,
                    sizeof(__u16));
                }
              return(-1);
            }
        }
      location += tlv_length_to_parameter_length(length);
    }
  if (HCNF.peer_certificate_required && !valid_cert)
    {
      hip_send_notify(hip_a, NOTIFY_AUTHENTICATION_FAILED, NULL, 0);
      return(-1);
    }

  return(status);
}

int hip_handle_I2(__u8 *buff, hip_assoc *hip_a_existing,
                  struct sockaddr *src, struct sockaddr *dst)
{
  int err = 0;
  hi_node *my_host_id = NULL;
  hip_assoc *hip_a = NULL;
  __u32 old_spi_in = 0, old_spi_out = 0;
  struct timeval time1;
  hiphdr *hiph;
  int old_state = 0;
  /* this is the SPI from the last received I2 packet, so we know
   * whether or not it is a retransmission */
  static __u32 last_I2_spi = 0;

  /* Accept I2 in all states but E_FAILED.
   * Special treatment when in ESTABLISHED. */
  if (hip_a_existing && (hip_a_existing->state == E_FAILED))
    {
      log_(NORM, "HIP_I2 packet not accepted in state=%d.\n",
           hip_a_existing->state);
      return(-1);
    }
  hiph = (hiphdr*) buff;

  /*
   * Is this my HIT?  If so, get corresponding HI. If not, fail
   */
  if ((my_host_id = check_if_my_hit(&hiph->hit_rcvr)) == NULL)
    {
      log_(NORM, "Received I2 with a recv. HIT that is not mine.\n");
      return(-1);
    }

  /*
   * Retransmit R2 if in state R2_SENT and this is a similar
   * I2 to the one that triggered moving to R2_SENT
   */
  if (hip_a_existing && (hip_a_existing->state == R2_SENT))
    {
      /* XXX should we instead process, then send R2? */
      if ((hip_a_existing->rexmt_cache.packet != NULL) &&
          (hip_a_existing->rexmt_cache.retransmits <
           HCNF.max_retries) && (0 == OPT.no_retransmit) &&
          (last_I2_spi == ntohl(
             ((tlv_esp_info*)&buff[sizeof(hiphdr)])->new_spi )))
        {
          log_(NORM, "Received I2 in R2_SENT, retransmitting ");
          log_(NORM, "R2...\n");
          hip_retransmit(hip_a,hip_a_existing->rexmt_cache.packet,
                         hip_a_existing->rexmt_cache.len,
                         dst, src);
          gettimeofday(&time1, NULL);
          hip_a_existing->rexmt_cache.xmit_time.tv_sec
            = time1.tv_sec;
          hip_a_existing->rexmt_cache.xmit_time.tv_usec
            = time1.tv_usec;
          hip_a_existing->rexmt_cache.retransmits++;
          set_state(hip_a_existing, R2_SENT);               /* update time */
          return(0);
        }
      /* If we get here, then we already have SAs that need to be
       * dropped because we are in R2_SENT, but this is a new I2
       * packet from a new HIP exchange. So we simply rush our
       * R2_SENT timer to become ESTABLISHED now.
       */
      log_(NORM, "Moving from state R2_SENT=>ESTABLISHED because ");
      log_(NORM, "a new HIP association requested.\n");
      set_state(hip_a_existing, ESTABLISHED);
      /* Compare HITs in state I2_SENT
       */
    }
  else if (hip_a_existing && (hip_a_existing->state == I2_SENT))
    {
      /* peer HIT larger than my HIT */
      if (compare_hits(hiph->hit_sndr, hiph->hit_rcvr) > 0)
        {
          log_(NORMT, "Dropping I2 in state I2_SENT because ");
          log_(NORM, "local HIT is smaller than peer HIT.\n");
          return(0);
        }
      /* local HIT is greater than peer HIT, send R2... */
    }

  /*
   * Prepare to drop old SAs
   */
  if (hip_a_existing && (hip_a_existing->state == ESTABLISHED))
    {
      old_state = hip_a_existing->state;
      old_spi_in = hip_a_existing->spi_in;
      old_spi_out = hip_a_existing->spi_out;
      log_(NORM, "Existing association already in ESTABLISHED, ");
      log_(NORM, "preparing to drop SAs.\n");
    }
  else
    {
      old_state = UNASSOCIATED;
    }


  /*
   * Process the I2, with appropriate checks
   */
  hip_a = hip_a_existing;       /* may be NULL */
  if (hip_parse_I2(buff, &hip_a, my_host_id, src, dst) < 0)
    {
      log_(WARN, "Error while processing I2, dropping.\n");
      /* stay in same state here */
      return(-1);
    }

  clear_retransmissions(hip_a);
  make_address_active(&hip_a->peer_hi->addrs);
  add_other_addresses_to_hi(hip_a->hi, TRUE);
  /* Need to send an SPI to peer */
  hip_a->spi_in = get_next_spi();
  /* build R2 and Responder's SA */
  if ((err = hip_send_R2(hip_a)) > 0)
    {
      last_I2_spi = hip_a->spi_out;           /* remember that this I2 put us
                                               *  into R2_SENT */
      draw_keys(hip_a, FALSE, hip_a->keymat_index);           /* draw ESP keys
                                                               */
      set_state(hip_a, R2_SENT);
      log_(NORM, "Sent R2 (%d bytes)\n", err);

      /* fill in LSI, update peer_hi_head */
      update_peer_list(hip_a);

      if (old_state == ESTABLISHED)
        {
          log_(NORM, "Dropping old SAs with SPIs of");
          log_(NORM, " 0x%x and 0x%x.\n",
               old_spi_out, old_spi_in);
          err = delete_associations(hip_a, old_spi_in,
                                    old_spi_out);
        }

      err = complete_base_exchange(hip_a);

      if (hip_a->spi_nat)
        {
          hip_assoc *hip_mr;
          __u16 keymat_index = hip_a->keymat_index;
          hip_mr = search_registrations2(REGTYPE_MR, REG_GRANTED);
          if (draw_mr_key(hip_a, hip_a->keymat_index) < 0)
            {
              log_(WARN, "Failed to draw mobile "
                   "router key");
            }
          else
            {
              hip_a->mr_keymat_index = keymat_index;
              log_(NORM, "Drawing MR proxy key %d\n",
                   hip_a->mr_keymat_index);
              /* If we are a mobile router client */
              /* use the same key for our mobile router */
              if (hip_mr &&
                  !hits_equal(hip_mr->peer_hi->hit,
                              hip_a->peer_hi->hit))
                {
                  hip_send_update_proxy_ticket(hip_mr,
                                               hip_a);
                }
            }
        }

      if (!err)
        {
#ifdef __MACOSX__
          hip_a->ipfw_rule = next_divert_rule();
          add_divert_rule(hip_a->ipfw_rule,
                          IPPROTO_ESP,logaddr(HIPA_DST(hip_a)));
#endif
          /* stay in state R2_SENT, awaiting
           * timeout or incoming ESP data */
        }
      else
        {
          log_(NORM, "SA incomplete (%d).\n", err);
        }
    }
  else
    {
      log_(NORM, "Failed to send R2: %s.\n", strerror(errno));
    }
  return(err);
}

/*
 *
 * function hip_parse_R2()
 *
 * in:		data = raw socket bytes
 *              hip_a = pointer to HIP connection instance
 *
 * out:		Returns -1 if error, packet length otherwise.
 *
 * parse HIP Second Responder packet
 *
 */
int hip_parse_R2(__u8 *data, hip_assoc *hip_a)
{
  hiphdr *hiph;
  int location, hi_loc, len, data_len, next_location;
  int type, length, last_type = 0;
  tlv_head *tlv;
  char sig_tlv_tmp[sizeof(tlv_hip_sig) + MAX_SIG_SIZE + 2];
  tlv_esp_info *esp_info;
  tlv_hmac hmac_tlv_tmp;
  unsigned char *hmac;
  __u16 proposed_keymat_index = 0;
  __u32 proposed_spi_out = 0;

  location = 0;
  hi_loc = 0;
  hiph = (hiphdr*) &data[location];
  data_len = location + ((hiph->hdr_len + 1) * 8);
  location += sizeof(hiphdr);
  while (location < data_len)
    {
      tlv = (tlv_head*) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      if (check_tlv_type_length(type, length, last_type, "R2") < 0)
        {
          return(-1);
        }
      else
        {
          last_type = type;
        }

      if (type == PARAM_ESP_INFO)
        {
          esp_info = (tlv_esp_info*)tlv;
          proposed_keymat_index = ntohs(esp_info->keymat_index);
          proposed_spi_out = ntohl(esp_info->new_spi);
        }
      else if (type == PARAM_HMAC_2)
        {
          /* save the HMAC_2 for processing after SIG is saved */
          memcpy(&hmac_tlv_tmp, tlv, sizeof(tlv_hmac));
          hi_loc = eight_byte_align(location);
        }
      else if (type == PARAM_HIP_SIGNATURE)
        {
          if ((hip_a == NULL) || (hip_a->peer_hi == NULL))
            {
              log_(WARN, "Received signature parameter "
                   "without any Host Identity context for "
                   "verification.\n");
              return(-1);
            }
          /* The PARAM_ESP_INFO_NOSIG seems to get overwritten
           * Should be reworked in future.
           * OTB (2/22/2010) */
          next_location = location +
                          tlv_length_to_parameter_length(length);
          if (next_location < data_len)
            {
              tlv_head *temp_tlv =
                (tlv_head*) &data[next_location];
              if (ntohs(temp_tlv->type) ==
                  PARAM_ESP_INFO_NOSIG)
                {
                  esp_info = (tlv_esp_info*)temp_tlv;
                  hip_a->spi_nat =
                    ntohl(esp_info->new_spi);
                  log_(NORMT, "Adding SPI NAT 0x%x\n",
                       hip_a->spi_nat);
                }
            }
          /* save SIG and do HMAC_2 verification */
          memcpy(sig_tlv_tmp, tlv, length + 4);
          /* When building host identity tlv for HMAC_2 verify,
           * use the DI (FQDN) regardless of HCNF.send_hi_name.
           * If no DI was rcvd in R1, then no DI will be used. */
          memset(&data[hi_loc], 0,
                 build_tlv_hostid_len(hip_a->peer_hi, TRUE));
          len = hi_loc + build_tlv_hostid(&data[hi_loc],
                                          hip_a->peer_hi, TRUE);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          hmac = hmac_tlv_tmp.hmac;
          log_(NORM, "HMAC_2 verify over %d bytes. ",len);
          log_(NORM, "hdr length=%d \n", hiph->hdr_len);
          if (validate_hmac(data, len,
                            hmac, 20,
                            get_key(hip_a, HIP_INTEGRITY, TRUE),
                            hip_a->hip_transform))
            {
              log_(WARN, "Invalid HMAC_2.\n");
              hip_send_notify(hip_a,
                              NOTIFY_HMAC_FAILED,
                              NULL, 0);
              if (OPT.permissive)
                {
                  return(0);
                }
              else
                {
                  return(-1);
                }
            }
          else
            {
              log_(NORM, "HMAC_2 verified OK.\n");
            }
          /* restore the HMAC_2 and SIG tlvs */
          memcpy(&data[hi_loc], &hmac_tlv_tmp, sizeof(tlv_hmac));
          memcpy(tlv, sig_tlv_tmp, length + 4);
          /* now do signature processing */
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          if (validate_signature(data, len, tlv,
                                 hip_a->peer_hi->dsa,
                                 hip_a->peer_hi->rsa) < 0)
            {
              log_(WARN, "Invalid signature.\n");
              hip_send_notify(hip_a,
                              NOTIFY_AUTHENTICATION_FAILED,
                              NULL, 0);
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          /* packet is OK, accept SPI and keymat index */
          hip_a->spi_out = proposed_spi_out;
          if (proposed_keymat_index > hip_a->keymat_index)
            {
              hip_a->keymat_index = proposed_keymat_index;
            }
          return(0);
        }
      else if (type == PARAM_REG_RESPONSE)                      /* R2 packet */
        {
          log_(NORM,
               "Received response from registrar in the R2 "
               "packet.\n");
          if (handle_reg_response(hip_a, &data[location]) < 0)
            {
              log_(WARN, "Problem with registration "
                   "response.\n");
            }
        }
      else if (type == PARAM_REG_FAILED)                        /* R2 packet */
        {
          log_(NORM, "Received failure from registrar in "
               "UPDATE packet.\n");
          if (handle_reg_failed(hip_a, &data[location]) < 0)
            {
              log_(WARN, "Problem with registration "
                   "failure.\n");
            }
        }
      else
        {
          if (check_tlv_unknown_critical(type, length) < 0)
            {
              __u16 t;
              t = (__u16)type;
              hip_send_notify(
                hip_a,
                NOTIFY_UNSUPPORTED_CRITICAL_PARAMETER_TYPE,
                (__u8 *)&t,
                sizeof(__u16));
              return(-1);
            }
        }
      location += tlv_length_to_parameter_length(length);
    }
  /* if we get here, no valid signature has been found */
  return(-1);
}

int hip_handle_R2(__u8 *buff, hip_assoc *hip_a)
{
  int err = 0;
  hip_assoc *hip_mr;

  /* R2 is only accepted in state I2_SENT */
  if (hip_a->state != I2_SENT)
    {
      log_(WARN, "HIP_R2 packet not accepted in state=%d.\n",
           hip_a->state);
      return(-1);
    }
  if (hip_parse_R2(buff, hip_a) < 0)
    {
      log_(WARN, "Error while processing R2, dropping.\n");
      clear_retransmissions(hip_a);
      set_state(hip_a, E_FAILED);
      return(-1);
    }
  clear_retransmissions(hip_a);
  make_address_active(&hip_a->peer_hi->addrs);
  /* draw new ESP keys using received/my keymat index */
  draw_keys(hip_a, FALSE, hip_a->keymat_index);

  err = complete_base_exchange(hip_a);
  if (!err)
    {
      set_state(hip_a, ESTABLISHED);
      if (OPT.mh && (hip_send_update_locators(hip_a) < 0))
        {
          log_(WARN, "Failed to send UPDATE with locators after "
               "receiving R2.\n");
        }
      hip_mr = search_registrations2(REGTYPE_MR, REG_GRANTED);
      if (hip_mr &&
          !hits_equal(hip_mr->peer_hi->hit, hip_a->peer_hi->hit))
        {
          /* we are registered with a mobile router service and
           * this association is not the one with the mr, so
           * create a proxy ticket */
          __u16 keymat_index = hip_a->keymat_index;
          if (draw_mr_key(hip_a, hip_a->keymat_index) < 0)
            {
              log_(WARN, "Failed to draw mobile router key");
            }
          else
            {
              hip_a->mr_keymat_index = keymat_index;
              log_(NORM, "Drawing MR proxy key %d\n",
                   hip_a->mr_keymat_index);
              hip_send_update_proxy_ticket(hip_mr, hip_a);
            }
        }
    }
  else
    {
      log_(NORM, "SA incomplete (%d).\n", err);
    }
#ifdef __MACOSX__
  hip_a->ipfw_rule = next_divert_rule();
  add_divert_rule(hip_a->ipfw_rule,IPPROTO_ESP,logaddr(HIPA_DST(hip_a)));
#endif
  return(err);
}

/*
 * function hip_parse_update()
 *
 * in:		data = the data to be parsed
 *              hip_a = the existing HIP association, for HMAC verification
 *              rk = struct for storing the peer's rekeying data
 *              nonce =
 *              src = source of received UPDATE, for UDP port
 *
 * out:
 */
int hip_parse_update(const __u8 *data, hip_assoc *hip_a, struct rekey_info *rk,
                     __u32 *nonce, struct sockaddr *src)
{
  hiphdr *hiph;
  int location, len, data_len;
  int type, length, last_type = 0, status;
  int loc_count, loc_len;
  int sig_verified = FALSE, hmac_verified = FALSE, ticket_verified =
    FALSE;
  tlv_head *tlv;
  __u32 new_spi = 0;
  __u8 g_id = 0, *hmac, *p;
  locator *locators[MAX_LOCATORS];
  tlv_esp_info *esp_info = NULL;
  tlv_from *from;
  tlv_via_rvs *via;
  struct sockaddr_storage rvs_addr;
  unsigned char *rvs_hmac;
  hip_assoc *hip_a_rvs;

  memset(locators, 0, sizeof(locators));
  loc_count = 0;
  *nonce = 0;
  location = 0;
  hiph = (hiphdr*) &data[location];
  data_len = location + ((hiph->hdr_len + 1) * 8);
  location += sizeof(hiphdr);

  status = -1;
  if (hip_a->spi_nat)
    {
      log_(NORM, "Received update for spinat connection\n");
    }

  while (location < data_len)
    {
      tlv = (tlv_head*) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      if (check_tlv_type_length(type, length, last_type,
                                "UPDATE") < 0)
        {
          return(-1);
        }
      else
        {
          last_type = type;
        }
      /* first verify HMAC and SIGNATURE */
      if (!hmac_verified && (type == PARAM_HMAC))
        {
          __u8 *key;
          hmac = ((tlv_hmac*)tlv)->hmac;
          /* reset the length and checksum for the HMAC */
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          log_(NORM, "HMAC verify over %d bytes. ",len);
          log_(NORM, "hdr length=%d \n", hiph->hdr_len);
          if (ticket_verified)
            {
              key = hip_a->mr_key.key;
            }
          else
            {
              key = get_key(hip_a, HIP_INTEGRITY, TRUE);
            }
          if (validate_hmac(data, len,
                            hmac, length,
                            key,
                            hip_a->hip_transform))
            {
              log_(WARN, "Invalid HMAC.\n");
              hip_send_notify(hip_a,
                              NOTIFY_HMAC_FAILED,
                              NULL, 0);
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          log_(NORM, "HMAC verified OK.\n");
          hmac_verified = TRUE;
          location += tlv_length_to_parameter_length(length);
          if (ticket_verified)                 /* No SIG yet */
            {
              status = 0;
              sig_verified = TRUE;
              last_type = 0;
              location = sizeof(hiphdr);
            }
          continue;
        }
      else if (!sig_verified && (type == PARAM_HIP_SIGNATURE))
        {
          if ((hip_a == NULL) || (hip_a->peer_hi == NULL))
            {
              log_(WARN, "Received signature parameter "
                   "without any Host Identity context for "
                   "verification.\n");
              return(-1);
            }
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          if (validate_signature(data, len, tlv,
                                 hip_a->peer_hi->dsa,
                                 hip_a->peer_hi->rsa) < 0)
            {
              log_(WARN, "Invalid signature.\n");
              hip_send_notify(hip_a,
                              NOTIFY_AUTHENTICATION_FAILED,
                              NULL, 0);
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          /* now we may save changes from this UPDATE */
          status = 0;
          sig_verified = TRUE;
          last_type = 0;
          location = sizeof(hiphdr);
          continue;
        }
      else if (!ticket_verified && (type == PARAM_AUTH_TICKET) &&
               hip_a->spi_nat)
        {
          tlv_auth_ticket *auth_ticket =
            (tlv_auth_ticket *) &data[location];
          if (hip_a->mr_keymat_index !=
              ntohs(auth_ticket->hmac_key_index))
            {
              log_(WARN, "Keymat indices do not match!\n");
              log_(WARN, "My mr_keymat_index is %d\n",
                   hip_a->mr_keymat_index);
              log_(WARN, "Proxy keymat_index is %d\n",
                   ntohs(auth_ticket->hmac_key_index));
              /* Generate new keymat? */
            }
          len = sizeof(auth_ticket->hmac_key_index) +
                sizeof(auth_ticket->transform_type) +
                sizeof(auth_ticket->action) +
                sizeof(auth_ticket->lifetime);
          log_(NORM, "HMAC verify ticket over %d bytes.\n",len);
          if (validate_hmac(
                (const __u8*)&auth_ticket->hmac_key_index,
                len,
                auth_ticket->hmac, sizeof(auth_ticket->hmac),
                get_key(hip_a, HIP_INTEGRITY, TRUE),
                hip_a->hip_transform))
            {
              log_(WARN, "Invalid HMAC over ticket.\n");
            }
          else
            {
              log_(NORM, "HMAC over ticket succeeded\n");
              ticket_verified = TRUE;
            }
        }

      /* skip all parameters until verification */
      if (!hmac_verified && !sig_verified)
        {
          location += tlv_length_to_parameter_length(length);
          continue;
        }

      if (type == PARAM_LOCATOR)
        {
          /* get location of first locator */
          locators[loc_count] = ((tlv_locator*)tlv)->locator1;
          loc_len = 8 + (4 * locators[loc_count]->locator_length);
          len = length - loc_len;
          loc_count++;
          /* read additional locators */
          while (len > 0)
            {
              if (loc_count >= MAX_LOCATORS)
                {
                  log_(WARN, "Only handling first %d loc",
                       "ators, dropping %d.\n",
                       MAX_LOCATORS, loc_count + 1);
                  break;
                }
              /* p used to point to next locator */
              p = (__u8*)locators[loc_count - 1];
              p += loc_len;
              locators[loc_count] = (locator*)p;
              /* calculate length of this locator */
              if ((locators[loc_count]->locator_length != 5)
                  &&
                  (locators[loc_count]->locator_length !=
                   4))
                {
                  log_(WARN, "Invalid locator length of");
                  log_(
                    NORM,
                    " %d found.\n",
                    locators[loc_count]->
                    locator_length);
                  return(-1);
                }
              loc_len = 8;
              loc_len += 4 *
                         locators[loc_count]->locator_length;
              len -= loc_len;
              loc_count++;
            }
        }
      else if (type == PARAM_ESP_INFO)
        {
          esp_info = (tlv_esp_info *) tlv;
          new_spi = ntohl(esp_info->new_spi);
          if (handle_esp_info(esp_info, hip_a->spi_out,
                              rk) < 0)
            {
              log_(WARN, "Problem with ESP_INFO.\n");
            }
        }
      else if (type == PARAM_SEQ)
        {
          rk->update_id = ntohl(((tlv_seq*)tlv)->update_id);
          rk->need_ack = TRUE;
          if (rk->update_id < hip_a->peer_hi->update_id)
            {
              log_(WARN, "Received Update ID is smaller ");
              log_(NORM, "than stored Update ID.\n");
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          else if (rk->update_id ==
                   hip_a->peer_hi->update_id)
            {
              /* probably a retransmission, but SHOULD
               * rate-limit against DOS here*/
            }
          /* save new update ID */
          hip_a->peer_hi->update_id = rk->update_id;
        }
      else if (type == PARAM_ACK)
        {
          if (handle_acks(hip_a, (tlv_ack*)tlv))
            {
              hip_a->rekey->need_ack = FALSE;
            }
        }
      else if (type == PARAM_DIFFIE_HELLMAN)
        {
          if (rk->keymat_index != 0)
            {
              log_(WARN, "Diffie-Hellman found in UPDATE, ");
              log_(NORM, "but keymat_index=%d.\n",
                   rk->keymat_index);
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          /* Save the DH context in rk->dh for later use */
          rk->dh = DH_new();
          if (handle_dh(NULL, &data[location], &g_id,
                        rk->dh) < 0)
            {
              return(-1);
            }
        }
      else if ((type == PARAM_ECHO_RESPONSE) ||
               (type == PARAM_ECHO_RESPONSE_NOSIG))
        {
          if (length != sizeof(__u32))
            {
              log_(WARN, "ECHO_RESPONSE has wrong length.\n");
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          memcpy(nonce, ((tlv_echo*)tlv)->opaque_data, length);
        }
      else if ((type == PARAM_ECHO_REQUEST) ||
               (type == PARAM_ECHO_REQUEST_NOSIG))
        {
          /* prevent excessive memory consumption */
          if (length > MAX_OPAQUE_SIZE)
            {
              log_(WARN,"ECHO_REQUEST in UPDATE is ");
              log_(NORM,"too large.\n");
              if (!OPT.permissive &&
                  (type & PARAM_CRITICAL_BIT))
                {
                  return(-1);
                }
            }
          else
            {
              hip_a->opaque = (struct opaque_entry*)
                              malloc(sizeof(struct
                                            opaque_entry));
              if (hip_a->opaque == NULL)
                {
                  log_(NORM,"Malloc err: ECHO_REQUEST\n");
                  return(-1);
                }
              hip_a->opaque->opaque_len = (__u16)length;
              memcpy(hip_a->opaque->opaque_data,
                     ((tlv_echo*)tlv)->opaque_data, length);
              hip_a->opaque->opaque_nosig =
                (type == PARAM_ECHO_REQUEST_NOSIG);
            }
        }
      else if (type == PARAM_PROXY_TICKET)
        {
#ifndef __WIN32__
          if (OPT.mr)
            {
              add_proxy_ticket(&data[location]);
            }
          else
#endif /* !__WIN32__ */
            {
              log_(WARN, "Ignoring proxy ticket in UPDATE packet.\n");
            }
        }
      else if (type == PARAM_REG_INFO)                   /* update packet */
        {
          log_(NORM,
               "Peer is a registrar providing registration "
               "info in its UPDATE packet.\n");
          if (handle_reg_info(hip_a, &data[location]) < 0)
            {
              log_(WARN, "Problem with registration info.\n");
            }
        }
      else if (type == PARAM_REG_REQUEST)                /* update packet */
        {
          log_(NORM, "Peer has requested registration(s) in its "
               "UPDATE packet.\n");
          if (handle_reg_request(hip_a, &data[location]) < 0)
            {
              log_(WARN, "Problem with registration "
                   "request.\n");
            }
        }
      else if (type == PARAM_REG_RESPONSE)               /* update packet */
        {
          log_(NORM, "Received response from registrar in "
               "UPDATE packet.\n");
          if (handle_reg_response(hip_a, &data[location]) < 0)
            {
              log_(WARN, "Problem with registration "
                   "response.\n");
            }
        }
      else if (type == PARAM_REG_FAILED)                /* update packet */
        {
          log_(NORM, "Received failure from registrar in "
               "UPDATE packet.\n");
          if (handle_reg_failed(hip_a, &data[location]) < 0)
            {
              log_(WARN, "Problem with registration "
                   "failure.\n");
            }
        }
      else if (type == PARAM_FROM)
        {
          from = (tlv_from*) &data[location];
          if (length > (sizeof(tlv_from) - 4))
            {
              log_(NORM, "Ignoring extra address data.\n");
            }
          add_from_via(hip_a, PARAM_FROM, NULL, from->address);
        }
      else if (type == PARAM_VIA_RVS)
        {
          via = (tlv_via_rvs *) &data[location];
          if (IN6_IS_ADDR_V4MAPPED(
                (struct in6_addr*)via->address))
            {
              rvs_addr.ss_family = AF_INET;
              memcpy(SA2IP(&rvs_addr), &via->address[12],
                     SAIPLEN(&rvs_addr));
            }
          else
            {
              rvs_addr.ss_family = AF_INET;
              memcpy(SA2IP(&rvs_addr), via->address,
                     SAIPLEN(&rvs_addr));
            }
          log_(NORM, "UPDATE packet relayed by the Rendezvous "
               "Server address %s.\n", logaddr(SA(&rvs_addr)));
        }
      else if (type == PARAM_RVS_HMAC)
        {
          hip_a_rvs = search_registrations2(REGTYPE_RVS,
                                            REG_GRANTED);
          if (!hip_a_rvs)
            {
              log_(WARN, "Received UPDATE with RVS_HMAC, "
                   "but could not find an association "
                   "with a Rendezvous Server.\n");
              if (hip_a->from_via)
                {
                  free(hip_a->from_via);
                  hip_a->from_via = NULL;
                }
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          else
            {
              rvs_hmac = ((tlv_hmac*)tlv)->hmac;
              /* reset the length and checksum for the HMAC */
              len = eight_byte_align(location);
              hiph->checksum = 0;
              hiph->hdr_len = (len / 8) - 1;
              log_(NORM, "RVS_HMAC verify over %d bytes. ",
                   len);
              log_(NORM, "hdr length=%d \n", hiph->hdr_len);
              if (validate_hmac(data, len, rvs_hmac, length,
                                get_key(hip_a_rvs,
                                        HIP_INTEGRITY, TRUE),
                                hip_a_rvs->hip_transform))
                {
                  log_(WARN, "Invalid RVS_HMAC.\n");
                  if (hip_a->from_via)
                    {
                      free(hip_a->from_via);
                      hip_a->from_via = NULL;
                    }
                  if (!OPT.permissive)
                    {
                      return(-1);
                    }
                }
              else
                {
                  log_(NORM, "RVS_HMAC verified OK.\n");
                }
            }
        }
      else if ((type == PARAM_HMAC) ||
               (type == PARAM_HIP_SIGNATURE) ||
               (type == PARAM_AUTH_TICKET))
        {
          /* these parameters already processed */
        }
      else
        {
          if (check_tlv_unknown_critical(type, length) < 0)
            {
              return(-1);
            }
        }
      location += tlv_length_to_parameter_length(length);
    }

  /* update peer address list */
  if (loc_count > 0)
    {
      if (handle_locators(hip_a, locators, loc_count, src,
                          new_spi) < 0)
        {
          log_(WARN, "Problem with LOCATOR.\n");
          status = -1;
        }
    }
  return(status);
}

int hip_handle_update(__u8 *data, hip_assoc *hip_a, struct sockaddr *src,
                      struct sockaddr *dst)
{
  int err;
  struct rekey_info rk;
  struct sockaddr *addrcheck = NULL;
  int need_to_send_update = FALSE;
  __u32 nonce;
  struct reg_info *reg;
  hip_assoc *hip_a_rvs;
  struct sockaddr_storage addr;
  __u8 *addrp;
  hip_assoc *hip_a_client;
  hip_hit *hitr;

  /* If RVS, check for RVS client */
  if (!hip_a)
    {
      if (OPT.rvs)
        {
          hitr = &(((hiphdr *)(data))->hit_rcvr);
          hip_a_client = search_registrations(*hitr, REGTYPE_RVS);
          if (!hip_a_client)
            {
              return(-1);
            }
          if (add_from_via(hip_a_client, PARAM_FROM, src, NULL)
              < 0)
            {
              return(-1);
            }
          if (hip_send_update_relay(data, hip_a_client) < 0)
            {
              return(-1);
            }
          else
            {
              return(0);
            }
        }
      else
        {
          return(-1);
        }
    }

  /*
   * UPDATE only accepted in ESTABLISHED and R2_SENT states
   */
  if ((hip_a->state != ESTABLISHED) && (hip_a->state != R2_SENT))
    {
      log_(WARN, "UPDATE not accepted in state %d, dropping.\n",
           hip_a->state);
      return(-1);
    }

  memset(&rk, 0, sizeof(struct rekey_info));
  nonce = 0;
  if ((err = hip_parse_update(data, hip_a, &rk, &nonce, src)) < 0)
    {
      log_(WARN, "Error while processing UPDATE, dropping.\n");
      return(-1);
    }

  /*
   * If received an UPDATE in R2_SENT state, move to ESTABLISHED state
   */
  if (hip_a->state == R2_SENT)
    {
      set_state(hip_a, ESTABLISHED);
    }

  /*
   * Only save the peer's rekeying state after the UPDATE
   * has been verified as OK.
   */
  if (!hip_a->peer_rekey)
    {
      /* No current peer_rekey; create new structure and
       * copy any rekey information from the UPDATE message.
       */
      hip_a->peer_rekey = malloc(sizeof(struct rekey_info));
      if (hip_a->peer_rekey)
        {
          memcpy(hip_a->peer_rekey, &rk,
                 sizeof(struct rekey_info));
        }
      else
        {
          log_(WARN, "Malloc error\n");
          return(-1);
        }
    }
  else if (rk.new_spi > 0)
    {
      /* A new SPI has been proposed, e.g. during readdress,
       * replace old peer information.
       */
      if (hip_a->peer_rekey->dh)
        {
          DH_free(hip_a->peer_rekey->dh);
        }
      memcpy(hip_a->peer_rekey, &rk, sizeof(struct rekey_info));
    }

  /*
   * Update address status if we received our
   * address verification nonce
   */
  if (nonce)
    {
      finish_address_check(hip_a, nonce, src);
    }

  /*
   * Handle rekeying, based on current state
   */
  if ((err = handle_update_rekey(hip_a)) < 0)
    {
      log_(WARN, "Problem with UPDATE rekey processing.\n");
      return(-1);
    }
  else if (err == 1)
    {
      need_to_send_update = TRUE;
    }

  /*
   * Generate a new UPDATE because of ACK?
   */
  if (hip_a->peer_rekey && hip_a->peer_rekey->need_ack)
    {
      log_(NORM, "Send new UPDATE to ack update ID %d.\n",
           hip_a->peer_rekey->update_id);
      need_to_send_update = TRUE;
    }

  /*
   * Generate a new UPDATE because of REG_REQUEST?
   */
  if (hip_a->regs)
    {
      for (reg = hip_a->regs->reginfos; reg; reg = reg->next)
        {
          if ((reg->state == REG_SEND_RESP) ||
              (reg->state == REG_SEND_CANCELLED) ||
              (reg->state == REG_SEND_FAILED))
            {
              log_(NORM,
                   "Send new UPDATE due to registration"
                   "request (state=%d).\n",
                   reg->state);
              need_to_send_update = TRUE;
              break;
            }
        }
    }

  /*
   * Handle readdress and address verification.
   * Look for new preferred addresses that may have been added,
   * and for addresses that need verifying
   */
  if ((err = handle_update_readdress(hip_a, &addrcheck)) < 0)
    {
      log_(WARN, "Problem with UPDATE readdress processing.\n");
      return(-1);
    }
  else if (err == 1)
    {
      need_to_send_update = TRUE;
    }

  /*
   * Relayed UPDATE from RVS, send to address in FROM parameter and fill
   * in address for VIA_RVS parameter.
   */
  if (need_to_send_update && hip_a->from_via &&
      (ntohs(hip_a->from_via->type) == PARAM_FROM))
    {
      /* get RVS */
      hip_a_rvs = search_registrations2(REGTYPE_RVS, REG_GRANTED);
      if (hip_a_rvs)
        {
          /* get address from FROM parameter */
          memset(&addr, 0, sizeof(addr));
          if (IN6_IS_ADDR_V4MAPPED((struct in6_addr*)
                                   hip_a->from_via->address))
            {
              addr.ss_family = AF_INET;
              addrp = &hip_a->from_via->address[12];
            }
          else
            {
              addr.ss_family = AF_INET6;
              addrp = &hip_a->from_via->address[0];
            }
          memcpy(SA2IP(&addr), addrp, SAIPLEN(&addr));
          src = SA(&addr);
          if (HIPA_DST(hip_a)->sa_family == AF_INET)
            {
              ((struct sockaddr_in *)src)->sin_port =
                ((struct sockaddr_in *)
                 HIPA_DST(hip_a))->sin_port;
            }
          log_(NORM, "Relayed UPDATE from RVS %s, ",
               logaddr(HIPA_DST(hip_a_rvs)));
          log_(NORM, "using %s as new destination address.\n",
               logaddr(src));
          /* store RVS address for VIA_RVS parameter */
          add_from_via(hip_a, PARAM_VIA_RVS,
                       HIPA_DST(hip_a_rvs), NULL);
        }
    }

  if (need_to_send_update)
    {
      if ((err = hip_send_update(hip_a, NULL, dst, addrcheck)) > 0)
        {
          log_(NORM, "Sent UPDATE (%d bytes)\n", err);
        }
      else
        {
          log_(WARN, "Failed to send UPDATE: %s.\n",
               strerror(errno));
        }
    }

  /*
   * cleanup unused structures
   */
  if ((hip_a->rekey) && !hip_a->rekey->need_ack &&
      !hip_a->rekey->new_spi && !hip_a->rekey->dh)
    {
      free(hip_a->rekey);
      hip_a->rekey = NULL;
    }
  if ((hip_a->peer_rekey) && !hip_a->peer_rekey->need_ack &&
      !hip_a->peer_rekey->new_spi && !hip_a->peer_rekey->dh)
    {
      free(hip_a->peer_rekey);
      hip_a->peer_rekey = NULL;
    }
  return(0);
}

/*
 * handle_update_rekey()
 *
 * in:		hip_a = the association containing peer_rekey, rekey structs
 *                      for building the UPDATE message, and the DH
 *
 * out:		Returns 0 if no update needs to be sent, 1 if update is needed,
 *              or -1 on error.
 *
 * Take care of the rekeying portion of UPDATE messages.
 * Uses hip_a->rekey and hip_a->peer_rekey for managing rekeying.
 */
int handle_update_rekey(hip_assoc *hip_a)
{
  int need_to_send_update = FALSE;

  if (!hip_a)
    {
      return(-1);
    }

  /* Did we initiate the rekey? */
  if (hip_a->rekey)
    {
      if (!hip_a->rekey->new_spi)
        {
          /* finish_address_check() should've already taken
           * care of this case
           */
          log_(WARN, "handle_update_rekey(): unexpected ");
          log_(NORM, "rekey state reached!\n");

        }
      /* We initiated the rekey, which will finish in
       * hip_handle_state_timeouts()
       */
      return(need_to_send_update);
    }

  if ((hip_a->state == ESTABLISHED) &&
      (hip_a->peer_rekey) &&
      (hip_a->peer_rekey->new_spi > 0))         /* 8.11.1 */
    {           /* use hip_a->rekey for the new update
                 * keymat_index = index to use in ESP_INFO
                 * dh_group_id, dh = new DH key to send
                 */
      if (build_rekey(hip_a) < 0)
        {
          log_(WARN, "handle_update_rekey() failed to build a "
               "new rekey structure for response to peer "
               "rekeying event.\n");
          return(-1);
        }
      need_to_send_update = TRUE;
    }
  /* 8.11.2
   * At this point the rekey can be finished if the updates
   * have been properly acked. However, we cannot call
   * hip_finish_rekey() here because there may be pending
   * expires on the ESP socket.
   *
   * Thus, defer until hip_handle_state_timeouts()
   */
  return(need_to_send_update);
}

/*
 * handle_update_readdress()
 *
 * in:		hip_a = the association containing peer_hi with the peer's
 *                      address list
 *
 * out:		Returns 0 if no update needs to be sent, 1 if update is needed,
 *              or -1 on error.
 *
 * Take care of the address verification and readdressing tasks when
 * receiving UPDATE messages. hip_a->peer_hi->addrs is a list of peer
 * addresses, and when the preferred flag is set, readdressing is needed;
 * when an address has a status of UNVERIFIED, we need to do an address check.
 */
int handle_update_readdress(hip_assoc *hip_a, struct sockaddr **addrcheck)
{
  int need_to_send_update = FALSE;
  sockaddr_list *l, *l_next, *peer_list, *my_list, *new_af = NULL;
  struct sockaddr *pref_addr, *new_af_addr = NULL;
  __u32 nonce, new_spi, new_peer_spi;

  if (!hip_a)
    {
      return(-1);
    }

  l = peer_list = &hip_a->peer_hi->addrs;
  while (l)
    {
      l_next = l->next;
      /* new preferred address, do readdressing tasks */
      if (l->preferred &&
          (hip_a->peer_hi->skip_addrcheck ||
           (l->status == ACTIVE)))
        {
          pref_addr = (struct sockaddr*)&l->addr;
          log_(NORMT, "Making new preferred address active: %s\n",
               logaddr(pref_addr));
          /* draw new keys, adopt new SPIs if necessary */
          new_spi = 0;
          new_peer_spi = 0;
          if ((hip_a->rekey) && (!hip_a->rekey->need_ack) &&
              (hip_a->peer_rekey) &&
              (hip_a->peer_rekey->new_spi > 0))
            {
              log_(NORMT, "Performing rekey...\n");
              new_spi = hip_a->rekey->new_spi;
              new_peer_spi = hip_a->peer_rekey->new_spi;
              hip_finish_rekey(hip_a, FALSE);
            }
          my_list = &hip_a->hi->addrs;
          if (l->addr.ss_family != my_list->addr.ss_family)
            {
              for (new_af = my_list;
                   new_af;
                   new_af = new_af->next)
                {
                  if (new_af->addr.ss_family ==
                      l->addr.ss_family)
                    {
                      break;
                    }
                }
              if (!new_af)
                {
                  log_(
                    WARN,
                    "Could not find an address of family %d\n",
                    l->addr.ss_family);
                  return(-1);
                }
              else
                {
                  log_(NORMT,
                       "Found new address family %s.\n",
                       logaddr((struct sockaddr*)&new_af
                               ->addr));
                }
            }
          if (!new_af)
            {
              rebuild_sa(hip_a, pref_addr, new_spi,
                         TRUE, TRUE);
              rebuild_sa(hip_a, pref_addr, new_peer_spi,
                         FALSE, TRUE);
            }
          else
            {
              new_af_addr = SA(&new_af->addr);
              rebuild_sa_x2(hip_a, pref_addr, new_af_addr,
                            new_peer_spi, TRUE);
              rebuild_sa_x2(hip_a, new_af_addr, pref_addr,
                            new_spi, FALSE);
            }
          log_hipa_fromto(QOUT, "Update completed (readdress)",
                          hip_a, FALSE, TRUE);
          if (l != peer_list)
            {
              memcpy(HIPA_DST(hip_a), pref_addr,
                     SALEN(pref_addr));
              hip_a->peer_hi->addrs.lifetime = l->lifetime;
              make_address_active(&hip_a->peer_hi->addrs);
              delete_address_entry_from_list(&peer_list, l);
            }
          if (new_af)
            {
              struct sockaddr_storage temp_addr;
              int temp_lifetime;
              log_hipa_fromto(QOUT,
                              "Update completed (readdress)",
                              hip_a,
                              TRUE,
                              FALSE);
              /* Swap addrs instead of just overwriting */
              memcpy(&temp_addr, HIPA_SRC(hip_a),
                     SALEN(HIPA_SRC(hip_a)));
              temp_lifetime = hip_a->hi->addrs.lifetime;
              memcpy(HIPA_SRC(hip_a), new_af_addr,
                     SALEN(new_af_addr));
              hip_a->hi->addrs.lifetime = new_af->lifetime;
              make_address_active(&hip_a->hi->addrs);
              memcpy(new_af_addr, &temp_addr,
                     SALEN(&temp_addr));
              new_af->lifetime = temp_lifetime;
            }
          /* adopt new SPIs; rekey structures freed later  */
          if (new_spi && new_peer_spi)
            {
              hip_a->spi_in = new_spi;
              hip_a->spi_out = new_peer_spi;
            }
          /* choose address to verify */
        }
      else if (!hip_a->peer_hi->skip_addrcheck &&
               (l->status == UNVERIFIED))
        {
          /* XXX for now, verify only the first address */
          *addrcheck = (struct sockaddr *)&l->addr;
          log_(NORMT, "Performing address check for: %s\n",
               logaddr(*addrcheck));
          RAND_bytes((__u8*)&nonce, sizeof(__u32));
          l->nonce = nonce;
          /* add SEQ parameter to UPDATE if it doesn't have one */
          if (!hip_a->rekey)
            {
              hip_a->rekey = malloc(sizeof(struct rekey_info));
              memset(hip_a->rekey, 0,
                     sizeof(struct rekey_info));
              hip_a->rekey->update_id =
                hip_a->hi->update_id++;
              hip_a->rekey->need_ack = TRUE;
              gettimeofday(&hip_a->rekey->rk_time, NULL);
            }
          need_to_send_update = TRUE;
        }
      l = l_next;
    }

  return (need_to_send_update);
}

void finish_address_check(hip_assoc *hip_a, __u32 nonce, struct sockaddr *src)
{
  sockaddr_list *l;

  if (!hip_a || !src)
    {
      return;
    }

  /* find peer address */
  for (l = &hip_a->peer_hi->addrs; l; l = l->next)
    {
      if ((l->addr.ss_family == src->sa_family) &&
          (!memcmp(SA2IP(&l->addr),SA2IP(src),SAIPLEN(src))))
        {
          break;
        }
    }
  if (!l)
    {
      log_(WARN, "Could not find address check address %s.\n",
           logaddr(src));
      /* check that echoed nonce matches, and update address status */
    }
  else if (nonce == l->nonce)
    {
      log_(NORM, "Address check succeeded for %s (preferred=%s).\n",
           logaddr(src), l->preferred ? "yes" : "no");
      make_address_active(l);
      /* cleanup structures if they have no more use */
      if ((!hip_a->rekey->need_ack) && (!hip_a->rekey->new_spi))
        {
          free(hip_a->rekey);
          hip_a->rekey = NULL;
        }
      if ((hip_a->peer_rekey) && (!hip_a->peer_rekey->need_ack) &&
          (!hip_a->peer_rekey->new_spi))
        {
          free(hip_a->peer_rekey);
          hip_a->peer_rekey = NULL;
        }
      clear_retransmissions(hip_a);
      /* readdressing occurs later, when address list is
       * scanned for new ACTIVE addresses */
    }
  else
    {
      log_(WARN, "Address check failed for source %s with nonce 0x%x"
           " (0x%x).\n", logaddr(src), nonce, l->nonce);
    }
}

/*
 * hip_finish_rekey()
 *
 * in:		hip_a = HIP association with rekey and peer_rekey data
 *              rebuild = TRUE if SAs should be rebuilt (rekey only)
 *                        FALSE to leave SAs alone (readdress + rekey)
 *
 * Completes the rekey process (UPDATE exchange) by drawing or generating
 * new keying material, adding SAs with new SPIs, and dropping the old SAs.
 */
int hip_finish_rekey(hip_assoc *hip_a, int rebuild)
{
  int len, keymat_index, err;
  unsigned char *dh_secret_key;

  /*
   * Rekey from section 8.11.3
   */

  /*
   * 1. if new DH from peer or me, generate new keying material
   */
  err = 0;
  if (hip_a->rekey->dh || hip_a->peer_rekey->dh)
    {
      log_(NORM, "At least one DH found in UPDATE exchange, ");
      log_(NORM, "computing new secret key.\n");
      if ((hip_a->rekey->dh && hip_a->peer_rekey->dh) &&
          (hip_a->rekey->dh_group_id !=
           hip_a->peer_rekey->dh_group_id))
        {
          log_(WARN, "Warning: UPDATE DH group mismatch!\n");
        }

      if (hip_a->rekey->dh)
        {
          unuse_dh_entry(hip_a->dh);
          hip_a->dh_group_id = hip_a->rekey->dh_group_id;
          hip_a->dh  = hip_a->rekey->dh;
          hip_a->rekey->dh = NULL;               /* moved to hip_a->dh */
        }
      if (hip_a->peer_rekey->dh)
        {
          hip_a->peer_dh = hip_a->peer_rekey->dh;
          hip_a->peer_rekey->dh = NULL;               /* moved to ->peer_dh*/
        }

      /*
       * compute a new secret key from our dh and peer's pub_key
       * and recompute the keymat
       */
      dh_secret_key = malloc(DH_size(hip_a->dh));
      if (!dh_secret_key)
        {
          log_(WARN, "hip_finish_rekey() malloc() error");
          return(-1);
        }
      memset(dh_secret_key, 0, DH_size(hip_a->dh));
      len = DH_compute_key(dh_secret_key,
                           hip_a->peer_dh->pub_key,
                           hip_a->dh);
      if (len != DH_size(hip_a->dh))
        {
          log_(WARN, "Warning: secret key len = %d, ", len);
          log_(NORM, "expected %d\n", DH_size(hip_a->dh));
        }
      set_secret_key(dh_secret_key, hip_a);
      keymat_index = 0;
      compute_keymat(hip_a);
      /* 2. set new keymat_index to 0, or choose lowest keymat index
       */
    }
  else
    {
      if (hip_a->rekey->keymat_index <
          hip_a->peer_rekey->keymat_index)
        {
          keymat_index = hip_a->rekey->keymat_index;
        }
      else
        {
          keymat_index = hip_a->peer_rekey->keymat_index;
        }
    }

  log_(NORM, "Using keymat index = %d for drawing new keys.\n",
       keymat_index);

  /*
   * 3. draw keys for new incoming/outgoing ESP SAs
   *    do not draw HIP keys!
   */
  if (draw_keys(hip_a, FALSE, keymat_index) < 0)
    {
      log_(WARN, "Error drawing new keys, old SAs retained.\n");
      return(-1);
    }

  /* 4. move to ESTABLISHED
   * 5. add the NEW outgoing/incoming SA
   */
  err = rebuild_sa(hip_a, NULL, hip_a->rekey->new_spi, TRUE, TRUE);
  err += rebuild_sa(hip_a, NULL, hip_a->peer_rekey->new_spi, FALSE, TRUE);
  /* no need to call sadb_readdress(), since address is not changing */

  if (!err)
    {
      log_hipa_fromto(QOUT, "Update completed (rekey)",
                      hip_a, FALSE, TRUE);
      hip_a->spi_out = hip_a->peer_rekey->new_spi;
      hip_a->spi_in = hip_a->rekey->new_spi;
      free(hip_a->peer_rekey);
      free(hip_a->rekey);           /* any DH already unused */
      hip_a->peer_rekey = NULL;
      hip_a->rekey = NULL;
    }
  return(err);
}

/*
 *
 * function hip_parse_close()
 *
 * in:		data = raw socket bytes
 *              hip_a = pointer to HIP connection instance
 *              *nonce = pointer for storing echo response
 *
 * out:		Returns -1 if error, packet length otherwise.
 *
 * parse HIP CLOSE and CLOSE_ACK packets
 *
 */
int hip_parse_close(const __u8 *data, hip_assoc *hip_a, __u32 *nonce)
{
  hiphdr *hiph;
  int location, len, data_len;
  int type, length, last_type = 0;
  tlv_head *tlv;
  __u8 *hmac;
  int is_ack;
  __u32 received_nonce = 0;

  location = 0;
  hiph = (hiphdr*) &data[location];
  data_len = location + ((hiph->hdr_len + 1) * 8);
  location += sizeof(hiphdr);
  is_ack = (hiph->packet_type == CLOSE_ACK);
  if (is_ack)
    {
      *nonce = 0;
    }

  while (location < data_len)
    {
      tlv = (tlv_head*) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      if (check_tlv_type_length(type, length, last_type,
                                is_ack ? "CLOSE_ACK" : "CLOSE") <
          0)
        {
          return(-1);
        }
      else
        {
          last_type = type;
        }

      if (type == PARAM_ECHO_REQUEST)
        {
          if (is_ack)
            {
              log_(WARN, "Found ECHO_REQUEST in CLOSE_ACK ");
              log_(NORM, "packet, dropping.\n");
              return(-1);
            }
          /* prevent excessive memory consumption */
          if (length > MAX_OPAQUE_SIZE)
            {
              log_(WARN,"ECHO_REQUEST in CLOSE too large.\n");
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          else
            {
              hip_a->opaque = (struct opaque_entry*)
                              malloc(sizeof(struct
                                            opaque_entry));
              if (hip_a->opaque == NULL)
                {
                  log_(NORM,"Malloc err: ECHO_REQUEST\n");
                  return(-1);
                }
              hip_a->opaque->opaque_len = (__u16)length;
              memcpy(hip_a->opaque->opaque_data,
                     ((tlv_echo*)tlv)->opaque_data, length);
              hip_a->opaque->opaque_nosig = FALSE;
            }
        }
      else if (type == PARAM_ECHO_RESPONSE)
        {
          if (!is_ack)
            {
              log_(WARN, "Found ECHO_RESPONSE in CLOSE ");
              log_(NORM, "packet, dropping.\n");
              return(-1);
            }
          if (length != sizeof(__u32))
            {
              log_(WARN, "ECHO_RESPONSE has wrong length.\n");
              if (!OPT.permissive)
                {
                  return(-1);
                }
            }
          memcpy(&received_nonce,
                 ((tlv_echo*)tlv)->opaque_data, length);
        }
      else if (type == PARAM_HIP_SIGNATURE)
        {
          if ((hip_a == NULL) || (hip_a->peer_hi == NULL))
            {
              log_(WARN, "Received signature parameter "
                   "without any Host Identity context for "
                   "verification.\n");
              return(-1);
            }
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          if (validate_signature(data, len, tlv,
                                 hip_a->peer_hi->dsa,
                                 hip_a->peer_hi->rsa) < 0)
            {
              log_(WARN, "Invalid signature.\n");
              hip_send_notify(hip_a,
                              NOTIFY_AUTHENTICATION_FAILED,
                              NULL, 0);
              if (OPT.permissive)
                {
                  return(0);
                }
              else
                {
                  return(-1);
                }
            }
          else
            {
              /* save nonce from echo reply */
              if (received_nonce > 0)
                {
                  *nonce = received_nonce;
                }
              return(0);
            }
        }
      else if (type == PARAM_HMAC)
        {
          hmac = ((tlv_hmac*)tlv)->hmac;
          /* reset the length and checksum for the HMAC */
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          log_(NORM, "HMAC verify over %d bytes. ",len);
          log_(NORM, "hdr length=%d \n", hiph->hdr_len);
          if (validate_hmac(data, len,
                            hmac, length,
                            get_key(hip_a, HIP_INTEGRITY, TRUE),
                            hip_a->hip_transform))
            {
              log_(WARN, "Invalid HMAC.\n");
              hip_send_notify(hip_a,
                              NOTIFY_HMAC_FAILED,
                              NULL, 0);
              if (OPT.permissive)
                {
                  return(0);
                }
              else
                {
                  return(-1);
                }
            }
          else
            {
              log_(NORM, "HMAC verified OK.\n");
            }
        }
      else
        {
          if (check_tlv_unknown_critical(type, length) < 0)
            {
              return(-1);
            }
        }
      location += tlv_length_to_parameter_length(length);
    }
  /* if we get here, no valid signature has been found */
  return(-1);
}

int hip_handle_close(__u8 *buff, hip_assoc *hip_a)
{
  int err = 0;
  int is_ack = (((hiphdr*)buff)->packet_type == CLOSE_ACK);
  __u32 nonce, saved_nonce;

  /* CLOSE_ACK is only accepted in state CLOSING or CLOSED */
  if (is_ack && (hip_a->state != CLOSING) && (hip_a->state != CLOSED))
    {
      log_(WARN, "CLOSE_ACK packet not accepted in state=%d.\n",
           hip_a->state);
      return(-1);
      /* CLOSE is only accepted in states ESTABLISHED, CLOSING, CLOSED
       */
    }
  else if (!is_ack && (hip_a->state != ESTABLISHED) &&
           (hip_a->state != CLOSING) && (hip_a->state != CLOSED) &&
           (hip_a->state != R2_SENT))
    {
      log_(WARN, "CLOSE packet not accepted in state=%d.\n",
           hip_a->state);
      return(-1);
    }
  if (hip_parse_close(buff, hip_a, &nonce) < 0)
    {
      log_(WARN, "Error while processing CLOSE%s, dropping.\n",
           is_ack ? "_ACK" : "");
      /* stay in the same state */
      return(-1);
    }
  clear_retransmissions(hip_a);
#ifdef __MACOSX__
  if (hip_a->ipfw_rule > 0)
    {
      del_divert_rule(hip_a->ipfw_rule);
      hip_a->ipfw_rule = 0;
    }
#endif
  if (!is_ack)         /* respond with CLOSE_ACK */
    {
      if ((err = hip_send_close(hip_a, TRUE)) > 0)
        {
          log_(NORM, "Sent CLOSE_ACK (%d bytes)\n", err);
        }
      else
        {
          log_(WARN, "Failed to send CLOSE_ACK: %s.\n",
               strerror(errno));
        }
    }
  else           /* check CLOSE_ACK echo response */
    {
      if (!hip_a->opaque)
        {
          log_(WARN, "CLOSE_ACK received but nonce has already "
               "been freed, dropping.");
          return(-1);
        }
      memcpy(&saved_nonce, hip_a->opaque->opaque_data, sizeof(__u32));
      if (nonce != saved_nonce)
        {
          log_(WARN, "CLOSE_ACK echo response did not match ");
          log_(NORM, "echo request.\n");
          return(-1);
        }
      /* ACK successful, discard state and go to UNASSOCIATED.
       * SAs have already been deleted upon transition to CLOSED or
       * CLOSING.
       */
      log_hipa_fromto(QOUT, "Close completed (received ack)",
                      hip_a, TRUE, TRUE);
      set_state(hip_a, UNASSOCIATED);
      free_hip_assoc(hip_a);
      return(0);
    }

  /* In the HIP state diagram, in ESTABLISHED we do not discard state,
   * but in the packet processing section of the draft, we see that
   * new data packets need to trigger new exchanges -- so here we
   * proceed with the deletes. */
  err = 0;
  set_state(hip_a, CLOSED);
  log_hipa_fromto(QOUT, "Close completed (sent ack)",
                  hip_a, TRUE, TRUE);
  err = delete_associations(hip_a, 0, 0);
  return(err);
}

int hip_parse_notify(__u8 *data,
                     hip_assoc *hip_a,
                     __u16 *code,
                     __u8 **nd,
                     __u16 *nd_len)
{
  hiphdr *hiph;
  int location, len, data_len;
  int type, length, last_type = 0;
  tlv_head *tlv;
  tlv_notify *notify;

  location = 0;
  hiph = (hiphdr*) &data[location];
  data_len = location + ((hiph->hdr_len + 1) * 8);
  location += sizeof(hiphdr);

  while (location < data_len)
    {
      tlv = (tlv_head*) &data[location];
      type = ntohs(tlv->type);
      length = ntohs(tlv->length);
      if (check_tlv_type_length(type, length, last_type,
                                "NOTIFY") < 0)
        {
          return(-1);
        }
      else
        {
          last_type = type;
        }

      if (type == PARAM_NOTIFY)
        {
          notify = (tlv_notify*)tlv;
          *code = ntohs(notify->notify_type);
          if (length > (sizeof(tlv_notify) - 4))
            {
              *nd_len = length - (sizeof(tlv_notify) - 4);
              if ((*nd_len > data_len) || (*nd_len < 1))
                {
                  log_(WARN,"Bad notify data length:%d\n",
                       *nd_len);
                  *nd_len = 0;
                  return(-1);
                }
              *nd = notify->notify_data;
            }
        }
      else if (type == PARAM_HIP_SIGNATURE)
        {
          if ((hip_a == NULL) || (hip_a->peer_hi == NULL))
            {
              log_(WARN, "Received signature parameter "
                   "without any Host Identity context for "
                   "verification.\n");
              return(-1);
            }
          len = eight_byte_align(location);
          hiph->checksum = 0;
          hiph->hdr_len = (len / 8) - 1;
          if (validate_signature(data, len, tlv,
                                 hip_a->peer_hi->dsa,
                                 hip_a->peer_hi->rsa) < 0)
            {
              log_(WARN, "Invalid signature.\n");
              /* Don't send NOTIFY responding to a NOTIFY
               * (this might create a NOTIFY war) */
              if (OPT.permissive)
                {
                  return(0);
                }
              else
                {
                  return(-1);
                }
            }
          else
            {
              return(0);
            }
        }
      else
        {
          if (check_tlv_unknown_critical(type, length) < 0)
            {
              return(-1);
            }
        }
      location += tlv_length_to_parameter_length(length);
    }
  /* if we get here, no valid signature has been found */
  return(-1);
}

int hip_handle_notify(__u8 *buff, hip_assoc *hip_a)
{
  int err = 0;
  __u16 code = 0, data_len = 0;
  __u8* data = NULL;
  /* NOTIFY accepted in all states? */
  if (!hip_a)
    {
      log_(WARN, "Received NOTIFY with no association.\n");
      return(-1);
    }

  if (hip_parse_notify(buff, hip_a, &code, &data, &data_len) < 0)
    {
      log_(WARN, "Error while processing NOTIFY, dropping.\n");
      /* stay in the same state */
      return(-1);
    }
  /* Do not change state based on NOTIFY... so assuming we don't want
   * to clear retransmissions here. */
  /* clear_retransmissions(hip_a); */
  log_(WARN, "Received NOTIFY from %s: ", logaddr(HIPA_SRC(hip_a)));

  switch (code)
    {
    case NOTIFY_UNSUPPORTED_CRITICAL_PARAMETER_TYPE:
      log_(NORM, "Unsupported critical parameter type.\n");
      break;
    case NOTIFY_INVALID_SYNTAX:
      log_(NORM, "Invalid syntax.\n");
      break;
    case NOTIFY_NO_DH_PROPOSAL_CHOSEN:
      log_(NORM, "No acceptable DH group ID proposed.\n");
      break;
    case NOTIFY_INVALID_DH_CHOSEN:
      log_(NORM, "Invalid DH group ID chosen.\n");
      break;
    case NOTIFY_NO_HIP_PROPOSAL_CHOSEN:
      log_(NORM, "No acceptable HIP Transform was proposed.\n");
      break;
    case NOTIFY_INVALID_HIP_TRANSFORM_CHOSEN:
      log_(NORM, "Invalid HIP Transform chosen.\n");
      break;
    case NOTIFY_NO_ESP_PROPOSAL_CHOSEN:
      log_(NORM, "No acceptable ESP Transform was proposed.\n");
      break;
    case NOTIFY_INVALID_ESP_TRANSFORM_CHOSEN:
      log_(NORM, "Invalid ESP Transform chosen.\n");
      break;
    case NOTIFY_AUTHENTICATION_FAILED:
      log_(NORM, "Authentication (signature) failed.\n");
      break;
    case NOTIFY_CHECKSUM_FAILED:
      log_(NORM, "Checksum failed.\n");
      break;
    case NOTIFY_HMAC_FAILED:
      log_(NORM, "Authentication (HMAC) failed.\n");
      break;
    case NOTIFY_ENCRYPTION_FAILED:
      log_(NORM, "Failed to decrypt the ENCRYPTED TLV.\n");
      break;
    case NOTIFY_INVALID_HIT:
      log_(NORM, "HI does not validate HIT.\n");
      break;
    case NOTIFY_BLOCKED_BY_POLICY:
      log_(NORM, "Blocked by policy.\n");
      break;
    case NOTIFY_SERVER_BUSY_PLEASE_RETRY:
      log_(NORM, "Server busy -- please retry.\n");
      break;
    case NOTIFY_LOCATOR_TYPE_UNSUPPORTED:
      log_(NORM, "Unsupported locator type.\n");
      break;
    case NOTIFY_I2_ACKNOWLEDGEMENT:
      log_(NORM, "I2 received but queued for later processing.\n");
      break;
    case NOTIFY_LOSS_DETECT:
      log_(NORM, "loss detected.\n");
      return(handle_notify_loss(data, data_len));
      break;
    default:
      log_(NORM, "Unknown notify code: %d\n", code);
      break;
    }

  if (data_len > 0)
    {
      log_(NORM, "NOTIFY data: ");
      print_hex(data, data_len);
      log_(NORM, "\n");
    }

  /*
   * This was deprecated in draft-06: do not change state based on
   * a received NOTIFY packet.
   */
#if 0
  /* NOTIFY is in response to a packet, assume request has failed. */
  if ((hip_a->state == I1_SENT) || (hip_a->state == I2_SENT) ||
      (hip_a->state == R2_SENT))
    {
      log_(WARN, "Association with %s moving from state %d to ",
           logaddr((hip_a->state == R2_SENT) ?
                   HIPA_SRC(hip_a) : HIPA_DST(hip_a)), hip_a->state);
      log_(NORM, "E_FAILED because of received NOTIFY.\n");
      clear_retransmissions(hip_a);
      set_state(hip_a, E_FAILED);
    }
#endif

  return(err);
}

int hip_handle_BOS(__u8 *data, struct sockaddr *src)
{
  hiphdr *hiph;
  hi_node *peer_hi;
  int location, len, err = 0;
  tlv_head *tlv;


  hiph = (hiphdr *) data;

  /* is HIT already known? */
  peer_hi = find_host_identity(peer_hi_head, hiph->hit_sndr);
  if (peer_hi)
    {
      log_(NORMT, "Received BOS from %s, with a HIT ", logaddr(src));
      log_(NORM,  "that we already have.\n");
      return(0);
    }
  peer_hi = NULL;
  location = sizeof(hiphdr);

  /* validate the packet first */
  /* Host Identity */
  tlv = (tlv_head*) &data[location];
  if (ntohs(tlv->type) != PARAM_HOST_ID)
    {
      log_(NORM, "Expected HOST_ID in BOS, dropping.\n");
      return(-1);
    }

  if (handle_hi(&peer_hi, &data[location]) < 0)
    {
      log_(NORM, "Problem with HOST_ID in BOS, dropping.\n");
      return(-1);
    }
  if (!validate_hit(hiph->hit_sndr, peer_hi))
    {
      log_(WARN, "HI in BOS does not match sender's HIT\n");
      if (!OPT.permissive)
        {
          err = -1;
        }
      goto bos_cleanup;
    }
  else
    {
      log_(NORM, "HI in BOS validates the sender's HIT.\n");
    }

  /* signature */
  location += tlv_length_to_parameter_length(ntohs(tlv->length));
  tlv = (tlv_head*) &data[location];
  if (ntohs(tlv->type) != PARAM_HIP_SIGNATURE)
    {
      log_(NORM, "Expected SIGNATURE in BOS, dropping.\n");
      err = -1;
      goto bos_cleanup;
    }
  len = eight_byte_align(location);
  hiph->checksum = 0;
  hiph->hdr_len = (len / 8) - 1;
  if (validate_signature( data, location, tlv, peer_hi->dsa,
                          peer_hi->rsa) < 0)
    {
      log_(WARN, "Invalid signature in BOS.\n");
      err = -1;
      goto bos_cleanup;
    }
  else           /* adopt the new HIT into our peer list */
    {
      log_(NORM, "BOS signature is good. Adding HIT from %s.\n",
           logaddr(src));
      add_peer_hit(hiph->hit_sndr, src);
      err = 0;
    }
bos_cleanup:
  free_hi_node(peer_hi);
  return(err);
}

int hip_handle_CER(__u8 *data, hip_assoc *hip_a)
{
  log_(NORM, "The CER packet has not been implemented.\n");
  return(0);
}

/*
 * function validate_signature()
 *
 * in:		data = data to sign
 *              data_len = bytes of data to sign
 *              tlv = sig tlv of signature to verify
 *
 *
 * out:		Returns 0 if signature is correct, -1 if incorrect or error.
 */
int validate_signature(const __u8 *data, int data_len, tlv_head *tlv,
                       DSA *dsa, RSA *rsa)
{
  int err;
  SHA_CTX c;
  unsigned char md[SHA_DIGEST_LENGTH];
  DSA_SIG dsa_sig;
  int length, sig_len;
  tlv_hip_sig *sig = (tlv_hip_sig*)tlv;
  __u8 alg;

  length = ntohs(sig->length);
  alg = sig->algorithm;

  switch (alg)
    {
    case HI_ALG_DSA:
      if (!dsa)
        {
          log_(WARN, "validate_signature(): ");
          log_(NORM, "no DSA context!\n");
          return(-1);
        }
      if (length != (1 + HIP_DSA_SIG_SIZE))
        {
          log_(WARN, "Invalid DSA signature size of %d ",
               length);
          log_(NORM, "(should be %d).\n",
               1 + HIP_DSA_SIG_SIZE);
          if (!OPT.permissive)
            {
              return(-1);
            }
        }
      break;
    case HI_ALG_RSA:
      if (!rsa)
        {
          log_(WARN, "validate_signature(): ");
          log_(NORM, "no RSA context!\n");
          return(-1);
        }
      if (length > (1 + RSA_size(rsa)))
        {
          log_(WARN, "Invalid RSA signature size of %d ",
               length);
          log_(NORM, "(should be %d).\n",
               1 + RSA_size(rsa));
          if (!OPT.permissive)
            {
              return(-1);
            }
        }
      break;
    default:
      log_(WARN, "Invalid signature algorithm.\n");
      return(-1);
    }
  sig_len = length - 1;

  /* calculate SHA1 hash of the HIP message */
  SHA1_Init(&c);
  SHA1_Update(&c, data, data_len);
  SHA1_Final(md, &c);

  /* for debugging, print out md or signature */
  log_(NORM, "SHA1: ");
  print_hex(md, SHA_DIGEST_LENGTH);
  log_(NORM, "\n");

  switch (alg)
    {
    case HI_ALG_DSA:
      /* build the DSA structure */
      dsa_sig.r = BN_bin2bn(&sig->signature[1], 20, NULL);
      dsa_sig.s = BN_bin2bn(&sig->signature[21], 20, NULL);
      /* verify the DSA signature */
      err = DSA_do_verify(md, SHA_DIGEST_LENGTH, &dsa_sig, dsa);
      BN_free(dsa_sig.r);
      BN_free(dsa_sig.s);
      break;
    case HI_ALG_RSA:
      /* verify the RSA signature */
      err = RSA_verify(NID_sha1, md, SHA_DIGEST_LENGTH,
                       sig->signature, sig_len, rsa);
      break;
    default:
      err = -1;
      break;
    }

  if (err < 0)
    {
      log_(WARN, "Error with verifying %s signature.\n",
           HI_TYPESTR(alg));
      return(-1);
    }
  else if (err == 0)
    {
      log_(WARN, "Incorrect %s signature found.\n", HI_TYPESTR(alg));
      log_(NORM, "Signature text (len=%d): ", sig_len);
      print_hex(sig->signature, sig_len);
      log_(NORM, "\n");
      return(-1);
    }
  else
    {
      log_(NORM, "%s HIP signature is good.\n", HI_TYPESTR(alg));
    }
  return(0);
}

/*
 * function validate_hmac()
 *
 * in:		data     = data to hash
 *              data_len = number of bytes of data to hash
 *              hmac     = the hmac sent in the packet, to verify
 *              hmac_len = length of the above hmac
 *              key      = key used for the HMAC keyed hashing algorithm
 *              key_len  = length of the above key
 *
 * out:		Returns 0 if HMAC is correct, -1 if incorrect or error.
 */
int validate_hmac(const __u8 *data, int data_len, __u8 *hmac, int hmac_len,
                  __u8 *key, int type)
{
  unsigned char hmac_md[EVP_MAX_MD_SIZE] = {0};
  unsigned int hmac_md_len = EVP_MAX_MD_SIZE;
  int key_len = auth_key_len(type);

  switch (type)
    {
    case ESP_AES_CBC_HMAC_SHA1:
    case ESP_3DES_CBC_HMAC_SHA1:
    case ESP_BLOWFISH_CBC_HMAC_SHA1:
    case ESP_NULL_HMAC_SHA1:
      HMAC(   EVP_sha1(),
              key, key_len,
              data, data_len,
              hmac_md, &hmac_md_len  );
      break;
    case ESP_3DES_CBC_HMAC_MD5:
    case ESP_NULL_HMAC_MD5:
      HMAC(   EVP_md5(),
              key, key_len,
              data, data_len,
              hmac_md, &hmac_md_len  );
      break;
    }
  /*
   * note that hmac_md_len may be < hmac_len,
   * i.e. for MD5 hmac_md_len==16
   */
  /* compare lower bits of received HMAC versus calculated HMAC
   * for MD5, this is the lower 128 bits; for SHA-1 it's 160-bits */
  if ((memcmp(&hmac[hmac_len - hmac_md_len], hmac_md,
              hmac_md_len) == 0))
    {
      return(0);
    }
  log_(WARN, "computed hmac: (%d) ", hmac_md_len);
  print_hex(hmac_md, hmac_md_len);
  log_(NORM, "\n    received hmac: (%d) ", hmac_len);
  print_hex(hmac, hmac_len);
  log_(NORM, "\n");
  return(-1);
}

/*
 * check_if_my_hit()
 *
 * in:		hit = the HIT to check
 *
 * out:		returns NULL if HIT is not known, pointer to HI otherwise
 *
 * Checks if the specified HIT corresponds to one of this machine's
 * Host Identities, and returns a pointer to it. Allows for NULL
 * HIT in opportunisitc mode (then the preferred HI is stored.)
 */
hi_node *check_if_my_hit(hip_hit *hit)
{
  hi_node *my_host_id = NULL;

  if ((OPT.opportunistic) &&
      (memcmp(hit, &zero_hit, sizeof(hip_hit)) == 0))
    {
      /* NULL HIT accepted with opportunistic */
      my_host_id = get_preferred_hi(my_hi_head);
    }
  else
    {
      /* lookup HIT in my HIT list */
      my_host_id = find_host_identity(my_hi_head, *hit);
    }

  return(my_host_id);
}

/*
 * handle_transforms()
 *
 * in:		hip_a = hip association where chosen transform is stored
 *                      and available_transforms bit mask resides
 *              transforms = pointer to a list of transforms
 *              length = byte length of transform list
 *
 * out:		Returns 0 if a transform was found, -1 on error.
 *              Stores the best transform into the hip association.
 *              Note that the signature should be verified beforehand, since
 *              hip_a is modified.
 */
int handle_transforms(hip_assoc *hip_a, __u16 *transforms, int length, int esp)
{
  __u16 *transform_id_packet;
  int transforms_left, offset;
  __u16 transform_id;
  __u16 *chosen = esp ? &hip_a->esp_transform : &hip_a->hip_transform;

  offset = esp ? ESP_OFFSET : 0;
  transforms_left = length / sizeof(__u16);
  transform_id_packet = transforms;
  *chosen = 0;
  if (transforms_left >= SUITE_ID_MAX)
    {
      log_(WARN, "Warning: There are %d transforms present but the "
           "maximum number is %d.\n",
           transforms_left, SUITE_ID_MAX - 1);
      /* continue to read the transforms... */
    }

  for (; (transforms_left > 0); transform_id_packet++,
       transforms_left--)
    {
      transform_id = ntohs(*transform_id_packet);

      if ((transform_id <= RESERVED) ||
          (transform_id >= SUITE_ID_MAX))
        {
          log_(WARN, "Ignoring invalid transform (%d).\n",
               transform_id);
          continue;
        }
      if ((hip_a->available_transforms >>
           (transform_id + offset)) & 0x1)
        {
          *chosen = transform_id;
          break;
        }
    }
  if (*chosen == 0)
    {
      log_(
        WARN,
        "Couldn't find a suitable HIP transform.  This error could indicate that hip.conf was not successfully loaded.\n");
      if (OPT.permissive)             /* AES is mandatory */
        {
          log_(WARN, "Continuing using AES.\n");
          *chosen = ESP_AES_CBC_HMAC_SHA1;
        }
      else
        {
          return(-1);
        }
    }
  return(0);
}

/*
 * handle_dh()
 *
 *
 * Parse a Diffie-Hellman parameter, storing its group ID into g and
 * the public key into hip_a->peer_dh or dh
 */
int handle_dh(hip_assoc *hip_a, const __u8 *data, __u8 *g, DH *dh)
{
  __u8 g_id, g_id2;
  int len, len2;
  unsigned char *pub_key, *pub;
  tlv_diffie_hellman *tlv_dh;
  tlv_diffie_hellman_pub_value *pub_val2;

  tlv_dh = (tlv_diffie_hellman*) data;

  g_id = tlv_dh->group_id;
  *g = g_id;
  if ((g_id <= DH_RESERVED) ||
      (g_id >= DH_MAX))
    {
      log_(WARN, "DH group unsupported %d\n", g_id);
      return(-1);
    }

  len = ntohs(tlv_dh->pub_len);
  if (len > (ntohs(tlv_dh->length) - 3))
    {
      log_(WARN, "Error: public key length specified (%d) was longer"
           " than TLV length!\n", len);
      return(-1);
    }
  /* DH_size = BN_num_bytes(dh->p) */
  if (len != dhprime_len[g_id])
    {
      log_(WARN, "Warning: public key len = %d, ", len);
      log_(NORM, "expected %d for this group id (%d)\n",
           dhprime_len[g_id], g_id);
    }
  pub = tlv_dh->pub;

  /* are there two DH values? */
  if ((ntohs(tlv_dh->length) - 3) > len)
    {
      pub_val2 = (tlv_diffie_hellman_pub_value*)&tlv_dh->pub[len];
      g_id2 = pub_val2->group_id;
      if ((g_id2 <= DH_RESERVED) ||
          (g_id2 >= DH_MAX))
        {
          log_(WARN, "Warning: DH group of second DH value is "
               "unsupported %d\n", g_id2);
          goto decode_dh;               /* use first DH value */
        }
      if (g_id >= g_id2)
        {
          goto decode_dh;               /* use first DH value */
        }
      /* use second DH value, it is stronger than the first */
      len2 = ntohs(pub_val2->pub_len);
      if ((6 + len + len2) > ntohs(tlv_dh->length))
        {
          log_(WARN, "Error: second public key length specified "
               "(%d) was longer than TLV length!\n", len);
          return(-1);
        }
      g_id = g_id2;
      len = len2;
      pub = pub_val2->pub;
    }
decode_dh:
  /* g_id, len, pub are set before this */
  pub_key = malloc(len);
  memcpy(pub_key, pub, len);

#ifndef HIP_VPLS
  log_(NORM, "Got DH public value of len %d: 0x", len);
  print_hex(pub_key, len);
  log_(NORM, "\n");
#endif

  /* store the public key in hip_a->peer_dh */
  if (dh == NULL)
    {
      if (hip_a->peer_dh)
        {
          DH_free(hip_a->peer_dh);
        }
      hip_a->peer_dh = DH_new();
      hip_a->peer_dh->g = BN_new();
      BN_set_word(hip_a->peer_dh->g, dhgen[g_id]);
      hip_a->peer_dh->p = BN_bin2bn(dhprime[g_id],
                                    dhprime_len[g_id], NULL);
      hip_a->peer_dh->pub_key = BN_bin2bn(pub_key, len, NULL);
      /* or return the public key */
    }
  else
    {
      dh->g = BN_new();
      BN_set_word(dh->g, dhgen[g_id]);
      dh->p = BN_bin2bn(dhprime[g_id], dhprime_len[g_id], NULL);
      dh->pub_key = BN_bin2bn(pub_key, len, NULL);
    }

  free(pub_key);
  return(0);
}

int handle_cert(hip_assoc *hip_a, const __u8 *data)
{
  int len;
  tlv_cert *cert;
  char cert_buf[MAX_CERT_LEN];

  hi_node *peer_hi;
  peer_hi = hip_a->peer_hi;
  if (!peer_hi)
    {
      return(-1);
    }
  memset(cert_buf, '\0', sizeof(cert_buf));
  cert = (tlv_cert*) data;
  len = ntohs(cert->length) - 4;
  memcpy(cert_buf, cert->certificate, len);
#ifdef HIP_VPLS
  len = hipcfg_verifyCert(cert_buf, peer_hi->hit);
  if (len == 1)
    {
      log_(NORM, "validated certificate with url: %s\n", cert_buf);
      return(0);
    }
#endif
  log_(WARN, "Fail to validate certificate with url: %s\n", cert_buf);
  return(-1);
}

/*
 * function handle_hi()
 *
 * in:		hi_p = pointer to pointer that will store new Host ID
 *              data  = pointer to start of HI TLV
 *
 * out:		*hi_p is created or modified,
 *              (*hi_p)->dsa or (*hi_p)->rsa must not exist, and is created
 *              Returns length of HI TLV used, -1 if error.
 *
 * Reads HI TLV into a hi_node structure.
 */
int handle_hi(hi_node **hi_p, const __u8 *data)
{
  /* Get received host id into a hi_p
   * value          number of bytes
   * type/length    4
   * HI length      2
   * DI type        4 bits
   * DI length     12 bits
   * RDATA header   4
   */

  int length, hi_length, di_length;
  char di_type;
  tlv_host_id *tlv = (tlv_host_id*)data;
  __u32 hi_hdr;
  __u8 alg;

  length = ntohs(tlv->length);
  hi_length = ntohs(tlv->hi_length);
  di_type = ntohs(tlv->di_type_length) >> 12;       /* 4 bits type */
  di_type &= 0x000F;
  di_length = ntohs(tlv->di_type_length) & 0x0FFF;       /* 12 bits length */

  memcpy(&hi_hdr, tlv->hi_hdr, 4);
  hi_hdr = ntohl(hi_hdr);
  alg = hi_hdr & 0xFF;       /* get algorithm from last byte of RDATA header */
  hi_length -= 4;               /* subtract RDATA length from HI length */
  length -= 8;                  /* subtract TLV fields and RDATA length */

  return(key_data_to_hi(  &data[sizeof(tlv_host_id)],
                          alg, hi_length, (__u8)di_type, di_length,
                          hi_p, length ));
}

int handle_acks(hip_assoc *hip_a, tlv_ack *ack)
{
  __u32 *p_ack, ack_update_id;
  int length, ret = FALSE;

  /* We may receive multiple ACKs, search them
   * for the update id matching hip_a->rekey->update_id */
  p_ack = &ack->peer_update_id;
  for (length = ntohs(ack->length);
       length > 0;
       p_ack++, length -= sizeof(__u32))
    {
      ack_update_id = ntohl(*p_ack);
      /* check if ACK corresponds to a previously sent UPDATE */
      if (hip_a->rekey &&
          (ack_update_id == hip_a->rekey->update_id))
        {
          log_(NORM, "Update id=0x%x has been acked.\n",
               ack_update_id);
          ret = TRUE;
          /* continue parsing so that ignored IDs are logged */
        }
      else
        {
          log_(NORM, "Ignoring unknown ID (0x%x) in ACK.\n",
               ack_update_id);
        }
    }
  return(ret);
}

/*
 * build rekeying state
 */
int handle_esp_info(tlv_esp_info *ei, __u32 spi_out, struct rekey_info *rk)
{
  __u32 old_spi, new_spi;

  old_spi = ntohl(ei->old_spi);
  new_spi = ntohl(ei->new_spi);

  /* add a new SPI/SA only */
  if ((old_spi == 0) && (new_spi > 0))
    {
      log_(NORM, "New SA requested for SPI 0x%x.\n", new_spi);
      log_(WARN, "Warning: creating additional new SAs is "
           "currently unsupported.\n");
      /* XXX May add a new SPI here, but need a way to
       *      keep track of SPIs so SA can be later deleted.
       *      Also, if this multi-homed host uses the SA as
       *      a fallback, it is pointless to create without
       *      a corresponding SPD rule.                     */
      return(0);
      /* Gratuitous */
    }
  else if (old_spi == new_spi)
    {
      log_(NORM, "Gratuitous ESP_INFO: keeping old SPI of 0x%x.\n",
           new_spi);
      rk->keymat_index = ntohs(ei->keymat_index);
      rk->new_spi = new_spi;
      return(0);
      /* Rekey with unknown SPI */
    }
  else if (old_spi != spi_out)
    {
      log_(WARN, "Old SPI in ESP_INFO (0x%x) is unknown.\n", old_spi);
      return(-1);
      /* Deprecating SA */
    }
  else if (new_spi == 0)
    {
      log_(NORM, "Request to deprecate SA with SPI 0x%x\n", old_spi);
      log_(WARN, "Warning: deprecating SAs is currently "
           "unsupported.\n");
      /* XXX Deprecate all locators uniquely bound to this SPI */
      /* change current SA */
    }
  else
    {
      rk->keymat_index = ntohs(ei->keymat_index);
      rk->new_spi = new_spi;
      log_(NORM, "Rekeying due to new SPI of 0x%x.\n", new_spi);
    }
  return(0);
}

/*
 * handle_locators()
 *
 * Following HIP packet parsing, handle the locator TLVs contained in the HIP
 * packet.
 */
int handle_locators(hip_assoc *hip_a,
                    locator **locators,
                    int num,
                    struct sockaddr *src,
                    __u32 new_spi)
{
  int i, preferred, first;
  locator *loc;
  struct sockaddr_storage ss_addr;
  struct sockaddr *addr;
  sockaddr_list *l, *peer_list;
  __u8 *p_addr;
  __u32 spi;
  struct timeval now;

  memset(&ss_addr, 0, sizeof(struct sockaddr_storage));
  addr = (struct sockaddr*)&ss_addr;
  first = TRUE;
  gettimeofday(&now, NULL);

  for (i = 0; i < num; i++)
    {
      loc = locators[i];
      if (loc->traffic_type == LOCATOR_TRAFFIC_TYPE_SIGNALING)
        {
          log_(WARN, "Warning: Ignoring signaling locator.\n");
          continue;
        }
      else if ((loc->traffic_type != LOCATOR_TRAFFIC_TYPE_BOTH) &&
               (loc->traffic_type != LOCATOR_TRAFFIC_TYPE_DATA))
        {
          log_(WARN, "Warning Ignoring unknown locator traffic ");
          log_(NORM, "type: %d.\n", loc->traffic_type);
          continue;
        }
      if ((loc->locator_type == LOCATOR_TYPE_IPV6) &&
          (loc->locator_length == 4))
        {
          p_addr = &loc->locator[0];
          spi = new_spi;
        }
      else if ((loc->locator_type == LOCATOR_TYPE_SPI_IPV6) &&
               (loc->locator_length == 5))
        {
          memcpy(&spi, &loc->locator[0], 4);
          spi = ntohl(spi);
          p_addr = &loc->locator[4];
        }
      else
        {
          /* send NOTIFY whether or not preferred; only include
           * maximum 20 bytes of locators to prevent overflows */
          log_(WARN, "Locator type %d unsupported (length %d)\n",
               loc->locator_type, loc->locator_length);
          hip_send_notify(hip_a, NOTIFY_LOCATOR_TYPE_UNSUPPORTED,
                          loc->locator,
                          (loc->locator_length <= 5) ?
                          4 * loc->locator_length : 20);
          continue;
        }

      if ((new_spi > 0) && (new_spi != spi))
        {
          log_(WARN, "SPIs in ESP_INFO and LOCATOR parameters "
               "do not match (0x%x, 0x%x)\n", new_spi, spi);
          continue;
        }

      /*
       * Read in address from LOCATOR
       */
      /* get address and check validity */
      if (IN6_IS_ADDR_V4MAPPED(
            (struct in6_addr*)p_addr))
        {
          addr->sa_family = AF_INET;
          memcpy(SA2IP(addr), p_addr + 12, SAIPLEN(addr));
          if (IN_MULTICAST(*(SA2IP(addr))))
            {
              continue;
            }
          if (((struct sockaddr_in*)addr)->sin_addr.s_addr
              == INADDR_BROADCAST)
            {
              continue;
            }
        }
      else
        {
          unsigned char *p = SA2IP(addr);
          addr->sa_family = AF_INET6;
          memcpy(SA2IP(addr), p_addr, SAIPLEN(addr));
          if (IN6_IS_ADDR_MULTICAST((struct in6_addr*)p))
            {
              continue;
            }
          /* IPv6 doesn't have broadcast addresses */
        }

      /* only check preferred (P) bit for
       * the first address in LOCATOR */
      preferred = FALSE;
      if (first && (loc->reserved & LOCATOR_PREFERRED))
        {
          preferred = TRUE;
        }
      first = FALSE;

      /* check the new preferred address against the source address
       * of the packet */
      if (src && preferred)
        {
          if ((!hip_a->from_via) &&
              ((addr->sa_family != src->sa_family) ||
               (memcmp(SA2IP(addr), SA2IP(src),
                       SAIPLEN(src)))))
            {
              log_(WARN, "Warning: source address is %s and ",
                   logaddr(src));
              log_(NORM, "new preferred LOCATOR is %s.\n",
                   logaddr(addr));
            }
          else if (src->sa_family == AF_INET)
            {
              /* addresses are equal, copy the port number
               * so UDP will work */
              ((struct sockaddr_in *)addr)->sin_port =
                ((struct sockaddr_in *)src)->sin_port;
              /* TODO: IPv6 UDP here */
            }
        }

      /* address already may already exists in peer list */
      peer_list = &hip_a->peer_hi->addrs;
      l = add_address_to_list(&peer_list, addr, 0);
      if (!l)
        {
          log_(WARN, "Unable to add new address (%s) to " \
               "peer list.\n", logaddr(addr));
          continue;
        }
      else if (preferred && (l == peer_list))
        {
          /* not a new preferred address */
          log_(NORM, "Preferred address %s for SPI=0x%x remains "
               "the same.\n", logaddr(addr), spi);
          continue;
        }
      l->status = UNVERIFIED;
      l->lifetime = ntohl(loc->locator_lifetime);
      l->creation_time.tv_sec = now.tv_sec;           /* update creation time */
      l->creation_time.tv_usec = now.tv_usec;
      log_(NORM, "New %saddress %s for SPI=0x%x\n",
           (preferred) ? "preferred " : "", logaddr(addr), spi);
      /* handle new preferred address */
      if (preferred && (l != peer_list))
        {
          l->preferred = TRUE;               /* this flags a readdress */
        }
      else if (!preferred)
        {
          l->preferred = FALSE;
        }
    }

  /* mark all unlisted addresses for this peer as deprecated */
  for (l = &hip_a->peer_hi->addrs; l; l = l->next)
    {
      if (l->creation_time.tv_sec != now.tv_sec)
        {
          l->status = DEPRECATED;
        }
    }

  return(0);
}

/*
 * complete_base_exchange()
 *
 * in:		hip_a = association containing all the necessary data
 *
 * Build incoming and outgoing SAs and display a message about
 * completing a successful base exchange.
 */
int complete_base_exchange(hip_assoc *hip_a)
{
  int err = 0;
  struct sockaddr_storage src_hit, dst_hit;

  log_(NORM, "---------- HIP exchange complete. ----------\n");
  log_sa_info(hip_a);

  hit_to_sockaddr(SA(&src_hit), hip_a->hi->hit);
  hit_to_sockaddr(SA(&dst_hit), hip_a->peer_hi->hit);

  if (hip_sadb_add(hip_a->udp ? 3 : 0, 2,
                   SA(&src_hit), SA(&dst_hit),
                   HIPA_SRC(hip_a), HIPA_DST(hip_a),
                   HIPA_SRC_LSI(hip_a), HIPA_DST_LSI(hip_a),
                   hip_a->spi_out, hip_a->spi_nat,
                   get_key(hip_a, ESP_ENCRYPTION, 0),
                   transform_to_ealg(hip_a->esp_transform),
                   enc_key_len(hip_a->esp_transform),
                   get_key(hip_a, ESP_AUTH, 0),
                   transform_to_aalg(hip_a->esp_transform),
                   auth_key_len(hip_a->esp_transform),
                   HCNF.sa_lifetime)
      < 0)
    {
      err = -1;
      log_(WARN, "Error building outgoing SA: %s.\n",
           strerror(errno));
    }
  if (hip_sadb_add(hip_a->udp ? 3 : 0, 1,
                   SA(&dst_hit), SA(&src_hit),
                   HIPA_DST(hip_a), HIPA_SRC(hip_a),
                   HIPA_DST_LSI(hip_a), HIPA_SRC_LSI(hip_a),
                   hip_a->spi_in, hip_a->spi_nat,
                   get_key(hip_a, ESP_ENCRYPTION, 1),
                   transform_to_ealg(hip_a->esp_transform),
                   enc_key_len(hip_a->esp_transform),
                   get_key(hip_a, ESP_AUTH, 1),
                   transform_to_aalg(hip_a->esp_transform),
                   auth_key_len(hip_a->esp_transform),
                   HCNF.sa_lifetime)
      < 0)
    {
      err = -2;
      log_(WARN, "Error building incoming SA: %s.\n",
           strerror(errno));
    }

  if (!err)
    {
      log_hipa_fromto(QOUT, "Base exchange completed",
                      hip_a, TRUE, TRUE);
    }
  return(err);
}

/*
 * rebuild_sa()
 *
 * in:		hip_a = association containing old addresses, SPIs, keys
 *              newaddr = the new address, or NULL if rekey only
 *              newspi = the new SPI, or zero if readdress only
 *              in = TRUE for incoming, FALSE for outgoing
 *              peer = TRUE if the new address is the peer's, FALSE if we have
 *                     changed addresses
 *
 * A single function to take care of rebuilding an SA and its SPD entry.
 * Handles both readdress and rekey cases.
 */
int rebuild_sa(hip_assoc *hip_a, struct sockaddr *newaddr, __u32 newspi,
               int in, int peer)
{
  __u32 spi;
  int err = 0, direction;
  struct sockaddr_storage src_hit_s, dst_hit_s;
  struct sockaddr *src_new, *dst_new, *src_old, *dst_old;
  struct sockaddr *src_hit = SA(&src_hit_s), *dst_hit = SA(&dst_hit_s);
  struct sockaddr *src_lsi, *dst_lsi;

  if (in)         /* incoming */
    {
      direction = 1;
      spi = hip_a->spi_in;
      hit_to_sockaddr(src_hit, hip_a->peer_hi->hit);
      hit_to_sockaddr(dst_hit, hip_a->hi->hit);
      src_old = HIPA_DST(hip_a);
      dst_old = HIPA_SRC(hip_a);
      src_lsi = HIPA_DST_LSI(hip_a);
      dst_lsi = HIPA_SRC_LSI(hip_a);
    }
  else           /* outgoing */
    {
      direction = 2;
      spi = hip_a->spi_out;
      hit_to_sockaddr(src_hit, hip_a->hi->hit);
      hit_to_sockaddr(dst_hit, hip_a->peer_hi->hit);
      src_old = HIPA_SRC(hip_a);
      dst_old = HIPA_DST(hip_a);
      src_lsi = HIPA_SRC_LSI(hip_a);
      dst_lsi = HIPA_DST_LSI(hip_a);
    }
  if (newaddr && (peer == in))
    {
      src_new = newaddr;
      dst_new = dst_old;
    }
  else if (newaddr)
    {
      src_new = src_old;
      dst_new = newaddr;
    }
  else           /* no change in address */
    {
      src_new = src_old;
      dst_new = dst_old;
    }

  if (hip_sadb_delete(spi) < 0)
    {
      log_(WARN, "Error removing old SA: %s\n",
           strerror(errno));
      err--;
    }

  /* new SPI is used if it is nonzero */
  if (hip_sadb_add(hip_a->udp ? 3 : 0, direction,
                   src_hit, dst_hit, src_new, dst_new, src_lsi, dst_lsi,
                   (newspi > 0) ? newspi : spi,
                   hip_a->spi_nat,
                   get_key(hip_a, ESP_ENCRYPTION, in),
                   transform_to_ealg(hip_a->esp_transform),
                   enc_key_len(hip_a->esp_transform),
                   get_key(hip_a, ESP_AUTH, in),
                   transform_to_aalg(hip_a->esp_transform),
                   auth_key_len(hip_a->esp_transform),
                   HCNF.sa_lifetime)
      < 0)
    {
      err = -1;
      log_(WARN, "Error building new SA: %s.\n",
           strerror(errno));
    }

  hip_a->used_bytes_in = 0;
  hip_a->used_bytes_out = 0;
  return(err);
}

/*
 * rebuild_sa_x2()
 *
 * in:		hip_a = association containing old addresses, SPIs, keys
 *              src_new = the new source address
 *              dst_new = the new destination address
 *              newspi = the new SPI, or zero if readdress only
 *              in = TRUE for incoming, FALSE for outgoing
 *
 * This function takes care of rebuilding an SA
 * when readdress involves a change of address family.
 */
int rebuild_sa_x2(hip_assoc *hip_a, struct sockaddr *src_new,
                  struct sockaddr *dst_new, __u32 newspi, int in)
{
  __u32 spi;
  int err = 0, direction;
  struct sockaddr_storage src_hit_s, dst_hit_s;
  struct sockaddr *src_hit = SA(&src_hit_s), *dst_hit = SA(&dst_hit_s);
  struct sockaddr *src_lsi, *dst_lsi;

  if (in)         /* incoming */
    {
      direction = 1;
      spi = hip_a->spi_in;
      hit_to_sockaddr(src_hit, hip_a->peer_hi->hit);
      hit_to_sockaddr(dst_hit, hip_a->hi->hit);
      src_lsi = HIPA_DST_LSI(hip_a);
      dst_lsi = HIPA_SRC_LSI(hip_a);
    }
  else           /* outgoing */
    {
      direction = 2;
      spi = hip_a->spi_out;
      hit_to_sockaddr(src_hit, hip_a->hi->hit);
      hit_to_sockaddr(dst_hit, hip_a->peer_hi->hit);
      src_lsi = HIPA_SRC_LSI(hip_a);
      dst_lsi = HIPA_DST_LSI(hip_a);
    }

  if (hip_sadb_delete(spi) < 0)
    {
      log_(WARN, "Error removing old outgoing SA: %s\n",
           strerror(errno));
      err--;
    }

  if (hip_sadb_add(hip_a->udp ? 3 : 0, direction,
                   src_hit, dst_hit, src_new, dst_new,
                   src_lsi, dst_lsi,
                   (newspi > 0) ? newspi : spi,
                   hip_a->spi_nat,
                   get_key(hip_a, ESP_ENCRYPTION, in),
                   transform_to_ealg(hip_a->esp_transform),
                   enc_key_len(hip_a->esp_transform),
                   get_key(hip_a, ESP_AUTH, in),
                   transform_to_aalg(hip_a->esp_transform),
                   auth_key_len(hip_a->esp_transform),
                   HCNF.sa_lifetime)
      < 0)
    {
      log_(WARN, "Error building new outgoing SA: %s\n",
           strerror(errno));
      err--;
    }

  hip_a->used_bytes_in = 0;
  hip_a->used_bytes_out = 0;
  return(err);
}

void update_peer_list(hip_assoc *hip_a)
{
  hi_node *peer, *tmp, *prev;
  __u32 lsi_hit;

  /* copy attributes learned from peer's HI back into peer_hi_head */
  peer = find_host_identity(peer_hi_head, hip_a->peer_hi->hit);
  if (VALID_FAM(&peer->lsi) && !VALID_FAM(&hip_a->peer_hi->lsi))
    {
      memcpy(&hip_a->peer_hi->lsi, &peer->lsi, SALEN(&peer->lsi));
    }
  if (peer->size == 0)
    {
      peer->size = hip_a->peer_hi->size;
    }
  if (peer->algorithm_id == 0)
    {
      peer->algorithm_id = hip_a->peer_hi->algorithm_id;
      peer->anonymous = hip_a->peer_hi->anonymous;
      peer->allow_incoming = hip_a->peer_hi->allow_incoming;
      /* could copy public key (RSA, DSA) if desired */
    }
  if ((strlen(peer->name) == 0) && (strlen(hip_a->peer_hi->name) > 0))
    {
      strncpy(peer->name, hip_a->peer_hi->name, sizeof(peer->name));
      peer->name_len = hip_a->peer_hi->name_len;
    }

  if (VALID_FAM(&hip_a->peer_hi->lsi))
    {
      return;
    }
  /* need to fill in LSI */
  prev = NULL;
  for (tmp = peer_hi_head; tmp; prev = tmp, tmp = tmp->next)
    {
      /* search for LSI-only entry bearing the same name */
      if (strcmp(tmp->name, hip_a->peer_hi->name) == 0)
        {
          if (!VALID_FAM(&tmp->lsi))
            {
              continue;
            }
          log_(NORM, "Found LSI %s for this association.\n",
               logaddr(SA(&tmp->lsi)));
          /* fill-in LSI for hip_assoc */
          memcpy( &hip_a->peer_hi->lsi, &tmp->lsi,
                  SALEN(&tmp->lsi));
          /* fill-in LSI for other peer_hi_head entry
           * that has no LSI */
          memcpy( &peer->lsi, &tmp->lsi, SALEN(&tmp->lsi));
          /* phantom entry is no longer needed */
          if (hits_equal(tmp->hit, zero_hit))
            {
              if (tmp == peer_hi_head)
                {
                  peer_hi_head = tmp->next;
                }
              else
                {
                  prev->next = tmp->next;
                }
              free(tmp);
            }
          break;
        }
    }

  if (!VALID_FAM(&hip_a->peer_hi->lsi))
    {
      log_(WARN, "Searched for corresponding LSI but none found.\n");
      lsi_hit = htonl(HIT2LSI(hip_a->peer_hi->hit));
      hip_a->peer_hi->lsi.ss_family = AF_INET;
      memcpy(SA2IP(&hip_a->peer_hi->lsi), &lsi_hit, sizeof(__u32));
      log_(NORM, "Falling back to HIT-based LSI: %s\n",
           logaddr(SA(&hip_a->peer_hi->lsi)));
      memcpy(&peer->lsi, &hip_a->peer_hi->lsi,
             SALEN(&hip_a->peer_hi->lsi));
    }

}

void log_sa_info(hip_assoc *hip_a)
{
  log_(NORMT, "Adding security association:\n\tsrc ip = %s",
       logaddr(HIPA_SRC(hip_a)));
  log_(NORM, " dst ip = %s\n\tSPIs in = 0x%x out = 0x%x\n",
       logaddr(HIPA_DST(hip_a)), hip_a->spi_in, hip_a->spi_out);
}

/*
 * returns -1 if there is a problem with the type or length field
 * also performs some logging
 */
int check_tlv_type_length(int type, int length, int last_type, char *p)
{
  log_(NORM, " %s TLV type = %d length = %d \n", p, type, length);

  /* TLV type strictly defines the order, except for types 2048-4095 */
  /* XXX this should only apply if both lastype and type are within
   *     the range 2048-4095
   */
  if ((last_type > type) &&
      (type >= PARAM_TRANSFORM_LOW) &&
      (type <= PARAM_TRANSFORM_HIGH))
    {
      log_(WARN, "Out of order TLV parameter, (%d > %d) ",
           last_type, type);
      log_(NORM, "malformed %s packet.\n", p);
      return(-1);
    }
  if (!check_tlv_length(type, length))
    {
      log_(WARN, "TLV parameter %d has invalid length %d ",
           type, length);
      log_(NORM, "malformed %s packet.\n", p);
      return(-1);
    }
  return(0);
}

/*
 * returns false if parameter has invalid length
 */
int check_tlv_length(int type, int length)
{
  if ((length < 0) || (length == 0))
    {
      return(FALSE);
    }

  /* some parameters have fixed lengths, enforce them */
  switch (type)
    {
    case PARAM_R1_COUNTER:
    case PARAM_PUZZLE:
      return(length == 12);
    case PARAM_SOLUTION:
    case PARAM_HMAC:
    case PARAM_HMAC_2:
      return(length == 20);
    case PARAM_SEQ:
      return(length == 4);
    /* not checking variable length */
    default:
      return(TRUE);
    }
  return(TRUE);
}

/*
 * check an unknown TLV for the critical bit, returning -1 if critical
 * also performs some logging
 */
int check_tlv_unknown_critical(int type, int length)
{
  log_(NORM,"Unknown TLV type %d, length %d.\n", type, length);

  if ((type & PARAM_CRITICAL_BIT) && (!OPT.permissive))
    {
      log_(WARN, "Unknown TLV has critical bit set, ");
      log_(NORM, "dropping packet.\n");
      return(-1);
    }

  return(0);
}

/*
 * handle_reg_info()
 *
 * Parse registration info received from a registrar in the R1 or UPDATE
 * packets.
 */
int handle_reg_info(hip_assoc *hip_a, const __u8 *data)
{
  tlv_reg_info *info = (tlv_reg_info *) data;
  int length, i, num_regs;
  __u8 *reg_types, lifetime;
  char str[128];

  if (ntohs(info->type) != PARAM_REG_INFO)
    {
      return(-1);
    }
  length = ntohs(info->length);
  num_regs = length - 2;
  reg_types = &(info->reg_type);

  if (!hip_a->regs)
    {
      hip_a->regs = (struct reg_entry *)
                    malloc(sizeof(struct reg_entry));
      if (!hip_a->regs)
        {
          return(-1);
        }
      memset(hip_a->regs, 0, sizeof(struct reg_entry));
      hip_a->regs->reginfos = NULL;
      hip_a->regs->number = 0;
    }
  hip_a->regs->min_lifetime = info->min_lifetime;
  hip_a->regs->max_lifetime = info->max_lifetime;
  lifetime = info->max_lifetime;       /* request the max lifetime */

  for (i = 0; i < num_regs; i++)
    {
      if (regtype_to_string(reg_types[i], str, sizeof(str)) < 0)
        {
          log_(NORM, "Skipping registration type %d: %s\n",
               reg_types[i], str);
          continue;
        }
      log_(NORM,"Registration type %d offered: %s\n",
           reg_types[i], str);
      add_reg_info(hip_a->regs, reg_types[i], REG_OFFERED, lifetime);
    }
  return(0);
}

/*
 * handle_reg_request()
 *
 * As a registrar, handle requests to register from the I2 or UPDATE packets.
 */
int handle_reg_request(hip_assoc *hip_a, const __u8 *data)
{
  tlv_reg_request *req = (tlv_reg_request *)data;
  int i, num_regs, length, state;
  __u8 *reg_types, lifetime;
  char str[128];

  if (ntohs(req->type) != PARAM_REG_REQUEST)
    {
      return(-1);
    }
  length = ntohs(req->length);
  lifetime = req->lifetime;
  num_regs = length - 1;       /* lifetime occupies first byte */
  reg_types = &(req->reg_type);

  /* process canceled registrations here */
  if (lifetime == 0)
    {
      log_(NORM,"Request to cancel registration(s).\n");
      if (!hip_a->regs)
        {
          log_(WARN, "No registrations exist with this peer.\n");
          return(-1);
        }
      for (i = 0; i < num_regs; i++)
        {
          regtype_to_string(reg_types[i], str, sizeof(str));
          log_(NORM,"Registration type %d canceled: %s\n",
               reg_types[i], str);
          add_reg_info(hip_a->regs, reg_types[i],
                       REG_SEND_CANCELLED, 0);
        }
      return(0);
    }

  /* prepare reg_entry structure */
  if (hip_a->regs)
    {
      log_(WARN, "Already have pending registration request(s), "
           "ignoring new registration request(s).\n");
      return(-1);
    }
  hip_a->regs = (struct reg_entry *) malloc(sizeof(struct reg_entry));
  if (!hip_a->regs)
    {
      return(-1);
    }
  hip_a->regs->reginfos = NULL;
  hip_a->regs->number = 0;
  /* as registrar, we enforce min/max lifetimes specified
   * in the conf file */
  if (lifetime < HCNF.min_reg_lifetime)
    {
      lifetime = HCNF.min_reg_lifetime;
    }
  else if (lifetime > HCNF.max_reg_lifetime)
    {
      lifetime = HCNF.max_reg_lifetime;
    }

  for (i = 0; i < num_regs; i++)
    {
      regtype_to_string(reg_types[i], str, sizeof(str));
      log_(NORM,"Registration type %d requested: %s\n",
           reg_types[i], str);

      state = REG_SEND_FAILED;
      if ((reg_types[i] == REGTYPE_RVS) && OPT.rvs)
        {
          state = REG_SEND_RESP;
          log_(NORM, "Registration with Rendezvous Service "
               "accepted.\n");
        }
#ifndef __WIN32__
      else if ((reg_types[i] == REGTYPE_MR) && OPT.mr)
        {
          if (init_hip_mr_client( hip_a->peer_hi->hit,
                                  HIPA_DST(hip_a)) < 0)
            {
              log_(WARN,"Error initializing mobile router "
                   "client\n");
            }
          log_(NORM, "Registration with Mobile Router Service "
               "accepted.\n");
          state = REG_SEND_RESP;
        }
#endif /* !__WIN32__ */
      else               /* Unknown or unsupported type */
        {
          state = REG_SEND_FAILED;
        }

      add_reg_info(hip_a->regs, reg_types[i], state, lifetime);
    }
  return(0);
}

/*
 * handle_reg_response()
 *
 * Parse the registration response from the registrar in the R2 or
 * UPDATE packets.
 */
int handle_reg_response(hip_assoc *hip_a, const __u8 *data)
{
  int i, length, num_regs;
  tlv_reg_response *resp = (tlv_reg_response *)data;
  __u8 *reg_types = &(resp->reg_type);
  char str[128];

  if (ntohs(resp->type) != PARAM_REG_RESPONSE)
    {
      return(-1);
    }
  length = ntohs(resp->length);
  num_regs = length - 1;

  for (i = 0; i < num_regs; i++)
    {
      if (regtype_to_string(reg_types[i], str, sizeof(str)) < 0)
        {
          log_(NORM, "Skipping unknown registration type %d: "
               "%s\n", reg_types[i], str);
          continue;
        }
      if (resp->lifetime == 0)
        {
          log_(NORM, "Registration type %d %s canceled.\n",
               reg_types[i], str);
          if (delete_reg_info(hip_a->regs, reg_types[i]) < 0)
            {
              log_(NORM, "Registration not found.\n");
            }
          else
            {
              log_(NORM, "Registration removed OK.\n");
            }
          continue;
        }
      log_(NORM,"Registration type %d %s succeeded with "
           "lifetime %d.\n", reg_types[i], str, resp->lifetime);

      add_reg_info(hip_a->regs, reg_types[i], REG_GRANTED,
                   resp->lifetime);
    }
  return(0);
}

/*
 * handle_reg_failed()
 *
 * Parse the registration failed response from the registrar.
 */
int handle_reg_failed(hip_assoc *hip_a, const __u8 *data)
{
  tlv_reg_failed *fail = (tlv_reg_failed *)data;
  int i, length, num_regs;
  __u8 *reg_types = &(fail->reg_type);
  struct reg_info *reg;
  char str[128];

  length = ntohs(fail->length);
  num_regs = length - 1;

  for (i = 0; i < num_regs; i++)
    {
      regtype_to_string(reg_types[i], str, sizeof(str));
      for (reg = hip_a->regs->reginfos; reg; reg = reg->next)
        {
          if (reg->type == reg_types[i])
            {
              break;
            }
        }
      if (!reg)
        {
          log_(NORM,
               "Registration type %d %s failed with code %d"
               " and there is no registration state.\n",
               reg_types[i],
               str,
               fail->fail_type);
          continue;
        }
      log_(NORM, "Registration type %d %s failed with failure "
           "code %d.\n", reg_types[i], str, fail->fail_type);
      reg->state = REG_FAILED;
      reg->failure_code = fail->fail_type;
      gettimeofday(&reg->state_time, NULL);
    }
  return(0);
}

/*
 * add_reg_info()
 *
 * Add or update a reg_info structure to the given reg_entry.
 */
int add_reg_info(struct reg_entry *regs, __u8 type, int state, __u8 lifetime)
{
  struct reg_info *reg;

  if (!regs)
    {
      return(-1);
    }

  /* search for existing registration */
  for (reg = regs->reginfos; reg; reg = reg->next)
    {
      if (type == reg->type)
        {
          break;
        }
    }

  /* allocate new reg_info if it doesn't already exist */
  if (!reg)
    {
      reg = (struct reg_info*) malloc(sizeof(struct reg_info));
      if (reg == NULL)
        {
          return(-1);
        }
      memset(reg, 0, sizeof(struct reg_info));
      reg->type = type;
      reg->next = regs->reginfos;           /* link it into the list */
      regs->reginfos = reg;
      regs->number++;
    }
  reg->state = state;
  reg->lifetime = lifetime;
  gettimeofday(&reg->state_time, NULL);
  return(0);
}

/*
 * Remove a reg_info structure from the given reg_entry.
 */
int delete_reg_info(struct reg_entry *regs, __u8 type)
{
  struct reg_info *reg, *prev = NULL;

  if (!regs)
    {
      return(-1);
    }

  /* search for existing registration */
  for (reg = regs->reginfos; reg; reg = reg->next)
    {
      if (type == reg->type)
        {
          break;
        }
      prev = reg;
    }

  if (!reg)
    {
      return(-1);
    }
  if (!prev)
    {
      regs->reginfos = reg->next;
    }
  else
    {
      prev->next = reg->next;
    }
  memset(reg, 0, sizeof(struct reg_info));
  free(reg);
  return(0);
}

/*
 * Add the from_via structure to a HIP association. This takes the form of the
 * FROM or VIA RVS TLVs and contains the address given in sockaddr or byte
 * string format. This is used for input functions to signal adding the FROM
 * or VIA RVS rendevous parameters on I1 or R1 output.
 */
int add_from_via(hip_assoc *hip_a, __u16 type, struct sockaddr *addr,
                 __u8* address)
{
  if (!addr && !address)         /* must specify either type of address */
    {
      return(-1);
    }
  if (!hip_a->from_via)
    {
      hip_a->from_via = malloc(eight_byte_align(sizeof(tlv_from)));
    }
  if (!hip_a->from_via)
    {
      return(-1);           /* malloc error */
    }
  memset(hip_a->from_via, 0, eight_byte_align(sizeof(tlv_from)));
  hip_a->from_via->type = htons(type);
  hip_a->from_via->length = htons(sizeof(tlv_from) - 4);
  if (addr && (addr->sa_family == AF_INET6))
    {
      memcpy(hip_a->from_via->address, SA2IP(addr), SAIPLEN(addr));
    }
  else if (addr && (addr->sa_family == AF_INET))
    {
      /* IPv4-in-IPv6 address format */
      memset(&hip_a->from_via->address[10], 0xFF, 2);
      memcpy(&hip_a->from_via->address[12], SA2IP(addr),
             SAIPLEN(addr));
    }
  else if (address)
    {
      memcpy(hip_a->from_via->address, address,
             sizeof(hip_a->from_via->address));
    }
  return(0);
}

