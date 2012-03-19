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
 *  \file  hip_output.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson,  <thomas.r.henderson@boeing.com>
 *
 *  \brief  Routines for building and sending HIP packets.
 *
 */

#include <stdio.h>              /* stderr, etc                  */
#include <stdlib.h>             /* rand()			*/
#include <errno.h>              /* strerror(), errno            */
#include <string.h>             /* memset()                     */
#include <time.h>               /* time()			*/
#include <ctype.h>              /* tolower()                    */
#include <sys/types.h>          /* getpid() support, etc        */
#include <openssl/crypto.h>     /* OpenSSL's crypto library     */
#include <openssl/bn.h>         /* Big Numbers                  */
#include <openssl/des.h>        /* 3DES support			*/
#include <openssl/blowfish.h>   /* BLOWFISH support             */
#include <openssl/aes.h>        /* AES support			*/
#include <openssl/dsa.h>        /* DSA support                  */
#include <openssl/dh.h>         /* Diffie-Hellman contexts      */
#include <openssl/sha.h>        /* SHA1 algorithms              */
#include <openssl/rand.h>       /* RAND_seed()                  */
#include <openssl/err.h>        /* ERR_ functions		*/
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <crt/io.h>
#include <win32/types.h>
#else
#ifndef __MACOSX__
#include <asm/types.h>
#endif
#include <unistd.h>             /* close()			*/
#include <sys/time.h>           /* gettimeofday()               */
#include <sys/uio.h>            /* iovec */
#include <pthread.h>            /* pthread_exit() */
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#include <netinet/in.h>
#endif
#include <netinet/ip.h>         /* struct iphdr                 */
#endif

#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>

#ifdef HIP_VPLS
#include <hip/hip_cfg_api.h>
#endif /* HIP_VPLS */

/*
 * Forward declaration of local functions.
 */
int hip_check_bind(struct sockaddr *src, int num_attempts);
int build_tlv_dh(__u8 *data, __u8 group_id, DH *dh, int debug);
int build_tlv_transform(__u8 *data, int type, __u16 *transforms, __u16 single);
int build_tlv_locators(__u8* data, sockaddr_list *addrs, __u32 spi, int force);
int build_tlv_echo_response(__u16 type, __u16 length, __u8 *buff, __u8 *data);
int build_tlv_cert(__u8 *buff);
int build_tlv_hmac(hip_assoc *hip_a, __u8 *data, int location, int type);
int build_tlv_reg_info(__u8 *data);
int build_tlv_reg_req(__u8 *data, struct reg_entry *regs);
int build_tlv_reg_resp(__u8 *data, struct reg_entry *regs);
int build_tlv_reg_failed(__u8 *data, struct reg_entry *regs);

#ifdef __MACOSX__
extern int next_divert_rule();
extern void add_divert_rule(int,int,char *);
extern void del_divert_rule(int);
#endif

/*
 * function hip_send_I1()
 *
 * in:		hit  = receiver's HIT, who we want to start communications with
 *                     or sender's HIT if we are a RVS relaying this I1 packet
 *              hip_a = association to use for addresses and retransmission;
 *                      if this is RVS relaying, then this is the assoc between
 *                      the RVS and the responder client
 *
 * out:		Returns bytes sent when successful, -1 on failure.
 *
 * Opens a socket and sends the HIP Initiator packet.
 *
 */
int hip_send_I1(hip_hit *hit, hip_assoc *hip_a)
{
  __u8 buff[sizeof(hiphdr) + sizeof(tlv_from) + 4 + sizeof(tlv_hmac)];
  struct sockaddr *src, *dst;
  hiphdr *hiph;
  int location = 0, do_retrans;

  memset(buff, 0, sizeof(buff));

  hiph = (hiphdr*) &buff[0];
  hiph->nxt_hdr = IPPROTO_NONE;
  hiph->hdr_len = 4;       /* 2*sizeof(hip_hit)/8*/
  hiph->packet_type = HIP_I1;
  hiph->version = HIP_PROTO_VER;
  hiph->res = HIP_RES_SHIM6_BITS;
  hiph->control = 0;
  hiph->checksum = 0;

  src = HIPA_SRC(hip_a);
  dst = HIPA_DST(hip_a);

  /* in RVS mode, relay the I1 packet instead of triggering bex */
  if (OPT.rvs && hip_a->from_via)
    {
      if (ntohs(hip_a->from_via->type) != PARAM_FROM)
        {
          log_(WARN, "Sending I1 RVS processing error.\n");
          return(-1);
        }
      /* sender's HIT passed in*/
      memcpy(hiph->hit_sndr, hit, HIT_SIZE);
      memcpy(hiph->hit_rcvr, hip_a->peer_hi->hit, HIT_SIZE);
      location = sizeof(hiphdr);

      /* add the FROM parameter */
      memcpy(&buff[location], hip_a->from_via, sizeof(tlv_from));
      location += eight_byte_align(sizeof(tlv_from));
      free(hip_a->from_via);
      hip_a->from_via = NULL;

      /* RVS_HMAC: hip_a is the pre-existing association between the
       * RVS and the responder for the HMAC key */
      hiph->hdr_len = (location / 8) - 1;
      location += build_tlv_hmac(hip_a, buff, location,
                                 PARAM_RVS_HMAC);

      hiph->hdr_len = (location / 8) - 1;

      /* send the packet */
      log_(NORMT, "Relaying HIP_I1 packet (%d bytes)...\n", location);
      do_retrans = FALSE;
    }
  else           /* normal I1, not relayed by RVS */
    {
      pthread_mutex_lock(hip_a->peer_hi->rvs_mutex);
      /* Block in case of RVS DNS resolution is NOT ready */
      if (*(hip_a->peer_hi->rvs_count) > 0)
        {
          log_(NORMT, "Waiting for RVS DNS resolution\n");
          pthread_cond_wait(hip_a->peer_hi->rvs_cond,
                            hip_a->peer_hi->rvs_mutex);
          log_(NORMT, "Waiting done, sending I1 now.\n");
        }
      pthread_mutex_unlock(hip_a->peer_hi->rvs_mutex);
      if (*(hip_a->peer_hi->rvs_addrs) != NULL)             /* use RVS instead
                                                             *of DST*/
        {
          dst = SA(&(*(hip_a->peer_hi->rvs_addrs))->addr);
          if (hip_a->udp && (dst->sa_family == AF_INET))
            {
              ((struct sockaddr_in *)dst)->sin_port =
                ((struct sockaddr_in *)
                 HIPA_DST(hip_a))->sin_port;
              /* TODO: support IPv6 over UDP here */
            }
        }

      /* NULL HITs only allowed for opportunistic I1s */
      if ((hit == NULL) && !OPT.opportunistic)
        {
          return(-1);
        }
      if (hit == NULL)
        {
          log_(NORM, "Sending NULL HIT to %s.\n", logaddr(dst));
        }
      else
        {
          log_(NORM, "Sending HIT corresponding to %s.\n",
               logaddr(dst));
        }

      memcpy(hiph->hit_sndr, hip_a->hi->hit, sizeof(hip_hit));
      if (hit == NULL)             /* opportunistic */
        {
          memset(hiph->hit_rcvr, 0, sizeof(hip_hit));
        }
      else
        {
          memcpy(hiph->hit_rcvr, hit, sizeof(hip_hit));
        }

      location = sizeof(hiphdr);
      log_(NORMT, "Sending HIP_I1 packet (%d bytes)...\n", location);
      do_retrans = TRUE;
    }
  if (!hip_a->udp)
    {
      hiph->checksum = checksum_packet(&buff[0], src, dst);
    }

  /* send the packet */
  return(hip_send(buff, location, src, dst, hip_a, do_retrans));
}

/*
 *
 * function hip_send_R1()
 *
 * in:		src
 *              dst
 *              hiti
 *              hi
 *
 * out:		Returns bytes sent when successful, -1 on error.
 *              hip_a will have DH context and retransmission packets
 *
 * Opens a socket and sends the HIP Responder packet.
 *
 */
int hip_send_R1(struct sockaddr *src, struct sockaddr *dst, hip_hit *hiti,
                hi_node *hi, hip_assoc *hip_rvs)
{
  int err, i, total_len, add_via;
  hiphdr *hiph;
  r1_cache_entry *r1_entry;
  __u8 *data;

  /* make a copy of a pre-computed R1 from the cache */
  i = compute_R1_cache_index(hiti, TRUE);
  r1_entry = &hi->r1_cache[i];
  total_len = r1_entry->len;
  log_(NORM,"Using premade R1 from %s cache slot %d.\n", hi->name, i);

  /* if received I1 with from parameter, add via_rvs parameter in R1 */
  if (hip_rvs && hip_rvs->from_via)
    {
      if (ntohs(hip_rvs->from_via->type) != PARAM_VIA_RVS)
        {
          log_(WARN, "RVS processing error sending R1.\n");
          return(-1);
        }
      total_len += sizeof(tlv_via_rvs);
      add_via = TRUE;
    }
  else
    {
      add_via = FALSE;
    }

  total_len = eight_byte_align(total_len);
  data = (__u8 *) malloc(total_len);
  if (!data)
    {
      return(-1);
    }
  memset(data, 0, total_len);
  hiph = (hiphdr*) data;
  memcpy(data, r1_entry->packet, r1_entry->len);
  if (add_via)
    {
      memcpy(&data[r1_entry->len], hip_rvs->from_via,
             sizeof(tlv_via_rvs));
      hiph->hdr_len = (total_len / 8) - 1;
      free(hip_rvs->from_via);
      hip_rvs->from_via = NULL;
      log_(NORM, "Adding VIA RVS parameter to R1.\n");
    }


  /* fill in receiver's HIT, checksum */
  memcpy(hiph->hit_rcvr, hiti, sizeof(hip_hit));
  hiph->checksum = 0;

  if ((dst->sa_family == AF_INET) &&
      (((struct sockaddr_in *)dst)->sin_port > 0))
    {
      /* this is a UDP encapsulated R1, checksum must be zero */
    }
  else
    {
      hiph->checksum = checksum_packet(data, src, dst);
    }

  /* send the packet */
  log_(NORMT, "Sending HIP_R1 packet (%d bytes)...\n", total_len);
  err = hip_send(data, total_len, src, dst, NULL, FALSE);

  free(data);       /* not retransmitted */
  return(err);
}

/*
 *
 * function hip_generate_R1()
 *
 * in:		data = ptr of where to store R1 (must have enough space)
 *              hi = ptr to my Host Identity to use
 *              cookie = the puzzle to insert into the R1
 *              dh_entry = the DH cache entry to use
 *
 */
int hip_generate_R1(__u8 *data, hi_node *hi, hipcookie *cookie,
                    dh_cache_entry *dh_entry)
{
  hiphdr *hiph;
  int location = 0, cookie_location = 0;
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
  hiph->checksum = 0;       /* 0 for SIG, set later */
  memcpy(hiph->hit_sndr, hi->hit, sizeof(hip_hit));
  memset(hiph->hit_rcvr, 0, sizeof(hip_hit));
  location = sizeof(hiphdr);

  /* set control bits */
  if (hi->anonymous)
    {
      hiph->control |= CTL_ANON;
    }
  hiph->control = htons(hiph->control);

  /* optionally build R1 COUNTER TLV */
  if (hi->r1_gen_count > 0)
    {
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
  memset(&puzzle->cookie, 0, len);       /* zero OPAQUE and I fields for SIG */
  puzzle->cookie.k = cookie->k;
  puzzle->cookie.lifetime = cookie->lifetime;
  cookie_location = location - len;
  if (D_VERBOSE == OPT.debug_R1)
    {
      log_(NORM, "Cookie sent in R1: ");
      print_cookie(cookie);
    }
  location = eight_byte_align(location);

  /* Diffie Hellman */
  location += build_tlv_dh(&data[location], dh_entry->group_id,
                           dh_entry->dh, OPT.debug_R1);

  /* HIP transform */
  location += build_tlv_transform(&data[location],
                                  PARAM_HIP_TRANSFORM,
                                  HCNF.hip_transforms,
                                  0);

  /* host_id */
  location += build_tlv_hostid(&data[location], hi, HCNF.send_hi_name);

  /* certificate */
  location += build_tlv_cert(&data[location]);

  /* reg_info */
  location += build_tlv_reg_info(&data[location]);

  /* if ECHO_REQUEST is needed, put it here */

  /* ESP transform */
  location += build_tlv_transform(&data[location],
                                  PARAM_ESP_TRANSFORM,
                                  HCNF.esp_transforms,
                                  0);

  /* hip_signature_2 - receiver's HIT and checksum zeroed */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_signature(hi, data, location, TRUE);

  hiph->hdr_len = (location / 8) - 1;

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
  __u8 buff[sizeof(hiphdr)            + sizeof(tlv_esp_info) +
            sizeof(tlv_r1_counter)    +
            sizeof(tlv_solution)      + sizeof(tlv_diffie_hellman) +
            DH_MAX_LEN                + sizeof(tlv_hip_transform) + 2 +
            sizeof(tlv_esp_transform) + sizeof(tlv_encrypted) +
            sizeof(tlv_host_id)       + 1 + DSA_PRIV +
            3 * (MAX_HI_BITS / 8)         + MAX_HI_NAMESIZE +
            sizeof(tlv_echo)          + MAX_OPAQUE_SIZE +
            sizeof(tlv_reg_request)   + MAX_REGISTRATION_TYPES +
            sizeof(tlv_hmac)          +
            sizeof(tlv_hip_sig)       + MAX_SIG_SIZE + 2];
  __u8 *unenc_data, *enc_data;
  __u16 zero16[1] = { 0x0 };
  int len, location = 0;

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
  unsigned char cbc_iv[16] = {0};

  __u64 solution = 0;

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

  if (!ENCR_NULL(hip_a->hip_transform))
    {
      RAND_bytes(cbc_iv, sizeof(cbc_iv));
    }

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
  if (hip_a->hi->anonymous)
    {
      hiph->control |= CTL_ANON;
    }
  hiph->control = htons(hiph->control);

  /* ESP INFO */
  esp_info = (tlv_esp_info*) &buff[location];
  esp_info->type = htons(PARAM_ESP_INFO);
  esp_info->length = htons(sizeof(tlv_esp_info) - 4);
  esp_info->reserved = 0;
  esp_info->keymat_index = 0;       /* this is set below, after compute_keys()*/
  esp_info->old_spi = 0;
  esp_info->new_spi = htonl(hip_a->spi_in);
  location += sizeof(tlv_esp_info);
  location = eight_byte_align(location);

  /* R1 counter - optional */
  if (hip_a->peer_hi->r1_gen_count > 0)
    {
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
                          &hip_a->hi->hit, &hip_a->peer_hi->hit)) < 0)
    {
      return(err);
    }
  sol->j = solution;       /* already in network byte order */
  hip_a->cookie_j = solution;       /* saved for use with keying material */
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
                                  PARAM_HIP_TRANSFORM,
                                  zero16,
                                  hip_a->hip_transform);

  /* encrypted(host_id) */
  enc = (tlv_encrypted*) &buff[location];
  enc->type = htons(PARAM_ENCRYPTED);
  memset(enc->reserved, 0, sizeof(enc->reserved));
  iv_len = enc_iv_len(hip_a->hip_transform);

  /* inner padding is 8-byte aligned */
  data_len = build_tlv_hostid_len(hip_a->hi, HCNF.send_hi_name);

  /* AES has 128-bit IV/block size with which we need to align */
  if (iv_len > 8)
    {
      data_len = (iv_len - 1) + data_len - (data_len - 1) % iv_len;
    }
  /* Set the encrypted TLV length. Encryption may require IV. */
  enc->length = htons((__u16)(data_len + sizeof(enc->reserved) + iv_len));
  if (iv_len)
    {
      memcpy(enc->iv, cbc_iv, iv_len);
    }
  unenc_data = (__u8 *)malloc(data_len);
  enc_data = (__u8 *)malloc(data_len);
  if (!unenc_data || !enc_data)
    {
      log_(ERR, "hip_send_I2: malloc error building encrypted TLV\n");
      return(-1);
    }
  memset(unenc_data, 0, data_len);
  memset(enc_data, 0, data_len);
  /* host_id */
  hi_location = build_tlv_hostid(unenc_data, hip_a->hi,HCNF.send_hi_name);
  /* Pad the data using PKCS5 padding - for n bytes of padding, set
   * those n bytes to 'n'. */
  memset((unenc_data + hi_location),
         (data_len - hi_location),         /* fill with pad length */
         (data_len - hi_location));

  switch (hip_a->hip_transform)
    {
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
      if ((err = AES_set_encrypt_key(key, 8 * len, &aes_key)) != 0)
        {
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
        {
          log_(WARN, "short key!");
        }
      memcpy(&secret_key1, key, len);
      memcpy(&secret_key2, key + 8, len);
      memcpy(&secret_key3, key + 16, len);

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

      if (((err = des_set_key_checked((
                                        (des_cblock *)&
                                        secret_key1),
                                      ks1)) != 0) ||
          ((err = des_set_key_checked((
                                        (des_cblock *)&
                                        secret_key2),
                                      ks2)) != 0) ||
          ((err = des_set_key_checked((
                                        (des_cblock *)&
                                        secret_key3),
                                      ks3)) != 0))
        {
          log_(WARN, "Unable to use calculated DH secret for ");
          log_(NORM, "3DES key (%d)\n", err);
          free(unenc_data);
          free(enc_data);
          return(-1);
        }
      log_(NORM, "Encrypting %d bytes using 3-DES.\n", data_len);
      des_ede3_cbc_encrypt(unenc_data,
                           enc_data,
                           data_len,
                           ks1,
                           ks2,
                           ks3,
                           (des_cblock*)cbc_iv,
                           DES_ENCRYPT);
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
  if (hip_a->regs)
    {
      location += build_tlv_reg_req(&buff[location], hip_a->regs);
    }

  /* add any echo response (included under signature) */
  if (hip_a->opaque && !hip_a->opaque->opaque_nosig)
    {
      location += build_tlv_echo_response(PARAM_ECHO_RESPONSE,
                                          hip_a->opaque->opaque_len,
                                          &buff[location],
                                          hip_a->opaque->opaque_data);
      location = eight_byte_align(location);
      free(hip_a->opaque);           /* no longer needed */
      hip_a->opaque = NULL;
    }

  /* esp transform */
  location += build_tlv_transform(&buff[location],
                                  PARAM_ESP_TRANSFORM,
                                  zero16,
                                  hip_a->esp_transform);

  /* add HMAC */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_hmac(hip_a, buff, location, PARAM_HMAC);

  /* build the HIP SIG in a SIG RR */
  hiph->hdr_len = (location / 8) - 1;
  location +=  build_tlv_signature(hip_a->hi, buff, location, FALSE);

  /* add any echo response (after signature) */
  if (hip_a->opaque && (hip_a->opaque->opaque_nosig))
    {
      location += build_tlv_echo_response(PARAM_ECHO_RESPONSE_NOSIG,
                                          hip_a->opaque->opaque_len,
                                          &buff[location],
                                          hip_a->opaque->opaque_data);
      location = eight_byte_align(location);
      free(hip_a->opaque);           /* no longer needed */
      hip_a->opaque = NULL;
    }

  /* finish with checksum, length */
  hiph->hdr_len = (location / 8) - 1;
  hiph->checksum = 0;
  if (!hip_a->udp)
    {
      hiph->checksum = checksum_packet(buff, src, dst);
    }


  /* send the packet */
  log_(NORMT, "Sending HIP_I2 packet (%d bytes)...\n", location);
  return(hip_send(buff, location, HIPA_SRC(hip_a), HIPA_DST(hip_a),
                  hip_a, TRUE));
}

/*
 *
 * function hip_send_R2()
 *
 * in:		hip_a = HIP association containing valid source/destination
 *                      addresses, HITs, SPIs, key material, pub key
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
  __u8 buff[sizeof(hiphdr)            + sizeof(tlv_esp_info) +
            sizeof(tlv_host_id)       + 1 + DSA_PRIV +
            3 * (MAX_HI_BITS / 8)         + MAX_HI_NAMESIZE +
            sizeof(tlv_hmac)          + sizeof(tlv_hip_sig) +
            MAX_SIG_SIZE + 2          + sizeof(tlv_reg_response)];
  int location = 0, hi_location;
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

  if (hip_a->regs)
    {
      location += build_tlv_reg_resp(&buff[location], hip_a->regs);
      location += build_tlv_reg_failed(&buff[location], hip_a->regs);
    }

  /* reg_required not defined yet */

  /* HMAC_2 */
  hi_location = location;       /* temporarily add host_id parameter */
  location += build_tlv_hostid(&buff[location], hip_a->hi,
                               HCNF.send_hi_name);
  location = eight_byte_align(location);
  hiph->hdr_len = (location / 8) - 1;
  build_tlv_hmac(hip_a, buff, location, PARAM_HMAC_2);
  /* memory areas overlap if sizeof(host_id) < sizeof(tlv_hmac) */
  memmove(&buff[hi_location], &buff[location], sizeof(tlv_hmac));
  location = hi_location + eight_byte_align(sizeof(tlv_hmac));

  /* HIP signature */
  hiph->hdr_len = (location / 8) - 1;
  location +=  build_tlv_signature(hip_a->hi, buff, location, FALSE);

  hiph->hdr_len = (location / 8) - 1;
  hiph->checksum = 0;
  if (!hip_a->udp)
    {
      hiph->checksum = checksum_packet(buff, src, dst);
    }

  /* send the packet */
  log_(NORMT, "Sending HIP_R2 packet (%d bytes)...\n", location);
  /* R2 packet is not scheduled for retrans., but saved for retrans. */

  return(hip_send(buff, location, HIPA_SRC(hip_a), HIPA_DST(hip_a),
                  hip_a, TRUE));
}

/*
 *
 * function hip_send_update_relay()
 *
 * in:		data = UPDATE packet to relay
 *		hip_a_client = HIP association for RVS client
 *
 * out:		Returns bytes sent when successful, -1 on error
 *
 * Adds FROM parameter and RVS_HMAC and relays the UPDATE to the RVS client
 *
 */
int hip_send_update_relay(__u8 *data, hip_assoc *hip_a_client)
{
  __u8 *buff;
  hiphdr *hiph;
  int location, data_len, new_len, do_retrans, ret;
  struct sockaddr *src, *dst;

  if (!hip_a_client->from_via)
    {
      return(-1);
    }

  if (ntohs(hip_a_client->from_via->type) != PARAM_FROM)
    {
      log_(WARN, "Relaying UPDATE RVS processing error.\n");
      return(-1);
    }
  src = HIPA_SRC(hip_a_client);
  dst = HIPA_DST(hip_a_client);

  location = 0;
  hiph = (hiphdr *) &data[location];
  data_len = location + ((hiph->hdr_len + 1) * 8);
  new_len = data_len + sizeof(tlv_from) + 4 + sizeof(tlv_hmac);
  buff = malloc(new_len);
  if (!buff)
    {
      free(hip_a_client->from_via);
      hip_a_client->from_via = NULL;
      log_(WARN, "MALLOC error.\n");
      return(-1);
    }

  memset(buff, 0, new_len);
  memcpy(buff, data, data_len);
  hiph = (hiphdr *) &buff[location];
  location += data_len;

  /* add the FROM parameter */
  memcpy(&buff[location], hip_a_client->from_via, sizeof(tlv_from));
  location += eight_byte_align(sizeof(tlv_from));
  free(hip_a_client->from_via);
  hip_a_client->from_via = NULL;

  /* RVS_HMAC: hip_a_client is the pre-existing association between the
   * RVS and the responder for the HMAC key */
  hiph->checksum = 0;
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_hmac(hip_a_client, buff, location,
                             PARAM_RVS_HMAC);
  hiph->hdr_len = (location / 8) - 1;

  /* send the packet */
  log_(NORMT, "Relaying HIP UPDATE packet (%d bytes)...\n", location);
  do_retrans = FALSE;

  if (!hip_a_client->udp)
    {
      hiph->checksum = 0;
      hiph->checksum = checksum_packet(&buff[0], src, dst);
    }

  /* send the packet */
  ret = hip_send(buff, location, src, dst, NULL, do_retrans);
  free(buff);
  return(ret);
}

/*
 *
 * function hip_send_update()
 *
 * in:		hip_a = HIP association containing valid source/destination
 *                      addresses, HITs, SPIs, key material, pub key
 *              newaddr = new preferred address to include in LOCATOR, or NULL
 *              dstaddr = alternate destination address, if this is an address
 *                      check message, otherwise NULL
 *
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Opens a socket and sends the UPDATE packet.
 * Packet will be scheduled for retransmission if it contains a SEQ (that
 * needs to be ACKed.)
 *
 */
int hip_send_update(hip_assoc *hip_a, struct sockaddr *newaddr,
                    struct sockaddr *src, struct sockaddr *dstaddr)
{
  struct sockaddr *dst;
  hiphdr *hiph;
  __u8 buff[sizeof(hiphdr)             +
            sizeof(tlv_locator)        + MAX_LOCATORS * sizeof(locator) +
            sizeof(tlv_esp_info)       +
            sizeof(tlv_seq)            + sizeof(tlv_ack) +
            sizeof(tlv_diffie_hellman) + DH_MAX_LEN +
            2 * sizeof(tlv_echo)         + 3 + MAX_OPAQUE_SIZE +
            sizeof(tlv_hmac)           + sizeof(tlv_hip_sig) +
            sizeof(tlv_reg_request)    + sizeof (tlv_reg_response) +
            sizeof(tlv_via_rvs)        + MAX_SIG_SIZE + 2];
  int location = 0, retransmit = FALSE;

  tlv_esp_info *esp_info;
  tlv_seq *seq;
  tlv_ack *ack;
  tlv_echo *echo;
  __u32 *nonce;
  sockaddr_list *l, *l2;
  hip_assoc *hip_mr;

  memset(buff, 0, sizeof(buff));

  /* address verfication reply may need to be sent from a different src */
  if (!src)
    {
      src = HIPA_SRC(hip_a);
    }
  /* for address verification, a new destination address will be given */
  dst = dstaddr ? dstaddr : HIPA_DST(hip_a);
  if (dst->sa_family != src->sa_family)
    {
      l2 = NULL;
/*
 *               for (l = my_addr_head; l; l = l->next) {
 */
      for (l = &hip_a->hi->addrs; l; l = l->next)
        {
          if (l->addr.ss_family != dst->sa_family)
            {
              continue;
            }
          if (!l2)
            {
              l2 = l;                   /* save first address in same family */
            }
          if (l->preferred)
            {
              break;
            }
        }
      /* use the preferred address or first one of this family */
      src = l ? SA(&l->addr) : (l2 ? SA(&l2->addr) : src);
    }
  log_(NORM, "Sending UPDATE from source address %s\n", logaddr(src));

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
      (hip_a->rekey && hip_a->rekey->new_spi &&
       hip_a->rekey->need_ack))
    {
      /* ESP_INFO */
      esp_info = (tlv_esp_info*) &buff[location];
      esp_info->type = htons(PARAM_ESP_INFO);
      esp_info->length = htons(sizeof(tlv_esp_info) - 4);
      esp_info->reserved = 0;
      esp_info->old_spi = htonl(hip_a->spi_in);
      if (hip_a->rekey)             /* rekeying */
        {
          esp_info->keymat_index =
            htons(hip_a->rekey->keymat_index);
          esp_info->new_spi = htonl(hip_a->rekey->new_spi);
        }
      else               /* gratuitous */
        {
          esp_info->keymat_index = htons(hip_a->keymat_index);
          esp_info->new_spi = esp_info->old_spi;
        }
      location += sizeof(tlv_esp_info);
      location = eight_byte_align(location);
    }

  if ((hip_a->from_via) &&
      (ntohs(hip_a->from_via->type) == PARAM_VIA_RVS))
    {
      hip_mr = search_registrations2(REGTYPE_MR, REG_GRANTED);
      if (!hip_mr ||
          hits_equal(hip_mr->peer_hi->hit, hip_a->peer_hi->hit))
        {
          if (!newaddr)
            {
              newaddr = src;
            }
        }
    }

  /*
   * Possibly add LOCATOR parameter when supplied with readdressing info,
   * or when unsent locators exist in hip_a->hi->addrs.
   */
  location += build_tlv_locators(
    &buff[location],
    &hip_a->hi->addrs,
    hip_a->rekey ? hip_a->rekey->new_spi :
    hip_a->spi_in,
    newaddr != NULL);


  if (hip_a->rekey && hip_a->rekey->need_ack)
    {
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
  if (hip_a->peer_rekey && hip_a->peer_rekey->need_ack)
    {
      ack = (tlv_ack*)  &buff[location];
      ack->type = htons(PARAM_ACK);
      ack->length = htons(sizeof(tlv_ack) - 4);
      ack->peer_update_id = htonl(hip_a->peer_rekey->update_id);
      hip_a->peer_rekey->need_ack = FALSE;
      location += sizeof(tlv_ack);
      location = eight_byte_align(location);
    }

  /* Add a Diffie-Hellman parameter when present
   * in hip_a->rekey->dh
   */
  if (hip_a->rekey && hip_a->rekey->dh)
    {
      location += build_tlv_dh(&buff[location],
                               hip_a->rekey->dh_group_id,
                               hip_a->rekey->dh,
                               OPT.debug);
    }

  /* Deal with registrations */
  /* TODO: decide when to send reg info in UPDATE */
  /*	location += build_tlv_reg_info(buff, location); */
  if (hip_a->regs)
    {
      location += build_tlv_reg_req(&buff[location], hip_a->regs);
      location += build_tlv_reg_resp(&buff[location], hip_a->regs);
      location += build_tlv_reg_failed(&buff[location], hip_a->regs);
    }

/* #define USE_UPDATE_ECHO_REQUEST_SIG // */
#ifdef USE_UPDATE_ECHO_REQUEST_SIG
  /* XXX this adds a non-critical echo request inside the signature
   *     for IETF61 testing with HIPL, this was moved outside
   */
  /* Add a nonce in an echo request parameter when
   * doing address verification
   */
  if (dstaddr)
    {
      echo = (tlv_echo*) &buff[location];
      echo->type = htons(PARAM_ECHO_REQUEST);
      echo->length = htons(4);           /* 4-byte nonce */
      nonce = (__u32*) echo->opaque_data;
      for (l = &hip_a->peer_hi->addrs; l; l = l->next)
        {
          if ((l->addr.ss_family == dstaddr->sa_family) &&
              (!memcmp(SA2IP(&l->addr), SA2IP(dstaddr),
                       SAIPLEN(dstaddr))))
            {
              break;
            }
        }
      if (!l)
        {
          log_(WARN, "Could not find nonce for address %s.\n",
               logaddr(dstaddr));
          return(-1);
        }
      *nonce = l->nonce;
      location += 8;
      location = eight_byte_align(location);
    }
#endif /* USE_UPDATE_ECHO_REQUEST_SIG */

  /* add any echo response (included under signature) */
  if (hip_a->opaque && !hip_a->opaque->opaque_nosig)
    {
      location += build_tlv_echo_response(PARAM_ECHO_RESPONSE,
                                          hip_a->opaque->opaque_len,
                                          &buff[location],
                                          hip_a->opaque->opaque_data);
      location = eight_byte_align(location);
      free(hip_a->opaque);           /* no longer needed */
      hip_a->opaque = NULL;
    }

  hiph->hdr_len = (location / 8) - 1;

  /* HMAC */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_hmac(hip_a, buff, location, PARAM_HMAC);

  /* HIP signature */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_signature(hip_a->hi, buff, location, FALSE);

  /* Add a nonce in an echo request parameter when
   * doing address verification (after signature)
   *  (for IETF61 testing with HIPL, this was moved outside of sig)
   */
#ifndef USE_UPDATE_ECHO_REQUEST_SIG
  if (dstaddr)
    {
      echo = (tlv_echo*) &buff[location];
      echo->type = htons(PARAM_ECHO_REQUEST_NOSIG);
      echo->length = htons(4);           /* 4-byte nonce */
      nonce = (__u32*) echo->opaque_data;
      for (l = &hip_a->peer_hi->addrs; l; l = l->next)
        {
          if ((l->addr.ss_family == dstaddr->sa_family) &&
              (!memcmp(SA2IP(&l->addr), SA2IP(dstaddr),
                       SAIPLEN(dstaddr))))
            {
              break;
            }
        }
      if (!l)
        {
          log_(WARN, "Could not find nonce for address %s.\n",
               logaddr(dstaddr));
          return(-1);
        }
      *nonce = l->nonce;
      location += 8;
      location = eight_byte_align(location);
    }
#endif /* ! USE_UPDATE_ECHO_REQUEST_SIG */

  /* add any echo response (after signature) */
  if (hip_a->opaque && hip_a->opaque->opaque_nosig)
    {
      location += build_tlv_echo_response(PARAM_ECHO_RESPONSE_NOSIG,
                                          hip_a->opaque->opaque_len,
                                          &buff[location],
                                          hip_a->opaque->opaque_data);
      location = eight_byte_align(location);
      free(hip_a->opaque);
      hip_a->opaque = NULL;
    }

  if (hip_a->from_via)
    {
      if (ntohs(hip_a->from_via->type) == PARAM_VIA_RVS)
        {
          memcpy(&buff[location], hip_a->from_via,
                 sizeof(tlv_via_rvs));
          location += sizeof(tlv_via_rvs);
          location = eight_byte_align(location);
          log_(NORM, "Adding VIA RVS parameter to UPDATE.\n");
        }
      free(hip_a->from_via);
      hip_a->from_via = NULL;
    }

  hiph->hdr_len = (location / 8) - 1;
  hiph->checksum = 0;
  if (!hip_a->udp)
    {
      hiph->checksum = checksum_packet(buff, src, dst);
    }

  /* send the packet */
  log_(NORMT, "sending UPDATE packet (%d bytes)...\n", location);

  /* Retransmit UPDATEs unless it contains a LOCATOR or address check */
  log_(NORM, "Sending UPDATE packet to dst : %s \n", logaddr(dst));
  hip_check_bind(src, HIP_UPDATE_BIND_CHECKS);
  return(hip_send(buff, location, src, dst, hip_a, retransmit));
}

/*
 *
 * function hip_send_update_proxy_ticket()
 *
 * in:		hip_mr = HIP association between mobile node and mobile router
 *              hip_a = HIP association between mobile node and peer node
 *              keymat_index = index to key material delagated from mobile
 *			node to mobile router
 *
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Opens a socket and sends the UPDATE packet.
 *
 */
int hip_send_update_proxy_ticket(hip_assoc *hip_mr, hip_assoc *hip_a)
{
  struct sockaddr *src, *dst;
  hiphdr *hiph;
  __u8 buff[sizeof(hiphdr)             + sizeof(tlv_proxy_ticket) +
            sizeof(tlv_hmac)           + sizeof(tlv_hip_sig) +
            MAX_SIG_SIZE + 2];
  int location = 0, retransmit = FALSE;
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

  switch (hip_a->hip_transform)
    {
    case ESP_AES_CBC_HMAC_SHA1:
    case ESP_3DES_CBC_HMAC_SHA1:
    case ESP_BLOWFISH_CBC_HMAC_SHA1:
    case ESP_NULL_HMAC_SHA1:
      HMAC(   EVP_sha1(),
              get_key(hip_a, HIP_INTEGRITY, FALSE),
              auth_key_len(hip_a->hip_transform),
              (__u8 *)&ticket->hmac_key_index, length_to_hmac,
              hmac_md, &hmac_md_len  );
      break;
    case ESP_3DES_CBC_HMAC_MD5:
    case ESP_NULL_HMAC_MD5:
      HMAC(   EVP_md5(),
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
          &hmac_md[hmac_md_len - sizeof(ticket->hmac)],
          sizeof(ticket->hmac));

  location += sizeof(tlv_proxy_ticket);
  location = eight_byte_align(location);

  /* HMAC */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_hmac(hip_mr, buff, location, PARAM_HMAC);

  /* HIP signature */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_signature(hip_mr->hi, buff, location, FALSE);

  hiph->hdr_len = (location / 8) - 1;
  hiph->checksum = 0;
  if (!hip_a->udp)
    {
      hiph->checksum = checksum_packet(buff, src, dst);
    }

  /* send the packet */
  log_(NORMT, "sending UPDATE packet (%d bytes)...\n", location);

  /* Retransmit UPDATEs unless it contains a LOCATOR or address check */
  log_(NORM, "Sending UPDATE packet to mobile router : %s \n",
       logaddr(dst));
  hip_check_bind(src, HIP_UPDATE_BIND_CHECKS);
  return(hip_send(buff, location, src, dst, hip_mr, retransmit));
}

/*
 *
 * function hip_send_update_locators()
 *
 * in:		hip_a = HIP association containing valid source/destination
 *                      addresses
 *
 * out:		Returns bytes sent when successful, -1 on error.
 *
 * Inform peer of our current address list (hip_a->hi->addrs).
 *
 */
int hip_send_update_locators(hip_assoc *hip_a)
{
  hiphdr *hiph;
  __u8 buff[sizeof(hiphdr) + sizeof(tlv_locator) - sizeof(locator) +
            MAX_LOCATORS * sizeof(locator) + sizeof(tlv_hmac) +
            sizeof(tlv_hip_sig) + MAX_SIG_SIZE + 2];
  int locators_len, location = 0;
  struct sockaddr *src, *dst;

  memset(buff, 0, sizeof(buff));

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

  /* build a locator parameter containing all of our addresses */
  locators_len = build_tlv_locators(&buff[location], &hip_a->hi->addrs,
                                    hip_a->spi_in, 0);
  if (locators_len == 0)
    {
      return(0);           /* no need to send this UPDATE packet */
    }
  location += locators_len;

  /* HMAC */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_hmac(hip_a, buff, location, PARAM_HMAC);

  /* HIP signature */
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_signature(hip_a->hi, buff, location, FALSE);

  src = HIPA_SRC(hip_a);
  dst = HIPA_DST(hip_a);

  hiph->hdr_len = (location / 8) - 1;
  hiph->checksum = 0;
  if (!hip_a->udp)
    {
      hiph->checksum = checksum_packet(buff, src, dst);
    }

  /* send the packet */
  log_(NORMT, "Sending UPDATE locators packet (%d bytes)...\n", location);
  log_(NORM, "Sending UPDATE packet to dst : %s \n", logaddr(dst));
  hip_check_bind(src, HIP_UPDATE_BIND_CHECKS);
  return(hip_send(buff, location, src, dst, hip_a, FALSE));
}

/*
 *
 * function hip_send_close()
 *
 * in:		hip_a = HIP association containing valid source/destination
 *                      addresses, HITs, SPIs, key material, pub key
 *              send_ack   = send CLOSE_ACK if true, CLOSE otherwise
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
  __u8 buff[sizeof(hiphdr)             +
            sizeof(tlv_echo)           + 3 + MAX_OPAQUE_SIZE +
            sizeof(tlv_hmac)           + sizeof(tlv_hip_sig) +
            MAX_SIG_SIZE + 2];

  int location = 0;
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

  if (send_ack && !hip_a->opaque)
    {
      log_(ERR, "CLOSE_ACK requested with no opaque data!\n");
      return(-1);
    }

  if (send_ack)         /* ECHO_RESPONSE */
    {
      location += build_tlv_echo_response(PARAM_ECHO_RESPONSE,
                                          hip_a->opaque->opaque_len,
                                          &buff[location],
                                          hip_a->opaque->opaque_data);
      location = eight_byte_align(location);
      free(hip_a->opaque);
      hip_a->opaque = NULL;
    }
  else                  /* ECHO_REQUEST */
    {           /* generate a 4-byte nonce and save it to hip_a->opaque */
      if (hip_a->opaque)             /* this should not be set */
        {
          free(hip_a->opaque);
        }
      hip_a->opaque = (struct opaque_entry*)
                      malloc(sizeof(struct opaque_entry));
      if (hip_a->opaque == NULL)
        {
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
  hiph->hdr_len = (location / 8) - 1;
  location += build_tlv_hmac(hip_a, buff, location, PARAM_HMAC);

  /* HIP signature */
  hiph->hdr_len = (location / 8) - 1;
  location +=  build_tlv_signature(hip_a->hi, buff, location, FALSE);

  hiph->hdr_len = (location / 8) - 1;
  hiph->checksum = 0;
  if (!hip_a->udp)
    {
      hiph->checksum = checksum_packet(buff, src, dst);
    }

  /* send the packet */
  log_(NORMT, "sending CLOSE%s packet (%d bytes)...\n",
       send_ack ? "_ACK" : "", location);
  /* CLOSE_ACK packet is not scheduled for retransmission */
#ifdef __MACOSX__
  if (hip_a->ipfw_rule > 0)
    {
      del_divert_rule(hip_a->ipfw_rule);
      hip_a->ipfw_rule = 0;
    }
#endif
  return(hip_send(buff, location, HIPA_SRC(hip_a), HIPA_DST(hip_a),
                  hip_a, !send_ack));
}

/*
 *
 * function hip_send_notify()
 *
 * in:		hip_a = HIP association containing valid source/destination
 *                      addresses, HITs, SPIs, key material, pub key
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
  __u8 buff[sizeof(hiphdr)            + sizeof(tlv_notify) +
            sizeof(tlv_host_id)       + 1 + DSA_PRIV +
            3 * (MAX_HI_BITS / 8)         + MAX_HI_NAMESIZE +
            sizeof(tlv_hip_sig)       + MAX_SIG_SIZE + 2];
  int location = 0;
  tlv_notify *notify;
  char msg[32];

  /* silent NO-OP if NOTIFY has been disabled */
  if (HCNF.disable_notify)
    {
      return(0);
    }

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
  if (data_len > 0)
    {
      memcpy(notify->notify_data, data, data_len);
      notify->length = htons((__u16)((sizeof(tlv_notify) - 4) +
                                     data_len));
      location += data_len;
    }
  location = eight_byte_align(location);

  /* HIP signature */
  hiph->hdr_len = (location / 8) - 1;
  location +=  build_tlv_signature(hip_a->hi, buff, location, FALSE);

  hiph->hdr_len = (location / 8) - 1;
  hiph->checksum = 0;
  if (!hip_a->udp)
    {
      hiph->checksum = checksum_packet(buff, src, dst);
    }

  /* send the packet */
  sprintf(msg, "Sent NOTIFY (code %d)", code);
  log_hipa_fromto(QOUT, msg, hip_a, FALSE, TRUE);
  /* NOTIFY packet is not scheduled for retransmission */
  return(hip_send(buff, location, HIPA_SRC(hip_a), HIPA_DST(hip_a),
                  NULL, FALSE));
}

/*
 * function hip_send()
 *
 * in:		data = pointer to data to send
 *              len = length of data
 *              hip_a = hip assoc for getting src, dst addresses and for
 *                      storing packet for retransmission
 *              retransmit = flag T/F to store packet in rexmt_cache
 *
 * out:		returns bytes sent
 *
 * Creates socket, binds, connects, and does sendmsg();
 * packets are saved when sent so they can be retransmitted.
 *
 */
int hip_send(__u8 *data, int len, struct sockaddr* src, struct sockaddr* dst,
             hip_assoc *hip_a, int retransmit)
{
  int s, flags, err = 0;
  struct timeval time1;
  int out_len, offset, do_retransmit = FALSE, do_udp = FALSE;
  __u8 *out;
  udphdr *udph;
  __u32 *p32;
#ifndef __WIN32__
  /* on win32 we use send(), otherwise use sendmsg() */
  struct msghdr msg = {0};
  struct iovec iov;
#endif /* __WIN32__ */

  out_len = len;
  offset = 0;

  if ((hip_a != NULL) && (!OPT.no_retransmit && retransmit))
    {
      do_retransmit = TRUE;
    }

  /* A non-zero port number in the destination address inidcates
   * that UDP encapsulation should be used. */
  if ((dst->sa_family == AF_INET) &&
      (((struct sockaddr_in *)dst)->sin_port > 0))
    {
      if (src->sa_family != AF_INET)
        {
          log_(WARN, "hip_send(): src and dst have different "
               "address families\n");
          return(-1);
        }
      do_udp = TRUE;
      out_len += sizeof(udphdr) + sizeof(__u32);
      offset = sizeof(udphdr) + sizeof(__u32);
    }

  /* malloc and memcpy the supplied data */
  if (do_retransmit || do_udp)
    {
      out = malloc(out_len);
      if (!out)
        {
          log_(WARN, "hip_send() malloc error\n");
          return(-1);
        }
      memset(out, 0, out_len);
      memcpy(&out[offset], data, len);
      /* no malloc and memcpy needed */
    }
  else
    {
      out = data;
    }

  if (do_udp)
    {
      /* TODO: experiment with ephemeral ports here */
      ((struct sockaddr_in *)src)->sin_port = htons(HIP_UDP_PORT);
      udph = (udphdr *) out;
      udph->src_port = htons(HIP_UDP_PORT);
      udph->dst_port = ((struct sockaddr_in*)dst)->sin_port;
      udph->len = htons((__u16)out_len);
      udph->checksum = 0;
      udph->checksum = checksum_udp_packet(out, src, dst);
      p32 = (__u32 *) &out[sizeof(udphdr)];
      *p32 = 0;           /* zero ESP SPI marker */
    }

#ifndef __WIN32__
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  iov.iov_len = out_len;
  iov.iov_base = out;
#endif /* __WIN32__ */

  s = socket(src->sa_family, SOCK_RAW, do_udp ? H_PROTO_UDP : H_PROTO_HIP);
  if (s < 0)
    {
      log_(WARN, "hip_send() socket() error: %s.\n", strerror(errno));
      err = -1;
      goto queue_retrans;
    }

  if (bind(s, src, SALEN(src)) < 0)
    {
      log_(WARN, "bind(%s) error: %s.\n",
           logaddr(src), strerror(errno));
      err = -1;
      goto queue_retrans;
    }

  if (connect(s, dst, SALEN(dst)) < 0)
    {
      log_(WARN, "connect(%s) error: %s.\n",
           logaddr(dst), strerror(errno));
      err = -1;
      goto queue_retrans;
    }

  log_(NORMT, "Sending HIP packet on %s socket\n", do_udp ? "UDP" : "RAW");
  flags = 0;
#ifndef __WIN32__
  if ((len = sendmsg(s, &msg, flags)) != out_len)
    {
      log_(WARN, "Sent unexpected length: %d", len);
    }
#else
  if (sendto(s, out, out_len, 0, dst, SALEN(dst)) < 0)
    {
      log_(WARN, "sendto(%s) error: %s.\n",
           logaddr(dst), strerror(errno));
      err = -1;
    }
#endif

  /* queue packet for retransmission, even if there are errors */
queue_retrans:
  if (hip_a != NULL)         /* XXX incorrect for RVS relaying */
    {
      clear_retransmissions(hip_a);
    }
  if (do_retransmit)         /* out buffer freed by hip_retransmit_wait...() */
    {
      hip_a->rexmt_cache.packet = out;
      hip_a->rexmt_cache.len = out_len;
      gettimeofday(&time1, NULL);
      hip_a->rexmt_cache.xmit_time.tv_sec = time1.tv_sec;
      hip_a->rexmt_cache.xmit_time.tv_usec = time1.tv_usec;
      hip_a->rexmt_cache.retransmits = 0;
      memcpy(&hip_a->rexmt_cache.dst, dst, SALEN(dst));
    }
  else if (do_udp)
    {
      free(out);
    }

  closesocket(s);

  return ((err < 0) ? err : out_len);
}

/*
 * function hip_retransmit()
 *
 * in:		hip_a = hip association
 *              data = packet data
 *              len = data length
 *              src = source address to bind to
 *              dst = destination address to send to
 *
 * out:		returns bytes sent if successful, -1 otherwise
 *
 * Retransmit a saved packet.
 */
int hip_retransmit(hip_assoc *hip_a, __u8 *data, int len,
                   struct sockaddr *src, struct sockaddr *dst)
{
  int s, err, use_udp;
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
    {
      use_udp = FALSE;
    }
  else
    {
      use_udp = hip_a->udp;
    }

  s = socket(src->sa_family, SOCK_RAW,
             use_udp ? H_PROTO_UDP : H_PROTO_HIP);
  if (s < 0)
    {
      log_(WARN, "hip_retransmit() socket() error: %s.\n",
           strerror(errno));
      return(-1);
    }

  if (bind(s, src, SALEN(src)) < 0)
    {
      log_(WARN, "hip_retransmit() bind(%s) error: %s.\n",
           logaddr(src), strerror(errno));
      return(-1);
    }
  if (connect(s, dst, SALEN(dst)) < 0)
    {
      log_(WARN, "hip_retransmit() connect(%s) error: %s.\n",
           logaddr(dst), strerror(errno));
      return(-1);
    }

  /* send the packet */
#ifndef __WIN32__
  if ((err = sendmsg(s, &msg, 0)) < 0)
    {
      log_(WARN, "hip_retransmit() sendmsg() error: %s",
           strerror(errno));
    }
#else
  if ((err = sendto(s, data, len, 0, dst, SALEN(dst))) < 0)
    {
      log_(WARN, "hip_retransmit() sendto() error: %s",
           strerror(errno));
    }
#endif
  closesocket(s);

  return(err);
}

/*
 * function hip_check_bind()
 *
 * in:		addr = pointer to address to bind
 *              num_attempts = number of times to try the bind() call
 *
 * out:		returns 0 if bind is successful, -1 otherwise
 *
 * Check if it is possible to bind() to an address.
 */
int hip_check_bind(struct sockaddr *src, int num_attempts)
{
  int i, s, ret = 0;

  if (num_attempts == 0)
    {
      return(0);
    }

  s = socket(src->sa_family, SOCK_RAW, H_PROTO_HIP);

  for (i = 0; i < num_attempts; i++)
    {
      if (bind(s, src, SALEN(src)) < 0)
        {
          ret = -1;
#ifdef __WIN32__
          Sleep(25);               /* wait for address to become avail. */
#else
          usleep(25000);               /* wait for address to become avail. */
#endif
        }
      else
        {
          ret = 0;               /* bind successful */
          break;
        }
    }

  closesocket(s);
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

  if (dh == NULL)
    {
      log_(WARN, "No Diffie Hellman context for DH tlv.\n");
      return(0);
    }

  d = (tlv_diffie_hellman*) data;
  d->type = htons(PARAM_DIFFIE_HELLMAN);
  d->group_id =  group_id;

  /* put dh->pub_key into tlv */
  len = dhprime_len[group_id];
  bin = (unsigned char*) malloc(len);
  if (!bin)
    {
      log_(WARN, "malloc error - generating Diffie Hellman\n");
      return(0);
    }
  len = bn2bin_safe(dh->pub_key, bin, len);
  memcpy(d->pub, bin, len);

  d->pub_len = ntohs((__u16)len);
  d->length = htons((__u16)(3 + len));       /* group_id + pub */

#ifndef HIP_VPLS
  if (D_VERBOSE == debug)
    {
      log_(NORM, "Using DH public value of len %d: 0x", len);
      print_hex(bin, len);
      log_(NORM, "\n");
    }
#endif
  free(bin);

  len += 5;       /* tlv hdr + group_id + pub */
  len = eight_byte_align(len);
  return(len);
}

/*
 * Returns number of bytes that it advances
 * Transforms is a pointer to an array of transforms to include.
 * Single is for specifying a single transform to use (i.e., in I2).
 */
int build_tlv_transform(__u8 *data, int type, __u16 *transforms, __u16 single)
{
  int i, len = 0;
  tlv_head *tlv;
  tlv_hip_transform *hip_trans;
  tlv_esp_transform *esp_trans;
  __u16 *transform_id;

  tlv = (tlv_head*) data;
  tlv->type = htons((__u16)type);
  len += 4;       /* advance for type, length */
  if (type == PARAM_HIP_TRANSFORM)
    {
      hip_trans = (tlv_hip_transform*) data;
      transform_id = &hip_trans->transform_id;
    }
  else           /* PARAM_ESP_TRANSFORM */
    {
      esp_trans = (tlv_esp_transform*) data;
      /* set E-bit here if using 64-bit sequence numbers */
      esp_trans->reserved = 0x0000;
      transform_id = &esp_trans->suite_id;
      len += 2;
    }
  if (single > 0)
    {
      *transform_id = htons(single);
      len += 2;
    }
  else
    {
      for (i = 0; (i < SUITE_ID_MAX) && (transforms[i] > 0); i++)
        {
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

  switch (hi->algorithm_id)
    {
    case HI_ALG_DSA:            /*       tlv + T + Q + P,G,Y */
      if (!hi->dsa)
        {
          log_(WARN, "No DSA context when building length!\n");
          return(0);
        }
      hi_len = sizeof(tlv_host_id) + 1 + DSA_PRIV + 3 * hi->size;
      break;
    case HI_ALG_RSA:            /*       tlv + e_len,e + N */
      if (!hi->rsa)
        {
          log_(WARN, "No RSA context when building length!\n");
          return(0);
        }
      hi_len = sizeof(tlv_host_id) + 1 + BN_num_bytes(hi->rsa->e)
               + RSA_size(hi->rsa);
      if (BN_num_bytes(hi->rsa->e) > 255)
        {
          hi_len += 2;
        }
      break;
    default:
      break;
    }

  /* use stored length instead of strlen(hi->name), because other
   * implementations may count a trailing NULL */
  if (use_hi_name && (hi->name_len > 0))
    {
      hi_len += hi->name_len;
    }

  return(eight_byte_align(hi_len));
}

int build_tlv_hostid(__u8 *data, hi_node *hi, int use_hi_name)
{
  int len, di_len = 0;
  __u32 hi_hdr;
  __u16 e_len;
  tlv_host_id *hostid;

  hostid = (tlv_host_id*) data;
  hostid->type = htons(PARAM_HOST_ID);
  hostid->hi_length = 0;       /* set this later */
  if (use_hi_name && (hi->name_len > 0))
    {
      /* 4 bits type + 12 bits length */
      di_len = hi->name_len;           /* preserves any trailing NULL */
      hostid->di_type_length =  htons((__u16)((DIT_FQDN << 12) |
                                              di_len));
    }
  else
    {
      hostid->di_type_length = 0;
    }

  /* RDATA word(32): flags(16), proto(8), alg(8) */
  /* flags = 0x..01 - key is associated with non-zone entity, or host */
  hi_hdr = htonl(0x0202ff00 | hi->algorithm_id);
  memcpy(hostid->hi_hdr, &hi_hdr, 4);
  len = sizeof(tlv_host_id);       /* 12 */

  switch (hi->algorithm_id)
    {
    case HI_ALG_DSA:     /* RDATA word: flags(16), proto(8), alg(8) */
      data[len] = (__u8) (hi->size - 64) / 8;           /* T value (1 byte) */
      len++;
      len += bn2bin_safe(hi->dsa->q, &data[len], DSA_PRIV);
      len += bn2bin_safe(hi->dsa->p, &data[len], hi->size);
      len += bn2bin_safe(hi->dsa->g, &data[len], hi->size);
      len += bn2bin_safe(hi->dsa->pub_key, &data[len], hi->size);
      break;
    case HI_ALG_RSA:
      e_len = BN_num_bytes(hi->rsa->e);
      /* exponent length */
      if (e_len <= 255)
        {
          data[len] = (__u8) e_len;
          len++;
        }
      else
        {
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
  if (di_len > 0)
    {
      sprintf((char *)&data[len], "%s", hi->name);
      len += di_len;
    }
  /* Subtract off 4 for Type, Length in TLV */
  hostid->length = htons((__u16)(len - 4));
  return(eight_byte_align(len));
}

/*
 * function build_tlv_locators()
 *
 * in:		data  = ptr to destination buffer
 *              addrs = list of addresses to include in the locator TLV
 *              spi   = SPI to use with LOCATOR_TYPE_SPI_IPV6 format
 *              force = when TRUE, add locators regardless of locator state
 *
 * out:		returns aligned length of buffer used
 *
 * All locators are included in the locator TLV (no incremental updates).
 * One has the preferred bit set.
 * This TLV will only be built if the force flag is TRUE or there are locators
 * in the addr list in the UNVERIFIED state (they have not already been sent).
 *
 */
int build_tlv_locators(__u8* data, sockaddr_list *addrs, __u32 spi,
                       int force)
{
  int n = 0;
  __u16 len = 0;
  sockaddr_list *l;
  tlv_locator *loc;
  locator *lp;

  /* calculate length based on number of locators */
  for (l = addrs; l; l = l->next)
    {
      len += sizeof(locator);
      if (l->status == UNVERIFIED)
        {
          n++;               /* locator has not already been sent */
        }
    }

  if (!force && (n < 2))         /* no other locators besides preferred */
    {
      return(0);
    }
  if (!force && !OPT.mh)         /* multihoming turned off, don't send all */
    {
      return(0);
    }
  memset(data, 0, len + sizeof(tlv_locator) - sizeof(locator));

  /* build a locator parameter containing all of our addresses */
  loc = (tlv_locator*) data;
  loc->type = htons(PARAM_LOCATOR);
  loc->length = htons(len);
  lp = &loc->locator1[0];

  for (l = addrs, n = 0; l; l = l->next, lp++, n++)
    {
      if (n > MAX_LOCATORS)             /* an artificial limit (for buff size)
                                         */
        {
          break;
        }
      lp->traffic_type = LOCATOR_TRAFFIC_TYPE_BOTH;
      lp->locator_type = LOCATOR_TYPE_SPI_IPV6;
      lp->locator_length = 5;           /* (32 + 128 bits) / 4 */
      if (l == addrs)             /* l->preferred */
        {
          lp->reserved = LOCATOR_PREFERRED;               /* set the P-bit */
        }
      else
        {
          lp->reserved = 0;
        }
      lp->locator_lifetime = htonl(HCNF.loc_lifetime);
      build_spi_locator(lp->locator, htonl(spi), SA(&l->addr));
      /* flag that this locator has been sent to peer */
      l->status = ACTIVE;
    }

  len += sizeof(tlv_locator) - sizeof(locator);
  return(eight_byte_align(len));
}

/* 32-bit SPI + 128-bit IPv6/IPv4-in-IPv6 address
 */
int build_spi_locator(__u8 *data, __u32 spi, struct sockaddr *addr)
{
  const int locator_size = 20;       /* 32 + 128 bits */
  memset(data, 0, locator_size);
  memcpy(&data[0], &spi, 4);
  if (addr->sa_family == AF_INET6)
    {
      memcpy(&data[4], SA2IP(addr), SAIPLEN(addr));
    }
  else           /* IPv4-in-IPv6 address format */
    {
      memset(&data[14], 0xFF, 2);
      memcpy(&data[16], SA2IP(addr), SAIPLEN(addr));
    }
  return(locator_size);
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
  return(0);
}

int build_tlv_signature(hi_node *hi, __u8 *data, int location, int R1)
{
  /* HIP sig */
  SHA_CTX c;
  unsigned char md[SHA_DIGEST_LENGTH] = {0};
  DSA_SIG *dsa_sig;
  tlv_hip_sig *sig;
  unsigned int sig_len;
  int err;

  if ((hi->algorithm_id == HI_ALG_DSA) && !hi->dsa)
    {
      log_(WARN, "No DSA context for building signature TLV.\n");
      return(0);
    }
  else if ((hi->algorithm_id == HI_ALG_RSA) && !hi->rsa)
    {
      log_(WARN, "No RSA context for building signature TLV.\n");
      return(0);
    }

  /* calculate SHA1 hash of the HIP message */
  SHA1_Init(&c);
  SHA1_Update(&c, data, location);
  SHA1_Final(md, &c);

  /* build tlv header */
  sig = (tlv_hip_sig*) &data[location];
  sig->type = htons((__u16)((R1 == TRUE) ? PARAM_HIP_SIGNATURE_2 :
                            PARAM_HIP_SIGNATURE));
  sig->length = 0;       /* set this later */
  sig->algorithm = hi->algorithm_id;


  switch (hi->algorithm_id)
    {
    case HI_ALG_DSA:
      sig_len = HIP_DSA_SIG_SIZE;
      memset(sig->signature, 0, sig_len);
      sig->signature[0] = 8; /* T */
      /* calculate the DSA signature of the message hash */
      dsa_sig = DSA_do_sign(md, SHA_DIGEST_LENGTH, hi->dsa);
      /* build signature from DSA_SIG struct */
      bn2bin_safe(dsa_sig->r, &sig->signature[1], 20);
      bn2bin_safe(dsa_sig->s, &sig->signature[21], 20);
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
      if (!err)
        {
          log_(WARN, "RSA_sign() error: %s",
               ERR_error_string(ERR_get_error(), NULL));
        }
      break;
    default:
      break;
    }

  /* signature debugging */
  if (!R1 || (D_VERBOSE == OPT.debug_R1))
    {
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

/*
 * build_tlv_hmac()
 */
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

  switch (hip_a->hip_transform)
    {
    case ESP_AES_CBC_HMAC_SHA1:
    case ESP_3DES_CBC_HMAC_SHA1:
    case ESP_BLOWFISH_CBC_HMAC_SHA1:
    case ESP_NULL_HMAC_SHA1:
      HMAC(   EVP_sha1(),
              get_key(hip_a, HIP_INTEGRITY, FALSE),
              auth_key_len(hip_a->hip_transform),
              data, location,
              hmac_md, &hmac_md_len  );
      break;
    case ESP_3DES_CBC_HMAC_MD5:
    case ESP_NULL_HMAC_MD5:
      HMAC(   EVP_md5(),
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
          &hmac_md[hmac_md_len - sizeof(hmac->hmac)],
          sizeof(hmac->hmac));
  return(eight_byte_align(sizeof(tlv_hmac)));
}

/*
 * build_tlv_reg_info()
 *
 * If there are any registration types stored in HCNF.reg_types[] then we
 * are acting as a registrar and include them in the REG_INFO TLV here.
 */
int build_tlv_reg_info(__u8 *data)
{
  tlv_reg_info *info = (tlv_reg_info*) data;
  __u8 *reg_types;
  char str[128];
  int len = 0, i;

  /* this server is not offering any registration types,
   * i.e, not a registrar */
  if ((HCNF.num_reg_types == 0) ||
      (HCNF.num_reg_types > MAX_REGISTRATION_TYPES))
    {
      return(0);
    }

  len += 4;
  info->type = htons(PARAM_REG_INFO);
  info->length = htons((__u16)(2 + HCNF.num_reg_types));
  len += 2 + HCNF.num_reg_types;
  info->min_lifetime = HCNF.min_reg_lifetime;
  info->max_lifetime = HCNF.max_reg_lifetime;
  reg_types = &(info->reg_type);
  for (i = 0; i < HCNF.num_reg_types; i++)
    {
      if (regtype_to_string(HCNF.reg_types[i], str,
                            sizeof(str)) < 0)
        {
          continue;               /* unknown type */
        }
      reg_types[i] = HCNF.reg_types[i];
      /*	log_(NORM, "Offering registration type %d: %s\n",
       *               HCNF.reg_types[i], str); */
    }

  return(eight_byte_align(len));
}

/*
 * build_tlv_reg_req()
 */
int build_tlv_reg_req(__u8 *data, struct reg_entry *regs)
{
  double tmp;
  tlv_reg_request *req = (tlv_reg_request*) data;
  __u8 *reg_typep = &(req->reg_type);
  __u8 lifetime;
  __u16 num = 0;
  struct reg_info *reg;
  char str[128];

  if (!regs || !regs->reginfos)
    {
      return(0);
    }
  lifetime = regs->max_lifetime;

  for (reg = regs->reginfos; reg; reg = reg->next)
    {
      if (regtype_to_string(reg->type, str, sizeof(str)) < 0)
        {
          continue;               /* skip unknown types */
        }
      if (reg->state == REG_OFFERED)
        {
          log_(NORM, "Requesting registration with %d %s.\n",
               reg->type, str);
          reg->state = REG_REQUESTED;
        }
      else if (reg->state == REG_SEND_CANCELLED)
        {
          log_(NORM, "Canceling registration with %d %s.\n",
               reg->type, str);
          reg->state = REG_CANCELLED;
          lifetime = 0;
        }
      else               /* skip regs in other states */
        {
          continue;
        }
      gettimeofday(&reg->state_time, NULL);
      *reg_typep = reg->type;
      num++;
      reg_typep++;
    }

  if (num)
    {
      req->type = htons(PARAM_REG_REQUEST);
      req->length = htons((__u16)(1 + num));           /* lifetime+reg_types */
      req->lifetime = lifetime;
      tmp = YLIFE(req->lifetime);
      tmp = pow(2, tmp);
      log_(NORM, "Requested lifetime = %d (%.3f seconds)\n",
           req->lifetime, tmp);
      /* tlv struct already includes one reg_type */
      return(eight_byte_align(sizeof(tlv_reg_request) + (num - 1)));
    }
  return(0);
}

int build_tlv_reg_resp(__u8 *data, struct reg_entry *regs)
{
  tlv_reg_response *resp = (tlv_reg_response *) data;
  double tmp;
  __u8 *reg_typep = &(resp->reg_type);
  __u8 lifetime = 0;
  __u16 num = 0;
  struct reg_info *reg;
  char str[128];

  for (reg = regs->reginfos; reg; reg = reg->next)
    {
      if (regtype_to_string(reg->type, str, sizeof(str)) < 0)
        {
          continue;               /* skip unknown types */
        }
      if (reg->state == REG_SEND_RESP)
        {
          reg->state = REG_GRANTED;
          lifetime = reg->lifetime;
          log_(NORM, "Client registered with type %d %s\n",
               reg->type, str);
        }
      else if (reg->state == REG_SEND_CANCELLED)
        {
          reg->state = REG_CANCELLED;
          lifetime = 0;
          log_(NORM, "Client canceled type %d %s\n",
               reg->type, str);
        }
      else               /* skip other registration states */
        {
          continue;
        }
      gettimeofday(&reg->state_time, NULL);
      *reg_typep = reg->type;
      reg_typep++;
      num++;
    }

  if (num)
    {
      resp->type = htons(PARAM_REG_RESPONSE);
      resp->length = htons((__u16)(1 + num));           /* lifet. + reg_types */
      resp->lifetime = lifetime;

      tmp = YLIFE(resp->lifetime);
      tmp = pow(2, tmp);
      log_(NORM, "Registered lifetime = %d (%.3f seconds)\n",
           resp->lifetime, tmp);

      return (eight_byte_align(sizeof(tlv_reg_response) + (num - 1)));
    }
  return(0);
}

/* TODO: support different fail types */
int build_tlv_reg_failed(__u8 *data, struct reg_entry *regs)
{
  tlv_reg_failed *fail = (tlv_reg_failed*) data;
  __u8 *reg_typep = &(fail->reg_type);
  __u8 failure_code = REG_FAIL_TYPE_UNAVAIL;
  __u16 num = 0;
  struct reg_info *reg;

  for (reg = regs->reginfos; reg; reg = reg->next)
    {
      if (reg->state != REG_SEND_FAILED)
        {
          continue;
        }

      reg->state = REG_FAILED;
      gettimeofday(&reg->state_time, NULL);
      *reg_typep = reg->type;
      /* currently unused: */
      /* failure_code = reg->failure_code; */
      log_(NORM, "Failed to register client with type %d\n",
           reg->type);
      reg_typep++;
      num++;
    }

  if (num)
    {
      fail->type = htons(PARAM_REG_FAILED);
      fail->length = htons((__u16)(1 + num));           /* fail_type+reg_types
                                                         */
      fail->fail_type = failure_code;
      return (eight_byte_align(sizeof(tlv_reg_failed) + (num - 1)));
    }
  return(0);
}

/* Create a new rekey structure in hip_a, taking into account keymat size
 * and whether or not peer initiated a rekey.
 */
int build_rekey(hip_assoc *hip_a)
{
  __u8 new_group_id = 0;
  dh_cache_entry *dh_entry;

  if (!hip_a)
    {
      return(-1);
    }
  if (hip_a->rekey)
    {
      log_(WARN,"build_rekey called with existing rekey structure\n");
      return(-1);
    }

  /* hip_a->rekey will be used in a new UPDATE
   * keymat_index = index to use in ESP_INFO
   * dh_group_id, dh = new DH key to send
   */
  hip_a->rekey = malloc(sizeof(struct rekey_info));
  if (!hip_a->rekey)
    {
      log_(WARN, "build_rekey malloc() error\n");
      return(-1);
    }
  memset(hip_a->rekey, 0, sizeof(struct rekey_info));
  /* Check for peer-initiated rekeying parameters */
  if (hip_a->peer_rekey)
    {
      if (hip_a->peer_rekey->dh)
        {
          /* use peer-suggested group ID */
          new_group_id = hip_a->rekey->dh_group_id;
          hip_a->rekey->keymat_index = 0;
        }
      else               /* use peer-suggested keymat index */
        {
          hip_a->rekey->keymat_index =
            hip_a->peer_rekey->keymat_index;
        }
    }
  else
    {
      hip_a->rekey->keymat_index = hip_a->keymat_index;
    }

  /* Generate new DH if we were to run out of keymat material when
   * drawing 4 new ESP keys or if the proposed DH group is different */
  if (((hip_a->rekey->keymat_index + (4 * HIP_KEY_SIZE)) >
       KEYMAT_SIZE) ||
      (new_group_id && (new_group_id != hip_a->dh_group_id)))
    {
      log_(NORM, "Including a new DH key in UPDATE.\n");
      if (new_group_id == 0)
        {
          new_group_id = hip_a->dh_group_id;
        }
      dh_entry = get_dh_entry(new_group_id, TRUE);
      dh_entry->ref_count++;
      hip_a->rekey->keymat_index = 0;
      hip_a->rekey->dh_group_id = new_group_id;
      hip_a->rekey->dh = dh_entry->dh;
    }

  gettimeofday(&hip_a->rekey->rk_time, NULL);
  hip_a->rekey->new_spi = get_next_spi();
  hip_a->rekey->need_ack = TRUE;
  hip_a->rekey->update_id = hip_a->hi->update_id++;

  return(0);
}

