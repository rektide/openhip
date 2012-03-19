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
 *  \file  hip_keymat.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Implements a HIP Keymat data structure for storing a
 *          shared secret key and it derivitives.
 *
 */
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/des.h> /* DES_KEY_SZ == 8 bytes*/
#include <openssl/dsa.h>
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#include <hip/hip_sadb.h>

#define MAX_KEYS 8

/*
 * keys should be:
 * 0 initiator HIP key (24 bytes (3DES))
 * 1 responder HIP key (24 bytes (3DES))
 * 2 initiator ESP key (24 bytes (3DES))
 * 3 responder ESP key (24 bytes (3DES))
 * 4 initiator AUTH key (20 bytes (SHA))
 * 5 responder AUTH key (20 bytes (SHA))
 */

/*
 * This function takes a Diffie Hellman computed key as binary input and
 * stores it in the hip_a->keymat
 *
 */
int set_secret_key(unsigned char *key, hip_assoc *hip_a)
{
  int keylen;

  if (NULL == key)
    {
      log_(NORM, "set_secret_key() passed in null key\n");
      return(-1);
    }

  keylen = DH_size(hip_a->dh);
  if (hip_a->dh_secret)
    {
      free(hip_a->dh_secret);
    }
  hip_a->dh_secret = key;

#ifndef HIP_VPLS
  log_(NORM, "************\nDH secret key set to:\n0x");
  print_hex(hip_a->dh_secret, keylen);
  log_(NORM, "\n***********\n");
#endif

  return(keylen);
}

/*
 * get_key()
 *
 * IN:		hip_a = contains HITs and keymat
 *		type = type of key to get
 *		peer = TRUE if you want the peer's key, FALSE for keys that
 *			are associated with my HIT.
 * OUT:		Pointer to the proper key from the keymat.
 */
unsigned char *get_key(hip_assoc *hip_a, int type, int peer)
{
  int result, num = 0;

  result = compare_hits(hip_a->peer_hi->hit, hip_a->hi->hit);

  /* result > 0 means peer HIT larger than my HIT */
  switch (type)
    {
    case HIP_ENCRYPTION:
      peer ?  ((result > 0) ? (num = GL_HIP_ENCRYPTION_KEY) :
               (num = LG_HIP_ENCRYPTION_KEY)) :
      ((result > 0) ? (num = LG_HIP_ENCRYPTION_KEY) :
       (num = GL_HIP_ENCRYPTION_KEY));
      break;
    case HIP_INTEGRITY:
      peer ?  ((result > 0) ? (num = GL_HIP_INTEGRITY_KEY) :
               (num = LG_HIP_INTEGRITY_KEY)) :
      ((result > 0) ? (num = LG_HIP_INTEGRITY_KEY) :
       (num = GL_HIP_INTEGRITY_KEY));
      break;
    case ESP_ENCRYPTION:
      peer ?  ((result > 0) ? (num = GL_ESP_ENCRYPTION_KEY) :
               (num = LG_ESP_ENCRYPTION_KEY)) :
      ((result > 0) ? (num = LG_ESP_ENCRYPTION_KEY) :
       (num = GL_ESP_ENCRYPTION_KEY));
      break;
    case ESP_AUTH:
      peer ?  ((result > 0) ? (num = GL_ESP_AUTH_KEY) :
               (num = LG_ESP_AUTH_KEY)) :
      ((result > 0) ? (num = LG_ESP_AUTH_KEY) :
       (num = GL_ESP_AUTH_KEY));
      break;
    default:
      num = 0;
      break;
    }

  return(hip_a->keys[num].key);
}

/*
 * This function will derive and store only the required HIP keys
 * (ESP keys are computed later)
 */
void compute_keys(hip_assoc *hip_a)
{
  compute_keymat(hip_a);
  draw_keys(hip_a, TRUE, 0);
}

/*
 * Compute a new keymat based on the DH secret Kij and HITs
 */
int compute_keymat(hip_assoc *hip_a)
{
  int i, result;
  int location, len, dh_secret_len, hashdata_len;
  char *hashdata;
  unsigned char hash[SHA_DIGEST_LENGTH], last_byte = 1;
  BIGNUM *hit1, *hit2;
  hip_hit *hitp;
  SHA_CTX c;

  if (hip_a == NULL)
    {
      log_(NORM, "no hip_a in compute_keymat()\n");
      return(-1);
    }
  hitp = &(hip_a->peer_hi->hit);
  if (hitp == NULL)
    {
      log_(NORM, "no peer HIT in compute_keymat()\n");
      return(-1);
    }
  hit1 = BN_bin2bn((unsigned char*)hitp, HIT_SIZE, NULL);
  hit2 = BN_bin2bn((unsigned char*)hip_a->hi->hit, HIT_SIZE, NULL);
  result = BN_ucmp(hit1, hit2);

  /* Kij */
  dh_secret_len = DH_size(hip_a->dh);
  hashdata_len = dh_secret_len + (2 * HIT_SIZE) + (2 * sizeof(__u64)) + 1;
  hashdata = malloc(hashdata_len);
  memcpy(hashdata, hip_a->dh_secret, dh_secret_len);
  location = dh_secret_len;
  /* sort(Resp-HIT, Init-HIT) */
  if (result <= 0)         /* hit1 <= hit2 */
    {
      memcpy(&hashdata[location], hitp, HIT_SIZE);
      location += HIT_SIZE;
      memcpy(&hashdata[location],
             hip_a->hi->hit, HIT_SIZE);
      location += HIT_SIZE;
    }
  else           /* hit1 > hit2 */
    {
      memcpy(&hashdata[location],
             hip_a->hi->hit, HIT_SIZE);
      location += HIT_SIZE;
      memcpy(&hashdata[location], hitp, HIT_SIZE);
      location += HIT_SIZE;
    }
  /* I | J */
  memcpy(&hashdata[location], &hip_a->cookie_r.i, sizeof(__u64));
  location += sizeof(__u64);
  memcpy(&hashdata[location], &hip_a->cookie_j, sizeof(__u64));
  location += sizeof(__u64);

  /* 1 */
  memcpy(&hashdata[location], &last_byte, sizeof(last_byte));
  location += sizeof(last_byte);

  /* SHA1 hash the concatenation */
  SHA1_Init(&c);
  SHA1_Update(&c, hashdata, location);
  SHA1_Final(hash, &c);
  memcpy(hip_a->keymat, hash, SHA_DIGEST_LENGTH);
  location = SHA_DIGEST_LENGTH;

  /* compute K2 ... K38
   * 768 bytes / 20 bytes per hash = 38 loops
   * this is enough space for 32 ESP keys
   */
  for (i = 1; i < (KEYMAT_SIZE / SHA_DIGEST_LENGTH); i++)
    {
      last_byte++;
      memcpy(hashdata, hip_a->dh_secret, dh_secret_len);           /* Kij */
      len = dh_secret_len;
      memcpy(&hashdata[len], hash, SHA_DIGEST_LENGTH);           /* K_i) */
      len += SHA_DIGEST_LENGTH;
      memcpy(&hashdata[len], &last_byte, sizeof(last_byte));           /* i+1 */
      len += sizeof(last_byte);
      SHA1_Init(&c);
      SHA1_Update(&c, hashdata, len);
      SHA1_Final(hash, &c);
      /* accumulate the keying material */
      memcpy(&hip_a->keymat[location], hash, SHA_DIGEST_LENGTH);
      location += SHA_DIGEST_LENGTH;
    }
  free(hashdata);
  BN_free(hit1);
  BN_free(hit2);
  return(0);
}

int draw_keys(hip_assoc *hip_a, int draw_hip_keys, int keymat_index)
{
  int location, i, k, max, key_type, len;

  if (hip_a == NULL)
    {
      log_(NORM, "no hip_a in draw_keys()\n");
      return(-1);
    }

  /* erase new key locations */
  if (draw_hip_keys)
    {
      i = 0;
      k = 0;
      max = GL_ESP_ENCRYPTION_KEY;
    }
  else
    {
      i = GL_ESP_ENCRYPTION_KEY;
      k = GL_ESP_ENCRYPTION_KEY;
      max = NUMKEYS;
    }
  for (; i < max; i++)
    {
      memset(hip_a->keys[i].key, 0, HIP_KEY_SIZE);
      hip_a->keys[i].length = 0;
      hip_a->keys[i].type = 0;
    }

  log_(NORM, "Using HIP transform of %d", hip_a->hip_transform);
  if (draw_hip_keys)
    {
      log_(NORM, ".\nDrawing new HIP encryption/integrity keys:\n");
    }
  else
    {
      log_(NORM, " ESP transform of %d.\nDrawing new ESP keys from "
           "keymat index %d:\n", hip_a->esp_transform, keymat_index);
    }

  location = keymat_index;

  /* draw keys from the keymat */
  for (; k < max; k++)
    {
      /* decide what type/length of key to use */
      switch (k)
        {
        case GL_HIP_ENCRYPTION_KEY:             /* ENCRYPTED payload keys */
        case LG_HIP_ENCRYPTION_KEY:
          key_type = hip_a->hip_transform;
          len = enc_key_len(key_type);
          break;
        case GL_HIP_INTEGRITY_KEY:              /* HMAC keys */
        case LG_HIP_INTEGRITY_KEY:
          key_type = hip_a->hip_transform;
          len = auth_key_len(key_type);
          break;
        case GL_ESP_ENCRYPTION_KEY:             /* ESP encryption keys */
        case LG_ESP_ENCRYPTION_KEY:
          key_type = hip_a->esp_transform;
          len = enc_key_len(key_type);
          break;
        case GL_ESP_AUTH_KEY:           /* ESP authentication keys */
        case LG_ESP_AUTH_KEY:
          key_type = hip_a->esp_transform;
          len = auth_key_len(key_type);
          break;
        default:
          key_type = 0;               /* no key */
          len = 0;
          break;
        }
      /* load the key */
      hip_a->keys[k].type = key_type;
      hip_a->keys[k].length = len;
      memset(hip_a->keys[k].key, 0, HIP_KEY_SIZE);
      if ((location + len) > KEYMAT_SIZE)
        {
          log_(NORM, "No more keymat material for key %d!\n", k);
          return(-1);
        }

      log_(NORM, "Key %d (%d,%d) keymat[%3d] 0x",
           k, key_type, len, location);
      if (len)
        {
          memcpy(hip_a->keys[k].key,
                 &hip_a->keymat[location], len);
          location += len;
        }
      print_hex(hip_a->keys[k].key, len);
      log_(NORM, "\n");
    }

  hip_a->keymat_index = location;
  return(location);
}

int draw_mr_key(hip_assoc *hip_a, int keymat_index)
{
  int location, key_type, len;

  if (hip_a == NULL)
    {
      log_(NORM, "no hip_a in draw_mr_key()\n");
      return(-1);
    }

  location = keymat_index;
  key_type = hip_a->hip_transform;
  len = auth_key_len(key_type);
  hip_a->mr_key.type = key_type;
  hip_a->mr_key.length = len;
  if ((location + len) > KEYMAT_SIZE)
    {
      log_(NORM, "No more keymat material for mobile router key!\n");
      return(-1);
    }
  log_(NORM, "Mobile router key (%d,%d) keymat[%3d] 0x",
       key_type, len, location);
  if (len)
    {
      memcpy(hip_a->mr_key.key, &hip_a->keymat[location], len);
      location += len;
    }
  print_hex(hip_a->mr_key.key, len);
  log_(NORM, "\n");

  hip_a->keymat_index = location;
  return(location);
}

int auth_key_len(int suite_id)
{
  switch (suite_id)
    {
    case ESP_AES_CBC_HMAC_SHA1:
    case ESP_3DES_CBC_HMAC_SHA1:
    case ESP_BLOWFISH_CBC_HMAC_SHA1:
    case ESP_NULL_HMAC_SHA1:
      return(KEY_LEN_SHA1);
    case ESP_3DES_CBC_HMAC_MD5:
    case ESP_NULL_HMAC_MD5:
      return(KEY_LEN_MD5);
    default:
      break;
    }
  return(0);
}

int enc_key_len(int suite_id)
{
  switch (suite_id)
    {
    case ESP_AES_CBC_HMAC_SHA1:
      return(KEY_LEN_AES);
    case ESP_3DES_CBC_HMAC_SHA1:
    case ESP_3DES_CBC_HMAC_MD5:
      return(KEY_LEN_3DES);
    case ESP_BLOWFISH_CBC_HMAC_SHA1:
      return(KEY_LEN_BLOWFISH);
    case ESP_NULL_HMAC_SHA1:
    case ESP_NULL_HMAC_MD5:
      return(KEY_LEN_NULL);
    default:
      break;
    }
  return(0);
}

int enc_iv_len(int suite_id)
{
  switch (suite_id)
    {
    case ESP_AES_CBC_HMAC_SHA1:
      return(16);               /* AES uses 128-bit IV */
    case ESP_3DES_CBC_HMAC_SHA1:
    case ESP_3DES_CBC_HMAC_MD5:
    case ESP_BLOWFISH_CBC_HMAC_SHA1:
      return(8);                /* 64-bit IV */
    case ESP_NULL_HMAC_SHA1:
    case ESP_NULL_HMAC_MD5:
      return(0);
    default:
      break;
    }
  return(0);
}

int transform_to_ealg(int transform)
{
  switch (transform)
    {
    case ESP_AES_CBC_HMAC_SHA1:                 /* AES-CBC enc */
      return(SADB_X_EALG_AESCBC);
    case ESP_3DES_CBC_HMAC_SHA1:                /* 3DES-CBC enc */
    case ESP_3DES_CBC_HMAC_MD5:
      return(SADB_EALG_3DESCBC);
    case ESP_BLOWFISH_CBC_HMAC_SHA1:            /* BLOWFISH-CBC enc */
      return(SADB_X_EALG_BLOWFISHCBC);
    case ESP_NULL_HMAC_SHA1:                    /* NULL enc */
    case ESP_NULL_HMAC_MD5:
      return(SADB_EALG_NULL);
    default:
      return(0);
    }
}

int transform_to_aalg(int transform)
{
  switch (transform)
    {
    case ESP_AES_CBC_HMAC_SHA1:                 /* HMAC-SHA1 auth */
    case ESP_3DES_CBC_HMAC_SHA1:
    case ESP_BLOWFISH_CBC_HMAC_SHA1:
    case ESP_NULL_HMAC_SHA1:
      return(SADB_AALG_SHA1HMAC);
    case ESP_3DES_CBC_HMAC_MD5:                 /* HMAC-MD5 auth */
    case ESP_NULL_HMAC_MD5:
      return(SADB_AALG_MD5HMAC);
    default:
      return(0);
    }
}

