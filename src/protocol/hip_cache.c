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
 *  \file  hip_cache.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson <thomas.r.henderson@boeing.com>
 *
 *  \brief  R1 Management Cache
 *          Stores precomputed R1s and their cookie solutions.
 *          Also stores DH contexts.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/time.h>
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>
#endif
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/asn1.h>
#include <openssl/rand.h>
#ifndef __WIN32__
#include <netinet/ip6.h>
#endif
#include <sys/types.h>
#include <errno.h>
#include <hip/hip_types.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>


static __u32 current_rand;  /* current random num. used to get cookie index  */
static __u32 previous_rand; /* previous random num. used to get cookie index */
static int current_index = 0; /* index of R1 cache slot replaced next */

/************************************
 *       R1 Cache functions         *
 ***********************************/
/* The R1 cache is a hash table of precomputed R1s. Each Host Identity bears
 * it's own R1 cache so that packets can be pre-signed for that HI.
 * Periodically one of the entries is expired and re-created in a round-robin
 * fashion. Each R1 cache entry contains its own cookie puzzle, and the
 * previously-used cookie puzzle. Entries also point to the DH entry of the
 * context used in the R1 packet.
 */


/*
 * ini_all_R1_caches
 *
 * in/out:	none
 *
 * Initialize all of my Host Identities
 * (Call init_R1_cache for every HI in my_hi_head.)
 */
void init_all_R1_caches()
{
  hi_node *h;
  /* assume random number generator already seeded by init_crypto() */

  /* pick a new random number for cookie mapping function */
  RAND_bytes((unsigned char *)&current_rand, 4);
  previous_rand = 0;

  /* initialize the cache for every one of our HIs */
  for (h = my_hi_head; h; h = h->next)
    {
      init_R1_cache(h);
    }
}

/*
 * init_R1_cache()
 *
 * in:		hi = the HI containing the R1 cache to initialize
 *
 * Populate the R1 cache with pre-computed R1s.
 */
void init_R1_cache(hi_node *hi)
{
  int i, len;
  r1_cache_entry *entry;

  if (!hi)
    {
      return;
    }

  log_(NORM, "Initializing R1 cache entries for identity %s (%d slots)."
       "\n", hi->name, R1_CACHE_SIZE);

  /* increase generation counter for this new set of R1s */
  if (hi->r1_gen_count > 0)
    {
      hi->r1_gen_count++;
    }

  len = calculate_r1_length(hi);

  for (i = 0; i < R1_CACHE_SIZE; i++)
    {
      entry = &hi->r1_cache[i];
      entry->current_puzzle = generate_cookie();
      entry->dh_entry = get_dh_entry(HCNF.dh_group, FALSE);
      entry->dh_entry->ref_count++;
      entry->packet = (__u8 *) malloc(len);
      if (entry->packet == NULL)
        {
          log_(NORM, "Malloc error! creating R1 packet.\n");
        }
      memset(entry->packet, 0, len);
      entry->len = hip_generate_R1(entry->packet, hi,
                                   entry->current_puzzle,
                                   entry->dh_entry);
      entry->previous_puzzle = NULL;
      gettimeofday(&entry->creation_time, NULL);
    }

}

/*
 * generate_cookie()
 *
 * in:		none
 * out:		the new cookie. mmm, cookies.
 *
 * Generates a new random cookie puzzle.
 */
hipcookie *generate_cookie()
{
  hipcookie *cookie;
  cookie = (hipcookie*) malloc(sizeof(hipcookie));
  memset(cookie, 0, sizeof(hipcookie));

  /* generate random 64-bit I */
  RAND_bytes((unsigned char*)&cookie->i, 8);
  /* K and lifetime are set from configuration */
  cookie->k = (__u8)HCNF.cookie_difficulty;
  cookie->lifetime = (__u8)HCNF.cookie_lifetime;
  cookie->opaque = 0;

  return(cookie);
}

/*
 * replace_next_R1()
 *
 * in/out:	none
 *
 * Called every few minutes to expire and replace one R1.
 * Also picks a new random number for the cookie index mapping function.
 */
void replace_next_R1()
{
  hi_node *h;
  r1_cache_entry *entry;
  int packet_len;

  /*log_(NORMT, "Expiring the R1 in cache slot %d.\n", current_index);*/

  /* every so often pick a new random number
   * (twice per cycle through current_index) */
  if ((current_index % (R1_CACHE_SIZE / 2)) == 2)
    {
      previous_rand = current_rand;
      RAND_bytes((unsigned char*)&current_rand, 4);
    }

  /* for all local Host Identities */
  for (h = my_hi_head; h; h = h->next)
    {

      entry = &h->r1_cache[current_index];
      /* new R1 entry may use a different cookie, DH entry */
      entry->dh_entry->ref_count--;
      if (entry->previous_puzzle)
        {
          free(entry->previous_puzzle);
        }
      entry->previous_puzzle = entry->current_puzzle;
      /* generate a new R1 entry */
      entry->current_puzzle = generate_cookie();
      entry->dh_entry = get_dh_entry(HCNF.dh_group, FALSE);
      entry->dh_entry->ref_count++;
      free(entry->packet);
      packet_len = calculate_r1_length(h);
      entry->packet = (__u8 *) malloc(packet_len);
      if (entry->packet == NULL)
        {
          log_(NORMT, "Malloc error! Trying to create R1 packet (%d bytes).\n",
               packet_len);
        }
      memset(entry->packet, 0, packet_len);
      entry->len = hip_generate_R1(entry->packet,
                                   h,
                                   entry->current_puzzle,
                                   entry->dh_entry);
      gettimeofday(&entry->creation_time, NULL);

      /* index is about to roll over, so all R1s have been replaced
       * at this point, we can increase the R1 generation count
       */
      if ((current_index + 1 >= R1_CACHE_SIZE) &&
          (h->r1_gen_count > 0))
        {
          h->r1_gen_count++;
        }

    }     /* end for */

  current_index++;
  if (current_index >= R1_CACHE_SIZE)
    {
      current_index = 0;
    }
}

/*
 * compute_cookie_index()
 *
 * in:		src = source address of I1 or I2 packet
 *              hiti = initiator's HIT
 *              current = TRUE means use current random number, FALSE means
 *                        use the previous random number
 *
 * Hash function to return an index to an R1 entry given src, HIT.
 * This mapping function must be considerably cheaper than computing SHA-1
 */
int compute_R1_cache_index(hip_hit *hiti, __u8 current)
{
  __u32 r, *p;
  int i;

  if (current)
    {
      r = current_rand;
    }
  else
    {
      r = previous_rand;
    }

  /* r = random + HIT
   * this is similar to checksumming, without using the overflow bit
   */
  p = (__u32*) hiti;
  for (i = 0; i < HIT_SIZE; i += 4)
    {
      r += *p++;
    }

  r %= R1_CACHE_SIZE;

  return (r);
}

int calculate_r1_length(hi_node *hi)
{
  int i, len, num_hip_transforms = 0, num_esp_transforms = 0, hi_len = 0;

  /* count transforms */
  for (i = 0; i < SUITE_ID_MAX; i++)
    {
      if (HCNF.hip_transforms[i] > 0)
        {
          num_hip_transforms++;
        }
      if (HCNF.esp_transforms[i] > 0)
        {
          num_esp_transforms++;
        }
    }

  hi_len = build_tlv_hostid_len(hi, HCNF.send_hi_name);

  len =   sizeof(hiphdr) + sizeof(tlv_esp_info) + 2 *
        sizeof(tlv_locator) +
        sizeof(tlv_r1_counter) + sizeof(tlv_puzzle) +
        sizeof(tlv_diffie_hellman) + dhprime_len[HCNF.dh_group] +
        eight_byte_align(sizeof(tlv_hip_transform) - 2 +
                         2 * num_hip_transforms) +
        eight_byte_align(sizeof(tlv_esp_transform) - 2 +
                         2 * num_esp_transforms) +
        eight_byte_align(hi_len) +
        eight_byte_align(sizeof(tlv_cert) + MAX_CERT_LEN - 1) +
        /* if opaque is used, add its length here */
        eight_byte_align(sizeof(tlv_hip_sig) + MAX_SIG_SIZE - 1);
  if (HCNF.num_reg_types > 0)
    {
      len +=  eight_byte_align(sizeof(tlv_reg_info) +
                               HCNF.num_reg_types - 1);
    }

  return(eight_byte_align(len));
}

/************************************
 *  Diffie-Hellman Cache functions  *
 ***********************************/
/* Stores Diffie-Hellman contexts used in precomputed R1s (R1 cache) and those
 * made when generating the I2. The only pre-generated DH entry will be for
 * the default group ID, so that R1s can be quickly precomputed. DH entries
 * become stale after HCNF.dh_lifetime (15 minutes) at which point they are
 * no longer used for new R1 packets. Entries are deleted once stale and
 * no longer referenced.
 *
 */

/*
 * init_dh_cache()
 *
 * Initialize the Diffie-Hellman cache
 * Add a single DH entry for the default configured group ID.
 */
void init_dh_cache()
{
  /* only called with empty cache */
  if (dh_cache)
    {
      return;
    }
  dh_cache = new_dh_cache_entry(HCNF.dh_group);
}

/*
 * new_dh_cache_entry()
 *
 * in:		group_id = the DH group for the new entry
 *
 * out:		returns a new malloc'd DH cache entry
 *
 * Build a new DH cache entry for the requested DH group.
 */
dh_cache_entry *new_dh_cache_entry(__u8 group_id)
{
  int err;
  dh_cache_entry *entry;

  entry = (dh_cache_entry*) malloc(sizeof(dh_cache_entry));
  entry->next       = NULL;
  entry->group_id   = group_id;
  entry->is_current = TRUE;
  entry->ref_count  = 0;

  entry->dh    = DH_new();
  entry->dh->g = BN_new();
  entry->dh->p = BN_new();
  /* Put prime corresponding to group_id into dh->p */
  BN_bin2bn(dhprime[group_id],
            dhprime_len[group_id], entry->dh->p);
  /* Put generator corresponding to group_id into dh->g */
  BN_set_word(entry->dh->g, dhgen[group_id]);
  /* By not setting dh->priv_key, allow crypto lib to pick at random */
  if ((err = DH_generate_key(entry->dh)) != 1)
    {
      log_(ERR, "DH key generation failed.\n");
      log_(NORMT, "DH key generation failed.\n");
      exit(1);
    }
  gettimeofday(&entry->creation_time, NULL);
  return(entry);
}

/*
 * get_dh_entry()
 *
 * in:		group_id = the DH group desired
 *              new = TRUE if a new entry is needed (i.e. rekeying),
 *                    FALSE if a cached entry is OK.
 *
 * out:		returns an existing, non-stale entry, or creates a new one
 *
 */
dh_cache_entry *get_dh_entry(__u8 group_id, int new)
{
  dh_cache_entry *entry, *last = NULL;

  for (entry = dh_cache; entry != NULL; entry = entry->next)
    {
      if (!new &&
          (entry->group_id == group_id) &&
          (entry->is_current == TRUE))
        {
          return(entry);
        }
      /* may want to check if entry is stale here */
      last = entry;
    }

  /* no entry exists for specified group_id or a new entry was requested,
   * so generate a new one */
  entry = new_dh_cache_entry(group_id);
  /* add it to the cache */
  last->next = entry;
  return(entry);
}

/*
 * unuse_dh_entry()
 *
 * in:		dh = pointer to DH context contained in the entry
 * out:		None.
 *
 * Given a DH context, find the corresponding cache entry and decrement
 * its usage count.
 */
void unuse_dh_entry(DH *dh)
{
  dh_cache_entry *entry;

  for (entry = dh_cache; entry != NULL; entry = entry->next)
    {
      if (entry->dh == dh)
        {
          if (entry->ref_count > 0)
            {
              entry->ref_count--;
            }
          return;
        }
    }
}

/*
 * expire_old_dh_entries()
 *
 * in/out:	none
 *
 * Called periodically to expire stale entries and delete unused entries
 * from the cache.
 */
void expire_old_dh_entries()
{
  dh_cache_entry *entry, *last = NULL, *next, *old;
  struct timeval now;

  gettimeofday(&now, NULL);

  entry = dh_cache;
  while (entry != NULL)
    {
      next = entry->next;
      if (TDIFF(now, entry->creation_time) > (int)HCNF.dh_lifetime)
        {
          /* mark entry as stale */
          entry->is_current = FALSE;
          /* delete unused cache entry */
          if (entry->ref_count == 0)
            {
              old = entry;
              /* replace default entry */
              if (old->group_id == HCNF.dh_group)
                {
                  entry =
                    new_dh_cache_entry(
                      old->group_id);
                  entry->next = next;
                  if (last)
                    {
                      last->next = entry;
                    }
                  else
                    {
                      dh_cache = entry;
                    }
                  /* remove non-default entries */
                }
              else
                {
                  entry = NULL;
                  if (last)
                    {
                      last->next = next;
                    }
                  else
                    {
                      dh_cache = next;
                    }
                }
              DH_free(old->dh);
              memset(old, 0, sizeof(dh_cache_entry));
              free(old);
            }
        }
      if (entry)
        {
          last = entry;
        }
      entry = next;
    }

}

