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
 *  \file  hip_status.c
 *
 *  \authors Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Status thread
 *
 */

#include <stdio.h>              /* printf() */
#ifdef __WIN32__
#include <win32/types.h>
#else
#include <unistd.h>
#include <pthread.h>            /* phread_exit() */
#include <sys/uio.h>            /* iovec */
#endif
#include <string.h>             /* strerror() */
#include <errno.h>              /* errno */
#include <hip/hip_service.h>
#include <hip/hip_types.h>
#include <hip/hip_sadb.h>               /* access to SADB */
#include <hip/hip_status.h>
#include <hip/hip_funcs.h>      /* pthread_mutex_lock() */

#ifdef HIP_VPLS
#include <utime.h>
#endif

/*
 * Local function declarations
 */
void handle_status_request(int type, char *buff, int *len);
void dump_sadb(char *buff, int *tlv_len, __u32 spi);
void dump_dst_entries(char *buff, int *tlv_len);
void dump_lsi_entries(char *buff, int *tlv_len);
void dump_all_spi(char *buff, int *tlv_len);
extern int sadb_hashfn(__u32 spi);

#define STATBUFSIZE 4096

/*
 * hip_status()
 *
 *
 */
#ifdef __WIN32__
void hip_status(void *arg)
#else
void *hip_status(void *arg)
#endif
{
  int err, s, len;
  socklen_t from_len;
  char buff[STATBUFSIZE];
  fd_set read_fdset;
  struct timeval timeout;
  struct sockaddr_in addr;
  struct sockaddr_storage ss_from;
  struct sockaddr *from = (struct sockaddr*) &ss_from;
  struct status_tlv *req;

#ifdef HIP_VPLS
  time_t last_time, now_time;

  last_time = time(NULL);
  printf("hip_status() thread (tid %d pid %d) started...\n",
         (unsigned)pthread_self(), getpid());
#else
  printf("hip_status() thread started...\n");
#endif
  if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
      printf("Status thread socket() error: %s\n", strerror(errno));
      fflush(stdout);
#ifdef __WIN32__
      return;
#else
      return(NULL);
#endif
    }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(WIN_STATUS_PORT);

  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
      printf("Status thread: bind() error - %s\n", strerror(errno));
      fflush(stdout);
#ifdef __WIN32__
      return;
#else
      return(NULL);
#endif
    }

  while (g_state == 0)
    {
      FD_ZERO(&read_fdset);
      FD_SET((unsigned)s, &read_fdset);
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

#ifdef HIP_VPLS
      now_time = time(NULL);
      if (now_time - last_time > 60)
        {
          printf("hip_status() heartbeat\n");
          last_time = now_time;
          utime("/usr/local/etc/hip/heartbeat_hip_status", NULL);
        }
#endif

      if ((err =
             select(s + 1, &read_fdset, NULL,NULL,
                    &timeout) < 0))
        {
          if (errno == EINTR)
            {
              continue;
            }
          printf("Status thread: select() error: %s.\n",
                 strerror(errno));
        }
      else if (FD_ISSET(s, &read_fdset))
        {
          memset(buff, 0, sizeof(buff));
          from_len = sizeof(struct sockaddr_storage);
          if ((err = recvfrom(s, buff, sizeof(buff), 0,
                              from, &from_len)) < 0)
            {
              if (err != -EINTR)
                {
                  printf("Status thread: recvfrom error:"
                         " %s\n", strerror(errno));
                }
              continue;
            }
          if (err < sizeof(struct status_tlv))
            {
              continue;
            }
          req = (struct status_tlv*)buff;
          len = sizeof(buff);
          handle_status_request(ntohs(req->tlv_type), buff, &len);
          len = sendto(s, buff, len, 0, from, from_len);
        }

    }

  printf("hip_status() thread shutdown.\n");
  fflush(stdout);
#ifndef __WIN32__
  pthread_exit((void *) 0);
  return(NULL);
#endif
}

/*
 * a status request is normally just a type code, and the supplied buff
 * will be filled with a response; if the type has a parameter, then buff
 * initially contains the entire request.
 */
void handle_status_request(int type, char *buff, int *len)
{
  int tlv_len = 0;
  struct status_tlv *t = (struct status_tlv*) buff;
  __u32 spi, *spi_p;

  switch (type)
    {
    case STAT_THREADS:
      t->tlv_type = htons(HIP_STATUS_REPLY_STRING);
      t->tlv_len = htons(40);
      t++;
      sprintf((char*)t,
              "Thread info not implemented yet.\n");
      tlv_len = 40;
      break;
    case STAT_SADB:
      /* read any SPI parameter */
      spi = 0;
      if (ntohs(t->tlv_len) == sizeof(__u32))
        {
          spi_p = (__u32*)&buff[sizeof(struct status_tlv)];
          spi = ntohl(*spi_p);
        }
      dump_sadb(buff, &tlv_len, spi);
      break;
    case STAT_DST:
      dump_dst_entries(buff, &tlv_len);
      break;
    case STAT_LSI:
      dump_lsi_entries(buff, &tlv_len);
      break;
    case STAT_ALL_SPI:
      dump_all_spi(buff, &tlv_len);
      break;
    case STAT_MIN:
    case STAT_MAX:
    default:
      printf("<Status thread: replying with error (%d)>",
             type);
      t->tlv_type = htons(HIP_STATUS_REPLY_ERROR);
      t->tlv_len = 0;
      t++;
      break;
    }
  t = (struct status_tlv*) ((char*)t + tlv_len);
  t->tlv_type = htons(HIP_STATUS_REPLY_DONE);
  t->tlv_len = 0;
  t++;
  *len = (char*)t - buff;
}

extern hip_sadb_entry *hip_sadb[SADB_SIZE];
extern hip_mutex_t hip_sadb_locks[SADB_SIZE];

int sockaddr_list_length(sockaddr_list *l)
{
  int count = 0;
  for (; l; l = l->next)
    {
      count++;
    }
  return(count);
}

void dump_sadb(char *buff, int *tlv_len, __u32 spi)
{
  hip_sadb_entry *entry;
  struct status_tlv *t = (struct status_tlv*)buff;
  int i = 0, len = 0, n;
  char *p;
  sockaddr_list *l;

  if (spi > 0)
    {
      i = sadb_hashfn(spi);
    }

  for (; i < SADB_SIZE; i++)
    {
      pthread_mutex_lock(&hip_sadb_locks[i]);
      for (entry = hip_sadb[i]; entry; entry = entry->next)
        {
          if ((spi > 0) && (entry->spi != spi))
            {
              continue;
            }
          pthread_mutex_lock(&entry->rw_lock);
          t->tlv_type = htons(HIP_STATUS_REPLY_SADB);
          t->tlv_len = 0;
          p = (char *)(t + 1);
          len = 0;
          ADD_ITEM(p, entry->spi, len);
          ADD_ITEM(p, entry->direction, len);
          ADD_ITEM(p, entry->hit_magic, len);
          ADD_ITEM(p, entry->mode, len);
          ADD_ITEM(p, entry->lsi, len);
          ADD_ITEM(p, entry->a_type, len);
          ADD_ITEM(p, entry->e_type, len);
          ADD_ITEM(p, entry->a_keylen, len);
          ADD_ITEM(p, entry->e_keylen, len);
          ADD_ITEM(p, entry->lifetime, len);
          ADD_ITEM(p, entry->bytes, len);
          ADD_ITEM(p, entry->sequence, len);
          /*ADD_ITEM(p, entry->replay_win, len);
           *  ADD_ITEM(p, entry->replay_map, len);
           *  ADD_ITEM(p, entry->iv, len);*/
          n = sockaddr_list_length(entry->src_addrs);
          ADD_ITEM(p, n, len);
          n = sockaddr_list_length(entry->dst_addrs);
          ADD_ITEM(p, n, len);
          t->tlv_len = htons((__u16)len);
          t = (struct status_tlv *)(p + len);

          /* addresses */
          t->tlv_type = htons(HIP_STATUS_REPLY_ADDR);
          t->tlv_len = 0;
          p = (char *)(t + 1);
          len = 0;
          for (l = entry->src_addrs; l; l = l->next)
            {
              ADD_ITEM(p, l->addr, len);
            }
          for (l = entry->dst_addrs; l; l = l->next)
            {
              ADD_ITEM(p, l->addr, len);
            }
          /* TODO: add NAT variables here */
          t->tlv_len = htons((__u16)len);
          t = (struct status_tlv *)(p + len);
          pthread_mutex_unlock(&entry->rw_lock);
          /* buffer size check */
          if (((char *)t - buff) > (STATBUFSIZE - len))
            {
              break;
            }
        }
      pthread_mutex_unlock(&hip_sadb_locks[i]);
      /* buffer size check */
      if (((char *)t - buff) > (STATBUFSIZE - len))
        {
          break;
        }

    }
  *tlv_len = (char*)t - buff;
}

extern hip_sadb_dst_entry *hip_sadb_dst[SADB_SIZE];
extern hip_mutex_t hip_sadb_dst_locks[SADB_SIZE];

void dump_dst_entries(char *buff, int *tlv_len)
{
  hip_sadb_dst_entry *entry;
  struct status_tlv *t = (struct status_tlv*)buff;
  int i, len;
  char *p;

  for (i = 0; i < SADB_SIZE; i++)
    {
      pthread_mutex_lock(&hip_sadb_dst_locks[i]);
      for (entry = hip_sadb_dst[i]; entry; entry = entry->next)
        {
          pthread_mutex_lock(&entry->rw_lock);
          t->tlv_type = htons(HIP_STATUS_REPLY_DST_ENTRY);
          t->tlv_len = 0;
          p = (char *)(t + 1);
          len = 0;
          ADD_ITEM(p, entry->addr, len);
          ADD_ITEM(p, entry->sadb_entry->spi, len);
          t->tlv_len = htons((__u16)len);
          t = (struct status_tlv *)(p + len);
          pthread_mutex_unlock(&entry->rw_lock);
        }
      pthread_mutex_unlock(&hip_sadb_dst_locks[i]);
    }
  *tlv_len = (char*)t - buff;
}

extern hip_lsi_entry *lsi_temp;
void dump_lsi_entries(char *buff, int *tlv_len)
{
  hip_lsi_entry *l;
  struct status_tlv *t = (struct status_tlv*)buff;
  int len;
  char *p;

  for (l = lsi_temp; l; l = l->next)
    {
      t->tlv_type = htons(HIP_STATUS_REPLY_LSI_ENTRY);
      t->tlv_len = 0;
      p = (char *)(t + 1);
      len = 0;
      ADD_ITEM(p, l->addr, len);
      ADD_ITEM(p, l->lsi4, len);
      ADD_ITEM(p, l->lsi6, len);
      ADD_ITEM(p, l->num_packets, len);
      ADD_ITEM(p, l->next_packet, len);
      ADD_ITEM(p, l->send_packets, len);
      ADD_ITEM(p, l->creation_time.tv_sec, len);
      t->tlv_len = htons((__u16)len);
      t = (struct status_tlv *)(p + len);
    }

  *tlv_len = (char*)t - buff;
}

/* dump all spi(s) in sadb*/
void dump_all_spi(char *buff, int *tlv_len)
{
  hip_sadb_entry *entry;
  struct status_tlv *t = (struct status_tlv*)buff;
  int i, len;
  char *p;

  for (i = 0; i < SADB_SIZE; i++)
    {
      for (entry = hip_sadb[i]; entry; entry = entry->next)
        {
          t->tlv_type = htons(HIP_STATUS_REPLY_ALL_SPI);
          t->tlv_len = 0;
          p = (char *)(t + 1);
          len = 0;
          ADD_ITEM(p, entry->spi, len);
          t->tlv_len = htons((__u16)len);
          t = (struct status_tlv *)(p + len);
        }

    }
  *tlv_len = (char*)t - buff;
}

