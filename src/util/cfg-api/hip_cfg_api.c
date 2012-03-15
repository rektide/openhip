/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2009-2012 the Boeing Company
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
 *  \file  hip_cfg_api.c
 *
 *  \authors	Jin Fang <jin.fang@boeing.com>
 *
 *  \brief  Configuration API shared library loader.
 *
 */

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <hip/hip_cfg_api.h>

/* hip ACL */
int (*hipcfg_init_p)(struct hip_conf *hc) = NULL;
int (*hipcfg_close_p)() = NULL;
int (*hipcfg_allowed_peers_p)(const hip_hit hit1, const hip_hit hit2) = NULL;
int (*hipcfg_peers_allowed_p)(hip_hit *hits1, hip_hit *hits2,
                              int max_cnt) = NULL;

/* endbox config */
int (*hipcfg_getEndboxByLegacyNode_p)(const struct sockaddr *host,
                                      struct sockaddr *eb) = NULL;

int (*hipcfg_getLlipByEndbox_p)(const struct sockaddr *eb,
                                struct sockaddr *llip) = NULL;

int (*hipcfg_getLegacyNodesByEndbox_p)(const struct sockaddr *eb,
                                       struct sockaddr_storage *hosts,
                                       int size) = NULL;

int (*hipcfg_setUnderlayIpAddress_p)(const char *ip);

int (*hipcfg_verifyCert_p)(const char *url, const hip_hit hit) = NULL;
int (*hipcfg_getLocalCertUrl_p)(char *url, unsigned int size) = NULL;
int (*hipcfg_postLocalCert_p)(const char *hit) = NULL;
hi_node *(*hipcfg_getMyHostId_p)() = NULL;
int (*hipcfg_getPeerNodes_p)(struct peer_node *peerNodes,
                             unsigned int max_count) = NULL;

int hipcfg_init(char *dlname, struct hip_conf *hc)
{
  void *module;
  module = dlopen(dlname, RTLD_NOW);
  if (!module)
    {
      fprintf(stderr, "Open %s error: %s\n", dlname, dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", dlname);

  hipcfg_init_p = dlsym(module, hipcfg_init_fn);
  if (hipcfg_init_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_init_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_init_fn);

  hipcfg_close_p = dlsym(module, hipcfg_close_fn);
  if (hipcfg_close_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_close_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_close_fn);

  hipcfg_setUnderlayIpAddress_p = dlsym(module,
                                        hipcfg_setUnderlayIpAddress_fn);
  if (hipcfg_setUnderlayIpAddress_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_setUnderlayIpAddress_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_setUnderlayIpAddress_fn);

  hipcfg_allowed_peers_p = dlsym(module, hipcfg_allowed_peers_fn);
  if (hipcfg_allowed_peers_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_allowed_peers_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n",  hipcfg_allowed_peers_fn);

  hipcfg_peers_allowed_p = dlsym(module, hipcfg_peers_allowed_fn);
  if (hipcfg_peers_allowed_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_peers_allowed_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n",  hipcfg_peers_allowed_fn);

  hipcfg_getEndboxByLegacyNode_p = dlsym(module,
                                         hipcfg_getEndboxByLegacyNode_fn);
  if (hipcfg_getEndboxByLegacyNode_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_getEndboxByLegacyNode_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_getEndboxByLegacyNode_fn);

  hipcfg_getLlipByEndbox_p = dlsym(module, hipcfg_getLlipByEndbox_fn);
  if (hipcfg_getLlipByEndbox_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_getLlipByEndbox_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_getLlipByEndbox_fn);

  hipcfg_getLegacyNodesByEndbox_p = dlsym(
    module,
    hipcfg_getLegacyNodesByEndbox_fn);
  if (hipcfg_getLegacyNodesByEndbox_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_getLegacyNodesByEndbox_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_getLegacyNodesByEndbox_fn);

  hipcfg_verifyCert_p = dlsym(module, hipcfg_verifyCert_fn);
  if (hipcfg_verifyCert_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_verifyCert_fn,
              dlerror());
      return(-1);
    }

  hipcfg_getLocalCertUrl_p = dlsym(module, hipcfg_getLocalCertUrl_fn);
  if (hipcfg_getLocalCertUrl_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_getLocalCertUrl_fn,
              dlerror());
      return(-1);
    }

  hipcfg_postLocalCert_p = dlsym(module, hipcfg_postLocalCert_fn);
  if (hipcfg_postLocalCert_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_postLocalCert_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_verifyCert_fn);

  hipcfg_getMyHostId_p = dlsym(module, hipcfg_getMyHostId_fn);
  if (hipcfg_getMyHostId_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_getMyHostId_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_getMyHostId_fn);

  hipcfg_getPeerNodes_p = dlsym(module, hipcfg_getPeerNodes_fn);
  if (hipcfg_getPeerNodes_p == NULL)
    {
      fprintf(stderr,
              "error loading function %s: %s\n",
              hipcfg_getPeerNodes_fn,
              dlerror());
      return(-1);
    }
  printf("loading %s succeed.\n", hipcfg_getPeerNodes_fn);

  return((*hipcfg_init_p)(hc));
}

int hipcfg_close()
{
  return((*hipcfg_close_p)());
}

int hipcfg_setUnderlayIpAddress(const char *ip)
{
  return((*hipcfg_setUnderlayIpAddress_p)(ip));
}

int hipcfg_allowed_peers(const hip_hit hit1, const hip_hit hit2)
{
  return((*hipcfg_allowed_peers_p)(hit1, hit2));
}

int hipcfg_peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt)
{
  return((*hipcfg_peers_allowed_p)(hits1, hits2, max_cnt));
}

int hipcfg_getEndboxByLegacyNode(const struct sockaddr *host,
                                 struct sockaddr *eb)
{
  return((*hipcfg_getEndboxByLegacyNode_p)(host, eb));
}

int hipcfg_getLlipByEndbox(const struct sockaddr *eb, struct sockaddr *llip)
{
  return((*hipcfg_getLlipByEndbox_p)(eb, llip));
}

int hipcfg_getLegacyNodesByEndbox(const struct sockaddr *eb,
                                  struct sockaddr_storage *hosts,
                                  int size)
{
  return((*hipcfg_getLegacyNodesByEndbox_p)(eb, hosts, size));
}

int hipcfg_verifyCert(const char *url, const hip_hit hit)
{
  return((*hipcfg_verifyCert_p)(url, hit));
}

int hipcfg_getLocalCertUrl(char *url, unsigned int size)
{
  return((*hipcfg_getLocalCertUrl_p)(url, size));
}

int hipcfg_postLocalCert(const char *hit)
{
  return((*hipcfg_postLocalCert_p)(hit));
}

hi_node *hipcfg_getMyHostId()
{
  return((*hipcfg_getMyHostId_p)());
}

int hipcfg_getPeerNodes(struct peer_node *peerNodes, unsigned int max_count)
{
  return((*hipcfg_getPeerNodes_p)(peerNodes, max_count));
}

