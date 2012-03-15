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
 *  hip_cfg_files.cpp
 *
 *  \authors	David Mattes <david.mattes@boeing.com>
 *
 * Configuration API using static files.
 *
 */

#include <iostream>
#include <openssl/engine.h>
#include <hip/hip_cfg_files.h>

hipCfgFiles *hipCfgFiles::_instance = NULL;

extern "C" {
int hipcfg_init(struct hip_conf *hc)
{
  /* printf("cfg-local hipcfg_init called\n"); */
  hipCfg *hs = hipCfgFiles::getInstance();
  return(hs->loadCfg(hc));
}

int hipcfg_close()
{
  /* printf("cfg-local hipcfg_init called\n"); */
  hipCfg *hs = hipCfgFiles::getInstance();
  return(hs->closeCfg());
}

int hipcfg_setUnderlayIpAddress(const char *ip)
{
  hipCfg *hs = hipCfgFiles::getInstance();
  return(hs->setUnderlayIpAddress(ip));
}

int hipcfg_allowed_peers(const hip_hit hit1, const hip_hit hit2)
{
  /* printf("cfg-local hit_peer_allowed\n"); */
  hipCfg *hs = hipCfgFiles::getInstance();
  return(hs->hit_peer_allowed(hit1, hit2));
}

int hipcfg_peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt)
{
  /* printf("cfg-local hit_peer_allowed\n"); */
  hipCfg *hs = hipCfgFiles::getInstance();
  return(hs->peers_allowed(hits1, hits2, max_cnt));
}

int hipcfg_getEndboxByLegacyNode(const struct sockaddr *host,
                                 struct sockaddr *eb)
{
  int rc = 0;

  hipCfg *hs = hipCfgFiles::getInstance();
  rc = hs->legacyNodeToEndbox(host, eb);
  return(rc);
}

int hipcfg_getLlipByEndbox(const struct sockaddr *eb, struct sockaddr *llip)
{
  int rc = 0;
  /* printf("entering hipcfg_getLlipByEndbox...\n"); */
  hipCfg *hs = hipCfgFiles::getInstance();
  rc = hs->endbox2Llip(eb, llip);
  return(rc);
}

int hipcfg_getLegacyNodesByEndbox(const struct sockaddr *eb,
                                  struct sockaddr_storage *hosts, int size)
{
  int rc = 0;
  /* printf("entering hipcfg_getLegacyNodesByEndbox...\n"); */
  hipCfg *hs = hipCfgFiles::getInstance();
  rc = hs->getLegacyNodesByEndbox(eb, hosts, size);
  return(rc);
}

int hipcfg_verifyCert(const char *url, const hip_hit hit)
{
  int rc = 0;
  hipCfg *hs = hipCfgFiles::getInstance();
  rc = hs->verifyCert(url, hit);
  return(rc);
}

int hipcfg_getLocalCertUrl(char *url, unsigned int size)
{
  int rc = 0;
  hipCfg *hs = hipCfgFiles::getInstance();
  rc = hs->getLocalCertUrl(url, size);
  return(rc);
}

int hipcfg_postLocalCert(const char *hit)
{
  int rc = 0;
  hipCfg *hs = hipCfgFiles::getInstance();
  rc = hs->postLocalCert(hit);
  return(rc);
}

hi_node *hipcfg_getMyHostId()
{
  hipCfgFiles *hs = hipCfgFiles::getInstance();
  return(hs->getMyHostId());
}

int hipcfg_getPeerNodes(struct peer_node *peerNodes, int max_count)
{
  hipCfgFiles *hs = hipCfgFiles::getInstance();
  return(hs->getPeerNodes(peerNodes, max_count));
}

} /* extern "C" */

hipCfgFiles::hipCfgFiles()
{
}

hipCfgFiles *hipCfgFiles::getInstance()
{
  if (_instance == NULL)
    {
      _instance = new hipCfgFiles();
    }
  return(_instance);
}

int hipCfgFiles::closeCfg()
{
  return(0);
}

int hipCfgFiles::loadCfg(struct hip_conf *hc)
{
  const char *fnName = "hipCfgFiles::loadCfg: ";
  SSL_CTX *ctx = NULL;

  if (hc == NULL)
    {
      cout << "loadCfg: ERROR: HCNF not set" << endl;
      return(-1);
    }

  _hcfg = hc;

  /* SSL context. */
  SSL_library_init();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(SSLv3_client_method());
  if (ctx == NULL)
    {
      cerr << fnName << "Error creating SSL context" << endl;
      return(-1);
    }
  _ssl = SSL_new(ctx);
  if (_ssl == NULL)
    {
      cerr << fnName << "Error open SSL connect" << endl;
      return(-1);
    }

  /* Don't need x509 store since not handling certs
   *  _store = X509_STORE_new();
   *  if(!_store){
   *   cerr << fnName << "error calling X509_STORE_new" << endl;
   *   return -1;
   *  }
   *
   *  X509_STORE_set_verify_cb_func(_store, hipCfgFiles::callb);
   *  X509_STORE_set_default_paths(_store);
   */

  hc->use_my_identities_file = 1;
  if (getEndboxMapsFromLocalFile() < 0)
    {
      return(-1);
    }

  return(0);
}

int hipCfgFiles::postLocalCert(const char *hit)
{
  const char *fnName = "hipCfgFiles::postLocalCert: ";

  if (_hcfg->peer_certificate_required)
    {
      cerr << fnName << "ERROR: <peer_certificate_required> is set to YES, "
           << "but OpenHIP only supports certificate URLs" << endl;
      return(-1);
    }
  return(0);
}

/* return the size of the certificate if succeed
 *        or 0 if the cert attribute doesn't exist
 *        or -1 if other error.
 */
int hipCfgFiles::verifyCert(const char *url, const hip_hit hit)
{
  const char *fnName = "hipCfgFiles::verifyCert: ";

  if (_hcfg->peer_certificate_required)
    {
      cerr << fnName << "ERROR: <peer_certificate_required> is set to YES, "
           << "but OpenHIP only supports certificate URLs" << endl;
    }
  return(1);
}

