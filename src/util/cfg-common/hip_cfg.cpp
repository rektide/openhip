/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2008-2012 the Boeing Company
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
 *  hip_cfg.cpp
 *
 *  \authors	Jin Fang <jin.fang@boeing.com>
 *
 * Implementation of HIP configuration API classes.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <iostream>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <hip/hip_cfg.h>
#include <libxml/tree.h>

certInfo::~certInfo()
{
}

pthread_mutex_t hipcfgmap_mutex;

int hipCfg::str_to_addr(const char *data, struct sockaddr *addr)
{
  /* TODO: use platform-independent getaddrinfo() w/AI_NUMERICHOST */
#ifdef __WIN32__
  int len = SALEN(addr);
  return(WSAStringToAddress((LPSTR)data, addr->sa_family, NULL,
                            addr, &len) == 0);
#else
  return(inet_pton(addr->sa_family, data, SA2IP(addr)));
#endif
}

int hipCfg::addr_to_str(const struct sockaddr *addr, char *data, int len)
{
#ifdef __WIN32__
  DWORD dw = (DWORD)len;
  return(WSAAddressToString(addr, SALEN(addr), NULL, data, &dw) != 0);
#else
  return(inet_ntop(addr->sa_family, SA2IP(addr), data, len) == NULL);
#endif
}

int hipCfg::hit2hitstr(char *hit_str, const hip_hit hit)
{
  struct sockaddr *addr;
  struct sockaddr_storage ss_addr;

  addr = (struct sockaddr*) &ss_addr;
  memset(&ss_addr, 0, sizeof(struct sockaddr_storage));
  ss_addr.ss_family = AF_INET6;
  memcpy(SA2IP(&ss_addr), hit, SAIPLEN(&ss_addr));
#ifdef __WIN32__
  DWORD dw = (DWORD)INET6_ADDRSTRLEN;
  return(WSAAddressToString(&ss_addr, SALEN(&ss_addr), NULL, hit_str, &dw) != 0);
#else
  return(inet_ntop(addr->sa_family, SA2IP(addr), hit_str,
                   INET6_ADDRSTRLEN) == NULL);
#endif
}

hipCfg::hipCfg()
{
  _ssl = NULL;
  _store = NULL;
  _hostid = NULL;
  _dsa = NULL;
  _rsa = NULL;
  _hcfg = NULL;
}

int hipCfg::hitstr2hit(hip_hit hit, const char *hit_str)
{
  struct sockaddr *addr;
  struct sockaddr_storage ss_addr;

  addr = (struct sockaddr*) &ss_addr;
  if (strchr(hit_str, ':'))
    {
      memset(addr, 0,sizeof(struct sockaddr_storage));
      addr->sa_family = AF_INET6;
      if (str_to_addr(hit_str, addr) <= 0)
        {
          cerr << "invalid HIT value: " << hit_str << endl;
          return(-1);
        }
      memcpy(hit, SA2IP(addr), HIT_SIZE);
      return(0);
    }
  return(hex_to_bin(hit_str, (char *)hit, HIT_SIZE));
}

void hitPair::print() const
{
  printf("hit1: %02x%02x, hit2: %02x%02x\n", _hit1[HIT_SIZE - 2],
         _hit1[HIT_SIZE - 1], _hit2[HIT_SIZE - 2], _hit2[HIT_SIZE - 1]);
}

/* DM: This is called on the order of per-packet for outgoing packets */
/* OTB: For incoming, it is called only for incoming I1 packets */
int hipCfg::hit_peer_allowed(const hip_hit hit1, const hip_hit hit2)
{
  int rc = 0;
  set <hitPair>::iterator si;
  hitPair *hpp;
/*
 *  int i;
 *  cout<<endl<<"hit_peer_allowed called with hit1: ";
 *  for(i=0; i<sizeof(hip_hit); i++)
 *    printf("%02x", hit1[i]);
 *  cout<<"  hit2: ";
 *  for(i=0; i<sizeof(hip_hit); i++)
 *    printf("%02x", hit2[i]);
 *  cout<<endl;
 */
  /* DM: 17May2010: Return 0 if hit1==hit2 does not allow EB to talk over
   * HIP to itself */
  if (memcmp(hit1, hit2, HIT_SIZE) < 0)
    {
      hpp = new hitPair(hit1, hit2);
    }
  else if (memcmp(hit1, hit2, HIT_SIZE) > 0)
    {
      hpp = new hitPair(hit2, hit1);
    }
  else
    {
      return(rc);
    }

  pthread_mutex_lock(&hipcfgmap_mutex);
  si = _allowed_peers.find(*hpp);
  if (si != _allowed_peers.end())
    {
      rc = 1;
    }
  pthread_mutex_unlock(&hipcfgmap_mutex);

  delete hpp;
  return(rc);
}

int hipCfg::peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt)
{
  set <hitPair, hp_compare>::iterator i;
  int j;

  pthread_mutex_lock(&hipcfgmap_mutex);
  for (j = 0, i = _allowed_peers.begin(); i != _allowed_peers.end(); i++, j++)
    {
      hitPair hp = *i;
      if (j >= max_cnt)
        {
          j = -1;
          break;
        }
      memcpy(hits1[j], hp._hit1, HIT_SIZE);
      memcpy(hits2[j], hp._hit2, HIT_SIZE);
    }
  pthread_mutex_unlock(&hipcfgmap_mutex);

  return(j);
}

/* return 0 if the maping found, 1 otherwise */
/* DM: This is called on the order of per-packet */
int hipCfg::legacyNodeToEndbox(const struct sockaddr *host, struct sockaddr *eb)
{
  char host_s[128];
  string host_str;
  string ip_s;
  int rc = 1;

  addr_to_str(host, host_s, 128);

  /* cout<<"legacyNodeToEndbox: look up host = "<<host_s<<endl; */
  host_str = host_s;

  map <string, string>::iterator i;

  pthread_mutex_lock(&hipcfgmap_mutex);
  i = _legacyNode2EndboxMap.find(host_str);
  if (i != _legacyNode2EndboxMap.end())
    {
      ip_s = (*i).second;
      if (eb->sa_family != AF_INET)
        {
          eb->sa_family = AF_INET6; /* default to return HIT */
        }
      if (eb->sa_family == AF_INET)
        {
          char lsi_s[INET_ADDRSTRLEN];
          hitstr2lsistr(lsi_s, ip_s.c_str());
          str_to_addr(lsi_s, eb);
        }
      else
        {
          str_to_addr(ip_s.c_str(), eb);
        }
      /* cout<<"legacyNodeToEndbox: get eb "<<ip_s.c_str()<<" for host =
       * "<<host_s<<endl; */
      rc = 0;
    }
  pthread_mutex_unlock(&hipcfgmap_mutex);

  return(rc);
}

int hipCfg::getLegacyNodesByEndbox(const struct sockaddr *eb,
                                   struct sockaddr_storage *hosts,
                                   int size)
{
  char eb_s[128];
  char eb_lsi[INET_ADDRSTRLEN];
  addr_to_str(eb, eb_s, 128);
  int idx = 0;
  map <string, string>::iterator i;

  pthread_mutex_lock(&hipcfgmap_mutex);
  for (i = _legacyNode2EndboxMap.begin(); i != _legacyNode2EndboxMap.end(); i++)
    {
      string host = (*i).first;
      string endbox = (*i).second;
      if (eb->sa_family == AF_INET)
        {
          hitstr2lsistr(eb_lsi, endbox.c_str());
          endbox = eb_lsi;
        }
      if ((endbox == eb_s) && (endbox != host))
        {
          if (idx >= size)
            {
              cout <<
              "error calling getLegacyNodesByEndbox: hosts array too small" <<
              endl;
              idx = -1;
              break;
            }
          struct sockaddr_storage host_ss;
          struct sockaddr *host_p = (struct sockaddr *)(&host_ss);
          host_p->sa_family = AF_INET; /* only handle IPv4 address only */
          str_to_addr(host.c_str(), host_p);
          hosts[idx++] = host_ss;
        }
    }
  pthread_mutex_unlock(&hipcfgmap_mutex);

  return(idx);
}

int hipCfg::endbox2Llip(const struct sockaddr *eb, struct sockaddr *llip)
{
  char eb_s[INET6_ADDRSTRLEN];
  string llip_s, hit_s;
  int rc;
  map <string, string>::iterator i;

  memset(eb_s, 0, INET6_ADDRSTRLEN);
  rc = addr_to_str(eb, eb_s, INET6_ADDRSTRLEN);
  if (rc)
    {
      return(-1);
    }

  rc = 1;

  pthread_mutex_lock(&hipcfgmap_mutex);
  if (eb->sa_family == AF_INET)
    {
      cout << "endbox2Llip: looking up IP for LSI = " << eb_s << endl;
      i = _legacyNode2EndboxMap.find(eb_s);
      if (i != _legacyNode2EndboxMap.end())
        {
          hit_s = (*i).second;
        }
    }
  else
    {
      hit_s = eb_s;
    }

  if (!hit_s.empty())
    {
      cout << "endbox2Llip: looking up IP for HIT = " << hit_s << endl;
      i = _endbox2LlipMap.find(hit_s);
      if (i != _endbox2LlipMap.end())
        {
          llip_s = (*i).second;
          llip->sa_family=AF_INET; /* only handle IPv4 address */
          str_to_addr(llip_s.c_str(), llip);
          cout << "endbox2Llip: got IP " << llip_s.c_str() <<
                  " for endbox = " << eb_s << endl;
          rc = 0;
        }
    }
  pthread_mutex_unlock(&hipcfgmap_mutex);

  return(rc);
}

/*
 *
 * hex_to_bin()
 * in:          src = input hex data
 *              dst = output binary data
 *              dst_len = requested number of binary bytes
 * out:         returns bytes converted if successful,
 *              -1 if error
 */
int hipCfg::hex_to_bin(const char *src, char *dst, int dst_len)
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
       *                  * Normally would use tolower(), but have found
       *problems
       *                                   * with dynamic linking and different
       *glibc versions
       *                                                    */
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
          cerr << "Binary conversion failed " << c << endl;
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
          cerr << "Binary conversion failed " << c << endl;
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

int hipCfg::hitstr2lsistr(char *lsi_str, const char *hit_str)
{
  hip_hit hit;
  hitstr2hit(hit, hit_str);
  struct sockaddr_in lsi;
  lsi.sin_family = AF_INET;
  lsi.sin_addr.s_addr = ntohl(HIT2LSI(hit));
  return(addr_to_str(SA(&lsi), lsi_str, INET_ADDRSTRLEN));
}

int hipCfg::hi_to_hit(hi_node *hi, hip_hit hit)
{
  int len;
  __u8 *data = NULL;
  SHA_CTX ctx;
  unsigned char hash[SHA_DIGEST_LENGTH];
  __u32 prefix;
  const unsigned char khi_context_id[16] = {
    0xf0, 0xef, 0xf0, 0x2f, 0xbf, 0xf4, 0x3d, 0x0f,
    0xe7, 0x93, 0x0c, 0x3c, 0x6e, 0x61, 0x74, 0xea
  };

  if (!hi)
    {
      printf("hi_to_hit(): NULL hi\n");
      return(-1);
    }


  /* calculate lengths and validate HIs */
  switch (hi->algorithm_id)
    {
    case HI_ALG_DSA:     /* RFC 2536 */
      if (!hi->dsa)
        {
          printf("hi_to_hit(): NULL dsa\n");
          return(-1);
        }
      len = sizeof(khi_context_id) + 1 + DSA_PRIV + (3 * hi->size);
      break;
    case HI_ALG_RSA:     /* RFC 3110 */
      if (!hi->rsa)
        {
          printf("hi_to_hit(): NULL rsa\n");
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
      printf("hi_to_hit(): invalid algorithm (%d)\n",
             hi->algorithm_id);
      return(-1);
    }

  /*
   * Prepare hash input
   * input = context_id | input
   */
  data = (__u8 *)malloc(len);
  if (!data)
    {
      printf("hi_to_hit(): malloc(%d) error\n", len);
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

/* generate KHI input from HI
 */
int hipCfg::khi_hi_input(hi_node *hi, __u8 *out)
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
 * function bn2bin_safe(BIGNUM *dest)
 *
 * BN_bin2bn() chops off the leading zero(es) of the BIGNUM,
 * so numbers end up being left shifted.
 * This fixes that by enforcing an expected destination length.
 */
int hipCfg::bn2bin_safe(const BIGNUM *a, unsigned char *to, int len)
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

/* KHI encode n-bits from bitstring
 */
int hipCfg::khi_encode_n(__u8 *in, int len, __u8 *out, int n)
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

int hipCfg::verify_certificate(X509 *cert)
{
  int ret = 1;
  X509_STORE_CTX *ctx;

  ctx = X509_STORE_CTX_new();
  if (ctx == NULL)
    {
      fprintf(stderr, "Error creating a cert store context\n");
      return(0);
    }
  ret = X509_STORE_CTX_init(ctx, _store, cert, NULL);
  if (ret != 1)
    {
      fprintf(stderr, "Error initializing cert store context\n");
      X509_STORE_CTX_free(ctx);
      return(0);
    }

  ret = X509_verify_cert(ctx);
  X509_STORE_CTX_free(ctx);
  if (ret != 1)
    {
      fprintf(stderr, "Error verifying signature against cert chain\n");
      return(0);
    }

  return(1);
}

/* This function is called for each cert in the cert chain and the cert being
 * verified. rc is set to 0 for errors with the cert and set to 1 for no
 * errors. Return 1 to accept the cert and return 0 to not accept the cert.
 */
int hipCfg::callb(int rc, X509_STORE_CTX *ctx)
{
  int err;
  X509 *err_cert;
  X509_NAME *subject;

  err = X509_STORE_CTX_get_error(ctx);
  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  subject = X509_get_subject_name(err_cert);

  /* Ignore time errors as endboxes may not be synchronized. */

  if (rc == 1)
    {
      fprintf(stderr, "Accepting cert for %s\n",
              X509_NAME_oneline(subject, NULL, 0));
      return(1);
    }
  else
    {
      if ((err == X509_V_ERR_CERT_NOT_YET_VALID) ||
          (err == X509_V_ERR_CERT_HAS_EXPIRED))
        {
          fprintf(stderr, "Accepting cert with invalid time for %s\n",
                  X509_NAME_oneline(subject, NULL, 0));
          ERR_clear_error();
          return(1);
        }
      else
        {
          fprintf(stderr, "Error with certificate %s\n",
                  X509_NAME_oneline(subject, NULL, 0));
          fprintf(stderr, "  rc %d, error %d at depth %d:\n  %s\n",
                  rc, err, X509_STORE_CTX_get_error_depth(ctx),
                  X509_verify_cert_error_string(err));
          return(0);
        }
    }
}

unsigned char *vtou(void *a)
{
  return((unsigned char *)a);
}

int hipCfg::mkHIfromSc()
{
  int rc;

  _hostid  = new hi_node();
  memset(_hostid, 0, sizeof(hi_node));
  rc = mkHIfromPkey(_rsa, _dsa, _hostid);

  /* the following parameters may need to be configurate  -TBD */
  _hostid->anonymous = 0;
  _hostid->allow_incoming = 1;
  _hostid->r1_gen_count = 10;
  _hostid->skip_addrcheck = 1;
  _hostid->r1_gen_count = 10;
  return(rc);
}

int hipCfg::mkHIfromPkey(RSA *rsa, DSA *dsa, hi_node *hostid)
{
  char hit_hex[INET6_ADDRSTRLEN], lsi_str[INET_ADDRSTRLEN];
  unsigned char *hitp;
  struct sockaddr_storage hit;
  struct sockaddr_in lsi;
  int bitsize = 1024;
  char basename[MAX_HI_NAMESIZE - 16];

  memset(&hit, 0, sizeof(struct sockaddr_storage));
  memset(hit_hex, 0, INET6_ADDRSTRLEN);

  if (rsa)
    {
      hostid->algorithm_id = HI_ALG_RSA;
      bitsize = BN_num_bits(rsa->n);
    }
  else if (dsa)
    {
      hostid->algorithm_id = HI_ALG_DSA;
    }
  else
    {
      hostid->algorithm_id = 0;
      return(-1);
    }

  hostid->size = bitsize / 8;
  hostid->rsa = rsa;
  hostid->dsa = dsa;

  hit.ss_family = AF_INET6;
  hitp = vtou(SA2IP(&hit));
  if (hi_to_hit(hostid, hitp) < 0)
    {
      printf("Error generating HIT!\n");
      return(-1);
    }

  if (addr_to_str(SA(&hit), hit_hex, INET6_ADDRSTRLEN))
    {
      printf(
        "Error generating HIT! Do you have the IPv6 protocol " "installed?\n");
      return(-1);
    }

  memcpy(hostid->hit, hitp, HIT_SIZE);

  memset(&lsi, 0, sizeof(struct sockaddr_in));
  memset(lsi_str, 0, INET_ADDRSTRLEN);
  lsi.sin_family = AF_INET;
  lsi.sin_addr.s_addr = ntohl(HIT2LSI(hitp));
  if (addr_to_str(SA(&lsi), lsi_str, INET_ADDRSTRLEN))
    {
      printf("Error generating LSI from HIT!\n");
      return(-1);
    }

  memcpy(&hostid->lsi, &lsi, sizeof(struct sockaddr_in));
  if (gethostname(basename, sizeof(basename)) < 0)
    {
      sprintf(basename, "default");
    }
  sprintf(hostid->name, "%s-%d", basename, bitsize);

  /* printf("This host hit: %s, lsi: %s HI, bitsize %d\n", hit_hex, lsi_str,
   * bitsize); */
  return(0);
}

int hipCfg::getPeerNodes(struct peer_node *peerNodes, unsigned int max_count)
{
  int j;
  if (_hit_to_peers.size() > max_count)
    {
      cout << "getPeerNodes Error: peerNodes array too small." << endl;
      return(-1);
    }
  else if (_hit_to_peers.size() == 0)
    {
      return(0);
    }

  memset(peerNodes, 0, sizeof(struct peer_node) * _hit_to_peers.size());
  map <string, struct peer_node *>::iterator i;
  for (j = 0, i = _hit_to_peers.begin(); i != _hit_to_peers.end(); i++, j++)
    {
      struct peer_node *p = (*i).second;
      memcpy(&peerNodes[j], p, sizeof(struct peer_node));
    }
  return(j);
}

int hipCfg::getLocalCertUrl(char *url, unsigned int size)
{
  int rc = 0;
  if (_localCertUrl.length() == 0)
    {
      return(1); /* OK, no local Cert to provide. */
    }
  if (_localCertUrl.length() >= size)
    {
      cout << "getLocalCertUrl: buffer too small." << endl;
      return(-1);
    }
  strcpy(url, _localCertUrl.c_str());
  return(rc);
}

/*
 * function locate_config_file(): lifted from hip_xml.c
 *
 * Search for existence of a file in the local directory or in the
 * HIP configuration directory. Store the path name into the supplied buffer.
 *
 * filename	string to store resulting full path name; may contain user-
 *    specified file name
 * filename_size  max length of filename buffer
 * default_name filename to use (without path) when user does not specify the
 *    filename
 *
 * Returns 0 if file or symlink exists, -1 if there is no suitable file.
 *
 */
int hipCfg::locate_config_file(char *filename,
                               int filename_size,
                               const char *default_name)
{
  struct stat stbuf;

  /* The user has specified the config file name. Only check if
   * it exists, do not try other locations. */
  if ('\0' != *filename)
    {
      if (stat(filename, &stbuf) < 0)
        {
          return(-1);
        }
      if (S_ISREG(stbuf.st_mode) || S_ISLNK(stbuf.st_mode))
        {
          return(0);               /* found OK */
        }
      else
        {
          return(-1);
        }
    }

  /* Check for default name in current working dir.
   */
  snprintf(filename, filename_size, "./%s", default_name);
  if (stat(filename, &stbuf) == 0)
    {
      if (S_ISREG(stbuf.st_mode) || S_ISLNK(stbuf.st_mode))
        {
          return(0);               /* found OK */
        }
    }
  /* Check for sysconfdir to locate the file.
   */
  snprintf(filename, filename_size, "%s/%s", SYSCONFDIR, default_name);
  if (stat(filename, &stbuf) == 0)
    {
      if (S_ISREG(stbuf.st_mode) || S_ISLNK(stbuf.st_mode))
        {
          return(0);               /* found OK */
        }
    }
  return(-1);
}

sockaddr_list * hipCfg::add_address_to_list(sockaddr_list **list,
                                            struct sockaddr *addr,
                                            int ifi)
{
  sockaddr_list *item, *new_item, *last_item;

  /* make a new sockaddr_list element */
  new_item = (sockaddr_list*) malloc(sizeof(sockaddr_list));
  if (!new_item)
    {
      return(NULL);
    }
  memset(new_item, 0, sizeof(sockaddr_list));
  memcpy(&new_item->addr, addr, SALEN(addr));
  new_item->if_index = ifi;
  new_item->status = UNVERIFIED;
  new_item->next = NULL;

  /* append element to list */
  if (*list)
    {
      for (item = *list; item; item = item->next)
        {
          /* check if new_item already exists */
          if ((item->if_index == new_item->if_index) &&
              (item->addr.ss_family == new_item->addr.ss_family)
              && (!memcmp(SA2IP(&item->addr),
                          SA2IP(&new_item->addr), SAIPLEN(addr))))
            {
              free(new_item);
              return(item);
            }
          last_item = item;
        }
      last_item->next = new_item;
    }
  else
    {
      *list = new_item;
    }
  return(new_item);
}

int hipCfg::getEndboxMapsFromLocalFile()
{
  string hit_s, underlayIp_s, hit1_s, hit2_s;
  xmlDocPtr doc;
  xmlNodePtr node;
  char *data;
  struct sockaddr_storage ss_addr;
  struct sockaddr *addr;

  addr = (struct sockaddr*) &ss_addr;

  char known_hi_filename[255] = { 0 };

  if (locate_config_file(known_hi_filename,
                         sizeof(known_hi_filename),
                         HIP_KNOWNID_FILENAME) == 0)
    {
      cout << "Will attempt to parse file: " << known_hi_filename << endl;
    }
  else
    {
      cout << "Could not find known_hi_filename" << endl;
      return(-1);
    }

  doc = xmlParseFile(known_hi_filename);
  if (doc == NULL)
    {
      cout << "Error parsing xml file " << known_hi_filename << endl;
      return(-1);
    }

  node = xmlDocGetRootElement(doc);
  for (node = node->children; node; node = node->next)
    {
      if (strcmp((char *)node->name, "host_identity") == 0)
        {
          struct peer_node *p;
          char lsi_s[INET_ADDRSTRLEN];
          string assetTag_s, underlayIp_s;
          list<string> legacyNodes;
          xmlAttrPtr attr;

          p = new (struct peer_node);
          memset(p, 0, sizeof(struct peer_node));

          attr = node->properties;
          p->r1_gen_count = 0;
          p->anonymous = 0;
          p->allow_incoming = 1;
          p->skip_addrcheck = 0;

          while (attr)
            {
              char *value;
              int tmp;
              if ((attr->type == XML_ATTRIBUTE_NODE) &&
                  (attr->children) && (attr->children->type == XML_TEXT_NODE))
                {
                  value = (char *)attr->children->content;
                }
              else /* no attribute value */
                {
                  continue;
                }
              /* save recognized attributes */
              if (strcmp((char *)attr->name, "alg_id") == 0)
                {
                  sscanf(value, "%d", &tmp);
                  p->algorithm_id = (char)tmp;
                }
              else if (strcmp((char *)attr->name, "length") == 0)
                {
                  sscanf(value, "%d", &p->size);
                }
              else if (strcmp((char *)attr->name, "anon") == 0)
                {
                  if (*value == 'y')
                    {
                      p->anonymous = 1;
                    }
                  else
                    {
                      p->anonymous = 0;
                    }
                }
              else if (strcmp((char *)attr->name, "incoming") == 0)
                {
                  if (*value == 'y')
                    {
                      p->allow_incoming = 1;
                    }
                  else
                    {
                      p->allow_incoming = 0;
                    }
                }
              else if (strcmp((char *)attr->name, "r1count") == 0)
                {
                  sscanf(value, "%llu", &p->r1_gen_count);
                }
              else if (strcmp((char *)attr->name, "addrcheck") == 0)
                {
                  if (strcmp(value, "no") == 0)
                    {
                      p->skip_addrcheck = 1;
                    }
                }
              attr = attr->next;
            }

          cout << "Loading Host Identity Tag ..." << endl;
          for (xmlNodePtr cnode = node->children; cnode; cnode = cnode->next)
            {
              if (strcmp((char *)cnode->name, "text") == 0)
                {
                  continue;
                }
              data = (char *)xmlNodeGetContent(cnode);
              if (strcmp((char *)cnode->name, "HIT") == 0)
                {
                  memset(addr, 0,sizeof(struct sockaddr_storage));
                  addr->sa_family = AF_INET6;
                  if (str_to_addr(data, addr) <= 0)
                    {
                      cout << "Waring parsing known host id - HIT " << data <<
                      " is invalid" << endl;
                      xmlFree(data);
                      continue;
                    }
                  hit_s = data;
                }
              else if (strcmp((char *)cnode->name, "name") == 0)
                {
                  assetTag_s = data;
                }
              else if (strcmp((char *)cnode->name, "addr") == 0)
                {
                  underlayIp_s = data;
                }
              else if (strcmp((char *)cnode->name, "legacyNodesIp") == 0)
                {
                  legacyNodes.push_back(data);
                }
              else if (strcmp((char *)node->name, "RVS") == 0)
                {
                  memset(addr, 0, sizeof(struct sockaddr_storage));
                  addr->sa_family =
                    ((strchr(data, ':') == NULL) ? AF_INET : AF_INET6);
                  if (str_to_addr(data, addr) > 0)
                    {
                      add_address_to_list(p->rvs_addrs, addr, 0);
                    }
                  else
                    {
                      cout <<
                      "Waring parsing known host id - not a valid address " <<
                      data <<
                      endl;
                    }

                }
              xmlFree(data);
            }
          _endbox2LlipMap[hit_s] = underlayIp_s;
          /* cout<<"add ("<<hit_s<<", "<<underlayIp_s<<") into
           * _endbox2LlipMap"<<endl; */
          list<string>::iterator i;
          for (i = legacyNodes.begin(); i != legacyNodes.end(); i++)
            {
              string lnode_s = *i;
              _legacyNode2EndboxMap[lnode_s] = hit_s;
              cout << "add (" << lnode_s << ", " << hit_s <<
              ") into _legacyNode2EndboxMap" << endl;
            }
          if (!hitstr2lsistr(lsi_s, hit_s.c_str()))
            {
              _legacyNode2EndboxMap[lsi_s] = hit_s;
              cout << "add (" << lsi_s << ", " << hit_s <<
              ") into _legacyNode2EndboxMap" << endl;
            }
          else
            {
              cout << "error convert HIT to LSI" << endl;
              return(-1);
            }
          hitstr2hit(p->hit, hit_s.c_str());

          strcpy(p->name, assetTag_s.c_str());
          _hit_to_peers.insert(std::make_pair(hit_s, p));
          cout << "add peer node " << assetTag_s << ", " << hit_s <<
          " into _hit_to_peers" << endl;
        }
      else if (strcmp((char *)node->name, "peer_allowed") == 0)
        {
          cout << "Loading peer_allowed Tag ..." << endl;
          xmlNodePtr cnode;
          string hit1_s, hit2_s;
          for (cnode = node->children; cnode; cnode = cnode->next)
            {
              if (strcmp((char *)cnode->name, "text") == 0)
                {
                  continue;
                }
              data = (char *)xmlNodeGetContent(cnode);
              if (strcmp((char *)cnode->name, "hit1") == 0)
                {
                  hit1_s = data;
                }
              else if (strcmp((char *)cnode->name, "hit2") == 0)
                {
                  hit2_s = data;
                }
              xmlFree(data);
            }
          hip_hit hit1, hit2;
          if (hitstr2hit(hit1, hit1_s.c_str()) < 0)
            {
              cout << "Error convert hit " << hit1_s << endl;
              continue;
            }
          else if (hitstr2hit(hit2, hit2_s.c_str()) < 0)
            {
              cout << "error convert hit " << hit2_s << endl;
              continue;
            }

          if (memcmp(hit1, hit2, HIT_SIZE) < 0)
            {
              hitPair hp(hit1, hit2);
              _allowed_peers.insert(hp);
            }
          else if (memcmp(hit1, hit2, HIT_SIZE) > 0)
            {
              hitPair hp(hit2, hit1);
              _allowed_peers.insert(hp);
            }
          cout << "insert a hitPair hit1: " << hit1_s << " hit2: " << hit2_s <<
          endl;
        }
    }
  return(0);
}

bool hitPair::operator<(const hitPair & hp) const
{
  /* this->print(); */
  return(memcmp(hp._hit1, _hit1, HIT_SIZE) > 0 ||
         (memcmp(hp._hit1, _hit1,
                 HIT_SIZE) == 0 && memcmp(hp._hit2, _hit2, HIT_SIZE) > 0));
}

hitPair::hitPair(const hip_hit hit1, const hip_hit hit2)
{
  memcpy(_hit1, hit1, HIT_SIZE);
  memcpy(_hit2, hit2, HIT_SIZE);
}

