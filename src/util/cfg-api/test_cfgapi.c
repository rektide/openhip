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
 *  \file  test_cfgapi.c
 *
 *  \authors	Jin Fang <jin.fang@boeing.com>
 *
 *  \brief  Configuration API test program.
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <libxml/tree.h>
#include <hip/hip_cfg_api.h>

#define SA2IP(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? \
  (void*)&((struct sockaddr_in*)x)->sin_addr : \
  (void*)&((struct sockaddr_in6*)x)->sin6_addr
#define SALEN(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)
#define SAIPLEN(x) (((struct sockaddr*)x)->sa_family == AF_INET) ? 4 : 16
#define SA(x) ((struct sockaddr*)x)


int hit2hitstr(char *hit_str, hip_hit hit)
{
  struct sockaddr *addr;
  struct sockaddr_storage ss_addr;

  addr = (struct sockaddr*) &ss_addr;
  memset(&ss_addr, 0, sizeof(struct sockaddr_storage));
  ss_addr.ss_family = AF_INET6;
  memcpy(SA2IP(&ss_addr), hit, SAIPLEN(&ss_addr));
  return(inet_ntop(addr->sa_family, SA2IP(addr), hit_str,
                   INET6_ADDRSTRLEN) == NULL);
}

int str_to_addr(const char *data, struct sockaddr *addr)
{
  return(inet_pton(addr->sa_family, (char*)data, SA2IP(addr)));
}

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
      c = src[i];
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

int hitstr2hit(hip_hit hit, char *hit_str)
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
          return(-1);
        }
      memcpy(hit, SA2IP(addr), HIT_SIZE);
      return(0);
    }
  return(hex_to_bin(hit_str, (char *)hit, HIT_SIZE));
}

/*
 * function read_conf_file()
 * Load configuration options from the XML file
 * stored in hip.conf
 */
int read_conf_file(char *filename, struct hip_conf *hc)
{
  xmlDocPtr doc = NULL;
  xmlNodePtr node = NULL;
  char *data;

  doc = xmlParseFile(filename);
  if (doc == NULL)
    {
      return(-1);
    }

  node = xmlDocGetRootElement(doc);
  for (node = node->children; node; node = node->next)
    {
      data = (char *)xmlNodeGetContent(node);
      if (strcmp((char *)node->name, "text") == 0)
        {
          ;
        }
      else if (strcmp((char *)node->name, "comment") == 0)
        {
          ;
        }
      else if (strcmp((char*)node->name,
                      "peer_certificate_required") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              hc->peer_certificate_required = TRUE;
            }
          else
            {
              hc->peer_certificate_required = FALSE;
            }
        }
      else if (strlen((char *)node->name))
        {
          ;
        }
      xmlFree(data);
    }

  xmlFreeDoc(doc);
  return(0);
}

int main(void)
{
  int rc, i;
  hip_hit hit1;
  hip_hit hit2;
  struct sockaddr_storage host_ss;
  struct sockaddr_storage eb_ss;
  struct sockaddr *host_p;
  struct sockaddr *eb_p;
  char host_s[64];
  char eb_s[64];
  struct sockaddr_storage hosts[5];
  int hosts_cnt = 5;
  char hit_s[64];
  char cert[2048];
  char url[128];
  struct sockaddr *lsi;

  struct hip_conf *hc;
  hc = malloc(sizeof(struct hip_conf));

  memset(hc, 0, sizeof(struct hip_conf));
  if (read_conf_file("hip.conf", hc) < 0)
    {
      printf("cannot read hip.conf\n");
      exit(-1);
    }

  host_p = (struct sockaddr*)&host_ss;
  eb_p = (struct sockaddr*)&eb_ss;

  char *dlname = "libhipcfg.so";
  rc = hipcfg_init(dlname, hc);
  if (rc < 0)
    {
      printf("hipcfg_init failed.\n");
      exit(-1);
    }

  hi_node *hi = hipcfg_getMyHostId();
  if (hi == NULL)
    {
      printf("cannot get local host identity.\n");
    }
  else
    {
      lsi = (struct sockaddr*)&hi->lsi;
      inet_ntop(lsi->sa_family, SA2IP(lsi), host_s, sizeof(host_s));
      hit2hitstr(hit_s, hi->hit);
      printf("my host identity hit: %s lsi: %s name: %s\n",
             hit_s,
             host_s,
             hi->name);
    }

  strcpy(hit_s, "2001:1d:52a7:1633:48ae:b657:e975:9efa");
  hitstr2hit(hit1, hit_s);
  sprintf(url, "hit=%s,dc=endboxes,dc=sma,dc=boeing,dc=com", hit_s);
  rc = hipcfg_verifyCert(url, hit1);
  if (rc == 1)
    {
      printf("certificate verified url %s\n", url);
    }
  else
    {
      printf("certificate not verified url %s\n", url);
    }

  strcpy(hit_s, "2001:1d:4e61:edab:ec2a:b310:201c:ffd0");
  hitstr2hit(hit1, hit_s);
  sprintf(url, "hit=%s,dc=endboxes,dc=sma,dc=boeing,dc=com", hit_s);
  rc = hipcfg_verifyCert(url, hit1);
  if (rc == 1)
    {
      printf("certificate verified url %s\n", url);
    }
  else
    {
      printf("certificate not verified url %s\n", url);
    }

  /* test cached cert that has been validated */
  strcpy(hit_s, "2001:1d:4e61:edab:ec2a:b310:201c:ffd0");
  hitstr2hit(hit1, hit_s);
  sprintf(url, "hit=%s,dc=endboxes,dc=sma,dc=boeing,dc=com", hit_s);
  rc = hipcfg_verifyCert(url, hit1);
  if (rc == 1)
    {
      printf("certificate verified url %s - using cached cert\n", url);
    }
  else
    {
      printf("certificate not verified url %s - using cached cert\n",
             url);
    }


  strcpy(hit_s, "2001:1d:4e61:edab:ec2a:b310:201c:ffd0");
  hitstr2hit(hit1, hit_s);
  strcpy(hit_s, "2001:1d:52a7:1633:48ae:b657:e975:9efa");
  hitstr2hit(hit2, hit_s);
  rc = hipcfg_allowed_peers(hit1, hit2);
  printf("hipcfg_allowed_peers positive case: returned %d\n", rc);
  rc = hipcfg_allowed_peers(hit2, hit1);
  printf("hipcfg_allowed_peers positive case: returned %d\n", rc);
  hit1[0] = 0x99;
  rc = hipcfg_allowed_peers(hit1, hit2);
  printf("hipcfg_allowed_peers negative case: returned %d\n", rc);

  hip_hit hits1[10], hits2[10];
  rc = hipcfg_peers_allowed(hits1, hits2, 10);
  if (rc > 0)
    {
      for (i = 0; i < rc; i++)
        {
          printf("peers_allowed: hit1 %02x%02x hit2 %02x%02x\n",
                 *(hits1[i] + 14),
                 *(hits1[i] + 15),
                 *(hits2[i] + 14),
                 *(hits2[i] + 15));
        }
    }
  else
    {
      printf("hipcfg_peers_allowed returned error\n");
    }

  strcpy(host_s, "192.168.0.15");
  host_p->sa_family = AF_INET;
  inet_pton(host_p->sa_family, host_s, SA2IP(host_p));
  eb_p->sa_family = AF_INET;
  rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
  inet_ntop(eb_p->sa_family, SA2IP(eb_p), eb_s, sizeof(eb_s));
  printf(
    "valid case hipcfg_getEndboxByLegacyNode, endbox in lsi, rc: %d host: %s eb: %s\n",
    rc,
    host_s,
    eb_s);

  eb_p->sa_family = AF_INET6;
  rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
  inet_ntop(eb_p->sa_family, SA2IP(eb_p), eb_s, sizeof(eb_s));
  printf(
    "valid case hipcfg_getEndboxByLegacyNode, endbox in hit, rc: %d host: %s eb: %s\n",
    rc,
    host_s,
    eb_s);

  strcpy(host_s, "192.168.5.36");
  host_p->sa_family = AF_INET;
  inet_pton(AF_INET, host_s, SA2IP(host_p));
  rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
  inet_ntop(eb_p->sa_family, SA2IP(eb_p), eb_s, sizeof(eb_s));
  printf("invalid case hipcfg_getEndboxByLegacyNode rc: %d host: %s \n",
         rc,
         host_s);

  strcpy(host_s, "1.117.158.250");
  host_p->sa_family = AF_INET;
  inet_pton(AF_INET, host_s, SA2IP(host_p));
  eb_p->sa_family = AF_INET;
  rc = hipcfg_getEndboxByLegacyNode(host_p, eb_p);
  inet_ntop(eb_p->sa_family, SA2IP(eb_p), eb_s, sizeof(eb_s));
  printf(
    "valid case hipcfg_getEndboxByLegacyNode rc: %d host: %s eb: %s\n",
    rc,
    host_s,
    eb_s);

  strcpy(eb_s, "2001:1d:52a7:1633:48ae:b657:e975:9efa");
  eb_p->sa_family = AF_INET6;
  inet_pton(eb_p->sa_family, eb_s, SA2IP(eb_p));
  rc = hipcfg_getLlipByEndbox(eb_p, host_p);
  inet_ntop(host_p->sa_family, SA2IP(host_p), host_s, sizeof(host_s));
  printf(
    "valid case hipcfg_getLlipByEndbox rc: %d endbox: %s bcwin: %s\n",
    rc,
    eb_s,
    host_s);

  strcpy(eb_s, "1.117.158.250");
  eb_p->sa_family = AF_INET;
  inet_pton(AF_INET, eb_s, SA2IP(eb_p));
  rc = hipcfg_getLegacyNodesByEndbox(eb_p, hosts, hosts_cnt);
  if (rc > 0)
    {
      printf(
        "valid case hipcfg_getLegacyNodesByEndbox rc: %d legacyNodes for endbox %s: ",
        rc,
        eb_s);
      for (i = 0; i < rc; i++)
        {
          host_p = (struct sockaddr *)&hosts[i];
          inet_ntop(host_p->sa_family, SA2IP(
                      host_p), host_s, sizeof(host_s));
          printf(" %s", host_s);
        }
      printf("\n");
    }
  else
    {
      printf("hipcfg_getLegacyNodesByEndbox returned %d\n", rc);
    }

  struct peer_node nodes[10];
  rc = hipcfg_getPeerNodes(nodes, 10);
  if (rc < 0)
    {
      printf("error calling hipcfg_getPeerNodes\n");
    }
  else if (rc == 0)
    {
      printf("no peer nodes found\n");
    }

  printf("hipcfg_getPeerNode returned %d entries\n", rc);
  for (i = 0; i < rc; i++)
    {
      hit2hitstr(hit_s, nodes[i].hit);
      printf("peer node: hit: %s, assetTag: %s\n",
             hit_s,
             nodes[i].name);
    }

  if (hi == NULL)
    {
      exit(0);           /* no further test if not use smartcard */

    }
  rc = hipcfg_getLocalCertUrl(url, sizeof(url));
  if (rc == 0)
    {
      printf("hipcfg_getLocalCertUrl succeed - url: %s\n", url);
    }
  else
    {
      printf("hipcfg_getLocalCertUrl returned error\n");
    }

  int fd = open("scCert.pem", O_RDONLY);
  if (fd < 0)
    {
      printf("error open scCert.pem\n");
    }
  else
    {
      rc = read(fd, cert, sizeof(cert));
    }
  if (fd < 0)
    {
      printf("error read scCert.pem\n");
    }

  BIO *bio_mem = BIO_new_mem_buf(cert, -1);
  X509 *scCert = PEM_read_bio_X509(bio_mem, NULL, 0, NULL);
  if (scCert == NULL)
    {
      printf("Error getting X509 certificate from PEM form\n");
      exit(1);
    }

  EVP_PKEY *pubkey = X509_get_pubkey(scCert);
  if (pubkey == NULL)
    {
      printf("error get public key from X509 cert.\n");
      exit(1);
    }

  for (i = 0; i < 30; i++)
    {
      SHA_CTX c;
      unsigned char md[SHA_DIGEST_LENGTH];
      unsigned char rsa_sig[1024];
      unsigned char data[512];
      unsigned int sig_len;

      SHA1_Init(&c);
      SHA1_Update(&c, data, sizeof(data));
      SHA1_Final(md, &c);

      if (hi->rsa)
        {
          sig_len = RSA_size(hi->rsa);
          rc = RSA_sign(NID_sha1,
                        md,
                        SHA_DIGEST_LENGTH,
                        rsa_sig,
                        &sig_len,
                        hi->rsa);
          if (rc != 1)
            {
              printf("RSA_sign failed\n");
            }
          else
            {
              printf(
                "successfully signed a message digest.\n");
            }
        }

      sig_len = RSA_size(hi->rsa);
      rc = RSA_verify(NID_sha1,
                      md,
                      SHA_DIGEST_LENGTH,
                      rsa_sig,
                      sig_len,
                      EVP_PKEY_get1_RSA(pubkey));
      if (rc != 1)
        {
          printf("RSA_verify failed\n");
        }
      else
        {
          printf("RSA signature verified.\n");
        }
    }

  return(0);
}

