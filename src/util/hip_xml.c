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
 *  \file  hip_xml.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson <thomas.r.henderson@boeing.com>
 *
 *  \brief  Functions involving reading/writing HIP configuration files:
 *          my_host_identities.xml, known_host_identities.xml, and hip.conf.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __WIN32__
#include <win32/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <crt/process.h>        /* getpid() */
#include <win32/ip.h>
#else
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>          /* inet_addr()                  */
#include <netinet/in.h>         /* INADDR_NONE                  */
#include <netinet/ip.h>         /* INADDR_NONE                  */
#include <netinet/ip6.h>
#include <pthread.h>            /* pthreads support		*/
#endif /* __WIN32__ */
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/asn1.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>           /* stat() support */
#include <errno.h>
#include <fcntl.h>              /* open()			*/
#include <libxml/tree.h>        /* all XML stuff		*/
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#ifdef HIP_VPLS
#include <hip/hip_cfg_api.h>
#endif /* HIP_VPLS */
#include <hip/hip_dns.h>        /* DNS headers			*/

/*
 * function locate_config_file()
 *
 * Search for existence of a file in the local directory or in the
 * HIP configuration directory. Store the path name into the supplied buffer.
 *
 * filename	string to store resulting full path name; may contain user-
 *              specified file name
 * filename_size  max length of filename buffer
 * default_name filename to use (without path) when user does not specify the
 *              filename
 *
 * Returns 0 if file or symlink exists, -1 if there is no suitable file.
 *
 */
#ifdef WIN32
#define stat _stat
#define S_ISREG(mode) ((mode & _S_IFMT) == _S_IFREG)
#define S_ISLNK(mode) (0)
#endif /* WIN32 */
int locate_config_file(char *filename, int filename_size, char *default_name)
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

/*
 * Traverse the linked-list of XML attributes stored in attr, and
 * store the value of each attribute into the hi_node structure.
 */
void parse_xml_attributes(xmlAttrPtr attr, hi_node *hi)
{
  char *value;
  int tmp;

  /* first set some defaults if certain attributes are absent */
  if (hi == NULL)
    {
      return;
    }
  hi->r1_gen_count = 0;
  hi->anonymous = 0;
  hi->allow_incoming = 1;
  hi->skip_addrcheck = 0;

  while (attr)
    {
      if ((attr->type == XML_ATTRIBUTE_NODE) &&
          (attr->children) &&
          (attr->children->type == XML_TEXT_NODE))
        {
          value = (char *)attr->children->content;
        }
      else             /* no attribute value */
        {
          continue;
        }
      /* save recognized attributes */
      if (strcmp((char *)attr->name, "alg") == 0)
        {
          /* ignored */
          /* memcpy(alg, value, strlen(value)); */
        }
      else if (strcmp((char *)attr->name, "alg_id") == 0)
        {
          sscanf(value, "%d", &tmp);
          hi->algorithm_id = (char)tmp;
        }
      else if (strcmp((char *)attr->name, "length") == 0)
        {
          sscanf(value, "%d", &hi->size);
        }
      else if (strcmp((char *)attr->name, "anon") == 0)
        {
          if (*value == 'y')
            {
              hi->anonymous = 1;
            }
          else
            {
              hi->anonymous = 0;
            }
        }
      else if (strcmp((char *)attr->name, "incoming") == 0)
        {
          if (*value == 'y')
            {
              hi->allow_incoming = 1;
            }
          else
            {
              hi->allow_incoming = 0;
            }
        }
      else if (strcmp((char *)attr->name, "r1count") == 0)
        {
          sscanf(value, "%llu", &hi->r1_gen_count);
        }
      else if (strcmp((char *)attr->name, "addrcheck") == 0)
        {
          if (strcmp(value, "no") == 0)
            {
              hi->skip_addrcheck = TRUE;
            }
        }
      attr = attr->next;
    }
}

/*
 * Traverse the linked-list of child nodes stored in node, and
 * store the content of each element into the DSA structure or
 * into the HIT.
 */
void parse_xml_hostid(xmlNodePtr node, hi_node *hi)
{
  char *data;
  struct sockaddr_storage ss_addr;
  struct sockaddr *addr;
  sockaddr_list *list, *l;

  addr = (struct sockaddr*) &ss_addr;
  memset(hi->hit, 0, HIT_SIZE);
  memset(&hi->lsi, 0, sizeof(struct sockaddr_storage));

  for (; node; node = node->next)
    {
      /* skip entity refs */
      if (strcmp((char *)node->name, "text") == 0)
        {
          continue;
        }

      data = (char *)xmlNodeGetContent(node);
      /* populate the DSA structure */
      switch (hi->algorithm_id)
        {
        case HI_ALG_DSA:
          if (strcmp((char *)node->name, "P") == 0)
            {
              BN_hex2bn(&hi->dsa->p, data);
            }
          else if (strcmp((char *)node->name, "Q") == 0)
            {
              BN_hex2bn(&hi->dsa->q, data);
            }
          else if (strcmp((char *)node->name, "G") == 0)
            {
              BN_hex2bn(&hi->dsa->g, data);
            }
          else if (strcmp((char *)node->name, "PUB") == 0)
            {
              BN_hex2bn(&hi->dsa->pub_key, data);
            }
          else if (strcmp((char *)node->name, "PRIV") == 0)
            {
              BN_hex2bn(&hi->dsa->priv_key, data);
            }
          break;
        case HI_ALG_RSA:
          if (strcmp((char *)node->name, "N") == 0)
            {
              BN_hex2bn(&hi->rsa->n, data);
            }
          else if (strcmp((char *)node->name, "E") == 0)
            {
              BN_hex2bn(&hi->rsa->e, data);
            }
          else if (strcmp((char *)node->name, "D") == 0)
            {
              BN_hex2bn(&hi->rsa->d, data);
            }
          else if (strcmp((char *)node->name, "P") == 0)
            {
              BN_hex2bn(&hi->rsa->p, data);
            }
          else if (strcmp((char *)node->name, "Q") == 0)
            {
              BN_hex2bn(&hi->rsa->q, data);
            }
          else if (strcmp((char *)node->name, "dmp1") == 0)
            {
              BN_hex2bn(&hi->rsa->dmp1, data);
            }
          else if (strcmp((char *)node->name, "dmq1") == 0)
            {
              BN_hex2bn(&hi->rsa->dmq1, data);
            }
          else if (strcmp((char *)node->name, "iqmp") == 0)
            {
              BN_hex2bn(&hi->rsa->iqmp, data);
            }
          break;
        default:
          break;
        }
      /* get HI values that are not algorithm-specific */
      if (strcmp((char *)node->name, "HIT") == 0)
        {
          /* HIT that looks like IPv6 address */
          if (strchr(data, ':'))
            {
              memset(addr, 0,sizeof(struct sockaddr_storage));
              addr->sa_family = AF_INET6;
              if (str_to_addr((__u8*)data, addr) <= 0)
                {
                  log_(WARN, "%s '%s' for %s invalid.\n",
                       node->name, data, hi->name);
                  xmlFree(data);
                  continue;
                }
              memcpy(hi->hit, SA2IP(addr), HIT_SIZE);
            }
          else                   /* HIT that is plain hex */
            {
              hex_to_bin(data, (char *)hi->hit, HIT_SIZE);
            }
        }
      else if (strcmp((char *)node->name, "name") == 0)
        {
          memset(hi->name, 0, sizeof(hi->name));
          strncpy(hi->name, data, sizeof(hi->name));
          hi->name_len = strlen(hi->name);
        }
      else if ((strcmp((char *)node->name, "LSI") == 0) ||
               (strcmp((char *)node->name, "addr") == 0) ||
               (strcmp((char *)node->name, "RVS") == 0))
        {
          memset(addr, 0, sizeof(struct sockaddr_storage));
          /* Determine address family - IPv6 must have a ':' */
          addr->sa_family = ((strchr(data, ':') == NULL) ? \
                             AF_INET : AF_INET6);
          if (str_to_addr((__u8*)data, addr) > 0)
            {
              list = &hi->addrs;
              /* additional address entry */
              if ((strcmp((char *)node->name,
                          "addr") == 0) &&
                  (VALID_FAM(&list->addr)))
                {
                  l = add_address_to_list(&list, addr, 0);
                  l->status = UNVERIFIED;
                  /* LSI */
                }
              else if (strcmp((char *)node->name,
                              "LSI") == 0)
                {
                  memcpy(&hi->lsi, addr, SALEN(addr));
                  /* rendevous server (RVS)  */
                }
              else if (strcmp((char *)node->name,
                              "RVS") == 0)
                {
                  add_address_to_list(hi->rvs_addrs,
                                      addr,
                                      0);
                  /* first (preferred) entry in address
                   *list */
                }
              else
                {
                  memcpy(&list->addr, addr, SALEN(addr));
                  list->status = ACTIVE;
                }
            }
          else
            {
              log_(WARN, "%s '%s' for %s not valid.\n",
                   node->name, data, hi->name);
            }
        }
      xmlFree(data);
    }
}

#ifdef HIP_VPLS
/*
 * function read_peer identities_from_hipcfg()
 *
 */
int read_peer_identities_from_hipcfg()
{
  hi_node *hi;
  int rc, i;
  char name[255];
  sockaddr_list *l;
  struct peer_node nodes[MAX_CONNECTIONS], *np;

  rc = hipcfg_getPeerNodes(nodes, MAX_CONNECTIONS);
  if (rc < 0)
    {
      return(-1);
    }

  for (i = 0; i < rc; i++)
    {
      log_(NORM, "Loading Host Identity %s...\n", nodes[i].name);
      hi = create_new_hi_node();

      np = &nodes[i];
      hi->algorithm_id = np->algorithm_id;
      hi->size = np->size;
      hi->anonymous = np->anonymous;
      hi->allow_incoming = np->allow_incoming;
      hi->r1_gen_count = np->r1_gen_count;
      hi->skip_addrcheck = np->skip_addrcheck;
      strcpy(hi->name, np->name);
      memcpy(hi->hit, np->hit, sizeof(hip_hit));

      __u32 lsi = ntohl(HIT2LSI(hi->hit));
      if (hits_equal(hi->hit, zero_hit))
        {
          log_(WARN, "No HIT or LSI for %s,", hi->name);
          log_(NORM, " skipping.\n");
          free_hi_node(hi);
          continue;
        }
      hi->lsi.ss_family = AF_INET;
      memcpy(SA2IP(&hi->lsi), &lsi, sizeof(__u32));
      log_(NORM, "%s ", logaddr(SA(&hi->lsi)));
      /* get HI name */
      strcpy(name, hi->name);

      /* lookup hipcfg module (DDL) */
      struct sockaddr_storage llip_ss;
      struct sockaddr_storage hit_ss;
      struct sockaddr *llip_p, *hit_p;

      llip_p = (struct sockaddr*)&llip_ss;
      hit_p = (struct sockaddr*)&hit_ss;
      memset(&hit_ss, 0, sizeof(struct sockaddr_storage));
      hit_ss.ss_family = AF_INET6;
      memcpy(SA2IP(&hit_ss), hi->hit, SAIPLEN(&hit_ss));

      memset(&llip_ss, 0, sizeof(struct sockaddr_storage));
      if (!hipcfg_getLlipByEndbox(hit_p, llip_p))
        {
          /* hipcfg only privides preferred address. */
          sockaddr_list *list = &hi->addrs;
          memset(list, 0, sizeof(sockaddr_list));
          memcpy(&list->addr, llip_p, SALEN(llip_p));
          list->status = ACTIVE;
        }
      else
        {
          /* address not listed, perform DNS, then
           * DHT lookup */
          if (add_addresses_from_dns(name, hi) < 0)
            {
              hip_dht_resolve_hi(hi, TRUE);
            }
        }
      log_(NORM, "%s = [ ", name);
      for (l = &hi->addrs; l; l = l->next)
        {
          log_(NORM, "%s ",
               logaddr((struct sockaddr*)&l->addr));
        }
      log_(NORM, "] ");

      if (np->rvs_addrs)
        {
          for (l = *(np->rvs_addrs); l != NULL; l = l->next)
            {
              add_address_to_list(hi->rvs_addrs, SA(&l->addr),
                                  0);
            }
        }

      if (!find_host_identity(peer_hi_head, hi->hit))
        {
          /* link this HI into a global list */
          append_hi_node(&peer_hi_head, hi);
          log_(NORM, "appended\n");
        }
      else
        {
          log_(NORM, "already in global table\n");
        }
    }

  add_addresses_from_dns(NULL, NULL);
  return(0);
}

#endif /* HIP_VPLS */

/*
 * function read_identities_file()
 *
 * filename	name of the XML file to open
 * mine		is this my list of Host Identities?
 *              if TRUE, store HIs/HITs into my_hi_list, otherwise
 *              store into peer_hi_list.
 *
 */
int read_identities_file(char *filename, int mine)
{
  xmlDocPtr doc = NULL;
  xmlNodePtr node = NULL;
  hi_node *hi;
  char name[255];
  uint8_t *out_buff = NULL;
  int out_buff_len = 0;

#ifdef HIP_VPLS
  if (!mine)
    {
      return(read_peer_identities_from_hipcfg());
    }
#endif /* HIP_VPLS */

  doc = xmlParseFile(filename);
  if (doc == NULL)
    {
      fprintf(stderr, "Error parsing xml file (%s)\n", filename);
      return(-1);
    }

  node = xmlDocGetRootElement(doc);
  for (node = node->children; node; node = node->next)
    {
      if (strcmp((char *)node->name, "host_identity") == 0)
        {
          hi = create_new_hi_node();
          parse_xml_attributes(node->properties, hi);
          switch (hi->algorithm_id)
            {
            case HI_ALG_DSA:
              hi->dsa = DSA_new();
              break;
            case HI_ALG_RSA:
              hi->rsa = RSA_new();
              break;
            default:
              if (mine)
                {
                  log_(WARN, "Unknown algorithm found ");
                  log_(WARN, "in XML file for %s: %u\n",
                       hi->name, hi->algorithm_id);
                  free_hi_node(hi);
                  continue;
                }
            }
          /* fill in the DSA/RSA structure, HIT, LSI, name */
          parse_xml_hostid(node->children, hi);
          /* if LSI is not configured, it is 24-bits of HIT */
          if (!VALID_FAM(&hi->lsi))
            {
              __u32 lsi = ntohl(HIT2LSI(hi->hit));
              if (hits_equal(hi->hit, zero_hit))
                {
                  log_(WARN, "No HIT or LSI for %s,",
                       hi->name);
                  log_(NORM, " skipping.\n");
                  free_hi_node(hi);
                  continue;
                }
              hi->lsi.ss_family = AF_INET;
              memcpy(SA2IP(&hi->lsi), &lsi, sizeof(__u32));
            }
          if (mine)
            {
              /* addresses for HIs in my_host_identities will
               * be added later per association */
              memset(&hi->addrs.addr, 0,
                     sizeof(struct sockaddr_storage));
              if (!validate_hit(hi->hit, hi))
                {
                  log_(WARN, "HIT validate failed for "
                       "%s\n.", hi->name);
                }
            }
          else
            {
              /* get HI name */
              strcpy(name, hi->name);
              if (strrchr(name, '-'))
                {
                  name[strlen(name) -
                       strlen(strrchr(name,'-'))] = 0;
                }

              /* address(es) listed in identities file */
              if (VALID_FAM(&hi->addrs.addr))
                {
                  /* address not listed, perform DNS, then
                   * DHT lookup */
                }
              else
                {
                  if (add_addresses_from_dns(name,
                                             hi) < 0)
                    {
                      hip_dht_resolve_hi(hi, TRUE);
                    }
                }
            }
          /* link this HI into a global list */
          append_hi_node(mine ? &my_hi_head : &peer_hi_head, hi);
          print_hi_to_buff(&out_buff, &out_buff_len, hi, mine);
        }
      /*
       * add other XML tags here
       */
    }

  add_addresses_from_dns(NULL, NULL);
  xmlFreeDoc(doc);

  log_(NORM, "%s host identities:\n%s",
       mine ? "My" : "Known peer", out_buff);
  free(out_buff);

  return(0);
}


/*
 * function print_hi_to_buff()
 *
 * Print a Host Identity (Tag) into a buffer. Caller must free the buffer.
 *
 */
void print_hi_to_buff(uint8_t **bufp, int *buf_len, hi_node *hi, int mine)
{
  uint8_t *old_buff;
  char tmp[1024];
  uint8_t addr_str[INET6_ADDRSTRLEN];
  int new_size, i;
  sockaddr_list *l;

  if (!hi)
    {
      return;
    }

  hit_to_str((char *)addr_str, hi->hit);
  memset(tmp, 0, sizeof(tmp));
  i = snprintf(tmp, sizeof(tmp), " HI%s: %s %s %s\n\t",
               mine ? "" : "T", hi->name, mine ? "HIT:" : "", addr_str);

  /* LSI */
  if (VALID_FAM(&hi->lsi))
    {
      addr_to_str(SA(&hi->lsi), addr_str, INET6_ADDRSTRLEN);
      i += snprintf(&tmp[i], sizeof(tmp) - i, "LSI: %s ", addr_str);
    }

  /* address list */
  if (!mine)
    {
      i += snprintf(&tmp[i], sizeof(tmp) - i, "[");
      pthread_mutex_lock(&hi->addrs_mutex);
      for (l = &hi->addrs; l; l = l->next)
        {
          if (!VALID_FAM(SA(&l->addr)))
            {
              continue;
            }
          addr_to_str(SA(&l->addr), addr_str, INET6_ADDRSTRLEN);
          i += snprintf(&tmp[i], sizeof(tmp) - i, "%s ", addr_str);
        }
      pthread_mutex_unlock(&hi->addrs_mutex);
      i += snprintf(&tmp[i], sizeof(tmp) - i, "]");
    }
  i += snprintf(&tmp[i], sizeof(tmp) - i, "\n");

  /* grow the buffer as necessary */
  if ((*bufp == NULL) ||
      ((int)(strlen((char *)*bufp) + strlen(tmp)) > *buf_len))
    {
      old_buff = *bufp;
      new_size = *buf_len + sizeof(tmp);           /* grow by 1024 bytes */
      *bufp = malloc(new_size);
      if (!*bufp)
        {
          return;                     /* malloc error */
        }
      memset(*bufp, 0, new_size);

      if (old_buff)
        {
          memcpy(*bufp, old_buff, *buf_len);
          free(old_buff);
        }
      *buf_len = new_size;

    }
  /* add new output to the buffer */
  strncat((char *)*bufp, tmp, *buf_len);
}


/*
 * function xmlNewChild_from_bn()
 *
 * Helper to add big number hex string as a child of the given XML node.
 */
void xmlNewChild_from_bn(xmlNodePtr node, BIGNUM *bn, char *name)
{
  char *cp = BN_bn2hex(bn);
  xmlNewChild(node, NULL, BAD_CAST name, BAD_CAST cp);
  OPENSSL_free(cp);
}

/*
 * function hi_to_xml()
 *
 * Turn hi_node into XML nodes for saving. Must later free the new child nodes.
 */
int hi_to_xml(xmlNodePtr root_node, hi_node *h, int mine)
{
  char tmp[22];
  xmlNodePtr hi;
  sockaddr_list *a;
  struct sockaddr_storage ss_hit;
  struct sockaddr *hit = SA(&ss_hit);
  char addr[INET6_ADDRSTRLEN], hit_hex[INET6_ADDRSTRLEN];
  sockaddr_list *l;

  /* skip anonymous peer HITs
   */
  if (!mine && h->anonymous)
    {
      return(0);
    }
  /*
   * store everything in XML nodes
   */
  hi = xmlNewChild(root_node, NULL, BAD_CAST "host_identity", NULL);
  xmlNewProp(hi, BAD_CAST "alg", BAD_CAST HI_TYPESTR(h->algorithm_id));
  sprintf(tmp, "%d", h->algorithm_id);
  xmlNewProp(hi, BAD_CAST "alg_id", BAD_CAST tmp);

  sprintf(tmp, "%d", h->size);
  xmlNewProp(hi, BAD_CAST "length", BAD_CAST tmp);
  xmlNewProp(hi, BAD_CAST "anon", BAD_CAST (yesno(h->anonymous)));
  xmlNewProp(hi, BAD_CAST "incoming", BAD_CAST(yesno(h->allow_incoming)));
  if (h->skip_addrcheck)
    {
      xmlNewProp(hi, BAD_CAST "addrcheck", BAD_CAST("no"));
    }
  if (h->r1_gen_count > 0)
    {
      sprintf(tmp, "%llu", h->r1_gen_count);
      xmlNewProp(hi, BAD_CAST "r1count", BAD_CAST tmp);
    }
  xmlNewChild(hi, NULL, BAD_CAST "name", BAD_CAST h->name);
  for (a = &h->addrs; a; a = a->next)
    {
      if (!VALID_FAM(&a->addr))
        {
          continue;
        }
      if ((a->addr.ss_family == AF_INET) && (IN_LOOP(&a->addr)))
        {
          continue;
        }
      if ((a->addr.ss_family == AF_INET6) && (IN6_LOOP(&a->addr)))
        {
          continue;
        }
      addr_to_str(SA(&a->addr),(__u8*)addr, INET6_ADDRSTRLEN);
      xmlNewChild(hi, NULL, BAD_CAST "addr", BAD_CAST addr);
    }
  /*
   * Save the HI only if saving my_host_identities.xml.
   * note that we could save the peer's public key here if desired
   */
  if (mine)
    {
      switch (h->algorithm_id)
        {
        case HI_ALG_DSA:
          xmlNewChild_from_bn(hi, h->dsa->p, "P");
          xmlNewChild_from_bn(hi, h->dsa->q, "Q");
          xmlNewChild_from_bn(hi, h->dsa->g, "G");
          xmlNewChild_from_bn(hi, h->dsa->pub_key, "PUB");
          xmlNewChild_from_bn(hi, h->dsa->priv_key, "PRIV");
          break;
        case HI_ALG_RSA:
          xmlNewChild_from_bn(hi, h->rsa->n, "N");
          xmlNewChild_from_bn(hi, h->rsa->e, "E");
          xmlNewChild_from_bn(hi, h->rsa->d, "D");
          xmlNewChild_from_bn(hi, h->rsa->p, "P");
          xmlNewChild_from_bn(hi, h->rsa->q, "Q");
          xmlNewChild_from_bn(hi, h->rsa->dmp1, "dmp1");
          xmlNewChild_from_bn(hi, h->rsa->dmq1, "dmq1");
          xmlNewChild_from_bn(hi, h->rsa->iqmp, "iqmp");
        default:
          break;
        }
    }
  /* it would be plausible to also save the R1 cache puzzles here
   * (maybe on restart) */

  memset(hit, 0, sizeof(struct sockaddr_storage));
  hit->sa_family = AF_INET6;
  memcpy(SA2IP(hit), h->hit, HIT_SIZE);
  memset(hit_hex, 0, sizeof(hit_hex));
  addr_to_str(hit, (__u8*)hit_hex, INET6_ADDRSTRLEN);
  xmlNewChild(hi, NULL, BAD_CAST "HIT", BAD_CAST hit_hex);
  if (VALID_FAM(&h->lsi))
    {
      addr_to_str(SA(&h->lsi), (__u8*)addr, INET6_ADDRSTRLEN);
      xmlNewChild(hi, NULL, BAD_CAST "LSI", BAD_CAST addr);
    }
  for (l = *(h->rvs_addrs); l != NULL; l = l->next)
    {
      addr_to_str(SA(&l->addr), (__u8*)addr, INET6_ADDRSTRLEN);
      xmlNewChild(hi, NULL, BAD_CAST "RVS", BAD_CAST addr);
    }

#ifdef HIP_VPLS
  if (!mine)
    {
      struct sockaddr_storage hosts[MAX_LEGACY_HOSTS];
      struct sockaddr *eb_p, *host_p;
      struct sockaddr_storage eb_ss;
      eb_p = (struct sockaddr*)&eb_ss;
      char host_s[64];
      int rc, i;

      eb_p->sa_family = AF_INET6;
      inet_pton(AF_INET6, hit_hex, SA2IP(eb_p));
      rc = hipcfg_getLegacyNodesByEndbox(eb_p,
                                         hosts,
                                         MAX_LEGACY_HOSTS);
      if (rc > 0)
        {
          for (i = 0; i < rc; i++)
            {
              host_p = (struct sockaddr *)&hosts[i];
              inet_ntop(host_p->sa_family, SA2IP(
                          host_p), host_s,
                        sizeof(host_s));
              xmlNewChild(hi,
                          NULL,
                          BAD_CAST "legacyNodesIp",
                          BAD_CAST host_s);
            }
        }
      else
        {
          log_(
            WARN,
            "hi_to_xml: Error call hipcfg_getLegacyNodesByEndbox while saving identities - HIT %s\n",
            hit_hex);
        }
    }
#endif
  return(0);
}

/*
 * function save_identities_file()
 *
 * Save my Host Identities back to XML - needed for storing R1 counter
 * Note that all comments and manual editing will be lost!
 */

int save_identities_file(int mine)
{
  char filename[255];
  xmlDocPtr doc = NULL;
  xmlNodePtr root_node = NULL, comment;
  hi_node *hi;
  int count = 0;

  for (hi = mine ? my_hi_head : peer_hi_head; hi; hi = hi->next)
    {
      count++;
    }
  if (count == 0)         /* no identities to save */
    {
      return(0);
    }

  /* create a new file */
  doc = xmlNewDoc(BAD_CAST "1.0");
  snprintf(filename, sizeof(filename), "%s",
           mine ? HCNF.my_hi_filename : HCNF.known_hi_filename);
  root_node = xmlNewNode(NULL, mine ? BAD_CAST "my_host_identities" :
                         BAD_CAST "known_host_identities");
  comment = xmlNewComment(
    BAD_CAST "This file has been saved by the HIP "
    "daemon. User edits may be lost\n    when the HIP "
    "daemon terminates. Comments are not preserved. ");
  xmlDocSetRootElement(doc, comment);
  xmlAddSibling(comment, root_node);

  /* convert all HIs to XML, adding them to the root node */
  hi = mine ? my_hi_head : peer_hi_head;
  while (hi)
    {
      if (hi_to_xml(root_node, hi, mine) < 0)
        {
          log_(WARN, "Error converting HI %s to XML.\n",
               hi->name);
          continue;
        }
      hi = hi->next;
    }
#ifdef HIP_VPLS
  /* XXX TODO: clean this up! */
  hip_hit hits1[MAX_HI_NAMESIZE], hits2[MAX_HI_NAMESIZE];
  int rc, i;
  xmlNodePtr np;
  char hit_hex[INET6_ADDRSTRLEN];
  rc = hipcfg_peers_allowed(hits1, hits2, MAX_HI_NAMESIZE);
  if (rc < 0)
    {
      log_(WARN, "hi_to_xml: Error calling hipcfg_peers_allowed");
    }
  else
    {
      for (i = 0; i < rc; i++)
        {
          np = xmlNewChild(root_node,
                           NULL,
                           BAD_CAST "peer_allowed",
                           NULL);
          hit_to_str(hit_hex, hits1[i]);
          xmlNewChild(np, NULL, BAD_CAST "hit1", BAD_CAST hit_hex);
          hit_to_str(hit_hex, hits2[i]);
          xmlNewChild(np, NULL, BAD_CAST "hit2", BAD_CAST hit_hex);
        }
    }
#endif
  log_(NORM, "Storing %s Host Identities to file '%s'.\n",
       mine ? "my" : "peer", filename);
  xmlSaveFormatFileEnc(filename, doc, "UTF-8", 1);
  xmlFreeDoc(doc);

  return(0);
}

/*
 * function read_conf_file()
 *
 * Load configuration options from the XML file
 * stored in hip.conf
 *
 */
int read_conf_file(char *filename)
{
  xmlDocPtr doc = NULL;
  xmlNodePtr node = NULL, child = NULL;
  char *data, *data2;
  int t, tmp, done;
  struct sockaddr *addr;
  __u16 *trns;

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
          /* common case - empty node */
        }
      else if (strcmp((char *)node->name, "comment") == 0)
        {
          /* silently ignore XML comments */
        }
      else if (strcmp((char *)node->name,
                      "cookie_difficulty") == 0)
        {
          sscanf(data, "%d", &HCNF.cookie_difficulty);
        }
      else if (strcmp((char *)node->name,
                      "cookie_lifetime") == 0)
        {
          sscanf(data, "%d", &HCNF.cookie_lifetime);
        }
      else if (strcmp((char *)node->name, "packet_timeout") == 0)
        {
          sscanf(data, "%d", &HCNF.packet_timeout);
        }
      else if (strcmp((char *)node->name, "max_retries") == 0)
        {
          sscanf(data, "%d", &HCNF.max_retries);
        }
      else if (strcmp((char *)node->name, "sa_lifetime") == 0)
        {
          sscanf(data, "%d", &HCNF.sa_lifetime);
        }
      else if (strcmp((char *)node->name, "loc_lifetime") == 0)
        {
          sscanf(data, "%d", &HCNF.loc_lifetime);
        }
      else if (strcmp((char *)node->name, "preferred_hi") == 0)
        {
          HCNF.preferred_hi = (char *)malloc(MAX_HI_NAMESIZE);
          strncpy(HCNF.preferred_hi, data, MAX_HI_NAMESIZE);
        }
      else if (strcmp((char *)node->name, "send_hi_name") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.send_hi_name = TRUE;
            }
          else
            {
              HCNF.send_hi_name = FALSE;
            }
        }
      else if (strcmp((char *)node->name, "dh_group") == 0)
        {
          sscanf(data, "%d", &tmp);
          HCNF.dh_group = (__u8)tmp;
#ifdef HIP_VPLS
        }
      else if (strcmp((char *)node->name,
                      "master_interface") == 0)
        {
          HCNF.master_interface = strdup(data);
        }
      else if (strcmp((char *)node->name,
                      "master_interface2") == 0)
        {
          HCNF.master_interface2 = strdup(data);
        }
      else if (strcmp((char *)node->name,
                      "endbox_hello_time") == 0)
        {
          sscanf(data, "%d", &HCNF.endbox_hello_time);
        }
      else if (strcmp((char *)node->name, "endbox_allow_core_dump") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.endbox_allow_core_dump = TRUE;
            }
          else
            {
              HCNF.endbox_allow_core_dump = FALSE;
            }
#endif
        }
      else if (strcmp((char *)node->name, "dh_lifetime") == 0)
        {
          sscanf(data, "%d", &HCNF.dh_lifetime);
        }
      else if (strcmp((char *)node->name, "r1_lifetime") == 0)
        {
          sscanf(data, "%d", &HCNF.r1_lifetime);
        }
      else if (strcmp((char *)node->name,
                      "failure_timeout") == 0)
        {
          sscanf(data, "%d", &HCNF.failure_timeout);
        }
      else if (strcmp((char *)node->name, "msl") == 0)
        {
          sscanf(data, "%d", &HCNF.msl);
        }
      else if (strcmp((char *)node->name, "ual") == 0)
        {
          sscanf(data, "%d", &HCNF.ual);
        }
      else if ((strcmp((char *)node->name, "hip_sa") == 0) ||
               (strcmp((char *)node->name, "esp_sa") == 0))
        {
          if (node->name[0] == 'e')
            {
              trns = HCNF.esp_transforms;
            }
          else
            {
              trns = HCNF.hip_transforms;
            }
          /* advance to child of <transforms> if it exists */
          done = FALSE;
          for (child = node->children; child && !done;
               child = child->next)
            {
              if (strcmp((char *)child->name,
                         "transforms") == 0)
                {
                  child = child->children;
                  done = TRUE;
                }
            }
          /* search child for <id> and store into HCNF global
           * t is the number of transforms we've found */
          memset(trns, 0, sizeof(__u16) * SUITE_ID_MAX);
          for (t = 0; child && (t < SUITE_ID_MAX);
               child = child->next)
            {
              data2 = (char*) xmlNodeGetContent(child);
              if (strcmp((char *)child->name, "id") == 0)
                {
                  sscanf(data2, "%d", &tmp);
                  trns[t] = (__u16)tmp;
                  t++;
                }                 /* end if <id> */
              xmlFree(data2);
            }             /* end for */
        }
      else if (strcmp((char *)node->name, "dht_server") == 0)
        {
          addr = (struct sockaddr*)&HCNF.dht_server;
          memset(addr, 0, sizeof(struct sockaddr_storage));
          addr->sa_family = ((strchr(data, ':') == NULL) ?
                             AF_INET : AF_INET6);
          if (str_to_addr((__u8*)data, addr) <= 0)
            {
              log_(WARN, "Invalid DHT server Address '%s'\n",
                   data);
            }
        }
      else if (strcmp((char *)node->name,
                      "dht_server_port") == 0)
        {
          sscanf(data, "%d", &tmp);
          addr = (struct sockaddr*)&HCNF.dht_server;
          if (addr->sa_family == AF_INET6)
            {
              ((struct sockaddr_in6*)addr)->sin6_port =
                htons((__u16)tmp);
            }
          else                 /* if no DHT address yet, default to IPv4 */
            {
              ((struct sockaddr_in*)addr)->sin_port =
                htons((__u16)tmp);
            }
        }
      else if (strcmp((char *)node->name, "dns_server") == 0)
        {
          addr = (struct sockaddr*)&HCNF.dns_server;
          memset(addr, 0, sizeof(struct sockaddr_storage));
          addr->sa_family = ((strchr(data, ':') == NULL) ?
                             AF_INET : AF_INET6);
          if (str_to_addr((__u8*)data, addr) <= 0)
            {
              log_(WARN, "Invalid DNS server Address '%s'\n",
                   data);
            }
        }
      else if (strcmp((char *)node->name,
                      "disable_dns_lookups") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.disable_dns_lookups = TRUE;
            }
          else
            {
              HCNF.disable_dns_lookups = FALSE;
            }
        }
      else if (strcmp((char *)node->name, "disable_notify") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.disable_notify = TRUE;
            }
          else
            {
              HCNF.disable_notify = FALSE;
            }
        }
      else if (strcmp((char *)node->name,
                      "disable_dns_thread") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.disable_dns_thread = TRUE;
            }
          else
            {
              HCNF.disable_dns_thread = FALSE;
            }
        }
      else if (strcmp((char *)node->name,
                      "enable_broadcast") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.enable_bcast = TRUE;
            }
          else
            {
              HCNF.enable_bcast = FALSE;
            }
        }
      else if (strcmp((char *)node->name,
                      "disable_udp") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.disable_udp = TRUE;
            }
          else
            {
              HCNF.disable_udp = FALSE;
            }
        }
      else if (strcmp((char *)node->name,
                      "min_reg_lifetime") == 0)
        {
          /* real_min_lifetime (sec) = 2^((min_lifetime-64)/8) */
          sscanf(data, "%d", &tmp);
          HCNF.min_reg_lifetime = (__u8)tmp;
        }
      else if (strcmp((char *)node->name,
                      "max_reg_lifetime") == 0)
        {
          /* real_max_lifetime (sec) = 2^((max_lifetime-64)/8) */
          sscanf(data, "%d", &tmp);
          HCNF.max_reg_lifetime = (__u8)tmp;
        }
      else if (strcmp((char*)node->name, "preferred") == 0)
        {
          addr = (struct sockaddr*)&HCNF.preferred;
          memset(addr, 0, sizeof(struct sockaddr_storage));
          addr->sa_family = ((strchr(data, ':') == NULL) ?
                             AF_INET : AF_INET6);
          if (str_to_addr((__u8*)data, addr) <= 0)
            {
              log_(WARN, "Invalid preferred address '%s'\n",
                   data);
            }
        }
      else if (strcmp((char*)node->name, "ignored_addr") == 0)
        {
          addr = (struct sockaddr*)&HCNF.ignored_addr;
          memset(addr, 0, sizeof(struct sockaddr_storage));
          addr->sa_family = ((strchr(data, ':') == NULL) ?
                             AF_INET : AF_INET6);
          if (str_to_addr((__u8*)data, addr) <= 0)
            {
              log_(WARN, "Invalid ignored address '%s'\n",
                   data);
            }
        }
      else if (strcmp((char*)node->name,
                      "preferred_interface") == 0)
        {
          HCNF.preferred_iface = malloc(strlen(data) + 1);
          if (!HCNF.preferred_iface)
            {
              log_(WARN, "Warning: preferred_iface malloc "
                   "error!\n");
            }
          else
            {
              strcpy(HCNF.preferred_iface, data);
            }
        }
      else if (strcmp((char*)node->name,
                      "outbound_interface") == 0)
        {
          struct name *temp = malloc(sizeof(struct name));
          if (!temp)
            {
              log_(WARN, "Warning: outbound_iface malloc "
                   "error!\n");
            }
          else
            {
              temp->name = malloc(strlen(data) + 1);
              if (!temp->name)
                {
                  log_(WARN, "Warning: outbound_iface "
                       "malloc error!\n");
                  free(temp);
                }
              else                       /* Should we check for duplicates? */
                {
                  strcpy(temp->name, data);
                  temp->next = HCNF.outbound_ifaces;
                  HCNF.outbound_ifaces = temp;
                }
            }
        }
      else if (strcmp((char*)node->name,
                      "save_known_identities") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.save_known_identities = TRUE;
            }
          else
            {
              HCNF.save_known_identities = FALSE;
            }
        }
      else if (strcmp((char*)node->name,
                      "save_my_identities") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.save_my_identities = TRUE;
            }
          else
            {
              HCNF.save_my_identities = FALSE;
            }
        }
      else if (strcmp((char*)node->name,
                      "peer_certificate_required") == 0)
        {
          if (strncmp(data, "yes", 3) == 0)
            {
              HCNF.peer_certificate_required = TRUE;
            }
          else
            {
              HCNF.peer_certificate_required = FALSE;
            }
#ifdef HIP_VPLS
        }
      /* Example: /usr/local/lib/libhipcfgldap.so */
      else if (strcmp((char*)node->name, "cfg_library") == 0)
        {
          HCNF.cfg_library = malloc(strlen(data) + 1);
          if (!HCNF.cfg_library)
            {
              log_(
                WARN,
                "Warning: HCNF.cfg_library malloc "
                "error!\n");
            }
          else
            {
              strcpy(HCNF.cfg_library, data);
            }
#endif
        }
      else if (strlen((char *)node->name))
        {
          log_(WARN,
               "Warning: unknown configuration option '%s' "
               "was ignored.\n",
               node->name);
        }
      xmlFree(data);
    }

  xmlFreeDoc(doc);
  return(0);
}

