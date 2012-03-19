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
 *  \file  hitgen.c
 *
 *  \authors	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *              Tom Henderson <thomas.r.henderson@boeing.com>
 *
 *  \brief  Generates DSA and RSA Host Identities and HIP configuration files.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <libxml/encoding.h>
#include <libxml/xmlIO.h>
#include <libxml/tree.h>
#include <sys/stat.h>
#include <errno.h>
#ifndef __WIN32__
#include <unistd.h>
#include <sys/wait.h>           /* wait_pid()                   */
#include <sys/time.h>           /* gettimeofday()		*/
#else
#include <io.h>                 /* access()                     */
#include <winsock2.h>
#include <ws2tcpip.h>           /* INET6_ADDRSTRLEN		*/
#endif
#include <hip/hip_version.h>
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_globals.h>

/* dummy globals to fix undefined variables when building */
int g_state;
int netlsp[2];

#ifdef __WIN32__
#define access _access
#define F_OK 0x00  /* test for file existence only */
#endif

/*
 * These are the default bit sizes to generate.
 */
int default_sizes[] = { 1024 };

/* seed is taken from the updated Appendix 5 to
 * FIPS PUB 186 and also appears in Appendix 5 to FIPS PIB 186-1 */
static unsigned char seed[20] = {
  0xd5,0x01,0x4e,0x4b,0x60,0xef,0x2b,0xa8,0xb6,0x21,0x1b,0x40,
  0x62,0xba,0x32,0x24,0xe0,0x42,0x7d,0xd3,
};

/* this struct is used only for passing options to generate_HI */
typedef struct _hi_options {
  int type;
  int bitsize;
  char anon;
  char incoming;
  __u64 r1count;
  char *name;
} hi_options;

extern struct hip_opt OPT;

int generate_HI(xmlNodePtr root_node, hi_options *opts)
{
  int err;
  char tmp[22], hit_hex[INET6_ADDRSTRLEN], lsi_str[INET_ADDRSTRLEN];
  unsigned char *hitp;
  struct sockaddr_storage hit;
  struct sockaddr_in lsi;
  xmlNodePtr hi;
  unsigned long e;
  hi_node hostid;

  /* Crypto stuff */
  BIO *bp;
  DSA *dsa = NULL;
  RSA *rsa = NULL;

  printf("Generating a %d-bit %s key\n",
         opts->bitsize, HI_TYPESTR(opts->type));
  if (opts->bitsize < 512)
    {
      printf("Error: bit size too small. ");
      printf("512 bits is the minimum size\n");
      return(-1);
    }
  else if (opts->bitsize % 64)
    {
      printf("Error: the bit size must be a mupltiple of 64.\n");
      return(-1);
    }

  /*
   * generate the HI
   */
  printf("Generating %s keys for HI...", HI_TYPESTR(opts->type));
  switch (opts->type)
    {
    case HI_ALG_DSA:
      printf("Generating DSA parameters (p,q,g)...");
      dsa = DSA_generate_parameters(opts->bitsize, seed, sizeof(seed),
                                    NULL, NULL, cb, stdout);
      printf("\n");
      if (dsa == NULL)
        {
          fprintf(stderr, "DSA_generate_parameters failed\n");
          exit(1);
        }
      printf("Generating DSA keys for HI...");
      err = DSA_generate_key(dsa);
      if (err < 0)
        {
          fprintf(stderr, "DSA_generate_key() failed.\n");
          exit(1);
        }
      break;
    case HI_ALG_RSA:
      e = HIP_RSA_DFT_EXP;
      rsa = RSA_generate_key(opts->bitsize, e, cb, stdout);
      if (!rsa)
        {
          fprintf(stderr, "RSA_generate_key() failed.\n");
          exit(1);
        }
      break;
    default:
      printf("Error: generate_HI() got invalid HI type\n");
      exit(1);
      break;
    }

  /*
   * store everything in XML nodes
   */
  hi = xmlNewChild(root_node, NULL, BAD_CAST "host_identity", NULL);
  xmlNewProp(hi, BAD_CAST "alg", BAD_CAST HI_TYPESTR(opts->type));
  sprintf(tmp, "%d", opts->type);
  xmlNewProp(hi, BAD_CAST "alg_id", BAD_CAST tmp);
  sprintf(tmp, "%d", opts->bitsize / 8);
  xmlNewProp(hi, BAD_CAST "length", BAD_CAST tmp);
  xmlNewProp(hi, BAD_CAST "anon", BAD_CAST (yesno(opts->anon)));
  xmlNewProp(hi, BAD_CAST "incoming", BAD_CAST (yesno(opts->incoming)));
  if (opts->r1count > 0)
    {
      sprintf(tmp, "%llu", opts->r1count);
      xmlNewProp(hi, BAD_CAST "r1count", BAD_CAST tmp);
    }
  xmlNewChild(hi, NULL, BAD_CAST "name", BAD_CAST opts->name);

  switch (opts->type)
    {
    case HI_ALG_DSA:
      xmlNewChild(hi, NULL, BAD_CAST "P", BAD_CAST BN_bn2hex(dsa->p));
      xmlNewChild(hi, NULL, BAD_CAST "Q", BAD_CAST BN_bn2hex(dsa->q));
      xmlNewChild(hi, NULL, BAD_CAST "G", BAD_CAST BN_bn2hex(dsa->g));
      xmlNewChild(hi, NULL, BAD_CAST "PUB",
                  BAD_CAST BN_bn2hex(dsa->pub_key));
      xmlNewChild(hi, NULL,BAD_CAST "PRIV",
                  BAD_CAST BN_bn2hex(dsa->priv_key));
      break;
    case HI_ALG_RSA:
      xmlNewChild(hi, NULL, BAD_CAST "N", BAD_CAST BN_bn2hex(rsa->n));
      xmlNewChild(hi, NULL, BAD_CAST "E", BAD_CAST BN_bn2hex(rsa->e));
      xmlNewChild(hi, NULL, BAD_CAST "D", BAD_CAST BN_bn2hex(rsa->d));
      xmlNewChild(hi, NULL, BAD_CAST "P", BAD_CAST BN_bn2hex(rsa->p));
      xmlNewChild(hi, NULL, BAD_CAST "Q", BAD_CAST BN_bn2hex(rsa->q));
      xmlNewChild(hi, NULL, BAD_CAST "dmp1",
                  BAD_CAST BN_bn2hex(rsa->dmp1));
      xmlNewChild(hi, NULL, BAD_CAST "dmq1",
                  BAD_CAST BN_bn2hex(rsa->dmq1));
      xmlNewChild(hi, NULL, BAD_CAST "iqmp",
                  BAD_CAST BN_bn2hex(rsa->iqmp));
      break;
    default:
      break;
    }

  /*
   * calculate and store the HIT
   */
  memset(&hostid, 0, sizeof(hi_node));
  memset(&hit, 0, sizeof(struct sockaddr_storage));
  memset(hit_hex, 0, INET6_ADDRSTRLEN);

  hostid.algorithm_id = opts->type;
  hostid.size = (opts->bitsize) / 8;
  hostid.rsa = rsa;
  hostid.dsa = dsa;

  hit.ss_family = AF_INET6;
  hitp = SA2IP(&hit);
  if (hi_to_hit(&hostid, hitp) < 0)
    {
      printf("Error generating HIT!\n");
      exit(1);
    }

  if (addr_to_str(SA(&hit), (__u8*)hit_hex, INET6_ADDRSTRLEN))
    {
      printf("Error generating HIT! Do you have the IPv6 protocol "
             "installed?\n");
      exit(1);
    }
  xmlNewChild(hi, NULL, BAD_CAST "HIT", BAD_CAST hit_hex);

  /*
   * calculate the LSI from the HIT
   */
  memset(&lsi, 0, sizeof(struct sockaddr_in));
  memset(lsi_str, 0, INET_ADDRSTRLEN);
  lsi.sin_family = AF_INET;
  lsi.sin_addr.s_addr = ntohl(HIT2LSI(hitp));
  if (addr_to_str(SA(&lsi), (__u8*)lsi_str, INET_ADDRSTRLEN))
    {
      printf("Error generating LSI from HIT!\n");
    }
  xmlNewChild(hi, NULL, BAD_CAST "LSI", BAD_CAST lsi_str);

  if (D_VERBOSE == OPT.debug)
    {
      bp = BIO_new_fp(stdout, BIO_NOCLOSE);
      if (dsa)
        {
          DSAparams_print(bp, dsa);
        }
      if (rsa)
        {
          RSA_print(bp, rsa, 0);
        }
      BIO_free(bp);
    }

  return(0);
}

/*
 * Delete whitespace from an XML document, which is necessary if you
 * want the document to be reformatted after reading it from a file.
 *
 * from:
 * http://mail.gnome.org/archives/gnome-devel-list/2003-May/msg00067.html
 *
 */
static void
delete_unused_whitespace_r(xmlNodePtr node)
{
  xmlNodePtr next;

  for (node = node->xmlChildrenNode; node; node = next)
    {
      next = node->next;
      if (xmlIsBlankNode(node))
        {
          xmlUnlinkNode(node);
          xmlFreeNode(node);
        }
      else
        {
          delete_unused_whitespace_r(node);
        }
    }
}

static void
delete_unused_whitespace(xmlDocPtr doc)
{
  delete_unused_whitespace_r(xmlDocGetRootElement(doc));
}

void publish_hits(char *out_filename)
{
  char filename[255];
  xmlChar *data;
  xmlDocPtr doc = NULL, doc_myids = NULL;
  xmlNodePtr root_node, node, hi, child;
  xmlAttrPtr attr;
  int out_filename_exists = 0;

  sprintf(filename, "%s/%s", SYSCONFDIR, HIP_MYID_FILENAME);
  doc_myids = xmlParseFile(filename);
  if (doc_myids == NULL)
    {
      fprintf(stderr, "Error parsing xml file (%s)\n", filename);
      return;
    }

  printf("Saving HITs to '%s'...\n", out_filename);
  /*
   * The below check for file existence will remove the
   * "I/O warning : failed to load external entity ..." messages
   */
  if (!access(out_filename, F_OK))
    {
      out_filename_exists = 1;
      doc = xmlParseFile(out_filename);
    }
  /* append to existing file */
  if (out_filename_exists && doc)
    {
      printf("Note: the file %s already exists, your ", out_filename);
      printf("HITs will be appended to the end.\n");
      delete_unused_whitespace(doc);
      root_node = xmlDocGetRootElement(doc);
      xmlDocSetRootElement(doc, root_node);
      /* create a new file */
    }
  else
    {
      doc = xmlNewDoc(BAD_CAST "1.0");
      node = xmlNewComment(
        BAD_CAST "The following HITs can be "
        "copied into a " HIP_KNOWNID_FILENAME
        " file.");
      xmlDocSetRootElement(doc, node);
      root_node = xmlNewNode(NULL, BAD_CAST "known_host_identities");
      xmlAddSibling(node, root_node);
    }

  node = xmlDocGetRootElement(doc_myids);
  for (node = node->children; node; node = node->next)
    {
      if (strcmp((char *)node->name, "host_identity") != 0)
        {
          continue;
        }
      hi = xmlNewChild(root_node,NULL,BAD_CAST "host_identity", NULL);
      /* copy attributes */
      for (attr = node->properties; attr; attr = attr->next)
        {
          if ((attr->type == XML_ATTRIBUTE_NODE) &&
              (attr->children) &&
              (attr->children->type == XML_TEXT_NODE))
            {
              data = attr->children->content;
            }
          else                 /* no attribute value */
            {
              continue;
            }
          /* save recognized attributes */
          if ((strcmp((char *)attr->name, "alg") == 0) ||
              (strcmp((char *)attr->name, "alg_id") == 0) ||
              (strcmp((char *)attr->name, "anon") == 0) ||
              (strcmp((char *)attr->name, "incoming") == 0) ||
              (strcmp((char *)attr->name, "length") == 0))
            {
              xmlNewProp(hi, BAD_CAST attr->name,
                         BAD_CAST data);
            }
        }
      /* copy the children nodes that we wish to publish */
      for (child = node->children; child; child = child->next)
        {
          if (strcmp((char *)child->name, "text") == 0)
            {
              continue;
            }
          if ((strcmp((char *)child->name, "name") != 0) &&
              (strcmp((char *)child->name, "HIT") != 0) &&
              (strcmp((char *)child->name, "LSI") != 0) &&
              (strcmp((char *)child->name, "addr") != 0))
            {
              continue;
            }
          data = xmlNodeGetContent(child);
          xmlNewChild(hi, NULL, BAD_CAST child->name,
                      BAD_CAST data);
          xmlFree(data);
        }
    }

  xmlSaveFormatFileEnc(out_filename, doc, "UTF-8", 1);
  xmlFreeDoc(doc);

}

void generate_conf_file(char *filename)
{
  xmlDocPtr doc = NULL;
  xmlNodePtr root_node, node;
  doc = xmlNewDoc(BAD_CAST "1.0");

  printf("Saving default configuration to '%s'...\n", filename);

  root_node = xmlNewNode(NULL, BAD_CAST "hip_configuration");
  xmlDocSetRootElement(doc, root_node);
  xmlNewDocComment(doc, BAD_CAST "HIP Configuration File");

  xmlNewChild(root_node, NULL, BAD_CAST "cookie_difficulty",BAD_CAST "10");
  xmlNewChild(root_node, NULL, BAD_CAST "packet_timeout", BAD_CAST "10");
  xmlNewChild(root_node, NULL, BAD_CAST "max_retries", BAD_CAST "5");
  xmlNewChild(root_node, NULL, BAD_CAST "sa_lifetime", BAD_CAST "900");
  xmlNewChild(root_node, NULL, BAD_CAST "send_hi_name", BAD_CAST "yes");
  xmlNewChild(root_node, NULL, BAD_CAST "dh_group", BAD_CAST "3");
  xmlNewChild(root_node, NULL, BAD_CAST "dh_lifetime", BAD_CAST "900");
  xmlNewChild(root_node, NULL, BAD_CAST "r1_lifetime", BAD_CAST "300");
  xmlNewChild(root_node, NULL, BAD_CAST "failure_timeout", BAD_CAST "50");
  xmlNewChild(root_node, NULL, BAD_CAST "msl", BAD_CAST "5");
  xmlNewChild(root_node, NULL, BAD_CAST "ual", BAD_CAST "600");
  xmlNewChild(root_node, NULL, BAD_CAST "min_reg_lifetime",BAD_CAST "96");
  xmlNewChild(root_node, NULL,BAD_CAST "max_reg_lifetime",BAD_CAST "255");
  node = xmlNewChild(root_node, NULL, BAD_CAST "hip_sa", NULL);
  node = xmlNewChild(node, NULL, BAD_CAST "transforms", NULL);
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "1");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "2");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "3");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "4");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "5");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "6");
  node = xmlNewChild(root_node, NULL, BAD_CAST "esp_sa", NULL);
  node = xmlNewChild(node, NULL, BAD_CAST "transforms", NULL);
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "1");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "2");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "3");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "4");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "5");
  xmlNewChild(node, NULL, BAD_CAST "id", BAD_CAST "6");
  xmlNewChild(root_node, NULL, BAD_CAST "disable_dns_lookups",
              BAD_CAST "no");
  xmlNewChild(root_node, NULL, BAD_CAST "save_known_identities",
              BAD_CAST "no");
  xmlNewChild(root_node, NULL, BAD_CAST "disable_notify", BAD_CAST "no");
  xmlNewChild(root_node, NULL, BAD_CAST "disable_dns_thread",
              BAD_CAST "yes");
  xmlNewChild(root_node, NULL, BAD_CAST "enable_broadcast",BAD_CAST "no");
  xmlNewChild(root_node, NULL, BAD_CAST "disable_udp",
#ifdef __MACOSX__
              BAD_CAST "yes");
#else
              BAD_CAST "no");
#endif
  xmlSaveFormatFileEnc(filename, doc, "UTF-8", 1);
  xmlFreeDoc(doc);
}

void print_hitgen_usage()
{
  int i;
  printf("usage: hitgen ");
  printf("\t[-v] ");
  printf("[-name <string>] ");
  printf("[-noinput] ");
  printf("[-file <file>] ");
  printf("[-append]\n");
  printf("\t\t[-type DSA|RSA] ");
  printf("[-bits|length <NN>] ");
  printf("[-anon] ");
  printf("[-incoming]\n");
  printf("\t\t[-publish] ");
  printf("[-conf]\n");
  printf("Generate host identities (public/private key pairs) for use"
         " with OpenHIP.\n");
  printf("General options:\n");
  printf(" -v \t\t show verbose debugging information\n");
  printf(" -name <string>\t is the human-readable handle for the HI\n");
  printf(" -noinput \t don't ask to seed random number generator\n");
  printf(" -file <file> \t write output to the specified file\n");
  printf(" -append\t append identity if file already exists\n");
  printf("Host identitiy generation:\n");
  printf(" -type \tfollowed by \"DSA\" or \"RSA\" specifies key type\n");
  printf(" -bits \t\t specifies the length in bits for (P,G,Y)\n");
  printf(" -length \t specifies the length in bytes for (P,G,Y)\n");
  printf(" -anon \t\t sets the anonymous flag for this HI\n");
  printf(" -incoming \t unsets the allow incoming flag for this HI\n");
  printf("Other operating modes:\n");
  printf(" -publish \t extract HITs from the existing '%s'\n",
         HIP_MYID_FILENAME);
  printf("\t\t file and create a file named ");
  printf("'hostname_host_identities.pub.xml'\n");
  printf(
    " -conf \t\t generates a default '%s' file (overwrites existing)"
    "\n",
    HIP_CONF_FILENAME);
  printf("Configuration files are stored in '%s'.\n", SYSCONFDIR);
  printf("By default, identities are generated and written to '%s'\n",
         HIP_MYID_FILENAME);
  printf("with the string of 'default', the anonymous flag set to false");
  printf(", allow \nincoming set to true, for each of the default ");
  printf("lengths (");
  for (i = 0; i < (sizeof(default_sizes) / sizeof(int)); i++)
    {
      printf("%d ", default_sizes[i]);
    }
  printf("bits).\n\n");
}

/*
 * main()
 *
 * opens hip.conf file and calls generate_HI()
 *
 */
int main(int argc, char *argv[])
{
  char name[255], basename[255], filename[255];
  char rnd_seed[255];
  int i, have_filename = 0, do_publish = 0, do_conf = 0, do_noinput = 0;
  int do_append = 0;
  hi_options opts;
  xmlDocPtr doc = NULL;
  xmlNodePtr root_node = NULL;
  int my_filename_exists = 0;

#ifndef __WIN32__
  struct stat stbuf;

  snprintf(filename, sizeof(filename), "%s", SYSCONFDIR);
  if (stat(filename, &stbuf) < 0)
    {
      mkdir(filename, 755);
    }
#else
  WORD wVer = MAKEWORD( 2, 2);
  WSADATA wsaData;
  HMODULE hLib = LoadLibrary("ADVAPI32.DLL");
  BOOLEAN (APIENTRY *pfn)(void*,
                          ULONG) =
    (BOOLEAN (APIENTRY*)(void*,ULONG))GetProcAddress(
      hLib,
      "SystemFunction036");

  WSAStartup(wVer, &wsaData);
#endif /* __WIN32__ */

  /*
   * Set default values
   */
  if (gethostname(basename, 255) < 0)
    {
      sprintf(basename, "default");
    }
  sprintf(filename, "%s/%s", SYSCONFDIR, HIP_MYID_FILENAME);
  OPT.debug = D_DEFAULT;

  opts.type = 0;
  opts.bitsize = 0;
  opts.anon = 0;
  opts.incoming = 1;
  opts.r1count = 10;
  opts.name = name;

  /*
   * Command-line parameters
   */
  argv++, argc--;
  while (argc > 0)
    {
      if (strcmp(*argv, "-v") == 0)
        {
          OPT.debug = D_VERBOSE;
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-name") == 0)
        {
          argv++, argc--;
          strncpy(basename, *argv, sizeof(basename));
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-type") == 0)
        {
          argv++, argc--;
          if (strcmp(*argv, "DSA") == 0)
            {
              opts.type = HI_ALG_DSA;
            }
          else if (strcmp(*argv, "RSA") == 0)
            {
              opts.type = HI_ALG_RSA;
            }
          else
            {
              printf("Invalid HI type.\n");
            }
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-bits") == 0)
        {
          argv++, argc--;
          sscanf(*argv, "%d", &opts.bitsize);
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-length") == 0)
        {
          int length;
          argv++, argc--;
          sscanf(*argv, "%d", &length);
          opts.bitsize = length * 8;
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-anon") == 0)
        {
          argv++, argc--;
          opts.anon = 1;
          continue;
        }
      else if (strcmp(*argv, "-incoming") == 0)
        {
          argv++, argc--;
          opts.incoming = 0;
          continue;
        }
      else if (strcmp(*argv, "-r1count") == 0)
        {
          argv++, argc--;
          sscanf(*argv, "%llu", &opts.r1count);
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-file") == 0)
        {
          argv++, argc--;
          sprintf(filename, "%s", *argv);
          have_filename = 1;
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-publish") == 0)
        {
          do_publish = 1;
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-conf") == 0)
        {
          do_conf = 1;
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-noinput") == 0)
        {
          do_noinput = 1;
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-append") == 0)
        {
          do_append = 1;
          argv++, argc--;
          continue;
        }
      print_hitgen_usage();
      exit(1);

    }

  /* Non-interactive modes */
  if (do_publish)
    {
      if (!have_filename)
        {
          sprintf(filename, "%s%s%s", HIP_PUB_PREFIX, basename,
                  HIP_PUB_SUFFIX);
        }
      publish_hits(filename);
      exit(0);
    }
  else if (do_conf)
    {
      if (!have_filename)
        {
          sprintf(filename, "%s", HIP_CONF_FILENAME);
        }
      generate_conf_file(filename);
      exit(0);
    }

  /* Interactive mode */
  printf("\nhitgen v%s\n\n", HIP_VERSION);
  printf("This utility will generate host identities for this machine."
         "\n\n");
  /*
   * The below check for file existence will remove the
   * "I/O warning : failed to load external entity ..." messages
   */
  if (!access(filename, F_OK))
    {
      if (!do_append)
        {
          printf("The file %s already exists. Use the -append "
                 "option to add identities to it.\n", filename);
          exit(0);
        }
      my_filename_exists = 1;
      doc = xmlParseFile(filename);
    }
  /* append to existing file */
  if (my_filename_exists && doc)
    {
      printf("The file %s already exists, will append.\n",
             filename);
      delete_unused_whitespace(doc);
      root_node = xmlDocGetRootElement(doc);
      xmlDocSetRootElement(doc, root_node);
      /* create a new file */
    }
  else
    {
      printf("The file %s does not exist; creating new file...\n",
             filename);
      doc = xmlNewDoc(BAD_CAST "1.0");
      root_node = xmlNewNode(NULL, BAD_CAST "my_host_identities");
      xmlDocSetRootElement(doc, root_node);
    }

  /* DTD support */
  /* dtd = xmlCreateIntSubset(doc,BAD_CAST "root",NULL,BAD_CAST "x.dtd");
   */
  /* xmlNewChild(parent, NsPtr ns, name, content) */
  /* */
  if (do_noinput)
    {
#ifdef __WIN32__
      if (hLib)
        {
          printf("\nUsing SystemFunction036 to seed the random "
                 "number generator.\n");
          pfn(rnd_seed, sizeof rnd_seed);
        }
      else
        {
          printf("\nUsing screen data to seed the random number "
                 "generator.\n");
          /* versions of Windows wihout SystemFunction036 */
          RAND_screen();
        }
#else
      FILE *f = fopen("/dev/urandom", "r");
      if (f)
        {
          printf(
            "\nUsing /dev/urandom to seed the random number "
            "generator.\n");
          if (fread(rnd_seed, sizeof(rnd_seed), 1, f) != 1)
            {
              printf("Warning: error reading /dev/urandom\n");
            }
          fclose(f);
        }
      else
        {
          printf(
            "\nUsing the system clock to seed the random num"
            "ber generator.\n");
          gettimeofday((struct timeval*)rnd_seed, NULL);
        }
#endif
    }
  else
    {
      printf("\nTo seed the random number generator, ");
      printf("please type some random text:\n");
      if (scanf("%s", rnd_seed) < 1)
        {
          printf("Warning: could not read any input.\n");
        }
    }
  RAND_seed(rnd_seed, sizeof rnd_seed);

  if (opts.bitsize)
    {
      /* generate only one HI for the specified length */
      if (!opts.type)
        {
          opts.type = HI_ALG_DSA;
        }
      sprintf(opts.name, "%s-%d", basename, opts.bitsize);
      generate_HI(root_node, &opts);
    }
  else
    {
      /* generate a HI for each of the default lengths */
      for (i = 0; i < (sizeof(default_sizes) / sizeof(int)); i++)
        {
          if (!opts.type)
            {
              opts.type = HI_ALG_RSA;
            }
          opts.bitsize = default_sizes[i];
          sprintf(opts.name, "%s-%d", basename, opts.bitsize);
          generate_HI(root_node, &opts);
        }
    }

  printf("\nStoring results to file '%s'.\n\n", filename);
  xmlSaveFormatFileEnc(filename, doc, "UTF-8", 1);
  xmlFreeDoc(doc);

#ifndef __WIN32__
  /* Change permissions of my_host_identities to 600 */
  if (chmod(filename, S_IRUSR | S_IWUSR) < 0)
    {
      printf("Error setting permissions for '%s'\n", filename);
    }
#else
  WSACleanup();
#endif
  return(0);
}

