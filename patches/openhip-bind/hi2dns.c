/*
Copyright (c) 2006-2011, The Boeing Company.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
    * Neither the name of The Boeing Company nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/dsa.h>
#include <openssl/dsa.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libxml2/libxml/tree.h> /* all XML stuff		*/
#include "hi2dns.h"

/* Globals */
hi_node *my_hi_head;

/* Function declarations - most taken from hip_util.c */
void parse_xml_attributes(xmlAttrPtr attr, hi_node *hi);
void parse_xml_hostid(xmlNodePtr node, hi_node *hi);
int read_identities_file(char *filename, int mine);
hi_node *create_new_hi_node();
void append_hi_node(hi_node **head, hi_node *append);
int hex_to_bin(char *src, char *dst, int dst_len);
int hi_to_base64(hi_node *hi, __u8 *p);
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len);
void print_hex(void* data, int len);


int main(int argc, char **argv)
{
	hi_node *hi;
	__u8 base64[2048];
	char fname[255];
	int tabs;
	char *dash;

	/* command-line parameters */
	sprintf(fname, "%s", HIP_MYID_FILENAME);
	if (argc > 1) {
		if ((argc > 2) || (strcmp(argv[1], "-h") == 0) ||
		    (strcmp(argv[1], "--help") == 0)) {
			fprintf(stderr, "usage: %s [file.xml]\n\n", argv[0]);
			fprintf(stderr, "Will read Host Identities from the ");
			fprintf(stderr, "specified file if provided, or from ");
			fprintf(stderr, "the\ndefault file %s.\n\n", fname);
			return(0);
		} else {
			strncpy(fname, argv[1], sizeof(fname));
		}
	}

	/* read HIs from XML */
	my_hi_head = NULL;
	printf("Loading Host Identities from XML file '%s'...\n", fname);
	if (read_identities_file(fname, TRUE) < 0) {
		fprintf(stderr, "error loading Host Identities.\n");
		return(-1);
	}
	printf("done.\n\n");

	/* output HIs in DNS RR format */
	printf("HIP RRs:\n");
	for (hi = my_hi_head; hi; hi=hi->next) {
		memset(base64, 0, sizeof(base64));
		dash = strrchr(hi->name, '-');   /* remove dash */
		if (dash)
			*dash = '\0';
		if ((40 - strlen(hi->name)) > 0) /* indent by 40 chars */
			tabs = (40 - strlen(hi->name))/8;
		else
			tabs = 0;		
		printf("%s", hi->name);
		if (strrchr(hi->name, '.'))      /* trailing dot if no domain */
			printf(".");
		for ( ; tabs > 0; tabs--)
			printf("\t");
		
		/* class, type, and record */
		printf("IN  HIP ( %u ", (hi->algorithm_id == HI_ALG_DSA) ? 1 :
			(hi->algorithm_id == HI_ALG_RSA) ? 2 : 0); /* pk_alg */
		print_hex(hi->hit, HIT_SIZE);			/* HIT */
		printf("\n");
		if (hi_to_base64(hi, base64) < 0)
			printf("\t\t*** error converting Host Identity ***\n");
		else
			printf("\t\t\t\t\t%s\n", base64);	/* pk */
		printf(" )\n");
	} /* end for */
	printf("\n");
	return 0;
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
		return;
	hi->r1_gen_count = 0;
	hi->anonymous = 0;
	hi->allow_incoming = 1;
	hi->skip_addrcheck = 0;
	
	while (attr) {
		if ((attr->type==XML_ATTRIBUTE_NODE) &&
		    (attr->children) && 
		    (attr->children->type==XML_TEXT_NODE))
			value = (char *)attr->children->content;
		else /* no attribute value */
			continue;
		/* save recognized attributes */
		if (strcmp((char *)attr->name, "alg")==0) {
			//memcpy(alg, value, strlen(value));
		} else if (strcmp((char *)attr->name, "alg_id")==0) {
			sscanf(value, "%d", &tmp);
			hi->algorithm_id = (char)tmp;
		} else if (strcmp((char *)attr->name, "length")==0) {
			sscanf(value, "%d", &hi->size);
		} else if (strcmp((char *)attr->name, "anon")==0) {
			if (*value == 'y')
				hi->anonymous = 1;
			else
				hi->anonymous = 0;
		} else if (strcmp((char *)attr->name, "incoming")==0) {
			if (*value == 'y')
				hi->allow_incoming = 1;
			else
				hi->allow_incoming = 0;
		} else if (strcmp((char *)attr->name, "r1count")==0) {
			sscanf(value, "%llu", &hi->r1_gen_count);
		} else if (strcmp((char *)attr->name, "addrcheck")==0) {
			if (strcmp(value, "no")==0)
				hi->skip_addrcheck = TRUE;
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
	sockaddr_list *list;

	addr = (struct sockaddr*) &ss_addr;
	memset(hi->hit, 0, HIT_SIZE);
	memset(&hi->lsi, 0, sizeof(struct sockaddr_storage));

	for (; node; node = node->next) {
		/* skip entity refs */
		if (strcmp((char *)node->name, "text")==0)
			continue;
		
		data = (char *)xmlNodeGetContent(node);
		/* populate the DSA structure */
		switch (hi->algorithm_id) {
		case HI_ALG_DSA:
			if (strcmp((char *)node->name, "P")==0) {
				BN_hex2bn(&hi->dsa->p, data);
			} else if (strcmp((char *)node->name, "Q")==0) {
				BN_hex2bn(&hi->dsa->q, data);
			} else if (strcmp((char *)node->name, "G")==0) {
				BN_hex2bn(&hi->dsa->g, data);
			} else if (strcmp((char *)node->name, "PUB")==0) {
				BN_hex2bn(&hi->dsa->pub_key, data);
			} else if (strcmp((char *)node->name, "PRIV")==0) {
				BN_hex2bn(&hi->dsa->priv_key, data);
			}
			break;
		case HI_ALG_RSA:
			if (strcmp((char *)node->name, "N")==0) {
				BN_hex2bn(&hi->rsa->n, data);
			} else if (strcmp((char *)node->name, "E")==0) {
				BN_hex2bn(&hi->rsa->e, data);
			} else if (strcmp((char *)node->name, "D")==0) {
				BN_hex2bn(&hi->rsa->d, data);
			} else if (strcmp((char *)node->name, "P")==0) {
				BN_hex2bn(&hi->rsa->p, data);
			} else if (strcmp((char *)node->name, "Q")==0) {
				BN_hex2bn(&hi->rsa->q, data);
			} else if (strcmp((char *)node->name, "dmp1")==0) {
				BN_hex2bn(&hi->rsa->dmp1, data);
			} else if (strcmp((char *)node->name, "dmq1")==0) {
				BN_hex2bn(&hi->rsa->dmq1, data);
			} else if (strcmp((char *)node->name, "iqmp")==0) {
				BN_hex2bn(&hi->rsa->iqmp, data);
			}
			break;
		default:
			break;
		}
		/* get HI values that are not algorithm-specific */
		if (strcmp((char *)node->name, "HIT")==0) {
			/* HIT that looks like IPv6 address */
			if (index(data, ':')) {
				memset(addr, 0, sizeof(addr));
				addr->sa_family = AF_INET6;
				if (inet_pton(addr->sa_family,
				    data, SA2IP(addr)) <= 0) {
					printf("%s '%s' for %s invalid.\n",
				    		node->name, data, hi->name);
					xmlFree(data);
					continue;
				}
				memcpy(hi->hit, SA2IP(addr), HIT_SIZE);
			} else { /* HIT that is plain hex */
				hex_to_bin(data, (char *)hi->hit, HIT_SIZE);
			}
		} else if (strcmp((char *)node->name, "name")==0) {
			memset(hi->name, 0, sizeof(hi->name));
			strncpy(hi->name, data, sizeof(hi->name));
			hi->name_len = strlen(hi->name);
		} else if ((strcmp((char *)node->name, "LSI")==0) || 
			   (strcmp((char *)node->name, "addr")==0)) {
			memset(addr, 0, sizeof(struct sockaddr_storage));
			/* Determine address family - IPv6 must have a ':' */
			addr->sa_family = ((index(data, ':')==NULL) ? AF_INET : AF_INET6);
			if (inet_pton(addr->sa_family, data, SA2IP(addr)) > 0) {
				list = &hi->addrs;
				/* first entry in address list */
				if ((strcmp((char *)node->name, "addr")==0) &&
				    (VALID_FAM(&list->addr))) {
			//		add_address_to_list(&list, addr, 0);
				/* LSI */
				} else if (strcmp((char *)node->name,"LSI")==0){
					memcpy(&hi->lsi, addr, SALEN(addr));
				/* additional address entry */
				} else {
					memcpy(&list->addr, addr, SALEN(addr));
				}
			} else {
				printf("%s '%s' for %s not valid.\n",
				    node->name, data, hi->name);
			}
		}
		xmlFree(data);
	}
}

/*
 * function read_identities_file()
 *
 * filename	name of the XML file to open
 * mine		is this my list of Host Identities?
 * 		if TRUE, store HIs/HITs into my_hi_list, otherwise
 * 		store into peer_hi_list.
 *
 */
int read_identities_file(char *filename, int mine)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = NULL;
	hi_node *hi;
	char name[255];

	doc = xmlParseFile(filename);
	if (doc == NULL) {
		fprintf(stderr, "Error parsing xml file (%s)\n", filename);
		return(-1);
	}

	node = xmlDocGetRootElement(doc);
	for (node = node->children; node; node = node->next)
	{
		if (strcmp((char *)node->name, "host_identity")==0) {
			printf("Loading Host Identity...");
			hi = create_new_hi_node();
			parse_xml_attributes(node->properties, hi);
			printf( "(%s %d-bit) ",
			    HI_TYPESTR(hi->algorithm_id), hi->size*8);
			switch (hi->algorithm_id) {
			case HI_ALG_DSA:
				hi->dsa = DSA_new();
				break;
			case HI_ALG_RSA:
				hi->rsa = RSA_new();
				break;
			 default:
				if (mine) {
					printf( "Unknown algorithm found ");
					printf( "in XML file: %u\n",
					    hi->algorithm_id);
					if (hi->dsa) DSA_free(hi->dsa);
					if (hi->rsa) RSA_free(hi->rsa);
					free(hi);
					continue;
				}
			}
			/* fill in the DSA/RSA structure, HIT, LSI, name */
			parse_xml_hostid(node->children, hi);
			/* if LSI is not configured, it is 24-bits of HIT */
			if (!VALID_FAM(&hi->lsi)) {
				__u32 lsi = ntohl(HIT2LSI(hi->hit));
				hi->lsi.ss_family = AF_INET;
				memcpy(SA2IP(&hi->lsi), &lsi, sizeof(__u32));
			}
			if (mine) {
				/* addresses for HIs in my_host_identities will
				 * be added later per association */
				memset(&hi->addrs.addr, 0, 
					sizeof(struct sockaddr_storage));
				printf( "%s\n", hi->name);
			} else {
				/* get HI name */
				strcpy(name, hi->name);
				if (rindex(name, '-'))
				   name[strlen(name)-strlen(rindex(name,'-'))] = 0;
				
			}
			/* link this HI into a global list */
			append_hi_node(mine ? &my_hi_head : NULL, hi);
		}
		/* 
		 * add other XML tags here
		 */
	}

	xmlFreeDoc(doc);
	xmlCleanupParser();
	return(0);
}

/*
 * Create an hi_node
 */
hi_node *create_new_hi_node()
{
	hi_node *ret;

	ret = (hi_node *) malloc(sizeof(hi_node));
	if (ret == NULL) {
		printf("Malloc error: creating new hi_node\n");
		return NULL;
	}
	memset(ret, 0, sizeof(hi_node));
	return(ret);
}

/* 
 * Append an hi_node to a list
 */
void append_hi_node(hi_node **head, hi_node *append)
{
	hi_node *hi_p;
	if (*head == NULL) {
		*head = append;
		return;
	}
	for (hi_p = *head; hi_p->next; hi_p = hi_p->next);
	hi_p->next = append;
}

/*
 *
 * function hex_to_bin()
 *
 * in:		src = input hex data
 *		dst = output binary data
 *		dst_len = requested number of binary bytes
 *
 * out:		returns bytes converted if successful,
 * 		-1 if error
 * 
 */
int hex_to_bin(char *src, char *dst, int dst_len)
{
	char hex[] = "0123456789abcdef";
	char hexcap[] = "0123456789ABCDEF";
	char *p, c;
	int src_len, total, i, val;
	unsigned char o;

	if ((!src) || (!dst)) 
		return(-1);
	src_len = strlen(src);
	if (dst_len > src_len) 
		return(-1);

	/* chop any '0x' prefix */
	if ((src[0]=='0') && (src[1]=='x')) {
		src += 2;
		src_len -= 2;
	}
	
	/* convert requested number of bytes from hex to binary */
	total = 0;
	for (i=0; (i < src_len) && (total < dst_len) ; i+=2) {
		/* most significant nibble */
		c = src[i];
		/* 
		 * Normally would use tolower(), but have found problems 
		 * with dynamic linking and different glibc versions
		 */ 
		if ((p = strchr(hex, c)) == NULL) {
			if ((p = strchr(hexcap, c)) == NULL) {
				continue;
			}
			val = p - hexcap;
		} else {
			val = p - hex;
		}
		if (val < 0 || val > 15) {
			return(-1);
		}
		o = val << 4;
		/* least significant nibble */
		c = src[i+1];
		if ((p = strchr(hex, c)) == NULL) {
			if ((p = strchr(hexcap, c)) == NULL) {
				continue;
			}	
			val = p - hexcap;
		} else {
			val = p - hex;
		}	
		if (val < 0 || val > 15) {
			return(-1);
		}
		o += val;
		dst[total] = o;
		total++;
		if (total >= src_len) 
			total = dst_len;
	}
	return total;
}

/*
 * function hi_to_base64()
 *
 * in:		hi = the Host Identity from which HIT is computed
 * 		p = ptr to destination bytes
 *
 * out:		Returns 0 if successful, -1 on error.
 *
 * Converts the Host Identity to a Type 1 SHA-1 HIT.
 * 		
 */
int hi_to_base64(hi_node *hi, __u8 *p)
{
	int len, location;
	__u8 *data=NULL;
	__u16 e_len;

	if (!hi)
		return(-1);

	switch (hi->algorithm_id) {
	case HI_ALG_DSA: /* RFC 2536 */
		if ((!hi->dsa) || (!hi->dsa->q) || (!hi->dsa->p) || 
		    (!hi->dsa->g) || (!hi->dsa->pub_key))
			return(-1);
		len = 1 + DSA_PRIV + (3*hi->size);
		data = malloc(len);
		if (!data)
			return(-1);
		/* Encode T, Q, P, G, Y */
		data[0] = (hi->size - 64)/8;
		bn2bin_safe(hi->dsa->q, &data[1], DSA_PRIV);
		bn2bin_safe(hi->dsa->p, &data[1+DSA_PRIV], hi->size);
		bn2bin_safe(hi->dsa->g, &data[1+DSA_PRIV+hi->size], hi->size);
		bn2bin_safe(hi->dsa->pub_key, &data[1+DSA_PRIV+(2*hi->size)], 
			    hi->size);
		location = len;
		break;
	case HI_ALG_RSA: /* RFC 3110 */
		if ((!hi->rsa) || (!hi->rsa->e) || (!hi->rsa->n))
			return(-1);
		e_len =  BN_num_bytes(hi->rsa->e);
		if (e_len > 255)
			len = 3 + e_len + RSA_size(hi->rsa);
		else
			len = 1 + e_len + RSA_size(hi->rsa);
		data = malloc(len);
		if (!data)
			return(-1);
		/* Encode e_len, exponent(e), modulus(n) */
		if (e_len > 255) {
			__u16 *p =  (__u16*) &data[1];
			data[0] = 0x0;
			*p = htons(e_len);
			location = 3;
		} else {
			data[0] = (__u8) e_len;
			location = 1;
		}
		location += bn2bin_safe(hi->rsa->e, &data[location], e_len);
		location += bn2bin_safe(hi->rsa->n, &data[location],
					RSA_size(hi->rsa));
		break;
	default:
		return(-1);
	}

	/* this base64 encodes the HI */
	len = EVP_EncodeBlock(p, data, location);
	/*printf("\n len = %d  location = %d \n", len, location);*/
	/*print_hex(data, location);*/

	free(data);

	return(len);
}

/*
 * function bn2bin_safe(BIGNUM *dest)
 *
 * BN_bin2bn() chops off the leading zero(es) of the BIGNUM,
 * so numbers end up being left shifted.
 * This fixes that by enforcing an expected destination length.
 */
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len)
{
	int padlen = len - BN_num_bytes(a);
	/* add leading zeroes when needed */
	if (padlen > 0)
		memset(to, 0, padlen);
	BN_bn2bin(a, &to[padlen]);
	/* return value from BN_bn2bin() may differ from length */
	return(len);
}

/*
 * function print_hex()
 *
 * Generic binary to hex printer.
 */
void print_hex(void* data, int len)
{
	int i;
	unsigned char *p = (unsigned char*) data;

	for (i=0; i < len; i++)
		printf("%.2X", p[i]);
}
