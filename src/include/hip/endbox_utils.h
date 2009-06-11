#ifndef __SMA_ENDBOX_UTILS__
#define __SMA_ENDBOX_UTILS__

#include <asm/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
/* #define _GNU_SOURCE */
#include <string.h>
#include <arpa/inet.h>

/* extern char *strndup(const char *, size_t); */

typedef struct _pList {
	char *ip;
	char *mac;
} pList;

typedef struct _spiList {
	__u32 src;
	__u32 dst;
  __u32 spi;
	struct _spiList *next;
} spiList;


typedef union _addrUnion {
  __u64 s64;
  struct  {
    __u32 src;
    __u32 dst;
  } c;
} addrUnion;


int read_private_hosts();
int read_hostmap();
void dump_private_hosts();
void dump_hostmap();
char *find_endbox(char *host);
char *find_endbox2(__u32 host);
int find_host(char *host);
int find_host2(__u32 host);

void read_endbox_config() ;

void addSpiEntry(__u32 spi, __u32 src, __u32 dst) ;
spiList *findSpiEntry(__u32 spi);
void endbox_init();
__u64 find_mac(__u32 host);
int find_address_extension(__u32 * src, __u32 *dst, __u8 *data);
#endif
