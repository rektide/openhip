#ifndef _ENDBOX_UTILS_H_
#define _ENDBOX_UTILS_H_

#include <asm/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
/* #define _GNU_SOURCE */
#include <string.h>
#include <arpa/inet.h>

extern __u32 g_tap_lsi;

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
__u64 find_mac(__u32 host);
__u64 find_mac2(int index);
int find_mac3(__u8 *mac);
void endbox_init();
int ack_request(__u32 src, __u32 dst);

int build_host_mac_map();
int endbox_ipv4_packet_check(struct ip *iph, struct sockaddr *lsi, 
        int *packet_count);
void endbox_periodic_heartbeat(time_t *now_time, time_t *last_time,
	int *packet_count, char *name, int touchHeartbeat);
void endbox_ipv4_multicast_write(__u8 *data, int offset, int len);
void endbox_esp_decrypt(__u8 *out, int *offset);

#endif /* _ENDBOX_UTILS_H_ */
