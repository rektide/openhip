/*
 * Interface with i3 and HIP for Hi3
 * Author: (c) Andrei Gurtov, HIIT
 * Licence: GPLv2
 * Written: 3.4.2005
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>   /* basic system data types */
#include <sys/socket.h>  /* basic socket definitions */
#include <sys/time.h>    /* timeval{} for select() */
#include <errno.h>
#include <sys/utsname.h>
#include <time.h>                /* timespec{} for pselect() */
#include <netinet/in.h>  /* sockaddr_in{} and other Internet defns */
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#include "i3_server/i3_matching.h"
#include "i3/i3.h"
#include "i3_client/i3_client_api.h"
#include "i3_client/i3_client_id.h"
#include "hip.h"

#define CFGFILE "i3-cfg-PL.xml"
//#define HI3_DEBUG 

int cl_register_callback(unsigned short, void (*)(), void*);
int send_i3(__u8 *, int, hip_hit *, struct sockaddr*, struct sockaddr*);
void hip_handle_packet(struct msghdr* , int, __u16);
int i3_init(hip_hit*);
void init_id_fromstr(ID *, char *);
void print_hit(const hip_hit *);
void clean_i3();
