/*
 * Copyright (C) 2005 Andrei Gurtov
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  Authors:    Andrei Gurtov, HIIT
 *  Written: 3.4.2005
 *
 * \brief Interface with i3 and HIP for Hi3
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
