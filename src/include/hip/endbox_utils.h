/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2004-2012 the Boeing Company
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
 *  \file endbox_utils.h
 *
 *  \authors	Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *  		Orlie Brewer <orlie.t.brewer@boeing.com>
 *  		Jeff Meegan <jeff.r.meegan@boeing.com>
 *
 *  \brief  Endbox-specific function definitions.
 */

#ifndef _ENDBOX_UTILS_H_
#define _ENDBOX_UTILS_H_

void endbox_init();
void endbox_send_hello(void);
void endbox_hello_check(__u8 *buffer);
void endbox_check_hello_time(time_t *now_time);
void endbox_ipv4_multicast_write(__u8 *data, int offset, int len);
void endbox_periodic_heartbeat(time_t *now_time,
                               time_t *last_time,
                               int *packet_count,
                               char *name,
                               int touchHeartbeat);
int endbox_ipv4_packet_check(struct ip *iph, struct sockaddr *lsi,
                             int *packet_count);
int endbox_arp_packet_check(struct arp_hdr *arph, struct sockaddr *lsi,
                            int *packet_count);
int endbox_check_cert(struct sockaddr *lsi);

#endif /* _ENDBOX_UTILS_H_ */
