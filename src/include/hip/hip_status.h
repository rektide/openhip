/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2005-2012 the Boeing Company
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
 *  \file  hip_status.h
 *
 *  \authors Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Status thread definitions.
 *
 */

#ifndef _HIP_STATUS_H_
#define _HIP_STATUS_H_

/*
 * Globals
 */
#define WIN_STATUS_PORT 4052
#define STATUS_PORT 4051

/*
 * Types and macros
 */
struct status_tlv
{
  unsigned short tlv_type;
  unsigned short tlv_len;
};

#define ADD_ITEM(a, b, c) memcpy(&a[c], &b, sizeof(b)); c += sizeof(b);

/*
 * Status request types serviced by hipd
 */
enum requests {
  HIP_STATUS_REQ_MIN,
  HIP_STATUS_REQ_PEERS,
  HIP_STATUS_REQ_MYIDS,
  HIP_STATUS_REQ_MYADDRS,
  HIP_STATUS_REQ_ASSOC,
  HIP_STATUS_REQ_OPTS,
  HIP_STATUS_REQ_CONF,
  HIP_STATUS_REQ_MAX
};

enum settings {
  HIP_STATUS_CONFIG_MIN=HIP_STATUS_REQ_MAX,
  HIP_STATUS_CONFIG_OPTS,
  HIP_STATUS_CONFIG_MAX
};

/*
 * Status request types handled by the Windows service
 */
enum win_requests {
  STAT_MIN,
  STAT_THREADS,
  STAT_SADB,
  STAT_DST,
  STAT_LSI,
  STAT_PEERS,
  STAT_IDS,
  STAT_ALL_SPI,
  STAT_MAX
};

enum responses {
  HIP_STATUS_REPLY_MIN,
  HIP_STATUS_REPLY_ERROR,
  HIP_STATUS_REPLY_STRING,
  HIP_STATUS_REPLY_SADB,
  HIP_STATUS_REPLY_ADDR,
  HIP_STATUS_REPLY_DST_ENTRY,
  HIP_STATUS_REPLY_LSI_ENTRY,
  HIP_STATUS_REPLY_HI,
  HIP_STATUS_REPLY_ASSOC,
  HIP_STATUS_REPLY_OPTS,
  HIP_STATUS_REPLY_ALL_SPI,
  HIP_STATUS_REPLY_DONE,
  HIP_STATUS_REPLY_MAX
};

#endif /* _HIP_STATUS_H_ */
