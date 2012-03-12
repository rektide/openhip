/*
 * Host Identity Protocol
 * Copyright (C) 2005 the Boeing Company
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
 *  hip_status.h
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 * Status thread definitions.
 * This file is shared by hipd, the Windows service, and status reporting
 * helper apps.
 *
 */

#ifndef __HIP_STATUS_H_
#define __HIP_STATUS_H_

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


/* Problems with multiple definitions of the arrays below */
#ifndef __UMH__

/*
 * Useful text definitions
 */
const char enc_alg_texts[7][28] = {
  "",
  "AES CBC with HMAC SHA1",
  "3DES CBC with HMAC SHA1",
  "3DES CBC with HMAC MD5",
  "BLOWFISH CBC with HMAC SHA1",
  "NULL with HMAC SHA1",
  "NULL with HMAC MD5",
};

const char state_texts[9][16] = {
  "Unassociated",
  "I1 Sent",
  "I2 Sent",
  "R2 Sent",
  "Established",
  "Rekeying",
  "Closing",
  "Closed",
  "E Failed",
};

#endif

#endif /* __HIP_STATUS_H_ */
