/*
 * Host Identity Protocol
 * Copyright (C) 2002-06 the Boeing Company
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
 * 		Definitions for the HIP protocol.
 *
 *  Version:	@(#)hip.h	1.5	08/12/04
 *
 *  Authors:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *		Tom Henderson, <thomas.r.henderson@boeing.com>
 *
 *
 */

#ifndef _HIP_PROTOCOL_H_
#define _HIP_PROTOCOL_H_

#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>


/* 
 * Protocol constants 
 */ 


#define H_PROTO_UDP 17
#define HIP_ESP_UDP_PORT 54500

#define HIP_PROTO_VER 1
#define H_PROTO_HIP 139 /* IP layer protocol number for private encryption */
#define HIP_PAYLOAD_PROTOCOL 59
#define STATUS_PORT 4051 /* UDP port for obtaining status data */

#define SPI_RESERVED 255
#define HIP_ALIGN 4
#define ACCEPTABLE_R1_COUNT_RANGE 2

#define HIT_SIZE 16
#define HIT_PREFIX_TYPE1_SHA1	0x40

typedef enum {
	UNASSOCIATED,	/* State machine start			*/
	I1_SENT,	/* Initiating HIP			*/
	I2_SENT,	/* Waiting to finish HIP		*/
	R2_SENT,	/* Waiting to finish HIP		*/
	ESTABLISHED,	/* HIP SA established			*/
	REKEYING,	/* HIP SA established, rekeying		*/
	CLOSING,	/* HIP SA closing, no data can be sent	*/
	CLOSED,		/* HIP SA closed, no data can be sent	*/
	E_FAILED	/* HIP SA establishment failed		*/
} HIP_STATES;

/* HIP packet types */
typedef enum {
        HIP_I1=1,
        HIP_R1,
        HIP_I2,
        HIP_R2,
        CER,    /* 5 - removed from draft-ietf-hip-base-03 */
        BOS=11, /* 11 - removed from draft-ietf-hip-base-01 */
        UPDATE=16, /* 16 */
        NOTIFY=17, /* 17 */
        CLOSE=18,  /* 18 */
        CLOSE_ACK=19, /* 19 */
} HIP_PACKETS;

/* HIP controls */
typedef enum {
        CTL_ANON        = 0x0001,
} HIP_CONTROLS;



/* HIP TLV parameters */
#define PARAM_ESP_INFO			65
#define PARAM_R1_COUNTER		128
#define PARAM_LOCATOR			193
#define PARAM_PUZZLE			257
#define PARAM_SOLUTION			321
#define PARAM_SEQ			385
#define PARAM_ACK			449
#define PARAM_DIFFIE_HELLMAN		513
#define PARAM_HIP_TRANSFORM		577
#define PARAM_ENCRYPTED			641
#define PARAM_HOST_ID			705
#define PARAM_CERT			768
#define PARAM_PROXY_TICKET		812
#define PARAM_AUTH_TICKET		822
#define PARAM_NOTIFY			832
#define PARAM_ECHO_REQUEST		897
#define PARAM_REG_INFO                  930
#define PARAM_REG_REQUEST               932
#define PARAM_REG_RESPONSE              934
#define PARAM_REG_FAILED                936
#define PARAM_REG_REQUIRED              /* TBD */
#define PARAM_ECHO_RESPONSE		961
#define PARAM_ESP_TRANSFORM		4095
#define PARAM_TRANSFORM_LOW		2048 /* defines range for transforms */
#define PARAM_TRANSFORM_HIGH		4095
#define PARAM_HMAC			61505
#define PARAM_HMAC_2			61569
#define PARAM_HIP_SIGNATURE_2		61633
#define PARAM_HIP_SIGNATURE		61697
#define PARAM_ESP_INFO_NOSIG		62565
#define PARAM_ECHO_REQUEST_NOSIG	63661
#define PARAM_ECHO_RESPONSE_NOSIG	63425
#define PARAM_FROM                      65498
#define PARAM_RVS_HMAC                  65500
#define PARAM_VIA_RVS                   65502
#define PARAM_CRITICAL_BIT		0x0001

/* encryption algorithms */
typedef enum {
	RESERVED,     			/* 0 */
	ESP_AES_CBC_HMAC_SHA1,		/* 1 */
	ESP_3DES_CBC_HMAC_SHA1,		/* 2 */
	ESP_3DES_CBC_HMAC_MD5,		/* 3 */
	ESP_BLOWFISH_CBC_HMAC_SHA1,	/* 4 */
	ESP_NULL_HMAC_SHA1,		/* 5 */
	ESP_NULL_HMAC_MD5,		/* 6 */
	SUITE_ID_MAX,			/* 7 */
} SUITE_IDS;
#define ENCR_NULL(a) ((a==ESP_NULL_HMAC_SHA1) || \
			(a==ESP_NULL_HMAC_MD5))
/* Supported transforms are compressed into a bitmask... */
/* Default HIP transforms proposed when none are specified in config */
#define DEFAULT_HIP_TRANS \
	((1 << ESP_AES_CBC_HMAC_SHA1) | \
	(1 << ESP_3DES_CBC_HMAC_SHA1) | \
	(1 << ESP_3DES_CBC_HMAC_MD5) | \
	(1 << ESP_BLOWFISH_CBC_HMAC_SHA1) | \
	(1 << ESP_NULL_HMAC_SHA1) | \
	(1 << ESP_NULL_HMAC_MD5))
/* Default ESP transforms proposed when none are specified in config */
#define ESP_OFFSET 8
#ifndef __CYGWIN__
#define DEFAULT_ESP_TRANS \
	((1 << (ESP_OFFSET + ESP_AES_CBC_HMAC_SHA1)) | \
	(1 << (ESP_OFFSET + ESP_3DES_CBC_HMAC_SHA1)) | \
	(1 << (ESP_OFFSET + ESP_3DES_CBC_HMAC_MD5)) | \
	(1 << (ESP_OFFSET + ESP_BLOWFISH_CBC_HMAC_SHA1)) | \
	(1 << (ESP_OFFSET + ESP_NULL_HMAC_SHA1)) | \
	(1 << (ESP_OFFSET + ESP_NULL_HMAC_MD5)))
#else /* Windows transform support more limited. */
#define DEFAULT_ESP_TRANS \
	((1 << (ESP_OFFSET + ESP_3DES_CBC_HMAC_SHA1)) | \
	(1 << (ESP_OFFSET + ESP_3DES_CBC_HMAC_MD5)) | \
	(1 << (ESP_OFFSET + ESP_NULL_HMAC_SHA1)) | \
	(1 << (ESP_OFFSET + ESP_NULL_HMAC_MD5)))
#endif

/* HI (signature) algorithms  */
enum {
	HI_ALG_RESERVED,
	HI_ALG_DSA = 3,
	HI_ALG_RSA = 5,
} HI_ALGORITHMS;
#define HIP_RSA_DFT_EXP RSA_F4 /* 0x10001L = 65537; 3 and 17 are also common */
#define HI_TYPESTR(a)  ((a==HI_ALG_DSA) ? "DSA" : \
			(a==HI_ALG_RSA) ? "RSA" : "UNKNOWN")

/* HI Domain Identifier types */
enum {
	DIT_NONE,	/* none included */
	DIT_FQDN,	/* Fully Qualified Domain Name, in binary format */
	DIT_NAI,	/* Network Access Identifier, binary, login@FQDN */
} HI_DIT;

typedef enum {
	UNVERIFIED,
	ACTIVE,
	DEPRECATED,
	DELETED,	/* not in spec, but used when address is removed */
} ADDRESS_STATES;

typedef enum {
	HIP_ENCRYPTION,
	HIP_INTEGRITY,
	ESP_ENCRYPTION,
	ESP_AUTH,
} KEY_TYPES;

typedef enum {
	GL_HIP_ENCRYPTION_KEY,	/* 0 */
	GL_HIP_INTEGRITY_KEY,
	LG_HIP_ENCRYPTION_KEY,
	LG_HIP_INTEGRITY_KEY,
	GL_ESP_ENCRYPTION_KEY,
	GL_ESP_AUTH_KEY,
	LG_ESP_ENCRYPTION_KEY,
	LG_ESP_AUTH_KEY	/* 7 */
} HIP_KEYMAT_KEYS;

typedef enum {
	KEY_LEN_NULL = 0,	/* RFC 2410 */
	KEY_LEN_MD5 = 16,	/* 128 bits per RFC 2403 */
	KEY_LEN_SHA1 = 20,	/* 160 bits per RFC 2404 */
	KEY_LEN_3DES = 24,	/* 192 bits (3x64-bit keys) RFC 2451 */
	KEY_LEN_AES = 16,	/* 128 bits per RFC 3686; also 192, 256-bits */
	KEY_LEN_BLOWFISH = 16,	/* 128 bits per RFC 2451 */
} HIP_KEYLENS;

/* Diffie-Hellman Group IDs */
typedef enum {
	DH_RESERVED,
	DH_384,
	DH_OAKLEY_1,
	DH_MODP_1536,
	DH_MODP_3072,
	DH_MODP_6144,
	DH_MODP_8192,
	DH_MAX
} DH_GROUP_IDS;
/* choose default DH group here */
#define DEFAULT_DH_GROUP_ID  DH_MODP_1536
#define DH_MAX_LEN 1024

/* 
 * HIP LOCATOR parameters 
 */
#define LOCATOR_PREFERRED 		0x01
#define LOCATOR_TRAFFIC_TYPE_BOTH 	0x00
#define LOCATOR_TRAFFIC_TYPE_SIGNALING	0x01
#define LOCATOR_TRAFFIC_TYPE_DATA 	0x02
#define LOCATOR_TYPE_IPV6		0x00
#define LOCATOR_TYPE_SPI_IPV6		0x01

/*
 * Notify error types
 */
#define NOTIFY_UNSUPPORTED_CRITICAL_PARAMETER_TYPE        1
#define NOTIFY_INVALID_SYNTAX                             7
#define NOTIFY_NO_DH_PROPOSAL_CHOSEN                     14
#define NOTIFY_INVALID_DH_CHOSEN                         15
#define NOTIFY_NO_HIP_PROPOSAL_CHOSEN                    16
#define NOTIFY_INVALID_HIP_TRANSFORM_CHOSEN              17
#define NOTIFY_NO_ESP_PROPOSAL_CHOSEN                    18
#define NOTIFY_INVALID_ESP_TRANSFORM_CHOSEN              19
#define NOTIFY_AUTHENTICATION_FAILED                     24
#define NOTIFY_CHECKSUM_FAILED                           26
#define NOTIFY_HMAC_FAILED                               28
#define NOTIFY_ENCRYPTION_FAILED                         32
#define NOTIFY_INVALID_HIT                               40
#define NOTIFY_BLOCKED_BY_POLICY                         42
#define NOTIFY_SERVER_BUSY_PLEASE_RETRY                  44
#define NOTIFY_LOCATOR_TYPE_UNSUPPORTED                  46
#define NOTIFY_I2_ACKNOWLEDGEMENT                        16384

/*
 * Registration types
 */
#define REG_RVS		1
#define REG_MR		2

#endif /* !_HIP_PROTOCOL_H_ */



