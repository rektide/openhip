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

#ifndef GENERIC_HIP_55_H
#define GENERIC_HIP_55_H 1

/* The following size limits may be changed. */
#define HIP_55_MAX_HIT_LENGTH	16	/* 128 bit HIT size limit */
#define HIP_55_MAX_PK_LENGTH	512	/* 4096 bit RSA key size limit */
#define MAX_NUM_RVS 8

#define check_hip_length(length, max) \
		if (length > max) return (ISC_R_FAILURE);

typedef struct dns_rdata_hip {
	dns_rdatacommon_t	common;
	isc_mem_t		*mctx;
	isc_uint8_t		hit_length;
	isc_uint8_t		pk_algorithm;
	isc_uint16_t		pk_length;

	unsigned char *		hit;
	unsigned char *		pk;

	/* RVS is optional */
	dns_name_t		rvs_name[MAX_NUM_RVS]; 
} dns_rdata_hip_t;


#endif /* GENERIC_HIP_55_H */
