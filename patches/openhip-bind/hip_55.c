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

/* Files to support draft-ietf-hip-dns */

#ifndef RDATA_GENERIC_HIP_55_C
#define RDATA_GENERIC_HIP_55_C

#include <math.h>
#include <dst/dst.h>

#define RRTYPE_HIP_ATTRIBUTES (0)
#define TOBEDEFINED_HIP_RR 55
/* #define HIP_55_DEBUG */

static inline isc_result_t
fromtext_hip(ARGS_FROMTEXT) {
	isc_token_t token;
	dns_secalg_t pk_alg;
	int pk_length, hit_length;
	isc_buffer_t buffer;
	dns_name_t name;
	isc_uint8_t *p;

	REQUIRE(type == TOBEDEFINED_HIP_RR);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(callbacks);

#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: fromtext_hip\n");
#endif

	/* PK algorithm */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      ISC_FALSE));
	pk_alg = (isc_uint8_t)token.value.as_ulong;
	/* save ptr to start of buffer, pk_length not yet known */
	p = isc_buffer_used(target);
	RETERR(uint8_tobuffer(0, target));	/* HIT length */
	RETERR(uint8_tobuffer(pk_alg, target));
	RETERR(uint16_tobuffer(0, target));	/* PK length */
	/* could also use isc_tokentype_string and 
 	   dns_secalg_fromtext(&pk_alg, &token.value.as_textregion) function */

	/* 
	 * HIT 
	 */
	hit_length = 16;
	RETERR(isc_hex_tobuffer(lexer, target, hit_length));
	p[0] = (isc_uint8_t)hit_length;

	/* 
	 * Public Key 
	 */

	/* There is no white space in the public key as per RFC 5205,
	 * so find out how many characters there are and put it back.
	 * Base64 encodes three bytes into four characters as per RFC 4648.
	 * The third parameter to isc_base64_tobuffer is the number of bytes
	 * to decode. -1 cannot be used as the third parameter to
	 * isc_base64_tobuffer because that reads until end of record.
	 */

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      ISC_FALSE));
	if (token.type != isc_tokentype_string)
		return (ISC_R_UNEXPECTEDTOKEN);
	pk_length = ceil(3*token.value.as_textregion.length/4.0);
	isc_lex_ungettoken(lexer, &token);

	if (pk_length > HIP_55_MAX_PK_LENGTH)
		RETERR(ISC_R_RANGE);
	RETERR(isc_base64_tobuffer(lexer, target, pk_length));
	p[2] = (isc_uint8_t) ((pk_length & 0xff00U) >> 8);
	p[3] = (isc_uint8_t)  (pk_length & 0x00ffU);
	
	/* Rendezvous Servers */
	while (isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      ISC_FALSE) == ISC_R_SUCCESS) {
		dns_name_init(&name, NULL);
		buffer_fromregion(&buffer, &token.value.as_region);
		origin = (origin != NULL) ? origin : dns_rootname;
		RETTOK(dns_name_fromtext(&name, &buffer, origin, 
					options, target));
	}
	
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_hip(ARGS_TOTEXT) {
        isc_region_t sr, dr;
	char buf[sizeof("256")];
	dns_secalg_t pk_alg;
	isc_uint8_t hit_length;
	isc_uint16_t pk_length;
	dns_name_t prefix, name;
	isc_boolean_t sub;

#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: totext_hip\n");
#endif
	REQUIRE(rdata->type == TOBEDEFINED_HIP_RR);
	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &sr);

	/*
	 * hit length   1
	 * pk algorithm 1
	 * pk length    1
	 */
	hit_length = sr.base[0];
	pk_alg = sr.base[1];
	isc_region_consume(&sr, 2);
	pk_length = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" (", target));
	sprintf(buf, "%u", pk_alg);
	RETERR(str_totext(buf, target));
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(str_totext(" ", target));

	/*
	 * HIT
	 */
	REQUIRE(hit_length <= sr.length);
	dr = sr;
	dr.length = hit_length;
	RETERR(isc_hex_totext(&dr, tctx->width - 2,
				 tctx->linebreak, target));

	if ((tctx->flags & DNS_STYLEFLAG_COMMENT) != 0)
		RETERR(str_totext(tctx->linebreak, target));
	else if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" ", target));
	isc_region_consume(&sr, hit_length);

	/*
	 * Public Key
	 */
	REQUIRE(pk_length <= sr.length);
	dr = sr;
	dr.length = pk_length;
	RETERR(str_totext(tctx->linebreak, target));
	RETERR(isc_base64_totext(&dr, tctx->width - 2,
				 tctx->linebreak, target));
	RETERR(str_totext(tctx->linebreak, target));
	isc_region_consume(&sr, pk_length);

	/*
	 * RVS (optional)
	 */
	while (sr.length > 0) {
		dns_name_init(&name, NULL);
		dns_name_init(&prefix, NULL);
		dns_name_fromregion(&name, &sr);
		isc_region_consume(&sr, name_length(&name));
		sub = name_prefix(&name, tctx->origin, &prefix);
		RETERR(str_totext(tctx->linebreak, target));
		RETERR(dns_name_totext(&prefix, sub, target));
	}
	if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		RETERR(str_totext(" )", target));
	
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_hip(ARGS_FROMWIRE) {
        isc_region_t sr;
	dns_name_t name;
	isc_uint8_t hit_length;
	isc_uint16_t pk_length;

#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: fromwire_hip\n");
#endif
	REQUIRE(type == TOBEDEFINED_HIP_RR);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(dctx);
	UNUSED(options);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);

	isc_buffer_activeregion(source, &sr);
	if (sr.length < 4)
		return (ISC_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 2));
	hit_length = sr.base[0];
	isc_buffer_forward(source, 2);

	isc_buffer_activeregion(source, &sr);
	pk_length = uint16_fromregion(&sr);
	isc_buffer_forward(source, 2);
	RETERR(mem_tobuffer(target, sr.base, 2));

	isc_buffer_activeregion(source, &sr);
	if (sr.length < (hit_length + pk_length))
		return (ISC_R_UNEXPECTEDEND);
	isc_buffer_forward(source, hit_length + pk_length);
	RETERR(mem_tobuffer(target, sr.base, hit_length + pk_length));

	isc_buffer_activeregion(source, &sr);
	while (sr.length > 0) {
		dns_name_init(&name, NULL);
		RETERR(dns_name_fromwire(&name, source, dctx, options, target));
		isc_buffer_activeregion(source, &sr); /* update sr.length */
	}
	return(ISC_R_SUCCESS);
}

static inline isc_result_t
towire_hip(ARGS_TOWIRE) {
	isc_region_t sr;
	dns_offsets_t offsets;
	dns_name_t name;
	isc_uint8_t hit_length;
	isc_uint16_t pk_length;

#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: towire_hip\n");
#endif
	REQUIRE(rdata->type == TOBEDEFINED_HIP_RR);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);
	dns_rdata_toregion(rdata, &sr);
	/*
	 * HIT length: 1
	 * PK algorithm: 1
	 * PK length: 2
	 */
	RETERR(mem_tobuffer(target, sr.base, 4));
	hit_length = sr.base[0];
	isc_region_consume(&sr, 2);
	pk_length = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);

	/*
	 * HIT: variable
	 * PK: variable
	 */
	REQUIRE(hit_length <= sr.length);
	RETERR(mem_tobuffer(target, sr.base, hit_length));
	isc_region_consume(&sr, hit_length);
	REQUIRE(pk_length <= sr.length);
	RETERR(mem_tobuffer(target, sr.base, pk_length));
	isc_region_consume(&sr, pk_length);

	/*
	 * RVS (optional)
	 */
	while (sr.length > 0) {
		dns_name_init(&name, offsets);
		dns_name_fromregion(&name, &sr);
		isc_region_consume(&sr, name_length(&name));
		RETERR( dns_name_towire(&name, cctx, target) );
	}

	return(ISC_R_SUCCESS);
}

static inline int
compare_hip(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == TOBEDEFINED_HIP_RR);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);

	/* XXX could more carefully do dns_name_rdatacompare() for RVS */
	return (isc_region_compare(&r1, &r2));
}

static inline isc_result_t
fromstruct_hip(ARGS_FROMSTRUCT) {
	dns_rdata_hip_t *hiprr = (dns_rdata_hip_t *) source;
	int i;

#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: fromstruct_hip\n");
#endif
	REQUIRE(type == TOBEDEFINED_HIP_RR);
	REQUIRE(source != NULL);
	REQUIRE(hiprr->common.rdtype == type);
	REQUIRE(hiprr->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint8_tobuffer(hiprr->hit_length, target));
	RETERR(uint8_tobuffer(hiprr->pk_algorithm, target));
	RETERR(uint16_tobuffer(hiprr->pk_length, target));
	RETERR(mem_tobuffer(target, hiprr->hit, hiprr->hit_length));
	RETERR(mem_tobuffer(target, hiprr->pk, hiprr->pk_length));

	for (i = 0; i < MAX_NUM_RVS; i++) {
		if (hiprr->rvs_name[i].length > 0)
			 RETERR(name_tobuffer(&hiprr->rvs_name[i], target));
		else
			break;
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
tostruct_hip(ARGS_TOSTRUCT) {
	dns_rdata_hip_t *hiprr = (dns_rdata_hip_t *) target;
	isc_region_t sr;
	dns_name_t name;
	int i;

#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: tostruct_hip\n");
#endif
	REQUIRE(rdata->type == TOBEDEFINED_HIP_RR);
	REQUIRE(target != NULL);
	REQUIRE(rdata->length != 0);

	hiprr->common.rdclass = rdata->rdclass;
	hiprr->common.rdtype  = rdata->type;
	ISC_LINK_INIT(&hiprr->common, link);

	dns_rdata_toregion(rdata, &sr);

	/* HIT length */
	if (sr.length < 1)
		return (ISC_R_UNEXPECTEDEND);
	hiprr->hit_length = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	check_hip_length(hiprr->hit_length, HIP_55_MAX_HIT_LENGTH);

	/*  Public Key algorithm */
	if (sr.length < 1)
		return (ISC_R_UNEXPECTEDEND);
	hiprr->pk_algorithm = uint8_fromregion(&sr);
	isc_region_consume(&sr, 1);
	
	/*  Public Key length */
	if (sr.length < 2)
		return (ISC_R_UNEXPECTEDEND);
	hiprr->pk_length = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	
	/* HIT */
	if (sr.length < hiprr->hit_length)
		return (ISC_R_UNEXPECTEDEND);
	hiprr->hit = mem_maybedup(mctx, sr.base, hiprr->hit_length);
	if (hiprr->hit == NULL)
		goto cleanup;
	isc_region_consume(&sr, hiprr->hit_length);

	/* Public Key */
	if (sr.length < hiprr->pk_length)
		return (ISC_R_UNEXPECTEDEND);
	hiprr->pk = mem_maybedup(mctx, sr.base, hiprr->pk_length);
	if (hiprr->pk == NULL)
		goto cleanup;
	isc_region_consume(&sr, hiprr->pk_length);

	/* optional RVS(s) */
	dns_name_init(&hiprr->rvs_name[0], NULL);
	for (i = 0; sr.length > 0 && i < MAX_NUM_RVS; i++) {
		dns_name_init(&hiprr->rvs_name[i], NULL);
		dns_name_init(&name, NULL);
		dns_name_fromregion(&name, &sr);
		RETERR(name_duporclone(&name, mctx, &hiprr->rvs_name[i]));
		isc_region_consume(&sr, name_length(&hiprr->rvs_name[i]));
	}

	hiprr->mctx = mctx;
	return (ISC_R_SUCCESS);

 cleanup:
	if (hiprr->hit != NULL)
		isc_mem_free(mctx, hiprr->hit);
	if (hiprr->pk != NULL)
		isc_mem_free(mctx, hiprr->pk);
	/* if (mctx != NULL)
		dns_name_free( &hiprr->rvs_name[0], mctx); */

	return (ISC_R_NOMEMORY);
}

static inline void
freestruct_hip(ARGS_FREESTRUCT) {
	dns_rdata_hip_t *hiprr = (dns_rdata_hip_t *) source;
	int i;

#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: freestruct_hip\n");
#endif
	REQUIRE(source != NULL);
	REQUIRE(hiprr->common.rdtype == TOBEDEFINED_HIP_RR);

	if (hiprr->mctx == NULL)
		return;

	if (hiprr->hit != NULL)
		isc_mem_free(hiprr->mctx, hiprr->hit);

	if (hiprr->pk != NULL)
		isc_mem_free(hiprr->mctx, hiprr->pk);

	for (i = 0; i < MAX_NUM_RVS; i++) {
		if (hiprr->rvs_name[i].length > 0)
			dns_name_free(&hiprr->rvs_name[i], hiprr->mctx);
		else
			break;
	}

	hiprr->mctx = NULL;
}

static inline isc_result_t
additionaldata_hip(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == TOBEDEFINED_HIP_RR);

	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_hip(ARGS_DIGEST) {
        isc_region_t r;
	
#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: digest_hip\n");
#endif
	REQUIRE(rdata->type == TOBEDEFINED_HIP_RR);

	dns_rdata_toregion(rdata, &r);

	return((digest)(arg, &r));
}

static inline isc_boolean_t
checkowner_hip(ARGS_CHECKOWNER) {

	REQUIRE(type == TOBEDEFINED_HIP_RR);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (ISC_TRUE);
}

static inline isc_boolean_t
checknames_hip(ARGS_CHECKNAMES) {
	isc_region_t region;
	dns_name_t name;
	isc_uint8_t hit_length;
	isc_uint16_t pk_length;
	int len;

#ifdef HIP_55_DEBUG
	fprintf(stderr, "HIPRR: checknames_hip\n");
#endif
	REQUIRE(rdata->type == TOBEDEFINED_HIP_RR);

	UNUSED(owner);

	dns_rdata_toregion(rdata, &region);
	hit_length = region.base[0];
	isc_region_consume(&region, 2);
	pk_length = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	len = hit_length + pk_length;
	isc_region_consume(&region, len); /* eat all data before rvs */
	
	while (region.length > 0) {
		dns_name_init(&name, NULL);
		dns_name_fromregion(&name, &region);
		if (!dns_name_ishostname(&name, ISC_FALSE)) {
			if (bad != NULL)
				dns_name_clone(&name, bad);
			return (ISC_FALSE);
		}
		if (name_length(&name) == 0)
			break;
		isc_region_consume(&region, name_length(&name));
	}
	return (ISC_TRUE);
}

static inline int
casecompare_hip(ARGS_COMPARE) {
        return (compare_hip(rdata1, rdata2));
}

#endif	/* RDATA_GENERIC_HIP_55_C */
