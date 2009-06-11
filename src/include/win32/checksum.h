/*
 * This file contains a combination of:
 * linux/include/asm-i386/checksum.h and
 * linux/include/net/checksum.h from the Linux 2.6.8.1 kernel,
 * plus HIP checksum modifications.
 * 
 */

/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Checksumming functions for IP, TCP, UDP and so on
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Borrows very liberally from tcp.c and ip.c, see those
 *		files for more names.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _CHECKSUM_H
#define _CHECKSUM_H

#ifndef __WIN32__
#include <asm/types.h>
#include <endian.h>
#include <netinet/in.h>
#else
#include <win32/types.h>
#include <ws2tcpip.h>
#endif /* __WIN32__ */

#ifdef __WIN32__
/* Windows' ws2tcpip.h has struct in6_addr with __u8 and __u16 members,
 * but no __u32 as we need here for accumulation.
 */
struct my_in6_addr {
	__u32 s6_addr32[4];
};
#endif

/*
 * the following inlines are from linux/include/asm-i386/checksum.h
 */

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *
 *	By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *	Arnt Gulbrandsen.
 */
#ifdef __WIN32__
/* This isn't the 'fast' checksum, since the GCC inline ASM version is not 
 * available in Windows; this is the same code from hip_util.c */
static __inline unsigned short ip_fast_csum(unsigned char * iph,
					  unsigned int ihl)
{
	__u16 checksum;
	unsigned long sum = 0;
	int count = ihl*4;
	unsigned short *p = (unsigned short *)iph;

	/* 
	 * this checksum algorithm can be found 
	 * in RFC 1071 section 4.1
	 */

	/* one's complement sum 16-bit words of data */
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;
 
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */ 
	checksum = (__u16)(~sum);
    
	return(checksum);
}
#else
static inline unsigned short ip_fast_csum(unsigned char * iph,
					  unsigned int ihl)
{
	unsigned int sum;

	__asm__ __volatile__(
	    "movl (%1), %0	;\n"
	    "subl $4, %2	;\n"
	    "jbe 2f		;\n"
	    "addl 4(%1), %0	;\n"
	    "adcl 8(%1), %0	;\n"
	    "adcl 12(%1), %0	;\n"
"1:	    adcl 16(%1), %0	;\n"
	    "lea 4(%1), %1	;\n"
	    "decl %2		;\n"
	    "jne 1b		;\n"
	    "adcl $0, %0	;\n"
	    "movl %0, %2	;\n"
	    "shrl $16, %0	;\n"
	    "addw %w2, %w0	;\n"
	    "adcl $0, %0	;\n"
	    "notl %0		;\n"
"2:				;\n"
	/* Since the input registers which are loaded with iph and ipl
	   are modified, we must also specify them as outputs, or gcc
	   will assume they contain their original values. */
	: "=r" (sum), "=r" (iph), "=r" (ihl)
	: "1" (iph), "2" (ihl)
	: "memory");
	return(sum);
}
#endif

/*
 *	Fold a partial checksum
 */

#ifdef __WIN32__
static __inline unsigned int csum_fold(unsigned int sum)
{
	/* this is from hip_util.c - checksum_packet() */
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */ 
	return((__u16)~sum);
}
#else

static inline unsigned int csum_fold(unsigned int sum)
{
	__asm__(
		"addl %1, %0		;\n"
		"adcl $0xffff, %0	;\n"
		: "=r" (sum)
		: "r" (sum << 16), "0" (sum & 0xffff0000)
	);
	return (~sum) >> 16;
}
#endif

#ifdef __WIN32__
static __inline unsigned int csum_add(unsigned int csum, unsigned int addend);
static __inline unsigned long csum_tcpudp_nofold(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
	sum = csum_add(sum, saddr);
	sum = csum_add(sum, daddr);
	sum = csum_add(sum, (__u32)len);
	sum = csum_add(sum, (__u32)proto);
	return(sum);	
}
#else

static inline unsigned long csum_tcpudp_nofold(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    __asm__(
	"addl %1, %0	;\n"
	"adcl %2, %0	;\n"
	"adcl %3, %0	;\n"
	"adcl $0, %0	;\n"
	: "=r" (sum)
	: "g" (daddr), "g"(saddr), "g"((ntohs(len)<<16)+proto*256), "0"(sum));
    return sum;
}
#endif

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
#ifdef __WIN32__
static __inline unsigned short int csum_tcpudp_magic(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
#else
static inline unsigned short int csum_tcpudp_magic(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
#endif
{
	return csum_fold(csum_tcpudp_nofold(saddr,daddr,len,proto,sum));
}

#ifndef __WIN32__
#define _HAVE_ARCH_IPV6_CSUM
static __inline__ unsigned short int csum_ipv6_magic(struct in6_addr *saddr,
						     struct in6_addr *daddr,
						     __u32 len,
						     unsigned short proto,
						     unsigned int sum)
{
	__asm__(
		"addl 0(%1), %0		;\n"
		"adcl 4(%1), %0		;\n"
		"adcl 8(%1), %0		;\n"
		"adcl 12(%1), %0	;\n"
		"adcl 0(%2), %0		;\n"
		"adcl 4(%2), %0		;\n"
		"adcl 8(%2), %0		;\n"
		"adcl 12(%2), %0	;\n"
		"adcl %3, %0		;\n"
		"adcl %4, %0		;\n"
		"adcl $0, %0		;\n"
		: "=&r" (sum)
		: "r" (saddr), "r" (daddr),
		  "r"(htonl(len)), "r"(htonl(proto)), "0"(sum));

	return csum_fold(sum);
}
#endif

/*
 * the following inlines are from linux/include/net/checksum.h
 */

#ifdef __WIN32__
static __inline unsigned int csum_add(unsigned int csum, unsigned int addend)
#else
static inline unsigned int csum_add(unsigned int csum, unsigned int addend)
#endif
{
	csum += addend;
	return csum + (csum < addend);
}

#ifdef __WIN32__
static __inline unsigned int csum_sub(unsigned int csum, unsigned int addend)
#else
static inline unsigned int csum_sub(unsigned int csum, unsigned int addend)
#endif
{
	return csum_add(csum, ~addend);
}

/* 
 * HIP checksum = tcp checksum + hitMagic - csum(saddr,daddr)
 */
#ifdef __WIN32__
static __inline unsigned short csum_tcpudp_hip_nofold(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short sum,
						   unsigned short  hitMagic)
#else
static inline unsigned short csum_tcpudp_hip_nofold(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short sum,
						   unsigned short  hitMagic)
#endif
{
	/* sum is assumed to be the folded complement, so get the sum back */
	unsigned short ret = ~sum;

	ret = ~csum_fold(csum_add(ret, hitMagic));
	ret = csum_fold(csum_sub(ret,~csum_fold(csum_add(saddr,daddr))));

	return ret;
}

#ifdef __WIN32__
static __inline unsigned short csum_hip_revert(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short sum,
						   unsigned short  hitMagic)
#else
static inline unsigned short csum_hip_revert(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short sum,
						   unsigned short  hitMagic)
#endif
{
	/* sum is assumed to be the folded complement, so get the sum back */
	unsigned short ret = ~sum;

	ret = ~csum_fold(csum_sub(ret, hitMagic));
	ret = csum_fold(csum_add(ret,~csum_fold(csum_add(saddr,daddr))));
	return ret;
}

/* 
 * HIP checksum = tcp checksum + hitMagic - csum(saddr,daddr)
 */
#ifdef __WIN32__
static __inline unsigned short csum_tcpudp_hip_nofold6(struct in6_addr *saddr1,
						     struct in6_addr *daddr1,
						     unsigned short sum,
						     unsigned short  hitMagic)
{
	int carry;
	unsigned int csum;
	/* sum is assumed to be the folded complement, so get the sum back */
	unsigned short ret = ~sum;
	
	/* Re-cast the struct since Windows has no 32-bit struct member. */
	struct my_in6_addr *saddr = (struct my_in6_addr*)saddr1;
	struct my_in6_addr *daddr = (struct my_in6_addr*)daddr1;

	/* First, sum saddr and daddr as done in csum_ipv6_magic() */
	csum = saddr->s6_addr32[0];
	carry = (csum < saddr->s6_addr32[0]);
	csum += carry;

	csum += saddr->s6_addr32[1];
	carry = (csum < saddr->s6_addr32[1]);
	csum += carry;

	csum += saddr->s6_addr32[2];
	carry = (csum < saddr->s6_addr32[2]);
	csum += carry;

	csum += saddr->s6_addr32[3];
	carry = (csum < saddr->s6_addr32[3]);
	csum += carry;

	csum += daddr->s6_addr32[0];
	carry = (csum < daddr->s6_addr32[0]);
	csum += carry;

	csum += daddr->s6_addr32[1];
	carry = (csum < daddr->s6_addr32[1]);
	csum += carry;

	csum += daddr->s6_addr32[2];
	carry = (csum < daddr->s6_addr32[2]);
	csum += carry;

	csum += daddr->s6_addr32[3];
	carry = (csum < daddr->s6_addr32[3]);
	csum += carry;

	/* Next, add in the hitMagic and subtract saddr+daddr */
	ret = ~csum_fold(csum_add(ret, hitMagic));
	ret = csum_fold(csum_sub(ret,~csum_fold(csum)));

	return ret;

}
#else

static inline unsigned short csum_tcpudp_hip_nofold6(struct in6_addr *saddr,
						     struct in6_addr *daddr,
						     unsigned short sum,
						     unsigned short  hitMagic)
{
	int carry;
	unsigned int csum;
	/* sum is assumed to be the folded complement, so get the sum back */
	unsigned short ret = ~sum;
	
	/* First, sum saddr and daddr as done in csum_ipv6_magic() */
#ifdef __CYGWIN__
	csum = saddr->__u6_addr.__u6_addr32[0];
	carry = (csum < saddr->__u6_addr.__u6_addr32[0]);
	csum += carry;

	csum += saddr->__u6_addr.__u6_addr32[1];
	carry = (csum < saddr->__u6_addr.__u6_addr32[1]);
	csum += carry;

	csum += saddr->__u6_addr.__u6_addr32[2];
	carry = (csum < saddr->__u6_addr.__u6_addr32[2]);
	csum += carry;

	csum += saddr->__u6_addr.__u6_addr32[3];
	carry = (csum < saddr->__u6_addr.__u6_addr32[3]);
	csum += carry;

	csum += daddr->__u6_addr.__u6_addr32[0];
	carry = (csum < daddr->__u6_addr.__u6_addr32[0]);
	csum += carry;

	csum += daddr->__u6_addr.__u6_addr32[1];
	carry = (csum < daddr->__u6_addr.__u6_addr32[1]);
	csum += carry;

	csum += daddr->__u6_addr.__u6_addr32[2];
	carry = (csum < daddr->__u6_addr.__u6_addr32[2]);
	csum += carry;

	csum += daddr->__u6_addr.__u6_addr32[3];
	carry = (csum < daddr->__u6_addr.__u6_addr32[3]);
	csum += carry;
#else
	csum = saddr->s6_addr32[0];
	carry = (csum < saddr->s6_addr32[0]);
	csum += carry;

	csum += saddr->s6_addr32[1];
	carry = (csum < saddr->s6_addr32[1]);
	csum += carry;

	csum += saddr->s6_addr32[2];
	carry = (csum < saddr->s6_addr32[2]);
	csum += carry;

	csum += saddr->s6_addr32[3];
	carry = (csum < saddr->s6_addr32[3]);
	csum += carry;

	csum += daddr->s6_addr32[0];
	carry = (csum < daddr->s6_addr32[0]);
	csum += carry;

	csum += daddr->s6_addr32[1];
	carry = (csum < daddr->s6_addr32[1]);
	csum += carry;

	csum += daddr->s6_addr32[2];
	carry = (csum < daddr->s6_addr32[2]);
	csum += carry;

	csum += daddr->s6_addr32[3];
	carry = (csum < daddr->s6_addr32[3]);
	csum += carry;
#endif

	/* Next, add in the hitMagic and subtract saddr+daddr */
	ret = ~csum_fold(csum_add(ret, hitMagic));
	ret = csum_fold(csum_sub(ret,~csum_fold(csum)));

	return ret;
}
#endif

#ifdef __WIN32__
static __inline unsigned short csum_hip_revert6(struct in6_addr *saddr1,
						   struct in6_addr *daddr1,
						   unsigned short sum,
						   unsigned short  hitMagic)
{
	int carry;
	unsigned int csum;
	/* sum is assumed to be the folded complement, so get the sum back */
	unsigned short ret = ~sum;

	/* Re-cast the struct since Windows has no 32-bit struct member. */
	struct my_in6_addr *saddr = (struct my_in6_addr*)saddr1;
	struct my_in6_addr *daddr = (struct my_in6_addr*)daddr1;
	
	/* First, sum saddr and daddr as done in csum_ipv6_magic() */
	csum = saddr->s6_addr32[0];
	carry = (csum < saddr->s6_addr32[0]);
	csum += carry;

	csum += saddr->s6_addr32[1];
	carry = (csum < saddr->s6_addr32[1]);
	csum += carry;

	csum += saddr->s6_addr32[2];
	carry = (csum < saddr->s6_addr32[2]);
	csum += carry;

	csum += saddr->s6_addr32[3];
	carry = (csum < saddr->s6_addr32[3]);
	csum += carry;

	csum += daddr->s6_addr32[0];
	carry = (csum < daddr->s6_addr32[0]);
	csum += carry;

	csum += daddr->s6_addr32[1];
	carry = (csum < daddr->s6_addr32[1]);
	csum += carry;

	csum += daddr->s6_addr32[2];
	carry = (csum < daddr->s6_addr32[2]);
	csum += carry;

	csum += daddr->s6_addr32[3];
	carry = (csum < daddr->s6_addr32[3]);
	csum += carry;

	/* Next, subtract hitMagic and add saddr+daddr */
	ret = ~csum_fold(csum_sub(ret, hitMagic));
	ret = csum_fold(csum_add(ret,~csum_fold(csum)));
	return ret;
}

#else
static inline unsigned short csum_hip_revert6(struct in6_addr *saddr,
						   struct in6_addr *daddr,
						   unsigned short sum,
						   unsigned short  hitMagic)
{
	int carry;
	unsigned int csum;
	/* sum is assumed to be the folded complement, so get the sum back */
	unsigned short ret = ~sum;
	
	/* First, sum saddr and daddr as done in csum_ipv6_magic() */
#ifdef __CYGWIN__
	csum = saddr->__u6_addr.__u6_addr32[0];
	carry = (csum < saddr->__u6_addr.__u6_addr32[0]);
	csum += carry;

	csum += saddr->__u6_addr.__u6_addr32[1];
	carry = (csum < saddr->__u6_addr.__u6_addr32[1]);
	csum += carry;

	csum += saddr->__u6_addr.__u6_addr32[2];
	carry = (csum < saddr->__u6_addr.__u6_addr32[2]);
	csum += carry;

	csum += saddr->__u6_addr.__u6_addr32[3];
	carry = (csum < saddr->__u6_addr.__u6_addr32[3]);
	csum += carry;

	csum += daddr->__u6_addr.__u6_addr32[0];
	carry = (csum < daddr->__u6_addr.__u6_addr32[0]);
	csum += carry;

	csum += daddr->__u6_addr.__u6_addr32[1];
	carry = (csum < daddr->__u6_addr.__u6_addr32[1]);
	csum += carry;

	csum += daddr->__u6_addr.__u6_addr32[2];
	carry = (csum < daddr->__u6_addr.__u6_addr32[2]);
	csum += carry;

	csum += daddr->__u6_addr.__u6_addr32[3];
	carry = (csum < daddr->__u6_addr.__u6_addr32[3]);
	csum += carry;
#else
	csum = saddr->s6_addr32[0];
	carry = (csum < saddr->s6_addr32[0]);
	csum += carry;

	csum += saddr->s6_addr32[1];
	carry = (csum < saddr->s6_addr32[1]);
	csum += carry;

	csum += saddr->s6_addr32[2];
	carry = (csum < saddr->s6_addr32[2]);
	csum += carry;

	csum += saddr->s6_addr32[3];
	carry = (csum < saddr->s6_addr32[3]);
	csum += carry;

	csum += daddr->s6_addr32[0];
	carry = (csum < daddr->s6_addr32[0]);
	csum += carry;

	csum += daddr->s6_addr32[1];
	carry = (csum < daddr->s6_addr32[1]);
	csum += carry;

	csum += daddr->s6_addr32[2];
	carry = (csum < daddr->s6_addr32[2]);
	csum += carry;

	csum += daddr->s6_addr32[3];
	carry = (csum < daddr->s6_addr32[3]);
	csum += carry;
#endif

	/* Next, subtract hitMagic and add saddr+daddr */
	ret = ~csum_fold(csum_sub(ret, hitMagic));
	ret = csum_fold(csum_add(ret,~csum_fold(csum)));
	return ret;
}
#endif

#endif
