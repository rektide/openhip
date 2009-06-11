/*
 * Host Identity Protocol
 * Copyright (C) 2002-04 The Boeing Company
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
 *  listen.c 
 *
 *  Author:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *  
 * Listens for PF_KEY messages and prints their field values.
 *
 */

#include <stdio.h>       	/* stderr, etc                  */
#include <stdlib.h>		/* rand()			*/
#include <errno.h>       	/* strerror(), errno            */
#include <string.h>      	/* memset()                     */
#include <time.h>		/* time()			*/
#include <ctype.h>		/* tolower()                    */
#include <arpa/inet.h>		/* inet_addr() 			*/
#include <sys/socket.h>  	/* sock(), recvmsg(), etc       */
#include <sys/types.h>		/* getpid() support, etc        */
#include <unistd.h>		/* getpid()			*/
#include <netinet/in.h>  	/* struct sockaddr_in, etc      */

//#include <linux/ipsec.h>
#include "/usr/src/linux/include/linux/pfkeyv2.h"		/* PF_KEY_V2 support 		*/
#include "hip.h"

#define IPSEC_PFKEYv2_ALIGN (sizeof(uint64_t) / sizeof(uint8_t))

/* local functions */
char * ip_to_s(__u32 ip);
int print_address(char* buff, struct sadb_address* addr);
int print_sa(char* buff, struct sadb_sa* sa);


int main(int argc, char *argv[])
{
    int s_pfk;
    fd_set read_fdset;
    fd_set excp_fdset;
    struct timeval timeout;
    
    struct msghdr msg;
    struct iovec iov;
    struct sockaddr_in addr;
    
    char buff[2048];
    char obuff[1024];

    int buff_len = sizeof(buff);
    
    int err=0;
  
    printf("== %s started ==\n",argv[0]);

    /* create required sockets */
    {
	addr.sin_family = AF_INET;
	/*
	addr.sin_port   = htons(H_PORT);
	*/
    	addr.sin_addr.s_addr = htonl(INADDR_ANY);
    	
	s_pfk = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    	if (s_pfk < 0){
	    fprintf(stderr, "socket() failed, maybe you need FreeS/WAN's KLIPS?\n");
    	    fprintf(stderr, "%s.\n", strerror(errno));
	    return(-1);
    	}
    }

    /* register PF_KEY types with kernel */
    {
	err = sadb_register_old(s_pfk, SADB_SATYPE_ESP);
	if (err > 0) {
	    printf("Registered PF_KEY ESP type with kernel.\n");
	}
    }

    /* setup message header with control and receive buffers */
    {
    	msg.msg_name = 0L;
   	msg.msg_namelen = 0;
    	msg.msg_iov = &iov;
    	msg.msg_iovlen = 1;
    	msg.msg_flags = 0;
    	memset(buff, 0, buff_len);
    	iov.iov_len = buff_len;
    	iov.iov_base = buff;
    }
 

    printf("Listening...\n");

    /*
     * main event loop 
     */
    while (1) {

	/* prepare file descriptor sets */
	{
	    FD_ZERO(&read_fdset);
	    FD_SET(s_pfk, &read_fdset);
	    FD_SET(s_pfk, &excp_fdset);
	    timeout.tv_sec = 1;
	    timeout.tv_usec = 0;
	}
	
	err = select(s_pfk+1, &read_fdset, NULL, &excp_fdset, &timeout);
	
	/* error */
	if (err < 0) {
	    fprintf(stderr, "select() error: %s.\n", strerror(errno));
	}
	/* select() timeout */
	else if (err == 0) {
	    //printf(".");
	}
	/* socket activity */
	else {
	    
	    /*
	     * PF_KEY messages 
	     */
	    if (FD_ISSET(s_pfk, &read_fdset)) {
    		struct sadb_msg *pfkey_msg;
		struct sadb_ext *pfkey_ext;
		struct sockaddr *src, *dst;
		int buffi=0;
		int l;
	  
	        src = dst = NULL;	

		err = read(s_pfk, buff, sizeof(buff));
		if (err < 0) {
		    fprintf(stderr, "PFKEY read() error - %d %s\n", errno, strerror(errno));
		}
		else { /* if (err < 0) */
		    printf("\n");
		    pfkey_msg = (struct sadb_msg *)&buff[0];

		    switch(pfkey_msg->sadb_msg_type) {
			case SADB_ACQUIRE:
			    printf("< SADB_ACQUIRE >\n");
			    break;
			    
			case SADB_GETSPI:
			    printf("< SADB_GETSPI >\n");
			    break;
			
			case SADB_UPDATE:
			    printf("< SADB_UPDATE >\n");
			    break;    
			    
			case SADB_RESERVED:
			    printf("< SADB_RESERVED >\n");
			    break;    
			case SADB_ADD:
			    printf("< SADB_ADD >\n");
			    break;    
			case SADB_DELETE:
			    printf("< SADB_DELETE >\n");
			    break;    
			case SADB_GET:
			    printf("< SADB_GET >\n");
			    break;    
			case SADB_REGISTER:
			    printf("< SADB_REGISTER >\n");
			    break;    
			case SADB_EXPIRE:
			    printf("< SADB_EXPIRE >\n");
			    break;    
			case SADB_FLUSH:
			    printf("< SADB_FLUSH >\n");
			    break;    
			case SADB_DUMP:
			    printf("< SADB_DUMP >\n");
			    break;    
			case SADB_X_PROMISC:
			    printf("< SADB_X_PROMISC >\n");
			    break;    
			case SADB_X_PCHANGE:
			    printf("< SADB_X_PCHANGE >\n");
			    break;    
			case SADB_X_SPDUPDATE:
			    printf("< SADB_X_SPDUPDATE >\n");
			    break;    
			case SADB_X_SPDADD:
			    printf("< SADB_X_SPDADD >\n");
			    break;    
			case SADB_X_SPDDELETE:
			    printf("< SADB_X_SPDDELETE >\n");
			    break;    
			case SADB_X_SPDGET:
			    printf("< SADB_X_SPDGET >\n");
			    break;    
			case SADB_X_SPDACQUIRE:
			    printf("< SADB_X_SPDACQUIRE >\n");
			    break;    
			case SADB_X_SPDDUMP:
			    printf("< SADB_X_SPDDUMP >\n");
			    break;    
			case SADB_X_SPDFLUSH:
			    printf("< SADB_X_SPDFLUSH >\n");
			    break;    
			case SADB_X_SPDSETIDX:
			    printf("< SADB_X_SPDSETIDX >\n");
			    break;    
			case SADB_X_SPDEXPIRE:
			    printf("< SADB_X_SPDEXPIRE >\n");
			    break;    
			case SADB_X_SPDDELETE2:
			    printf("< SADB_X_SPDDELETE2 >\n");
			    break;    
			case SADB_X_NAT_T_NEW_MAPPING:
			    printf("< SADB_X_NAT_T_NEW_MAPPING >\n");
			    break;    

			default:
			    printf("Got an uknown PFKEY message type (%d).\n",
			           pfkey_msg->sadb_msg_type);
			    break;
		    } 
		    buffi = sizeof(struct sadb_msg);
		    l = 0;
		    printf("<base");
		    
		    while(buffi < err) {
			pfkey_ext = (struct sadb_ext*) &buff[buffi];
			switch(pfkey_ext->sadb_ext_type) {
			    case SADB_EXT_RESERVED:
			    printf(",resrv");
			    break;
			case SADB_EXT_SA:
			    l += print_sa(&obuff[l], (struct sadb_sa*)pfkey_ext);
			    printf(",SA");
			    break;
			case SADB_EXT_LIFETIME_CURRENT:
			    printf(",lifeC");
			    break;
			case SADB_EXT_LIFETIME_HARD:
			    printf(",lifeH");
			    break;
			case SADB_EXT_LIFETIME_SOFT:
			    printf(",lifeS");
			    break;
			case SADB_EXT_ADDRESS_SRC:
			    l += print_address(&obuff[l], (struct sadb_address*)pfkey_ext);
			    printf(",address_S");
			    break;
			case SADB_EXT_ADDRESS_DST:
			    l += print_address(&obuff[l], (struct sadb_address*)pfkey_ext);
			    printf(",address_D");
			    break;
			case SADB_EXT_ADDRESS_PROXY:
			    printf(",address_P");
			    break;
			case SADB_EXT_KEY_AUTH:
			    printf(",key_A");
			    break;
			case SADB_EXT_KEY_ENCRYPT:
			    printf(",key_E");
			    break;
    			case SADB_EXT_IDENTITY_SRC:
			    printf(",ident_S");
			    break;
			case SADB_EXT_IDENTITY_DST:
			    printf(",ident_D");
			    break;
			case SADB_EXT_SENSITIVITY:
			    printf(",sensitivity");
			    break;
			case SADB_EXT_PROPOSAL:
			    printf(",proposal");
			    break;
			case SADB_EXT_SUPPORTED_AUTH:
			    printf(",supported_auth");
			    break;
			case SADB_EXT_SUPPORTED_ENCRYPT:
			    printf(",supported_encrypt");
			    break;
			case SADB_EXT_SPIRANGE:
			    printf(",spirange");
			    break;
			case SADB_X_EXT_KMPRIVATE:
			    printf(",x_kmprivate");
			    break;
			case SADB_X_EXT_SA2:
			    printf(",x_SA2");
			    break;
			case SADB_X_EXT_POLICY:
			    printf(",x_POLICY");
			    break;
			case SADB_X_EXT_NAT_T_TYPE:
			    printf(",_X_EXT_NAT_T_TYPE");
			    break;
			case SADB_X_EXT_NAT_T_SPORT:
			    printf(",x_EXT_NAT_T_SPORT");
			    break;
			case SADB_X_EXT_NAT_T_DPORT:
			    printf(",x_EXT_NAT_T_DPORT");
			    break;
			case SADB_X_EXT_NAT_T_OA:
			    printf(",x_EXT_NAT_T_OA");
			    break;
			default:
			    printf(",(unk %d)", pfkey_ext->sadb_ext_type);
			    break;

			} /* ebd switch */
			    buffi += pfkey_ext->sadb_ext_len * IPSEC_PFKEYv2_ALIGN;
		    } /* end while */
	  	    printf(">\n");

		    printf("(ver=%d ", pfkey_msg->sadb_msg_version);
		    printf("type=%d ", pfkey_msg->sadb_msg_type);
		    printf("errno=%d ", pfkey_msg->sadb_msg_errno);
		    printf("satype=%d ", pfkey_msg->sadb_msg_satype);
		    printf("len=%d ", pfkey_msg->sadb_msg_len);
		    printf("reserved=%d ", pfkey_msg->sadb_msg_reserved);
		    printf("seq=%d ", pfkey_msg->sadb_msg_seq);
		    printf("pid=%d)\n", pfkey_msg->sadb_msg_pid);
		    if (l > 0) {
			l = 0;
	                printf("%s\n", obuff);
		        memset(obuff, 0, l);
		    }

		    memset(buff, 0, err);

			
		 } /* end if err */

		
	    } /* end if FDSET */
	    
	    /*
	     * unknown (exception)
	     */
	    else {
		/* TODO: handle exceptions from excp_fdset here */
		printf("unknown socket activity.");
	    }
	    
	}
	
    } /* end while(1) */

    return(0);

}


/*
 *
 * function ip_to_s()
 *
 * turn an unsigned 32-bit IP address into a string
 * (dotted-decimal notation)
 * 
 */
char * ip_to_s(__u32 ip)
{
    static char sIP[16];
    memset(sIP, 0, sizeof(sIP));
    sprintf(sIP, "%d.%d.%d.%d", 
		((ip >> 0)& 0xFF), ((ip >> 8)& 0xFF),
		((ip >> 16)& 0xFF),((ip >> 24)& 0xFF) ); 
    return sIP;
}

int sadb_verify(char *data, int num)
{
    struct sadb_ext *ext;
    ext = (struct sadb_ext*) &data[sizeof(struct sadb_msg)];
    
    while (num) {
	if (ext->sadb_ext_type == 0) break;
	printf("(%d)", ext->sadb_ext_type);
	ext = (struct sadb_ext *)((char *)ext + (ext->sadb_ext_len * IPSEC_PFKEYv2_ALIGN));
	num--;
    }
    printf("\n");
    return(0);

}

/*
 *
 * function sadb_register_old()
 *
 * in:		s_pfk =	an open PF_KEYv2 socket
 * 		satype = type of SA to listen for
 *
 * out:		returns success or failure
 *
 * sends PF_KEYv2 messages to the kernel, validates the reponse if necessary
 * 
 *
 */

int sadb_register_old(int s_pfk, int satype)
{
    static int pfk_seqno = 0;
    pid_t pid = getpid();
    struct sadb_msg pfkey_msgh;
    struct sadb_msg *pfkey_msg;
    int len, err=0;
    char rbuff[20];

    memset(&pfkey_msgh, 0, sizeof(struct sadb_msg));

    {	
 	/* register PF_KEY types with kernel */
	/* build the PF_KEY message */
        pfkey_msgh.sadb_msg_version = PF_KEY_V2;
	pfkey_msgh.sadb_msg_type = SADB_REGISTER; 
	pfkey_msgh.sadb_msg_errno = 0;
 	pfkey_msgh.sadb_msg_satype = satype;
	pfkey_msgh.sadb_msg_len = sizeof(struct sadb_msg) / IPSEC_PFKEYv2_ALIGN;
  	pfkey_msgh.sadb_msg_reserved = 0;
  	pfkey_msgh.sadb_msg_seq = ++pfk_seqno;
	pfkey_msgh.sadb_msg_pid = pid;
	len = sizeof(pfkey_msgh);
    }

    /* send SADB_REGISTER message to the kernel */
    err = write(s_pfk, &pfkey_msgh, len);
    if (err < 1){
        fprintf(stderr, "pfkey write() error: %s.\n", strerror(errno));
    }
	    
    /* note: select does not work here */
    /* read kernel response*/
    memset(rbuff, 0, sizeof(rbuff));
    err = read(s_pfk, rbuff, sizeof(rbuff));
    if (err < 0) {
        fprintf(stderr, "PF_KEY read() error: %s.\n", strerror(errno));
        return(-1);
    }
	
    /* verify response */    
    {
        pfkey_msg = (struct sadb_msg*)rbuff;
	if ((pfkey_msg->sadb_msg_version == 2) &&
	    (pfkey_msg->sadb_msg_type == SADB_REGISTER) &&
	    (pfkey_msg->sadb_msg_errno == 0) &&
	    (pfkey_msg->sadb_msg_satype == satype) &&
	    (pfkey_msg->sadb_msg_seq == pfk_seqno)){
	    /* TODO: if needed, insert more validation here */
	    /* may want to check pid */
	    /* may want to keep reading if seqno doesn't match */
	    return(err);
	}
	else {
	    fprintf(stderr, "Got invalid SADB_REGISTER back from kernel!\n");
	    return(-1);
	}
    }
    return(err);
    
}

int print_address(char* buff, struct sadb_address* addr) {
    char s[100];
    int len;
    char ip_string[INET6_ADDRSTRLEN];
    struct sockaddr *saddr;

    memset(s, 0, sizeof(s));

    saddr = (struct sockaddr*)((char*)addr + sizeof(struct sadb_address));
    inet_ntop(saddr->sa_family, SA2IP(saddr), ip_string, INET6_ADDRSTRLEN);

    sprintf(s, "(len=%d exttype=%d proto=%d prefixlen=%d reserved=%d fam=%d addr=%s)\n",
            addr->sadb_address_len,
	    addr->sadb_address_exttype,
	    addr->sadb_address_proto,
	    addr->sadb_address_prefixlen,
	    addr->sadb_address_reserved,
	    saddr->sa_family,
	    ip_string);

    len = strlen(s);
    memcpy(buff, s, len);

    return len;
}

int print_sa(char* buff, struct sadb_sa* sa) {

    char s[100];
    int len;

    sprintf(s, "(len=%d exttype=%d SA=%08x replay=%d state=%d auth=%d encrypt=%d flags=%d)\n",
	    sa->sadb_sa_len,
	    sa->sadb_sa_exttype,
            sa->sadb_sa_spi,
	    sa->sadb_sa_replay,
	    sa->sadb_sa_state,
	    sa->sadb_sa_auth,
	    sa->sadb_sa_encrypt,
	    sa->sadb_sa_flags);

    len = strlen(s);
    memcpy(buff, s, len);
    
    return len;
}
