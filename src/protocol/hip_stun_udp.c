/*
 * Host Identity Protocol
 * 
 *  STUN client based on the code provided by Vovida Networks, Inc.
 *  (see end of file)
 *  Translated from C++ code to C code by Vivien Schmitt
 *
 *  hip_stun_udp.c
 *
 * Author : Vivien Schmitt, <schmitt@netlab.nec.de>
 *
 * STUN client used for NAT detection
 *
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#ifdef __WIN32__
#include <win32/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <win32/ip.h>
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#endif /* __WIN32__ */
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include <hip/hip_stun_udp.h>

#ifdef __WIN32__
#define EADDRINUSE	WSAEADDRINUSE
#define EADDRNOTAVAIL	WSAEADDRNOTAVAIL
#define ENOTSOCK	WSAENOTSOCK
#define ECONNRESET	WSAECONNRESET
#define ECONNREFUSED	WSAECONNREFUSED
#define EHOSTDOWN	WSAEHOSTDOWN
#define EHOSTUNREACH	WSAEHOSTUNREACH
#define EAFNOSUPPORT	WSAEAFNOSUPPORT

#else
int closesocket( int fd ) { return close(fd); };
#endif

int getErrno() { return errno; }


int
openPort( unsigned short port, unsigned int interfaceIp, int verbose )
{
   int fd;
   struct sockaddr_in addr;
    
   fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if ( fd == INVALID_SOCKET )
   {
      int err = getErrno();
      fprintf (stderr, "Could not create a UDP socket: %u \n", err);
      return INVALID_SOCKET;
   }
    
   memset((char*) &(addr),0, sizeof((addr)));
   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = htonl(INADDR_ANY);
   addr.sin_port = htons(port);
    
   if ( (interfaceIp != 0) && 
        ( interfaceIp != 0x100007f ) )
   {
      addr.sin_addr.s_addr = htonl(interfaceIp);
      if (verbose )
      {
         printf ("Binding to interface 0x%x\n", htonl(interfaceIp));
      }
   }
	
   if ( bind( fd,(struct sockaddr*)&addr, sizeof(addr)) != 0 )
   {
      int e = getErrno();
        
      switch (e)
      {
         case 0:
         {
            fprintf (stderr, "Could not bind socket\n");
            return INVALID_SOCKET;
         }
         case EADDRINUSE:
         {
            fprintf(stderr, "Port %u for receiving UDP is in use\n", port);
            return INVALID_SOCKET;
         }
         break;
         case EADDRNOTAVAIL:
         {
            if ( verbose ) 
            {
               fprintf (stderr, "Cannot assign requested address\n");
            }
            return INVALID_SOCKET;
         }
         break;
         default:
         {
            fprintf ( stderr, "Could not bind UDP receive port. Error=%u %s\n",
			e, strerror(e));
            return INVALID_SOCKET;
         }
         break;
      }
   }
   if ( verbose )
   {
      printf("Opened port %u with fd %u\n", port, fd);
   }
   
   assert( fd != INVALID_SOCKET  );
	
   return fd;
}


int 
getMessage( int fd, char* buf, int* len,
            unsigned int* srcIp, unsigned short* srcPort,
            int verbose)
{
   int originalSize = *len;
   struct sockaddr_in from;
   int fromLen;

   assert( fd != INVALID_SOCKET );
   assert( originalSize > 0 );
   
   fromLen = sizeof(from);
	
   *len = recvfrom(fd,
                   buf,
                   originalSize,
                   0,
                   (struct sockaddr *)&from,
                   (socklen_t*)&fromLen);
	
   if ( *len == SOCKET_ERROR )
   {
      int err = getErrno();
		
      switch (err)
      {
         case ENOTSOCK:
            fprintf (stderr, "Error fd not a socket\n");
            break;
         case ECONNRESET:
            fprintf (stderr, "Error connection reset - host not reachable\n");
            break;
				
         default:
            fprintf(stderr, "Socket Error= %u\n", err);
      }
		
      return FALSE;
   }
	
   if ( *len < 0 )
   {
      printf("socket closed? negative len\n");
      return FALSE;
   }
    
   if ( *len == 0 )
   {
      printf("socket closed? zero len\n");
      return FALSE;
   }
    
   *srcPort = ntohs(from.sin_port);
   *srcIp = ntohl(from.sin_addr.s_addr);
	
   if ( (*len)+1 >= originalSize )
   {
      if (verbose)
      {
         printf("Received a message that was too large\n");
      }
      return FALSE;
   }
   buf[*len]=0;
    
   return TRUE;
}


int 
sendMessage( int fd, char* buf, int l, 
             unsigned int dstIp, unsigned short dstPort,
             int verbose)
{
   struct sockaddr_in to;
   int toLen;
   int s, e;
   assert( fd != INVALID_SOCKET );
    
   if ( dstPort == 0 )
   {
      /* sending on a connected port */
      assert( dstIp == 0 );
		
      s = send(fd,buf,l,0);
   }
   else
   {
      assert( dstIp != 0 );
      assert( dstPort != 0 );
        
      toLen = sizeof(to);
      memset(&to,0,toLen);
        
      to.sin_family = AF_INET;
      to.sin_port = htons(dstPort);
      to.sin_addr.s_addr = htonl(dstIp);
        
      s = sendto(fd, buf, l, 0,(struct sockaddr*)&to, toLen);
   }
    
   if ( s == SOCKET_ERROR )
   {
      e = getErrno();
      switch (e)
      {
         case ECONNREFUSED:
         case EHOSTDOWN:
         case EHOSTUNREACH:
         {
            /* quietly ignore this */
         }
         break;
         case EAFNOSUPPORT:
         {
            fprintf(stderr, "err EAFNOSUPPORT in send\n");
         }
         break;
         default:
         {
            fprintf(stderr, "err %u %s in send.\n", e, strerror(e) );
         }
      }
      return FALSE;
   }
    
   if ( s == 0 )
   {
      fprintf(stderr, "no data sent in send\n");
      return FALSE;
   }
    
   if ( s != l )
   {
      if (verbose)
      {
         fprintf(stderr, "only %u out of %u bytes sent\n", s, l);
      }
      return FALSE;
   }
    
   return TRUE;
}



/* ====================================================================
 * The Vovida Software License, Version 1.0 
 * 
 * Copyright (c) 2000 Vovida Networks, Inc.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * 3. The names "VOCAL", "Vovida Open Communication Application Library",
 *    and "Vovida Open Communication Application Library (VOCAL)" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact vocal@vovida.org.
 *
 * 4. Products derived from this software may not be called "VOCAL", nor
 *    may "VOCAL" appear in their name, without prior written
 *    permission of Vovida Networks, Inc.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL VOVIDA
 * NETWORKS, INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT DAMAGES
 * IN EXCESS OF $1,000, NOR FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * 
 * ====================================================================
 * 
 * This software consists of voluntary contributions made by Vovida
 * Networks, Inc. and many individuals on behalf of Vovida Networks,
 * Inc.  For more information on Vovida Networks, Inc., please see
 * <http://www.vovida.org/>.
 *
 */
