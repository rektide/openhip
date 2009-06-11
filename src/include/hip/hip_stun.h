/*
 * Host Identity Protocol
 * 
 *  STUN client based on the code provided by Vovida Networks, Inc.
 *  (see end of file)
 *  Translated from C++ code to C code by Vivien Schmitt
 *
 *  hip_stun.h
 *
 * Author : Vivien Schmitt, <schmitt@netlab.nec.de>
 *
 * STUN client used for NAT detection
 *
 */




#ifndef STUN_H
#define STUN_H

#include <time.h>
#include "hip_stun_udp.h"

#define TRUE 1
#define FALSE 0

/* if you change this version, change in makefile too */
#define STUN_VERSION "0.96"

#define STUN_MAX_STRING 256
#define STUN_MAX_UNKNOWN_ATTRIBUTES 8
#define STUN_MAX_MESSAGE_SIZE 2048

#define STUN_PORT 3478

/* define some basic types*/
typedef unsigned char  UInt8;
typedef unsigned short UInt16;
typedef unsigned int   UInt32;
#ifdef __WIN32__
typedef __u64 UInt64;
#else
typedef unsigned long long UInt64;
#endif /* __WIN32__ */
typedef struct { unsigned char octet[16]; }  UInt128;

/*/ define a structure to hold a stun address */
extern UInt8  IPv4Family;
extern UInt8  IPv6Family;

/* define  flags  */
extern UInt32 ChangeIpFlag;
extern UInt32 ChangePortFlag;

/* define  stun attribute*/
extern UInt16 MappedAddress;
extern UInt16 ResponseAddress;
extern UInt16 ChangeRequest;
extern UInt16 SourceAddress;
extern UInt16 ChangedAddress;
extern UInt16 Username;
extern UInt16 Password;
extern UInt16 MessageIntegrity;
extern UInt16 ErrorCode;
extern UInt16 UnknownAttribute;
extern UInt16 ReflectedFrom;
extern UInt16 XorMappedAddress;
extern UInt16 XorOnly;
extern UInt16 ServerName;
extern UInt16 SecondaryAddress; /* Non standard extention*/

/* define types for a stun message */
extern UInt16 BindRequestMsg;
extern UInt16 BindResponseMsg;
extern UInt16 BindErrorResponseMsg;
extern UInt16 SharedSecretRequestMsg;
extern UInt16 SharedSecretResponseMsg;
extern UInt16 SharedSecretErrorResponseMsg;

typedef struct 
{
      UInt16 msgType;
      UInt16 msgLength;
      UInt128 id;
} StunMsgHdr;


typedef struct
{
      UInt16 type;
      UInt16 length;
} StunAtrHdr;

typedef struct
{
      UInt16 port;
      UInt32 addr;
} StunAddress4;

typedef struct
{
      UInt8 pad;
      UInt8 family;
      StunAddress4 ipv4;
} StunAtrAddress4;

typedef struct
{
      UInt32 value;
} StunAtrChangeRequest;

typedef struct
{
      UInt16 pad; /* all 0*/
      UInt8 errorClass;
      UInt8 number;
      char reason[STUN_MAX_STRING];
      UInt16 sizeReason;
} StunAtrError;

typedef struct
{
      UInt16 attrType[STUN_MAX_UNKNOWN_ATTRIBUTES];
      UInt16 numAttributes;
} StunAtrUnknown;

typedef struct
{
      char value[STUN_MAX_STRING];      
      UInt16 sizeValue;
} StunAtrString;

typedef struct
{
      char hash[20];
} StunAtrIntegrity;

typedef enum 
{
   HmacUnkown=0,
   HmacOK,
   HmacBadUserName,
   HmacUnkownUserName,
   HmacFailed,
} StunHmacStatus;

typedef struct
{
      StunMsgHdr msgHdr;
	
      int hasMappedAddress;
      StunAtrAddress4  mappedAddress;
	
      int hasResponseAddress;
      StunAtrAddress4  responseAddress;
	
      int hasChangeRequest;
      StunAtrChangeRequest changeRequest;
	
      int hasSourceAddress;
      StunAtrAddress4 sourceAddress;
	
      int hasChangedAddress;
      StunAtrAddress4 changedAddress;
	
      int hasUsername;
      StunAtrString username;
	
      int hasPassword;
      StunAtrString password;
	
      int hasMessageIntegrity;
      StunAtrIntegrity messageIntegrity;
	
      int hasErrorCode;
      StunAtrError errorCode;
	
      int hasUnknownAttributes;
      StunAtrUnknown unknownAttributes;
	
      int hasReflectedFrom;
      StunAtrAddress4 reflectedFrom;

      int hasXorMappedAddress;
      StunAtrAddress4  xorMappedAddress;
	
      int xorOnly;

      int hasServerName;
      StunAtrString serverName;
      
      int hasSecondaryAddress;
      StunAtrAddress4 secondaryAddress;
} StunMessage; 


/* Define enum with different types of NAT */
typedef enum 
{
   StunTypeUnknown=0,
   StunTypeFailure,
   StunTypeOpen,
   StunTypeBlocked,

   StunTypeIndependentFilter,
   StunTypeDependentFilter,
   StunTypePortDependedFilter,
   StunTypeDependentMapping,

   StunTypeFirewall,
} NatType;

#define MAX_MEDIA_RELAYS 500
#define MAX_RTP_MSG_SIZE 1500
#define MEDIA_RELAY_TIMEOUT 3*60

typedef struct 
{
      int relayPort;       /* media relay port*/
      int fd;              /* media relay file descriptor*/
      StunAddress4 destination; /* NAT IP:port*/
      time_t expireTime;      /* if no activity after time, close the socket */
} StunMediaRelay;

typedef struct
{
      StunAddress4 myAddr;
      StunAddress4 altAddr;
      int myFd;
      int altPortFd;
      int altIpFd;
      int altIpPortFd;
      int relay; /* true if media relaying is to be done */
      StunMediaRelay relays[MAX_MEDIA_RELAYS];
} StunServerInfo;

int
stunParseMessage( char* buf, 
                  unsigned int bufLen, 
                  StunMessage *message, 
                  int verbose );

void
stunBuildReqSimple( StunMessage* msg,
                    const StunAtrString *username,
                    int changePort, int changeIp, unsigned int id);

unsigned int
stunEncodeMessage( const StunMessage *message, 
                   char* buf, 
                   unsigned int bufLen, 
                   const StunAtrString *password,
                   int verbose);

void
stunCreateUserName(const StunAddress4 *addr, StunAtrString* username);

void 
stunGetUserNameAndPassword(  const StunAddress4 *dest, 
                             StunAtrString* username,
                             StunAtrString* password);

void
stunCreatePassword(const StunAtrString *username, StunAtrString* password);

void printIPv4Addr (const StunAddress4 *ad);
void printUInt128 (UInt128 r);

int 
stunRand();

UInt64
stunGetSystemTimeSecs();

/*/ find the IP address of a the specified stun server - return false is fails parse */
int  
stunParseServerName( char* serverName, StunAddress4 *stunServerAddr);

int 
stunParseHostName( char* peerName,
                   UInt32 *ip,
                   UInt16 *portVal,
                   UInt16 defaultPort );

/*/ return true if all is OK
/// Create a media relay and do the STERN thing if startMediaPort is non-zero*/
int
stunInitServer(StunServerInfo *info, 
               const StunAddress4 *myAddr, 
               const StunAddress4 *altAddr,
               int startMediaPort,
               int verbose);

void
stunStopServer(StunServerInfo *info);

/*/ return true if all is OK */
int
stunServerProcess(StunServerInfo *info, int verbose);

/*/ returns number of address found - take array or addres */
int 
stunFindLocalInterfaces(UInt32* addresses, int maxSize );

void 
stunTest( StunAddress4 *dest, int testNum, int verbose, StunAddress4* srcAddr );

NatType
stunNatType( StunAddress4 *dest, int verbose, 
             int* preservePort, /* if set, is return for if NAT preservers ports or not */
             int* hairpin ,  /* if set, is the return for if NAT will hairpin packets */
             int port, /* port to use for the test, 0 to choose random port */
             StunAddress4* sAddr /* NIC to use  */
   );

/*/ prints a StunAddress */
/*std::ostream &
operator<<( std::ostream& strm, const StunAddress4& addr);

std::ostream& 
operator<< ( std::ostream& strm, const UInt128& );
*/

int
stunServerProcessMsg( char* buf,
                      unsigned int bufLen,
                      StunAddress4 *from, 
                      StunAddress4 *secondary,
                      StunAddress4 *myAddr,
                      StunAddress4 *altAddr, 
                      StunMessage* resp,
                      StunAddress4* destination,
                      StunAtrString* hmacPassword,
                      int* changePort,
                      int* changeIp,
                      int verbose);

int
stunOpenSocket( StunAddress4 *dest, 
                StunAddress4* mappedAddr, 
                int port, 
                StunAddress4* srcAddr, 
                int verbose );

int
stunOpenSocketPair( StunAddress4 *dest, StunAddress4* mappedAddr, 
                    int* fd1, int* fd2, 
                    int srcPort,  StunAddress4* srcAddr,
                    int verbose);

int
stunRandomPort();

#endif


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
