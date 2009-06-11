/*
 * Host Identity Protocol
 * 
 *  STUN client based on the code provided by Vovida Networks, Inc.
 *  (see end of file)
 *  Translated from C++ code to C code by Vivien Schmitt
 *
 *  hip_stun.c
 *
 * Author : Vivien Schmitt, <schmitt@netlab.nec.de>
 *
 * STUN client used for NAT detection
 *
 */



#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

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
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <net/if.h>
#endif /* __WIN32__ */
#include <string.h>
#include <sys/types.h> 
#include <fcntl.h>
#include <openssl/rand.h> /* RAND_bytes() */
#include <time.h> /* time() */


/*#define NOSSL*/

#include <hip/hip_stun_udp.h>
#include <hip/hip_stun.h>

UInt8  IPv4Family = 0x01;
UInt8  IPv6Family = 0x02;

/* define  flags  */
UInt32 ChangeIpFlag   = 0x04;
UInt32 ChangePortFlag = 0x02;

/* define  stun attribute*/
UInt16 MappedAddress    = 0x0001;
UInt16 ResponseAddress  = 0x0002;
UInt16 ChangeRequest    = 0x0003;
UInt16 SourceAddress    = 0x0004;
UInt16 ChangedAddress   = 0x0005;
UInt16 Username         = 0x0006;
UInt16 Password         = 0x0007;
UInt16 MessageIntegrity = 0x0008;
UInt16 ErrorCode        = 0x0009;
UInt16 UnknownAttribute = 0x000A;
UInt16 ReflectedFrom    = 0x000B;
UInt16 XorMappedAddress = 0x8020;
UInt16 XorOnly          = 0x0021;
UInt16 ServerName       = 0x8022;
UInt16 SecondaryAddress = 0x8050; /* Non standard extention */

/* define types for a stun message */
UInt16 BindRequestMsg               = 0x0001;
UInt16 BindResponseMsg              = 0x0101;
UInt16 BindErrorResponseMsg         = 0x0111;
UInt16 SharedSecretRequestMsg       = 0x0002;
UInt16 SharedSecretResponseMsg      = 0x0102;
UInt16 SharedSecretErrorResponseMsg = 0x0112;

static void
computeHmac(char* hmac, const char* input, int length, const char* key, int keySize);

static int 
stunParseAtrAddress( char* body, unsigned int hdrLen,  StunAtrAddress4 *result )
{
   UInt16 nport;
   UInt32 naddr;
   
   if ( hdrLen != 8 )
   {
      printf("hdrLen wrong for Address\n");
      return FALSE;
   }
   result->pad = *body++;
   result->family = *body++;
   if (result->family == IPv4Family)
   {
      memcpy(&nport, body, 2); body+=2;
      result->ipv4.port = ntohs(nport);
		
      memcpy(&naddr, body, 4); body+=4;
      result->ipv4.addr = ntohl(naddr);
      return TRUE;
   }
   else if (result->family == IPv6Family)
   {
      printf ( "ipv6 not supported\n");
   }
   else
   {
      printf ( "bad address family: %u\n", result->family);
   }
	
   return FALSE;
}

static int 
stunParseAtrChangeRequest( char* body, unsigned int hdrLen,  StunAtrChangeRequest *result )
{
   if ( hdrLen != 4 )
   {
#ifndef __MACOSX__
      printf ( "hdr length = %u expecting %u\n",
		hdrLen, (unsigned int)sizeof(StunAtrChangeRequest));
#endif /* __MACOSX__ */
      printf ( "Incorrect size for ChangeRequest\n");
      return FALSE;
   }
   else
   {
      memcpy(&result->value, body, 4);
      result->value = ntohl(result->value);
      return TRUE;
   }
}

static int 
stunParseAtrError( char* body, unsigned int hdrLen,  StunAtrError *result )
{
   if ( hdrLen >= sizeof(StunAtrError) )
   {
      printf ( "head on Error too large\n");
      return FALSE;
   }
   else
   {
      memcpy(&result->pad, body, 2); body+=2;
      result->pad = ntohs(result->pad);
      result->errorClass = *body++;
      result->number = *body++;
		
      result->sizeReason = hdrLen - 4;
      memcpy(&result->reason, body, result->sizeReason);
      result->reason[result->sizeReason] = 0;
      return TRUE;
   }
}

static int 
stunParseAtrUnknown( char* body, unsigned int hdrLen,  StunAtrUnknown *result )
{
   int i;

   if ( hdrLen >= sizeof(StunAtrUnknown) )
   {
      return FALSE;
   }
   else
   {
      if (hdrLen % 4 != 0) return FALSE;
      result->numAttributes = hdrLen / 4;
      for (i=0; i<result->numAttributes; i++)
      {
         memcpy(&result->attrType[i], body, 2); body+=2;
         result->attrType[i] = ntohs(result->attrType[i]);
      }
      return TRUE;
   }
}


static int 
stunParseAtrString( char* body, unsigned int hdrLen,  StunAtrString *result )
{
   if ( hdrLen >= STUN_MAX_STRING )
   {
      printf ( "String is too large\n");
      return FALSE;
   }
   else
   {
      if (hdrLen % 4 != 0)
      {
         printf ( "Bad length string %u\n ", hdrLen);
         return FALSE;
      }
		
      result->sizeValue = hdrLen;
      memcpy(&result->value, body, hdrLen);
      result->value[hdrLen] = 0;
      return TRUE;
   }
}


static int 
stunParseAtrIntegrity( char* body, unsigned int hdrLen,  StunAtrIntegrity *result )
{
   if ( hdrLen != 20)
   {
      printf ( "MessageIntegrity must be 20 bytes\n");
      return FALSE;
   }
   else
   {
      memcpy(&result->hash, body, hdrLen);
      return TRUE;
   }
}


int
stunParseMessage( char* buf, unsigned int bufLen, StunMessage *msg, int verbose)
{
   char* body;
   unsigned int size;
   StunAtrHdr* attr;
   unsigned int attrLen;
   int atrType;

   if (verbose) printf ( "Received stun message: %u bytes\n", bufLen);
   memset(msg, 0, sizeof(msg));
	
   if (sizeof(StunMsgHdr) > bufLen)
   {
      printf ( "Bad message\n");
      return FALSE;
   }
	
   memcpy(&msg->msgHdr, buf, sizeof(StunMsgHdr));
   msg->msgHdr.msgType = ntohs(msg->msgHdr.msgType);
   msg->msgHdr.msgLength = ntohs(msg->msgHdr.msgLength);
	
   if (msg->msgHdr.msgLength + sizeof(StunMsgHdr) != bufLen)
   {
      printf ( "Message header length doesn't match message size: %u - %u\n", 
		msg->msgHdr.msgLength, bufLen);
      return FALSE;
   }
	
   body = buf + sizeof(StunMsgHdr);
   size = msg->msgHdr.msgLength;
	
   /*printf ( "bytes after header = " << size << endl;*/
	
   while ( size > 0 )
   {
      /* !jf! should check that there are enough bytes left in the buffer*/
		
      attr = (StunAtrHdr*)(body);
		
      attrLen = ntohs(attr->length);
      atrType = ntohs(attr->type);
		
      /*if (verbose) printf ( "Found attribute type=" << AttrNames[atrType] << " length=" << attrLen << endl;*/
      if ( attrLen+4 > size ) 
      {
         printf ( "claims attribute is larger than size of message (attribute type= %u)\n", atrType);
         return FALSE;
      }
		
      body += 4; /* skip the length and type in attribute header*/
      size -= 4;
		
      switch ( atrType )
      {
         case 0x0001: /*MappedAddress:*/
            msg->hasMappedAddress = TRUE;
            if ( stunParseAtrAddress(  body,  attrLen,  &msg->mappedAddress )== FALSE )
            {
               printf ( "problem parsing MappedAddress\n");
               return FALSE;
            }
            else
            {
               if (verbose) {
			printf ( "MappedAddress = ");
			printIPv4Addr(&msg->mappedAddress.ipv4);
			printf("\n");
		}
            }
					
            break;  

         case 0x0002: /*ResponseAddress:*/
            msg->hasResponseAddress = TRUE;
            if ( stunParseAtrAddress(  body,  attrLen,  &msg->responseAddress )== FALSE )
            {
               printf ( "problem parsing ResponseAddress\n");
               return FALSE;
            }
            else
            {
               if (verbose) {
			printf ( "ResponseAddress = ");
			printIPv4Addr(&msg->responseAddress.ipv4);
			printf( "\n");
		}
            }
            break;  
				
         case 0x0003: /*ChangeRequest:*/
            msg->hasChangeRequest = TRUE;
            if (stunParseAtrChangeRequest( body, attrLen, &msg->changeRequest) == FALSE)
            {
               printf ( "problem parsing ChangeRequest\n");
               return FALSE;
            }
            else
            {
               if (verbose) printf ( "ChangeRequest = %u\n", msg->changeRequest.value);
            }
            break;
				
         case 0x0004: /*SourceAddress:*/
            msg->hasSourceAddress = TRUE;
            if ( stunParseAtrAddress(  body,  attrLen,  &msg->sourceAddress )== FALSE )
            {
               printf ( "problem parsing SourceAddress\n");
               return FALSE;
            }
            else
            {
               if (verbose) {
			printf ( "SourceAddress = ");
			printIPv4Addr(&msg->sourceAddress.ipv4);
			printf ("\n");
		}
            }
            break;  
				
         case 0x0005: /*ChangedAddress:*/
            msg->hasChangedAddress = TRUE;
            if ( stunParseAtrAddress(  body,  attrLen,  &msg->changedAddress )== FALSE )
            {
               printf ( "problem parsing ChangedAddress\n");
               return FALSE;
            }
            else
            {
               if (verbose) {
			printf ( "ChangedAddress = ");
			printIPv4Addr(&msg->changedAddress.ipv4);
			printf("\n");
		}
            }
            break;  
				
         case 0x0006: /*Username: */
            msg->hasUsername = TRUE;
            if (stunParseAtrString( body, attrLen, &msg->username) == FALSE)
            {
               printf ( "problem parsing Username\n");
               return FALSE;
            }
            else
            {
               if (verbose) printf ( "Username = %s\n", msg->username.value);
            }
					
            break;
				
         case 0x0007: /*Password: */
            msg->hasPassword = TRUE;
            if (stunParseAtrString( body, attrLen, &msg->password) == FALSE)
            {
               printf ( "problem parsing Password\n");
               return FALSE;
            }
            else
            {
               if (verbose) printf ( "Password = %s\n", msg->password.value);
            }
            break;
				
         case 0x0008: /*MessageIntegrity:*/
            msg->hasMessageIntegrity = TRUE;
            if (stunParseAtrIntegrity( body, attrLen, &msg->messageIntegrity) == FALSE)
            {
               printf ( "problem parsing MessageIntegrity\n");
               return FALSE;
            }
            else
            {
               /*if (verbose) printf ( "MessageIntegrity = " << msg->messageIntegrity.hash << endl;*/
            }
					
            /* read the current HMAC
            // look up the password given the user of given the transaction id 
            // compute the HMAC on the buffer
            // decide if they match or not*/
            break;
				
         case 0x0009: /*ErrorCode:*/
            msg->hasErrorCode = TRUE;
            if (stunParseAtrError(body, attrLen, &msg->errorCode) == FALSE)
            {
               printf ( "problem parsing ErrorCode\n");
               return FALSE;
            }
            else
            {
               if (verbose) printf ( "ErrorCode = %u %u %s\n", 
			        (int)(msg->errorCode.errorClass),
				(int)(msg->errorCode.number), 
				msg->errorCode.reason);
            }
					
            break;
				
         case 0x000A: /*UnknownAttribute:*/
            msg->hasUnknownAttributes = TRUE;
            if (stunParseAtrUnknown(body, attrLen, 
				    &msg->unknownAttributes) == FALSE)
            {
               printf ( "problem parsing UnknownAttribute\n");
               return FALSE;
            }
            break;
				
         case 0x000B: /*ReflectedFrom:*/
            msg->hasReflectedFrom = TRUE;
            if ( stunParseAtrAddress(body,  attrLen,  
				    &msg->reflectedFrom ) == FALSE )
            {
               printf ( "problem parsing ReflectedFrom\n");
               return FALSE;
            }
            break;  
				
         case 0x8020: /*XorMappedAddress:*/
            msg->hasXorMappedAddress = TRUE;
            if ( stunParseAtrAddress(body,  attrLen,
				    &msg->xorMappedAddress ) == FALSE )
            {
               printf ( "problem parsing XorMappedAddress\n");
               return FALSE;
            }
            else
            {
               if (verbose) {
			printf ( "XorMappedAddress = ");
			printIPv4Addr( &msg->mappedAddress.ipv4);
			printf("\n");
		}
            }
            break;  

         case 0x0021: /*XorOnly:*/
            msg->xorOnly = TRUE;
            if (verbose) 
            {
               printf ( "xorOnly = TRUE\n");
            }
            break;  
				
         case 0x8022: /*ServerName: */
            msg->hasServerName = TRUE;
            if (stunParseAtrString( body, attrLen, &msg->serverName) == FALSE)
            {
               printf ( "problem parsing ServerName\n");
               return FALSE;
            }
            else
            {
               if (verbose) printf ( "ServerName = %s\n", msg->serverName.value);
            }
            break;
				
         case 0x8050: /*SecondaryAddress:*/
            msg->hasSecondaryAddress = TRUE;
            if ( stunParseAtrAddress(body,  attrLen,
				    &msg->secondaryAddress ) == FALSE )
            {
               printf ( "problem parsing secondaryAddress\n");
               return FALSE;
            }
            else
            {
               if (verbose){
			printf ( "SecondaryAddress = ");
			printIPv4Addr(&msg->secondaryAddress.ipv4);
			printf("\n");
		}
            }
            break;  
					
         default:
            if (verbose) printf ( "Unknown attribute: %u\n",atrType);
            if ( atrType <= 0x7FFF ) 
            {
               return FALSE;
            }
      }
		
      body += attrLen;
      size -= attrLen;
   }
    
   return TRUE;
}


static char* 
encode16(char* buf, UInt16 data)
{
   UInt16 ndata = htons(data);
   memcpy(buf, (void*)(&ndata), sizeof(UInt16));
   return buf + sizeof(UInt16);
}

static char* 
encode32(char* buf, UInt32 data)
{
   UInt32 ndata = htonl(data);
   memcpy(buf, (void*)(&ndata), sizeof(UInt32));
   return buf + sizeof(UInt32);
}


static char* 
encode(char* buf, const char* data, unsigned int length)
{
   memcpy(buf, data, length);
   return buf + length;
}


static char* 
encodeAtrAddress4(char* ptr, UInt16 type, const StunAtrAddress4 atr)
{
   ptr = encode16(ptr, type);
   ptr = encode16(ptr, 8);
   *ptr++ = atr.pad;
   *ptr++ = IPv4Family;
   ptr = encode16(ptr, atr.ipv4.port);
   ptr = encode32(ptr, atr.ipv4.addr);
	
   return ptr;
}

static char* 
encodeAtrChangeRequest(char* ptr, const StunAtrChangeRequest atr)
{
   ptr = encode16(ptr, ChangeRequest);
   ptr = encode16(ptr, 4);
   ptr = encode32(ptr, atr.value);
   return ptr;
}

static char* 
encodeAtrError(char* ptr, const StunAtrError atr)
{
   ptr = encode16(ptr, ErrorCode);
   ptr = encode16(ptr, (UInt16)(6 + atr.sizeReason));
   ptr = encode16(ptr, atr.pad);
   *ptr++ = atr.errorClass;
   *ptr++ = atr.number;
   ptr = encode(ptr, atr.reason, atr.sizeReason);
   return ptr;
}


static char* 
encodeAtrUnknown(char* ptr, const StunAtrUnknown atr)
{
   int i;
   ptr = encode16(ptr, UnknownAttribute);
   ptr = encode16(ptr, (UInt16)(2+2*atr.numAttributes));
   for (i=0; i<atr.numAttributes; i++)
   {
      ptr = encode16(ptr, atr.attrType[i]);
   }
   return ptr;
}


static char* 
encodeXorOnly(char* ptr)
{
   ptr = encode16(ptr, XorOnly );
   return ptr;
}


static char* 
encodeAtrString(char* ptr, UInt16 type, const StunAtrString atr)
{
   assert(atr.sizeValue % 4 == 0);
	
   ptr = encode16(ptr, type);
   ptr = encode16(ptr, atr.sizeValue);
   ptr = encode(ptr, atr.value, atr.sizeValue);
   return ptr;
}


static char* 
encodeAtrIntegrity(char* ptr, const StunAtrIntegrity *atr)
{
   ptr = encode16(ptr, MessageIntegrity);
   ptr = encode16(ptr, 20);
   ptr = encode(ptr, atr->hash, sizeof(atr->hash));
   return ptr;
}


unsigned int
stunEncodeMessage( const StunMessage *msg, 
                   char* buf, 
                   unsigned int bufLen, 
                   const StunAtrString *password, 
                   int verbose)
{
   char* ptr = buf;
   char* lengthp;

   StunAtrIntegrity integrity;

   assert(bufLen >= sizeof(StunMsgHdr));

   integrity.hash[0] = 0;
   integrity.hash[2] = 3;
   integrity.hash[10] = 5;
	
   ptr = encode16(ptr, msg->msgHdr.msgType);
   lengthp = ptr;
   ptr = encode16(ptr, 0);
   ptr = encode(ptr, (const char*)(msg->msgHdr.id.octet), 
		   sizeof(msg->msgHdr.id));
	
   if (verbose) printf ( "Encoding stun message: \n");
   if (msg->hasMappedAddress)
   {
      if (verbose){
		printf ( "Encoding MappedAddress: ");
		printIPv4Addr((StunAddress4*)&(msg->mappedAddress.ipv4));
		printf("\n");
	}
      ptr = encodeAtrAddress4 (ptr, MappedAddress, msg->mappedAddress);
   }
   if (msg->hasResponseAddress)
   {
      if (verbose) {
		printf ( "Encoding ResponseAddress: ");
		printIPv4Addr((StunAddress4*)&msg->responseAddress.ipv4);
		printf("\n");
	}
      ptr = encodeAtrAddress4(ptr, ResponseAddress, msg->responseAddress);
   }
   if (msg->hasChangeRequest)
   {
      if (verbose) printf ( "Encoding ChangeRequest: %u\n" , 
		      		msg->changeRequest.value);
      ptr = encodeAtrChangeRequest(ptr, msg->changeRequest);
   }
   if (msg->hasSourceAddress)
   {
      if (verbose) {
		printf ( "Encoding SourceAddress: ");
		printIPv4Addr((StunAddress4*)&msg->sourceAddress.ipv4);
		printf("\n");
	}
      ptr = encodeAtrAddress4(ptr, SourceAddress, msg->sourceAddress);
   }
   if (msg->hasChangedAddress)
   {
      if (verbose) {
		printf ( "Encoding ChangedAddress: ");
		printIPv4Addr((StunAddress4*)&msg->changedAddress.ipv4);
		printf("\n");
	}
      ptr = encodeAtrAddress4(ptr, ChangedAddress, msg->changedAddress);
   }
   if (msg->hasUsername)
   {
      if (verbose) printf ( "Encoding Username: %s\n" ,msg->username.value);
      ptr = encodeAtrString(ptr, Username, msg->username);
   }
   if (msg->hasPassword)
   {
      if (verbose) printf ( "Encoding Password: %s\n", msg->password.value);
      ptr = encodeAtrString(ptr, Password, msg->password);
   }
   if (msg->hasErrorCode)
   {
      if (verbose) printf ( "Encoding ErrorCode: class=%u number=%u reason=%s\n",
			(int)(msg->errorCode.errorClass),
			(int)(msg->errorCode.number),
			msg->errorCode.reason );
		
      ptr = encodeAtrError(ptr, msg->errorCode);
   }
   if (msg->hasUnknownAttributes)
   {
      if (verbose) printf ( "Encoding UnknownAttribute: ???\n");
      ptr = encodeAtrUnknown(ptr, msg->unknownAttributes);
   }
   if (msg->hasReflectedFrom)
   {
      if (verbose) {
		printf ( "Encoding ReflectedFrom: ");
		printIPv4Addr((StunAddress4*)&msg->reflectedFrom.ipv4);
		printf("\n");
	}
      ptr = encodeAtrAddress4(ptr, ReflectedFrom, msg->reflectedFrom);
   }
   if (msg->hasXorMappedAddress)
   {
      if (verbose) {
		printf ( "Encoding XorMappedAddress: ");
		printIPv4Addr((StunAddress4*)&msg->xorMappedAddress.ipv4);
		printf("\n");
	}
      ptr = encodeAtrAddress4 (ptr, XorMappedAddress, msg->xorMappedAddress);
   }
   if (msg->xorOnly)
   {
      if (verbose) printf ( "Encoding xorOnly: \n");
      ptr = encodeXorOnly( ptr );
   }
   if (msg->hasServerName)
   {
      if (verbose) printf ( "Encoding ServerName: %s\n", msg->serverName.value);
      ptr = encodeAtrString(ptr, ServerName, msg->serverName);
   }
   if (msg->hasSecondaryAddress)
   {
      if (verbose) {
		printf ( "Encoding SecondaryAddress: ");
		printIPv4Addr((StunAddress4*)&msg->secondaryAddress.ipv4);
		printf("\n");
	}
      ptr = encodeAtrAddress4 (ptr, SecondaryAddress, msg->secondaryAddress);
   }

   if (password->sizeValue > 0)
   {
      if (verbose) printf ( "HMAC with password: %s\n", password->value);
		
      computeHmac(integrity.hash, buf, (int)(ptr-buf) , 
		  password->value, password->sizeValue);
      ptr = encodeAtrIntegrity(ptr, &integrity);
   }
   if (verbose) printf ( "\n");
	
   encode16(lengthp, (UInt16)(ptr - buf - sizeof(StunMsgHdr)));
   return (int)(ptr - buf);
}

int 
stunRand()
{
   /* return 32 bits of random stuff*/
   int r;
   
   RAND_bytes((unsigned char*)&r, 4);

   return r;
}


/* return a random number to use as a port  */
int
stunRandomPort()
{
   int min=0x4000;
   int max=0x7FFF;
	
   int ret = stunRand();
   ret = ret|min;
   ret = ret&max;
	
   return ret;
}


#ifdef NOSSL
static void
computeHmac(char* hmac, const char* input, int length, const char* key, int sizeKey)
{
   strncpy(hmac,"hmac-not-implemented",20);
}
#else
#include <openssl/hmac.h>

static void
computeHmac(char* hmac, const char* input, int length, const char* key, int sizeKey)
{
   unsigned int resultSize=0;
#ifdef ORIG
   HMAC(EVP_sha1(), 
        key, sizeKey, 
        reinterpret_cast<const unsigned char*>(input), length, 
        reinterpret_cast<unsigned char*>(hmac), &resultSize);
#endif
   HMAC(EVP_sha1(), 
        key, sizeKey, 
        (const unsigned char*)(input), length, 
        (unsigned char*)(hmac), &resultSize);
   assert(resultSize == 20);
}
#endif


static void
toHex(const char* buffer, int bufferSize, char* output) 
{
   static char hexmap[] = "0123456789abcdef";
	
   const char* p = buffer;
   char* r = output;
   int i, hi, low;
   unsigned char temp;
   for (i=0; i < bufferSize; i++)
   {
      temp = *p++;
		
      hi = (temp & 0xf0)>>4;
      low = (temp & 0xf);
		
      *r++ = hexmap[hi];
      *r++ = hexmap[low];
   }
   *r = 0;
}

void
stunCreateUserName(const StunAddress4 *source, StunAtrString* username)
{
   char buffer[1024];
   UInt64 lotime, time = stunGetSystemTimeSecs();
   char hmac[20];
   char key[] = "Jason";
   char hmacHex[41];
   int l;
   
   time -= (time % 20*60);
   /*UInt64 hitime = time >> 32;*/
   lotime = time & 0xFFFFFFFF;
	
   sprintf(buffer,
           "%08x:%08x:%08x:", 
           (UInt32)(source->addr),
           (UInt32)(stunRand()),
           (UInt32)(lotime));
   assert( strlen(buffer) < 1024 );
	
   assert(strlen(buffer) + 41 < STUN_MAX_STRING);
	
   computeHmac(hmac, buffer, strlen(buffer), key, strlen(key) );
   toHex(hmac, 20, hmacHex );
   hmacHex[40] =0;
	
   strcat(buffer,hmacHex);
	
   l = strlen(buffer);
   assert( l+1 < STUN_MAX_STRING );
   assert( l%4 == 0 );
   
   username->sizeValue = l;
   memcpy(username->value,buffer,l);
   username->value[l]=0;
	
   /*if (verbose) printf ( "computed username=" << username.value << endl;*/
}

void
stunCreatePassword(const StunAtrString *username, StunAtrString* password)
{
   char hmac[20];
   char key[] = "Fluffy";
   /*char buffer[STUN_MAX_STRING];*/
   computeHmac(hmac, username->value, strlen(username->value), key,strlen(key));
   toHex(hmac, 20, password->value);
   password->sizeValue = 40;
   password->value[40]=0;
	
   /*printf ( "password=" << password->value << endl;*/
}


UInt64
stunGetSystemTimeSecs()
{
   UInt64 t=0;
#ifdef __WIN32__
   /* t = _time64(NULL);   how do we link this fn? */
   /* SYSTEMTIME st; GetSystemTime(&st);  another option to use here */
   t = (UInt64)time(NULL);
#else
   struct timeval now;
   gettimeofday( &now , NULL );
   /*assert( now );*/
   t = now.tv_sec;
#endif
   return t;
}

void printIPv4Addr (const StunAddress4 *ad){
	UInt32 addr = ad->addr;
	printf("%u.", (int)(addr>>24)&0xFF);
	printf("%u.", (int)(addr>>16)&0xFF);
	printf("%u.", (int)(addr>> 8)&0xFF);
	printf("%u",  (int)(addr>> 0)&0xFF);
}

void printUInt128 (UInt128 r){
	int i;
	printf("%u", (int) r.octet[0]);
	for (i=1; i<16; i++) {
		printf (":%u", (int) r.octet[i]);
	}
}
/*
ostream& operator<< ( ostream& strm, const UInt128& r )
{
   strm << int(r.octet[0]);
   for ( int i=1; i<16; i++ )
   {
      strm << ':' << int(r.octet[i]);
   }
    
   return strm;
}

ostream& 
operator<<( ostream& strm, const StunAddress4& addr)
{
   UInt32 ip = addr.addr;
   strm << ((int)(ip>>24)&0xFF) << ".";
   strm << ((int)(ip>>16)&0xFF) << ".";
   strm << ((int)(ip>> 8)&0xFF) << ".";
   strm << ((int)(ip>> 0)&0xFF) ;
	
   strm << ":" << addr.port;
	
   return strm;
}
*/

/* returns TRUE if it scucceeded*/
int 
stunParseHostName( char* peerName,
               UInt32 *ip,
               UInt16 *portVal,
               UInt16 defaultPort )
{
   struct in_addr sin_addr;
   char* port = NULL;
   int portNum, err;
   char *sep, *endPtr=NULL;
   struct hostent* h;
    
   char host[512];
   strncpy(host,peerName,512);
   host[512-1]='\0';
	
   portNum = defaultPort;
	
   /* pull out the port part if present.*/
   sep = strchr(host,':');
	
   if ( sep == NULL )
   {
      portNum = defaultPort;
   }
   else
   {
      *sep = '\0';
      port = sep + 1;
      /* set port part*/
		
      portNum = strtol(port,&endPtr,10);
		
      if ( endPtr != NULL )
      {
         if ( *endPtr != '\0' )
         {
            portNum = defaultPort;
         }
      }
   }
    
   if ( portNum < 1024 ) return FALSE;
   if ( portNum >= 0xFFFF ) return FALSE;
	
   /* figure out the host part */
	
   h = gethostbyname( host );
   if ( h == NULL )
   {
      err = errno;
      fprintf(stderr, "error was %u\n", err);
      *ip = ntohl( 0x7F000001L );
      return FALSE;
   }
   else
   {
      sin_addr = *(struct in_addr*)h->h_addr;
      *ip = ntohl( sin_addr.s_addr );
   }
	
   *portVal = portNum;
	
   return TRUE;
}


int
stunParseServerName( char* name, StunAddress4 *addr)
{
   int ret;

   assert(name);
	
   /* TODO - put in DNS SRV stuff.*/
	
   ret = stunParseHostName( name, &addr->addr, &addr->port, 3478); 
   if ( ret != TRUE ) 
   {
       addr->port=0xFFFF;
   }	
   return ret;
}


static void
stunCreateErrorResponse(StunMessage *response, int cl, int number, const char* msg)
{
   response->msgHdr.msgType = BindErrorResponseMsg;
   response->hasErrorCode = TRUE;
   response->errorCode.errorClass = cl;
   response->errorCode.number = number;
   strcpy(response->errorCode.reason, msg);
}

static void
stunCreateSharedSecretResponse(const StunMessage *request, const StunAddress4 *source, StunMessage *response)
{
   response->msgHdr.msgType = SharedSecretResponseMsg;
   response->msgHdr.id = request->msgHdr.id;
	
   response->hasUsername = TRUE;
   stunCreateUserName( source, &response->username);
	
   response->hasPassword = TRUE;
   stunCreatePassword( &response->username, &response->password);
}


/* This funtion takes a single message sent to a stun server, parses
// and constructs an apropriate repsonse - returns TRUE if message is
// valid*/
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
                      int verbose)
{
   int ok, i;
   UInt32 flags, id32, source;
   UInt16 id16;
   StunMessage req;
   StunAddress4 *mapped, *respondTo;
   unsigned char hmac[20];
   unsigned int hmacSize=20;
   const char serverName[] = "Vovida.org " STUN_VERSION; /* must pad to mult of 4*/
    
   /* set up information for default response */
	
   memset( resp, 0 , sizeof(*resp) );
	
   *changeIp = FALSE;
   *changePort = FALSE;
	
   ok = stunParseMessage( buf,bufLen, &req, verbose);
	
   if (!ok)      /* Complete garbage, drop it on the floor*/
   {
      if (verbose) printf ( "Request did not parse\n");
      return FALSE;
   }
   if (verbose) printf ( "Request parsed ok\n");
	
   mapped= &req.mappedAddress.ipv4;
   respondTo= &req.responseAddress.ipv4;
   flags = req.changeRequest.value;
	
   switch (req.msgHdr.msgType)
   {
      case 0x0002:/*SharedSecretRequestMsg:*/
         if(verbose) printf ( "Received SharedSecretRequestMsg on udp. send error 433.\n");
         /* !cj! - should fix so you know if this came over TLS or UDP*/
         stunCreateSharedSecretResponse(&req, from, resp);
         /*stunCreateSharedSecretErrorResponse(*resp, 4, 33, "this request must be over TLS");*/
         return TRUE;
			
      case 0x0001: /*BindRequestMsg:*/
         if (!req.hasMessageIntegrity)
         {
            if (verbose) printf ( "BindRequest does not contain MessageIntegrity\n");
				
            if (0) /* !jf! mustAuthenticate*/
            {
               if(verbose) printf ( "Received BindRequest with no MessageIntegrity. Sending 401.\n");
               stunCreateErrorResponse(resp, 4, 1, "Missing MessageIntegrity");
               return TRUE;
            }
         }
         else
         {
            if (!req.hasUsername)
            {
               if (verbose) printf ( "No UserName. Send 432.\n");
               stunCreateErrorResponse(resp, 4, 32, "No UserName and contains MessageIntegrity");
               return TRUE;
            }
            else
            {
               if (verbose) printf ( "Validating username: %s\n", req.username.value);
               /* !jf! could retrieve associated password from provisioning here*/
               if (strcmp(req.username.value, "test") == 0)
               {
                  if (0)
                  {
                     /* !jf! if the credentials are stale */
                     stunCreateErrorResponse(resp, 4, 30, "Stale credentials on BindRequest");
                     return TRUE;
                  }
                  else
                  {
                     if (verbose) printf ( "Validating MessageIntegrity\n");
                     /* need access to shared secret*/
							
#ifndef NOSSL
                     hmacSize=20;

                     HMAC(EVP_sha1(), 
                          "1234", 4, 
                          (const unsigned char*)(buf), bufLen-20-4, 
                          hmac, &hmacSize);
                     assert(hmacSize == 20);
#endif
							
                     if (memcmp(buf, hmac, 20) != 0)
                     {
                        if (verbose) printf ( 
				       "MessageIntegrity is bad. Sending \n");
                        stunCreateErrorResponse(resp, 4, 3, 
			    "Unknown username. Try test with password 1234");
                        return TRUE;
                     }
							
                     /* need to compute this later after message is filled in*/
                     resp->hasMessageIntegrity = TRUE;
                     assert(req.hasUsername);
                     resp->hasUsername = TRUE;
                     resp->username = req.username; /* copy username in*/
                  }
               }
               else
               {
                  if (verbose) printf ( "Invalid username: %s Send 430.\n", req.username.value); 
               }
            }
         }
			
         /* TODO !jf! should check for unknown attributes here and send 420 listing the
         // unknown attributes. */
			
         if ( respondTo->port == 0 ) respondTo = from;
         if ( mapped->port == 0 ) mapped = from;
				
         *changeIp   = ( flags & ChangeIpFlag )?TRUE:FALSE;
         *changePort = ( flags & ChangePortFlag )?TRUE:FALSE;
			
         if (verbose)
         {
            printf ( "Request is valid:\n");
            printf ( "\t flags=%u\n", flags);
            printf ( "\t changeIp=%u\n", *changeIp);
            printf ( "\t changePort=%u\n", *changePort);
            printf ( "\t from = ");
	    printIPv4Addr(from);
            printf ( "\n\t respond to = ");
	    printIPv4Addr(respondTo);
            printf ( "\n\t mapped = ");
	    printIPv4Addr(mapped);
	    printf("\n");
         }
				
         /* form the outgoing message*/
         resp->msgHdr.msgType = BindResponseMsg;
         for ( i=0; i<16; i++ )
         {
            resp->msgHdr.id.octet[i] = req.msgHdr.id.octet[i];
         }
		
         if ( req.xorOnly == FALSE )
         {
            resp->hasMappedAddress = TRUE;
            resp->mappedAddress.ipv4.port = mapped->port;
            resp->mappedAddress.ipv4.addr = mapped->addr;
         }

         if (1) /* do xorMapped address or not */
         {
            resp->hasXorMappedAddress = TRUE;
            id16 = req.msgHdr.id.octet[0]<<8 
               | req.msgHdr.id.octet[1];
            id32 = req.msgHdr.id.octet[0]<<24 
               | req.msgHdr.id.octet[1]<<16 
               | req.msgHdr.id.octet[2]<<8 
               | req.msgHdr.id.octet[3];
            resp->xorMappedAddress.ipv4.port = mapped->port^id16;
            resp->xorMappedAddress.ipv4.addr = mapped->addr^id32;
         }
         
         resp->hasSourceAddress = TRUE;
         resp->sourceAddress.ipv4.port = (*changePort) ? altAddr->port : myAddr->port;
         resp->sourceAddress.ipv4.addr = (*changeIp)   ? altAddr->addr : myAddr->addr;
			
         resp->hasChangedAddress = TRUE;
         resp->changedAddress.ipv4.port = altAddr->port;
         resp->changedAddress.ipv4.addr = altAddr->addr;
	
         if ( secondary->port != 0 )
         {
            resp->hasSecondaryAddress = TRUE;
            resp->secondaryAddress.ipv4.port = secondary->port;
            resp->secondaryAddress.ipv4.addr = secondary->addr;
         }
         
         if ( req.hasUsername && req.username.sizeValue > 0 ) 
         {
            /* copy username in*/
            resp->hasUsername = TRUE;
            assert( req.username.sizeValue % 4 == 0 );
            assert( req.username.sizeValue < STUN_MAX_STRING );
            memcpy( resp->username.value, req.username.value, req.username.sizeValue );
            resp->username.sizeValue = req.username.sizeValue;
         }
		
         if (1) /* add ServerName */
         {
            resp->hasServerName = TRUE;
            
            assert( sizeof(serverName) < STUN_MAX_STRING );
            /*cerr << "sizeof serverName is "  << sizeof(serverName) << endl;*/
            assert( sizeof(serverName)%4 == 0 );
            memcpy( resp->serverName.value, serverName, sizeof(serverName));
            resp->serverName.sizeValue = sizeof(serverName);
         }
         
         if ( req.hasMessageIntegrity & req.hasUsername )  
         {
            /* this creates the password that will be used in the HMAC when then
            // messages is sent*/
            stunCreatePassword( &req.username, hmacPassword );
         }
				
         if (req.hasUsername && (req.username.sizeValue > 64 ) )
         {
            assert( sizeof(int) == sizeof(UInt32) );
					
            sscanf(req.username.value, "%x", &source);
            resp->hasReflectedFrom = TRUE;
            resp->reflectedFrom.ipv4.port = 0;
            resp->reflectedFrom.ipv4.addr = source;
         }
				
         destination->port = respondTo->port;
         destination->addr = respondTo->addr;
			
         return TRUE;
			
      default:
         if (verbose) printf ( "Unknown or unsupported request \n");
         return FALSE;
   }
	
   assert(0);
   return FALSE;
}

int
stunInitServer(StunServerInfo *info, const StunAddress4 *myAddr,
               const StunAddress4 *altAddr, int startMediaPort, int verbose )
{
   int i;
   assert( myAddr->port != 0 );
   assert( altAddr->port!= 0 );
   assert( myAddr->addr  != 0 );
   /*assert( altAddr.addr != 0 );*/
	
   memcpy(&info->myAddr, myAddr, sizeof(myAddr));
   memcpy(&info->altAddr, altAddr, sizeof(altAddr));
	
   info->myFd = INVALID_SOCKET;
   info->altPortFd = INVALID_SOCKET;
   info->altIpFd = INVALID_SOCKET;
   info->altIpPortFd = INVALID_SOCKET;

   memset(info->relays, 0, sizeof(info->relays));
   if (startMediaPort > 0)
   {
      info->relay = TRUE;
      for (i=0; i<MAX_MEDIA_RELAYS; ++i)
      {
         StunMediaRelay* relay = &info->relays[i];
         relay->relayPort = startMediaPort+i;
         relay->fd = 0;
         relay->expireTime = 0;
      }
   }
   else
   {
      info->relay = FALSE;
   }
   
   if ((info->myFd = openPort(myAddr->port, myAddr->addr,verbose)) == INVALID_SOCKET)
   {
      printf ( "Can't open ");
      printIPv4Addr((StunAddress4*)myAddr);
      printf("\n");
      stunStopServer(info);

      return FALSE;
   }
   /*if (verbose) printf ( "Opened " << myAddr.addr << ":" << myAddr.port << " --> " << info->myFd << endl;*/

   if ((info->altPortFd = openPort(altAddr->port,myAddr->addr,verbose)) == INVALID_SOCKET)
   {
      printf ( "Can't open ");
	printIPv4Addr((StunAddress4*)myAddr);
	printf("\n");
      stunStopServer(info);
      return FALSE;
   }
   /*if (verbose) printf ( "Opened " << myAddr.addr << ":" << altAddr.port << " --> " << info->altPortFd << endl;*/
   
   
   info->altIpFd = INVALID_SOCKET;
   if (  altAddr->addr != 0 )
   {
      if ((info->altIpFd = openPort( myAddr->port, altAddr->addr,verbose)) == INVALID_SOCKET)
      {
         printf ( "Can't open ");
	printIPv4Addr((StunAddress4*)altAddr);
	printf("\n");
         stunStopServer(info);
         return FALSE;
      }
      /*if (verbose) printf ( "Opened " << altAddr.addr << ":" << myAddr.port << " --> " << info->altIpFd << endl;;*/
   }
   
   info->altIpPortFd = INVALID_SOCKET;
   if (  altAddr->addr != 0 )
   {  if ((info->altIpPortFd = openPort(altAddr->port, altAddr->addr,verbose)) == INVALID_SOCKET)
      {
         printf ( "Can't open ");
	printIPv4Addr((StunAddress4*)altAddr);
	printf("\n");
         stunStopServer(info);
         return FALSE;
      }
      /*if (verbose) printf ( "Opened " << altAddr.addr << ":" << altAddr.port << " --> " << info->altIpPortFd << endl;;*/
   }
   
   return TRUE;
}

void
stunStopServer(StunServerInfo *info)
{
   int i;
   if (info->myFd > 0) closesocket(info->myFd);
   if (info->altPortFd > 0) closesocket(info->altPortFd);
   if (info->altIpFd > 0) closesocket(info->altIpFd);
   if (info->altIpPortFd > 0) closesocket(info->altIpPortFd);
   
   if (info->relay)
   {
      for (i=0; i<MAX_MEDIA_RELAYS; ++i)
      {
         StunMediaRelay* relay = &info->relays[i];
         if (relay->fd)
         {
            closesocket(relay->fd);
            relay->fd = 0;
         }
      }
   }
}


int
stunServerProcess(StunServerInfo *info, int verbose)
{
   char msg[STUN_MAX_MESSAGE_SIZE];
   int msgLen = sizeof(msg);
   	
   int i;
   int ok = FALSE;
   int recvAltIp =FALSE;
   int recvAltPort = FALSE;
	
   fd_set fdSet; 
   int maxFd=0;
   
   struct timeval tv;
   int e, err;
   StunAddress4 from;
   time_t now;
   
   char rtp_msg[MAX_RTP_MSG_SIZE];
   int rtp_msgLen = sizeof(msg);
   StunAddress4 rtpFrom;
   
   int relayPort = 0;
   StunMediaRelay* relay;
   int changePort = FALSE;
   int changeIp = FALSE;

   StunMessage resp;
   StunAddress4 dest;
   StunAtrString hmacPassword;  


   StunAddress4 secondary;
   char buf[STUN_MAX_MESSAGE_SIZE];
   int len = sizeof(buf);
   		
   int sendFd;			
   int sendAltIp;
   int sendAltPort;

   hmacPassword.sizeValue = 0;
   secondary.port = 0;
   secondary.addr = 0;
            
   FD_ZERO(&fdSet); 
   FD_SET((unsigned int)info->myFd,&fdSet); 
   if ( info->myFd >= maxFd ) maxFd=info->myFd+1;
   FD_SET((unsigned int)info->altPortFd,&fdSet); 
   if ( info->altPortFd >= maxFd ) maxFd=info->altPortFd+1;

   if ( info->altIpFd != INVALID_SOCKET )
   {
      FD_SET((unsigned int)info->altIpFd,&fdSet);
      if (info->altIpFd>=maxFd) maxFd=info->altIpFd+1;
   }
   if ( info->altIpPortFd != INVALID_SOCKET )
   {
      FD_SET((unsigned int)info->altIpPortFd,&fdSet);
      if (info->altIpPortFd>=maxFd) maxFd=info->altIpPortFd+1;
   }

   if (info->relay)
   {
      for (i=0; i<MAX_MEDIA_RELAYS; ++i)
      {
         StunMediaRelay* relay = &info->relays[i];
         if (relay->fd)
         {
            FD_SET((unsigned int)relay->fd, &fdSet);
            if (relay->fd >= maxFd) 
			{
				maxFd=relay->fd+1;
			}
         }
      }
   }
   
   if ( info->altIpFd != INVALID_SOCKET )
   {
      FD_SET((unsigned int)info->altIpFd,&fdSet);
      if (info->altIpFd>=maxFd) maxFd=info->altIpFd+1;
   }
   if ( info->altIpPortFd != INVALID_SOCKET )
   {
      FD_SET((unsigned int)info->altIpPortFd,&fdSet);
      if (info->altIpPortFd>=maxFd) maxFd=info->altIpPortFd+1;
   }
   
   tv.tv_sec = 0;
   tv.tv_usec = 1000;
	
   e = select( maxFd, &fdSet, NULL,NULL, &tv );
   if (e < 0)
   {
      err = errno;
      printf ( "Error on select: %s\n", strerror(err));
   }
   else if (e >= 0)
   {

      /* do the media relaying */
      if (info->relay)
      {
         now = time(0);
         for (i=0; i<MAX_MEDIA_RELAYS; ++i)
         {
            StunMediaRelay* relay = &info->relays[i];
            if (relay->fd)
            {
               if (FD_ISSET(relay->fd, &fdSet))
               {
                  ok = getMessage( relay->fd, rtp_msg, &rtp_msgLen, 
				   &rtpFrom.addr, &rtpFrom.port ,verbose);
                  if (ok)
                  {
                     sendMessage(info->myFd, rtp_msg, rtp_msgLen, 
				     relay->destination.addr, 
				     relay->destination.port, verbose);
                     relay->expireTime = now + MEDIA_RELAY_TIMEOUT;
                     if ( verbose ) {
			printf ( "Relay packet on %u from ", relay->fd);
			printIPv4Addr(&rtpFrom);
			printf(" -> ");
			printIPv4Addr(&relay->destination);
			printf("\n");
		     }
                  }
               }
               else if (now > relay->expireTime)
               {
                  closesocket(relay->fd);
                  relay->fd = 0;
               }
            }
         }
      }
      
     
      if (FD_ISSET(info->myFd,&fdSet))
      {
         if (verbose) printf ( "received on A1:P1\n");
         recvAltIp = FALSE;
         recvAltPort = FALSE;
         ok = getMessage( info->myFd, msg, &msgLen, &from.addr, &from.port,verbose );
      }
      else if (FD_ISSET(info->altPortFd, &fdSet))
      {
         if (verbose) printf ( "received on A1:P2\n");
         recvAltIp = FALSE;
         recvAltPort = TRUE;
         ok = getMessage( info->altPortFd, msg, &msgLen, &from.addr, &from.port,verbose );
      }
      else if ( (info->altIpFd!=INVALID_SOCKET) && FD_ISSET(info->altIpFd,&fdSet))
      {
         if (verbose) printf ( "received on A2:P1\n");
         recvAltIp = TRUE;
         recvAltPort = FALSE;
         ok = getMessage( info->altIpFd, msg, &msgLen, &from.addr, &from.port ,verbose);
      }
      else if ( (info->altIpPortFd!=INVALID_SOCKET) && FD_ISSET(info->altIpPortFd, &fdSet))
      {
         if (verbose) printf ( "received on A2:P2\n");
         recvAltIp = TRUE;
         recvAltPort = TRUE;
         ok = getMessage( info->altIpPortFd, msg, &msgLen, &from.addr, &from.port,verbose );
      }
      else
      {
         return TRUE;
      }

      if (info->relay)
      {
         for (i=0; i<MAX_MEDIA_RELAYS; ++i)
         {
            relay = &info->relays[i];
            if (relay->destination.addr == from.addr && 
                relay->destination.port == from.port)
            {
               relayPort = relay->relayPort;
               relay->expireTime = time(0) + MEDIA_RELAY_TIMEOUT;
               break;
            }
         }

         if (relayPort == 0)
         {
            for (i=0; i<MAX_MEDIA_RELAYS; ++i)
            {
               relay = &info->relays[i];
               if (relay->fd == 0)
               {
                  if ( verbose ) printf ( "Open relay port %u\n", 
					  relay->relayPort);
                  
                  relay->fd = openPort((UInt16)relay->relayPort, 
				       info->myAddr.addr, verbose);
                  relay->destination.addr = from.addr;
                  relay->destination.port = from.port;
                  relay->expireTime = time(0) + MEDIA_RELAY_TIMEOUT;
                  relayPort = relay->relayPort;
                  break;
               }
            }
         }
      }
         
      if ( !ok ) 
      {
         if ( verbose ) printf ( "Get message did not return a valid message\n");
         return TRUE;
      }
		
      if ( verbose ) {
		printf ( "Got a request (len=%u) from ", msgLen);
		printIPv4Addr(&from);
		printf("\n");
	}
		
      if ( msgLen <= 0 )
      {
         return TRUE;
      }
		
      if (info->relay && relayPort)
      {
         memcpy(&secondary, &from, sizeof (secondary));
         
         from.addr = info->myAddr.addr;
         from.port = relayPort;
      }
      
      ok = stunServerProcessMsg( msg, msgLen, &from, &secondary,
                                 recvAltIp ? &info->altAddr : &info->myAddr,
                                 recvAltIp ? &info->myAddr : &info->altAddr, 
                                 &resp,
                                 &dest,
                                 &hmacPassword,
                                 &changePort,
                                 &changeIp,
                                 verbose );
		
      if ( !ok )
      {
         if ( verbose ) printf ( "Failed to parse message\n");
         return TRUE;
      }
		
      len = stunEncodeMessage( &resp, buf, len, &hmacPassword,verbose );
		
      if ( dest.addr == 0 )  ok=FALSE;
      if ( dest.port == 0 ) ok=FALSE;
		
      if ( ok )
      {
         assert( dest.addr != 0 );
         assert( dest.port != 0 );
			
         sendAltIp   = recvAltIp;   /* send on the received IP address */
         sendAltPort = recvAltPort; /* send on the received port*/
			
         if ( changeIp )   sendAltIp   = !sendAltIp;   /* if need to change IP, then flip logic */
         if ( changePort ) sendAltPort = !sendAltPort; /* if need to change port, then flip logic */
			
         if ( !sendAltPort )
         {
            if ( !sendAltIp )
            {
               sendFd = info->myFd;
            }
            else
            {
               sendFd = info->altIpFd;
            }
         }
         else
         {
            if ( !sendAltIp )
            {
               sendFd = info->altPortFd;
            }
            else
            {
               sendFd = info->altIpPortFd;
            }
         }
	
         if ( sendFd != INVALID_SOCKET )
         {
            sendMessage( sendFd, buf, len, dest.addr, dest.port, verbose );
         }
      }
   }
	
   return TRUE;
}

int 
stunFindLocalInterfaces(UInt32* addresses,int maxRet)
{
#ifdef __WIN32__
	// XXX re-use interface code from hip_netlink.c here
	return 0;
#else /* __WIN32__ */
   struct ifconf ifc;
	
   int s = socket( AF_INET, SOCK_DGRAM, 0 );
   int len = 100 * sizeof(struct ifreq);
	
   char buf[ len ];
	
   ifc.ifc_len = len;
   ifc.ifc_buf = buf;
	
   int e = ioctl(s,SIOCGIFCONF,&ifc);
   char *ptr = buf;
   int tl = ifc.ifc_len;
   int si, count=0;

   struct ifreq *ifr, ifr2;
	
   struct sockaddr a;
   struct sockaddr_in* addr = (struct sockaddr_in*) &a;
   UInt32 ai;

   while ( (tl > 0) && ( count < maxRet) )
   {
      ifr = (struct ifreq *)ptr;
		
      si = sizeof(ifr->ifr_name) + sizeof(struct sockaddr);
      tl -= si;
      ptr += si;
      /*char* name = ifr->ifr_ifrn.ifrn_name;
      //cerr << "name = " << name << endl;*/
		
      ifr2 = *ifr;
		
      e = ioctl(s,SIOCGIFADDR,&ifr2);
      if ( e == -1 )
      {
         break;
      }
		
      /*cerr << "ioctl addr e = " << e << endl;*/
		
      a = ifr2.ifr_addr;
      addr = (struct sockaddr_in*) &a;
		
      ai = ntohl( addr->sin_addr.s_addr );
      if ((int)((ai>>24)&0xFF) != 127)
      {
         addresses[count++] = ai;
      }
		
#if 0
      fprintf (stderr, "Detected interface %u.%u.%u.%u\n",
		(int)((ai>>24)&0xFF), (int)((ai>>16)&0xFF),
		(int)((ai>> 8)&0xFF), (int)((ai    )&0xFF));
#endif
   }
	
   closesocket(s);
	
   return count;
#endif /* __WIN32__ */
}


void
stunBuildReqSimple( StunMessage* msg,
                    const StunAtrString *username,
                    int changePort, int changeIp, unsigned int id )
{
   int i, r;
   assert( msg );
   memset( msg , 0 , sizeof(*msg) );
	
   msg->msgHdr.msgType = BindRequestMsg;
	
   for ( i=0; i<16; i=i+4 )
   {
      assert(i+3<16);
      r = stunRand();
      msg->msgHdr.id.octet[i+0]= r>>0;
      msg->msgHdr.id.octet[i+1]= r>>8;
      msg->msgHdr.id.octet[i+2]= r>>16;
      msg->msgHdr.id.octet[i+3]= r>>24;
   }
	
   if ( id != 0 )
   {
      msg->msgHdr.id.octet[0] = id; 
   }
	
   msg->hasChangeRequest = TRUE;
   msg->changeRequest.value =(changeIp?ChangeIpFlag:0) | 
      (changePort?ChangePortFlag:0);
	
   if ( username->sizeValue > 0 )
   {
      msg->hasUsername = TRUE;
      memcpy(&msg->username, username, sizeof (username));
   }
}


static void 
stunSendTest( int myFd, StunAddress4 *dest, 
              const StunAtrString *username, const StunAtrString *password, 
              int testNum, int verbose )
{ 
   int changePort=FALSE;
   int changeIP=FALSE;
   int discard=FALSE;
	
   char buf[STUN_MAX_MESSAGE_SIZE];
   int len = STUN_MAX_MESSAGE_SIZE;
   
   StunMessage req;

   assert( dest->addr != 0 );
   assert( dest->port != 0 );
	
   switch (testNum)
   {
      case 1:
      case 10:
      case 11:
         break;
      case 2:
         /*changePort=TRUE;*/
         changeIP=TRUE;
         break;
      case 3:
         changePort=TRUE;
         break;
      case 4:
         changeIP=TRUE;
         break;
      case 5:
         discard=TRUE;
         break;
      default:
         fprintf(stderr, "Test %u is unknown\n", testNum);
         assert(0);
   }
	
   memset(&req, 0, sizeof(StunMessage));
	
   stunBuildReqSimple( &req, username, 
                       changePort , changeIP , 
                       testNum );
	
   len = stunEncodeMessage( &req, buf, len, password,verbose );
	
   if ( verbose )
   {
      printf ( "About to send msg of len %u to ", len);
      printIPv4Addr(dest);
      printf ("\n");
   }
	
   sendMessage( myFd, buf, len, dest->addr, dest->port, verbose );
	
   /* add some delay so the packets don't get sent too quickly */
#ifdef __WIN32__
   Sleep(10);
#else
		 usleep(10*1000);
#endif

}


void 
stunGetUserNameAndPassword(  const StunAddress4 *dest, 
                             StunAtrString* username,
                             StunAtrString* password)
{ 
   /* !cj! This is totally bogus - need to make TLS connection to dest and get a
   // username and password to use */
   stunCreateUserName(dest, username);
   stunCreatePassword(username, password);
}


void 
stunTest( StunAddress4 *dest, int testNum, int verbose, StunAddress4* sAddr )
{ 
   int port = stunRandomPort();
   UInt32 interfaceIp=0;
   int myFd;

   StunAtrString username;
   StunAtrString password;

   char msg[STUN_MAX_MESSAGE_SIZE];
   int msgLen = STUN_MAX_MESSAGE_SIZE;
   
   StunAddress4 from;
   StunMessage resp;
   int ok;

	
   assert( dest->addr != 0 );
   assert( dest->port != 0 );
	
   if (sAddr)
   {
      interfaceIp = sAddr->addr;
      if ( sAddr->port != 0 )
      {
        port = sAddr->port;
      }
   }
   myFd = openPort((UInt16)port,interfaceIp,verbose);
	
   username.sizeValue = 0;
   password.sizeValue = 0;
	
#ifdef USE_TLS
   stunGetUserNameAndPassword( dest, username, password );
#endif
	
   stunSendTest( myFd, dest, &username, &password, testNum, verbose );
    
   getMessage( myFd,
               msg,
               &msgLen,
               &from.addr,
               &from.port,verbose );
	
   memset(&resp, 0, sizeof(StunMessage));
	
   if ( verbose ) printf ( "Got a response\n");
   ok = stunParseMessage( msg,msgLen, &resp,verbose );
	
   if ( verbose )
   {
      printf ( "\t ok=%u\n", ok);
      printf ( "\t id=");
      printUInt128(resp.msgHdr.id);
      printf ( "\n\t mappedAddr=");
      printIPv4Addr(&resp.mappedAddress.ipv4);
      printf ( "\n\t changedAddr=");
      printIPv4Addr(&resp.changedAddress.ipv4);
      printf("\n");
   }
	
   if (sAddr)
   {
      sAddr->port = resp.mappedAddress.ipv4.port;
      sAddr->addr = resp.mappedAddress.ipv4.addr;
   }
}


NatType
stunNatType( StunAddress4 *dest, 
             int verbose,
             int* preservePort, /* if set, is return for if NAT preservers ports or not*/
             int* hairpin,  /* if set, is the return for if NAT will hairpin packets*/
             int portnb, /* port to use for the test, 0 to choose random port*/
             StunAddress4* sAddr /* NIC to use */
   )
{ 
   int i, port, myFd1, myFd2;
   UInt32 interfaceIp=0;

   StunAddress4 from;
   StunMessage resp;

   struct timeval tv;
   fd_set fdSet; 
   int fdSetSize, e, err;

   int myFd;
   char msg[STUN_MAX_MESSAGE_SIZE];
   int msgLen = sizeof(msg);

   int s;

   StunAtrString username;
   StunAtrString password;

   int count;

   int respTestI2=FALSE; 
   int respTestI=FALSE;
   int respTestII=FALSE;
   int respTestIII=FALSE;

   int respTestHairpin=FALSE;
   int respTestPreservePort=FALSE;
   int isNat=TRUE;
   int mappedIpSame = TRUE;

   StunAddress4 testI2dest;
   StunAddress4 testIchangedAddr;
   StunAddress4 testImappedAddr;
   StunAddress4 testI2mappedAddr;


   port = portnb ;

   assert( dest->addr != 0 );
   assert( dest->port != 0 );
	
   if ( hairpin ) 
   {
      *hairpin = FALSE;
   }
	
   if ( port == 0 )
   {
      port = stunRandomPort();
   }
   if (sAddr)
   {
      interfaceIp = sAddr->addr;
   }
   myFd1 = openPort((UInt16)port,interfaceIp,verbose);
   myFd2 = openPort((UInt16)(port+1),interfaceIp,verbose);

   if ( ( myFd1 == INVALID_SOCKET) || ( myFd2 == INVALID_SOCKET) )
   {
       fprintf(stderr, "Some problem opening port/interface to send on\n");
       return StunTypeFailure; 
   }

   assert( myFd1 != INVALID_SOCKET );
   assert( myFd2 != INVALID_SOCKET );
    
   memcpy(&testI2dest,dest,sizeof(dest));
   memset(&testImappedAddr,0,sizeof(testImappedAddr));
	
	
   username.sizeValue = 0;
   password.sizeValue = 0;
	
#ifdef USE_TLS 
   stunGetUserNameAndPassword( dest, &username, &password );
#endif
	
   count=0;
   while ( count < 7 )
   {
      FD_ZERO(&fdSet); fdSetSize=0;
      FD_SET((unsigned int)myFd1,&fdSet); 
      fdSetSize = (myFd1+1>fdSetSize) ? myFd1+1 : fdSetSize;
      FD_SET((unsigned int)myFd2,&fdSet); 
      fdSetSize = (myFd2+1>fdSetSize) ? myFd2+1 : fdSetSize;
      tv.tv_sec=0;
      tv.tv_usec=150*1000; /* 150 ms */
      if ( count == 0 ) tv.tv_usec=0;
		
      err = select(fdSetSize, &fdSet, NULL, NULL, &tv);
      e = errno;
      if ( err == SOCKET_ERROR )
      {
         /* error occured*/
         fprintf(stderr, "Error %u %s in select\n", e, strerror(e));
        return StunTypeFailure; 
     }
      else if ( err == 0 )
      {
         /* timeout occured */
         count++;
			
         if ( !respTestI ) 
         {
            stunSendTest( myFd1, dest, &username, &password, 1 ,verbose );
         }         
			
         if ( (!respTestI2) && respTestI ) 
         {
            /* check the address to send to if valid */
            if (  ( testI2dest.addr != 0 ) &&
                  ( testI2dest.port != 0 ) )
            {
               stunSendTest( myFd1, &testI2dest, &username, &password, 10  ,verbose);
            }
         }
			
         if ( !respTestII )
         {
            stunSendTest( myFd2, dest, &username, &password, 2 ,verbose );
         }
			
         if ( !respTestIII )
         {
            stunSendTest( myFd2, dest, &username, &password, 3 ,verbose );
         }
			
         if ( respTestI && (!respTestHairpin) )
         {
            if (  ( testImappedAddr.addr != 0 ) &&
                  ( testImappedAddr.port != 0 ) )
            {
               stunSendTest( myFd1, &testImappedAddr, &username, &password, 
			     11 ,verbose );
            }
         }
      }
      else
      {
      /*if (verbose) printf ( "-----------------------------------------\n");*/
         assert( err>0 );
         /* data is avialbe on some fd */
			
         for ( i=0; i<2; i++)
         {

            if ( i==0 ) 
            {
               myFd=myFd1;
            }
            else
            {
               myFd=myFd2;
            }
				
            if ( myFd!=INVALID_SOCKET ) 
            {					
               if ( FD_ISSET(myFd,&fdSet) )
               {
                  						

                  getMessage( myFd,
                              msg,
                              &msgLen,
                              &from.addr,
                              &from.port,verbose );
						

                  memset(&resp, 0, sizeof(StunMessage));
						
                  stunParseMessage( msg,msgLen, &resp,verbose );
						
                  if ( verbose )
                  {
                     printf ( "Received message of type %u id=%u\n", 
			      resp.msgHdr.msgType,
				(int)(resp.msgHdr.id.octet[0]));
                  }
						
                  switch( resp.msgHdr.id.octet[0] )
                  {
                     case 1:
                     {
                        if ( !respTestI )
                        {
									
                           testIchangedAddr.addr = resp.changedAddress.ipv4.addr;
                           testIchangedAddr.port = resp.changedAddress.ipv4.port;
                           testImappedAddr.addr = resp.mappedAddress.ipv4.addr;
                           testImappedAddr.port = resp.mappedAddress.ipv4.port;
			
                           respTestPreservePort = ( testImappedAddr.port == port ); 
                           if ( preservePort )
                           {
                              *preservePort = respTestPreservePort;
                           }								
									
                           testI2dest.addr = resp.changedAddress.ipv4.addr;
									
                           if (sAddr)
                           {
                              sAddr->port = testImappedAddr.port;
                              sAddr->addr = testImappedAddr.addr;
                           }
									
                           count = 0;
                        }		
                        respTestI=TRUE;
                     }
                     break;
                     case 2:
                     {  
                        respTestII=TRUE;
                     }
                     break;
                     case 3:
                     {
                        respTestIII=TRUE;
                     }
                     break;
                     case 10:
                     {
                        if ( !respTestI2 )
                        {
                           testI2mappedAddr.addr = resp.mappedAddress.ipv4.addr;
                           testI2mappedAddr.port = resp.mappedAddress.ipv4.port;
								
                           mappedIpSame = FALSE;
                           if ( (testI2mappedAddr.addr  == testImappedAddr.addr ) &&
                                (testI2mappedAddr.port == testImappedAddr.port ))
                           { 
                              mappedIpSame = TRUE;
                           }
								
							
                        }
                        respTestI2=TRUE;
                     }
                     break;
                     case 11:
                     {
							
                        if ( hairpin ) 
                        {
                           *hairpin = TRUE;
                        }
                        respTestHairpin = TRUE;
                     }
                     break;
                  }
               }
            }
         }
      }
   }
	
   /* see if we can bind to this address 
   //cerr << "try binding to " << testImappedAddr << endl;*/
   s = openPort( 0/*use ephemeral*/, testImappedAddr.addr, FALSE );
   if ( s != INVALID_SOCKET )
   {
      closesocket(s);
      isNat = FALSE;
      /*cerr << "binding worked\n");*/
   }
   else
   {
      isNat = TRUE;
      /*cerr << "binding failed\n");*/
   }
	
   if (verbose)
   {
      printf ( "test I = %u\n", respTestI);
      printf ( "test II = %u\n", respTestII);
      printf ( "test III = %u\n", respTestIII);
      printf ( "test I(2) = %u\n", respTestI2);
      printf ( "is nat  = %u\n", isNat);
      printf ( "mapped IP same = %u\n", mappedIpSame);
      printf ( "hairpin = %u\n", respTestHairpin);
      printf ( "preserver port = %u\n", respTestPreservePort);
   }
	
   if ( respTestI ) /* not blocked */
   {
      if ( isNat )
      {
         if ( mappedIpSame )
         {
            if (respTestII)
            {
               return StunTypeIndependentFilter;
            }
            else
            {
               if ( respTestIII )
               {
                  return StunTypeDependentFilter;
               }
               else
               {
                  return StunTypePortDependedFilter;
               }
            }
         }
         else /* mappedIp is not same */
         {
            return StunTypeDependentMapping;
         }
      }
      else  /* isNat is FALSE */
      {
         if (respTestII)
         {
            return StunTypeOpen;
         }
         else
         {
            return StunTypeFirewall;
         }
      }
   }
   else
   {
      return StunTypeBlocked;
   }
	
   return StunTypeUnknown;
}


int
stunOpenSocket( StunAddress4 *dest, StunAddress4* mapAddr, 
                int portnb, StunAddress4* srcAddr, 
                int verbose )
{
   int myFd, ok, port = portnb;
   unsigned int interfaceIp;
   char msg[STUN_MAX_MESSAGE_SIZE];
   int msgLen = sizeof(msg);

   StunAddress4 mappedAddr;
   StunAtrString username;
   StunAtrString password;
	
   StunAddress4 from;	
   StunMessage resp;

   assert( dest->addr != 0 );
   assert( dest->port != 0 );
   assert( mapAddr );
   
   if ( port == 0 )
   {
      port = stunRandomPort();
   }
   interfaceIp = 0;
   if ( srcAddr )
   {
      interfaceIp = srcAddr->addr;
   }
   
   myFd = openPort((UInt16)port,interfaceIp,verbose);
   if (myFd == INVALID_SOCKET)
   {
      return myFd;
   }
   
   username.sizeValue = 0;
   password.sizeValue = 0;
	
#ifdef USE_TLS
   stunGetUserNameAndPassword( dest, &username, &password );
#endif
	
   stunSendTest(myFd, dest, &username, &password, 1, 0/*FALSE*/ );
	
   getMessage( myFd, msg, &msgLen, &from.addr, &from.port,verbose );
   memset(&resp, 0, sizeof(StunMessage));
	
   ok = stunParseMessage( msg, msgLen, &resp,verbose );
   if (!ok)
   {
      return -1;
   }
	
   mappedAddr = resp.mappedAddress.ipv4;

   *mapAddr = mappedAddr;
	
   return myFd;
}


int
stunOpenSocketPair( StunAddress4 *dest, StunAddress4* mapAddr, 
                    int* fd1, int* fd2, 
                    int port, StunAddress4* srcAddr, 
                    int verbose )
{
   const int NUM=3;
   char msg[STUN_MAX_MESSAGE_SIZE];
   int msgLen =sizeof(msg);
	
   StunAddress4 from;
   int fd[3]; /* [NUM] */
   int i;
	
   unsigned int interfaceIp = 0;

   StunAtrString username;
   StunAtrString password;
   StunAddress4 mappedAddr[3]; /* [NUM] */

   int ok;

   StunMessage resp;
	
   assert( dest->addr!= 0 );
   assert( dest->port != 0 );
   assert( mapAddr );
   

   if ( port == 0 )
   {
      port = stunRandomPort();
   }
	
   *fd1=-1;
   *fd2=-1;
	
   if ( srcAddr )
   {
      interfaceIp = srcAddr->addr;
   }

   for( i=0; i<NUM; i++)
   {
      fd[i] = openPort( (UInt16)((port == 0) ? 0 : (port + i)), 
                        interfaceIp, verbose);
      if (fd[i] < 0) 
      {
         while (i > 0)
         {
            closesocket(fd[--i]);
         }
         return FALSE;
      }
   }
	
   username.sizeValue = 0;
   password.sizeValue = 0;
	
#ifdef USE_TLS
   stunGetUserNameAndPassword( dest, &username, &password );
#endif
	
   for( i=0; i<NUM; i++)
   {
      stunSendTest(fd[i], dest, &username, &password, 1/*testNum*/, verbose );
   }
	

   for( i=0; i<NUM; i++)
   {
      msgLen = sizeof(msg)/sizeof(*msg);
      getMessage( fd[i],
                  msg,
                  &msgLen,
                  &from.addr,
                  &from.port ,verbose);
		

      memset(&resp, 0, sizeof(StunMessage));
		
      ok = stunParseMessage( msg, msgLen, &resp, verbose );
      if (!ok) 
      {
         return FALSE;
      }
		
      mappedAddr[i] = resp.mappedAddress.ipv4;
   }
	
   if (verbose)
   {               
      printf ( "--- stunOpenSocketPair --- ");
      for( i=0; i<NUM; i++)
      {
         printf ( "\n\t mappedAddr=");
	 printIPv4Addr(&mappedAddr[i]);
      }
      printf("\n");
   }
	
   if ( mappedAddr[0].port %2 == 0 )
   {
      if (  mappedAddr[0].port+1 ==  mappedAddr[1].port )
      {
         *mapAddr = mappedAddr[0];
         *fd1 = fd[0];
         *fd2 = fd[1];
         closesocket( fd[2] );
         return TRUE;
      }
   }
   else
   {
      if (( mappedAddr[1].port %2 == 0 )
          && (  mappedAddr[1].port+1 ==  mappedAddr[2].port ))
      {
         *mapAddr = mappedAddr[1];
         *fd1 = fd[1];
         *fd2 = fd[2];
         closesocket( fd[0] );
         return TRUE;
      }
   }

   /* something failed, close all and return error */
   for( i=0; i<NUM; i++)
   {
      closesocket( fd[i] );
   }
	
   return FALSE;
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

