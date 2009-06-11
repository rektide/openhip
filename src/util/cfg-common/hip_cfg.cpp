#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <iostream>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <hip/hip_cfg.h>

#define SA2IP(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? \
        (void *)&((struct sockaddr_in*)x)->sin_addr : \
        (void *)&((struct sockaddr_in6*)x)->sin6_addr
#define SALEN(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? \ 
        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)
#define SAIPLEN(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? 4 : 16
#define SA(x) ((struct sockaddr*)x)

int hipCfg::str_to_addr(const char *data, struct sockaddr *addr)
{
        /* TODO: use platform-independent getaddrinfo() w/AI_NUMERICHOST */
#ifdef __WIN32__
        int len = SALEN(addr);
        return(WSAStringToAddress((LPSTR)data, addr->sa_family, NULL,
                        addr, &len)==0);
#else
        return(inet_pton(addr->sa_family, (char*)data, SA2IP(addr)));
#endif
}

int hipCfg::addr_to_str(const struct sockaddr *addr, char *data, int len)
{
#ifdef __WIN32__
        DWORD dw = (DWORD)len;
        return(WSAAddressToString(addr, SALEN(addr), NULL, data, &dw)!=0);
#else
        return(inet_ntop(addr->sa_family, SA2IP(addr), data, len)==NULL);
#endif
}

certInfo::~certInfo()
{
}

int hipCfg::hit2hitstr(char *hit_str, const hip_hit hit)
{
  struct sockaddr *addr;
  struct sockaddr_storage ss_addr;

  addr = (struct sockaddr*) &ss_addr;
  memset(&ss_addr, 0, sizeof(struct sockaddr_storage));
  ss_addr.ss_family = AF_INET6;
  memcpy(SA2IP(&ss_addr), hit, SAIPLEN(&ss_addr));
#ifdef __WIN32__
   DWORD dw = (DWORD)INET6_ADDRSTRLEN;
   return(WSAAddressToString(&ss_addr, SALEN(&ss_addr), NULL, hit_str, &dw)!=0);
#else
   return(inet_ntop(addr->sa_family, SA2IP(addr), hit_str, INET6_ADDRSTRLEN)==NULL);
#endif
}

int hipCfg::hitstr2hit(hip_hit hit, char *hit_str)
{
  struct sockaddr *addr;
  struct sockaddr_storage ss_addr;

  addr = (struct sockaddr*) &ss_addr;
  if(strchr(hit_str, ':')){
        memset(addr, 0,sizeof(struct sockaddr_storage)); 
        addr->sa_family = AF_INET6;
        if(str_to_addr(hit_str, addr) <= 0) { 
          cerr<<"invalid HIT value: "<<hit_str<<endl;
	  return -1; 
         }
         memcpy(hit, SA2IP(addr), HIT_SIZE);
	 return 0;
  }
  return hex_to_bin(hit_str, (char *)hit, HIT_SIZE); 
}

void hitPair::print() const
{
  printf("hit1: %02x%02x, hit2: %02x%02x\n", _hit1[HIT_SIZE-2], _hit1[HIT_SIZE-1], _hit2[HIT_SIZE-2], _hit2[HIT_SIZE-1]);
}

int hipCfg::hit_peer_allowed(const hip_hit hit1, const hip_hit hit2)
{

  int i;
  set <hitPair>::iterator si;
  hitPair *hpp;
/*
  cout<<endl<<"hit_peer_allowed called with hit1: ";
  for(i=0; i<sizeof(hip_hit); i++)
     printf("%02x", hit1[i]);
  cout<<"  hit2: ";
  for(i=0; i<sizeof(hip_hit); i++)
     printf("%02x", hit2[i]);
  cout<<endl;
*/
 if(memcmp(hit1, hit2, HIT_SIZE) <0){
     hpp = new hitPair(hit1, hit2);
 } else if(memcmp(hit1, hit2, HIT_SIZE) >0) {
     hpp= new hitPair(hit2, hit1);
 } else
    return 1;

  si = _allowed_peers.find(*hpp);
  if(si == _allowed_peers.end()){
    delete hpp;
    return 0;
  }

  delete hpp;
  return 1;
}

int hipCfg::peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt)
{
   set <hitPair, hp_compare>::iterator i;
   int j;
   for(j=0, i=_allowed_peers.begin(); i!=_allowed_peers.end(); i++, j++){
     hitPair hp = *i;
     if(j>=max_cnt)
	return -1;
     memcpy(hits1[j], hp._hit1, HIT_SIZE);
     memcpy(hits2[j], hp._hit2, HIT_SIZE);
   }
   return j;
}

/* return 0 if the maping found, 1 otherwise */
int hipCfg::legacyNodeToEndbox(const struct sockaddr *host, struct sockaddr *eb)
{
  char host_s[128];
  string host_str;
  string ip_s;

  addr_to_str(host, host_s, 128);

  //cout<<"legacyNodeToEndbox: look up host = "<<host_s<<endl;
  host_str = host_s;

  map <string, string>::iterator i;
  i = _legacyNode2EndboxMap.find(host_str);
  if(i != _legacyNode2EndboxMap.end()){
    ip_s = (*i).second;
    if(eb->sa_family!=AF_INET)
	eb->sa_family = AF_INET6; //default to return HIT
    if(eb->sa_family==AF_INET){
	char lsi_s[INET_ADDRSTRLEN];
	hitstr2lsistr(lsi_s, (char *)ip_s.c_str());
	str_to_addr(lsi_s, eb);
    } else
      str_to_addr(ip_s.c_str(), eb);
    //cout<<"legacyNodeToEndbox: get eb "<<ip_s.c_str()<<" for host = "<<host_s<<endl;
    return 0;
  }
  return 1;
}

int hipCfg::getLegacyNodesByEndbox(const struct sockaddr *eb, struct sockaddr_storage *hosts, int size)
{
  char eb_s[128];
  char eb_lsi[INET_ADDRSTRLEN];
  addr_to_str(eb, eb_s, 128);
  int idx = 0;
  map <string, string>::iterator i;
  for(i=_legacyNode2EndboxMap.begin(); i!=_legacyNode2EndboxMap.end(); i++){
     string host = (*i).first;
     string endbox = (*i).second;
     if(eb->sa_family==AF_INET){
	hitstr2lsistr(eb_lsi, (char *)endbox.c_str());
	endbox = eb_lsi;
     }
     if(endbox==eb_s && endbox != host) {
	if(idx>=size) {
	   cout<<"error calling getLegacyNodesByEndbox: hosts array too small"<<endl;
	   return -1;
 	}
	struct sockaddr_storage host_ss;
        struct sockaddr *host_p = (struct sockaddr *)(&host_ss);
	host_p->sa_family=AF_INET; //only handle IPv4 address only
	str_to_addr(host.c_str(), host_p);
	hosts[idx++] = host_ss;
     }
  }
  return idx;
}

int  hipCfg::endbox2Llip(const struct sockaddr *eb, struct sockaddr *llip)
{
  char eb_s[INET6_ADDRSTRLEN];
  string llip_s;
  int rc;

  memset(eb_s, 0, INET6_ADDRSTRLEN);
  rc=addr_to_str(eb, eb_s, INET6_ADDRSTRLEN);
  if(rc)
    return -1;

  //cout<<"endbox2Llip: look up bcwin for endbox = "<<eb_s<<endl;

  map <string, string>::iterator i;
  i = _endbox2LlipMap.find(eb_s);
  if(i != _endbox2LlipMap.end()){
    llip_s = (*i).second;
    llip->sa_family=AF_INET; //only handle IPv4 address only
    str_to_addr(llip_s.c_str(), llip);
    //cout<<"endbox2Llip: get llip (bcwin) "<<llip_s.c_str()<<" for endbox = "<<eb_s<<endl;
    return 0;
  }
  return 1;
}

/*
 *  
 * hex_to_bin()
 * in:          src = input hex data
 *              dst = output binary data
 *              dst_len = requested number of binary bytes
 * out:         returns bytes converted if successful,
 *              -1 if error
 */
int hipCfg::hex_to_bin(char *src, char *dst, int dst_len)
{
        char hex[] = "0123456789abcdef";
        char hexcap[] = "0123456789ABCDEF";
        char *p, c;
        int src_len, total, i, val;
        unsigned char o;

        if ((!src) || (!dst))
                return(-1);
        src_len = strlen(src);
        if (dst_len > src_len)
                return(-1);

        /* chop any '0x' prefix */
        if ((src[0]=='0') && (src[1]=='x')) {
                src += 2;
                src_len -= 2;
        }

        /* convert requested number of bytes from hex to binary */
        total = 0;
        for (i=0; (i < src_len) && (total < dst_len) ; i+=2) {
                /* most significant nibble */
                c = src[i];
                /*
 *                  * Normally would use tolower(), but have found problems
 *                                   * with dynamic linking and different glibc versions
 *                                                    */
                if ((p = strchr(hex, c)) == NULL) {
                        if ((p = strchr(hexcap, c)) == NULL) {
                                continue;
                        }
                        val = p - hexcap;
                } else {
                        val = p - hex;
                }
                if (val < 0 || val > 15) {
                        cerr<<"Binary conversion failed " <<c<<endl;
                        return(-1);
                }
                o = val << 4;
                /* least significant nibble */
                c = src[i+1];
                if ((p = strchr(hex, c)) == NULL) {
                        if ((p = strchr(hexcap, c)) == NULL) {
                                continue;
                        }
                        val = p - hexcap;
                } else {
                        val = p - hex;
                }
                if (val < 0 || val > 15) {
                        cerr<<"Binary conversion failed " << c <<endl;
                        return(-1);
                }
                o += val;
                dst[total] = o;
                total++;
                if (total >= src_len)
                        total = dst_len;
        }
        return total;
}

#define HIT2LSI(a) ( 0x01000000L | \
        ((a[HIT_SIZE-3]<<16)+(a[HIT_SIZE-2]<<8)+(a[HIT_SIZE-1])))

int hipCfg::hitstr2lsistr(char *lsi_str, char *hit_str)
{
  hip_hit hit;
  hitstr2hit(hit, hit_str);
  struct sockaddr_in lsi;
  lsi.sin_family = AF_INET;
  lsi.sin_addr.s_addr = ntohl(HIT2LSI(hit));
  return addr_to_str(SA(&lsi), lsi_str, INET_ADDRSTRLEN);
}
