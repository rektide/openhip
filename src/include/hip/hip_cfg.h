#ifndef _HIPSPD_H_
#define _HIPSPD_H_
#include <netinet/in.h>
#include <netinet/ether.h>
#include <map>
#include <set>
#include <string>

#define HIT_SIZE 16
typedef __u8 hip_hit [HIT_SIZE];

using namespace std;

class certInfo
{
public:
  certInfo(char *hit) { _hit = hit; time(&_ts);};
  ~certInfo();
   time_t getTs() { return _ts; };
   const char *getHit() { return _hit.c_str(); };
  certInfo(){};

private:
  string _hit;
  time_t _ts;
};

class hitPair
{
public:
  hitPair(const hip_hit hit1, const hip_hit hit2);
  void print() const;
  bool operator<(const hitPair & hp) const;

public:
  hip_hit _hit1;
  hip_hit _hit2;
};

struct hp_compare
{
bool operator ()(const hitPair & hp1, const hitPair & hp2)
{
  return hp1 < hp2;
}
};


class hipCfg{
public:
  hipCfg(){};
  virtual ~hipCfg(){};
  int hit_peer_allowed(const hip_hit hit1, const hip_hit hit2);
  int peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt);
  int legacyNodeToEndbox(const struct sockaddr *host, struct sockaddr *eb);
  int endbox2Llip(const struct sockaddr *eb, struct sockaddr *llip);
  int getLegacyNodesByEndbox(const struct sockaddr *eb,
			     struct sockaddr_storage *hosts, int size);
  virtual int getLocalCertUrl(char *url, int size) = 0;
  virtual int verifyCert(const char *url, const hip_hit hit) = 0;
  virtual int postLocalCert(const char *hit) = 0;
  virtual int loadCfg(struct hip_conf *hc) = 0;
  static int hit2hitstr(char *hit_str, const hip_hit hit);
  static int hitstr2lsistr(char *lsi_str, char *hit_str);
  static int addr_to_str(const struct sockaddr *addr, char *data, int len);
  static int hitstr2hit(hip_hit hit, char *hit_str);
  static int hex_to_bin(char *src, char *dst, int dst_len);
  static int str_to_addr(const char *data, struct sockaddr *addr);

protected:
  map <string, string> _legacyNode2EndboxMap;
  map <string, string> _endbox2LlipMap; /* endbox (LSI) to Llip (BCWIN) mapping */
  string _localCertUrl;
  map <string, certInfo> _certs; /* cached certificates data indexed by cert url*/
  set <hitPair, hp_compare> _allowed_peers; /* pairs of hits allowed to start HIP base exchange */
};

#endif
