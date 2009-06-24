#ifndef _HIPSPD_LDAP_H_
#define _HIPSPD_LDAP_H_
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <hip/hip_cfg.h>
#include "LDAPConnection.h"

class hipCfgLdap : public hipCfg
{
public:
  int loadCfg(struct hip_conf *hc);
  int closeCfg();
  int postLocalCert(const char *hit);
  int verifyCert(const char *url, const hip_hit hit);
  static hipCfgLdap *getInstance();

private:
  hipCfgLdap();
  int connectToLdap();
  void disconnectLdap();
  int getCertFromLdap(const char *url, char *buf, int size);
  int getEndboxMapsFromLdap();
  int getPeerAllowedFromLdap();

private:
  string _basedn;
  static LDAPConnection *_lc;
  static hipCfgLdap *_instance;
};

#endif
