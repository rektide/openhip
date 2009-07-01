#ifndef _HIPSPD_FILES_H
#define _HIPSPD_FILES_H
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <hip/hip_cfg.h>

class hipCfgFiles : public hipCfg
{
public:
  int loadCfg(struct hip_conf *hc);
  int closeCfg();
  int postLocalCert(const char *hit);
  int verifyCert(const char *url, const hip_hit hit);
  static hipCfgFiles *getInstance();

private:
  hipCfgFiles();

private:
  static hipCfgFiles *_instance;
};

#endif
