#ifndef _HIPSPD_LDAP_H_
#define _HIPSPD_LDAP_H_
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <hip/hip_cfg.h>
#include "LDAPConnection.h"
#include "hip_types.h"

class hipCfgLdap : public hipCfg
{
public:
  int loadCfg(struct hip_conf *hc);
  int getLocalCertUrl(char *url, int size);
  int postLocalCert(const char *hit);
  int verifyCert(const char *url, const hip_hit hit);
  hi_node *getMyHostId(){ return _hostid;};
  int getPeerNodes(struct peer_node *peerNodes, int max_count);
  static hipCfgLdap *getInstance();

private:
  hipCfgLdap();
  int connectToLdap();
  void disconnectLdap();
  int getCertFromLdap(const char *url, char *buf, int size);
  int getCertFromSc(char *buf, int size);
  int connect_card(struct sc_context *ctx, struct sc_card **cardp,
                 int reader_id, int slot_id, int wait);
  int verify_pin(struct sc_pkcs15_card *p15card, const char *pincode);
  int read_sc_cert(struct sc_pkcs15_card *p15card, u8 *out_buf, int len);
  int init_ssl_context();
  int hi_to_hit(hi_node *hi, hip_hit hit);
  int khi_hi_input(hi_node *hi, __u8 *out);
  int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len);
  int khi_encode_n(__u8 *in, int len, __u8 *out, int n);
  ENGINE *engine_init(const char *pin);
  int load_engine_fn(ENGINE *e, const char *engine_id,
                   const char **pre_cmds, int pre_num,
                   const char **post_cmds, int post_num);

  void engine_teardown(ENGINE *e);
  SSL_CTX *ssl_ctx_init(ENGINE *e, const char *pin);
  int mkHIfromSc();
  int mkHIfromPkey(RSA *rsa, DSA *dsa,  hi_node *hostid);
  int getEndboxMapsFromLdap();
  int getEndboxMapsFromLocalFile();
  int getPeerAllowedFromLdap();
  int verify_certificate(X509 *cert);
  static int callb(int rc, X509_STORE_CTX *ctx);

private:
  map <string, struct peer_node *> _hit_to_peers; /* configured peers indexed by hit string */
  string _basedn;
  static LDAPConnection *_lc;
  static hipCfgLdap *_instance;
  string _scPrivKeyID;
  string _scPin;
  string _scCert;
  hi_node *_hostid;
  SSL *_ssl;
  X509_STORE *_store;
  RSA *_rsa;
  DSA *_dsa;
  struct hip_conf *_hcfg;
};

#endif
