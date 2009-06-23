#ifndef SCUTILS_H
#define SCUTILS_H

#include <openssl/ssl.h>
#include <openssl/engine.h>

#define NAMELENGTH 256
#define BUFFERSIZE 1024
#define NUM_RETRIES 0
#define NUM_PING_RETRIES 3

int 		load_engine_fn(ENGINE *e, const char *engine_id,
			       const char **pre_cmds, int pre_num,
			       const char **post_cmds, int post_num);
ENGINE *	engine_init(char *pin);
void 		engine_teardown(ENGINE *e);
int 		verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
EVP_PKEY *	load_sc_pkey(const char *file, ENGINE *e, const char *pin);
SSL_CTX *	ssl_ctx_init(ENGINE *e, const char *pin);
#endif
