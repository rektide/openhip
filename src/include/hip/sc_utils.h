#ifndef SCUTILS_H
#define SCUTILS_H

#include <openssl/ssl.h>
#include <openssl/engine.h>

#include <opensc/opensc.h>
#include <opensc/pkcs15.h>

#define NAMELENGTH 256
#define BUFFERSIZE 1024
#define NUM_RETRIES 0
#define NUM_PING_RETRIES 3
#define MAX_PINSIZE 8

enum HTTP_REQUEST_TYPE {
		    HTTP_HEADER, 
		    CERT_REQ, 
		    IPSEC_SC_CONF, 
		    IPSEC_SC_SECRETS, 
		    IPSEC_TC_CONF, 
		    IPSEC_TC_SECRETS
		       };

enum DATA_REQUEST_TYPE {
		    TCERT_FILE, 
		    TCERT_KEY_FILE, 
		    SCCERT_FILE, 
		    IPSEC_CONF_FILE, 
		    IPSEC_SECRETS_FILE, 
		    SC_PIN,
		    VPN_SERVER,
		    HTTPS_SERVER,
		    IPSEC_CONF,
		    NETWORK_INTERFACE,
		    LDAP_UPDATE,
		    MY_HOST
		       };

enum IPSEC_ERRORS {
		    NO_DETECTED_ERROR=0,
		    NETWORK_ERROR,
		    CERT_ERROR_LOCAL,
		    CERT_READ_ERROR,
		    CERT_EXPIRED_LOCAL,
		    CERT_EXPIRED_REMOTE,
		    STALE_SA,
		    IPSEC_TO_PHYS_INT_ERROR,
		    NO_ISAKMP
		  };

	       
struct vpn {
    char addr[NAMELENGTH];
    char gw[NAMELENGTH];
    char subnet[NAMELENGTH];
    char dn[NAMELENGTH];
};

void *		my_malloc(const char *caller, size_t size);
void *		my_calloc(const char *caller, size_t nmemb, size_t size);
void *		my_realloc(const char *caller, void *ptr_old, size_t size);
void 		my_free(const char *caller, void *ptr);
void 		proc_config(char * conf_filename);
void 		print_options();
int 		tcp_connect();
int 		load_engine_fn(ENGINE *e, const char *engine_id,
			       const char **pre_cmds, int pre_num,
			       const char **post_cmds, int post_num);
ENGINE *	engine_init(char *pin);
void 		engine_teardown(ENGINE *e);
int 		verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
EVP_PKEY *	load_sc_pkey(const char *file, ENGINE *e, const char *pin);
SSL_CTX *	ssl_ctx_init(ENGINE *e, const char *pin);
int 		send_bytes(SSL *ssl, int nbytes, char *ptr);
int 		recv_bytes(SSL *ssl, int nbytes, char *ptr);
char *		msgrecv(SSL *ssl, int *nread);
int 		bio_setup( FILE * outputFile );
void 		bio_teardown();
char *		make_message(int message_len, const char *fmt, ...);
char *		read_file(char *fname, int *nread);
char *		url_encode(char *string);
char *		generate_request(int form);
char *		parse_cert(char *input);
int 		write_file(char *data, char *fname);
int 		connect_card(struct sc_context *ctx, struct sc_card **cardp,
			     int reader_id, int slot_id);
int 		connect_card2(struct sc_context *ctx, struct sc_card **cardp,
			      int reader_id, int slot_id, int wait);
int 		read_sc_cert(struct sc_pkcs15_card *p15card, char *outfile, u8 *buf);
int 		verify_pin(struct sc_pkcs15_card *p15card, const char *pincode);
int 		check_files();
int 		remove_files();
void *		get_data(int flag);
void 		put_data(int flag, void *data);
int 		getPlutoPID(char * plutoPID, int nTries);
int 		checkIPSecErrors(char * plutoPID);
int 		checkIPSecErrorLog();
int 		checkIPSecRuntime();
int		checkIPSecInterface();
int 		checkIPSecIFConnections();
int 		pcscStart();
int 		pcscStatus();
int 		pcscStop();
int 		ipsecStart();
int 		ipsecStop();
int 		ipsecRestart();
int 		ipsecReplaceConnection(char * connName);
int 		ipsecRestartConnection(char * connName);
int 		ipsecDeleteConnection(char * connName);
int 		ipsecReattachConnection();
int		isWirelessUp();
int		isWirelessConfig();
int		pingVPN();
int		pingRA();

#endif
