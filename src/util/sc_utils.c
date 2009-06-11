#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include <opensc/opensc.h>
#include <opensc/pkcs15.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#include <hip/sc_utils.h>

char scPrivKeyID[NAMELENGTH] = "45";

/*******************************************************************/
/*  connect_card2

Taken from opensc/util.c
Had to change slots[] to slot_ids[] because of QT conflict.

returns: 0 on success, -1 on failure.
*/
int connect_card2(struct sc_context *ctx, struct sc_card **cardp,
		 int reader_id, int slot_id, int wait)
{
    const char *fn_name = "connect_card2";
    sc_reader_t *reader;
    sc_card_t *card;
    int r;

    if (wait) {
	struct sc_reader *readers[16];
	int slot_ids[16];
	int i, j, k, found;
	unsigned int event;

	for (i = k = 0; i < ctx->reader_count; i++) {
	    if (reader_id >= 0 && reader_id != i)
		continue;
	    reader = ctx->reader[i];
	    for (j = 0; j < reader->slot_count; j++, k++) {
		readers[k] = reader;
		slot_ids[k] = j;
	    }
	}

	printf("%s: Waiting for card to be inserted...\n",
		   fn_name);
	r = sc_wait_for_event(readers, slot_ids, k,
			SC_EVENT_CARD_INSERTED | SC_EVENT_CARD_REMOVED,
			&found, &event, -1);
	if (r < 0) {
		printf("Error while waiting for card: %s\n",
			   sc_strerror(r));
		return -3;
	}

	reader = readers[found];
	slot_id = slot_ids[found];
    } else {
	if (reader_id < 0)
	    reader_id = 0;
	if (ctx->reader_count == 0) {
	    printf("%s: No smart card readers configured.\n",
		       fn_name);
	    return -1;
	}
	if (reader_id >= ctx->reader_count) {
	    printf("%s: Illegal reader number. "
		    "Only %d reader(s) configured.\n",
		    fn_name, ctx->reader_count);
	    return -1;
	}

	reader = ctx->reader[reader_id];
	slot_id = 0;
	if (sc_detect_card_presence(reader, 0) <= 0) {
	    printf("%s: Card not present.\n", fn_name);
	    return -3;
	}
    }

    printf("%s: Connecting to card in reader %s...\n",
    	       fn_name, reader->name);
    if ((r = sc_connect_card(reader, slot_id, &card)) < 0) {
	printf("%s: Failed to connect to card: %s\n",
		   fn_name, sc_strerror(r));
	return -1;
    }

    printf("%s: Using card driver %s.\n",
    	       fn_name, card->driver->name);

    if ((r = sc_lock(card)) < 0) {
	printf("%s: Failed to lock card: %s\n",
		   fn_name, sc_strerror(r));
	sc_disconnect_card(card, 0);
	return -1;
    }

    *cardp = card;
    return 0;
}

/*******************************************************************/
/*  verify_pin

Verifies PIN entry for PKCS15 smartcard

returns: 0 on success
	 -1 on card errors
	 -2 on invalid pin
	 -3 on incorrect pin
	 -4 on blocked card
*/
int verify_pin(struct sc_pkcs15_card *p15card, const char *pincode)
{
    const char *fn_name = "verify_pin";

    struct sc_pkcs15_object *key, *pin;
    struct sc_pkcs15_id	id;
    int rc;
    char usage_name[NAMELENGTH] = "signature";
    int usage = SC_PKCS15_PRKEY_USAGE_SIGN;

    if (pincode == NULL || *pincode == '\0')
    	return -2;

    if (strlen(pincode) > MAX_PINSIZE)
    	return -2;

    printf("%s: Usage-name [hardcoded]: %s [0x%2X]\n",
    	       fn_name, usage_name, usage);
    sc_pkcs15_hex_string_to_id(scPrivKeyID, &id);
    rc = sc_pkcs15_find_prkey_by_id_usage(p15card, NULL, usage, &key);
    if (rc < 0)
    {
    	printf("%s: Unable to find private %s [0x%2X] key"
			   " '%s': %s\n",
			   fn_name, usage_name, usage, 
			   scPrivKeyID, sc_strerror(rc));
	return -1;
    }

    if (key->auth_id.len)
    {
    	rc = sc_pkcs15_find_pin_by_auth_id(p15card, &key->auth_id, &pin);
	if (rc)
	{
	    printf("%s: Unable to find PIN code for private key: %s: %s\n",
	    	       fn_name, scPrivKeyID, sc_strerror(rc));
	    return -1;
	}

	rc = sc_pkcs15_verify_pin(p15card, 
				  (struct sc_pkcs15_pin_info *)pin->data,
				  (const u8 *)pincode,
				  strlen(pincode));
	if (rc)
	{
	    printf("%s: PIN code verification failed: rc: %d: %s\n",
	    	       fn_name, rc, sc_strerror(rc));
	    if (rc == SC_ERROR_PIN_CODE_INCORRECT)
		return -3;
	    else if (rc == SC_ERROR_AUTH_METHOD_BLOCKED)
	    	return -4;
	    else return -1;
	}

	printf("%s: PIN code correct\n", fn_name);
    }
    return 0;
}

/*******************************************************************/
/*  read_sc_cert

Reads certificate from pkcs15 smartcard with same ID as private key.

Writes PEM encoded cert to file specified in outfile (if outfile != NULL),
and to the bio_info output.

returns: 0 on success, -1 on failure.
*/
int read_sc_cert(struct sc_pkcs15_card *p15card, char *outfile, u8 *out_buf)
{
    const char *fn_name = "read_sc_cert";

    int rc;
    struct sc_pkcs15_id id;
    struct sc_pkcs15_object *obj;
    FILE *certfile;
    u8 buf[2048];

    id.len = SC_PKCS15_MAX_ID_SIZE;
    sc_pkcs15_hex_string_to_id(scPrivKeyID, &id);
    rc = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, &obj, 1);
    if (rc < 0)
    {
    	printf("%s: get object failed: %s\n", fn_name, sc_strerror(rc));
	return -1;
    }

    struct sc_pkcs15_cert_info *cinfo = (struct sc_pkcs15_cert_info *)obj->data;
    struct sc_pkcs15_cert *cert;

    if (sc_pkcs15_compare_id(&id, &cinfo->id) != 1)
    {
    	printf("%s: Cert IDs do not match!\n", fn_name);
	return -1;
    }
    /* read cert */
    rc = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
    if (rc)
    {
    	printf("%s: Cert read failed: %s\n", fn_name, sc_strerror(rc));
	return -1;
    }

    /* convert cert to base64 format */
    rc = sc_base64_encode(cert->data, cert->data_len, buf, sizeof(buf), 64);
    if (rc < 0)
    {
    	printf("%s: Base64 encoding failed: %s\n",
		   fn_name, sc_strerror(rc));
	return -1;
    }

    /* write cert to file if a file is specified */
    if (outfile != NULL)
    {
	if ((certfile = fopen(outfile, "w")) == NULL)
	{
	    printf("%s: Can't open file %s\n", fn_name, outfile);
	    return -1;
	}
	fprintf(certfile, "-----BEGIN CERTIFICATE-----\n"
			 "%s"
			 "-----END CERTIFICATE-----\n",
			 buf);
	fclose(certfile);
    }

    sprintf((char *)out_buf,"-----BEGIN CERTIFICATE-----\n"
			"%s"
			"-----END CERTIFICATE-----\n",
			buf);
    return 0;
}

int 
pcscStop()
{
    static const char * fnName = "pcscStop";

    int rc = 0;
    rc = system("/etc/init.d/pcscd stop");
    return rc;
}

int load_engine_fn(ENGINE *e, const char *engine_id,
		   const char **pre_cmds, int pre_num,
		   const char **post_cmds, int post_num)
{
    const char *fn_name = "load_engine_fn";

    /* This code is written from examples given in the manpage
       for openssl-0.9.7c engine (man 3 engine) */

    /* Process pre-initialize commands */
    while (pre_num--)
    {
    	if (!ENGINE_ctrl_cmd_string(e, pre_cmds[0], pre_cmds[1], 0))
	{
	    printf("%s: Failed pre command (%s - %s:%s)\n",
	    	      fn_name, engine_id, pre_cmds[0],
		      (pre_cmds[1] ? pre_cmds[1] : "(NULL)"));
	    ENGINE_free(e);
	    return 0;
	}
	printf("%s: Engine pre-init command (%s - %s:%s)\n",
		   fn_name, engine_id, pre_cmds[0],
		   (pre_cmds[1] ? pre_cmds[1] : "(NULL)"));
	pre_cmds += 2;
    }

    if (!ENGINE_init(e))
    {
    	printf("%s: Failed engine initialization for %s\n",
		  fn_name, engine_id);
	ENGINE_free(e);
	return 0;
    }

    /* ENGINE_init() returned a functional reference, so free the */
    /* structural reference with ENGINE_free */
    ENGINE_free(e);

    /* Process post-initialize commands */
    while (post_num--)
    {
    	if (!ENGINE_ctrl_cmd_string(e, post_cmds[0], post_cmds[1], 0))
	{
	   printf("%s: Failed post command (%s - %s:%s)\n",
	    	      fn_name, engine_id, post_cmds[0],
		      (post_cmds[1] ? post_cmds[1] : "(NULL)"));
	    /* Release the functional reference with ENGINE_finish */
	    ENGINE_finish(e);
	    return 0;
	}
	/* Don't display PIN! */
	printf("%s: Engine post-init command (%s - %s:XXXXXXXX)\n",
		   fn_name, engine_id, post_cmds[0]);
	post_cmds += 2;
    }

    ENGINE_set_default(e, ENGINE_METHOD_RSA);

    printf("%s: Engine pre and post commands successfully applied to \"%s\"\n",
    	       fn_name, engine_id);

    return 1;
}

ENGINE *engine_init(char *pin)
{
    const char *fn_name = "engine_init";
    char opensc_engine[NAMELENGTH] = "/usr/lib/opensc/engine_opensc.so";

    ENGINE *e;
    const char *engine_id = "dynamic";
    const char *pre_cmds[] = { "SO_PATH", opensc_engine,
    			       "ID", "opensc",
			       "LIST_ADD", "1",
			       "LOAD", NULL };
    int pre_num = 4;
    char *post_cmds[] = { "PIN", "123456"};
    int post_num = 1;

    ENGINE_load_builtin_engines();

    e = ENGINE_by_id(engine_id);
    if (!e)
    {
    	printf("%s: Engine isn't available: %s\n", fn_name, engine_id);
	return NULL;
    }

    if(pin)
      post_cmds[1]=pin;

    if (!load_engine_fn(e, engine_id, pre_cmds, pre_num, (const char **)post_cmds, post_num))
    {
    	printf("%s: load_engine_fn() failed for %s\n",
		  fn_name, engine_id);
	return NULL;
    }

    if (!ENGINE_set_default_RSA(e))
    {
    	printf("%s: Couldn't set RSA method on engine: %s\n",
		  fn_name, engine_id);
	return NULL;
    }
    ENGINE_set_default_DSA(e);
    ENGINE_set_default_ciphers(e);

    printf("%s: Engine initialization successful: \"%s\"\n",
    	       fn_name, engine_id);

    return e;
}

void engine_teardown(ENGINE *e)
{
    const char *fn_name = "engine_teardown";

    /* Release functional reference from ENGINE_init() */
    ENGINE_finish(e);

    /* Release structural reference from ENGINE_by_id() */
    ENGINE_free(e);

    /* Do Engine cleanup */
    /* The ENGINE_cleanup call was causing segfaults under certain
     * conditions.  The function is poorly documented, so I 
     * don't call it.  We are on our way out of the program anyway,
     * so system garbage collection takes over */
    printf("%s: Skipping ENGINE_cleanup() call\n", fn_name);
    ENGINE_cleanup();

    printf("%s: Engine teardown successful\n", fn_name);
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
   return preverify_ok;
}

SSL_CTX *ssl_ctx_init(ENGINE *e, const char *pin)
{
    const char *fn_name = "ssl_ctx_init";

    char serr[120];

    SSL_CTX *ctx = NULL;
    EVP_PKEY *scPrivKey = NULL;
    EVP_PKEY *scPubKey = NULL;

    /* Initialize SSL */
    SSL_library_init();
    SSL_load_error_strings();

    /* Create SSL context */
    ctx = SSL_CTX_new(SSLv3_client_method());
    if (ctx == NULL)
    {
    	printf("%s: Error creating SSL context\n", fn_name);
	return NULL;
    }

    /* Require the SSL session to authenticate the server */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    /* Allow the server cert to have a cert chain no more than 3 certs deep */
    SSL_CTX_set_verify_depth(ctx, 3);

    scPrivKey =  ENGINE_load_private_key(e, "45", NULL, NULL);
    if (!scPrivKey)
    {
    	printf("%s: Error loading smartcard private key\n", fn_name);
	SSL_CTX_free(ctx);
	return NULL;
    }

/* how to get the public key from openssl context once loaded?
    scPubKey =  ENGINE_load_public_key(e, "45", NULL, NULL);
    if (!scPubKey)
    {
    	printf("%s: Error loading smartcard public e key\n", fn_name);
	SSL_CTX_free(ctx);
	return NULL;
    }
*/

    /* Load private key into SSL context */
    if (!SSL_CTX_use_PrivateKey(ctx,scPrivKey))
    {
    	printf("%s: Error loading smartcard private key into SSL context: %s\n",
		  fn_name,ERR_error_string(ERR_get_error(),serr));
	SSL_CTX_free(ctx);
	return NULL;
    }
    return ctx;
}
