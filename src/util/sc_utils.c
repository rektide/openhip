/*
 * Host Identity Protocol
 * Copyright (C) 2009 the Boeing Company
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>

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

int load_engine_fn(ENGINE *e, const char *engine_id,
                   const char **pre_cmds, int pre_num,
                   const char **post_cmds, int post_num)
{
	const char *fn_name = "load_engine_fn";

	/* This code is written from examples given in the manpage
	 *  for openssl-0.9.7c engine (man 3 engine) */

	/* Process pre-initialize commands */
	while (pre_num--)
	{
		if (!ENGINE_ctrl_cmd_string(e, pre_cmds[0], pre_cmds[1], 0))
		{
			printf("%s: Failed pre command (%s - %s:%s)\n",
			       fn_name, engine_id, pre_cmds[0],
			       (pre_cmds[1] ? pre_cmds[1] : "(NULL)"));
			ENGINE_free(e);
			return(0);
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
		return(0);
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
			/* Release the functional reference with ENGINE_finish
			 **/
			ENGINE_finish(e);
			return(0);
		}
		/* Don't display PIN! */
		printf("%s: Engine post-init command (%s - %s:XXXXXXXX)\n",
		       fn_name, engine_id, post_cmds[0]);
		post_cmds += 2;
	}

	ENGINE_set_default(e, ENGINE_METHOD_RSA);

	printf(
	        "%s: Engine pre and post commands successfully applied to \"%s\"\n",
	        fn_name,
	        engine_id);

	return(1);
}

ENGINE *engine_init(char *pin)
{
	const char *fn_name = "engine_init";
	char opensc_engine[NAMELENGTH] = "/usr/lib64/engines/engine_pkcs11.so";
	char opensc_module[NAMELENGTH] = "/usr/lib64/pkcs11/opensc-pkcs11.so";

	ENGINE *e;
	const char *engine_id = "dynamic";
	const char *pre_cmds[] = { "SO_PATH", opensc_engine,
		                   "ID", "pkcs11",
		                   "LIST_ADD", "1",
		                   "LOAD", NULL,
		                   "MODULE_PATH", opensc_module };
	int pre_num = 5;
	char *post_cmds[] = { "PIN", "123456" };
	int post_num = 1;

	ENGINE_load_builtin_engines();

	e = ENGINE_by_id(engine_id);
	if (!e)
	{
		printf("%s: Engine isn't available: %s\n", fn_name, engine_id);
		return(NULL);
	}

	if(pin) {
		post_cmds[1] = pin;
	}

	if (!load_engine_fn(e, engine_id, pre_cmds, pre_num,
	                    (const char **)post_cmds, post_num))
	{
		printf("%s: load_engine_fn() failed for %s\n",
		       fn_name, engine_id);
		return(NULL);
	}

	if (!ENGINE_set_default_RSA(e))
	{
		printf("%s: Couldn't set RSA method on engine: %s\n",
		       fn_name, engine_id);
		return(NULL);
	}
	ENGINE_set_default_DSA(e);
	ENGINE_set_default_ciphers(e);

	printf("%s: Engine initialization successful: \"%s\"\n",
	       fn_name, engine_id);

	return(e);
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
	return(preverify_ok);
}

SSL_CTX *ssl_ctx_init(ENGINE *e, const char *pin)
{
	const char *fn_name = "ssl_ctx_init";

	char serr[120];

	SSL_CTX *ctx = NULL;
	EVP_PKEY *scPrivKey = NULL;

	/* Initialize SSL */
	SSL_library_init();
	SSL_load_error_strings();

	/* Create SSL context */
	ctx = SSL_CTX_new(SSLv3_client_method());
	if (ctx == NULL)
	{
		printf("%s: Error creating SSL context\n", fn_name);
		return(NULL);
	}

	/* Require the SSL session to authenticate the server */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

	/* Allow the server cert to have a cert chain no more than 3 certs deep
	 **/
	SSL_CTX_set_verify_depth(ctx, 3);

	scPrivKey =  ENGINE_load_private_key(e, "4:45", NULL, NULL);
	if (!scPrivKey)
	{
		printf("%s: Error loading smartcard private key\n", fn_name);
		SSL_CTX_free(ctx);
		return(NULL);
	}

/* how to get the public key from openssl context once loaded?
 *   scPubKey =  ENGINE_load_public_key(e, "45", NULL, NULL);
 *   if (!scPubKey)
 *   {
 *       printf("%s: Error loading smartcard public e key\n", fn_name);
 *       SSL_CTX_free(ctx);
 *       return NULL;
 *   }
 */

	/* Load private key into SSL context */
	if (!SSL_CTX_use_PrivateKey(ctx,scPrivKey))
	{
		printf(
		        "%s: Error loading smartcard private key into SSL context: %s\n",
		        fn_name,
		        ERR_error_string(ERR_get_error(),serr));
		SSL_CTX_free(ctx);
		return(NULL);
	}
	return(ctx);
}

