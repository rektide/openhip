/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2009-2012 the Boeing Company
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *  \file  sc_utils.h
 *
 *  \authors	Jin Fang <jin.fang@boeing.com>
 *
 *  \brief  Smartcard utility function definitions.
 *
 */

#ifndef _SC_UTILS_H_
#define _SC_UTILS_H_

#include <openssl/ssl.h>
#include <openssl/engine.h>

#define NAMELENGTH 256
#define BUFFERSIZE 1024
#define NUM_RETRIES 0
#define NUM_PING_RETRIES 3

int             load_engine_fn(ENGINE *e, const char *engine_id,
                               const char **pre_cmds, int pre_num,
                               const char **post_cmds, int post_num);
ENGINE *        engine_init(char *pin);
void            engine_teardown(ENGINE *e);
int             verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
EVP_PKEY *      load_sc_pkey(const char *file, ENGINE *e, const char *pin);
SSL_CTX *       ssl_ctx_init(ENGINE *e, const char *pin);
#endif
