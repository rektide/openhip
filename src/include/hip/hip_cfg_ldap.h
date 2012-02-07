/*
 * Host Identity Protocol
 * Copyright (c) 2008-2012 the Boeing Company
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
 *  \file  hip_cfg_ldap.h
 *
 *  \authors	Jin Fang <jin.fang@boeing.com>
 *
 *  \brief  Class definitions for LDAP configuration API implementation.
 *
 */

#ifndef _HIP_CFG_LDAP_H_
#define _HIP_CFG_LDAP_H_
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
