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
 *  Authors:    Jin Fang
 */

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
