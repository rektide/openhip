/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
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
 *  \file  hip_cfg_files.h
 *
 *  \authors	Jin Fang <jin.fang@boeing.com>
 *
 *  \brief  Configuration API class definitions using static files.
 *
 */

#ifndef _HIP_CFG_FILES_H
#define _HIP_CFG_FILES_H
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
  int setUnderlayIpAddress(const char *ip)
  {       /*printf ("In setUnderlayIpAddress (%s)\n", ip);*/
    return(0);
  };

private:
  hipCfgFiles();

private:
  static hipCfgFiles *_instance;
};

#endif
