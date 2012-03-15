/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2011-2012 the Boeing Company
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
 *  \file  hip_cfg_map.h
 *
 *  \authors	David Mattes, <david.mattes@boeing.com>
 *
 *  \brief  IF-MAP Plug-in for Endbox mode: Subclass declaration of hipCfg
 *
 */

#ifndef _HIP_CFG_MAP_
#define _HIP_CFG_MAP_
#include <openssl/ssl.h>

#include <QtCore>

#include <hip/hip_cfg.h>

class IfmapThread;

class hipCfgMap : public QObject, public hipCfg
{
  Q_OBJECT
public:
  int loadCfg(struct hip_conf *hc);
  int closeCfg();
  int postLocalCert(const char *hit);
  int verifyCert(const char *url, const hip_hit hit);
  int setUnderlayIpAddress(const char *ip);

  static hipCfgMap *getInstance();

  /* Used by ifmap_client to get results back to this thread */
  void updateMaps(string myDN,
                  string myHIT,
                  list<string> newPeerDNs,
                  map<string,string> newPeerDN_HITs,
                  map<string,string> newPeerDN_ULIPs,
                  map<string,string> newPeerDN_LNIPs,
                  map<string,string> newPeerDN_Certs);

private:
  hipCfgMap();

  int getCertFromMap(const char *url, char *buf, int size);
  int getHITFromLocalFile();
  int getHITFromCert(const char *cert_file_name);
  int getCACert(const char *ca_cert_file_name);

  int stringListContains(list<string> haystack, string needle);

  /* returns number of config items read, or -1 on error */
  int readIPMConfigFile();
  bool readIPMConfigXML(QIODevice *device);
  void addConfigItem(QString key, QString value);

  bool readNextStartElement(QXmlStreamReader &xmlReader);
  void skipCurrentElement(QXmlStreamReader &xmlReader);

signals:
  void connectToMap(QMap<QString,QString> *mapConfig);
  void publishCert(QString cert);
  void setUnderlayIp(QString ip);

private:
  static hipCfgMap *_instance;
  string _DN;
  string _CN;

  QMap<QString,QString> _mapConfig;

  QString _serviceURL;
  QString _serviceProxy;
  QString _serviceProxyPort;

  IfmapThread *_ifmapThread;
  QCoreApplication *_qtApp;

};

#endif
