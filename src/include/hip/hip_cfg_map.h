/*
 * Host Identity Protocol
 * Copyright (C) 2011 the Boeing Company
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
 *  hip_cfg_map.h
 *
 *  Authors:	David Mattes, <david.mattes@boeing.com>
 *
 *  IF-MAP Plug-in for Endbox mode: Subclass declaration of hipCfg
 *
 */

#ifndef _HIPCFG_MAP_
#define _HIPCFG_MAP_
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

  // Used by ifmap_client to get results back to this thread
  void updateMaps(string myDN, 
		  string myHIT,
		  list<string> newPeerDNs,
		  map<string,string> newPeerDN_HITs,
		  map<string,string> newPeerDN_ULIPs,
		  map<string,string> newPeerDN_LNIPs);

private:
  hipCfgMap();

  int getCertFromMap(const char *url, char *buf, int size);
  int getCertDN();
  int getHITFromLocalFile();

  int stringListContains(list<string> haystack, string needle);

  // returns number of config items read, or -1 on error
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
  string _scDN;
  string _scCN;

  QMap<QString,QString> _mapConfig;

  QString _serviceURL;
  QString _serviceProxy;
  QString _serviceProxyPort;

  IfmapThread *_ifmapThread;
  QCoreApplication *_qtApp;

};

#endif
