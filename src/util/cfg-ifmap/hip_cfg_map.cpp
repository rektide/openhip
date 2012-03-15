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
 *  \file hip_cfg_map.cpp
 *
 *  \authors	David Mattes, <david.mattes@boeing.com>
 *
 *  \brief IF-MAP Plug-in for Endbox mode: Subclass implementation of hipCfg
 *
 */

#include <string>
#include <list>
#include <iostream>

#include <pthread.h>

#include <libxml/tree.h>

#include <QtCore>

#include "ifmap1_1.h"
#include "ifmap_thread.h"

#include <hip/hip_cfg_map.h>

using namespace std;

extern pthread_mutex_t hipcfgmap_mutex;

extern QMutex mapMutex;
extern QWaitCondition mapWaitCond;

hipCfgMap *hipCfgMap::_instance = NULL;

extern "C" {
int hipcfg_init(struct hip_conf *hc)
{
  /* printf("cfg-local hipcfg_init called\n"); */
  hipCfg *hs = hipCfgMap::getInstance();
  int rc = hs->loadCfg(hc);
  printf("cfg-local hipcfg_init returned: %d\n", rc);
  return(rc);
}

int hipcfg_close()
{
  /* printf("cfg-local hipcfg_init called\n"); */
  hipCfg *hs = hipCfgMap::getInstance();
  return(hs->closeCfg());
}

int hipcfg_allowed_peers(const hip_hit hit1, const hip_hit hit2)
{
  /* printf("cfg-local hit_peer_allowed\n"); */
  /* this is the (approximately) per-packet check */
  hipCfg *hs = hipCfgMap::getInstance();
  return(hs->hit_peer_allowed(hit1, hit2));
}

int hipcfg_peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt)
{
  /* printf("cfg-local peers_allowed\n"); */
  hipCfg *hs = hipCfgMap::getInstance();
  return(hs->peers_allowed(hits1, hits2, max_cnt));
}

int hipcfg_setUnderlayIpAddress(const char *ip)
{
  hipCfg *hs = hipCfgMap::getInstance();
  return(hs->setUnderlayIpAddress(ip));
}

int hipcfg_getEndboxByLegacyNode(const struct sockaddr *host,
                                 struct sockaddr *eb)
{
  int rc = 0;

  hipCfg *hs = hipCfgMap::getInstance();
  rc = hs->legacyNodeToEndbox(host, eb);
  return(rc);
}

int hipcfg_getLlipByEndbox(const struct sockaddr *eb, struct sockaddr *llip)
{
  int rc = 0;
  /* printf("entering hipcfg_getLlipByEndbox...\n"); */
  hipCfg *hs = hipCfgMap::getInstance();
  rc = hs->endbox2Llip(eb, llip);
  return(rc);
}

int hipcfg_getLegacyNodesByEndbox(const struct sockaddr *eb,
                                  struct sockaddr_storage *hosts, int size)
{
  int rc = 0;
  /* printf("entering hipcfg_getLegacyNodesByEndbox...\n"); */
  hipCfg *hs = hipCfgMap::getInstance();
  rc = hs->getLegacyNodesByEndbox(eb, hosts, size);
  return(rc);
}

int hipcfg_verifyCert(const char *url, const hip_hit hit)
{
  int rc = 0;
  hipCfg *hs = hipCfgMap::getInstance();
  rc = hs->verifyCert(url, hit);
  return(rc);
}

int hipcfg_getLocalCertUrl(char *url, int size)
{
  int rc = 0;
  hipCfg *hs = hipCfgMap::getInstance();
  rc = hs->getLocalCertUrl(url, size);
  return(rc);
}

int hipcfg_postLocalCert(const char *hit)
{
  int rc = 0;
  hipCfg *hs = hipCfgMap::getInstance();
  rc = hs->postLocalCert(hit);
  return(rc);
}

hi_node *hipcfg_getMyHostId()
{
  hipCfgMap *hs = hipCfgMap::getInstance();
  return(hs->getMyHostId());
}

int hipcfg_getPeerNodes(struct peer_node *peerNodes, int max_count)
{
  hipCfgMap *hs = hipCfgMap::getInstance();
  return(hs->getPeerNodes(peerNodes, max_count));
}

} /* extern "C" */

hipCfgMap::hipCfgMap()
{
  _ssl = NULL;
  _store = NULL;
  _hostid = NULL;
  _dsa = NULL;
  _rsa = NULL;
  _hcfg = NULL;

  const char *argv = { "hip_cfg_map" };
  int argc = 1;

  _qtApp = new QCoreApplication(argc,(char **)&argv);
  _ifmapThread = new IfmapThread(0);
  _ifmapThread->start();

  /* sleep(1); // To let thread start */

}

hipCfgMap *hipCfgMap::getInstance()
{
  if (_instance == NULL)
    {
      _instance = new hipCfgMap();
    }
  return(_instance);
}

int hipCfgMap::closeCfg()
{
  int rc = 1;
  const char *fnName = "hipCfgMap::closeCfg:";
  qDebug() << fnName;

  cerr << fnName << "Deleting MAP Client" << endl;
  _ifmapThread->deleteMapClient();

  _ifmapThread->exit(0);  /* exit thread's event loop */
  if (_ifmapThread->wait(1000))    /* Wait 1000msec for thread to exit */
    {
      rc = 0;
    }
  else
    {
      rc = 1;
    }

  return(rc);
}

int hipCfgMap::readIPMConfigFile()
{
  const char *fnName = "hipCfgMap::readIPMConfigFile:";

  QFile cfile("mapcfg.conf");
  if (!cfile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
      qDebug() << fnName << "Error opening IPM Config File" << cfile.fileName();
      qDebug() << fnName << "-->" << cfile.error();
      return(-1);
    }

  if (!readIPMConfigXML(&cfile))
    {
      qDebug() << fnName << "Error reading XML in IPM Config File"
               << cfile.fileName();
      return(-1);
    }

  static QString mapkey = "map_server_url";
  if (!_mapConfig.contains(mapkey))
    {
      qDebug() << fnName << "Error: No MAP Server url specified";
      return(-1);
    }

  static QString ulki = "use_local_known_identities";
  if (!_mapConfig.contains(ulki))
    {
      qDebug() << fnName << "Disabling <use_local_known_identites> by default";
      _mapConfig.insert(ulki,"no");
    }

  static QString pcr = "peer_certificate_required";
  if (!_mapConfig.contains(pcr))
    {
      qDebug() << fnName << "Disabling <peer_certificate_required> by default";
      _mapConfig.insert(pcr, "no");
    }
  else if (_mapConfig.value(pcr).compare("yes", Qt::CaseInsensitive) == 0)
    {
      /* Make sure the following are set: */
      /*
       *  <my_certificate_file/>
       *  <my_private_key_file/>
       *  <my_private_key_passwd/>
       *  <my_ca_chain_file/>
       */
      static QString mcf = "my_certificate_file";
      if (!_mapConfig.contains(mcf))
        {
          qDebug() << fnName << "my_certificate_file not set";
          return(-1);
        }
      static QString mpkf = "my_private_key_file";
      if (!_mapConfig.contains(mpkf))
        {
          qDebug() << fnName << "my_private_key_file not set";
          return(-1);
        }
      static QString mpkp = "my_private_key_passwd";
      if (!_mapConfig.contains(mpkp))
        {
          qDebug() << fnName << "my_private_key_passwd not set";
          return(-1);
        }
      static QString mccf = "my_ca_chain_file";
      if (!_mapConfig.contains(mccf))
        {
          qDebug() << fnName << "my_ca_chain_file not set";
          return(-1);
        }
    }

  return(_mapConfig.count());
}

void hipCfgMap::addConfigItem(QString key, QString value)
{
  const char *fnName = "hipCfgMap::addConfigItem:";
  if (!value.isEmpty())
    {
      qDebug() << fnName << "Adding:" << key << "-->" << value;
      _mapConfig.insert(key, value);
    }
}

/* Implementing this Qt-4.6 method in order to use Qt-4.5 on OpenWRT */
bool hipCfgMap::readNextStartElement(QXmlStreamReader &xmlReader)
{
  while (xmlReader.readNext() != QXmlStreamReader::Invalid)
    {
      if (xmlReader.isEndElement())
        {
          return(false);
        }
      else if (xmlReader.isStartElement())
        {
          return(true);
        }
    }
  return(false);
}

/* Implementing this Qt-4.6 method in order to use Qt-4.5 on OpenWRT */
void hipCfgMap::skipCurrentElement(QXmlStreamReader &xmlReader)
{
  int depth = 1;
  while (depth && xmlReader.readNext() != QXmlStreamReader::Invalid)
    {
      if (xmlReader.isEndElement())
        {
          --depth;
        }
      else if (xmlReader.isStartElement())
        {
          ++depth;
        }
    }
}

bool hipCfgMap::readIPMConfigXML(QIODevice *device)
{
  const char *fnName = "hipCfgMap::readIPMConfigXML:";
  QXmlStreamReader xmlReader(device);

  if (readNextStartElement(xmlReader))
    {
      if ((xmlReader.name() == "ipm_configuration") &&
          (xmlReader.attributes().value("version") == "1.0"))
        {

          xmlReader.readNext();

          while (readNextStartElement(xmlReader))
            {
              if (xmlReader.name() == "use_local_known_identities")
                {
                  QString value = xmlReader.readElementText();
                  if ((value.compare("yes", Qt::CaseInsensitive) == 0) ||
                      (value.compare("no", Qt::CaseInsensitive) == 0))
                    {
                      addConfigItem(xmlReader.name().toString(), value);
                    }
                  else
                    {
                      xmlReader.raiseError(QObject::tr(
                                             "Incorrect value for <use_local_known_identities>"));
                    }
                }
              else if (xmlReader.name() == "peer_certificate_required")
                {
                  QString value = xmlReader.readElementText();
                  if ((value.compare("yes", Qt::CaseInsensitive) == 0) ||
                      (value.compare("no", Qt::CaseInsensitive) == 0))
                    {
                      addConfigItem(xmlReader.name().toString(), value);
                    }
                  else
                    {
                      xmlReader.raiseError(QObject::tr(
                                             "Incorrect value for <peer_certificate_required>"));
                    }
                }
              else if (xmlReader.name() == "peer_ca")
                {
                  addConfigItem(
                    xmlReader.name().toString(), xmlReader.readElementText());
                }
              else if (xmlReader.name() == "my_certificate_file")
                {
                  addConfigItem(
                    xmlReader.name().toString(), xmlReader.readElementText());
                }
              else if (xmlReader.name() == "my_ca_chain_file")
                {
                  addConfigItem(
                    xmlReader.name().toString(), xmlReader.readElementText());
                }
              else if (xmlReader.name() == "my_private_key_file")
                {
                  addConfigItem(
                    xmlReader.name().toString(), xmlReader.readElementText());
                }
              else if (xmlReader.name() == "my_private_key_passwd")
                {
                  addConfigItem(
                    xmlReader.name().toString(), xmlReader.readElementText());
                }
              else if (xmlReader.name() == "map_proxy_passwd")
                {
                  addConfigItem(
                    xmlReader.name().toString(), xmlReader.readElementText());
                }
              else if ((xmlReader.name() == "ipm_map_configuration") &&
                       (xmlReader.attributes().value("version") == "1.0"))
                {
                  while (readNextStartElement(xmlReader))
                    {
                      if (xmlReader.name() == "map_server_url")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_server_vendor")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_ignore_ssl_errors")
                        {
                          QString value = xmlReader.readElementText();
                          if ((value.compare("yes",
                                             Qt::CaseInsensitive) == 0) ||
                              (value.compare("no", Qt::CaseInsensitive) == 0))
                            {
                              addConfigItem(xmlReader.name().toString(), value);
                            }
                          else
                            {
                              xmlReader.raiseError(QObject::tr(
                                                     "Incorrect value for <map_ignore_ssl_errors>"));
                            }
                        }
                      else if (xmlReader.name() == "map_server_ca_file")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_certificate_file")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_private_key_file")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_private_key_passwd")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_http_username")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_http_password")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_proxy_server")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_proxy_port")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_proxy_user")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else if (xmlReader.name() == "map_proxy_passwd")
                        {
                          addConfigItem(
                            xmlReader.name().toString(),
                            xmlReader.readElementText());
                        }
                      else
                        {
                          skipCurrentElement(xmlReader);
                        }
                    }
                }
              else
                {
                  skipCurrentElement(xmlReader);
                }

              xmlReader.readNext();
            }
        }
      else
        {
          xmlReader.raiseError(QObject::tr(
                                 "The file is not an IPM Config file version 1.0"));
        }

    }

  if (xmlReader.error())
    {
      qDebug() << fnName << "XML Error:";
      qDebug() << fnName << "-->" << xmlReader.errorString();
    }

  return(!xmlReader.error());
}

int hipCfgMap::loadCfg(struct hip_conf *hc)
{
  const char *fnName = "hipCfgMap::loadCfg:";
  SSL_CTX *ctx = NULL;

  if (hc == NULL)
    {
      cerr << fnName << "ERROR: HCNF not set" << endl;
      return(-1);
    }

  _hcfg = hc;

  /* Load MAP config file options */

  if (readIPMConfigFile() < 0)
    {
      return(-1);
    }

  if (_mapConfig.value("peer_certificate_required").compare("yes",
                                                            Qt::CaseInsensitive)
      == 0)
    {
      qDebug() << fnName << "Loading SSL functionality";
      SSL_library_init();
      SSL_load_error_strings();

      ctx = SSL_CTX_new(SSLv3_client_method());
      if (ctx == NULL)
        {
          cerr << fnName << "Error creating SSL context" << endl;
          return(-1);
        }

      _ssl = SSL_new(ctx);
      if (_ssl == NULL)
        {
          cerr << fnName << "Error open SSL connect" << endl;
          return(-1);
        }

      _store = X509_STORE_new();
      if (!_store)
        {
          cerr << fnName << "Error calling X509_STORE_new" << endl;
          return(-1);
        }

      X509_STORE_set_verify_cb_func(_store, hipCfgMap::callb);
      X509_STORE_set_default_paths(_store);

      /* Read my HIP Identity from certificate file */

      static QString mcf = "my_certificate_file";
      qDebug() << fnName << "Reading cert file" << _mapConfig.value(mcf);
      if (getHITFromCert(_mapConfig.value(mcf).toAscii().constData()))
        {
          return(-1);
        }
      static QString mccf = "my_ca_chain_file";
      qDebug() << fnName << "Reading CA cert file"
               << _mapConfig.value(mccf);
      if (getCACert(_mapConfig.value(mccf).toAscii().constData()))
        {
          return(-1);
        }
    }
  else /* Get HIT from my_host_identities.xml */
    {
      hc->use_my_identities_file = 1;
      if (getHITFromLocalFile() != 0)
        {
          return(-1);
        }
    }

  /* Use an on-disk known_host_identites.xml file to initialize the */
  /* overlay configuration.  Then if MAP never comes up, at least we've */
  /* got something going. */

  static QString ulki = "use_local_known_identities";
  if (_mapConfig.value(ulki).compare("yes", Qt::CaseInsensitive) == 0)
    {
      if (getEndboxMapsFromLocalFile() < 0)
        {
          cerr << fnName
               << "Error initializing state from local known identities file"
               << endl;
        }
    }

  /* Setup Qt signal-slot connections: */

  bool connected = false;
  while (!connected)
    {
      /* Give thread time to start */
      sleep(1);

      connected = connect(this, SIGNAL(connectToMap(QMap<QString,QString> *)),
                          (QObject *)_ifmapThread->_client,
                          SLOT(connectToMap(QMap<QString,QString> *)));
    }

  /* Now that thread is up, other connections should be made instantly */
  connected = connect(this, SIGNAL(setUnderlayIp(QString)),
                      (QObject *)_ifmapThread->_client,
                      SLOT(setUnderlayIp(QString)));
  if (!connected)
    {
      qDebug() << fnName << "Error: Could not connect setUnderlayIp signal";
      return(-1);
    }

  /*
   *  // connectToMap asynchronously
   *  qDebug() << fnName << "About to emit connectToMap";
   *  emit connectToMap(&_mapConfig);
   *  sleep(20);
   */

  /* Make connectToMap act like a synchronous call */
  mapMutex.lock();
  emit connectToMap(&_mapConfig);
  /* mapWaitCond.wait(&mapMutex); */
  mapMutex.unlock();

  qDebug() << fnName << "About to exit loadCfg";
  return(0);
}

/* return 1 if the certificate is verified and the hit matches
 *        or if peer certificate not required,
 *        or 0 if the cert is verified but the hit doesn't match
 *        or -1 if other error.
 * Note: If the certificate verified, the timestamp and hit are set.
 */
/* DM: url in hipCfgMap is a DN */
int hipCfgMap::verifyCert(const char *url, const hip_hit hit)
{
  char cert[2048];
  hip_hit cached_hit;
  X509 *x509Cert = NULL;
  BIO *bio_mem = NULL;
  char hit_s[128];
  map <string, struct peer_node *>::iterator pn_i;
  map <string, certInfo>::iterator m_i;
  const char *fnName = "hipCfgMap::verifyCert: ";

  if (_mapConfig.value("peer_certificate_required").compare(
        "no", Qt::CaseInsensitive) == 0)
    {
      qDebug() << fnName << "peer certificate not required";
      return(1);
    }

  hit2hitstr(hit_s, hit);
  if (!url)
    {
      pn_i = _hit_to_peers.find((const char *)hit_s);
      if (pn_i == _hit_to_peers.end())
        {
          qDebug() << fnName << "Unable to find DN for" << hit_s;
          return(-1);
        }
      struct peer_node *p = (*pn_i).second;
      url = p->name;
    }

  m_i = _certs.find(url);
  if (m_i != _certs.end())
    {
      hitstr2hit(cached_hit, (char *)(*m_i).second.getHit());
      if (memcmp(cached_hit, hit, HIT_SIZE) == 0)
        {
          /* qDebug() << fnName << "Cert already verified for" << url; */
          return(1);
        }
    }
  else
    {
      qDebug() << fnName << "Unable to find cert for" << url;
      return(-1);
    }

  memcpy(cert, (*m_i).second.getCert(), (*m_i).second.certLength());
  bio_mem = BIO_new_mem_buf(cert, -1);

  x509Cert = PEM_read_bio_X509(bio_mem, NULL, 0, NULL);
  if (x509Cert == NULL)
    {
      qDebug() << fnName << "Error reading certificate data for" << url;
      return(-1);
    }

  if (verify_certificate(x509Cert) != 1)
    {
      qDebug() << fnName << "Cert not verified for" << url;
      return(-1);
    }

  /* Obtain public key (host identity) from the certificate */
  hi_node hi;
  EVP_PKEY *pubkey = NULL;
  pubkey = X509_get_pubkey(x509Cert);
  if (pubkey == NULL)
    {
      qDebug() << fnName <<
      "Error getting X509 public key from certificate for"
               << url;
      return(-1);
    }

  memset(&hi, 0, sizeof(hi_node));
  if (mkHIfromPkey(EVP_PKEY_get1_RSA(pubkey),EVP_PKEY_get1_DSA(pubkey),&hi) < 0)
    {
      return(-1);
    }

  /* verify hit derived from the certificate is the same from */
  /* the peer hit who has signed R1 or I2 packet. */
  if (memcmp(hi.hit, hit, HIT_SIZE) != 0)
    {
      qDebug() << fnName << "HIT does not match for" << url;
      return(0);
    }

  (*m_i).second.setVerified(hit_s);

  return(1);
}

/* DM: url in hipCfgMap is DN */
int hipCfgMap::getCertFromMap(const char *url, char *buf, int size)
{
  const char *fnName = "hipCfgMap::getCertFromMap: ";
  map <string, certInfo>::iterator m_i;

  qDebug() << fnName << "Searching for cert for" << url;

  m_i = _certs.find(url);
  if (m_i != _certs.end())
    {
      if (size <= (*m_i).second.certLength())
        {
          /* qDebug() << fnName << "Cert found for" << url; */
          memcpy(buf, (*m_i).second.getCert(), (*m_i).second.certLength());
          return(1);
        }
      else
        {
          qDebug() << fnName << "Buffer size" << size << "less than cert size"
                   << (*m_i).second.certLength();
          return(-1);
        }
    }
  else
    {
      qDebug() << fnName << "Unable to find cert for" << url;
      return(-1);
    }
}

/* Publish cert to MAP */
int hipCfgMap::postLocalCert(const char *hit)
{
  const char *fnName = "hipCfgMap::postLocalCert: ";

  qDebug() << fnName << "Called with HIT" << hit;

  return(0);
}

/* Publish Current Underlay IP Address */
int hipCfgMap::setUnderlayIpAddress(const char *ip)
{
  const char *fnName = "hipCfgMap::setUnderlayIpAddress: ";

  cout << fnName << "Will publish current ip" << endl;
  emit setUnderlayIp(ip);

  return(0);
}

void hipCfgMap::updateMaps(string myDN,
                           string myHIT,
                           list<string> newPeerDNs,
                           map<string,string> newPeerDN_HITs,
                           map<string,string> newPeerDN_ULIPs,
                           map<string,string> newPeerDN_LNIPs,
                           map<string,string> newPeerDN_Certs)
{
  const char *fnName = "hipCfgMap::updateMaps:";
  hip_hit myHITh;

  qDebug() << fnName << "Called with DN" << myDN.c_str() << "and HIT"
           << myHIT.c_str();

  set <hitPair, hp_compare> allowed_peers;
  map <string, string> endbox2LlipMap;
  map <string, string> legacyNode2EndboxMap;
  map <string, struct peer_node *> hit_to_peers;
  map <string, certInfo> certs;

  /* Get hex representation of my HIT */
  hitstr2hit(myHITh, _mapConfig.value("HIT").toAscii().constData());

  list<string>::iterator si;
  map<string,string>::iterator mi;
  for (si = newPeerDNs.begin(); si != newPeerDNs.end(); si++)
    {
      string peerDN = *si;
      qDebug() << fnName << "Updating maps for peerDN" << peerDN.c_str();
      string peerHIT;

      /* DN-HIT Mapping */
      mi = newPeerDN_HITs.find(peerDN);
      if (mi != newPeerDN_HITs.end())
        {
          peerHIT = mi->second;
          qDebug() << fnName << "Adding mapping for DN<->HIT:" << peerDN.c_str()
                   << " <-> " << peerHIT.c_str();
          hip_hit peerHITh;
          hitstr2hit(peerHITh, (char *)peerHIT.c_str());
          if (memcmp(myHITh, peerHITh, HIT_SIZE) < 0)
            {
              hitPair hp(myHITh, peerHITh);
              allowed_peers.insert(hp);
            }
          else if (memcmp(myHITh, peerHITh, HIT_SIZE) > 0)
            {
              /* Reverse order */
              hitPair hp(peerHITh, myHITh);
              allowed_peers.insert(hp);
            }
          else
            {
              qDebug() << fnName << "Not adding allowed_peers for myself!";
            }
        }
      else
        {
          qDebug() << fnName << "Could not find peerHIT for peerDN:"
                   << peerDN.c_str();
          continue;
        }

      /* HIT-ULIP Mapping */
      mi = newPeerDN_ULIPs.find(peerDN);
      if (mi != newPeerDN_ULIPs.end())
        {
          string peerULIP = mi->second;
          qDebug() << fnName << "Adding mapping for HIT<->UnderlayIP:"
                   << peerHIT.c_str() << " <-> " << peerULIP.c_str();
          endbox2LlipMap[peerHIT] = peerULIP;
        }
      else
        {
          qDebug() << fnName << "Could not find peerULIP for peerDN:"
                   << peerDN.c_str();
        }

      /* Find all legacy nodes belonging to the peer endbox */
      map<string,string>::iterator lni;
      for (lni = newPeerDN_LNIPs.begin(); lni != newPeerDN_LNIPs.end(); lni++)
        {
          string peerLNIP = lni->first;
          string testDN = lni->second;
          if (testDN.compare(peerDN) == 0)
            {
              qDebug() << fnName << "Adding mapping for HIT<->LegacyNodeIP:"
                       << peerHIT.c_str() << " <-> " << peerLNIP.c_str();
              legacyNode2EndboxMap.insert(std::make_pair(peerLNIP, peerHIT));
            }
        }

      /* Endbox LSI to HIT mapping */
      char peerLSI[INET_ADDRSTRLEN];
      if (!hitstr2lsistr(peerLSI, (char *)peerHIT.c_str()))
        {
          mi = legacyNode2EndboxMap.find(peerLSI);
          if (mi == legacyNode2EndboxMap.end())
            {
              legacyNode2EndboxMap.insert(std::make_pair(peerLSI, peerHIT));
              qDebug() << fnName << "Adding (" << peerLSI << ", "
                       << peerHIT.c_str() << ") into legacyNode2EndboxMap";
            }
        }
      else
        {
          qDebug() << fnName << "Error converting HIT to LSI for DN:"
                   << peerDN.c_str();
        }

      /* Find all certs belonging to the peer endbox */
      map<string,string>::iterator certi;
      for (certi = newPeerDN_Certs.begin(); certi != newPeerDN_Certs.end();
           certi++)
        {
          string testDN = certi->first;
          string peerCert = certi->second;
          if (testDN.compare(peerDN) == 0)
            {
              qDebug() << fnName << "Adding cert for peer:" << testDN.c_str();
              certInfo cinfo(peerCert);
              certs.insert(std::make_pair(testDN, cinfo));
            }
        }

      /* Endbox HIT to hip peer entry */
      qDebug() << fnName << "Adding entry to hit_to_peers HIT:"
               << peerHIT.c_str();
      struct peer_node *p = new(struct peer_node);
      memset(p, 0, sizeof(struct peer_node));
      hitstr2hit(p->hit, (char *)peerHIT.c_str());
      strcpy(p->name, (char *)peerDN.c_str());
      /* TODO: These parameters should be specified somewhere? */
      p->algorithm_id = 0;
      p->r1_gen_count = 10;
      p->anonymous = 0;
      p->allow_incoming = 1;
      p->skip_addrcheck = 0;
      /* Make pair */
      hit_to_peers.insert(std::make_pair(peerHIT, p));
    }

  /* This needs to be mutex'd because ifmap_client calls this function from */
  /* its own thread to update these objects. */
  pthread_mutex_lock(&hipcfgmap_mutex);
  _allowed_peers = allowed_peers;
  _endbox2LlipMap = endbox2LlipMap;
  _legacyNode2EndboxMap = legacyNode2EndboxMap;
  _certs = certs;

  /* Delete existing peer_node structs */
  map <string, struct peer_node *>::iterator i;
  for (i = _hit_to_peers.begin(); i != _hit_to_peers.end(); i++)
    {
      struct peer_node *p = (*i).second;
      delete p;
    }
  _hit_to_peers = hit_to_peers;
  pthread_mutex_unlock(&hipcfgmap_mutex);
}

int hipCfgMap::stringListContains(list<string> haystack, string needle)
{
  list<string>::iterator si;
  int loc = 0;
  for (si = haystack.begin(); si != haystack.end(); si++)
    {
      string h = *si;
      if (needle.compare(h) == 0)
        {
          return(loc);
        }
      loc++;
    }

  return(-1);
}

int hipCfgMap::getHITFromLocalFile()
{
  const char *fnName = "hipCfgMap::getHITFromLocalFile: ";
  string hit_s;
  xmlDocPtr doc;
  xmlNodePtr node;
  char *data;
  struct sockaddr_storage ss_addr;
  struct sockaddr *addr;
  struct sockaddr_in lsi;
  char lsi_str[INET_ADDRSTRLEN];
  int rc = 0;
  bool haveDN = false;

  _hostid  = new hi_node();
  memset(_hostid, 0, sizeof(hi_node));

  /* the following parameters may need to be configurate  -TBD */
  _hostid->anonymous = 0;
  _hostid->allow_incoming = 1;
  _hostid->r1_gen_count = 10;
  _hostid->skip_addrcheck = TRUE;

  char my_hi_filename[255] = "my_host_identities.xml";

  if (locate_config_file(my_hi_filename,
                         sizeof(my_hi_filename),
                         HIP_MYID_FILENAME) == 0)
    {
      cout << "Will attempt to parse file: " << my_hi_filename << endl;
    }
  else
    {
      cout << "Could not find my_hi_filename" << endl;
      return(-1);
    }

  doc = xmlParseFile(my_hi_filename);
  if (doc == NULL)
    {
      cout << "Error parsing xml file " << my_hi_filename << endl;
      return(-1);
    }

  addr = (struct sockaddr*) &ss_addr;
  node = xmlDocGetRootElement(doc);
  for (node = node->children; node; node = node->next)
    {
      if (strcmp((char *)node->name, "host_identity") == 0)
        {

          for (xmlNodePtr cnode = node->children; cnode; cnode = cnode->next)
            {
              if (strcmp((char *)cnode->name, "text") == 0)
                {
                  continue;
                }
              data = (char *)xmlNodeGetContent(cnode);
              if (strcmp((char *)cnode->name, "name") == 0)
                {
                  /* Setting distinguished-name to name */
                  _DN = string(data);
                  _mapConfig.insert("DistinguishedName", QString(_DN.c_str()));
                  haveDN = true;
                  cout << fnName << "Setting distinguished name: " << _DN <<
                  endl;
                }
              if (strcmp((char *)cnode->name, "HIT") == 0)
                {
                  memset(addr, 0,sizeof(struct sockaddr_storage));
                  addr->sa_family = AF_INET6;
                  if (str_to_addr(data, addr) <= 0)
                    {
                      cout << fnName << "Warning parsing HIT " << data <<
                      " is invalid" << endl;
                      xmlFree(data);
                      rc = -1;
                      continue;
                    }
                  hit_s = data;
                  cout << fnName << "Got HIT from " << my_hi_filename << ": "
                       << hit_s << endl;
                  _mapConfig.insert("HIT", QString(hit_s.c_str()));
                  rc = hitstr2hit(_hostid->hit, (char *)hit_s.c_str());
                }
              xmlFree(data);
            }

        }
    }

  xmlFreeDoc(doc);

  memset(&lsi, 0, sizeof(struct sockaddr_in));
  memset(lsi_str, 0, INET_ADDRSTRLEN);
  lsi.sin_family = AF_INET;
  lsi.sin_addr.s_addr = ntohl(HIT2LSI(_hostid->hit));
  if (addr_to_str(SA(&lsi), lsi_str, INET_ADDRSTRLEN))
    {
      printf("Error generating LSI from HIT!\n");
      return(-1);
    }
  memcpy(&_hostid->lsi, &lsi, sizeof(struct sockaddr_in));

  /* Make sure we were able to find DN from file */
  if (haveDN != true)
    {
      rc = -1;
    }

  return(rc);
}

int hipCfgMap::getHITFromCert(const char *my_cert_filename)
{
  int rc, return_value = -1;;
  char *data_p = NULL;
  long result;
  const char *fnName = "hipCfgMap::getHITFromCert:";
  char lsi_str[INET_ADDRSTRLEN];
  char hit_str[INET6_ADDRSTRLEN];
  char CN[128];
  QString mpkf = "my_private_key_file";
  QString mpkp = "my_private_key_passwd";
  hi_node hi;
  X509 *x509Cert = NULL;
  X509_NAME *subject = NULL;
  int index;
  X509_NAME_ENTRY *ne = NULL;
  ASN1_STRING *cn_str = NULL;
  EVP_PKEY *pubkey = NULL;
  BIO *bio_mem = NULL;
  RSA *rsa_key = NULL;
  DSA *dsa_key = NULL;
  FILE *key_fp = NULL;
  FILE *fp = fopen(my_cert_filename, "r");

  if (!fp)
    {
      qDebug() << fnName << "Error opening cert file" << my_cert_filename;
      goto clean_up;
    }

  x509Cert = PEM_read_X509(fp, NULL, 0, NULL);
  fclose(fp);

  if (!x509Cert)
    {
      qDebug() << fnName << "Error reading certificate" << my_cert_filename;
      goto clean_up;
    }

  /* Get the common name from the subject of the certificate */

  subject = X509_get_subject_name(x509Cert);
  if (!subject)
    {
      qDebug() << fnName << "Error getting subject name from certificate"
               << my_cert_filename;
      goto clean_up;
    }

  index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
  ne = X509_NAME_get_entry(subject,index);
  cn_str = X509_NAME_ENTRY_get_data(ne);
  strncpy(CN, (const char *)cn_str->data, sizeof(CN));
  qDebug() << fnName << "CN from cert file" << CN;

  /* Get the public key and HIT from the certificate */

  pubkey = X509_get_pubkey(x509Cert);
  if (!pubkey)
    {
      qDebug() << fnName << "Error getting X509 public key from certificate "
               << my_cert_filename;
      goto clean_up;
    }

  memset(&hi, 0, sizeof(hi_node));
  rc = mkHIfromPkey(EVP_PKEY_get1_RSA(pubkey), EVP_PKEY_get1_DSA(pubkey), &hi);
  if (rc < 0)
    {
      qDebug() << fnName << "Error getting HIT from public key in certificate "
               << my_cert_filename;
      goto clean_up;
    }

  qDebug() << fnName << "Reading private key file" << _mapConfig.value(mpkf);

  key_fp = fopen(_mapConfig.value(mpkf).toAscii().constData(), "r");
  if (!key_fp)
    {
      qDebug() << fnName << "Unable to open private key file"
               << _mapConfig.value(mpkf);
      goto clean_up;
    }

  if (hi.algorithm_id == HI_ALG_RSA)
    {
      rsa_key = PEM_read_RSAPrivateKey(key_fp, NULL, NULL,
                                       (char *)_mapConfig.value(
                                         mpkp).toAscii().constData());
      fclose(key_fp);
      if (!rsa_key)
        {
          qDebug() << fnName << "Unable to read private key in file"
                   << _mapConfig.value(mpkf);
          goto clean_up;
        }
    }
  else if (hi.algorithm_id == HI_ALG_DSA)
    {
      dsa_key = PEM_read_DSAPrivateKey(key_fp, NULL, NULL,
                                       (char *)_mapConfig.value(
                                         mpkp).toAscii().constData());
      fclose(key_fp);
      if (!dsa_key)
        {
          qDebug() << fnName << "Unable to read private key in file"
                   << _mapConfig.value(mpkf);
          goto clean_up;
        }
    }
  else
    {
      fclose(key_fp);
      qDebug() << fnName << "Unknown key";
      goto clean_up;
    }

  bio_mem = BIO_new(BIO_s_mem());
  if (!bio_mem)
    {
      qDebug() << fnName << "Unable to allocate memory for storing cert";
      goto clean_up;
    }

  if (!PEM_write_bio_X509(bio_mem, x509Cert))
    {
      qDebug() << fnName << "Unable to write cert to memory";
      goto clean_up;
    }

  result = BIO_get_mem_data(bio_mem, &data_p);
  /* The encoded cert string doesn't appear to be NULL terminated */
  data_p[result] = 0;

  hit2hitstr(hit_str, hi.hit);
  addr_to_str(SA(&hi.lsi), lsi_str, INET_ADDRSTRLEN);
  qDebug() << fnName << "HIT from cert" << hit_str;
  qDebug() << fnName << "LSI from cert" << lsi_str;

  _Cert = string(data_p);
  _CN = CN;
  _DN = X509_NAME_oneline(subject, NULL, 0);
  _localCertUrl = _DN;

  _mapConfig.insert("DistinguishedName",
                    QString(X509_NAME_oneline(subject, NULL, 0)));
  _mapConfig.insert("HIT", QString(hit_str));
  _mapConfig.insert("LSI", QString(lsi_str));
  _mapConfig.insert("Cert", QString(data_p));

  _hostid = new hi_node();
  memset(_hostid, 0, sizeof(hi_node));
  memcpy(_hostid->hit, hi.hit, HIT_SIZE);
  memcpy(&_hostid->lsi, &hi.lsi, sizeof(struct sockaddr_in));
  strncpy(_hostid->name, X509_NAME_oneline(subject, NULL, 0),
          sizeof(_hostid->name));
  _hostid->name_len = strlen(_hostid->name);
  _hostid->algorithm_id = hi.algorithm_id;
  _hostid->size = hi.size;

  if (hi.algorithm_id == HI_ALG_RSA)
    {
      _hostid->rsa = RSA_new();
      _hostid->rsa->n = BN_dup(rsa_key->n);
      _hostid->rsa->e = BN_dup(rsa_key->e);
      _hostid->rsa->d = BN_dup(rsa_key->d);
      _hostid->rsa->p = BN_dup(rsa_key->p);
      _hostid->rsa->q = BN_dup(rsa_key->q);
      _hostid->rsa->dmp1 = BN_dup(rsa_key->dmp1);
      _hostid->rsa->dmq1 = BN_dup(rsa_key->dmq1);
      _hostid->rsa->iqmp = BN_dup(rsa_key->iqmp);
      RSA_free(hi.rsa);
      RSA_free(rsa_key);
    }
  else if (hi.algorithm_id == HI_ALG_DSA)
    {
      _hostid->dsa = DSA_new();
      _hostid->rsa->p = BN_dup(dsa_key->p);
      _hostid->dsa->q = BN_dup(dsa_key->q);
      _hostid->dsa->g = BN_dup(dsa_key->g);
      _hostid->dsa->pub_key = BN_dup(dsa_key->pub_key);
      _hostid->dsa->priv_key = BN_dup(dsa_key->priv_key);
      DSA_free(hi.dsa);
      DSA_free(dsa_key);
    }

  /* Do the following parameters need to be configured?  -TBD */
  _hostid->anonymous = 0;
  _hostid->allow_incoming = 1;
  _hostid->r1_gen_count = 10;
  _hostid->skip_addrcheck = TRUE;

  /* postLocalCert(hit_str); */
  return_value = 0;

clean_up:

  if (pubkey)
    {
      EVP_PKEY_free(pubkey);
    }
  if (x509Cert)
    {
      X509_free(x509Cert);
    }
  if (bio_mem)
    {
      BIO_free_all(bio_mem);
    }

  return (return_value);
}

int hipCfgMap::getCACert(const char *my_ca_cert_filename)
{
  int rc, return_value = -1;
  const char *fnName = "hipCfgMap::getCACert:";
  X509_LOOKUP *lookup = NULL;

  lookup = X509_STORE_add_lookup(_store, X509_LOOKUP_file());
  if (lookup == NULL)
    {
      qDebug() << fnName << "Unable to add lookup to cert store";
      goto clean_up;
    }

  rc = X509_LOOKUP_load_file(lookup, my_ca_cert_filename, X509_FILETYPE_PEM);
  if (!rc)
    {
      qDebug() << fnName << "Error loading ca cert file" << my_ca_cert_filename;
      goto clean_up;
    }

  X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

  return_value = 0;

clean_up:

  return (return_value);
}

