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
 *  hip_cfg_map.cpp
 *
 *  Authors:	David Mattes, <david.mattes@boeing.com>
 *
 *  IF-MAP Plug-in for Endbox mode: Subclass implementation of hipCfg
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
  //printf("cfg-local hipcfg_init called\n");
  hipCfg *hs=hipCfgMap::getInstance();
  int rc = hs->loadCfg(hc);
  printf("cfg-local hipcfg_init returned: %d\n", rc);
  return rc;
}

int hipcfg_close()
{
  //printf("cfg-local hipcfg_init called\n");
  hipCfg *hs=hipCfgMap::getInstance();
  return hs->closeCfg();
}

int hipcfg_allowed_peers(const hip_hit hit1, const hip_hit hit2)
{
  //printf("cfg-local hit_peer_allowed\n");
  /* this is the (approximately) per-packet check */
  hipCfg *hs=hipCfgMap::getInstance();
  return hs->hit_peer_allowed(hit1, hit2);
}

int hipcfg_peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt)
{
  //printf("cfg-local peers_allowed\n");
  hipCfg *hs=hipCfgMap::getInstance();
  return hs->peers_allowed(hits1, hits2, max_cnt);
}

int hipcfg_setUnderlayIpAddress(const char *ip)
{
  hipCfg *hs=hipCfgMap::getInstance();
  return hs->setUnderlayIpAddress(ip);
}

int hipcfg_getEndboxByLegacyNode(const struct sockaddr *host, struct sockaddr *eb)
{
  int rc=0;
  
  hipCfg *hs=hipCfgMap::getInstance();
  rc = hs->legacyNodeToEndbox(host, eb);
  return rc;
}

int hipcfg_getLlipByEndbox(const struct sockaddr *eb, struct sockaddr *llip)
{
  int rc=0;
  //printf("entering hipcfg_getLlipByEndbox...\n");
  hipCfg *hs=hipCfgMap::getInstance();
  rc = hs->endbox2Llip(eb, llip);
  return rc;
}

int hipcfg_getLegacyNodesByEndbox(const struct sockaddr *eb,
   struct sockaddr_storage *hosts, int size)
{
  int rc=0;
  //printf("entering hipcfg_getLegacyNodesByEndbox...\n");
  hipCfg *hs=hipCfgMap::getInstance();
  rc = hs->getLegacyNodesByEndbox(eb, hosts, size);
  return rc;
}

int hipcfg_verifyCert(const char *url, const hip_hit hit)
{
  int rc = 0;
  hipCfg *hs=hipCfgMap::getInstance();
  rc = hs->verifyCert(url, hit);
  return rc;
}


int hipcfg_getLocalCertUrl(char *url, int size)
{
  int rc=0;
  hipCfg *hs=hipCfgMap::getInstance();
  rc = hs->getLocalCertUrl(url, size);
  return rc;
}

int hipcfg_postLocalCert(const char *hit)
{
  int rc = 0;
  hipCfg *hs=hipCfgMap::getInstance();
  rc = hs->postLocalCert(hit);
  return rc;
}

hi_node *hipcfg_getMyHostId()
{
  hipCfgMap *hs=hipCfgMap::getInstance();
  return hs->getMyHostId();
}

int hipcfg_getPeerNodes(struct peer_node *peerNodes, int max_count)
{
  hipCfgMap *hs=hipCfgMap::getInstance();
  return hs->getPeerNodes(peerNodes, max_count);
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

    const char *argv = {"hip_cfg_map"};
    int argc = 1;

  _qtApp = new QCoreApplication(argc,(char **)&argv);
  _ifmapThread = new IfmapThread(0);
  _ifmapThread->start();

  //sleep(1); // To let thread start

}

hipCfgMap *hipCfgMap::getInstance()
{
  if(_instance==NULL){
    _instance = new hipCfgMap();
  }
  return _instance;
}

int hipCfgMap::closeCfg()
{
    int rc = 1;
    const char *fnName = "hipCfgMap::closeCfg:";
    qDebug() << fnName;

    cerr << fnName << "Deleting MAP Client" << endl;
    _ifmapThread->deleteMapClient();

    _ifmapThread->exit(0);  // exit thread's event loop
    if (_ifmapThread->wait(1000)) {  // Wait 1000msec for thread to exit
        rc = 0;
    } else {
        rc = 1;
    }

    return rc;
}

int hipCfgMap::readIPMConfigFile()
{
    const char *fnName = "hipCfgMap::readIPMConfigFile:";
    int rc = 0;

    QFile cfile("mapcfg.conf");
    if (!cfile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << fnName << "Error opening IPM Config File:" << cfile.fileName();
        qDebug() << fnName << "-->" << cfile.error();
	return -1;
    }

    if (!readIPMConfigXML(&cfile)) {
        qDebug() << fnName << "Error reading XML in IPM Config File:" << cfile.fileName();
	return -1;
    }

    static QString mapkey = "map_server_url";
    if (! _mapConfig.contains(mapkey)) {
        qDebug() << fnName << "Error: No MAP Server url specified";
        return -1;
    }

    static QString ulki = "use_local_known_identities";
    if (! _mapConfig.contains(ulki)) {
        qDebug() << fnName << "Disabling <use_local_known_identites> by default";
        _mapConfig.insert(ulki,"no");
    }

    static QString pcr = "peer_certificate_required";
    if (! _mapConfig.contains(pcr)) {
        qDebug() << fnName << "Disabling <peer_certificate_required> by default";
        _mapConfig.insert(pcr, "no");
    } else if (_mapConfig.value(pcr).compare("yes", Qt::CaseInsensitive) == 0) {
        // Make sure the following are set:
        /*
        <my_certificate_file/>
        <my_private_key_file/>
        <my_private_key_passwd/>
        <my_ca_chain_file/>
        */
    }

    return _mapConfig.count();
}

void hipCfgMap::addConfigItem(QString key, QString value)
{
    const char *fnName = "hipCfgMap::addConfigItem:";
    if (! value.isEmpty()) {
        qDebug() << fnName << "Adding:" << key << "-->" << value;
        _mapConfig.insert(key, value);
    }
}

// Implementing this Qt-4.6 method in order to use Qt-4.5 on OpenWRT
bool hipCfgMap::readNextStartElement(QXmlStreamReader &xmlReader)
{
    while (xmlReader.readNext() != QXmlStreamReader::Invalid) {
        if (xmlReader.isEndElement())
            return false;
        else if (xmlReader.isStartElement())
            return true;
    }
    return false;
}

// Implementing this Qt-4.6 method in order to use Qt-4.5 on OpenWRT
void hipCfgMap::skipCurrentElement(QXmlStreamReader &xmlReader) {
    int depth = 1;
    while (depth && xmlReader.readNext() != QXmlStreamReader::Invalid) {
        if (xmlReader.isEndElement())
            --depth;
        else if (xmlReader.isStartElement())
            ++depth;
    }
}

bool hipCfgMap::readIPMConfigXML(QIODevice *device)
{
    const char *fnName = "hipCfgMap::readIPMConfigXML:";
    QXmlStreamReader xmlReader(device);

    if (readNextStartElement(xmlReader)) {
        if (xmlReader.name() == "ipm_configuration" &&
            xmlReader.attributes().value("version") == "1.0") {

            xmlReader.readNext();

            while (readNextStartElement(xmlReader)) {
                if (xmlReader.name() == "use_local_known_identities") {
                    QString value = xmlReader.readElementText();
                    if (value.compare("yes", Qt::CaseInsensitive) == 0 ||
                        value.compare("no", Qt::CaseInsensitive) == 0) {
                        addConfigItem(xmlReader.name().toString(), value);
                    } else {
                        xmlReader.raiseError(QObject::tr("Incorrect value for <use_local_known_identities>"));
                    }
                } else if (xmlReader.name() == "peer_certificate_required") {
                    QString value = xmlReader.readElementText();
                    if (value.compare("yes", Qt::CaseInsensitive) == 0 ||
                        value.compare("no", Qt::CaseInsensitive) == 0) {
                        addConfigItem(xmlReader.name().toString(), value);
                    } else {
                        xmlReader.raiseError(QObject::tr("Incorrect value for <peer_certificate_required>"));
                    }
                } else if (xmlReader.name() == "peer_ca") {
                    addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                } else if (xmlReader.name() == "my_certificate_file") {
                    addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                } else if (xmlReader.name() == "my_ca_chain_file") {
                    addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                } else if (xmlReader.name() == "my_private_key_file") {
                    addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                } else if (xmlReader.name() == "my_private_key_passwd") {
                    addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                } else if (xmlReader.name() == "map_proxy_passwd") {
                    addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                } else if (xmlReader.name() == "ipm_map_configuration" &&
                           xmlReader.attributes().value("version") == "1.0") {
                    while (readNextStartElement(xmlReader)) {
                        if (xmlReader.name() == "map_server_url") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_server_vendor") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_ignore_ssl_errors") {
			    QString value = xmlReader.readElementText();
			    if (value.compare("yes", Qt::CaseInsensitive) == 0 ||
				value.compare("no", Qt::CaseInsensitive) == 0) {
				addConfigItem(xmlReader.name().toString(), value);
			    } else {
				xmlReader.raiseError(QObject::tr("Incorrect value for <map_ignore_ssl_errors>"));
			    }
                        } else if (xmlReader.name() == "map_server_ca_file") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_certificate_file") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_private_key_file") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_private_key_passwd") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_http_username") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_http_password") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_proxy_server") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_proxy_port") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_proxy_user") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else if (xmlReader.name() == "map_proxy_passwd") {
                            addConfigItem(xmlReader.name().toString(), xmlReader.readElementText());
                        } else {
                            skipCurrentElement(xmlReader);
                        }
                    }
                } else {
                    skipCurrentElement(xmlReader);
		}

                xmlReader.readNext();
	    }
        } else {
	    xmlReader.raiseError(QObject::tr("The file is not an IPM Config file version 1.0"));
	}
       
    }

    if (xmlReader.error()) {
        qDebug() << fnName << "XML Error:";
        qDebug() << fnName << "-->" << xmlReader.errorString();
    }

    return !xmlReader.error();
}

int hipCfgMap::loadCfg(struct hip_conf *hc)
{
    const char *fnName = "hipCfgMap::loadCfg: ";
    SSL_CTX *ctx = NULL;

    if(hc==NULL){
	cerr << fnName << "ERROR: HCNF not set" << endl;
	return -1;
    }

    _hcfg = hc;

    // Load config file options
    if (readIPMConfigFile() < 0) {
        return -1;
    }

    if (_mapConfig.value("peer_certificate_required").compare("yes", Qt::CaseInsensitive) == 0) {
        //SSL context without smartcard engine.
        SSL_library_init();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(SSLv3_client_method());
        if (ctx == NULL) {
            cerr << fnName << "Error creating SSL context" << endl;
            return -1;
        }
        _ssl = SSL_new(ctx);
        if (_ssl == NULL) {
            cerr << fnName << "Error open SSL connect" << endl;
            return -1;
        }

        _store = X509_STORE_new();
        if(!_store){
            cerr << fnName << "Error calling X509_STORE_new" << endl;
            return -1;
        }

        X509_STORE_set_verify_cb_func(_store, hipCfgMap::callb);
        X509_STORE_set_default_paths(_store);

        // Read my HIP Identity from certificate file
    } else {
        // Get HIT from my_host_identities.xml
        if (getHITFromLocalFile()!=0) {
            return -1;
        }
    }

    // Use an on-disk known_host_identites.xml file to initialize the
    // overlay configuration.  Then if MAP never comes up, at least we've
    // got something going.
    if(_hcfg->use_local_known_identities) {
	if(getEndboxMapsFromLocalFile() < 0) {
	    cerr << fnName 
	    	 << "Error initializing state from local known identities file" << endl;
	}
    }

    // Setup signal-slot connections:
    bool connected = false;
    while ( !connected ) {
        // Give thread time to start
        sleep(1);

        connected = connect(this, SIGNAL(connectToMap(QMap<QString,QString> *)),
                (QObject *)_ifmapThread->_client, SLOT(connectToMap(QMap<QString,QString> *)));
    }

    // Now that thread is up, other connections should be made instantly
    connected = connect(this, SIGNAL(setUnderlayIp(QString)),
    		(QObject *)_ifmapThread->_client, SLOT(setUnderlayIp(QString)));
    if (!connected) {
        qDebug() << fnName << "Error: Could not connect setUnderlayIp signal/slot";
	return -1;
    }

    /*
    // connectToMap asynchronously
    qDebug() << fnName << "About to emit connectToMap";
    emit connectToMap(&_mapConfig);
    sleep(20);
    */

    // Make connectToMap act like a synchronous call
    mapMutex.lock();
    emit connectToMap(&_mapConfig);
    mapWaitCond.wait(&mapMutex);
    mapMutex.unlock();

    qDebug() << fnName << "About to exit loadCfg";
    return 0;
}

/* return the size of the certificate if succeed
 *        or 0 if the cert attribute doesn't exist
 *        or -1 if other error.
 */
//DM: url in hipCfgMap is a DN
int hipCfgMap::verifyCert(const char *url, const hip_hit hit)
{
  int rc;
  char cert[2048];
  hip_hit cached_hit;
  time_t now;
  X509 *x509Cert = NULL;
  BIO *bio_mem = NULL;
  char hit_s[128];

  map <string, certInfo>::iterator m_i;

  m_i = _certs.find(url);
  if(m_i != _certs.end()){
     time(&now);
     if((*m_i).second.getTs() > (now - 3600*24)){ //not expired
        hitstr2hit(cached_hit, (char *)(*m_i).second.getHit());
	if(memcmp(cached_hit, hit, HIT_SIZE)==0){
	  //cout<<"Use cached certInfo, url "<<url<<endl;
	  return 1;
	}
     }
  }
  
  hit2hitstr(hit_s, hit);
  if(getCertFromMap(url, cert, sizeof(cert)) <= 0)
    return -1;

  bio_mem = BIO_new_mem_buf(cert, -1);

  x509Cert = PEM_read_bio_X509(bio_mem, NULL, 0, NULL);
  if(x509Cert==NULL){
     cout<<"Error with certificate data for url "<<url<<endl;
     return -1;
  }

  rc = verify_certificate(x509Cert);
  if(rc != 1)
    return -1;

  hi_node hi;
  EVP_PKEY *pubkey = NULL;
  pubkey=X509_get_pubkey(x509Cert); //obtain public key (host identity) from the certificate
  if(pubkey==NULL){
    cout<< "error get X509 public key from certificate for url "<<url<<endl;
    return -1;
  }

  memset(&hi, 0, sizeof(hi_node));
  rc = mkHIfromPkey(EVP_PKEY_get1_RSA(pubkey), EVP_PKEY_get1_DSA(pubkey), &hi);
  if(rc < 0)
    return -1;

  //verify hit derived from the certificate is the same from
  //the peer hit who has signed R1 or I2 packet.
  if(memcmp(hi.hit, hit, HIT_SIZE) != 0)
    return 0;
  hit2hitstr(hit_s, hi.hit);

  certInfo ci(hit_s);
  _certs[url] = ci;

  return 1; 
}

//DM: url in hipCfgMap is DN
int hipCfgMap::getCertFromMap(const char *url, char *buf, int size)
{
  const char *fnName = "hipCfgMap::getCertFromMap: ";
  int rc = -1;

  cout<< fnName << "search for entry "<<url<<endl;

  return rc;
}

// Publish cert to MAP
int hipCfgMap::postLocalCert(const char *hit)
{
  const char *fnName = "hipCfgMap::postLocalCert: ";
  char buf[2048];
  int rc;

  if(_hcfg->use_local_known_identities)
     return 0;

  if(_scCert.length() == 0){
    cout<<"postLocalCert: local cert not loaded from smart card yet"<<endl;
    return -1;
  }

  if (_scDN.length() == 0) {
      getCertDN();
  }

  if(getCertFromMap(_localCertUrl.c_str(), buf, sizeof(buf))>0 &&
     strcmp(_scCert.c_str(), buf)==0){
     cout<<"cert in MAP server is identical to the one in smartcard"<<endl;
     return 0;
  }

  return 0;
}

int hipCfgMap::getCertDN()
{
  X509 *x509Cert = NULL;
  BIO *bio_mem = NULL;
  string subject;

  if(_scCert.length() == 0){
    cout<<"getCertDN: local cert not loaded from smart card yet"<<endl;
    return -1;
  }

  bio_mem = BIO_new_mem_buf((char *)_scCert.c_str(), -1);

  x509Cert = PEM_read_bio_X509(bio_mem, NULL, 0, NULL);
  if(x509Cert==NULL){
     cout<<"getCertDN: Could not load cert into X509 structure"<<endl;
     return -1;
  }

  subject = X509_NAME_oneline(X509_get_subject_name(x509Cert), NULL, 0);
  if(subject.length() == 0){
    cout<<"getCertDN: Could not read DN from cert"<<endl;
    return -1;
  }

  cout << "getCertDN: Got cert DN: " << subject << endl;
  _scDN = subject;

  // localCertUrl when using MAP is the DN of the cert
  _localCertUrl = _scDN;


  // DM: TODO: Parse CN from DN
  /* Something like:
    int loc = subject.find( "CN=", 0 );
    CN = subject.remove(0, loc+3);
   */

   return 0;
}

// Publish Current Underlay IP Address
int hipCfgMap::setUnderlayIpAddress(const char *ip)
{
  const char *fnName = "hipCfgMap::setUnderlayIpAddress: ";

  cout << fnName << "Will publish current ip" << endl;
  emit setUnderlayIp(ip);

  return 0;
}

void hipCfgMap::updateMaps(string myDN,
			   string myHIT,
			   list<string> newPeerDNs,
			   map<string,string> newPeerDN_HITs,
			   map<string,string> newPeerDN_ULIPs,
			   map<string,string> newPeerDN_LNIPs)
{
    const char *fnName = "hipCfgMap::updateMaps: ";
    hip_hit myHITh;

    set <hitPair, hp_compare> allowed_peers; // To become _allowed_peers
    map <string, string> endbox2LlipMap; // To become _endbox2LlipMap
    map <string, string> legacyNode2EndboxMap; // To become _legacyNode2EndboxMap
    map <string, struct peer_node *> hit_to_peers; // To become _hit_to_peers

    // Get hex representation of my HIT
    //hitstr2hit(myHITh, (char *)myHIT.c_str());
    hitstr2hit(myHITh, _mapConfig.value("HIT").toAscii().constData());

    list<string>::iterator si;
    map<string,string>::iterator mi;
    for (si = newPeerDNs.begin(); si != newPeerDNs.end(); si++ ) {
        string peerDN = *si;
	cout << fnName << "Updating maps for peerDN: " << peerDN << endl;
	string peerHIT;

	// DN-HIT
	mi = newPeerDN_HITs.find(peerDN);
	if (mi != newPeerDN_HITs.end()) {
	      peerHIT = mi->second;
	      cout << fnName << "Adding mapping for DN<->HIT: " << peerDN << " <-> " << peerHIT << endl;
	      hip_hit peerHITh;
	      hitstr2hit(peerHITh, (char *)peerHIT.c_str());
	      if (memcmp(myHITh, peerHITh, HIT_SIZE) < 0) {
		  hitPair hp(myHITh, peerHITh);
		  allowed_peers.insert(hp);
	      } else if (memcmp(myHITh, peerHITh, HIT_SIZE) > 0) {
		  // Reverse order
		  hitPair hp(peerHITh, myHITh);
		  allowed_peers.insert(hp);
	      } else {
		  cout << fnName << "Not adding allowed_peers for myself!" << endl;
	      }
	} else {
	    cout << fnName << "Could not find peerHIT for peerDN: " << peerDN << endl;
	    continue;
	}

	mi = newPeerDN_ULIPs.find(peerDN);
	if (mi != newPeerDN_ULIPs.end()) {
	    string peerULIP = mi->second;
	    cout << fnName << "Adding mapping for HIT<->UnderlayIP: " << peerHIT << " <-> " << peerULIP << endl;
	    endbox2LlipMap[peerHIT] = peerULIP;
	} else {
	    cout << fnName << "Could not find peerULIP for peerDN: " << peerDN << endl;
	}

	// Find all legacy nodes belonging to the peer endbox
	map<string,string>::iterator lni;
	for (lni = newPeerDN_LNIPs.begin(); lni != newPeerDN_LNIPs.end(); lni++) {
	    string peerLNIP = lni->first;
	    string testDN = lni->second;
	    if (testDN.compare(peerDN) == 0) {
		cout << fnName << "Adding mapping for HIT<->LegacyNodeIP: " << peerHIT << " <-> " << peerLNIP << endl;
		legacyNode2EndboxMap.insert(std::make_pair(peerLNIP, peerHIT));
	    }
	}

        // Endbox LSI to HIT mapping
        char peerLSI[INET_ADDRSTRLEN];
        if (!hitstr2lsistr(peerLSI, (char *)peerHIT.c_str())) {
            mi = legacyNode2EndboxMap.find(peerLSI);
	    if (mi == legacyNode2EndboxMap.end()) {
		legacyNode2EndboxMap.insert(std::make_pair(peerLSI, peerHIT));
		cout << fnName << "Adding (" << peerLSI << ", " << peerHIT
	      		       << ") into legacyNode2EndboxMap" << endl;
	    }
        } else {
            cout << fnName << "Error converting HIT to LSI for DN: " << peerDN << endl;
        }

        // Endbox HIT to hip peer entry
	cout << fnName << "Adding entry to hit_to_peers HIT: " << peerHIT << endl;
        struct peer_node *p = new(struct peer_node);
        memset(p, 0, sizeof(struct peer_node));
        hitstr2hit(p->hit, (char *)peerHIT.c_str());
        strcpy(p->name, (char *)peerDN.c_str());
        //TODO: These parameters should be specified somewhere?
        p->algorithm_id = 0;
        p->r1_gen_count = 10;
        p->anonymous = 0;
        p->allow_incoming = 1;
        p->skip_addrcheck = 0;
        // Make pair
        hit_to_peers.insert(std::make_pair(peerHIT, p));
    }

    // This needs to be mutex'd because ifmap_client calls this function from
    // its own thread to update these objects.
    pthread_mutex_lock(&hipcfgmap_mutex);
	_allowed_peers = allowed_peers;
	_endbox2LlipMap = endbox2LlipMap;
	_legacyNode2EndboxMap = legacyNode2EndboxMap;
	_hit_to_peers = hit_to_peers;
    pthread_mutex_unlock(&hipcfgmap_mutex);

}

int hipCfgMap::stringListContains(list<string> haystack, string needle)
{
    list<string>::iterator si;
    int loc = 0;
    for (si = haystack.begin(); si != haystack.end(); si++ ) {
        string h = *si;
	if (needle.compare(h) == 0) {
	    return loc;
	}
	loc++;
    }

    return -1;
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
    char basename[MAX_HI_NAMESIZE - 16];
    int rc = 0;
    bool haveDN = false;

    _hostid  = new hi_node();
    memset(_hostid, 0, sizeof(hi_node));

    //the following parameters may need to be configurate  -TBD
    _hostid->anonymous = 0;
    _hostid->allow_incoming = 1;
    _hostid->r1_gen_count = 10;
    _hostid->skip_addrcheck = TRUE;
    _hostid->r1_gen_count = 10;

    char my_hi_filename[255] = "my_host_identities.xml";

    if (locate_config_file(my_hi_filename,
                           sizeof(my_hi_filename),
                           HIP_MYID_FILENAME) == 0) {
        cout<<"Will attempt to parse file: "<<my_hi_filename<<endl;
    } else {
        cout << "Could not find my_hi_filename" << endl;
        return -1;
    }

    doc = xmlParseFile(my_hi_filename);
    if(doc == NULL) {
        cout<<"Error parsing xml file "<<my_hi_filename<<endl;
        return(-1);
    }

    addr = (struct sockaddr*) &ss_addr;
    node = xmlDocGetRootElement(doc);
    for (node = node->children; node; node = node->next){
       if(strcmp((char *)node->name, "host_identity")==0) {

	   for (xmlNodePtr cnode = node->children; cnode; cnode = cnode->next) {
	     if(strcmp((char *)cnode->name, "text")==0)
		continue;
	     data = (char *)xmlNodeGetContent(cnode);
	     if(strcmp((char *)cnode->name, "name")==0) {
	       //Setting distinguished-name to name
	       _scDN = string(data);
               _mapConfig.insert("DistinguishedName", QString(_scDN.c_str()));
	       haveDN = true;
	       cout << fnName << "Setting distinguished name: " << _scDN << endl;
	     }
	     if(strcmp((char *)cnode->name, "HIT")==0) {
	       memset(addr, 0,sizeof(struct sockaddr_storage));
	       addr->sa_family = AF_INET6;
	       if (str_to_addr(data, addr) <= 0) {
		    cout<< fnName << "Warning parsing HIT "<< data<< " is invalid"<<endl;
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

    memset(&lsi, 0, sizeof(struct sockaddr_in));
    memset(lsi_str, 0, INET_ADDRSTRLEN);
    lsi.sin_family = AF_INET;
    lsi.sin_addr.s_addr = ntohl(HIT2LSI(_hostid->hit)); 
    if (addr_to_str(SA(&lsi), lsi_str, INET_ADDRSTRLEN)){
        printf("Error generating LSI from HIT!\n");
        return -1;
    }
    memcpy(&_hostid->lsi, &lsi, sizeof(struct sockaddr_in));

    // Make sure we were able to find DN from file
    if (haveDN != true) rc = -1;

    return rc;
}
