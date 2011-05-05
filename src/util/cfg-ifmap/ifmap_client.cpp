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
 *  ifmap_client.cpp
 *
 *  Authors:	David Mattes, <david.mattes@boeing.com>
 *
 *  IF-MAP Plug-in for Endbox mode: MAP Client class implementation
 *
 */

#include <string>
#include <list>

#include <QtNetwork>

#include "ifmap1_1.h"
#include "ifmap_client.h"
#include <hip/hip_cfg_map.h>

using namespace std;

extern QMutex mapMutex;
extern QWaitCondition mapWaitCond;

IfmapClient::IfmapClient(QObject *parent)
	: QObject(parent)
{
    _ifmap = new Ifmap();

    //_ifmap->setDebug(Ifmap::ShowClientOps | Ifmap::ShowHTTPState);
    //_ifmap->setDebug(Ifmap::ShowClientOps | Ifmap::ShowXML);

    // Delay in msec before re-trying MAP request
    _retryDelay = 10000;

    _scadaNS = "http://www.trustedcomputinggroup.org/2006/IFMAP-SCADANET-METADATA/1";
    _ifmap->addNamespace("scada", _scadaNS);

    _matchLinks = QString("scada:dn-hit or scada:underlay-ip or scada:scada-node ") +
    		  QString("or scada:policy");
    _resultsFilter = QString("scada:underlay-ip or scada:scada-node or scada:dn-hit ") + 
    		     QString("or scada:cert or scada:role or scada:policy");
    connect(_ifmap, SIGNAL(responseARC(MapResponse *)),
            this, SLOT(mapResponseOnARC(MapResponse *)));
}

IfmapClient::~IfmapClient()
{
}

void IfmapClient::connectToMap(QMap<QString, QString> *mapConfig)
{
    const char *fnName = "IfmapClient::connectToMap:";
    // Save mapConfig
    qDebug() << fnName << "Slot called!";
    _mapConfig = QMap<QString,QString>(*mapConfig);

    _ifmap->setHost(QUrl(_mapConfig.value("map_server_url")));

    if (_mapConfig.contains("map_server_ca_file")) {
        _ifmap->addCACertificate(_mapConfig.value("map_server_ca_file"));
    }

    if (_mapConfig.contains("map_certificate_file") && _mapConfig.contains("map_private_key_file")) {
	QFile certFile(_mapConfig.value("map_certificate_file"));
	certFile.open(QIODevice::ReadOnly);
        QSslCertificate clientCert(&certFile, QSsl::Pem);

	QByteArray pass;
	if (_mapConfig.contains("map_private_key_passwd")) {
	    pass = _mapConfig.value("map_private_key_passwd").toLatin1();
	}

	QFile keyFile(_mapConfig.value("map_private_key_file"));
        keyFile.open(QIODevice::ReadOnly);
        QSslKey clientKey(&keyFile, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, pass);

	_ifmap->setClientCertAndKey(clientCert, clientKey);
    }

    if (_mapConfig.contains("map_http_username") && _mapConfig.contains("map_http_password")) {
        _ifmap->setUser(_mapConfig.value("map_http_username"), _mapConfig.value("map_http_password"));
    }

    if (_mapConfig.contains("map_proxy_server")) {
        if (_mapConfig.contains("map_proxy_port")) {
            _ifmap->setProxy(_mapConfig.value("map_proxy_server"), _mapConfig.value("map_proxy_port").toUInt());
        } else {
            _ifmap->setProxy(_mapConfig.value("map_proxy_server"));
        }
    }

    if (_mapConfig.contains("map_server_vendor") &&
        _mapConfig.value("map_server_vendor").compare("infoblox") == 0) {
        // Note that at least in Stu's test server max-depth of 1 means 2 links away
        _maxDepth = 1;
    } else {
        // But in omapd and juniper and Infoblox IBOS max-depth of 2 means 2 links away
        _maxDepth = 2;
    }

    /*
    // Return from "synchronous" call
    mapMutex.lock();
    mapWaitCond.wakeAll();
    mapMutex.unlock();
    */

    this->newSession();
}

void IfmapClient::newSession()
{
    const char *fnName = "IfmapClient::newSession:";

    _haveValidSession = false;

    NewSessionRequest newSession;
    MapResponse *mapResponse = _ifmap->submitRequest(&newSession);

    if (mapResponse->type() == MapResponse::SessionResponse) {

	_sessionId = mapResponse->sessionId();
	_publisherId = mapResponse->publisherId();

	qDebug() << fnName << "Setting sessionId:" << _sessionId 
			   << "and publisherId:" << _publisherId;
	_haveValidSession = true;

        if (!purgePublisher() || !publishCurrentState() || !setupEndboxMapSubscriptions()) {
            // Try to connect every _retryDelay milliseconds
            QTimer::singleShot(_retryDelay, this, SLOT(newSession()));
        } else {
            // Attach Session
            AttachSessionRequest attachSession(_sessionId);
            _ifmap->submitRequest(&attachSession);
        }
    } else {
        qDebug() << fnName << "Received unexpected response type:" <<
		 mapResponse->typeString();

	// Try to connect every _retryDelay milliseconds
	QTimer::singleShot(_retryDelay, this, SLOT(newSession()));
    }
}

bool IfmapClient::purgePublisher() {
    const char *fnName = "IfmapClient::purgePublisher:";
    bool rc = false;

    PurgePublisherRequest ppReq(_publisherId);
    MapResponse *mapResponse = _ifmap->submitRequest(&ppReq);
    if (mapResponse->type() == MapResponse::PurgePublisherResponse) {
        qDebug() << fnName << "Successfully executed purgePublisher";
        rc = true;
    } else {
        qDebug() << fnName << "Got unexpected response:" << mapResponse->typeString();
    }

    return rc;
}

bool IfmapClient::publishCurrentState()
{
    const char *fnName = "IfmapClient::publishCurrentState:";
    bool rc = false;

    IdentityId dnId(Identifier::IdentityDistinguishedName, _mapConfig.value("DistinguishedName"));

    // HIT
    IdentityId hitId(Identifier::IdentityAikName, _mapConfig.value("HIT"));
    Metadata dnhitMeta("dn-hit", _scadaNS);
    Link dnhitLink(&dnId, &hitId);
    PublishRequest pub(&dnhitLink, &dnhitMeta);

    // IP Addr
    if (! _currentIp.isEmpty()) {
        IpAddressId ipId(Identifier::IPv4, _currentIp);
        Link dnipLink(&ipId, &dnId);
        Metadata dnipMeta("underlay-ip", _scadaNS);
        pub.addToRequest(&dnipLink, &dnipMeta);
    }

    // Cert
    if (_mapConfig.value("peer_certificate_required").compare("yes", Qt::CaseInsensitive) == 0) {
    }

    MapResponse *mapResponse = _ifmap->submitRequest(&pub);

    if (mapResponse->type() == MapResponse::PublishResponse) {
        qDebug() << fnName << "Successfully published current state";
        rc = true;
    } else {
        qDebug() << fnName << "Got unexpected response:" << mapResponse->typeString();
    }

    return rc;
}

void IfmapClient::setUnderlayIp(QString ip)
{
    // Save passed in ip locally
    _currentIp = ip;

    if (_haveValidSession) {
	// Start a zero-length timer to get this call into this thread's event queue
	QTimer::singleShot(0, this, SLOT(publishUnderlayIp()));
    }
}

void IfmapClient::publishUnderlayIp()
{
    const char *fnName = "IfmapClient::publishUnderlayIp:";

    if (_currentIp.isEmpty()) {
        qDebug() << fnName << "Underlay IP string is empty!";
	return;
    }
	
    IdentityId dnId(Identifier::IdentityDistinguishedName, _mapConfig.value("DistinguishedName"));
    IpAddressId ipId(Identifier::IPv4, _currentIp);
    Link ipDnLink(&ipId, &dnId);
    Metadata ipDnMeta("underlay-ip", _scadaNS);

    PublishRequest pub(&ipDnLink, &ipDnMeta);
    MapResponse *mapResponse = _ifmap->submitRequest(&pub);

    if (mapResponse->type() == MapResponse::PublishResponse) {
        qDebug() << fnName << "Successfully published underlay-ip link:" << _currentIp;
	_currentIp = QString();
    } else {
        qDebug() << fnName << "Got unexpected response:" << mapResponse->typeString();
	// Restart MAP Client session and re-publish everything
	QTimer::singleShot(_retryDelay, this, SLOT(newSession()));
    }
}

bool IfmapClient::setupEndboxMapSubscriptions()
{
    const char *fnName = "IfmapClient::setupEndboxMapSubscriptions:";
    bool rc = false;

    IdentityId myId(Identifier::IdentityDistinguishedName, _mapConfig.value("DistinguishedName"));

    // Note that at least in Stu's server max-depth of 1 means 2 links away
    SearchRequest search(&myId, _matchLinks, _maxDepth);	
    search.setResultFilter(_resultsFilter);

    SubscribeRequest subscription;
    subscription.addUpdateRequest(&search, "overlaySub");
    MapResponse *mapResponse = _ifmap->submitRequest(&subscription);

    if (mapResponse->type() == MapResponse::SubscribeResponse) {
        qDebug() << fnName << "Successfully subscribed to overlay changes";
        rc = true;
    } else {
        qDebug() << fnName << "Got unexpected response type:" <<
		 mapResponse->typeString();
    }

    return rc;
}

void IfmapClient::mapResponseOnARC(MapResponse *mapResponse)
{
    const char *fnName = "IfmapClient::mapResponseOnARC:";

    if (mapResponse->type() == MapResponse::SessionResponse) {
        qDebug() << fnName << "Attached ARC Session";

        qDebug() << fnName << "Submitting MAP poll request";
        PollRequest poll;
        _ifmap->submitRequest(&poll);

    } else if (mapResponse->type() == MapResponse::PollResponse) {

        processPollResponse(mapResponse);

    } else {
        qDebug() << fnName << "Got unexpected response type:" <<
                 mapResponse->typeString();

        QTimer::singleShot(_retryDelay, this, SLOT(newSession()));
    }
}

void IfmapClient::processPollResponse(MapResponse *mapResponse)
{
    const char *fnName = "IfmapClient::pollResponse:";

    MapResult *mapResult = mapResponse->resultWithSubscriptionName("overlaySub");

    if (mapResult != 0) {
	qDebug() << fnName << "Got result of type:" << mapResult->typeString();
        qDebug() << fnName << "Got result for subscription:" << mapResult->subscriptionName();
        if (mapResult->type() == MapResult::SearchResult) {
	    this->updateEndboxMapping((SearchResult *)mapResult);

	    // Poll again
	    qDebug() << fnName << "Submitting MAP poll request";
	    PollRequest poll;
	    _ifmap->submitRequest(&poll);
	} else {
	    qDebug() << fnName << "Got ErrorResult in poll for subscription";
	    qDebug() << fnName << "Error:" << ((ErrorResult *)mapResult)->errorString();

	    // Start over
	    QTimer::singleShot(_retryDelay, this, SLOT(newSession()));
	}
    } else {
        qDebug() << fnName << "No poll response matching subscription name";
	QList <MapResult *> mapResults = mapResponse->mapResultList();
	qDebug() << fnName << "mapResults length:" << mapResults.length();
	
	QListIterator<MapResult *> mrit(mapResults);
	while (mrit.hasNext()) {
	    MapResult *mr = mrit.next();
	    qDebug() << fnName << "Got unexpected subscription:" << mr->subscriptionName();
	    qDebug() << fnName << "With unexpected mapResult type:" << mr->typeString();

	    if (mr->type() == MapResult::ErrorResult) {
		qDebug() << fnName << "Error Code:" << ((ErrorResult *)mr)->errorCodeAsString();
		qDebug() << fnName << "Error String:" << ((ErrorResult *)mr)->errorString();
	    }
	}

        // Start over
        QTimer::singleShot(_retryDelay, this, SLOT(newSession()));
    }
}

void IfmapClient::updateEndboxMapping(SearchResult *searchResult)
{
    const char *fnName = "IfmapClient::updateEndboxMapping:";

    QString myDN = _mapConfig.value("DistinguishedName");

    list<string> newPeerDNs;
    map<string,string> newPeerDN_HITs;
    map<string,string> newPeerDN_ULIPs;
    map<string,string> newPeerDN_LNIPs;

    // 0. Init newPeerDNs list with myself
    string dn = myDN.toAscii().constData();
    newPeerDNs.push_back(dn);

    // 1. Get my peers by DN
    QList<LinkResult *> peerList = searchResult->linksWithMetadata("policy",_scadaNS);
    qDebug() << fnName << "found num peers" << peerList.count();
    QListIterator<LinkResult *> peerIt(peerList);
    while (peerIt.hasNext()) {
    	//policy links are between 2 Identifier::IdentityDistinguishedName identifiers
	Link *link = peerIt.next()->link();

	IdentityId *dn1 = (IdentityId *)link->id1();
	IdentityId *dn2 = (IdentityId *)link->id2();
        string sdn1 = dn1->name().toAscii().constData();
        string sdn2 = dn2->name().toAscii().constData();

        if (dn1->name() == myDN) {
            newPeerDNs.push_back(sdn2);
        } else if (dn2->name() == myDN) {
            newPeerDNs.push_back(sdn1);
	} else {
            qDebug() << fnName << "Policy link does not contain with my DN: ("
	    	     << dn1->name() << "<-->" << dn2->name() << ")";
	}
    }
    qDebug() << fnName << "Have scada:policy links with num peers:" << newPeerDNs.size();


    // 2. Get HITs, Underlay IPs, LegacyNode IPs
    QList<LinkResult *> linkResults = searchResult->linkResultList();
    qDebug() << fnName << "linkResults length:" << linkResults.length();

    QListIterator<LinkResult *> lrIt(linkResults);
    while (lrIt.hasNext()) {
	LinkResult *lr = lrIt.next();
	Metadata *meta = lr->metadata();

	if (lr->link()->containsTypes(Identifier::IdentityDistinguishedName,
				      Identifier::IpAddress)) {

	    IpAddressId *ip = (IpAddressId *)lr->link()->identifierForType(Identifier::IpAddress);
	    IdentityId *dn = (IdentityId *)lr->link()->
	    	identifierForType(Identifier::IdentityDistinguishedName);

            string sip = ip->value().toAscii().constData();
            string sdn = dn->name().toAscii().constData();

	    if (meta->containsElement("scada-node",_scadaNS)) {
		// LegacyNode IP
		qDebug() << fnName << "Got scada-node ip<-->dn link:" 
			 << ip->value() << "<-->" << dn->name();

		//BUG! inserting pair(sdn,sip) allows only 1 legacy node per EB!
                //newPeerDN_LNIPs.insert(std::make_pair(sdn,sip));
                newPeerDN_LNIPs.insert(std::make_pair(sip,sdn));

	    } else if (meta->containsElement("underlay-ip",_scadaNS)) {
		// Underlay IP
		qDebug() << fnName << "Got underlay ip<-->dn link:" 
			 << ip->value() << "<-->" << dn->name();

                // Note that only a single underlay ip will be possible with this pairing.
                newPeerDN_ULIPs.insert(std::make_pair(sdn,sip));
	    }

	} else if (lr->link()->containsTypes(Identifier::IdentityAikName,
					     Identifier::IdentityDistinguishedName)) {

	    IdentityId *dn = (IdentityId *)lr->link()->
	    	identifierForType(Identifier::IdentityDistinguishedName);
	    IdentityId *hit = (IdentityId *)lr->link()->
	    	identifierForType(Identifier::IdentityAikName);

            string sdn = dn->name().toAscii().constData();
            string shit = hit->name().toAscii().constData();

	    if (meta->containsElement("dn-hit",_scadaNS)) {
		// Peer HIT
		qDebug() << fnName << "Got hit<-->dn link:" 
			 << hit->name() << "<-->" << dn->name();
                if (myDN == dn->name()) {
		    qDebug() << fnName << "Found my HIT:" << hit->name();
		}
                newPeerDN_HITs.insert(std::make_pair(sdn,shit));
	    }
	}
    }

    hipCfgMap *hcm = hipCfgMap::getInstance();
    string sdn = myDN.toAscii().constData();
    string shit = _mapConfig.value("HIT").toAscii().constData();
    hcm->updateMaps(sdn, shit, newPeerDNs, newPeerDN_HITs, newPeerDN_ULIPs, newPeerDN_LNIPs);
}

QString IfmapClient::interfaceAddr()
{
    const char *fnName = "IfmapClient::interfaceAddr:";
    QString ifAddr = "";

    QString netIF = _mapConfig.value("underlay_interface");

    QNetworkInterface mi = QNetworkInterface::interfaceFromName(netIF);
    if (mi.isValid()) {
	QList<QNetworkAddressEntry> miAddrs = mi.addressEntries();
	// Just take first address on interface...
	if (miAddrs.length() > 0) {
	    ifAddr = miAddrs.at(0).ip().toString();
	    qDebug() << fnName << "Got interface ip:" << ifAddr;
	} else {
            qDebug() << fnName << "No IP Address on interface:" << netIF;
	}
    } else {
        qDebug() << fnName << "Got invalid info about interface:" << netIF;
    }

    return ifAddr;
}
