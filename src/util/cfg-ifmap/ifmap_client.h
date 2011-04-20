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
 *  ifmap_client.h
 *
 *  Authors:	David Mattes, <david.mattes@boeing.com>
 *
 *  IF-MAP Plug-in for Endbox mode: MAP Client class declaration
 *
 */

#ifndef IFMAP_CLIENT_H
#define IFMAP_CLIENT_H

#include <QtCore>
#include "ifmap1_1.h"

using namespace ifmap11;

class IfmapClient : public QObject {
    Q_OBJECT
public:
    IfmapClient(QObject *parent = 0);
    ~IfmapClient();

public slots:
    void connectToMap(QMap<QString,QString> *mapConfig);

private slots:
    void newSession();
    void mapResponseOnARC(MapResponse *mapResponse);

private:
    void updateEndboxMapping(SearchResult *searchResult);
    QString interfaceAddr();
    bool purgePublisher();
    bool publishCurrentState();
    bool setupEndboxMapSubscriptions();
    void processPollResponse(MapResponse *mapResponse);

private:
    Ifmap *_ifmap;
    bool _haveValidSession;
    QString _sessionId;
    QString _publisherId;

    QString _scadaNS;

    QString _matchLinks;
    QString _resultsFilter;
    int _maxDepth;

    int _retryDelay;

    QMap<QString,QString> _mapConfig;
};

#endif
