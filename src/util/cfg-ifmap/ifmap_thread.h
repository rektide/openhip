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
 *  ifmap_thread.h
 *
 *  Authors:	David Mattes, <david.mattes@boeing.com>
 *
 *  IF-MAP Plug-in for Endbox mode: Qt thread exec for MAP Client
 *
 */

#ifndef IFMAP_THREAD_H
#define IFMAP_THREAD_H

#include <QtCore>

extern QMutex mapMutex;
extern QWaitCondition mapWaitCond;

class IfmapClient;

class IfmapThread : public QThread {
	Q_OBJECT
public:
	IfmapThread(QObject *parent = 0);
	~IfmapThread();

	void run();

	void deleteMapClient();

public:
	IfmapClient *_client;

};

#endif
