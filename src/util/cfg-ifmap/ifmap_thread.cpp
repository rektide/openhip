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
 *  ifmap_thread.cpp
 *
 *  Authors:	David Mattes, <david.mattes@boeing.com>
 *
 *  IF-MAP Plug-in for Endbox mode: Qt thread exec for MAP Client
 *
 */

#include "ifmap_client.h"
#include "ifmap_thread.h"

QMutex mapMutex;
QWaitCondition mapWaitCond;

IfmapThread::IfmapThread(QObject *parent)
	: QThread(parent)
{
    qDebug() << "In IfmapThread constructor";
}

IfmapThread::~IfmapThread()
{
    qDebug() << "In IfmapThread destructor";
}

void IfmapThread::run()
{
    qDebug() << "in IfmapThread::run()";

    _client = new IfmapClient(0);
    exec();
}

void IfmapThread::deleteMapClient()
{
    qDebug() << "In IfmapThread::deleteMapClient";
    delete _client;
}
