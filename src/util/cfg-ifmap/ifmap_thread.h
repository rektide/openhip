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

public:
    IfmapClient *_client;

};

#endif
