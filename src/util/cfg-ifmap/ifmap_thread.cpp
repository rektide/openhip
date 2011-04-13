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
}

void IfmapThread::run()
{
    qDebug() << "in IfmapThread::run()";

    _client = new IfmapClient(0);
    exec();
}
