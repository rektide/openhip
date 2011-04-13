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
