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
