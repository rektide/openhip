#include <openssl/engine.h>
#include <hip/hip_cfg_ldap.h>
#include "LDAPSearchResults.h"
#include "LDAPAttribute.h"
#include "LDAPAttributeList.h"
#include "LDAPEntry.h"
#include "LDAPException.h"
#include <libxml/tree.h>

LDAPConnection *hipCfgLdap::_lc = NULL;
hipCfgLdap *hipCfgLdap::_instance = NULL;

extern "C" {
int hipcfg_init(struct hip_conf *hc)
{
  //printf("cfg-local hipcfg_init called\n");
  hipCfg *hs=hipCfgLdap::getInstance();
  return hs->loadCfg(hc);
}

int hipcfg_close()
{
  //printf("cfg-local hipcfg_init called\n");
  hipCfg *hs=hipCfgLdap::getInstance();
  return hs->closeCfg();
}

int hipcfg_allowed_peers(const hip_hit hit1, const hip_hit hit2)
{
  //printf("cfg-local hit_peer_allowed\n");
  hipCfg *hs=hipCfgLdap::getInstance();
  return hs->hit_peer_allowed(hit1, hit2);
}

int hipcfg_peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt)
{
  //printf("cfg-local hit_peer_allowed\n");
  hipCfg *hs=hipCfgLdap::getInstance();
  return hs->peers_allowed(hits1, hits2, max_cnt);
}

int hipcfg_getEndboxByLegacyNode(const struct sockaddr *host, struct sockaddr *eb)
{
  int rc=0;
  
  hipCfg *hs=hipCfgLdap::getInstance();
  rc = hs->legacyNodeToEndbox(host, eb);
  return rc;
}

int hipcfg_getLlipByEndbox(const struct sockaddr *eb, struct sockaddr *llip)
{
  int rc=0;
  //printf("entering hipcfg_getLlipByEndbox...\n");
  hipCfg *hs=hipCfgLdap::getInstance();
  rc = hs->endbox2Llip(eb, llip);
  return rc;
}

int hipcfg_getLegacyNodesByEndbox(const struct sockaddr *eb,
   struct sockaddr_storage *hosts, int size)
{
  int rc=0;
  //printf("entering hipcfg_getLegacyNodesByEndbox...\n");
  hipCfg *hs=hipCfgLdap::getInstance();
  rc = hs->getLegacyNodesByEndbox(eb, hosts, size);
  return rc;
}

int hipcfg_verifyCert(const char *url, const hip_hit hit)
{
  int rc = 0;
  hipCfg *hs=hipCfgLdap::getInstance();
  rc = hs->verifyCert(url, hit);
  return rc;
}


int hipcfg_getLocalCertUrl(char *url, unsigned int size)
{
  int rc=0;
  hipCfg *hs=hipCfgLdap::getInstance();
  rc = hs->getLocalCertUrl(url, size);
  return rc;
}

int hipcfg_postLocalCert(const char *hit)
{
  int rc = 0;
  hipCfg *hs=hipCfgLdap::getInstance();
  rc = hs->postLocalCert(hit);
  return rc;
}

hi_node *hipcfg_getMyHostId()
{
  hipCfgLdap *hs=hipCfgLdap::getInstance();
  return hs->getMyHostId();
}

int hipcfg_getPeerNodes(struct peer_node *peerNodes, int max_count)
{
  hipCfgLdap *hs=hipCfgLdap::getInstance();
  return hs->getPeerNodes(peerNodes, max_count);
}

} /* extern "C" */

hipCfgLdap::hipCfgLdap()
{
  _lc = NULL;
}

hipCfgLdap *hipCfgLdap::getInstance()
{
  if(_instance==NULL){
    _instance = new hipCfgLdap();
  }
  return _instance;
}

int hipCfgLdap::closeCfg()
{
    disconnectLdap();
    return 0;
}

int hipCfgLdap::connectToLdap()
{
  string host("localhost"), binddn(""), bindpw("");
  int port = 389;

  if(_hcfg->cfg_serv_host)
    host = _hcfg->cfg_serv_host;
  if(_hcfg->cfg_serv_login_id)
    binddn=_hcfg->cfg_serv_login_id;
  if(_hcfg->cfg_serv_login_pwd)
    bindpw = _hcfg->cfg_serv_login_pwd;
  if(_hcfg->cfg_serv_login_id)
    _basedn=_hcfg->cfg_serv_basedn;
  else
     _basedn = "dc=sma,dc=boeing,dc=com";
  if(_hcfg->cfg_serv_port!=0)
    port = _hcfg->cfg_serv_port;

  _lc=new LDAPConnection(host, port);

  try {
    _lc->bind(binddn, bindpw, NULL);
    cout <<" ldap bind successfully."<<endl;
  } catch (LDAPException e){
     cout << "------------------------- caught Exception ---------"<< endl;
     delete _lc;
     _lc = NULL;
     return -1;
  }
  return 0;
}

void hipCfgLdap::disconnectLdap()
{
  if(_lc== NULL) {
	cout<<"warnning: disconnectLAP: not connected."<<endl;
	return;
  }

  try {
    _lc->unbind();
  } catch (LDAPException e){
        cout << "------------------------- caught Exception ---------"<< endl;
        cout << e << endl;
  }
  delete _lc;
  _lc = NULL;
}

int hipCfgLdap::getEndboxMapsFromLdap()
{
  map <string, string>::iterator mi;
  string dn;

  if(connectToLdap() != 0){
     cout<<"Error loadCfg: fail to connect to LDAP server."<<endl;
     return -1;
  }

  dn = "dc=endboxes," + _basedn;
  try {
    const LDAPAttributeList* attrs;
    StringList values;
    StringList s2;
    values.add("top");
    values.add("endbox");
    LDAPSearchResults* entries = _lc->search(dn, LDAPConnection::SEARCH_ONE);
    if(entries != NULL)
    {
       LDAPEntry* entry = entries->getNext();
       while(entry){
         try{
	   const LDAPAttribute *underlayIp_attr, *hit_attr, *legacyNode_attr, *assetTag_attr;
	   StringList underlayIp_sl, hit_sl, assetTag_sl;
           string underlayIp_s, hit_s, assetTag_s;
	   StringList::const_iterator i;

	   attrs = entry->getAttributes();

	   underlayIp_attr=attrs->getAttributeByName("underlayIp");
	   if(underlayIp_attr){
	     underlayIp_sl = underlayIp_attr->getValues();
	     i = underlayIp_sl.begin();
	     underlayIp_s = *i;
	   }

	   hit_attr=attrs->getAttributeByName("hit");
	   if(!hit_attr){
	     cout<<"no value found for attribute hit"<<endl;
	     return -1;
 	   }
	   hit_sl = hit_attr->getValues();
	   i = hit_sl.begin();
	   hit_s = *i;
	   //cout<<"hit: "<<hit_s;

	   assetTag_attr=attrs->getAttributeByName("assetTag");
	   if(!assetTag_attr){
	     cout<<"no value found for attribute assetTag"<<endl;
	     return -1;
 	   }
	   assetTag_sl = assetTag_attr->getValues();
	   i = assetTag_sl.begin();
	   assetTag_s = *i;
	   //cout<<"assetTag: "<<assetTag_s<<endl;

	   if(underlayIp_attr){
	     mi=_endbox2LlipMap.find(hit_s);
             if(mi==_endbox2LlipMap.end())
               _endbox2LlipMap[hit_s] = underlayIp_s;
	      //cout<<" underlayIp: "<<underlayIp_s<<endl;
	   } else
	     cout<<"underLayIp is not set for HIT "<<hit_s<<", will lookup DNS or DHT"<<endl;

	   legacyNode_attr=attrs->getAttributeByName("legacyNodesIp");
	   if(legacyNode_attr){
	     StringList lnodes_sl = legacyNode_attr->getValues();
             for(i = lnodes_sl.begin(); i != lnodes_sl.end(); i++){
               string lnode_s = *i;
	       _legacyNode2EndboxMap.insert(std::make_pair(lnode_s,hit_s));
	       //cout<<"add ("<<lnode_s<<", "<<hit_s<<") into _legacyNode2EndboxMap.insert"<<endl;
             }
	   }

	   //Insert an entry (lsi, hit) so that pinging endbox to endbox will work
	   char lsi_s[INET_ADDRSTRLEN];
	   if(!hitstr2lsistr(lsi_s, (char *)hit_s.c_str())){
	     mi=_legacyNode2EndboxMap.find(lsi_s);
	     if(mi==_legacyNode2EndboxMap.end()){
               _legacyNode2EndboxMap.insert(std::make_pair(lsi_s, hit_s));
		//cout<<"add ("<<lsi_s<<", "<<hit_s<<") into _legacyNode2EndboxMap.insert"<<endl;
	     }
	    } else 
		cout<<"error convert HIT to LSI"<<endl;

	   struct peer_node *p = new(struct peer_node);
	   memset(p, 0, sizeof(struct peer_node));

	   hitstr2hit(p->hit, (char *)hit_s.c_str());
	   strcpy(p->name, (char *)assetTag_s.c_str());

	   //Need to set these parameters, where to get it?
	   p->algorithm_id = 0;
	   p->r1_gen_count = 10;
	   p->anonymous = 0;
	   p->allow_incoming = 1;
	   p->skip_addrcheck = 0;

	   // Need to add a LDAP attribute RVS for p->rvs ?

	   _hit_to_peers.insert(std::make_pair(hit_s, p));
	    
           delete entry;
           entry = entries->getNext();
         } catch (LDAPException e){
            cout << "Caught exception" << endl;
         }
       }
    } else {
      cout<<"No result for ldap search."<<endl;
    }
    disconnectLdap();
    return 0;
  } catch (LDAPException e){
     cout << "------------------------- caught Exception ---------"<< endl;
     cout << e << endl;
     disconnectLdap();
     return -1;
  }
  return 0;
}

int hipCfgLdap::getPeerAllowedFromLdap()
{
  string dn;
  if(connectToLdap() != 0){
     cout<<"Error loadCfg: fail to connect to LDAP server."<<endl;
     return -1;
  }

  dn = "dc=peerAllowed,dc=acl," + _basedn;
  try {
    const LDAPAttributeList* attrs;
    StringList values;
    StringList s2;
    values.add("top");
    values.add("peerAllowed");
    LDAPSearchResults* entries = _lc->search(dn, LDAPConnection::SEARCH_ONE);
    if(entries != NULL)
    {
       LDAPEntry* entry = entries->getNext();
       while(entry){
         try{
	   const LDAPAttribute *hit1_attr, *hit2_attr;
	   StringList hit1_sl, hit2_sl;
           string hit1_s, hit2_s;
	   StringList::const_iterator i;

	   attrs = entry->getAttributes();

	   hit1_attr=attrs->getAttributeByName("host1");
	   if(!hit1_attr){
	     cout<<"no value found for attribute host1"<<endl;
	     return -1;
	   }
	   hit1_sl = hit1_attr->getValues();
	   i = hit1_sl.begin();
	   hit1_s = *i;

	   hit2_attr=attrs->getAttributeByName("host2");
	   if(!hit2_attr){
	     cout<<"no value found for attribute host2"<<endl;
	     return -1;
 	   }
	   hit2_sl = hit2_attr->getValues();
	   i = hit2_sl.begin();
	   hit2_s = *i;
	   //cout<<"hit1: " << hit1_s <<" hit2: "<<hit2_s<<endl;

	   hip_hit hit1, hit2;
	   hitstr2hit(hit1, (char *)hit1_s.c_str());
	   hitstr2hit(hit2, (char *)hit2_s.c_str());
	   
	   if(memcmp(hit1, hit2, HIT_SIZE) <0){
	     hitPair hp(hit1, hit2);
	    _allowed_peers.insert(hp);
	   } else if(memcmp(hit1, hit2, HIT_SIZE) >0) {
	     hitPair hp(hit2, hit1);
	     _allowed_peers.insert(hp);
	   }
	   //cout<<"insert a hitPair hit1: "<<hit1_s<<" hit2: "<<hit2_s<<endl;

           delete entry;
           entry = entries->getNext();
         } catch (LDAPException e){
            cout << "Caught exception" << endl;
         }
       }
    } else {
      cout<<"No result for ldap search."<<endl;
    }
    disconnectLdap();
    return 0;
  } catch (LDAPException e){
     cout << "------------------------- caught Exception ---------"<< endl;
     cout << e << endl;
     disconnectLdap();
     return -1;
  }
  return 0;
}

int hipCfgLdap::loadCfg(struct hip_conf *hc)
{
  SSL_CTX *ctx = NULL;

  if(hc==NULL){
    cout<<"loadCfg: ERROR: HCNF not set"<<endl;
    return -1;
  }

  _hcfg = hc;

  if(_hcfg->use_smartcard){

    if(init_ssl_context() != 0)
      return -1;

    if(mkHIfromSc() !=0 )
      return -1;

    char hit_s[128];
    if(hit2hitstr(hit_s, _hostid->hit)!=0){
      cout<<"invalid hit in local host identify (_hostid)"<<endl;
      return -1;
    }

    if(postLocalCert(hit_s)!=0)
      return -1;
  } else {
    //SSL context without smartcard engine.
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv3_client_method());
    if (ctx == NULL)
    {
        printf("hipCfgLdap::loadCfg: Error creating SSL context\n");
        return -1;
    }
    _ssl = SSL_new(ctx);
    if (_ssl == NULL) {
        fprintf(stderr,"Error open SSL connect\n");
        return -1;
    }
  }

  _store = X509_STORE_new();
  if(!_store){
    cerr<<"error calling X509_STORE_new"<<endl;
    return -1;
  }

  X509_STORE_set_verify_cb_func(_store, hipCfgLdap::callb);
  X509_STORE_set_default_paths(_store);

  if(_hcfg->use_local_known_identities){
    if(getEndboxMapsFromLocalFile()<0)
      return -1;
  }
  else {
    if(getEndboxMapsFromLdap()<0)
      return -1;
    if(getPeerAllowedFromLdap()<0)
      return -1;
  }

  return 0;
}

int hipCfgLdap::postLocalCert(const char *hit)
{
  _localCertUrl = "hit=";
  _localCertUrl += hit;
  _localCertUrl += ",dc=endboxes,dc=sma,dc=boeing,dc=com";
  char buf[2048];

  if(_hcfg->use_local_known_identities)
     return 0;

  if(_scCert.length() == 0){
    cout<<"postLocalCert: local cert not loaded from smart card yet"<<endl;
    return -1;
  }

  if(getCertFromLdap(_localCertUrl.c_str(), buf, sizeof(buf))>0 &&
     strcmp(_scCert.c_str(), buf)==0){
     cout<<"cert in Ldap server is identical to the one in smcart card."<<endl;
     return 0;
  }

  if(connectToLdap() != 0){
     cout<<"Error loadCfg: fail to connect to LDAP server."<<endl;
     return -1;
  }

  LDAPAttribute newattr("cert", _scCert.c_str());
  LDAPModification::mod_op op = LDAPModification::OP_REPLACE;
  LDAPModList *mod=new LDAPModList();
  mod->addModification(LDAPModification(newattr,op));

  try {
   _lc->modify(_localCertUrl, mod);
   delete mod;
   disconnectLdap();
  } catch (LDAPException e){
     cout << "------------------------- caught Exception ---------"<< endl;
     cout << e << endl;
     disconnectLdap();
     return -1;
  }

  return 0;
}

/* return the size of the certificate if succeed
 *        or 0 if the cert attribute doesn't exist
 *        or -1 if other error.
 */
int hipCfgLdap::verifyCert(const char *url, const hip_hit hit)
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
  
  if(getCertFromLdap(url, cert, sizeof(cert)) <= 0)
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


int hipCfgLdap::getCertFromLdap(const char *url, char *buf, int size)
{
  int rc = 0;
  StringList cert_l;
  StringList::const_iterator i;

  if(connectToLdap() != 0){
     cout<<"Error loadCfg: fail to connect to LDAP server."<<endl;
     return -1;
  }

  //cout<<"search for entry "<<url<<endl;
  try {
    const LDAPAttributeList* attrs;
    LDAPSearchResults* entries = _lc->search(url, LDAPConnection::SEARCH_BASE);
    if(entries != NULL)
    {
       LDAPEntry* entry = entries->getNext();
       if(entry){
	   const LDAPAttribute *cert_attr;
	   attrs = entry->getAttributes();
	   cert_attr=attrs->getAttributeByName("cert");
	   if(!cert_attr){
	     //cout<<"no value found for attribute cert"<<endl;
	     delete entry;
             disconnectLdap();
	     return 0;
	   }
	   cert_l = cert_attr->getValues();
	   i = cert_l.begin();
	   if(i != cert_l.end()){
		if((*i).length() > (unsigned int)size)
		  rc = -1;
		else {
		  strcpy(buf, (*i).c_str());
		  rc = strlen(buf);
		}
	   } else {
		rc = 0;
	   }
           delete entry;
       } else {
	 cout<<"entry not found for url "<<url<<endl;
	 rc = -1;
       }
    } else {
      cout<<"No result for ldap search for url "<<url<<endl;
      rc = -1;
    }
  } catch (LDAPException e){
     cout << "------------------------- caught Exception ---------"<< endl;
     cout << "while search for entry: "<<url<< " error: "<<e<< endl;
     rc = -1;
     disconnectLdap();
  }
  return rc;
}

