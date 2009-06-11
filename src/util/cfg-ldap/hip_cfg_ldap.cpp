#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
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


int hipcfg_getLocalCertUrl(char *url, int size)
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
  _ssl = NULL;
  _store = NULL;
  _hostid = NULL;
  _dsa = NULL;
  _rsa = NULL;
  _hcfg = NULL;
}

hipCfgLdap *hipCfgLdap::getInstance()
{
  if(_instance==NULL){
    _instance = new hipCfgLdap();
  }
  return _instance;
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

int hipCfgLdap::getEndboxMapsFromLocalFile()
{
  string hit_s, underlayIp_s, hit1_s, hit2_s;
  xmlDocPtr doc;
  xmlNodePtr node;
  char name[255];
  char known_hi_filename[255];
  FILE *fp;
  char *data;
  struct sockaddr_storage ss_addr;
  struct sockaddr *addr;

  addr = (struct sockaddr*) &ss_addr;
  sprintf(known_hi_filename, "%s", HIP_KNOWNID_FILENAME);
  fp = fopen(known_hi_filename, "r");
  if(!fp) {
    sprintf(known_hi_filename, "%s", HIP_DEFAULT_KNOWNID_FILENAME);
    fp = fopen(known_hi_filename, "r");
    if (fp) {
      cout<<"Using "<<HIP_DEFAULT_KNOWNID_FILENAME<<" file location"<<endl;
      fclose(fp);
    }
  } else {
    cout<<"Using "<<HIP_KNOWNID_FILENAME<<" file location"<<endl;
    fclose(fp);
  }

  doc = xmlParseFile(known_hi_filename);
  if(doc == NULL) {
    cout<<"Error parsing xml file "<<known_hi_filename<<endl;
    return(-1);
  }

  node = xmlDocGetRootElement(doc);
  for (node = node->children; node; node = node->next){
     if(strcmp((char *)node->name, "host_identity")==0) {
       struct peer_node *p;
       char lsi_s[INET_ADDRSTRLEN];
       string assetTag_s, underlayIp_s;
       StringList legacyNodes;
       xmlAttrPtr attr;

       p = new(struct peer_node);
       memset(p, 0, sizeof(struct peer_node));

       attr = node->properties;
       p->r1_gen_count = 0;
       p->anonymous = 0;
       p->allow_incoming = 1;
       p->skip_addrcheck = 0;

       while (attr) {
	  char *value;
          int tmp;
          if((attr->type==XML_ATTRIBUTE_NODE) &&
             (attr->children) && (attr->children->type==XML_TEXT_NODE))
            value = (char *)attr->children->content;
           else /* no attribute value */
             continue;
           /* save recognized attributes */
           if(strcmp((char *)attr->name, "alg_id")==0) {
              sscanf(value, "%d", &tmp);
              p->algorithm_id = (char)tmp;
            } else if (strcmp((char *)attr->name, "length")==0) {
               sscanf(value, "%d", &p->size);
            } else if(strcmp((char *)attr->name, "anon")==0) {
              if(*value == 'y')
                 p->anonymous = 1;
              else
                 p->anonymous = 0;
            } else if(strcmp((char *)attr->name, "incoming")==0) {
              if(*value == 'y')
                 p->allow_incoming = 1;
              else
                 p->allow_incoming = 0;
            } else if(strcmp((char *)attr->name, "r1count")==0) {
              sscanf(value, "%llu", &p->r1_gen_count);
            } else if(strcmp((char *)attr->name, "addrcheck")==0) {
              if(strcmp(value, "no")==0)
                p->skip_addrcheck = TRUE;
            }
            attr = attr->next;
        }
        
       //cout<<"Loading Host Identity Tag ..."<<endl;
       for (xmlNodePtr cnode = node->children; cnode; cnode = cnode->next) {
	 if(strcmp((char *)cnode->name, "text")==0)
            continue;
	 data = (char *)xmlNodeGetContent(cnode);
	 if(strcmp((char *)cnode->name, "HIT")==0) {
           memset(addr, 0,sizeof(struct sockaddr_storage));
           addr->sa_family = AF_INET6;
           if (str_to_addr(data, addr) <= 0) {
                cout<<"Waring parsing known host id - HIT "<< data<< " is invalid"<<endl;
                xmlFree(data);
                continue;
           }
	   hit_s = data;
	 } else if(strcmp((char *)cnode->name, "name")==0) {
 	   assetTag_s = data;
	 } else if(strcmp((char *)cnode->name, "addr")==0) {
	   underlayIp_s = data;
	 } else if(strcmp((char *)cnode->name, "legacyNodesIp")==0) {
	   legacyNodes.add(data);
	 } else if(strcmp((char *)node->name, "RVS")==0) {
	   memset(addr, 0, sizeof(struct sockaddr_storage));
	   addr->sa_family = ((strchr(data, ':')==NULL)?AF_INET:AF_INET6);
	   if (str_to_addr(data, addr) > 0)
	      memcpy(&p->rvs, addr, SALEN(addr));
	   else
	      cout<<"Waring parsing known host id - not a valid address "<<data<<endl;
	   
	 }
	 xmlFree(data);
       }
       _endbox2LlipMap[hit_s] = underlayIp_s;
       //cout<<"add ("<<hit_s<<", "<<underlayIp_s<<") into _endbox2LlipMap"<<endl;
       StringList::const_iterator i;
       for(i = legacyNodes.begin(); i != legacyNodes.end(); i++){
         string lnode_s = *i;
         _legacyNode2EndboxMap[lnode_s] = hit_s;
         //cout<<"add ("<<lnode_s<<", "<<hit_s<<") into _legacyNode2EndboxMap"<<endl;
       }
       if(!hitstr2lsistr(lsi_s, (char *)hit_s.c_str())){
	  _legacyNode2EndboxMap[lsi_s] = hit_s;
          //cout<<"add ("<<lsi_s<<", "<<hit_s<<") into _legacyNode2EndboxMap"<<endl;
       } else {
            cout<<"error convert HIT to LSI"<<endl;
	    return -1;
       }
       hitstr2hit(p->hit, (char *)hit_s.c_str());

       strcpy(p->name, (char *)assetTag_s.c_str());
       _hit_to_peers.insert(std::make_pair(hit_s, p));
       //cout<<"add peer node "<<assetTag_s<<", "<<hit_s<<" into _hit_to_peers"<<endl;
     } else if(strcmp((char *)node->name, "peer_allowed")==0){
       //cout<<"Loading peer_allowed Tag ..."<<endl;
       xmlNodePtr cnode;
       string hit1_s, hit2_s;
       for (cnode = node->children; cnode; cnode = cnode->next) {
	 if(strcmp((char *)cnode->name, "text")==0)
            continue;
	 data = (char *)xmlNodeGetContent(cnode);
	 if(strcmp((char *)cnode->name, "hit1")==0) {
	    hit1_s = data;
	 } else if(strcmp((char *)cnode->name, "hit2")==0) {
	    hit2_s = data;
	 }
	 xmlFree(data);
       }
       hip_hit hit1, hit2;
       if(hitstr2hit(hit1, (char *)hit1_s.c_str())<0){
         cout<<"Error convert hit "<<hit1_s<<endl;
	 continue;
       } else if(hitstr2hit(hit2, (char *)hit2_s.c_str())<0){
         cout<<"error convert hit "<<hit2_s<<endl;
	 continue;
       }

       if(memcmp(hit1, hit2, HIT_SIZE) <0){
         hitPair hp(hit1, hit2);
         _allowed_peers.insert(hp);
       } else if(memcmp(hit1, hit2, HIT_SIZE) >0) {
         hitPair hp(hit2, hit1);
         _allowed_peers.insert(hp);
       }
       //cout<<"insert a hitPair hit1: "<<hit1_s<<" hit2: "<<hit2_s<<endl;
     }
  }
  return 0;
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

bool hitPair::operator<(const hitPair & hp) const
{
  //this->print();
  return memcmp(hp._hit1, _hit1, HIT_SIZE) > 0 ||
           memcmp(hp._hit1, _hit1, HIT_SIZE) == 0 && memcmp(hp._hit2, _hit2, HIT_SIZE) > 0;
}

hitPair::hitPair(const hip_hit hit1, const hip_hit hit2)
{
  memcpy(_hit1, hit1, HIT_SIZE);
  memcpy(_hit2, hit2, HIT_SIZE);
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
  char cert_buf[4096];
  SSL_CTX *ctx = NULL;

  if(hc==NULL){
    cout<<"loadCfg: ERROR: HCNF not set"<<endl;
    return -1;
  }

  _hcfg = hc;

  if(_hcfg->use_smartcard){
    if(getCertFromSc(cert_buf, sizeof(cert_buf)) != 0)
      return -1;

    _scCert = cert_buf;

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

int hipCfgLdap::getLocalCertUrl(char *url, int size)
{
  int rc = 0;
  if(_localCertUrl.length()==0){
    if(_hcfg->use_smartcard){
      cout<<"fail to get local cert URL -  local cert was not posted."<<endl;
      return -1;
    }
    else 
     return 1; //OK, no local Cert to provide.
  }
  if(_localCertUrl.length()>=size){
    cout<<"getLocalCertUrl: buffer too small."<<endl;
    return -1;
  }
  strcpy(url, _localCertUrl.c_str());
  return rc;
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

int hipCfgLdap::callb(int rc, X509_STORE_CTX *ctx)
{
  int err;
  X509 *err_cert;

  err=X509_STORE_CTX_get_error(ctx);
  if(err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
    return 0;

  if (rc==1) {
     //printf("certificate certified at depth %d\n ", X509_STORE_CTX_get_error_depth(ctx));
     return 1;
   } else {
      err_cert=X509_STORE_CTX_get_current_cert(ctx);
      printf("error with certificate - error %d at depth %d\n%s\n",
              err, X509_STORE_CTX_get_error_depth(ctx), X509_verify_cert_error_string(err));
      return 0;
   }
}

int hipCfgLdap::verify_certificate(X509 *cert)
{
    int ret = 1;
    X509_STORE_CTX *ctx;

    ctx = X509_STORE_CTX_new();
    if (ctx==NULL){
      fprintf(stderr, "Error calling X509_STORE_CTX_new()\n");
      return 0;
    }
    ret = X509_STORE_CTX_init(ctx, _store, cert, NULL);
    if (ret!=1){
      fprintf(stderr, "Error calling X509_STORE_CTX_init :\n");
      X509_STORE_CTX_free(ctx);
      return 0;
    }

    ret=X509_verify_cert(ctx);
    if (ret!=1){
      fprintf(stderr, "Error verifying signature on issued certificate:\n");
      X509_STORE_CTX_free(ctx);
      return 0;
    }

    X509_STORE_CTX_free(ctx);
    return 1;
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

/*
Reads certificate from pkcs15 smartcard with same ID as private key.
Writes PEM encoded cert to file specified in outfile (if outfile != NULL),
and to the bio_info output.
returns: 0 on success, -1 on failure.
*/
int hipCfgLdap::read_sc_cert(struct sc_pkcs15_card *p15card, u8 *out_buf, int len)
{
    const char *fn_name = "read_sc_cert";

    int rc;
    struct sc_pkcs15_id id;
    struct sc_pkcs15_object *obj;
    u8 buf[2048];

    id.len = SC_PKCS15_MAX_ID_SIZE;
    sc_pkcs15_hex_string_to_id(_scPrivKeyID.c_str(), &id);
    rc = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, &obj, 1);
    if (rc < 0)
    {
    	printf("%s: get object failed: %s\n", fn_name, sc_strerror(rc));
	return -1;
    }

    struct sc_pkcs15_cert_info *cinfo = (struct sc_pkcs15_cert_info *)obj->data;
    struct sc_pkcs15_cert *cert;

    if (sc_pkcs15_compare_id(&id, &cinfo->id) != 1)
    {
    	printf("%s: Cert IDs do not match!\n", fn_name);
	return -1;
    }
    /* read cert */
    rc = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
    if (rc)
    {
    	printf("%s: Cert read failed: %s\n", fn_name, sc_strerror(rc));
	return -1;
    }

    /* convert cert to base64 format */
    rc = sc_base64_encode(cert->data, cert->data_len, buf, sizeof(buf), 64);
    if (rc < 0)
    {
    	printf("%s: Base64 encoding failed: %s\n",
		   fn_name, sc_strerror(rc));
	return -1;
    }

    if(len<(int)(sizeof(buf) + 64)){
	printf("%s: buffer too small", fn_name);
        return -1;
    }

    sprintf((char *)out_buf,"-----BEGIN CERTIFICATE-----\n"
			"%s" "-----END CERTIFICATE-----\n", buf);
    return 0;
}

/*
  verify_pin
  Verifies PIN entry for PKCS15 smartcard
  returns: 0 on success
	 -1 on card errors
	 -2 on invalid pin
	 -3 on incorrect pin
	 -4 on blocked card
*/
int hipCfgLdap::verify_pin(struct sc_pkcs15_card *p15card, const char *pincode)
{
    const char *fn_name = "verify_pin";

    struct sc_pkcs15_object *key, *pin;
    struct sc_pkcs15_id	id;
    int rc;
    char *usage_name = "signature";
    int usage = SC_PKCS15_PRKEY_USAGE_SIGN;

    if (pincode == NULL || *pincode == '\0')
    	return -2;

    printf("%s: Usage-name [hardcoded]: %s [0x%2X]\n",
    	       fn_name, usage_name, usage);
    sc_pkcs15_hex_string_to_id(_scPrivKeyID.c_str(), &id);
    rc = sc_pkcs15_find_prkey_by_id_usage(p15card, NULL, usage, &key);
    if (rc < 0)
    {
    	printf("%s: Unable to find private %s [0x%2X] key"
			   " '%s': %s\n",
			   fn_name, usage_name, usage, 
			   _scPrivKeyID.c_str(), sc_strerror(rc));
	return -1;
    }

    if (key->auth_id.len)
    {
    	rc = sc_pkcs15_find_pin_by_auth_id(p15card, &key->auth_id, &pin);
	if (rc)
	{
	    printf("%s: Unable to find PIN code for private key: %s: %s\n",
	    	       fn_name, _scPrivKeyID.c_str(), sc_strerror(rc));
	    return -1;
	}

	rc = sc_pkcs15_verify_pin(p15card, 
				  (struct sc_pkcs15_pin_info *)pin->data,
				  (const u8 *)pincode,
				  strlen(pincode));
	if (rc)
	{
	    printf("%s: PIN code verification failed: rc: %d: %s\n",
	    	       fn_name, rc, sc_strerror(rc));
	    if (rc == SC_ERROR_PIN_CODE_INCORRECT)
		return -3;
	    else if (rc == SC_ERROR_AUTH_METHOD_BLOCKED)
	    	return -4;
	    else return -1;
	}

	printf("%s: PIN code correct\n", fn_name);
    }
    return 0;
}

/*
  connect_card
  Taken from opensc/util.c
  Had to change slots[] to slot_ids[] because of QT conflict.
  returns: 0 on success, -1 on failure.
*/
int hipCfgLdap::connect_card(struct sc_context *ctx, struct sc_card **cardp,
		 int reader_id, int slot_id, int wait)
{
    const char *fn_name = "connect_card";
    sc_reader_t *reader;
    sc_card_t *card;
    int r;

    if (wait) {
	struct sc_reader *readers[16];
	int slot_ids[16];
	int i, j, k, found;
	unsigned int event;

	for (i = k = 0; i < ctx->reader_count; i++) {
	    if (reader_id >= 0 && reader_id != i)
		continue;
	    reader = ctx->reader[i];
	    for (j = 0; j < reader->slot_count; j++, k++) {
		readers[k] = reader;
		slot_ids[k] = j;
	    }
	}

	printf("%s: Waiting for card to be inserted...\n",
		   fn_name);
	r = sc_wait_for_event(readers, slot_ids, k,
			SC_EVENT_CARD_INSERTED | SC_EVENT_CARD_REMOVED,
			&found, &event, -1);
	if (r < 0) {
		printf("Error while waiting for card: %s\n",
			   sc_strerror(r));
		return -3;
	}

	reader = readers[found];
	slot_id = slot_ids[found];
    } else {
	if (reader_id < 0)
	    reader_id = 0;
	if (ctx->reader_count == 0) {
	    printf("%s: No smart card readers configured.\n",
		       fn_name);
	    return -1;
	}
	if (reader_id >= ctx->reader_count) {
	    printf("%s: Illegal reader number. "
		    "Only %d reader(s) configured.\n",
		    fn_name, ctx->reader_count);
	    return -1;
	}

	reader = ctx->reader[reader_id];
	slot_id = 0;
	if (sc_detect_card_presence(reader, 0) <= 0) {
	    printf("%s: Card not present.\n", fn_name);
	    return -3;
	}
    }

    printf("%s: Connecting to card in reader %s...\n",
    	       fn_name, reader->name);
    if ((r = sc_connect_card(reader, slot_id, &card)) < 0) {
	printf("%s: Failed to connect to card: %s\n",
		   fn_name, sc_strerror(r));
	return -1;
    }

    printf("%s: Using card driver %s.\n",
    	       fn_name, card->driver->name);

    if ((r = sc_lock(card)) < 0) {
	printf("%s: Failed to lock card: %s\n",
		   fn_name, sc_strerror(r));
	sc_disconnect_card(card, 0);
	return -1;
    }

    *cardp = card;
    return 0;
}

int hipCfgLdap::getCertFromSc(char *cert_buf, int cert_buf_size)
{
  int rc;
  struct sc_context *sc_ctx = NULL;
  struct sc_card *card = NULL;
  int reader = 0, slot = 0;
  struct sc_pkcs15_card *p15card = NULL;

  if(_hcfg->smartcard_pin==NULL)
    _scPin = "123456";
  else
    _scPin = _hcfg->smartcard_pin;
 
  _scPrivKeyID = "45"; //get it from config?
 
  rc = sc_establish_context(&sc_ctx, "tcget-headless");
  if(rc<0){
      fprintf(stderr, "Error sc_establish_context.\n");
      return -1;
  }
  rc = connect_card(sc_ctx, &card, reader, slot, 0);
  if(rc<0){
      fprintf(stderr, "Error calling connect_card.\n");
      return -1;
  }
  rc = sc_pkcs15_bind(card, &p15card);
  if(rc<0){
      fprintf(stderr, "Error sc_pkcs15_bind.\n");
      return -1;
  }
  rc = verify_pin(p15card, _scPin.c_str());
  if(rc<0){
      fprintf(stderr, "Error verify_pin.\n");
      return -1;
  }

  memset(cert_buf, '\0', cert_buf_size);
  rc = read_sc_cert(p15card, (u8 *)cert_buf, cert_buf_size);

  if(rc<0){
      fprintf(stderr, "Error read_sc_cert.\n");
      return -1;
  }

  sc_pkcs15_unbind(p15card);
  sc_unlock(card);
  sc_disconnect_card(card, 0);
  sc_release_context(sc_ctx);

  return 0;
}

int hipCfgLdap::init_ssl_context()
{
  ENGINE *e = NULL;
  SSL_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;
  
  /* Initialize OpenSC engine for OpenSSL */
    e = engine_init(_scPin.c_str());
    if (e == NULL) {
            fprintf(stderr,"Error in engine init, restarting pcsc with ssl\n");
            return -1;
    }

    /* Initialize OpenSSL context, sending PIN for smartcard */
    ctx = ssl_ctx_init(e, _scPin.c_str());
    if (ctx == NULL) {
            fprintf(stderr,"Error in ssl init, bailing...\n");
            return -1;
    }

    /* Initialize the OpenSSL connection */
    _ssl = SSL_new(ctx);
    if (_ssl == NULL) {
        fprintf(stderr,"Error open SSL connect\n");
        return -1;
    }

    pkey=SSL_get_privatekey(_ssl);
    if(pkey==NULL){
        fprintf(stderr,"Error call SSL_get_privatekey\n");
        return -1;
    }
   _rsa=EVP_PKEY_get1_RSA(pkey);
   _dsa=EVP_PKEY_get1_DSA(pkey);

  return 0;
}

unsigned char *vtou(void *a)
{
  return (unsigned char *)a;
}

int hipCfgLdap::mkHIfromSc()
{
  int rc;

  _hostid  = new hi_node();
  memset(_hostid, 0, sizeof(hi_node));
  rc = mkHIfromPkey(_rsa, _dsa, _hostid);

  //the following parameters may need to be configurate  -TBD
  _hostid->anonymous = 0;
  _hostid->allow_incoming = 1;
  _hostid->r1_gen_count = 10;
  _hostid->skip_addrcheck = TRUE;
  _hostid->r1_gen_count = 10;
  return rc;
}

int hipCfgLdap::mkHIfromPkey(RSA *rsa, DSA *dsa, hi_node *hostid)
{
  char hit_hex[INET6_ADDRSTRLEN], lsi_str[INET_ADDRSTRLEN];
  unsigned char *hitp;
  struct sockaddr_storage hit;
  struct sockaddr_in lsi;
  int bitsize = 1024;
  char basename[MAX_HI_NAMESIZE - 16];

  memset(&hit, 0, sizeof(struct sockaddr_storage));
  memset(hit_hex, 0, INET6_ADDRSTRLEN);

  if(rsa){
    hostid->algorithm_id = HI_ALG_RSA;
     bitsize = BN_num_bits(rsa->n);
  }
  else if(dsa)
    hostid->algorithm_id = HI_ALG_DSA;
  else {
     hostid->algorithm_id = 0;
     return -1;
  }

  hostid->size = bitsize/8;
  hostid->rsa = rsa;
  hostid->dsa = dsa;

  hit.ss_family = AF_INET6;
  hitp = vtou(SA2IP(&hit));
  if (hi_to_hit(hostid, hitp) < 0) {
    printf("Error generating HIT!\n");
    return -1;
  }
  
  if (addr_to_str(SA(&hit), hit_hex, INET6_ADDRSTRLEN)) {
    printf("Error generating HIT! Do you have the IPv6 protocol " "installed?\n");
    return -1;
  }

  memcpy(hostid->hit, hitp, HIT_SIZE);

  memset(&lsi, 0, sizeof(struct sockaddr_in));
  memset(lsi_str, 0, INET_ADDRSTRLEN);
  lsi.sin_family = AF_INET;
  lsi.sin_addr.s_addr = ntohl(HIT2LSI(hitp)); 
  if (addr_to_str(SA(&lsi), lsi_str, INET_ADDRSTRLEN)){
    printf("Error generating LSI from HIT!\n");
    return -1;
  }

  memcpy(&hostid->lsi, &lsi, sizeof(struct sockaddr_in));
  if (gethostname(basename, sizeof(basename)) < 0)
                sprintf(basename, "default");
  sprintf(hostid->name, "%s-%d", basename, bitsize);

  //printf("This host hit: %s, lsi: %s HI, bitsize %d\n", hit_hex, lsi_str, bitsize); 
  return 0;
}


int hipCfgLdap::hi_to_hit(hi_node *hi, hip_hit hit)
{
	int len;
	__u8 *data=NULL;
	SHA_CTX ctx;
	unsigned char hash[SHA_DIGEST_LENGTH];
	__u32 prefix;
	const unsigned char khi_context_id[16] = {
		0xf0, 0xef, 0xf0, 0x2f, 0xbf, 0xf4, 0x3d, 0x0f,
		0xe7, 0x93, 0x0c, 0x3c, 0x6e, 0x61, 0x74, 0xea
	};

	if (!hi) {
		printf("hi_to_hit(): NULL hi\n");
		return(-1);
	}


	/* calculate lengths and validate HIs */
	switch (hi->algorithm_id) {
	case HI_ALG_DSA: /* RFC 2536 */
		if (!hi->dsa) {
			printf("hi_to_hit(): NULL dsa\n");
			return(-1);
		}
		len = sizeof(khi_context_id) + 1 + DSA_PRIV + (3*hi->size);
		break;
	case HI_ALG_RSA: /* RFC 3110 */
		if (!hi->rsa) {
			printf("hi_to_hit(): NULL rsa\n");
			return(-1);
		}
		len = sizeof(khi_context_id);
		len += BN_num_bytes(hi->rsa->e) + RSA_size(hi->rsa);
		if (BN_num_bytes(hi->rsa->e) > 255)
			len += 3;
		else
			len++;
		break;
	default:
		printf("hi_to_hit(): invalid algorithm (%d)\n",
			hi->algorithm_id);
		return(-1);
	}

	/* 
	 * Prepare hash input
	 * input = context_id | input 
	 */
	data = (__u8 *)malloc(len);
	if (!data) {
		printf("hi_to_hit(): malloc(%d) error\n", len);
		return(-1);
	}
	memcpy(&data[0], khi_context_id, sizeof(khi_context_id));
	khi_hi_input(hi, &data[sizeof(khi_context_id)]);
	/* Compute the hash */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, len);
	SHA1_Final(hash, &ctx);

	/* KHI = Prefix | Encode_n( Hash)
	 */
	prefix = htonl(HIT_PREFIX_SHA1_32BITS); 
	memcpy(&hit[0], &prefix, 4); /* 28-bit prefix */
	khi_encode_n(hash, SHA_DIGEST_LENGTH, &hit[3], 100 );
						/* lower 100 bits of HIT */
	hit[3] = (HIT_PREFIX_SHA1_32BITS & 0xFF) | 
		 (hit[3] & 0x0F); /* fixup the 4th byte */
	free(data);
	return(0);
}

/* generate KHI input from HI
 */
int hipCfgLdap::khi_hi_input(hi_node *hi, __u8 *out)
{
	int location;
	__u16 e_len;

	switch (hi->algorithm_id) {
	case HI_ALG_DSA: /* RFC 2536 */
		/* Encode T, Q, P, G, Y */
		location = 0;
		out[location] = (hi->size - 64)/8;
		location++;
		bn2bin_safe(hi->dsa->q, &out[location], DSA_PRIV);
		bn2bin_safe(hi->dsa->p, &out[location + DSA_PRIV], hi->size);
		bn2bin_safe(hi->dsa->g, &out[location + DSA_PRIV + hi->size], 
			    hi->size);
		bn2bin_safe(hi->dsa->pub_key,
			    &out[location + DSA_PRIV + (2*hi->size)], 
			    hi->size);
		break;
	case HI_ALG_RSA: /* RFC 3110 */
		/* Encode e_len, exponent(e), modulus(n) */
		location = 0;
		e_len = BN_num_bytes(hi->rsa->e);
		if (e_len > 255) {
			__u16 *p =  (__u16*) &out[location+1];
			out[location] = 0x0;
			*p = htons(e_len);
			location += 3;
		} else {
			out[location] = (__u8) e_len;
			location++;
		}
		location += bn2bin_safe(hi->rsa->e, &out[location], e_len);
		location += bn2bin_safe(hi->rsa->n, &out[location],
					RSA_size(hi->rsa));
		break;
	default:
		return(-1);
	}
	return(0);
}

/*
 * function bn2bin_safe(BIGNUM *dest)
 *
 * BN_bin2bn() chops off the leading zero(es) of the BIGNUM,
 * so numbers end up being left shifted.
 * This fixes that by enforcing an expected destination length.
 */
int hipCfgLdap::bn2bin_safe(const BIGNUM *a, unsigned char *to, int len)
{
	int padlen = len - BN_num_bytes(a);
	/* add leading zeroes when needed */
	if (padlen > 0)
		memset(to, 0, padlen);
	BN_bn2bin(a, &to[padlen]);
	/* return value from BN_bn2bin() may differ from length */
	return(len);
}


/* KHI encode n-bits from bitstring
 */
int hipCfgLdap::khi_encode_n(__u8 *in, int len, __u8 *out, int n)
{
	BIGNUM *a;
	int m = ((SHA_DIGEST_LENGTH * 8) - n) / 2;
	/* 
	 * take middle n bits of a number:
	 *
	 * |-----+------------------+-----|
	 *   m=30       n=100         m=30   = 160 bits
	 */

	a = BN_bin2bn(in, len, NULL);
	BN_rshift(a, a, m); /* shift a m-bits to the right */
	BN_mask_bits(a, n); /* truncate a to an n-bit number */
	
	/* Round up one byte if indivisible by 8, since 100 bits = 12.5 bytes */
	bn2bin_safe(a, out, n/8 + (n % 8 ? 1 : 0));
	BN_free(a);

	return(0);
}

ENGINE *hipCfgLdap::engine_init(const char *pin)
{
    const char *fn_name = "engine_init";
    char opensc_engine[] = "/usr/lib/opensc/engine_opensc.so";

    ENGINE *e;
    const char *engine_id = "dynamic";
    const char *pre_cmds[] = { "SO_PATH", opensc_engine,
    			       "ID", "opensc",
			       "LIST_ADD", "1",
			       "LOAD", NULL };
    int pre_num = 4;
    char *post_cmds[] = { "PIN", "123456"};
    int post_num = 1;

    ENGINE_load_builtin_engines();

    e = ENGINE_by_id(engine_id);
    if (!e)
    {
    	printf("%s: Engine isn't available: %s\n", fn_name, engine_id);
	return NULL;
    }

    if(pin)
      post_cmds[1]=(char *)pin;

    if (!load_engine_fn(e, engine_id, pre_cmds, pre_num, (const char **)post_cmds, post_num))
    {
    	printf("engine_init failed engine id %s\n", engine_id);
	return NULL;
    }

    if (!ENGINE_set_default_RSA(e))
    {
    	printf("engine_init couldn't set RSA method - engine id : %s\n", engine_id);
	return NULL;
    }
    ENGINE_set_default_DSA(e);
    ENGINE_set_default_ciphers(e);

    printf("engine_init initialization successful - engine id %s\n", engine_id);
    return e;
}

void hipCfgLdap::engine_teardown(ENGINE *e)
{
    const char *fn_name = "engine_teardown";

    /* Release functional reference from ENGINE_init() */
    ENGINE_finish(e);

    /* Release structural reference from ENGINE_by_id() */
    ENGINE_free(e);

    /* Do Engine cleanup */
    /* The ENGINE_cleanup call was causing segfaults under certain
     * conditions.  The function is poorly documented, so I 
     * don't call it.  We are on our way out of the program anyway,
     * so system garbage collection takes over */
    printf("%s: Skipping ENGINE_cleanup() call\n", fn_name);
    ENGINE_cleanup();

    printf("%s: Engine teardown successful\n", fn_name);
}

SSL_CTX *hipCfgLdap::ssl_ctx_init(ENGINE *e, const char *pin)
{
    const char *fn_name = "ssl_ctx_init";

    char serr[120];

    SSL_CTX *ctx = NULL;
    EVP_PKEY *scPrivKey = NULL;

    /* Initialize SSL */
    SSL_library_init();
    SSL_load_error_strings();

    /* Create SSL context */
    ctx = SSL_CTX_new(SSLv3_client_method());
    if (ctx == NULL)
    {
    	printf("%s: Error creating SSL context\n", fn_name);
	return NULL;
    }

    scPrivKey =  ENGINE_load_private_key(e, "45", NULL, NULL);
    if (!scPrivKey)
    {
    	printf("%s: Error loading smartcard private key\n", fn_name);
	SSL_CTX_free(ctx);
	return NULL;
    }

    /* Load private key into SSL context */
    if (!SSL_CTX_use_PrivateKey(ctx,scPrivKey))
    {
    	printf("%s: Error loading smartcard private key into SSL context: %s\n",
		  fn_name,ERR_error_string(ERR_get_error(),serr));
	SSL_CTX_free(ctx);
	return NULL;
    }
    return ctx;
}

int hipCfgLdap::load_engine_fn(ENGINE *e, const char *engine_id,
		   const char **pre_cmds, int pre_num,
		   const char **post_cmds, int post_num)
{
    const char *fn_name = "load_engine_fn";

    /* This code is written from examples given in the manpage
       for openssl-0.9.7c engine (man 3 engine) */

    /* Process pre-initialize commands */
    while (pre_num--)
    {
    	if (!ENGINE_ctrl_cmd_string(e, pre_cmds[0], pre_cmds[1], 0))
	{
	    printf("%s: Failed pre command (%s - %s:%s)\n",
	    	      fn_name, engine_id, pre_cmds[0],
		      (pre_cmds[1] ? pre_cmds[1] : "(NULL)"));
	    ENGINE_free(e);
	    return 0;
	}
	printf("%s: Engine pre-init command (%s - %s:%s)\n",
		   fn_name, engine_id, pre_cmds[0],
		   (pre_cmds[1] ? pre_cmds[1] : "(NULL)"));
	pre_cmds += 2;
    }

    if (!ENGINE_init(e))
    {
    	printf("%s: Failed engine initialization for %s\n",
		  fn_name, engine_id);
	ENGINE_free(e);
	return 0;
    }

    /* ENGINE_init() returned a functional reference, so free the */
    /* structural reference with ENGINE_free */
    ENGINE_free(e);

    /* Process post-initialize commands */
    while (post_num--)
    {
    	if (!ENGINE_ctrl_cmd_string(e, post_cmds[0], post_cmds[1], 0))
	{
	   printf("%s: Failed post command (%s - %s:%s)\n",
	    	      fn_name, engine_id, post_cmds[0],
		      (post_cmds[1] ? post_cmds[1] : "(NULL)"));
	    /* Release the functional reference with ENGINE_finish */
	    ENGINE_finish(e);
	    return 0;
	}
	/* Don't display PIN! */
	printf("%s: Engine post-init command (%s - %s:XXXXXXXX)\n",
		   fn_name, engine_id, post_cmds[0]);
	post_cmds += 2;
    }

    ENGINE_set_default(e, ENGINE_METHOD_RSA);

    printf("%s: Engine pre and post commands successfully applied to \"%s\"\n",
    	       fn_name, engine_id);

    return 1;
}

int hipCfgLdap::getPeerNodes(struct peer_node *peerNodes, int max_count)
{
  int j;
  if(_hit_to_peers.size() > max_count){
     cout<<"getPeerNodes Error: peerNodes array too small."<<endl;
     return -1;
  } else if (_hit_to_peers.size() == 0)
    return 0;

  memset(peerNodes, 0, sizeof(struct peer_node)*_hit_to_peers.size());
  map <string, struct peer_node *>::iterator i;
  for(j=0, i=_hit_to_peers.begin(); i!=_hit_to_peers.end(); i++, j++){
    struct peer_node *p = (*i).second;
    memcpy(&peerNodes[j], p, sizeof(struct peer_node));
  }
  return j;
}
