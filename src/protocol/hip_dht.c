/*
 * Host Identity Protocol
 * Copyright (C) 2005-06 the Boeing Company
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
 *  hip_dht.c
 *
 *  Author:	Jeff Ahrenholz, <jeffrey.m.ahrenholz@boeing.com>
 *
 * DHT interface for publishing IP addresses using the HIT as the key.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <win32/types.h>
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#include <sys/time.h>
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>		/* INADDR_NONE                  */
#include <netinet/ip.h>		/* INADDR_NONE                  */
#include <pthread.h>		/* pthreads support		*/
#endif
#include <openssl/evp.h>
#ifndef __CYGWIN__
#ifndef __WIN32__
#include <netinet/ip6.h>
#endif
#endif
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>		/* open()			*/
#include <libxml/tree.h> 	/* XML support			*/
#ifndef __MACOSX__
#include <libxml/xmlwriter.h>
#endif
#include <hip/hip_version.h>    /* HIP_VERSION */
#include <hip/hip_types.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>

/* constants */
#define XMLRPC_MODE_GET		0x0001
#define XMLRPC_MODE_PUT		0x0002
#define XMLRPC_MODE_RETRY_OFF	0x0010
#define XMLRPC_MODE_RETRY_ON	0x0020
#define XMLRPC_APP_HIT		"hip-hit"	/* HIT lookup service */
#define XMLRPC_APP_ADDR		"hip-addr"	/* addr lookup service */

extern __u32 get_preferred_addr();

/* public functions */
int hip_dht_lookup_hit(struct sockaddr *lsi, hip_hit *hit, int retry);
int hip_dht_lookup_address(hip_hit *hit, struct sockaddr *addr, int retry);
int hip_dht_publish_addr(hip_hit *hit, struct sockaddr *addr, int retry);
int hip_dht_publish_hit(struct sockaddr *lsi, hip_hit *hit, int retry);
int hip_dht_select_server(struct sockaddr *addr);

/* local functions */
#ifdef __WIN32__
void add_addresses_from_dht_thread(void *void_hi);
void publish_my_hits_thread(sockaddr_list *l);
#else
void *add_addresses_from_dht_thread(void *void_hi);
#endif
int hip_xmlrpc_getput(int mode, char *app, struct sockaddr *server,
			char *key, int key_len,	char *value, int value_len);
int hip_xmlrpc_parse_response(int mode, char *xmldata, int len, 
			      char *value, int value_len);
xmlNodePtr xml_new_param(xmlNodePtr node_parent, char *type, char *value);
int build_http_post_header(char *buff, int content_len, struct sockaddr *addr);

/*
 * function hip_dht_lookup_hit()
 * 
 * in:		lsi  = LSI used for lookup
 * out:		hit = pointer to store HIT
 * 		Returns 0 on success, -1 on error.
 *
 * Given an LSI, lookup associated HIT using a DHT server.
 */
int hip_dht_lookup_hit(struct sockaddr *lsi, hip_hit *hit, int retry)
{
	int mode;
	struct sockaddr_storage ss_server;
	struct sockaddr *server = (struct sockaddr*)&ss_server;

	if (hip_dht_select_server(server) < 0)
		return(-1);

	/* log_(NORM, "hip_dht_lookup_hit(%s, hitp=%p, retry=%d)\n", 
		logaddr(lsi),hit,retry); // */
	/* 
	 * For the Bamboo DHT (OpenDHT), this is tied
	 * to an XML RPC "GET" call 
	 */
	mode = XMLRPC_MODE_GET;
	mode |= (retry) ? XMLRPC_MODE_RETRY_ON : XMLRPC_MODE_RETRY_OFF;
	return(hip_xmlrpc_getput(mode, XMLRPC_APP_HIT, server,
			(char *)lsi, SALEN(lsi), (char *)hit, HIT_SIZE));
}

/*
 * function hip_dht_lookup_address()
 * 
 * in:		hit  = pointer to HIT for use with the lookup
 * out:		addr = pointer to sockaddr_storage
 * 		Returns 0 on success, -1 on error.
 *
 * Given a HIT, lookup an address using a DHT server.
 */
int hip_dht_lookup_address(hip_hit *hit, struct sockaddr *addr, int retry)
{
	int mode, err;
	struct sockaddr_storage ss_server;
	struct sockaddr *server = (struct sockaddr*)&ss_server;

	if (hip_dht_select_server(server) < 0)
		return(-1);
	
	/* 
	 * For the Bamboo DHT (OpenDHT), this is tied
	 * to an XML RPC "GET" call 
	 */
	mode = XMLRPC_MODE_GET;
	mode |= (retry) ? XMLRPC_MODE_RETRY_ON : XMLRPC_MODE_RETRY_OFF;
	err = hip_xmlrpc_getput(mode, XMLRPC_APP_ADDR, server,
			(char *)hit, HIT_SIZE, (char *)addr, SALEN(addr));
	if (!VALID_FAM(addr)) /* check that an address was returned */
		return(-1);
	return(err);
}

/*
 * function hip_dht_publish_hit()
 * 
 * in:		lsi  = LSI to use as the DHT key
 * 		hit  = HIT to use for the DHT value
 * out:		Returns 0 on success, -1 on error.
 *
 * Store this LSI and HIT on the DHT server.
 */
int hip_dht_publish_hit(struct sockaddr *lsi, hip_hit *hit, int retry)
{
	int mode;
	struct sockaddr_storage ss_server;
	struct sockaddr *server = (struct sockaddr*)&ss_server;

	if (hip_dht_select_server(server) < 0)
		return(-1);

	/* log_(NORM, "hip_dht_publish_hit(%s, hitp=%p, retry=%d)\n", 
		logaddr(lsi),hit,retry); // */
	/* 
	 * For the Bamboo DHT (OpenDHT), this is tied
	 * to an XML RPC "PUT" call 
	 */
	mode = XMLRPC_MODE_PUT;
	mode |= (retry) ? XMLRPC_MODE_RETRY_ON : XMLRPC_MODE_RETRY_OFF;
	return(hip_xmlrpc_getput(mode, XMLRPC_APP_HIT, server,
			(char *)lsi, SALEN(lsi), (char *)hit, HIT_SIZE));
}

/*
 * function hip_dht_publish_addr()
 * 
 * in:		hit  = HIT to use as the DHT key
 * 		addr = address to use for the DHT value
 * out:		Returns 0 on success, -1 on error.
 *
 * Store this HIT and address on the DHT server.
 */
int hip_dht_publish_addr(hip_hit *hit, struct sockaddr *addr, int retry)
{
	int mode;
	struct sockaddr_storage ss_server;
	struct sockaddr *server = (struct sockaddr*)&ss_server;

	if (hip_dht_select_server(server) < 0)
		return(-1);

	/* 
	 * For the Bamboo DHT (OpenDHT), this is tied
	 * to an XML RPC "PUT" call 
	 */
	mode = XMLRPC_MODE_PUT;
	mode |= (retry) ? XMLRPC_MODE_RETRY_ON : XMLRPC_MODE_RETRY_OFF;
	return(hip_xmlrpc_getput(mode, XMLRPC_APP_ADDR, server,
			(char *)hit, HIT_SIZE, (char *)addr, SALEN(addr)));
}

/*
 * function hip_dht_select_server()
 * 
 * out:		addr = pointer to store address of the server
 * 		Returns 0 on success, -1 on error.
 *
 * Select the address of the DHT server to use.
 */
int hip_dht_select_server(struct sockaddr *addr)
{
	/*
	 * we leave room for more complex server selection schemes here
	 *
	 * for now, a single server+port is specified via the conf file
	 *
	 */
	if (VALID_FAM(&HCNF.dht_server)) {
		memcpy(addr, &HCNF.dht_server, SALEN(&HCNF.dht_server));
		return(0);
	}
	return(-1);
}

/*******************************************************************************
 * Below are HIP helper functions that are DHT releated
 * 
 ******************************************************************************/

/*
 * function add_addresses_from_dht()
 *
 * in:		hi = contains HIT for lookup, hi->addrs for storing result
 * 		retry = if TRUE, will fork and allow hip_dht_lookup_address()
 * 		        to retry multiple times
 * Given a Host Identity, perform a DHT lookup using its HIT and store any
 * resulting address in the hi_node.
 */
int add_addresses_from_dht(hi_node *hi, int retry)
{
	int err;
	struct sockaddr_storage ss_addr;
	struct sockaddr *addr = (struct sockaddr*) &ss_addr;
#ifndef __WIN32__
	pthread_attr_t attr;
	pthread_t thr;
#endif

	/* When retry is turned on, a separate thread will be forked that
	 * will perform the DHT lookup(s), retry a certain number of times,
	 * and exit */
	if (retry) {
#ifdef __WIN32__
		_beginthread(add_addresses_from_dht_thread, 0, (void *)hi);
#else
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&thr, &attr, add_addresses_from_dht_thread, hi);
#endif
		return(0);
	}

	/* If there is no HIT configured, first use DHT
	 * to find it using the LSI */
	if (hits_equal(hi->hit, zero_hit)) {
		log_(NORM, "HIT not present for %s, performing lookup.\n",
			logaddr(SA(&hi->lsi)));
		if ((err = hip_dht_lookup_hit(	SA(&hi->lsi), 
						&hi->hit, retry)) < 0) {
			/* no HIT from LSI, so we cannot do address lookup */
			log_(WARN, "Unable to find HIT for %s in the DHT.\n",
				logaddr(SA(&hi->lsi)));
			return(err);
		/*} else {
			log_(NORM, "DHT err=%d HIT=", err);
			print_hex(hi->hit, HIT_SIZE);
			log_(NORM, "\n");*/
		}
	}
	
	/* lookup current IP address using HIT */
	addr->sa_family = AF_INET;
	if ((err = hip_dht_lookup_address(&hi->hit, addr, retry)) < 0) {
		if (retry)
			exit(0);
		else
			return(err);
	/*} else {
		log_(NORM, "DHT err=%d ADDR=%s\n", err, logaddr(addr));
	*/
	}

	/* assume since we are here, there are no addresses in
	 * the XML file, nor in DNS, and the addrlist is empty */
	pthread_mutex_lock(&hi->addrs_mutex);
	memset(&hi->addrs, 0, sizeof(sockaddr_list));
	memcpy(&hi->addrs.addr, addr, SALEN(addr));
	pthread_mutex_unlock(&hi->addrs_mutex);
	/* in the future, may want to retrieve multiple 
	 * addresses, and use add_address_to_list() 
	 */

	return(0);
}

#ifdef __WIN32__
void add_addresses_from_dht_thread(void *void_hi)
#else
void *add_addresses_from_dht_thread(void *void_hi)
#endif
{
	hi_node *hi = (hi_node*)void_hi;
	int err;
	struct sockaddr_storage ss_addr;
	struct sockaddr *addr = (struct sockaddr*) &ss_addr;

	/* If there is no HIT configured, first use DHT
	 * to find it using the LSI*/
	if (hits_equal(hi->hit, zero_hit)) {
		log_(NORM, "HIT not present for %s, performing lookup.\n",
			logaddr(SA(&hi->lsi)));
		if ((err = hip_dht_lookup_hit(	SA(&hi->lsi), 
						&hi->hit, TRUE)) < 0) {
			/* no HIT from LSI, so we cannot do address lookup */
			log_(WARN, "Unable to find HIT for %s in the DHT.\n",
				logaddr(SA(&hi->lsi)));
			goto add_addresses_from_dht_thread_exit;
		/*} else {
			log_(NORM, "DHT err=%d HIT=", err);
			print_hex(hi->hit, HIT_SIZE);
			log_(NORM, "\n");*/
		}
	}
	
	/* lookup current IP address using HIT */
	addr->sa_family = AF_INET;
	if ((err = hip_dht_lookup_address(&hi->hit, addr, TRUE)) < 0) {
		goto add_addresses_from_dht_thread_exit;
	/*} else {
		log_(NORM, "DHT err=%d ADDR=%s\n", err, logaddr(addr));
	*/
	}

	/* assume since we are here, there are no addresses in
	 * the XML file, nor in DNS, and the addrlist is empty */
	pthread_mutex_lock(&hi->addrs_mutex);
	memset(&hi->addrs, 0, sizeof(sockaddr_list));
	memcpy(&hi->addrs.addr, addr, SALEN(addr));
	pthread_mutex_unlock(&hi->addrs_mutex);
	/* in the future, may want to retrieve multiple 
	 * addresses, and use add_address_to_list() 
	 */

add_addresses_from_dht_thread_exit:
#ifdef __WIN32__
	return;
#else
	return(NULL);
#endif
}

/*
 * function publish_my_hits()
 *
 * Publish (HIT, IP) and (LSI, HIT) combinations to a DHT,
 * to support both type of lookups.
 */
void publish_my_hits()
{
	sockaddr_list *l;
#ifndef __WIN32__
	hi_node *hi;
#endif

#ifdef SMA_CRAWLER
        struct sockaddr_storage ss_server;
        struct sockaddr *server = (struct sockaddr*)&ss_server;

        if (hip_dht_select_server(server) < 0)
               return;
#endif

	/* for now, only publish our preferred address */
	for (l = my_addr_head; l; l=l->next) {
		if (IS_LSI(&l->addr)) /* skip any LSIs */
			continue;
		if (l->preferred)
			break;
	}
	if (!l)
		return;

	/* parent process returns */
#ifdef __WIN32__
	_beginthread(publish_my_hits_thread, 0, l);
	return;
}

void publish_my_hits_thread(sockaddr_list *l) {
	hi_node *hi;
#else
	if (fork() != 0)
		return;
#endif

	/* send a publish request for each configured HIT */	
	for (hi = my_hi_head; hi; hi=hi->next) {
		/* since retry is on, if there is an error returned 
		 * we will give up trying */
		if (hip_dht_publish_addr(&hi->hit, 
					 (struct sockaddr*) &l->addr, TRUE) < 0)
			break;
		if (hip_dht_publish_hit((struct sockaddr*)&hi->lsi, 
					&hi->hit, TRUE) < 0)
			break;
	}
#ifndef __WIN32__
	_exit(0);
#endif
}

/*******************************************************************************
 * Below are functions specific to different DHT implementations.
 * 
 *
 ******************************************************************************/

/*
 * function hip_xmlrpc_getput()
 *
 * in:		mode   = determines get or put, app, retry on/off
 * 		         If retry is off only one attempt should be made,
 * 			 on means the connect() should keep retrying
 * 		server = server address and port
 * 		hit    = HIT used as key for get or put
 * 		addr   = address to publish for PUTs, storage for GETs
 * 
 * Since XML RPC GET and PUT for the Bamboo DHT are so similar, both are
 * handled in the same function below.
 */
int hip_xmlrpc_getput(int mode, char *app, struct sockaddr *server,
			char *key, int key_len,	char *value, int value_len)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root_node = NULL, node;
	int len=0, s, retval=0;
	char buff[2048];
	unsigned char key64[30], val64[30], tmp[32], *xmlbuff=NULL;
	fd_set read_fdset;
	struct timeval timeout;
	char *p;
	unsigned int retry_attempts = 0;
	struct sockaddr_in src_addr;

	int retry = ((mode & 0x00F0) == XMLRPC_MODE_RETRY_ON);

	/* 
	 * create a new XML document 
	 */
	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "methodCall");
	xmlDocSetRootElement(doc, root_node);
	node = xmlNewChild(root_node, NULL, BAD_CAST "methodName", 
		 BAD_CAST(((mode & 0x000F) == XMLRPC_MODE_PUT) ? "put": "get"));
	node = xmlNewChild(root_node, NULL, BAD_CAST "params", NULL);
	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, key, key_len);
	EVP_EncodeBlock(key64, tmp, key_len);
	xml_new_param(node, "base64", (char *)key64);		/* key */
	/* log_(NORM, "Doing %s using key(%d)=", 
	     ((mode & 0x000F)==XMLRPC_MODE_PUT) ? "PUT":"GET", key_len);
	   print_hex(key, key_len);
	   log_(NORM, " [%s]\n", base64); // */
	if ((mode & 0x000F) == XMLRPC_MODE_PUT) {
		memcpy(tmp, value, value_len);
		EVP_EncodeBlock(val64, tmp, value_len);
		xml_new_param(node, "base64", (char *)val64);	/* value */
		xml_new_param(node, "int", "604800");	/* lifetime */
		/*log_(NORM, "value(%d)=", value_len);
		  print_hex(value, value_len);
		  log_(NORM, " [%s]\n", base64); // */
	} else if ((mode & 0x000F) == XMLRPC_MODE_GET) {
		/* additional GET parameters */
		xml_new_param(node, "int", "10");	/* maxvals */
		xml_new_param(node, "base64", "");	/* placemark */
		memset(value, 0, value_len);
	}
	xml_new_param(node, "string", app);		/* app */
	xmlDocDumpFormatMemory(doc, &xmlbuff, &len, 0);
	
	/*
	 * Build an HTTP POST and transmit to server
	 */
	memset(buff, 0, sizeof(buff));
	build_http_post_header(buff, len, server); /* len is XML length above */
	memcpy(&buff[strlen(buff)], xmlbuff, len);
	xmlFree(xmlbuff);
	len = strlen(buff) + 1;
connect_retry:
	/* Connect and send the XML RPC */	
	if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log_(WARN, "DHT connect - socket error: %s\n", strerror(errno));
		retval = -1;
		goto putget_exit;
	}
	/* Use the preferred address as source */
	memset(&src_addr, 0, sizeof(src_addr)); 
	src_addr.sin_family = AF_INET;
	src_addr.sin_addr.s_addr = get_preferred_addr();
	if (!src_addr.sin_addr.s_addr) {
		log_(NORM, "No preferred address, deferring DHT!\n");
		return(-1);
	}
	log_(NORM, "Using source address of %s for DHT lookup.\n", 
		logaddr(SA(&src_addr)));
	fflush(stdout);
	if (bind(s, SA(&src_addr), SALEN(&src_addr)) < 0) {
		log_(WARN, "DHT connect - bind error: %s\n", strerror(errno));
	}

#ifdef __UMH__
	if (g_state != 0)
		return -1;
#endif
	if (retry && (retry_attempts > 0)) {
		/* quit after a certain number of retries */
		if (retry_attempts >= HCNF.max_retries) {
			retval = -2;
			goto putget_exit;
		}
		/* wait packet_timeout seconds before retrying */
		hip_sleep(HCNF.packet_timeout);
	}
	retry_attempts++;

	if (connect(s, server, SALEN(server)) < 0) {
		log_(WARN, "DHT server connect error: %s\n", strerror(errno));
#ifdef __WIN32__
		closesocket(s);
#else
		close(s);
#endif
#ifdef __WIN32__
		errno = WSAGetLastError();
		if (retry && ((errno == WSAETIMEDOUT) || 
			      (errno == WSAENETUNREACH)))
			goto connect_retry;
#else
		if (retry && ((errno == ETIMEDOUT) || (errno == EHOSTUNREACH)))
			goto connect_retry;
#endif
		retval = -3;
		goto putget_exit;
	}

	if (send(s, buff, len, 0) != len) {
		log_(WARN, "DHT sent incorrect number of bytes\n");
		retval = -4;
		goto putget_exit;
	}
	xmlFreeDoc(doc);
	doc = NULL;

	/*
	 * Receive XML RPC response from server
	 */
	FD_ZERO(&read_fdset);
	FD_SET((unsigned int)s, &read_fdset);
	/* use longer timeout when retry==TRUE, because we have own thread */
	if (retry) {
		timeout.tv_sec = 3;
		timeout.tv_usec = 0;
	} else {
		timeout.tv_sec = 0;
		timeout.tv_usec = 300000; /* 300ms */
	}
	if (select(s+1, &read_fdset, NULL, NULL, &timeout) < 0) {
		log_(WARN, "DHT select error: %s\n", strerror(errno));
		retval = -5;
		goto putget_exit;
	} else if (FD_ISSET(s, &read_fdset)) {
		if ((len = recv(s, buff, sizeof(buff)-1, 0)) <= 0) {
			log_(WARN, "DHT error receiving from server: %s\n",
				strerror(errno));
			retval = -6;
			goto putget_exit;
		}
		if (strncmp(buff, "HTTP", 4) != 0)
			return(-7);
		if ((p = strstr(buff, "Content-Length: ")) == NULL)
			return(-8);
		else /* advance ptr to Content-Length */
			p += 16;
		sscanf(p, "%d", &len);
		p = strchr(p, '\n') + 3; /* advance to end of line */
		retval = hip_xmlrpc_parse_response(mode, p, len,
						   value, value_len);
	} else {
		/* select timeout */
		if (retry) /* XXX testme: retry select instead? */
			goto connect_retry;
		retval = -9;
	}

putget_exit:
#ifdef __WIN32__
	closesocket(s);
#else
	close(s);
#endif
	if (doc != NULL) xmlFreeDoc(doc);
	return(retval);
}

/*
 * function xml_new_param()
 *
 * insert a value embedded in XML in the format
 *  <param><value><type>value</type></value></param>
 */
xmlNodePtr xml_new_param(xmlNodePtr node_parent, char *type, char *value)
{
	xmlNodePtr node_param, node_value;
	node_param = xmlNewChild(node_parent, NULL, BAD_CAST "param", NULL);
	node_value = xmlNewChild(node_param, NULL, BAD_CAST "value", NULL);
	return(xmlNewChild(node_value, NULL, BAD_CAST type, BAD_CAST value)); 
}

/*
 * function  build_http_post_header()
 */
int build_http_post_header(char *buff, int content_len, struct sockaddr *addr)
{
	unsigned short port = 0;
	char addrstr[INET6_ADDRSTRLEN];

	addr_to_str(addr, (__u8*)addrstr, INET6_ADDRSTRLEN);
	if (AF_INET == addr->sa_family)
		port = ntohs(((struct sockaddr_in*)addr)->sin_port);
	else if (AF_INET6 == addr->sa_family)
		port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
	
        sprintf(buff, "POST /RPC2 HTTP/1.0\r\nUser-Agent: %s %s\r\nHost: %s:%d\r\nContent-Type: text/xml\r\nContent-length: %d\r\n\r\n",
                HIP_NAME, HIP_VERSION, addrstr, port, content_len);
	return(strlen(buff));
}

/*
 * function hip_xmlrpc_parse_response()
 *
 * in:		mode = is this an XML RPC GET/PUT? store response in hit/addr?
 * 		xmldata = pointer to XML character data
 * 		len = length of data
 * 
 * out:		For GETs, the address or HIT is returned in addr or hit, 
 * 		and 0 is returned for success.
 * 		For PUTs, the XML RPC return code is returned,
 * 		which is 0 for success, or 1 or 2. -1 is returned on error.
 */
int hip_xmlrpc_parse_response(int mode, char *xmldata, int len, 
			      char *value, int value_len)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node, node_val;
	int retval=-10;
	xmlChar *data;
	
	/*
	printf("Got the response (content-length=%d):\n", len);
	printf(xmldata);
	printf("\n");
	// */
	if ((doc = xmlParseMemory(xmldata, len)) == NULL)
		goto parse_response_exit;
	node = xmlDocGetRootElement(doc); 		/* <methodResponse> */
	if (node->children) node = node->children;	/* <params> */
	node = node->children;
	if (!node)					/* <param> */
		goto parse_response_exit;
	node_val = NULL;
	if (!strcmp((char *)node->name, "param") && node->children &&
	    !strcmp((char *)node->children->name, "value"))
		node_val = node->children->children;
	if (!node_val)
		goto parse_response_exit;
	
	if ((mode & 0x000F) == XMLRPC_MODE_PUT) {/* retrieve status code only */
		data = xmlNodeGetContent(node_val);
		/* status code is first int that we encounter */
		if (strcmp((char *)node_val->name, "int")==0) {
			sscanf((const char *)data, "%d", &retval);
			xmlFree(data);
			goto parse_response_exit;
		}
	} else {				 /* retrieve address or HIT */
		/* <?xml version="1.0" encoding="ISO-8859-1"?>
		 *   <methodResponse>
		 *     <params><param><value><array><data>
		 *        <value><array><data>
		 *           <value><base64>AgAAAMCoAQAAAAAAA==</base64></value>
		 *           <value><base64>AgAAAMCoAgcAAAAAA==</base64></value>
		 *        </data></array></value>
		 *        <value><base64></base64></value>
		 *     </data></array></value></param></params>
		 *   </methodResponse>
		 */
		if (!strcmp((char *)node_val->name, "array") && 
		    node_val->children &&
		    !strcmp((char *)node_val->children->name, "data"))
			node = node_val->children->children;
		
		if (!strcmp((char *)node->name, "value") && node->children &&
		    !strcmp((char *)node->children->name, "array"))
			node = node->children->children; /* <data> */

		/* step through array of responses */
		for (node = node->children; node; node = node->next) {
			node_val = node->children; /* <value><base64> */
			if ((!node_val) || 
			    (strcmp((char *)node_val->name, "base64")))
				continue;
			data = xmlNodeGetContent(node_val);
			/* protect against unusually large values */
			if (strlen((char *)data) > 
				   ((unsigned)(((value_len+2)/3) *4)+1)) {
				xmlFree(data);
				continue;
			}
			/* decode base64 into value pointer */
			EVP_DecodeBlock((unsigned char *)value, 
					data, strlen((char *)data));
			retval = 0;
			xmlFree(data);
			/* the last value encountered will be returned */
		} /* end for */
		/* placemark and other tags are ignored */
	}
	
parse_response_exit:
	if (doc != NULL) xmlFreeDoc(doc);
	return(retval);
}

/* Testing code -- compile with:
 * gcc -g -Wall -o hip_dht hip_dht.c hip_globals.o hip_util.o -lcrypto -L/usr/lib -lxml2 -lz -liconv -lm -I/usr/include/libxml2 -DTEST_XMLRPC
 */
#ifdef TEST_XMLRPC
sockaddr_list *add_address_to_list(sockaddr_list **list, struct sockaddr *addr,
    int ifi) { return NULL; }

void delete_address_from_list(sockaddr_list **list, struct sockaddr *addr, 
	int ifi)
{ return; }
void unuse_dh_entry(DH *dh) { return; }
int flush_hip_associations() { return 0;}
int g_state;

int main(int argc, char **argv)
{
	int err, publish;
	hip_hit hit;
	struct sockaddr_storage addr;
	struct sockaddr_in *addr4 = (struct sockaddr_in*)&addr;

	memset(&addr, 0, sizeof(addr));
	addr4->sin_family = AF_INET;
	addr4->sin_addr.s_addr = inet_addr("192.168.1.2");
	hex_to_bin("7BE901B3AF2679C8C580619535641713", hit, HIT_SIZE);
	
	printf("Doing XML RPC put 1...\n");
	err = hip_dht_publish(&hit, (struct sockaddr*)&addr);
	printf("return value = %d\n", err);
	
	addr4->sin_addr.s_addr = inet_addr("192.168.2.7");
	
	printf("Doing XML RPC put 2...\n");
	err = hip_dht_publish(&hit, (struct sockaddr*)&addr);
	printf("return value = %d\n", err);

	
	addr4->sin_addr.s_addr = 0;
	memset(&addr, 0, sizeof(addr));
	addr4->sin_family = AF_INET;

	printf("addr is at: %p\n", &addr);
	printf("Doing XML RPC get...\n");
	err = hip_dht_lookup_address(&hit, (struct sockaddr*)&addr);
	printf("return value = %d\n", err);
	printf("Address = %s\n", logaddr((struct sockaddr*)&addr));
	return(0);
}
#endif /* TEST_XMLRPC */

