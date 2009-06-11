#ifndef _HIPCFGAPI_H_
#define _HIPCFGAPI_H_
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <hip/hip_types.h>

/* Input: the name of the dynamic link library
 *    e.g. the xml file based library "libhipcfg.so"
 *   Return: 0 if succeed, non-zero if error.
 */
#define hipcfg_init_fn "hipcfg_init"
extern int (*hipcfg_init_p)(struct hip_conf *hc);
extern int hipcfg_init(char *dlname, struct hip_conf *hc);


/* Input: the two peer hosts identified by their HITs
 * Return: 1 if a HIP base exchange is allowed between the peers.
 *         0 otherwise.
 */
#define hipcfg_allowed_peers_fn "hipcfg_allowed_peers"
extern int (*hipcfg_allowed_peers_p)(const hip_hit hit1, const hip_hit hit2);
extern int hipcfg_allowed_peers(const hip_hit hit1, const hip_hit hit2);


/* Get all pairs of peers allowed to comunicate with each other
 * Return: the number of hit pairs returned if succeed
 *         0 if no such hit pair
 *         -1 if error.
 * Note: hits1 and hits2 are arrays with the at least max_cnt size, and have pre-alloced
 *       when calling this function.
 */
#define hipcfg_peers_allowed_fn "hipcfg_peers_allowed"
extern int (*hipcfg_peers_allowed_p)(hip_hit *hits1, hip_hit *hits2, int max_cnt);
extern int hipcfg_peers_allowed(hip_hit *hits1, hip_hit *hits2, int max_cnt);


/* Input: host - the legacy host IPv4/IPv6 address
 *               the sockaddr should point to a sockaddr_storage structure so that
 *               either an IPv4 or IPv6 address can be passed in. The sa_family must
 *               be set to AF_INET for an IPv4 address, or AF_INET6 for an IPv6 address.
 * Output: eb - the endbox's LSI/HIT. sockaddr should point to a sockaddr_storage
 *              structure so that either an IPv4 or IPv6 address can be returned.
 *              When the call is returned, the sa_family is set to AF_INET if 
 *              sockaddr_storage contains an IPv4 address, or AF_INET6 if it
 *              contains an IPv6 address.
 * Return: 0 if the mapping found, a positive number if not found, -1 if error.
 *
 * Note: the old function is find_endbox2() which
 *       looking up file host_map.
 */
#define hipcfg_getEndboxByLegacyNode_fn "hipcfg_getEndboxByLegacyNode"
extern int (*hipcfg_getEndboxByLegacyNode_p)(const struct sockaddr *host, struct sockaddr *eb);
extern int hipcfg_getEndboxByLegacyNode(const struct sockaddr *host, struct sockaddr *eb);

/* Input: eb - endbox address either in IPv4 (LSI) or IPv6 (HIT)
 *             The sa_family must be set to ether  AF_INET or AF_INET6
 *             before calling this function.
 * Output: llip -  lower layer IP address (e.g. BCWIN) in eihter IPv4/v6.
 *             sa_family will be set to either AF_INET or AF_INET6 after successfully
 *             calling this function per its actual IP address family.
 * Return: 0 - if the lookup succeeed, 1 - if the mapping is not found, -1 if error.
 */
#define hipcfg_getLlipByEndbox_fn "hipcfg_getLlipByEndbox"
extern int (*hipcfg_getLlipByEndbox_p)(const struct sockaddr *eb, struct sockaddr *llip);
extern int hipcfg_getLlipByEndbox(const struct sockaddr *eb, struct sockaddr *llip);

/* Input eb - endbox address either in IPv4 (LSI) or IPv6 (HIT)
 * 	      The sa_family must be set to ether  AF_INET or AF_INET6
 *            before calling this function.
 * Output hosts - an array of legacy nodes. sa_family of each element
 *                will be set to either AF_INET or AF_INET6 per its actual IP address family
 *                The caller must provide the storage for the  array.
 *        size - the size of array hosts (maximum number of elements can be returned).
 * Return -1 if error,  0 if cannot find a match, a positivie number for the actual elements in hosts.
 */
#define hipcfg_getLegacyNodesByEndbox_fn "hipcfg_getLegacyNodesByEndbox"
extern int (*hipcfg_getLegacyNodesByEndbox_p)(const struct sockaddr *eb, struct sockaddr_storage *hosts, int size);
extern int hipcfg_getLegacyNodesByEndbox(const struct sockaddr *eb, struct sockaddr_storage *hosts, int size);

/* obtain the certificate that hold host identity (public key) in PEM format indexed by hit
 * that is derived from the public key
 * Input: hit - the hit in IPv6 notation string
 *        size - the buffer size
 *
 * Output: cert - a buffer that will hold certificate in PEM format
 * Return -1 if error,  0 if succeeded
 */
#define hipcfg_verifyCert_fn "hipcfg_verifyCert"
extern int (*hipcfg_verifyCert_p)(const char *url, const hip_hit hit1);
extern int hipcfg_verifyCert(const char *url, const hip_hit hit1);

/* obtain the local certificate URL which is null terminated string 
 *
 * Output: url - a buffer that will hold url certificate URL
 * Input:  size - the buffer size
 * Return -1 if error,  0 if succeeded
 */
#define hipcfg_getLocalCertUrl_fn "hipcfg_getLocalCertUrl"
extern int (*hipcfg_getLocalCertUrl_p)(char *url, int size);
extern int hipcfg_getLocalCertUrl(char *url, int size);

/* Post the certificate that holds host identity (public key) in PEM format indexed by hit
 * that is derived from the public key
 * Input: hit - the hit in IPv6 notation string
 *        cert - a null terminated certificate in PEM format
 * Return -1 if error,  0 if succeeded.
 */
#define hipcfg_postLocalCert_fn "hipcfg_postLocalCert"
extern int (*hipcfg_postLocalCert_p)(const char *hit);
extern int hipcfg_postLocalCert(const char *hit);

/* return a pointer to the local host identity struct */
#define hipcfg_getMyHostId_fn "hipcfg_getMyHostId"
extern hi_node *(*hipcfg_getMyHostId_p)();
extern hi_node *hipcfg_getMyHostId();

/* Get an array of configured known host peers.
   return a positive number indicating the number of actual entries.
          0 if there is no entries
         -1 if error
   Input:
        peerNodes: an array of peer_node which will hold the configured peers
		   the memory must have been allocated before calling the function.
        max_count: the size of the peerNodes array
        
*/

#define hipcfg_getPeerNodes_fn "hipcfg_getPeerNodes"
extern int (*hipcfg_getPeerNodes_p)(struct peer_node *peerNodes, int max_count);
extern int hipcfg_getPeerNodes(struct peer_node *peerNodes, int max_count);

#endif
