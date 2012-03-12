#ifndef _ENDBOX_UTILS_H_
#define _ENDBOX_UTILS_H_

void endbox_init();
void endbox_send_hello(void);
void endbox_hello_check(__u8 *buffer);
void endbox_check_hello_time(time_t *now_time);
void endbox_ipv4_multicast_write(__u8 *data, int offset, int len);
void endbox_periodic_heartbeat(time_t *now_time,
                               time_t *last_time,
                               int *packet_count,
                               char *name,
                               int touchHeartbeat);
int endbox_ipv4_packet_check(struct ip *iph, struct sockaddr *lsi,
                             int *packet_count);
int endbox_arp_packet_check(struct arp_hdr *arph, struct sockaddr *lsi,
                            int *packet_count);
int endbox_check_cert(struct sockaddr *lsi);

#endif /* _ENDBOX_UTILS_H_ */
