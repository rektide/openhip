/*
 * Implementation of Hi3 receiver
 * Author: (c) Andrei Gurtov, HIIT
 * Licence: GPLv2
 * Based on a modified example from UCB i3
 * Written: 3.3.2005
*/

#include <hip/i3_hip.h>

/*
 * Called from i3 when a data packet arrives to a trigger
 * Creates msg envelop and passes the packet to HIP
 */
void receive_payload(cl_trigger *t, void* data, void *fun_ctx) {
#ifdef HI3_DEBUG
  int i;
#endif
  struct msghdr msg;
  struct iovec iov;
  cl_buf* clb = (cl_buf *) data;  

#if 0
  /* This is for the case when IP header is not tunneled through i3
     and needs to be reconstructed for interfacing with HIP at the receiver 
  */
  struct ip         *iph;
  char            buf[2000];
  hiphdr *hiph;
  int dglen;
  struct in_addr srcaddr, dstaddr;
  struct sockaddr_in src, dst;
  struct hostent *hptr;
  struct utsname myname;
  
  srcaddr.s_addr = inet_addr("128.214.112.3");
  dstaddr.s_addr = inet_addr("128.214.112.2");
  uname(&myname);
  hptr = gethostbyname(myname.nodename);
  dstaddr.s_addr = *((in_addr_t *)hptr->h_addr_list[0]);

  src.sin_addr = (struct in_addr) srcaddr;
  src.sin_family = AF_INET;
  dst.sin_addr = (struct in_addr) dstaddr;
  dst.sin_family = AF_INET;
              
  memset(buf, 0, sizeof(buf));

  printf("Received %d bytes through I3\n", clb->data_len);
  for (i=0; i < clb->data_len; i++)
    printf("%.2x ", (unsigned char)clb->data[i]);
  printf("\n");
  
  iph = (struct ip *) buf;
  hiph = (hiphdr *) ((char *)iph + sizeof(struct ip));

  memcpy((char *)iph + sizeof(struct ip), clb->data, clb->data_len);
  dglen = sizeof(struct ip) + clb->data_len;                 
  
  iph->ip_v = 4;
  iph->ip_hl = sizeof(struct ip) >> 2;
  iph->ip_tos = 0;
  iph->ip_len = htons(dglen);    /* network byte order */
  iph->ip_id = 0;                  /* let IP set this */
  iph->ip_off = 0;                 /* frag offset, MF and DF flags */
  iph->ip_ttl = 200;
  iph->ip_p = 99;
  iph->ip_src = srcaddr;
  iph->ip_dst = dstaddr;
  iph->ip_sum = in_cksum((unsigned short *)iph, sizeof (struct ip));
  
  hiph->checksum = 0;
  hiph->checksum = checksum_packet((char *)hiph, 
				   (struct sockaddr *) &src, 
				   (struct sockaddr *) &dst);
#endif

#ifdef HI3_DEBUG
  printf("Passing following packet of %d to HIP\n", clb->data_len);
  for (i=0; i < clb->data_len; i++)
    printf("%.2x ", ((unsigned char *) clb->data)[i]);
  printf("\n");
#endif      	

  //Construct message envelop as required by hip_handle_packet()
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  iov.iov_len = clb->data_len;
  iov.iov_base = clb->data;
  
  hip_handle_packet(&msg, clb->data_len, AF_INET);
}

/* 
 * Initialize i3 trigger from ascii string
 */
void init_id_fromstr(ID *id, char *name) {
  uint i;

  for (i = 0; i < ID_LEN; i++)
    id->x[i] = name[i % strlen(name)];
}

/* 
 * i3 callbacks for trigger management
 */
void constraint_failed(cl_trigger *t, void *data, void *fun_ctx) {
  printf("Trigger constraint failed\n");
}
void trigger_inserted(cl_trigger *t, void *data, void *fun_ctx) {
  printf("Trigger inserted\n");
}
void trigger_failure(cl_trigger *t, void *data, void *fun_ctx) {
  printf("Trigger failed\n");

  /* reinsert trigger */
  cl_insert_trigger(t, 0);
}

/*
 * Initialize i3, insert trigger chain for host's HIT
 */
int i3_init(hip_hit *hit) {
  struct hostent *hptr;
  struct utsname myname;
  char str[INET6_ADDRSTRLEN];
  char **pptr;
  cl_trigger *t1, *t;
  ID id, ida;
  Key key;

  if (uname(&myname) < 0) {
    err_sys("uname error.\n");
    exit(-1);
  }

  if ((hptr = gethostbyname(myname.nodename)) == NULL) {
    err_sys("gethostbyname error\n");
    exit(-1);
  }

  printf("name = %s\n", hptr->h_name);
  for (pptr = hptr->h_addr_list; *pptr != NULL; pptr++) {
    printf("address = %s\n", inet_ntop(hptr->h_addrtype, 
				       *pptr, str, sizeof(str)));
  }
 
  /* initialize context */
  cl_init(CFGFILE);

  /*
   * Create and insert triggers (id, ida), and (ida, R), respectively.
   * All triggers are r-constrained (right constrained)
   */
  bzero(&id, ID_LEN);
  memcpy(&id, hit, HIT_SIZE);
  init_id_fromstr(&ida, "this is another test id");
  cl_set_private_id(&id);
  cl_set_private_id(&ida);

  /* Note: ida will be updated as ida.key = h_r(id.key) */
  t1 = cl_create_trigger_id(&id, ID_LEN_BITS, &ida,
                            CL_TRIGGER_CFLAG_R_CONSTRAINT);
  t  = cl_create_trigger(&ida, ID_LEN_BITS, &key,
                         CL_TRIGGER_CFLAG_R_CONSTRAINT);

  /* associate callbacks with the inserted trigger */
  cl_register_trigger_callback(t, CL_CBK_TRIGGER_CONSTRAINT_FAILED,
                               constraint_failed, NULL);
  cl_register_trigger_callback(t, CL_CBK_RECEIVE_PAYLOAD,
                               receive_payload, NULL);
  cl_register_trigger_callback(t, CL_CBK_TRIGGER_INSERTED,
                               trigger_inserted, NULL);
  cl_register_trigger_callback(t, CL_CBK_TRIGGER_REFRESH_FAILED,
                               trigger_failure, NULL);

  /* insert triggers */
  cl_insert_trigger(t, 0);
  cl_insert_trigger(t1, 0);

  printf("Listening to HIT in I3: ");
  print_hit((const hip_hit*) hit);
  printf("\n");
  printf("Public trigger");
  printf_i3_id(&id, 2);
  printf("Private trigger");
  printf_i3_id(&ida, 2);

  return 0;
}

/*
 * Removes i3 triggers
 */
void clean_i3(cl_trigger *t1, cl_trigger *t) {
  /* remove & destroy trigger */
  cl_destroy_trigger(t);
  cl_destroy_trigger(t1);

  /* destroy context */
  cl_exit();
}
