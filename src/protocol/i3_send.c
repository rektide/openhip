/*
 * Copyright (C) 2005 Andrei Gurtov
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
 *  Authors:    Andrei Gurtov, HIIT
 *  Written: 10.2.2005
 *
 * \brief Implementation of Hi3 sender
 * Based on a modified example from UCB i3
 */

#include <hip/i3_hip.h>

/*
 * Prints out HIT for debugging
 */
void print_hit(const hip_hit *hit) {
  int i;
  unsigned char *c;
  
  c = (unsigned char*) hit;
  printf("0x");
  for (i=0; i < HIT_SIZE; i++) {
    printf("%.2x", c[i]);
  }
}

/*
 * Create i3 trigger id from ascii hex string
 */
void read_id(ID *id, char *hstr) {
  int i;
  char h[3];
  int  dummy;

  for (i = 0; i < ID_LEN; i++) {
    /* covert from string into hexa number */
    h[0] = hstr[2*i];
    h[1] = hstr[2*i + 1];
    h[2] = 0;
    sscanf(h, "%x", &dummy);
    id->x[i] = dummy;
  }
}

/*
 * Calculate checksum for IP header, example from Stevens
 */
unsigned short in_cksum(unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }
  
  /* 4mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w ;
    sum += answer;
  }
  
  /* 4add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);			/* add carry */
  answer = ~sum;				/* truncate to 16 bits */
  return(answer);
}

/*
 * Callback for i3 
 */
void no_matching_trigger(void *ctx_data, void *data, void *fun_ctx) {
  ID *id = (ID *) ctx_data;

  printf("Following ID not found, ");
  printf_i3_id(id, 0);
}

/*
* Send a packet to i3 assuming the responder's hit is inserted as a trigger 
*/
int send_i3(__u8 *data, int size, hip_hit *hit, struct sockaddr* src, 
	    struct sockaddr* dst) {
  ID id;
  cl_buf  *clb;
  struct ip *iph;
  int dglen;
#ifdef HI3_DEBUG
  int i;
#endif

  dglen = size + sizeof(struct ip);
  clb = cl_alloc_buf(dglen);
  
  iph = (struct ip *) clb->data;
  memcpy((char *)iph + sizeof(struct ip), data, size);
 
  /* create IP header for tunneling HIP packet through i3 */                   
  iph->ip_v = 4;
  iph->ip_hl = sizeof(struct ip) >> 2;
  iph->ip_tos = 0;
  iph->ip_len = htons(dglen);    /* network byte order */
  iph->ip_id = 0;                  /* let IP set this */
  iph->ip_off = 0;                 /* frag offset, MF and DF flags */
  iph->ip_ttl = 200;
  iph->ip_p = 99;
  iph->ip_src = ((struct sockaddr_in *)src)->sin_addr;
  iph->ip_dst = ((struct sockaddr_in *)dst)->sin_addr;
  iph->ip_sum = in_cksum((unsigned short *)iph, sizeof (struct ip));
    
  clb->data_len = dglen;

  bzero(&id, ID_LEN);
  memcpy(&id, hit, HIT_SIZE);
  cl_set_private_id(&id);

  /* exception when matching trigger not found */
  cl_register_callback(CL_CBK_TRIGGER_NOT_FOUND, no_matching_trigger, NULL);

  printf("Responder's HIT for I3: ");
  print_hit((const hip_hit*) hit);
  printf("\n");
  printf_i3_id(&id, 2);

#ifdef HI3_DEBUG
  printf("Passing following packet of %d to i3\n", clb->data_len);
  for (i=0; i < clb->data_len; i++)
    printf("%.2x ", ((unsigned char *) clb->data)[i]);
  printf("\n");
#endif
  
  cl_send(&id, clb, 0);  
  cl_free_buf(clb);
  
  return size;
}
