/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2002-2012 the Boeing Company
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *  \file  hip_main.c
 *
 *  \authors Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *           Tom Henderson <thomas.r.henderson@boeing.com>
 *
 *  \brief  Main program for HIP daemon.
 *
 */
#include <stdio.h>           /* stderr, etc                  */
#include <stdlib.h>          /* rand()                       */
#include <errno.h>           /* strerror(), errno            */
#include <string.h>          /* memset()                     */
#include <time.h>            /* time()                       */
#include <ctype.h>           /* tolower()                    */
#include <fcntl.h>
#ifdef HIP_VPLS
#include <utime.h>
#endif
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <win32/types.h>
#include <process.h>
#include <io.h>
#else
#include <sys/socket.h>      /* sock(), recvmsg(), etc       */
#include <sys/time.h>        /* gettimeofday()               */
#include <sys/uio.h>            /* iovec */
#include <sys/wait.h>           /* waitpid() */
#include <arpa/inet.h>       /* inet_pton()                  */
#ifdef __MACOSX__
#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>      /* struct sockaddr_in, etc      */
#include <netinet/ip.h>      /* struct iphdr                 */
#include <unistd.h>          /* fork(), getpid()             */
#include <math.h>            /* pow()                        */
#include <pthread.h>
#include <netdb.h>
#endif
#include <sys/types.h>       /* getpid() support, etc        */
#include <signal.h>          /* signal()                     */
#include <openssl/crypto.h>  /* OpenSSL's crypto library     */
#include <openssl/bn.h>      /* Big Numbers                  */
#include <openssl/dsa.h>     /* DSA support                  */
#include <openssl/asn1.h>    /* DSAparams_dup()              */
#include <openssl/dh.h>      /* Diffie-Hellman contexts      */
#include <openssl/sha.h>     /* SHA1 algorithms              */
#include <openssl/rand.h>    /* RAND_seed()                  */
#include <hip/hip_types.h>
#include <hip/hip_proto.h>
#include <hip/hip_globals.h>
#include <hip/hip_funcs.h>
#include <hip/hip_version.h> /* HIP_VERSION */
#ifdef HIP_VPLS
#include <hip/hip_cfg_api.h>
#endif

#ifdef __MACOSX__
extern void del_divert_rule(int);
#endif
#ifdef __WIN32__
extern int socketpair(int, int, int, int sv[2]);
#endif

#ifndef __MACOSX__
#ifndef __WIN32__
#define IPV6_HIP
#endif
#endif
/*
 * Function prototypes
 */
int main(int argc, char *argv[]);

/* HIP packets */
#ifdef __WIN32__
void hip_handle_packet(__u8* buff, int length, struct sockaddr *src);
#else
void hip_handle_packet(struct msghdr *msg, int length, __u16 family);
#endif
void hip_handle_state_timeouts(struct timeval *time1);
void hip_handle_locator_state_timeouts(hip_assoc *hip_a, struct timeval *time1);
void hip_handle_registrations(struct timeval *time1);
void hip_check_next_rvs(hip_assoc *hip_a);
static void hip_retransmit_waiting_packets(struct timeval *time1);
int hip_trigger(struct sockaddr *dst);
int hip_trigger_rvs(struct sockaddr*rvs, hip_hit *responder);

#ifndef __WIN32__
void post_init_tap();
#endif
#ifdef HIP_VPLS
void endbox_init();
#endif

/*
 * main():  HIP daemon main event loop
 *     - read command line options
 *     - read configuration file
 *     - crypto init -- generate Diffie Hellman material
 *     - generate R1s
 *     - some timer for timeout activies (rotate R1, expire states)
 *     - create HIP and ESP sockets
 *     - go to endless loop, selecting on the sockets
 */

int main_loop(int argc, char **argv)
{
  struct timeval time1, timeout;       /* Used in select() loop */
#ifndef __WIN32__
  struct msghdr msg = {0};
  struct iovec iov = {0};
#endif
  struct sockaddr_in addr;       /* For IPv4 */

  struct sockaddr_storage addr_from;
  __u32 addr_from_len;
  fd_set read_fdset;
  char buff[2048];
#ifdef IPV6_HIP
  struct sockaddr_in6 addr6;       /* For IPv6 */
  int optval = 1;
#ifndef __WIN32__
  char cbuff[CMSG_SPACE(256)];
#endif
#endif
  int num_icmp_errors = 0;
  int highest_descriptor = 0;
  int flags = 0, err = 0, length = 0, last_expire = 0, i;
  int need_select_preferred = FALSE;
#ifdef HIP_VPLS
  time_t last_time, now_time;
#endif

  /* Initializing global variables */
  memset(hip_assoc_table, 0, sizeof(hip_assoc_table));

  /*
   * Set default options
   * later modified by command-line parameters
   */
  memset(&OPT, 0, sizeof(struct hip_opt));
  OPT.daemon = FALSE;
  OPT.debug = D_DEFAULT;
  OPT.debug_R1 = D_QUIET;
  OPT.no_retransmit = FALSE;
  OPT.permissive = FALSE;
  OPT.opportunistic = FALSE;
  OPT.allow_any = FALSE;
  OPT.trigger = NULL;
  OPT.rvs = FALSE;
  OPT.mr = FALSE;
  OPT.mh = FALSE;

  /*
   * Set default configuration
   * later modified by command-line parameters or conf file
   */
  memset(&HCNF, 0, sizeof(struct hip_conf));
  HCNF.cookie_difficulty = 10;
  HCNF.cookie_lifetime = 39;       /* 2^(39-32) = 2^7 = 128 seconds */
  HCNF.packet_timeout = 5;
  HCNF.max_retries = 5;
  HCNF.sa_lifetime = 900;       /* 15 minutes, as recommended by draft-esp */
  HCNF.loc_lifetime = 1800;       /* 30 minutes */
  HCNF.preferred_hi = NULL;
  HCNF.send_hi_name = TRUE;
  HCNF.dh_group = DEFAULT_DH_GROUP_ID;
  HCNF.dh_lifetime = 900;
  HCNF.r1_lifetime = 300;
  HCNF.msl = 5;
  HCNF.ual = 600;
  HCNF.failure_timeout = (HCNF.max_retries * HCNF.packet_timeout);
  for (i = 0; i < (SUITE_ID_MAX - 1); i++)
    {
      HCNF.esp_transforms[i] = HCNF.hip_transforms[i] = (__u16)(i + 1);
    }
  HCNF.log_filename = NULL;
  HCNF.disable_dns_lookups = FALSE;
  HCNF.disable_notify = FALSE;
  HCNF.disable_dns_thread = TRUE;
#ifdef __MACOSX__
  HCNF.disable_udp = TRUE;
#else
  HCNF.disable_udp = FALSE;
#endif
  HCNF.enable_bcast = FALSE;
  HCNF.num_reg_types = 0;
  HCNF.min_reg_lifetime = 96;        /* min offered 2^((96-64)/8) = s */
  HCNF.max_reg_lifetime = 255;       /* max offered 2^((255-64)/8) = s */
  HCNF.preferred_iface = NULL;
  HCNF.outbound_ifaces = NULL;
  HCNF.save_known_identities = FALSE;
  HCNF.save_my_identities = TRUE;
  HCNF.peer_certificate_required = FALSE;
  memset(HCNF.conf_filename, 0, sizeof(HCNF.conf_filename));
  memset(HCNF.my_hi_filename, 0, sizeof(HCNF.my_hi_filename));
  memset(HCNF.known_hi_filename, 0, sizeof(HCNF.known_hi_filename));
#ifdef HIP_VPLS
  HCNF.use_my_identities_file = 0;
  HCNF.endbox_hello_time = 0;
  HCNF.endbox_allow_core_dump = 0;
#endif

  /*
   * check program arguments
   */
  argv++, argc--;
  while (argc > 0)
    {
      if (strcmp(*argv, "-v") == 0)
        {
          OPT.debug = D_VERBOSE;
          argv++, argc--;
          continue;

        }
      else if (strcmp(*argv, "-q") == 0)
        {
          OPT.debug = D_QUIET;
          OPT.debug_R1 = D_QUIET;
          argv++, argc--;
          continue;
        }
      else if (strcmp(*argv, "-d") == 0)
        {
          OPT.daemon = TRUE;
          argv++, argc--;
          continue;
        }
      if (strcmp(*argv, "-r1") == 0)
        {
          OPT.debug_R1 = OPT.debug;
          argv++, argc--;
          continue;
        }
      if (strcmp(*argv, "-p") == 0)
        {
          OPT.permissive = TRUE;
          argv++, argc--;
          continue;
        }
      if (strcmp(*argv, "-nr") == 0)
        {
          OPT.no_retransmit = TRUE;
          argv++, argc--;
          continue;
        }
      if (strcmp(*argv, "-o") == 0)
        {
          OPT.opportunistic = TRUE;
          argv++, argc--;
          continue;
        }
      if (strcmp(*argv, "-a") == 0)
        {
          OPT.allow_any = TRUE;
          argv++, argc--;
          continue;
        }
      if (strcmp(*argv, "-t") == 0)
        {
          int af;
          argv++, argc--;
          if ((argc == 0) || !argv)
            {
              log_(ERR, "Please supply a trigger address.\n");
              exit(1);
            }
          af = ((strchr(*argv, ':') == NULL) ? AF_INET : AF_INET6);
          OPT.trigger = (struct sockaddr*)malloc(
            (af == AF_INET) ?
            sizeof(struct
                   sockaddr_in) :
            sizeof(struct
                   sockaddr_in6));
          memset(OPT.trigger, 0, sizeof(OPT.trigger));
          OPT.trigger->sa_family = af;
          if (str_to_addr((__u8*)*argv, OPT.trigger) < 1)
            {
              log_(ERR, "Invalid trigger address.\n");
              exit(1);
            }
          argv++, argc--;
          continue;
        }
      if (strcmp(*argv, "-u") == 0)
        {
          log_(WARN, "The -u option has been deprecated. UDP "
               "encapsulation is enabled by default and can be"
               "disabled in hip.conf.\n");
          argv++, argc--;
          continue;
        }
      if (strcmp(*argv, "-conf") == 0)
        {
          argv++, argc--;
          strncpy(HCNF.conf_filename, *argv,
                  sizeof(HCNF.conf_filename));
          log_(NORM,      "Using user-provided hip.conf file " \
               "location.\n");
          argv++, argc--;
          continue;
        }
      /* Mobile router service or rendezvous server */
      if ((strcmp(*argv, "-mr") == 0) ||
          (strcmp(*argv, "-rvs") == 0))
        {
          if (HCNF.num_reg_types >= MAX_REGISTRATION_TYPES)
            {
              log_(ERR, "Error: number of registration "
                   "types exceeds %d\n",
                   MAX_REGISTRATION_TYPES);
              exit(1);
            }
          if (strcmp(*argv, "-mr") == 0)
            {
              OPT.mr = TRUE;
              HCNF.reg_types[HCNF.num_reg_types] = REGTYPE_MR;
              HCNF.num_reg_types++;
            }
          else
            {
              OPT.rvs = TRUE;
              HCNF.reg_types[HCNF.num_reg_types] =
                REGTYPE_RVS;
              HCNF.num_reg_types++;
            }
          argv++,argc--;
          continue;
        }
      /* Turn on experimental multihoming for lost packets */
      if (strcmp(*argv, "-mh") == 0)
        {
          OPT.mh = TRUE;
          argv++,argc--;
          continue;
        }

      print_usage();
      exit(1);
    }

  if (init_log() < 0)
    {
      goto hip_main_error_exit;
    }

#ifdef __WIN32__
  log_(QOUT, "hipd v%s started.\n", HIP_VERSION);
#else
  log_(QOUT, "hipd v%s (%d) started.\n", HIP_VERSION, getpid());
#endif
  log_hipopts();

  /*
   * Load hip.conf configuration file
   * user may have provided path using command line, or search defaults
   */
  if ((locate_config_file(HCNF.conf_filename, sizeof(HCNF.conf_filename),
                          HIP_CONF_FILENAME) < 0) ||
      (read_conf_file(HCNF.conf_filename) < 0))
    {
      log_(ERR, "Problem with configuration file, using defaults.\n");
    }
  else
    {
      log_(NORM, "Using configuration file:\t%s\n",
           HCNF.conf_filename);
    }

  /*
   * Load the my_host_identities.xml file.
   */
  my_hi_head = NULL;
#ifdef HIP_VPLS
  hi_node *my_hi;
  if (!HCNF.cfg_library)
    {
      log_(ERR, "Must specify <cfg_library> in hip.conf\n");
      goto hip_main_error_exit;
    }
  if (hipcfg_init(HCNF.cfg_library, &HCNF))
    {
      log_(ERR, "Error loading configuration library: %s\n",
           HCNF.cfg_library);
      goto hip_main_error_exit;
    }
  if (!HCNF.use_my_identities_file)
    {
      if ((my_hi = hipcfg_getMyHostId()) == NULL)
        {
          log_(ERR, "Error retrieving host identity from cert\n");
          goto hip_main_error_exit;
        }
      append_hi_node(&my_hi_head, my_hi);
    }
  else
    {
#endif /* HIP_VPLS */
  if ((locate_config_file(HCNF.my_hi_filename,
                          sizeof(HCNF.my_hi_filename),
                          HIP_MYID_FILENAME) < 0))
    {
      log_(ERR, "Unable to locate this machine's %s file.\n",
           HIP_MYID_FILENAME);
    }
  else
    {
      log_(NORM, "Using my host IDs file:\t\t%s\n",
           HCNF.my_hi_filename);
    }
  if (read_identities_file(HCNF.my_hi_filename, TRUE) < 0)
    {
      log_(ERR, "Problem with my host identities file.\n");
      log_(QOUT, "\n  You must have a valid %s file containing the "
           "identities\n  for this host. You can create this file "
           "using the 'hitgen' utility.\n", HIP_MYID_FILENAME);
      goto hip_main_error_exit;           /* fatal error */
    }
#ifdef HIP_VPLS
}
#endif

  /*
   * Load the known_host_identities.xml file.
   */
  peer_hi_head = NULL;
#ifndef HIP_VPLS
  if ((locate_config_file(HCNF.known_hi_filename,
                          sizeof(HCNF.known_hi_filename),
                          HIP_KNOWNID_FILENAME) < 0))
    {
      log_(ERR, "Unable to locate this machine's %s file.\n",
           HIP_KNOWNID_FILENAME);
    }
  else
    {
      log_(NORM, "Using known host IDs file:\t%s\n",
           HCNF.known_hi_filename);
    }
#endif
  if (read_identities_file(HCNF.known_hi_filename, FALSE) < 0)
    {
      log_(ERR, "Problem reading the %s file which is used to "
           "specify\n  peer HITs.\n",
           HIP_KNOWNID_FILENAME);
      if (!OPT.allow_any)
        {
          log_(ERR, "Because there are no peer identities, "
               "the -a\n  (allow any) option likely needed.\n");
        }
    }

  if (get_preferred_hi(my_hi_head) == NULL)
    {
      log_(ERR, "The preferred HI specified in %s was not found.\n",
           HIP_CONF_FILENAME);
      goto hip_main_error_exit;
    }

#ifdef HIP_VPLS
  if (!HCNF.endbox_allow_core_dump)
    {
      signal(SIGSEGV, hip_exit);
    }
#else
  signal(SIGSEGV, hip_exit);
#endif
  signal(SIGINT, hip_exit);
  signal(SIGTERM, hip_exit);
  hip_writelock();

  /* Netlink socket */
  if (hip_netlink_open() < 0)
    {
      log_(ERR, "Netlink socket error: %s\n", strerror(errno));
      goto hip_main_error_exit;
    }
  get_my_addresses();
  select_preferred_address();
#ifndef __WIN32__
  hip_mr_set_external_ifs();
#endif /* !__WIN32__ */
  /* Precompute R1s, cookies, DH material */
  init_dh_cache();
  init_all_R1_caches();
  gettimeofday(&time1, NULL);
  last_expire = time1.tv_sec;
  hip_dht_update_my_entries(1);       /* initalize and publish */
#ifndef __WIN32__
  post_init_tap();
#endif
  /* Status socket */
  if (hip_status_open() < 0)
    {
      log_(ERR, "Unable to start status socket: %s\n",
           strerror(errno));
    }

#ifdef IPV6_HIP
  /* IPv6 HIP socket */
  memset(&addr6, 0, sizeof(addr6));
  addr6.sin6_family = AF_INET6;
  addr6.sin6_port = 0;
  if (str_to_addr((__u8*)"0::0", (struct sockaddr*)&addr6) == 0)
    {
      log_(ERR, "inet_pton() error\n");
      goto hip_main_error_exit;
    }
  s6_hip = socket(PF_INET6, SOCK_RAW, H_PROTO_HIP);
  if (s6_hip < 0)
    {
      log_(ERR, "raw IPv6 socket() for hipd failed\n");
      goto hip_main_error_exit;
    }
#endif

  /* IPv4 HIP socket */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s_hip = socket(PF_INET, SOCK_RAW, H_PROTO_HIP);
  if (s_hip < 0)
    {
      log_(ERR, "raw IPv4 socket() for hipd failed\n");
      goto hip_main_error_exit;
    }

  /* socketpair for communicating with the ESP input/output threads */
#ifdef __MACOSX__
  if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNSPEC, espsp))
    {
#else
  if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, espsp))
    {
#endif /* __MACOSX__ */
      log_(ERR, "socketpair() for ESP threads failed\n");
    }

#ifndef __WIN32__
#if !defined(__MACOSX__)
  /* indicate that socket wants to receive ICMP messages */
  setsockopt(s_hip, SOL_IP, IP_RECVERR, &optval, sizeof(optval));
#endif
#endif /* __WIN32__ */
       /* bind to specific local address */
  if (bind(s_hip, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
      log_(ERR, "bind() for IPv4 HIP socket failed.\n");
      goto hip_main_error_exit;
    }

#ifdef IPV6_HIP
  setsockopt(s6_hip, IPPROTO_IPV6, IPV6_RECVERR, &optval, sizeof(optval));
  setsockopt(s6_hip, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval,
             sizeof(optval));
  if (bind(s6_hip, (struct sockaddr*)&addr6, sizeof(addr6)) < 0)
    {
      log_(ERR, "bind() for IPv6 HIP socket failed.\n");
      goto hip_main_error_exit;
    }

  highest_descriptor = maxof(5, espsp[1], s_hip, s6_hip, s_net, s_stat);
#else /* IPV6_HIP */
  highest_descriptor = maxof(4, espsp[1], s_hip, s_net, s_stat);
#endif /* IPV6_HIP */

  log_(NORMT, "Listening for HIP control packets...\n");

#ifdef HIP_VPLS
  endbox_init();
  last_time = time(NULL);
#endif

  /* main event loop */
  for (;;)
    {
      /* this line causes a performance hit, used for debugging... */
      fflush_log();

      if (g_state != 0)
        {
          return(-EINTR);
        }

      /* prepare file descriptor sets */
      FD_ZERO(&read_fdset);
      FD_SET((unsigned)s_hip, &read_fdset);
#ifdef IPV6_HIP
      FD_SET((unsigned)s6_hip, &read_fdset);
#endif
      FD_SET((unsigned)espsp[1], &read_fdset);
      FD_SET((unsigned)s_net, &read_fdset);
      FD_SET((unsigned)s_stat, &read_fdset);
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      /* setup message header with control and receive buffers */
#ifndef __WIN32__
      msg.msg_name = &addr_from;
      msg.msg_namelen = sizeof(struct sockaddr_storage);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
#if !defined(__MACOSX__)
      memset(cbuff, 0, sizeof(cbuff));
      msg.msg_control = cbuff;
      msg.msg_controllen = sizeof(cbuff);
      msg.msg_flags = 0;
#endif
      memset(buff, 0, sizeof(buff));
      iov.iov_len = sizeof(buff);
      iov.iov_base = buff;
#endif /* __WIN32__ */
#ifdef HIP_VPLS
      now_time = time(NULL);
      if (now_time - last_time > 60)
        {
          log_(NORMT, "hipd_main() heartbeat\n");
          last_time = now_time;
          utime("heartbeat_hipd_main", NULL);
        }
#endif

      /* wait for socket activity */
      if ((err = select((highest_descriptor + 1), &read_fdset,
                        NULL, NULL, &timeout)) < 0)
        {
          /* sometimes select receives interrupt in addition
           * to the hip_exit() signal handler */
          if (errno == EINTR)
            {
              return(-EINTR);
            }
          log_(WARN, "select() error: %s.\n", strerror(errno));
        }
      else if (err == 0)
        {
          /* idle cycle - select() timeout */
          /* retransmit any waiting packets */
          gettimeofday(&time1, NULL);
          hip_retransmit_waiting_packets(&time1);
          hip_handle_state_timeouts(&time1);
          hip_handle_registrations(&time1);
          if (OPT.mh)
            {
              hip_handle_multihoming_timeouts(&time1);
            }
#ifndef __WIN32__       /* cleanup zombie processes from fork() */
          waitpid(0, &err, WNOHANG);
#endif
          /* by default, every 5 minutes */
          if ((time1.tv_sec - last_expire) >
              (int)HCNF.r1_lifetime)
            {
              last_expire = time1.tv_sec;
              /* expire old DH contexts */
              expire_old_dh_entries();
              /* precompute a new R1 for each HI, and
               * sometimes pick a new random index for
               * cookies */
              replace_next_R1();
            }
          if (OPT.trigger)
            {
              hip_trigger(OPT.trigger);
            }
          if (need_select_preferred)
            {
              need_select_preferred = FALSE;
              select_preferred_address();
              hip_dht_update_my_entries(0);
            }
        }
      else if (FD_ISSET(s_hip, &read_fdset))
        {
          /* Something on HIP socket */
          flags = 0;
          /* extra check to prevent recvmsg() from blocking */
          if (g_state != 0)
            {
              return(-EINTR);
            }
#ifdef __WIN32__
          addr_from_len = sizeof(addr_from);
          length = recvfrom(s_hip, buff, sizeof(buff), flags,
                            SA(&addr_from), &addr_from_len);
#else
          length = recvmsg(s_hip, &msg, flags);
#endif
          /* ICMP packet */
          if (length < 0)
            {
              if (D_VERBOSE == OPT.debug)
                {
                  log_(NORMT, "Received ICMP error ");
                  log_(NORM,  "(count=%d) - %d %s\n",
                       ++num_icmp_errors,
                       errno, strerror(errno));
                }
#ifndef __MACOSX__
#ifndef __WIN32__
              /* retrieve ICMP message before looping */
              flags = MSG_ERRQUEUE;
              length = recvmsg(s_hip, &msg, flags);
              /*
               * Presently, we do not do anything
               * with ICMP messages
               */
#endif
#endif
            }
          else                   /* HIP packet */
            {
#ifdef __WIN32__
              hip_handle_packet(buff, length, SA(&addr_from));
#else
              hip_handle_packet(&msg, length, AF_INET);
#endif
            }
#ifdef IPV6_HIP
        }
      else if (FD_ISSET(s6_hip, &read_fdset))
        {
          /* Something on HIP v6 socket */
          flags = 0;
#ifdef __WIN32__
          addr_from_len = sizeof(addr_from);
          length = recvfrom(s6_hip, buff, sizeof(buff), flags,
                            SA(&addr_from), &addr_from_len);
#else
          length = recvmsg(s6_hip, &msg, flags);
#endif
          /* ICMPv6 packet */
          if (length < 0)
            {
              if (D_VERBOSE == OPT.debug)
                {
                  log_(NORMT, "Received ICMPv6 error ");
                  log_(NORM,  "(count=%d) - %d %s\n",
                       ++num_icmp_errors,
                       errno, strerror(errno));
                }
#ifndef __MACOSX__
#ifndef __WIN32__
              /* retrieve ICMP message before looping */
              flags = MSG_ERRQUEUE;
              length = recvmsg(s6_hip, &msg, flags);
              /*
               * Presently, we do not do anything
               * with ICMP messages
               */
#endif
#endif
            }
          else
            {
#ifdef __WIN32__
              hip_handle_packet(buff, length, SA(
                                  &addr_from), FALSE);
#else
              hip_handle_packet(&msg, length, AF_INET6);
#endif
            }
#endif /* IPV6_HIP */
        }
      else if (FD_ISSET(espsp[1], &read_fdset))
        {
          /* Data from the ESP input/output threads */
#ifdef __WIN32__
          if ((length =
                 recv(espsp[1], buff, sizeof(buff),
                      0)) < 0)
            {
#else
          if ((length =
                 read(espsp[1], buff, sizeof(buff))) < 0)
            {
#endif
              log_(WARN, "ESP socket read() error - %d %s\n",
                   errno, strerror(errno));
            }
          else
            {
              /* acquire, expire, or control data over UDP */
              hip_handle_esp(buff, length);
            }
        }
      else if (FD_ISSET(s_net, &read_fdset))
        {
          /* Something on Netlink socket */
#ifdef __WIN32__
          if ((length =
                 recv(s_net, buff, sizeof(buff), 0)) < 0)
            {
#else
          if ((length = read(s_net, buff, sizeof(buff))) < 0)
            {
#endif
              log_(WARN, "Netlink read() error - %d %s\n",
                   errno, strerror(errno));
            }
          else
            {
              if (hip_handle_netlink(buff, length) == 1)
                {
                  /* changes to address require new
                   * preferred address */
                  need_select_preferred = TRUE;
                }
            }
        }
      else if (FD_ISSET(s_stat, &read_fdset))
        {
          /* Something on Status socket */
          flags = 0;
          addr_from_len = sizeof(addr_from);
          length = sizeof(buff);
          if ((length = recvfrom(s_stat, buff, length, flags,
                                 SA(&addr_from),
                                 &addr_from_len)) < 0)
            {
#ifdef __WIN32__
              log_(WARN, "Status read() ");
              log_WinError(GetLastError());
#else
              log_(WARN, "Status read() error - %d %s\n",
                   errno, strerror(errno));
#endif
            }
          else
            {
              hip_handle_status_request((__u8*)buff, length,
                                        SA(&addr_from));
            }
        }
      else
        {
          log_(NORMT, "unknown socket activity.");
        }         /* select */
    }     /* end for(;;) */
  return(0);
hip_main_error_exit:
#ifndef __WIN32__
  snprintf(buff, sizeof(buff), "%s/run/%s", LOCALSTATEDIR,
           HIP_LOCK_FILENAME);
  unlink(buff);
#endif
  exit(1);
}

/*
 * HIP packet handling routines
 */

/*
 * Check HIP packet for sanity.  Switch on the type of packet and call
 * separate handling routines.
 *
 * buff:  pointer to datagram data (including IP header for IPv4)
 * length:  length of datagram
 */
#ifdef __WIN32__
void hip_handle_packet(__u8* buff, int length, struct sockaddr *src)
{
  __u16 family;
#else
void hip_handle_packet(struct msghdr *msg, int length, __u16 family)
{
  __u8 *buff;
  struct sockaddr *src;
  struct cmsghdr *cmsg;
#endif
  struct in6_pktinfo *pktinfo = NULL;
  char typestr[12];
  hiphdr* hiph = NULL;
  hip_assoc* hip_a = NULL;
  hip_hit hit_tmp;
  int err = 0;

  struct sockaddr *dst;
  struct sockaddr_storage dst_ss;

#ifndef __WIN32__
  struct sockaddr_storage src_ss;

  buff = msg->msg_iov->iov_base;
  src = (struct sockaddr*) &src_ss;
  memset(src, 0, sizeof(struct sockaddr_storage));
#endif
  dst = (struct sockaddr*) &dst_ss;
  memset(dst, 0, sizeof(struct sockaddr_storage));

#ifndef __WIN32__
  /* TODO: need proper ifdefs here for WIN32/IPv6 addresses */
  /* for IPv6, we determine the src/dst addresses here */
  if (family == AF_INET6)
    {
      /* destination address comes from ancillary data passed
       * with msg due to IPV6_PKTINFO socket option */
      for (cmsg = CMSG_FIRSTHDR(msg);
           cmsg;
           cmsg = CMSG_NXTHDR(msg,cmsg))
        {
          if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
              (cmsg->cmsg_type == IPV6_PKTINFO))
            {
              pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);
              break;
            }
        }
      if (!pktinfo)
        {
          log_(NORMT,"Could not determine IPv6 dst, dropping.\n");
          return;
        }
      dst->sa_family = AF_INET6;
      memcpy(SA2IP(dst), &pktinfo->ipi6_addr, SAIPLEN(dst));
      /* source address is filled in from call
       * to recvmsg() */
      src->sa_family = AF_INET6;
      memcpy(SA2IP(src), SA2IP(msg->msg_name), SAIPLEN(src));

      /* debug */
      log_(NORMT, "IPv6 packet from %s to ", logaddr(src));
      log_(NORM, "%s on if %d.\n",logaddr(dst),pktinfo->ipi6_ifindex);
    }
#else  /* !__WIN32__ */
  family = src->sa_family;
#endif /* !__WIN32__ */

  err = hip_parse_hdr(buff, length, src, dst, family, &hiph);

  if (err < 0)
    {
      /* attempt to send a NOTIFY packet */
      if (VALID_FAM(src) && VALID_FAM(dst) && hiph)
        {
          hip_a = find_hip_association(src, dst, hiph);
          if ((hip_a) && (hip_a->state >= I1_SENT) &&
              (hip_a->state < E_FAILED))
            {
              log_(WARN, "Header error, sending NOTIFY.\n");
              if (err == -3)                     /* bad checksum */
                {
                  hip_send_notify(hip_a,
                                  NOTIFY_CHECKSUM_FAILED,
                                  NULL,
                                  0);
                }
              else if (err == -2)                       /* various problems */
                {
                  hip_send_notify(hip_a,
                                  NOTIFY_INVALID_SYNTAX,
                                  NULL,
                                  0);
                }
            }
        }
      log_(WARN, "Header error but not enough state for NOTIFY --");
      log_(NORM, "dropping packet.\n");
      return;
    }
  if (hiph == NULL)
    {
      log_(NORMT, "Dropping HIP packet - bad header\n");
      return;
    }
  hip_packet_type(hiph->packet_type, typestr);
  log_(NORMT, "Received %s packet from %s", typestr, logaddr(src));
  log_(NORM, " on %s socket length %d\n",
       (((struct sockaddr_in*)src)->sin_port > 0) ? "udp" : "raw",
       length);

  /* lookup using addresses and HITs */
  hip_a = find_hip_association(src, dst, hiph);
  /* for opportunistic HIP, adopt unknown HIT from R1 */
  if ((hip_a == NULL) && OPT.opportunistic &&
      (hiph->packet_type == HIP_R1))
    {
      /* perform lookup with a zero HIT */
      memcpy(&hit_tmp, hiph->hit_sndr, sizeof(hip_hit));
      memcpy(hiph->hit_sndr, &zero_hit, sizeof(hip_hit));
      if ((hip_a = find_hip_association(src, dst, hiph)))
        {
          memcpy(hip_a->peer_hi->hit, &hit_tmp, sizeof(hip_hit));
          add_peer_hit(hit_tmp, src);
        }
      /* put the HIT back so signature will verify */
      memcpy(hiph->hit_sndr, &hit_tmp, sizeof(hip_hit));
    }

  /* XXX May allow lookup of other packets based solely on HITs
   *     in the future. Currently, UPDATE and HIP_R1 are accepted
   *     from anywhere. */
  if (!hip_a &&
      ((hiph->packet_type == UPDATE) || (hiph->packet_type == HIP_R1)))
    {
      hip_a = find_hip_association2(hiph);
    }

  /* UPDATE packet might be for RVS client. */
  if (!hip_a &&
      (hiph->packet_type != HIP_I1) &&
      (hiph->packet_type != HIP_I2) &&
      (hiph->packet_type != UPDATE))
    {
      log_(NORMT, "Dropping packet type %s -- no state was ",typestr);
      log_(NORM, "found, need to receive an I1 first.\n");
      return;
    }

  switch (hiph->packet_type)
    {
    case HIP_I1:
      err = hip_handle_I1((__u8 *)hiph, hip_a, src, dst);
      break;
    case HIP_R1:
      err = hip_handle_R1((__u8 *)hiph, hip_a, src);
      break;
    case HIP_I2:
      err = hip_handle_I2((__u8 *)hiph, hip_a, src, dst);
      break;
    case HIP_R2:
      err = hip_handle_R2((__u8 *)hiph, hip_a);
      break;
    case CER:
      err = hip_handle_CER((__u8 *)hiph, hip_a);
      break;
    case BOS:     /* BOS was removed starting with base-01 */
      err = hip_handle_BOS((__u8 *)hiph, src);
      break;
    case UPDATE:
      err = hip_handle_update((__u8 *)hiph, hip_a, src, dst);
      break;
    case NOTIFY:
      err = hip_handle_notify((__u8 *)hiph, hip_a);
      break;
    case CLOSE:
    case CLOSE_ACK:
      err = hip_handle_close((__u8 *)hiph, hip_a);
      break;
    default:
      log_(NORMT, "Unknown HIP packet type(%d), dropping\n",
           hiph->packet_type);
      break;
    }     /* end switch */
  if (err)
    {
      log_(NORMT, "Error with %s packet from %s\n",
           typestr, logaddr(src));
    }
  return;
}

/* Check for the next RVS for retransmission
 */
void
hip_check_next_rvs(hip_assoc *hip_a)
{
  struct sockaddr *src, *dst;
  struct _sockaddr_list *item;
  hiphdr *hiph;
  int offset;

  if (!(*(hip_a->peer_hi->rvs_addrs)))
    {
      return;
    }

  src = HIPA_SRC(hip_a);
  dst = NULL;

  offset = 0;
  if (hip_a->udp)
    {
      offset += sizeof(udphdr) + sizeof(__u32);
    }
  hiph = (hiphdr*) &hip_a->rexmt_cache.packet[offset];

  if ((hiph->packet_type == UPDATE) &&
      (0 == memcmp(SA2IP(&hip_a->rexmt_cache.dst), SA2IP(HIPA_DST(hip_a)),
                   SAIPLEN(&hip_a->rexmt_cache.dst))))
    {
      /* Use the first RVS */
      item = *(hip_a->peer_hi->rvs_addrs);
      dst = SA(&item->addr);
    }
  else
    {
      /* Find the next RVS */
      for (item = *(hip_a->peer_hi->rvs_addrs); item;
           item = item->next)
        {
          if (item->status != DEPRECATED)
            {
              struct sockaddr *cur_rvs;
              cur_rvs = SA(&item->addr);
              log_(NORMT, "RVS server %s not reachable,"
                   " changing status to DEPRECATED.\n",
                   logaddr(cur_rvs));
              item->status = DEPRECATED;
              /* Send to next RVS server if available */
              if (item->next)
                {
                  dst = SA(&item->next->addr);
                }
              break;
            }
        }
    }

  if (dst)
    {
      memcpy(&hip_a->rexmt_cache.dst, dst, SALEN(dst));
      if (!hip_a->udp)
        {
          /* recalcualte HIP checksum because of changed
           *  destination IP/HIT*/
          hiph->checksum = 0;
          hiph->checksum = checksum_packet((__u8 *)hiph,src,dst);
        }
      hip_a->rexmt_cache.retransmits = 0;
    }
  else
    {
      /* No more RVS, reset the status of all RVS servers */
      for (item = *(hip_a->peer_hi->rvs_addrs); item;
           item = item->next)
        {
          item->status = UNVERIFIED;
        }
    }
}

/*
 * Iterate among HIP connections and retransmit packets if needed,
 * or free them if they have reached HCNF.max_retries
 */
void
hip_retransmit_waiting_packets(struct timeval* time1)
{
  int i;
#ifdef DO_EXTRA_DHT_LOOKUPS
  int err;
  struct sockaddr_storage ss_addr_tmp;
  struct sockaddr *addr_tmp = (struct sockaddr*)&ss_addr_tmp;
#endif
  struct sockaddr *src, *dst;
  hip_assoc *hip_a;
  hiphdr *hiph;
  char typestr[12];
  int offset;

  for (i = 0; i < max_hip_assoc; i++)
    {
      hip_a = &hip_assoc_table[i];
#ifndef __WIN32__
      /* retransmit UPDATE-PROXY packets for mobile router clients
       * that have registered and are ESTABLISHED */
      if (OPT.mr && (hip_a->state == ESTABLISHED))
        {
          hip_mr_retransmit(time1, hip_a->peer_hi->hit);
        }
#endif /* !__WIN32__ */
      if ((hip_a->rexmt_cache.len < 1) ||
          (TDIFF(*time1, hip_a->rexmt_cache.xmit_time) <=
           (int)HCNF.packet_timeout))
        {
          continue;
        }

      /* See if a RVS is available */
      if ((hip_a->rexmt_cache.retransmits >=
           (int)HCNF.max_retries))
        {
          hip_check_next_rvs(hip_a);
        }

      if ((OPT.no_retransmit == FALSE) &&
          (hip_a->rexmt_cache.retransmits < (int)HCNF.max_retries) &&
          (hip_a->state != R2_SENT))
        {
          src = SA(&hip_a->hi->addrs.addr);
          dst = SA(&hip_a->rexmt_cache.dst);
          if ((src->sa_family != dst->sa_family) &&
              (get_addr_from_list(my_addr_head,
                                  dst->sa_family, src) < 0))
            {
              log_(WARN,
                   "Cannot determine source address for"
                   " retransmission to %s.\n",
                   logaddr(dst));
            }
          offset = 0;
          if (hip_a->udp)
            {
              offset += sizeof(udphdr) + sizeof(__u32);
            }
          hiph = (hiphdr*) &hip_a->rexmt_cache.packet[offset];
          /* TODO: the address may have changed, could
           * perform a DHT lookup here and retransmit using the
           * different address. */
          hip_packet_type(hiph->packet_type, typestr);
          log_(NORMT, "Retransmitting %s packet from %s to ",
               typestr, logaddr(src));
          log_(NORM,  "%s (attempt %d of %d)...\n", logaddr(dst),
               hip_a->rexmt_cache.retransmits + 1,
               HCNF.max_retries);
          hip_retransmit(hip_a, hip_a->rexmt_cache.packet,
                         hip_a->rexmt_cache.len, src, dst);
          gettimeofday(&hip_a->rexmt_cache.xmit_time, NULL);
          hip_a->rexmt_cache.retransmits++;
        }
      else
        {
          /* move to state E_FAILED for I1_SENT/I2_SENT */
          switch (hip_a->state)
            {
            case I1_SENT:
            case I2_SENT:
              set_state(hip_a, E_FAILED);
              break;
            default:
              break;
            }
          clear_retransmissions(hip_a);
        }
    }
}

/*
 * check_reg_info()
 *
 * Check if the given registration type is in the given reg_info structure.
 */
int check_reg_info(struct reg_entry *regs, __u8 type, int state,
                   struct timeval *now)
{
  double tmp;
  struct reg_info *reg;

  if (!regs)
    {
      return(0);
    }

  /* search for existing registration */
  for (reg = regs->reginfos; reg; reg = reg->next)
    {
      if ((type == reg->type) && (state == reg->state))
        {
          tmp = YLIFE(reg->lifetime);
          tmp = pow(2, tmp);
          if (TDIFF(*now, reg->state_time) > (int)tmp)
            {
              return(0);
            }
          else
            {
              return(1);
            }
        }
    }
  return(0);
}

/* Iterate over HIP connections and handle state timeout.
 */
void hip_handle_state_timeouts(struct timeval *time1)
{
  int i, remove_rxmt, do_close, err;
  hip_assoc *hip_a;

  for (i = 0; i < max_hip_assoc; i++)
    {
      do_close = FALSE;
      remove_rxmt = FALSE;
      hip_a = &hip_assoc_table[i];
      switch (hip_a->state)
        {
        case R2_SENT:         /* R2 -> ESTABLISHED */
          if (check_last_used(hip_a, 1, time1) > 0)
            {
              set_state(hip_a, ESTABLISHED);
              remove_rxmt = TRUE;
              log_(NORMT, "HIP association %d moved ", i);
              log_(NORM,  "from R2_SENT=>ESTABLISHED ");
              log_(NORM,  "due to incoming ESP data.\n");
              if (OPT.mh &&
                  (hip_send_update_locators(hip_a) < 0))
                {
                  log_(WARN,
                       "Failed to send UPDATE with loca"
                       "tors following incoming data.\n");
                }
              /* any packet sent during UAL minutes? */
            }
          else if (check_last_used(hip_a, 0, time1) > 0)
            {
              /* data being sent, compare time */
              if (TDIFF(*time1, hip_a->use_time) >
                  (int)HCNF.ual)
                {
                  do_close = TRUE;
                }
              /* no packet sent or received, check UAL minutes
              **/
            }
          else if (TDIFF(*time1, hip_a->state_time) >
                   (int)HCNF.ual)
            {
              do_close = TRUE;
            }
          break;
        case CLOSING:
        case CLOSED:
          if (TDIFF(*time1, hip_a->state_time) >
              (HCNF.ual + (hip_a->state == CLOSED) ?
               (int)(2 * HCNF.msl) : (int)HCNF.msl))
            {
              set_state(hip_a, UNASSOCIATED);
              log_(NORMT, "HIP association %d moved from", i);
              log_(NORM, " %s=>UNASSOCIATED\n",
                   (hip_a->state ==
                    CLOSED) ? "CLOSED" : "CLOSING");
              /* max_hip_assoc may decrease here, but this
               * shouldn't ruin this for loop */
              free_hip_assoc(hip_a);
            }
          break;
        case E_FAILED:         /* E_FAILED -> UNASSOCIATED */
          if (TDIFF(*time1, hip_a->state_time) >
              (int)HCNF.failure_timeout)
            {
              set_state(hip_a, UNASSOCIATED);
              log_(NORMT, "HIP association %d moved from", i);
              log_(NORM,  " E_FAILED=>UNASSOCIATED\n");
              free_hip_assoc(hip_a);
            }
          break;
        case ESTABLISHED:
          /*
           * If a pending rekey has been completely ACKed and
           * a NES has been received, we can finish the rekey.
           */
          if ((hip_a->rekey) && (!hip_a->rekey->need_ack) &&
              (hip_a->peer_rekey) &&
              (hip_a->peer_rekey->new_spi > 0))
            {
              hip_finish_rekey(hip_a, TRUE);
              remove_rxmt = TRUE;
              /*
               * Fail rekey using stored creation time
               */
            }
          else if (hip_a->rekey &&
                   (TDIFF(*time1, hip_a->rekey->rk_time) >
                    (int)HCNF.failure_timeout))
            {
              log_hipa_fromto(QOUT, "Rekey failed (timeout)",
                              hip_a, TRUE, TRUE);
              log_(NORMT, "HIP association %d moved from", i);
              log_(NORM,  " %d=>UNASSOCIATED because of "
                   "rekey failure.\n", hip_a->state);
              set_state(hip_a, UNASSOCIATED);
              delete_associations(hip_a, 0, 0);
              free_hip_assoc(hip_a);
              break;
            }
          /*
           * Check last used time
           */
          /* don't send SADB_GETs multiple times per second! */
          if (TDIFF(*time1, hip_a->use_time) < 2)
            {
              break;
            }
          /* Do not timeout SAs for MR registration */
          if (check_reg_info(hip_a->regs, REGTYPE_MR, REG_GRANTED,
                             time1))
            {
              hip_a->use_time.tv_sec = time1->tv_sec;
              hip_a->use_time.tv_usec = time1->tv_usec;
            }
          err = check_last_used(hip_a, 1, time1);
          err += check_last_used(hip_a, 0, time1);
          /* no use time available, first check state time for UAL
           * also check the use time because after a rekey,
           * bytes=0 and check_last_used() will return 0, but it
           * is not time to expire yet due to use_time */
          if ((err == 0) &&
              (TDIFF(*time1,
                     hip_a->state_time) > (int)HCNF.ual))
            {
              /* state time has exceeded UAL */
              if (hip_a->use_time.tv_sec == 0)
                {
                  do_close = TRUE;                       /* no bytes ever sent*/
                }
              else if (TDIFF(*time1,hip_a->use_time) >
                       (int)HCNF.ual)
                {
                  do_close = TRUE;                       /* both state time and
                                                          *  use time have
                                                          *  exceeded UAL*/
                }
              /* last used time is available, check for UAL */
            }
          else if ((err == 2) || (err == 1))
            {
              if (TDIFF(*time1, hip_a->use_time) >
                  (int)HCNF.ual)
                {
                  do_close = TRUE;
                }
            }
          break;
        default:
          break;
        }
      /* move to CLOSING if flagged */
      if (do_close)
        {
          log_hipa_fromto(QOUT, "Close initiated (timeout)",
                          hip_a, FALSE, TRUE);
          delete_associations(hip_a, 0, 0);
#ifdef __MACOSX__
          if (hip_a->ipfw_rule > 0)
            {
              del_divert_rule(hip_a->ipfw_rule);
              hip_a->ipfw_rule = 0;
            }
#endif
          hip_send_close(hip_a, FALSE);
          set_state(hip_a, CLOSING);
        }
      /* clean up rxmt queue if flagged */
      if (remove_rxmt && hip_a->rexmt_cache.packet)
        {
          clear_retransmissions(hip_a);
        }
      /* age peer locators, verify addresses */
      hip_handle_locator_state_timeouts(hip_a, time1);
    }

}

/* Iterate over HIP connections and handle registrations.
 */
void hip_handle_registrations(struct timeval *time1)
{
  int i, do_update = 0;
  hip_assoc *hip_a;
  struct reg_info *reg;
  double tmp;

  for (i = 0; i < max_hip_assoc; i++)
    {
      do_update = 0;
      hip_a = &hip_assoc_table[i];
      if (hip_a->state != ESTABLISHED)
        {
          continue;
        }
      if (!hip_a->regs)
        {
          continue;
        }
      for (reg = hip_a->regs->reginfos; reg; reg = reg->next)
        {
          /* we've requested a registration but haven't heard
           * back after a certain amount of time */
          if (reg->state == REG_REQUESTED)
            {
              if (TDIFF(*time1, reg->state_time) >
                  (int)HCNF.ual)
                {
                  reg->state = REG_OFFERED;
                  do_update = 1;
                }
              /* an active registration has expired */
            }
          else if (reg->state == REG_GRANTED)
            {
              tmp = YLIFE (reg->lifetime);
              tmp = pow (2, tmp);
              tmp = 0.9 * tmp;
              if (TDIFF(*time1,
                        reg->state_time) > (int)tmp)
                {
                  reg->state = REG_OFFERED;
                  do_update = 1;
                }
            }
        }
      if (do_update)
        {
          hip_send_update(hip_a, NULL, NULL, NULL);
        }
    }
}

/*
 * hip_handle_locator_state_timeouts()
 *
 * Age peer locators, sending address verification when necessary.
 * ACTIVE or UNVERIFIED -> DEPRECATED - locator lifetime expires
 * ACTIVE -> UNVERIFIED - no traffic and local policy mandates
 *                        reachability (TODO)
 */
void hip_handle_locator_state_timeouts(hip_assoc *hip_a, struct timeval *time1)
{
  sockaddr_list *l;
  struct sockaddr *addrcheck;
  __u32 nonce;

  if (!hip_a->peer_hi)
    {
      return;
    }
  if (hip_a->peer_hi->skip_addrcheck)
    {
      return;
    }
  for (l = &hip_a->peer_hi->addrs; l; l = l->next)
    {
      if (l->lifetime == 0)             /* no locator lifetime set */
        {
          continue;
        }
      if (TDIFF(*time1, l->creation_time) < l->lifetime)
        {
          continue;
        }
      /* address has expired */
      addrcheck = SA(&l->addr);
      if ((l->status == ACTIVE) ||
          (l->status == UNVERIFIED))
        {
          l->status = DEPRECATED;
          log_(NORMT, "Locator %s has expired after %d seconds," \
               " performing address check.\n",
               logaddr(addrcheck), l->lifetime);
        }
      if (hip_a->rekey)             /* UPDATE already pending for  */
        {
          continue;               /* some other reason           */
        }
      /* perform address check */
      hip_a->rekey = malloc(sizeof(struct rekey_info));
      memset(hip_a->rekey, 0, sizeof(struct rekey_info));
      hip_a->rekey->update_id = hip_a->hi->update_id++;
      hip_a->rekey->need_ack = TRUE;
      hip_a->rekey->rk_time.tv_sec = time1->tv_sec;
      RAND_bytes((__u8*)&nonce, sizeof(__u32));
      l->nonce = nonce;
      hip_send_update(hip_a, NULL, NULL, addrcheck);
    }     /* end for */
}

/*
 * Manually trigger HIP exchange
 */
int hip_trigger(struct sockaddr *dst)
{
  hip_hit *hitp;
  struct sockaddr *src;
  struct sockaddr_storage src_buff;
  hip_assoc* hip_a = NULL;
  hiphdr hiph;
  hi_node *mine = NULL;
  sockaddr_list *a;

  memset(&src_buff, 0, sizeof(struct sockaddr_storage));
  src = (struct sockaddr*)&src_buff;

  log_(NORMT, "Manually triggering exchange with %s.\n", logaddr(dst));
  hitp = hit_lookup(dst);
  if ((hitp == NULL) && (!OPT.opportunistic))
    {
      log_(NORM, "HIT for ip %s not found, ", logaddr(dst));
      log_(NORM, "unable to send I1. Add HIT to known_host_");
      log_(NORM, "identities or use opportunistic mode.\n");
      return(-1);
    }
  /* Create pseudo-HIP header for lookup */
  if ((mine = get_preferred_hi(my_hi_head)) == NULL)
    {
      log_(WARN, "No local identities to use.\n");
      return(-1);
    }
  memcpy(hiph.hit_rcvr, mine->hit, sizeof(hip_hit));
  if (hitp == NULL)
    {
      memcpy(hiph.hit_sndr, &zero_hit, sizeof(hip_hit));
    }
  else
    {
      memcpy(hiph.hit_sndr, hitp, sizeof(hip_hit));
    }
  /* here dst is peer */
  hip_a = find_hip_association(dst, src, &hiph);
  if (hip_a && (hip_a->state > UNASSOCIATED))
    {
      /* already have a HIP association for this HIT */
      log_(NORM, "HIP association for ip %s ", logaddr(dst));
      log_(NORM, "already exists -- ignoring trigger.\n");
      return(0);
    }
  else if (!hip_a)
    {
      /* Create another HIP association */
      hip_a = init_hip_assoc(mine, (const hip_hit*)&hiph.hit_sndr);
      if (!hip_a)
        {
          log_(WARN, "Unable to create triggered association.\n");
          /* don't remove trigger here and we will retry later */
          return(-1);
        }
    }

  /* fill in addresses */
  for (a = my_addr_head; a; a = a->next)
    {
      if (a->addr.ss_family != dst->sa_family)
        {
          continue;
        }
      memset(HIPA_SRC(hip_a), 0, sizeof(struct sockaddr_storage));
      memcpy(HIPA_SRC(hip_a), &a->addr,
             SALEN(&a->addr));
      if (!a->preferred)             /* break if preferred address */
        {
          continue;
        }
      log_(NORM, "Using the configured source address of %s.\n",
           logaddr(HIPA_SRC(hip_a)));
      break;
    }
  make_address_active(&hip_a->hi->addrs);
  memcpy(HIPA_DST(hip_a), dst, SALEN(dst));
  memcpy(&(hip_a->peer_hi->hit), hiph.hit_sndr, sizeof(hip_hit));

  /* Remove the trigger */
  free(OPT.trigger);
  OPT.trigger = NULL;

  /* Send the I1 */
  if (hip_send_I1(hitp, hip_a) > 0)
    {
      set_state(hip_a, I1_SENT);
    }
  return(0);
}

/*
 * Manually trigger HIP exchange through a rvs
 */
int hip_trigger_rvs(struct sockaddr *rvs, hip_hit *rsp)
{
  hip_assoc* hip_a = NULL;
  hiphdr hiph;
  hi_node *mine = NULL;
  sockaddr_list *a;

  log_(NORMT,     "Manually triggering exchange with rvs: %s to "
       "communicate with responder: ", logaddr(rvs));
  print_hex(rsp, HIT_SIZE);
  log_(NORM, "\n");

  /* Create pseudo-HIP header for lookup */
  if ((mine = get_preferred_hi(my_hi_head)) == NULL)
    {
      log_(WARN, "No local identities to use.\n");
      return(-1);
    }
  memcpy(hiph.hit_rcvr, mine->hit, HIT_SIZE);
  memcpy(hiph.hit_sndr, rsp, HIT_SIZE);

  hip_a = find_hip_association2(&hiph);                 /* Looks for an existing
                                                         * hip_association
                                                         * between Initiator &
                                                         * Responder */
  if (hip_a && (hip_a->state > UNASSOCIATED))
    {
      /* already have a HIP association for this HIT */
      log_(NORM, "HIP association for ip %s ", logaddr(rvs));
      log_(NORM, "already exists -- ignoring trigger.\n");
      return(0);
    }
  else if (!hip_a)
    {
      /* Create another HIP association */
      hip_a = init_hip_assoc(mine, (const hip_hit*)rsp);
      if (!hip_a)
        {
          log_(WARN, "Unable to create triggered association.\n");
          /* don't remove trigger here and we will retry later */
          return(-1);
        }
    }
  /* fill in addresses */
  for (a = my_addr_head; a; a = a->next)
    {
      if (a->addr.ss_family != rvs->sa_family)
        {
          continue;
        }
      memset(HIPA_SRC(hip_a), 0, sizeof(struct sockaddr_storage));
      memcpy(HIPA_SRC(hip_a), &a->addr, SALEN(&a->addr));
      if (!a->preferred)             /* break if preferred address */
        {
          continue;
        }
      log_(NORM, "Using the configured source address of %s.\n",
           logaddr(HIPA_SRC(hip_a)));
      break;
    }
  make_address_active(&hip_a->hi->addrs);
  memcpy(HIPA_DST(hip_a), rvs, SALEN(rvs));

  /* Remove the trigger */
  free(OPT.trigger);
  OPT.trigger = NULL;

  /* Send the I1 */
  if (hip_send_I1(rsp, hip_a) > 0)
    {
      set_state(hip_a, I1_SENT);
    }

  return(0);
}

