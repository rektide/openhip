/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2004-2012 the Boeing Company
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
 *  \file  hip_linux_umh.c
 *
 *  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  User-mode HIP main program and initialization code.
 *          Multiple threads are spawned that perform the actual work.
 */
#include <stdio.h>      /* stderr, stdout */
#include <unistd.h>     /* chdir() */
#include <pthread.h>    /* pthread_create() */
#include <sys/time.h>   /* gettimeofday() */
#include <sys/errno.h>  /* errno */
#include <sys/ioctl.h>  /* ioctl() */
#include <fcntl.h>      /* open() */
#ifdef __MACOSX__
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>          /* inet_addr() */
#include <string.h>             /* strerror() */
#include <netdb.h>              /* inet_pton() */
#include <openssl/rand.h>       /* RAND_seed() */
#include <net/if.h>             /* TAP support */
#else
#include <linux/socket.h>       /* AF_UNIX, SOCK_RAW, etc */
#include <netinet/in.h>         /* in_addr_t, etc */
#include <arpa/inet.h>          /* inet_addr() */
#include <string.h>             /* strerror() */
#include <netdb.h>              /* inet_pton() */
#include <openssl/rand.h>       /* RAND_seed() */
#include <linux/if.h>           /* TAP support */
#include <linux/if_tun.h>       /* TAP support */
#endif

#include <hip/hip_version.h>
#include <hip/hip_service.h>
#include <hip/hip_types.h>
#include <hip/hip_funcs.h>
#include <hip/hip_globals.h>
#include <hip/hip_usermode.h>
#include <hip/hip_sadb.h>

extern int devname_to_index(char *dev, __u64 *mac);
extern int add_address_to_iface(struct sockaddr *addr, int plen, int if_index);
extern int set_link_params(char *dev, int mtu);
extern void add_local_hip_nameserver(__u32 ip);
extern int get_preferred_lsi(struct sockaddr *lsi);
extern int is_dns_thread_disabled();
extern int is_mobile_router();


/*
 * Globals
 */
extern int tapfd;
extern int s_esp, s_esp_udp, s_esp_udp_dg, s_esp6;

int g_state;
char tap_dev_name[16];

int init_tap()
{
#ifndef __MACOSX__
  struct ifreq ifr;
  int err;
#endif
  int tap;
  printf("init_tap()\n");


  /* Open TAP device */
  /* XXX note: for FreeBSD, should execute ifconfig before this open */
#ifdef __MACOSX__
  if ((tap = open("/dev/tap0", O_RDWR)) < 0)
    {
#else
  if ((tap = open("/dev/net/tun", O_RDWR)) < 0)
    {
#endif
      printf("Opening TAP device failed. Do you have the correct ");
      printf("module loaded (modprobe tun)?\n");
      return(-1);
    }

#ifndef __MACOSX__
  /* setup address */
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP;              /* TAP device */
  ifr.ifr_flags |= IFF_NO_PI;           /* Do not provide packet information */
  sprintf(ifr.ifr_name, "hip0");

  /* set TAP-32 status to connected */
  if ((err = ioctl(tap, TUNSETIFF, (void*)&ifr)) < 0)
    {
      close(tap);
      printf("Error setting TAP parameters.\n");
      return(-1);
    }

  strncpy(tap_dev_name, ifr.ifr_name, sizeof(tap_dev_name));
#else
  strcpy(tap_dev_name,"tap0");
#endif
  printf("Using TAP device %s.\n", tap_dev_name);

  /* The netlink socket is not available yet, so setup
   * of the tap address occurs later in post_init_tap().
   */
  return(tap);
}

void post_init_tap()
{
  int if_index;
  struct sockaddr_storage addr;
#ifdef __MACOSX__
  __u32 taplsi;
  char buff[255];
#endif

  memset(&addr, 0, sizeof(struct sockaddr_storage));
  addr.ss_family = AF_INET;

  /* this performs the equivalent of:
   * system("/sbin/ip addr add 1.0.0.1/8 broadcast 1.255.255.255 dev
   *        hip0")
   * system("/sbin/ip link set hip0 mtu 1400");
   * system("/sbin/ip link set hip0 up");
   */

  /* Get the index and MAC address of the TAP
   */
post_init_tap_retry:
  g_tap_mac = 0;       /* MAC is needed for building eth hdrs in esp_input */
  if_index = devname_to_index(tap_dev_name, &g_tap_mac);
  if (if_index < 0)
    {
      /* sometimes the TAP interface takes a second to come up */
      printf("Waiting for TAP device %s to become ready...\n",
             tap_dev_name);
      usleep(50000);
      goto post_init_tap_retry;
    }

#ifdef __MACOSX__ /* I do not know why the tap driver will not take the ioctl
                   *     so, do things the "hard" way. */
  taplsi = get_preferred_lsi(SA(&addr));
  sprintf(
    buff,
    "/sbin/ifconfig %s %u.%u.%u.%u netmask 255.0.0.0 broadcast 1.255.255.255 up",
    tap_dev_name,
    NIPQUAD(LSI4((struct sockaddr *)&addr)));
  printf("cmd = %s\n",buff);
  system(buff);
#else
  /* Add the 1.x.x.x LSI address to the TAP interface
   */
  get_preferred_lsi(SA(&addr));
  if (add_address_to_iface(SA(&addr), 8, if_index) < 0)
    {
      printf("Error setting TAP address for %s.\n", tap_dev_name);
    }
#endif
  /* Set the link MTU and flag link UP
   */
  if (set_link_params(tap_dev_name, HIP_TAP_INTERFACE_MTU) < 0)
    {
      printf("Error setting TAP link MTU, up for %s\n", tap_dev_name);
    }

#ifndef __MACOSX__
  /* Add the 2001::10/28 HIT to the TAP (must occur after link is up)
   */
  addr.ss_family = AF_INET6;
  get_preferred_lsi(SA(&addr));
  if (add_address_to_iface(SA(&addr), 28, if_index) < 0)
    {
      printf("Error setting IPv6 TAP address for %s.\n",tap_dev_name);
    }
#endif /* __MACOSX__ */

  /* Set the nameserver by adding 1.x.x.x to /etc/resolv.conf
   */
  if (!is_dns_thread_disabled())
    {
      add_local_hip_nameserver(LSI4(&addr));
    }
}

/*
 * init_hip()
 *
 * HIP Windows service initialization. Start all of the threads.
 */
void init_hip(int ac, char **av)
{
  pthread_t tunreader_thrd, esp_output_thrd, esp_input_thrd;
  pthread_t hipd_thrd, dns_thrd, status_thrd;
  pthread_t mr_thrd;
  char hipd_args[255];
  int i;
  char timestr[26];
  struct timeval time1;
  int do_daemon = 0;

  printf("%s v%s HIP daemon\n", HIP_NAME, HIP_VERSION);
  /*printf("init_hip()\n");*/

  /* get arguments for hipd */
  memset(hipd_args, 0, sizeof(hipd_args));
  if (ac > 0)
    {
      ac--, av++;
    }
  i = 0;
  while (ac > 0)
    {
      /* printf("adding arg: %s\n", *av); */
      if (i > 0)             /* add a space between parameters */
        {
          hipd_args[i++] = ' ';
        }
      snprintf(&hipd_args[i], sizeof(hipd_args) - i, "%s", *av);
      i += strlen(*av);
      if (((*av)[0] == '-') && ((*av)[1] == 'd'))
        {
          do_daemon = 1;
        }
      av++, ac--;
    }

  init_crypto();
  hip_sadb_init();
  g_state = 0;

  /*
   * Run in background as daemon.
   */
  if (do_daemon)
    {
      /* Do not fork() later in hipd_main since that is a child
       * thread. The '-d' option is still passed to hipd_main in
       * order to log output. Output from the other threads is lost;
       * they need to be converted from printf() to a logging
       * function. */
      printf("Running in background as daemon.\n");
      if (daemon(0, 0) < 0)
        {
          fprintf(stderr, "error running as daemon\n");
        }
    }

  /*
   * Kernel helpers
   */
  if (pthread_create(&status_thrd, NULL, hip_status, NULL))
    {
      printf("Error creating status thread.\n");
      exit(1);
    }

  /*
   * HIP daemon
   */
  if (pthread_create(&hipd_thrd, NULL, hipd_main, &hipd_args))
    {
      printf("Error creating HIP daemon thread.\n");
      exit(1);
    }

  /*
   * tap device
   */
  if ((tapfd = init_tap()) > 0)
    {
      printf("Initialized TAP device.\n");
    }
  else
    {
      printf("Error initializing TAP device.\n");
      exit(1);
    }

  if (pthread_create(&tunreader_thrd, NULL, tunreader, NULL))
    {
      printf("Error creating tunreader thread.\n");
      exit(1);
    }

  /*
   * ESP handlers
   */
  if (pthread_create(&esp_output_thrd, NULL, hip_esp_output, NULL))
    {
      printf("Error creating ESP output thread.\n");
      exit(1);
    }
#ifdef __MACOSX__
  if ((s_esp = init_esp_input(AF_INET, SOCK_RAW, IPPROTO_DIVERT, 5150,
                              "IPv4 divert")) < 0)
    {
      printf("Error creating IPv4 divert socket for ESP input.\n");
      exit(1);
    }
#else
  if ((s_esp = init_esp_input(AF_INET, SOCK_RAW, IPPROTO_ESP, 0,
                              "IPv4 ESP")) < 0)
    {
      printf("Error creating IPv4 ESP input socket.\n");
      exit(1);
    }
#endif
  if ((s_esp_udp = init_esp_input(AF_INET, SOCK_RAW, IPPROTO_UDP,
                                  HIP_UDP_PORT, "IPv4 UDP")) < 0)
    {
      printf("Error creating IPv4 UDP input socket.\n");
      exit(1);
    }
  /* this socket is to prevent ICMP port unreachable messages */
  if ((s_esp_udp_dg = init_esp_input(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                                     HIP_UDP_PORT, "IPv4 UDP dg")) < 0)
    {
      printf("Error creating IPv4 UDP datagram socket.\n");
      exit(1);
    }
#ifndef __MACOSX__
  if ((s_esp6 = init_esp_input(AF_INET6, SOCK_RAW, IPPROTO_ESP, 0,
                               "IPv6 ESP")) < 0)
    {
      printf("Error creating IPv6 ESP input socket.\n");
      exit(1);
    }
#endif

  if (pthread_create(&esp_input_thrd, NULL, hip_esp_input, NULL))
    {
      printf("Error creating ESP input thread.\n");
      exit(1);
    }
  hip_sleep(1);       /* Wait a sec for config */
  if (!is_dns_thread_disabled())
    {
      /* XXX hip.conf may not be loaded yet */
      if (pthread_create(&dns_thrd, NULL, hip_dns, NULL))
        {
          printf("Error creating DNS thread.\n");
          exit(1);
        }
    }

  hip_sleep(1);       /* allow thread start before printing message */
  if (is_mobile_router())
    {
      /* XXX command-line opts may not be loaded yet */
      if (pthread_create(&mr_thrd, NULL, hip_mobile_router, NULL))
        {
          printf("Error creating Mobile Router thread.\n");
          exit(1);
        }
    }
  gettimeofday(&time1, NULL);
  ctime_r(&time1.tv_sec, timestr);
  timestr[strlen(timestr) - 1] = 0;
  printf("%s  HIP threads initialization completed.\n", timestr);
  /*
   * Wait for all threads to complete
   */
  while (g_state == 0)
    {
      hip_sleep(1);
    }
  pthread_join(hipd_thrd, NULL);       /* hipd should exit first */
  hip_sadb_deinit();
  pthread_exit((void *) 0);
}

/******* MAIN ROUTINES *******/

/*
 * main()
 *
 * Main command-line routine.
 */
int main (int argc, char **argv)
{
/*
 *       if (freopen("hip_ipsec_error.log", "a", stderr) == NULL)
 *               return;
 *       if (freopen("hip_ipsec.log", "a", stdout) == NULL)
 *               return;
 *       init_hip(ac, av);
 */
  argv++, argc--;
  while (argc > 0)
    {
      if (strstr("-v-q-d-r1-p-nr-o-a-t-u-conf-mn-mr-mh-g", *argv))
        {
          argv--, argc++;
          goto start_hip;
        }
      else
        {
          print_usage();
          exit(0);
        }
      return(0);
    }     /* end while */

start_hip:
  init_hip(argc, argv);
  return(0);
}

