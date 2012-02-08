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
 *  \file  hip_umh_main.c
 *
 *  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *            Tom Henderson <thomas.r.henderson@boeing.com>
 *
 *  \brief  User-mode preparation for main_loop() and other functions that are
 *          common to both Linux and win32 user-mode versions.
 *
 */
#include <stdio.h>           /* stderr, etc                  */
#include <string.h>          /* memset()                     */
#include <time.h>            /* time()                       */
#ifdef __WIN32__
#include <win32/types.h>
#include <process.h>
#include <io.h>
#else
#include <sys/socket.h>      /* sock(), recvmsg(), etc       */
#include <sys/time.h>        /* gettimeofday()               */
#include <unistd.h>          /* fork(), getpid()             */
#include <pthread.h>
#include <arpa/inet.h>
#endif
#include <errno.h>
#include <sys/types.h>       /* getpid() support, etc        */
#include <hip/hip_types.h>
#include <hip/hip_usermode.h>
#include <hip/hip_globals.h> /* g_state */
#include <hip/hip_funcs.h>

#ifdef __WIN32__
void hipd_main(void *args)
#else
void *hipd_main(void *args)
#endif
{
  char *argv[10];
  char *strargs;
  int argc, err;

  /* Convert the single void *args containing a string of program
   * arguments into the standard argc with argv array.
   * Must be NULL-terminated, with arguments separated by a space. */
  memset(argv, 0, sizeof(argv));
  argc = 1;
  if (args)
    {
      strargs = (char *) args;
      argv[argc] = strargs;
      if (*strargs != '\0')
        {
          argc++;
          strargs++;
        }
      /* scan string until NULL */
      while (*strargs != '\0')
        {
          if (*strargs == ' ')
            {
              *strargs = '\0';                   /* split into substrings by
                                                  *  adding NULL */
              strargs++;                   /* point to next item */
              argv[argc] = strargs;
              argc++;
              if (argc == 10)                     /* stop at end of array */
                {
                  break;
                }
            }
          strargs++;
        }
    }
  err = main_loop(argc, argv);
  if (err == -EINTR)
    {
      /* wait for signal handler shutdown,
       * otherwise program will hang */
      while (g_state == 0)
#ifdef __WIN32__
        { Sleep(1000); }
    }
  return;
#else
        { sleep(1); }
    }
  pthread_exit((void *) 0);
  return(NULL);
#endif
}

/*
 * init_esp_input()
 *
 * Perform socket() and bind() calls and return a socket.
 */
int init_esp_input(int family, int type, int proto, int port, char *msg)
{
  int s, err;
  struct sockaddr_storage local_s;
  struct sockaddr *local = SA(&local_s);

  if ((family != AF_INET) && (family != AF_INET6))
    {
      return(-1);
    }
  if ((s = socket(family, type, proto)) < 0)
    {
      printf("%s socket() error: (%d) %s\n",
             msg, errno, strerror(errno));
      return(-1);
    }

  memset(local, 0, sizeof(struct sockaddr_storage));
  local->sa_family = family;
  if (family == AF_INET)
    {
      ((struct sockaddr_in*)local)->sin_port = htons((__u16)port);
      ((struct sockaddr_in*)local)->sin_addr.s_addr = INADDR_ANY;
    }
  else
    {
      str_to_addr((__u8*)"0::0", local);
      ((struct sockaddr_in6*)local)->sin6_port = htons((__u16)port);
    }
  if ((err = bind(s, local, SALEN(local))) < 0)
    {
      printf("%s bind() error: (%d) %s\n",
             msg, errno, strerror(errno));
      return(-1);
    }

  return(s);
}

