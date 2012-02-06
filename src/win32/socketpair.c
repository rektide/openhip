/*
 * Host Identity Protocol
 * Copyright (C) 2006 the Boeing Company
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
 *  socketpair.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 * Windows is missing the socketpair() function, this implements it.
 *
 */

#ifdef __WIN32__        /* only use where socketpair() is missing */

#include <stdio.h>              /* printf() */
#include <io.h>
#include <win32/types.h>
#include <string.h>             /* memset, etc */
#include <winsock2.h>

int socketpair(int d, int type, int protocol, unsigned int *sp)
{
  unsigned int s1, s2;
  int err;
  struct sockaddr_in addr1, addr2;
  int addr1_len, addr2_len;

  /* Only one type of socketpair is implemented here. */
  if ((d != AF_UNIX) || (type != SOCK_DGRAM) || (protocol != PF_UNIX))
    {
      return(-1);
    }
  if (sp == NULL)
    {
      return(-1);
    }

  s1 = socket(AF_INET, type, 0);
  if (s1 == INVALID_SOCKET)
    {
      return(-1);
    }

  addr1.sin_family = AF_INET;
  addr1.sin_addr.s_addr = INADDR_ANY;
  addr1.sin_port = 0;       /* bind to any available port */
  addr1_len = sizeof(addr1);

  err = bind(s1, (struct sockaddr *)&addr1, addr1_len);
  if (err < 0)
    {
      goto socketpair_error1;
    }

  err = getsockname(s1, (struct sockaddr *)&addr1, &addr1_len);
  if (err < 0)
    {
      goto socketpair_error1;
    }

  s2 = socket(AF_INET, type, 0);
  if (s2 == INVALID_SOCKET)
    {
      goto socketpair_error1;
    }

  addr2.sin_family = AF_INET;
  addr2.sin_addr.s_addr = INADDR_ANY;
  addr2.sin_port = 0;       /* bind to any available port */
  addr2_len = sizeof(addr2);

  err = bind(s2, (struct sockaddr *)&addr2, addr2_len);
  if (err < 0)
    {
      goto socketpair_error2;
    }

  err = getsockname(s2, (struct sockaddr *)&addr2, &addr2_len);
  if (err < 0)
    {
      goto socketpair_error2;
    }

  addr1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  err = connect(s2, (struct sockaddr *)&addr1, addr1_len);
  if (err < 0)
    {
      goto socketpair_error2;
    }
  err = connect(s1, (struct sockaddr *)&addr2, addr2_len);
  if (err < 0)
    {
      goto socketpair_error2;
    }

  sp[0] = s1;
  sp[1] = s2;

  return(0);
socketpair_error2:
  closesocket(s2);
socketpair_error1:
  closesocket(s1);
  return(-1);
}

#endif /* __WIN32__ */
