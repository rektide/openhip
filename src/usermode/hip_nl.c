/* -*- Mode:cc-mode; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* vim: set ai sw=2 ts=2 et cindent cino={1s: */
/*
 * Host Identity Protocol
 * Copyright (c) 2005-2012 the Boeing Company
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
 *  \file  hip_nl.c
 *
 *  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  User-mode minimal Netlink sockets layer
 *
 */
#ifdef __WIN32__
#include <win32/types.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <io.h>
#else
#include <windows.h>
#include <w32api/iphlpapi.h>
#include <unistd.h>
#include <pthread.h>            /* phread_exit() */
#endif
#include <stdio.h>              /* printf() */
#include <string.h>             /* strerror() */
#include <errno.h>              /* errno */
#include <hip/hip_service.h>
#include <hip/hip_types.h>
#include <hip/hip_sadb.h>               /* access to SADB */
#include <win32/netlink.h>

/*
 * Globals
 */
int netlsp[2] = { -1, -1 };
extern __u32 g_tap_lsi;

/*
 * Local function declarations
 */
void readIpAddrTable(PMIB_IPADDRTABLE *pTable);
int checkIpAddrTableChanges(PMIB_IPADDRTABLE pNew, PMIB_IPADDRTABLE pOld);
int netlink_send_addr(int add_del, DWORD addr, DWORD ifindex);
int sendIpAddrTable(PMIB_IPADDRTABLE pTable);

/*
 * hip_netlink()
 *
 * A simple rtnetlink socket emulation layer, acts as the kernel side
 * of netlink sockets, for providing address updates to the HIP daemon.
 *
 */
#ifdef __WIN32__
void hip_netlink(void *arg)
#else
void *hip_netlink(void *arg)
#endif
{
  int err;
  char buff[1024];
  PMIB_IPADDRTABLE pTable, pTableOld;
  fd_set read_fdset;
  struct timeval timeout;

  /* note that this would be cleaner with the libiphlpapi.a function:
   *  ret = NotifyAddrChange(&hand, &overlap);
   *  which is not currently supported by Cygwin/mingw
   */
  printf("hip_netlink() thread started...\n");
  if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, netlsp))
    {
      printf("hip_netlink() - socketpair() failed: %s\n",
             strerror(errno));
      fflush(stdout);
#ifdef __WIN32__
      return;
#else
      return(NULL);
#endif
    }

  pTable = NULL;
  pTableOld = NULL;

  while (g_state == 0)
    {
      readIpAddrTable(&pTable);
      if (!pTableOld)             /* first loop, set pTableOld */
        {
          pTableOld = pTable;
          pTable = NULL;
        }
      if (checkIpAddrTableChanges(pTable, pTableOld))
        {
          /* save newly-changed table */
          free(pTableOld);
          pTableOld = pTable;
          pTable = NULL;
        }
      FD_ZERO(&read_fdset);
      FD_SET((unsigned)netlsp[0], &read_fdset);
#ifdef __WIN32__
      Sleep(500);
#else
      timeout.tv_sec = 0;
      timeout.tv_usec = 500000;           /* refresh every 0.5 seconds */
      select(0, NULL, NULL, NULL, &timeout);
#endif
      timeout.tv_sec = 0;
      timeout.tv_usec = 0;

      if ((err = select((netlsp[0] + 1), &read_fdset,
                        NULL, NULL, &timeout) < 0))
        {
          if (errno == EINTR)
            {
              continue;
            }
          printf("hip_netlink(): select() error: %s.\n",
                 strerror(errno));
          /* } else if (err == 0) { */
        }
      else if (FD_ISSET(netlsp[0], &read_fdset))
        {
#ifdef __WIN32__
          if ((err =
                 recv(netlsp[0], buff, sizeof(buff),
                      0)) < 0)
            {
#else
          if ((err = read(netlsp[0], buff, sizeof(buff))) < 0)
            {
#endif
              if (errno == EINTR)
                {
                  continue;
                }
              printf("Netlink read error: %s\n",
                     strerror(errno));
              continue;
            }
          if (((struct nlmsghdr*)buff)->nlmsg_type ==
              RTM_GETADDR)
            {
              /* send dump of IP address table */
              sendIpAddrTable(pTableOld);
            }
          else
            {
              printf("Received unknown netlink message");
              printf("type %d, ignoring.\n",
                     ((struct nlmsghdr*)buff)->nlmsg_type);
            }
        }

    }

  printf("hip_netlink() thread shutdown.\n");
  fflush(stdout);
#ifndef __WIN32__
  pthread_exit((void *) 0);
  return(NULL);
#endif
}

void readIpAddrTable(PMIB_IPADDRTABLE *pTable)
{
  DWORD size = 0, ret;

  if (*pTable == NULL)
    {
      *pTable = (MIB_IPADDRTABLE*) malloc(sizeof(MIB_IPADDRTABLE));
    }
  if (GetIpAddrTable(*pTable, &size, 0) ==
      ERROR_INSUFFICIENT_BUFFER)
    {
      free(*pTable);
      *pTable = (MIB_IPADDRTABLE*) malloc(size);
    }

  if ((ret = GetIpAddrTable(*pTable, &size, 0)) == NO_ERROR)
    {
    }
}

/* typedef struct _MIB_IPADDRTABLE { */
/*  DWORD dwNumEntries; */
/*    MIB_IPADDRROW table[ANY_SIZE]; */
/* } MIB_IPADDRTABLE, */
/*    *PMIB_IPADDRTABLE; */
/* typedef struct _MIB_IPADDRROW { */
/*  DWORD dwAddr;		// IP Address */
/*  DWORDIF_INDEX dwIndex;      // Interface index */
/*  DWORD dwMask; */
/*  DWORD dwBCastAddr; */
/*  DWORD dwReasmSize; */
/*  unsigned short unused1; */
/*  unsigned short wType;	// IP address type/state */
/* } MIB_IPADDRROW, */
/* *PMIB_IPADDRROW; */
/* */
#define MIB_IPADDR_PRIMARY 0x0001       /* Primary IP address */
#define MIB_IPADDR_DYNAMIC 0x0004       /* Dynamic IP address */
#define MIB_IPADDR_DISCONNECTED 0x0008  /* Address is on disconnected iface */
#define MIB_IPADDR_DELETED 0x0040       /* Address is being deleted */
#define MIB_IPADDR_TRANSIENT 0x0080     /* Transient Address */


int checkIpAddrTableChanges(PMIB_IPADDRTABLE pNew, PMIB_IPADDRTABLE pOld)
{
  enum {
    IP_ADD,
    IP_DEL,
    IP_CHG,
  };
  int i, max, ret = 0;

  if (!pNew || !pOld)
    {
      return(0);
    }

  max = (pNew->dwNumEntries > pOld->dwNumEntries) ? pNew->dwNumEntries :
        pOld->dwNumEntries;

  /* printf("IP table: ["); */
  for (i = 0; i < max; i++)
    {
      /* printf("%u.%u.%u.%u(%d) ", NIPQUAD(pNew->table[i].dwAddr), */
      /*	(int)pNew->table[i].dwIndex); */
#ifdef __WIN32__
      if ((pNew->table[i].dwAddr != pOld->table[i].dwAddr) ||
          (pNew->table[i].wType != pOld->table[i].wType))
        {
          if ((pNew->table[i].wType & MIB_IPADDR_DELETED) ||
              ((pNew->table[i].wType &
                MIB_IPADDR_DISCONNECTED)))
            {
              netlink_send_addr(1, pOld->table[i].dwAddr,
                                pOld->table[i].dwIndex);
            }
#else
      if ((pNew->table[i].dwAddr != pOld->table[i].dwAddr) ||
          (pNew->table[i].unused2 != pOld->table[i].unused2))
        {
          /* unused2 is wType */
          /* Address deleted due to flags */
          if ((pNew->table[i].unused2 & MIB_IPADDR_DELETED) ||
              ((pNew->table[i].unused2 &
                MIB_IPADDR_DISCONNECTED)))
            {
              netlink_send_addr(1, pOld->table[i].dwAddr,
                                pOld->table[i].dwIndex);
            }
#endif
          /* Address deleted, replaced by 0.0.0.0 */
          else if ((pNew->table[i].dwAddr == 0) &&
                   (pOld->table[i].dwAddr) &&
                   (pOld->table[i].dwIndex ==
                    pNew->table[i].dwIndex))
            {
              netlink_send_addr(1, pOld->table[i].dwAddr,
                                pOld->table[i].dwIndex);
            }
          /* New address */
          else
            {
              /* first delete old address, if any */
              if ((pOld->table[i].dwAddr) &&
                  (pOld->table[i].dwIndex ==
                   pNew->table[i].dwIndex))
                {
                  netlink_send_addr(
                    1,
                    pOld->table[i].dwAddr,
                    pOld->table[i].
                    dwIndex);
                }
              /* send new address */
              netlink_send_addr(0, pNew->table[i].dwAddr,
                                pNew->table[i].dwIndex);
            }
          ret = 1;
        }
    }
  /* printf("]\n"); */
  return(ret);
}

/*
 * 0 = add, 1 = deleted
 */
int netlink_send_addr(int add_del, DWORD addr, DWORD ifindex)
{
  char buff[512];
  int len;
  struct nlmsghdr *msg;
  struct ifaddrmsg *ifa;
  struct rtattr *rta;
  __u32 *p_addr;

  /* ignore 0.0.0.0 and 1.x.x.x */
  if ((addr == 0) || (addr == g_tap_lsi))
    {
      return(0);
    }

  /* printf("Address %u.%u.%u.%u has been ", NIPQUAD(addr));
   *  printf("%s.\n", add_del ? "deleted" : "added"); */

  /* netlink message header */
  memset(buff, 0, sizeof(buff));
  msg = (struct nlmsghdr*) &buff[0];
  len = NLMSG_LENGTH( sizeof(struct ifaddrmsg) + sizeof(struct rtattr) +
                      sizeof(__u32));
  msg->nlmsg_len = NLMSG_ALIGN(len);
  msg->nlmsg_type = add_del ? RTM_DELADDR : RTM_NEWADDR;
  msg->nlmsg_flags = 0;
  msg->nlmsg_seq = 0;
  msg->nlmsg_pid = 0;

  /* interface address message */
  ifa = (struct ifaddrmsg*) NLMSG_DATA(msg);
  ifa->ifa_family = AF_INET;
  ifa->ifa_prefixlen = 32;
  ifa->ifa_flags = IFA_F_PERMANENT;
  ifa->ifa_scope = IFA_LOCAL;
  ifa->ifa_index = ifindex;

  /* route attributes */
  rta = IFA_RTA(ifa);
  rta->rta_len = RTA_LENGTH(sizeof(__u32));
  rta->rta_type = IFA_LOCAL;
  p_addr = (__u32*)(rta + 1);
  *p_addr = addr;       /* host byte order */

#ifdef __WIN32__
  if (send(netlsp[0], buff, len, 0) < 0)
    {
#else
  if (write(netlsp[0], buff, len) < 0)
    {
#endif
      printf("netlink_send_addr() write error: %s", strerror(errno));
      return(-1);
    }

  return(0);
}

int sendIpAddrTable(PMIB_IPADDRTABLE pTable)
{
  char buff[1024];
  int len, total_len = 0, status, i;
  struct nlmsghdr *msg;
  struct ifaddrmsg *ifa;
  struct rtattr *rta;
  __u32 *p_addr;

  if (!pTable)
    {
      return(-1);
    }

  memset(buff, 0, sizeof(buff));
  status = sizeof(buff);
  len = NLMSG_LENGTH( sizeof(struct ifaddrmsg) + sizeof(struct rtattr) +
                      sizeof(__u32));
  msg = (struct nlmsghdr *) buff;
  /* due to timing, 1.0.0.1 is not in Window's IP table yet,
   * but is needed by hipd for the ACQUIRE, so here we add
   * it manually */
  msg->nlmsg_len = NLMSG_ALIGN(len);
  total_len += len;
  msg->nlmsg_type = NLMSG_NOOP;
  msg->nlmsg_flags = 0;
  msg->nlmsg_seq = 0;
  msg->nlmsg_pid = 0;
  ifa = (struct ifaddrmsg*) NLMSG_DATA(msg);
  ifa->ifa_family = AF_INET;
  ifa->ifa_prefixlen = 32;
  ifa->ifa_flags = IFA_F_PERMANENT;
  ifa->ifa_scope = IFA_LOCAL;
  ifa->ifa_index = 65542;
  rta = IFA_RTA(ifa);
  rta->rta_len = RTA_LENGTH(sizeof(__u32));
  rta->rta_type = IFA_LOCAL;
  p_addr = (__u32*)(rta + 1);
  *p_addr = g_tap_lsi;
  msg = NLMSG_NEXT(msg, status);
  /* step through IP address table and add to netlink dump message */
  for (i = 0; i < (int)pTable->dwNumEntries; i++)
    {
      /* omit 0.0.0.0; (1.0.0.1 is needed for ACQUIRE mechanism) */
      if (pTable->table[i].dwAddr == 0)
        {
          continue;
        }

      msg->nlmsg_len = NLMSG_ALIGN(len);
      total_len += len;
      msg->nlmsg_type = NLMSG_NOOP;
      msg->nlmsg_flags = 0;
      msg->nlmsg_seq = 0;
      msg->nlmsg_pid = 0;

      /* interface address message */
      ifa = (struct ifaddrmsg*) NLMSG_DATA(msg);
      ifa->ifa_family = AF_INET;
      ifa->ifa_prefixlen = 32;
      ifa->ifa_flags = IFA_F_PERMANENT;
      ifa->ifa_scope = IFA_LOCAL;
      ifa->ifa_index = pTable->table[i].dwIndex;

      /* route attributes */
      rta = IFA_RTA(ifa);
      rta->rta_len = RTA_LENGTH(sizeof(__u32));
      rta->rta_type = IFA_LOCAL;
      p_addr = (__u32*)(rta + 1);
      *p_addr = pTable->table[i].dwAddr;

      msg = NLMSG_NEXT(msg, status);
    }

  /* finish with a done message */
  msg->nlmsg_len = NLMSG_LENGTH(0);
  msg->nlmsg_type = NLMSG_DONE;
  msg->nlmsg_flags = 0;
  msg->nlmsg_seq = 0;
  msg->nlmsg_pid = 0;
  total_len += msg->nlmsg_len;

#ifdef __WIN32__
  send(netlsp[0], buff, total_len, 0);
#else
  write(netlsp[0], buff, total_len);
#endif
  return(total_len);
}

