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
 *  \file  usermode-status.c
 *
 *  \authors	Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Usermode status reporting tool.
 */

#include <stdio.h>
#ifndef __WIN32__
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <hip/hip_types.h>
#else
#include <win32/types.h>
#endif
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#ifndef __WIN32__
#include <netinet/in.h>      /* struct sockaddr_in, etc      */
#endif

#include <hip/hip_service.h>
#include <hip/hip_status.h>

int cmd_to_code(char *cmd);
void print_help();
int read_response(int s, char *buff, int *len, int time);
void print_header(int code);
int parse_response(char *buff, int len);

typedef struct _cent {
  char *command;
  int code;
} cent;

cent commands[] = { { "threads", STAT_THREADS },
                    { "sadb", STAT_SADB },
                    { "dst", STAT_DST },
                    { "lsi", STAT_LSI },
                    { "peers", STAT_PEERS },
                    { "ids", STAT_IDS },
                    { "spi", STAT_ALL_SPI },
                    { 0, STAT_MAX },};

void parse_cmd(char *buf, char *cmd, char *parm)
{
  int i, len;

  parm[0] = '\0';
  cmd[0] = '\0';
  len = strlen(buf);
  for (i = 0; i < len; i++)
    {
      if (buf[i] == '\n')
        {
          buf[i] = '\0';
        }
    }

  len = strlen(buf);
  for (i = 0; i < len; i++)
    {
      if (buf[i] == ' ')
        {
          cmd[i] = '\0';
          if (i < len)
            {
              strcpy(parm, &buf[i + 1]);
            }
          return;
        }
      cmd[i] = buf[i];
    }
  cmd[i] = '\0';
}

int main(int argc, char **argv)
{
  int s, len, done;
  struct sockaddr_in addr;

  char cmd[128], buff[4096], cmd_buf[128], parm[128];
  struct status_tlv *request;
  int status_code;
  __u32 *parm_ptr32;

#ifdef __WIN32__
  WORD wVer;
  WSADATA wsaData;
  wVer = MAKEWORD(2,2);
  WSAStartup(wVer, &wsaData);
#endif
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(WIN_STATUS_PORT);

  if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
#ifdef __WIN32__
      printf("socket() error: %d\n", WSAGetLastError());
#else
      printf("socket() error: %s\n", strerror(errno));
#endif
      return(-1);
    }

  done = 0;

  print_help();

  while (!done)
    {
      memset(cmd, 0, sizeof(cmd));
      printf("status>");
      if (fgets(cmd_buf, sizeof(cmd_buf), stdin) == NULL)
        {
          done = 1;
          continue;
        }
      parse_cmd(cmd_buf, cmd, parm);

      /* handle exit */
      if ((strncmp(cmd, "quit",
                   4) == 0) || (strncmp(cmd, "exit", 4) == 0))
        {
          done = 1;
          continue;
        }
      else if (strncmp(cmd, "help", 4) == 0)
        {
          print_help();
          continue;
        }
      else if (cmd[0] == '\0')
        {
          continue;
        }

      if ((status_code = cmd_to_code(cmd)) < 0)
        {
          printf("Syntax error.\n");
          continue;
        }
      request = (struct status_tlv*) buff;
      request->tlv_type = htons((__u16)status_code);
      request->tlv_len = 0;

      /* optional spi parameter */
      if ((status_code == STAT_SADB) && (strlen(parm) > 0))
        {
          parm_ptr32 = (__u32*)&buff[sizeof(struct status_tlv)];
          *parm_ptr32 = htonl((__u32)(strtoul(parm, NULL, 0)));
          request->tlv_len = htons(sizeof(__u32));
        }

      len = sizeof(struct status_tlv) + ntohs(request->tlv_len);

      if ((len = sendto(s, buff, len, 0, (struct sockaddr*)&addr,
                        sizeof(addr))) < 0)
        {
          printf("Error contacting status thread.\n");
          continue;
        }
      else
        {
          len = sizeof(buff);
          if (read_response(s, buff, &len, 2) < 0)
            {
              continue;
            }
          print_header(status_code);
          parse_response(buff, len);
        }

    }
#ifdef __WIN32__
  closesocket(s);
#else
  close(s);
#endif

  return(0);

}

int cmd_to_code(char *cmd)
{
  int i;
  for (i = 0; commands[i].code < STAT_MAX; i++)
    {
      if (strncmp(cmd, commands[i].command,
                  strlen(commands[i].command)) == 0)
        {
          return(commands[i].code);
        }
    }
  return(-1);
}

void print_help()
{
  int i, width = 0;
  printf("Available commands:\n");
  for (i = 0; commands[i].code < STAT_MAX; i++)
    {
      printf("%s ", commands[i].command);
      width += strlen(commands[i].command);
      if (width > 70)
        {
          printf("\n");
        }
    }
  printf("\n");
}

int read_response(int s, char *buff, int *len, int time)
{
  struct timeval timeout;
  fd_set read_fdset;
  int err;

  FD_ZERO(&read_fdset);
  FD_SET((unsigned)s, &read_fdset);
  timeout.tv_sec = time;
  timeout.tv_usec = 0;

  if ((err = select(s + 1, &read_fdset, NULL, NULL, &timeout) < 0))
    {
      if (errno != EINTR)
        {
          printf("status select() error: %s\n", strerror(errno));
        }
      return(-1);
    }
  else if (FD_ISSET(s, &read_fdset))
    {
#ifdef __WIN32__
      if ((*len = recv(s, buff, *len, 0)) < 0)
        {
          printf("recv() error: %s\n", strerror(errno));
          return(-1);
        }
#else
      if ((*len = read(s, buff, *len)) < 0)
        {
          printf("read() error: %s\n", strerror(errno));
          return(-1);
        }
#endif
      return(0);
    }
  else
    {
      printf("(timeout waiting for response)\n");
    }
  return(-1);
}

void print_header(int code)
{
  switch (code)
    {
    case STAT_THREADS:
      printf("Threads:\n");
      break;
    case STAT_SADB:
      printf("Security Association database:\n");
      break;
    case STAT_DST:
      printf("Destination Cache Entries:\n");
      break;
    case STAT_LSI:
      printf("LSI entries:\n");
      break;
    case STAT_ALL_SPI:
      printf("SPI entries:\n");
      break;
    default:
      break;
    }
}

void print_ipv6(struct sockaddr_storage *addr)
{
  int i;
  unsigned int *p;
  if (!addr)
    {
      return;
    }
  p = (unsigned int *) &((struct sockaddr_in6 *)(addr))->sin6_addr;
  for (i = 0; i < 4; i++)
    {
      printf("%x", htonl(p[i]));
    }
}

/* PRINTPTR(data type, printf format, destination ptr, source ptr) */
#define PRINTPTR(type, fmt, a, b) a = (type*) b; printf(fmt, *a); a++;

int parse_response(char *buff, int len)
{
  struct status_tlv *r;
  int done = 0, tlv_len, count = 0, bytes, num_src = 0;
  __u16 *p16;
  __u32 *p32, ip;
  __u64 *p64;
  struct sockaddr_storage *pss;

  r = (struct status_tlv*) buff;

  while (!done)
    {
      tlv_len = ntohs(r->tlv_len);
      switch (ntohs(r->tlv_type))
        {
        case HIP_STATUS_REPLY_ERROR:
          printf("error with request\n");
          return(-1);
        case HIP_STATUS_REPLY_STRING:
          printf("%s\n", (char*)(r + 1));
          break;
        case HIP_STATUS_REPLY_SADB:
          PRINTPTR(__u32, "\tSPI: 0x%x ", p32, (r + 1));
          printf("%s ", (*p32 == 1) ? "incoming" :
                 (*p32 == 2) ? "outgoing" : "??");
          PRINTPTR(__u16, "hit_magic=0x%d ", p16, (p32 + 1));
          PRINTPTR(__u32, "mode=%d ", p32, p16);
          pss = (struct sockaddr_storage*) p32;
          ip = htonl(((struct sockaddr_in*)pss)->sin_addr.s_addr);
          printf("LSI: %u.%u.%u.%u\n", NIPQUAD(ip));
          PRINTPTR(__u32, "\ta_type=%d ", p32, (pss + 1));
          PRINTPTR(__u32, "e_type=%d ", p32, p32);
          PRINTPTR(__u32, "a_keylen=%d ", p32, p32);
          PRINTPTR(__u32, "e_keylen=%d ", p32, p32);
          PRINTPTR(__u64, "lifetime=%lld\n", p64, p32);
          PRINTPTR(__u64, "\tbytes=%lld ", p64, p64);
          PRINTPTR(__u32, "seq=%d ", p32, p64);
          /*PRINTPTR(__u32, "replay_win=%d ", p32, p32);
           *  PRINTPTR(__u32, "replay_map=%d ", p32, p32);*/
          /*iv*/
          /* save number of addresses */
          num_src = *p32;
          PRINTPTR(__u32, "#src=%d ", p32, p32);
          PRINTPTR(__u32, "#dst=%d\n", p32, p32);
          break;
        case HIP_STATUS_REPLY_ADDR:
          count = 0;
          pss = (struct sockaddr_storage*) (r + 1);
          printf("\tsrc: ");
          for (bytes = tlv_len; bytes > 0;
               bytes -= sizeof(struct sockaddr_storage))
            {
              if (count == num_src)
                {
                  printf(" dst: ");
                }
              ip =
                ((struct sockaddr_in*)pss)->sin_addr.
                s_addr;
              printf("%u.%u.%u.%u ", NIPQUAD(ip));
              count++;
              pss++;
            }
          printf("\n\n");
          break;
        case HIP_STATUS_REPLY_DST_ENTRY:
          pss = (struct sockaddr_storage*) (r + 1);
          if (pss->ss_family == AF_INET)
            {
              ip =
                ((struct sockaddr_in*)pss)->sin_addr.
                s_addr;
              printf("\taddr: %u.%u.%u.%u  ", NIPQUAD(ip));
            }
          else
            {
              printf("\taddr: ");
              print_ipv6(pss);
              printf("  ");
            }
          PRINTPTR(__u32, "spi=0x%x\n", p32, (pss + 1));
          break;
        case HIP_STATUS_REPLY_LSI_ENTRY:
          pss = (struct sockaddr_storage*) (r + 1);
          ip = ((struct sockaddr_in*)pss)->sin_addr.s_addr;
          printf("\taddr: %u.%u.%u.%u ", NIPQUAD(ip));
          pss++;
          ip = ((struct sockaddr_in*)pss)->sin_addr.s_addr;
          printf("lsi4: %u.%u.%u.%u ", NIPQUAD(ip));
          pss++;
          printf("lsi6: ");
          print_ipv6(pss);
          printf("\n ");
          PRINTPTR(__u32, "\tnum_pkt=%d ", p32, (pss + 1));
          PRINTPTR(__u32, "next_pkt=%d ", p32, p32);
          PRINTPTR(__u32, "send_pkt=%d ", p32, p32);
          PRINTPTR(__u32, "time=%d\n", p32, p32);
          break;
        case HIP_STATUS_REPLY_ALL_SPI:
          PRINTPTR(__u32, "  SPI: 0x%x\n", p32, (r + 1));
          break;
        case HIP_STATUS_REPLY_DONE:
          done = 1;
          continue;
        case HIP_STATUS_REPLY_MIN:
        case HIP_STATUS_REPLY_MAX:
        default:
          printf("error reading response (%d)\n",
                 ntohs(r->tlv_type));
          return(-1);
        }
      r = (struct status_tlv *) ((char*)(r + 1) + tlv_len);
      if ((char*)r > buff + len)
        {
          printf("response has wrong length: %d\n", tlv_len);
          return(-1);
        }

    }
  return(0);
}

