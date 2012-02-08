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
 *  \file  win32/types.h
 *
 *  \authors	Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 *  \brief  Replacement for asm/types.h.
 *
 */

#ifndef _WIN32_TYPES_H_
#define _WIN32_TYPES_H_

typedef unsigned char __u8;

typedef unsigned short __u16;

typedef unsigned int __u32;
typedef signed int __s32;

typedef unsigned __int64 __u64;

typedef char * caddr_t;
typedef unsigned char uint8_t;
typedef unsigned char u_int8_t;
typedef unsigned short uint16_t;
typedef unsigned short u_int16_t;
typedef unsigned int uint32_t;
typedef unsigned int u_int32_t;
typedef unsigned __int64 uint64_t;
typedef unsigned __int64 u_int64_t;

#endif
