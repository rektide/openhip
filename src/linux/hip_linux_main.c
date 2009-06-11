/*
 * Host Identity Protocol
 * Copyright (C) 2002-06 the Boeing Company
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
 *  hip_linux_main.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * Stub program for Linux kernel version, calls main_loop().
 *
 */

extern int main_loop(int argc, char **argv);

int main(int argc, char **argv)
{
	return(main_loop(argc, argv));
}
