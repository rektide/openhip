#!/usr/local/sbin/setkey -f
flush;
spdflush;

spdadd 10.0.0.1 10.0.0.2 any -P out ipsec
	hip/transport//require;

