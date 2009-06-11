#!/usr/local/sbin/setkey -f
flush;
spdflush;

spdadd ::/0 ::/0 icmp6 -P in none;
spdadd ::/0 ::/0 icmp6 -P out none;

spdadd dead:2::1 dead:2::2 any -P out ipsec
	hip/transport//require;

