#!/bin/sh
ldapadd -x -c -D "cn=crawler,dc=sma,dc=boeing,dc=com" -w secret <<END
dn: dc=com
objectClass: top
objectClass: domain
dc: com

dn: dc=boeing,dc=com
objectClass: top
objectClass: domain
dc: boeing

dn: dc=sma,dc=boeing,dc=com
objectClass: top
objectClass: domain
dc: sma

dn: dc=endboxes,dc=sma,dc=boeing,dc=com
objectClass: top
objectClass: domain
dc: endboxes

dn: cn=crawler,dc=sma,dc=boeing,dc=com
objectClass: top
objectClass: person
sn: endboxes
cn: crawler

dn: dc=acl,dc=sma,dc=boeing,dc=com
objectClass: top
objectClass: domain
dc: acl

dn: dc=peerAllowed,dc=acl,dc=sma,dc=boeing,dc=com
objectClass: top
objectClass: domain
dc: peerAllowed
END
