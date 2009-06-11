INC=-I../../include -I/usr/include/libxml2
# -I/local/pkgs/opensc-0.9.6/include 

all: libhipcfg.so.0

libhipcfg.so.0: ../cfg-common/hip_cfg.cpp hip_cfg_ldap.cpp
	c++ ${INC} -c -MD -fPIC -g -Wall -Woverloaded-virtual -Wcast-qual ../cfg-common/hip_cfg.cpp hip_cfg_ldap.cpp
	g++ -g  -shared -Wl,-soname,libhipcfg.so.0 -o libhipcfg.so.0 hip_cfg_ldap.o hip_cfg.o -lc -lxml2 -L/usr/local/lib -lldapcpp -lldap -L/local/pkgs/opensc-0.9.6/lib -lopensc 
	ln -sf libhipcfg.so.0 libhipcfg.so

clean:
	rm -f libhipcfg.so libhipcfg.so.0 hip_cfg.d hip_cfg_ldap.d
	rm -f *.o
