INC=-I../../include -I/usr/include/libxml2
test_spd: test_cfgapi.c hip_cfg_api.c
	gcc -Wall -g ${INC} -o test_hipcfg \
		test_cfgapi.c hip_cfg_api.c -ldl -lssl -lxml2
clean:
	rm -f *.o
	rm -f test_hipcfg
