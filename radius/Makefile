default: plg_radius_pap.c radlib.c md5.c
	gcc -fPIC plg_radius_pap.c radlib.c md5.c -Wall -shared -o plg_radius_pap.so
	
debug: plg_radius_pap.c radlib.c md5.c
	gcc -fPIC -g plg_radius_pap.c radlib.c md5.c -Wall -shared -o plg_radius_pap.so
	
clean:
	rm plg_radius_pap.so