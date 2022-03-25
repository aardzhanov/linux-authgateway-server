default: plg_radius.c radlib.c md5.c
	gcc -fPIC plg_radius.c radlib.c md5.c -Wall -shared -o plg_radius.so
	
debug: plg_radius.c radlib.c md5.c
	gcc -fPIC -g plg_radius.c radlib.c md5.c -Wall -shared -o plg_radius.so
	
clean:
	rm plg_radius.so