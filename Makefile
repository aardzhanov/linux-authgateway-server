default: authgwd.c radlib.c md5.c
	gcc authgwd.c radlib.c md5.c -o authgwd -Wall -Wl,-lconfuse

debug: authgwd.c radlib.c md5.c
	gcc -g authgwd.c radlib.c md5.c -o authgwd -Wall -Wl,-lconfuse
	
clean:
	rm authgwd