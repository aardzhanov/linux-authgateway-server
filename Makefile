default: authgwd.c
	gcc authgwd.c -o authgwd -Wall -Wl,-lconfuse,-ldl
	
debug: authgwd.c
	gcc -g authgwd.c -o authgwd -Wall -Wl,-lconfuse,-ldl
	
clean:
	rm authgwd