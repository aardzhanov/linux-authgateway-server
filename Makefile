default: authgwd.c
	gcc authgwd.c -o authgwd -Wall -Wl,-lconfuse,-ldl
	gcc authgwd-control.c -o authgwd-control -Wall
	
debug: authgwd.c
	gcc -g authgwd.c -o authgwd -Wall -Wl,-lconfuse,-ldl
	gcc -g authgwd-control.c -o authgwd-control -Wall

clean:
	rm authgwd
	rm authgwd-control