#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "authgwd-control.h"




int recvtimeout(int s,  char * buf, int len, int timeout)
{

 fd_set fds;
 int n;
 struct timeval tv;
 
 FD_ZERO(&fds);
 FD_SET(s, &fds);
 
 tv.tv_sec=timeout;
 tv.tv_usec=0;
 
 n = select(s+1, &fds, NULL, NULL, &tv);
 
 if(n==0) return -2;//timeout!
 if(n==-1) return -1;//error
 return recv(s,buf,len,0);

}




int killuser(char * user, int socknum)
{
 
 char command[255];
 int rstat;
 
 memset(&command[0], '\0', 255);
 snprintf(command, 255, "close %s", user);
 if (send(socknum, command, strlen(command), 0) < 0)
    {
     printf("Writing on stream socket error\n");
    }
 memset(&command[0], '\0', 255);    
 rstat=recvtimeout(socknum, &command[0], sizeof(command)-1, 5);
 switch (rstat)
  {
   case -2: 
        printf("Timeout\n");
        break;
   case -1:
        printf("Error in select()\n");
        break;
   default:
         printf("%s\n", command);
         break;
  }
 return 0;

}


int showuserlist(int socknum)
{
 char command[86];
 int rstat;
 int count=0;
 
 if (send(socknum, "userlist", 8, 0) < 0)
    {
     printf("Writing on stream socket error\n");
    }
 
 printf("-------------------------------------------------------------------------------------\n%-10s%-17s%-31s%-10s%-10s%-7s\n-------------------------------------------------------------------------------------\n", "SOCKET:", "IP:","USER:", "LEVEL:", "TIME:", "STATUS:");
 do
   {
    memset(&command[0], '\0', 86);
    rstat=recvtimeout(socknum, &command[0], sizeof(command)-1, 500);
    if (rstat<0)
       {
        printf("Timeout\n");
        break;
       }
    else if (rstat>0)
       {
        printf("%s\n", command);
        count++;
       }
   }
 while(rstat>0);
 printf("-------------------------------------------------------------------------------------\nTOTAL: %i\n-------------------------------------------------------------------------------------\n", count);

 return 0;
}



int main(int argc, char **argv)
{
 int sock;
 struct sockaddr_un server;


 if (argc < 2) 
    {
     printf("Usage: %s <unix socket>\n", argv[0]);
     exit(1);
    }
 
 sock = socket(AF_LOCAL, SOCK_STREAM, 0);
 if (sock < 0) {
     printf("Opening stream socket error\n");
     exit(1);
    }

 bzero(&server, sizeof(server));
 server.sun_family = AF_LOCAL;
 strcpy(server.sun_path, argv[1]);

 if (connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) 
    {
     close(sock);
     printf("Connecting stream socket %s error\n", argv[1]);
     exit(1);
    }
  
	if (!strncmp("close", argv[2], 5))
	   {
	    killuser(argv[3], sock);
	   }
	else if (!strncmp("userlist", argv[2], 8))
	   {
	    showuserlist(sock);
	   }
	else
	   {
	    printf("Incorrect command or parameter");
	   }
	 
 close(sock);
 
 return 0;
}




