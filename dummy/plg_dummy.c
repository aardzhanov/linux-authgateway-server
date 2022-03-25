#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../authserver.h"
#include "../plugin.h"


/**************************************************************************************************
* Функция проверки логина
**************************************************************************************************/

int checklogin(const char * username, const char * password, int * acclevel, const int * socknum, const struct in_addr * clientip, const authserver * asrvs, const int * ascnt)
{
*acclevel=10;
FILE  *fp; 
fp = fopen("./plg_dummy.log",  "a");


if(!strcmp(username, "AcceptLogin"))
  {
   fprintf(fp, "\nUsername: %s\nPassword: %s\nAccess_level: %i\nSocketNumber: %i\nIPAddress: %s\nAuthServersCount: %i\nAction: ACCEPT\n--------------------------------------------------\n", username, password, *acclevel, *socknum, inet_ntoa(*clientip) , *ascnt);
   fclose(fp);
   return AUTH_ACCEPT;
  }
else if (!strcmp(username, "RejectLogin"))
  {
   fprintf(fp, "\nUsername: %s\nPassword: %s\nAccess_level: %i\nSocketNumber: %i\nIPAddress: %s\nAuthServersCount: %i\nAction: REJECT\n--------------------------------------------------\n", username, password, *acclevel, *socknum, inet_ntoa(*clientip) , *ascnt);
   fclose(fp);  
   return AUTH_REJECT;
  }
else
  {
   fprintf(fp, "\nUsername: %s\nPassword: %s\nAccess_level: %i\nSocketNumber: %i\nIPAddress: %s\nAuthServersCount: %i\nAction: NORESPONSE\n--------------------------------------------------\n", username, password, *acclevel, *socknum, inet_ntoa(*clientip) , *ascnt);
   fclose(fp);
   return AUTH_NORESPONSE;
  }

}

/**************************************************************************************************
* Конец Функции проверки логина
**************************************************************************************************/
