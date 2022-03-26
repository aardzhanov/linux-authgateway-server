#include "../authserver.h"
#include "../plugin.h"
#include "radlib.h"
#include "radlib_private.h"

/**************************************************************************************************
* Функция проверки логина
**************************************************************************************************/

int checklogin(const char * username, const char * password, int * acclevel, const int * socknum, const struct in_addr * clientip, const authserver * radsrvs, const int * radcnt)
{
  int                   i;
  struct rad_handle *   radreq   =  rad_auth_open();
  *acclevel=0;
  
  for(i=0; i<*radcnt; i++)
     {
      rad_add_server(radreq, radsrvs[i].authhost, radsrvs[i].authport, radsrvs[i].authsecret, radsrvs[i].authtimeout, radsrvs[i].authtries);
     }
  rad_create_request(radreq, RAD_ACCESS_REQUEST);
  rad_put_string(radreq, RAD_USER_NAME, username);
  rad_put_string(radreq, RAD_USER_PASSWORD, password);
  
  switch(rad_send_request(radreq))
        {
        case RAD_ACCESS_ACCEPT:
             rad_close(radreq);
             return AUTH_ACCEPT;
             break;
        case RAD_ACCESS_REJECT:
             rad_close(radreq);
             return AUTH_REJECT;
             break;
        default:
             rad_close(radreq);
             return AUTH_NORESPONSE;
             break;
        }

                 
  

}

/**************************************************************************************************
* Конец Функции проверки логина
**************************************************************************************************/
