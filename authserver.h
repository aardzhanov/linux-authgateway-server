#define AUTH_ACCEPT 0
#define AUTH_REJECT 1
#define AUTH_NORESPONSE 2

typedef struct struct_authserver
{
  char * authhost;
  int    authport;
  char * authsecret;
  int    authtries;
  int    authtimeout;
} authserver;
