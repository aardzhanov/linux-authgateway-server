#define DAEMON_PATH "/usr/local/authgwd/"
/**************************************************************************************************
* ���������� ���� ����
**************************************************************************************************/
typedef struct struct_radserver
{
  char * radhost;
  int    radport;
  char * radsecret;
  int    radtries;
  int    radtimeout;
} radserver;


typedef enum stat_enum
             {
              opened,
              authed,
              closed,
              listened
             } 
        statenum;

typedef struct sock_stat_struc
               {
                time_t last_ans;
                char * sockuser;
                statenum status;
                struct in_addr clentaddr;
               } 
        sockstat;

typedef sockstat * psockstat;

/**************************************************************************************************
* ����� ���������� ���� ����
**************************************************************************************************/
int set_socket_status (psockstat *, int, statenum, fd_set *, char *);
