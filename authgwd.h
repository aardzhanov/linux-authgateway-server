#define DAEMON_PATH "/usr/local/authgwd/"
/**************************************************************************************************
* Определяем свои типы
**************************************************************************************************/


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
                int accesslvl;
               } 
        sockstat;

typedef sockstat * psockstat;
typedef psockstat * ind_psockstat;

/**************************************************************************************************
* Конец Определяем свои типы
**************************************************************************************************/
void daemonize(void);
void update_socket_status (ind_psockstat *, int);
int set_socket_status (ind_psockstat *, int, statenum, fd_set *, char *, int);
int main(void);
