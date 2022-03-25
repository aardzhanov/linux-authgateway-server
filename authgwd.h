#define DAEMON_PATH "/usr/sbin/"
/**************************************************************************************************
* Определяем свои типы
**************************************************************************************************/


typedef enum stat_enum
             {
              opened,
              authed,
              admin
             } 
        statenum;

typedef struct sock_stat_descr
               {
                char * sockuser;
                struct in_addr clentaddr;
                int accesslvl;
               }
        sockdescr;

typedef struct sock_stat_struc
               {
                statenum status;
                int socknum;
                time_t last_ans;
                sockdescr * socket_data;
                struct sock_stat_struc * nextrec;
                struct sock_stat_struc * prevrec;
               } 
        sockstat;

typedef sockstat * psockstat;

/**************************************************************************************************
* Конец Определяем свои типы
**************************************************************************************************/
void daemonize(void);
void update_socket_status (psockstat *);
int set_socket_closed (psockstat * , psockstat * , psockstat *, fd_set * );
int set_socket_opened (psockstat * , psockstat * , psockstat *, int );
int set_socket_authed (psockstat * , char * , int );
int set_socket_admin (psockstat * , psockstat * , psockstat *, int );
psockstat get_socket_by_id(psockstat *, psockstat *, int );
int main(int, char **);
