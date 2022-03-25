#define DAEMON_PATH "/usr/sbin/"
/**************************************************************************************************
* ���������� ���� ����
**************************************************************************************************/


typedef enum stat_enum
             {
              opened,
              authed
             } 
        statenum;

typedef struct sock_stat_struc
               {
                time_t last_ans;
                char * sockuser;
                statenum status;
                struct in_addr clentaddr;
                int accesslvl;
                int socknum;
                struct sock_stat_struc * nextrec;
                struct sock_stat_struc * prevrec;
               } 
        sockstat;

typedef sockstat * psockstat;

/**************************************************************************************************
* ����� ���������� ���� ����
**************************************************************************************************/
void daemonize(void);
void update_socket_status (psockstat *);
int set_socket_closed (psockstat * , psockstat * , psockstat *, fd_set * mysockfd);
int set_socket_opened (psockstat * , psockstat * , psockstat *, int sockdescr);
int set_socket_authed (psockstat * , char * user, int acclvl);
int main(int, char **);
