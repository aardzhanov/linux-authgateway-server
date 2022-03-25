#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <confuse.h>
#include <time.h>

#include "radlib.h"
#include "radlib_private.h"
#include "authgwd.h"



/**************************************************************************************************
* Определяем глобальные переменные
**************************************************************************************************/
int log_verbose=2;                  // 0 - silent, 1 - normal, 2 - debug
int port = 9034;
int timer = 100;
int stoptimeout=200;
int selecttime=100;
char *bindaddr = NULL;
char *startscript = NULL;           //скрипт выполняемый при успешной аутентификации сокета
char *stopscript = NULL;            //скрипт выполняемый при разрыве сокета
int var_keepalive=1;
int var_keepidle=10;
int var_keepcnt=2;
int var_keepinvl=5;
radserver * radsrvs;
int radcnt;
/**************************************************************************************************
* Конец Определяем глобальные переменные
**************************************************************************************************/






/**************************************************************************************************
* Функция для перехода в режиим демона
**************************************************************************************************/

void daemonize(void)
{

  pid_t pid, sid;

  // Fork off the parent process
  pid = fork();
  
  if (pid < 0) 
     {
      exit(EXIT_FAILURE);
     }

  // If we got a good PID, then we can exit the parent process.
  if (pid > 0) 
     {
      exit(EXIT_SUCCESS);
     }

  // Change the file mode mask
  umask(0);

  sid = setsid();
  if (sid < 0) 
     {
      exit(EXIT_FAILURE);
     }
     if ((chdir(DAEMON_PATH)) < 0) 
        {
         exit(EXIT_FAILURE);
        }

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

}

/**************************************************************************************************
* Конец Функция для перехода в режиим демона
**************************************************************************************************/




/**************************************************************************************************
* Функция проверки логина
**************************************************************************************************/

int checklogin(char * authrec, int sockdescr, psockstat * arr_st, fd_set * mysockfd){

 char * user;
 char * pass;
 int i;


  if (strchr(authrec, '@')<=0)
     {
      send(sockdescr, "INVALID", 7, 0);
      if (log_verbose>0) syslog(LOG_INFO, "User from %s on socket %d make invalid quiery", inet_ntoa((*arr_st)[sockdescr].clentaddr), sockdescr);
      set_socket_status(arr_st, sockdescr, closed, mysockfd, NULL);
      return -1;
     }
  
  if (log_verbose>1) 
	 {
    syslog(LOG_DEBUG, "Userpass var: \"%s\"", authrec);
   }
  
  //parsing variables
  
  pass = calloc(1, strlen(strchr(authrec, '@')));
  if(!pass) 
    { 
      syslog(LOG_ERR, "Password variable allocation error");
    }
  strncpy(pass, strchr(authrec, '@')+1, strlen(strchr(authrec, '@')));
  
  user = calloc(1,strlen(authrec)-strlen(strchr(authrec, '@'))+1);
  if(!user) { 
     syslog(LOG_ERR, "User variable allocation error");      
  }
  
  
  strncpy(user, authrec, strlen(authrec)-strlen(strchr(authrec, '@')));
  
  if (log_verbose>1) 
     {
     syslog(LOG_DEBUG, "User: \"%s\", Password: \"%s\"", user, pass);
     }
  //end parsing variables

  //Sending request on radius server
  struct rad_handle * radreq = rad_auth_open();
  for(i=0; i<radcnt; i++)
     {
      rad_add_server(radreq, radsrvs[i].radhost, radsrvs[i].radport, radsrvs[i].radsecret, radsrvs[i].radtimeout, radsrvs[i].radtries);
     }
  rad_create_request(radreq, RAD_ACCESS_REQUEST);
  rad_put_string(radreq, RAD_USER_NAME, user);
  rad_put_string(radreq, RAD_USER_PASSWORD, pass);
  switch(rad_send_request(radreq))
        {
        case RAD_ACCESS_ACCEPT:
             send(sockdescr, "ACCEPT", 6, 0);
             set_socket_status(arr_st, sockdescr, authed, mysockfd, user);
             if (log_verbose>0) syslog(LOG_INFO, "User \"%s\" from %s on socket %d accepted", user, inet_ntoa((*arr_st)[sockdescr].clentaddr), sockdescr);
             memset(user, '\0', strlen(user));
             memset(pass, '\0', strlen(pass));
             free(user);
             free(pass);
             break;
        case RAD_ACCESS_REJECT:
             send(sockdescr, "REJECT", 6, 0);
             if (log_verbose>0) syslog(LOG_INFO, "User \"%s\" from %s on socket %d rejected", user, inet_ntoa((*arr_st)[sockdescr].clentaddr), sockdescr);
             set_socket_status(arr_st, sockdescr, closed, mysockfd, NULL);
             free(user);
             free(pass);
             break;
        default:
             send(sockdescr, "NORESPONSE", 10, 0);
             if (log_verbose>0) syslog(LOG_INFO, "Radius server did not response to user from %s on socket %d make quiery",inet_ntoa((*arr_st)[sockdescr].clentaddr), sockdescr);
             set_socket_status(arr_st, sockdescr, closed, mysockfd, NULL);
             break;
        }
 rad_close(radreq);
 return 0;                    
  

}


/**************************************************************************************************
* Конец Функции проверки логина
**************************************************************************************************/



/**************************************************************************************************
* Функция установки статуса на сокет
**************************************************************************************************/
int set_socket_status (psockstat * arr_st, int sockdescr, statenum mystatus, fd_set * mysockfd, char * user)
{
 char * dynrule;
 struct linger sclsmethod;
 struct sockaddr_in rmtaddr;
 socklen_t len;
 int clsstat;

 switch(mystatus)
       {
       case closed:
            sclsmethod.l_onoff=1;
            sclsmethod.l_linger=0;
            setsockopt(sockdescr, SOL_SOCKET, SO_LINGER, &sclsmethod, sizeof(sclsmethod));
            clsstat=close(sockdescr);
            FD_CLR(sockdescr, &(*mysockfd));
            if ((*arr_st)[sockdescr].status==authed)
               {
                dynrule = malloc(250);
                if(!dynrule) 
                  { 
                   syslog(LOG_ERR, "Command variable allocation error");
                  }
                memset(dynrule, '\0', 250);
                sprintf(dynrule, "%s %s %i %s", stopscript, inet_ntoa((*arr_st)[sockdescr].clentaddr), sockdescr, (*arr_st)[sockdescr].sockuser);
                system(dynrule);
                free(dynrule);
                if (log_verbose>0) syslog(LOG_DEBUG, "User %s from %s on socket %d close connection with status %d", (*arr_st)[sockdescr].sockuser, inet_ntoa((*arr_st)[sockdescr].clentaddr), sockdescr, clsstat);
                free((*arr_st)[sockdescr].sockuser);
               }
            else
               {
                if (log_verbose>0) syslog(LOG_DEBUG, "User from %s on socket %d close connection with status %d", inet_ntoa((*arr_st)[sockdescr].clentaddr), sockdescr, clsstat);
               }
            (*arr_st)[sockdescr].status=closed;
            (*arr_st)[sockdescr].clentaddr.s_addr=0;
            break;
       case opened:
            (*arr_st)[sockdescr].status=mystatus;
            (*arr_st)[sockdescr].last_ans=time((time_t *)NULL);
            len = sizeof(rmtaddr);
            getpeername(sockdescr, (struct sockaddr*)&rmtaddr, &len);
            (*arr_st)[sockdescr].clentaddr=rmtaddr.sin_addr;
            break;
       case authed:
            dynrule = malloc(250);
            if(!dynrule) 
              { 
               syslog(LOG_ERR, "Command variable allocation error");
              }
            memset(dynrule, '\0', 250);
            sprintf(dynrule, "%s %s %i %s", startscript, inet_ntoa((*arr_st)[sockdescr].clentaddr), sockdescr, user);
            system(dynrule);
            free(dynrule);
            (*arr_st)[sockdescr].sockuser=calloc(1, strlen(user)+1);
            strncpy((*arr_st)[sockdescr].sockuser, user, strlen(user));
            (*arr_st)[sockdescr].status=mystatus;
            (*arr_st)[sockdescr].last_ans=time((time_t *)NULL);
            break;
       case listened:
            (*arr_st)[sockdescr].status=mystatus;
            (*arr_st)[sockdescr].last_ans=time((time_t *)NULL);
            break;
       }
 
 return sockdescr;

}

/**************************************************************************************************
* Конец Функция установки статуса на сокет
**************************************************************************************************/


/**************************************************************************************************
* Функция Обновления времени сокета
**************************************************************************************************/
void update_socket_status (psockstat * arr_st, int sockdescr)
{

 (*arr_st)[sockdescr].last_ans=time((time_t *)NULL);

}
/**************************************************************************************************
* Конец Функция Обновления времени сокета
**************************************************************************************************/





int main(void)
{
 fd_set master;                     // master file descriptor list
 fd_set read_fds;                   // temp file descriptor list for select()
 struct sockaddr_in myaddr;         // server address
 struct sockaddr_in remoteaddr;     // client address
 int fdmax;                         // maximum file descriptor number
 int listener;                      // listening socket descriptor
 int newfd;                         // newly accept()ed socket descriptor
 char buf[256];                     // buffer for client data
 int nbytes;                        // кол-во считанных байт из сокета
 int yes=1;                         // for setsockopt() SO_REUSEADDR, below
 socklen_t addrlen;                 
 int i, k;                          // Переменная для цикла обхода сокетов
 psockstat status_array;            // Ссылка на массив состояний сокета
 int currsock=0;
 struct timeval tv;
 int selectstatus;



 // Read config file
 cfg_opt_t server_opts[] =
    {
     CFG_STR("radhost", "127.0.0.1", CFGF_NONE),
     CFG_INT("radport", 1645, CFGF_NONE),
     CFG_STR("radsecret", "secret", CFGF_NONE),
     CFG_INT("radtries", 3, CFGF_NONE),
     CFG_INT("radtimeout", 1, CFGF_NONE),
     CFG_END()
    };

 cfg_opt_t opts[] = {
     CFG_SIMPLE_INT("log_verbose", &log_verbose),
     CFG_SIMPLE_INT("port", &port),
     CFG_SIMPLE_INT("timer", &timer),
     CFG_SIMPLE_INT("stoptimeout", &stoptimeout),
     CFG_SIMPLE_INT("keepalive", &var_keepalive),
     CFG_SIMPLE_INT("keepidle", &var_keepidle),
     CFG_SIMPLE_INT("keepcnt", &var_keepcnt),
     CFG_SIMPLE_INT("keepinvl", &var_keepinvl),
     CFG_SIMPLE_INT("selecttime", &selecttime),
     CFG_SIMPLE_STR("bindaddr", &bindaddr),
     CFG_SIMPLE_STR("startscript", &startscript),
     CFG_SIMPLE_STR("stopscript", &stopscript),
     CFG_SEC("server", server_opts, CFGF_TITLE | CFGF_MULTI),
     CFG_END()
     };
 cfg_t *cfg, *cfg_server;
 bindaddr = strdup("0.0.0.0");
 cfg = cfg_init(opts, 0);
 cfg_parse(cfg, "authgwd.conf");
 //Выделяем память под хранения настроек северов
 radcnt=cfg_size(cfg, "server");
 radsrvs=calloc(radcnt, sizeof(radserver));
 if (!radsrvs)
    {
     syslog(LOG_ERR, "Can not allocate memory for radius servers array");
     exit(1);
    }
 for(k = 0; k < radcnt; k++)
    {
    cfg_server = cfg_getnsec(cfg, "server", k);
    radsrvs[k].radhost=calloc(1, strlen(cfg_getstr(cfg_server, "radhost"))+1);
    strcpy(radsrvs[k].radhost, cfg_getstr(cfg_server, "radhost"));
    radsrvs[k].radport = cfg_getint(cfg_server, "radport");
    radsrvs[k].radsecret=calloc(1, strlen(cfg_getstr(cfg_server, "radsecret"))+1);
    strcpy(radsrvs[k].radsecret, cfg_getstr(cfg_server, "radsecret"));
    radsrvs[k].radtries = cfg_getint(cfg_server, "radtries");
    radsrvs[k].radtimeout = cfg_getint(cfg_server, "radtimeout");
    }

 cfg_free(cfg);
 // End of read config


 if (stoptimeout<=timer)
    {
     syslog(LOG_ERR, "Timer value must be great than stoptimeout. Please check your config.");
     printf("%s", "Timer value must be great than stoptimeout. Please check your config.");
     exit(1);
    }


 daemonize();

 FD_ZERO(&master);    // clear the master and temp sets
 FD_ZERO(&read_fds);

 memset(&buf[0], '\0', 255);   //Initialize buffer with \0
 
 openlog("authgwd", LOG_PID, LOG_DAEMON);                        

 // get the listener
 if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
     syslog(LOG_ERR, "Can not create listener");
     exit(1);
    }

 // lose the pesky "address already in use" error message
 if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) 
    {
     syslog(LOG_ERR, "Can not change listener properties");
     exit(1);
    }

 // bind
 myaddr.sin_family = AF_INET;
 myaddr.sin_addr.s_addr = inet_addr(bindaddr);
 myaddr.sin_port = htons(port);
 memset(&(myaddr.sin_zero), '\0', 8);
 syslog(LOG_INFO, "Binding on %s:%i",inet_ntoa(myaddr.sin_addr), port);
 if (bind(listener, (struct sockaddr *)&myaddr, sizeof(myaddr)) == -1) 
    {
     syslog(LOG_ERR, "Can not bind on %s:%i",inet_ntoa(myaddr.sin_addr), port);
     exit(1);
    }

 // listen
 if (listen(listener, 10) == -1) 
    {
     syslog(LOG_ERR, "Can not listen on %s:%i",inet_ntoa(myaddr.sin_addr), port);
     exit(1);
    }

 // add the listener to the master set
 FD_SET(listener, &master);

 // keep track of the biggest file descriptor
 fdmax = listener; // so far, it's this one
 
 //выделяем память под динамический массив с состоянием сокетов
 status_array=calloc(fdmax+1, sizeof(sockstat));
 if (!status_array)
    {
     syslog(LOG_ERR, "Can not allocate memory for status array");
     exit(1);
    }
 //Инициализируем память массива
 for (k=0; k<=fdmax; k++)
     {
      status_array[k].status=closed;
      status_array[k].last_ans=time((time_t *)NULL);
      status_array[k].clentaddr.s_addr=0;
     } 

 set_socket_status(&status_array, listener, listened, &master, NULL);
 
 for(;;) 
    { // main loop

  
  
     do {
         currsock++;
        } 
     while ( (fdmax>currsock) && !FD_ISSET(currsock, &master) );
  
  if ( (difftime(time((time_t *)NULL), status_array[currsock].last_ans)>stoptimeout) && ((status_array[currsock].status==opened) || (status_array[currsock].status==authed)))
      {
       set_socket_status(&status_array, currsock, closed, &master, NULL);
      }
  
  if (fdmax<=currsock)
     {
      currsock=0;
     }  
     

     tv.tv_sec = selecttime;
     tv.tv_usec = 0;
     read_fds = master; // copy it
     selectstatus=select(fdmax+1, &read_fds, NULL, NULL, &tv); 
     if (selectstatus == -1) 
        {
         syslog(LOG_ERR, "Error in select()");
         exit(1);
        }

     if (selectstatus>0)
        {
         // run through the existing connections looking for data to read
         for(i = 0; i <= fdmax; i++) 
            {
             if (FD_ISSET(i, &read_fds)) 
                { // we got one!!
                 
                 if (i == listener) 
                    {
                     // handle new connections
                     addrlen = sizeof(remoteaddr);
                     if ((newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen)) == -1)
                         { 
                          syslog(LOG_ERR, "Can not accept new connection from %s on socket %d", inet_ntoa(remoteaddr.sin_addr), newfd);
                         } 
                     else 
                         {
                          FD_SET(newfd, &master); // add to master set
                       
                          if (newfd > fdmax) // keep track of the maximum
                             {    
                              //Выделяем в своем массиве новую память
                              status_array=realloc(status_array, (newfd+1)*sizeof(sockstat));
                              //Инициализируем новые элементы
                              for (k=fdmax+1; k<=newfd; k++)
                                  {
                                   status_array[k].status=closed;
                                   status_array[k].last_ans=time((time_t *)NULL);
                                   status_array[k].clentaddr.s_addr=0;
                                  }                          
                              fdmax = newfd;
                             }
                          //добавляем сокет в массив состояний
                          set_socket_status(&status_array, newfd, opened, &master, NULL);
                          setsockopt(newfd, SOL_SOCKET, SO_KEEPALIVE, &var_keepalive, sizeof(int));
                          setsockopt(newfd, SOL_TCP, TCP_KEEPIDLE, &var_keepidle, sizeof(int));
                          setsockopt(newfd, SOL_TCP, TCP_KEEPINTVL, &var_keepinvl, sizeof(int));
                          setsockopt(newfd, SOL_TCP, TCP_KEEPCNT, &var_keepcnt, sizeof(int));
                          sprintf(&buf[0], "%i", timer);
                          if (send(newfd, buf, strlen(buf), 0) == -1) 
                             {
                              syslog(LOG_ERR, "Can not send key to %s on socket %d", inet_ntoa(remoteaddr.sin_addr), newfd);
                             }
                          if (log_verbose>1)
                             {
                              syslog(LOG_DEBUG, "New connection from %s on socket %d", inet_ntoa(remoteaddr.sin_addr), newfd);
                             }
                         }
                    } 
                 else 
                    {
                     // handle data from a client
                                         
                     if ((nbytes = recv(i, buf, sizeof(buf)-1, 0)) <= 0)
                        {
                         // got error or connection closed by client
                         if (nbytes == 0) 
                            {
                             if (log_verbose>1)
                                {
                                 syslog(LOG_DEBUG, "Close query on socket %d", i);
                                }
                            } 
                         else 
                            {
                             syslog(LOG_ERR, "Receive error from %s on socket %d", inet_ntoa(status_array[i].clentaddr),i);
                            }

                         set_socket_status(&status_array, i, closed, &master, NULL);
                        } 
                     else 
                        {
                        
                         if (status_array[i].status==opened)
                            {
                             checklogin(&buf[0], i, &status_array, &master);
                            }
                         else if ((status_array[i].status==authed) && !strcmp(buf, "ALIVE"))
                            {
                             update_socket_status(&status_array, i);
                            }
                         else
                            {
                             send(i, "INCORRECTMSG", 12, 0);
                             set_socket_status(&status_array, i, closed, &master, NULL);
                            }
                         
                        }
                     memset(&buf[0], '\0', 255);
                    }
                }
            }
        }//end selectstatus check
    } // End main loop

 closelog();
 return 0;
}
