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
#include <dlfcn.h>
#include "authgwd.h"
#include "authserver.h"


/**************************************************************************************************
* Определяем глобальные переменные
**************************************************************************************************/
int             log_verbose      = 3;              // 0 - silent, 1 - normal, 2 - verbose, 3 - debug
int             port             = 9034;
int             timer            = 100;
int             stoptimeout      = 200;
int             selecttime       = 100;
int             floodtimer       = 20;
char *          bindaddr         = NULL;
char *          startscript      = NULL;           //скрипт выполняемый при успешной аутентификации сокета
char *          stopscript       = NULL;           //скрипт выполняемый при разрыве сокета
char *          authplugin       = NULL;           //Плагин аутентификации
int             var_keepalive    = 1;
int             var_keepidle     = 10;
int             var_keepcnt      = 2;
int             var_keepinvl     = 5;
authserver *    authsrvs;
int             authcnt;
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
* Функция установки статуса на сокет: Закрыт
**************************************************************************************************/
int set_socket_closed (psockstat * current_l, psockstat * begin_l, psockstat * end_l, fd_set * mysockfd)
{
  
 char dynrule[512];
 int clsstat;
 psockstat tmp_l;
 struct linger sclsmethod;
  
 
  sclsmethod.l_onoff=1;
  sclsmethod.l_linger=0;
  setsockopt((*current_l)->socknum, SOL_SOCKET, SO_LINGER, &sclsmethod, sizeof(sclsmethod));
  clsstat=close((*current_l)->socknum);
  FD_CLR((*current_l)->socknum, &(*mysockfd));
  if ((*current_l)->status==authed)
     {
      memset(&dynrule[0], '\0', 512);
      snprintf(dynrule, 512, "%s %s %i %s %i", stopscript, inet_ntoa((*current_l)->clentaddr), (*current_l)->socknum, (*current_l)->sockuser, (*current_l)->accesslvl);
      system(dynrule);
      if (log_verbose>0) syslog(LOG_INFO, "User %s from %s on socket %d with level %d close connection with status %d", (*current_l)->sockuser, inet_ntoa((*current_l)->clentaddr), (*current_l)->socknum, (*current_l)->accesslvl, clsstat);
      free((*current_l)->sockuser);
     }
  else
     {
      if (log_verbose>0) syslog(LOG_INFO, "User from %s on socket %d close connection with status %d", inet_ntoa((*current_l)->clentaddr), (*current_l)->socknum, clsstat);
     }
  
  tmp_l=(*current_l)->nextrec;
  if ((*current_l)->prevrec!=NULL) 
     {
      (*current_l)->prevrec->nextrec=(*current_l)->nextrec;
     }
  else
     {
      (*begin_l)=(*current_l)->nextrec;
     }

  if ((*current_l)->nextrec!=NULL)
     {
      (*current_l)->nextrec->prevrec=(*current_l)->prevrec;
     }
  else
     {
      (*end_l)=(*current_l)->prevrec;
     }
  free ((*current_l));
 (*current_l)=tmp_l;
 return 0;
 
}



/**************************************************************************************************
* Функция установки статуса на сокет: Открыт
**************************************************************************************************/


int set_socket_opened (psockstat * current_l, psockstat * begin_l, psockstat * end_l, int sockdescr)
{
  
 struct sockaddr_in rmtaddr;
 socklen_t len; 
  
  
  
  if (!(*begin_l))
     {
      (*begin_l)=calloc(1, sizeof(sockstat));
      (*begin_l)->prevrec=NULL;    
      (*begin_l)->nextrec=NULL;
      (*end_l)=(*begin_l);
     }
  else
     {
      (*end_l)->nextrec=calloc(1, sizeof(sockstat));
      (*end_l)->nextrec->nextrec=NULL;
      (*end_l)->nextrec->prevrec=(*end_l);
      (*end_l)=(*end_l)->nextrec;
     }
  
  (*end_l)->status=opened;
  (*end_l)->last_ans=time((time_t *)NULL);
  len = sizeof(rmtaddr);
  getpeername(sockdescr, (struct sockaddr*)&rmtaddr, &len);
  (*end_l)->clentaddr=rmtaddr.sin_addr;
  (*end_l)->accesslvl=0;
  (*end_l)->socknum=sockdescr;
  (*end_l)->sockuser=NULL;
 
 return 0;
 
}



/**************************************************************************************************
* Функция установки статуса на сокет: Пользователь аутентифицирован
**************************************************************************************************/

int set_socket_authed (psockstat * current_l, char * user, int acclvl)
{
  char dynrule[512];
  

  memset(&dynrule[0], '\0', 512);
  snprintf(dynrule, 512, "%s %s %i %s %i", startscript, inet_ntoa((*current_l)->clentaddr), (*current_l)->socknum, user, acclvl);
  system(dynrule);
  (*current_l)->sockuser=calloc(strlen(user)+1, sizeof(char));
  strncpy((*current_l)->sockuser, user, strlen(user));
  (*current_l)->status=authed;
  (*current_l)->last_ans=time((time_t *)NULL);
  (*current_l)->accesslvl=acclvl;
 
 return 0;
}


/**************************************************************************************************
* Конец Функция установки статуса на сокет
**************************************************************************************************/





/**************************************************************************************************
* Функция Обновления времени сокета
**************************************************************************************************/
void update_socket_status (psockstat * curr_socket)
{

 (*curr_socket)->last_ans=time((time_t *)NULL);

}
/**************************************************************************************************
* Конец Функция Обновления времени сокета
**************************************************************************************************/





int main(int argc, char **argv)
{
 fd_set                    master;                                // master file descriptor list
 fd_set                    read_fds;                              // temp file descriptor list for select()
 struct sockaddr_in        myaddr;                                // server address
 struct sockaddr_in        remoteaddr;                            // client address
 int                       fdmax;                                 // maximum file descriptor number
 int                       listener;                              // listening socket descriptor
 int                       newfd;                                 // newly accept()ed socket descriptor
 char                      buf[256];                              // buffer for client data
 int                       nbytes;                                // кол-во считанных байт из сокета
 int                       yes=1;                                 // for setsockopt() SO_REUSEADDR, below
 socklen_t                 addrlen;                               
 int                       i;                                     
 int                       k;                                     // Переменная для цикла обхода сокетов
 psockstat                 bstat_list           =NULL;            // Ссылка на массив состояний сокета
 psockstat                 estat_list           =NULL;
 psockstat                 cstat_list           =NULL;
 struct timeval            tv;
 int                       selectstatus;
 char *                    user;                                  //Переменная, хранящая имя пользователя
 char *                    pass;                                  //Переменная, хранящая пароль
 int                       accesslevel;                           //Переменная, хранящая уровень доступа
 void *                    plg_handle;                            //Ссылка на плагин

 // Read config file
 cfg_opt_t server_opts[] =
    {
     CFG_STR("authhost", "127.0.0.1", CFGF_NONE),
     CFG_INT("authport", 1645, CFGF_NONE),
     CFG_STR("authsecret", "secret", CFGF_NONE),
     CFG_INT("authtries", 3, CFGF_NONE),
     CFG_INT("authtimeout", 1, CFGF_NONE),
     CFG_END()
    };

 cfg_opt_t opts[] = {
     CFG_SIMPLE_INT("log_verbose", &log_verbose),
     CFG_SIMPLE_INT("port", &port),
     CFG_SIMPLE_INT("timer", &timer),
     CFG_SIMPLE_INT("stoptimeout", &stoptimeout),
     CFG_SIMPLE_INT("floodtimer", &floodtimer),
     CFG_SIMPLE_INT("keepalive", &var_keepalive),
     CFG_SIMPLE_INT("keepidle", &var_keepidle),
     CFG_SIMPLE_INT("keepcnt", &var_keepcnt),
     CFG_SIMPLE_INT("keepinvl", &var_keepinvl),
     CFG_SIMPLE_INT("selecttime", &selecttime),
     CFG_SIMPLE_STR("bindaddr", &bindaddr),
     CFG_SIMPLE_STR("startscript", &startscript),
     CFG_SIMPLE_STR("stopscript", &stopscript),
     CFG_SIMPLE_STR("authplugin", &authplugin),
     CFG_SEC("server", server_opts, CFGF_TITLE | CFGF_MULTI),
     CFG_END()
     };
 cfg_t *cfg, *cfg_server;
 bindaddr = strdup("0.0.0.0");
 cfg = cfg_init(opts, 0);
 cfg_parse(cfg, argc > 1 ? argv[1] : "/etc/authgwd.conf");
 //Выделяем память под хранения настроек северов
 authcnt=cfg_size(cfg, "server");
 authsrvs=calloc(authcnt, sizeof(authserver));
 if (!authsrvs)
    {
     syslog(LOG_ERR, "Can not allocate memory for radius servers array");
     exit(1);
    }
 for(k = 0; k < authcnt; k++)
    {
    cfg_server = cfg_getnsec(cfg, "server", k);
    authsrvs[k].authhost=calloc(strlen(cfg_getstr(cfg_server, "authhost"))+1, sizeof(char));
    strcpy(authsrvs[k].authhost, cfg_getstr(cfg_server, "authhost"));
    authsrvs[k].authport = cfg_getint(cfg_server, "authport");
    authsrvs[k].authsecret=calloc(strlen(cfg_getstr(cfg_server, "authsecret"))+1, sizeof(char));
    strcpy(authsrvs[k].authsecret, cfg_getstr(cfg_server, "authsecret"));
    authsrvs[k].authtries = cfg_getint(cfg_server, "authtries");
    authsrvs[k].authtimeout = cfg_getint(cfg_server, "authtimeout");
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
 
 //Загружаем плагин работы с сервером аутентификации
 int (*check_login)(const char *, const char *, int *, const int *, const struct in_addr *, const authserver *, const int *);
 plg_handle = dlopen (authplugin, RTLD_LAZY);
 if (!plg_handle) 
    {
     syslog(LOG_ERR, "Can not load plugin");
     exit(1);
    }
 check_login = dlsym(plg_handle, "checklogin");
 if(dlerror() != NULL) 
   {
    dlclose(plg_handle);
    exit(1);
   }


 

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
 if (log_verbose>0) syslog(LOG_INFO, "Binding on %s:%i",inet_ntoa(myaddr.sin_addr), port);
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
 

 for(;;) 
    { // main loop

  
  //Закрываем все сокеты с истекшим временем
     cstat_list=bstat_list;
     while (cstat_list!=NULL)
           {
            if (difftime(time((time_t *)NULL), (cstat_list->last_ans))>stoptimeout)
               {
                if (log_verbose>0) syslog(LOG_INFO, "User from %s on socket %d reset, because he is not ALIVE", inet_ntoa(cstat_list->clentaddr), cstat_list->socknum);
                set_socket_closed(&cstat_list, &bstat_list, &estat_list, &master);
               }
            else
               {
                cstat_list=cstat_list->nextrec;
               }
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
                     // Запрос на новое соединение
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
                              fdmax = newfd;
                             }
                          //добавляем сокет в массив состояний
                          set_socket_opened(&cstat_list, &bstat_list, &estat_list, newfd);
                          setsockopt(newfd, SOL_SOCKET, SO_KEEPALIVE, &var_keepalive, sizeof(int));
                          setsockopt(newfd, SOL_TCP, TCP_KEEPIDLE, &var_keepidle, sizeof(int));
                          setsockopt(newfd, SOL_TCP, TCP_KEEPINTVL, &var_keepinvl, sizeof(int));
                          setsockopt(newfd, SOL_TCP, TCP_KEEPCNT, &var_keepcnt, sizeof(int));
                          sprintf(&buf[0], "%i", timer);
                          if (send(newfd, buf, strlen(buf), 0) == -1) 
                             {
                              syslog(LOG_ERR, "Can not send key to %s on socket %d", inet_ntoa(remoteaddr.sin_addr), newfd);
                             }
                          if (log_verbose>0)
                             {
                              syslog(LOG_INFO, "New connection from %s on socket %d", inet_ntoa(remoteaddr.sin_addr), newfd);
                             }
                         }
                    } 
                 else 
                    {
                     // Пришли даннае от клиента
                     
                     //Находим нужный нам сокет в списке и работаем с ним 
                     cstat_list=bstat_list;
                     while ((cstat_list!=NULL) && (cstat_list->socknum!=i))
                       {
                        cstat_list=cstat_list->nextrec;
                       }
                     //Если не нашли сокет в списке статусов
                     if (cstat_list==NULL)
                        {
                         syslog(LOG_ERR, "Socket %d not in list. This is programm error, please contact with developer.", i);
                         exit(1);
                        }
                                         
                     
                     if ((nbytes = recv(i, buf, sizeof(buf)-1, 0)) <= 0)
                        {
                         // got error or connection closed by client
                         if (nbytes == 0) 
                            {
                             if (log_verbose>1) syslog(LOG_DEBUG, "Close query on socket %d", i);
                            } 
                         else 
                            {
                             syslog(LOG_ERR, "Receive error from %s on socket %d", inet_ntoa(cstat_list->clentaddr),i);
                            }
                         set_socket_closed(&cstat_list, &bstat_list, &estat_list, &master);
                        } 

                     else 
                        {
                         
                         
                        //Сокет открыт, пришел логин-пароль
                         if (cstat_list->status==opened && strchr(&buf[0], '@')>0)
                            {

                             //Запрос корректный, парсим переменные
                                
                                 //Если включена отладка пишем в лог файл   
                                 if (log_verbose>1) 
	                                  {
                                     syslog(LOG_DEBUG, "Userpass var: \"%s\"", buf);
                                    }
  
                                 pass = calloc(strlen(strchr(&buf[0], '@')), sizeof(char));
                                 if(!pass) 
                                   { 
                                     syslog(LOG_ERR, "Password variable allocation error");
                                   }
                                 strncpy(pass, strchr(&buf[0], '@')+1, strlen(strchr(&buf[0], '@')));
                                 
                                 user = calloc(strlen(&buf[0])-strlen(strchr(&buf[0], '@'))+1, sizeof(char));
                                 if(!user) { 
                                    syslog(LOG_ERR, "User variable allocation error");      
                                 }
                                 
                                 strncpy(user, &buf[0], strlen(&buf[0])-strlen(strchr(&buf[0], '@')));
                                 
                                 if (log_verbose>1) 
                                    {
                                    syslog(LOG_DEBUG, "User: \"%s\", Password: \"%s\"", user, pass);
                                    }
                                  
                                 switch(check_login(user, pass, &accesslevel, &i, &(cstat_list->clentaddr), authsrvs, &authcnt))
                                       {
                                        case AUTH_ACCEPT:
                                             send(i, "ACCEPT", 6, 0);
                                             set_socket_authed(&cstat_list, user, accesslevel);
                                             if (log_verbose>0) syslog(LOG_INFO, "User \"%s\" from %s on socket %d accepted with level %d", user, inet_ntoa(cstat_list->clentaddr), i, accesslevel);
                                             break;
                                        case AUTH_REJECT:
                                             send(i, "REJECT", 6, 0);
                                             if (log_verbose>0) syslog(LOG_INFO, "User \"%s\" from %s on socket %d rejected", user, inet_ntoa(cstat_list->clentaddr), i);
                                             set_socket_closed(&cstat_list, &bstat_list, &estat_list, &master);
                                             break;
                                        case AUTH_NORESPONSE:
                                             send(i, "NORESPONSE", 10, 0);
                                             if (log_verbose>0) syslog(LOG_INFO, "Radius server did not response to user from %s on socket %d make quiery",inet_ntoa(cstat_list->clentaddr), i);
                                             set_socket_closed(&cstat_list, &bstat_list, &estat_list, &master);
                                             break;
                                        default:
                                             set_socket_closed(&cstat_list, &bstat_list, &estat_list, &master);
                                             if (log_verbose>0) syslog(LOG_ERR, "Invalid plugin work");
                                             break;                                             
                                       }
                                 memset(user, '\0', strlen(user));
                                 memset(pass, '\0', strlen(pass));
                                 free(user);
                                 free(pass);                       
                                
                                }
                            
                            
                            
                            
                         
                         
                         
                        //Сокет аутентифицирован, пришло сообщение об активности
                         else if ((cstat_list->status==authed) && !strcmp(buf, "ALIVE"))
                            {
                             if (difftime(time((time_t *)NULL), cstat_list->last_ans)<floodtimer)
                                {
                                 if (log_verbose>0) syslog(LOG_INFO, "User \"%s\" from %s on socket %d makes flood", cstat_list->sockuser, inet_ntoa(cstat_list->clentaddr), i);
                                 send(i, "FLOOD", 5, 0);
                                 set_socket_closed(&cstat_list, &bstat_list, &estat_list, &master);
                                }
                             else
                                {
                                 update_socket_status(&cstat_list);
                                 if (log_verbose>2) syslog(LOG_DEBUG, "User \"%s\" from %s on socket %d sends ALIVE message", cstat_list->sockuser, inet_ntoa(cstat_list->clentaddr), i);
                                }
                            }
                            
                            
                        //В любом другом случае отвечаем о некорректности и закрываем сокет
                         else
                            {
                             send(i, "INVALID", 7, 0);
                             if (log_verbose>0) syslog(LOG_INFO, "Invalid query from %s on socket %d",inet_ntoa(cstat_list->clentaddr), i);
                             set_socket_closed(&cstat_list, &bstat_list, &estat_list, &master);
                            }
                         
                        }
                     memset(&buf[0], '\0', 255);
                    }
                }
            }
        }//end selectstatus check
    } // End main loop

 
 
 for(k = 0; k < authcnt; k++)
    {
     free(authsrvs[k].authhost);
     free(authsrvs[k].authsecret);
    }
 free(bindaddr);
 free(startscript);
 free(stopscript);
 free(authplugin);
 free(authsrvs);
 closelog();
 dlclose(plg_handle);
 return 0;
}
