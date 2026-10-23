#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
static void handle(int fd,const char*q){char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",q);FILE*f=popen(cmd,"r");(void)f;(void)fd;}
static void route(int fd,const char*method,const char*path){const char*query;query=strchr(path,'?');if(strcmp(method,"GET")==0)handle(fd,query?query+1:NULL);}
int main(void){int s=socket(2,1,0);char buf[512];int c=accept(s,0,0);ssize_t n=read(c,buf,511);char m[16],p[256];buf[n]=0;sscanf(buf,"%15s %255s",m,p);route(c,m,p);return 0;}
