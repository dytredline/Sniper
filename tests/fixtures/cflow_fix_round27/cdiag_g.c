#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
static int qp(const char*query,const char*key,char*value,size_t vs){char search[64];const char*p;snprintf(search,sizeof search,"%s=",key);p=strstr(query,search);if(!p)return 0;p+=strlen(search);size_t len=strcspn(p,"&");if(len>=vs)len=vs-1;memcpy(value,p,len);value[len]='\0';return 1;}
static void handle(int fd,const char*q){char h[256];char cmd[600];if(!q||!qp(q,"host",h,sizeof h))return;snprintf(cmd,sizeof cmd,"ping -c1 %s",h);FILE*f=popen(cmd,"r");(void)f;(void)fd;}
int main(void){int s=socket(2,1,0);char buf[512];int c=accept(s,0,0);ssize_t n=read(c,buf,511);buf[n]=0;handle(c,strchr(buf,'?'));return 0;}
