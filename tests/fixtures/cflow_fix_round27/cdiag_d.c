#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
static int getp(const char*q,const char*k,char*v,size_t n){const char*p=strstr(q,k);if(!p)return 0;p+=strlen(k)+1;size_t i=0;while(p[i]&&p[i]!='&'&&i+1<n){v[i]=p[i];i++;}v[i]=0;return 1;}
static void handle(const char*q){char h[256];if(!getp(q,"host",h,sizeof h))return;char cmd[600];snprintf(cmd,sizeof cmd,"ping %s",h);FILE*f=popen(cmd,"r");(void)f;}
int main(void){int s=socket(2,1,0);int c=accept(s,0,0);char buf[512];read(c,buf,511);const char*q=strchr(buf,'?');if(q)handle(q+1);return 0;}
