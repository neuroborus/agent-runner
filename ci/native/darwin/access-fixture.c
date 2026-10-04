/* External CI only. Output is diagnostic; protected native readers own proof.
 * Positive controls/objects are separately admitted and receipted by setup. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <poll.h>
#include <semaphore.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
static void need(int ok) { if (!ok) _exit(126); }
static unsigned port(const char *text) {
  char *end; errno = 0; unsigned long value = strtoul(text, &end, 10);
  need(*text && !errno && !*end && value <= 65535); return (unsigned)value;
}
static void acknowledge(void) { char value; need(read(0, &value, 1) == 1 && value == 'P'); }
static int wait_read(int fd) {
  struct pollfd event = {.fd=fd,.events=POLLIN};
  if (poll(&event, 1, 5000) != 1) {errno=ETIMEDOUT; return -1;}
  return 0;
}
static socklen_t address(struct sockaddr_storage *storage, int family, const char *text, unsigned value) {
  memset(storage, 0, sizeof(*storage));
  if (family == AF_INET) {
    struct sockaddr_in *a = (void *)storage; a->sin_len=sizeof(*a); a->sin_family=family;
    a->sin_port=htons(value); need(inet_pton(family,text,&a->sin_addr) == 1); return sizeof(*a);
  }
  struct sockaddr_in6 *a = (void *)storage; a->sin6_len=sizeof(*a); a->sin6_family=family;
  a->sin6_port=htons(value); need(inet_pton(family,text,&a->sin6_addr) == 1); return sizeof(*a);
}
static int network(const char *op, const char *target, unsigned remote, unsigned local, const char *nonce) {
  int family=strstr(op,"6") ? AF_INET6 : AF_INET, type=strstr(op,"udp") ? SOCK_DGRAM : SOCK_STREAM;
  struct sockaddr_storage destination, source;
  socklen_t length=address(&destination,family,target,remote);
  int fd=socket(family,type,0); if (fd < 0) return -1;
  if (family == AF_INET6) {int one=1; if (setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one))) return -1;}
  int flags=fcntl(fd,F_GETFL); need(flags >= 0 && !fcntl(fd,F_SETFL,flags | O_NONBLOCK));
  if (strstr(op,"listen")) {
    if (bind(fd,(struct sockaddr *)&destination,length) || (type == SOCK_STREAM && listen(fd,1))) return -1;
    printf("{\"nonce\":\"%s\",\"ready\":true}\n",nonce); fflush(stdout); acknowledge();
    if (wait_read(fd)) return -1;
    if (type == SOCK_STREAM) {int connected=accept(fd,NULL,NULL); if (connected < 0) return -1; close(fd); fd=connected;}
    int acceptedFlags=fcntl(fd,F_GETFL); need(acceptedFlags >= 0 && !fcntl(fd,F_SETFL,acceptedFlags & ~O_NONBLOCK));
    socklen_t size=sizeof(source); char bytes[33];
    struct timeval timeout={.tv_sec=5}; need(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) &&
      !setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)));
    ssize_t count=type == SOCK_STREAM ? recv(fd,bytes,32,MSG_WAITALL) :
      recvfrom(fd,bytes,sizeof(bytes),0,(struct sockaddr *)&source,&size);
    need(count == 32 && !memcmp(bytes,nonce,32));
    ssize_t sent=type == SOCK_STREAM ? send(fd,bytes,32,0) : sendto(fd,bytes,32,0,(struct sockaddr *)&source,size);
    need(sent == 32); close(fd); return 0;
  }
  socklen_t sourceLength=address(&source,family,family == AF_INET ? "127.0.0.1" : "::1",local);
  if (bind(fd,(struct sockaddr *)&source,sourceLength)) return -1;
  int result=connect(fd,(struct sockaddr *)&destination,length);
  if (result && errno == EINPROGRESS) {
    struct pollfd event={.fd=fd,.events=POLLOUT};
    if (poll(&event,1,5000) != 1) {errno=ETIMEDOUT; return -1;}
    int error; socklen_t size=sizeof(error);
    if (getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)) return -1;
    if (error) {errno=error; return -1;}
  } else if (result) return -1;
  need(!fcntl(fd,F_SETFL,flags));
  struct timeval timeout={.tv_sec=5}; need(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) &&
    !setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)));
  if (send(fd,nonce,32,0) != 32) return -1;
  if (wait_read(fd)) return -1;
  char bytes[33]; ssize_t count=recv(fd,bytes,type == SOCK_STREAM ? 32 : sizeof(bytes),type == SOCK_STREAM ? MSG_WAITALL : 0);
  need(count == 32 && !memcmp(bytes,nonce,32)); close(fd); return 0;
}
static int pair(const char *op, const char *target, unsigned remote, unsigned local, const char *nonce) {
  /* Both endpoints inherit the admitted UID/audit session. The controller
   * independently verifies the parked listener before the second P. */
  int ready[2], release[2]; need(!pipe(ready) && !pipe(release));
  pid_t listener=fork(); need(listener >= 0);
  if (!listener) {
    close(ready[0]); close(release[1]);
    need(dup2(release[0],0) == 0 && dup2(ready[1],1) == 1);
    close(release[0]); close(ready[1]);
    char server[16]; need(snprintf(server,sizeof(server),"%.4s-listen",op) == 11);
    _exit(network(server,target,remote,local,nonce) ? 126 : 0);
  }
  close(ready[1]); close(release[0]);
  char expected[96], bytes[96];
  int length=snprintf(expected,sizeof(expected),"{\"nonce\":\"%s\",\"ready\":true}\n",nonce);
  need(length > 0 && (size_t)length < sizeof(expected));
  /* The fixed readiness frame is flushed as one bounded pipe write. Short or
   * additional data fails instead of extending the readiness deadline. */
  need(!wait_read(ready[0]) && read(ready[0],bytes,sizeof(bytes)) == length);
  need(!memcmp(bytes,expected,(size_t)length) && !close(ready[0]));
  printf("{\"nonce\":\"%s\",\"listener\":%d,\"ready\":true}\n",nonce,listener);
  fflush(stdout); acknowledge();
  need(write(release[1],"P",1) == 1 && !close(release[1]));
  int result=network(op,target,remote,local,nonce), error=errno, status;
  while (waitpid(listener,&status,0) < 0) need(errno == EINTR);
  if (!WIFEXITED(status) || WEXITSTATUS(status)) {errno=EIO; return -1;}
  errno=error; return result;
}
int main(int argc, char **argv) {
  need(argc == 6 && strlen(argv[1]) == 32 && strspn(argv[1],"0123456789abcdef") == 32 &&
    getenv("CI") && !strcmp(getenv("CI"),"true") && getenv("GITHUB_ACTIONS") &&
    !strcmp(getenv("GITHUB_ACTIONS"),"true") && getuid() > 500 && geteuid() == getuid());
  const char *nonce=argv[1], *op=argv[2], *target=argv[3];
  unsigned remote=port(argv[4]), local=port(argv[5]);
  printf("{\"nonce\":\"%s\",\"parked\":true,\"pid\":%d}\n",nonce,getpid()); fflush(stdout); acknowledge();
  int result=-1, fd=-1; errno=0;
  if (!strcmp(op,"read")) {
    fd=open(target,O_RDONLY | O_NOFOLLOW); char bytes[33];
    if (fd >= 0) {
      ssize_t count=read(fd,bytes,sizeof(bytes)); result=count < 0 ? -1 : 0;
      if (!result) {
        need(count == 32 && !memcmp(bytes,nonce,32)); bytes[32]=0;
        printf("{\"readNonce\":\"%s\"}\n",bytes);
      }
    }
  }
  else if (!strcmp(op,"write")) {fd=open(target,O_WRONLY | O_NOFOLLOW); if (fd >= 0) {char bytes[38]; snprintf(bytes,sizeof(bytes),"%s-edit",nonce); result=write(fd,bytes,37) == 37 ? 0 : -1;}}
  else if (!strcmp(op,"unlink")) result=unlink(target);
  else if (!strcmp(op,"replace")) {char source[4096]; need(strlen(target)+13 < sizeof(source)); snprintf(source,sizeof(source),"%s.replacement",target); result=rename(source,target);}
  else if (!strcmp(op,"unix")) {struct sockaddr_un a={.sun_len=sizeof(a),.sun_family=AF_UNIX}; need(strlen(target) < sizeof(a.sun_path)); strcpy(a.sun_path,target); fd=socket(AF_UNIX,SOCK_STREAM,0); if (fd >= 0) result=connect(fd,(struct sockaddr *)&a,sizeof(a));}
  else if (!strcmp(op,"mach")) {mach_port_t service=MACH_PORT_NULL; kern_return_t code=bootstrap_look_up(bootstrap_port,(char *)target,&service); result=code == KERN_SUCCESS ? 0 : -1; errno=code; if (service != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(),service);}
  else if (!strcmp(op,"shm")) {fd=shm_open(target,O_RDWR,0); if (fd >= 0) {void *memory=mmap(NULL,32,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0); if (memory != MAP_FAILED) {memcpy(memory,nonce,32); result=munmap(memory,32);}}}
  else if (!strcmp(op,"sem")) {sem_t *sem=sem_open(target,0); if (sem != SEM_FAILED) {result=sem_post(sem); sem_close(sem);}}
  else if (!strcmp(op,"sysv-shm")) {need((key_t)remote != IPC_PRIVATE); int id=shmget((key_t)remote,32,0); if (id >= 0) {void *memory=shmat(id,NULL,0); if (memory != (void *)-1) {memcpy(memory,nonce,32); result=shmdt(memory);}}}
  else if (!strcmp(op,"sysv-sem")) {need((key_t)remote != IPC_PRIVATE); int id=semget((key_t)remote,1,0); if (id >= 0) {struct sembuf change={.sem_num=0,.sem_op=1,.sem_flg=IPC_NOWAIT}; result=semop(id,&change,1);}}
  else {need(!strcmp(op,"tcp4") || !strcmp(op,"tcp6") || !strcmp(op,"udp4") || !strcmp(op,"udp6") ||
      !strcmp(op,"tcp4-pair") || !strcmp(op,"tcp6-pair") || !strcmp(op,"udp4-pair") || !strcmp(op,"udp6-pair") ||
      !strcmp(op,"tcp4-listen") || !strcmp(op,"tcp6-listen") || !strcmp(op,"udp4-listen") || !strcmp(op,"udp6-listen"));
    result=strstr(op,"-pair") ? pair(op,target,remote,local,nonce) : network(op,target,remote,local,nonce);}
  int error=result < 0 ? errno : 0; if (fd >= 0) close(fd);
  printf("{\"nonce\":\"%s\",\"result\":%d,\"nativeCode\":%d}\n",nonce,result,error);
  return 0;
}
