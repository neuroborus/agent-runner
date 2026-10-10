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
#include <stdbool.h>
#include <signal.h>
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
static int retained[8], retained_count;
static int held_fd = -1, prepared_fd = -1;
static pid_t pair_pid;
static int pair_release = -1;
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
  int fd = prepared_fd; prepared_fd = -1;
  unsigned selected = strstr(op,"listen") ? remote : local;
  for (int i = 0; i < retained_count; i++) {
    struct sockaddr_storage a; socklen_t size = sizeof(a); int t; socklen_t ts = sizeof(t);
    need(!getsockname(retained[i], (void *)&a, &size) && !getsockopt(retained[i], SOL_SOCKET, SO_TYPE, &t, &ts));
    unsigned p = a.ss_family == AF_INET ? ntohs(((struct sockaddr_in *)&a)->sin_port) : ntohs(((struct sockaddr_in6 *)&a)->sin6_port);
    if (fd < 0 && a.ss_family == family && t == type && p == selected) fd = dup(retained[i]);
  }
  bool bound = fd >= 0;
  if (fd < 0) fd=socket(family,type,0); if (fd < 0) return -1;
  held_fd = fd;
  if (family == AF_INET6 && !bound) {int one=1; if (setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one))) return -1;}
  int flags=fcntl(fd,F_GETFL); need(flags >= 0 && !fcntl(fd,F_SETFL,flags | O_NONBLOCK));
  if (strstr(op,"listen")) {
    int listener_fd = fd;
    if ((!bound && bind(fd,(struct sockaddr *)&destination,length)) || (type == SOCK_STREAM && listen(fd,1))) return -1;
    if (getenv("NATIVE_ACCESS_CUSTODY")) printf("{\"nonce\":\"%s\",\"ready\":true,\"pid\":%d,\"descriptor\":%d}\n",nonce,getpid(),fd);
    else printf("{\"nonce\":\"%s\",\"ready\":true}\n",nonce); fflush(stdout); acknowledge();
    if (wait_read(fd)) return -1;
    if (type == SOCK_STREAM) {int connected=accept(fd,NULL,NULL); if (connected < 0) return -1; fd=connected;}
    int acceptedFlags=fcntl(fd,F_GETFL); need(acceptedFlags >= 0 && !fcntl(fd,F_SETFL,acceptedFlags & ~O_NONBLOCK));
    socklen_t size=sizeof(source); char bytes[33];
    struct timeval timeout={.tv_sec=5}; need(!setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) &&
      !setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)));
    ssize_t count=type == SOCK_STREAM ? recv(fd,bytes,32,MSG_WAITALL) :
      recvfrom(fd,bytes,sizeof(bytes),0,(struct sockaddr *)&source,&size);
    need(count == 32 && !memcmp(bytes,nonce,32));
    ssize_t sent=type == SOCK_STREAM ? send(fd,bytes,32,0) : sendto(fd,bytes,32,0,(struct sockaddr *)&source,size);
    need(sent == 32);
    if (getenv("NATIVE_ACCESS_CUSTODY")) acknowledge();
    if (fd != listener_fd) need(!close(listener_fd));
    close(fd); held_fd = -1; return 0;
  }
  socklen_t sourceLength=address(&source,family,family == AF_INET ? "127.0.0.1" : "::1",local);
  if (!bound && bind(fd,(struct sockaddr *)&source,sourceLength)) return -1;
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
  need(count == 32 && !memcmp(bytes,nonce,32)); return 0;
}
static int pair(const char *op, const char *target, unsigned remote, unsigned local, const char *nonce) {
  /* Both endpoints inherit the admitted UID/audit session. The controller
   * independently verifies the parked listener before the second P. */
  int ready[2], release[2]; need(!pipe(ready) && !pipe(release));
  pid_t listener=fork(); need(listener >= 0);
  if (!listener) {
    close(ready[0]); close(release[1]);
    if (prepared_fd >= 0) need(!close(prepared_fd)); prepared_fd = -1;
    need(dup2(release[0],0) == 0 && dup2(ready[1],1) == 1);
    close(release[0]); close(ready[1]);
    char server[16]; need(snprintf(server,sizeof(server),"%.4s-listen",op) == 11);
    _exit(network(server,target,remote,local,nonce) ? 126 : 0);
  }
  close(ready[1]); close(release[0]);
  char expected[256], bytes[256]; int descriptor = -1;
  int length=snprintf(expected,sizeof(expected),"{\"nonce\":\"%s\",\"ready\":true}\n",nonce);
  need(length > 0 && (size_t)length < sizeof(expected));
  /* The fixed readiness frame is flushed as one bounded pipe write. Short or
   * additional data fails instead of extending the readiness deadline. */
  need(!wait_read(ready[0])); ssize_t received = read(ready[0],bytes,sizeof(bytes) - 1); need(received > 0); bytes[received] = 0;
  if (getenv("NATIVE_ACCESS_CUSTODY")) {
    char observed[33]; int pid; need(sscanf(bytes, "{\"nonce\":\"%32[0-9a-f]\",\"ready\":true,\"pid\":%d,\"descriptor\":%d}", observed, &pid, &descriptor) == 3 && pid == listener && !strcmp(observed, nonce) && descriptor >= 0);
  } else need(received == length && !memcmp(bytes,expected,(size_t)length));
  need(!close(ready[0]));
  if (getenv("NATIVE_ACCESS_CUSTODY")) printf("{\"nonce\":\"%s\",\"listener\":%d,\"descriptor\":%d,\"ready\":true}\n",nonce,listener,descriptor);
  else printf("{\"nonce\":\"%s\",\"listener\":%d,\"ready\":true}\n",nonce,listener);
  fflush(stdout); acknowledge();
  need(write(release[1],"P",1) == 1);
  if (!getenv("NATIVE_ACCESS_CUSTODY")) need(!close(release[1]));
  int result=network(op,target,remote,local,nonce), error=errno, status;
  if (getenv("NATIVE_ACCESS_CUSTODY")) {
    pair_pid = listener; pair_release = release[1]; errno = error; return result;
  }
  while (waitpid(listener,&status,0) < 0) need(errno == EINTR);
  if (!WIFEXITED(status) || WEXITSTATUS(status)) {errno=EIO; return -1;}
  errno=error; return result;
}
static int execute(int argc, char **argv) {
  need(argc == 6 && strlen(argv[1]) == 32 && strspn(argv[1],"0123456789abcdef") == 32 &&
    getenv("CI") && !strcmp(getenv("CI"),"true") && getenv("GITHUB_ACTIONS") &&
    !strcmp(getenv("GITHUB_ACTIONS"),"true") && geteuid() == getuid() && (getuid() > 500 || (getuid() == 0 && getenv("NATIVE_ACCESS_CONTROL"))));
  /* Direct root controls and payload workers share the bounded attempt owner. */
  if (getenv("NATIVE_ACCESS_CUSTODY")) alarm(30);
  const char *nonce=argv[1], *op=argv[2], *target=argv[3];
  unsigned remote=port(argv[4]), local=port(argv[5]);
  if (getenv("NATIVE_ACCESS_CUSTODY") && (!strncmp(op, "tcp", 3) || !strncmp(op, "udp", 3))) {
    int family = strstr(op,"6") ? AF_INET6 : AF_INET, type = strstr(op,"udp") ? SOCK_DGRAM : SOCK_STREAM;
    unsigned selected = strstr(op,"listen") ? remote : local;
    for (int i = 0; i < retained_count; i++) {
      struct sockaddr_storage a; socklen_t size = sizeof(a); int t; socklen_t ts = sizeof(t);
      need(!getsockname(retained[i], (void *)&a, &size) && !getsockopt(retained[i], SOL_SOCKET, SO_TYPE, &t, &ts));
      unsigned p = a.ss_family == AF_INET ? ntohs(((struct sockaddr_in *)&a)->sin_port) : ntohs(((struct sockaddr_in6 *)&a)->sin6_port);
      if (a.ss_family == family && t == type && p == selected) prepared_fd = dup(retained[i]);
    }
    if (prepared_fd < 0) {
      prepared_fd = socket(family, type, 0); need(prepared_fd >= 0);
      if (family == AF_INET6) {int one=1; need(!setsockopt(prepared_fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one)));}
      struct sockaddr_storage a; socklen_t size = address(&a, family, strstr(op,"listen") ? target : (family == AF_INET ? "127.0.0.1" : "::1"), selected);
      need(!bind(prepared_fd, (void *)&a, size));
    }
  }
  if (getenv("NATIVE_ACCESS_CUSTODY")) printf("{\"nonce\":\"%s\",\"parked\":true,\"pid\":%d,\"descriptor\":%d}\n",nonce,getpid(),prepared_fd);
  else printf("{\"nonce\":\"%s\",\"parked\":true,\"pid\":%d}\n",nonce,getpid()); fflush(stdout); acknowledge();
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
  else if (!strcmp(op,"replace") || !strcmp(op,"parent")) {char source[4096]; need(strlen(target)+13 < sizeof(source)); snprintf(source,sizeof(source),"%s.replacement",target); result=!strcmp(op,"parent") ? rename(target,source) : rename(source,target);}
  else if (!strcmp(op,"unix")) {struct sockaddr_un a={.sun_len=sizeof(a),.sun_family=AF_UNIX}; need(strlen(target) < sizeof(a.sun_path)); strcpy(a.sun_path,target); fd=socket(AF_UNIX,SOCK_STREAM,0); if (fd >= 0) result=connect(fd,(struct sockaddr *)&a,sizeof(a));}
  else if (!strcmp(op,"mach")) {mach_port_t service=MACH_PORT_NULL; kern_return_t code=bootstrap_look_up(bootstrap_port,(char *)target,&service); result=code == KERN_SUCCESS ? 0 : -1; errno=code; if (service != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(),service);}
  else if (!strcmp(op,"shm")) {fd=shm_open(target,O_RDWR,0); if (fd >= 0) {void *memory=mmap(NULL,32,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0); if (memory != MAP_FAILED) {memcpy(memory,nonce,32); result=munmap(memory,32);}}}
  else if (!strcmp(op,"sem")) {sem_t *sem=sem_open(target,0); if (sem != SEM_FAILED) {if (getenv("NATIVE_ACCESS_CUSTODY")) result=sem_close(sem); else {result=sem_post(sem); sem_close(sem);}}}
  else if (!strcmp(op,"sysv-shm")) {need((key_t)remote != IPC_PRIVATE); int id=shmget((key_t)remote,32,0); if (id >= 0) {void *memory=shmat(id,NULL,0); if (memory != (void *)-1) {memcpy(memory,nonce,32); result=shmdt(memory);}}}
  else if (!strcmp(op,"sysv-sem")) {need((key_t)remote != IPC_PRIVATE); int id=semget((key_t)remote,1,0); if (id >= 0) {if (getenv("NATIVE_ACCESS_CUSTODY")) result=0; else {struct sembuf change={.sem_num=0,.sem_op=1,.sem_flg=IPC_NOWAIT}; result=semop(id,&change,1);}}}
  else {need(!strcmp(op,"tcp4") || !strcmp(op,"tcp6") || !strcmp(op,"udp4") || !strcmp(op,"udp6") ||
      !strcmp(op,"tcp4-pair") || !strcmp(op,"tcp6-pair") || !strcmp(op,"udp4-pair") || !strcmp(op,"udp6-pair") ||
      !strcmp(op,"tcp4-listen") || !strcmp(op,"tcp6-listen") || !strcmp(op,"udp4-listen") || !strcmp(op,"udp6-listen"));
    result=strstr(op,"-pair") ? pair(op,target,remote,local,nonce) : network(op,target,remote,local,nonce);}
  int error=result < 0 ? errno : 0; if (fd >= 0) close(fd);
  printf("{\"nonce\":\"%s\",\"result\":%d,\"nativeCode\":%d}\n",nonce,result,error); fflush(stdout);
  if (getenv("NATIVE_ACCESS_CUSTODY")) {
    acknowledge();
    if (pair_pid) {
      need(write(pair_release, "P", 1) == 1 && !close(pair_release)); int status;
      while (waitpid(pair_pid, &status, 0) < 0) need(errno == EINTR);
      need(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
  }
  if (held_fd >= 0) close(held_fd);
  return 0;
}

/* The long-lived fixture consumes only the sealed owner's finite vectors. Its
 * children inherit the admitted UID/ASID and park on both sides of each syscall.
 * Text still supplies no authority, audit event, object identity or verdict. */
int main(int argc, char **argv) {
  if (!getenv("NATIVE_ACCESS_CUSTODY") || getenv("NATIVE_ACCESS_CONTROL")) return execute(argc, argv);
  const char *fixed[] = {"", "space value", "λ雪", "'\"", "$(false); & | < > *"};
  need(argc == 6 && getuid() > 500 && geteuid() == getuid());
  for (int i = 0; i < 5; i++) need(!strcmp(argv[i + 1], fixed[i]));
  setvbuf(stdin, NULL, _IONBF, 0); alarm(420); puts("{\"phase\":\"armed\"}"); fflush(stdout);
  char rights[CMSG_SPACE(8 * sizeof(int))], flag; struct iovec io = {.iov_base = &flag, .iov_len = 1};
  struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = rights, .msg_controllen = sizeof(rights)};
  need(recvmsg(0, &message, 0) == 1 && flag == 'F' && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  need(header && !CMSG_NXTHDR(&message, header) && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(retained)));
  memcpy(retained, CMSG_DATA(header), sizeof(retained)); retained_count = 8;
  puts("{\"held\":8}"); fflush(stdout);
  char bytes[8192];
  for (;;) {
    need(fgets(bytes, sizeof(bytes), stdin) && strchr(bytes, '\n'));
    char *fields[6], *next; int n = 0;
    for (char *p = strtok_r(bytes, " \n", &next); p; p = strtok_r(NULL, " \n", &next)) { need(n < 6); fields[n++] = p; }
    need(n == 5 && strlen(fields[2]) % 2 == 0 && strlen(fields[2]) < 8192);
    char target[4096];
    for (size_t i = 0; i < strlen(fields[2]); i += 2) { unsigned byte; need(sscanf(fields[2] + i, "%2x", &byte) == 1 && byte); target[i / 2] = byte; }
    target[strlen(fields[2]) / 2] = 0;
    int channel[2], reply[2]; need(!pipe(channel) && !pipe(reply));
    pid_t worker = fork(); need(worker >= 0);
    if (!worker) {
      close(channel[1]); close(reply[0]); need(dup2(channel[0], 0) == 0 && dup2(reply[1], 1) == 1); close(channel[0]); close(reply[1]);
      char *vector[] = {argv[0], fields[0], fields[1], target, fields[3], fields[4], NULL};
      _exit(execute(6, vector));
    }
    close(channel[0]); close(reply[1]);
    FILE *stream = fdopen(reply[0], "r"); need(stream && !setvbuf(stream, NULL, _IONBF, 0));
    need(fgets(bytes, sizeof(bytes), stream)); fputs(bytes, stdout); fflush(stdout);
    /* P starts the operation; the second P releases the retained worker. */
    for (int phase = 0; phase < 2; phase++) {
      acknowledge(); need(write(channel[1], "P", 1) == 1);
      if (!phase) {
        for (;;) {
          need(fgets(bytes, sizeof(bytes), stream)); fputs(bytes, stdout); fflush(stdout);
          if (strstr(bytes, "\"ready\":true")) { acknowledge(); need(write(channel[1], "P", 1) == 1); }
          if (strstr(bytes, "\"nativeCode\":")) break;
        }
      }
    }
    int status; while (waitpid(worker, &status, 0) < 0) need(errno == EINTR);
    need(WIFEXITED(status) && WEXITSTATUS(status) == 0 && !fclose(stream) && !close(channel[1]));
    puts("{\"complete\":true}"); fflush(stdout);
  }
}
