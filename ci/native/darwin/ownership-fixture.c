/* Dedicated external, signed synthetic case. No timeout establishes proof. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
static void need(int ok) { if (!ok) _exit(126); }
static void ready(const char *nonce, const char *phase, int count) {
  printf("{\"nonce\":\"%s\",\"phase\":\"%s\",\"pid\":%d,\"count\":%d}\n", nonce, phase, getpid(), count); fflush(stdout);
}
static void ack(char expected) { char value; need(read(0, &value, 1) == 1 && value == expected); }
static void fault(const char *nonce) {
  ack('B');
  if (getenv("NATIVE_OWNERSHIP_CUSTODY")) { ready(nonce, "fault-armed", 0); ack('C'); }
}
static void leaf(const char *nonce) {
  /* fork clears alarms; each fixed-custody child needs its own lifetime. */
  if (getenv("NATIVE_OWNERSHIP_CUSTODY")) alarm(150);
  char name[64]; snprintf(name, sizeof(name), "nonce-%d", getpid());
  int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  need(fd >= 0 && write(fd, nonce, 32) == 32 && !fsync(fd) && !close(fd));
  ready(nonce, "leaf", 1); for (;;) pause();
}
static void image(char **argv) {
  char *args[] = {argv[0], argv[1], "leaf", NULL}; execve(argv[0], args, environ); _exit(126);
}
int main(int argc, char **argv) {
  need(argc == 3 && strlen(argv[1]) == 32 && strspn(argv[1], "0123456789abcdef") == 32 &&
    getuid() > 500 && geteuid() == getuid());
  const char *custody = getenv("NATIVE_OWNERSHIP_CUSTODY");
  if (custody) { need(!strcmp(custody, "true")); alarm(150); }
  struct rlimit limit; need(!getrlimit(RLIMIT_NPROC, &limit) && limit.rlim_cur == 32 && limit.rlim_max == 32);
  if (!strcmp(argv[2], "leaf")) leaf(argv[1]);
  need(!strcmp(argv[2], "fork-exec") || !strcmp(argv[2], "double-fork") || !strcmp(argv[2], "reparent") ||
    !strcmp(argv[2], "cancel") || !strcmp(argv[2], "owner-loss") || !strcmp(argv[2], "helper-loss") ||
    !strcmp(argv[2], "receipt-recovery") || !strcmp(argv[2], "stale-identity") || !strcmp(argv[2], "process-limit"));
  ready(argv[1], "armed", 0); ack('A');
  if (!strcmp(argv[2], "stale-identity")) image(argv);
  if (!strcmp(argv[2], "process-limit")) {
    int count = 0;
    for (; count < 32; count++) {
      pid_t child = fork();
      if (child < 0) { need(errno == EAGAIN && count == 31); break; }
      if (!child) leaf(argv[1]);
    }
    need(count == 31); ready(argv[1], "limit", count); fault(argv[1]); for (;;) pause();
  }
  pid_t child = fork(); need(child >= 0);
  if (!child) {
    if (!strcmp(argv[2], "double-fork")) {
      pid_t grandchild = fork(); need(grandchild >= 0); if (grandchild) _exit(0);
      need(setsid() >= 0);
    }
    image(argv);
  }
  if (!strcmp(argv[2], "double-fork")) {
    int status; need(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  ready(argv[1], "parent", 1); fault(argv[1]);
  if (!strcmp(argv[2], "reparent")) return 0;
  for (;;) pause();
}
