/* Dedicated external CI only. The protected controller supplies a disposable
 * repository, immutable Git/loader closure and independently reviewed identity.
 * The parked root helper accepts no other grant, message, file or Git flags. */
#define _DARWIN_C_SOURCE 1
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static void need(int ok) { if (!ok) _exit(126); }
static void expire(int signal) { (void)signal; _exit(124); }
static const char *git, *metadata, *workspace, *hooks, *head;
static char *environment[] = {"PATH=/nonexistent", "HOME=/nonexistent", "LANG=C", "GIT_CONFIG_NOSYSTEM=1",
  "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", NULL};
static void command(const char *const *arguments, const char *expected) {
  char hook[8192]; need(snprintf(hook,sizeof(hook),"core.hooksPath=%s",hooks) > 0);
  char *vector[40] = {(char *)git, "-c", hook, "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
    "-c", "commit.cleanup=verbatim", "-c", "core.attributesFile=/dev/null", "-c", "gc.auto=0",
    "-c", "maintenance.auto=false", "--git-dir", (char *)metadata, "--work-tree", (char *)workspace};
  int count=19; for (int i=0; arguments[i]; i++) {need(count < 39); vector[count++]=(char *)arguments[i];} vector[count]=NULL;
  int output[2]; need(!pipe(output)); pid_t child=fork(); need(child >= 0);
  if (!child) {
    close(output[0]); need(dup2(output[1],1) == 1); close(output[1]);
    int empty=open("/dev/null",O_RDWR); need(empty >= 0 && dup2(empty,0) == 0 && dup2(empty,2) == 2);
    if (empty > 2) close(empty);
    /* Independent native exec/audit readers track these trusted Git children
     * by complete identities, never by their ancestry or waitpid result alone. */
    execve(git,vector,environment); _exit(127);
  }
  need(!close(output[1])); char bytes[4096]; size_t length=0;
  while (1) {need(length < sizeof(bytes)-1); ssize_t size=read(output[0],bytes+length,sizeof(bytes)-1-length); need(size >= 0); if (!size) break; length+=(size_t)size;}
  bytes[length]=0; need(!close(output[0])); int status; need(waitpid(child,&status,0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  if (expected) need(length == strlen(expected) && !memcmp(bytes,expected,length));
}
int main(int argc, char **argv) {
  need(argc == 9 && getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 &&
    getenv("CI") && !strcmp(getenv("CI"),"true") && getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"),"true") &&
    strlen(argv[1]) == 32 && strspn(argv[1],"0123456789abcdef") == 32 && strlen(argv[6]) == 40 &&
    strspn(argv[6],"0123456789abcdef") == 40 && !strcmp(argv[7],"commit") && !strcmp(argv[8],"test(fixture): record owned edit"));
  for (int i=2; i<=5; i++) need(argv[i][0] == '/' && strlen(argv[i]) < 4096 && !strchr(argv[i],'\n'));
  git=argv[2]; metadata=argv[3]; workspace=argv[4]; hooks=argv[5]; head=argv[6];
  signal(SIGALRM,expire); alarm(25); umask(0077);
  /* Do not export inherited descriptors to Git. stdin is only the private
   * admission pipe; no provider receives it or this root executable grant. */
  struct proc_fdinfo descriptors[4096]; int size=proc_pidinfo(getpid(),PROC_PIDLISTFDS,0,descriptors,sizeof(descriptors));
  need(size > 0 && size < (int)sizeof(descriptors) && size % sizeof(descriptors[0]) == 0);
  for (size_t i=0; i<(size_t)size/sizeof(descriptors[0]); i++) if (descriptors[i].proc_fd >= 3) need(!close(descriptors[i].proc_fd));
  printf("{\"nonce\":\"%s\",\"phase\":\"ready\",\"pid\":%d}\n",argv[1],getpid()); need(!fflush(stdout));
  char acknowledgement, extra; need(read(0,&acknowledgement,1) == 1 && acknowledgement == 'P' && read(0,&extra,1) == 0);
  int directory=open(workspace,O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); need(directory >= 0 && !fchdir(directory));
  int file=openat(directory,"content.txt",O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK); struct stat info;
  need(file >= 0 && !fstat(file,&info) && S_ISREG(info.st_mode) && info.st_nlink == 1 && info.st_size == 11);
  char content[12]; need(read(file,content,sizeof(content)) == 11 && !memcmp(content,"owned edit\n",11) && !close(file) && !close(directory));
  char expected[42]; snprintf(expected,sizeof(expected),"%s\n",head);
  const char *parent[]={"rev-parse","HEAD",NULL}; command(parent,expected);
  const char *branch[]={"symbolic-ref","HEAD",NULL}; command(branch,"refs/heads/proof\n");
  const char *status[]={"status","--porcelain=v1",NULL}; command(status," M content.txt\n");
  const char *add[]={"add","--","content.txt",NULL}; command(add,NULL);
  const char *commit[]={"commit","--cleanup=verbatim","-m","test(fixture): record owned edit",NULL}; command(commit,NULL);
  printf("{\"nonce\":\"%s\",\"phase\":\"finished\",\"pid\":%d}\n",argv[1],getpid()); need(!fflush(stdout)); return 0;
}
