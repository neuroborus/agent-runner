/* Untrusted ordinary-profile probe. The existing private UID/audit/Seatbelt/PF
 * launcher admits this literal image. Git exit and native decisions are joined
 * by an independent protected reader, never inferred from diagnostic output. */
#define _DARWIN_C_SOURCE 1
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void need(int ok) { if (!ok) _exit(126); }
int main(int argc, char **argv) {
  need(argc == 7 && getuid() > 500 && geteuid() == getuid() &&
    getenv("CI") && !strcmp(getenv("CI"),"true") && getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"),"true") &&
    strlen(argv[1]) == 32 && strspn(argv[1],"0123456789abcdef") == 32);
  for (int i=3; i<=6; i++) need(argv[i][0] == '/' && strlen(argv[i]) < 4096 && !strchr(argv[i],'\n'));
  need(!strcmp(argv[2],"inspect") || !strcmp(argv[2],"git-add") || !strcmp(argv[2],"git-commit"));
  printf("{\"nonce\":\"%s\",\"parked\":true,\"pid\":%d}\n",argv[1],getpid()); need(!fflush(stdout));
  char release; need(read(0,&release,1) == 1 && release == 'P');
  char hook[8192], safe[8192]; need(snprintf(hook,sizeof(hook),"core.hooksPath=%s",argv[6]) > 0 &&
    snprintf(safe,sizeof(safe),"safe.directory=%s",argv[5]) > 0);
  char *vector[40]={argv[3],"-c",hook,"-c","core.fsmonitor=false","-c","commit.gpgsign=false",
    "-c","core.attributesFile=/dev/null","-c","gc.auto=0","-c","maintenance.auto=false","-c",safe,
    "--git-dir",argv[4],"--work-tree",argv[5]};
  int count=19;
  if (!strcmp(argv[2],"inspect")) {vector[count++]="log"; vector[count++]="-1"; vector[count++]="--format=%H";}
  else if (!strcmp(argv[2],"git-add")) {vector[count++]="add"; vector[count++]="--"; vector[count++]="content.txt";}
  else {vector[count++]="commit"; vector[count++]="-m"; vector[count++]="test(fixture): record owned edit";}
  vector[count]=NULL;
  char *environment[]={"PATH=/nonexistent","HOME=/nonexistent","LANG=C","GIT_CONFIG_NOSYSTEM=1","GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_ATTR_NOSYSTEM=1","GIT_TERMINAL_PROMPT=0","GIT_OPTIONAL_LOCKS=0",NULL};
  struct proc_fdinfo descriptors[4096]; int size=proc_pidinfo(getpid(),PROC_PIDLISTFDS,0,descriptors,sizeof(descriptors));
  need(size > 0 && size < (int)sizeof(descriptors) && size % sizeof(descriptors[0]) == 0);
  for (size_t i=0; i<(size_t)size/sizeof(descriptors[0]); i++) if (descriptors[i].proc_fd >= 3) need(!close(descriptors[i].proc_fd));
  execve(argv[3],vector,environment); _exit(127);
}
