/* Untrusted ordinary-profile probe. The existing private UID/audit/Seatbelt/PF
 * launcher admits this literal image. Git exit and native decisions are joined
 * by an independent protected reader, never inferred from diagnostic output. */
#define __APPLE_API_PRIVATE 1
#define _DARWIN_C_SOURCE 1
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <bsm/audit.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "custody.h"
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
  /* The root reader independently admits the actual Git image while it is
   * suspended, then reads native audit returns across the acknowledged window. */
  int output[2]; need(!pipe(output)); posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
  need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) &&
    !posix_spawn_file_actions_addopen(&files, 0, "/dev/null", O_RDONLY, 0) &&
    !posix_spawn_file_actions_adddup2(&files, output[1], 1) &&
    !posix_spawn_file_actions_addopen(&files, 2, "/dev/null", O_WRONLY, 0) &&
    !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT));
  pid_t worker; need(!posix_spawn(&worker, argv[3], &files, &attributes, vector, environment) &&
    !posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes) && !close(output[1]));
  printf("{\"worker\":"); emit(inspect(worker)); puts("}"); need(!fflush(stdout));
  need(read(0, &release, 1) == 1 && release == 'R');
  unsigned char bytes[4096]; size_t length = 0;
  while (1) { need(length < sizeof(bytes)); ssize_t size = read(output[0], bytes + length, sizeof(bytes) - length); need(size >= 0); if (!size) break; length += size; }
  need(!close(output[0])); int status; while (waitpid(worker, &status, 0) < 0) need(errno == EINTR); need(WIFEXITED(status));
  printf("{\"exitCode\":%d,\"stdoutHex\":\"", WEXITSTATUS(status)); for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]); puts("\"}"); need(!fflush(stdout));
  need(read(0, &release, 1) == 1 && release == 'S'); return 0;
}
