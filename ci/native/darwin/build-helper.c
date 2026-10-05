/* A sealed, short-lived CI compiler entry. The independent reader checks both
 * native identities before the suspended tool can execute. No shell or daemon. */
#define __APPLE_API_PRIVATE 1
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <bsm/audit.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "custody.h"

static void control(char expected) {
  struct pollfd wait = {.fd = 0, .events = POLLIN}; char byte;
  need(poll(&wait, 1, 30000) == 1 && (wait.revents & POLLIN) &&
    read(0, &byte, 1) == 1 && byte == expected);
}
static void ancestors(const char *path) {
  char name[PATH_MAX], canonical[PATH_MAX]; struct stat stat;
  need(strlen(path) < sizeof(name) && realpath(path, canonical) && !strcmp(path, canonical));
  strcpy(name, path); char *slash = strrchr(name, '/'); need(slash); *slash = 0;
  while (*name) {
    need(!lstat(name, &stat) && S_ISDIR(stat.st_mode) && stat.st_uid == 0 && !(stat.st_mode & 022));
    slash = strrchr(name, '/'); need(slash); *slash = 0;
  }
}
static void protected_input(const char *path, const char *pin) {
  struct stat stat; need(!lstat(path, &stat) && !(stat.st_mode & 06022));
  ancestors(path); free(file(path, stat.st_gid, stat.st_mode & 07777, 134217728, pin, &stat));
}
/* sudo preserves only standard descriptors. Create the tool pipes inside this
 * sealed entry and return bounded bytes as data on the private control pipe. */
static void capture(int out, int err, unsigned char *output, size_t *out_size,
                    unsigned char *errors, size_t *err_size) {
  struct pollfd pipes[] = {{.fd = out, .events = POLLIN}, {.fd = err, .events = POLLIN}};
  unsigned char bytes[4096];
  while (pipes[0].fd >= 0 || pipes[1].fd >= 0) {
    int ready = poll(pipes, 2, 30000);
    if (ready < 0 && errno == EINTR) continue;
    need(ready > 0);
    for (unsigned i = 0; i < 2; i++) {
      need(!(pipes[i].revents & (POLLERR | POLLNVAL)));
      if (!(pipes[i].revents & (POLLIN | POLLHUP))) continue;
      ssize_t n = read(pipes[i].fd, bytes, sizeof(bytes));
      if (n < 0 && errno == EINTR) continue;
      need(n >= 0 && *out_size + *err_size + (size_t)n <= 65536);
      if (!n) { need(!close(pipes[i].fd)); pipes[i].fd = -1; continue; }
      unsigned char *target = i ? errors : output;
      size_t *size = i ? err_size : out_size;
      memcpy(target + *size, bytes, (size_t)n); *size += (size_t)n;
    }
  }
}
static void emit_bytes(const unsigned char *bytes, size_t size) {
  for (size_t i = 0; i < size; i++) printf("%02x", bytes[i]);
}
static void publish(int work, const char *cwd, const char *leaf) {
  struct stat held, named;
  need(!fstat(work, &held) && held.st_uid == 0 && held.st_gid == 0 &&
    (held.st_mode & 07777) == 0700 && !lstat(cwd, &named) &&
    held.st_dev == named.st_dev && held.st_ino == named.st_ino && held.st_mode == named.st_mode);
  if (leaf) {
    int image = openat(work, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat actual;
    need(image >= 0 && !fstat(image, &actual) && S_ISREG(actual.st_mode) &&
      actual.st_uid == 0 && actual.st_gid == 0 && actual.st_nlink == 1 &&
      actual.st_size > 0 && (uint64_t)actual.st_size <= 134217728 && !(actual.st_mode & 06022));
    need(!fchmod(image, 0555) && !fstatat(work, leaf, &named, AT_SYMLINK_NOFOLLOW) &&
      actual.st_dev == named.st_dev && actual.st_ino == named.st_ino &&
      named.st_uid == 0 && named.st_gid == 0 && named.st_nlink == 1 &&
      (named.st_mode & 07777) == 0555 && !close(image));
  }
  /* The runner can now read immutable outputs through its private report
   * directory. The next admitted provisioning operation reseals this to 0700. */
  need(!fchmod(work, 0555));
}
static void expire(int signal) { (void)signal; _exit(124); }
int main(int argc, char **argv) {
  need(argc == 11 && getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 &&
    getenv("CI") && !strcmp(getenv("CI"), "true") && getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"), "true"));
  /* mode, tool, SHA, cdhash, private output, SDK, source, SHA, target, seconds */
  const char *mode = argv[1], *tool = argv[2], *cwd = argv[5], *sdk = argv[6], *source = argv[7], *target = argv[9];
  unsigned seconds = number(argv[10]); need(seconds > 0 && seconds <= 30);
  need(signal(SIGALRM, expire) != SIG_ERR); alarm(seconds);
  protected_input(tool, argv[3]); signature(tool, argv[4]);
  int work = directory(cwd, 0, 0, 0700); need(!fchdir(work));
  const char *publication = NULL;
  char *vector[24] = {(char *)tool, NULL};
  if (!strcmp(mode, "compiler-version")) {
    need(!strcmp(tool, "/usr/bin/clang")); vector[1] = "--version";
  } else if (!strcmp(mode, "sdk-version")) {
    need(!strcmp(tool, "/usr/bin/xcrun")); vector[1] = "--show-sdk-build-version";
  } else if (!strcmp(mode, "compile")) {
    need(!strcmp(tool, "/usr/bin/clang")); protected_input(source, argv[8]);
    char canonical[PATH_MAX]; struct stat stat;
    need(realpath(sdk, canonical) && !strcmp(sdk, canonical) && !lstat(sdk, &stat) &&
      S_ISDIR(stat.st_mode) && stat.st_uid == 0 && !(stat.st_mode & 022));
    ancestors(sdk);
    need(strlen(target) > strlen(cwd) + 1 && !strncmp(target, cwd, strlen(cwd)) &&
      target[strlen(cwd)] == '/' && !strchr(target + strlen(cwd) + 1, '/') &&
      strcmp(target + strlen(cwd) + 1, ".") && strcmp(target + strlen(cwd) + 1, ".."));
    errno = 0; need(lstat(target, &stat) < 0 && errno == ENOENT);
    publication = target + strlen(cwd) + 1;
    char *args[] = {(char *)tool, "-std=c17", "-O2", "-Wall", "-Wextra", "-arch", "x86_64",
      "-isysroot", (char *)sdk, (char *)source, "-o", (char *)target + strlen(cwd) + 1, "-Wl,-no_uuid",
      "-fblocks", "-framework", "Security", "-framework", "CoreFoundation", "-lbsm", "-lsandbox", NULL}; memcpy(vector, args, sizeof(args));
  } else {
    need(!strcmp(mode, "sign") && !strcmp(tool, "/usr/bin/codesign"));
    need(strlen(target) > strlen(cwd) + 1 && !strncmp(target, cwd, strlen(cwd)) &&
      target[strlen(cwd)] == '/' && !strchr(target + strlen(cwd) + 1, '/'));
    struct stat stat; const char *leaf = target + strlen(cwd) + 1;
    need(strcmp(leaf, ".") && strcmp(leaf, "..") && !lstat(leaf, &stat) && !(stat.st_mode & 06022));
    free(file(target, 0, stat.st_mode & 07777, 134217728, argv[8], &stat));
    publication = leaf;
    char *args[] = {(char *)tool, "--force", "--sign", "-", "--timestamp=none", (char *)leaf, NULL};
    memcpy(vector, args, sizeof(args));
  }
  auditinfo_addr_t audit = {0}; audit.ai_auid = 0; audit.ai_asid = AU_ASSIGN_ASID; audit.ai_termid.at_type = AU_IPv4;
  need(!setaudit_addr(&audit, sizeof(audit)) && !getaudit_addr(&audit, sizeof(audit)) &&
    audit.ai_asid != AU_DEFAUDITSID && audit.ai_asid != AU_ASSIGN_ASID);
  printf("{\"helper\":"); emit(inspect(getpid())); puts("}"); fflush(stdout); control('P');
  int output[2], errors[2]; need(!pipe(output) && !pipe(errors));
  posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
  need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) &&
    !posix_spawn_file_actions_addopen(&files, 0, "/dev/null", O_RDONLY, 0) &&
    !posix_spawn_file_actions_adddup2(&files, output[1], 1) &&
    !posix_spawn_file_actions_adddup2(&files, errors[1], 2) &&
    !posix_spawn_file_actions_addclose(&files, output[0]) &&
    !posix_spawn_file_actions_addclose(&files, errors[0]) &&
    !posix_spawn_file_actions_addclose(&files, output[1]) &&
    !posix_spawn_file_actions_addclose(&files, errors[1]) &&
    !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT));
  char sdk_environment[PATH_MAX + 9]; need(strlen(sdk) < PATH_MAX);
  snprintf(sdk_environment, sizeof(sdk_environment), "SDKROOT=%s", sdk);
  char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", "LANG=C", "PATH=/nonexistent", sdk_environment, NULL};
  pid_t worker; need(!posix_spawn(&worker, tool, &files, &attributes, vector, environment));
  need(!posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes));
  need(!close(output[1]) && !close(errors[1]));
  struct identity identity = inspect(worker);
  printf("{\"worker\":"); emit(identity); puts("}"); fflush(stdout); control('R');
  need(!proc_signal_with_audittoken(&identity.token, SIGCONT));
  unsigned char output_bytes[65536], error_bytes[65536]; size_t out_size = 0, err_size = 0;
  capture(output[0], errors[0], output_bytes, &out_size, error_bytes, &err_size);
  int status; while (waitpid(worker, &status, 0) < 0) need(errno == EINTR);
  need(WIFEXITED(status));
  printf("{\"exitCode\":%d,\"signal\":null,\"stdoutHex\":\"", WEXITSTATUS(status));
  emit_bytes(output_bytes, out_size); printf("\",\"stderrHex\":\"");
  emit_bytes(error_bytes, err_size); puts("\"}"); fflush(stdout);
  control('S');
  if (WEXITSTATUS(status) == 0) publish(work, cwd, publication);
  need(!close(work)); return 0;
}
