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
#include <sys/acl.h>
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
    int parent = open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); need(parent >= 0); no_acl(parent); need(!close(parent));
    slash = strrchr(name, '/'); need(slash); *slash = 0;
  }
}
static void protected_input(const char *path, const char *pin, int installed) {
  struct stat stat; need(!lstat(path, &stat) && !(stat.st_mode & 06022));
  int held = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); need(held >= 0); no_acl(held);
  ancestors(path);
  free((installed ? installed_file : file)(path, stat.st_gid, stat.st_mode & 07777, 134217728, pin, &stat));
  struct stat actual; need(!fstat(held, &actual) && actual.st_dev == stat.st_dev && actual.st_ino == stat.st_ino &&
    actual.st_mode == stat.st_mode && actual.st_uid == 0 && actual.st_gid == stat.st_gid && actual.st_nlink == stat.st_nlink &&
    actual.st_size == stat.st_size && actual.st_mtimespec.tv_sec == stat.st_mtimespec.tv_sec && actual.st_mtimespec.tv_nsec == stat.st_mtimespec.tv_nsec &&
    actual.st_ctimespec.tv_sec == stat.st_ctimespec.tv_sec && actual.st_ctimespec.tv_nsec == stat.st_ctimespec.tv_nsec);
  no_acl(held); need(!close(held));
}
/* Hold the selected SDK across its query or compilation. Preliminary selector
 * metadata is only an expected identity; these native predicates admit it. */
static int selected_sdk(const char *sdk, const char *dev, const char *ino, const char *settings_pin) {
  char canonical[PATH_MAX]; struct stat stat;
  int sdk_resolved = realpath(sdk, canonical) != NULL, sdk_resolve_error = errno;
  int sdk_equal = -1, sdk_stat = -2, sdk_stat_error = -1, sdk_kind = -1, sdk_owner = -1, sdk_writable = -1;
  bool sdk_ok = sdk_resolved && (sdk_equal = !strcmp(sdk, canonical)) &&
    (sdk_stat = lstat(sdk, &stat), sdk_stat_error = errno, !sdk_stat) &&
    (sdk_kind = S_ISDIR(stat.st_mode)) && (sdk_owner = stat.st_uid == 0) &&
    (sdk_writable = !!(stat.st_mode & 022), !sdk_writable);
  if (!sdk_ok) {
    int sdk_error = errno;
    fprintf(stderr, "native-darwin-sdk: realpath=%d realpath-errno=%d equal=%d lstat=%d lstat-errno=%d kind=%d owner=%d writable=%d\n",
      sdk_resolved, sdk_resolve_error, sdk_equal, sdk_stat, sdk_stat_error, sdk_kind, sdk_owner, sdk_writable);
    if (sdk_stat == 0)
      fprintf(stderr, "native-darwin-sdk-metadata: uid=%ju gid=%ju mode=%#o dev=%ju inode=%ju\n",
        (uintmax_t)stat.st_uid, (uintmax_t)stat.st_gid, (unsigned)stat.st_mode, (uintmax_t)stat.st_dev, (uintmax_t)stat.st_ino);
    fflush(stderr); errno = sdk_error;
  }
  need(sdk_ok);
  ancestors(sdk);
  int sdk_fd = directory(sdk, 0, stat.st_gid, stat.st_mode & 07777);
  no_acl(sdk_fd);
#ifdef NATIVE_CI_EXPERIMENT
  struct stat held, named;
  need(!fstat(sdk_fd, &held) && file_stat_same(&stat, &held) &&
    !lstat(sdk, &named) && file_stat_same(&held, &named));
  char *end; errno = 0;
  need(*dev && strlen(dev) <= 20 && strspn(dev, "0123456789") == strlen(dev));
  unsigned long long expected_dev = strtoull(dev, &end, 10); need(!errno && !*end);
  errno = 0;
  need(*ino && strlen(ino) <= 20 && strspn(ino, "0123456789") == strlen(ino));
  unsigned long long expected_ino = strtoull(ino, &end, 10); need(!errno && !*end);
  need((uintmax_t)held.st_dev == expected_dev && (uintmax_t)held.st_ino == expected_ino);
  char settings[PATH_MAX];
  need(snprintf(settings, sizeof(settings), "%s/SDKSettings.json", sdk) < sizeof(settings));
  protected_input(settings, settings_pin, 1);
  need(!fstat(sdk_fd, &named) && file_stat_same(&held, &named) &&
    !lstat(sdk, &named) && file_stat_same(&held, &named));
  no_acl(sdk_fd); return sdk_fd;
#else
  (void)dev; (void)ino; (void)settings_pin;
  need(!close(sdk_fd)); return -1;
#endif
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
    no_acl(image);
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
#ifdef NATIVE_CI_EXPERIMENT
  const int expected_argc = 15;
#else
  const int expected_argc = 11;
#endif
  need(argc == expected_argc && getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 &&
    getenv("CI") && !strcmp(getenv("CI"), "true") && getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"), "true"));
  /* mode, tool, SHA, cdhash, private output, SDK, source, SHA, target, seconds;
   * experiment adds header SHA, selected SDK device/inode and settings SHA. */
  const char *mode = argv[1], *tool = argv[2], *cwd = argv[5], *sdk = argv[6], *source = argv[7], *target = argv[9];
  unsigned seconds = number(argv[10]); need(seconds > 0 && seconds <= 30);
  need(signal(SIGALRM, expire) != SIG_ERR); alarm(seconds);
  int work = directory(cwd, 0, 0, 0700); need(!fchdir(work));
  no_acl(work);
  /* Retain the original birth and audit domain before installed-input refusal.
   * P authorizes admission checks only; no tool exists until they all pass. */
  auditinfo_addr_t audit = {0}; audit.ai_auid = 0; audit.ai_asid = AU_ASSIGN_ASID; audit.ai_termid.at_type = AU_IPv4;
  need(!setaudit_addr(&audit, sizeof(audit)) && !getaudit_addr(&audit, sizeof(audit)) &&
    audit.ai_asid != AU_DEFAUDITSID && audit.ai_asid != AU_ASSIGN_ASID);
  printf("{\"helper\":"); emit(inspect(getpid())); puts("}"); fflush(stdout); control('P');
  protected_input(tool, argv[3], 1); signature(tool, argv[4]);
  const char *publication = NULL;
#ifdef NATIVE_CI_EXPERIMENT
  int sdk_fd = -1; struct stat sdk_identity;
  if (!strcmp(mode, "sdk-version") || !strcmp(mode, "compile"))
    sdk_fd = selected_sdk(sdk, argv[12], argv[13], argv[14]);
  if (sdk_fd >= 0) need(!fstat(sdk_fd, &sdk_identity));
#endif
  char *vector[32] = {(char *)tool, NULL};
#ifdef NATIVE_CI_EXPERIMENT
  char purpose_header[PATH_MAX], dependencies[PATH_MAX];
#endif
  if (!strcmp(mode, "compiler-version")) {
    need(!strcmp(tool, "/usr/bin/clang")); vector[1] = "--version";
  } else if (!strcmp(mode, "sdk-version")) {
    need(!strcmp(tool, "/usr/bin/xcrun"));
#ifdef NATIVE_CI_EXPERIMENT
    vector[1] = "--sdk"; vector[2] = (char *)sdk; vector[3] = "--show-sdk-build-version";
#else
    vector[1] = "--show-sdk-build-version";
#endif
  } else if (!strcmp(mode, "compile")) {
    need(!strcmp(tool, "/usr/bin/clang")); protected_input(source, argv[8], 0);
#ifndef NATIVE_CI_EXPERIMENT
    selected_sdk(sdk, NULL, NULL, NULL);
#endif
    struct stat stat;
    need(strlen(target) > strlen(cwd) + 1 && !strncmp(target, cwd, strlen(cwd)) &&
      target[strlen(cwd)] == '/' && !strchr(target + strlen(cwd) + 1, '/') &&
      strcmp(target + strlen(cwd) + 1, ".") && strcmp(target + strlen(cwd) + 1, ".."));
    errno = 0; need(lstat(target, &stat) < 0 && errno == ENOENT);
    publication = target + strlen(cwd) + 1;
#ifdef NATIVE_CI_EXPERIMENT
    const char *slash = strrchr(source, '/'); need(slash && slash - source < PATH_MAX);
    need(snprintf(purpose_header, sizeof(purpose_header), "%.*s/experiment.h", (int)(slash - source), source) < sizeof(purpose_header));
    protected_input(purpose_header, argv[11], 0);
    need(snprintf(dependencies, sizeof(dependencies), "%s.deps", publication) < sizeof(dependencies));
    errno = 0; need(fstatat(work, dependencies, &stat, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
#endif
    char *args[] = {(char *)tool, "-std=c17", "-O2", "-Wall", "-Wextra", "-arch", "x86_64",
      "-isysroot", (char *)sdk,
#ifdef NATIVE_CI_EXPERIMENT
      "-DNATIVE_CI_EXPERIMENT=1", "-include", purpose_header,
      "-MD", "-MF", dependencies,
#endif
      (char *)source, "-o", (char *)target + strlen(cwd) + 1, "-Wl,-no_uuid",
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
  if (WEXITSTATUS(status) == 0) {
#ifdef NATIVE_CI_EXPERIMENT
    if (!strcmp(mode, "compile")) {
      int fd = openat(work, dependencies, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); struct stat st;
      need(fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == 0 && st.st_gid == 0 && st.st_nlink == 1 && st.st_size > 0 && st.st_size <= 1048576);
      no_acl(fd); need(!fchmod(fd, 0444) && !close(fd));
    }
#endif
    publish(work, cwd, publication);
  }
#ifdef NATIVE_CI_EXPERIMENT
  if (sdk_fd >= 0) {
    struct stat held, named;
    need(!fstat(sdk_fd, &held) && file_stat_same(&sdk_identity, &held) &&
      !lstat(sdk, &named) && file_stat_same(&held, &named));
    no_acl(sdk_fd); need(!close(sdk_fd));
  }
#endif
  need(!close(work)); return 0;
}
