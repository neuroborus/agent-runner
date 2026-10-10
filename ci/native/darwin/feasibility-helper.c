/* Bounded experiment only. No complete Darwin descendant-domain claim. */
#define _DARWIN_C_SOURCE 1
#define __APPLE_API_PRIVATE 1
#if !defined(__APPLE__) || !defined(__x86_64__)
#error The experiment helper requires the matching macOS x64 SDK.
#endif
#include <arpa/inet.h>
#include <bsm/audit.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach.h>
#include <sandbox.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "feasibility-sandbox.h"

#ifdef NATIVE_FEASIBILITY_COMMAND
static void command_failure(void);
#endif
static const char *failed_operation, *failed_domain;
static int failed_value;
static const char *cleanup_operation, *cleanup_domain;
static int cleanup_value;
static bool prerequisite_mode, prerequisite_signalled, resource_uncertain, admitted_effects;
static int prerequisite_gate[2] = {-1, -1}, prerequisite_status;
static pid_t prerequisite_child = -1;
static void remember(const char *operation, const char *domain, int value) {
  if (!failed_operation) { failed_operation = operation; failed_domain = domain; failed_value = value; }
}
static void remember_cleanup(const char *operation, const char *domain, int value) {
  resource_uncertain = true;
  if (!cleanup_operation) { cleanup_operation = operation; cleanup_domain = domain; cleanup_value = value; }
}
static void settle_prerequisite(void) {
  for (unsigned i = 0; i < 2; i++) if (prerequisite_gate[i] >= 0) {
    if (close(prerequisite_gate[i])) remember_cleanup("prerequisite-close", "errno", errno);
    prerequisite_gate[i] = -1;
  }
  if (prerequisite_child > 0) {
    /* Only the owned, unreleased pipe control exists here. EOF releases it to
     * exit, never to exec. Reap it independently even when identity reads fail. */
    for (unsigned pass = 0; pass < 200; pass++) {
      pid_t reaped = waitpid(prerequisite_child, &prerequisite_status, WNOHANG);
      if (reaped == prerequisite_child) {
        prerequisite_child = -1;
        if (WIFSIGNALED(prerequisite_status) && WTERMSIG(prerequisite_status) == SIGALRM)
          remember_cleanup("prerequisite-backstop", "invariant", SIGALRM);
        else if (!(WIFEXITED(prerequisite_status) && WEXITSTATUS(prerequisite_status) == 0) &&
          !(prerequisite_signalled && WIFSIGNALED(prerequisite_status) && WTERMSIG(prerequisite_status) == SIGKILL))
          remember_cleanup("prerequisite-child-status", "invariant", prerequisite_status);
        return;
      }
      if (reaped < 0 && errno != EINTR) { remember_cleanup("prerequisite-wait", "errno", errno); break; }
      usleep(10000);
    }
    remember_cleanup("prerequisite-wait", "invariant", 0);
  }
}
static void failure(int code) {
  if (prerequisite_mode) settle_prerequisite();
  fprintf(stderr, "native-darwin: operation=%s domain=%s value=%d effects=%s settlement=%s\n",
    failed_operation ? failed_operation : "helper-invariant", failed_domain ? failed_domain : "invariant",
    failed_operation ? failed_value : 0, admitted_effects ? "possible" : "none",
    prerequisite_mode && !resource_uncertain && prerequisite_child < 0 ? "settled" : "unsettled");
  if (cleanup_operation) fprintf(stderr, "native-darwin-cleanup: operation=%s domain=%s value=%d effects=%s settlement=unsettled\n",
    cleanup_operation, cleanup_domain, cleanup_value, admitted_effects ? "possible" : "none");
  fflush(stderr);
#ifdef NATIVE_FEASIBILITY_COMMAND
  command_failure();
#endif
  _exit(code);
}
static void need(int ok) { if (!ok) { remember("helper-invariant", "invariant", 0); failure(126); } }
static void invariant(bool ok, const char *operation) {
  if (!ok) { remember(operation, "invariant", 0); failure(126); }
}
static void posix_check(int result, const char *operation) {
  if (result < 0) { int error = errno; remember(operation, "errno", error); failure(error == ENOTSUP || error == ENOSYS ? 78 : 126); }
}
static unsigned long long number(const char *s) {
  char *end; errno = 0; unsigned long long n = strtoull(s, &end, 10);
  need(*s && *s != '-' && !errno && !*end && n <= 9007199254740991ULL); return n;
}
struct identity { audit_token_t token; struct proc_bsdinfo bsd; };
typedef int (*audit_signal_fn)(audit_token_t *, int);
static audit_signal_fn audit_signal;
static struct feasibility_sandbox_binding sandbox_binding;

/* Same double BSD/audit read as custody.h, with a prerequisite refusal path. */
static bool inspect(pid_t pid, struct identity *value) {
  struct proc_bsdinfo after; audit_token_t again;
  mach_port_t task = MACH_PORT_NULL; mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  bool ok = false; errno = 0;
  int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value->bsd, sizeof(value->bsd));
  if (size != sizeof(value->bsd)) { remember("bsd-identity", size == 0 ? "errno" : "invariant", size == 0 ? errno : size); goto done; }
  kern_return_t error = task_name_for_pid(mach_task_self(), pid, &task);
  if (error != KERN_SUCCESS) { remember("task-name", "mach", error); goto done; }
  if (task == MACH_PORT_NULL) { remember("task-name", "invariant", 0); goto done; }
  error = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&value->token, &count);
  if (error != KERN_SUCCESS) { remember("task-audit", "mach", error); goto done; }
  if (count != TASK_AUDIT_TOKEN_COUNT) { remember("task-audit-count", "invariant", (int)count); goto done; }
  errno = 0; size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after));
  if (size != sizeof(after)) { remember("bsd-identity-again", size == 0 ? "errno" : "invariant", size == 0 ? errno : size); goto done; }
  count = TASK_AUDIT_TOKEN_COUNT; error = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&again, &count);
  if (error != KERN_SUCCESS) { remember("task-audit-again", "mach", error); goto done; }
  if (count != TASK_AUDIT_TOKEN_COUNT) { remember("task-audit-count", "invariant", (int)count); goto done; }
  ok = !memcmp(&again, &value->token, sizeof(again)) &&
    after.pbi_start_tvsec == value->bsd.pbi_start_tvsec && after.pbi_start_tvusec == value->bsd.pbi_start_tvusec &&
    after.pbi_svuid == value->bsd.pbi_svuid && after.pbi_svgid == value->bsd.pbi_svgid &&
    value->token.val[5] == (unsigned)pid && value->token.val[1] == after.pbi_uid &&
    value->token.val[2] == after.pbi_gid && value->token.val[3] == after.pbi_ruid && value->token.val[4] == after.pbi_rgid;
  if (!ok) remember("identity-stable", "invariant", 0);
done:
  if (task != MACH_PORT_NULL) {
    kern_return_t release_error = mach_port_deallocate(mach_task_self(), task);
    if (release_error != KERN_SUCCESS) { remember("task-release", "mach", release_error); remember_cleanup("task-release", "mach", release_error); ok = false; }
  }
  return ok;
}
static void identity_failure(void) {
  failure(failed_domain && !strcmp(failed_domain, "invariant") ? 126 : 78);
}
static void emit_identity(struct identity v) {
  unsigned *t = v.token.val; struct proc_bsdinfo *b = &v.bsd;
  printf("{\"pid\":%u,\"pidVersion\":%u,\"asid\":%u,\"auid\":%u,\"uid\":%u,\"gid\":%u,"
    "\"ruid\":%u,\"rgid\":%u,\"svuid\":%u,\"svgid\":%u,\"startSeconds\":%llu,\"startMicroseconds\":%llu}",
    t[5], t[7], t[6], t[0], t[1], t[2], t[3], t[4], b->pbi_svuid, b->pbi_svgid,
    (unsigned long long)b->pbi_start_tvsec, (unsigned long long)b->pbi_start_tvusec);
}
static struct identity parse_identity(char **args) {
  struct identity value = {0};
  for (int i = 0; i < 8; i++) { unsigned long long n = number(args[i]); need(n <= UINT32_MAX); value.token.val[i] = (unsigned)n; }
  value.bsd.pbi_start_tvsec = number(args[8]); value.bsd.pbi_start_tvusec = number(args[9]);
  value.bsd.pbi_svuid = (unsigned)number(args[10]); value.bsd.pbi_svgid = (unsigned)number(args[11]);
  need(value.token.val[5] > 1 && value.token.val[5] <= INT32_MAX && value.token.val[5] != (unsigned)getpid() &&
    value.token.val[7] && value.bsd.pbi_start_tvsec && value.bsd.pbi_start_tvusec < 1000000);
  return value;
}
static bool live(struct identity expected) {
  struct proc_bsdinfo bsd; errno = 0;
  int n = proc_pidinfo((int)expected.token.val[5], PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd));
  if (!n && errno == ESRCH) return false;
  need(n == sizeof(bsd));
  if (bsd.pbi_start_tvsec != expected.bsd.pbi_start_tvsec || bsd.pbi_start_tvusec != expected.bsd.pbi_start_tvusec) return false;
  if (bsd.pbi_status == SZOMB) return false;
  struct identity actual; need(inspect((int)expected.token.val[5], &actual));
  if (actual.token.val[7] != expected.token.val[7]) return false;
  /* A credential/audit transition is uncertainty, not retirement of this birth. */
  need(bsd.pbi_svuid == expected.bsd.pbi_svuid && bsd.pbi_svgid == expected.bsd.pbi_svgid &&
    !memcmp(&actual.token, &expected.token, sizeof(actual.token)));
  return true;
}
static void signal_identity(struct identity value, int signal) {
  need(audit_signal != NULL);
  if (!live(value)) return;
  /* Kernel lookup uses the pidversion. Never fall back to kill(numeric_pid). */
  admitted_effects = true;
  int error = audit_signal(&value.token, signal);
  if (error && error != ESRCH) { remember("audit-signal", "errno", error); failure(126); }
}
static void prerequisites(void) {
  struct identity self;
  invariant(getuid() > 500 && geteuid() == getuid(), "worker-identity");
  if (!audit_signal) { remember("audit-binding", "invariant", 0); failure(78); }
  if (!feasibility_sandbox_available(sandbox_binding)) { remember("sandbox-binding", "invariant", 0); failure(78); }
  if (!inspect(getpid(), &self)) identity_failure();
  int *control = prerequisite_gate; posix_check(pipe(control), "prerequisite-pipe");
  pid_t child = fork(); posix_check((int)child, "prerequisite-fork");
  if (!child) { close(control[1]); alarm(5); char byte; (void)read(control[0], &byte, 1); close(control[0]); _exit(0); }
  prerequisite_child = child;
  int closed = close(control[0]); control[0] = -1;
  if (closed) remember_cleanup("prerequisite-close", "errno", errno); posix_check(closed, "prerequisite-close");
  struct identity value; if (!inspect(child, &value)) identity_failure();
  /* The libproc wrapper returns errno directly, not -1 plus global errno. */
  int error = audit_signal(&value.token, SIGKILL);
  if (error) { remember("audit-signal", "errno", error); failure(error == EPERM || error == EACCES || error == ENOTSUP || error == ENOSYS ? 78 : 126); }
  prerequisite_signalled = true;
  settle_prerequisite();
  invariant(!resource_uncertain && prerequisite_child < 0, "prerequisite-settlement");
  invariant(WIFSIGNALED(prerequisite_status) && WTERMSIG(prerequisite_status) == SIGKILL, "signal-control");
  puts("{\"identitySafeSignal\":true,\"sandboxCheckBinding\":true}");
}

static bool same_file_stat(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
    a->st_birthtimespec.tv_sec == b->st_birthtimespec.tv_sec &&
    a->st_birthtimespec.tv_nsec == b->st_birthtimespec.tv_nsec &&
    a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
    a->st_mode == b->st_mode && a->st_nlink == b->st_nlink;
}
static void no_acl(int fd, const struct stat *expected) {
  struct stat inspected, after; acl_t acl = NULL; bool ok = false;
  int code = 126, present = -1, result, error;
  errno = 0; filesec_t security = filesec_init(); error = errno;
  if (!security) { remember("filesec-init", "errno", error); goto done; }

  /* acl_get_fd_np collapses an absent FILESEC_ACL into a null/ENOENT read.
   * Inspect the held descriptor and query presence instead of accepting errno. */
  errno = 0; result = fstatx_np(fd, &inspected, security); error = errno;
  if (result) {
    remember("filesec-stat", "errno", error);
    if (error == ENOTSUP || error == ENOSYS) code = 78;
    goto done;
  }
  if (!same_file_stat(expected, &inspected)) { remember("file-stable", "invariant", 0); goto done; }
  errno = 0; result = filesec_query_property(security, FILESEC_ACL, &present); error = errno;
  if (result) {
    remember("acl-query", "errno", error);
    if (error == ENOTSUP || error == ENOSYS) code = 78;
    goto done;
  }
  /* A successful query sets present to a validity bitmask, not a Boolean 0/1 value.
   * Zero is absent; any nonzero value requires the independently read ACL. */
  if (present != 0) {
    /* FILESEC_ACL returns an independently owned ACL, not the filesec storage. */
    errno = 0; result = filesec_get_property(security, FILESEC_ACL, &acl); error = errno;
    if (result || !acl) {
      remember("acl-read", result ? "errno" : "invariant", result ? error : 0);
      if (result && (error == ENOTSUP || error == ENOSYS)) code = 78;
      goto done;
    }
    errno = 0; result = acl_valid(acl); error = errno;
    if (result) { remember("acl-valid", "errno", error); goto done; }
    acl_entry_t entry;
    errno = 0; result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry); error = errno;
    /* Darwin returns zero for an entry and EINVAL at the end of a valid ACL. */
    bool empty = result == -1 && error == EINVAL;
    if (!empty) { remember("acl-empty", result == -1 ? "errno" : "invariant", result == -1 ? error : 0); goto done; }
  }
  errno = 0; result = fstat(fd, &after); error = errno;
  if (result) { remember("file-stat-again", "errno", error); goto done; }
  if (!same_file_stat(expected, &after)) { remember("file-stable", "invariant", 0); goto done; }
  ok = true;
done:
  if (acl) {
    errno = 0; int freed = acl_free(acl), free_error = errno;
    if (freed) {
      remember("acl-release", "errno", free_error);
      remember_cleanup("acl-release", "errno", free_error); ok = false;
    }
  }
  /* filesec_free has no status result; release it even after ACL release fails. */
  if (security) filesec_free(security);
  if (!ok) failure(code);
}
static void object_identity_links(int fd, char out[256], unsigned links) {
  struct stat st; struct statfs fs; posix_check(fstat(fd, &st), "file-stat"); posix_check(fstatfs(fd, &fs), "volume-stat");
  invariant(st.st_uid == getuid(), "file-owner"); invariant(st.st_gid == getgid(), "file-group");
  invariant(st.st_ino && st.st_birthtimespec.tv_sec > 0 &&
    (S_ISDIR(st.st_mode) ? (st.st_mode & 07777) == 0700 : S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0600 && st.st_nlink == links), "file-shape");
  no_acl(fd, &st);
  struct attrlist attrs = {.bitmapcount = ATTR_BIT_MAP_COUNT, .volattr = ATTR_VOL_INFO | ATTR_VOL_UUID};
  struct { uint32_t length; unsigned char uuid[16]; } volume;
  _Static_assert(sizeof(volume) == 20, "Volume UUID attributes use four-byte packing.");
  int result = fgetattrlist(fd, &attrs, &volume, sizeof(volume), 0);
  posix_check(result, "volume-uuid"); invariant(volume.length == sizeof(volume), "volume-length");
  unsigned nonzero = 0; char hex[33];
  for (int i = 0; i < 16; i++) { nonzero |= volume.uuid[i]; snprintf(hex + 2*i, 3, "%02x", volume.uuid[i]); }
  invariant(nonzero, "volume-nonzero");
  int n = snprintf(out, 256, "%u:%u:%u:%" PRIu64 ":%lld:%ld:%u:%u:%o:%s",
    (unsigned)st.st_dev, (unsigned)fs.f_fsid.val[0], (unsigned)fs.f_fsid.val[1], st.st_ino,
    (long long)st.st_birthtimespec.tv_sec, st.st_birthtimespec.tv_nsec, st.st_uid, st.st_gid, st.st_mode, hex);
  need(n > 0 && n < 256);
}
static void object_identity(int fd, char out[256]) { object_identity_links(fd, out, 1); }
static int directory(const char *path) {
  int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); char id[256];
  posix_check(fd, "directory-open"); object_identity(fd, id); return fd;
}
static void emit_file_links(int fd, unsigned links) {
  char id[256]; object_identity_links(fd, id, links); struct stat st; need(!fstat(fd, &st));
  printf("{\"identity\":\"%s\",\"sha256\":", id);
  if (S_ISDIR(st.st_mode)) printf("null");
  else {
    need(st.st_size >= 0 && st.st_size <= 65536); unsigned char data[65537], hash[CC_SHA256_DIGEST_LENGTH];
    ssize_t n = pread(fd, data, sizeof(data), 0); need(n == st.st_size && CC_SHA256(data, (CC_LONG)n, hash));
    putchar('"'); for (unsigned i = 0; i < sizeof(hash); i++) printf("%02x", hash[i]); putchar('"');
    char again[256]; object_identity_links(fd, again, links); need(!strcmp(id, again));
  }
  putchar('}');
}
static void emit_file(int fd) { emit_file_links(fd, 1); }
static void storage(const char *parent_path) {
  int parent = directory(parent_path); admitted_effects = true;
  need(!flock(parent, LOCK_EX | LOCK_NB) && !mkdirat(parent, "allocation", 0700));
  int base = openat(parent, "allocation", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); need(base >= 0);
  int leaf = openat(base, "leaf", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); need(leaf >= 0 && write(leaf, "owned", 5) == 5);
  char expected[256]; object_identity(leaf, expected);
  printf("{\"event\":\"allocated\",\"owner\":"); emit_file(parent); printf(",\"parent\":"); emit_file(base); printf(",\"leaf\":"); emit_file(leaf); puts("}"); fflush(stdout);
  char command; need(read(0, &command, 1) == 1 && (command == 'N' || command == 'S'));
  int named = openat(base, "leaf", O_RDONLY | O_NOFOLLOW | O_CLOEXEC); need(named >= 0);
  char actual[256]; object_identity(named, actual); bool match = !strcmp(expected, actual);
  if (command == 'N') need(match && !unlinkat(base, "leaf", 0)); else need(!match);
  printf("{\"event\":\"cleanup\",\"removed\":%s,\"held\":", match ? "true" : "false"); emit_file_links(leaf, match ? 0 : 1); puts("}");
  need(!close(named) && !close(leaf) && !close(base) && !close(parent));
}
static void remove_owned(char **args, bool is_directory) {
  need(!strchr(args[1], '/') && strcmp(args[1], ".") && strcmp(args[1], "..") && *args[1]);
  int parent = directory(args[0]); need(!flock(parent, LOCK_EX | LOCK_NB));
  char owner[256]; object_identity(parent, owner); need(!strcmp(owner, args[3]));
  int fd = openat(parent, args[1], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (is_directory ? O_DIRECTORY : 0)); need(fd >= 0);
  char identity[256]; object_identity(fd, identity); need(!strcmp(args[2], identity));
  admitted_effects = true;
  struct stat held, named; need(!fstat(fd, &held) && !fstatat(parent, args[1], &named, AT_SYMLINK_NOFOLLOW) &&
    held.st_dev == named.st_dev && held.st_ino == named.st_ino && held.st_birthtimespec.tv_sec == named.st_birthtimespec.tv_sec &&
    held.st_birthtimespec.tv_nsec == named.st_birthtimespec.tv_nsec && !unlinkat(parent, args[1], is_directory ? AT_REMOVEDIR : 0));
  puts("{\"removed\":true}"); need(!close(fd) && !close(parent));
}

static void policy(const char *file) {
  fprintf(stderr, "native-darwin-phase: phase=policy-enter\n"); fflush(stderr);
  int fd = open(file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); posix_check(fd, "policy-open");
  char bytes[16385]; ssize_t n = read(fd, bytes, sizeof(bytes)); int error_number = errno;
  if (n < 0) { remember("policy-read", "errno", error_number); close(fd); failure(126); }
  need(n > 0 && n < (ssize_t)sizeof(bytes)); bytes[n] = 0; posix_check(close(fd), "policy-close");
  char *error = NULL; int result = sandbox_init(bytes, 0, &error);
  if (error) sandbox_free_error(error);
  if (result) { remember("sandbox-apply", "status", result); failure(126); }
  fprintf(stderr, "native-darwin-phase: phase=policy-applied\n"); fflush(stderr);
}
static void parked(void) {
  puts("{\"phase\":\"armed\"}"); fflush(stdout);
  char acknowledgement; need(read(0, &acknowledgement, 1) == 1 && acknowledgement == 'A');
}
static void launch_fixture(char *image, char **arguments) {
  fprintf(stderr, "native-darwin-phase: phase=exec-enter\n"); fflush(stderr);
  admitted_effects = true;
  execv(image, arguments); int error = errno;
  remember("exec-launch", "errno", error); failure(126);
}
/* Ready callers inspect the live kernel image and independently held file bytes. */
static void image_identity(struct identity value, const char *expected) {
  char actual[4096], again[4096];
  need(live(value) && proc_pidpath((pid_t)value.token.val[5], actual, sizeof(actual)) > 0 && !strcmp(actual, expected));
  int fd = open(actual, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); posix_check(fd, "image-open");
  struct stat before, after, named; unsigned char bytes[8192], sum[CC_SHA256_DIGEST_LENGTH];
  need(!fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_nlink == 1 &&
    before.st_uid == getuid() && before.st_gid == getgid() && (before.st_mode & 07777) == 0500 && before.st_size > 0 && before.st_size <= 16777216);
  CC_SHA256_CTX context; need(CC_SHA256_Init(&context)); ssize_t n;
  while ((n = read(fd, bytes, sizeof(bytes))) > 0) need(CC_SHA256_Update(&context, bytes, (CC_LONG)n));
  if (n < 0) { int error = errno; remember("image-read", "errno", error); close(fd); failure(126); }
  need(CC_SHA256_Final(sum, &context) && !fstat(fd, &after) && !lstat(actual, &named) &&
    same_file_stat(&before, &after) && same_file_stat(&before, &named) && before.st_size == after.st_size &&
    before.st_size == named.st_size && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
    before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec && before.st_mtimespec.tv_sec == named.st_mtimespec.tv_sec &&
    before.st_mtimespec.tv_nsec == named.st_mtimespec.tv_nsec && live(value) &&
    proc_pidpath((pid_t)value.token.val[5], again, sizeof(again)) > 0 && !strcmp(actual, again));
  posix_check(close(fd), "image-close"); printf("{\"sha256\":\"");
  for (unsigned i = 0; i < sizeof(sum); i++) printf("%02x", sum[i]); puts("\"}");
}
static int connection(bool tcp, const char *address, const char *nonce) {
  admitted_effects = true;
  int fd = socket(tcp ? AF_INET : AF_UNIX, SOCK_STREAM, 0); if (fd < 0) return errno; int result;
  if (tcp) {
    unsigned long long port = number(address); need(port > 0 && port <= 65535);
    struct sockaddr_in endpoint = {.sin_len = sizeof(endpoint), .sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    need(inet_pton(AF_INET, "127.0.0.1", &endpoint.sin_addr) == 1); result = connect(fd, (struct sockaddr *)&endpoint, sizeof(endpoint));
  } else {
    struct sockaddr_un endpoint = {.sun_len = sizeof(endpoint), .sun_family = AF_UNIX};
    need(strlen(address) < sizeof(endpoint.sun_path)); strcpy(endpoint.sun_path, address);
    result = connect(fd, (struct sockaddr *)&endpoint, sizeof(endpoint));
  }
  int error = result ? errno : 0;
  if (!result) { char reply[33] = {0}; need(write(fd, nonce, 32) == 32); size_t offset = 0;
    while (offset < 32) { ssize_t n = read(fd, reply + offset, 32 - offset); need(n > 0); offset += (size_t)n; }
    need(!strcmp(reply, nonce)); }
  need(!close(fd)); return error;
}
static void receipt(const char *operation, int error) {
  printf("{\"event\":\"completed\",\"operation\":\"%s\",\"error\":%d}\n", operation, error); fflush(stdout);
}
static void attempt(const char *operation) { printf("{\"event\":\"attempt\",\"operation\":\"%s\"}\n", operation); fflush(stdout); }
static void write_attempt(const char *operation, const char *file, bool create, const char *nonce) {
  attempt(operation); int fd = open(file, O_WRONLY | (create ? O_CREAT | O_EXCL : 0), 0600); int error = fd < 0 ? errno : 0;
  if (fd >= 0) { if (write(fd, nonce, 32) != 32) error = errno ? errno : EIO; need(!close(fd)); } receipt(operation, error);
}
static void bundle(char **args) {
  const char *workspace = args[1], *nonce = args[6]; need(strlen(nonce) == 32 && !chdir(workspace)); policy(args[0]);
  puts("{\"event\":\"ready\"}"); char release; need(read(0, &release, 1) == 1 && release == 'A');
  admitted_effects = true; attempt("inspect");
  int fd = open("inspection.txt", O_RDONLY | O_NOFOLLOW); char contents[33] = {0};
  need(fd >= 0 && read(fd, contents, sizeof(contents)) == 32 && !strcmp(contents, nonce) && !close(fd)); receipt("inspect", 0);
  write_attempt("edit", "edited.txt", true, nonce);
  int gate[2]; need(!pipe(gate)); pid_t child = fork(); need(child >= 0);
  if (!child) { close(gate[1]); char byte; if (read(gate[0], &byte, 1) != 1 || byte != 'G') _exit(126); close(gate[0]);
    int null = open("/dev/null", O_WRONLY); need(null >= 0 && dup2(null, 1) >= 0 && dup2(null, 2) >= 0);
    execl(args[7], "git", "-c", "core.fsmonitor=false", "status", "--porcelain", (char *)NULL); _exit(126); }
  close(gate[0]); struct identity git;
  if (!inspect(child, &git)) { close(gate[1]); int status; need(waitpid(child, &status, 0) == child); identity_failure(); }
  printf("{\"event\":\"attempt\",\"operation\":\"git-status\",\"child\":"); emit_identity(git); puts("}"); fflush(stdout);
  need(write(gate[1], "G", 1) == 1 && !close(gate[1]));
  int status; need(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0); receipt("git-status", 0);
  write_attempt("git-index", ".git/index.lock", true, nonce);
  write_attempt("git-ref", ".git/refs/heads/fixture", false, nonce);
  write_attempt("control", args[2], false, nonce); write_attempt("outside", args[3], false, nonce);
  attempt("tcp"); receipt("tcp", connection(true, args[4], nonce));
  attempt("unix"); receipt("unix", connection(false, args[5], nonce));
}
static void fault(void) {
  admitted_effects = true;
  /* Unreleased children exit on owner EOF; released fixture has a safety alarm. */
  int release[2], acknowledged[2]; need(!pipe(release) && !pipe(acknowledged)); pid_t child = fork(); need(child >= 0);
  if (!child) {
    close(release[1]); close(acknowledged[0]); char byte;
    if (read(release[0], &byte, 1) != 1 || byte != 'A') _exit(0);
    need(setsid() > 0); alarm(25); need(write(acknowledged[1], "A", 1) == 1);
    close(release[0]); close(acknowledged[1]); close(0); close(1); close(2); for (;;) pause();
  }
  close(release[0]); close(acknowledged[1]); struct identity owner, descendant;
  if (!inspect(getpid(), &owner) || !inspect(child, &descendant)) {
    close(release[1]); close(acknowledged[0]); int status; need(waitpid(child, &status, 0) == child); identity_failure();
  }
  printf("{\"event\":\"armed\",\"owner\":"); emit_identity(owner); printf(",\"descendant\":"); emit_identity(descendant); puts("}"); fflush(stdout);
  char command;
  if (read(0, &command, 1) != 1 || command != 'A') { close(release[1]); int status; need(waitpid(child, &status, 0) == child); return; }
  need(write(release[1], "A", 1) == 1 && read(acknowledged[0], &command, 1) == 1 && command == 'A');
  close(release[1]); close(acknowledged[0]); puts("{\"event\":\"detached\"}"); fflush(stdout);
  need(read(0, &command, 1) == 1 && (command == 'C' || command == 'L'));
  printf("{\"event\":\"fault-ack\",\"caseId\":\"%s\"}\n", command == 'C' ? "cancel" : "owner-loss"); fflush(stdout);
  for (;;) pause();
}
#ifdef NATIVE_FEASIBILITY_COMMAND
#include "feasibility-command.h"
#endif
int main(int argc, char **argv) {
  umask(077); setvbuf(stdout, NULL, _IOLBF, 0); alarm(20);
  prerequisite_mode = argc >= 2 && !strcmp(argv[1], "prerequisites");
#ifdef NATIVE_FEASIBILITY_COMMAND
  if (argc >= 2 && !strncmp(argv[1], "command-", 8)) { admitted_effects = true; return command_entry(argc, argv); }
#endif
  invariant(getuid() > 500 && geteuid() == getuid() && argc >= 2, "worker-identity");
  invariant(getenv("CI") && !strcmp(getenv("CI"), "true") &&
    getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"), "true") &&
    getenv("RUNNER_ENVIRONMENT") && !strcmp(getenv("RUNNER_ENVIRONMENT"), "github-hosted") &&
    getenv("RUNNER_OS") && !strcmp(getenv("RUNNER_OS"), "macOS"), "worker-environment");
  audit_signal = (audit_signal_fn)dlsym(RTLD_DEFAULT, "proc_signal_with_audittoken");
  sandbox_binding = feasibility_sandbox_load();
  if (!strcmp(argv[1], "prerequisites") && argc == 3) { int fd = directory(argv[2]);
    int closed = close(fd); if (closed) remember_cleanup("directory-close", "errno", errno); posix_check(closed, "directory-close"); prerequisites(); }
  else if (!strcmp(argv[1], "identity") && argc == 3) { struct identity value; if (!inspect((pid_t)number(argv[2]), &value)) identity_failure(); emit_identity(value); puts(""); }
  else if ((!strcmp(argv[1], "observe") || !strcmp(argv[1], "retire") || !strcmp(argv[1], "cancel")) && argc == 14) {
    struct identity value = parse_identity(argv + 2);
    if (strcmp(argv[1], "observe")) { signal_identity(value, !strcmp(argv[1], "cancel") ? SIGTERM : SIGKILL); for (int i = 0; i < 1000 && live(value); i++) usleep(10000); }
    printf("{\"status\":\"%s\"}\n", live(value) ? "LIVE" : "RETIRED");
  } else if ((!strcmp(argv[1], "policy") || !strcmp(argv[1], "policy-absent")) && argc == 14) {
    struct identity value = parse_identity(argv + 2); need(live(value));
    int expected = !strcmp(argv[1], "policy") ? 1 : 0;
    errno = 0; int active = feasibility_sandbox_active(sandbox_binding, (pid_t)value.token.val[5]);
    if (active < 0 && (errno == ENOSYS || errno == ENOTSUP)) { remember("sandbox-query", "errno", errno); failure(78); }
    if (active != expected) remember("sandbox-active", active < 0 ? "errno" : "invariant", active < 0 ? errno : active);
    need(active == expected && live(value)); printf("{\"sandboxed\":%s}\n", expected ? "true" : "false");
  } else if (!strcmp(argv[1], "image") && argc == 15) {
    image_identity(parse_identity(argv + 2), argv[14]);
  } else if (!strcmp(argv[1], "files") && argc >= 3 && argc <= 10) {
    putchar('['); for (int i = 2; i < argc; i++) { int fd = open(argv[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC); need(fd >= 0);
      if (i > 2) putchar(','); emit_file(fd); need(!close(fd)); } puts("]");
  } else if ((!strcmp(argv[1], "remove") || !strcmp(argv[1], "remove-dir")) && argc == 6) remove_owned(argv + 2, !strcmp(argv[1], "remove-dir"));
  else if (!strcmp(argv[1], "storage") && argc == 3) storage(argv[2]);
  else if (!strcmp(argv[1], "control") && argc == 5) { need(strlen(argv[4]) == 32);
    need(!strcmp(argv[2], "tcp") || !strcmp(argv[2], "unix")); need(connection(!strcmp(argv[2], "tcp"), argv[3], argv[4]) == 0); puts("{\"ready\":true}"); }
  else if (!strcmp(argv[1], "control-closed") && argc == 5) { need(strlen(argv[4]) == 32);
    need(!strcmp(argv[2], "tcp") || !strcmp(argv[2], "unix")); bool tcp = !strcmp(argv[2], "tcp");
    need(connection(tcp, argv[3], argv[4]) == (tcp ? ECONNREFUSED : ENOENT)); puts("{\"closed\":true}"); }
  else if ((!strcmp(argv[1], "policy-only") || !strcmp(argv[1], "policy-invalid")) && argc == 3) {
    if (!strcmp(argv[1], "policy-invalid")) parked();
    policy(argv[2]);
    if (!strcmp(argv[1], "policy-only")) { parked(); puts("{\"policyApplied\":true}"); }
  } else if ((!strcmp(argv[1], "exec") || !strcmp(argv[1], "exec-control")) && argc >= 4) {
    if (!strcmp(argv[1], "exec-control")) parked();
    policy(argv[2]); launch_fixture(argv[3], argv + 3);
  } else if (!strcmp(argv[1], "fixture-control") && argc >= 2) {
    /* Fixed sibling fixture only: an outside control, never a launch fallback. */
    char image[4096]; need(proc_pidpath(getpid(), image, sizeof(image)) > 0);
    char *name = strrchr(image, '/'); need(name && !strcmp(name + 1, "helper"));
    need((size_t)(name - image) + sizeof("/argv-fixture") <= sizeof(image));
    strcpy(name + 1, "argv-fixture"); argv[1] = image; launch_fixture(image, argv + 1);
  }
  else if (!strcmp(argv[1], "bundle") && argc == 10) bundle(argv + 2);
  else if (!strcmp(argv[1], "fault") && argc == 2) fault();
  else need(0);
  invariant(!ferror(stdout), "helper-output"); return 0;
}
