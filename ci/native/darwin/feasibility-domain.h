/* Fixed feasibility fault custody only. No full PoC preparation or path RPC. */
#include <bsm/libbsm.h>
#include <grp.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <security/audit/audit_ioctl.h>
#include <mach/mach_vm.h>
#include <mach/mig.h>

static void domain_check(bool ok, const char *operation, const char *kind, int value) {
  if (!ok) { remember(operation, kind, value); failure(126); }
}
static void domain_io(ssize_t result, size_t expected, const char *operation) {
  int error = errno;
  domain_check(result == (ssize_t)expected, operation, result < 0 ? "errno" : "status", result < 0 ? error : (int)result);
}
static void domain_mach(kern_return_t result, const char *operation) {
  domain_check(result == KERN_SUCCESS, operation, "mach", result);
}
static struct identity fault_inspect(pid_t pid) {
  struct identity value; if (!inspect(pid, &value)) identity_failure(); return value;
}
#define NATIVE_AUDIT_DOMAIN_ONLY 1
#define NATIVE_AUDIT_DOMAIN 1
#define AUDIT_DOMAIN_INSPECT(pid) fault_inspect(pid)
#define AUDIT_DOMAIN_DIAG(ok, operation, kind, value) domain_check(ok, operation, kind, value)
#define emit(value) emit_identity(value)
#define NATIVE_RUNTIME_REPLIES 1
#include "custody.h"
#undef NATIVE_RUNTIME_REPLIES
#undef emit

struct fault_record {
  unsigned version, stage, members, emergency;
  uid_t uid; gid_t gid; au_asid_t asid;
  char candidate[41], case_id[16], helper_hash[65], policy_hash[65], intent[65];
  struct identity custodian, owner, descendant, known[32];
  unsigned observer_count; struct identity observers[4];
  unsigned observer_kinds[4]; char observer_hashes[4][65];
  char creator_receipt[512], constructor_program[65], constructor_capture[65];
};
static struct fault_record domain_record;
static char domain_path[4096], domain_helper[4096], domain_policy[4096];
static int domain_root = -1, domain_journal = -1;
static mach_port_t domain_pin;
static bool domain_fenced;
/* One entry per owned reference, even when local names alias. Special-port
 * slots and uninspected census names never enter this cleanup inventory. */
static pid_t domain_port_owner;
static mach_port_t domain_bootstrap_local, domain_host_copy, domain_access_copy, domain_thread_copy;
static domain_special_reply_fn domain_special_reply;
static void domain_special_reply_load(void) {
  domain_special_reply = domain_special_reply_lookup();
  invariant(domain_special_reply != NULL, "fault-special-reply-binding");
}
static mach_port_t domain_reply_borrowed, domain_special_reply_borrowed;
static void domain_ports_begin(void) {
  invariant(domain_port_owner != getpid(), "fault-port-owner");
  /* libSystem reinitializes Mach state after fork and exec. Copied bookkeeping
   * from another process is not authority over names in this new IPC space. */
  domain_port_owner = getpid();
  domain_host_copy = domain_access_copy = domain_thread_copy = MACH_PORT_NULL;
  domain_runtime_replies_begin(domain_port_owner);
  extern mach_port_t bootstrap_port;
  domain_bootstrap_local = bootstrap_port; bootstrap_port = MACH_PORT_NULL;
  domain_reply_borrowed = domain_special_reply_borrowed = MACH_PORT_NULL;
  domain_special_reply_load();
  domain_reply_borrowed = mig_get_reply_port();
  invariant(MACH_PORT_VALID(domain_reply_borrowed), "fault-reply-port");
  /* This cached acquisition returns the existing special reply if present;
   * its producer allocates only for an absent cache. The raw allocating and
   * rebinding thread_get_special_reply_port trap is never used as a query. */
  domain_special_reply_borrowed = domain_special_reply();
  invariant(MACH_PORT_VALID(domain_special_reply_borrowed) &&
    domain_special_reply_borrowed != domain_reply_borrowed, "fault-special-reply-port");
}
static kern_return_t domain_port_release(mach_port_t *held, const char *operation) {
  mach_port_t name = *held; *held = MACH_PORT_NULL;
  if (!MACH_PORT_VALID(name)) return KERN_SUCCESS;
  kern_return_t result = mach_port_deallocate(mach_task_self(), name);
  if (result != KERN_SUCCESS) {
    remember(operation, "mach", result); remember_cleanup(operation, "mach", result);
  }
  return result;
}
static void domain_port_cleanup(void) {
  if (domain_port_owner != getpid()) return;
  domain_port_owner = 0;
  domain_port_release(&domain_bootstrap_local, "fault-bootstrap-release");
  domain_port_release(&domain_access_copy, "fault-access-release");
  domain_port_release(&domain_host_copy, "fault-host-release");
  domain_port_release(&domain_thread_copy, "fault-thread-release");
  domain_reply_borrowed = domain_special_reply_borrowed = MACH_PORT_NULL;
  /* Constructor observations and cache borrows remain runtime-owned. Retain
   * observations through release RPCs; exec resets them, fork must rebind them. */
}
static pid_t domain_controller, domain_child = -1;
static int domain_status, domain_pipes[5][2] = {{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1}};
static bool domain_released, domain_exit_reported;
static bool domain_stream(const unsigned char *bytes, ssize_t size, const char *stream) {
  printf("{\"stream\":\"%s\",\"hex\":\"", stream);
  for (ssize_t at = 0; at < size; at++) printf("%02x", bytes[at]); puts("\"}");
  if (!ferror(stdout)) return true;
  remember("fault-output-write", "errno", errno);
  remember_cleanup("fault-output-write", "errno", errno); return false;
}
static bool domain_exited(void);
/* Failure owns acquired pipe endpoints before any subsequent operation. An
 * unreleased direct child exits on EOF; no numeric-PID signal is authorized. */
static void settle_domain(void) {
  domain_port_cleanup();
  if (domain_controller != getpid()) return;
  bool capture = domain_child > 0 && !domain_released, waiting = capture, reaped_child = false;
  unsigned totals[2] = {0, 0};
  for (unsigned pipe = 0; pipe < 5; pipe++) for (unsigned end = 0; end < 2; end++) {
    if (capture && (pipe == 1 || pipe == 2) && !end) continue;
    int fd = domain_pipes[pipe][end]; domain_pipes[pipe][end] = -1;
    if (fd >= 0 && close(fd)) remember_cleanup("fault-close", "errno", errno);
  }
  if (!capture) return;
  for (unsigned pass = 0; pass < 200; pass++) {
    for (unsigned pipe = 1; pipe <= 2; pipe++) {
      int fd = domain_pipes[pipe][0]; if (fd < 0) continue;
      struct pollfd stream = {.fd = fd, .events = POLLIN};
      int available = poll(&stream, 1, 0);
      if (!available || (available < 0 && errno == EINTR)) continue;
      ssize_t size = -1; unsigned char bytes[4096];
      if (available < 0) remember_cleanup("fault-poll", "errno", errno);
      else {
        size = read(fd, bytes, sizeof(bytes));
        if (size < 0 && errno == EINTR) continue;
        if (size < 0) remember_cleanup("fault-output-read", "errno", errno);
        else {
          totals[pipe - 1] += (unsigned)size;
          if (totals[pipe - 1] > 65536) { remember_cleanup("fault-output-bound", "invariant", 0); size = -1; }
          else if (size > 0) (void)domain_stream(bytes, size, pipe == 1 ? "stdout" : "stderr");
        }
      }
      if (size <= 0) {
        domain_pipes[pipe][0] = -1;
        if (close(fd)) remember_cleanup("fault-close", "errno", errno);
      }
    }
    if (waiting) {
      pid_t reaped = waitpid(domain_child, &domain_status, WNOHANG);
      if (reaped == domain_child) { domain_child = -1; waiting = false; reaped_child = true; }
      else if (reaped < 0 && errno != EINTR) { remember_cleanup("fault-wait", "errno", errno); waiting = false; }
    }
    if (!waiting && domain_pipes[1][0] < 0 && domain_pipes[2][0] < 0) break;
    (void)poll(NULL, 0, 10);
  }
  if (waiting) remember_cleanup("fault-wait", "invariant", 0);
  for (unsigned pipe = 1; pipe <= 2; pipe++) {
    int fd = domain_pipes[pipe][0]; domain_pipes[pipe][0] = -1;
    if (fd < 0) continue;
    remember_cleanup("fault-output-drain", "invariant", 0);
    if (close(fd)) remember_cleanup("fault-close", "errno", errno);
  }
  if (reaped_child) (void)domain_exited();
}
static void domain_close(int *fd) {
  int held = *fd; *fd = -1;
  if (held >= 0) posix_check(close(held), "fault-close");
}
static void domain_reap(void) {
  if (domain_child <= 0) return;
  pid_t reaped = waitpid(domain_child, &domain_status, WNOHANG);
  if (reaped == domain_child) {
    domain_child = -1;
    invariant(!(WIFSIGNALED(domain_status) && WTERMSIG(domain_status) == SIGALRM), "fault-child-backstop");
  } else domain_check(reaped == 0 || (reaped < 0 && errno == EINTR), "fault-wait", "errno", errno);
}
static void domain_output(int *fd, const char *stream) {
  unsigned total = 0;
  while (*fd >= 0) {
    unsigned char bytes[4096]; ssize_t size = read(*fd, bytes, sizeof(bytes));
    posix_check((int)size, "fault-output-read");
    if (!size) { domain_close(fd); return; }
    total += (unsigned)size; invariant(total <= 65536, "fault-output-bound");
    invariant(domain_stream(bytes, size, stream), "fault-output-write");
  }
}
static bool domain_exited(void) {
  if (domain_child > 0 || domain_exit_reported) return true;
  if (!(WIFEXITED(domain_status) || WIFSIGNALED(domain_status))) {
    remember_cleanup("fault-child-status", "invariant", domain_status); return false;
  }
  domain_exit_reported = true;
  printf("{\"exit\":{\"code\":%d,\"signal\":%d}}\n", WIFEXITED(domain_status) ? WEXITSTATUS(domain_status) : -1,
    WIFSIGNALED(domain_status) ? WTERMSIG(domain_status) : 0);
  if (!ferror(stdout)) return true;
  remember("fault-output-write", "errno", errno);
  remember_cleanup("fault-output-write", "errno", errno); return false;
}
static void domain_hex(const void *bytes, size_t length, char out[65]) {
  unsigned char sum[32]; need(CC_SHA256(bytes, (CC_LONG)length, sum));
  for (unsigned i = 0; i < 32; i++) snprintf(out + 2*i, 3, "%02x", sum[i]);
}
static bool domain_hash(const char *value) { return strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64; }
static bool domain_file_same(const struct stat *a, const struct stat *b) {
  return same_file_stat(a, b) && a->st_size == b->st_size &&
    a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
    a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static void domain_metadata(const char *object, const struct stat *st) {
  fprintf(stderr, "native-darwin-fault-metadata: object=%s uid=%ju gid=%ju mode=%#o links=%ju size=%jd dev=%ju inode=%ju\n",
    object, (uintmax_t)st->st_uid, (uintmax_t)st->st_gid, (unsigned)st->st_mode,
    (uintmax_t)st->st_nlink, (intmax_t)st->st_size, (uintmax_t)st->st_dev, (uintmax_t)st->st_ino);
  fflush(stderr);
}
static void domain_shape(bool ok, const struct stat *st, const char *operation) {
  if (!ok) domain_metadata(operation, st);
  invariant(ok, operation);
}
/* Only freshly created objects enter here; recovery never repairs metadata. */
static void domain_initialize(int fd, bool directory) {
  struct stat before, after;
  const char *shape = directory ? "fault-root-shape" : "fault-journal-shape";
  const char *stat_operation = directory ? "fault-root-stat" : "fault-journal-stat";
  posix_check(fstat(fd, &before), stat_operation);
  domain_metadata(directory ? "created-root" : "created-journal", &before);
  domain_shape(directory ? S_ISDIR(before.st_mode) :
    S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_size == 0, &before, shape);
  posix_check(fchown(fd, 0, 0), directory ? "fault-root-owner" : "fault-journal-owner");
  mode_t mode = directory ? 0700 : 0400;
  posix_check(fchmod(fd, mode), directory ? "fault-root-mode" : "fault-journal-mode");
  posix_check(fstat(fd, &after), stat_operation);
  struct stat expected = before; expected.st_uid = 0; expected.st_gid = 0;
  expected.st_mode = (before.st_mode & S_IFMT) | mode;
  domain_shape(same_file_stat(&expected, &after) && (directory || after.st_size == 0), &after, shape);
  no_acl(fd, &after);
}
static void domain_location(const char *nonce) {
  need(strlen(nonce) == 32 && strspn(nonce, "0123456789abcdef") == 32);
  need(snprintf(domain_path, sizeof(domain_path), "/private/var/run/native-feasibility-%s", nonce) < sizeof(domain_path));
  snprintf(domain_helper, sizeof(domain_helper), "%s/helper", domain_path);
  snprintf(domain_policy, sizeof(domain_policy), "%s/policy", domain_path);
}
static void domain_store(unsigned stage) {
  domain_record.stage = stage;
  domain_io(pwrite(domain_journal, &domain_record, sizeof(domain_record), 0), sizeof(domain_record), "fault-journal-write");
  posix_check(fsync(domain_journal), "fault-journal-sync");
  posix_check(fsync(domain_root), "fault-root-sync");
}
static void domain_emit(void) {
  char pin[65]; domain_hex(&domain_record, sizeof(domain_record), pin);
  printf("{\"candidateSha\":\"%s\",\"caseId\":\"%s\",\"asid\":%u,\"stage\":%u,\"emergency\":%s,\"receiptSha256\":\"%s\",\"intentSha256\":\"%s\",\"helperSha256\":\"%s\",\"policySha256\":\"%s\",\"custodian\":",
    domain_record.candidate, domain_record.case_id, domain_record.asid, domain_record.stage, domain_record.emergency ? "true" : "false", pin, domain_record.intent, domain_record.helper_hash, domain_record.policy_hash);
  emit_identity(domain_record.custodian); fputs(",\"owner\":", stdout); emit_identity(domain_record.owner);
  fputs(",\"descendant\":", stdout); emit_identity(domain_record.descendant); fputs(",\"members\":[", stdout);
  for (unsigned i = 0; i < domain_record.members; i++) { if(i) putchar(','); emit_identity(domain_record.known[i]); }
  char creator[65] = {0}; if (domain_record.creator_receipt[0]) domain_hex(domain_record.creator_receipt, sizeof(domain_record.creator_receipt), creator);
  printf("],\"creatorReceiptSha256\":\"%s\",\"constructorProgramSha256\":\"%s\",\"constructorCaptureSha256\":\"%s\"}",
    creator, domain_record.constructor_program, domain_record.constructor_capture);
}
static void domain_copy(const char *source, const char *leaf, const char *pin, mode_t mode, uid_t uid, gid_t gid) {
  int fd = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat before, after, named;
  posix_check(fd, "fault-copy-open"); posix_check(fstat(fd, &before), "fault-copy-stat");
  invariant(S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_uid == uid && before.st_gid == gid &&
    !(before.st_mode & 022) && before.st_size > 0 && before.st_size <= 16777216, "fault-copy-shape");
  no_acl(fd, &before); unsigned char *bytes = malloc((size_t)before.st_size); invariant(bytes != NULL, "fault-copy-buffer");
  domain_io(pread(fd, bytes, before.st_size, 0), before.st_size, "fault-copy-read");
  posix_check(fstat(fd, &after), "fault-copy-stat"); posix_check(lstat(source, &named), "fault-copy-stat");
  invariant(domain_file_same(&before, &after) && domain_file_same(&before, &named), "fault-copy-binding");
  char hash[65]; domain_hex(bytes, before.st_size, hash); invariant(!strcmp(hash, pin), "fault-copy-hash"); posix_check(close(fd), "fault-copy-close");
  int target = openat(domain_root, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  posix_check(target, "fault-copy-create"); domain_io(write(target, bytes, before.st_size), before.st_size, "fault-copy-write");
  posix_check(fchown(target, 0, 0), "fault-copy-owner"); posix_check(fchmod(target, mode), "fault-copy-mode");
  posix_check(fsync(target), "fault-copy-sync"); posix_check(close(target), "fault-copy-close"); free(bytes);
}
static void domain_image(struct identity value) {
  char image[4096]; need(proc_pidpath(value.token.val[5], image, sizeof(image)) > 0 && !strcmp(image, domain_helper));
  int fd = openat(domain_root, "helper", O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat before, after, named;
  need(fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) && !before.st_uid && !before.st_gid &&
    before.st_nlink == 1 && (before.st_mode & 07777) == 0555 && before.st_size > 0 && before.st_size <= 16777216);
  no_acl(fd, &before); unsigned char *bytes = malloc(before.st_size); need(bytes && pread(fd, bytes, before.st_size, 0) == before.st_size);
  char hash[65]; domain_hex(bytes, before.st_size, hash); free(bytes);
  need(!strcmp(hash, domain_record.helper_hash) && !fstat(fd, &after) && !fstatat(domain_root, "helper", &named, AT_SYMLINK_NOFOLLOW) &&
    domain_file_same(&before, &after) && domain_file_same(&before, &named) && !close(fd) && audit_identity_same(value, fault_inspect(value.token.val[5])));
}
static void domain_policy_check(void) {
  int fd = openat(domain_root,"policy",O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat before, after, named; unsigned char bytes[16385];
  need(fd >= 0 && !fstat(fd,&before) && S_ISREG(before.st_mode) && !before.st_uid && !before.st_gid &&
    before.st_nlink == 1 && (before.st_mode & 07777) == 0444 && before.st_size > 0 && before.st_size <= 16384);
  no_acl(fd,&before); need(pread(fd,bytes,sizeof(bytes),0) == before.st_size && !memchr(bytes,0,before.st_size));
  char hash[65]; domain_hex(bytes,before.st_size,hash);
  need(!strcmp(hash,domain_record.policy_hash) && !fstat(fd,&after) && !fstatat(domain_root,"policy",&named,AT_SYMLINK_NOFOLLOW) &&
    domain_file_same(&before,&after) && domain_file_same(&before,&named) && !close(fd));
}
static void domain_access_diagnostic(const char *phase, kern_return_t got, mach_port_t access,
                                     mach_port_type_t type, int query, int released) {
  int saved = errno;
  fprintf(stderr, "native-darwin-fault-access-lifecycle: phase=%s pid=%d parent=%d uid=%ju euid=%ju gid=%ju egid=%ju get=%d name=%u type=%#x query=%d release=%d\n",
    phase, getpid(), getppid(), (uintmax_t)getuid(), (uintmax_t)geteuid(),
    (uintmax_t)getgid(), (uintmax_t)getegid(), got, access, type, query, released);
  fflush(stderr); errno = saved;
}
/* Observe our own public getter only. Its copied send reference belongs to this
 * call even if the optional type query fails; no message is sent to the port.
 * Neither a local name nor releasing this copy identifies or clears the slot. */
static void domain_access_observe(const char *phase) {
  int saved = errno; task_t self = mach_task_self(); mach_port_t access = MACH_PORT_NULL;
  kern_return_t got = task_get_special_port(self, TASK_ACCESS_PORT, &access);
  mach_port_type_t type = access == MACH_PORT_DEAD ? MACH_PORT_TYPE_DEAD_NAME : MACH_PORT_TYPE_NONE;
  int query = -1, released = -1;
  if (got == KERN_SUCCESS && MACH_PORT_VALID(access)) {
    query = mach_port_type(self, access, &type);
    released = mach_port_deallocate(self, access);
  }
  domain_access_diagnostic(phase, got, access, type, query, released); errno = saved;
  if (released != -1 && released != KERN_SUCCESS) {
    remember_cleanup("fault-access-release", "mach", released);
    domain_mach(released, "fault-access-release");
  }
}
static void domain_access_release(task_t self, mach_port_t access, mach_port_type_t type) {
  bool owned = type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE | MACH_PORT_TYPE_DEAD_NAME);
  domain_access_copy = MACH_PORT_NULL;
  kern_return_t released = owned ? mach_port_deallocate(self, access) : KERN_SUCCESS;
  domain_access_diagnostic("payload", KERN_SUCCESS, access, type, KERN_SUCCESS, owned ? released : -1);
  if (released != KERN_SUCCESS) {
    remember("fault-access-release", "mach", released);
    remember_cleanup("fault-access-release", "mach", released);
    failure(126);
  }
}
/* Diagnostic reads occur at the first failed census predicate, before releases.
 * They grant no authority and never replace that predicate's original refusal. */
static void domain_port_diagnostic(mach_port_t name, mach_port_type_t census_type) {
  int saved = errno, query, object_query = -1;
  mach_port_type_t current = MACH_PORT_TYPE_NONE; natural_t kind = 0; mach_vm_address_t object = 0;
  query = mach_port_type(mach_task_self(), name, &current);
  if (query == KERN_SUCCESS && (current & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE | MACH_PORT_TYPE_RECEIVE)))
    object_query = mach_port_kobject(mach_task_self(), name, &kind, &object);
  fprintf(stderr, "native-darwin-fault-port: name=%u census-type=%#x type-query=%d type=%#x object-query=%d object-kind=%u object=%llu\n",
    name, census_type, query, current, object_query, kind, (unsigned long long)object);
  fflush(stderr); errno = saved;
}
static void domain_sanitize(void) {
  invariant(domain_port_owner == getpid(), "fault-port-owner");
  task_t self = mach_task_self(); thread_t thread = mach_thread_self();
  domain_thread_copy = thread;
  invariant(MACH_PORT_VALID(thread) && thread != self, "fault-thread-port");
  mach_port_t host = MACH_PORT_NULL, access = MACH_PORT_NULL;
  natural_t type; mach_vm_address_t address;
  kern_return_t host_get = task_get_special_port(self,TASK_HOST_PORT,&host);
  if (host_get == KERN_SUCCESS) domain_host_copy = host;
  domain_mach(host_get, "fault-host-port");
  domain_mach(mach_port_kobject(self,host,&type,&address), "fault-host-kind"); invariant(type == 3, "fault-host-kind");
  kern_return_t access_get = task_get_special_port(self,TASK_ACCESS_PORT,&access);
  if (access_get == KERN_SUCCESS) domain_access_copy = access;
  domain_mach(access_get, "fault-access-port");
  /* XNU consults the target task's access port when authorizing task_for_pid.
   * Ordinary hosted execution trusts that inherited authorization service, not
   * arbitrary SEND rights. Require the slot's exact SEND type and IKOT_NONE;
   * a task/thread or other kernel object cannot stand in for the service.
   * Keep this getter copy through the census. Its local name is meaningful only
   * in this task; releasing it never clears or overwrites the special slot. */
  bool access_held = false;
  mach_port_type_t access_type = access == MACH_PORT_DEAD ? MACH_PORT_TYPE_DEAD_NAME : MACH_PORT_TYPE_NONE;
  kern_return_t access_query = KERN_SUCCESS;
  if (MACH_PORT_VALID(access)) access_query = mach_port_type(self, access, &access_type);
  /* A successful getter transfers a copy before the required type query. Its
   * failure must not lose that acquired reference. A successful query exposing
   * no deallocatable reference still cannot authorize a receive-right release. */
  if (access_query == KERN_SUCCESS &&
      !(access_type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE | MACH_PORT_TYPE_DEAD_NAME)))
    domain_access_copy = MACH_PORT_NULL;
  if (access != MACH_PORT_NULL) {
    fprintf(stderr, "native-darwin-fault-access: name=%u type=%#x query=%d\n", access, access_type, access_query);
    fflush(stderr);
  }
  /* Query refusal authorizes no use of the endpoint; failure only settles copies. */
  if (access_query != KERN_SUCCESS)
    domain_access_diagnostic("payload", KERN_SUCCESS, access, access_type, access_query, -1);
  domain_mach(access_query, "fault-access-kind");
  if (MACH_PORT_VALID(access)) {
    kern_return_t service_query = KERN_SUCCESS;
    if (access_type == MACH_PORT_TYPE_SEND) {
      service_query = mach_port_kobject(self, access, &type, &address);
      if (service_query != KERN_SUCCESS) remember("fault-access-service", "mach", service_query);
      else access_held = type == 0; /* IKOT_NONE, not task-control authority. */
    }
    bool accepted = access_held || access_type == MACH_PORT_TYPE_DEAD_NAME;
    if (!accepted && service_query == KERN_SUCCESS) remember("fault-access-authority", "invariant", 0);
    if (!access_held) domain_access_release(self, access, access_type);
    if (!accepted) failure(126);
  } else domain_access_diagnostic("payload", KERN_SUCCESS, access, access_type, -1, -1);
  domain_mach(task_set_special_port(self, TASK_BOOTSTRAP_PORT, MACH_PORT_NULL), "fault-bootstrap-port");
  /* Clearing the kernel slot does not consume libSystem's local reference. */
  domain_mach(domain_port_release(&domain_bootstrap_local, "fault-bootstrap-release"), "fault-bootstrap-release");
  domain_mach(task_set_special_port(self,TASK_DEBUG_CONTROL_PORT,MACH_PORT_NULL), "fault-debug-port");
  /* XNU omits both resource-notify selectors without CONFIG_PROC_RESOURCE_LIMITS.
   * Only that paired result on our own task establishes unavailability. A live
   * slot must clear and read back null; getter copies are independent references. */
  mach_port_t notify = MACH_PORT_NULL, readback = MACH_PORT_NULL;
  kern_return_t notify_get = task_get_special_port(self, TASK_RESOURCE_NOTIFY_PORT, &notify);
  kern_return_t notify_set = task_set_special_port(self, TASK_RESOURCE_NOTIFY_PORT, MACH_PORT_NULL);
  bool notify_unavailable = notify_get == KERN_INVALID_ARGUMENT && notify_set == KERN_INVALID_ARGUMENT;
  kern_return_t notify_read = KERN_FAILURE;
  if (!notify_unavailable) {
    if (notify_get != KERN_SUCCESS) remember("fault-notify-get", "mach", notify_get);
    else if (notify_set != KERN_SUCCESS) remember("fault-notify-port", "mach", notify_set);
    else {
      notify_read = task_get_special_port(self, TASK_RESOURCE_NOTIFY_PORT, &readback);
      if (notify_read != KERN_SUCCESS) remember("fault-notify-read", "mach", notify_read);
      else if (readback != MACH_PORT_NULL) remember("fault-notify-read", "invariant", 0);
    }
  }
  kern_return_t notify_release = notify_get == KERN_SUCCESS && MACH_PORT_VALID(notify)
    ? mach_port_deallocate(self, notify) : KERN_SUCCESS;
  kern_return_t readback_release = notify_read == KERN_SUCCESS && MACH_PORT_VALID(readback)
    ? mach_port_deallocate(self, readback) : KERN_SUCCESS;
  if (notify_release != KERN_SUCCESS) {
    remember("fault-notify-release", "mach", notify_release);
    remember_cleanup("fault-notify-release", "mach", notify_release);
  }
  if (readback_release != KERN_SUCCESS) {
    remember("fault-notify-release", "mach", readback_release);
    remember_cleanup("fault-notify-release", "mach", readback_release);
  }
  if ((!notify_unavailable && (notify_get != KERN_SUCCESS || notify_set != KERN_SUCCESS ||
      notify_read != KERN_SUCCESS || readback != MACH_PORT_NULL)) ||
      notify_release != KERN_SUCCESS || readback_release != KERN_SUCCESS) failure(126);
  domain_mach(mach_ports_register(self, NULL, 0), "fault-registered-ports");
  domain_mach(task_set_exception_ports(self, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE), "fault-task-exceptions");
  domain_mach(thread_set_exception_ports(thread, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE), "fault-thread-exceptions");
  /* Cache reads and producer returns are provenance; the census only checks
   * that those exact names and types survive. Never invalidate a runtime cache
   * or promote an unknown receive right by its type or IKOT_NONE observation. */
  mach_port_t reply = domain_reply_borrowed, special = domain_special_reply_borrowed;
  invariant(MACH_PORT_VALID(reply) && reply != self && reply != thread &&
    reply != host && (!access_held || reply != access) && mig_get_reply_port() == reply, "fault-reply-port");
  invariant(MACH_PORT_VALID(special) && special != self && special != thread &&
    special != host && special != reply && (!access_held || special != access) &&
    domain_special_reply() == special, "fault-special-reply-port");
  unsigned runtime_count = domain_runtime_reply_count, runtime_seen = 0;
  invariant(domain_runtime_reply_owner == getpid() && domain_runtime_reply_imported && !domain_runtime_reply_overflow &&
    runtime_count <= 8, "fault-runtime-reply-port");
  for (unsigned i = 0; i < runtime_count; i++) {
    mach_port_t name = domain_runtime_replies[i];
    invariant(MACH_PORT_VALID(name) && name != self && name != thread && name != host &&
      (!access_held || name != access), "fault-runtime-reply-port");
    for (unsigned j = 0; j < i; j++)
      invariant(name != domain_runtime_replies[j], "fault-runtime-reply-port");
  }
  mach_port_name_array_t names; mach_port_type_array_t types; mach_msg_type_number_t n, nt;
  domain_mach(mach_port_names(self, &names, &n, &types, &nt), "fault-port-list");
  bool census_ok = n == nt && n <= 4096;
  if (!census_ok) remember("fault-port-count", "invariant", 0);
  if (mig_get_reply_port() != reply) {
    remember("fault-reply-port", "invariant", 0); census_ok = false;
  }
  if (domain_special_reply() != special) {
    remember("fault-special-reply-port", "invariant", 0); census_ok = false;
  }
  if (domain_runtime_reply_owner != getpid() || !domain_runtime_reply_imported || domain_runtime_reply_overflow ||
      domain_runtime_reply_count != runtime_count) {
    remember("fault-runtime-reply-port", "invariant", 0); census_ok = false;
  }
  bool self_seen = false, thread_seen = false, reply_seen = false, special_seen = false;
  bool host_seen = false, access_seen = !access_held;
  for (unsigned i = 0; census_ok && i < n; i++) {
    bool allowed, runtime_reply = false;
    for (unsigned j = 0; j < runtime_count; j++) if (names[i] == domain_runtime_replies[j]) {
      runtime_reply = true; runtime_seen |= 1u << j;
    }
    if (names[i] == self) {
      allowed = types[i] == MACH_PORT_TYPE_SEND; self_seen = true;
    } else if (names[i] == thread) {
      allowed = types[i] == MACH_PORT_TYPE_SEND; thread_seen = true;
    } else if (names[i] == reply) {
      allowed = types[i] == MACH_PORT_TYPE_RECEIVE; reply_seen = true;
    } else if (names[i] == special) {
      allowed = types[i] == (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE); special_seen = true;
    } else if (names[i] == host) {
      allowed = types[i] == MACH_PORT_TYPE_SEND; host_seen = true;
    } else if (access_held && names[i] == access) {
      allowed = types[i] == MACH_PORT_TYPE_SEND; access_seen = true;
    } else if (runtime_reply) allowed = types[i] == MACH_PORT_TYPE_RECEIVE;
    else allowed = types[i] == MACH_PORT_TYPE_DEAD_NAME;
    for (unsigned j = 0; j < i; j++) if (names[j] == names[i]) allowed = false;
    if (!allowed) {
      remember("fault-port-authority", "invariant", 0);
      domain_port_diagnostic(names[i], types[i]); census_ok = false;
    }
  }
  /* Unknown live rights refuse exec; destroying them cannot prove confinement. */
  if (census_ok && !(self_seen && thread_seen && reply_seen && special_seen && host_seen && access_seen &&
      runtime_seen == ((1u << runtime_count) - 1))) {
    remember("fault-port-authority", "invariant", 0);
    mach_port_t missing = !self_seen ? self : !thread_seen ? thread : !reply_seen ? reply :
      !special_seen ? special : !host_seen ? host : !access_seen ? access : MACH_PORT_NULL;
    if (!MACH_PORT_VALID(missing)) for (unsigned i = 0; i < runtime_count; i++)
      if (!(runtime_seen & (1u << i))) { missing = domain_runtime_replies[i]; break; }
    domain_port_diagnostic(missing, MACH_PORT_TYPE_NONE); census_ok = false;
  }
  kern_return_t names_release = mach_vm_deallocate(self, (mach_vm_address_t)names, n*sizeof(*names));
  kern_return_t types_release = mach_vm_deallocate(self, (mach_vm_address_t)types, nt*sizeof(*types));
  if (names_release != KERN_SUCCESS) {
    remember("fault-port-list-release", "mach", names_release); remember_cleanup("fault-port-list-release", "mach", names_release);
  }
  if (types_release != KERN_SUCCESS) {
    remember("fault-port-list-release", "mach", types_release); remember_cleanup("fault-port-list-release", "mach", types_release);
  }
  if (!census_ok || names_release != KERN_SUCCESS || types_release != KERN_SUCCESS) failure(126);
  if (access_held) domain_access_release(self, access, access_type);
  domain_port_cleanup();
  if (resource_uncertain) failure(126);
  invariant(mig_get_reply_port() == reply, "fault-reply-port");
  invariant(domain_special_reply() == special, "fault-special-reply-port");
  invariant(domain_runtime_reply_owner == getpid() && domain_runtime_reply_imported && !domain_runtime_reply_overflow &&
    domain_runtime_reply_count == runtime_count, "fault-runtime-reply-port");
}
static void domain_denied(int result, const char *operation) {
  int error = errno;
  domain_check(result == -1 && error == EPERM, operation, result == -1 ? "errno" : "status", result == -1 ? error : result);
}
static void domain_controls(void) {
  auditinfo_addr_t before, after; posix_check(getaudit_addr(&before, sizeof(before)), "fault-control-audit-read");
  errno = 0; domain_denied(setuid(0), "fault-control-uid"); errno = 0; domain_denied(setgid(0), "fault-control-gid");
  gid_t root = 0; errno = 0; domain_denied(setgroups(1, &root), "fault-control-groups");
  after = before; after.ai_asid = AU_ASSIGN_ASID; errno = 0; domain_denied(setaudit_addr(&after, sizeof(after)), "fault-control-audit-create");
  const char *parent = getenv("NATIVE_FAULT_PARENT_ASID"); invariant(parent != NULL, "fault-control-parent");
  mach_port_t port = MACH_PORT_NULL; errno = 0; domain_denied(audit_session_port(number(parent), &port), "fault-control-audit-hold");
  invariant(port == MACH_PORT_NULL, "fault-control-audit-port");
  task_t task = MACH_PORT_NULL; kern_return_t result = task_for_pid(mach_task_self(), getppid(), &task);
  domain_check(result == KERN_FAILURE || result == KERN_PROTECTION_FAILURE, "fault-control-task", "mach", result);
  invariant(task == MACH_PORT_NULL, "fault-control-task-port"); posix_check(getaudit_addr(&after, sizeof(after)), "fault-control-audit-read");
  invariant(after.ai_asid == before.ai_asid && after.ai_auid == before.ai_auid, "fault-control-audit-binding");
}
static void domain_known(struct identity value) {
  need(value.token.val[6] == domain_record.asid && value.token.val[0] == domain_record.uid);
  for (unsigned i = 0; i < domain_record.members; i++) if (audit_identity_same(value, domain_record.known[i])) return;
  need(domain_record.members < 32); domain_record.known[domain_record.members++] = value;
}
static bool domain_birth_same(struct identity value, struct proc_bsdinfo b) {
  return b.pbi_pid == value.token.val[5] && b.pbi_start_tvsec == value.bsd.pbi_start_tvsec &&
    b.pbi_start_tvusec == value.bsd.pbi_start_tvusec && b.pbi_uid == value.token.val[1] && b.pbi_gid == value.token.val[2] &&
    b.pbi_ruid == value.token.val[3] && b.pbi_rgid == value.token.val[4] &&
    b.pbi_svuid == value.bsd.pbi_svuid && b.pbi_svgid == value.bsd.pbi_svgid;
}
static void domain_recheck(void) {
  for (unsigned i = 0; i < domain_record.members; i++) {
    struct identity value = domain_record.known[i]; struct proc_bsdinfo b; errno = 0;
    int size = proc_pidinfo(value.token.val[5], PROC_PIDTBSDINFO, 1, &b, sizeof(b));
    if (!size) { need(errno == ESRCH || errno == ENOENT); continue; }
    need(size == sizeof(b) && domain_birth_same(value, b));
    if (b.pbi_status != SZOMB) need(audit_identity_same(value, fault_inspect(value.token.val[5])));
  }
}
static bool domain_observers_retired(bool retire) {
  need(domain_record.observer_count <= 4); bool complete = true;
  for (unsigned i = 0; i < domain_record.observer_count; i++) {
    struct identity value = domain_record.observers[i];
    if (retire && constructor_observer_live(value)) {
      signal_identity(value, SIGKILL);
      for (unsigned pass = 0; pass < 1000 && constructor_observer_live(value); pass++) (void)poll(NULL, 0, 10);
    }
    if (constructor_observer_live(value)) complete = false;
  }
  return complete;
}
static void domain_retire(void) {
  need(domain_record.stage == 3 && domain_pin != MACH_PORT_NULL); domain_fenced = true; domain_store(4);
  for (unsigned pass = 0; pass < 32; pass++) {
    domain_reap();
    struct audit_domain_view view = audit_census(domain_record.uid, domain_record.asid); domain_recheck();
    for (unsigned i = 0; i < view.nd; i++) {
      bool known = false; for (unsigned j = 0; j < domain_record.members; j++) {
        struct identity value = domain_record.known[j];
        if (domain_birth_same(value, view.dead[i])) known = true;
      } need(known);
    }
    if (!view.nl && !view.nd && domain_child < 0) { need(domain_observers_retired(true)); domain_store(5); return; }
    for (unsigned i = 0; i < view.nl; i++) {
      domain_known(view.live[i]); domain_store(4); /* exact signal intent precedes the effect */
      need(audit_identity_same(view.live[i], fault_inspect(view.live[i].token.val[5]))); signal_identity(view.live[i], SIGKILL);
    }
    (void)poll(NULL, 0, 10);
  }
  need(false);
}
static void domain_open(const char *nonce, const char *pin) {
  domain_location(nonce); domain_root = open(domain_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  posix_check(domain_root, "fault-root-open"); struct stat st;
  posix_check(fstat(domain_root, &st), "fault-root-stat");
  domain_shape(S_ISDIR(st.st_mode) && !st.st_uid && !st.st_gid &&
    ((st.st_mode & 07777) == 0711 || (st.st_mode & 07777) == 0700), &st, "fault-root-shape"); no_acl(domain_root, &st);
  domain_journal = openat(domain_root, "receipt", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  posix_check(domain_journal, "fault-journal-open"); posix_check(fstat(domain_journal, &st), "fault-journal-stat");
  domain_shape(S_ISREG(st.st_mode) && !st.st_uid && !st.st_gid &&
    st.st_nlink == 1 && (st.st_mode & 07777) == 0400 && st.st_size == sizeof(domain_record), &st, "fault-journal-shape"); no_acl(domain_journal, &st);
  domain_io(pread(domain_journal, &domain_record, sizeof(domain_record), 0), sizeof(domain_record), "fault-journal-read");
  char hash[65]; domain_hex(&domain_record, sizeof(domain_record), hash);
  invariant((!pin || (domain_hash(pin) && !strcmp(pin, hash))) && domain_record.version == 3, "fault-journal-binding");
}
static void domain_transfer(void) {
  struct stat inherited, held;
  posix_check(fstat(3, &inherited), "fault-inherited-stat");
  posix_check(fstat(domain_journal, &held), "fault-journal-stat");
  invariant(domain_root != 3 && domain_journal != 3 && same_file_stat(&inherited, &held), "fault-journal-transfer");
  int flags = fcntl(3, F_GETFL); posix_check(flags, "fault-journal-flags");
  invariant((flags & O_ACCMODE) == O_RDWR, "fault-journal-access");
  posix_check(close(domain_journal), "fault-journal-close");
  domain_journal = 3; /* Retain the original writable description, never reopen by name. */
  posix_check(fcntl(domain_journal, F_SETFD, FD_CLOEXEC), "fault-journal-flags");
}
static void domain_verify(bool closed, const char *nonce, const char *pin) {
  domain_open(nonce, pin); need(domain_observers_retired(false)); need(!domain_record.emergency && domain_record.stage == (closed ? 6 : 5));
  domain_policy_check();
  audit_fresh(0); /* sudo preserves the runner's login audit identity. */
  struct identity verifier = fault_inspect(getpid()); need(verifier.token.val[6] != domain_record.asid);
  if (!closed) {
    struct identity holder = fault_inspect(domain_record.custodian.token.val[5]); need(audit_identity_same(holder, domain_record.custodian)); domain_image(holder);
    domain_pin = audit_hold(domain_record.asid); need(audit_identity_same(holder, fault_inspect(holder.token.val[5])));
  } else {
    struct proc_bsdinfo gone; errno = 0;
    need(!proc_pidinfo(domain_record.custodian.token.val[5], PROC_PIDTBSDINFO, 1, &gone, sizeof(gone)) && (errno == ESRCH || errno == ENOENT));
    struct audit_domain_view holders = audit_census((uid_t)-1,domain_record.custodian.token.val[6]); need(!holders.nl && !holders.nd);
  }
  struct audit_domain_view view = audit_census(domain_record.uid, domain_record.asid); domain_recheck(); need(!view.nl && !view.nd);
  fputs("{\"independent\":true,\"complete\":true,\"held\":", stdout); fputs(closed ? "false" : "true", stdout);
  fputs(",\"verifier\":", stdout); emit_identity(verifier); fputs(",\"record\":", stdout); domain_emit(); puts("}");
}
static void domain_parent_verify(const char *nonce) {
  domain_open(nonce, NULL); need(domain_record.stage <= 1 && !domain_record.emergency);
  struct identity actual = fault_inspect(domain_record.custodian.token.val[5]);
  need(audit_identity_same(actual, domain_record.custodian)); domain_image(actual);
  need(domain_record.observer_count <= 4);
  for (unsigned i = 0; i < domain_record.observer_count; i++) {
    char hash[65]; need(domain_record.observer_kinds[i] == 1 || domain_record.observer_kinds[i] == 2);
    need(audit_observer_digest(domain_record.observer_kinds[i] == 1 ? "/usr/bin/sudo" : "/usr/sbin/dtrace", hash) &&
      !strcmp(hash, domain_record.observer_hashes[i]));
  }
  fputs("{\"parent\":", stdout); emit_identity(actual); puts("}");
}
static void domain_parent_gate(void) {
  char line[512];
  for (;;) {
    need(fgets(line, sizeof(line), stdin) && strchr(line, '\n'));
    if (!strcmp(line, "P\n")) break;
    char *fields[15]; unsigned count = 0;
    for (char *word = strtok(line, " \n"); word; word = strtok(NULL, " \n")) { need(count < 15); fields[count++] = word; }
    need(count == 14 && !strcmp(fields[0], "O") && domain_hash(fields[13])); struct identity expected = parse_identity(fields + 1), actual;
    const char *kind = startup_observer(expected.token.val[5], &actual); char hash[65];
    need(audit_identity_same(expected, actual) && audit_observer_digest(!strcmp(kind, "sudo") ? "/usr/bin/sudo" : "/usr/sbin/dtrace", hash) && !strcmp(hash, fields[13]));
    bool known = false; for (unsigned i = 0; i < domain_record.observer_count; i++) if (audit_identity_same(expected, domain_record.observers[i])) { need(!strcmp(hash, domain_record.observer_hashes[i])); known = true; }
    if (!known) {
      need(domain_record.observer_count < 4); unsigned index = domain_record.observer_count++;
      domain_record.observers[index] = expected; domain_record.observer_kinds[index] = !strcmp(kind, "sudo") ? 1 : 2;
      strcpy(domain_record.observer_hashes[index], hash); domain_store(0);
    }
    fputs("{\"observerStored\":true}\n", stdout); fflush(stdout);
  }
  need(audit_identity_same(domain_record.custodian, fault_inspect(getpid())));
}
static void domain_start(int argc, char **argv) {
  invariant(argc == 10 && strlen(argv[3]) == 40 && strspn(argv[3], "0123456789abcdef") == 40 &&
    (!strcmp(argv[4], "cancel") || !strcmp(argv[4], "owner-loss")) && domain_hash(argv[6]) && domain_hash(argv[7]), "fault-start-input");
  uid_t uid = number(argv[8]); gid_t gid = number(argv[9]); invariant(uid > 500 && gid > 0, "fault-start-input");
  char canonical[4096]; struct stat root;
  errno = 0; char *resolved = realpath(argv[2], canonical); int resolve_error = errno;
  domain_check(resolved != NULL, "fault-root-resolve", "errno", resolve_error);
  posix_check(lstat(canonical, &root), "fault-root-stat");
  invariant(!strcmp(canonical, argv[2]) && S_ISDIR(root.st_mode) && root.st_uid == uid && root.st_gid == gid && (root.st_mode & 07777) == 0700, "fault-start-root");
  admitted_effects = true;
  domain_location(argv[5]);
  if (!strcmp(argv[1], "fault-custody")) {
    domain_open(argv[5], NULL);
    invariant(!domain_record.stage && !strcmp(domain_record.candidate, argv[3]) && !strcmp(domain_record.case_id, argv[4]) &&
      !strcmp(domain_record.helper_hash, argv[6]) && !strcmp(domain_record.policy_hash, argv[7]) && domain_record.uid == 90001 && domain_record.gid == 90002, "fault-reexec-binding");
    domain_transfer();
  } else {
  domain_access_observe("custodian-entry");
  posix_check(mkdir(domain_path, 0700), "fault-root-create");
  domain_root = open(domain_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); posix_check(domain_root, "fault-root-open");
  domain_initialize(domain_root, true);
  domain_journal = openat(domain_root, "receipt", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400); posix_check(domain_journal, "fault-journal-open");
  domain_initialize(domain_journal, false);
  domain_record.version = 3; domain_record.uid = 90001; domain_record.gid = 90002;
  strcpy(domain_record.candidate, argv[3]); strcpy(domain_record.case_id, argv[4]); strcpy(domain_record.helper_hash, argv[6]); strcpy(domain_record.policy_hash, argv[7]);
  domain_record.custodian = fault_inspect(getpid()); domain_store(0);
  char source[4096]; snprintf(source, sizeof(source), "%s/build/helper", canonical); domain_copy(source, "helper", argv[6], 0555, uid, gid);
  snprintf(source, sizeof(source), "%s/evidence/%s.sb", canonical, argv[4]); domain_copy(source, "policy", argv[7], 0444, uid, gid);
  struct stat held, traversable, journal;
  posix_check(fstat(domain_root, &held), "fault-root-stat");
  posix_check(fchmod(domain_root, 0711), "fault-root-mode");
  posix_check(fstat(domain_root, &traversable), "fault-root-stat");
  held.st_uid = 0; held.st_gid = 0; held.st_mode = S_IFDIR | 0711;
  domain_shape(same_file_stat(&held, &traversable), &traversable, "fault-root-shape"); no_acl(domain_root, &traversable);
  posix_check(fstat(domain_journal, &journal), "fault-journal-stat");
  domain_shape(S_ISREG(journal.st_mode) && !journal.st_uid && !journal.st_gid && journal.st_nlink == 1 &&
    (journal.st_mode & 07777) == 0400 && journal.st_size == sizeof(domain_record), &journal, "fault-journal-shape"); no_acl(domain_journal, &journal);
  posix_check(fsync(domain_root), "fault-root-sync");
  posix_check(dup2(domain_journal, 3), "fault-journal-duplicate"); posix_check(fcntl(3, F_SETFD, 0), "fault-journal-flags");
  argv[0] = domain_helper; argv[1] = "fault-custody"; execv(domain_helper, argv);
  int exec_error = errno; remember("fault-reexec", "errno", exec_error); failure(126);
  }
  au_asid_t parent_asid = audit_fresh(0); domain_record.custodian = fault_inspect(getpid()); domain_store(0);
  fputs("{\"hello\":", stdout); domain_emit(); puts("}"); fflush(stdout);
  domain_parent_gate();
  const char *lease_path = "/private/var/run/native-feasibility-fault.lock";
  int lease = open(lease_path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
  bool lease_created = lease >= 0;
  if (lease < 0 && errno == EEXIST)
    lease = open(lease_path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  posix_check(lease, "fault-lease-open");
  struct stat lease_before, lease_stat, lease_named;
  posix_check(fstat(lease, &lease_before), "fault-lease-stat");
  domain_shape(S_ISREG(lease_before.st_mode) && lease_before.st_nlink == 1 &&
    (lease_created || (!lease_before.st_uid && !lease_before.st_gid &&
      (lease_before.st_mode & 07777) == 0600)), &lease_before, "fault-lease-shape");
  posix_check(flock(lease,LOCK_EX|LOCK_NB), "fault-lease-lock");
  struct stat lease_expected = lease_before;
  if (lease_created) {
    /* Exclusive creation and the held lock authorize initialization, never reuse. */
    domain_metadata("created-lease", &lease_before);
    posix_check(fchown(lease, 0, 0), "fault-lease-owner");
    posix_check(fchmod(lease, 0600), "fault-lease-mode");
    lease_expected.st_uid = 0; lease_expected.st_gid = 0;
    lease_expected.st_mode = (lease_before.st_mode & S_IFMT) | 0600;
  }
  posix_check(fstat(lease, &lease_stat), "fault-lease-stat");
  domain_shape(same_file_stat(&lease_expected, &lease_stat), &lease_stat, "fault-lease-shape");
  no_acl(lease, &lease_stat);
  posix_check(lstat(lease_path, &lease_named), "fault-lease-stat");
  domain_shape(domain_file_same(&lease_stat, &lease_named), &lease_named, "fault-lease-shape");
  /* Keep this description locked through custody; never unlink or replace it. */
  struct audit_domain_view absent = audit_census(domain_record.uid, 0); invariant(!absent.nl && !absent.nd, "fault-uid-empty");
  domain_controller = getpid();
  invariant(signal(SIGPIPE, SIG_IGN) != SIG_ERR, "fault-signal");
  int *in = domain_pipes[0], *out = domain_pipes[1], *err = domain_pipes[2], *ready = domain_pipes[3], *release = domain_pipes[4];
  posix_check(pipe(in), "fault-pipe"); posix_check(pipe(out), "fault-pipe"); posix_check(pipe(err), "fault-pipe");
  posix_check(pipe(ready), "fault-pipe"); posix_check(pipe(release), "fault-pipe");
  domain_access_observe("custodian-fork");
  struct proc_taskinfo threads;
  invariant(proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &threads, sizeof(threads)) == sizeof(threads) && threads.pti_threadnum == 1, "fault-fork-threads");
  pid_t child = fork(); posix_check(child, "fault-fork");
  if (!child) {
    alarm(20); domain_ports_begin(); domain_access_observe("child-fork");
    posix_check(close(ready[0]), "fault-close"); posix_check(close(release[1]), "fault-close"); audit_fresh(domain_record.uid);
    struct rlimit limit = {.rlim_cur = 32, .rlim_max = 32}; posix_check(setrlimit(RLIMIT_NPROC, &limit), "fault-process-limit");
    posix_check(setgroups(0, NULL), "fault-groups"); posix_check(setgid(domain_record.gid), "fault-gid"); posix_check(setuid(domain_record.uid), "fault-uid");
    posix_check(dup2(in[0], 0), "fault-stdio"); posix_check(dup2(out[1], 1), "fault-stdio"); posix_check(dup2(err[1], 2), "fault-stdio");
    domain_check(dup2(ready[1], 3) == 3 && dup2(release[0], 4) == 4 &&
      !fcntl(3, F_SETFD, FD_CLOEXEC) && !fcntl(4, F_SETFD, FD_CLOEXEC), "fault-creator-descriptors", "errno", errno);
    struct proc_fdinfo fds[512]; errno = 0; int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    int fd_error = errno; domain_check(size > 0, "fault-fd-list", fd_error ? "errno" : "status", fd_error ? fd_error : size);
    invariant(size < sizeof(fds) && !(size % sizeof(fds[0])), "fault-fd-count");
    for (unsigned i = 0; i < (unsigned)size/sizeof(fds[0]); i++) if (fds[i].proc_fd > 4) posix_check(close(fds[i].proc_fd), "fault-close");
    char parent[24]; snprintf(parent, sizeof(parent), "%u", parent_asid);
    posix_check(setenv("NATIVE_FAULT_PARENT_ASID", parent, 1), "fault-environment"); posix_check(unsetenv("NATIVE_STARTUP_CUSTODY"), "fault-environment");
    /* Finish libc setup before the final census: an environment allocation
     * cannot introduce an uninspected runtime right between sanitation and exec. */
    struct identity birth = fault_inspect(getpid());
    invariant(domain_creator_checkpoint(3, 4, birth), "fault-creator-receipt");
    char *arguments[] = {domain_helper, "exec", domain_policy, domain_helper, "fault", NULL};
    extern char **environ;
    domain_sanitize();
    invariant(domain_creator_final(3, birth), "fault-creator-final");
    char gate; ssize_t gate_read = read(4, &gate, 1);
    if (gate_read != 1) domain_exec_failure(2, gate_read < 0 ? "native-darwin: operation=fault-gate-read domain=errno value=" : "native-darwin: operation=fault-gate-read domain=status value=", " effects=possible settlement=unsettled\n", gate_read < 0 ? errno : (int)gate_read);
    if (gate != 'R') domain_exec_failure(2, "native-darwin: operation=fault-gate-value domain=invariant value=", " effects=possible settlement=unsettled\n", 0);
    if (close(4)) domain_exec_failure(2, "native-darwin: operation=fault-close domain=errno value=", " effects=possible settlement=unsettled\n", errno);
    (void)domain_prepared_exec(domain_helper, arguments, environ); int exec_error = errno;
    domain_exec_failure(2, "native-darwin: operation=fault-payload-exec domain=errno value=", " effects=possible settlement=unsettled\n", exec_error);
  }
  domain_child = child;
  domain_close(&ready[1]); domain_close(&release[0]); domain_close(&in[0]);
  domain_close(&out[1]); domain_close(&err[1]);
  struct domain_creator_frame pre, post;
  domain_io(read(ready[0], &pre, sizeof(pre)), sizeof(pre), "fault-birth-read");
  invariant(pre.version == 1 && pre.phase == 1 && pre.identity.token.val[5] == (unsigned)child &&
    audit_identity_same(pre.identity, fault_inspect(child)), "fault-birth-binding");
  domain_record.owner = pre.identity;
  domain_record.asid = domain_record.owner.token.val[6]; domain_store(1); domain_pin = audit_hold(domain_record.asid);
  invariant(audit_identity_same(domain_record.owner, fault_inspect(child)), "fault-birth-binding");
  fputs("{\"creator\":{\"version\":1,\"phase\":1,\"record\":", stdout); domain_emit(); puts("}}"); fflush(stdout);
  char line[1040], receipt[DOMAIN_CREATOR_BYTES];
  invariant(fgets(line, sizeof(line), stdin) && strlen(line) == 1033 && !strncmp(line, "creator ", 8) && line[1032] == '\n', "fault-creator-frame");
  for (unsigned i = 0; i < DOMAIN_CREATOR_BYTES; i++) {
    char pair[3] = {line[8+2*i], line[9+2*i], 0};
    invariant(strspn(pair, "0123456789abcdef") == 2, "fault-creator-frame");
    receipt[i] = (char)strtoul(pair, NULL, 16);
  }
  memcpy(domain_record.creator_receipt, receipt, sizeof(receipt)); domain_store(1);
  domain_io(write(release[1], receipt, sizeof(receipt)), sizeof(receipt), "fault-gate-write");
  domain_io(read(ready[0], &post, sizeof(post)), sizeof(post), "fault-final-read");
  char trailing; domain_io(read(ready[0], &trailing, 1), 0, "fault-final-drain"); domain_close(&ready[0]);
  invariant(post.version == 1 && post.phase == 2 && audit_identity_same(post.identity, domain_record.owner) &&
    audit_identity_same(domain_record.owner, fault_inspect(child)), "fault-final-binding");
  fputs("{\"sealed\":{\"version\":1,\"phase\":2,\"record\":", stdout); domain_emit(); puts("}}"); fflush(stdout);
  char seal[137];
  invariant(fgets(seal, sizeof(seal), stdin) && strlen(seal) == 136 && !strncmp(seal, "seal1 ", 6) && seal[70] == ' ' && seal[135] == '\n', "fault-final-release");
  memcpy(domain_record.constructor_program, seal + 6, 64); memcpy(domain_record.constructor_capture, seal + 71, 64);
  invariant(domain_hash(domain_record.constructor_program) && domain_hash(domain_record.constructor_capture), "fault-final-release");
  domain_store(1);
  domain_released = true; /* Persisted original birth owns an uncertain write. */
  domain_io(write(release[1], "R", 1), 1, "fault-gate-write"); domain_close(&release[1]);
  fputs("{\"ready\":", stdout); domain_emit(); puts("}");
  unsigned expected_sequence = 0;
  for (;;) {
    struct pollfd streams[] = {{0,POLLIN,0}, {out[0],POLLIN,0}, {err[0],POLLIN,0}};
    bool closing = out[0] < 0 && err[0] < 0 && !domain_exit_reported;
    int polled = poll(streams, 3, closing ? 10 : 12000), poll_error = errno;
    domain_check(polled > 0 || (closing && !polled), "fault-poll", polled < 0 ? "errno" : "status", polled < 0 ? poll_error : polled);
    for (unsigned i = 1; i < 3; i++) if (streams[i].fd >= 0 && (streams[i].revents & (POLLIN | POLLHUP))) {
      unsigned char bytes[4096]; ssize_t size = read(streams[i].fd, bytes, sizeof(bytes)); posix_check((int)size, "fault-output-read");
      if (!size) { domain_close(i == 1 ? &out[0] : &err[0]); continue; }
      invariant(domain_stream(bytes, size, i == 1 ? "stdout" : "stderr"), "fault-output-write");
    }
    if (out[0] < 0 && err[0] < 0) { domain_reap(); invariant(domain_exited(), "fault-child-status"); }
    if (!(streams[0].revents & (POLLIN | POLLHUP))) continue;
    char line[1024]; need(fgets(line, sizeof(line), stdin) && strchr(line, '\n')); char *fields[20]; unsigned count = 0;
    for (char *word = strtok(line, " \n"); word; word = strtok(NULL, " \n")) { need(count < 20); fields[count++] = word; }
    need(count >= 2); unsigned sequence = number(fields[0]); need(sequence == ++expected_sequence);
    if (!strcmp(fields[1], "recover")) {
      need(count == 2 && !domain_record.emergency && ((domain_record.stage >= 1 && domain_record.stage <= 3) || domain_record.stage == 5) && domain_pin != MACH_PORT_NULL);
      domain_fenced = true; domain_close(&in[1]);
      if (domain_record.stage != 5) { domain_store(3); domain_retire(); }
      domain_output(&out[0], "stdout"); domain_output(&err[0], "stderr"); invariant(domain_exited(), "fault-child-status");
    }
    printf("{\"sequence\":%u,\"value\":", sequence);
    if (!strcmp(fields[1], "payload")) { need(count == 3 && !domain_fenced && strlen(fields[2]) == 1 && strchr("ACL", *fields[2]) && domain_record.stage >= 2 && domain_record.stage < 4); need(write(in[1], fields[2], 1) == 1); fputs("null",stdout);
    } else if (!strcmp(fields[1], "identity")) {
      need(count == 4); pid_t pid = number(fields[2]); struct identity value = fault_inspect(pid);
      need(value.bsd.pbi_ppid == number(fields[3]) && (pid == child || value.bsd.pbi_ppid == child) && value.token.val[6] == domain_record.asid &&
        value.token.val[0] == domain_record.uid && value.token.val[1] == domain_record.uid && value.token.val[2] == domain_record.gid && value.token.val[3] == domain_record.uid && value.token.val[4] == domain_record.gid && value.bsd.pbi_svuid == domain_record.uid && value.bsd.pbi_svgid == domain_record.gid);
      if (pid == child) domain_record.owner = value; else { need(!domain_record.descendant.token.val[5] || domain_record.descendant.token.val[5] == (unsigned)pid); domain_record.descendant = value; }
      domain_known(value); emit_identity(value);
    } else if (!strcmp(fields[1], "image") || !strcmp(fields[1], "policy") || !strcmp(fields[1], "observe")) {
      need(count == 14); struct identity value = parse_identity(fields + 2); need(value.token.val[5] == domain_record.owner.token.val[5] || value.token.val[5] == domain_record.descendant.token.val[5]);
      if (!strcmp(fields[1], "observe")) printf("{\"status\":\"%s\"}", live(value) ? "LIVE" : "RETIRED");
      else { need(live(value)); domain_image(value); if (!strcmp(fields[1], "image")) printf("{\"sha256\":\"%s\"}", domain_record.helper_hash);
        else { need(feasibility_sandbox_active(sandbox_binding,value.token.val[5]) == 1); fputs("{\"sandboxed\":true}",stdout); } }
    } else if (!strcmp(fields[1], "files")) { need(count == 2); domain_policy_check(); printf("[{\"sha256\":\"%s\"}]",domain_record.policy_hash);
    } else if (!strcmp(fields[1], "intent")) {
      need(count == 3 && domain_record.stage == 1 && domain_record.members == 2 && domain_hash(fields[2])); strcpy(domain_record.intent, fields[2]); domain_store(2); domain_emit();
    } else if (!strcmp(fields[1], "fault")) {
      need(count == 2 && domain_record.stage == 2); domain_store(3); signal_identity(domain_record.owner, !strcmp(domain_record.case_id,"cancel") ? SIGTERM : SIGKILL);
      int status; pid_t reaped; do { reaped = waitpid(child,&status,0); } while (reaped < 0 && errno == EINTR);
      posix_check(reaped, "fault-wait"); invariant(reaped == child, "fault-wait");
      domain_child = -1; domain_status = status; domain_exit_reported = true;
      domain_check(WIFSIGNALED(status) && WTERMSIG(status) == (!strcmp(domain_record.case_id,"cancel") ? SIGTERM : SIGKILL), "fault-child-status", "status", status);
      char trailing; invariant(out[0] >= 0 && err[0] >= 0, "fault-output-state");
      domain_io(read(out[0],&trailing,1), 0, "fault-output-drain"); domain_io(read(err[0],&trailing,1), 0, "fault-output-drain");
      domain_close(&out[0]); domain_close(&err[0]); fputs("{\"status\":\"RETIRED\"}",stdout);
    } else if (!strcmp(fields[1], "retire")) { need(count == 2); domain_retire(); domain_emit();
    } else if (!strcmp(fields[1], "recover")) { domain_emit();
    } else if (!strcmp(fields[1], "emergency")) {
      need(count == 2 && domain_record.stage >= 1 && domain_record.stage <= 3); domain_record.emergency = 1; domain_store(3);
      domain_fenced = true; domain_close(&in[1]); signal_identity(domain_record.owner,SIGKILL);
      pid_t reaped; do { reaped = waitpid(child,&domain_status,0); } while (reaped < 0 && errno == EINTR);
      need(reaped == child || (reaped < 0 && errno == ECHILD && domain_child < 0));
      domain_child = -1; domain_retire(); domain_emit();
    } else if (!strcmp(fields[1], "close")) {
      need(count == 2 && domain_record.stage == 5); domain_recheck(); struct audit_domain_view view = audit_census(domain_record.uid,domain_record.asid); need(!view.nl && !view.nd);
      domain_store(6); need(!fchmod(domain_root,0700) && mach_port_deallocate(mach_task_self(),domain_pin) == KERN_SUCCESS); domain_emit(); puts("}"); return;
    } else need(false);
    puts("}");
  }
}
