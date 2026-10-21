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
#include "custody.h"
#undef emit

struct fault_record {
  unsigned version, stage, members, emergency;
  uid_t uid; gid_t gid; au_asid_t asid;
  char candidate[41], case_id[16], helper_hash[65], policy_hash[65], intent[65];
  struct identity custodian, owner, descendant, known[32];
};
static struct fault_record domain_record;
static char domain_path[4096], domain_helper[4096], domain_policy[4096];
static int domain_root = -1, domain_journal = -1;
static mach_port_t domain_pin;
static bool domain_fenced;
static pid_t domain_controller, domain_child = -1;
static int domain_status, domain_pipes[5][2] = {{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1}};
static bool domain_released, domain_exit_reported;
/* Failure owns acquired pipe endpoints before any subsequent operation. An
 * unreleased direct child exits on EOF; no numeric-PID signal is authorized. */
static void settle_domain(void) {
  if (domain_controller != getpid()) return;
  for (unsigned pipe = 0; pipe < 5; pipe++) for (unsigned end = 0; end < 2; end++) {
    int fd = domain_pipes[pipe][end]; domain_pipes[pipe][end] = -1;
    if (fd >= 0 && close(fd)) remember_cleanup("fault-close", "errno", errno);
  }
  if (domain_child <= 0 || domain_released) return;
  for (unsigned pass = 0; pass < 200; pass++) {
    pid_t reaped = waitpid(domain_child, &domain_status, WNOHANG);
    if (reaped == domain_child) { domain_child = -1; return; }
    if (reaped < 0 && errno != EINTR) { remember_cleanup("fault-wait", "errno", errno); return; }
    (void)poll(NULL, 0, 10);
  }
  remember_cleanup("fault-wait", "invariant", 0);
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
    printf("{\"stream\":\"%s\",\"hex\":\"", stream);
    for (ssize_t at = 0; at < size; at++) printf("%02x", bytes[at]); puts("\"}");
  }
}
static void domain_exited(void) {
  if (domain_child > 0 || domain_exit_reported) return;
  invariant(WIFEXITED(domain_status) || WIFSIGNALED(domain_status), "fault-child-status");
  domain_exit_reported = true;
  printf("{\"exit\":{\"code\":%d,\"signal\":%d}}\n", WIFEXITED(domain_status) ? WEXITSTATUS(domain_status) : -1,
    WIFSIGNALED(domain_status) ? WTERMSIG(domain_status) : 0);
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
  for (unsigned i = 0; i < domain_record.members; i++) { if(i) putchar(','); emit_identity(domain_record.known[i]); } fputs("]}",stdout);
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
  kern_return_t released = owned ? mach_port_deallocate(self, access) : KERN_SUCCESS;
  domain_access_diagnostic("payload", KERN_SUCCESS, access, type, KERN_SUCCESS, owned ? released : -1);
  if (released != KERN_SUCCESS) {
    remember("fault-access-release", "mach", released);
    remember_cleanup("fault-access-release", "mach", released);
    failure(126);
  }
}
static void domain_sanitize(void) {
  task_t self = mach_task_self(); thread_t thread = mach_thread_self();
  mach_port_t host, access; natural_t type; mach_vm_address_t address;
  domain_mach(task_get_special_port(self,TASK_HOST_PORT,&host), "fault-host-port");
  domain_mach(mach_port_kobject(self,host,&type,&address), "fault-host-kind"); invariant(type == 3, "fault-host-kind");
  domain_mach(task_get_special_port(self,TASK_ACCESS_PORT,&access), "fault-access-port");
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
  if (access != MACH_PORT_NULL) {
    fprintf(stderr, "native-darwin-fault-access: name=%u type=%#x query=%d\n", access, access_type, access_query);
    fflush(stderr);
  }
  /* A failed query cannot authorize another operation on an uninspected name. */
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
  domain_mach(task_set_special_port(self,TASK_DEBUG_CONTROL_PORT,MACH_PORT_NULL), "fault-debug-port");
  domain_mach(task_set_special_port(self,TASK_RESOURCE_NOTIFY_PORT,MACH_PORT_NULL), "fault-notify-port");
  domain_mach(mach_ports_register(self, NULL, 0), "fault-registered-ports");
  domain_mach(task_set_exception_ports(self, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE), "fault-task-exceptions");
  domain_mach(thread_set_exception_ports(thread, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE), "fault-thread-exceptions");
  extern mach_port_t bootstrap_port; bootstrap_port = MACH_PORT_NULL;
  mig_dealloc_reply_port(mig_get_reply_port()); mach_port_t reply = mig_get_reply_port();
  mach_port_name_array_t names; mach_port_type_array_t types; mach_msg_type_number_t n, nt;
  domain_mach(mach_port_names(self, &names, &n, &types, &nt), "fault-port-list"); invariant(n == nt && n <= 4096, "fault-port-count");
  bool host_seen = false, access_seen = !access_held;
  for (unsigned i = 0; i < n; i++) {
    if (names[i] == self || names[i] == thread || names[i] == reply) continue;
    if (names[i] == host) {
      invariant(types[i] == MACH_PORT_TYPE_SEND, "fault-port-authority"); host_seen = true;
    } else if (access_held && names[i] == access) {
      invariant(types[i] == MACH_PORT_TYPE_SEND, "fault-port-authority"); access_seen = true;
    } else invariant(types[i] == MACH_PORT_TYPE_DEAD_NAME, "fault-port-authority");
  }
  /* Unknown live rights refuse exec; destroying them cannot prove confinement. */
  invariant(host_seen && access_seen, "fault-port-authority");
  domain_mach(mach_vm_deallocate(self, (mach_vm_address_t)names, n*sizeof(*names)), "fault-port-list-release");
  domain_mach(mach_vm_deallocate(self, (mach_vm_address_t)types, nt*sizeof(*types)), "fault-port-list-release");
  if (access_held) domain_access_release(self, access, access_type);
  domain_mach(mach_port_deallocate(self, host), "fault-host-release");
  domain_mach(mach_port_deallocate(self, thread), "fault-thread-release");
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
    if (!view.nl && !view.nd && domain_child < 0) { domain_store(5); return; }
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
  invariant((!pin || (domain_hash(pin) && !strcmp(pin, hash))) && domain_record.version == 2, "fault-journal-binding");
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
  domain_open(nonce, pin); need(!domain_record.emergency && domain_record.stage == (closed ? 6 : 5));
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
  domain_record.version = 2; domain_record.uid = 90001; domain_record.gid = 90002;
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
  pid_t child = fork(); posix_check(child, "fault-fork");
  if (!child) {
    alarm(20); domain_access_observe("child-fork");
    posix_check(close(ready[0]), "fault-close"); posix_check(close(release[1]), "fault-close"); audit_fresh(domain_record.uid);
    struct rlimit limit = {.rlim_cur = 32, .rlim_max = 32}; posix_check(setrlimit(RLIMIT_NPROC, &limit), "fault-process-limit");
    posix_check(setgroups(0, NULL), "fault-groups"); posix_check(setgid(domain_record.gid), "fault-gid"); posix_check(setuid(domain_record.uid), "fault-uid");
    struct identity birth = fault_inspect(getpid()); domain_io(write(ready[1], &birth, sizeof(birth)), sizeof(birth), "fault-birth-write");
    char gate; domain_io(read(release[0], &gate, 1), 1, "fault-gate-read"); invariant(gate == 'P', "fault-gate-value");
    posix_check(dup2(in[0], 0), "fault-stdio"); posix_check(dup2(out[1], 1), "fault-stdio"); posix_check(dup2(err[1], 2), "fault-stdio");
    struct proc_fdinfo fds[512]; errno = 0; int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    int fd_error = errno; domain_check(size > 0, "fault-fd-list", fd_error ? "errno" : "status", fd_error ? fd_error : size);
    invariant(size < sizeof(fds) && !(size % sizeof(fds[0])), "fault-fd-count");
    for (unsigned i = 0; i < (unsigned)size/sizeof(fds[0]); i++) if (fds[i].proc_fd > 2) posix_check(close(fds[i].proc_fd), "fault-close");
    domain_sanitize(); char parent[24]; snprintf(parent, sizeof(parent), "%u", parent_asid);
    posix_check(setenv("NATIVE_FAULT_PARENT_ASID", parent, 1), "fault-environment"); posix_check(unsetenv("NATIVE_STARTUP_CUSTODY"), "fault-environment");
    execl(domain_helper, domain_helper, "exec", domain_policy, domain_helper, "fault", NULL);
    int exec_error = errno; remember("fault-payload-exec", "errno", exec_error); failure(126);
  }
  domain_child = child;
  domain_close(&ready[1]); domain_close(&release[0]); domain_close(&in[0]);
  domain_close(&out[1]); domain_close(&err[1]);
  domain_io(read(ready[0], &domain_record.owner, sizeof(domain_record.owner)), sizeof(domain_record.owner), "fault-birth-read");
  domain_close(&ready[0]);
  invariant(domain_record.owner.token.val[5] == (unsigned)child && audit_identity_same(domain_record.owner, fault_inspect(child)), "fault-birth-binding");
  domain_record.asid = domain_record.owner.token.val[6]; domain_store(1); domain_pin = audit_hold(domain_record.asid);
  invariant(audit_identity_same(domain_record.owner,fault_inspect(child)), "fault-birth-binding");
  domain_released = true; /* A failed write cannot prove the child remained parked. */
  domain_io(write(release[1], "P", 1), 1, "fault-gate-write"); domain_close(&release[1]);
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
      printf("{\"stream\":\"%s\",\"hex\":\"", i == 1 ? "stdout" : "stderr"); for (ssize_t at = 0; at < size; at++) printf("%02x",bytes[at]); puts("\"}");
    }
    if (out[0] < 0 && err[0] < 0) { domain_reap(); domain_exited(); }
    if (!(streams[0].revents & (POLLIN | POLLHUP))) continue;
    char line[1024]; need(fgets(line, sizeof(line), stdin) && strchr(line, '\n')); char *fields[20]; unsigned count = 0;
    for (char *word = strtok(line, " \n"); word; word = strtok(NULL, " \n")) { need(count < 20); fields[count++] = word; }
    need(count >= 2); unsigned sequence = number(fields[0]); need(sequence == ++expected_sequence);
    if (!strcmp(fields[1], "recover")) {
      need(count == 2 && !domain_record.emergency && ((domain_record.stage >= 1 && domain_record.stage <= 3) || domain_record.stage == 5) && domain_pin != MACH_PORT_NULL);
      domain_fenced = true; domain_close(&in[1]);
      if (domain_record.stage != 5) { domain_store(3); domain_retire(); }
      domain_output(&out[0], "stdout"); domain_output(&err[0], "stderr"); domain_exited();
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
