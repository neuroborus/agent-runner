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
#define NATIVE_CREATION_INPUTS 1
#include "custody.h"
#undef NATIVE_CREATION_INPUTS
#undef emit
#include "image-closure.h"
#include <Security/Security.h>

struct fault_record {
  unsigned version, stage, members, emergency;
  uid_t uid; gid_t gid; au_asid_t asid;
  char candidate[41], case_id[16], helper_hash[65], policy_hash[65], intent[65];
  struct identity custodian, owner, descendant, known[32];
  unsigned observer_count; struct identity observers[4];
  unsigned observer_kinds[4]; char observer_hashes[4][65];
  char creator_receipt[512], constructor_program[65], constructor_capture[65];
  /* The aligned prefix remains the exact version-three recovery format. */
  struct identity creator, target;
  unsigned execution, continuation;
  uint64_t deadline;
  char observations[65], cdhash[41], root[4096];
  /* Version five keeps the complete version-four ABI as a recovery prefix. */
  _Alignas(uint64_t) unsigned control;
  unsigned control_retired, probe_consumed;
  struct identity control_creator, control_target;
  char control_hash[65], control_cdhash[41], control_observations[65], control_output[65];
  struct stat control_file, control_parent;
  struct exec_probe probe;
};
static struct fault_record domain_record;
static unsigned char domain_control_bytes[4096];
static size_t domain_control_used;
/* Historical receipts are read using their original ABI, never upgraded in place. */
struct fault_record_legacy {
  unsigned version, stage, members, emergency;
  uid_t uid; gid_t gid; au_asid_t asid;
  char candidate[41], case_id[16], helper_hash[65], policy_hash[65], intent[65];
  struct identity custodian, owner, descendant, known[32];
  unsigned observer_count; struct identity observers[4];
  unsigned observer_kinds[4]; char observer_hashes[4][65];
  char creator_receipt[512], constructor_program[65], constructor_capture[65];
};
#define DOMAIN_LEGACY_SIZE offsetof(struct fault_record, creator)
_Static_assert(DOMAIN_LEGACY_SIZE == sizeof(struct fault_record_legacy), "fault recovery ABI");
#define DOMAIN_V4_SIZE offsetof(struct fault_record, control)
static bool domain_legacy, domain_historical;
static size_t domain_record_size(void) { return domain_legacy ? DOMAIN_LEGACY_SIZE : domain_historical ? DOMAIN_V4_SIZE : sizeof(domain_record); }

static unsigned domain_image_phase;
static struct image_closure domain_inherited, domain_inspected;
static struct exec_handoff *domain_handoff, *domain_probe_handoff;
static struct exec_mapping domain_mapping = {.fd = -1}, domain_map_control = {.fd = -1};
static void domain_mapping_diagnostic(void) {
  int saved = errno;
  const struct exec_mapping *work = &domain_mapping, *authorized = &domain_map_control;
  fprintf(stderr, "native-darwin-mapping: owner=fault round=%s workspace=%s:%ld:%d workspace-map=%d:%d workspace-unmap=%d:%d workspace-close=%d:%d authorized=%s:%ld:%d authorized-map=%d:%d authorized-unmap=%d:%d authorized-close=%d:%d\n",
    domain_record.control ? "outside" : "primary", work->operation ? work->operation : "none", work->result, work->error,
    work->map, work->map_error, work->unmap, work->unmap_error, work->closed, work->close_error,
    authorized->operation ? authorized->operation : "none", authorized->result, authorized->error,
    authorized->map, authorized->map_error, authorized->unmap, authorized->unmap_error, authorized->closed, authorized->close_error);
  fflush(stderr); errno = saved;
}
static int domain_map_parent = -1;
static struct stat domain_map_directory;
static char domain_path[4096], domain_helper[4096], domain_policy[4096], domain_control_asset[4096];
static int domain_root = -1, domain_journal = -1;
static mach_port_t domain_pin;
static bool domain_fenced;
/* Each successful getter acquisition owns one release, including aliases. */
static mach_port_t domain_bootstrap_local;
static void domain_port_cleanup(void) {
  if (!exec_mapping_close(&domain_mapping)) remember_cleanup("fault-map-close", "errno", errno);
  if (!exec_mapping_close(&domain_map_control)) remember_cleanup("fault-map-close", "errno", errno);
  if (domain_map_parent >= 0) { int fd = domain_map_parent; domain_map_parent = -1; if (close(fd)) remember_cleanup("fault-map-parent-close", "errno", errno); }
  if (domain_probe_handoff) {
    struct exec_handoff *probe = domain_probe_handoff; domain_probe_handoff = NULL; exec_handoff_destroy(probe);
    if (probe->files_cleanup) remember_cleanup("fault-image-cleanup", "errno", probe->files_cleanup);
    if (probe->attributes_cleanup) remember_cleanup("fault-image-cleanup", "errno", probe->attributes_cleanup);
  }
  if (domain_handoff) {
    struct exec_handoff *handoff = domain_handoff; domain_handoff = NULL;
    exec_handoff_destroy(handoff);
    if (handoff->operation) remember(handoff->operation, handoff->kind, handoff->value);
    if (handoff->files_cleanup) remember_cleanup("fault-image-cleanup", "errno", handoff->files_cleanup);
    if (handoff->attributes_cleanup) remember_cleanup("fault-image-cleanup", "errno", handoff->attributes_cleanup);
  }
  mach_port_t local = domain_bootstrap_local; domain_bootstrap_local = MACH_PORT_NULL;
  image_copy(&domain_inspected, local);
  struct image_closure *values[] = {&domain_inspected, &domain_inherited};
  for (unsigned j = 0; j < 2; j++) {
    (void)image_closure_release(values[j]);
    for (unsigned i = 0; i < values[j]->outcome.count; i++) {
      struct domain_bootstrap_issue issue = values[j]->outcome.issues[i];
      remember("fault-image-closure", issue.kind, issue.value);
      if (issue.cleanup) remember_cleanup("fault-image-cleanup", issue.kind, issue.value);
      fprintf(stderr, "native-darwin-image-cleanup: operation=%s domain=%s value=%d cleanup=%d\n", issue.operation, issue.kind, issue.value, issue.cleanup);
    }
  }
}
static pid_t domain_controller, domain_child = -1;
static int domain_status, domain_pipes[5][2] = {{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1}};
static bool domain_released, domain_exit_reported, domain_child_bound;
static void domain_fault_bind(void) {
  alarm(20); domain_child_bound = true;
  extern mach_port_t bootstrap_port;
  domain_bootstrap_local = bootstrap_port; bootstrap_port = MACH_PORT_NULL;
}
static pid_t domain_fault_fork(void) {
  struct domain_bootstrap_fork outcome; domain_bootstrap_fork(&outcome, &domain_child, domain_fault_bind);
  if (outcome.child == 0 && !domain_child_bound) alarm(20);
  /* remember/remember_cleanup borrow these pointers until failure finishes. */
  char operations[DOMAIN_FORK_ISSUES][80];
  for (unsigned i = 0; i < outcome.count; i++) {
    struct domain_bootstrap_issue issue = outcome.issues[i];
    snprintf(operations[i], sizeof(operations[i]), "fault-%s", issue.operation);
    remember(operations[i], issue.kind, issue.value);
    if (issue.cleanup) remember_cleanup(operations[i], issue.kind, issue.value);
  }
  if (outcome.count) { domain_fork_diagnostic("fault"); failure(126); }
  return outcome.child;
}
static bool domain_stream(const unsigned char *bytes, ssize_t size, const char *stream) {
  if (domain_record.control && !strcmp(stream, "stdout")) {
    if (size < 0 || (size_t)size > sizeof(domain_control_bytes) - domain_control_used) return false;
    memcpy(domain_control_bytes + domain_control_used, bytes, (size_t)size); domain_control_used += (size_t)size;
  }
  printf("{\"stream\":\"%s\",\"hex\":\"", stream);
  for (ssize_t at = 0; at < size; at++) printf("%02x", bytes[at]); puts("\"}");
  if (!ferror(stdout)) return true;
  remember("fault-output-write", "errno", errno);
  remember_cleanup("fault-output-write", "errno", errno); return false;
}
static bool domain_exited(void);
static void domain_failure_retire(void);
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
  if (!capture) { domain_failure_retire(); return; }
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
  domain_failure_retire();
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
  snprintf(domain_control_asset, sizeof(domain_control_asset), "%s/exec-control", domain_path);
}
static void domain_store(unsigned stage) {
  need(!domain_legacy && domain_record.version == 5);
  domain_record.stage = stage;
  domain_io(pwrite(domain_journal, &domain_record, sizeof(domain_record), 0), sizeof(domain_record), "fault-journal-write");
  posix_check(fsync(domain_journal), "fault-journal-sync");
  posix_check(fsync(domain_root), "fault-root-sync");
}
static void domain_emit(void) {
  char pin[65]; domain_hex(&domain_record, domain_record_size(), pin);
  printf("{\"candidateSha\":\"%s\",\"caseId\":\"%s\",\"asid\":%u,\"stage\":%u,\"emergency\":%s,\"receiptSha256\":\"%s\",\"intentSha256\":\"%s\",\"helperSha256\":\"%s\",\"policySha256\":\"%s\",\"custodian\":",
    domain_record.candidate, domain_record.case_id, domain_record.asid, domain_record.stage, domain_record.emergency ? "true" : "false", pin, domain_record.intent, domain_record.helper_hash, domain_record.policy_hash);
  emit_identity(domain_record.custodian); fputs(",\"owner\":", stdout); emit_identity(domain_record.owner);
  fputs(",\"descendant\":", stdout); emit_identity(domain_record.descendant); fputs(",\"members\":[", stdout);
  for (unsigned i = 0; i < domain_record.members; i++) { if(i) putchar(','); emit_identity(domain_record.known[i]); }
  char creator[65] = {0}; if (domain_record.creator_receipt[0]) domain_hex(domain_record.creator_receipt, sizeof(domain_record.creator_receipt), creator);
  printf("],\"creatorReceiptSha256\":\"%s\",\"constructorProgramSha256\":\"%s\",\"constructorCaptureSha256\":\"%s\"",
    creator, domain_record.constructor_program, domain_record.constructor_capture);
  if (!domain_legacy) {
    printf(",\"version\":%u,\"execution\":%u,\"continuation\":%u,\"observationsSha256\":\"%s\",\"imageCdhash\":\"%s\",\"creator\":",
      domain_record.version, domain_record.execution, domain_record.continuation, domain_record.observations, domain_record.cdhash);
    emit_identity(domain_record.creator); fputs(",\"target\":", stdout);
    if (domain_record.target.token.val[5]) emit_identity(domain_record.target); else fputs("null", stdout);
  }
  if (!domain_legacy && !domain_historical) {
    printf(",\"control\":%s,\"controlRetired\":%s,\"controlSha256\":\"%s\",\"probeConsumed\":%s,\"probeStatus\":%d,\"controlCreator\":", domain_record.control ? "true" : "false", domain_record.control_retired ? "true" : "false", domain_record.control_hash, domain_record.probe_consumed ? "true" : "false", domain_record.probe.status);
    if (domain_record.control_creator.token.val[5]) emit_identity(domain_record.control_creator); else fputs("null", stdout);
    fputs(",\"controlTarget\":", stdout); if (domain_record.control_target.token.val[5]) emit_identity(domain_record.control_target); else fputs("null", stdout);
    printf(",\"controlCdhash\":\"%s\",\"controlObservationsSha256\":\"%s\",\"controlOutputSha256\":\"%s\"", domain_record.control_cdhash, domain_record.control_observations, domain_record.control_output);
  }
  putchar('}');
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
  char image[4096]; need(proc_pidpath(value.token.val[5], image, sizeof(image)) > 0);
  bool control = (domain_record.control && domain_record.target.token.val[5] == value.token.val[5]) ||
    (!domain_legacy && !domain_historical && domain_fenced && !domain_record.target.token.val[5] &&
      value.token.val[5] == domain_record.creator.token.val[5] && (domain_record.control || domain_record.probe_consumed) && !strcmp(image, domain_control_asset));
  const char *leaf = control ? "exec-control" : "helper", *expected = control ? domain_control_asset : domain_helper;
  need(!strcmp(image, expected));
  int fd = openat(domain_root, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat before, after, named;
  need(fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) && !before.st_uid && !before.st_gid &&
    before.st_nlink == 1 && (before.st_mode & 07777) == 0555 && before.st_size > 0 && before.st_size <= 16777216);
  no_acl(fd, &before); unsigned char *bytes = malloc(before.st_size); need(bytes && pread(fd, bytes, before.st_size, 0) == before.st_size);
  char hash[65]; domain_hex(bytes, before.st_size, hash); free(bytes);
  need(!strcmp(hash, control ? domain_record.control_hash : domain_record.helper_hash) && !fstat(fd, &after) && !fstatat(domain_root, leaf, &named, AT_SYMLINK_NOFOLLOW) &&
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
static uint64_t domain_image_now(void) {
  struct timespec now; need(!clock_gettime(CLOCK_MONOTONIC, &now));
  return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static void domain_creator_check(struct identity creator, au_asid_t parent_asid) {
  if (!domain_record.control && domain_record.version == 5) need(creator.token.val[6] != domain_record.control_target.token.val[6]);
  invariant(creator.token.val[0] == domain_record.uid && creator.token.val[1] == domain_record.uid &&
    creator.token.val[2] == domain_record.gid && creator.token.val[3] == domain_record.uid &&
    creator.token.val[4] == domain_record.gid && creator.bsd.pbi_svuid == domain_record.uid &&
    creator.bsd.pbi_svgid == domain_record.gid && creator.token.val[6] > 0 &&
    creator.token.val[6] != (unsigned)AU_ASSIGN_ASID && creator.token.val[6] != (unsigned)parent_asid,
    "fault-image-credentials");
}
static void domain_image_bound(void) {
  need(!domain_legacy && domain_record.version == 5 && !domain_fenced && domain_record.stage == 1 &&
    domain_record.deadline && domain_image_now() <= domain_record.deadline);
}
static void domain_image_inputs(struct image_closure *value, struct identity expected) {
  task_t task = MACH_PORT_NULL; thread_act_array_t threads = NULL; mach_msg_type_number_t count = 0;
  kern_return_t got = task_for_pid(mach_task_self(), expected.token.val[5], &task);
  if (got == KERN_SUCCESS) image_copy(value, task);
  bool ok = image_mach(value, got, "image-control-get");
  audit_token_t token = {{0}}; mach_msg_type_number_t size = TASK_AUDIT_TOKEN_COUNT;
  if (ok) ok = image_mach(value, task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &size), "image-control-epoch") &&
    image_assert(value, size == TASK_AUDIT_TOKEN_COUNT && !memcmp(&token, &expected.token, sizeof(token)), "image-control-binding");
  if (ok) {
    got = task_threads(task, &threads, &count); ok = image_mach(value, got, "image-threads-get");
    if (got == KERN_SUCCESS) {
      bool single = count == 1 && threads; ok = image_assert(value, single, "image-single-thread") && ok;
      if (single) { image_copy(value, threads[0]); if (ok) ok = image_closure_read(value, task, threads[0]); }
      else for (unsigned i = 0; threads && i < count; i++) {
        kern_return_t result = mach_port_deallocate(mach_task_self(), threads[i]);
        domain_bootstrap_check(&value->outcome, result == KERN_SUCCESS, "image-thread-release", "mach", result, true);
      }
      if (threads) {
        kern_return_t result = mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)threads, count * sizeof(*threads));
        ok = domain_bootstrap_check(&value->outcome, result == KERN_SUCCESS, "image-threads-array-release", "mach", result, true) && ok;
      }
    }
  }
  if (!ok) { domain_port_cleanup(); failure(126); }
  need(audit_identity_same(expected, fault_inspect(expected.token.val[5])));
}
static void domain_signature_at(const char *path, char hash[41]) {
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
  SecStaticCodeRef code = NULL; CFDictionaryRef info = NULL;
  bool ok = url && SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess && code &&
    SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL) == errSecSuccess &&
    SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess && info;
  if (ok) {
    CFDataRef cd = CFDictionaryGetValue(info, kSecCodeInfoUnique);
    CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
    ok = cd && CFGetTypeID(cd) == CFDataGetTypeID() && CFDataGetLength(cd) == 20 &&
      (!entitlements || (CFGetTypeID(entitlements) == CFDictionaryGetTypeID() && !CFDictionaryGetCount(entitlements)));
    if (ok) for (unsigned i = 0; i < 20; i++) snprintf(hash + i*2, 3, "%02x", CFDataGetBytePtr(cd)[i]);
  }
  if (info) CFRelease(info); if (code) CFRelease(code); if (url) CFRelease(url);
  invariant(ok, "fault-image-signature");
}
static void domain_signature(char hash[41]) { domain_signature_at(domain_record.control ? domain_control_asset : domain_helper, hash); }
static void domain_mapping_observe(void) {
  char path[4096], parent[4096], signature[41], control[41]; struct stat directory;
  need(audit_identity_same(domain_record.custodian, fault_inspect(domain_record.custodian.token.val[5])));
  need(snprintf(parent, sizeof(parent), "%s/workspace", domain_record.root) < sizeof(parent) &&
    snprintf(path, sizeof(path), "%s/map-fixture", parent) < sizeof(path) && !lstat(parent, &directory) && S_ISDIR(directory.st_mode));
  struct exec_mapping value = {.fd = -1};
  bool ok = exec_mapping_open(&value, path, domain_record.control_hash) &&
    exec_mapping_held(domain_record.custodian.token.val[5], value.object) && exec_mapping_held(domain_record.custodian.token.val[5], directory);
  if (domain_mapping.fd >= 0) ok = ok && exec_mapping_same(value.object, domain_mapping.object) && exec_mapping_same(directory, domain_map_directory);
  bool closed = exec_mapping_close(&value); need(ok && closed);
  if (getpid() != domain_record.custodian.token.val[5]) {
    domain_signature_at(path, signature); domain_signature_at(domain_control_asset, control); need(!strcmp(signature, control));
  }
  struct stat named, parent_after;
  need(!lstat(path, &named) && exec_mapping_same(named, value.object) && !lstat(parent, &parent_after) && exec_mapping_same(directory, parent_after) &&
    audit_identity_same(domain_record.custodian, fault_inspect(domain_record.custodian.token.val[5])));
}
static void domain_control_asset_check(void) {
  domain_mapping_observe();
  struct stat held, parent, named; int fd = openat(domain_root, "exec-control", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  need(fd >= 0 && !fstat(fd, &held) && !fstat(domain_root, &parent) && !fstatat(domain_root, "exec-control", &named, AT_SYMLINK_NOFOLLOW));
  need(domain_file_same(&held, &domain_record.control_file) && domain_file_same(&held, &named) && same_file_stat(&parent, &domain_record.control_parent));
  no_acl(fd, &held); no_acl(domain_root, &parent);
  unsigned char *bytes = malloc(held.st_size); need(bytes && pread(fd, bytes, held.st_size, 0) == held.st_size);
  char hash[65]; domain_hex(bytes, held.st_size, hash);
  need(held.st_size >= 32 && ((uint32_t *)bytes)[0] == 0xfeedfacf && ((uint32_t *)bytes)[1] == 0x01000007 && ((uint32_t *)bytes)[3] == 2 && !strcmp(hash, domain_record.control_hash));
  free(bytes); need(!fstat(fd, &named) && domain_file_same(&held, &named) && !close(fd));
}
/* Advisory only: row -1 selects the fork query; errno is an observation, not an interpretation. */
static void domain_effective_diagnostic(struct identity target, int row, const char *operation, int expected, int actual, int observed_errno) {
  int saved = errno;
  if (row == 5 && !strcmp(operation, "file-read-data")) {
    struct stat link_type, runtime_type;
    int link_result = lstat("/usr/lib/libSystem.B.dylib", &link_type);
    int link_errno = link_result < 0 ? errno : 0;
    int runtime_result = stat("/usr/lib/libSystem.B.dylib", &runtime_type);
    int runtime_errno = runtime_result < 0 ? errno : 0;
    const char *link_kind = link_result != 0 ? "unavailable" :
      S_ISREG(link_type.st_mode) ? "regular" : S_ISLNK(link_type.st_mode) ? "symlink" : "other";
    const char *runtime_kind = runtime_result != 0 ? "unavailable" :
      S_ISREG(runtime_type.st_mode) ? "regular" : S_ISLNK(runtime_type.st_mode) ? "symlink" : "other";
    fprintf(stderr, "native-darwin-fault-policy: caller=%d target=%u row=%d operation=%s expected=%d actual=%d observed_errno=%d lstat_result=%d lstat_errno=%d lstat_type=%s stat_result=%d stat_errno=%d stat_type=%s\n",
      getpid(), target.token.val[5], row, operation, expected, actual, observed_errno,
      link_result, link_errno, link_kind, runtime_result, runtime_errno, runtime_kind);
  } else fprintf(stderr, "native-darwin-fault-policy: caller=%d target=%u row=%d operation=%s expected=%d actual=%d observed_errno=%d\n",
    getpid(), target.token.val[5], row, operation, expected, actual, observed_errno);
  fflush(stderr); errno = saved;
}
/* The fixed policy's complete file/process decision matrix, not an active bit. */
static void domain_effective(struct identity target) {
  char paths[4][4096]; const char *names[] = {"build/helper", "build/argv-fixture", "build/git", "workspace"};
  for (unsigned i = 0; i < 4; i++) need(snprintf(paths[i], sizeof(paths[i]), "%s/%s", domain_record.root, names[i]) < sizeof(paths[i]));
  const char *objects[] = {domain_helper, paths[0], paths[1], paths[2], paths[3], "/usr/lib/libSystem.B.dylib", "/dev/null", "/", domain_policy};
  const char *operations[] = {"file-read-data", "file-write-data", "file-write-create", "file-write-unlink", "file-map-executable"};
  need(!domain_record.control && domain_record.control_retired && exec_handoff_refused(domain_record.probe));
  for (unsigned i = 0; i < 9; i++) for (unsigned j = 0; j < 5; j++) {
    /* Directories (workspace/root) and the null character device have no
     * regular-file map slot. The held workspace denial plus authorized image
     * positive discharges those slots; every read/write and regular query stays. */
    if (j == 4 && (i == 4 || i == 6 || i == 7)) {
      struct stat type; need(!lstat(objects[i], &type) && (i == 6 ? S_ISCHR(type.st_mode) : S_ISDIR(type.st_mode))); continue;
    }
    bool read = i != 8, write = i == 6, executable = i < 4 || i == 5;
    int expected = j == 0 ? !read : j < 4 ? !write : !executable;
    int actual = feasibility_sandbox_path(sandbox_binding, target.token.val[5], operations[j], objects[i]);
    int observed_errno = errno;
    if (actual != expected) domain_effective_diagnostic(target, i, operations[j], expected, actual, observed_errno);
    invariant(actual == expected, "fault-image-policy");
  }
  need(feasibility_sandbox_path(sandbox_binding, target.token.val[5], "file-read-data", domain_control_asset) == 0 &&
    feasibility_sandbox_path(sandbox_binding, target.token.val[5], "file-map-executable", domain_control_asset) == 0);
  int actual = sandbox_binding.check(target.token.val[5], "process-fork", *sandbox_binding.no_report);
  int observed_errno = errno;
  if (actual != 0) domain_effective_diagnostic(target, -1, "process-fork", 0, actual, observed_errno);
  invariant(actual == 0, "fault-image-policy");
}
static void domain_image_observe(bool inheritance) {
  domain_image_bound(); need(domain_record.target.token.val[5]);
  struct identity target = fault_inspect(domain_record.creator.token.val[5]);
  need(exec_handoff_identity(domain_record.creator, target) && audit_identity_same(target, domain_record.target));
  domain_control_asset_check(); domain_image(target); domain_policy_check(); char signature[41]; domain_signature(signature);
  if (*domain_record.cdhash) need(!strcmp(signature, domain_record.cdhash)); else strcpy(domain_record.cdhash, signature);
  struct proc_vnodepathinfo cwd; struct stat root;
  need(!fstat(domain_root, &root) && proc_pidinfo(target.token.val[5], PROC_PIDVNODEPATHINFO, 0, &cwd, sizeof(cwd)) == sizeof(cwd));
  need(cwd.pvi_cdir.vip_vi.vi_stat.vst_dev == root.st_dev && cwd.pvi_cdir.vip_vi.vi_stat.vst_ino == root.st_ino);
  struct proc_fdinfo descriptors[4]; int size = proc_pidinfo(target.token.val[5], PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
  need(size == 3 * sizeof(*descriptors)); unsigned mask = 0;
  for (unsigned i = 0; i < 3; i++) { need(descriptors[i].proc_fd >= 0 && descriptors[i].proc_fd <= 2); mask |= 1u << descriptors[i].proc_fd; }
  need(mask == 7 && feasibility_sandbox_active(sandbox_binding, target.token.val[5]) == (domain_record.control ? 0 : 1));
  if (!domain_record.control) domain_effective(target);
  memset(&domain_inspected, 0, sizeof(domain_inspected)); domain_image_inputs(&domain_inspected, target);
  bool same = !inheritance || (domain_inspected.host == domain_inherited.host && domain_inspected.access == domain_inherited.access &&
    domain_inspected.resource_unsupported == domain_inherited.resource_unsupported);
  bool released = image_closure_release(&domain_inspected);
  if (!same) remember("fault-image-provenance", "invariant", 0);
  if (!same || !released) { domain_port_cleanup(); failure(126); }
  need(audit_identity_same(target, fault_inspect(target.token.val[5])) && fault_inspect(target.token.val[5]).bsd.pbi_status == SSTOP);
  if (inheritance) domain_image_phase = 3;
}
static void domain_known(struct identity value);
static void domain_probe(void) {
  domain_image_bound(); need(!domain_record.control && domain_record.control_retired && !domain_record.probe_consumed && domain_image_phase == 1);
  struct identity creator = fault_inspect(domain_record.creator.token.val[5]); need(audit_identity_same(creator, domain_record.creator));
  domain_control_asset_check(); domain_policy_check(); need(feasibility_sandbox_active(sandbox_binding, creator.token.val[5]) == 1 &&
    feasibility_sandbox_path(sandbox_binding, creator.token.val[5], "file-read-data", domain_control_asset) == 0 &&
    feasibility_sandbox_path(sandbox_binding, creator.token.val[5], "file-map-executable", domain_control_asset) == 0);
  uint64_t before[8][4], after[8][4]; need(image_descriptors(creator.token.val[5], before));
  domain_record.probe_consumed = 1; domain_store(1);
  struct exec_handoff channel = {0}; need(exec_handoff_byte(&channel, domain_pipes[4][1], true, 'T'));
  domain_io(read(domain_pipes[3][0], &domain_record.probe, sizeof(domain_record.probe)), sizeof(domain_record.probe), "fault-probe-read");
  need(exec_handoff_refused(domain_record.probe) && exec_handoff_receive(&channel, domain_pipes[3][0], false));
  need(audit_identity_same(creator, fault_inspect(creator.token.val[5])) &&
    image_descriptors(creator.token.val[5], after) && !memcmp(before, after, sizeof(before))); domain_image(creator);
  memset(&domain_inspected, 0, sizeof(domain_inspected)); domain_image_inputs(&domain_inspected, creator);
  bool same = domain_inspected.host == domain_inherited.host && domain_inspected.access == domain_inherited.access && domain_inspected.resource_unsupported == domain_inherited.resource_unsupported;
  bool settled = image_closure_release(&domain_inspected); need(same && settled); domain_control_asset_check(); domain_policy_check(); domain_image_bound(); domain_store(1);
}
static void domain_image_exec(void) {
  domain_image_bound(); need(domain_image_phase == 1 && domain_pin != MACH_PORT_NULL && (domain_record.control || (domain_record.control_retired && exec_handoff_refused(domain_record.probe))));
  need(audit_identity_same(domain_record.creator, fault_inspect(domain_record.creator.token.val[5])));
  domain_store(1); domain_image_phase = 2; domain_released = true; /* consume before uncertain X */
  int *ready = domain_pipes[3], *release = domain_pipes[4]; struct exec_handoff handoff = {0};
  bool replaced = exec_handoff_release(&handoff, &release[1]) && exec_handoff_receive(&handoff, ready[0], true);
  domain_check(replaced, "fault-image-exec", handoff.kind ? handoff.kind : "invariant", handoff.value);
  domain_close(&ready[0]); struct identity target;
  for (;;) {
    domain_image_bound(); target = fault_inspect(domain_record.creator.token.val[5]);
    if (exec_handoff_identity(domain_record.creator, target)) break;
    (void)poll(NULL, 0, 1);
  }
  domain_record.target = domain_record.owner = target; domain_known(target);
  domain_image_observe(true); domain_store(1);
}
static void domain_image_readback(const char *pin) {
  need(domain_hash(pin)); int fd = openat(domain_root, "receipt", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  struct stat before, after, named; struct fault_record record;
  need(fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) && !before.st_uid && !before.st_gid && before.st_nlink == 1 &&
    (before.st_mode & 07777) == 0400 && before.st_size == sizeof(record)); no_acl(fd, &before);
  need(pread(fd, &record, sizeof(record), 0) == sizeof(record) && !fstat(fd, &after) &&
    !fstatat(domain_root, "receipt", &named, AT_SYMLINK_NOFOLLOW) && domain_file_same(&before, &after) && domain_file_same(&before, &named) && !close(fd));
  char hash[65]; domain_hex(&record, sizeof(record), hash);
  need(!strcmp(hash, pin) && !memcmp(&record, &domain_record, sizeof(record)));
}
static void domain_image_continue(const char *pin) {
  domain_image_bound(); need(domain_image_phase == 3 && domain_record.continuation == 1);
  domain_image_readback(pin); domain_image_observe(true);
  bool released = image_closure_release(&domain_inherited);
  if (!released) { domain_port_cleanup(); failure(126); }
  domain_image_bound(); domain_image_phase = 4; domain_record.continuation = 2; domain_store(1);
  struct identity target = fault_inspect(domain_record.target.token.val[5]);
  need(audit_identity_same(target, domain_record.target) && target.bsd.pbi_status == SSTOP);
  signal_identity(target, SIGCONT);
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
    if (query != KERN_SUCCESS || (type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE | MACH_PORT_TYPE_DEAD_NAME)))
      released = mach_port_deallocate(self, access);
  }
  domain_access_diagnostic(phase, got, access, type, query, released); errno = saved;
  if (released != -1 && released != KERN_SUCCESS) {
    remember_cleanup("fault-access-release", "mach", released);
    domain_mach(released, "fault-access-release");
  }
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
    if (b.pbi_status != SZOMB) {
      struct identity actual = fault_inspect(value.token.val[5]);
      if (!audit_identity_same(value, actual)) {
        need(!domain_legacy && domain_record.execution && audit_identity_same(value, domain_record.creator));
        for (unsigned j = 0; j < 7; j++) need(value.token.val[j] == actual.token.val[j]);
        if (domain_record.target.token.val[5]) need(audit_identity_same(actual, domain_record.target));
        domain_image(actual);
      }
    }
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
/* A refused native observation must not orphan an already stopped replacement.
 * Keep the primary cause; every signal still requires the original pin, complete
 * identity checks and a durable intent. Recursive cleanup cannot repeat effects. */
static void domain_failure_retire(void) {
  static bool settling;
  if (settling || domain_pin == MACH_PORT_NULL || domain_record.stage < 1 || domain_record.stage > 4) return;
  settling = true; domain_fenced = true; domain_failure_cleanup = true;
  domain_store(3); domain_retire();
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
    st.st_nlink == 1 && (st.st_mode & 07777) == 0400 && (st.st_size == sizeof(domain_record) || st.st_size == DOMAIN_V4_SIZE || st.st_size == DOMAIN_LEGACY_SIZE), &st, "fault-journal-shape"); no_acl(domain_journal, &st);
  domain_legacy = st.st_size == DOMAIN_LEGACY_SIZE; domain_historical = st.st_size == DOMAIN_V4_SIZE; memset(&domain_record, 0, sizeof(domain_record));
  domain_io(pread(domain_journal, &domain_record, st.st_size, 0), st.st_size, "fault-journal-read");
  struct stat after, named;
  need(!fstat(domain_journal, &after) && !fstatat(domain_root, "receipt", &named, AT_SYMLINK_NOFOLLOW) &&
    domain_file_same(&st, &after) && domain_file_same(&st, &named));
  char hash[65]; domain_hex(&domain_record, st.st_size, hash);
  invariant((!pin || (domain_hash(pin) && !strcmp(pin, hash))) && domain_record.version == (domain_legacy ? 3 : domain_historical ? 4 : 5), "fault-journal-binding");
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
static void domain_control_verify(const char *nonce, const char *pin) {
  domain_open(nonce, pin); need(domain_record.version == 5 && domain_record.control && domain_record.control_retired && domain_record.stage == 1);
  struct identity custodian = fault_inspect(domain_record.custodian.token.val[5]); need(audit_identity_same(custodian, domain_record.custodian)); domain_image(custodian);
  struct audit_domain_view view = audit_census(domain_record.uid, domain_record.asid); need(!view.nl && !view.nd); domain_control_asset_check(); domain_policy_check();
  struct identity verifier = fault_inspect(getpid()); need(verifier.token.val[5] != custodian.token.val[5] && verifier.token.val[6] != domain_record.asid);
  fputs("{\"independent\":true,\"verifier\":", stdout); emit_identity(verifier); fputs(",\"record\":", stdout); domain_emit(); puts("}");
}
static void domain_admission_verify(const char *nonce, const char *pin) {
  domain_open(nonce, pin); need(!domain_legacy && domain_record.version == 5 && domain_record.stage == 1);
  struct identity custodian = fault_inspect(domain_record.custodian.token.val[5]);
  need(audit_identity_same(custodian, domain_record.custodian)); domain_image(custodian);
  domain_mapping_observe();
  if (domain_record.target.token.val[5]) domain_image_observe(false);
  else need(audit_identity_same(domain_record.creator, fault_inspect(domain_record.creator.token.val[5])));
  fputs("{\"independent\":true,\"record\":", stdout); domain_emit(); puts("}");
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
  char line[4]; need(fgets(line, sizeof(line), stdin) && !strcmp(line, "P\n"));
  need(audit_identity_same(domain_record.custodian, fault_inspect(getpid())));
}
static void domain_fault_refuse(struct domain_bootstrap_fork *out) {
  if (!out->count) return;
  /* Failure emission borrows these names until it exits, never past this scope. */
  char operations[DOMAIN_FORK_ISSUES][80];
  for (unsigned i = 0; i < out->count; i++) {
    struct domain_bootstrap_issue issue = out->issues[i];
    snprintf(operations[i], sizeof(operations[i]), "fault-%s", issue.operation);
    remember(operations[i], issue.kind, issue.value);
    if (issue.cleanup) remember_cleanup(operations[i], issue.kind, issue.value);
  }
  failure(126);
}
static void domain_fault_bootstrap_entry(void) {
  struct domain_bootstrap_fork entry = {0}; domain_bootstrap_entry(&entry);
  domain_fault_refuse(&entry);
}
static void domain_reexec(char **argv) {
  extern char **environ;
  posix_spawn_file_actions_t actions; posix_spawnattr_t attributes;
  struct domain_bootstrap_fork spawn = {0}; bool actions_owned = false, attributes_owned = false;
  bool ready = domain_spawn_check(&spawn, posix_spawn_file_actions_init(&actions), "spawn-actions-init", false);
  actions_owned = ready;
  if (ready) ready = domain_spawn_attributes(&spawn, &attributes, &attributes_owned, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_CLOEXEC_DEFAULT);
  for (int fd = 0; ready && fd <= 3; fd++)
    ready = domain_spawn_check(&spawn, posix_spawn_file_actions_adddup2(&actions, fd, fd), "spawn-descriptor", false);
  if (ready) {
    pid_t unused = -1;
    int result = posix_spawn(&unused, domain_helper, &actions, &attributes, argv, environ);
    domain_spawn_check(&spawn, result, "reexec", false);
    /* Successful SETEXEC replaces this image. Even a zero return is refusal. */
    domain_bootstrap_check(&spawn, result != 0, "reexec-return", "invariant", 0, false);
  }
  domain_spawn_settle(&spawn, &actions, &actions_owned, &attributes, &attributes_owned);
  domain_fault_refuse(&spawn);
  failure(126);
}
static void domain_start(int argc, char **argv) {
  invariant(argc == 11 && strlen(argv[3]) == 40 && strspn(argv[3], "0123456789abcdef") == 40 &&
    (!strcmp(argv[4], "cancel") || !strcmp(argv[4], "owner-loss")) && domain_hash(argv[6]) && domain_hash(argv[7]) && domain_hash(argv[10]), "fault-start-input");
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
    invariant(!domain_legacy && domain_record.version == 5 && !domain_record.stage && !strcmp(domain_record.root, canonical) && !strcmp(domain_record.candidate, argv[3]) && !strcmp(domain_record.case_id, argv[4]) &&
      !strcmp(domain_record.helper_hash, argv[6]) && !strcmp(domain_record.policy_hash, argv[7]) && domain_record.uid == 90001 && domain_record.gid == 90002, "fault-reexec-binding");
    domain_transfer();
  } else {
  domain_access_observe("custodian-entry");
  posix_check(mkdir(domain_path, 0700), "fault-root-create");
  domain_root = open(domain_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); posix_check(domain_root, "fault-root-open");
  domain_initialize(domain_root, true);
  domain_journal = openat(domain_root, "receipt", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400); posix_check(domain_journal, "fault-journal-open");
  domain_initialize(domain_journal, false);
  domain_record.version = 5; domain_record.uid = 90001; domain_record.gid = 90002;
  strcpy(domain_record.control_hash, argv[10]);
  domain_record.deadline = domain_image_now() + 12000;
  strcpy(domain_record.root, canonical); strcpy(domain_record.candidate, argv[3]); strcpy(domain_record.case_id, argv[4]); strcpy(domain_record.helper_hash, argv[6]); strcpy(domain_record.policy_hash, argv[7]);
  domain_record.custodian = fault_inspect(getpid()); domain_store(0);
  char source[4096]; snprintf(source, sizeof(source), "%s/build/helper", canonical); domain_copy(source, "helper", argv[6], 0555, uid, gid);
  snprintf(source, sizeof(source), "%s/build/argv-fixture", canonical); domain_copy(source, "exec-control", argv[10], 0555, uid, gid);
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
  need(!fstatat(domain_root, "exec-control", &domain_record.control_file, AT_SYMLINK_NOFOLLOW) && !fstat(domain_root, &domain_record.control_parent));
  domain_store(0);
  posix_check(fsync(domain_root), "fault-root-sync");
  posix_check(dup2(domain_journal, 3), "fault-journal-duplicate"); posix_check(fcntl(3, F_SETFD, 0), "fault-journal-flags");
  argv[0] = domain_helper; argv[1] = "fault-custody"; domain_reexec(argv);
  }
  au_asid_t parent_asid = audit_fresh(0); domain_record.custodian = fault_inspect(getpid()); domain_store(0);
  fputs("{\"hello\":", stdout); domain_emit(); puts("}"); fflush(stdout);
  domain_parent_gate();
  char mapping_path[4096], mapping_parent[4096];
  need(snprintf(mapping_parent, sizeof(mapping_parent), "%s/workspace", canonical) < sizeof(mapping_parent) &&
    snprintf(mapping_path, sizeof(mapping_path), "%s/map-fixture", mapping_parent) < sizeof(mapping_path));
  /* Parent custody stays here; children retain only the two read-only probes. */
  domain_map_parent = open(mapping_parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(domain_map_parent > 4 && !fstat(domain_map_parent, &domain_map_directory) &&
    exec_mapping_open(&domain_mapping, mapping_path, domain_record.control_hash) &&
    exec_mapping_open(&domain_map_control, domain_control_asset, domain_record.control_hash));
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
  unsigned expected_sequence = 0;
  for (unsigned round = 0; round < 2; round++) {
  domain_mapping_observe();
  if (round) need(domain_record.control_retired && domain_image_now() <= domain_record.deadline);
  domain_record.control = round == 0; domain_record.probe_consumed = 0; domain_record.probe = (struct exec_probe){0};
  domain_record.creator = domain_record.target = domain_record.owner = (struct identity){0};
  domain_record.members = domain_record.continuation = 0;
  memset(&domain_inherited, 0, sizeof(domain_inherited)); memset(&domain_inspected, 0, sizeof(domain_inspected)); *domain_record.observations = *domain_record.cdhash = 0;
  domain_control_used = 0;
  domain_exit_reported = domain_released = false; domain_image_phase = 0; domain_store(0);
  int *in = domain_pipes[0], *out = domain_pipes[1], *err = domain_pipes[2], *ready = domain_pipes[3], *release = domain_pipes[4];
  posix_check(pipe(in), "fault-pipe"); posix_check(pipe(out), "fault-pipe"); posix_check(pipe(err), "fault-pipe");
  posix_check(pipe(ready), "fault-pipe"); posix_check(pipe(release), "fault-pipe");
  domain_access_observe("custodian-fork");
  struct proc_taskinfo threads;
  invariant(proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &threads, sizeof(threads)) == sizeof(threads) && threads.pti_threadnum == 1, "fault-fork-threads");
  pid_t child = domain_fault_fork();
  if (!child) {
    domain_access_observe("child-fork");
    posix_check(close(ready[0]), "fault-close"); posix_check(close(release[1]), "fault-close");
    posix_check(fchdir(domain_root), "fault-cwd");
    posix_check(dup2(in[0], 0), "fault-stdio"); posix_check(dup2(out[1], 1), "fault-stdio"); posix_check(dup2(err[1], 2), "fault-stdio");
    bool descriptors_ready = dup2(ready[1], 3) == 3 && dup2(release[0], 4) == 4 &&
      !fcntl(3, F_SETFD, FD_CLOEXEC) && !fcntl(4, F_SETFD, FD_CLOEXEC);
    int descriptor_error = errno;
    domain_check(descriptors_ready, "fault-creator-descriptors", "errno", descriptor_error);
    struct proc_fdinfo fds[512]; int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    invariant(size > 0 && size < sizeof(fds) && !(size % sizeof(fds[0])), "fault-fd-count");
    for (unsigned i = 0; i < (unsigned)size/sizeof(fds[0]); i++) if (fds[i].proc_fd > 4 &&
      fds[i].proc_fd != domain_mapping.fd && fds[i].proc_fd != domain_map_control.fd) {
      int fd = fds[i].proc_fd;
      /* Failure cleanup must never retry this child's parent close. */
      if (fd == domain_map_parent) domain_map_parent = -1;
      posix_check(close(fd), "fault-close");
    }
    need(domain_map_parent < 0);
    char parent[24]; snprintf(parent, sizeof(parent), "%u", parent_asid);
    posix_check(setenv("NATIVE_FAULT_PARENT_ASID", parent, 1), "fault-environment"); posix_check(unsetenv("NATIVE_STARTUP_CUSTODY"), "fault-environment");
    char *arguments[] = {domain_helper, "fault", NULL}; extern char **environ;
    char *control_arguments[] = {domain_control_asset, "", "space value", "λ雪", "'\"", "$(false); & | < > *", NULL};
    posix_check(setenv("NATIVE_OWNERSHIP_CUSTODY", "true", 1), "fault-environment");
    struct exec_handoff probe = {0};
    struct exec_handoff handoff = {0}; domain_handoff = &handoff; const int descriptors[] = {0, 1, 2};
    if (!exec_handoff_prepare(&handoff, descriptors, 3)) {
      remember("fault-image-prepare", handoff.kind, handoff.value); failure(126);
    }
    if (!domain_record.control) { domain_probe_handoff = &probe; need(exec_handoff_prepare(&probe, descriptors, 3) && image_spawn_inputs(&probe)); }
    audit_fresh(domain_record.uid);
    struct rlimit limit = {.rlim_cur = 32, .rlim_max = 32}, observed;
    posix_check(setrlimit(RLIMIT_NPROC, &limit), "fault-process-limit");
    posix_check(setgroups(0, NULL), "fault-groups"); posix_check(setgid(domain_record.gid), "fault-gid"); posix_check(setuid(domain_record.uid), "fault-uid");
    gid_t group; invariant(getgroups(1, &group) == 1 && group == domain_record.gid &&
      !getrlimit(RLIMIT_NPROC, &observed) && observed.rlim_cur == 32 && observed.rlim_max == 32, "fault-image-credentials");
    domain_creator_check(fault_inspect(getpid()), parent_asid);
    if (!domain_record.control) policy(domain_policy);
    invariant(feasibility_sandbox_active(sandbox_binding, getpid()) == (domain_record.control ? 0 : 1), "fault-image-policy");
    bool mapped = exec_mapping_check(&domain_mapping, !domain_record.control);
    mapped = exec_mapping_check(&domain_map_control, false) && mapped;
    bool map_closed = exec_mapping_close(&domain_mapping); map_closed = exec_mapping_close(&domain_map_control) && map_closed;
    if (!(mapped && map_closed)) {
      remember("fault-image-mapping", "invariant", 0); domain_mapping_diagnostic();
    }
    invariant(mapped && map_closed, "fault-image-mapping");
    mach_port_t local = domain_bootstrap_local; domain_bootstrap_local = MACH_PORT_NULL;
    image_closure_prepare(&handoff, local);
    struct identity birth = fault_inspect(getpid());
    domain_io(write(3, &birth, sizeof(birth)), sizeof(birth), "fault-birth-write");
    if (!domain_record.control) {
      need(exec_handoff_byte(&handoff, 3, true, 'B') && exec_handoff_byte(&handoff, 4, false, 'T'));
      struct exec_probe result = exec_handoff_attempt(&probe, domain_control_asset, control_arguments, environ); domain_probe_handoff = NULL;
      domain_io(write(3, &result, sizeof(result)), sizeof(result), "fault-probe-write"); need(exec_handoff_refused(result));
    }
    exec_handoff_execute(&handoff, 4, 3, domain_record.control ? domain_control_asset : domain_helper,
      domain_record.control ? control_arguments : arguments, environ);
    remember("fault-image-exec", handoff.kind ? handoff.kind : "invariant", handoff.value);
    failure(126);
  }
  domain_child = child;
  domain_close(&ready[1]); domain_close(&release[0]); domain_close(&in[0]); domain_close(&out[1]); domain_close(&err[1]);
  struct identity creator; struct exec_handoff handoff = {0};
  domain_io(read(ready[0], &creator, sizeof(creator)), sizeof(creator), "fault-birth-read");
  invariant(creator.token.val[5] == (unsigned)child && audit_identity_same(creator, fault_inspect(child)) && exec_handoff_receive(&handoff, ready[0], false), "fault-birth-binding");
  domain_creator_check(creator, parent_asid);
  domain_record.creator = domain_record.owner = creator; domain_record.asid = creator.token.val[6];
  domain_record.execution = 1; domain_known(creator); domain_store(1); domain_pin = audit_hold(domain_record.asid);
  domain_image_inputs(&domain_inherited, creator);
  domain_image_bound(); domain_store(1); domain_image_phase = 1;
  fputs("{\"creator\":{\"version\":5,\"phase\":1,\"record\":", stdout); domain_emit(); puts("}}"); fflush(stdout);
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
      domain_fenced = true; domain_close(&release[1]); domain_close(&in[1]);
      domain_port_cleanup(); need(!resource_uncertain);
      if (domain_record.stage != 5) { domain_store(3); domain_retire(); }
      domain_output(&out[0], "stdout"); domain_output(&err[0], "stderr"); invariant(domain_exited(), "fault-child-status");
    }
    printf("{\"sequence\":%u,\"value\":", sequence);
    if (!strcmp(fields[1], "image-probe")) {
      need(count == 2); domain_probe(); domain_emit();
    } else if (!strcmp(fields[1], "control-settle")) {
      need(count == 2 && domain_record.control && domain_record.continuation == 2 && domain_child < 0 && WIFEXITED(domain_status) && !WEXITSTATUS(domain_status));
      struct audit_domain_view view = audit_census(domain_record.uid, domain_record.asid); need(!view.nl && !view.nd);
      const char expected[] = "{\"phase\":\"armed\"}\n[\"\",\"space value\",\"λ雪\",\"'\\\"\",\"$(false); & | < > *\"]\n";
      need(domain_control_used == sizeof(expected) - 1 && !memcmp(domain_control_bytes, expected, sizeof(expected) - 1));
      domain_hex(domain_control_bytes, domain_control_used, domain_record.control_output);
      strcpy(domain_record.control_cdhash, domain_record.cdhash); strcpy(domain_record.control_observations, domain_record.observations);
      domain_record.control_creator = domain_record.creator; domain_record.control_target = domain_record.target;
      domain_record.control_retired = 1; domain_store(1); domain_emit();
    } else if (!strcmp(fields[1], "control-next")) {
      need(count == 3 && domain_record.control && domain_record.control_retired); domain_image_readback(fields[2]);
      struct audit_domain_view view = audit_census(domain_record.uid, domain_record.asid); need(!view.nl && !view.nd);
      need(mach_port_deallocate(mach_task_self(), domain_pin) == KERN_SUCCESS); domain_pin = MACH_PORT_NULL;
      domain_close(&in[1]); domain_close(&out[0]); domain_close(&err[0]);
      puts("null}"); break;
    } else if (!strcmp(fields[1], "image-exec")) { need(count == 2); domain_image_exec(); domain_emit();
    } else if (!strcmp(fields[1], "image-read")) { need(count == 2); domain_image_observe(true); domain_emit();
    } else if (!strcmp(fields[1], "image-seal")) {
      need(count == 3 && domain_image_phase == 3 && !domain_fenced && domain_hash(fields[2]) && !domain_record.continuation);
      strcpy(domain_record.observations, fields[2]); domain_record.continuation = 1; domain_store(1); domain_emit();
    } else if (!strcmp(fields[1], "image-continue")) { need(count == 3); domain_image_continue(fields[2]); domain_emit();
    } else if (!strcmp(fields[1], "payload")) { need(count == 3 && !domain_fenced && strlen(fields[2]) == 1 && strchr("ACL", *fields[2]) && ((domain_record.control && domain_record.continuation == 2 && *fields[2] == 'A') || (domain_record.stage >= 2 && domain_record.stage < 4))); need(write(in[1], fields[2], 1) == 1); fputs("null",stdout);
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
      need(count == 3 && domain_record.stage == 1 && domain_record.continuation == 2 && domain_record.members >= 2 && domain_hash(fields[2])); strcpy(domain_record.intent, fields[2]); domain_store(2); domain_emit();
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
      domain_store(6); bool maps_closed = exec_mapping_close(&domain_mapping); maps_closed = exec_mapping_close(&domain_map_control) && maps_closed;
      domain_close(&domain_map_parent); need(maps_closed);
      need(!fchmod(domain_root,0700) && mach_port_deallocate(mach_task_self(),domain_pin) == KERN_SUCCESS); domain_emit(); puts("}"); return;
    } else need(false);
    puts("}");
  }
  }
}
