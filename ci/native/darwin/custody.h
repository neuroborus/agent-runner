/* Shared protected bytes, signatures and audit-token identity reads. */
#ifndef NATIVE_DARWIN_CUSTODY_H
#define NATIVE_DARWIN_CUSTODY_H
#include <stdbool.h>
#include <time.h>
#include <poll.h>
/* Only the ordinary creator inspection supplies these passive observations. */
#ifndef IMAGE_CALL
#define IMAGE_CALL(operation, call) ((void)(operation), (call))
#endif
#ifndef IMAGE_NOTE
#define IMAGE_NOTE(operation, entry, result, error) ((void)(result))
#endif
/* EXC_MASK_ALL omits the public CRASH and CORPSE_NOTIFY classes. */
#define DOMAIN_EXCEPTION_MASK (EXC_MASK_ALL | EXC_MASK_CRASH | EXC_MASK_CORPSE_NOTIFY)
struct domain_bootstrap_issue {
  const char *operation, *kind; int value; bool cleanup;
};
#define DOMAIN_FORK_ISSUES 64
struct domain_bootstrap_fork {
  pid_t child; unsigned count; struct domain_bootstrap_issue issues[DOMAIN_FORK_ISSUES];
};
static bool domain_bootstrap_check(struct domain_bootstrap_fork *out, bool ok, const char *operation, const char *kind, int value, bool cleanup) {
  if (!ok) {
    if (out->count < DOMAIN_FORK_ISSUES) out->issues[out->count++] = (struct domain_bootstrap_issue){operation, kind, value, cleanup};
    else out->issues[DOMAIN_FORK_ISSUES-1] = (struct domain_bootstrap_issue){"fork-issues-truncated", "invariant", 0, true};
  }
  return ok;
}
#if defined(NATIVE_CI_EXPERIMENT) || defined(NATIVE_CREATION_INPUTS)
#include <spawn.h>
/* Use the selected SDK declaration and linked native implementation directly.
 * POSIX spawn errors are return values, not the caller's ambient errno. */
static bool domain_spawn_check(struct domain_bootstrap_fork *out, int result, const char *operation, bool cleanup) {
  return domain_bootstrap_check(out, result == 0, operation, "errno", result, cleanup);
}
static bool domain_spawn_attributes(struct domain_bootstrap_fork *out, posix_spawnattr_t *attributes, bool *owned, short flags) {
  if (!domain_spawn_check(out, posix_spawnattr_init(attributes), "spawn-attributes-init", false)) return false;
  *owned = true;
  return domain_spawn_check(out, posix_spawnattr_setflags(attributes, flags), "spawn-flags", false) &&
    domain_spawn_check(out, posix_spawnattr_setspecialport_np(attributes, MACH_PORT_NULL, TASK_BOOTSTRAP_PORT), "spawn-bootstrap", false);
}
static void domain_spawn_settle(struct domain_bootstrap_fork *out, posix_spawn_file_actions_t *actions, bool *actions_owned, posix_spawnattr_t *attributes, bool *attributes_owned) {
  if (*actions_owned) {
    *actions_owned = false;
    domain_spawn_check(out, posix_spawn_file_actions_destroy(actions), "spawn-actions-destroy", true);
  }
  if (*attributes_owned) {
    *attributes_owned = false;
    domain_spawn_check(out, posix_spawnattr_destroy(attributes), "spawn-attributes-destroy", true);
  }
}
#endif
/* One release attempt per successful getter acquisition, including aliases.
 * Counts are untrusted; initialized bounded storage is the only cleanup input. */
static bool domain_exception_settle(struct domain_bootstrap_fork *out, mach_port_t handlers[EXC_TYPES_COUNT], mach_msg_type_number_t count, int releases[EXC_TYPES_COUNT]) {
  bool ok = true;
  kern_return_t settlement = KERN_SUCCESS;
  IMAGE_NOTE("mach_port_deallocate/exception-copies", true, 0, 0);
  for (unsigned i = 0; i < count && i < EXC_TYPES_COUNT; i++) {
    releases[i] = -1;
    if (MACH_PORT_VALID(handlers[i])) {
      releases[i] = mach_port_deallocate(mach_task_self(), handlers[i]);
      if (releases[i] != KERN_SUCCESS) settlement = releases[i];
      ok = domain_bootstrap_check(out, releases[i] == KERN_SUCCESS, "exception-copy-release", "mach", releases[i], true) && ok;
    }
  }
  IMAGE_NOTE("mach_port_deallocate/exception-copies", false, settlement, errno);
  return ok;
}
/* XNU can skip individual MAC actions while a setter returns success. Both
 * required getters must prove null slots and settle their own copies before
 * any caller refuses or proceeds to census. Failed getter outputs own nothing. */
static bool domain_exception_readback(struct domain_bootstrap_fork *out, task_t self, thread_t thread) {
  bool ok = true;
  for (unsigned which = 0; which < 2; which++) {
    exception_mask_t masks[EXC_TYPES_COUNT] = {0}, seen = 0; mach_port_t handlers[EXC_TYPES_COUNT] = {0};
    exception_behavior_t behaviors[EXC_TYPES_COUNT] = {0}; thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {0};
    mach_msg_type_number_t count = EXC_TYPES_COUNT; int releases[EXC_TYPES_COUNT];
    const char *operation = which ? "thread-exception-read" : "task-exception-read";
    kern_return_t got = which
      ? thread_get_exception_ports(thread, DOMAIN_EXCEPTION_MASK, masks, &count, handlers, behaviors, flavors)
      : task_get_exception_ports(self, DOMAIN_EXCEPTION_MASK, masks, &count, handlers, behaviors, flavors);
    if (!domain_bootstrap_check(out, got == KERN_SUCCESS, operation, "mach", got, false)) { ok = false; continue; }
    /* XNU 43a9088 returns thread count0 when tro_exc_actions is absent.
     * The independently queried task table must still cover every class. */
    bool empty = count <= EXC_TYPES_COUNT && (which || count > 0);
    for (unsigned i = 0; i < count && i < EXC_TYPES_COUNT; i++) {
      if (!masks[i] || handlers[i] != MACH_PORT_NULL || (seen & masks[i]) || (masks[i] & ~DOMAIN_EXCEPTION_MASK)) empty = false;
      seen |= masks[i];
    }
    ok = domain_bootstrap_check(out, empty && ((which && !count) || seen == DOMAIN_EXCEPTION_MASK), operation, "invariant", 0, false) && ok;
    ok = domain_exception_settle(out, handlers, count, releases) && ok;
  }
  return ok;
}
/* Only the feasibility helper and experimental launcher opt into shared
 * pre-fork input fencing. Sanitation and failure policy stay local. */
#ifdef NATIVE_CREATION_INPUTS
#include <dlfcn.h>
#include <mach/mig.h>
#if !defined(__APPLE__) || !defined(__x86_64__)
#error Creation input fencing requires the matching macOS x64 SDK.
#endif
/* XNU 43a9088: task.defs/std_types.defs use COPY_SEND for the setter;
 * ipc_task_init creates a fresh space and copies the parent's bootstrap slot.
 * Prevent runtime acquisition there instead of releasing unproved userspace refs.
 * The exported bootstrap value is borrowed here, never an owned acquisition. */
struct domain_registered_ports {
  mach_port_array_t ports; mach_msg_type_number_t count; bool owned;
};
static bool domain_registered_capture(struct domain_bootstrap_fork *out, struct domain_registered_ports *snapshot, const char *operation, bool cleanup) {
  kern_return_t got = mach_ports_lookup(mach_task_self(), &snapshot->ports, &snapshot->count);
  if (!domain_bootstrap_check(out, got == KERN_SUCCESS, operation, "mach", got, cleanup)) {
    /* A failed getter's output parameters grant no references or array. */
    snapshot->ports = NULL; snapshot->count = 0; return false;
  }
  snapshot->owned = true;
  return domain_bootstrap_check(out, !snapshot->count || snapshot->ports != NULL, operation, "invariant", 0, cleanup);
}
static bool domain_registered_release(struct domain_bootstrap_fork *out, struct domain_registered_ports *snapshot) {
  if (!snapshot->owned) return true;
  snapshot->owned = false; bool ok = true;
  if (snapshot->ports) {
    /* Each entry is a separate getter reference, including repeated names. */
    for (unsigned i = 0; i < snapshot->count; i++) if (MACH_PORT_VALID(snapshot->ports[i])) {
      kern_return_t released = mach_port_deallocate(mach_task_self(), snapshot->ports[i]);
      ok = domain_bootstrap_check(out, released == KERN_SUCCESS, "registered-copy-release", "mach", released, true) && ok;
    }
    kern_return_t released = vm_deallocate(mach_task_self(), (vm_address_t)snapshot->ports, (vm_size_t)snapshot->count * sizeof(*snapshot->ports));
    ok = domain_bootstrap_check(out, released == KERN_SUCCESS, "registered-array-release", "mach", released, true) && ok;
  }
  snapshot->ports = NULL; snapshot->count = 0; return ok;
}
static bool domain_registered_read(struct domain_bootstrap_fork *out, mach_port_array_t expected, mach_msg_type_number_t count, bool empty, const char *operation, bool cleanup) {
  struct domain_registered_ports observed = {0};
  bool ok = domain_registered_capture(out, &observed, operation, cleanup);
  if (ok) {
    bool matches = empty || observed.count == count;
    for (unsigned i = 0; i < observed.count; i++)
      if (empty ? observed.ports[i] != MACH_PORT_NULL : i >= count || observed.ports[i] != expected[i]) matches = false;
    ok = domain_bootstrap_check(out, matches, operation, "invariant", 0, cleanup);
  }
  return domain_registered_release(out, &observed) && ok;
}
/* Getter tuples omit the setter's privilege/MAC state (XNU ipc_tt.c:4411+).
 * Observe the original pre-fork slots without clearing or replaying them. Names
 * cached below are diagnostic integers after their getter copies are released. */
static struct {
  bool active, complete; pid_t parent; kern_return_t result; mach_msg_type_number_t count;
  exception_mask_t masks[EXC_TYPES_COUNT]; mach_port_t handlers[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT]; thread_state_flavor_t flavors[EXC_TYPES_COUNT];
  int releases[EXC_TYPES_COUNT];
} domain_fork_exceptions;
static bool domain_exception_observe(struct domain_bootstrap_fork *out) {
  memset(&domain_fork_exceptions, 0, sizeof(domain_fork_exceptions));
  domain_fork_exceptions.active = true; domain_fork_exceptions.parent = getpid();
  exception_mask_t masks[EXC_TYPES_COUNT] = {0}; mach_port_t handlers[EXC_TYPES_COUNT] = {0};
  exception_behavior_t behaviors[EXC_TYPES_COUNT] = {0}; thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {0};
  mach_msg_type_number_t count = EXC_TYPES_COUNT;
  kern_return_t got = task_get_exception_ports(mach_task_self(), DOMAIN_EXCEPTION_MASK, masks, &count, handlers, behaviors, flavors);
  domain_fork_exceptions.result = got;
  /* Unavailable observation adds no exception-specific fork precondition. */
  if (got != KERN_SUCCESS) return true;
  domain_fork_exceptions.count = count;
  bool ok = domain_bootstrap_check(out, count <= EXC_TYPES_COUNT, "exception-count", "invariant", 0, false);
  domain_fork_exceptions.complete = ok;
  for (unsigned i = 0; i < count && i < EXC_TYPES_COUNT; i++) {
    domain_fork_exceptions.masks[i] = masks[i]; domain_fork_exceptions.handlers[i] = handlers[i];
    domain_fork_exceptions.behaviors[i] = behaviors[i]; domain_fork_exceptions.flavors[i] = flavors[i];
  }
  return domain_exception_settle(out, handlers, count, domain_fork_exceptions.releases) && ok;
}
static void domain_fork_diagnostic(const char *owner) {
  if (!domain_fork_exceptions.active) return;
  int saved = errno;
  fprintf(stderr, "native-darwin-fork-inheritance: owner=%s reporter=%d parent=%d exception-result=%d count=%u complete=%u\n",
    owner, getpid(), domain_fork_exceptions.parent, domain_fork_exceptions.result, domain_fork_exceptions.count, !!domain_fork_exceptions.complete);
  for (unsigned i = 0; i < domain_fork_exceptions.count && i < EXC_TYPES_COUNT; i++)
    fprintf(stderr, "native-darwin-fork-exception: owner=%s parent=%d index=%u mask=%#x handler=%u behavior=%d flavor=%d release=%d\n",
      owner, domain_fork_exceptions.parent, i, domain_fork_exceptions.masks[i], domain_fork_exceptions.handlers[i], domain_fork_exceptions.behaviors[i], domain_fork_exceptions.flavors[i], domain_fork_exceptions.releases[i]);
  errno = saved;
}
static bool domain_bootstrap_read(struct domain_bootstrap_fork *out, mach_port_t expected, const char *operation, bool cleanup) {
  mach_port_t observed = MACH_PORT_NULL;
  kern_return_t got = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &observed);
  bool ok = domain_bootstrap_check(out, got == KERN_SUCCESS, operation, "mach", got, cleanup);
  if (got == KERN_SUCCESS) {
    ok = domain_bootstrap_check(out, observed == expected, operation, "invariant", 0, cleanup) && ok;
    if (MACH_PORT_VALID(observed)) {
      kern_return_t released = mach_port_deallocate(mach_task_self(), observed);
      ok = domain_bootstrap_check(out, released == KERN_SUCCESS, "bootstrap-copy-release", "mach", released, true) && ok;
    }
  }
  return ok;
}
/* Read before setup or cache clearing. Only successful getter copies are owned;
 * the exported cache remains a borrow even when it aliases a getter result. */
static void domain_bootstrap_entry(struct domain_bootstrap_fork *out) {
  extern mach_port_t bootstrap_port;
  domain_bootstrap_read(out, MACH_PORT_NULL, "bootstrap-entry", false);
  domain_bootstrap_check(out, bootstrap_port == MACH_PORT_NULL, "bootstrap-entry-cache", "invariant", 0, false);
}
static void domain_bootstrap_fork(struct domain_bootstrap_fork *out, pid_t *retained, void (*bind)(void)) {
  memset(out, 0, sizeof(*out)); out->child = -1;
  domain_fork_exceptions.active = false;
  extern mach_port_t bootstrap_port;
  mach_port_t saved = MACH_PORT_NULL;
  kern_return_t got = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &saved);
  if (!domain_bootstrap_check(out, got == KERN_SUCCESS, "bootstrap-capture", "mach", got, false)) return;
  mach_port_t cached = bootstrap_port;
  struct domain_registered_ports registered = {0};
  bool registered_captured = domain_registered_capture(out, &registered, "registered-capture", false);
  bool ready = domain_exception_observe(out) && registered_captured;
  bool bootstrap_changed = false;
  /* Callers have independently verified one thread. No cache right is released
   * or private runtime reset called. Parent fork handlers also see null. */
  if (ready) {
    bootstrap_port = MACH_PORT_NULL; bootstrap_changed = true;
    kern_return_t cleared = task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, MACH_PORT_NULL);
    ready = domain_bootstrap_check(out, cleared == KERN_SUCCESS, "bootstrap-clear", "mach", cleared, false);
  }
  if (ready) ready = domain_bootstrap_read(out, MACH_PORT_NULL, "bootstrap-empty", false);
  /* XNU ipc_tt.c:265-287 inherits registered slots separately; Libsystem's
   * init.c:509-542 runs callbacks before our child code can sanitize them. */
  if (ready) {
    kern_return_t cleared = mach_ports_register(mach_task_self(), NULL, 0);
    ready = domain_bootstrap_check(out, cleared == KERN_SUCCESS, "registered-clear", "mach", cleared, false);
  }
  if (ready) ready = domain_registered_read(out, NULL, 0, true, "registered-empty", false);
  if (ready) {
    struct proc_taskinfo threads;
    int inspected = proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &threads, sizeof(threads)), error = errno;
    ready = domain_bootstrap_check(out, inspected == sizeof(threads), "bootstrap-threads", inspected < 0 ? "errno" : "status", inspected < 0 ? error : inspected, false);
    if (ready) ready = domain_bootstrap_check(out, threads.pti_threadnum == 1, "bootstrap-threads", "invariant", 0, false);
  }
  if (ready) {
    ready = domain_bootstrap_check(out, bootstrap_port == MACH_PORT_NULL, "bootstrap-cache", "invariant", 0, false);
  }
  if (ready) {
    out->child = fork(); int error = errno;
    if (out->child > 0) *retained = out->child;
    domain_bootstrap_check(out, out->child >= 0, "fork", "errno", error, false);
    domain_bootstrap_check(out, bootstrap_port == MACH_PORT_NULL, "bootstrap-cache", "invariant", 0, false);
  }
  if (out->child == 0) {
    /* The parent's getter name was not inherited into this new IPC space.
     * It must never enter child cleanup, even if a new local name aliases it. */
    if (!out->count) {
      bind();
      /* Runtime child callbacks can repopulate kernel slots before fork returns.
       * Replacing them releases no userspace getter copies or borrowed names. */
      kern_return_t cleared = mach_ports_register(mach_task_self(), NULL, 0);
      domain_bootstrap_check(out, cleared == KERN_SUCCESS, "registered-child-clear", "mach", cleared, false);
      domain_bootstrap_read(out, MACH_PORT_NULL, "bootstrap-empty", false);
      domain_registered_read(out, NULL, 0, true, "registered-child-empty", false);
      domain_bootstrap_check(out, bootstrap_port == MACH_PORT_NULL, "bootstrap-cache", "invariant", 0, false);
    }
  } else {
    /* Restore after a failed fork or preparation too. COPY_SEND leaves saved
     * owned until its one release; the independent readback owns another copy. */
    if (registered_captured) {
      kern_return_t restored = mach_ports_register(mach_task_self(), registered.ports, registered.count);
      domain_bootstrap_check(out, restored == KERN_SUCCESS, "registered-restore", "mach", restored, true);
      domain_registered_read(out, registered.ports, registered.count, false, "registered-match", true);
    }
    if (bootstrap_changed) {
      bootstrap_port = cached;
      kern_return_t restored = task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, saved);
      domain_bootstrap_check(out, restored == KERN_SUCCESS, "bootstrap-restore", "mach", restored, true);
      domain_bootstrap_read(out, saved, "bootstrap-match", true);
    }
    domain_registered_release(out, &registered);
    if (MACH_PORT_VALID(saved)) {
      kern_return_t released = mach_port_deallocate(mach_task_self(), saved);
      domain_bootstrap_check(out, released == KERN_SUCCESS, "bootstrap-copy-release", "mach", released, true);
    }
    domain_bootstrap_check(out, bootstrap_port == cached, "bootstrap-cache", "invariant", 0, true);
  }
}
#endif
#ifndef NATIVE_AUDIT_DOMAIN_ONLY
#include <mach-o/loader.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <time.h>
static void need_at(bool ok, const char *file, unsigned line) {
  if (!ok) {
    int error = errno;
    fprintf(stderr, "native-darwin-guard: file=%s line=%u errno=%d\n", file, line, error);
    fflush(stderr); _exit(126);
  }
}
#define need(ok) need_at(!!(ok), __FILE__, __LINE__)
static unsigned number(const char *s) {
  char *end; errno = 0; unsigned long n = strtoul(s, &end, 10);
  need(*s && !errno && !*end && n <= 0x7fffffffUL); return (unsigned)n;
}
static void hex(const unsigned char *data, size_t n, char *out) {
  for (size_t i = 0; i < n; i++) sprintf(out + 2*i, "%02x", data[i]);
}
static int directory(const char *name, uid_t uid, gid_t gid, mode_t mode) {
  char canonical[PATH_MAX]; struct stat st;
  need(realpath(name, canonical) && !strcmp(name, canonical));
  int fd = open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(fd >= 0 && !fstat(fd, &st) && S_ISDIR(st.st_mode) && st.st_uid == uid &&
       st.st_gid == gid && (st.st_mode & 07777) == mode); return fd;
}
static int file_stat_same(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
    a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
    a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
    a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
/* A null acl_get_fd_np result cannot distinguish absence from a failed read.
 * Inspect FILESEC_ACL on the held object. A hash request serializes actual ACL
 * text, or zero bytes for inspected absence. Private/reviewed reads also
 * require no entries; hosted installed authority reads observe the actual ACL. */
static void custody_acl(int fd, char hash[65], bool require_empty) {
  struct stat before, inspected, after;
  filesec_t security = NULL; acl_t acl = NULL; char *bytes = NULL; ssize_t length = 0;
  const char *operation = NULL, *domain = "errno";
  int result, error = 0, present = -1, text_result = 0, acl_result = 0, text_error = 0, acl_error = 0;
  unsigned char sum[32];
  errno = 0; result = fstat(fd, &before); error = errno;
  if (result) { operation = "file-stat"; goto done; }
  errno = 0; security = filesec_init(); error = errno;
  if (!security) { operation = "filesec-init"; goto done; }
  errno = 0; result = fstatx_np(fd, &inspected, security); error = errno;
  if (result) { operation = "filesec-stat"; goto done; }
  if (!file_stat_same(&before, &inspected)) { operation = "file-stable"; domain = "invariant"; error = 0; goto done; }
  errno = 0; result = filesec_query_property(security, FILESEC_ACL, &present); error = errno;
  if (result) { operation = "acl-query"; goto done; }
  /* Presence is a validity bitmask, not a Boolean restricted to zero and one. */
  if (present != 0) {
    errno = 0; result = filesec_get_property(security, FILESEC_ACL, &acl); error = errno;
    if (result || !acl) { operation = "acl-read"; domain = result ? "errno" : "invariant"; if (!result) error = 0; goto done; }
    errno = 0; result = acl_valid(acl); error = errno;
    if (result) { operation = "acl-valid"; goto done; }
    if (require_empty) {
      acl_entry_t entry;
      errno = 0; result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry); error = errno;
      /* Darwin returns zero for an entry and -1/EINVAL after a valid empty ACL. */
      if (!(result == -1 && error == EINVAL)) {
        operation = "acl-empty"; domain = result == -1 ? "errno" : "invariant"; if (result != -1) error = 0; goto done;
      }
    }
    if (hash) {
      errno = 0; bytes = acl_to_text(acl, &length); error = errno;
      if (!bytes) { operation = "acl-text"; goto done; }
      if (length < 0 || length > 65536) { operation = "acl-text-size"; domain = "invariant"; error = 0; goto done; }
    }
  }
  errno = 0; result = fstat(fd, &after); error = errno;
  if (result) { operation = "file-stat-again"; goto done; }
  if (!file_stat_same(&before, &after)) { operation = "file-stable"; domain = "invariant"; error = 0; goto done; }
  if (hash && !CC_SHA256(bytes ? bytes : "", (CC_LONG)length, sum)) {
    operation = "acl-hash"; domain = "invariant"; error = 0;
  }
done:
  if (bytes) { errno = 0; text_result = acl_free(bytes); text_error = errno; }
  if (acl) { errno = 0; acl_result = acl_free(acl); acl_error = errno; }
  /* filesec_free has no status; it is independent of both ACL releases. */
  if (security) filesec_free(security);
  if (operation) fprintf(stderr, "native-darwin-acl: operation=%s domain=%s value=%d\n", operation, domain, error);
  if (text_result) fprintf(stderr, "native-darwin-acl-cleanup: operation=acl-text-release domain=errno value=%d\n", text_error);
  if (acl_result) fprintf(stderr, "native-darwin-acl-cleanup: operation=acl-release domain=errno value=%d\n", acl_error);
  if (operation || text_result || acl_result) {
    fflush(stderr); errno = operation ? error : text_result ? text_error : acl_error; need(false);
  }
  if (hash) hex(sum, sizeof(sum), hash);
}
static void no_acl(int fd) { custody_acl(fd, NULL, true); }
static bool installed_cache_path(const char *name) {
  const char *base = strrchr(name, '/');
  return base && (!strcmp(base + 1, "dyld_shared_cache_x86_64") || !strcmp(base + 1, "dyld_shared_cache_x86_64h")) &&
    (!strncmp(name, "/System/Library/dyld/", 21) || !strncmp(name, "/System/Volumes/Preboot/", 24));
}
/* Classification is independent of reviewed file eligibility and custody kind. */
static bool installed_input_path(const char *name) {
  return !strcmp(name, "/usr/bin/clang") || !strcmp(name, "/usr/bin/xcrun") ||
    !strcmp(name, "/usr/bin/codesign") || !strcmp(name, "/usr/bin/env") ||
    !strcmp(name, "/usr/bin/sudo") || !strcmp(name, "/usr/bin/git") ||
    !strcmp(name, "/usr/bin/hdiutil") || !strcmp(name, "/usr/bin/log") || !strcmp(name, "/sbin/pfctl") ||
    !strcmp(name, "/usr/lib/dyld") || !strcmp(name, "/private/etc/security/audit_event") ||
    !strcmp(name, "/private/etc/security/audit_class") || !strcmp(name, "/etc/security/audit_event") ||
    !strcmp(name, "/etc/security/audit_class") || !strncmp(name, "/Library/Developer/", 19) ||
    (!strncmp(name, "/Applications/", 14) && strstr(name, "/Contents/Developer/")) ||
    !strncmp(name, "/usr/include/", 13) || !strncmp(name, "/usr/lib/clang/", 15) || installed_cache_path(name);
}
static bool experiment_installed_path(const char *name) {
#ifdef NATIVE_CI_EXPERIMENT
  return installed_input_path(name) || !strcmp(name, "/usr/sbin/dtrace");
#else
  (void)name; return false;
#endif
}
static bool is_bootstrap_parent(const char *name, const struct stat *st) {
  return S_ISDIR(st->st_mode) &&
    (experiment_installed_path(name) || (st->st_uid == 0 && !(st->st_mode & 022)));
}
/* Only fixed ordinary case inputs cross the observed hosted run directory.
 * Every generated descendant retains the generic private ancestry guard. */
static bool experiment_case_parent(const char *name, const char *parent, const struct stat *st) {
#ifdef NATIVE_CI_EXPERIMENT
  const char *root = "/private/var/run/native-poc/cases/";
  size_t length = strlen(root);
  if (strncmp(name, root, length)) return false;
  const char *context = name + length;
  if (strspn(context, "0123456789abcdef") != 64 || (context[64] && context[64] != '/')) return false;
  return !strcmp(parent, "/private/var/run") && S_ISDIR(st->st_mode) &&
    st->st_uid == 0 && !(st->st_mode & 06002);
#else
  (void)name; (void)parent; (void)st; return false;
#endif
}
/* A pin or custody kind never makes a generated input an installed input. */
static int installed_path(const char *name, const struct stat *st) {
  const char *tools[] = {"/usr/bin/clang", "/usr/bin/xcrun", "/usr/bin/codesign", "/usr/bin/env",
    "/usr/bin/sudo", "/usr/bin/git", "/usr/bin/hdiutil", "/usr/bin/log", "/sbin/pfctl"};
  if (!S_ISREG(st->st_mode) || st->st_uid != 0 || st->st_nlink <= 0) return 0;
  mode_t mode = st->st_mode & 07777;
  for (unsigned i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) if (!strcmp(name, tools[i]))
    return st->st_gid == 0 && (!strcmp(name, "/usr/bin/sudo") ? mode == 04555 || mode == 04755 : mode == 0555 || mode == 0755);
  if (mode & 06022) return 0;
  return installed_input_path(name);
}
/* Diagnostic samples never acquire metadata or replace the guard's errno. */
static void input_refusal(const char *name, const char *predicate, const struct stat *st) {
  int error = errno; size_t size = strlen(name); char encoded[PATH_MAX*2+1] = {0};
  if (size < PATH_MAX) {
    hex((const unsigned char *)name, size, encoded);
    fprintf(stderr, "native-darwin-input: predicate=%s path-length=%zu path-hex=%s errno=%d\n", predicate, size, encoded, error);
    if (st) fprintf(stderr, "native-darwin-input-stat: dev=%jd inode=%ju uid=%ju gid=%ju mode=%#jo links=%ju size=%jd\n",
      (intmax_t)st->st_dev, (uintmax_t)st->st_ino, (uintmax_t)st->st_uid, (uintmax_t)st->st_gid,
      (uintmax_t)st->st_mode, (uintmax_t)st->st_nlink, (intmax_t)st->st_size);
  }
  fflush(stderr); errno = error;
}
static int installed_input(const char *name, const struct stat *identity) {
  bool hosted = experiment_installed_path(name);
  if (!(hosted ? S_ISREG(identity->st_mode) && identity->st_nlink > 0 : installed_path(name, identity))) return 0;
  char canonical[PATH_MAX], parent[PATH_MAX];
  need(realpath(name, canonical) && !strcmp(name, canonical) && strlen(name) < sizeof(parent));
  strcpy(parent, name); int leaf = 1;
  for (;;) {
    int fd = open(parent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (leaf ? 0 : O_DIRECTORY));
    struct stat before, after, named;
    bool sampled = false; const char *predicate = "open";
    bool ok = fd >= 0 && (predicate = "stat", sampled = fstat(fd, &before) == 0) &&
      (predicate = "kind", leaf ? S_ISREG(before.st_mode) : S_ISDIR(before.st_mode)) &&
      (predicate = "links", !leaf || before.st_nlink > 0) &&
      (predicate = "eligibility", hosted || (before.st_uid == 0 && !(before.st_mode & 022))) &&
      (predicate = "identity", !leaf || file_stat_same(identity, &before));
    if (!ok) input_refusal(parent, predicate, sampled ? &before : NULL);
    need(ok);
    if (!hosted) no_acl(fd);
    need(!fstat(fd, &after) && !lstat(parent, &named) && file_stat_same(&before, &after) &&
      file_stat_same(&before, &named) && !close(fd));
    if (!strcmp(parent, "/")) break;
    char *slash = strrchr(parent, '/'); need(slash); if (slash == parent) parent[1] = 0; else *slash = 0;
    leaf = 0;
  }
  return 1;
}
static unsigned char *read_file(const char *name, gid_t gid, mode_t mode,
                           size_t limit, const char *pin, struct stat *identity, int installed) {
  char canonical[PATH_MAX], hash[65]; unsigned char sum[CC_SHA256_DIGEST_LENGTH];
  need(realpath(name, canonical) && !strcmp(name, canonical));
  int fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  /* Sample only evaluated terms; -2 distinguishes an uncalled fstat from -1. */
  int file_fd = -1, file_stat = -2, file_kind = -1, file_owner = -1, file_group = -1;
  int file_single = -1, file_installed = -1, file_eligible = -1, file_mode = -1;
  int file_positive = -1, file_limit = -1, file_pin = -1; size_t pin_length = 0;
  bool file_ok = (file_fd = fd >= 0) && (file_stat = fstat(fd, identity), !file_stat) &&
       (file_kind = S_ISREG(identity->st_mode)) && (file_owner = identity->st_uid == 0) &&
       (file_group = identity->st_gid == gid) &&
       ((file_single = identity->st_nlink == 1) ||
        ((file_installed = !!installed) && (file_eligible = installed_input(name, identity)))) &&
       (file_mode = (identity->st_mode & 07777) == mode) && (file_positive = identity->st_size > 0) &&
       (file_limit = (uint64_t)identity->st_size <= limit) && (pin_length = strlen(pin), file_pin = pin_length == 64);
  if (!file_ok) {
    int file_error = errno;
    /* Successful canonicalization/equality already bounds the complete name. */
    size_t path_length = strlen(name); char path_hex[2*PATH_MAX] = {0};
    hex((const unsigned char *)name, path_length, path_hex);
    fprintf(stderr, "native-darwin-file: path-length=%zu path-hex=%s expected-gid=%ju expected-mode=%#jo installed=%d limit=%zu errno=%d\n",
      path_length, path_hex, (uintmax_t)gid, (uintmax_t)mode, installed, limit, file_error);
    fprintf(stderr, "native-darwin-file-predicates: fd=%d fstat=%d kind=%d owner=%d group=%d single=%d installed=%d eligible=%d mode=%d positive=%d limit=%d pin=%d\n",
      file_fd, file_stat, file_kind, file_owner, file_group, file_single, file_installed,
      file_eligible, file_mode, file_positive, file_limit, file_pin);
    if (file_stat == 0)
      fprintf(stderr, "native-darwin-file-metadata: dev=%jd inode=%ju uid=%ju gid=%ju links=%ju mode=%#jo size=%jd\n",
        (intmax_t)identity->st_dev, (uintmax_t)identity->st_ino, (uintmax_t)identity->st_uid,
        (uintmax_t)identity->st_gid, (uintmax_t)identity->st_nlink, (uintmax_t)identity->st_mode, (intmax_t)identity->st_size);
    if (file_pin != -1) fprintf(stderr, "native-darwin-file-pin: length=%zu\n", pin_length);
    fflush(stderr); errno = file_error;
  }
  need(file_ok);
  size_t size = (size_t)identity->st_size, offset = 0;
  unsigned char *bytes = calloc(size + 1, 1); need(bytes != NULL);
  while (offset < size) {
    ssize_t n = read(fd, bytes + offset, size - offset);
    if (n < 0 && errno == EINTR) continue;
    need(n > 0); offset += (size_t)n;
  }
  unsigned char extra; struct stat after, named;
  need(read(fd, &extra, 1) == 0 && !fstat(fd, &after) && !lstat(name, &named) &&
       file_stat_same(identity, &after) && file_stat_same(identity, &named) &&
       (identity->st_nlink == 1 || installed_input(name, &named)));
  need(CC_SHA256(bytes, (CC_LONG)size, sum) != NULL); hex(sum, sizeof(sum), hash);
  need(!strcmp(hash, pin) && !close(fd)); return bytes;
}
static unsigned char *file(const char *name, gid_t gid, mode_t mode,
                           size_t limit, const char *pin, struct stat *identity) {
  return read_file(name, gid, mode, limit, pin, identity, 0);
}
static unsigned char *installed_file(const char *name, gid_t gid, mode_t mode,
                           size_t limit, const char *pin, struct stat *identity) {
  return read_file(name, gid, mode, limit, pin, identity, 1);
}
#ifndef NATIVE_CI_EXPERIMENT
static void reviewed_image(const char *name) {
  /* Fixed experimental helpers are thin x64 images. Their purpose section
   * remains disqualifying even after a valid native signature is attached. */
  int fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  struct stat before, after; struct mach_header_64 header;
  need(fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) &&
    pread(fd, &header, sizeof(header), 0) == sizeof(header));
  if (header.magic == MH_MAGIC_64) {
    need(header.ncmds <= 512 && header.sizeofcmds <= 1048576 &&
      sizeof(header) + (uint64_t)header.sizeofcmds <= (uint64_t)before.st_size);
    unsigned char *commands = malloc(header.sizeofcmds); need(commands);
    need(pread(fd, commands, header.sizeofcmds, sizeof(header)) == header.sizeofcmds);
    size_t at = 0;
    for (unsigned i = 0; i < header.ncmds; i++) {
      need(at + sizeof(struct load_command) <= header.sizeofcmds);
      const struct load_command *command = (const void *)(commands + at);
      need(command->cmdsize >= 8 && command->cmdsize % 8 == 0 && at + command->cmdsize <= header.sizeofcmds);
      if (command->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *segment = (const void *)command;
        need(command->cmdsize >= sizeof(*segment) && segment->nsects <= 128 &&
          sizeof(*segment) + (uint64_t)segment->nsects * sizeof(struct section_64) == command->cmdsize);
        const struct section_64 *sections = (const void *)(segment + 1);
        for (unsigned section = 0; section < segment->nsects; section++)
          need(strncmp(sections[section].sectname, "__nexp", 16));
      }
      at += command->cmdsize;
    }
    need(at == header.sizeofcmds); free(commands);
  }
  need(!fstat(fd, &after) && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
    before.st_size == after.st_size && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
    before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec && !close(fd));
}
#endif
/* Fixed UTF-8 byte prefixes are hex encoded; no diagnostic text becomes syntax. */
static void signature_text(const char *field, CFStringRef value) {
  UInt8 bytes[128] = {0}; char encoded[257] = {0};
  CFIndex length = 0, used = 0, converted = 0;
  bool available = value != NULL && CFGetTypeID(value) == CFStringGetTypeID();
  if (available) {
    length = CFStringGetLength(value);
    if (length >= 0) converted = CFStringGetBytes(value, CFRangeMake(0, length), kCFStringEncodingUTF8,
      0, false, bytes, sizeof(bytes), &used);
    available = length >= 0 && converted >= 0 && converted <= length && used >= 0 && used <= sizeof(bytes) &&
      (!length || converted > 0) && (converted ? used > 0 : used == 0);
  }
  if (available) for (CFIndex i = 0; i < used; i++) {
    encoded[2*i] = "0123456789abcdef"[bytes[i] >> 4];
    encoded[2*i + 1] = "0123456789abcdef"[bytes[i] & 15];
  }
  fprintf(stderr, "native-darwin-signature-error-%s: available=%d truncated=%d utf8-hex=%s\n",
    field, available, available && converted < length, encoded);
}
static void signature_error_details(CFErrorRef error) {
  bool available = error != NULL && CFGetTypeID(error) == CFErrorGetTypeID();
  if (available) fprintf(stderr, "native-darwin-signature-error: available=1 code=%jd\n", (intmax_t)CFErrorGetCode(error));
  else fprintf(stderr, "native-darwin-signature-error: available=0\n");
  signature_text("domain", available ? CFErrorGetDomain(error) : NULL);
  CFStringRef description = available ? CFErrorCopyDescription(error) : NULL;
  signature_text("description", description);
  if (description) CFRelease(description);
}
struct identity { audit_token_t token; struct proc_bsdinfo bsd; };
/* Reuse a successfully inspected self identity, including its audit context. */
static struct identity signature_caller;
struct signature_sample {
  struct identity caller; struct timespec before, after;
  int pid, birth, audit, started, ended;
};
static void signature_begin(struct signature_sample *sample) {
  int saved = errno; sample->pid = getpid();
  if (signature_caller.token.val[5] == (unsigned)sample->pid) {
    sample->caller = signature_caller; sample->birth = sample->audit = 1;
  } else {
    sample->birth = proc_pidinfo(sample->pid, PROC_PIDTBSDINFO, 0, &sample->caller.bsd, sizeof(sample->caller.bsd)) == (int)sizeof(sample->caller.bsd);
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    sample->audit = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&sample->caller.token, &count) == KERN_SUCCESS && count == TASK_AUDIT_TOKEN_COUNT;
  }
  sample->started = clock_gettime(CLOCK_REALTIME, &sample->before) == 0;
  errno = saved;
}
static void signature_end(struct signature_sample *sample) {
  int saved = errno;
  sample->ended = clock_gettime(CLOCK_REALTIME, &sample->after) == 0;
  errno = saved;
}
static void signature_sample_report(struct signature_sample *sample, OSStatus status) {
  struct proc_bsdinfo *b = &sample->caller.bsd; unsigned *t = sample->caller.token.val;
  fprintf(stderr, "native-darwin-signature-call: {\"pid\":%d,\"birthAvailable\":%d,\"birth\":[%ju,%ju],"
    "\"credentials\":[%u,%u,%u,%u,%u,%u],\"auditAvailable\":%d,\"auditToken\":[%u,%u,%u,%u,%u,%u,%u,%u],"
    "\"startAvailable\":%d,\"start\":[%jd,%jd],\"endAvailable\":%d,\"end\":[%jd,%jd],\"status\":%jd}\n",
    sample->pid, sample->birth, (uintmax_t)b->pbi_start_tvsec, (uintmax_t)b->pbi_start_tvusec,
    b->pbi_uid, b->pbi_gid, b->pbi_ruid, b->pbi_rgid, b->pbi_svuid, b->pbi_svgid,
    sample->audit, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7],
    sample->started, (intmax_t)sample->before.tv_sec, (intmax_t)sample->before.tv_nsec,
    sample->ended, (intmax_t)sample->after.tv_sec, (intmax_t)sample->after.tv_nsec, (intmax_t)status);
}
static CFDictionaryRef signature_information(const char *name, bool detailed) {
#ifndef NATIVE_CI_EXPERIMENT
  reviewed_image(name);
#endif
  size_t path_length = strlen(name);
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)name,
                                                        (CFIndex)path_length, false);
  SecStaticCodeRef code = NULL; CFDictionaryRef info = NULL;
  CFErrorRef error = NULL;
  bool create_called = false, validity_called = false, info_called = false;
  OSStatus create_status = 0, validity_status = 0, info_status = 0;
  struct signature_sample sample = {0};
  /* Keep observation reads on their original API. Requesting errors for pinned
   * admission additionally enables internal full-report work. */
  bool signature_ok = url &&
       (create_called = true, create_status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code), create_status == errSecSuccess) &&
       (validity_called = true, validity_status = detailed ?
         (signature_begin(&sample), validity_status = SecStaticCodeCheckValidityWithErrors(code, kSecCSStrictValidate, NULL, &error), signature_end(&sample), validity_status) :
         SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL), validity_status == errSecSuccess) &&
       (info_called = true, info_status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info), info_status == errSecSuccess);
  int signature_errno = errno;
  if (!signature_ok) {
    size_t emitted = path_length < PATH_MAX ? path_length : PATH_MAX - 1;
    char path_hex[2*PATH_MAX] = {0};
    hex((const unsigned char *)name, emitted, path_hex);
    fprintf(stderr, "native-darwin-signature: path-length=%zu path-emitted=%zu path-truncated=%d path-hex=%s url=%d\n",
      path_length, emitted, emitted != path_length, path_hex, url != NULL);
    if (create_called) fprintf(stderr, "native-darwin-signature-create: status=%jd\n", (intmax_t)create_status);
    else fprintf(stderr, "native-darwin-signature-create: uncalled\n");
    if (validity_called) fprintf(stderr, "native-darwin-signature-validity: status=%jd\n", (intmax_t)validity_status);
    else fprintf(stderr, "native-darwin-signature-validity: uncalled\n");
    if (info_called) fprintf(stderr, "native-darwin-signature-info: status=%jd\n", (intmax_t)info_status);
    else fprintf(stderr, "native-darwin-signature-info: uncalled\n");
    if (detailed && validity_called && validity_status != errSecSuccess) {
      signature_error_details(error); signature_sample_report(&sample, validity_status);
    }
    fflush(stderr);
  }
  if (error) CFRelease(error);
  errno = signature_errno;
  need(signature_ok);
  CFRelease(code); CFRelease(url); errno = signature_errno;
  return info;
}
static void signature_rule(const char *name, const char *predicate, bool ok) {
  if (!ok) { input_refusal(name, predicate, NULL); need(false); }
}
static void signature_hash(const char *name, CFDictionaryRef info, char actual[41]) {
  CFDataRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
  signature_rule(name, "signature-cdhash-data", hash && CFGetTypeID(hash) == CFDataGetTypeID());
  signature_rule(name, "signature-cdhash-size", CFDataGetLength(hash) == 20);
  hex(CFDataGetBytePtr(hash), 20, actual);
}
static void signature_entitlements(const char *name, CFDictionaryRef entitlements) {
  /* An allowed JIT entitlement is not permission to obtain foreign task/persona rights. */
  if (entitlements) {
    signature_rule(name, "helper-entitlements-dictionary", CFGetTypeID(entitlements) == CFDictionaryGetTypeID());
    const void *keys[2], *values[2]; CFIndex n = CFDictionaryGetCount(entitlements);
    signature_rule(name, "helper-entitlements-count", n >= 0 && n <= 2);
    CFDictionaryGetKeysAndValues(entitlements, keys, values);
    for (CFIndex i = 0; i < n; i++) {
      signature_rule(name, "helper-entitlement-value", values[i] == kCFBooleanTrue);
      signature_rule(name, "helper-entitlement-key", CFEqual(keys[i], CFSTR("com.apple.security.cs.allow-jit")) ||
        CFEqual(keys[i], CFSTR("com.apple.security.cs.allow-unsigned-executable-memory")));
    }
  }
}
static void signature(const char *name, const char *pin) {
  CFDictionaryRef info = signature_information(name, true);
  char actual[41]; signature_hash(name, info, actual);
  signature_rule(name, "signature-cdhash-match", !strcmp(actual, pin));
  /* Only ordinary installed originals use hosted toolchain trust. Private
   * copies, generated helpers and every reviewed caller retain the allowlist. */
  if (!experiment_installed_path(name))
    signature_entitlements(name, CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict));
  CFRelease(info);
}
#ifdef NATIVE_CI_EXPERIMENT
/* Derive one documented installation, never search for another toolchain.
 * Resolve the installation's named clang separately from the stock shim. */
static inline void developer_paths(const char *sdk, char developer[PATH_MAX], char compiler[PATH_MAX]) {
  const char *clt = "/Library/Developer/CommandLineTools", *sdk_prefix = "/Library/Developer/CommandLineTools/SDKs/", *leaf;
  char named[PATH_MAX], canonical[PATH_MAX];
  if (!strncmp(sdk, sdk_prefix, strlen(sdk_prefix))) {
    strcpy(developer, clt); leaf = sdk + strlen(sdk_prefix);
    need(snprintf(named, sizeof(named), "%s/usr/bin/clang", developer) < sizeof(named));
  } else {
    const char *layout = ".app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/";
    const char *marker = strstr(sdk, layout);
    need(!strncmp(sdk, "/Applications/", 14) && marker && marker > sdk + 14 &&
      (size_t)(marker - sdk) < PATH_MAX && !memchr(sdk + 14, '/', (size_t)(marker - sdk - 14)));
    size_t size = (size_t)(marker - sdk) + strlen(".app/Contents/Developer");
    need(size < PATH_MAX); memcpy(developer, sdk, size); developer[size] = 0;
    leaf = marker + strlen(layout);
    need(snprintf(named, sizeof(named), "%s/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang", developer) < sizeof(named));
  }
  need(*leaf && !strchr(leaf, '/') && strcmp(leaf, ".") && strcmp(leaf, "..") &&
    realpath(developer, canonical) && !strcmp(developer, canonical) && realpath(named, compiler));
  char *slash = strrchr(named, '/'); need(slash); slash[1] = 0;
  need(!strncmp(compiler, named, strlen(named)) && compiler[strlen(named)] && !strchr(compiler + strlen(named), '/'));
}
#endif
static struct identity inspect(pid_t pid) {
  struct identity value = {0}; struct proc_bsdinfo after; audit_token_t again;
  mach_port_t task = MACH_PORT_NULL; mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  need(IMAGE_CALL("inspect/bsd-before", proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value.bsd, sizeof(value.bsd))) == (int)sizeof(value.bsd) &&
       IMAGE_CALL("inspect/task-name", task_name_for_pid(mach_task_self(), pid, &task)) == KERN_SUCCESS && task != MACH_PORT_NULL &&
       IMAGE_CALL("inspect/token-before", task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&value.token, &count)) == KERN_SUCCESS &&
       count == TASK_AUDIT_TOKEN_COUNT);
  count = TASK_AUDIT_TOKEN_COUNT;
  need(IMAGE_CALL("inspect/bsd-after", proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after))) == (int)sizeof(after) &&
       IMAGE_CALL("inspect/token-after", task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&again, &count)) == KERN_SUCCESS &&
       count == TASK_AUDIT_TOKEN_COUNT && !memcmp(&again, &value.token, sizeof(again)) &&
       after.pbi_start_tvsec == value.bsd.pbi_start_tvsec && after.pbi_start_tvusec == value.bsd.pbi_start_tvusec &&
       after.pbi_svuid == value.bsd.pbi_svuid && after.pbi_svgid == value.bsd.pbi_svgid &&
       value.token.val[5] == (unsigned)pid &&
       value.token.val[1] == after.pbi_uid && value.token.val[2] == after.pbi_gid &&
       value.token.val[3] == after.pbi_ruid && value.token.val[4] == after.pbi_rgid &&
       IMAGE_CALL("inspect/name-release", mach_port_deallocate(mach_task_self(), task)) == KERN_SUCCESS);
  int inspected_errno = errno;
  if (pid == getpid()) signature_caller = value;
  errno = inspected_errno;
  return value;
}
static void emit(struct identity value) {
  unsigned *t = value.token.val; struct proc_bsdinfo *b = &value.bsd;
  printf("{\"pid\":%u,\"pidVersion\":%u,\"asid\":%u,\"auid\":%u,\"uid\":%u,\"gid\":%u,"
    "\"ruid\":%u,\"rgid\":%u,\"svuid\":%u,\"svgid\":%u,\"startSeconds\":%llu,\"startMicroseconds\":%llu}",
    t[5], t[7], t[6], t[0], t[1], t[2], t[3], t[4], b->pbi_svuid, b->pbi_svgid,
    (unsigned long long)b->pbi_start_tvsec, (unsigned long long)b->pbi_start_tvusec);
}
#endif
/* Only fixed native domain owners opt into these shared native operations.
 * The existing exact custody.h source/dependency inventory binds their bytes. */
#ifdef NATIVE_AUDIT_DOMAIN
#ifndef AUDIT_DOMAIN_INSPECT
#define AUDIT_DOMAIN_INSPECT(pid) inspect(pid)
#endif
#ifndef AUDIT_DOMAIN_DIAG
#define AUDIT_DOMAIN_DIAG(ok, operation, kind, value) do { (void)(operation); (void)(kind); (void)(value); need(ok); } while (0)
#endif
static bool audit_identity_same(struct identity a, struct identity b) {
  return !memcmp(&a.token, &b.token, sizeof(a.token)) &&
    a.bsd.pbi_start_tvsec == b.bsd.pbi_start_tvsec && a.bsd.pbi_start_tvusec == b.bsd.pbi_start_tvusec &&
    a.bsd.pbi_svuid == b.bsd.pbi_svuid && a.bsd.pbi_svgid == b.bsd.pbi_svgid;
}
static au_asid_t audit_fresh(uid_t uid) {
  auditinfo_addr_t audit = {0}; audit.ai_auid = uid; audit.ai_asid = AU_ASSIGN_ASID; audit.ai_termid.at_type = AU_IPv4;
  int result = setaudit_addr(&audit, sizeof(audit)), error = errno;
  AUDIT_DOMAIN_DIAG(!result, "audit-session-create", "errno", error);
  result = getaudit_addr(&audit, sizeof(audit)); error = errno;
  AUDIT_DOMAIN_DIAG(!result, "audit-session-read", "errno", error);
  AUDIT_DOMAIN_DIAG(audit.ai_auid == uid && audit.ai_asid > 0 && audit.ai_asid != AU_ASSIGN_ASID, "audit-session-binding", "invariant", 0);
  return audit.ai_asid;
}
static mach_port_t audit_hold(au_asid_t asid) {
  mach_port_t port = MACH_PORT_NULL;
  AUDIT_DOMAIN_DIAG(asid > 0 && asid != AU_ASSIGN_ASID, "audit-session-binding", "invariant", 0);
  int result = audit_session_port(asid, &port), error = errno;
  AUDIT_DOMAIN_DIAG(!result, "audit-session-hold", "errno", error);
  AUDIT_DOMAIN_DIAG(port != MACH_PORT_NULL, "audit-session-port", "invariant", 0); return port;
}
struct audit_domain_view { struct identity live[32]; struct proc_bsdinfo dead[32]; unsigned nl, nd; };
static struct audit_domain_view audit_census(uid_t uid, au_asid_t asid) {
  /* A listed process can vanish before either BSD/audit sample. Only that
   * exact absence restarts the complete view, immediately and at most twice. */
  for (unsigned attempt = 1; ; attempt++) {
    struct audit_domain_view view = {0}; pid_t pids[4096] = {0}; errno = 0;
    bool vanished = false;
    int size = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    int error = errno;
    AUDIT_DOMAIN_DIAG(!error && size > 0, "audit-census-list", error ? "errno" : "status", error ? error : size);
    AUDIT_DOMAIN_DIAG(size < sizeof(pids) && size % sizeof(pid_t) == 0, "audit-census-capacity", "status", size);
    for (unsigned i = 0; i < (unsigned)size / sizeof(pid_t); i++) {
      if (!pids[i]) continue;
      AUDIT_DOMAIN_DIAG(pids[i] > 0, "audit-census-pid", "status", pids[i]);
      for (unsigned j = 0; j < i; j++) AUDIT_DOMAIN_DIAG(pids[i] != pids[j], "audit-census-duplicate", "status", pids[i]);
      struct proc_bsdinfo before, after; auditpinfo_addr_t audit = {.ap_pid = pids[i]}, again = {.ap_pid = pids[i]};
      errno = 0; int result = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &before, sizeof(before)); error = errno;
      if (!result && error == ESRCH && attempt < 3) { vanished = true; break; }
      AUDIT_DOMAIN_DIAG(result == sizeof(before), "audit-census-bsd", !result && error ? "errno" : "status", !result && error ? error : result);
      errno = 0; result = auditon(A_GETPINFO_ADDR, &audit, sizeof(audit)); error = errno;
      if (result == -1 && error == ESRCH && attempt < 3) { vanished = true; break; }
      AUDIT_DOMAIN_DIAG(!result, "audit-census-audit", "errno", error);
      errno = 0; result = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &after, sizeof(after)); error = errno;
      if (!result && error == ESRCH && attempt < 3) { vanished = true; break; }
      AUDIT_DOMAIN_DIAG(result == sizeof(after), "audit-census-bsd-again", !result && error ? "errno" : "status", !result && error ? error : result);
      errno = 0; result = auditon(A_GETPINFO_ADDR, &again, sizeof(again)); error = errno;
      if (result == -1 && error == ESRCH && attempt < 3) { vanished = true; break; }
      AUDIT_DOMAIN_DIAG(!result, "audit-census-audit-again", "errno", error);
      AUDIT_DOMAIN_DIAG(before.pbi_pid == after.pbi_pid && (before.pbi_status == SZOMB) == (after.pbi_status == SZOMB) &&
        before.pbi_start_tvsec == after.pbi_start_tvsec && before.pbi_start_tvusec == after.pbi_start_tvusec &&
        before.pbi_uid == after.pbi_uid && before.pbi_gid == after.pbi_gid &&
        before.pbi_ruid == after.pbi_ruid && before.pbi_rgid == after.pbi_rgid &&
        before.pbi_svuid == after.pbi_svuid && before.pbi_svgid == after.pbi_svgid &&
        audit.ap_asid == again.ap_asid && audit.ap_auid == again.ap_auid, "audit-census-binding", "invariant", 0);
      if ((!asid || audit.ap_asid != asid) && before.pbi_uid != uid) continue;
      /* A reserved UID outside its admitted session is an escape, never absence.
       * Members inside it remain visible even if their credentials have changed. */
      AUDIT_DOMAIN_DIAG(!asid || audit.ap_asid == asid, "audit-census-session", "invariant", 0);
      AUDIT_DOMAIN_DIAG(view.nl + view.nd < 32, "audit-census-capacity", "invariant", 0);
      if (before.pbi_status == SZOMB) view.dead[view.nd++] = after;
      else {
        struct identity value = AUDIT_DOMAIN_INSPECT(pids[i]); AUDIT_DOMAIN_DIAG(value.token.val[6] == (unsigned)audit.ap_asid &&
          value.token.val[0] == (unsigned)audit.ap_auid && value.bsd.pbi_start_tvsec == before.pbi_start_tvsec &&
          value.bsd.pbi_start_tvusec == before.pbi_start_tvusec, "audit-census-binding", "invariant", 0); view.live[view.nl++] = value;
      }
    }
    if (!vanished) return view;
  }
}
static void audit_emit_view(struct audit_domain_view view, uid_t uid, au_asid_t asid) {
  printf("{\"uid\":%u,\"asid\":%u,\"scope\":\"%s\",\"complete\":true,\"capacity\":33,\"live\":[", uid, asid, asid ? "audit-session" : "reserved-uid");
  for (unsigned i = 0; i < view.nl; i++) { if (i) putchar(','); emit(view.live[i]); }
  fputs("],\"zombies\":[", stdout);
  for (unsigned i = 0; i < view.nd; i++) { struct proc_bsdinfo *b = &view.dead[i];
    printf("%s{\"pid\":%u,\"uid\":%u,\"gid\":%u,\"ruid\":%u,\"rgid\":%u,\"svuid\":%u,\"svgid\":%u,\"startSeconds\":%llu,\"startMicroseconds\":%llu}",
      i ? "," : "", b->pbi_pid, b->pbi_uid, b->pbi_gid, b->pbi_ruid, b->pbi_rgid, b->pbi_svuid, b->pbi_svgid,
      (unsigned long long)b->pbi_start_tvsec, (unsigned long long)b->pbi_start_tvusec);
  }
  fputs("]}", stdout);
}
/* Fixed ordinary observer images only. Held bytes and metadata are sampled
 * independently of the traced process; no arbitrary path enters this reader. */
static bool audit_observer_digest(const char *name, char hash[65]) {
  if (strcmp(name, "/usr/bin/sudo") && strcmp(name, "/usr/sbin/dtrace")) return false;
  int fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); if (fd < 0) return false;
  struct stat before, after, named; unsigned char bytes[8192], sum[32]; CC_SHA256_CTX context;
  bool ok = !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_uid == 0 &&
    !(before.st_mode & 022) && before.st_size > 0 && before.st_size <= 134217728 && CC_SHA256_Init(&context);
  ssize_t used = 0; uint64_t total = 0;
  while (ok && (used = read(fd, bytes, sizeof(bytes))) > 0) {
    total += (uint64_t)used; ok = total <= (uint64_t)before.st_size && CC_SHA256_Update(&context, bytes, (CC_LONG)used);
  }
  ok = ok && used == 0 && total == (uint64_t)before.st_size && CC_SHA256_Final(sum, &context) &&
    !fstat(fd, &after) && !lstat(name, &named);
  const struct stat *checks[] = {&after, &named};
  for (unsigned i = 0; ok && i < 2; i++) {
    const struct stat *value = checks[i];
    ok = before.st_dev == value->st_dev && before.st_ino == value->st_ino && before.st_mode == value->st_mode &&
      before.st_uid == value->st_uid && before.st_gid == value->st_gid && before.st_size == value->st_size && before.st_nlink == value->st_nlink &&
      before.st_mtimespec.tv_sec == value->st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == value->st_mtimespec.tv_nsec &&
      before.st_ctimespec.tv_sec == value->st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec == value->st_ctimespec.tv_nsec;
  }
  int closed = close(fd); if (!ok || closed) return false;
  for (unsigned i = 0; i < 32; i++) snprintf(hash + 2*i, 3, "%02x", sum[i]); return true;
}
#endif
#endif
