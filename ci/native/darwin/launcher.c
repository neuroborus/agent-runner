/* CI-only, compiled with independently reviewed macOS SDK/framework inputs.
 * Private/deprecated interfaces are prerequisites, never portable fallbacks. */
#define __APPLE_API_PRIVATE 1
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <bsm/audit.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <mach/mach_vm.h>
#include <poll.h>
#include <pwd.h>
#include <sandbox.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern mach_port_t bootstrap_port;
#define NATIVE_AUDIT_DOMAIN 1
#ifdef NATIVE_CI_EXPERIMENT
#define NATIVE_RUNTIME_REPLIES 1
#endif
#include "custody.h"
#undef NATIVE_RUNTIME_REPLIES
#ifdef NATIVE_CI_EXPERIMENT
static void launch_need_at(bool ok, const char *file, unsigned line);
#undef need
#define need(ok) launch_need_at(!!(ok), __FILE__, __LINE__)
#endif
static int launch_diagnostic = -1;
static void descriptors(void) {
  struct proc_fdinfo fds[4096];
  int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  need(size > 0 && size < (int)sizeof(fds) && size % sizeof(fds[0]) == 0);
  for (size_t i = 0; i < (size_t)size / sizeof(fds[0]); i++)
    if (fds[i].proc_fd >= 5 && fds[i].proc_fd != launch_diagnostic) need(!close(fds[i].proc_fd));
  size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  unsigned expected = launch_diagnostic == 5 ? 6 : 5;
  need(size == expected * (int)sizeof(fds[0]));
  unsigned mask = 0;
  for (size_t i = 0; i < (size_t)size / sizeof(fds[0]); i++) {
    need(fds[i].proc_fd >= 0 && fds[i].proc_fd < expected); mask |= 1U << fds[i].proc_fd;
  }
  need(mask == (1U << expected) - 1);
  need(!fcntl(3, F_SETFD, FD_CLOEXEC) && !fcntl(4, F_SETFD, FD_CLOEXEC));
}
static pid_t launcher_pid, launch_child;
static struct identity launcher_identity;
#ifdef NATIVE_CI_EXPERIMENT
/* Fixed child-only call sites, never one record per censused Mach right. */
static void launch_stage(const char *stage, const char *operation, long result, int error) {
  int saved = errno;
  char bytes[512];
  int size = snprintf(bytes, sizeof(bytes), "native-darwin-launch-stage: entered=1 stage=%.48s launcher=%d reporter=%d start-seconds=%llu start-micros=%llu prior-operation=%s prior-result=%ld prior-errno=%d\n",
    stage, launcher_pid, getpid(), (unsigned long long)launcher_identity.bsd.pbi_start_tvsec,
    (unsigned long long)launcher_identity.bsd.pbi_start_tvusec, operation ? operation : "none", operation ? result : 0, operation ? error : 0);
  if (size > 0 && size < (int)sizeof(bytes)) {
    struct sigaction ignored = {0}, previous; ignored.sa_handler = SIG_IGN;
    if (!sigemptyset(&ignored.sa_mask) && !sigaction(SIGPIPE, &ignored, &previous)) {
      (void)write(2, bytes, (size_t)size); (void)sigaction(SIGPIPE, &previous, NULL);
    }
  }
  errno = saved;
}
#else
#define launch_stage(stage, operation, result, error) ((void)0)
#endif
static void launch_failure(const char *operation, long result, int error, int revents, long used, pid_t child);
#ifdef NATIVE_CI_EXPERIMENT
static pid_t launch_reply_owner;
static mach_port_t launch_bootstrap_local, launch_reply_borrowed, launch_special_borrowed;
static domain_special_reply_fn launch_special_reply;
static char launch_exec_suffix[256];
static void launch_replies_begin(void);
static pid_t launch_bootstrap_fork(void) {
  struct domain_bootstrap_fork outcome; domain_bootstrap_fork(&outcome, &launch_child, launch_replies_begin);
  if (outcome.count) {
    (void)signal(SIGPIPE, SIG_IGN);
    for (unsigned i = 0; i < outcome.count; i++) if (outcome.issues[i].cleanup) {
      struct domain_bootstrap_issue issue = outcome.issues[i];
      fprintf(stderr, "native-darwin-launch-cleanup: owner=launcher operation=%s domain=%s result=%d\n", issue.operation, issue.kind, issue.value);
    }
    struct domain_bootstrap_issue issue = outcome.issues[0];
    launch_failure(issue.operation, !strcmp(issue.kind, "errno") ? -1 : issue.value,
      !strcmp(issue.kind, "errno") ? issue.value : 0, 0, -1, launch_child);
  }
  return outcome.child;
}
/* Early setup guards precede mach_rights. Only this child's captured local
 * reference belongs to them; copied parent state supplies no cleanup authority. */
static void launch_need_at(bool ok, const char *file, unsigned line) {
  if (!ok) {
    int error = errno;
    if (launch_reply_owner == getpid()) {
      mach_port_t local = launch_bootstrap_local; launch_bootstrap_local = MACH_PORT_NULL;
      if (MACH_PORT_VALID(local)) {
        kern_return_t released = mach_port_deallocate(mach_task_self(), local); int cleanup_error = errno;
        if (released != KERN_SUCCESS) {
          (void)signal(SIGPIPE, SIG_IGN);
          fprintf(stderr, "native-darwin-launch-cleanup: owner=launcher operation=%s result=%d errno=%d\n", "mach_port_deallocate/bootstrap", released, cleanup_error);
          fflush(stderr);
        }
      }
    }
    errno = error;
  }
  need_at(ok, file, line);
}
/* Bind before the child's first observation. Borrowing a cache never creates
 * an owned reference; the inherited bootstrap local is a separate acquisition. */
static void launch_replies_begin(void) {
  const char *operation = "mig_get_special_reply_port/binding"; long result = 0; int error = 0;
  launch_reply_owner = getpid(); domain_runtime_replies_begin(launch_reply_owner);
  launch_bootstrap_local = bootstrap_port; bootstrap_port = MACH_PORT_NULL;
  launch_reply_borrowed = launch_special_borrowed = MACH_PORT_NULL;
  launch_special_reply = domain_special_reply_lookup();
  if (!launch_special_reply) goto reply_failure;
  launch_stage("mach-reply-bind", NULL, 0, 0);
  operation = "mig_get_reply_port/identity"; launch_reply_borrowed = mig_get_reply_port();
  result = launch_reply_borrowed; error = errno;
  if (!MACH_PORT_VALID(launch_reply_borrowed)) goto reply_failure;
  operation = "mig_get_special_reply_port/identity"; launch_special_borrowed = launch_special_reply();
  result = launch_special_borrowed; error = errno;
  if (MACH_PORT_VALID(launch_special_borrowed) && launch_special_borrowed != launch_reply_borrowed) return;
reply_failure:
  launch_failure(operation, result, error, 0, -1, 0);
}
/* Cache/PID/producer stability is a launcher policy, not a type exemption. */
static const char *launch_replies_changed(unsigned count, const mach_port_t *runtime) {
  if (launch_reply_owner != getpid()) return "runtime-reply-owner";
  if (mig_get_reply_port() != launch_reply_borrowed) return "mig_get_reply_port/identity";
  if (!launch_special_reply || launch_special_reply() != launch_special_borrowed) return "mig_get_special_reply_port/identity";
  if (domain_runtime_reply_owner != getpid() || !domain_runtime_reply_imported || domain_runtime_reply_overflow || domain_runtime_reply_count != count)
    return "runtime-reply-producer";
  for (unsigned i = 0; i < count; i++)
    if (runtime[i] != domain_runtime_replies[i]) return "runtime-reply-producer";
  return NULL;
}
#endif
static void mach_rights(void) {
#ifdef NATIVE_CI_EXPERIMENT
  launch_stage("mach-acquire", NULL, 0, 0);
  task_t self = mach_task_self(); thread_t thread = MACH_PORT_NULL;
  mach_port_t host = MACH_PORT_NULL, access = MACH_PORT_NULL, reply = launch_reply_borrowed, special = launch_special_borrowed;
  mach_port_t held_host = MACH_PORT_NULL, held_access = MACH_PORT_NULL, held_bootstrap = MACH_PORT_NULL;
  mach_port_t held_thread = MACH_PORT_NULL, runtime[8] = {0}, refused_name = MACH_PORT_NULL;
  mach_port_t bootstrap = MACH_PORT_NULL; int bootstrap_query = -1, bootstrap_release = -1;
  long long bootstrap_refs = -1;
  mach_port_type_t refused_type = MACH_PORT_TYPE_NONE; const char *binding = "unproved";
  unsigned runtime_count = 0, runtime_seen = 0; bool replies_bound = false;
  mach_port_type_t access_type = MACH_PORT_TYPE_NONE, reply_type = MACH_PORT_TYPE_NONE;
  natural_t type = 0; mach_vm_address_t address = 0;
  mach_port_name_array_t names = NULL; mach_port_type_array_t types = NULL;
  mach_msg_type_number_t n = 0, nt = 0; bool service = false, seen = false;
  kern_return_t notify_release = KERN_SUCCESS, readback_release = KERN_SUCCESS;
  int notify_error = 0, readback_error = 0;
  const char *operation; long result = 0; int error = 0;
  operation = "runtime-reply-owner"; result = launch_reply_owner; error = errno;
  if (launch_reply_owner != getpid()) goto mach_cleanup;
  held_bootstrap = launch_bootstrap_local; launch_bootstrap_local = MACH_PORT_NULL;
  bootstrap = held_bootstrap;
  thread = mach_thread_self(); held_thread = MACH_PORT_VALID(thread) ? thread : MACH_PORT_NULL;
  operation = "mach_thread_self"; result = thread; error = errno;
  if (!MACH_PORT_VALID(thread) || thread == self) goto mach_cleanup;
  launch_stage("mach-host", NULL, 0, 0);
  operation = "task_get_special_port/TASK_HOST_PORT";
  result = task_get_special_port(self, TASK_HOST_PORT, &host); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  held_host = MACH_PORT_VALID(host) ? host : MACH_PORT_NULL;
  operation = "mach_port_kobject"; result = mach_port_kobject(self, host, &type, &address); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  operation = "mach_port_kobject/type"; result = type;
  if (type != 3) goto mach_cleanup;
  launch_stage("mach-access", NULL, 0, 0);
  operation = "task_get_special_port/TASK_ACCESS_PORT";
  result = task_get_special_port(self, TASK_ACCESS_PORT, &access); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  if (MACH_PORT_VALID(access)) {
    /* The getter owns a copy before the fallible query. Unsupported types with
     * no deallocatable reference grant no authority over an unowned receive. */
    held_access = access;
    operation = "mach_port_type/access"; result = mach_port_type(self, access, &access_type); error = errno;
    if (result == KERN_SUCCESS && !(access_type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE | MACH_PORT_TYPE_DEAD_NAME)))
      held_access = MACH_PORT_NULL;
    if (result != KERN_SUCCESS) goto mach_cleanup;
    if (access_type == MACH_PORT_TYPE_SEND) {
      type = ~0U;
      operation = "mach_port_kobject/access"; result = mach_port_kobject(self, access, &type, &address); error = errno;
      if (result != KERN_SUCCESS) goto mach_cleanup;
      operation = "mach_port_kobject/access/type"; result = type;
      if (type != 0) goto mach_cleanup; /* IKOT_NONE, never task/thread authority. */
      operation = "TASK_ACCESS_PORT/identity"; result = access;
      if (access == self || access == thread || access == host) goto mach_cleanup;
      service = true;
    } else {
      operation = "TASK_ACCESS_PORT/authority"; result = access_type;
      if (access_type != MACH_PORT_TYPE_DEAD_NAME) goto mach_cleanup;
      held_access = MACH_PORT_NULL;
      operation = "mach_port_deallocate/access"; result = mach_port_deallocate(self, access); error = errno;
      if (result != KERN_SUCCESS) goto mach_cleanup;
    }
  }
  launch_stage("mach-special-ports", NULL, 0, 0);
  operation = "task_set_special_port/TASK_BOOTSTRAP_PORT"; result = task_set_special_port(self, TASK_BOOTSTRAP_PORT, MACH_PORT_NULL); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  if (MACH_PORT_VALID(held_bootstrap)) {
    mach_port_t local = held_bootstrap; held_bootstrap = MACH_PORT_NULL;
    bootstrap_refs = domain_send_refs(local, &bootstrap_query);
    operation = "mach_port_deallocate/bootstrap"; result = mach_port_deallocate(self, local); error = errno;
    bootstrap_release = (int)result;
    if (result != KERN_SUCCESS) goto mach_cleanup;
  }
  operation = "task_set_special_port/TASK_DEBUG_CONTROL_PORT"; result = task_set_special_port(self, TASK_DEBUG_CONTROL_PORT, MACH_PORT_NULL); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  {
    /* XNU may omit both resource-notify selectors. Failed getter output owns
     * nothing; successful getter copies must settle before later sanitation. */
    mach_port_t notify = MACH_PORT_NULL, readback = MACH_PORT_NULL;
    kern_return_t notify_get = task_get_special_port(self, TASK_RESOURCE_NOTIFY_PORT, &notify); int get_error = errno;
    kern_return_t notify_set = task_set_special_port(self, TASK_RESOURCE_NOTIFY_PORT, MACH_PORT_NULL); int set_error = errno;
    kern_return_t notify_read = KERN_FAILURE;
    operation = NULL;
    if (!(notify_get == KERN_INVALID_ARGUMENT && notify_set == KERN_INVALID_ARGUMENT)) {
      if (notify_get != KERN_SUCCESS) {
        operation = "task_get_special_port/TASK_RESOURCE_NOTIFY_PORT"; result = notify_get; error = get_error;
      } else if (notify_set != KERN_SUCCESS) {
        operation = "task_set_special_port/TASK_RESOURCE_NOTIFY_PORT"; result = notify_set; error = set_error;
      } else {
        notify_read = task_get_special_port(self, TASK_RESOURCE_NOTIFY_PORT, &readback); error = errno;
        if (notify_read != KERN_SUCCESS) {
          operation = "task_get_special_port/TASK_RESOURCE_NOTIFY_PORT/readback"; result = notify_read;
        } else if (readback != MACH_PORT_NULL) {
          operation = "TASK_RESOURCE_NOTIFY_PORT/null"; result = readback;
        }
      }
    }
    launch_stage("resource-notify-cleanup", operation, result, error);
    if (notify_get == KERN_SUCCESS && MACH_PORT_VALID(notify)) {
      notify_release = mach_port_deallocate(self, notify); notify_error = errno;
    }
    if (notify_read == KERN_SUCCESS && MACH_PORT_VALID(readback)) {
      readback_release = mach_port_deallocate(self, readback); readback_error = errno;
    }
    if (operation || notify_release != KERN_SUCCESS || readback_release != KERN_SUCCESS) goto mach_cleanup;
  }
  launch_stage("mach-exceptions", NULL, 0, 0);
  operation = "mach_ports_register"; result = mach_ports_register(self, NULL, 0); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  operation = "task_set_exception_ports"; result = task_set_exception_ports(self, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  operation = "thread_set_exception_ports"; result = thread_set_exception_ports(thread, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  operation = "mig_get_reply_port/identity"; result = reply; error = errno;
  if (!MACH_PORT_VALID(reply) || reply == self || reply == thread || reply == host || (service && reply == access)) goto mach_cleanup;
  operation = "mig_get_special_reply_port/identity"; result = special;
  if (!MACH_PORT_VALID(special) || special == self || special == thread || special == host || special == reply || (service && special == access)) goto mach_cleanup;
  runtime_count = domain_runtime_reply_count;
  operation = "runtime-reply-producer"; result = runtime_count;
  if (domain_runtime_reply_owner != getpid() || !domain_runtime_reply_imported || domain_runtime_reply_overflow || runtime_count > 8) goto mach_cleanup;
  for (unsigned i = 0; i < runtime_count; i++) {
    runtime[i] = domain_runtime_replies[i]; result = runtime[i];
    if (!MACH_PORT_VALID(runtime[i]) || runtime[i] == self || runtime[i] == thread || runtime[i] == host || (service && runtime[i] == access)) goto mach_cleanup;
    for (unsigned j = 0; j < i; j++) if (runtime[j] == runtime[i]) goto mach_cleanup;
  }
  replies_bound = true;
  operation = launch_replies_changed(runtime_count, runtime); result = 0;
  if (operation) goto mach_cleanup;
  operation = "mach_port_type/reply"; result = mach_port_type(self, reply, &reply_type); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  operation = "mach_port_type/reply/type"; result = reply_type;
  if (reply_type != MACH_PORT_TYPE_RECEIVE) {
    refused_name = reply; refused_type = reply_type; binding = "ordinary-cache"; goto mach_cleanup;
  }
  launch_stage("mach-census", NULL, 0, 0);
  operation = "mach_port_names"; result = mach_port_names(self, &names, &n, &types, &nt); error = errno;
  if (result != KERN_SUCCESS) goto mach_cleanup;
  operation = "mach_port_names/count"; result = n;
  if (n != nt || n > 4096 || !names || !types) goto mach_cleanup;
  operation = launch_replies_changed(runtime_count, runtime); result = 0;
  if (operation) goto mach_cleanup;
  launch_stage("mach-census-check", NULL, 0, 0);
  bool self_seen = false, thread_seen = false, host_seen = false, reply_seen = false, special_seen = false;
  for (mach_msg_type_number_t i = 0; i < n; i++) {
    bool allowed, produced = false;
    for (unsigned j = 0; j < runtime_count; j++) if (names[i] == runtime[j]) { produced = true; runtime_seen |= 1u << j; }
    if (names[i] == self) { allowed = types[i] == MACH_PORT_TYPE_SEND; self_seen = true; }
    else if (names[i] == thread) { allowed = types[i] == MACH_PORT_TYPE_SEND; thread_seen = true; }
    else if (names[i] == host) { allowed = types[i] == MACH_PORT_TYPE_SEND; host_seen = true; }
    else if (names[i] == reply) { allowed = types[i] == MACH_PORT_TYPE_RECEIVE; reply_seen = true; }
    else if (names[i] == special) { allowed = types[i] == (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE); special_seen = true; }
    else if (service && names[i] == access) { allowed = types[i] == MACH_PORT_TYPE_SEND; seen = true; }
    else if (produced) allowed = types[i] == MACH_PORT_TYPE_RECEIVE;
    else allowed = types[i] == MACH_PORT_TYPE_DEAD_NAME;
    for (unsigned j = 0; j < i; j++) if (names[j] == names[i]) allowed = false;
    if (!allowed) {
      operation = "mach_port_names/authority"; result = types[i]; refused_name = names[i]; refused_type = types[i];
      binding = names[i] == reply ? "ordinary-cache" : names[i] == special ? "special-cache" : produced ? "producer" :
        names[i] == self ? "task" : names[i] == thread ? "thread" : names[i] == host ? "host" : service && names[i] == access ? "task-access" : "unproved";
      goto mach_cleanup;
    }
  }
  operation = "mach_port_names/authority"; result = MACH_PORT_TYPE_NONE;
  if (!(self_seen && thread_seen && host_seen && reply_seen && special_seen && (!service || seen) && runtime_seen == ((1u << runtime_count) - 1))) {
    refused_name = !self_seen ? self : !thread_seen ? thread : !host_seen ? host : !reply_seen ? reply : !special_seen ? special : service && !seen ? access : MACH_PORT_NULL;
    if (!MACH_PORT_VALID(refused_name)) for (unsigned i = 0; i < runtime_count; i++)
      if (!(runtime_seen & (1u << i))) { refused_name = runtime[i]; break; }
    binding = "missing"; goto mach_cleanup;
  }
  operation = NULL;
mach_cleanup: {
    const char *prior = operation; long prior_result = result; int prior_error = error;
    if (!prior && notify_release != KERN_SUCCESS) { prior = "mach_port_deallocate/notify"; prior_result = notify_release; prior_error = notify_error; }
    if (!prior && readback_release != KERN_SUCCESS) { prior = "mach_port_deallocate/readback"; prior_result = readback_release; prior_error = readback_error; }
    launch_stage("mach-cleanup", prior, prior_result, prior_error);
    /* One refused-name fact or failed bootstrap release, before cleanup RPCs,
     * never a broader inventory or an explanation of an earlier child's right. */
    if (operation && (MACH_PORT_VALID(refused_name) || (bootstrap_release != -1 && bootstrap_release != KERN_SUCCESS))) {
      int saved = errno, send_query = -1;
      long long send_refs = domain_send_refs(refused_name, &send_query);
      (void)signal(SIGPIPE, SIG_IGN);
      fprintf(stderr, "native-darwin-launch-port: pid=%d name=%u type=%#x binding=%s bootstrap=%u bootstrap-query=%d bootstrap-refs=%lld bootstrap-release=%d send-query=%d send-refs=%lld\n",
        getpid(), refused_name, refused_type, binding, bootstrap, bootstrap_query, bootstrap_refs, bootstrap_release, send_query, send_refs);
      fflush(stderr); errno = saved;
    }
    /* One entry per acquisition, even when local names alias. Never retry a
     * failed release or let it replace the original refusal. */
    const char *cleanup_operations[] = {"mach_port_deallocate/notify", "mach_port_deallocate/readback", "mach_vm_deallocate/names", "mach_vm_deallocate/types", "mach_port_deallocate/access", "mach_port_deallocate/host", "mach_port_deallocate/thread", "mach_port_deallocate/bootstrap"};
    kern_return_t releases[8] = {notify_release,readback_release,KERN_SUCCESS,KERN_SUCCESS,KERN_SUCCESS,KERN_SUCCESS,KERN_SUCCESS,KERN_SUCCESS};
    int errors[8] = {notify_error,readback_error,0,0,0,0,0,0};
    if (names) { releases[2] = mach_vm_deallocate(self, (mach_vm_address_t)names, (mach_vm_size_t)n * sizeof(*names)); errors[2] = errno; }
    if (types) { releases[3] = mach_vm_deallocate(self, (mach_vm_address_t)types, (mach_vm_size_t)nt * sizeof(*types)); errors[3] = errno; }
    if (MACH_PORT_VALID(held_access)) { releases[4] = mach_port_deallocate(self, held_access); errors[4] = errno; }
    if (MACH_PORT_VALID(held_host)) { releases[5] = mach_port_deallocate(self, held_host); errors[5] = errno; }
    if (MACH_PORT_VALID(held_thread)) { releases[6] = mach_port_deallocate(self, held_thread); errors[6] = errno; }
    if (MACH_PORT_VALID(held_bootstrap)) { releases[7] = mach_port_deallocate(self, held_bootstrap); errors[7] = errno; }
    for (unsigned i = 0; i < 8; i++) if (releases[i] != KERN_SUCCESS) {
      (void)signal(SIGPIPE, SIG_IGN);
      fprintf(stderr, "native-darwin-launch-cleanup: owner=launcher operation=%s result=%d errno=%d\n", cleanup_operations[i], releases[i], errors[i]);
      fflush(stderr);
      if (!operation) { operation = cleanup_operations[i]; result = releases[i]; error = errors[i]; }
    }
    if (!operation && replies_bound) { operation = launch_replies_changed(runtime_count, runtime); result = 0; error = 0; }
    if (operation) {
      launch_failure(operation, result, error, 0, -1, 0);
    }
  }
#else
  task_t self = mach_task_self(); thread_t thread = mach_thread_self();
  mach_port_t host, access; natural_t type; mach_vm_address_t address;
  /* SIP forbids clearing itk_host. Require the ordinary IKOT_HOST (XNU value 3),
   * never a privileged host port; bind this private type/export to the actual SDK. */
  kern_return_t status = task_get_special_port(self, TASK_HOST_PORT, &host); int error = errno;
  if (status != KERN_SUCCESS) launch_failure("task_get_special_port/TASK_HOST_PORT", status, error, 0, -1, 0);
  status = mach_port_kobject(self, host, &type, &address); error = errno;
  if (status != KERN_SUCCESS) launch_failure("mach_port_kobject", status, error, 0, -1, 0);
  if (type != 3) launch_failure("mach_port_kobject/type", type, error, 0, -1, 0);
  status = mach_port_deallocate(self, host); error = errno;
  if (status != KERN_SUCCESS) launch_failure("mach_port_deallocate/host", status, error, 0, -1, 0);
  status = task_get_special_port(self, TASK_ACCESS_PORT, &access); error = errno;
  if (status != KERN_SUCCESS) launch_failure("task_get_special_port/TASK_ACCESS_PORT", status, error, 0, -1, 0);
  if (access != MACH_PORT_NULL) launch_failure("TASK_ACCESS_PORT/null", access, error, 0, -1, 0);
  need(task_set_special_port(self, TASK_BOOTSTRAP_PORT, MACH_PORT_NULL) == KERN_SUCCESS &&
       task_set_special_port(self, TASK_DEBUG_CONTROL_PORT, MACH_PORT_NULL) == KERN_SUCCESS &&
       task_set_special_port(self, TASK_RESOURCE_NOTIFY_PORT, MACH_PORT_NULL) == KERN_SUCCESS &&
       mach_ports_register(self, NULL, 0) == KERN_SUCCESS &&
       task_set_exception_ports(self, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE) == KERN_SUCCESS &&
       thread_set_exception_ports(thread, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE) == KERN_SUCCESS);
  bootstrap_port = MACH_PORT_NULL;
  /* mach_port_destroy itself uses MIG. Replace its cached receive-only reply
   * port, then retain this new local port so the sanitation RPCs can complete. */
  mig_dealloc_reply_port(mig_get_reply_port());
  mach_port_t reply = mig_get_reply_port(); mach_port_type_t replyType;
  need(reply != MACH_PORT_NULL && reply != self && reply != thread &&
       mach_port_type(self, reply, &replyType) == KERN_SUCCESS && replyType == MACH_PORT_TYPE_RECEIVE);
  mach_port_name_array_t names; mach_port_type_array_t types;
  mach_msg_type_number_t n, nt;
  need(mach_port_names(self, &names, &n, &types, &nt) == KERN_SUCCESS && n == nt && n <= 4096);
  for (mach_msg_type_number_t i = 0; i < n; i++)
    if (names[i] != self && names[i] != thread && names[i] != reply)
      need(mach_port_destroy(self, names[i]) == KERN_SUCCESS);
  need(mach_vm_deallocate(self, (mach_vm_address_t)names, n * sizeof(*names)) == KERN_SUCCESS &&
       mach_vm_deallocate(self, (mach_vm_address_t)types, nt * sizeof(*types)) == KERN_SUCCESS &&
       mach_port_deallocate(self, thread) == KERN_SUCCESS);
#endif
}
/* Status inspection is diagnostic only: never reap or replace the original
 * child, consume a protocol frame, or use it as retirement/admission proof. */
static void launch_failure(const char *operation, long result, int error, int revents, long used, pid_t child) {
  /* Failure-only disposition: no successful payload inherits this change. */
  (void)signal(SIGPIPE, SIG_IGN);
  struct proc_bsdinfo identity = {0}; siginfo_t status = {0};
  int identityResult = -1, identityError = 0;
  if (getpid() == launcher_pid) {
    errno = 0; identityResult = proc_pidinfo(launcher_pid, PROC_PIDTBSDINFO, 1, &identity, sizeof(identity)); identityError = errno;
  } else if (launcher_identity.token.val[5] == (unsigned)launcher_pid) {
    identity = launcher_identity.bsd; identityResult = (int)sizeof(identity);
  }
  bool original = getpid() == launcher_pid && child > 0 && child == launch_child;
  errno = 0;
  int waitResult = original ? waitid(P_PID, (id_t)child, &status, WEXITED | WNOHANG | WNOWAIT) : -1;
  int waitError = errno;
  bool matched = original && !waitResult && status.si_pid == child;
  if (!matched) memset(&status, 0, sizeof(status));
  fprintf(stderr, "native-darwin-launch: owner=launcher operation=%s result=%ld errno=%d revents=%d read=%ld launcher=%d reporter=%d child=%d identity-result=%d identity-errno=%d start-seconds=%llu start-micros=%llu wait-result=%d wait-errno=%d status-pid=%d status-code=%d status=%d\n",
    operation, result, error, revents, used, launcher_pid, getpid(), child, identityResult, identityError,
    identityResult == (int)sizeof(identity) ? (unsigned long long)identity.pbi_start_tvsec : 0,
    identityResult == (int)sizeof(identity) ? (unsigned long long)identity.pbi_start_tvusec : 0,
    waitResult, waitError, status.si_pid, status.si_code, status.si_status);
  /* sys/wait.h already owns this compiled contract. No SDK-verified richer
   * exit-reason interface is established; never guess a proc_pidinfo flavor. */
  if (original) fprintf(stderr, "native-darwin-launch-termination: launcher=%d child=%d wait-result=%d wait-errno=%d available=%d pid=%d code=%d status=%d kernel-reason=unavailable\n",
    launcher_pid, child, waitResult, waitError, (int)matched, status.si_pid, status.si_code, status.si_status);
  fflush(stderr); errno = error; need(false);
}
static char command(int fd, int milliseconds) {
  struct pollfd p = { .fd = fd, .events = POLLIN }; char value;
  int result = poll(&p, 1, milliseconds), error = result < 0 ? errno : 0;
  if (result != 1) launch_failure("command-poll", result, error, p.revents, -1, launch_child);
  if (!(p.revents & POLLIN)) launch_failure("command-poll-events", result, 0, p.revents, -1, launch_child);
  ssize_t used = read(fd, &value, 1); error = used < 0 ? errno : 0;
  if (used != 1) launch_failure("command-read", used, error, p.revents, used, launch_child);
  return value;
}
static void child_stdio(int workspace, bool provider) {
  int result = fchdir(workspace); if (result) launch_failure("fchdir", result, errno, 0, -1, 0);
  result = dup2(3, 1); if (result != 1) launch_failure("dup2-output", result, errno, 0, -1, 0);
  /* Keep ordinary setup errors on the original stderr until the exec handoff.
   * Provider descriptor 5 must still be duplicated before sanitation closes it. */
  if (provider) { result = dup2(5, 2); if (result != 2) launch_failure("dup2-stderr", result, errno, 0, -1, 0); }
  result = dup2(provider ? 4 : 3, 0); if (result != 0) launch_failure("dup2-input", result, errno, 0, -1, 0);
}
static void child_exec(char **argv, char **environment, bool provider) {
  if (provider) { execve(argv[6], &argv[12], environment); _exit(126); }
  /* This copy cannot survive successful exec. Only a failed exec uses it. */
#ifdef NATIVE_CI_EXPERIMENT
  (void)domain_prepared_exec(argv[6], &argv[12], environment); int error = errno;
  domain_exec_failure(launch_diagnostic, "native-darwin-launch: owner=child operation=execve result=-1 errno=", launch_exec_suffix, error);
#else
  int diagnostic = fcntl(2, F_DUPFD_CLOEXEC, 3);
  if (diagnostic < 0) launch_failure("fcntl-stderr", diagnostic, errno, 0, -1, 0);
  int result = dup2(1, 2); if (result != 2) launch_failure("dup2-stderr", result, errno, 0, -1, 0);
  result = execve(argv[6], &argv[12], environment); int error = errno;
  (void)signal(SIGPIPE, SIG_IGN);
  dprintf(diagnostic, "native-darwin-launch: owner=child operation=%s result=%ld errno=%d revents=%d read=%ld launcher=%d reporter=%d start-seconds=%llu start-micros=%llu\n",
    "execve", (long)result, error, 0, (long)-1, launcher_pid, getpid(),
    (unsigned long long)launcher_identity.bsd.pbi_start_tvsec, (unsigned long long)launcher_identity.bsd.pbi_start_tvusec);
  errno = error; _exit(126);
#endif
}
static struct identity parked_identity(int fd, pid_t child) {
  struct pollfd waitReady = { .fd = fd, .events = POLLIN }; struct identity parked;
  int result = poll(&waitReady, 1, 10000), error = result < 0 ? errno : 0;
  if (result != 1) launch_failure("parked-poll", result, error, waitReady.revents, -1, child);
  ssize_t used = read(fd, &parked, sizeof(parked)); error = used < 0 ? errno : 0;
  if (used != sizeof(parked)) launch_failure("parked-read", used, error, waitReady.revents, used, child);
  if (parked.token.val[5] != (unsigned)child) launch_failure("parked-identity", parked.token.val[5], 0, waitReady.revents, used, child);
  result = close(fd); if (result) launch_failure("parked-close", result, errno, waitReady.revents, used, child);
  return parked;
}
static uint64_t bounded_number(const char *s, uint64_t maximum) {
  char *end; errno = 0; unsigned long long n = strtoull(s, &end, 10);
  need(*s && *s != '-' && !errno && !*end && n <= maximum); return n;
}
static void verifier_barrier(void) {
  printf("{\"verifier\":"); emit(inspect(getpid())); puts("}"); fflush(stdout);
  need(command(0, 30000) == 'P');
}
static void members(uid_t uid, au_asid_t asid) {
  audit_emit_view(audit_census(uid, asid), uid, asid); putchar('\n');
}
/* Native negative controls run after sandbox/Mach/descriptor sanitation and
 * before the parked identity can be published. No denied operation is assumed. */
static void domain_controls(au_asid_t parent_asid, pid_t parent) {
  auditinfo_addr_t before, after; need(!getaudit_addr(&before, sizeof(before)));
  errno = 0; need(setuid(0) == -1 && errno == EPERM);
  errno = 0; need(setgid(0) == -1 && errno == EPERM);
  gid_t root = 0; errno = 0; need(setgroups(1, &root) == -1 && errno == EPERM);
  auditinfo_addr_t change = before; change.ai_asid = AU_ASSIGN_ASID;
  errno = 0; need(setaudit_addr(&change, sizeof(change)) == -1 && errno == EPERM);
  mach_port_t foreign = MACH_PORT_NULL; errno = 0;
  need(audit_session_port(parent_asid, &foreign) == -1 && errno == EPERM && foreign == MACH_PORT_NULL);
  task_t task = MACH_PORT_NULL; kern_return_t result = task_for_pid(mach_task_self(), parent, &task);
  need((result == KERN_FAILURE || result == KERN_PROTECTION_FAILURE) && task == MACH_PORT_NULL);
  need(!getaudit_addr(&after, sizeof(after)) && after.ai_asid == before.ai_asid && after.ai_auid == before.ai_auid);
}
static void signal_identity(char **args) {
  audit_token_t token; for (unsigned i = 0; i < 8; i++) token.val[i] = (unsigned)bounded_number(args[i], UINT32_MAX);
  uint64_t seconds = bounded_number(args[8], UINT64_MAX), micros = bounded_number(args[9], 999999);
  uid_t saved_uid = (uid_t)bounded_number(args[10], UINT32_MAX); gid_t saved_gid = (gid_t)bounded_number(args[11], UINT32_MAX);
  need(token.val[5] > 1 && token.val[5] <= INT_MAX && token.val[5] != (unsigned)getpid());
  struct proc_bsdinfo b; errno = 0;
  int size = proc_pidinfo((pid_t)token.val[5], PROC_PIDTBSDINFO, 1, &b, sizeof(b));
  if (!size && errno == ESRCH) { puts("{\"outcome\":\"not-found\"}"); return; }
  need(size == (int)sizeof(b));
  if (b.pbi_start_tvsec != seconds || b.pbi_start_tvusec != micros || b.pbi_svuid != saved_uid || b.pbi_svgid != saved_gid ||
      b.pbi_uid != token.val[1] || b.pbi_gid != token.val[2] || b.pbi_ruid != token.val[3] || b.pbi_rgid != token.val[4]) {
    puts("{\"outcome\":\"stale\"}"); return;
  }
  if (b.pbi_status == SZOMB) { puts("{\"outcome\":\"zombie\"}"); return; }
  struct identity current = inspect((pid_t)token.val[5]);
  if (memcmp(&current.token, &token, sizeof(token)) || current.bsd.pbi_start_tvsec != seconds ||
      current.bsd.pbi_start_tvusec != micros || current.bsd.pbi_svuid != saved_uid || current.bsd.pbi_svgid != saved_gid) {
    puts("{\"outcome\":\"stale\"}"); return;
  }
  /* The API returns errno directly. Kernel pidversion lookup reacquires a
   * proc_ident after MAC checks; numeric PID signalling is never a fallback. */
  int error = proc_signal_with_audittoken(&token, SIGKILL);
  need(!error || error == ESRCH);
  puts(error ? "{\"outcome\":\"not-found\"}" : "{\"outcome\":\"sent\"}");
}
static void claim(int fd, const char *kind, unsigned id, const char *nonce) {
  char name[64]; snprintf(name, sizeof(name), "%s-%u", kind, id);
  int file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
  need(file >= 0 && strlen(nonce) == 32 && write(file, nonce, 32) == 32 && !fsync(file) && !close(file) && !fsync(fd));
}
static void pfctl(char **args) {
  /* The protected reader binds the complete immutable private tool closure. */
  struct stat tool, config;
  free(file(args[0], 0, 0550, 134217728, args[1], &tool));
  free(file(args[3], 0, 0400, 1048576, args[4], &config));
  need(strlen(args[5]) == 43 && !strncmp(args[5], "native-poc/", 11) &&
    strspn(args[5] + 11, "0123456789abcdef") == 32);
  bool validate = !strcmp(args[6], "validate") || !strcmp(args[6], "validate-restore");
  need(validate || !strcmp(args[6], "install") || !strcmp(args[6], "restore"));
  int ready[2], release[2]; need(!pipe(ready) && !pipe(release));
  pid_t worker = fork(); need(worker >= 0);
  if (!worker) {
    close(ready[0]); close(release[1]); struct identity identity = inspect(getpid());
    need(write(ready[1], &identity, sizeof(identity)) == (ssize_t)sizeof(identity));
    need(command(release[0], 30000) == 'R');
    /* Security.framework may create threads. Verify after fork, before exec;
     * no framework state or worker thread crosses this fork boundary. */
    signature(args[0], args[2]);
    int null = open("/dev/null", O_RDWR); need(null >= 0);
    for (int i = 0; i < 3; i++) need(dup2(null, i) == i);
    struct proc_fdinfo fds[4096];
    int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    need(size > 0 && size < (int)sizeof(fds) && size % sizeof(fds[0]) == 0);
    for (size_t i = 0; i < (size_t)size / sizeof(fds[0]); i++)
      if (fds[i].proc_fd >= 3) need(!close(fds[i].proc_fd));
    char *vector[] = {args[0], "-a", args[5], "-f", args[3], NULL, NULL};
    if (validate) {vector[3] = "-n"; vector[4] = "-f"; vector[5] = args[3];}
    char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", NULL};
    execve(args[0], vector, environment); _exit(126);
  }
  close(ready[1]); close(release[0]); struct identity identity;
  need(read(ready[0], &identity, sizeof(identity)) == (ssize_t)sizeof(identity) &&
    identity.token.val[5] == (unsigned)worker && !close(ready[0]));
  printf("{\"worker\":"); emit(identity); puts("}"); fflush(stdout);
  need(command(0, 30000) == 'R' && write(release[1], "R", 1) == 1 && !close(release[1]));
  int status; while (waitpid(worker, &status, 0) < 0) need(errno == EINTR);
  need(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  puts("{\"exitCode\":0,\"signal\":null}");
}
/* Version-two provider input is public capability data, never credentials.
 * Every key/value also belongs to the candidate-bound native launch receipt. */
static char **provider_environment(const char *nonce) {
  static const char *names[] = {"HOME", "PATH", "LANG", "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME",
    "CODEX_HOME", "NATIVE_POC_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_MODEL", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "CLAUDE_CONFIG_DIR", "DISABLE_AUTOUPDATER", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "CLAUDE_CODE_GIT_BASH_PATH"};
  const char *input = getenv("NATIVE_PROVIDER_ENV"); need(input && strlen(input) <= 32768);
  char *block = strdup(input); need(block); static char *values[sizeof(names) / sizeof(names[0]) + 1]; unsigned seen = 0, count = 0;
  char *next = block;
  while (next && *next) {
    char *line = next, *end = strchr(line, '\n'); if (end) { *end = 0; next = end + 1; } else next = NULL;
    char *equals = strchr(line, '='); need(equals && equals > line && equals[1] && strlen(line) <= 8192);
    for (char *p = line; *p; p++) need((unsigned char)*p >= 32 && (unsigned char)*p != 127);
    unsigned index; for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) if (strlen(names[index]) == (size_t)(equals - line) && !strncmp(names[index], line, (size_t)(equals - line))) break;
    need(index < sizeof(names) / sizeof(names[0]) && !(seen & (1U << index)) && count < sizeof(names) / sizeof(names[0])); seen |= 1U << index;
    if (index == 8 || index == 10) need(!strncmp(equals + 1, "native-poc-", 11) && !strcmp(equals + 12, nonce));
    values[count++] = line;
  }
  need((seen & 1) && (seen & 2) && ((seen & (1U << 8)) != 0) != ((seen & (1U << 10)) != 0));
  values[count] = NULL; return values;
}

int main(int argc, char **argv) {
  launcher_pid = getpid();
  need(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 && getenv("CI") && !strcmp(getenv("CI"), "true") &&
       getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"), "true"));
  if (argc == 14 && !strcmp(argv[1], "--audit-holder")) {
    struct identity subject = {0};
    for (unsigned i = 0; i < 8; i++) subject.token.val[i] = bounded_number(argv[i + 2], UINT32_MAX);
    subject.bsd.pbi_start_tvsec = bounded_number(argv[10], UINT64_MAX); subject.bsd.pbi_start_tvusec = bounded_number(argv[11], 999999);
    subject.bsd.pbi_svuid = bounded_number(argv[12], UINT32_MAX); subject.bsd.pbi_svgid = bounded_number(argv[13], UINT32_MAX);
    need(subject.token.val[0] > 500 && subject.token.val[1] == subject.token.val[0] && subject.token.val[6] > 0);
    alarm(600); (void)audit_fresh(0); struct identity birth = inspect(getpid());
    need(write(1, &birth, sizeof(birth)) == sizeof(birth) && command(0, 30000) == 'P');
    struct identity before = inspect(subject.token.val[5]); need(audit_identity_same(before, subject));
    mach_port_t pin = audit_hold(subject.token.val[6]); need(pin != MACH_PORT_NULL && audit_identity_same(before, inspect(subject.token.val[5])));
    struct proc_fdinfo fds[512]; int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    need(size > 0 && size < sizeof(fds) && !(size % sizeof(fds[0])));
    for (unsigned i = 0; i < (unsigned)size / sizeof(fds[0]); i++) if (fds[i].proc_fd != 1) need(!close(fds[i].proc_fd));
    need(write(1, "H", 1) == 1 && !close(1)); for (;;) pause();
  }
  if (argc == 9 && !strcmp(argv[1], "--pfctl")) {
    verifier_barrier(); pfctl(&argv[2]); return 0;
  }
  if (argc == 4 && !strcmp(argv[1], "--members")) {
    uid_t uid = number(argv[2]); au_asid_t asid = number(argv[3]); need(uid > 500 && asid > 0); verifier_barrier(); members(uid, asid); return 0;
  }
  if (argc == 14 && !strcmp(argv[1], "--signal")) {
    verifier_barrier(); signal_identity(&argv[2]); return 0;
  }
  if (argc == 15 && !strcmp(argv[1], "--custody")) {
    au_asid_t asid = (au_asid_t)bounded_number(argv[2], INT32_MAX); need(asid > 0);
    verifier_barrier(); struct identity expected = {0};
    for (unsigned i = 0; i < 8; i++) expected.token.val[i] = bounded_number(argv[i + 3], UINT32_MAX);
    expected.bsd.pbi_start_tvsec = bounded_number(argv[11], UINT64_MAX); expected.bsd.pbi_start_tvusec = bounded_number(argv[12], 999999);
    expected.bsd.pbi_svuid = bounded_number(argv[13], UINT32_MAX); expected.bsd.pbi_svgid = bounded_number(argv[14], UINT32_MAX);
    need(!expected.token.val[1] && !expected.token.val[3] && !expected.bsd.pbi_svuid &&
      !expected.token.val[2] && !expected.token.val[4] && !expected.bsd.pbi_svgid && expected.token.val[5] > 1);
    struct identity before = inspect(expected.token.val[5]); need(audit_identity_same(before, expected));
    char source[PATH_MAX], own[PATH_MAX]; need(proc_pidpath(expected.token.val[5], source, sizeof(source)) > 0 &&
      proc_pidpath(getpid(), own, sizeof(own)) > 0 && !strcmp(source, own));
    mach_port_t pin = audit_hold(asid); need(audit_identity_same(before, inspect(expected.token.val[5])));
    printf("{\"asid\":%u,\"held\":true}\n", asid); fflush(stdout);
    need(command(0, 60000) == 'S' && mach_port_deallocate(mach_task_self(), pin) == KERN_SUCCESS); return 0;
  }
  if (argc == 3 && !strcmp(argv[1], "--inspect")) {
    pid_t pid = (pid_t)number(argv[2]); struct identity before = inspect(pid), after;
    struct proc_vnodepathinfo cwd;
    need(proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &cwd, sizeof(cwd)) == (int)sizeof(cwd));
    after = inspect(pid);
    need(!memcmp(&before.token, &after.token, sizeof(before.token)) &&
      before.bsd.pbi_start_tvsec == after.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == after.bsd.pbi_start_tvusec &&
      S_ISDIR(cwd.pvi_cdir.vip_vi.vi_stat.vst_mode));
    struct vinfo_stat *st = &cwd.pvi_cdir.vip_vi.vi_stat;
    printf("{\"verifier\":"); emit(inspect(getpid())); printf(",\"process\":");
    emit(after); printf(",\"cwd\":{\"dev\":\"%u\",\"ino\":\"%llu\",\"uid\":%u,\"gid\":%u,\"mode\":%u}}\n",
      st->vst_dev, (unsigned long long)st->vst_ino, st->vst_uid, st->vst_gid, st->vst_mode & 07777); return 0;
  }
  /* Read-only verification runs in its own receipted root process. Library
   * worker threads and directory-service state never precede the launch fork. */
  if ((argc == 8 && !strcmp(argv[1], "--verify-inputs")) || (argc == 9 && !strcmp(argv[1], "--verify-provider-inputs"))) {
    int providerInput = argc == 9; size_t maximum = providerInput ? bounded_number(argv[8], 536870912) : 134217728; need(maximum > 0);
#ifdef NATIVE_CI_EXPERIMENT
    need(!providerInput);
#endif
    printf("{\"verifier\":"); emit(inspect(getpid())); puts("}"); fflush(stdout);
    need(command(0, 30000) == 'P');
    uid_t uid = number(argv[2]); gid_t gid = number(argv[3]); need(uid > 500 && gid > 500);
#ifdef NATIVE_CI_EXPERIMENT
    /* Numeric authority is censused under the case reader's held reservation;
     * no directory-service login is created for an ordinary experiment. */
    int workspace = directory(argv[4], uid, gid, 0700); need(!close(workspace));
#else
    struct passwd *pw = getpwuid(uid); struct group *gr = getgrgid(gid);
    need(pw);
    need(gr);
    need(pw->pw_gid == gid);
    need(!strcmp(pw->pw_shell, "/usr/bin/false"));
    need(!strcmp(pw->pw_passwd, "*"));
    need(!strcmp(pw->pw_dir, argv[4]));
    need(gr->gr_mem);
    need(!gr->gr_mem[0]);
#endif
    struct stat image; unsigned char *bytes = file(argv[5], gid, 0550, maximum, argv[6], &image);
    need(image.st_size >= 32 && ((uint32_t *)bytes)[0] == 0xfeedfacf &&
         ((uint32_t *)bytes)[1] == 0x01000007 && ((uint32_t *)bytes)[3] == 2);
    need(!providerInput || (size_t)image.st_size == maximum);
    free(bytes); signature(argv[5], argv[7]);
    printf("{\"sha256\":\"%s\",\"cdhash\":\"%s\"}\n", argv[6], argv[7]); return 0;
  }
  /* uid gid custody storage workspace executable exe-sha cdhash policy policy-sha nonce -- argv... */
  int provider = argc >= 13 && !strcmp(argv[12], "--provider");
#ifdef NATIVE_CI_EXPERIMENT
  need(!provider);
#endif
  need(argc >= 13 && argc <= 77 && (provider || !strcmp(argv[12], "--")));
  const char *ownership = getenv("NATIVE_OWNERSHIP_CUSTODY");
  need(!ownership || (!provider && !strcmp(ownership, "true")));
  const char *access = getenv("NATIVE_ACCESS_CUSTODY");
  need(!access || (!provider && !strcmp(access, "true")));
  if (access) alarm(420);
  if (ownership) alarm(150); /* Fixed ownership work budget plus separate cleanup. */
  const char *imageBound = getenv("NATIVE_PROVIDER_BYTES"); need(!provider || imageBound);
  size_t imageMaximum = provider ? bounded_number(imageBound, 536870912) : 134217728;
  need(imageMaximum > 0); char **providerEnv = provider ? provider_environment(argv[11]) : NULL;
  size_t argumentBytes = 0;
  for (int i = 13; i < argc; i++) {
    size_t length = strlen(argv[i]); need(length <= 4096); argumentBytes += length + 1;
  }
  need(argumentBytes <= 32768);
  /* Privileged setup itself waits for a protected, independently verified
   * helper receipt. No UID/GID claim or fork precedes this acknowledgement. */
  au_asid_t parent_asid = audit_fresh(0);
  launcher_identity = inspect(getpid());
  printf("{\"helper\":"); emit(launcher_identity); puts(",\"payload\":null}"); fflush(stdout);
  need(command(0, 30000) == 'P');
  uid_t uid = number(argv[1]); gid_t gid = number(argv[2]); need(uid > 500 && gid > 500);
  int custody = directory(argv[3], 0, 0, 0700), storage = directory(argv[4], 0, gid, 0710);
  int workspace = directory(argv[5], uid, gid, 0700); struct stat image, policyIdentity;
  unsigned char *imageBytes = file(argv[6], gid, 0550, imageMaximum, argv[7], &image);
  need(image.st_size >= 32 && ((uint32_t *)imageBytes)[0] == 0xfeedfacf &&
       ((uint32_t *)imageBytes)[1] == 0x01000007 && ((uint32_t *)imageBytes)[3] == 2);
  need(!provider || (size_t)image.st_size == imageMaximum);
  free(imageBytes);
  unsigned char *policy = file(argv[9], 0, 0400, 1048576, argv[10], &policyIdentity);
  need(!memchr(policy, 0, (size_t)policyIdentity.st_size));
  claim(custody, "uid", uid, argv[11]); claim(custody, "gid", gid, argv[11]);
  int ready[2], release[2]; need(!pipe(ready) && !pipe(release));
  /* No directory-service or Security framework call precedes this fork.
   * Reject an unexpected multithreaded launcher instead of forking it. */
  struct proc_taskinfo task;
  need(proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &task, sizeof(task)) == (int)sizeof(task) && task.pti_threadnum == 1);
#ifdef NATIVE_CI_EXPERIMENT
  pid_t child = launch_bootstrap_fork();
#else
  pid_t child = fork(); if (child < 0) launch_failure("fork", child, errno, 0, -1, 0);
#endif
  if (child > 0) launch_child = child;
  if (!child) {
    launch_stage("child-entry", NULL, 0, 0);
    close(ready[0]); close(release[1]);
    launch_stage("child-stdio", NULL, 0, 0);
    child_stdio(workspace, provider);
    launch_stage("child-descriptors", NULL, 0, 0);
    need(dup2(ready[1], 3) == 3 && dup2(release[0], 4) == 4); descriptors();
#ifdef NATIVE_CI_EXPERIMENT
    launch_diagnostic = fcntl(2, F_DUPFD_CLOEXEC, 5); int diagnostic_error = errno;
    if (!(launch_diagnostic == 5)) launch_failure("fcntl-stderr", launch_diagnostic, diagnostic_error, 0, -1, 0);
#endif
    auditinfo_addr_t audit = {0}; audit.ai_auid = uid; audit.ai_asid = AU_ASSIGN_ASID;
    audit.ai_termid.at_type = AU_IPv4;
    struct rlimit limit = { .rlim_cur = 32, .rlim_max = 32 }, observed;
    launch_stage("limits-audit-session", NULL, 0, 0);
    need(!setrlimit(RLIMIT_NPROC, &limit));
    need(!setaudit_addr(&audit, sizeof(audit)) && !getaudit_addr(&audit, sizeof(audit)) &&
         audit.ai_asid != AU_DEFAUDITSID && audit.ai_asid != AU_ASSIGN_ASID);
    launch_stage("credentials", NULL, 0, 0);
    need(!setgroups(0, NULL));
    need(!setgid(gid));
    need(!setuid(uid));
    gid_t only; need(getgroups(1, &only) == 1 && only == gid);
    need(!getrlimit(RLIMIT_NPROC, &observed) && observed.rlim_cur == 32 && observed.rlim_max == 32);
    launch_stage("sandbox", NULL, 0, 0);
    char *error = NULL; need(!sandbox_init((const char *)policy, 0, &error));
#ifdef NATIVE_CI_EXPERIMENT
    char home[PATH_MAX + 6]; int length = snprintf(home, sizeof(home), "HOME=%s", argv[5]);
    need(length > 0 && (size_t)length < sizeof(home));
    char *env[] = { home, "PATH=/nonexistent", "LANG=en_US.UTF-8", "TMPDIR=.",
      "CI=true", "GITHUB_ACTIONS=true", ownership ? "NATIVE_OWNERSHIP_CUSTODY=true" : access ? "NATIVE_ACCESS_CUSTODY=true" : NULL, NULL };
    int suffix_size = snprintf(launch_exec_suffix, sizeof(launch_exec_suffix), " revents=0 read=-1 launcher=%d reporter=%d start-seconds=%llu start-micros=%llu\n",
      launcher_pid, getpid(), (unsigned long long)launcher_identity.bsd.pbi_start_tvsec, (unsigned long long)launcher_identity.bsd.pbi_start_tvusec);
    need(suffix_size > 0 && suffix_size < sizeof(launch_exec_suffix));
    alarm(30);
    struct identity creator_identity = inspect(getpid());
    need(domain_creator_checkpoint(3, 4, creator_identity));
#endif
    mach_rights();
    launch_stage("domain-controls", NULL, 0, 0);
    descriptors(); domain_controls(parent_asid, getppid()); struct identity identity = inspect(getpid());
    need(identity.bsd.pbi_uid == uid && identity.bsd.pbi_ruid == uid && identity.bsd.pbi_svuid == uid &&
         identity.bsd.pbi_gid == gid && identity.bsd.pbi_rgid == gid && identity.bsd.pbi_svgid == gid &&
         identity.token.val[0] == uid && identity.token.val[6] == (unsigned)audit.ai_asid);
#ifdef NATIVE_CI_EXPERIMENT
    struct stat named; need(!lstat(argv[6], &named) && named.st_dev == image.st_dev &&
      named.st_ino == image.st_ino && named.st_mode == image.st_mode && named.st_uid == 0 &&
      named.st_gid == gid && named.st_nlink == 1 && named.st_size == image.st_size &&
      named.st_mtimespec.tv_sec == image.st_mtimespec.tv_sec && named.st_mtimespec.tv_nsec == image.st_mtimespec.tv_nsec &&
      named.st_ctimespec.tv_sec == image.st_ctimespec.tv_sec && named.st_ctimespec.tv_nsec == image.st_ctimespec.tv_nsec);
#endif
    launch_stage("parked-publication", NULL, 0, 0);
#ifdef NATIVE_CI_EXPERIMENT
    need(!launch_replies_changed(domain_runtime_reply_count, domain_runtime_replies));
    need(audit_identity_same(identity, creator_identity) && dup2(1, 2) == 2 && domain_creator_final(3, identity));
#else
    need(write(3, &identity, sizeof(identity)) == sizeof(identity) && !close(3));
#endif
#ifdef NATIVE_CI_EXPERIMENT
    char final_gate; ssize_t final_read = read(4, &final_gate, 1);
    if (final_read != 1) domain_exec_failure(launch_diagnostic,
      final_read < 0 ? "native-darwin: operation=creator-release-read domain=errno value=" : "native-darwin: operation=creator-release-read domain=status value=",
      " effects=possible settlement=unsettled\n", final_read < 0 ? errno : (int)final_read);
    if (final_gate != 'R') domain_exec_failure(launch_diagnostic, "native-darwin: operation=creator-release-value domain=invariant value=", " effects=possible settlement=unsettled\n", 0);
    if (close(4)) domain_exec_failure(launch_diagnostic, "native-darwin: operation=creator-release-close domain=errno value=", " effects=possible settlement=unsettled\n", errno);
    alarm(0);
#else
    need(command(4, 30000) == 'R' && !close(4));
    struct stat named; need(!lstat(argv[6], &named) && named.st_dev == image.st_dev &&
      named.st_ino == image.st_ino && named.st_mode == image.st_mode && named.st_uid == 0 &&
      named.st_gid == gid && named.st_nlink == 1 && named.st_size == image.st_size &&
      named.st_mtimespec.tv_sec == image.st_mtimespec.tv_sec && named.st_mtimespec.tv_nsec == image.st_mtimespec.tv_nsec &&
      named.st_ctimespec.tv_sec == image.st_ctimespec.tv_sec && named.st_ctimespec.tv_nsec == image.st_ctimespec.tv_nsec);
    char home[PATH_MAX + 6]; int length = snprintf(home, sizeof(home), "HOME=%s", argv[5]);
    need(length > 0 && (size_t)length < sizeof(home));
    char *env[] = { home, "PATH=/nonexistent", "LANG=en_US.UTF-8", "TMPDIR=.",
      "CI=true", "GITHUB_ACTIONS=true", ownership ? "NATIVE_OWNERSHIP_CUSTODY=true" : access ? "NATIVE_ACCESS_CUSTODY=true" : NULL, NULL };
#endif
    argv[12] = argv[6]; child_exec(argv, provider ? providerEnv : env, provider);
  }
  if (provider) { close(4); close(5); }
  free(policy); close(ready[1]); close(release[0]); close(3); close(workspace); close(storage); close(custody);
#ifdef NATIVE_CI_EXPERIMENT
  struct domain_creator_frame pre, post;
  need(read(ready[0], &pre, sizeof(pre)) == sizeof(pre) && pre.version == 1 && pre.phase == 1 && pre.identity.token.val[5] == (unsigned)child);
  struct identity first = inspect(child); need(audit_identity_same(first, pre.identity));
  (void)audit_hold(first.token.val[6]); need(audit_identity_same(first, inspect(child)));
  printf("{\"helper\":"); emit(inspect(getpid())); printf(",\"payload\":"); emit(first); puts(",\"creator\":{\"version\":1,\"phase\":1}}"); fflush(stdout);
  char creator[DOMAIN_CREATOR_BYTES];
  need(read(0, creator, sizeof(creator)) == sizeof(creator) && write(release[1], creator, sizeof(creator)) == sizeof(creator));
  need(read(ready[0], &post, sizeof(post)) == sizeof(post) && post.version == 1 && post.phase == 2 &&
    audit_identity_same(first, post.identity));
  char trailing; need(read(ready[0], &trailing, 1) == 0 && !close(ready[0]));
  struct identity parked = post.identity;
#else
  struct identity parked = parked_identity(ready[0], child);
#endif
  /* Acquire after fork: only root custody gets the session reference. This
   * original launcher remains a recoverable holder if reader IPC is lost. */
#ifndef NATIVE_CI_EXPERIMENT
  (void)audit_hold(parked.token.val[6]);
#endif
  struct identity live = inspect(child);
  need(!memcmp(&live.token, &parked.token, sizeof(live.token)) &&
       live.bsd.pbi_start_tvsec == parked.bsd.pbi_start_tvsec && live.bsd.pbi_start_tvusec == parked.bsd.pbi_start_tvusec);
  printf("{\"helper\":"); emit(inspect(getpid())); printf(",\"payload\":"); emit(live); puts(",\"controls\":true}"); fflush(stdout);
  char value = command(0, 30000); need(value == 'R' && write(release[1], &value, 1) == 1 && !close(release[1]));
  int status; while (waitpid(child, &status, 0) < 0) need(errno == EINTR);
  if (ownership) {
    printf("{\"exitCode\":");
    if (WIFEXITED(status)) printf("%d", WEXITSTATUS(status)); else fputs("null", stdout);
    printf(",\"signal\":%s}\n", WIFSIGNALED(status) ? "\"signal\"" : "null"); fflush(stdout);
  }
  /* Direct-child exit is not domain retirement. Retain this session reference
   * until the protected retirement owner stops this exact native identity,
   * after admitting separate recovered audit custody. */
  for (;;) pause();
}
