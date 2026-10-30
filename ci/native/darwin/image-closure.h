/* CI-private creation inputs. Include after custody.h; no namespace census or
 * task-access setter/message. Getter names are compared only by one reader. */
#ifndef NATIVE_DARWIN_IMAGE_CLOSURE_H
#define NATIVE_DARWIN_IMAGE_CLOSURE_H
#include <signal.h>
#include <mach/task.h>
#if __has_include(<mach/task_internal.h>)
#include <mach/task_internal.h>
#endif
#include "exec-handoff.h"
/* XNU task.defs supplies three caller-local outputs, unlike task.c's wrapper
 * which allocates in the target task. SDKs may omit the private MIG declaration;
 * this matching redeclaration also rejects incompatible exposed SDK types.
 * Keep a direct, strong symbol reference; there is no alternate read path. */
extern kern_return_t _kernelrpc_mach_ports_lookup3(task_t target_task,
  mach_port_t *port1, mach_port_t *port2, mach_port_t *port3);
_Static_assert(_Generic(&_kernelrpc_mach_ports_lookup3,
  kern_return_t (*)(task_t, mach_port_t *, mach_port_t *, mach_port_t *): 1, default: 0),
  "registered-port RPC must match the task.defs prototype");
struct image_closure {
  struct domain_bootstrap_fork outcome;
  mach_port_t copies[16], host, access;
  unsigned count;
  bool resource_unsupported;
};
/* Compare held descriptor objects across a refused SETEXEC, not just numbers.
 * Mutable offsets, pipe byte counts and socket traffic are intentionally absent. */
static bool image_descriptors(pid_t pid, uint64_t state[8][4]) {
  struct proc_fdinfo fds[8]; int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  if (size <= 0 || size >= sizeof(fds) || size % sizeof(*fds)) return false;
  memset(state, 0, sizeof(uint64_t) * 8 * 4);
  for (unsigned i = 0; i < (unsigned)size / sizeof(*fds); i++) {
    int fd = fds[i].proc_fd; if (fd < 0 || fd >= 8 || state[fd][0]) return false;
    state[fd][0] = fds[i].proc_fdtype;
    if (fds[i].proc_fdtype == PROX_FDTYPE_PIPE) {
      struct pipe_fdinfo value = {0}; if (proc_pidfdinfo(pid, fd, PROC_PIDFDPIPEINFO, &value, sizeof(value)) != sizeof(value) || !value.pipeinfo.pipe_handle) return false;
      state[fd][1] = value.pfi.fi_openflags; state[fd][2] = value.pipeinfo.pipe_handle; state[fd][3] = value.pipeinfo.pipe_peerhandle;
    } else if (fds[i].proc_fdtype == PROX_FDTYPE_SOCKET) {
      struct socket_fdinfo value = {0}; if (proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &value, sizeof(value)) != sizeof(value) || !value.psi.soi_so) return false;
      state[fd][1] = value.pfi.fi_openflags; state[fd][2] = value.psi.soi_so;
    } else if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
      struct vnode_fdinfowithpath value = {0}; if (proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &value, sizeof(value)) != sizeof(value)) return false;
      state[fd][1] = value.pfi.fi_openflags; state[fd][2] = value.pvip.vip_vi.vi_stat.vst_dev; state[fd][3] = value.pvip.vip_vi.vi_stat.vst_ino;
    } else return false;
  }
  return true;
}
static bool image_mach(struct image_closure *value, kern_return_t result, const char *operation) {
  return domain_bootstrap_check(&value->outcome, result == KERN_SUCCESS, operation, "mach", result, false);
}
static bool image_assert(struct image_closure *value, bool ok, const char *operation) {
  return domain_bootstrap_check(&value->outcome, ok, operation, "invariant", 0, false);
}
static void image_copy(struct image_closure *value, mach_port_t port) {
  if (MACH_PORT_VALID(port)) { need(value->count < 16); value->copies[value->count++] = port; }
}
static bool image_closure_release(struct image_closure *value) {
  bool ok = true;
  kern_return_t settlement = KERN_SUCCESS;
  IMAGE_NOTE("mach_port_deallocate/held-copies", true, 0, 0);
  for (unsigned i = 0; i < value->count; i++) {
    mach_port_t port = value->copies[i]; value->copies[i] = MACH_PORT_NULL;
    if (MACH_PORT_VALID(port)) {
      kern_return_t released = mach_port_deallocate(mach_task_self(), port);
      if (released != KERN_SUCCESS) settlement = released;
      ok = domain_bootstrap_check(&value->outcome, released == KERN_SUCCESS, "image-copy-release", "mach", released, true) && ok;
    }
  }
  value->count = 0;
  IMAGE_NOTE("mach_port_deallocate/held-copies", false, settlement, errno);
  return ok;
}
static bool image_special(struct image_closure *value, task_t task, int slot, mach_port_t *port) {
  *port = MACH_PORT_NULL;
  const char *operation = slot == TASK_HOST_PORT ? "special/host" : slot == TASK_ACCESS_PORT ? "special/access" :
    slot == TASK_BOOTSTRAP_PORT ? "special/bootstrap" : slot == TASK_DEBUG_CONTROL_PORT ? "special/debug" : "special/resource";
  kern_return_t got = IMAGE_CALL(operation, task_get_special_port(task, slot, port));
  if (slot == TASK_RESOURCE_NOTIFY_PORT && got == KERN_INVALID_ARGUMENT) {
    value->resource_unsupported = true; return true;
  }
  if (!image_mach(value, got, "image-special-get")) return false;
  image_copy(value, *port); /* ownership precedes every fallible query */
  return true;
}
static bool image_access(struct image_closure *value) {
  mach_port_t port = value->access;
  if (!MACH_PORT_VALID(port)) return true;
  mach_port_type_t type = MACH_PORT_TYPE_NONE;
  kern_return_t got = IMAGE_CALL("access/type", mach_port_type(mach_task_self(), port, &type));
  if (got == KERN_SUCCESS && !(type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_SEND_ONCE | MACH_PORT_TYPE_DEAD_NAME)))
    value->copies[value->count - 1] = MACH_PORT_NULL; /* rejected unowned receive */
  if (!image_mach(value, got, "image-access-type")) return false;
  if (type == MACH_PORT_TYPE_DEAD_NAME) return true;
  if (!image_assert(value, type == MACH_PORT_TYPE_SEND, "image-access-authority")) return false;
  natural_t kind = ~0U; mach_vm_address_t object = 0;
  return image_mach(value, IMAGE_CALL("access/object", mach_port_kobject(mach_task_self(), port, &kind, &object)), "image-access-object") &&
    image_assert(value, kind == 0, "image-access-service");
}
static bool image_exceptions(struct image_closure *value, task_t task, thread_t thread) {
  bool ok = true, noted = false;
  for (unsigned which = 0; which < 2; which++) {
    exception_mask_t masks[EXC_TYPES_COUNT] = {0}, seen = 0, invalid = 0;
    mach_port_t ports[EXC_TYPES_COUNT] = {0}; exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT]; mach_msg_type_number_t count = EXC_TYPES_COUNT;
    kern_return_t got = which
      ? IMAGE_CALL("exceptions/thread", thread_get_exception_ports(thread, DOMAIN_EXCEPTION_MASK, masks, &count, ports, behaviors, flavors))
      : IMAGE_CALL("exceptions/task", task_get_exception_ports(task, DOMAIN_EXCEPTION_MASK, masks, &count, ports, behaviors, flavors));
    bool queried = image_mach(value, got, "image-exceptions-get");
    bool empty = queried && count <= EXC_TYPES_COUNT && (which || count > 0);
    unsigned first_invalid = EXC_TYPES_COUNT;
    for (unsigned i = 0; queried && i < count && i < EXC_TYPES_COUNT; i++) {
      if (!masks[i] || ports[i] != MACH_PORT_NULL || (seen & masks[i]) || (masks[i] & ~DOMAIN_EXCEPTION_MASK)) {
        empty = false;
        if (first_invalid == EXC_TYPES_COUNT) { first_invalid = i; invalid = masks[i]; }
      }
      seen |= masks[i];
    }
    /* Only a successful absent thread table is empty without mask coverage. */
    empty = empty && ((which && !count) || seen == DOMAIN_EXCEPTION_MASK);
    if (queried) ok = image_assert(value, empty, "image-exceptions-empty") && ok;
    else ok = false;
    if (!empty && !noted) {
      noted = true;
      /* One bounded failure-only record for custody and both fault consumers.
       * Capture grants no authority and cannot interrupt independent cleanup. */
      int saved = errno; char bytes[256];
      int length = queried
        ? snprintf(bytes, sizeof(bytes), "native-darwin-image-exception: scope=%s return=%d count=%u requested=%#x observed=%#x first-invalid=%u/%#x\n",
          which ? "thread" : "task", got, count, DOMAIN_EXCEPTION_MASK, seen, first_invalid, invalid)
        : snprintf(bytes, sizeof(bytes), "native-darwin-image-exception: scope=%s return=%d count=unavailable requested=%#x observed=unavailable first-invalid=unavailable\n",
          which ? "thread" : "task", got, DOMAIN_EXCEPTION_MASK);
      sigset_t blocked, previous, pending;
      if (length > 0 && length < (int)sizeof(bytes) && !sigemptyset(&blocked) && !sigaddset(&blocked, SIGPIPE) &&
          !sigprocmask(SIG_BLOCK, &blocked, &previous)) {
        if (!sigpending(&pending)) {
          bool was_pending = sigismember(&pending, SIGPIPE) == 1;
          ssize_t written = write(STDERR_FILENO, bytes, (size_t)length); int error = errno;
          if (written < 0 && error == EPIPE && !was_pending && !sigpending(&pending) && sigismember(&pending, SIGPIPE) == 1) {
            int received; (void)sigwait(&blocked, &received);
          }
        }
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
      }
      errno = saved;
    }
    if (!queried) continue; /* Failed getter outputs own nothing. */
    int releases[EXC_TYPES_COUNT];
    ok = domain_exception_settle(&value->outcome, ports, count, releases) && ok;
  }
  return ok;
}
static bool image_closure_read(struct image_closure *value, task_t task, thread_t thread) {
  mach_port_t port; natural_t kind = ~0U; mach_vm_address_t object = 0;
  if (!image_special(value, task, TASK_HOST_PORT, &value->host)) return false;
  mach_port_type_t type = 0;
  if (!image_mach(value, IMAGE_CALL("host/type", mach_port_type(mach_task_self(), value->host, &type)), "image-host-type") ||
      !image_assert(value, type == MACH_PORT_TYPE_SEND, "image-host-send") ||
      !image_mach(value, IMAGE_CALL("host/object", mach_port_kobject(mach_task_self(), value->host, &kind, &object)), "image-host-object") ||
      !image_assert(value, kind == 3, "image-host-ordinary") ||
      !image_special(value, task, TASK_ACCESS_PORT, &value->access) || !image_access(value)) return false;
  const int slots[] = {TASK_BOOTSTRAP_PORT, TASK_DEBUG_CONTROL_PORT, TASK_RESOURCE_NOTIFY_PORT};
  bool ok = true;
  for (unsigned i = 0; i < 3; i++) {
    bool got = image_special(value, task, slots[i], &port);
    ok = got && ok;
    if (got) ok = image_assert(value, port == MACH_PORT_NULL, "image-special-empty") && ok;
  }
  mach_port_t registered[3] = {MACH_PORT_NULL, MACH_PORT_NULL, MACH_PORT_NULL};
  kern_return_t got = IMAGE_CALL("registered/get", _kernelrpc_mach_ports_lookup3(task, &registered[0], &registered[1], &registered[2]));
  if (image_mach(value, got, "image-registered-get")) {
    bool empty = true;
    for (unsigned i = 0; i < 3; i++) if (registered[i] != MACH_PORT_NULL) empty = false;
    ok = image_assert(value, empty, "image-registered-empty") && ok;
    kern_return_t settlement = KERN_SUCCESS;
    IMAGE_NOTE("mach_port_deallocate/registered-copies", true, 0, 0);
    /* Each successful getter copy owns a reference, even with aliases. */
    for (unsigned i = 0; i < 3; i++) {
      if (MACH_PORT_VALID(registered[i])) {
        kern_return_t release = mach_port_deallocate(mach_task_self(), registered[i]);
        if (release != KERN_SUCCESS) settlement = release;
        ok = domain_bootstrap_check(&value->outcome, release == KERN_SUCCESS, "image-registered-release", "mach", release, true) && ok;
      }
    }
    IMAGE_NOTE("mach_port_deallocate/registered-copies", false, settlement, errno);
  } else ok = false;
  return image_exceptions(value, task, thread) && ok;
}
static void image_closure_require(struct image_closure *value, bool ok) {
  if (ok && !value->outcome.count) return;
  (void)signal(SIGPIPE, SIG_IGN); /* failure-only; no payload inherits this */
  for (unsigned i = 0; i < value->outcome.count; i++) {
    struct domain_bootstrap_issue issue = value->outcome.issues[i];
    fprintf(stderr, "native-darwin-image: operation=%s domain=%s value=%d cleanup=%d\n", issue.operation, issue.kind, issue.value, issue.cleanup);
  }
  need(false);
}
/* Mutate only the owned trusted child. Never rewrite parent exception metadata.
 * Access is immutable: no setter, including an attempted NULL overwrite. */
static bool image_spawn_inputs(struct exec_handoff *handoff) {
  return exec_handoff_posix(handoff, posix_spawnattr_setspecialport_np(&handoff->attributes, MACH_PORT_NULL, TASK_BOOTSTRAP_PORT), "image-spawn-bootstrap") &&
    exec_handoff_posix(handoff, posix_spawnattr_setspecialport_np(&handoff->attributes, MACH_PORT_NULL, TASK_DEBUG_CONTROL_PORT), "image-spawn-debug") &&
    exec_handoff_posix(handoff, posix_spawnattr_setexceptionports_np(&handoff->attributes, DOMAIN_EXCEPTION_MASK, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE), "image-spawn-exceptions");
}
static void image_closure_prepare(struct exec_handoff *handoff, mach_port_t local_bootstrap) {
  struct image_closure value = {0}; task_t task = mach_task_self(); thread_t thread = mach_thread_self();
  image_copy(&value, thread); image_copy(&value, local_bootstrap);
  bool ok = image_mach(&value, mach_ports_register(task, NULL, 0), "image-registered-clear");
  const int slots[] = {TASK_BOOTSTRAP_PORT, TASK_DEBUG_CONTROL_PORT, TASK_RESOURCE_NOTIFY_PORT};
  for (unsigned i = 0; i < 3; i++) {
    mach_port_t previous = MACH_PORT_NULL;
    kern_return_t got = task_get_special_port(task, slots[i], &previous);
    if (got == KERN_SUCCESS) image_copy(&value, previous);
    kern_return_t set = task_set_special_port(task, slots[i], MACH_PORT_NULL);
    if (i == 2 && got == KERN_INVALID_ARGUMENT && set == KERN_INVALID_ARGUMENT) continue;
    ok = image_mach(&value, got, "image-special-before-clear") && ok;
    ok = image_mach(&value, set, "image-special-clear") && ok;
  }
  ok = image_mach(&value, task_set_exception_ports(task, DOMAIN_EXCEPTION_MASK, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE), "image-task-exceptions-clear") && ok;
  ok = image_mach(&value, thread_set_exception_ports(thread, DOMAIN_EXCEPTION_MASK, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE), "image-thread-exceptions-clear") && ok;
  ok = image_closure_read(&value, task, thread) && ok;
  if (ok) {
    ok = image_spawn_inputs(handoff);
  }
  if (!ok && handoff->operation) domain_bootstrap_check(&value.outcome, false, handoff->operation, handoff->kind, handoff->value, false);
  bool released = image_closure_release(&value);
  if (!ok || !released) {
    exec_handoff_destroy(handoff);
    domain_bootstrap_check(&value.outcome, handoff->files_cleanup == 0, "image-files-destroy", "errno", handoff->files_cleanup, true);
    domain_bootstrap_check(&value.outcome, handoff->attributes_cleanup == 0, "image-attributes-destroy", "errno", handoff->attributes_cleanup, true);
  }
  image_closure_require(&value, ok && released);
}
#endif
