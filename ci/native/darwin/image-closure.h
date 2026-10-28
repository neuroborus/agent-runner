/* CI-private creation inputs. Include after custody.h; no namespace census or
 * task-access setter/message. Getter names are compared only by one reader. */
#ifndef NATIVE_DARWIN_IMAGE_CLOSURE_H
#define NATIVE_DARWIN_IMAGE_CLOSURE_H
#include <signal.h>
#include "exec-handoff.h"
struct image_closure {
  struct domain_bootstrap_fork outcome;
  mach_port_t copies[16], host, access;
  unsigned count;
  bool resource_unsupported;
};
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
  bool ok = true;
  for (unsigned which = 0; which < 2; which++) {
    exception_mask_t masks[EXC_TYPES_COUNT] = {0}, seen = 0;
    mach_port_t ports[EXC_TYPES_COUNT] = {0}; exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT]; mach_msg_type_number_t count = EXC_TYPES_COUNT;
    kern_return_t got = which
      ? IMAGE_CALL("exceptions/thread", thread_get_exception_ports(thread, DOMAIN_EXCEPTION_MASK, masks, &count, ports, behaviors, flavors))
      : IMAGE_CALL("exceptions/task", task_get_exception_ports(task, DOMAIN_EXCEPTION_MASK, masks, &count, ports, behaviors, flavors));
    if (!image_mach(value, got, "image-exceptions-get")) { ok = false; continue; }
    bool empty = count > 0 && count <= EXC_TYPES_COUNT;
    for (unsigned i = 0; i < count && i < EXC_TYPES_COUNT; i++) {
      if (ports[i] != MACH_PORT_NULL || (seen & masks[i]) || (masks[i] & ~DOMAIN_EXCEPTION_MASK)) empty = false;
      seen |= masks[i];
    }
    ok = image_assert(value, empty && seen == DOMAIN_EXCEPTION_MASK, "image-exceptions-empty") && ok;
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
  mach_port_array_t registered = NULL; mach_msg_type_number_t count = 0;
  kern_return_t got = IMAGE_CALL("registered/get", mach_ports_lookup(task, &registered, &count));
  if (image_mach(value, got, "image-registered-get")) {
    bool empty = count <= 32 && (!count || registered);
    for (unsigned i = 0; registered && i < count; i++) if (registered[i] != MACH_PORT_NULL) empty = false;
    ok = image_assert(value, empty, "image-registered-empty") && ok;
    kern_return_t settlement = KERN_SUCCESS;
    IMAGE_NOTE("mach_port_deallocate/registered-copies", true, 0, 0);
    /* Each successful getter copy owns a reference, even with aliases. */
    for (unsigned i = 0; registered && i < count; i++) {
      if (MACH_PORT_VALID(registered[i])) {
        kern_return_t release = mach_port_deallocate(mach_task_self(), registered[i]);
        if (release != KERN_SUCCESS) settlement = release;
        ok = domain_bootstrap_check(&value->outcome, release == KERN_SUCCESS, "image-registered-release", "mach", release, true) && ok;
      }
    }
    IMAGE_NOTE("mach_port_deallocate/registered-copies", false, settlement, errno);
    if (registered) {
      kern_return_t release = IMAGE_CALL("registered/array-release", mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)registered, count * sizeof(*registered)));
      ok = domain_bootstrap_check(&value->outcome, release == KERN_SUCCESS, "image-registered-array-release", "mach", release, true) && ok;
    }
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
    ok = exec_handoff_posix(handoff, posix_spawnattr_setspecialport_np(&handoff->attributes, MACH_PORT_NULL, TASK_BOOTSTRAP_PORT), "image-spawn-bootstrap") &&
      exec_handoff_posix(handoff, posix_spawnattr_setspecialport_np(&handoff->attributes, MACH_PORT_NULL, TASK_DEBUG_CONTROL_PORT), "image-spawn-debug") &&
      exec_handoff_posix(handoff, posix_spawnattr_setexceptionports_np(&handoff->attributes, DOMAIN_EXCEPTION_MASK, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE), "image-spawn-exceptions");
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
