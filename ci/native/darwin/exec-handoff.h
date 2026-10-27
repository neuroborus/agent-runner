/* CI-private suspended SETEXEC mechanics, not complete image/domain admission.
 * Callers own deadlines, capture, custody, policy/image checks and continuation.
 * Include after the owning translation unit's struct identity declaration. */
#ifndef NATIVE_DARWIN_EXEC_HANDOFF_H
#define NATIVE_DARWIN_EXEC_HANDOFF_H
#include <spawn.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

struct exec_handoff {
  posix_spawnattr_t attributes;
  posix_spawn_file_actions_t files;
  bool attributes_owned, files_owned;
  const char *operation, *kind;
  int value, files_cleanup, attributes_cleanup;
};
static bool exec_handoff_check(struct exec_handoff *handoff, bool ok, const char *operation, const char *kind, int value) {
  if (!ok && !handoff->operation) {
    handoff->operation = operation; handoff->kind = kind; handoff->value = value;
  }
  return ok;
}
/* Spawn APIs return positive POSIX errors, independently of ambient errno. */
static bool exec_handoff_posix(struct exec_handoff *handoff, int result, const char *operation) {
  return exec_handoff_check(handoff, result == 0, operation, "errno", result);
}
static bool exec_handoff_prepare(struct exec_handoff *handoff, const int *descriptors, unsigned count) {
  if (!exec_handoff_posix(handoff, posix_spawnattr_init(&handoff->attributes), "handoff-attributes-init")) return false;
  handoff->attributes_owned = true;
  if (!exec_handoff_posix(handoff, posix_spawn_file_actions_init(&handoff->files), "handoff-files-init")) return false;
  handoff->files_owned = true;
  if (!exec_handoff_posix(handoff, posix_spawnattr_setflags(&handoff->attributes,
      POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT), "handoff-flags")) return false;
  for (unsigned i = 0; i < count; i++)
    if (!exec_handoff_posix(handoff, posix_spawn_file_actions_adddup2(&handoff->files, descriptors[i], (int)i), "handoff-descriptor")) return false;
  return true;
}
/* Both releases are attempted, even after the primary operation or a release
 * refuses. Never destroy an uninitialized object or retry an uncertain destroy. */
static void exec_handoff_destroy(struct exec_handoff *handoff) {
  if (handoff->files_owned) {
    handoff->files_owned = false;
    handoff->files_cleanup = posix_spawn_file_actions_destroy(&handoff->files);
  }
  if (handoff->attributes_owned) {
    handoff->attributes_owned = false;
    handoff->attributes_cleanup = posix_spawnattr_destroy(&handoff->attributes);
  }
}
static bool exec_handoff_byte(struct exec_handoff *handoff, int fd, bool sending, char expected) {
  char byte = expected;
  ssize_t result = sending ? write(fd, &byte, 1) : read(fd, &byte, 1);
  int error = errno;
  if (!exec_handoff_check(handoff, result == 1, sending ? "handoff-write" : "handoff-read",
      result < 0 ? "errno" : "invariant", result < 0 ? error : 0)) return false;
  return exec_handoff_check(handoff, byte == expected, "handoff-byte", "invariant", 0);
}
static bool exec_handoff_close(struct exec_handoff *handoff, int fd) {
  int result = close(fd), error = errno;
  return exec_handoff_check(handoff, result == 0, "handoff-close", "errno", error);
}
/* The child's receipt writer must already be CLOEXEC. Only this owner-provided
 * one-shot X allows replacement; gate EOF never reaches posix_spawn. */
static void exec_handoff_execute(struct exec_handoff *handoff, int gate, int receipt, const char *image, char **argv, char **environment) {
  if (!exec_handoff_byte(handoff, receipt, true, 'B') ||
      !exec_handoff_byte(handoff, gate, false, 'X') ||
      !exec_handoff_close(handoff, gate)) return;
  int result = posix_spawn(NULL, image, &handoff->files, &handoff->attributes, argv, environment);
  /* Successful SETEXEC cannot return. Even a zero return refuses admission. */
  exec_handoff_check(handoff, false, "handoff-setexec-return", result ? "errno" : "invariant", result);
}
static bool exec_handoff_release(struct exec_handoff *handoff, int *gate) {
  if (!exec_handoff_byte(handoff, *gate, true, 'X') || !exec_handoff_close(handoff, *gate)) return false;
  *gate = -1;
  return true;
}
static bool exec_handoff_receive(struct exec_handoff *handoff, int receipt, bool replaced) {
  if (!replaced) return exec_handoff_byte(handoff, receipt, false, 'B');
  char byte;
  ssize_t result = read(receipt, &byte, 1); int error = errno;
  /* EOF is only an observation. The owner must still admit the stopped image. */
  return exec_handoff_check(handoff, result == 0, "handoff-receipt", result < 0 ? "errno" : "invariant", result < 0 ? error : 0);
}
static bool exec_handoff_identity(struct identity parked, struct identity target) {
  if (target.bsd.pbi_status != SSTOP ||
      target.bsd.pbi_start_tvsec != parked.bsd.pbi_start_tvsec ||
      target.bsd.pbi_start_tvusec != parked.bsd.pbi_start_tvusec ||
      target.bsd.pbi_svuid != parked.bsd.pbi_svuid || target.bsd.pbi_svgid != parked.bsd.pbi_svgid ||
      target.token.val[7] == parked.token.val[7]) return false;
  for (unsigned i = 0; i < 7; i++) if (target.token.val[i] != parked.token.val[i]) return false;
  return true;
}
#endif
