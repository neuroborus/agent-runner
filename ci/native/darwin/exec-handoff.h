/* CI-private suspended SETEXEC mechanics, not complete image/domain admission.
 * Callers own deadlines, capture, custody, policy/image checks and continuation.
 * Include after the owning translation unit's struct identity declaration. */
#ifndef NATIVE_DARWIN_EXEC_HANDOFF_H
#define NATIVE_DARWIN_EXEC_HANDOFF_H
#include <spawn.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>

/* Read-only custody survives both rounds; only the child releases its copies.
 * Callers additionally bind the signed source, parent, policy and creator. */
struct exec_mapping { int fd; struct stat object; char hash[65]; };
static bool exec_mapping_same(struct stat a, struct stat b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode &&
    a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_nlink == b.st_nlink && a.st_size == b.st_size &&
    a.st_birthtimespec.tv_sec == b.st_birthtimespec.tv_sec && a.st_birthtimespec.tv_nsec == b.st_birthtimespec.tv_nsec &&
    a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
    a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
}
static bool exec_mapping_close(struct exec_mapping *value) {
  int fd = value->fd; value->fd = -1;
  return fd < 0 || close(fd) == 0;
}
static bool exec_mapping_read(struct exec_mapping *value, unsigned char *bytes) {
  struct stat before, after; unsigned char sum[32]; char hash[65];
  if (fstat(value->fd, &before) || !exec_mapping_same(before, value->object) ||
      pread(value->fd, bytes, before.st_size, 0) != before.st_size ||
      !CC_SHA256(bytes, (CC_LONG)before.st_size, sum) || fstat(value->fd, &after) ||
      !exec_mapping_same(before, after)) return false;
  for (unsigned i = 0; i < 32; i++) snprintf(hash + 2*i, 3, "%02x", sum[i]);
  return !strcmp(hash, value->hash);
}
static bool exec_mapping_open(struct exec_mapping *value, const char *path, const char *hash) {
  int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  /* Never collide with stdio, ready/release or the diagnostic copy. */
  value->fd = fcntl(fd, F_DUPFD_CLOEXEC, 64); int closed = close(fd);
  if (value->fd < 0 || closed || fstat(value->fd, &value->object)) return false;
  struct stat st = value->object, named;
  if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size <= 0 || st.st_size > 16777216 ||
      (st.st_mode & 022) || (fcntl(value->fd, F_GETFL) & O_ACCMODE) != O_RDONLY ||
      lstat(path, &named) || !exec_mapping_same(st, named) || strlen(hash) != 64) return false;
  memcpy(value->hash, hash, 65);
  unsigned char *bytes = malloc((size_t)st.st_size);
  bool ok = bytes && exec_mapping_read(value, bytes); free(bytes); return ok;
}
static bool exec_mapping_check(struct exec_mapping *value, bool denied) {
  size_t size = (size_t)value->object.st_size;
  /* One fixed prefix; the outside control must prove executable applicability. */
  size_t range = size < 4096 ? size : 4096;
  unsigned char *bytes = malloc(size);
  bool ok = bytes && exec_mapping_read(value, bytes);
  if (ok) {
    void *mapped = mmap(NULL, range, PROT_READ | PROT_EXEC, MAP_PRIVATE, value->fd, 0);
    if (mapped == MAP_FAILED) { int error = errno; ok = denied && (error == EPERM || error == EACCES); }
    else {
      ok = !denied && !memcmp(mapped, bytes, range);
      int unmapped = munmap(mapped, range); ok = !unmapped && ok;
    }
    struct stat after; ok = !fstat(value->fd, &after) && exec_mapping_same(value->object, after) && ok;
  }
  free(bytes); return ok;
}
/* Independent readers join named bytes to the original live custodian's held
 * vnode, not a ready bit or a freshly opened substitute. */
static bool exec_mapping_held(pid_t pid, struct stat object) {
  struct proc_fdinfo fds[512]; int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  if (size <= 0 || size >= sizeof(fds) || size % sizeof(fds[0])) return false;
  for (unsigned i = 0; i < (unsigned)size / sizeof(fds[0]); i++) if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
    struct vnode_fdinfowithpath info;
    if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO, &info, sizeof(info)) != sizeof(info)) return false;
    struct vinfo_stat *st = &info.pvip.vip_vi.vi_stat;
    if (st->vst_dev == object.st_dev && st->vst_ino == object.st_ino && st->vst_mode == object.st_mode &&
        st->vst_uid == object.st_uid && st->vst_gid == object.st_gid && st->vst_nlink == object.st_nlink && st->vst_size == object.st_size) return true;
  }
  return false;
}

struct exec_handoff {
  posix_spawnattr_t attributes;
  posix_spawn_file_actions_t files;
  bool attributes_owned, files_owned;
  const char *operation, *kind;
  int value, files_cleanup, attributes_cleanup;
};
/* Private version-one probe receipt. A returned POSIX status is distinct from
 * setup, settlement and ambient errno; refusal never changes the final handoff. */
struct exec_probe {
  unsigned version, prepared;
  int status, files_cleanup, attributes_cleanup;
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
static struct exec_probe exec_handoff_attempt(struct exec_handoff *probe, const char *image, char **argv, char **environment) {
  struct exec_probe result = {.version = 1, .status = -1};
  result.prepared = probe->attributes_owned && probe->files_owned && !probe->operation;
  if (result.prepared) result.status = posix_spawn(NULL, image, &probe->files, &probe->attributes, argv, environment);
  /* Success replaces this process while suspended. Neither EOF nor a returned
   * zero grants refusal authority. Destroy each initialized object once. */
  exec_handoff_destroy(probe);
  result.files_cleanup = probe->files_cleanup;
  result.attributes_cleanup = probe->attributes_cleanup;
  return result;
}
static bool exec_handoff_refused(struct exec_probe result) {
  return result.version == 1 && result.prepared == 1 &&
    (result.status == EPERM || result.status == EACCES) &&
    !result.files_cleanup && !result.attributes_cleanup;
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
