/* Held volume/object identity shared with the private custody reader. */
#ifndef NATIVE_DARWIN_FILE_IDENTITY_H
#define NATIVE_DARWIN_FILE_IDENTITY_H
#include <dirent.h>
/* Held stat/birth/volume joins do not use catalog object-ID lookup. Ordinary
 * readers need known name semantics; publication additionally needs hardlinks.
 * Reviewed consumers retain their original complete capability requirement. */
static void file_identity_capabilities(int fd, bool publication) {
  struct attrlist attrs = {.bitmapcount = ATTR_BIT_MAP_COUNT, .volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES};
  struct { uint32_t length; vol_capabilities_attr_t value; } caps = {0};
  errno = 0; int result = fgetattrlist(fd, &attrs, &caps, sizeof(caps), 0), error = errno;
  if (result) fprintf(stderr, "native-darwin-volume: predicate=query return=%d errno=%d\n", result, error);
  need(result == 0);
  if (caps.length != sizeof(caps)) fprintf(stderr, "native-darwin-volume: predicate=length actual=%u expected=%zu\n", caps.length, sizeof(caps));
  need(caps.length == sizeof(caps));
  uint32_t required = VOL_CAP_FMT_CASE_SENSITIVE | VOL_CAP_FMT_CASE_PRESERVING |
    VOL_CAP_FMT_PERSISTENTOBJECTIDS | VOL_CAP_FMT_HARDLINKS;
  uint32_t known = required;
#ifdef NATIVE_CI_EXPERIMENT
  required = VOL_CAP_FMT_CASE_PRESERVING | (publication ? VOL_CAP_FMT_HARDLINKS : 0);
  known = required | VOL_CAP_FMT_CASE_SENSITIVE;
#else
  (void)publication;
#endif
  uint32_t valid = caps.value.valid[VOL_CAPABILITIES_FORMAT], values = caps.value.capabilities[VOL_CAPABILITIES_FORMAT];
  if ((valid & known) != known) fprintf(stderr, "native-darwin-volume: predicate=valid actual=%u required=%u\n", valid, known);
  need((valid & known) == known);
  if ((values & required) != required) fprintf(stderr, "native-darwin-volume: predicate=supported actual=%u required=%u\n", values, required);
  need((values & required) == required);
}
/* A folded lookup is not an exact name. Enumerate a fresh description of the
 * held parent, then join the exact directory entry back to the opened birth.
 * No alternate spelling or filesystem-specific folding algorithm is admitted. */
static void file_name_at(int parent, const char *name, int fd) {
#ifdef NATIVE_CI_EXPERIMENT
  need(*name && !strchr(name, '/') && strcmp(name, ".") && strcmp(name, ".."));
  int scan = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat before, after, named, held;
  need(scan >= 0 && !fstat(scan, &before) && S_ISDIR(before.st_mode));
  DIR *directory = fdopendir(scan); need(directory);
  unsigned count = 0, exact = 0;
  for (;;) {
    errno = 0; struct dirent *entry = readdir(directory); int error = errno;
    if (!entry) { need(!error); break; }
    need(++count <= 4096); if (!strcmp(entry->d_name, name)) exact++;
  }
  need(exact == 1 && !fstat(scan, &after));
  need(before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
    before.st_birthtimespec.tv_sec == after.st_birthtimespec.tv_sec && before.st_birthtimespec.tv_nsec == after.st_birthtimespec.tv_nsec &&
    before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
    before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec);
  need(!fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) && !fstat(fd, &held));
  need(named.st_dev == held.st_dev && named.st_ino == held.st_ino && named.st_mode == held.st_mode &&
    named.st_uid == held.st_uid && named.st_gid == held.st_gid && named.st_nlink == held.st_nlink &&
    named.st_birthtimespec.tv_sec == held.st_birthtimespec.tv_sec && named.st_birthtimespec.tv_nsec == held.st_birthtimespec.tv_nsec);
  need(!closedir(directory));
#else
  (void)parent; (void)name; (void)fd;
#endif
}
struct file_identity { uint32_t device, fs0, fs1, nanos; uint64_t inode, seconds; unsigned char volume[16]; };
static void text(char out[192], struct file_identity id) {
  int length = snprintf(out, 192, "%u:%u:%u:%" PRIu64 ":%" PRIu64 ":%u:",
    id.device, id.fs0, id.fs1, id.inode, id.seconds, id.nanos);
  need(length > 0 && length + 32 < 192);
  for (int i = 0; i < 16; i++) snprintf(out + length + i * 2, 3, "%02x", id.volume[i]);
}
static bool same(struct file_identity a, struct file_identity b) {
  char left[192], right[192]; text(left, a); text(right, b); return !strcmp(left, right);
}
static bool matches(const char *expected, struct file_identity id) {
  char value[192]; text(value, id); return !strcmp(value, expected);
}
static struct file_identity identify(int fd, bool directory, unsigned links) {
  struct stat s; struct statfs fs;
  need(!fstat(fd, &s) && !fstatfs(fd, &fs) && s.st_uid == 0 && s.st_gid == 0 &&
    s.st_birthtimespec.tv_sec > 0 && s.st_birthtimespec.tv_nsec >= 0 &&
    s.st_birthtimespec.tv_nsec < 1000000000 && s.st_ino > 0 &&
    (directory ? S_ISDIR(s.st_mode) && (s.st_mode & 07777) == 0700 :
      S_ISREG(s.st_mode) && (s.st_mode & 07777) == 0600 && s.st_nlink == links && s.st_size >= 0 && s.st_size <= 4096));
  struct attrlist attrs = {.bitmapcount = ATTR_BIT_MAP_COUNT, .volattr = ATTR_VOL_INFO | ATTR_VOL_UUID};
  struct { uint32_t length; unsigned char uuid[16]; } volume;
  need(!fgetattrlist(fd, &attrs, &volume, sizeof(volume), 0) && volume.length == sizeof(volume));
  unsigned char nonzero = 0; for (int i = 0; i < 16; i++) nonzero |= volume.uuid[i]; need(nonzero);
  file_identity_capabilities(fd, true);
  struct file_identity id = {(uint32_t)s.st_dev, (uint32_t)fs.f_fsid.val[0], (uint32_t)fs.f_fsid.val[1],
    (uint32_t)s.st_birthtimespec.tv_nsec, s.st_ino, (uint64_t)s.st_birthtimespec.tv_sec, {0}};
  memcpy(id.volume, volume.uuid, 16); return id;
}
#endif
