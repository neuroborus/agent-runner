/* Held volume/object identity shared with the private custody reader. */
#ifndef NATIVE_DARWIN_FILE_IDENTITY_H
#define NATIVE_DARWIN_FILE_IDENTITY_H
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
  attrs.volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES;
  struct { uint32_t length; vol_capabilities_attr_t value; } caps;
  need(!fgetattrlist(fd, &attrs, &caps, sizeof(caps), 0) && caps.length == sizeof(caps));
  uint32_t required = VOL_CAP_FMT_CASE_SENSITIVE | VOL_CAP_FMT_CASE_PRESERVING |
    VOL_CAP_FMT_PERSISTENTOBJECTIDS | VOL_CAP_FMT_HARDLINKS;
  need((caps.value.valid[VOL_CAPABILITIES_FORMAT] & required) == required &&
    (caps.value.capabilities[VOL_CAPABILITIES_FORMAT] & required) == required);
  struct file_identity id = {(uint32_t)s.st_dev, (uint32_t)fs.f_fsid.val[0], (uint32_t)fs.f_fsid.val[1],
    (uint32_t)s.st_birthtimespec.tv_nsec, s.st_ino, (uint64_t)s.st_birthtimespec.tv_sec, {0}};
  memcpy(id.volume, volume.uuid, 16); return id;
}
#endif
