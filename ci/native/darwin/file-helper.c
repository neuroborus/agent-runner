/* Dedicated external CI only. The protected owner supplies held root (fd 3)
 * and parent (fd 4), reserves their volume, and excludes every foreign writer.
 * No pathname fallback, recursive removal or payload descriptor export exists. */
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

struct identity { uint32_t device, fs0, fs1, nanos; uint64_t inode, seconds; unsigned char volume[16]; };
static int root = 3, base = 4, parent = -1, leaf = -1, temporary = -1;
static struct identity root_id, base_id, parent_id, leaf_id, temporary_id;
static const char *nonce;
static void need(int ok) { if (!ok) _exit(126); }
static void expire(int signal) { (void)signal; _exit(124); }
static void text(char out[192], struct identity id) {
  int length = snprintf(out, 192, "%u:%u:%u:%" PRIu64 ":%" PRIu64 ":%u:",
    id.device, id.fs0, id.fs1, id.inode, id.seconds, id.nanos);
  need(length > 0 && length + 32 < 192);
  for (int i = 0; i < 16; i++) snprintf(out + length + i * 2, 3, "%02x", id.volume[i]);
}
static bool same(struct identity a, struct identity b) {
  char left[192], right[192]; text(left, a); text(right, b); return !strcmp(left, right);
}
static bool matches(const char *expected, struct identity id) {
  char value[192]; text(value, id); return !strcmp(value, expected);
}
static struct identity identify(int fd, bool directory, unsigned links) {
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
  struct identity id = {(uint32_t)s.st_dev, (uint32_t)fs.f_fsid.val[0], (uint32_t)fs.f_fsid.val[1],
    (uint32_t)s.st_birthtimespec.tv_nsec, s.st_ino, (uint64_t)s.st_birthtimespec.tv_sec, {0}};
  memcpy(id.volume, volume.uuid, 16); return id;
}
static bool volume_matches(struct identity id) {
  return id.device == root_id.device && id.fs0 == root_id.fs0 && id.fs1 == root_id.fs1 &&
    !memcmp(id.volume, root_id.volume, 16);
}
static int held(int at, const char *name, bool directory) {
  int fd = openat(at, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (directory ? O_DIRECTORY : 0));
  need(fd >= 0); return fd;
}
static void named(int at, const char *name, int fd, struct identity expected, bool directory, unsigned links) {
  struct stat s; need(!fstatat(at, name, &s, AT_SYMLINK_NOFOLLOW));
  need(directory ? S_ISDIR(s.st_mode) : S_ISREG(s.st_mode));
  int current = held(at, name, directory);
  struct identity id = identify(fd, directory, links), other = identify(current, directory, links);
  need(s.st_ino == other.inode && (uint32_t)s.st_dev == other.device && same(id, expected) &&
    same(other, expected) && volume_matches(id) && !close(current));
}
static void ancestors(void) {
  need(same(identify(base, true, 0), base_id) && volume_matches(base_id));
  named(base, "files", root, root_id, true, 0);
  if (parent >= 0) named(root, "allocation", parent, parent_id, true, 0);
}
static void objects(unsigned links) {
  ancestors();
  if (leaf >= 0) named(parent, "value", leaf, leaf_id, false, links);
  if (temporary >= 0) named(parent, ".pending", temporary, temporary_id, false, links);
}
static void absent(int at, const char *name) {
  struct stat s; need(fstatat(at, name, &s, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
}
static void report(const char *phase, bool alias) {
  char r[192], b[192], p[196] = "null", l[196] = "null", t[196] = "null", value[192];
  text(r, root_id); text(b, base_id);
  if (parent >= 0) {text(value, parent_id); snprintf(p, sizeof(p), "\"%s\"", value);}
  if (leaf >= 0) {text(value, leaf_id); snprintf(l, sizeof(l), "\"%s\"", value);}
  if (temporary >= 0) {text(value, temporary_id); snprintf(t, sizeof(t), "\"%s\"", value);}
  need(printf("{\"nonce\":\"%s\",\"phase\":\"%s\",\"base\":\"%s\",\"root\":\"%s\","
    "\"allocation\":%s,\"leaf\":%s,\"temporary\":%s,\"alias\":%s}\n",
    nonce, phase, b, r, p, l, t, alias ? "true" : "false") > 0 && !fflush(stdout));
}
static void line(char *out, size_t size) {
  need(fgets(out, (int)size, stdin) != NULL); size_t length = strlen(out);
  need(length > 0 && out[length - 1] == '\n'); out[length - 1] = 0;
}
static void barrier(const char *phase, bool alias) {
  report(phase, alias); char ack[32]; line(ack, sizeof(ack));
  need(!strcmp(ack, "continue - - - -")); objects(alias ? 2 : 1);
}
static void remove_pending(unsigned links) {
  objects(links); need(temporary >= 0 && !unlinkat(parent, ".pending", 0) && !close(temporary));
  temporary = -1; absent(parent, ".pending");
  if (leaf >= 0) named(parent, "value", leaf, leaf_id, false, 1);
  need(!fsync(parent));
}
static int digit(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; need(0); return 0; }
static void publish(const char *hex, bool replace) {
  need(parent >= 0 && temporary < 0 && (!replace || leaf >= 0)); objects(1);
  unsigned char bytes[4096]; size_t size = !strcmp(hex, "-") ? 0 : strlen(hex);
  need(size <= 8192 && size % 2 == 0);
  for (size_t i = 0; i < size; i += 2) bytes[i / 2] = digit(hex[i]) * 16 + digit(hex[i + 1]);
  temporary = openat(parent, ".pending", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  need(temporary >= 0); temporary_id = identify(temporary, false, 1); need(volume_matches(temporary_id));
  size_t written = 0; while (written < size / 2) {
    ssize_t count = write(temporary, bytes + written, size / 2 - written); need(count > 0); written += count;
  }
  /* Require the reviewed interface; no unsupported-full-sync fallback. This
   * still claims process interruption, never universal power-loss durability. */
  need(!fsync(temporary) && !fcntl(temporary, F_FULLFSYNC) && !fsync(parent));
  barrier("prepared", false);
  if (replace) {
    need(!renameat(parent, ".pending", parent, "value") && !close(leaf));
    leaf = temporary; leaf_id = temporary_id; temporary = -1;
  } else if (linkat(parent, ".pending", parent, "value", 0)) {
    need(errno == EEXIST && leaf >= 0); objects(1); remove_pending(1); report("exists", false); return;
  } else {
    need(leaf < 0); leaf = dup(temporary); need(leaf >= 0); leaf_id = temporary_id;
    barrier("linked", true); /* Exactly this owned staging/publication alias. */
    remove_pending(2);
  }
  barrier("published", false); objects(1); absent(parent, ".pending");
  need(!fsync(parent)); report("complete", false);
}
static int optional(int at, const char *name) {
  struct stat s;
  if (fstatat(at, name, &s, AT_SYMLINK_NOFOLLOW)) {need(errno == ENOENT); return -1;}
  need(S_ISREG(s.st_mode)); return held(at, name, false);
}
static void recover(const char *allocation, const char *old, const char *pending) {
  need(parent < 0 && strcmp(allocation, "-"));
  parent = held(root, "allocation", true); parent_id = identify(parent, true, 0);
  need(matches(allocation, parent_id) && volume_matches(parent_id)); ancestors();
  leaf = optional(parent, "value"); temporary = optional(parent, ".pending");
  struct stat s; unsigned links = 1;
  if (temporary >= 0) {need(!fstat(temporary, &s)); links = (unsigned)s.st_nlink; need(links == 1 || links == 2);
    temporary_id = identify(temporary, false, links); need(matches(pending, temporary_id) && volume_matches(temporary_id));}
  if (leaf >= 0) {
    leaf_id = identify(leaf, false, links == 2 ? 2 : 1); need(volume_matches(leaf_id));
    need(matches(old, leaf_id) || matches(pending, leaf_id));
  }
  need(links != 2 || (leaf >= 0 && same(leaf_id, temporary_id)));
  /* An absent staging name may mean rename/unlink completed before receipt.
   * Every remaining identity must nevertheless have been recorded beforehand. */
  objects(links); report("recovered", links == 2);
}
static void cleanup(void) {
  need(parent >= 0); bool alias = temporary >= 0 && leaf >= 0 && same(leaf_id, temporary_id);
  barrier("removing", alias);
  if (temporary >= 0) remove_pending(alias ? 2 : 1);
  if (leaf >= 0) {objects(1); need(!unlinkat(parent, "value", 0) && !close(leaf)); leaf = -1; absent(parent, "value");}
  ancestors(); need(!fsync(parent) && !unlinkat(root, "allocation", AT_REMOVEDIR) && !close(parent));
  parent = -1; need(!fsync(root)); absent(root, "allocation"); report("removed", false);
}
int main(int argc, char **argv) {
  need(argc == 4 && getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 &&
    getenv("CI") && !strcmp(getenv("CI"), "true") && getenv("GITHUB_ACTIONS") &&
    !strcmp(getenv("GITHUB_ACTIONS"), "true") && strlen(argv[1]) == 32 && strspn(argv[1], "0123456789abcdef") == 32);
  nonce = argv[1]; umask(0077); signal(SIGALRM, expire); alarm(25);
  root_id = identify(root, true, 0); base_id = identify(base, true, 0);
  need(matches(argv[2], root_id) && matches(argv[3], base_id) && volume_matches(base_id));
  /* Inherited duplicates share a file description and thus a flock owner.
   * Reopen only the held root itself, never a pathname or ancestor fallback. */
  int locked = held(root, ".", true);
  need(same(identify(locked, true, 0), root_id) && dup2(locked, root) == root &&
    !close(locked) && !flock(root, LOCK_EX | LOCK_NB));
  struct proc_fdinfo descriptors[4096]; int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
  need(size > 0 && size < (int)sizeof(descriptors) && size % sizeof(descriptors[0]) == 0);
  for (size_t i = 0; i < (size_t)size / sizeof(descriptors[0]); i++)
    if (descriptors[i].proc_fd >= 5) need(!close(descriptors[i].proc_fd));
  ancestors(); report("ready", false);
  char input[9000]; line(input, sizeof(input)); need(!strcmp(input, "start - - - -"));
  for (int count = 0; count < 32; count++) {
    char op[16], allocation[192], value[192], pending[192], bytes[8193], extra;
    line(input, sizeof(input)); need(sscanf(input, "%15s %191s %191s %191s %8192s %c", op, allocation, value, pending, bytes, &extra) == 5);
    ancestors();
    if (!strcmp(op, "allocate")) {
      need(parent < 0 && !strcmp(allocation, "-") && !strcmp(value, "-") && !strcmp(pending, "-") && !strcmp(bytes, "-"));
      absent(root, "allocation"); need(!mkdirat(root, "allocation", 0700)); parent = held(root, "allocation", true);
      parent_id = identify(parent, true, 0); need(volume_matches(parent_id) && !fsync(root)); report("allocated", false); continue;
    }
    if (!strcmp(op, "recover")) {need(!strcmp(bytes, "-")); recover(allocation, value, pending); continue;}
    need((parent < 0 ? !strcmp(allocation, "-") : matches(allocation, parent_id)) &&
      (leaf < 0 ? !strcmp(value, "-") : matches(value, leaf_id)) &&
      (temporary < 0 ? !strcmp(pending, "-") : matches(pending, temporary_id)));
    if (!strcmp(op, "publish") || !strcmp(op, "replace")) {publish(bytes, !strcmp(op, "replace")); continue;}
    need(!strcmp(bytes, "-"));
    if (!strcmp(op, "cleanup")) {cleanup(); continue;}
    if (!strcmp(op, "inspect")) {objects(1); report("inspected", false); continue;}
    if (!strcmp(op, "finish")) {bool alias = temporary >= 0 && leaf >= 0 && same(leaf_id, temporary_id); objects(alias ? 2 : 1); report("finished", alias); return 0;}
    need(0);
  }
  _exit(126);
}
