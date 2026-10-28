/* Dedicated external CI. Sealed reviewed code, a data-only plan, private pipes,
 * bounded held resources and acknowledged release; never a privileged daemon. */
#define __APPLE_API_PRIVATE 1
#define _DARWIN_C_SOURCE 1
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <bsm/audit.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld_images.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <sys/un.h>
#include <semaphore.h>
#include <servers/bootstrap.h>
#include <sys/wait.h>
#include <unistd.h>
#define NATIVE_AUDIT_DOMAIN 1
#ifdef NATIVE_CI_EXPERIMENT
static void image_note(const char *operation, bool entry, long result, int error);
static long image_result(const char *operation, long result);
#define IMAGE_NOTE image_note
#define IMAGE_CALL(operation, call) (image_note(operation, true, 0, 0), image_result(operation, (call)))
#endif
#include "custody.h"
#include "file-identity.h"
#include "feasibility-sandbox.h"
#ifdef NATIVE_CI_EXPERIMENT
#include "image-closure.h"
static char image_cdhash[41];
static unsigned image_policy_index;
static unsigned image_phase;
static bool experiment_exec;
static bool image_control, image_control_retired, image_probed;
static struct identity image_control_creator, image_control_target;
static void image_exec_evidence(pid_t pid);
static char image_control_cdhash[41];
static struct exec_probe image_probe_result;
static bool image_recovering;
static struct image_closure image_inherited, image_inspected;
static bool image_diagnostic_active, image_diagnostic_failed;
static unsigned image_diagnostic_records, image_diagnostic_sequence;
static struct identity image_diagnostic_identity;
static bool image_settle(void) {
  bool ok = image_closure_release(&image_inspected);
  ok = image_closure_release(&image_inherited) && ok;
  return ok && !image_inspected.outcome.count && !image_inherited.outcome.count;
}
static void image_failure_cleanup(void) {
  (void)image_settle();
  struct image_closure *values[] = {&image_inspected, &image_inherited};
  for (unsigned j = 0; j < 2; j++) for (unsigned i = 0; i < values[j]->outcome.count; i++) {
    struct domain_bootstrap_issue issue = values[j]->outcome.issues[i];
    fprintf(stderr, "native-darwin-image-cleanup: operation=%s domain=%s value=%d cleanup=%d\n", issue.operation, issue.kind, issue.value, issue.cleanup);
  }
}
static void image_reader_need(bool ok, const char *file, unsigned line) {
  if (!ok) image_failure_cleanup();
  need_at(ok, file, line);
}
#undef need
#define need(ok) image_reader_need(!!(ok), __FILE__, __LINE__)
#endif

/* The matched SDK/export review must bind these dyld interfaces and this
 * version-one record. Absence is a build/admission failure, never a fallback. */
struct cache_text { uint64_t version, loadAddress, textSegmentSize; unsigned char dylibUuid[16]; const char *dylibPath; };
extern bool _dyld_get_shared_cache_uuid(unsigned char uuid[16]);
extern const void *_dyld_get_shared_cache_range(size_t *length);
extern int dyld_shared_cache_iterate_text(const unsigned char uuid[16], void (^callback)(const struct cache_text *));
extern const struct mach_header_64 _mh_execute_header;

#define SLOTS 128
#define FRAME 262144
struct entry { char kind[16], pin[65], path[PATH_MAX]; int fd; struct stat stat; };
static struct entry entries[SLOTS];
static unsigned count, sequence, operations;
static struct feasibility_sandbox_binding sandbox_binding;
static int sandbox_active(pid_t pid) {
  int value = feasibility_sandbox_active(sandbox_binding, pid);
  need(value == 0 || value == 1); return value;
}
static uint64_t bytes_read;
static mach_port_t sessions[32];
static unsigned session_count;
static struct identity root_domains[32];
static unsigned root_domain_count;
static pid_t file_pid;
static int file_in = -1, file_out = -1, file_decision = -1;
static char candidate[41];
static uid_t subject_uid;
static gid_t subject_gid;
static bool build_mode, preparation_mode, case_mode, case_started, case_policy_possible, operation_mode;
static bool operations_retired(void);
static bool operation_domain_finished(void);
static char case_path[PATH_MAX], case_context[65];
static int case_sockets[8];
static unsigned case_socket_count;
static pid_t case_pid;
static int case_in = -1, case_out = -1, case_data = -1;
static bool case_recovery;
static au_asid_t case_asid;
static bool case_fenced;
static int build_parent = -1, build_root = -1;
static char build_path[PATH_MAX], report_path[PATH_MAX];
static struct stat build_identity, report_identity;
static void expire(int signal) { (void)signal; _exit(124); }
static void line(int fd, char *out, size_t bound) {
  size_t offset = 0;
  while (offset + 1 < bound) {
    struct pollfd wait = {.fd = fd, .events = POLLIN}; char byte;
    need(poll(&wait, 1, 30000) == 1 && (wait.revents & POLLIN));
    ssize_t n = read(fd, &byte, 1); if (n < 0 && errno == EINTR) continue;
    need(n == 1 && byte != 0 && (unsigned char)byte < 128);
    if (byte == '\n') { out[offset] = 0; return; }
    out[offset++] = byte;
  }
  need(0);
}
static int digit(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; need(0); return 0; }
static void decode(const char *in, char *out, size_t bound) {
  size_t n = strlen(in); need(n && n % 2 == 0 && n / 2 < bound);
  for (size_t i = 0; i < n; i += 2) { out[i / 2] = digit(in[i]) * 16 + digit(in[i + 1]); need(out[i / 2]); }
  out[n / 2] = 0;
}
static void same_stat(struct stat a, struct stat b) {
  need(a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode &&
    a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_nlink == b.st_nlink && a.st_size == b.st_size &&
    a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
    a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec);
}
static int lease_parent = -1, lease_base = -1;
static struct stat lease_parent_identity, lease_base_identity, lease_identity;
static bool lease_entry(struct entry *value) {
#ifdef NATIVE_CI_EXPERIMENT
  if (!case_mode || strcmp(value->path, "/private/var/run/native-poc/pf-lease")) return false;
  need(!strcmp(value->kind, "data") && !strcmp(value->pin, "4670840cca5efc5a69097d8b0be5b85030474dcd30449162919de4fffbeca572"));
  return true;
#else
  (void)value; return false;
#endif
}
/* Only the ordinary producer's exact private base joins disposable host
 * ancestry. Held no-follow descriptors retain both sides of that boundary. */
static void lease_guard(struct entry *value) {
  char canonical[PATH_MAX]; struct stat parent, base, named, leaf;
  need(lease_entry(value) && realpath(value->path, canonical) && !strcmp(value->path, canonical));
  bool opening = lease_parent < 0;
  if (opening) {
    need(lease_base < 0);
    lease_parent = open("/private/var/run", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(lease_parent >= 0 && !fstat(lease_parent, &lease_parent_identity));
    lease_base = openat(lease_parent, "native-poc", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(lease_base >= 0 && !fstat(lease_base, &lease_base_identity));
  }
  need(!fstat(lease_parent, &parent) && !lstat("/private/var/run", &named)); same_stat(parent, named);
  need(S_ISDIR(parent.st_mode) && parent.st_uid == 0 && !(parent.st_mode & 06002) &&
    parent.st_dev == lease_parent_identity.st_dev && parent.st_ino == lease_parent_identity.st_ino &&
    parent.st_mode == lease_parent_identity.st_mode && parent.st_uid == lease_parent_identity.st_uid && parent.st_gid == lease_parent_identity.st_gid &&
    parent.st_birthtimespec.tv_sec == lease_parent_identity.st_birthtimespec.tv_sec && parent.st_birthtimespec.tv_nsec == lease_parent_identity.st_birthtimespec.tv_nsec);
  need(!fstat(lease_base, &base) && !fstatat(lease_parent, "native-poc", &named, AT_SYMLINK_NOFOLLOW)); same_stat(base, named);
  need(!lstat("/private/var/run/native-poc", &named)); same_stat(base, named);
  need(S_ISDIR(base.st_mode) && base.st_uid == 0 && base.st_gid == 0 && (base.st_mode & 07777) == 0711 &&
    base.st_dev == lease_base_identity.st_dev && base.st_ino == lease_base_identity.st_ino &&
    base.st_mode == lease_base_identity.st_mode && base.st_uid == lease_base_identity.st_uid && base.st_gid == lease_base_identity.st_gid &&
    base.st_birthtimespec.tv_sec == lease_base_identity.st_birthtimespec.tv_sec && base.st_birthtimespec.tv_nsec == lease_base_identity.st_birthtimespec.tv_nsec);
  no_acl(lease_base);
  need(!fstatat(lease_base, "pf-lease", &leaf, AT_SYMLINK_NOFOLLOW) && !lstat(value->path, &named)); same_stat(leaf, named);
  need(S_ISREG(leaf.st_mode) && leaf.st_uid == 0 && leaf.st_gid == 0 && (leaf.st_mode & 07777) == 0400 && leaf.st_nlink == 1 && leaf.st_size == sizeof("native-poc-pf-lease-v1\n") - 1);
  if (opening) lease_identity = leaf;
  else {
    same_stat(lease_identity, leaf);
    need(leaf.st_birthtimespec.tv_sec == lease_identity.st_birthtimespec.tv_sec && leaf.st_birthtimespec.tv_nsec == lease_identity.st_birthtimespec.tv_nsec);
  }
  if (value->fd >= 0) { same_stat(value->stat, leaf); no_acl(value->fd); }
}
static void ancestors(const char *path) {
  char name[PATH_MAX], canonical[PATH_MAX]; struct stat st;
  need(realpath(path, canonical) && !strcmp(path, canonical));
  need(strlen(path) < sizeof(name)); strcpy(name, path);
  char *slash = strrchr(name, '/'); need(slash && slash != name); *slash = 0;
  for (;;) {
    errno = 0; int result = lstat(name, &st), error = errno;
    bool sampled = result == 0, ok = sampled &&
      (is_bootstrap_parent(path, &st) || experiment_case_parent(path, name, &st));
    if (!ok) {
      /* A successful sample supplies metadata, never an API-error explanation. */
      int primary_error = sampled ? 0 : error; errno = primary_error;
      input_refusal(path, "ancestors-input", NULL);
      input_refusal(name, sampled ? "is_bootstrap_parent" : "lstat", sampled ? &st : NULL);
      fprintf(stderr, "native-darwin-ancestor: operation=lstat return=%d errno=%d error-kind=%s\n",
        result, error, sampled ? "none" : error ? "errno" : "unavailable");
      fflush(stderr); errno = primary_error;
    }
    need(ok);
    slash = strrchr(name, '/'); if (slash == name) break; need(slash); *slash = 0;
  }
}
static void stable_identity(struct entry *value) {
  struct stat current, named; need(value->fd >= 0 && !fstat(value->fd, &current) && !lstat(value->path, &named));
  if (S_ISDIR(value->stat.st_mode)) {
    struct stat before = value->stat;
    need(current.st_dev == before.st_dev && current.st_ino == before.st_ino && current.st_mode == before.st_mode && current.st_uid == before.st_uid && current.st_gid == before.st_gid &&
      named.st_dev == before.st_dev && named.st_ino == before.st_ino && named.st_mode == before.st_mode && named.st_uid == before.st_uid && named.st_gid == before.st_gid &&
      current.st_birthtimespec.tv_sec == before.st_birthtimespec.tv_sec && current.st_birthtimespec.tv_nsec == before.st_birthtimespec.tv_nsec);
  } else { same_stat(value->stat, current); same_stat(value->stat, named); }
}
static void build_guard(void) {
  struct stat root, parent, named; char canonical[PATH_MAX];
  need(realpath(report_path, canonical) && !strcmp(report_path, canonical) &&
    realpath(build_path, canonical) && !strcmp(build_path, canonical));
  need(build_root >= 0 && build_parent >= 0 && !fstat(build_root, &root) && !lstat(build_path, &named) &&
    S_ISDIR(root.st_mode) && root.st_dev == build_identity.st_dev && root.st_ino == build_identity.st_ino &&
    root.st_birthtimespec.tv_sec == build_identity.st_birthtimespec.tv_sec && root.st_birthtimespec.tv_nsec == build_identity.st_birthtimespec.tv_nsec &&
    root.st_uid == 0 && root.st_gid == 0 && ((root.st_mode & 07777) == 0700 || (root.st_mode & 07777) == 0555) &&
    (!case_mode || (root.st_mode == build_identity.st_mode && (root.st_mode & 07777) == 0555)));
  same_stat(root, named);
  need(!fstat(build_parent, &parent) && !lstat(report_path, &named) && S_ISDIR(parent.st_mode) &&
    parent.st_dev == report_identity.st_dev && parent.st_ino == report_identity.st_ino &&
    parent.st_birthtimespec.tv_sec == report_identity.st_birthtimespec.tv_sec && parent.st_birthtimespec.tv_nsec == report_identity.st_birthtimespec.tv_nsec &&
    parent.st_uid == report_identity.st_uid && parent.st_gid == report_identity.st_gid && (parent.st_mode & 07777) == 0700);
  same_stat(parent, named);
  need(!fstatat(build_parent, "platform-build", &named, AT_SYMLINK_NOFOLLOW)); same_stat(root, named);
  no_acl(build_root); no_acl(build_parent);
}
static void build_root_open(const char *name);
/* A declared direct child joins the already approved root, never a pathname
 * prefix or a generic exemption for user-owned ancestors. */
static bool build_entry(struct entry *value) {
  if (!case_mode && !preparation_mode) return false;
  bool directory = !strcmp(value->kind, "directory");
  if (!directory && strcmp(value->kind, "helper") && strcmp(value->kind, "image") && strcmp(value->kind, "data")) return false;
  char name[PATH_MAX]; need(strlen(value->path) < sizeof(name)); strcpy(name, value->path);
  char *leaf = strrchr(name, '/'); need(leaf && leaf != name);
  if (!directory) *leaf = 0;
  leaf = strrchr(name, '/');
  if (!leaf || strcmp(leaf + 1, "platform-build")) return false;
  unsigned approved = 0;
  for (unsigned i = 0; i < count; i++)
    if (!strcmp(entries[i].kind, "directory") && !strcmp(entries[i].path, name)) approved++;
  if (!approved) return false;
  need(approved == 1);
  if (preparation_mode) {
    char expected[PATH_MAX]; need(snprintf(expected, sizeof(expected), "%s/platform-build", report_path) < sizeof(expected));
    need(!strcmp(name, expected));
  }
  if (!directory) need(strlen(value->pin) == 64 && strspn(value->pin, "0123456789abcdef") == 64);
  if (build_root < 0) build_root_open(name); else need(!strcmp(name, build_path));
  return true;
}
static void entry_ancestors(struct entry *value) {
  if (lease_entry(value)) { lease_guard(value); return; }
  if (!build_entry(value)) { ancestors(value->path); return; }
  build_guard();
  char canonical[PATH_MAX]; need(realpath(value->path, canonical) && !strcmp(value->path, canonical));
  if (!strcmp(value->kind, "directory")) return;
  need((build_identity.st_mode & 07777) == 0555);
  const char *leaf = strrchr(value->path, '/'); struct stat held, named;
  need(leaf && !fstatat(build_root, leaf + 1, &held, AT_SYMLINK_NOFOLLOW) && !lstat(value->path, &named));
  same_stat(held, named);
  need(S_ISREG(held.st_mode) && held.st_uid == 0 && held.st_gid == 0 && held.st_nlink == 1 && !(held.st_mode & 06022));
  if (value->fd >= 0) { same_stat(value->stat, held); no_acl(value->fd); }
}
static void stable(struct entry *value) {
  stable_identity(value);
  if (!strcmp(value->kind, "build")) build_guard();
  else if (case_mode && !strncmp(value->path, case_path, strlen(case_path)) &&
    (!value->path[strlen(case_path)] || value->path[strlen(case_path)] == '/')) {
    for (unsigned i = 0; i < count; i++) if (entries[i].fd >= 0 && S_ISDIR(entries[i].stat.st_mode) &&
      !strncmp(entries[i].path, case_path, strlen(case_path))) {
      struct stat held, named; need(!fstat(entries[i].fd, &held) && !lstat(entries[i].path, &named));
      need(held.st_dev == entries[i].stat.st_dev && held.st_ino == entries[i].stat.st_ino &&
        held.st_uid == entries[i].stat.st_uid && held.st_gid == entries[i].stat.st_gid && held.st_mode == entries[i].stat.st_mode);
      same_stat(held, named); no_acl(entries[i].fd);
    }
  } else if (experiment_installed_path(value->path) && S_ISREG(value->stat.st_mode)) need(installed_input(value->path, &value->stat));
  else entry_ancestors(value);
}
static void read_at(int fd, void *out, size_t n, uint64_t offset) {
  need(offset <= INT64_MAX && bytes_read + n <= 2147483648ULL); bytes_read += n;
  size_t done = 0;
  while (done < n) { ssize_t got = pread(fd, (char *)out + done, n - done, (off_t)(offset + done));
    if (got < 0 && errno == EINTR) continue; need(got > 0); done += (size_t)got; }
}
static void sha_range(int fd, uint64_t offset, uint64_t size, char result[65]) {
  need(size <= 536870912 && offset <= INT64_MAX && offset + size <= INT64_MAX);
  CC_SHA256_CTX context; unsigned char buffer[65536], sum[32]; need(CC_SHA256_Init(&context));
  for (uint64_t at = 0; at < size;) { size_t n = size - at > sizeof(buffer) ? sizeof(buffer) : (size_t)(size - at);
    read_at(fd, buffer, n, offset + at); need(CC_SHA256_Update(&context, buffer, (CC_LONG)n)); at += n; }
  need(CC_SHA256_Final(sum, &context)); hex(sum, 32, result);
}
static struct entry *slot(const char *text) {
  unsigned index = number(text); need(index < count && entries[index].fd >= 0); stable(&entries[index]); return &entries[index];
}
static void identity(struct entry *value) {
  struct stat *s = &value->stat; struct statfs fs;
  struct attrlist attrs = {.bitmapcount = ATTR_BIT_MAP_COUNT, .volattr = ATTR_VOL_INFO | ATTR_VOL_UUID};
  struct { uint32_t length; unsigned char uuid[16]; } volume;
  need(!fstatfs(value->fd, &fs) && !fgetattrlist(value->fd, &attrs, &volume, sizeof(volume), 0) && volume.length == sizeof(volume));
  unsigned char nonzero = 0; for (int i = 0; i < 16; i++) nonzero |= volume.uuid[i]; need(nonzero);
  struct file_identity id = {(uint32_t)s->st_dev, (uint32_t)fs.f_fsid.val[0], (uint32_t)fs.f_fsid.val[1],
    (uint32_t)s->st_birthtimespec.tv_nsec, s->st_ino, (uint64_t)s->st_birthtimespec.tv_sec, {0}};
  need(id.inode && id.seconds && id.nanos < 1000000000); memcpy(id.volume, volume.uuid, 16);
  char result[192]; text(result, id);
  printf("{\"identity\":\"%s\",\"bytes\":%llu,\"uid\":%u,\"gid\":%u,\"mode\":%u,\"directory\":%s}", result,
    (unsigned long long)(S_ISDIR(s->st_mode) ? 0 : s->st_size), s->st_uid, s->st_gid, s->st_mode & 07777, S_ISDIR(s->st_mode) ? "true" : "false");
}
#ifdef NATIVE_CI_EXPERIMENT
#define CASE_BASE_COUNT (experiment_exec ? 13 : 12)
#else
#define CASE_BASE_COUNT 12
#endif
static void case_directories(void) {
  /* Plan admission opened these before any case slots. Their roles, metadata
   * and held identities are expectations for the independent process probe. */
  need(case_mode && build_parent == 3 && build_root == 4 && (build_identity.st_mode & 07777) == 0555);
  build_guard();
  struct entry parent = {.fd = build_parent, .stat = report_identity}, root = {.fd = build_root, .stat = build_identity};
  fputs("[{\"role\":\"workspace\",\"fd\":3,\"object\":", stdout); identity(&parent);
  fputs("},{\"role\":\"build\",\"fd\":4,\"object\":", stdout); identity(&root); fputs("}]", stdout);
}
static void signing_check(const char *path, bool report) {
  CFDictionaryRef info = signature_information(path, false);
  char cdhash[41], entitlement[65]; signature_hash(path, info, cdhash);
  CFDictionaryRef grants = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
  CFDataRef data = grants ? CFPropertyListCreateData(NULL, grants, kCFPropertyListBinaryFormat_v1_0, 0, NULL) : NULL;
  need(!grants || (data && CFDataGetLength(data) <= 65536));
  unsigned char sum[32]; need(CC_SHA256(data ? CFDataGetBytePtr(data) : (const unsigned char *)"", data ? (CC_LONG)CFDataGetLength(data) : 0, sum));
  hex(sum, 32, entitlement); if (report) printf("{\"cdhash\":\"%s\",\"entitlementsSha256\":\"%s\",\"valid\":true}", cdhash, entitlement);
  if (data) CFRelease(data); CFRelease(info);
}
static void signing(const char *path) { signing_check(path, true); }
static void macho(const unsigned char *bytes, size_t size) {
  need(size >= sizeof(struct mach_header_64)); const struct mach_header_64 *h = (const void *)bytes;
  need(h->magic == MH_MAGIC_64 && h->cputype == CPU_TYPE_X86_64 && h->ncmds > 0 && h->ncmds <= 512 &&
    h->sizeofcmds <= 1048576 && sizeof(*h) + h->sizeofcmds == size && (h->filetype == MH_EXECUTE || h->filetype == MH_DYLIB || h->filetype == MH_DYLINKER));
  char sum[65]; unsigned char digest_bytes[32]; need(CC_SHA256(bytes, (CC_LONG)size, digest_bytes)); hex(digest_bytes, 32, sum);
  printf("{\"headerSha256\":\"%s\",\"dependencies\":[", sum);
  size_t string_bytes = 0;
  for (unsigned pass = 0; pass < 2; pass++) {
    size_t at = sizeof(*h); unsigned items = 0;
    for (unsigned i = 0; i < h->ncmds; i++) {
      need(at + sizeof(struct load_command) <= size); const struct load_command *lc = (const void *)(bytes + at);
      need(lc->cmdsize >= 8 && lc->cmdsize % 8 == 0 && at + lc->cmdsize <= size);
      need(lc->cmd != LC_DYLD_ENVIRONMENT);
#ifndef NATIVE_CI_EXPERIMENT
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *segment = (const void *)lc;
        need(lc->cmdsize >= sizeof(*segment) && segment->nsects <= 128 &&
          sizeof(*segment) + (uint64_t)segment->nsects * sizeof(struct section_64) == lc->cmdsize);
        const struct section_64 *sections = (const void *)(segment + 1);
        for (unsigned section = 0; section < segment->nsects; section++)
          need(strncmp(sections[section].sectname, "__nexp", 16));
      }
#endif
      bool library = lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB || lc->cmd == LC_LOAD_UPWARD_DYLIB || lc->cmd == LC_LAZY_LOAD_DYLIB;
      bool interpreter = lc->cmd == LC_LOAD_DYLINKER;
      if ((pass == 0 && (library || interpreter)) || (pass == 1 && lc->cmd == LC_RPATH)) {
        size_t minimum = library ? sizeof(struct dylib_command) : interpreter ? sizeof(struct dylinker_command) : sizeof(struct rpath_command);
        need(lc->cmdsize >= minimum);
        unsigned offset = library ? ((const struct dylib_command *)lc)->dylib.name.offset : interpreter ? ((const struct dylinker_command *)lc)->name.offset : ((const struct rpath_command *)lc)->path.offset;
        need(offset >= minimum && offset < lc->cmdsize);
        const unsigned char *name = bytes + at + offset; size_t n = strnlen((const char *)name, lc->cmdsize - offset);
        need(n > 0 && n < lc->cmdsize - offset && n < PATH_MAX && ++items <= 128 && (string_bytes += n) <= 65536);
        if (items > 1) putchar(','); putchar('"'); char encoded[PATH_MAX * 2 + 1]; hex(name, n, encoded); fputs(encoded, stdout); putchar('"');
      }
      at += lc->cmdsize;
    }
    need(at == size); if (pass == 0) printf("],\"rpaths\":[");
  }
  size_t at = sizeof(*h); unsigned sdk = 0, minimum = 0; unsigned char uuid[16] = {0}; bool found_sdk = false, found_uuid = false;
  for (unsigned i = 0; i < h->ncmds; i++) {
    const struct load_command *lc = (const void *)(bytes + at);
    if (lc->cmd == LC_BUILD_VERSION) { const struct build_version_command *v = (const void *)lc;
      need(!found_sdk && lc->cmdsize >= sizeof(*v) && v->platform == PLATFORM_MACOS && sizeof(*v) + (uint64_t)v->ntools * sizeof(struct build_tool_version) == lc->cmdsize);
      sdk = v->sdk; minimum = v->minos; found_sdk = true; }
    if (lc->cmd == LC_VERSION_MIN_MACOSX) { const struct version_min_command *v = (const void *)lc;
      need(!found_sdk && lc->cmdsize == sizeof(*v)); sdk = v->sdk; minimum = v->version; found_sdk = true; }
    if (lc->cmd == LC_UUID) { need(!found_uuid && lc->cmdsize == sizeof(struct uuid_command)); memcpy(uuid, ((const struct uuid_command *)lc)->uuid, 16); found_uuid = true; }
    at += lc->cmdsize;
  }
  char id[33]; hex(uuid, 16, id); need(found_sdk && sdk && minimum);
  printf("],\"sdk\":%u,\"minimum\":%u,\"uuid\":\"%s\"}", sdk, minimum, id);
}
static bool installed_loader(struct entry *value) {
  return experiment_installed_path(value->path) && !strcmp(value->path, "/usr/lib/dyld");
}
static uint64_t container_number(const unsigned char *bytes, unsigned width, bool little) {
  uint64_t result = 0;
  for (unsigned i = 0; i < width; i++) result = result * 256 + bytes[little ? width - 1 - i : i];
  return result;
}
static void image(struct entry *value) {
  need(value->stat.st_size > 0 && (uint64_t)value->stat.st_size >= sizeof(struct mach_header_64));
  uint64_t offset = 0, limit = value->stat.st_size; uint32_t subtype = 0;
  unsigned char prefix[8]; read_at(value->fd, prefix, sizeof(prefix), 0);
  bool universal = container_number(prefix, 4, true) != MH_MAGIC_64;
  if (universal) {
    /* Only the ordinary held loader gains container admission. Private helpers,
     * reviewed images and other installed tools retain their existing rules. */
    need(installed_loader(value));
    uint64_t magic = container_number(prefix, 4, false);
    need(magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
    bool wide = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64, little = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
    unsigned count = container_number(prefix + 4, 4, little), width = wide ? 32 : 20;
    uint64_t table_end = sizeof(prefix) + (uint64_t)count * width, starts[128], lengths[128];
    need(count > 0 && count <= 128 && table_end <= (uint64_t)value->stat.st_size);
    bool found = false;
    for (unsigned i = 0; i < count; i++) {
      unsigned char record[32]; read_at(value->fd, record, width, sizeof(prefix) + (uint64_t)i * width);
      uint64_t start = container_number(record + 8, wide ? 8 : 4, little),
        length = container_number(record + (wide ? 16 : 12), wide ? 8 : 4, little);
      unsigned alignment = container_number(record + (wide ? 24 : 16), 4, little);
      need(start >= table_end && start <= (uint64_t)value->stat.st_size && length > 0 &&
        length <= (uint64_t)value->stat.st_size - start && alignment < 63 && start % (1ULL << alignment) == 0 &&
        (!wide || container_number(record + 28, 4, little) == 0));
      for (unsigned j = 0; j < i; j++) need(start + length <= starts[j] || starts[j] + lengths[j] <= start);
      starts[i] = start; lengths[i] = length;
      if (container_number(record, 4, little) == CPU_TYPE_X86_64) {
        need(!found); found = true; offset = start; limit = length; subtype = container_number(record + 4, 4, little);
      }
    }
    need(found);
  }
  need(limit >= sizeof(struct mach_header_64));
  struct mach_header_64 header; read_at(value->fd, &header, sizeof(header), offset);
  need(header.magic == MH_MAGIC_64 && header.cputype == CPU_TYPE_X86_64 && (!universal || (uint32_t)header.cpusubtype == subtype) &&
    header.sizeofcmds <= 1048576 && sizeof(header) + (uint64_t)header.sizeofcmds <= limit);
  size_t size = sizeof(header) + header.sizeofcmds; unsigned char *bytes = malloc(size); need(bytes);
  read_at(value->fd, bytes, size, offset); macho(bytes, size); free(bytes); stable(value);
}
static void case_members(unsigned asid, bool independent);
static void probe(pid_t pid, int asid) {
  struct proc_bsdinfo b; errno = 0; int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, &b, sizeof(b)), error = errno;
  printf("{\"verifier\":"); emit(inspect(getpid())); printf(",\"subject\":");
  if (n == 0 && error == ESRCH) { need(asid < 0); puts("{\"status\":\"absent\"}}"); return; }
  need(n == sizeof(b) && b.pbi_status != SZOMB); struct identity before = inspect(pid);
  char path[PATH_MAX]; need(proc_pidpath(pid, path, sizeof(path)) > 0); ancestors(path);
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat st, after; need(fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && (experiment_installed_path(path) ? installed_input(path, &st) : st.st_uid == 0 && !(st.st_mode & 022) && (st.st_nlink == 1 || installed_input(path, &st))));
  char hash[65]; sha_range(fd, 0, (uint64_t)st.st_size, hash);
  printf("{\"status\":\"live\",\"identity\":"); emit(before); printf(",\"sha256\":\"%s\",\"signature\":", hash); signing(path);
  printf(",\"directories\":["); unsigned dirs = 0;
  for (int target = 3; target <= 4; target++) {
    struct vnode_fdinfowithpath info; errno = 0; n = proc_pidfdinfo(pid, target, PROC_PIDFDVNODEPATHINFO, &info, sizeof(info));
    if (n == 0 && errno == EBADF) continue;
    if (n == 0 && errno == EINVAL) continue;
    need(n == sizeof(info)); struct vinfo_stat *v = &info.pvip.vip_vi.vi_stat;
    if (!S_ISDIR(v->vst_mode)) continue;
    if (dirs++) putchar(','); printf("{\"fd\":%d,\"dev\":\"%u\",\"ino\":\"%llu\",\"uid\":%u,\"gid\":%u,\"mode\":%u}", target, v->vst_dev, (unsigned long long)v->vst_ino, v->vst_uid, v->vst_gid, v->vst_mode & 07777);
  }
  struct identity current = inspect(pid); need(!memcmp(&before.token, &current.token, sizeof(before.token)) &&
    before.bsd.pbi_start_tvsec == current.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == current.bsd.pbi_start_tvusec && !fstat(fd, &after));
  same_stat(st, after); need(!lstat(path, &after)); same_stat(st, after);
  need(st.st_nlink == 1 || installed_input(path, &after)); need(!close(fd)); fputs("]}", stdout);
  if (asid >= 0) { fputs(",\"enumeration\":", stdout); case_members((unsigned)asid, true); }
  puts("}");
}
static void plan(const char *path, const char *pin) {
  ancestors(path); struct stat st; char *bytes = (char *)file(path, 0, 0400, FRAME, pin, &st); need(!memchr(bytes, 0, (size_t)st.st_size));
  char *next, *record = strtok_r(bytes, "\n", &next), extra; unsigned uid, gid;
#ifdef NATIVE_CI_EXPERIMENT
  experiment_exec = record && !strncmp(record, "native-experiment-custody-v2 ", strlen("native-experiment-custody-v2 "));
#endif
  const char *header =
#ifdef NATIVE_CI_EXPERIMENT
    experiment_exec ? "native-experiment-custody-v2 " : "native-experiment-custody-v1 ";
#else
    "native-custody-v1 ";
#endif
  need(record && !strncmp(record, header, strlen(header)) && sscanf(record + strlen(header), "%40s %u %u %c", candidate, &uid, &gid, &extra) == 3 && strlen(candidate) == 40 && strspn(candidate, "0123456789abcdef") == 40 && uid > 500 && uid <= INT_MAX && gid > 500 && gid <= INT_MAX);
  subject_uid = uid; subject_gid = gid;
  while ((record = strtok_r(NULL, "\n", &next))) {
    /* Match the protocol scan width; decode separately enforces PATH_MAX. */
    need(count < SLOTS); struct entry *entry = &entries[count]; char encoded[8193];
    need(sscanf(record, "%15s %64s %8192s %c", entry->kind, entry->pin, encoded, &extra) == 3);
    need(!strcmp(entry->kind, "directory") || !strcmp(entry->kind, "authority") || !strcmp(entry->kind, "image") || !strcmp(entry->kind, "data") || !strcmp(entry->kind, "cache") || !strcmp(entry->kind, "helper"));
    need((!strcmp(entry->kind, "directory") || !strcmp(entry->kind, "authority")) ? !strcmp(entry->pin, "-") : strlen(entry->pin) == 64 && strspn(entry->pin, "0123456789abcdef") == 64);
    decode(encoded, entry->path, sizeof(entry->path));
    entry->fd = -1;
    for (unsigned i = 0; i < count; i++) need(strcmp(entries[i].path, entry->path)); count++;
  }
  need(count); free(bytes);
  /* The approved root may follow its pinned consumers in the plan. */
  for (unsigned i = 0; i < count; i++) {
    struct entry *entry = &entries[i]; const char *leaf = strrchr(entry->path, '/');
    bool private_case = case_mode && !strncmp(entry->path, case_path, strlen(case_path)) &&
      (!entry->path[strlen(case_path)] || entry->path[strlen(case_path)] == '/');
    if (!private_case && !(build_mode && !strcmp(entry->kind, "directory") && leaf && !strcmp(leaf + 1, "platform-build"))) entry_ancestors(entry);
  }
}
/* Compiler descendants share a fresh root audit session. Observe its complete
 * kernel membership; reaping the compiler alone cannot retire that domain. */
static unsigned root_members(au_asid_t asid, bool output) {
  struct audit_domain_view view = audit_census((uid_t)-1, asid);
  need(!view.nd); /* Without a recorded birth, an unknown zombie is uncertain. */
  for (unsigned i = 0; output && i < view.nl; i++) { if (i) putchar(','); emit(view.live[i]); }
  return view.nl;
}
static void root_domain(pid_t pid, unsigned asid, unsigned version) {
  unsigned index;
  for (index = 0; index < root_domain_count; index++)
    if (root_domains[index].token.val[5] == (unsigned)pid && root_domains[index].token.val[7] == version && root_domains[index].token.val[6] == asid) break;
  if (index == root_domain_count) {
    need(root_domain_count < 32 && session_count < 32 && asid > 0 && asid < UINT32_MAX);
    struct identity helper = inspect(pid); need(helper.token.val[1] == 0 && helper.token.val[6] == asid && helper.token.val[7] == version);
    char image[PATH_MAX]; need(proc_pidpath(pid, image, sizeof(image)) > 0);
    unsigned found;
    for (found = 0; found < count; found++) if (!strcmp(entries[found].kind, "helper") && !strcmp(entries[found].path, image)) break;
    if (found == count) { char owner_image[PATH_MAX]; need(proc_pidpath(getpid(), owner_image, sizeof(owner_image)) > 0 && !strcmp(image, owner_image)); }
    struct stat stat; if (found < count) entry_ancestors(&entries[found]); else ancestors(image);
    need(!lstat(image, &stat) && !(stat.st_mode & 06022));
    if (found < count) free(file(image, case_mode ? stat.st_gid : 0, stat.st_mode & 07777, 536870912, entries[found].pin, &stat));
    need(!audit_session_port(asid, &sessions[session_count]) && sessions[session_count] != MACH_PORT_NULL);
    session_count++; root_domains[root_domain_count++] = helper;
  }
  printf("{\"helper\":"); emit(root_domains[index]); printf(",\"complete\":true,\"members\":[");
  root_members(asid, true); printf("]}");
}
static void transfer(struct entry *helper, struct entry *root, struct entry *base, const char *nonce, const char *cdhash) {
  need(!file_pid && !strcmp(helper->kind, "helper") && strlen(nonce) == 32 && strspn(nonce, "0123456789abcdef") == 32 && strlen(cdhash) == 40 && strspn(cdhash, "0123456789abcdef") == 40 && (helper->stat.st_mode & 07777) == 0550);
  struct file_identity r = identify(root->fd, true, 0), b = identify(base->fd, true, 0);
  char rtext[192], btext[192]; text(rtext, r); text(btext, b);
  int named = openat(base->fd, "files", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(named >= 0); file_name_at(base->fd, "files", named);
  need(same(identify(named, true, 0), r) && !close(named) && r.device == b.device && r.fs0 == b.fs0 && r.fs1 == b.fs1 && !memcmp(r.volume, b.volume, 16));
  struct proc_taskinfo task; need(proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &task, sizeof(task)) == sizeof(task) && task.pti_threadnum == 1);
  int input[2], output[2], decision[2]; need(!pipe(input) && !pipe(output) && !pipe(decision)); file_pid = fork(); need(file_pid >= 0);
  if (!file_pid) {
    need(dup2(input[0], 0) == 0 && dup2(output[1], 1) == 1);
    int null = open("/dev/null", O_WRONLY | O_CLOEXEC); need(null >= 0 && dup2(null, 2) == 2);
    int rcopy = fcntl(root->fd, F_DUPFD_CLOEXEC, 10), bcopy = fcntl(base->fd, F_DUPFD_CLOEXEC, 10);
    need(rcopy >= 10 && bcopy >= 10 && dup2(rcopy, 3) == 3 && dup2(bcopy, 4) == 4);
    need(dup2(decision[1], 5) == 5);
    /* The helper owns exactly these two transferred directory descriptors. */
    struct proc_fdinfo fds[4096]; int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    need(size > 0 && size < sizeof(fds) && size % sizeof(fds[0]) == 0);
    for (size_t i = 0; i < (size_t)size / sizeof(fds[0]); i++) if (fds[i].proc_fd >= 6) need(!close(fds[i].proc_fd));
    signature(helper->path, cdhash);
    char *args[] = {helper->path, (char *)nonce, rtext, btext, NULL};
    char *env[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", "NATIVE_FILE_CUSTODY=true", NULL};
    execve(helper->path, args, env); _exit(126);
  }
  need(!close(input[0]) && !close(output[1]) && !close(decision[1])); file_decision = decision[0]; file_in = input[1]; file_out = output[0]; printf("{\"pid\":%d}", file_pid);
}
static bool cache_contains(uint64_t base, uint64_t length, uint64_t address, uint64_t size) {
  return base && length && size && length <= UINT64_MAX - base && address >= base &&
    address - base <= length && size <= length - (address - base);
}
static struct dyld_all_image_infos cache_loader(const unsigned char uuid[16], uint64_t base) {
  task_dyld_info_data_t info = {0}; mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  need(task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) == KERN_SUCCESS);
  struct dyld_all_image_infos images = {0};
  /* Read only the SDK-defined prefix through the version-15 cache base. The
   * kernel's record may have a newer tail; no private layout or export is used. */
  const size_t size = offsetof(struct dyld_all_image_infos, sharedCacheBaseAddress) + sizeof(images.sharedCacheBaseAddress);
  need(count == TASK_DYLD_INFO_COUNT && info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64 &&
    info.all_image_info_addr && info.all_image_info_size >= size &&
    info.all_image_info_size <= UINT64_MAX - info.all_image_info_addr);
  mach_vm_size_t actual = 0;
  need(mach_vm_read_overwrite(mach_task_self(), info.all_image_info_addr, size, (mach_vm_address_t)&images, &actual) == KERN_SUCCESS && actual == size);
  need(images.version >= 15 && images.sharedCacheBaseAddress == base &&
    !memcmp(images.sharedCacheUUID, uuid, sizeof(images.sharedCacheUUID)));
  return images;
}
static void cache_image(struct entry *entry, const char *name) {
  need(!strcmp(entry->kind, "cache")); unsigned char header[104], uuid[16]; read_at(entry->fd, header, sizeof(header), 0);
  need((!memcmp(header, "dyld_v1  x86_64", 16) || !memcmp(header, "dyld_v1 x86_64h", 16)) &&
    _dyld_get_shared_cache_uuid(uuid) && !memcmp(header + 88, uuid, 16));
  uint64_t offset, length; memcpy(&offset, header + 40, 8); memcpy(&length, header + 48, 8);
  need(length && length <= 134217728 && offset <= (uint64_t)entry->stat.st_size &&
    length <= (uint64_t)entry->stat.st_size - offset); char signature_hash[65]; sha_range(entry->fd, offset, length, signature_hash);
  __block unsigned matched = 0; __block uint64_t address = 0, text_size = 0;
  __block struct { unsigned char bytes[16]; } image_uuid = {{0}};
  need(!dyld_shared_cache_iterate_text(uuid, ^(const struct cache_text *info) {
    need(info->version == 1 && info->dylibPath && strnlen(info->dylibPath, PATH_MAX) < PATH_MAX);
    if (!strcmp(info->dylibPath, name)) { matched++; address = info->loadAddress; text_size = info->textSegmentSize; memcpy(image_uuid.bytes, info->dylibUuid, 16); }
  }) && matched == 1);
  size_t range_size = 0; const void *range = _dyld_get_shared_cache_range(&range_size);
  uint64_t base = (uintptr_t)range; need(cache_contains(base, range_size, base, sizeof(struct mach_header_64)));
  struct dyld_all_image_infos images = cache_loader(uuid, base);
  need(address <= UINT64_MAX - images.sharedCacheSlide); address += images.sharedCacheSlide;
  need(cache_contains(base, range_size, address, sizeof(struct mach_header_64)));
  struct mach_header_64 image_header; mach_vm_size_t actual;
  need(mach_vm_read_overwrite(mach_task_self(), address, sizeof(image_header), (mach_vm_address_t)&image_header, &actual) == KERN_SUCCESS && actual == sizeof(image_header) && image_header.sizeofcmds <= 1048576);
  size_t size = sizeof(image_header) + image_header.sizeofcmds; need(cache_contains(base, range_size, address, size));
  unsigned char *bytes = malloc(size); need(bytes);
  need(mach_vm_read_overwrite(mach_task_self(), address, size, (mach_vm_address_t)bytes, &actual) == KERN_SUCCESS && actual == size);
  char id[33], image_id[33]; hex(uuid, 16, id); hex(image_uuid.bytes, 16, image_id);
  printf("{\"cacheUuid\":\"%s\",\"imageUuid\":\"%s\",\"signatureSha256\":\"%s\",\"macho\":", id, image_id, signature_hash); macho(bytes, size);
#ifdef NATIVE_CI_EXPERIMENT
  /* The experiment pins actual immutable mapped Mach-O text, separately from
   * the held cache's UUID and CodeDirectory bytes. Never invent a file hash. */
  need(text_size >= size && text_size <= 134217728 && cache_contains(base, range_size, address, text_size));
  unsigned char *text = malloc(text_size); need(text); unsigned char sums[2][CC_SHA256_DIGEST_LENGTH];
  for (unsigned pass = 0; pass < 2; pass++) {
    need(mach_vm_read_overwrite(mach_task_self(), address, text_size, (mach_vm_address_t)text, &actual) == KERN_SUCCESS && actual == text_size);
    need(CC_SHA256(text, (CC_LONG)text_size, sums[pass]));
  }
  need(!memcmp(sums[0], sums[1], sizeof(sums[0]))); char text_hash[65]; hex(sums[0], sizeof(sums[0]), text_hash);
  printf(",\"sha256\":\"%s\"", text_hash); free(text);
#endif
  struct dyld_all_image_infos after = cache_loader(uuid, base); size_t after_size = 0;
  need(after.sharedCacheSlide == images.sharedCacheSlide && _dyld_get_shared_cache_range(&after_size) == range && after_size == range_size);
  putchar('}'); free(bytes); stable(entry);
}
static bool owned_access_socket(const char *name, const struct stat *st);
#include "effective-reader.h"
/* Read the suspended tool's effective credentials, Seatbelt state and complete
 * inherited descriptor set. Expected build vectors are not observations. */
static void compiler_policy(pid_t pid, unsigned version, unsigned asid) {
  struct identity before = inspect(pid), after;
  need(before.token.val[7] == version && before.token.val[6] == asid && asid > 0);
  int sandboxed = sandbox_active(pid);
  struct proc_fdinfo fds[64]; int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  need(size > 0 && size < sizeof(fds) && size % sizeof(fds[0]) == 0);
  printf("{\"identity\":"); emit(before);
  printf(",\"uid\":%u,\"gid\":%u,\"ruid\":%u,\"rgid\":%u,\"sandboxed\":%s,\"descriptors\":[",
    before.bsd.pbi_uid, before.bsd.pbi_gid, before.bsd.pbi_ruid, before.bsd.pbi_rgid, sandboxed ? "true" : "false");
  unsigned mask = 0;
  for (unsigned i = 0; i < (unsigned)size / sizeof(fds[0]); i++) {
    need(fds[i].proc_fd >= 0 && fds[i].proc_fd < 3 && !(mask & (1U << fds[i].proc_fd)));
    mask |= 1U << fds[i].proc_fd;
    need(fds[i].proc_fdtype == PROX_FDTYPE_VNODE || fds[i].proc_fdtype == PROX_FDTYPE_PIPE);
    if (i) putchar(','); printf("{\"fd\":%d,\"type\":\"%s\"}", fds[i].proc_fd,
      fds[i].proc_fdtype == PROX_FDTYPE_VNODE ? "vnode" : "pipe");
  }
  need(mask == 7); after = inspect(pid);
  need(!memcmp(&before.token, &after.token, sizeof(before.token)) &&
    before.bsd.pbi_start_tvsec == after.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == after.bsd.pbi_start_tvusec);
  fputs("]}", stdout);
}
/* Finite case setup lives in this same sealed owner. Every destination is a
 * pinned-plan slot under one context-derived, exclusively created private root. */
static struct entry *unopened(const char *text) {
  unsigned index = number(text); need(index < count && entries[index].fd < 0); return &entries[index];
}
struct case_accounts { unsigned uid_accounts, primary_members, gid_groups; };
static struct case_accounts case_account(void) {
  reservation_guard();
#ifndef NATIVE_CI_EXPERIMENT
  struct passwd *pw = getpwuid(subject_uid); struct group *gr = getgrgid(subject_gid);
  char home[PATH_MAX]; need(snprintf(home, sizeof(home), "%s/storage/work", case_path) < sizeof(home));
  need(pw);
  need(gr);
  need(pw->pw_uid == subject_uid);
  need(pw->pw_gid == subject_gid);
  need(gr->gr_gid == subject_gid);
  need(!strcmp(pw->pw_shell, "/usr/bin/false"));
  need(!strcmp(pw->pw_passwd, "*"));
  need(!strcmp(pw->pw_dir, home));
  need(gr->gr_mem);
  need(!gr->gr_mem[0]);
  gid_t groups[2]; int count = 2;
  need(getgrouplist(pw->pw_name, subject_gid, groups, &count) >= 0);
  need(count == 1);
  need(groups[0] == subject_gid);
#endif
  /* gr_mem omits primary membership. Enumerate both namespaces so another
   * login or group alias cannot acquire the reserved numeric authority. */
  struct case_accounts accounts = {0}; setpwent();
  for (unsigned scanned = 0;; scanned++) {
    errno = 0; struct passwd *value = getpwent(); if (!value) { need(!errno); break; } need(scanned < 4096);
    if (value->pw_uid == subject_uid) {
#ifndef NATIVE_CI_EXPERIMENT
      need(value->pw_gid == subject_gid);
#endif
      accounts.uid_accounts++;
    }
    if (value->pw_gid == subject_gid) {
#ifndef NATIVE_CI_EXPERIMENT
      need(value->pw_uid == subject_uid);
#endif
      accounts.primary_members++;
    }
  } endpwent();
  setgrent();
  for (unsigned scanned = 0;; scanned++) {
    errno = 0; struct group *value = getgrent(); if (!value) { need(!errno); break; } need(scanned < 4096);
    if (value->gr_gid == subject_gid) {
#ifndef NATIVE_CI_EXPERIMENT
      need(value->gr_mem && !value->gr_mem[0]);
#endif
      accounts.gid_groups++;
    }
  } endgrent();
  const unsigned expected =
#ifdef NATIVE_CI_EXPERIMENT
    0;
#else
    1;
#endif
  bool exclusive = accounts.uid_accounts == expected && accounts.primary_members == expected && accounts.gid_groups == expected;
  if (!exclusive) fprintf(stderr, "native-darwin-case-accounts expected=%u uidAccounts=%u primaryGroupMembers=%u gidGroups=%u\n",
    expected, accounts.uid_accounts, accounts.primary_members, accounts.gid_groups);
  need(exclusive); return accounts;
}
static bool git_path(const char *suffix, bool dir) {
  if (dir && (!strcmp(suffix, "/storage/hooks") || !strcmp(suffix, "/storage/control-hooks"))) return true;
  const char *roots[] = {"/storage/metadata", "/storage/control"};
  for (unsigned i = 0; i < 2; i++) {
    size_t length = strlen(roots[i]); if (strncmp(suffix, roots[i], length)) continue;
    const char *name = suffix + length;
    if (dir) {
      if (!*name || !strcmp(name, "/hooks") || !strcmp(name, "/refs") || !strcmp(name, "/refs/heads") || !strcmp(name, "/objects") || !strcmp(name, "/logs") || !strcmp(name, "/logs/refs") || !strcmp(name, "/logs/refs/heads")) return true;
      if (!strncmp(name, "/objects/", 9) && strlen(name + 9) == 2 && strspn(name + 9, "0123456789abcdef") == 2) return true;
    } else {
      if (!strcmp(name, "/HEAD") || !strcmp(name, "/config") || !strcmp(name, "/index") || !strcmp(name, "/refs/heads/proof")) return true;
      if (!strncmp(name, "/objects/", 9) && strlen(name + 9) == 41 && name[11] == '/' && strspn(name + 9, "0123456789abcdef/") == 41) return true;
    }
  } return false;
}
static void case_directory(struct entry *entry) {
  need(case_mode); reservation_guard(); no_subjects();
  const char *suffix = entry->path + strlen(case_path);
  need(!strncmp(entry->path, case_path, strlen(case_path)));
  bool root = !*suffix, custody = !strcmp(suffix, "/custody") || !strcmp(suffix, "/custody/files"), storage = !strcmp(suffix, "/storage"), work = !strcmp(suffix, "/storage/work");
#ifdef NATIVE_CI_EXPERIMENT
  custody = custody || !strcmp(suffix, "/custody/aliases");
#endif
  need((root && !case_started && !strcmp(entry->kind, "directory")) ||
    (case_started && (custody || storage || work || (count > CASE_BASE_COUNT &&
      (!strcmp(suffix, "/custody/files") || git_path(suffix, true) || !strcmp(suffix, "/storage/control-work") || !strcmp(suffix, "/checkout") || !strcmp(suffix, "/configuration") ||
       !strcmp(suffix, "/credentials") || !strcmp(suffix, "/outside") || !strcmp(suffix, "/storage/work.replacement")))) && !strcmp(entry->kind, "authority")));
  case_account();
  char parent[PATH_MAX]; strcpy(parent, entry->path); char *leaf = strrchr(parent, '/'); need(leaf); *leaf++ = 0;
  char canonical[PATH_MAX]; need(realpath(parent, canonical) && !strcmp(parent, canonical));
  int base = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat st;
  need(base >= 0 && !fstat(base, &st) && S_ISDIR(st.st_mode) && !(st.st_mode & 022)); no_acl(base); file_capabilities(base);
  if (root) need(st.st_uid == 0 && st.st_gid == 0 && (st.st_mode & 07777) == 0711);
  else {
    unsigned matched = 0; for (unsigned i = 0; i < count; i++) if (entries[i].fd >= 0 && !strcmp(entries[i].path, parent)) {
      stable(&entries[i]); need(st.st_dev == entries[i].stat.st_dev && st.st_ino == entries[i].stat.st_ino); matched++;
    } need(matched == 1);
  }
  need(!mkdirat(base, leaf, 0700)); entry->fd = openat(base, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(entry->fd >= 0 && !fchown(entry->fd, work ? subject_uid : 0, custody ? 0 : subject_gid) &&
    !fchmod(entry->fd, (root || storage || (count > CASE_BASE_COUNT && !custody && !work)) ? 0710 : 0700) && !fstat(entry->fd, &entry->stat));
  need(!fstatat(base, leaf, &st, AT_SYMLINK_NOFOLLOW)); same_stat(st, entry->stat); no_acl(entry->fd); file_capabilities(entry->fd);
  need(!close(base)); if (root) case_started = true; stable(entry); identity(entry);
}
static void case_copy(struct entry *target, struct entry *source) {
  need(case_mode && case_started); reservation_guard(); no_subjects(); stable(source); if (!experiment_installed_path(source->path)) no_acl(source->fd); file_capabilities(source->fd);
  const char *suffix = target->path + strlen(case_path);
  need(!strncmp(target->path, case_path, strlen(case_path)));
  bool policy = !strcmp(suffix, "/custody/policy") || (count > CASE_BASE_COUNT &&
    (!strcmp(suffix, "/custody/darwin-pf.conf") || !strcmp(suffix, "/custody/darwin-pf-before.conf") || !strcmp(suffix, "/custody/access-cases") || !strncmp(suffix, "/custody/git-policy-", 19))), executable = !strcmp(suffix, "/custody/launcher") || !strcmp(suffix, "/storage/payload") ||
#ifdef NATIVE_CI_EXPERIMENT
    !strcmp(suffix, "/storage/exec-control") ||
#endif
    (count > CASE_BASE_COUNT && (!strcmp(suffix, "/custody/pfctl") || !strcmp(suffix, "/custody/observer") || !strcmp(suffix, "/custody/git-executor") || !strcmp(suffix, "/storage/git")));
  bool git_data = !strcmp(suffix, "/outside/sentinel") || git_path(suffix, false) || !strcmp(suffix, "/storage/work/.git") || !strcmp(suffix, "/storage/work/content.txt") || !strcmp(suffix, "/storage/control-work/.git") || !strcmp(suffix, "/storage/control-work/content.txt");
  need(((policy || git_data) && !strcmp(target->kind, "data") && !strcmp(source->kind, "data")) ||
    (executable && (!strcmp(target->kind, "image") || !strcmp(target->kind, "helper")) && (!strcmp(source->kind, "image") || !strcmp(source->kind, "helper"))));
  need(strcmp(source->path, target->path) && !strncmp(source->pin, target->pin, 65) &&
    (experiment_installed_path(source->path) || (source->stat.st_uid == 0 && source->stat.st_gid == 0 && !(source->stat.st_mode & 022))) && S_ISREG(source->stat.st_mode) && source->stat.st_size > 0 && source->stat.st_size <= 134217728);
  char parent[PATH_MAX]; strcpy(parent, target->path); char *leaf = strrchr(parent, '/'); need(leaf); *leaf++ = 0;
  struct entry *base = NULL; for (unsigned i = 0; i < count; i++) if (entries[i].fd >= 0 && !strcmp(entries[i].path, parent)) base = &entries[i];
  need(base); stable(base); int writer = openat(base->fd, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); need(writer >= 0);
  unsigned char bytes[65536]; for (uint64_t offset = 0; offset < (uint64_t)source->stat.st_size;) {
    size_t size = (uint64_t)source->stat.st_size - offset > sizeof(bytes) ? sizeof(bytes) : (size_t)((uint64_t)source->stat.st_size - offset);
    read_at(source->fd, bytes, size, offset); size_t done = 0;
    while (done < size) { ssize_t n = write(writer, bytes + done, size - done); if (n < 0 && errno == EINTR) continue; need(n > 0); done += n; } offset += size;
  }
  struct stat written; need(!fchown(writer, git_data && (!strncmp(suffix, "/storage/work/", 14) || !strncmp(suffix, "/storage/control-work/", 22)) ? subject_uid : 0, policy || strncmp(suffix, "/custody/", 9) == 0 ? 0 : subject_gid) && !fchmod(writer, policy ? 0400 : git_data ? (git_path(suffix, false) ? 0440 : 0400) : 0550) && !fsync(writer) && !fstat(writer, &written) && !close(writer));
  target->fd = openat(base->fd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); need(target->fd >= 0 && !fstat(target->fd, &target->stat)); same_stat(written, target->stat);
  need(target->stat.st_nlink == 1); no_acl(target->fd); file_capabilities(target->fd);
  char hash[65]; sha_range(target->fd, 0, target->stat.st_size, hash); need(!strcmp(hash, target->pin)); stable(source); stable(target); identity(target);
}
#ifdef NATIVE_CI_EXPERIMENT
static void case_exec_control(const char *cdhash) {
  need(experiment_exec && case_mode && !case_fenced && count >= CASE_BASE_COUNT && !case_pid);
  struct entry *target = &entries[12], *base = &entries[11], source = {.fd = -1};
  char expected[PATH_MAX];
  need(snprintf(expected, sizeof(expected), "%s/storage/exec-control", case_path) < sizeof(expected) && !strcmp(target->path, expected));
  stable(base); need(base->stat.st_uid == 0 && base->stat.st_gid == 0 && (base->stat.st_mode & 07777) == 0555);
  need(snprintf(source.path, sizeof(source.path), "%s/argv-fixture", base->path) < sizeof(source.path));
  strcpy(source.kind, "image"); strcpy(source.pin, target->pin);
  free(file(source.path, 0, 0555, 134217728, source.pin, &source.stat));
  source.fd = open(source.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); need(source.fd >= 0); stable(&source);
  signature(source.path, cdhash); no_acl(source.fd);
  fputs("{\"object\":", stdout); case_copy(target, &source);
  signature(target->path, cdhash); fputs(",\"sourceMacho\":", stdout); image(&source);
  fputs(",\"macho\":", stdout); image(target); putchar('}');
  stable(base); stable(&source); need(!close(source.fd));
  memcpy(image_control_cdhash, cdhash, 41); image_control = true; image_control_retired = image_probed = false;
}
#endif
static void case_rejoin(struct entry *entry) {
  need(case_mode);
  /* Fenced recovery may only read the original root/custody and signed images
   * before acquiring the lease still held by an interrupted reader. */
  bool handoff = case_fenced && reservation_fd < 0 &&
    (entry == &entries[0] || entry == &entries[1] || entry == &entries[4] || entry == &entries[5]
#ifdef NATIVE_CI_EXPERIMENT
      || (experiment_exec && entry == &entries[12])
#endif
    );
  if (!handoff) { reservation_guard(); if (!case_recovery) no_subjects(); }
  size_t length = strlen(case_path); need(!strncmp(entry->path, case_path, length) && (!entry->path[length] || entry->path[length] == '/'));
  bool dir = !strcmp(entry->kind, "directory") || !strcmp(entry->kind, "authority");
  entry->fd = open(entry->path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (dir ? O_DIRECTORY : 0));
  need(entry->fd >= 0 && !fstat(entry->fd, &entry->stat) &&
    (entry->stat.st_uid == 0 || entry->stat.st_uid == subject_uid) && (entry->stat.st_gid == 0 || entry->stat.st_gid == subject_gid) && !(entry->stat.st_mode & 022));
  need(dir ? S_ISDIR(entry->stat.st_mode) : S_ISREG(entry->stat.st_mode) && entry->stat.st_nlink == 1 && entry->stat.st_size > 0 && entry->stat.st_size <= 134217728);
  no_acl(entry->fd); file_capabilities(entry->fd); if (!dir) { char hash[65]; sha_range(entry->fd, 0, entry->stat.st_size, hash); need(!strcmp(hash, entry->pin)); }
  if (!entry->path[length]) { case_started = true; case_recovery = true; } stable(entry); identity(entry);
}
#ifdef NATIVE_CI_EXPERIMENT
/* Private write-ahead PF custody. The baseline is immutable; fixed-size records
 * append intent before each ioctl and completion afterward. A torn append or a
 * lost token publication retains exclusion, never guesses an enable reference. */
struct pf_baseline {
  unsigned version; char context[65]; struct identity owner;
  unsigned rules, anchors, interfaces;
  struct pfioc_rule rule[64]; struct pf_generation generation[64];
  struct pfi_kif interface[128]; char routes[65]; bool active;
};
struct pf_step { unsigned phase; uint64_t token; struct pfioc_token reference; struct identity writer; bool changed; };
enum { PF_SEED, PF_ENABLE_POSSIBLE, PF_ENABLED, PF_ATTACH_POSSIBLE,
  PF_ATTACHED, PF_SKIP_POSSIBLE, PF_READY, PF_REMOVE_POSSIBLE, PF_REMOVED,
  PF_FLAGS_POSSIBLE, PF_FLAGS_RESTORED, PF_RELEASE_POSSIBLE, PF_DONE };
static struct pf_baseline pf_baseline;
static struct pf_step pf_step;
static bool pf_attachment_changed;
static struct pfioc_token pf_owned_reference;
static int pf_journal = -1;
static struct stat pf_journal_identity;
static void pf_journal_guard(void) {
  struct stat held, named; need(pf_journal >= 0 && !fstat(pf_journal, &held) &&
    !fstatat(entries[1].fd, "pf-reference", &named, AT_SYMLINK_NOFOLLOW)); same_stat(held, named);
  need(held.st_dev == pf_journal_identity.st_dev && held.st_ino == pf_journal_identity.st_ino &&
    S_ISREG(held.st_mode) && (held.st_mode & 07777) == 0400 && !held.st_uid && !held.st_gid && held.st_nlink == 1);
  no_acl(pf_journal); stable(&entries[1]); reservation_guard();
}
static void pf_record(unsigned phase) {
  pf_journal_guard(); pf_step.phase = phase; pf_step.token = pf_enable_token; pf_step.reference = pf_owned_reference; pf_step.writer = inspect(getpid()); pf_step.changed = pf_attachment_changed;
  need(lseek(pf_journal, 0, SEEK_END) >= 0 && write(pf_journal, &pf_step, sizeof(pf_step)) == sizeof(pf_step) && !fsync(pf_journal)); pf_journal_guard();
}
static bool pf_owned(const char *anchor) { return !strcmp(anchor, "native-poc") || !strncmp(anchor, "native-poc/", 11); }
static bool pf_attachment(const struct pfioc_rule *r) { return !*r->anchor && !strcmp(r->anchor_call, "native-poc/*"); }
static void pf_position(struct pfioc_rule *r) {
  r->ticket = r->nr = 0;
  if (!*r->anchor && r->rule.action == PF_PASS) { r->rule.nr = 0; memset(r->rule.skip, 0, sizeof(r->rule.skip)); }
}
static unsigned pf_preserved(void) {
  unsigned old = 0, attached = 0;
  need(pf_baseline.rules <= 64 && pf_baseline.anchors <= 64 && pf_baseline.interfaces < 128);
  /* Retain the original route observation, without requiring host routes to
   * rewind before independently verified retirement can restore owned PF. */
  need(strnlen(pf_baseline.routes, sizeof(pf_baseline.routes)) == 64 && strspn(pf_baseline.routes, "0123456789abcdef") == 64);
  for (unsigned i = 0; i < pf_read_rule_count; i++) {
    struct pfioc_rule current = pf_read_rules[i];
    if (pf_owned(current.anchor)) { need(0); } /* private rules must retire first */
    if (pf_attachment(&current)) {
      need(++attached == 1 && current.rule.nr == 0 && current.rule.action == PF_PASS && current.rule.quick && !current.rule.keep_state &&
        !current.rule.direction && !*current.rule.ifname && !current.rule.af && !current.rule.proto && !current.rule.uid.op &&
        !current.rule.src.xport.range.op && !current.rule.dst.xport.range.op);
      continue;
    }
    need(old < pf_baseline.rules); struct pfioc_rule original = pf_baseline.rule[old++];
    pf_position(&current); pf_position(&original); need(!memcmp(&current, &original, sizeof(current)));
  }
  need(old == pf_baseline.rules && pf_interface_count == pf_baseline.interfaces);
  for (unsigned i = 0; i < pf_interface_count; i++) {
    struct pfi_kif *a = &pf_interfaces[i], *b = &pf_baseline.interface[i];
    need(!strcmp(a->pfik_name, b->pfik_name) && (a->pfik_flags == b->pfik_flags ||
      (!strcmp(a->pfik_name, "lo0") && a->pfik_flags == (b->pfik_flags & ~PFI_IFLAG_SKIP))));
  }
  unsigned foreign = 0;
  for (unsigned i = 0; i < pf_anchors; i++) if (!pf_owned(pf_generations[i].anchor)) {
    need(foreign < pf_baseline.anchors); struct pf_generation *a = &pf_generations[i], *b = &pf_baseline.generation[foreign++];
    need(!strcmp(a->anchor, b->anchor));
    for (unsigned set = 0; set < PF_RULESET_MAX; set++) if (*a->anchor || set != PF_RULESET_FILTER)
      need(a->tickets[set] == b->tickets[set] && a->counts[set] == b->counts[set]);
    unsigned child = 0;
    for (unsigned n = 0; n < a->children; n++) if (*a->anchor || strcmp(a->names[n], "native-poc")) {
      need(child < b->children && !strcmp(a->names[n], b->names[child++]));
    }
    need(child == b->children);
  }
  need(foreign == pf_baseline.anchors); return attached;
}
static bool pf_token_present(int pf, bool acquiring) {
  struct pfioc_token tokens[128], confirmed[128]; struct pfioc_tokens query = {0};
  errno = 0; int result = ioctl(pf, DIOCGETSTARTERS, &query);
  if (result < 0) { need(errno == ENOENT); return false; } /* source-defined empty inventory */
  need(query.size > 0 && query.size < sizeof(tokens) && query.size % sizeof(tokens[0]) == 0);
  int size = query.size; query.size = sizeof(tokens); query.buffer.buf = (caddr_t)tokens;
  need(!ioctl(pf, DIOCGETSTARTERS, &query) && query.size == size); unsigned matches = 0;
  for (unsigned i = 0; i < (unsigned)size / sizeof(tokens[0]); i++) {
    need(tokens[i].token_value == pf_enable_token && tokens[i].pid == (pid_t)pf_baseline.owner.token.val[5]);
    if (acquiring) {
      need(!i && pf_step.phase == PF_ENABLE_POSSIBLE && !pf_owned_reference.token_value && tokens[i].timestamp &&
        strnlen(tokens[i].proc_name, sizeof(tokens[i].proc_name)) < sizeof(tokens[i].proc_name)); pf_owned_reference = tokens[i];
    } else need(!memcmp(&tokens[i], &pf_owned_reference, sizeof(tokens[i])));
    matches++;
  }
  query.size = sizeof(confirmed); query.buffer.buf = (caddr_t)confirmed;
  need(!ioctl(pf, DIOCGETSTARTERS, &query) && query.size == size && !memcmp(tokens, confirmed, size));
  query.size = 0; need(!ioctl(pf, DIOCGETSTARTERS, &query) && query.size == size);
  need(matches <= 1); return matches == 1;
}
/* Advance only the root filter generation that our conditional change owns.
 * Every foreign generation and child remains pinned throughout the write. */
static void pf_changed(int pf, bool attached) {
  struct pf_generation *root = &pf_generations[0], children = {0}; need(!*root->anchor);
  struct pfioc_rule query = {0}; query.rule.action = PF_PASS;
  need(!ioctl(pf, DIOCGETRULES, &query) && query.ticket == root_tickets[PF_RULESET_FILTER] + 1 &&
    query.nr == root_counts[PF_RULESET_FILTER] + (attached ? 1 : -1));
  root_tickets[PF_RULESET_FILTER] = root->tickets[PF_RULESET_FILTER] = query.ticket;
  root_counts[PF_RULESET_FILTER] = root->counts[PF_RULESET_FILTER] = query.nr;
  pf_children(pf, &children, false); unsigned foreign = 0, owned = 0;
  for (unsigned n = 0; n < children.children; n++) {
    if (!strcmp(children.names[n], "native-poc")) { owned++; continue; }
    while (foreign < root->children && !strcmp(root->names[foreign], "native-poc")) foreign++;
    need(foreign < root->children && !strcmp(children.names[n], root->names[foreign++]));
  }
  while (foreign < root->children && !strcmp(root->names[foreign], "native-poc")) foreign++;
  need(foreign == root->children && owned == (attached ? 1 : 0));
  root->children = children.children; memcpy(root->names, children.names, sizeof(root->names));
  unsigned kept = 0;
  for (unsigned n = 0; n < pf_anchors; n++) if (!pf_owned(pf_generations[n].anchor)) pf_generations[kept++] = pf_generations[n];
  pf_anchors = kept;
  if (attached) {
    need(pf_anchors < 64); struct pf_generation *node = &pf_generations[pf_anchors++]; memset(node, 0, sizeof(*node)); strcpy(node->anchor, "native-poc");
    pf_children(pf, node, false); need(!node->children);
    for (unsigned set = 0; set < PF_RULESET_MAX; set++) {
      struct pfioc_rule rule = {0}; strcpy(rule.anchor, node->anchor); rule.rule.action = pf_action(set);
      need(!ioctl(pf, DIOCGETRULES, &rule) && !rule.nr); node->tickets[set] = rule.ticket;
    }
  }
  pf_observation_guard(pf);
}
static void pf_lifecycle_recover(void) {
  need(case_mode && case_started && case_recovery && pf_journal < 0); reservation_guard(); no_subjects(); stable(&entries[1]);
  pf_journal = openat(entries[1].fd, "pf-reference", O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  need(pf_journal >= 0 && !fstat(pf_journal, &pf_journal_identity)); pf_journal_guard(); file_capabilities(pf_journal);
  off_t bytes = pf_journal_identity.st_size;
  need(bytes >= sizeof(pf_baseline) + sizeof(pf_step) && bytes <= sizeof(pf_baseline) + 64 * sizeof(pf_step) &&
    (bytes - sizeof(pf_baseline)) % sizeof(pf_step) == 0);
  read_at(pf_journal, &pf_baseline, sizeof(pf_baseline), 0); need(pf_baseline.version == 2 && !memcmp(pf_baseline.context, case_context, 65) && !pf_baseline.active);
  unsigned previous = PF_SEED; uint64_t token = 0; bool changed = false; struct pfioc_token reference = {0};
  for (off_t at = sizeof(pf_baseline); at < bytes; at += sizeof(pf_step)) {
    read_at(pf_journal, &pf_step, sizeof(pf_step), at);
    need(pf_step.phase <= PF_DONE && (at == sizeof(pf_baseline) ? pf_step.phase == PF_SEED :
      pf_step.phase == previous + 1 ||
      (previous <= PF_READY && (pf_step.phase == PF_REMOVE_POSSIBLE || pf_step.phase == PF_REMOVED)) ||
      (pf_step.phase == previous && (previous == PF_REMOVE_POSSIBLE || previous == PF_FLAGS_POSSIBLE || previous == PF_RELEASE_POSSIBLE))));
    need(pf_step.phase < PF_ENABLED ? !pf_step.token :
      pf_step.phase <= PF_READY ? pf_step.token && (!token || pf_step.token == token) : pf_step.token == token);
    need((!changed || pf_step.changed) && (!pf_step.changed || changed || pf_step.phase == PF_ATTACHED || pf_step.phase == PF_REMOVE_POSSIBLE) &&
      (pf_step.phase < PF_ATTACHED || pf_step.phase > PF_READY || pf_step.changed)); changed = pf_step.changed;
    if (!token && pf_step.token) {
      need(pf_step.reference.token_value == pf_step.token && pf_step.reference.pid == (pid_t)pf_baseline.owner.token.val[5] &&
        pf_step.reference.timestamp && strnlen(pf_step.reference.proc_name, sizeof(pf_step.reference.proc_name)) < sizeof(pf_step.reference.proc_name)); reference = pf_step.reference;
    }
    need(!memcmp(&reference, &pf_step.reference, sizeof(reference)));
    token = pf_step.token; previous = pf_step.phase;
    struct proc_bsdinfo original; errno = 0;
    need(pf_step.writer.token.val[1] == 0 && pf_step.writer.token.val[5] > 1 && pf_step.writer.token.val[6] > 0 &&
      pf_step.writer.bsd.pbi_start_tvsec > 0 && proc_pidinfo(pf_step.writer.token.val[5], PROC_PIDTBSDINFO, 0, &original, sizeof(original)) == 0 &&
      (errno == ESRCH || errno == ENOENT) && root_members(pf_step.writer.token.val[6], false) == 0);
    if (at == sizeof(pf_baseline)) need(!memcmp(&pf_step.writer.token, &pf_baseline.owner.token, sizeof(pf_step.writer.token)) &&
      pf_step.writer.bsd.pbi_start_tvsec == pf_baseline.owner.bsd.pbi_start_tvsec && pf_step.writer.bsd.pbi_start_tvusec == pf_baseline.owner.bsd.pbi_start_tvusec);
  }
  /* A missing enable result cannot authorize adoption, even when PF is off. */
  need(pf_step.phase != PF_ENABLE_POSSIBLE);
  pf_attachment_changed = pf_step.changed; pf_owned_reference = reference;
  pf_enable_token = pf_step.phase == PF_DONE ? 0 : pf_step.token;
  struct stat after; need(!fstat(pf_journal, &after)); same_stat(pf_journal_identity, after);
  pf_journal_guard(); fputs("{\"held\":true}", stdout);
}
static void pf_lifecycle_write(bool installing) {
  need(case_mode && case_started && pf_observed); no_subjects(); reservation_guard();
  stable(&entries[1]); need(!entries[1].stat.st_uid && !entries[1].stat.st_gid && (entries[1].stat.st_mode & 07777) == 0700);
  int pf = open("/dev/pf", O_RDWR | O_CLOEXEC); need(pf >= 0); pf_observation_guard(pf);
  if (installing) {
    need(!case_recovery && pf_journal < 0 && !pf_active);
    memset(&pf_baseline, 0, sizeof(pf_baseline)); pf_baseline.version = 2; strcpy(pf_baseline.context, case_context); pf_baseline.owner = inspect(getpid());
    pf_baseline.rules = pf_read_rule_count; memcpy(pf_baseline.rule, pf_read_rules, sizeof(pf_read_rules));
    pf_baseline.anchors = pf_anchors; memcpy(pf_baseline.generation, pf_generations, sizeof(pf_generations));
    pf_baseline.interfaces = pf_interface_count; memcpy(pf_baseline.interface, pf_interfaces, sizeof(pf_interfaces)); strcpy(pf_baseline.routes, pf_routes);
    for (unsigned i = 0; i < pf_anchors; i++) need(!pf_owned(pf_generations[i].anchor));
    need(!pf_token_present(pf, false));
    pf_journal = openat(entries[1].fd, "pf-reference", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
    need(pf_journal >= 0 && !fstat(pf_journal, &pf_journal_identity)); no_acl(pf_journal);
    need(write(pf_journal, &pf_baseline, sizeof(pf_baseline)) == sizeof(pf_baseline) && !fsync(pf_journal) && !fsync(entries[1].fd)); pf_record(PF_SEED);
    pf_record(PF_ENABLE_POSSIBLE); need(!ioctl(pf, DIOCSTARTREF, &pf_enable_token) && pf_enable_token && pf_token_present(pf, true)); pf_record(PF_ENABLED);
    pf_active = true; pf_observation_guard(pf);
    pf_record(PF_ATTACH_POSSIBLE);
    struct pfioc_pooladdr pool = {0}; need(!ioctl(pf, DIOCBEGINADDRS, &pool));
    pf_observation_guard(pf);
    struct pfioc_rule add = {0}; add.action = PF_CHANGE_ADD_HEAD; add.ticket = root_tickets[PF_RULESET_FILTER]; add.pool_ticket = pool.ticket;
    add.rule.action = PF_PASS; add.rule.quick = 1; strcpy(add.anchor_call, "native-poc/*");
    need(!ioctl(pf, DIOCCHANGERULE, &add)); pf_attachment_changed = true; pf_record(PF_ATTACHED); pf_changed(pf, true);
    pf_record(PF_SKIP_POSSIBLE);
    struct pfioc_iface loopback = {0}; strcpy(loopback.pfiio_name, "lo0"); loopback.pfiio_flags = PFI_IFLAG_SKIP;
    need(!ioctl(pf, DIOCCLRIFFLAG, &loopback));
    for (unsigned i = 0; i < pf_interface_count; i++) if (!strcmp(pf_interfaces[i].pfik_name, "lo0")) pf_interfaces[i].pfik_flags &= ~PFI_IFLAG_SKIP;
    pf_observation_guard(pf); pf_record(PF_READY);
  } else {
    need(pf_journal >= 0); unsigned attached = pf_preserved();
    uint32_t expected_ticket = pf_baseline.generation[0].tickets[PF_RULESET_FILTER] + (attached ? 1 : pf_attachment_changed ? 2 : 0);
    need(root_tickets[PF_RULESET_FILTER] == expected_ticket);
    need((pf_step.phase != PF_SEED || (!attached && !pf_active && !pf_enable_token)) &&
      (pf_step.phase < PF_ENABLED || pf_step.phase >= PF_REMOVE_POSSIBLE || pf_active) &&
      (pf_step.phase < PF_ATTACHED || pf_step.phase >= PF_REMOVE_POSSIBLE || attached) &&
      (pf_step.phase < PF_REMOVED || !attached));
    if (pf_step.phase >= PF_FLAGS_RESTORED) for (unsigned i = 0; i < pf_interface_count; i++)
      need(pf_interfaces[i].pfik_flags == pf_baseline.interface[i].pfik_flags);
    if (pf_step.phase == PF_DONE) { need(!attached && !pf_active && !pf_enable_token); }
    else {
      need(pf_step.phase != PF_ENABLE_POSSIBLE);
      if (attached) {
        pf_attachment_changed = true;
        pf_record(PF_REMOVE_POSSIBLE); struct pfioc_rule remove = {0}; remove.action = PF_CHANGE_REMOVE;
        remove.ticket = root_tickets[PF_RULESET_FILTER]; remove.rule.action = PF_PASS; remove.nr = 0;
        need(!ioctl(pf, DIOCCHANGERULE, &remove)); pf_changed(pf, false);
      }
      if (pf_step.phase < PF_REMOVED) pf_record(PF_REMOVED);
      if (pf_step.phase < PF_FLAGS_RESTORED) {
        pf_record(PF_FLAGS_POSSIBLE);
        for (unsigned i = 0; i < pf_baseline.interfaces; i++) if (!strcmp(pf_baseline.interface[i].pfik_name, "lo0") &&
          pf_interfaces[i].pfik_flags != pf_baseline.interface[i].pfik_flags) {
          struct pfioc_iface loopback = {0}; strcpy(loopback.pfiio_name, "lo0"); loopback.pfiio_flags = PFI_IFLAG_SKIP;
          need(!ioctl(pf, pf_baseline.interface[i].pfik_flags & PFI_IFLAG_SKIP ? DIOCSETIFFLAG : DIOCCLRIFFLAG, &loopback));
          pf_interfaces[i].pfik_flags = pf_baseline.interface[i].pfik_flags;
        }
        pf_record(PF_FLAGS_RESTORED);
      }
      pf_observation_guard(pf);
      bool present = pf_token_present(pf, false);
      need(present || !pf_enable_token || pf_step.phase == PF_RELEASE_POSSIBLE);
      pf_record(PF_RELEASE_POSSIBLE);
      if (present) { struct pfioc_remove_token release = {.token_value = pf_enable_token}; need(!ioctl(pf, DIOCSTOPREF, &release) && !release.refcount); }
      pf_active = pf_baseline.active; pf_observation_guard(pf);
      need(!pf_token_present(pf, false)); pf_record(PF_DONE); pf_enable_token = 0;
    }
  }
  need(!close(pf));
}
static void pf_restored_guard(void) {
  if (pf_journal < 0) { need(!case_policy_possible); return; }
  need(pf_step.phase == PF_DONE && !pf_enable_token && !pf_active && !pf_preserved()); pf_journal_guard();
  for (unsigned i = 0; i < pf_interface_count; i++) need(pf_interfaces[i].pfik_flags == pf_baseline.interface[i].pfik_flags);
  int pf = open("/dev/pf", O_RDONLY | O_CLOEXEC); need(pf >= 0); pf_observation_guard(pf); need(!pf_token_present(pf, false) && !close(pf));
}
#endif
/* The reference is born inside held root custody before a root-policy write.
 * Recovery reads it independently; no caller can choose a global PF token. */
static void pf_reference(bool recovering) {
#ifdef NATIVE_CI_EXPERIMENT
  need(recovering); pf_lifecycle_recover();
#else
  need(case_mode && case_started && (!recovering || case_recovery)); reservation_guard(); no_subjects();
  struct entry *custody = &entries[1]; stable(custody); need(custody->stat.st_uid == 0 && custody->stat.st_gid == 0 && (custody->stat.st_mode & 07777) == 0700);
  char bytes[96]; int length = snprintf(bytes, sizeof(bytes), "%.64s %llu\n", case_context, (unsigned long long)pf_enable_token); need(length > 0 && length < sizeof(bytes));
  if (!recovering) {
    int writer = openat(custody->fd, "pf-reference", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400); need(writer >= 0); no_acl(writer);
    need(write(writer, bytes, length) == length && !fsync(writer) && !close(writer) && !fsync(custody->fd));
  }
  int fd = openat(custody->fd, "pf-reference", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); struct stat held, named, after;
  need(fd >= 0 && !fstat(fd, &held) && S_ISREG(held.st_mode) && held.st_uid == 0 && held.st_gid == 0 && (held.st_mode & 07777) == 0400 && held.st_nlink == 1 && held.st_size > 66 && held.st_size < sizeof(bytes)); no_acl(fd); file_capabilities(fd);
  read_at(fd, bytes, held.st_size, 0); bytes[held.st_size] = 0; need(!memcmp(bytes, case_context, 64) && bytes[64] == ' ' && bytes[65] >= '0' && bytes[65] <= '9');
  char *end; errno = 0; unsigned long long token = strtoull(bytes + 65, &end, 10); need(!errno && !strcmp(end, "\n"));
  need(!fstat(fd, &after)); same_stat(held, after); need(!fstatat(custody->fd, "pf-reference", &named, AT_SYMLINK_NOFOLLOW)); same_stat(held, named); need(!close(fd));
  if (recovering) { need(!pf_enable_token); pf_enable_token = token; fputs("{\"held\":true}", stdout); }
  else need(token == pf_enable_token);
#endif
}
static void case_endpoint(unsigned family, unsigned protocol, unsigned port) {
  need(case_mode && case_started && case_socket_count < 8 && (family == 4 || family == 6) && (protocol == 6 || protocol == 17) && port >= 1024 && port <= 65535);
  reservation_guard(); no_subjects(); int af = family == 4 ? AF_INET : AF_INET6;
  int handoff[2] = {-1, -1}; pid_t owner = 0;
  if (count > CASE_BASE_COUNT) {
    need(!socketpair(AF_UNIX, SOCK_STREAM, 0, handoff)); owner = fork(); need(owner >= 0);
    if (!owner) { need(!close(handoff[0]) && !setgroups(0, NULL) && !setgid(subject_gid) && !setuid(subject_uid)); }
  }
  int fd = owner > 0 ? -1 : socket(af, protocol == 6 ? SOCK_STREAM : SOCK_DGRAM, protocol);
  if (owner > 0) {
    need(!close(handoff[1])); char rights[CMSG_SPACE(sizeof(int))], flag; struct iovec io = {.iov_base = &flag, .iov_len = 1};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = rights, .msg_controllen = sizeof(rights)};
    need(recvmsg(handoff[0], &message, 0) == 1 && flag == 'F' && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    need(header && !CMSG_NXTHDR(&message, header) && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(int)));
    memcpy(&fd, CMSG_DATA(header), sizeof(fd)); int status;
    while (waitpid(owner, &status, 0) < 0) need(errno == EINTR);
    need(WIFEXITED(status) && WEXITSTATUS(status) == 0 && !close(handoff[0]));
    case_sockets[case_socket_count++] = fd; fputs("null", stdout); return;
  }
  need(fd >= 0 && !fcntl(fd, F_SETFD, FD_CLOEXEC));
  int reuse; socklen_t size = sizeof(reuse); need(!getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, &size) && !reuse);
  size = sizeof(reuse); need(!getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, &size) && !reuse);
  if (af == AF_INET) { struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)}; need(!bind(fd, (void *)&address, sizeof(address))); }
  else { int only = 1; need(!setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only))); struct sockaddr_in6 address = {.sin6_len = sizeof(address), .sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_LOOPBACK_INIT}; need(!bind(fd, (void *)&address, sizeof(address))); }
  /* Access endpoints are provisioned client then server for each pair. A TCP
   * client must remain bound, rather than becoming a listening socket. */
  if (protocol == 6 && (count == CASE_BASE_COUNT || case_socket_count % 2 == 1)) need(!listen(fd, 1));
  if (count > CASE_BASE_COUNT) {
    char rights[CMSG_SPACE(sizeof(int))] = {0}, flag = 'F'; struct iovec io = {.iov_base = &flag, .iov_len = 1};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = rights, .msg_controllen = sizeof(rights)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message); header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd)); need(sendmsg(handoff[1], &message, 0) == 1); _exit(0);
  }
  case_sockets[case_socket_count++] = fd; fputs("null", stdout);
}
static void case_read(void) {
  need(case_mode && case_started); reservation_guard(); struct case_accounts accounts = case_account();
  printf("{"
#ifdef NATIVE_CI_EXPERIMENT
    "\"purpose\":\"experiment\",\"accountVerified\":false,"
#else
    "\"accountVerified\":true,"
#endif
    "\"contextSha256\":\"%s\",\"uid\":%u,\"gid\":%u,\"accounts\":{\"uidAccounts\":%u,\"primaryGroupMembers\":%u,\"gidGroups\":%u},\"objects\":[",
    case_context, subject_uid, subject_gid, accounts.uid_accounts, accounts.primary_members, accounts.gid_groups);
  unsigned emitted = 0; for (unsigned i = 0; i < count; i++) if (entries[i].fd >= 0 && !strncmp(entries[i].path, case_path, strlen(case_path))) {
    stable(&entries[i]); no_acl(entries[i].fd); if (emitted++) putchar(','); printf("{\"index\":%u,\"object\":", i); identity(&entries[i]); putchar('}');
  }
  fputs("],\"endpoints\":[", stdout);
  for (unsigned i = 0; i < case_socket_count; i++) {
    struct sockaddr_storage address; socklen_t size = sizeof(address); int type; socklen_t type_size = sizeof(type);
    need(!getsockname(case_sockets[i], (void *)&address, &size) && !getsockopt(case_sockets[i], SOL_SOCKET, SO_TYPE, &type, &type_size));
    need(address.ss_family == AF_INET || address.ss_family == AF_INET6);
    need(type == SOCK_STREAM || type == SOCK_DGRAM);
    if (address.ss_family == AF_INET) need(((struct sockaddr_in *)&address)->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    else need(IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)&address)->sin6_addr));
    int reuse; socklen_t reuse_size = sizeof(reuse);
    need(!getsockopt(case_sockets[i], SOL_SOCKET, SO_REUSEADDR, &reuse, &reuse_size) && !reuse);
    reuse_size = sizeof(reuse); need(!getsockopt(case_sockets[i], SOL_SOCKET, SO_REUSEPORT, &reuse, &reuse_size) && !reuse);
    unsigned port = address.ss_family == AF_INET ? ntohs(((struct sockaddr_in *)&address)->sin_port) : ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    if (i) putchar(','); printf("{\"family\":\"%s\",\"protocol\":\"%s\",\"port\":%u}", address.ss_family == AF_INET ? "inet" : "inet6", type == SOCK_STREAM ? "tcp" : "udp", port);
  } fputs("]}", stdout);
}
/* Finite ownership operations. Privilege is checked here, at the executing
 * owner. No caller path, environment, executable or arbitrary command is used. */
static void case_child_failure(pid_t child, const char *operation, long result, int error, int revents, long used) {
  /* This turn is already fatal; a broken diagnostic pipe must not replace it. */
  (void)signal(SIGPIPE, SIG_IGN);
  struct proc_bsdinfo identity = {0}; siginfo_t status = {0};
  errno = 0; int identityResult = child > 0 ? proc_pidinfo(child, PROC_PIDTBSDINFO, 1, &identity, sizeof(identity)) : -1;
  int identityError = errno; errno = 0;
  int waitResult = child > 0 ? waitid(P_PID, (id_t)child, &status, WEXITED | WNOHANG | WNOWAIT) : -1;
  int waitError = errno;
  if (waitResult || status.si_pid != child) memset(&status, 0, sizeof(status));
  fprintf(stderr, "native-darwin-launch: owner=reader operation=%s result=%ld errno=%d revents=%d read=%ld launcher=%d identity-result=%d identity-errno=%d start-seconds=%llu start-micros=%llu wait-result=%d wait-errno=%d status-pid=%d status-code=%d status=%d\n",
    operation, result, error, revents, used, child, identityResult, identityError,
    identityResult == (int)sizeof(identity) ? (unsigned long long)identity.pbi_start_tvsec : 0,
    identityResult == (int)sizeof(identity) ? (unsigned long long)identity.pbi_start_tvusec : 0,
    waitResult, waitError, status.si_pid, status.si_code, status.si_status);
  fflush(stderr); errno = error; need(false);
}
static void case_launch_failure(const char *operation, long result, int error, int revents, long used) {
  case_child_failure(case_pid, operation, result, error, revents, used);
}
static void case_launch_check(const char *operation, int result) {
  if (result) case_launch_failure(operation, result, result < 0 ? errno : 0, 0, -1);
}
#ifdef NATIVE_CI_EXPERIMENT
static void case_spawn_refuse(struct domain_bootstrap_fork *out, pid_t child) {
  if (!out->count) return;
  (void)signal(SIGPIPE, SIG_IGN);
  for (unsigned i = 0; i < out->count; i++) if (out->issues[i].cleanup)
    fprintf(stderr, "native-darwin-launch-cleanup: owner=reader operation=%s result=%d errno=0\n", out->issues[i].operation, out->issues[i].value);
  struct domain_bootstrap_issue first = out->issues[0];
  case_child_failure(child, first.operation, first.value, 0, 0, -1);
}
#endif
static void case_start(const char *mode, const char *cdhash) {
  need(!case_fenced);
  need(case_mode && case_started && !case_pid && !case_recovery && (count == CASE_BASE_COUNT || !strcmp(mode, "access")));
  reservation_guard(); no_subjects(); case_account();
  const char *fixed[] = {"literal", "storage", "fork-exec", "double-fork", "reparent", "cancel", "owner-loss", "helper-loss", "receipt-recovery", "stale-identity", "process-limit"};
  bool allowed = count > CASE_BASE_COUNT && !strcmp(mode, "access"); for (unsigned i = 0; i < 11; i++) if (!strcmp(mode, fixed[i])) allowed = true; need(allowed);
  struct entry *launcher = &entries[4], *payload = &entries[5], *policy = &entries[6];
  for (unsigned i = 0; i < 7; i++) stable(&entries[i]);
  signature(payload->path, cdhash);
#ifdef NATIVE_CI_EXPERIMENT
  need(experiment_exec); memcpy(image_cdhash, cdhash, 41); image_policy_index = 6;
#endif
  /* The launcher copy is joined to the independently approved final build pin
   * by the controller before this command; native validity is checked again. */
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)launcher->path, strlen(launcher->path), false);
  SecStaticCodeRef code = NULL; need(url && SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess &&
    SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL) == errSecSuccess); CFRelease(code); CFRelease(url);
  int control[2], output[2], data[2];
  case_launch_check("pipe-control", pipe(control)); case_launch_check("pipe-output", pipe(output));
  case_launch_check("socketpair-data", socketpair(AF_UNIX, SOCK_STREAM, 0, data));
  posix_spawn_file_actions_t actions; posix_spawnattr_t attributes;
#ifdef NATIVE_CI_EXPERIMENT
  struct domain_bootstrap_fork spawn = {0}; bool actions_owned = false, attributes_owned = false;
  bool ready = domain_spawn_check(&spawn, posix_spawn_file_actions_init(&actions), "spawn-actions-init", false);
  actions_owned = ready;
  if (ready) ready = domain_spawn_attributes(&spawn, &attributes, &attributes_owned, POSIX_SPAWN_CLOEXEC_DEFAULT);
  if (ready) ready = domain_spawn_check(&spawn, posix_spawn_file_actions_adddup2(&actions, control[0], 0), "spawn-control", false) &&
    domain_spawn_check(&spawn, posix_spawn_file_actions_adddup2(&actions, output[1], 1), "spawn-output", false) &&
    domain_spawn_check(&spawn, posix_spawn_file_actions_adddup2(&actions, 2, 2), "spawn-stderr", false) &&
    domain_spawn_check(&spawn, posix_spawn_file_actions_adddup2(&actions, data[1], 3), "spawn-data", false);
#else
  case_launch_check("posix_spawn_file_actions_init", posix_spawn_file_actions_init(&actions));
  case_launch_check("posix_spawnattr_init", posix_spawnattr_init(&attributes));
  case_launch_check("posix_spawnattr_setflags", posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT));
  case_launch_check("spawn-control", posix_spawn_file_actions_adddup2(&actions, control[0], 0));
  case_launch_check("spawn-output", posix_spawn_file_actions_adddup2(&actions, output[1], 1));
  /* Explicitly retain the existing diagnostic channel under CLOEXEC_DEFAULT. */
  case_launch_check("spawn-stderr", posix_spawn_file_actions_adddup2(&actions, 2, 2));
  case_launch_check("spawn-data", posix_spawn_file_actions_adddup2(&actions, data[1], 3));
#endif
  char uid[24], gid[24], nonce[33]; snprintf(uid, sizeof(uid), "%u", subject_uid); snprintf(gid, sizeof(gid), "%u", subject_gid);
  memcpy(nonce, case_context, 32); nonce[32] = 0;
  char *argv[20] = {launcher->path, uid, gid, entries[1].path, entries[2].path, entries[3].path,
    payload->path, payload->pin, (char *)cdhash, policy->path, policy->pin, nonce, "--"};
  if (!strcmp(mode, "literal") || !strcmp(mode, "storage") || !strcmp(mode, "access")) {
    argv[13] = ""; argv[14] = "space value"; argv[15] = "λ雪"; argv[16] = "'\""; argv[17] = "$(false); & | < > *";
  } else { argv[13] = nonce; argv[14] = (char *)mode; }
#ifdef NATIVE_CI_EXPERIMENT
  char control_path[PATH_MAX + 32], control_hash[96];
  need(*image_control_cdhash && entries[12].fd >= 0);
  snprintf(control_path, sizeof(control_path), "NATIVE_EXEC_CONTROL=%s", entries[12].path);
  snprintf(control_hash, sizeof(control_hash), "NATIVE_EXEC_CONTROL_SHA256=%s", entries[12].pin);
  image_control = true; image_control_retired = image_probed = false;
  char evidence_candidate[80];
  need(snprintf(evidence_candidate, sizeof(evidence_candidate), "NATIVE_EVIDENCE_CANDIDATE=%s", candidate) == 66);
  char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", !strcmp(mode, "access") ? "NATIVE_ACCESS_CUSTODY=true" : "NATIVE_OWNERSHIP_CUSTODY=true", evidence_candidate, control_path, control_hash, NULL};
#else
  char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", !strcmp(mode, "access") ? "NATIVE_ACCESS_CUSTODY=true" : "NATIVE_OWNERSHIP_CUSTODY=true", NULL};
#endif
#ifdef NATIVE_CI_EXPERIMENT
  pid_t child = -1;
  if (ready) ready = domain_spawn_check(&spawn, posix_spawn(&child, launcher->path, &actions, &attributes, argv, environment), "spawn-launch", false);
  /* Failed output owns no PID. Retain success before either destroy can fail. */
  if (ready) { case_pid = child; case_in = control[1]; case_out = output[0]; case_data = data[0]; }
  domain_spawn_settle(&spawn, &actions, &actions_owned, &attributes, &attributes_owned);
  case_spawn_refuse(&spawn, case_pid);
#else
  case_launch_check("posix_spawn", posix_spawn(&case_pid, launcher->path, &actions, &attributes, argv, environment));
  case_launch_check("posix_spawn_file_actions_destroy", posix_spawn_file_actions_destroy(&actions));
  case_launch_check("posix_spawnattr_destroy", posix_spawnattr_destroy(&attributes));
#endif
  case_launch_check("close-control", close(control[0])); case_launch_check("close-output", close(output[1]));
  case_launch_check("close-data", close(data[1]));
  case_in = control[1]; case_out = output[0]; case_data = data[0];
  /* The hello is consumed separately. No P acknowledgement has been sent. */
  printf("{\"pid\":%d}", case_pid);
}
static void case_line(int fd, bool encoded) {
  need(case_mode && case_pid && fd >= 0); char bytes[8192]; unsigned length = 0;
  for (;;) {
    struct pollfd wait = {.fd = fd, .events = POLLIN}; char byte;
    int result = poll(&wait, 1, 30000), error = result < 0 ? errno : 0;
    if (result != 1) case_launch_failure("case-poll", result, error, wait.revents, -1);
    if (!(wait.revents & POLLIN)) case_launch_failure("case-poll-events", result, 0, wait.revents, -1);
    ssize_t used = read(fd, &byte, 1); error = used < 0 ? errno : 0;
    if (used != 1) case_launch_failure("case-read", used, error, wait.revents, used);
    if (!byte || length + 1 >= sizeof(bytes)) case_launch_failure("case-frame", byte, 0, wait.revents, used);
    bytes[length++] = byte; if (byte == '\n') break;
  }
  if (encoded) { char out[16385]; hex((void *)bytes, length, out); printf("{\"hex\":\"%s\"}", out); }
  else { bytes[length - 1] = 0; fputs(bytes, stdout); }
}
static uint64_t case_number(const char *value, uint64_t maximum) {
  char *end; errno = 0; uint64_t result = strtoull(value, &end, 10);
  need(*value && *value != '-' && !errno && !*end && result <= maximum); return result;
}
#ifdef NATIVE_CI_EXPERIMENT
/* Fixed installed observer reads: no arbitrary image or numeric-PID effect. */
static const char *case_observer_identity(pid_t pid, struct identity *value) {
  *value = inspect(pid); char image[PATH_MAX], after[PATH_MAX];
  need(proc_pidpath(pid, image, sizeof(image)) > 0);
  const char *kind = !strcmp(image, "/usr/sbin/dtrace") ? "dtrace" : !strcmp(image, "/usr/bin/sudo") ? "sudo" : NULL;
  need(kind);
  struct stat st; need(!lstat(image, &st) && installed_input(image, &st));
  struct identity again = inspect(pid);
  need(audit_identity_same(*value, again) && value->bsd.pbi_ppid == again.bsd.pbi_ppid &&
    proc_pidpath(pid, after, sizeof(after)) > 0 && !strcmp(image, after)); return kind;
}
static bool case_observer_live(struct identity expected) {
  struct proc_bsdinfo b; errno = 0;
  int size = proc_pidinfo(expected.token.val[5], PROC_PIDTBSDINFO, 1, &b, sizeof(b));
  if (!size) { need(errno == ESRCH || errno == ENOENT); return false; }
  need(size == sizeof(b) && b.pbi_status != SZOMB);
  struct identity actual; case_observer_identity(expected.token.val[5], &actual);
  need(audit_identity_same(expected, actual)); return true;
}
static void case_observer(char **fields, bool retire) {
  struct identity expected = {0};
  for (unsigned i = 0; i < 8; i++) expected.token.val[i] = case_number(fields[i], UINT32_MAX);
  expected.bsd.pbi_start_tvsec = case_number(fields[8], UINT64_MAX); expected.bsd.pbi_start_tvusec = case_number(fields[9], 999999);
  expected.bsd.pbi_svuid = case_number(fields[10], UINT32_MAX); expected.bsd.pbi_svgid = case_number(fields[11], UINT32_MAX);
  need(expected.token.val[5] > 1 && expected.token.val[5] <= INT_MAX);
  if (retire && case_observer_live(expected)) {
    int error = proc_signal_with_audittoken(&expected.token, SIGKILL); need(!error || error == ESRCH);
    for (unsigned pass = 0; pass < 1000 && case_observer_live(expected); pass++) (void)poll(NULL, 0, 10);
  }
  printf("{\"status\":\"%s\"}", case_observer_live(expected) ? "LIVE" : "RETIRED");
}
#endif
static void case_send(bool payload, const char *value) {
  need(payload || !case_fenced);
  need(case_mode && case_pid && strlen(value) == 1 &&
    (payload ? (*value == 'A' || *value == 'B' || *value == 'C') : (*value == 'P' || *value == 'R')));
  need(write(payload ? case_data : case_in, value, 1) == 1); fputs("null", stdout);
}
static void case_receipt(unsigned index, const char *pin, const char *encoded, bool optional) {
  need(case_mode && index < 32768 && strlen(pin) == 64 && strspn(pin, "0123456789abcdef") == 64);
  struct entry *root = &entries[1]; char name[64]; snprintf(name, sizeof(name), "receipt-%u.json", index);
  /* Recovery may read a receipt before rejoining the mutable workspace. */
  bool temporary = root->fd < 0;
  if (temporary) {
    root->fd = directory(root->path, 0, 0, 0700); need(!fstat(root->fd, &root->stat)); no_acl(root->fd); case_recovery = true;
  }
  stable(root);
  if (encoded) {
    char bytes[65536]; decode(encoded, bytes, sizeof(bytes)); size_t length = strlen(bytes);
    unsigned char sum[32]; char hash[65]; need(CC_SHA256(bytes, length, sum)); hex(sum, 32, hash); need(!strcmp(hash, pin));
    int fd = openat(root->fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    need(fd >= 0); no_acl(fd);
    need(write(fd, bytes, length) == (ssize_t)length && !fchmod(fd, 0400) && !fsync(fd) && !close(fd) && !fsync(root->fd));
  }
  char path[PATH_MAX]; need(snprintf(path, sizeof(path), "%s/%s", root->path, name) < sizeof(path)); struct stat st;
  int fd = openat(root->fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0 && optional && errno == ENOENT) { stable(root); if (temporary) { need(!close(root->fd)); root->fd = -1; } fputs("null", stdout); return; }
  need(fd >= 0); no_acl(fd);
  unsigned char *bytes = file(path, 0, 0400, 65535, pin, &st); char out[131071]; hex(bytes, st.st_size, out);
  struct stat held; need(!fstat(fd, &held)); same_stat(st, held); need(!close(fd));
  printf("{\"hex\":\"%s\"}", out); free(bytes); stable(root); if (temporary) { need(!close(root->fd)); root->fd = -1; }
}
static void case_members(unsigned asid, bool independent) {
  need(case_mode && asid < INT32_MAX);
  if (!independent) { need(asid > 0 && case_asid == asid); reservation_guard(); }
  audit_emit_view(audit_census(subject_uid, asid), subject_uid, asid);
}
static struct identity case_identity(char **fields) {
  struct identity value = {0};
  for (unsigned i = 0; i < 8; i++) value.token.val[i] = case_number(fields[i], UINT32_MAX);
  value.bsd.pbi_start_tvsec = case_number(fields[8], UINT64_MAX); value.bsd.pbi_start_tvusec = case_number(fields[9], 999999);
  value.bsd.pbi_svuid = case_number(fields[10], UINT32_MAX); value.bsd.pbi_svgid = case_number(fields[11], UINT32_MAX);
  need(value.token.val[5] > 1 && value.token.val[5] <= INT_MAX && value.bsd.pbi_start_tvsec > 0); return value;
}
struct case_audit_custody {
  unsigned version; char context[65]; struct identity subject, source, owner, custodian; bool ready, closed;
};
static struct case_audit_custody case_audit;
static pid_t case_custodian_child;
static off_t case_audit_offset;
static void case_audit_store(int fd) {
  need(pwrite(fd, &case_audit, sizeof(case_audit), case_audit_offset) == sizeof(case_audit) && !fsync(fd) && !fsync(entries[1].fd));
}
static int case_audit_open(bool create) {
  stable(&entries[1]); int fd = openat(entries[1].fd, "audit-custody", O_RDWR | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0400);
  struct stat held, named;
  need(fd >= 0 && !fstat(fd, &held) && !fstatat(entries[1].fd, "audit-custody", &named, AT_SYMLINK_NOFOLLOW)); same_stat(held, named);
  need(S_ISREG(held.st_mode) && !held.st_uid && !held.st_gid && held.st_nlink == 1 && (held.st_mode & 07777) == 0400 &&
    (create ? held.st_size == 0 : held.st_size >= sizeof(case_audit) && held.st_size <= 32 * sizeof(case_audit) && held.st_size % sizeof(case_audit) == 0)); no_acl(fd); return fd;
}
static void case_audit_guard(bool closing) {
  struct stat named, before, after; errno = 0;
  if (fstatat(entries[1].fd, "audit-custody", &named, AT_SYMLINK_NOFOLLOW) == -1) { need(errno == ENOENT && !case_audit.version); return; }
  int fd = case_audit_open(false); need(!fstat(fd, &before));
  for (off_t at = 0; at < before.st_size; at += sizeof(case_audit)) {
    struct case_audit_custody value; read_at(fd, &value, sizeof(value), at);
    need(value.version == 1 && !memcmp(value.context, case_context, 65) && value.ready && value.custodian.token.val[5] > 1);
    if (!value.closed) need(!closing && case_asid == value.subject.token.val[6] && case_audit_offset == at &&
      audit_identity_same(value.subject, case_audit.subject) && audit_identity_same(value.custodian, case_audit.custodian));
  }
  need(!fstat(fd, &after)); same_stat(before, after); need(!close(fd));
}
static void case_audit_emit(void) {
  printf("{\"asid\":%u,\"held\":%s,\"closed\":%s,\"owner\":", case_audit.subject.token.val[6], case_audit.closed ? "false" : "true", case_audit.closed ? "true" : "false"); emit(inspect(getpid()));
  fputs(",\"subject\":", stdout); emit(case_audit.subject); fputs(",\"source\":", stdout); emit(case_audit.source);
  fputs(",\"custodian\":", stdout); emit(case_audit.custodian); putchar('}');
}
static void case_session(char **fields, bool recovering, bool reconstructing) {
  if (reconstructing) need(case_fenced && case_recovery);
  need(case_mode);
  if (recovering) need(case_fenced && case_recovery);
  if (!recovering || reservation_fd >= 0) reservation_guard();
  struct identity subject = case_identity(fields);
  unsigned asid = subject.token.val[6]; need(asid > 0 && asid < INT32_MAX && subject.token.val[0] == subject_uid);
  if (!recovering) {
    need((!case_fenced || reconstructing) && !case_asid && (!case_audit.version || case_audit.closed)); struct identity source = case_identity(fields + 12);
    need(audit_identity_same(source, inspect(source.token.val[5])) && source.token.val[1] == 0);
    char path[PATH_MAX]; need(proc_pidpath(source.token.val[5], path, sizeof(path)) > 0 && !strcmp(path, entries[4].path));
    stable(&entries[4]); struct stat st; free(file(path, 0, 0550, 134217728, entries[4].pin, &st));
    struct identity parked = inspect(subject.token.val[5]);
    need(audit_identity_same(parked, subject) && parked.bsd.pbi_ppid == source.token.val[5] &&
      parked.token.val[1] == subject_uid && parked.token.val[2] == subject_gid && parked.token.val[3] == subject_uid &&
      parked.token.val[4] == subject_gid && parked.bsd.pbi_svuid == subject_uid && parked.bsd.pbi_svgid == subject_gid &&
      parked.token.val[6] != source.token.val[6]);
    struct stat existing; errno = 0; int fd;
    if (fstatat(entries[1].fd, "audit-custody", &existing, AT_SYMLINK_NOFOLLOW) == -1) {
      need(errno == ENOENT); fd = case_audit_open(true); case_audit_offset = 0;
    } else {
      fd = case_audit_open(false); need(existing.st_size < 32 * sizeof(case_audit));
      for (off_t at = 0; at < existing.st_size; at += sizeof(case_audit)) {
        struct case_audit_custody previous; read_at(fd, &previous, sizeof(previous), at);
        need(previous.version == 1 && !memcmp(previous.context, case_context, 65) && previous.closed && previous.subject.token.val[6] != asid);
      }
      case_audit_offset = existing.st_size;
    }
    memset(&case_audit, 0, sizeof(case_audit)); case_audit.version = 1; strcpy(case_audit.context, case_context);
    case_audit.subject = subject; case_audit.source = source; case_audit.owner = inspect(getpid()); case_audit_store(fd);
    need(session_count < 32); sessions[session_count++] = audit_hold(asid);
    need(audit_identity_same(source, inspect(source.token.val[5])));
    int ready[2], release[2]; need(!pipe(ready) && !pipe(release));
    posix_spawn_file_actions_t actions; posix_spawnattr_t attributes;
    need(!posix_spawn_file_actions_init(&actions) && !posix_spawnattr_init(&attributes) &&
      !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) &&
      !posix_spawn_file_actions_adddup2(&actions, release[0], 0) && !posix_spawn_file_actions_adddup2(&actions, ready[1], 1) &&
      !posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0));
    char text[12][32]; char *args[15] = {entries[4].path, "--audit-holder"};
    for (unsigned i = 0; i < 8; i++) { need(snprintf(text[i], sizeof(text[i]), "%u", subject.token.val[i]) > 0); args[i + 2] = text[i]; }
    snprintf(text[8], sizeof(text[8]), "%llu", (unsigned long long)subject.bsd.pbi_start_tvsec); snprintf(text[9], sizeof(text[9]), "%llu", (unsigned long long)subject.bsd.pbi_start_tvusec);
    snprintf(text[10], sizeof(text[10]), "%u", subject.bsd.pbi_svuid); snprintf(text[11], sizeof(text[11]), "%u", subject.bsd.pbi_svgid);
    for (unsigned i = 8; i < 12; i++) args[i + 2] = text[i];
    char *env[] = {"CI=true", "GITHUB_ACTIONS=true", NULL}; pid_t child;
    need(!posix_spawn(&child, entries[4].path, &actions, &attributes, args, env) &&
      !posix_spawn_file_actions_destroy(&actions) && !posix_spawnattr_destroy(&attributes) && !close(ready[1]) && !close(release[0]));
    need(read(ready[0], &case_audit.custodian, sizeof(case_audit.custodian)) == sizeof(case_audit.custodian));
    need(case_audit.custodian.token.val[5] == (unsigned)child && audit_identity_same(case_audit.custodian, inspect(child)));
    case_custodian_child = child; case_audit_store(fd); /* birth precedes reference acquisition */
    need(write(release[1], "P", 1) == 1 && !close(release[1])); char held;
    need(read(ready[0], &held, 1) == 1 && held == 'H' && !close(ready[0]));
    case_audit.ready = true; case_audit_store(fd); need(!close(fd)); case_asid = asid;
  } else {
    need(!case_asid && (!case_audit.version || case_audit.closed)); int fd = case_audit_open(false); struct stat before, after;
    need(!fstat(fd, &before)); unsigned matches = 0;
    for (off_t at = 0; at < before.st_size; at += sizeof(case_audit)) {
      struct case_audit_custody value; read_at(fd, &value, sizeof(value), at);
      need(value.version == 1 && !memcmp(value.context, case_context, 65));
      if (value.subject.token.val[6] == asid && value.subject.token.val[5] == subject.token.val[5] &&
        value.subject.bsd.pbi_start_tvsec == subject.bsd.pbi_start_tvsec && value.subject.bsd.pbi_start_tvusec == subject.bsd.pbi_start_tvusec) {
        need(++matches == 1); case_audit = value; case_audit_offset = at;
      }
    }
    need(matches == 1 && !fstat(fd, &after)); same_stat(before, after); need(!close(fd));
    need(case_audit.version == 1 && !memcmp(case_audit.context, case_context, 65) && case_audit.subject.token.val[6] == asid &&
      case_audit.subject.token.val[5] == subject.token.val[5] && case_audit.subject.token.val[0] == subject.token.val[0] &&
      case_audit.subject.bsd.pbi_start_tvsec == subject.bsd.pbi_start_tvsec && case_audit.subject.bsd.pbi_start_tvusec == subject.bsd.pbi_start_tvusec &&
      case_audit.ready && case_audit.custodian.token.val[5] > 1 && case_audit.custodian.token.val[1] == 0 && case_audit.custodian.token.val[6] > 0 && case_audit.custodian.token.val[6] != asid);
    if (!case_audit.closed) {
      struct proc_bsdinfo status; struct identity expected = case_audit.custodian; errno = 0;
      int size = proc_pidinfo(expected.token.val[5], PROC_PIDTBSDINFO, 1, &status, sizeof(status));
      bool auxiliary = size != 0;
      if (!size) {
        need((errno == ESRCH || errno == ENOENT) && !root_members(expected.token.val[6], false));
        /* An original live member/source still pins the same session. Never
         * recreate the lost custodian or adopt another process/session birth. */
        expected = subject; errno = 0;
        size = proc_pidinfo(expected.token.val[5], PROC_PIDTBSDINFO, 1, &status, sizeof(status));
        if (!size) { need(errno == ESRCH || errno == ENOENT); expected = case_audit.source; }
      }
      struct identity holder = inspect(expected.token.val[5]);
      need(audit_identity_same(holder, expected)
#ifdef NATIVE_CI_EXPERIMENT
        || (image_recovering && case_fenced && case_recovery && expected.token.val[1] == subject_uid && exec_handoff_identity(expected, holder))
#endif
      );
      char path[PATH_MAX]; need(proc_pidpath(holder.token.val[5], path, sizeof(path)) > 0);
      if (auxiliary) { struct stat pinned; stable(&entries[4]); need(!strcmp(path, entries[4].path)); free(file(path, 0, 0550, 134217728, entries[4].pin, &pinned)); }
      else { unsigned index = holder.token.val[1] ? 5 : 4; struct stat pinned;
#ifdef NATIVE_CI_EXPERIMENT
        if (index == 5 && image_recovering && experiment_exec && entries[12].fd >= 0 && !strcmp(path, entries[12].path)) index = 12;
#endif
        stable(&entries[index]);
        need(!strcmp(path, entries[index].path)); free(file(path, index == 4 ? 0 : subject_gid, 0550, 134217728, entries[index].pin, &pinned)); }
      need(session_count < 32); sessions[session_count++] = audit_hold(asid);
      need(audit_identity_same(holder, inspect(holder.token.val[5]))); case_asid = asid;
    } else {
      struct proc_bsdinfo gone; errno = 0;
      need(!proc_pidinfo(case_audit.custodian.token.val[5], PROC_PIDTBSDINFO, 1, &gone, sizeof(gone)) &&
        (errno == ESRCH || errno == ENOENT) && !root_members(case_audit.custodian.token.val[6], false));
    }
  }
  case_audit_emit();
}
static void case_session_closed(void) {
  need(case_mode && (case_fenced || operation_domain_finished()
#ifdef NATIVE_CI_EXPERIMENT
    || (image_control && image_phase == 4)
#endif
    ) && case_audit.version && (reservation_fd < 0 || operation_domain_finished()
#ifdef NATIVE_CI_EXPERIMENT
    || (image_control && image_phase == 4)
#endif
    )); no_subjects();
  struct audit_domain_view view = audit_census(subject_uid, case_asid); need(!view.nl && !view.nd);
  struct proc_bsdinfo gone; errno = 0;
  need(!proc_pidinfo(case_audit.custodian.token.val[5], PROC_PIDTBSDINFO, 1, &gone, sizeof(gone)) &&
    (errno == ESRCH || errno == ENOENT) && !root_members(case_audit.custodian.token.val[6], false));
  int fd = case_audit_open(false); case_audit.closed = true; case_audit_store(fd); need(!close(fd)); case_asid = 0; fputs("{\"closed\":true}", stdout);
}
#ifdef NATIVE_CI_EXPERIMENT
/* Only the already recorded observer in the original reader's audit domain.
 * Its full birth/epoch is checked by case_signal before this image check. */
static bool image_recovery_observer(struct identity actual, const char *path) {
  if (!image_recovering || !case_fenced || !case_recovery || !case_audit.ready || case_audit.closed ||
      actual.token.val[6] != case_audit.owner.token.val[6]) return false;
  char expected[PATH_MAX]; need(snprintf(expected, sizeof(expected), "%s/custody/observer", case_path) < sizeof(expected));
  if (strcmp(path, expected)) return false;
  unsigned found = 0;
  for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].path, path)) {
    need(!strcmp(entries[i].kind, "helper")); struct stat st;
    free(file(path, subject_gid, 0550, 134217728, entries[i].pin, &st)); found++;
  }
  need(found == 1); return true;
}
#endif
static void case_signal(char **fields) {
  need(case_mode); struct identity expected = {0}; unsigned order[] = {0, 1, 2, 3, 4, 5, 6, 7};
  for (unsigned i = 0; i < 8; i++) expected.token.val[order[i]] = case_number(fields[i], UINT32_MAX);
  expected.bsd.pbi_start_tvsec = case_number(fields[8], UINT64_MAX); expected.bsd.pbi_start_tvusec = case_number(fields[9], 999999);
  expected.bsd.pbi_svuid = case_number(fields[10], UINT32_MAX); expected.bsd.pbi_svgid = case_number(fields[11], UINT32_MAX);
  need(expected.token.val[5] > 1 && expected.token.val[5] <= INT_MAX); pid_t pid = expected.token.val[5]; need(pid != getpid());
  struct proc_bsdinfo b; errno = 0; int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, &b, sizeof(b));
  const char *outcome;
  if (!size && errno == ESRCH) outcome = "not-found";
  else {
    need(size == sizeof(b));
    if (b.pbi_status == SZOMB) {
      need(b.pbi_start_tvsec == expected.bsd.pbi_start_tvsec && b.pbi_start_tvusec == expected.bsd.pbi_start_tvusec &&
        b.pbi_uid == expected.token.val[1] && b.pbi_gid == expected.token.val[2] && b.pbi_ruid == expected.token.val[3] &&
        b.pbi_rgid == expected.token.val[4] && b.pbi_svuid == expected.bsd.pbi_svuid && b.pbi_svgid == expected.bsd.pbi_svgid); outcome = "zombie";
    } else {
      struct identity actual = inspect(pid);
      if (memcmp(&actual.token, &expected.token, sizeof(actual.token)) || actual.bsd.pbi_start_tvsec != expected.bsd.pbi_start_tvsec ||
        actual.bsd.pbi_start_tvusec != expected.bsd.pbi_start_tvusec || actual.bsd.pbi_svuid != expected.bsd.pbi_svuid || actual.bsd.pbi_svgid != expected.bsd.pbi_svgid) outcome = "stale";
      else {
        if (!actual.token.val[1] && !(case_asid && actual.token.val[6] == case_asid && actual.token.val[0] == subject_uid)) {
          char path[PATH_MAX]; need(proc_pidpath(pid, path, sizeof(path)) > 0);
          if (!strcmp(path, entries[4].path)) { stable(&entries[4]); struct stat st; free(file(path, 0, 0550, 134217728, entries[4].pin, &st)); }
          else { char own[PATH_MAX]; need(proc_pidpath(getpid(), own, sizeof(own)) > 0);
#ifdef NATIVE_CI_EXPERIMENT
            need(!strcmp(path, own) || image_recovery_observer(actual, path));
#else
            need(!strcmp(path, own));
#endif
          }
        } else need(case_asid && actual.token.val[6] == case_asid && actual.token.val[0] == subject_uid);
        need(!proc_signal_with_audittoken(&actual.token, SIGKILL)); outcome = "sent";
        if (pid == case_custodian_child) { int status; while (waitpid(pid, &status, 0) < 0) need(errno == EINTR); need(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL); case_custodian_child = 0; }
        if (pid == case_pid) {
          int status; while (waitpid(case_pid, &status, 0) < 0) need(errno == EINTR);
          need(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
          need(!close(case_in) && !close(case_out) && !close(case_data)); case_pid = 0;
        }
      }
    }
  }
  printf("{\"identity\":"); emit(expected); printf(",\"outcome\":\"%s\"}", outcome);
}
static void case_subject(pid_t pid) {
  need(case_mode); reservation_guard(); struct identity before = inspect(pid);
  need(before.token.val[0] == subject_uid && before.token.val[1] == subject_uid && before.token.val[2] == subject_gid);
  char path[PATH_MAX]; need(proc_pidpath(pid, path, sizeof(path)) > 0 && !strcmp(path, entries[5].path)); stable(&entries[5]);
  struct proc_vnodepathinfo cwd; need(proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &cwd, sizeof(cwd)) == sizeof(cwd));
  struct vinfo_stat *v = &cwd.pvi_cdir.vip_vi.vi_stat; struct entry *work = &entries[3]; stable(work);
  need(v->vst_dev == work->stat.st_dev && v->vst_ino == work->stat.st_ino && v->vst_uid == subject_uid && v->vst_gid == subject_gid && (v->vst_mode & 07777) == 0700);
  need(sandbox_active(pid) == 1);
  printf("{\"identity\":"); emit(before); printf(",\"imageSha256\":\"%s\",\"cwd\":{\"dev\":\"%u\",\"ino\":\"%llu\"},\"sandboxed\":true,\"decisions\":[", entries[5].pin, v->vst_dev, (unsigned long long)v->vst_ino);
  for (unsigned i = 0; i < 7; i++) {
    int result = feasibility_sandbox_path(sandbox_binding, pid, "file-write-data", entries[i].path);
    need(result == 0 || result == 1); printf("%s%d", i ? "," : "", result);
  }
  struct identity after = inspect(pid); need(!memcmp(&before.token, &after.token, sizeof(before.token)) && before.bsd.pbi_start_tvsec == after.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == after.bsd.pbi_start_tvusec);
  fputs("]}", stdout);
}
static void case_retire(void) {
  case_audit_guard(false);
  need(case_mode && !case_policy_possible && !file_pid); reservation_guard(); no_subjects(); case_account();
  if (case_pid) {
    int status; while (waitpid(case_pid, &status, 0) < 0) need(errno == EINTR);
    need(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    need(!close(case_in) && !close(case_out) && !close(case_data)); case_pid = 0;
  }
  for (unsigned i = 0; i < case_socket_count; i++) need(!close(case_sockets[i])); case_socket_count = 0;
  no_subjects();
#ifdef NATIVE_CI_EXPERIMENT
  need(image_settle());
#endif
  if (count == CASE_BASE_COUNT || (operation_mode && operations_retired())) { need(!close(reservation_fd)); reservation_fd = -1; reservation_entry = NULL; }
  fputs("{\"noLiveUid\":true,\"closed\":true}", stdout);
}
/* Only a directory in the independently pinned plan may be created/resealed.
 * The runner-owned report parent stays private; native handles bind both names. */
static void build_directory(const char *encoded) {
  need(build_root < 0); decode(encoded, build_path, sizeof(build_path));
  unsigned approved = 0;
  for (unsigned i = 0; i < count; i++)
    if (!strcmp(entries[i].kind, "directory") && !strcmp(entries[i].path, build_path)) approved++;
  need(approved == 1); strcpy(report_path, build_path);
  char *leaf = strrchr(report_path, '/'); need(leaf && !strcmp(leaf + 1, "platform-build")); *leaf = 0;
  char canonical[PATH_MAX]; need(realpath(report_path, canonical) && !strcmp(report_path, canonical));
  build_parent = open(report_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(build_parent >= 0 && !fstat(build_parent, &report_identity) && S_ISDIR(report_identity.st_mode) &&
    report_identity.st_uid > 500 && (report_identity.st_mode & 07777) == 0700); no_acl(build_parent);
  struct stat named; bool created = false;
  if (fstatat(build_parent, "platform-build", &named, AT_SYMLINK_NOFOLLOW) < 0) {
    need(errno == ENOENT && !mkdirat(build_parent, "platform-build", 0700));
    created = true;
    need(!fstatat(build_parent, "platform-build", &named, AT_SYMLINK_NOFOLLOW));
  }
  need(S_ISDIR(named.st_mode) && named.st_uid == 0);
  if (created) need(named.st_gid == report_identity.st_gid && !(named.st_mode & 07077));
  else need(named.st_gid == 0 && ((named.st_mode & 07777) == 0700 || (named.st_mode & 07777) == 0555));
  build_root = openat(build_parent, "platform-build", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(build_root >= 0 && !fstat(build_root, &build_identity));
  same_stat(named, build_identity); no_acl(build_root);
  need(build_identity.st_birthtimespec.tv_sec == named.st_birthtimespec.tv_sec && build_identity.st_birthtimespec.tv_nsec == named.st_birthtimespec.tv_nsec);
  struct stat parent, parent_named, current;
  need(!fstat(build_parent, &parent) && !lstat(report_path, &parent_named));
  need(parent.st_dev == report_identity.st_dev && parent.st_ino == report_identity.st_ino &&
    parent.st_mode == report_identity.st_mode && parent.st_uid == report_identity.st_uid && parent.st_gid == report_identity.st_gid &&
    parent.st_birthtimespec.tv_sec == report_identity.st_birthtimespec.tv_sec && parent.st_birthtimespec.tv_nsec == report_identity.st_birthtimespec.tv_nsec);
  same_stat(parent, parent_named); no_acl(build_parent);
  need(!fstatat(build_parent, "platform-build", &current, AT_SYMLINK_NOFOLLOW)); same_stat(named, current);
  need(current.st_birthtimespec.tv_sec == named.st_birthtimespec.tv_sec && current.st_birthtimespec.tv_nsec == named.st_birthtimespec.tv_nsec);
  /* XNU vn_attribute_prepare inherits the parent GID. Only our successful
   * exclusive mkdir permits normalization, through the joined held descriptor. */
  if (created) need(!fchown(build_root, 0, 0));
  need(!fchmod(build_root, 0700) && !fstat(build_root, &build_identity));
  need(build_identity.st_dev == named.st_dev && build_identity.st_ino == named.st_ino &&
    build_identity.st_birthtimespec.tv_sec == named.st_birthtimespec.tv_sec && build_identity.st_birthtimespec.tv_nsec == named.st_birthtimespec.tv_nsec &&
    build_identity.st_nlink == named.st_nlink && S_ISDIR(build_identity.st_mode) &&
    build_identity.st_uid == 0 && build_identity.st_gid == 0 && (build_identity.st_mode & 07777) == 0700);
  struct entry value = {.fd = build_root}; strcpy(value.kind, "build"); strcpy(value.path, build_path); value.stat = build_identity;
  stable(&value); identity(&value);
}
static void build_root_open(const char *name) {
  need(build_root < 0); /* A fresh read-only join never reseals a published directory. */
  need(strlen(name) < sizeof(build_path)); strcpy(build_path, name);
  strcpy(report_path, build_path); char *parent = strrchr(report_path, '/'); need(parent && !strcmp(parent + 1, "platform-build")); *parent = 0;
  char canonical[PATH_MAX]; need(realpath(report_path, canonical) && !strcmp(report_path, canonical));
  unsigned approved = 0; for (unsigned i = 0; i < count; i++)
    if (!strcmp(entries[i].kind, "directory") && !strcmp(entries[i].path, build_path)) approved++;
  need(approved == 1);
  build_parent = open(report_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  build_root = open(build_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(build_parent >= 0 && build_root >= 0 && !fstat(build_parent, &report_identity) &&
    report_identity.st_uid > 500 && (report_identity.st_mode & 07777) == 0700 &&
    !fstat(build_root, &build_identity) && build_identity.st_uid == 0 && build_identity.st_gid == 0 &&
    ((build_identity.st_mode & 07777) == 0700 || (build_identity.st_mode & 07777) == 0555));
  no_acl(build_parent); no_acl(build_root);
}
static void build_root_snapshot(const char *encoded) {
  char name[PATH_MAX]; decode(encoded, name, sizeof(name)); build_root_open(name);
  struct entry root = {.fd = build_root}; strcpy(root.kind, "build"); strcpy(root.path, build_path); root.stat = build_identity;
  stable(&root); identity(&root);
}
static void build_open(const char *encoded, const char *pin) {
  char name[PATH_MAX], parent[PATH_MAX]; decode(encoded, name, sizeof(name)); strcpy(parent, name);
  char *leaf = strrchr(parent, '/'); need(leaf); *leaf = 0; build_root_open(parent);
  need((build_identity.st_mode & 07777) == 0555);
  const char *base = strrchr(name, '/') + 1;
  const char *fixed[] = {"launcher", "argv-fixture", "ownership-fixture", "access-fixture", "file-helper", "git-executor", "git-fixture", "observer-helper", "custody-reader", "build-helper"};
  unsigned approved = 0; for (unsigned i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) if (!strcmp(base, fixed[i])) approved++;
#ifdef NATIVE_CI_EXPERIMENT
  bool dependencies = false;
  for (unsigned i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
    char dependency[PATH_MAX]; snprintf(dependency, sizeof(dependency), "%s.deps", fixed[i]);
    if (!strcmp(base, dependency)) { approved++; dependencies = true; }
  }
#endif
  need(approved == 1 && count < SLOTS);
  unsigned index = count++; struct entry *value = &entries[index]; strcpy(value->kind, "build"); strcpy(value->path, name);
  value->fd = openat(build_root, base, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
#ifdef NATIVE_CI_EXPERIMENT
  const mode_t mode = dependencies ? 0444 : 0555;
#else
  const mode_t mode = 0555;
#endif
  need(value->fd >= 0 && !fstat(value->fd, &value->stat) && S_ISREG(value->stat.st_mode) && value->stat.st_uid == 0 &&
    value->stat.st_gid == 0 && value->stat.st_nlink == 1 && (value->stat.st_mode & 07777) == mode &&
    value->stat.st_size > 0 && value->stat.st_size <= 134217728); no_acl(value->fd);
  char actual[65]; sha_range(value->fd, 0, value->stat.st_size, actual); need(!strcmp(pin, "-") || !strcmp(pin, actual));
  stable(value); printf("{\"index\":%u,\"object\":", index); identity(value);
  struct entry root = {.fd = build_root}; strcpy(root.kind, "build"); strcpy(root.path, build_path); need(!fstat(build_root, &root.stat)); stable(&root);
  fputs(",\"root\":", stdout); identity(&root); printf(",\"sha256\":\"%s\"}", actual);
}
static size_t preparation_receipt_limit(const char *name) {
  const char *leaf = strrchr(name, '/');
  return !strcmp(leaf ? leaf + 1 : name, "darwin-experiment-preparation.json") ? 4194304 : 1048576;
}
static void build_receipt(const char *encoded, const char *pin) {
  char name[PATH_MAX], parent[PATH_MAX], canonical[PATH_MAX]; decode(encoded, name, sizeof(name));
  need(realpath(name, canonical) && !strcmp(name, canonical)); strcpy(parent, name);
  char *leaf = strrchr(parent, '/'); need(leaf && (!strncmp(leaf + 1, "darwin-", 7) || (preparation_mode && !strncmp(leaf + 1, "provider-", 9)))); *leaf = 0;
  unsigned approved = 0;
  for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].kind, "directory")) {
    char directory[PATH_MAX]; strcpy(directory, entries[i].path); char *base = strrchr(directory, '/');
    if (base && !strcmp(base + 1, "platform-build")) { *base = 0; if (!strcmp(directory, parent)) approved++; }
  }
  need(approved == 1);
  int root = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), fd;
  struct stat before, after, named, authority, parent_after;
  need(root >= 0 && !fstat(root, &authority) && authority.st_uid > 500 && (authority.st_mode & 07777) == 0700); no_acl(root);
  fd = openat(root, strrchr(name, '/') + 1, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  need(fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_uid == authority.st_uid &&
    (before.st_mode & 07777) == 0400 && before.st_nlink == 1 && before.st_size > 0 &&
    before.st_size <= preparation_receipt_limit(name)); no_acl(fd);
  char actual[65]; sha_range(fd, 0, before.st_size, actual);
  need(!strcmp(actual, pin) && !fstat(fd, &after) && !lstat(name, &named)); same_stat(before, after); same_stat(before, named);
  need(!fstat(root, &parent_after) && !lstat(parent, &named)); same_stat(authority, parent_after); same_stat(authority, named);
  no_acl(root); no_acl(fd); need(!close(fd) && !close(root)); printf("{\"receipt\":\"%s\"}\n", actual); fflush(stdout);
}
#ifdef NATIVE_CI_EXPERIMENT
/* Read installed build inputs without adding hundreds of SDK headers to the
 * finite custody slots. Observed pins confer no reviewed authority. */
static void build_input(const char *encoded, const char *pin, const char *cdhash) {
  char name[PATH_MAX]; decode(encoded, name, sizeof(name)); need(build_mode);
  bool declared = false;
  for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].path, name) && !strcmp(entries[i].pin, pin)) declared = true;
  bool hosted = experiment_installed_path(name);
  need(declared || hosted || (!strncmp(name, "/Library/native-poc-", 20) && strlen(name) > 85 && strspn(name + 20, "0123456789abcdef") == 64 && name[84] == '/' && !strchr(name + 85, '/')));
  ancestors(name);
  char parent[PATH_MAX]; strcpy(parent, name); char *slash = strrchr(parent, '/');
  while (slash && slash != parent) {
    *slash = 0; int fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat held, named;
    need(fd >= 0 && !fstat(fd, &held) && is_bootstrap_parent(name, &held));
    if (!hosted) no_acl(fd);
    need(!lstat(parent, &named)); same_stat(held, named); need(!close(fd)); slash = strrchr(parent, '/');
  }
  struct entry sdk = {.fd = -1}, developer = {.fd = -1}; char compiler[PATH_MAX];
  const char *leaf = strrchr(name, '/');
  if (leaf && !strcmp(leaf, "/SDKSettings.json")) {
    size_t length = (size_t)(leaf - name); need(length < sizeof(sdk.path));
    memcpy(sdk.path, name, length); sdk.path[length] = 0;
    sdk.fd = open(sdk.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(sdk.fd >= 0 && !fstat(sdk.fd, &sdk.stat) && S_ISDIR(sdk.stat.st_mode) &&
      (hosted || (sdk.stat.st_uid == 0 && !(sdk.stat.st_mode & 022)))); if (!hosted) no_acl(sdk.fd); stable_identity(&sdk);
    developer_paths(sdk.path, developer.path, compiler);
    developer.fd = open(developer.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(developer.fd >= 0 && !fstat(developer.fd, &developer.stat) && S_ISDIR(developer.stat.st_mode) &&
      (hosted || (developer.stat.st_uid == 0 && !(developer.stat.st_mode & 022)))); if (!hosted) no_acl(developer.fd); stable_identity(&developer);
  }
  struct entry value = {.fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
  strcpy(value.kind, "data"); strcpy(value.path, name);
  bool sampled = false; const char *predicate = "open";
  bool ok = value.fd >= 0 && (predicate = "stat", sampled = fstat(value.fd, &value.stat) == 0) &&
    (predicate = "kind", S_ISREG(value.stat.st_mode)) && (predicate = "links", value.stat.st_nlink > 0) &&
    (predicate = "eligibility", hosted || (value.stat.st_uid == 0 && !(value.stat.st_mode & 06022) && value.stat.st_nlink == 1)) &&
    (predicate = "size", value.stat.st_size > 0 && (uint64_t)value.stat.st_size <= 536870912ULL);
  if (!ok) input_refusal(name, predicate, sampled ? &value.stat : NULL);
  need(ok); if (hosted) need(installed_input(name, &value.stat)); else no_acl(value.fd);
  printf("{\"object\":"); identity(&value);
  char actual[65]; sha_range(value.fd, 0, value.stat.st_size, actual); need(!strcmp(actual, pin)); printf(",\"sha256\":\"%s\"", actual); uint32_t magic = 0; if (value.stat.st_size >= sizeof(magic)) read_at(value.fd, &magic, sizeof(magic), 0); if (magic == MH_MAGIC_64 || installed_loader(&value)) { fputs(",\"macho\":", stdout); image(&value); }
  stable(&value); if (hosted) need(installed_input(name, &value.stat)); else no_acl(value.fd);
  if (cdhash) {
    need(strlen(cdhash) == 40 && strspn(cdhash, "0123456789abcdef") == 40);
    signature(name, cdhash); stable(&value); printf(",\"cdhash\":\"%s\"", cdhash);
  }
  if (sdk.fd >= 0) {
    stable_identity(&sdk); if (!hosted) no_acl(sdk.fd); fputs(",\"sdk\":", stdout); identity(&sdk); need(!close(sdk.fd));
    char current_developer[PATH_MAX], current_compiler[PATH_MAX], encoded_compiler[PATH_MAX*2+1];
    developer_paths(sdk.path, current_developer, current_compiler);
    need(!strcmp(developer.path, current_developer) && !strcmp(compiler, current_compiler));
    stable_identity(&developer); if (!hosted) no_acl(developer.fd); fputs(",\"developer\":", stdout); identity(&developer);
    hex((const unsigned char *)compiler, strlen(compiler), encoded_compiler);
    printf(",\"compilerPathHex\":\"%s\"", encoded_compiler); need(!close(developer.fd));
  }
  need(!close(value.fd)); putchar('}');
}
#endif
/* Read-only provider preparation lane. The approved plan admits each source,
 * stock tool and helper pin; only sealed private report records are unpinned.
 * No compiler, payload, policy mutation or provider command is exposed here. */
static void preparation_observe(const char *encoded, const char *pin, bool directory) {
  char name[PATH_MAX], canonical[PATH_MAX], parent[PATH_MAX]; decode(encoded, name, sizeof(name));
  need(preparation_mode && realpath(name, canonical) && !strcmp(name, canonical));
  int root = open(report_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat authority;
  need(root >= 0 && !fstat(root, &authority) && authority.st_uid > 500 && (authority.st_mode & 07777) == 0700); no_acl(root);
  bool approved = directory && !strcmp(name, report_path);
  unsigned roots = 0;
  for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].kind, "directory")) {
    char selected[PATH_MAX]; strcpy(selected, entries[i].path); char *base = strrchr(selected, '/');
    if (base && !strcmp(base + 1, "platform-build")) { *base = 0; if (!strcmp(selected, report_path)) roots++; }
  }
  need(roots == 1);
  bool receipt = !strncmp(name, report_path, strlen(report_path)) && name[strlen(report_path)] == '/' &&
    !strncmp(name + strlen(report_path) + 1, "provider-", 9) && !strchr(name + strlen(report_path) + 1, '/');
  /* Declared Darwin receipts use the same bounds without admitting unpinned data. */
  const char *suffix = strrchr(name, '.');
  bool darwin_receipt = !directory && suffix && !strcmp(suffix, ".json") &&
    !strncmp(name, report_path, strlen(report_path)) && name[strlen(report_path)] == '/' &&
    !strncmp(name + strlen(report_path) + 1, "darwin-", 7) && !strchr(name + strlen(report_path) + 1, '/');
  if (receipt) {
    const char *base = name + strlen(report_path) + 1; size_t length = strlen(base);
    need(length > 14 && length <= 240 && !strcmp(base + length - 5, ".json") &&
      strspn(base, "abcdefghijklmnopqrstuvwxyz0123456789-.") == length);
  }
  for (unsigned i = 0; i < count; i++) if (!strcmp(name, entries[i].path) && !strcmp(pin, entries[i].pin)) approved = true;
  need(approved || (!directory && receipt));
  strcpy(parent, name); char *leaf = strrchr(parent, '/'); need(leaf); if (!directory) *leaf = 0;
  for (;;) {
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); struct stat before, named, after;
    need(fd >= 0 && !fstat(fd, &before) && S_ISDIR(before.st_mode) && (before.st_uid == 0 || before.st_uid == authority.st_uid) && !(before.st_mode & 022)); no_acl(fd);
    need(!lstat(parent, &named) && !fstat(fd, &after)); same_stat(before, named); same_stat(before, after); need(!close(fd));
    if (!strcmp(parent, "/")) break; char *base = strrchr(parent, '/'); need(base); if (base == parent) parent[1] = 0; else *base = 0;
  }
  struct entry value = {.fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
  need(value.fd >= 0 && !fstat(value.fd, &value.stat)); strcpy(value.path, name); strcpy(value.kind, directory ? "directory" : "data"); no_acl(value.fd);
  need(directory ? S_ISDIR(value.stat.st_mode) : S_ISREG(value.stat.st_mode) && value.stat.st_nlink == 1 && value.stat.st_size > 0 && value.stat.st_size <= 536870912);
  bool stock_tool = approved && !directory && (!strcmp(name, "/usr/bin/clang") || !strcmp(name, "/usr/bin/xcrun") || !strcmp(name, "/usr/bin/codesign"));
  need(directory || ((value.stat.st_uid == 0 || value.stat.st_uid == authority.st_uid) && !(value.stat.st_mode & 06022) &&
    (!(value.stat.st_mode & 0200) || (stock_tool && value.stat.st_uid == 0 && value.stat.st_gid == 0))));
  if (receipt || darwin_receipt) need(value.stat.st_uid == authority.st_uid && (value.stat.st_mode & 07777) == 0400 &&
    value.stat.st_size <= preparation_receipt_limit(name));
  char actual[65]; if (!directory) { sha_range(value.fd, 0, value.stat.st_size, actual); need(!strcmp(pin, actual)); }
  struct stat after, named; need(!fstat(value.fd, &after) && !lstat(name, &named)); same_stat(value.stat, after); same_stat(value.stat, named); no_acl(value.fd);
  printf("{\"object\":"); identity(&value); printf(",\"sha256\":");
  if (directory) fputs("null", stdout); else printf("\"%s\"", actual);
  fputs(",\"protectedParents\":true}", stdout); need(!close(value.fd) && !close(root));
}
/* Private access operations share the held case lease and exact copied images.
 * No operator-selected executable, environment, root rule or arbitrary path. */
static pid_t access_pf_pid, access_audit_pid, access_control_pid;
static int access_pf_in = -1, access_pf_out = -1, access_audit_in = -1, access_audit_out = -1;
static int access_control_in = -1, access_control_out = -1;
static struct identity access_pf_helper, access_pf_worker, access_subject, access_peer_identity;
static int access_peer_descriptor = -1;
static char access_vectors[39][8192];
static unsigned access_index;
static int access_descriptor = -1;
static bool access_control, access_ready, access_pending, access_ran;
static unsigned char access_audit_bytes[131072];
static unsigned access_audit_used;
static void access_spawn(struct entry *image, char **args, char **environment, pid_t *pid, int *input, int *output, int *binary) {
  stable(image); int in[2], out[2], data[2]; need(!pipe(in) && !pipe(out)); if (binary) need(!pipe(data));
  posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
  need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) &&
    !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) &&
    !posix_spawn_file_actions_adddup2(&files, in[0], 0) && !posix_spawn_file_actions_adddup2(&files, out[1], 1) &&
    !posix_spawn_file_actions_addopen(&files, 2, "/dev/null", O_WRONLY, 0));
  if (binary) need(!posix_spawn_file_actions_adddup2(&files, data[1], 3));
  need(!posix_spawn(pid, image->path, &files, &attributes, args, environment) &&
    !posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes) && !close(in[0]) && !close(out[1]));
  *input = in[1]; *output = out[0];
  if (binary) { need(!close(data[1])); *binary = data[0]; }
  stable(image);
}
static void access_wait(pid_t *pid, int *input, int *output) {
  need(*pid > 1); int status; while (waitpid(*pid, &status, 0) < 0) need(errno == EINTR);
  need(WIFEXITED(status) && WEXITSTATUS(status) == 0); char byte;
  need(read(*output, &byte, 1) == 0 && !close(*output) && !close(*input)); *input = *output = -1; *pid = 0;
}
static struct entry *access_named(const char *suffix) {
  char name[PATH_MAX]; need(snprintf(name, sizeof(name), "%s%s", case_path, suffix) < sizeof(name));
  struct entry *found = NULL;
  for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].path, name)) { need(!found); found = &entries[i]; }
  need(found && found->fd >= 0); stable(found); return found;
}
static void access_pf_start(struct entry *tool, struct entry *configuration, const char *cdhash, const char *operation) {
  need(case_mode && !access_pf_pid && count > CASE_BASE_COUNT); reservation_guard();
  need(!strcmp(operation, "validate") || !strcmp(operation, "install") || !strcmp(operation, "validate-restore") || !strcmp(operation, "restore"));
  bool restoring = strstr(operation, "restore") != NULL;
  need(tool == access_named("/custody/pfctl") && configuration == access_named(restoring ? "/custody/darwin-pf-before.conf" : "/custody/darwin-pf.conf"));
  signature(tool->path, cdhash); stable(&entries[4]);
  char anchor[64]; snprintf(anchor, sizeof(anchor), "native-poc/%.32s", case_context);
  char *args[] = {entries[4].path, "--pfctl", tool->path, tool->pin, (char *)cdhash,
    configuration->path, configuration->pin, anchor, (char *)operation, NULL};
  char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", NULL};
  access_spawn(&entries[4], args, environment, &access_pf_pid, &access_pf_in, &access_pf_out, NULL);
  char hello[8192]; line(access_pf_out, hello, sizeof(hello)); access_pf_helper = inspect(access_pf_pid);
  printf("{\"helper\":"); emit(access_pf_helper); putchar('}');
}
static void access_pf_park(void) {
  need(access_pf_pid && access_pf_in >= 0); struct identity live = inspect(access_pf_pid);
  need(!memcmp(&live.token, &access_pf_helper.token, sizeof(live.token)) &&
    live.bsd.pbi_start_tvsec == access_pf_helper.bsd.pbi_start_tvsec && live.bsd.pbi_start_tvusec == access_pf_helper.bsd.pbi_start_tvusec);
  need(write(access_pf_in, "P", 1) == 1); char hello[8192]; line(access_pf_out, hello, sizeof(hello));
  /* The declared worker frame is independently read through proc_pidinfo before
   * R. Only the parked helper's one direct child may be accepted. */
  int pids[32]; int size = proc_listchildpids(access_pf_pid, pids, sizeof(pids));
  need(size == sizeof(pid_t) && pids[0] > 1); access_pf_worker = inspect(pids[0]);
  need(access_pf_worker.bsd.pbi_ppid == (unsigned)access_pf_pid && !access_pf_worker.bsd.pbi_uid && !access_pf_worker.bsd.pbi_gid);
  printf("{\"worker\":"); emit(access_pf_worker); putchar('}');
}
static void access_pf_run(void) {
  need(access_pf_pid && access_pf_in >= 0); struct identity worker = inspect(access_pf_worker.token.val[5]);
  need(!memcmp(&worker.token, &access_pf_worker.token, sizeof(worker.token)) &&
    worker.bsd.pbi_start_tvsec == access_pf_worker.bsd.pbi_start_tvsec && worker.bsd.pbi_start_tvusec == access_pf_worker.bsd.pbi_start_tvusec);
  /* Rejoin the last independently read root and owned anchor at the write
   * barrier. A replaced ruleset cannot be overwritten by a parked worker. */
  need(pf_observed); int pf = open("/dev/pf", O_RDONLY | O_CLOEXEC); need(pf >= 0);
  struct pf_status status; need(!ioctl(pf, DIOCGETSTATUS, &status) && status.running && !status.states);
  for (unsigned set = 0; set < PF_RULESET_MAX; set++) {
    struct pfioc_rule rule = {0}; rule.rule.action = pf_action(set);
    need(!ioctl(pf, DIOCGETRULES, &rule) && rule.ticket == root_tickets[set] && rule.nr == root_counts[set]);
    snprintf(rule.anchor, sizeof(rule.anchor), "native-poc/%.32s", case_context); rule.rule.action = pf_action(set);
    need(!ioctl(pf, DIOCGETRULES, &rule) && rule.ticket == case_tickets[set] && rule.nr == case_counts[set]);
  }
#ifdef NATIVE_CI_EXPERIMENT
  pf_observation_guard(pf);
#endif
  need(!close(pf));
  need(write(access_pf_in, "R", 1) == 1); char result[8192]; line(access_pf_out, result, sizeof(result));
  need(!strcmp(result, "{\"exitCode\":0,\"signal\":null}")); access_wait(&access_pf_pid, &access_pf_in, &access_pf_out);
  fputs("{\"exitCode\":0,\"signal\":null}", stdout);
}
static void access_audit_start(struct entry *observer, const char *cdhash, unsigned classes) {
  need(case_mode && count > CASE_BASE_COUNT && !access_audit_pid && classes && observer == access_named("/custody/observer"));
  reservation_guard(); signature(observer->path, cdhash);
  char uid[24], mask[24], outside[24]; snprintf(uid, sizeof(uid), "%u", subject_uid); snprintf(mask, sizeof(mask), "%u", classes);
  struct identity owner = inspect(getpid()); snprintf(outside, sizeof(outside), "%u", owner.token.val[0]);
  char *args[] = {observer->path, uid, mask, outside, NULL};
  char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", NULL}; int diagnostic;
  access_spawn(observer, args, environment, &access_audit_pid, &access_audit_in, &diagnostic, &access_audit_out);
  need(!close(diagnostic)); access_audit_used = 0;
  printf("{\"identity\":"); emit(inspect(access_audit_pid)); putchar('}');
}
static void access_exact(int fd, void *bytes, size_t length) {
  size_t done = 0;
  while (done < length) {
    struct pollfd wait = {.fd = fd, .events = POLLIN}; need(poll(&wait, 1, 30000) == 1 && !(wait.revents & (POLLERR | POLLNVAL)));
    ssize_t n = read(fd, (char *)bytes + done, length - done); if (n < 0 && errno == EINTR) continue; need(n > 0); done += n;
  }
}
static void access_audit(const char *command) {
  need(access_audit_pid && strlen(command) == 1 && strchr("ABS", *command)); reservation_guard();
  need(write(access_audit_in, command, 1) == 1); access_audit_used = 0;
  for (;;) {
    uint32_t marker; access_exact(access_audit_out, &marker, 4); uint32_t size = ntohl(marker);
    need(access_audit_used + 4 <= sizeof(access_audit_bytes)); memcpy(access_audit_bytes + access_audit_used, &marker, 4); access_audit_used += 4;
    unsigned length = size == UINT32_MAX - 1 ? 12 : size == UINT32_MAX ? 8 : size;
    need(length <= 65536 && access_audit_used + length <= sizeof(access_audit_bytes));
    access_exact(access_audit_out, access_audit_bytes + access_audit_used, length); access_audit_used += length;
    if (size == 0 || size >= UINT32_MAX - 1) break;
  }
  char encoded[262145]; hex(access_audit_bytes, access_audit_used, encoded); printf("{\"hex\":\"%s\"}", encoded); memset(access_audit_bytes, 0, sizeof(access_audit_bytes));
}
static void access_audit_close(void) {
  need(access_audit_pid && !access_pending); reservation_guard(); no_subjects(); int status;
  while (waitpid(access_audit_pid, &status, 0) < 0) need(errno == EINTR);
  need(WIFEXITED(status) && WEXITSTATUS(status) == 0); char byte; need(read(access_audit_out, &byte, 1) == 0 && !close(access_audit_out) && !close(access_audit_in));
  access_audit_out = access_audit_in = -1; access_audit_pid = 0; fputs("{\"code\":0,\"signal\":null}", stdout);
}
static int access_targets[39][2], access_servers[39];
static char access_names[39][2][PATH_MAX];
static int access_shm = -1, access_sysv_shm = -1, access_sysv_sem = -1;
static sem_t *access_sem = SEM_FAILED;
static mach_port_t access_mach = MACH_PORT_NULL;
#ifdef NATIVE_CI_EXPERIMENT
static struct timeval access_mach_start, access_mach_end;
static pid_t access_log_pid;
static int access_log_out = -1;
static struct identity access_log_identity;
static struct entry *access_log_tool;
static void access_time(char value[40], struct timeval time) {
  struct tm utc; time_t seconds = time.tv_sec; need(gmtime_r(&seconds, &utc));
  need(strftime(value, 24, "%Y-%m-%dT%H:%M:%S", &utc) == 19);
  need(snprintf(value + 19, 21, ".%06dZ", (int)time.tv_usec) == 8);
}
static void access_mach_result(const char *result) {
  struct identity after = inspect(access_subject.token.val[5]);
  need(!gettimeofday(&access_mach_end, NULL));
  int64_t elapsed = (access_mach_end.tv_sec - access_mach_start.tv_sec) * 1000000LL + access_mach_end.tv_usec - access_mach_start.tv_usec;
  need(elapsed >= 0 && elapsed <= 30000000);
  need(!memcmp(&after.token, &access_subject.token, sizeof(after.token)) &&
    after.bsd.pbi_start_tvsec == access_subject.bsd.pbi_start_tvsec &&
    after.bsd.pbi_start_tvusec == access_subject.bsd.pbi_start_tvusec &&
    after.bsd.pbi_svuid == access_subject.bsd.pbi_svuid && after.bsd.pbi_svgid == access_subject.bsd.pbi_svgid);
  char nonce[33], send[16], canonical[256]; int outcome, native, lookup;
  need(sscanf(result, "{\"nonce\":\"%32[0-9a-f]\",\"result\":%d,\"nativeCode\":%d,\"lookupCode\":%d,\"sendCode\":%15[0-9a-z]}", nonce, &outcome, &native, &lookup, send) == 5);
  snprintf(canonical, sizeof(canonical), "{\"nonce\":\"%.32s\",\"result\":%d,\"nativeCode\":%d,\"lookupCode\":%d,\"sendCode\":%s}", case_context, outcome, native, lookup, send);
  need(!strcmp(canonical, result));
  need(access_control ? !outcome && !native && !lookup && !strcmp(send, "0") :
    outcome == -1 && native == BOOTSTRAP_NOT_PRIVILEGED && lookup == BOOTSTRAP_NOT_PRIVILEGED && !strcmp(send, "null"));
  char started[40], ended[40]; access_time(started, access_mach_start); access_time(ended, access_mach_end);
  canonical[strlen(canonical) - 1] = 0;
  printf("%s,\"mach\":{\"source\":\"custody-mach-v1\",\"startedAt\":\"%s\",\"endedAt\":\"%s\",\"before\":", canonical, started, ended);
  emit(access_subject); fputs(",\"after\":", stdout); emit(after); fputs(",\"receipt\":", stdout);
  if (access_control) {
    struct message { mach_msg_header_t header; char nonce[32]; };
    struct { struct message message; mach_msg_max_trailer_t trailer; } received = {0};
    need(mach_msg(&received.message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT |
      MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
      0, sizeof(received), access_mach, 5000, MACH_PORT_NULL) == MACH_MSG_SUCCESS);
    mach_msg_header_t *header = &received.message.header;
    need(header->msgh_size == sizeof(struct message) && !(header->msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
      header->msgh_local_port == access_mach && header->msgh_remote_port == MACH_PORT_NULL &&
      header->msgh_id == 0x4e504f43 && !memcmp(received.message.nonce, case_context, 32));
    mach_msg_audit_trailer_t *trailer = (void *)((char *)&received + ((header->msgh_size + 3u) & ~3u));
    need(trailer->msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0 && trailer->msgh_trailer_size == sizeof(*trailer) &&
      !memcmp(&trailer->msgh_audit, &access_subject.token, sizeof(access_subject.token)));
    mach_port_status_t status; mach_msg_type_number_t size = MACH_PORT_RECEIVE_STATUS_COUNT;
    need(mach_port_get_attributes(mach_task_self(), access_mach, MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &size) == KERN_SUCCESS &&
      size == MACH_PORT_RECEIVE_STATUS_COUNT && !status.mps_msgcount);
    printf("{\"nonce\":\"%.32s\",\"service\":\"%s\",\"sender\":", case_context, access_names[13][0]);
    emit(after); fputs(",\"auditToken\":[", stdout);
    for (unsigned i = 0; i < 8; i++) printf("%s%u", i ? "," : "", trailer->msgh_audit.val[i]);
    fputs("]}", stdout);
  } else fputs("null", stdout);
  fputs("}}", stdout);
}
static void access_log_start(struct entry *tool, const char *cdhash) {
  need(case_mode && access_pending && access_ran && access_index == 13 && !access_control && !access_log_pid &&
    !strcmp(tool->path, "/usr/bin/log")); reservation_guard(); stable(tool); signature(tool->path, cdhash);
  char start[40], end[40], predicate[512]; struct tm utc; time_t seconds = access_mach_start.tv_sec;
  need(gmtime_r(&seconds, &utc) && strftime(start, sizeof(start), "%Y-%m-%d %H:%M:%S+0000", &utc));
  seconds = access_mach_end.tv_sec + 1;
  need(gmtime_r(&seconds, &utc) && strftime(end, sizeof(end), "%Y-%m-%d %H:%M:%S+0000", &utc));
  snprintf(predicate, sizeof(predicate), "processID == 0 AND senderImagePath == \"/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox\" AND eventMessage CONTAINS \"(%u)\" AND eventMessage CONTAINS \"org.native-poc.%.32s\"", access_subject.token.val[5], case_context);
  char *args[] = {tool->path, "show", "--style", "ndjson", "--start", start, "--end", end, "--info", "--debug", "--predicate", predicate, NULL};
  char *env[] = {"PATH=/usr/bin:/bin", "LANG=C", NULL}; int output[2]; need(!pipe(output));
  posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
  need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) &&
    !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED) &&
    !posix_spawn_file_actions_addopen(&files, 0, "/dev/null", O_RDONLY, 0) &&
    !posix_spawn_file_actions_adddup2(&files, output[1], 1) &&
    !posix_spawn_file_actions_addopen(&files, 2, "/dev/null", O_WRONLY, 0) &&
    !posix_spawn(&access_log_pid, tool->path, &files, &attributes, args, env) &&
    !posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes) && !close(output[1]));
  access_log_out = output[0]; access_log_tool = tool; access_log_identity = inspect(access_log_pid);
  need(access_log_identity.bsd.pbi_ppid == (unsigned)getpid() && !access_log_identity.token.val[1] && !access_log_identity.token.val[2]);
  emit(access_log_identity);
}
static void access_log_run(void) {
  need(access_log_pid && access_log_out >= 0); reservation_guard(); stable(access_log_tool);
  struct identity live = inspect(access_log_pid);
  need(!memcmp(&live.token, &access_log_identity.token, sizeof(live.token)) &&
    live.bsd.pbi_start_tvsec == access_log_identity.bsd.pbi_start_tvsec && live.bsd.pbi_start_tvusec == access_log_identity.bsd.pbi_start_tvusec &&
    !proc_signal_with_audittoken(&live.token, SIGCONT));
  unsigned char bytes[65537]; size_t used = 0; struct timespec start, now; need(!clock_gettime(CLOCK_MONOTONIC, &start));
  for (;;) {
    need(!clock_gettime(CLOCK_MONOTONIC, &now)); long remaining = 12000 - (now.tv_sec - start.tv_sec) * 1000 - (now.tv_nsec - start.tv_nsec) / 1000000;
    struct pollfd wait = {.fd = access_log_out, .events = POLLIN};
    need(remaining > 0 && poll(&wait, 1, (int)remaining) == 1 && !(wait.revents & (POLLERR | POLLNVAL)));
    ssize_t size = read(access_log_out, bytes + used, sizeof(bytes) - used); if (size < 0 && errno == EINTR) continue;
    need(size >= 0); if (!size) break; used += size; need(used <= 65536);
  }
  int status;
  for (;;) {
    pid_t done = waitpid(access_log_pid, &status, WNOHANG); need(done >= 0 || errno == EINTR); if (done > 0) break;
    need(!clock_gettime(CLOCK_MONOTONIC, &now) &&
      (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 < 12000); poll(NULL, 0, 1);
  }
  need(WIFEXITED(status) && WEXITSTATUS(status) == 0 && !close(access_log_out));
  access_log_pid = 0; access_log_out = -1; stable(access_log_tool); access_log_tool = NULL;
  char encoded[131073]; hex(bytes, used, encoded); printf("{\"hex\":\"%s\",\"exitCode\":0,\"signal\":null}", encoded);
}
#endif
static struct timeval access_created;
static struct stat access_unix_identity, access_shm_identity;
static struct shmid_ds access_sysv_shm_identity;
static struct semid_ds access_sysv_sem_identity;
static struct entry *access_directory(const char *path) {
  struct entry *found = NULL;
  for (unsigned i = 0; i < count; i++) if (entries[i].fd >= 0 && !strcmp(entries[i].path, path)) { need(!found); found = &entries[i]; }
  need(found && S_ISDIR(found->stat.st_mode)); stable(found); return found;
}
static int access_seed(const char *path, bool custody) {
  char parent[PATH_MAX]; strcpy(parent, path); char *name = strrchr(parent, '/'); need(name); *name++ = 0;
  struct entry *directory = access_directory(parent);
  int fd = openat(directory->fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); need(fd >= 0); no_acl(fd);
  need(write(fd, case_context, 32) == 32 && !fchown(fd, custody ? 0 : subject_uid, custody ? 0 : subject_gid) &&
    !fchmod(fd, custody ? 0400 : 0600) && !fsync(fd));
  return fd;
}
static uint32_t access_scope(const char *text, char *literal, size_t capacity) {
  size_t length = strcspn(text, "%"); need(length > 0 && length < capacity);
  memcpy(literal, text, length); literal[length] = 0;
  uint64_t scope = 0;
  if (text[length]) {
    size_t offset = length + 1; need(text[offset] >= '1' && text[offset] <= '9');
    for (; text[offset]; offset++) {
      need(text[offset] >= '0' && text[offset] <= '9'); scope = scope * 10 + (unsigned)(text[offset] - '0'); need(scope <= UINT32_MAX);
    }
  }
  return (uint32_t)scope;
}
static socklen_t access_address(struct sockaddr_storage *storage, unsigned family, const char *name, unsigned port) {
  char literal[INET6_ADDRSTRLEN]; uint32_t scope = access_scope(name, literal, sizeof(literal));
#ifndef NATIVE_CI_EXPERIMENT
  need(!scope);
#endif
  memset(storage, 0, sizeof(*storage));
  if (family == AF_INET) { need(!scope); struct sockaddr_in *a = (void *)storage; a->sin_len = sizeof(*a); a->sin_family = family; a->sin_port = htons(port); need(inet_pton(family, literal, &a->sin_addr) == 1); return sizeof(*a); }
  need(family == AF_INET6);
  struct sockaddr_in6 *a = (void *)storage; a->sin6_len = sizeof(*a); a->sin6_family = family; a->sin6_port = htons(port); need(inet_pton(family, literal, &a->sin6_addr) == 1);
  need(!!scope == !!IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr)); a->sin6_scope_id = scope; return sizeof(*a);
}
static bool owned_access_socket(const char *name, const struct stat *st) {
  if (strcmp(name, "ipc")) return false;
  need(access_servers[14] >= 0 && S_ISSOCK(st->st_mode)); same_stat(access_unix_identity, *st); return true;
}
static void access_resources(void) {
  need(!gettimeofday(&access_created, NULL));
  for (unsigned i = 0; i < 39; i++) { access_targets[i][0] = access_targets[i][1] = access_servers[i] = -1; }
  const char *targets[] = {"/storage/work/inspection", "/storage/work/edit", "/storage/metadata/sentinel", "/storage/work/.git", "/storage/work/.git", "/storage/work/.git", "/storage/work", "/custody/sentinel", "/custody/sentinel", "/checkout/sentinel", "/configuration/sentinel", "/credentials/sentinel", "/outside/sentinel"};
  for (unsigned i = 0; i < 39; i++) {
    char vector[8192]; strcpy(vector, access_vectors[i]); char *next, *op = strtok_r(vector, " ", &next), *encoded = strtok_r(NULL, " ", &next), *remote = strtok_r(NULL, " ", &next), *local = strtok_r(NULL, " ", &next);
    need(op && encoded && remote && local && !strtok_r(NULL, " ", &next)); decode(encoded, access_names[i][0], PATH_MAX);
    const char *operations[] = {"read", "write", "write", "write", "unlink", "replace", "parent", "read", "write", "read", "read", "read", "write", "mach", "unix", "shm", "sem", "sysv-shm", "sysv-sem"};
    if (i < 19) need(!strcmp(op, operations[i]));
    else if (i < 35) need(!strcmp(op, (i - 19) % 4 == 0 ? "tcp4" : (i - 19) % 4 == 1 ? "udp4" : (i - 19) % 4 == 2 ? "tcp6" : "udp6"));
    else need(!strcmp(op, "tcp4-pair") || !strcmp(op, "tcp6-pair") || !strcmp(op, "udp4-pair") || !strcmp(op, "udp6-pair"));
    if (i < 13) {
      char expected[PATH_MAX]; need(snprintf(expected, sizeof(expected), "%s%s", case_path, targets[i]) < sizeof(expected) && !strcmp(expected, access_names[i][0]));
      if (i == 6) access_targets[i][0] = dup(entries[3].fd);
      else {
        int previous = -1; for (unsigned j = 0; j < i; j++) if (!strcmp(access_names[j][0], expected)) previous = (int)j;
        access_targets[i][0] = previous < 0 ? access_seed(expected, i == 7 || i == 8) : dup(access_targets[previous][0]);
      }
      need(access_targets[i][0] >= 0);
      if (i >= 2) {
        snprintf(access_names[i][1], PATH_MAX, "%s/outside/control-%u", case_path, i);
        if (i == 6) {
          struct entry *parent = access_named("/outside"); char leaf[64]; snprintf(leaf, sizeof(leaf), "control-%u", i);
          need(!mkdirat(parent->fd, leaf, 0700)); int fd = openat(parent->fd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); need(fd >= 0);
          int seed = openat(fd, "inspection", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); need(seed >= 0 && write(seed, case_context, 32) == 32 && !fsync(seed) && !close(seed));
          access_targets[i][1] = fd; snprintf(leaf, sizeof(leaf), "control-%u.replacement", i); need(!mkdirat(parent->fd, leaf, 0700));
        } else access_targets[i][1] = access_seed(access_names[i][1], false);
        if (!strcmp(op, "replace")) { char replacement[PATH_MAX]; need(snprintf(replacement, sizeof(replacement), "%s.replacement", access_names[i][1]) < sizeof(replacement)); need(!close(access_seed(replacement, false))); }
      }
    } else if (i == 13) {
      char expected[128]; snprintf(expected, sizeof(expected), "org.native-poc.%.32s", case_context); need(!strcmp(expected, access_names[i][0]));
      mach_port_t absent; need(bootstrap_look_up(bootstrap_port, expected, &absent) == BOOTSTRAP_UNKNOWN_SERVICE &&
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &access_mach) == KERN_SUCCESS &&
        mach_port_insert_right(mach_task_self(), access_mach, access_mach, MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS &&
        bootstrap_register(bootstrap_port, expected, access_mach) == KERN_SUCCESS);
    } else if (i == 14) {
      char expected[PATH_MAX]; snprintf(expected, sizeof(expected), "%s/ipc", case_path); need(!strcmp(expected, access_names[i][0]));
      struct sockaddr_un address = {.sun_len = sizeof(address), .sun_family = AF_UNIX}; need(strlen(expected) < sizeof(address.sun_path)); strcpy(address.sun_path, expected);
      int fd = socket(AF_UNIX, SOCK_STREAM, 0); need(fd >= 0 && !bind(fd, (void *)&address, sizeof(address)) && !chmod(expected, 0600) && !listen(fd, 1)); access_servers[i] = fd; need(!lstat(expected, &access_unix_identity) && S_ISSOCK(access_unix_identity.st_mode));
    } else if (i == 15 || i == 16) {
      char expected[64]; snprintf(expected, sizeof(expected), "/native-poc-%.32s", case_context); need(!strcmp(expected, access_names[i][0]));
      if (i == 15) { access_shm = shm_open(expected, O_RDWR | O_CREAT | O_EXCL, 0600); need(access_shm >= 0 && !ftruncate(access_shm, 32) && pwrite(access_shm, case_context, 32, 0) == 32 && !fstat(access_shm, &access_shm_identity)); }
      else { access_sem = sem_open(expected, O_CREAT | O_EXCL, 0600, 0); need(access_sem != SEM_FAILED); }
    } else if (i == 17 || i == 18) {
      key_t key = (key_t)number(remote); need(key != IPC_PRIVATE);
      if (i == 17) { access_sysv_shm = shmget(key, 32, IPC_CREAT | IPC_EXCL | 0600); need(access_sysv_shm >= 0); void *bytes = shmat(access_sysv_shm, NULL, 0); need(bytes != (void *)-1); memcpy(bytes, case_context, 32); need(!shmdt(bytes) && !shmctl(access_sysv_shm, IPC_STAT, &access_sysv_shm_identity)); }
      else { access_sysv_sem = semget(key, 1, IPC_CREAT | IPC_EXCL | 0600); need(access_sysv_sem >= 0); union semun argument = {.buf = &access_sysv_sem_identity}; need(!semctl(access_sysv_sem, 0, IPC_STAT, argument)); }
    } else if (i < 35) {
      unsigned family = strstr(op, "6") ? AF_INET6 : AF_INET, protocol = strstr(op, "udp") ? IPPROTO_UDP : IPPROTO_TCP;
      need(number(remote) >= 1024 && number(local) >= 1024);
      int fd = socket(family, protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, protocol); need(fd >= 0 && !fcntl(fd, F_SETFD, FD_CLOEXEC));
      struct sockaddr_storage address; socklen_t size = access_address(&address, family, access_names[i][0], number(remote));
      if (family == AF_INET6) { int only = 1; need(!setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only))); }
      need(!bind(fd, (void *)&address, size) && (protocol != IPPROTO_TCP || !listen(fd, 1))); access_servers[i] = fd;
    }
  }
  char replacement[PATH_MAX]; snprintf(replacement, sizeof(replacement), "%s/storage/work/.git.replacement", case_path); need(!close(access_seed(replacement, false)));
}
/* Service readiness is an actual bound exclusive socket. Echo is a fixed nonce
 * response inside the acknowledged window, never a fake successful peer. */
static void access_service(unsigned index) {
  int fd = access_servers[index], type; socklen_t ts = sizeof(type); need(fd >= 0 && !getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &ts));
  struct sockaddr_storage peer; socklen_t size = sizeof(peer); char bytes[33];
  if (type == SOCK_STREAM) {
    int connected = accept(fd, NULL, NULL); need(connected >= 0); struct timeval timeout = {.tv_sec = 5}; need(!setsockopt(connected, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    need(recv(connected, bytes, 32, MSG_WAITALL) == 32 && !memcmp(bytes, case_context, 32) && send(connected, bytes, 32, 0) == 32 && !close(connected));
  } else need(recvfrom(fd, bytes, sizeof(bytes), 0, (void *)&peer, &size) == 32 && !memcmp(bytes, case_context, 32) && sendto(fd, bytes, 32, 0, (void *)&peer, size) == 32);
}
static void access_result_line(int fd, char *out, size_t bound) {
  size_t offset = 0;
  for (;;) {
    struct pollfd waits[40] = {{.fd = fd, .events = POLLIN}}; unsigned used = 1, indexes[39];
    for (unsigned i = 19; i < 35; i++) if (access_servers[i] >= 0) { indexes[used - 1] = i; waits[used++] = (struct pollfd){.fd = access_servers[i], .events = POLLIN}; }
    need(poll(waits, used, 30000) > 0);
    for (unsigned i = 1; i < used; i++) if (waits[i].revents & POLLIN) access_service(indexes[i - 1]);
    if (!(waits[0].revents & POLLIN)) continue;
    char byte; need(read(fd, &byte, 1) == 1 && byte && offset + 1 < bound);
    if (byte == '\n') { out[offset] = 0; return; } out[offset++] = byte;
  }
}
static void access_file_target(unsigned index, bool control) {
  int fd = access_targets[index][control]; need(fd >= 0); struct stat before, after; need(!fstat(fd, &before)); no_acl(fd);
  bool dir = S_ISDIR(before.st_mode); int bytes = dir ? openat(fd, "inspection", O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : fd; need(bytes >= 0);
  struct stat contents; need(!fstat(bytes, &contents) && contents.st_size > 0 && contents.st_size <= 65536);
  char hash[65], data[131073]; unsigned char value[65536]; read_at(bytes, value, contents.st_size, 0); sha_range(bytes, 0, contents.st_size, hash); hex(value, contents.st_size, data);
  need(!fstat(fd, &after)); same_stat(before, after);
  if (!control) { struct stat named; need(!lstat(access_names[index][0], &named)); same_stat(before, named); }
  struct entry object = {.fd = fd, .stat = after};
  printf("{\"kind\":\"path\",\"path\":\"%s\",\"value\":{\"object\":", access_names[index][control]); identity(&object);
  printf(",\"sha256\":\"%s\",\"hex\":\"%s\"}}", hash, data); if (dir) need(!close(bytes));
}
static void access_socket_value(pid_t pid, int descriptor, bool source) {
  struct identity before = inspect(pid), after; struct socket_fdinfo socket;
  need(proc_pidfdinfo(pid, descriptor, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) == sizeof(socket) && socket.psi.soi_so &&
    (socket.psi.soi_family == AF_INET || socket.psi.soi_family == AF_INET6) &&
    (socket.psi.soi_protocol == IPPROTO_TCP || socket.psi.soi_protocol == IPPROTO_UDP) && !(socket.psi.soi_options & (SO_REUSEADDR | SO_REUSEPORT)));
  struct in_sockinfo *in = socket.psi.soi_protocol == IPPROTO_TCP ? &socket.psi.soi_proto.pri_tcp.tcpsi_ini : &socket.psi.soi_proto.pri_in;
  char address[INET6_ADDRSTRLEN]; const void *local = socket.psi.soi_family == AF_INET ? (const void *)&in->insi_laddr.ina_46.i46a_addr4 : (const void *)&in->insi_laddr.ina_6;
  need(inet_ntop(socket.psi.soi_family, local, address, sizeof(address)) && ntohs((uint16_t)in->insi_lport) >= 1024);
  after = inspect(pid); need(!memcmp(&before.token, &after.token, sizeof(before.token)) && before.bsd.pbi_start_tvsec == after.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == after.bsd.pbi_start_tvusec);
  fputs("{\"subject\":", stdout); emit(after); printf(",\"descriptor\":%d,\"kernelId\":\"%llx\",\"family\":\"%s\",\"protocol\":\"%s\",\"address\":\"%s\",\"port\":%u,\"exclusive\":true}", descriptor,
    (unsigned long long)socket.psi.soi_so, socket.psi.soi_family == AF_INET ? "inet" : "inet6", socket.psi.soi_protocol == IPPROTO_TCP ? "tcp" : "udp", address, ntohs((uint16_t)in->insi_lport));
  (void)source;
}
static void access_target_socket(unsigned index) {
  int server = access_servers[index];
  if (index >= 35) {
    unsigned port = 0; char vector[8192]; strcpy(vector, access_vectors[index]); char *next; strtok_r(vector, " ", &next); strtok_r(NULL, " ", &next); port = number(strtok_r(NULL, " ", &next));
    for (unsigned i = 0; i < case_socket_count; i++) { struct sockaddr_storage a; socklen_t size = sizeof(a); need(!getsockname(case_sockets[i], (void *)&a, &size)); unsigned p = a.ss_family == AF_INET ? ntohs(((struct sockaddr_in *)&a)->sin_port) : ntohs(((struct sockaddr_in6 *)&a)->sin6_port); if (p == port) server = case_sockets[i]; }
  }
  need(server >= 0 && access_descriptor >= 0);
  fputs("{\"kind\":\"socket\",\"path\":\"\",\"value\":{\"source\":", stdout); access_socket_value(access_subject.token.val[5], access_descriptor, true);
  fputs(",\"target\":", stdout); access_socket_value(getpid(), server, false); fputs("}}", stdout);
}
static void access_controls_close(void) {
  need(!access_pending && !access_control_pid && !access_audit_pid && !access_pf_pid); reservation_guard(); no_subjects();
  for (unsigned i = 0; i < 39; i++) {
    for (unsigned j = 0; j < 2; j++) if (access_targets[i][j] >= 0) { need(!close(access_targets[i][j])); access_targets[i][j] = -1; }
    if (access_servers[i] >= 0) { need(!close(access_servers[i])); access_servers[i] = -1; }
  }
  if (access_mach != MACH_PORT_NULL) {
    mach_port_t named; need(bootstrap_look_up(bootstrap_port, access_names[13][0], &named) == KERN_SUCCESS && named == access_mach);
    need(mach_port_deallocate(mach_task_self(), named) == KERN_SUCCESS && bootstrap_register(bootstrap_port, access_names[13][0], MACH_PORT_NULL) == KERN_SUCCESS && mach_port_destroy(mach_task_self(), access_mach) == KERN_SUCCESS); access_mach = MACH_PORT_NULL;
  }
  struct stat named;
  need(!lstat(access_names[14][0], &named)); same_stat(access_unix_identity, named); need(!unlink(access_names[14][0]));
  if (access_shm >= 0) {
    int fd = shm_open(access_names[15][0], O_RDONLY, 0); need(fd >= 0 && !fstat(fd, &named)); same_stat(access_shm_identity, named);
    need(!close(fd) && !shm_unlink(access_names[15][0]) && !close(access_shm)); access_shm = -1;
  }
  if (access_sem != SEM_FAILED) {
    sem_t *named_sem = sem_open(access_names[16][0], 0); need(named_sem != SEM_FAILED && named_sem == access_sem);
    need(!sem_close(named_sem) && !sem_unlink(access_names[16][0]) && !sem_close(access_sem)); access_sem = SEM_FAILED;
  }
  if (access_sysv_shm >= 0) {
    struct shmid_ds actual; need(!shmctl(access_sysv_shm, IPC_STAT, &actual) && actual.shm_ctime == access_sysv_shm_identity.shm_ctime && !memcmp(&actual.shm_perm, &access_sysv_shm_identity.shm_perm, sizeof(actual.shm_perm)));
    need(!shmctl(access_sysv_shm, IPC_RMID, NULL)); access_sysv_shm = -1;
  }
  if (access_sysv_sem >= 0) {
    struct semid_ds actual; union semun argument = {.buf = &actual}; need(!semctl(access_sysv_sem, 0, IPC_STAT, argument) && actual.sem_ctime == access_sysv_sem_identity.sem_ctime && !memcmp(&actual.sem_perm, &access_sysv_sem_identity.sem_perm, sizeof(actual.sem_perm)));
    need(semctl(access_sysv_sem, 0, IPC_RMID) == 0); access_sysv_sem = -1;
  }
  fputs("null", stdout);
}
/* Fresh recovery never adopts or unlinks a named IPC object. The immutable
 * bank pins exact names/keys; all named objects and old owner domains must be
 * independently absent before policy or exclusion can be released. */
static void access_controls_retired(struct entry *bank) {
  need(case_mode && case_recovery && bank == access_named("/custody/access-cases")); reservation_guard(); no_subjects(); stable(bank);
  char bytes[65536]; need(bank->stat.st_size > 0 && bank->stat.st_size < sizeof(bytes)); read_at(bank->fd, bytes, bank->stat.st_size, 0); bytes[bank->stat.st_size] = 0;
  char *next; unsigned row = 0;
  for (char *value = strtok_r(bytes, "\n", &next); value; value = strtok_r(NULL, "\n", &next)) {
    char *field, *op = strtok_r(value, " ", &field), *encoded = strtok_r(NULL, " ", &field), *remote = strtok_r(NULL, " ", &field), *local = strtok_r(NULL, " ", &field);
    need(row < 39 && op && encoded && remote && local && !strtok_r(NULL, " ", &field)); char name[PATH_MAX]; decode(encoded, name, sizeof(name));
    if (row == 13) { char expected[128]; snprintf(expected, sizeof(expected), "org.native-poc.%.32s", case_context); need(!strcmp(op, "mach") && !strcmp(name, expected)); mach_port_t found; need(bootstrap_look_up(bootstrap_port, name, &found) == BOOTSTRAP_UNKNOWN_SERVICE); }
    if (row == 14) { char expected[PATH_MAX]; snprintf(expected, sizeof(expected), "%s/ipc", case_path); need(!strcmp(op, "unix") && !strcmp(name, expected)); struct stat st; errno = 0; need(lstat(name, &st) < 0 && errno == ENOENT); }
    if (row == 15 || row == 16) { char expected[64]; snprintf(expected, sizeof(expected), "/native-poc-%.32s", case_context); need(!strcmp(name, expected)); errno = 0;
      if (row == 15) need(!strcmp(op, "shm") && shm_open(name, O_RDONLY, 0) < 0 && errno == ENOENT);
      else need(!strcmp(op, "sem") && sem_open(name, 0) == SEM_FAILED && errno == ENOENT);
    }
    if (row == 17 || row == 18) { key_t key = (key_t)number(remote); need(key != IPC_PRIVATE); errno = 0;
      if (row == 17) need(!strcmp(op, "sysv-shm") && shmget(key, 1, 0) < 0 && errno == ENOENT);
      else need(!strcmp(op, "sysv-sem") && semget(key, 1, 0) < 0 && errno == ENOENT);
    }
    row++;
  }
  need(row == 39); stable(bank); fputs("{\"absent\":true}", stdout);
}
static void access_counters(void) {
  reservation_guard(); int fd = open("/dev/pf", O_RDONLY | O_CLOEXEC); need(fd >= 0);
#ifdef NATIVE_CI_EXPERIMENT
  need(pf_observed); pf_observation_guard(fd);
#endif
  struct pfioc_rule query = {0}; snprintf(query.anchor, sizeof(query.anchor), "native-poc/%.32s", case_context); query.rule.action = PF_PASS;
  need(!ioctl(fd, DIOCGETRULES, &query)); unsigned total = query.nr, ticket = query.ticket; need(total <= 64); putchar('[');
  for (unsigned i = 0; i < total; i++) {
    query.nr = i; query.ticket = ticket; query.rule.action = PF_PASS; need(!ioctl(fd, DIOCGETRULE, &query));
    struct pf_rule *r = &query.rule;
#ifdef NATIVE_CI_EXPERIMENT
    uint64_t rule_ticket = r->ticket;
#endif
    uint64_t packets = r->packets[0] + r->packets[1]; need(packets >= r->packets[0]);
    memset(&r->entries, 0, sizeof(r->entries));
#ifndef NATIVE_CI_EXPERIMENT
    memset(r->skip, 0, sizeof(r->skip));
#endif
    r->kif = NULL; r->anchor = NULL; r->overload_tbl = NULL;
    pf_rule_counters(r);
    memset(&r->rpool.list, 0, sizeof(r->rpool.list)); r->rpool.cur = NULL;
    unsigned char sum[32]; char hash[65]; need(CC_SHA256(r, sizeof(*r), sum)); hex(sum, sizeof(sum), hash);
#ifdef NATIVE_CI_EXPERIMENT
    printf("%s{\"purpose\":\"experiment\",\"anchor\":\"%s\",\"set\":1,\"ticket\":%u,\"ruleTicket\":\"%llu\",", i ? "," : "", query.anchor, ticket, (unsigned long long)rule_ticket);
    const char *start = "";
#else
    const char *start = i ? ",{" : "{";
#endif
    printf("%s\"index\":%u,\"packets\":\"%llu\",\"ruleSha256\":\"%s\",\"action\":\"%s\"}", start, i, (unsigned long long)packets, hash, r->action == PF_PASS ? "permit" : "deny");
  }
  query.rule.action = PF_PASS; need(!ioctl(fd, DIOCGETRULES, &query) && query.nr == total && query.ticket == ticket);
#ifdef NATIVE_CI_EXPERIMENT
  pf_observation_guard(fd);
#endif
  need(!close(fd)); putchar(']');
}

static void access_provision(struct entry *bank) {
  need(case_mode && count > CASE_BASE_COUNT && !access_ready && !access_pending && bank == access_named("/custody/access-cases"));
  reservation_guard(); no_subjects(); need(bank->stat.st_size > 0 && bank->stat.st_size < 65536);
  char bytes[65536]; read_at(bank->fd, bytes, bank->stat.st_size, 0); need(!memchr(bytes, 0, bank->stat.st_size)); bytes[bank->stat.st_size] = 0;
  char *next; unsigned row = 0;
  for (char *value = strtok_r(bytes, "\n", &next); value; value = strtok_r(NULL, "\n", &next)) {
    need(row < 39 && strlen(value) < sizeof(access_vectors[0])); strcpy(access_vectors[row++], value);
  }
  need(row == 39); access_resources(); access_ready = true; fputs("null", stdout);
}
static void access_attempt(unsigned control, unsigned index) {
  need(access_ready && !access_pending && index < 39 && control <= 1 && (!control || (index >= 2 && index < 35))); reservation_guard();
  access_index = index; access_control = control != 0; access_peer_descriptor = -1;
  char vector[8192]; strcpy(vector, access_vectors[index]); char *args[5], *next; unsigned n = 0;
  for (char *p = strtok_r(vector, " ", &next); p; p = strtok_r(NULL, " ", &next)) { need(n < 4); args[n++] = p; } need(n == 4);
  char nonce[33], target[PATH_MAX]; memcpy(nonce, case_context, 32); nonce[32] = 0; decode(args[1], target, sizeof(target));
  if (control && index < 13) strcpy(target, access_names[index][1]);
  if (control) {
    need(!access_control_pid); char *argv[] = {entries[5].path, nonce, args[0], target, args[2], index >= 19 ? "0" : args[3], NULL};
    char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", "NATIVE_ACCESS_CUSTODY=true", "NATIVE_ACCESS_CONTROL=true", NULL};
    access_spawn(&entries[5], argv, environment, &access_control_pid, &access_control_in, &access_control_out, NULL);
    char parked[8192]; line(access_control_out, parked, sizeof(parked)); access_subject = inspect(access_control_pid);
    char nonceRead[33]; unsigned pid; need(sscanf(parked, "{\"nonce\":\"%32[0-9a-f]\",\"parked\":true,\"pid\":%u,\"descriptor\":%d}", nonceRead, &pid, &access_descriptor) == 3 && pid == (unsigned)access_control_pid && !strncmp(nonceRead, case_context, 32));
    need(!access_subject.bsd.pbi_uid && !access_subject.bsd.pbi_gid);
  } else {
    need(case_pid && case_data >= 0); char command[8192]; int size = snprintf(command, sizeof(command), "%s %s\n", nonce, access_vectors[index]);
    need(size > 0 && size < sizeof(command) && write(case_data, command, size) == size);
    char parked[8192]; line(case_data, parked, sizeof(parked));
    unsigned pid; char expected[128]; need(sscanf(parked, "{\"nonce\":\"%32[0-9a-f]\",\"parked\":true,\"pid\":%u,\"descriptor\":%d}", nonce, &pid, &access_descriptor) == 3);
    snprintf(expected, sizeof(expected), "{\"nonce\":\"%.32s\",\"parked\":true,\"pid\":%u,\"descriptor\":%d}", case_context, pid, access_descriptor); need(!strcmp(parked, expected));
    access_subject = inspect(pid); need(access_subject.token.val[0] == subject_uid && access_subject.token.val[1] == subject_uid && access_subject.token.val[2] == subject_gid);
  }
  access_pending = true; access_ran = false; printf("{\"identity\":"); emit(access_subject); putchar('}');
}
static void access_run(unsigned control) {
  need(access_pending && !access_ran && control == access_control); reservation_guard(); struct identity live = inspect(access_subject.token.val[5]);
  need(!memcmp(&live.token, &access_subject.token, sizeof(live.token)) && live.bsd.pbi_start_tvsec == access_subject.bsd.pbi_start_tvsec && live.bsd.pbi_start_tvusec == access_subject.bsd.pbi_start_tvusec && live.bsd.pbi_svuid == access_subject.bsd.pbi_svuid && live.bsd.pbi_svgid == access_subject.bsd.pbi_svgid);
  int fd = access_control ? access_control_in : case_data, output = access_control ? access_control_out : case_data;
#ifdef NATIVE_CI_EXPERIMENT
  if (access_index == 13) need(!gettimeofday(&access_mach_start, NULL));
#endif
  need(write(fd, "P", 1) == 1); char result[8192];
  for (unsigned i = 0; i < 4; i++) {
    access_result_line(output, result, sizeof(result));
    if (strstr(result, "\"nativeCode\":")) {
#ifdef NATIVE_CI_EXPERIMENT
      if (access_index == 13) access_mach_result(result); else
#endif
        fputs(result, stdout);
      access_ran = true; return;
    }
    if (strstr(result, "\"ready\":true")) {
      char nonce[33]; unsigned pid; need(access_index >= 35 && !access_control && sscanf(result, "{\"nonce\":\"%32[0-9a-f]\",\"listener\":%u,\"descriptor\":%d,\"ready\":true}", nonce, &pid, &access_peer_descriptor) == 3 && !strncmp(nonce, case_context, 32) && access_peer_descriptor >= 0);
      access_peer_identity = inspect(pid); need(access_peer_identity.bsd.pbi_ppid == access_subject.token.val[5] && access_peer_identity.token.val[0] == subject_uid && access_peer_identity.token.val[1] == subject_uid && access_peer_identity.token.val[2] == subject_gid && access_peer_identity.token.val[6] == case_asid);
      need(write(fd, "P", 1) == 1);
    }
    else need(strstr(result, "\"readNonce\":"));
  } need(0);
}
static void access_peer(void) {
  need(access_pending && access_ran && access_index >= 35 && !access_control && access_peer_descriptor >= 0);
  struct identity actual = inspect(access_peer_identity.token.val[5]); need(!memcmp(&actual.token, &access_peer_identity.token, sizeof(actual.token)) && actual.bsd.pbi_start_tvsec == access_peer_identity.bsd.pbi_start_tvsec && actual.bsd.pbi_start_tvusec == access_peer_identity.bsd.pbi_start_tvusec);
  fputs("{\"identity\":", stdout); emit(actual); fputs(",\"socket\":", stdout); access_socket_value(actual.token.val[5], access_peer_descriptor, true); putchar('}');
}
static void access_complete(unsigned control) {
  need(access_pending && access_ran && control == access_control); reservation_guard();
#ifdef NATIVE_CI_EXPERIMENT
  need(!access_log_pid);
#endif
  if (access_control) { need(write(access_control_in, "P", 1) == 1); access_wait(&access_control_pid, &access_control_in, &access_control_out); }
  else { need(write(case_data, "P", 1) == 1); char complete[64]; line(case_data, complete, sizeof(complete)); need(!strcmp(complete, "{\"complete\":true}")); }
  access_pending = false; access_ran = false; fputs("null", stdout);
}
static void access_target(unsigned index, unsigned control) {
  need(access_ready && access_pending && index == access_index && control == access_control && index < 39); reservation_guard();
  char vector[8192]; strcpy(vector, access_vectors[index]); char *next, *operation = strtok_r(vector, " ", &next), *encoded = strtok_r(NULL, " ", &next);
  need(operation && encoded); char name[PATH_MAX]; decode(encoded, name, sizeof(name));
  if (index < 13) { access_file_target(index, control); return; }
  if (index >= 19) { access_target_socket(index); return; }
  printf("{\"kind\":\"ipc\",\"path\":\"%s\",\"value\":", name);
  if (index == 17 || index == 18) {
    const char *key = strtok_r(NULL, " ", &next); need(key); int id = index == 17 ? shmget((key_t)number(key), 32, 0) : semget((key_t)number(key), 1, 0); need(id >= 0);
    effective_ipc(index == 17 ? 3 : 2, id);
  } else {
    /* These objects have independently held native creation custody. An audit
     * route still needs an actual matching selector; missing Mach/POSIX routes
     * cannot be replaced by fixture return values. */
    unsigned type = index == 13 ? 4 : index == 14 ? 5 : index == 15 ? 6 : 7;
    uint64_t handle = index == 13 ? access_mach : index == 14 ? (unsigned)access_servers[index] : index == 15 ? (unsigned)access_shm : (uint64_t)(uintptr_t)access_sem;
    need(handle > 0);
    if (index == 13) { mach_port_type_t rights; need(mach_port_type(mach_task_self(), access_mach, &rights) == KERN_SUCCESS && (rights & MACH_PORT_TYPE_RECEIVE)); }
    if (index == 15) { struct stat st; need(!fstat(access_shm, &st) && st.st_uid == 0 && st.st_size == 32); }
    if (index == 16) { sem_t *named = sem_open(name, 0); need(named != SEM_FAILED && named == access_sem && !sem_close(named)); }
    unsigned char sum[32]; char hash[65]; need(CC_SHA256(name, strlen(name), sum)); hex(sum, sizeof(sum), hash);
    printf("{\"type\":%u,\"id\":null,\"nativeHandle\":\"%llu\",\"created\":\"%llu\",\"authoritySha256\":\"%s\"}", type, (unsigned long long)handle, (unsigned long long)access_created.tv_sec, hash);
  }
  putchar('}');
}
static void access_payload_sockets(void) {
  need(case_mode && case_pid && case_data >= 0 && case_socket_count == 8); reservation_guard();
  char rights[CMSG_SPACE(sizeof(case_sockets))] = {0}, flag = 'F'; struct iovec io = {.iov_base = &flag, .iov_len = 1};
  struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = rights, .msg_controllen = sizeof(rights)};
  struct cmsghdr *header = CMSG_FIRSTHDR(&message); header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(case_sockets));
  memcpy(CMSG_DATA(header), case_sockets, sizeof(case_sockets)); need(sendmsg(case_data, &message, 0) == 1);
  char ready[64]; line(case_data, ready, sizeof(ready)); need(!strcmp(ready, "{\"held\":8}")); fputs(ready, stdout);
}
static void access_sockets(void) {
  need(case_mode && case_socket_count == 8); reservation_guard(); putchar('[');
  for (unsigned i = 0; i < case_socket_count; i++) { if (i) putchar(','); printf("{\"subject\":"); emit(inspect(getpid())); printf(",\"descriptor\":%d}", case_sockets[i]); } putchar(']');
}


/* Fixed file probes execute in this sealed owner. Each child parks before the
 * independent reader admits its complete identity. No caller pathname enters
 * a syscall; roots and foreign volumes come only from the pinned slot plan. */
struct operation_child { pid_t pid; int input, output; struct identity identity; };
static struct operation_child file_callers[3], file_reader, file_probe;
static unsigned file_caller_count;
static int control_root = -1, control_parent = -1, control_saved = -1, control_foreign = -1;
static char control_kind[16];
static bool control_mounted;
static struct operation_child volume_owner;
static int volume_mode;
static void operation_guard(void) { need(case_mode && case_started && getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0); reservation_guard(); }
static void operation_session(uid_t uid) {
  (void)audit_fresh(uid);
}
static void operation_control(int fd, char expected) { char byte; struct pollfd wait = {.fd = fd, .events = POLLIN};
  need(poll(&wait, 1, 30000) == 1 && read(fd, &byte, 1) == 1 && byte == expected); }
static void operation_ready(int fd) { struct identity value = inspect(getpid()); need(write(fd, &value, sizeof(value)) == sizeof(value)); }
static void operation_fds(int first, int second) {
  struct proc_fdinfo descriptors[512]; int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
  need(size > 0 && size < sizeof(descriptors) && !(size % sizeof(descriptors[0])));
  for (unsigned i = 0; i < (unsigned)size / sizeof(descriptors[0]); i++) {
    int fd = descriptors[i].proc_fd; if (fd != first && fd != second) need(!close(fd));
  }
}
static void operation_born(struct operation_child *child, int in[2], int out[2], pid_t pid) {
  need(pid > 1 && !close(in[0]) && !close(out[1])); child->pid = pid; child->input = in[1]; child->output = out[0];
  need(read(child->output, &child->identity, sizeof(child->identity)) == sizeof(child->identity) && child->identity.token.val[5] == (unsigned)pid);
  emit(child->identity);
}
static void operation_reap(struct operation_child *child) { int status; while (waitpid(child->pid, &status, 0) < 0) need(errno == EINTR);
  need(WIFEXITED(status) && WEXITSTATUS(status) == 0 && !close(child->input)); char extra;
  need(read(child->output, &extra, 1) == 0 && !close(child->output)); child->pid = 0; }
static void file_root(struct entry *root) { operation_guard(); char expected[PATH_MAX];
  need(snprintf(expected, sizeof(expected), "%s/custody/files", case_path) < sizeof(expected) && !strcmp(root->path, expected));
  (void)identify(root->fd, true, 0); }
static void file_object(int at, const char *name, bool directory, bool optional) {
  struct stat named, held; errno = 0;
  if (fstatat(at, name, &named, AT_SYMLINK_NOFOLLOW)) { need(optional && errno == ENOENT); fputs("null", stdout); return; }
  bool symlink = S_ISLNK(named.st_mode);
  int fd = openat(at, name, O_RDONLY | O_CLOEXEC | O_NONBLOCK | (symlink ? O_SYMLINK : O_NOFOLLOW) | (directory && !symlink ? O_DIRECTORY : 0));
  need(fd >= 0 && !fstat(fd, &held)); same_stat(named, held); no_acl(fd);
  if (strcmp(name, ".")) file_name_at(at, name, fd);
  struct statfs fs; char id[192];
  struct attrlist attrs = {.bitmapcount = ATTR_BIT_MAP_COUNT, .volattr = ATTR_VOL_INFO | ATTR_VOL_UUID};
  struct { uint32_t length; unsigned char uuid[16]; } uuid;
  need(!fstatfs(fd, &fs) && !fgetattrlist(fd, &attrs, &uuid, sizeof(uuid), 0) && uuid.length == sizeof(uuid));
  struct file_identity value = {(uint32_t)held.st_dev, (uint32_t)fs.f_fsid.val[0], (uint32_t)fs.f_fsid.val[1], (uint32_t)held.st_birthtimespec.tv_nsec, held.st_ino, held.st_birthtimespec.tv_sec, {0}};
  memcpy(value.volume, uuid.uuid, 16); text(id, value);
  printf("{\"identity\":\"%s\",\"namedIdentity\":\"%s\",\"uid\":%u,\"gid\":%u,\"mode\":%u,\"links\":%u,\"kind\":\"%s\",\"bytes\":", id, id, held.st_uid, held.st_gid, held.st_mode & 07777, held.st_nlink, symlink ? "symlink" : directory ? "directory" : "file");
  if (directory || symlink) fputs("null", stdout);
  else { need(S_ISREG(held.st_mode) && held.st_size >= 0 && held.st_size <= 4096); unsigned char bytes[4096]; char encoded[8193] = {0};
    if (held.st_size) read_at(fd, bytes, held.st_size, 0); hex(bytes, held.st_size, encoded); printf("\"%s\"", encoded); }
  if (symlink) { char target[PATH_MAX]; ssize_t size = readlinkat(at, name, target, sizeof(target)); need(size == 11 && !memcmp(target, ".held-value", 11)); fputs(",\"target\":\".held-value\"", stdout); }
  need(!fstat(fd, &named)); same_stat(held, named); need(!fstatat(at, name, &named, AT_SYMLINK_NOFOLLOW)); same_stat(held, named);
  need(!close(fd)); putchar('}');
}
static void file_view(struct entry *root, struct entry *base) {
  file_root(root); (void)identify(base->fd, true, 0);
  fputs("{\"base\":", stdout); file_object(base->fd, ".", true, false);
  fputs(",\"root\":", stdout); file_object(base->fd, "files", true, false);
  fputs(",\"allocation\":", stdout); file_object(root->fd, "allocation", true, true);
  int parent = openat(root->fd, "allocation", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent < 0) { need(errno == ENOENT); fputs(",\"leaf\":null,\"temporary\":null}", stdout); return; }
  fputs(",\"leaf\":", stdout); file_object(parent, "value", false, true);
  fputs(",\"temporary\":", stdout); file_object(parent, ".pending", false, true); putchar('}'); need(!close(parent));
}
static void private_probe_start(struct entry *root) {
  file_root(root); need(!file_probe.pid); int in[2], out[2]; need(!pipe(in) && !pipe(out)); pid_t pid = fork(); need(pid >= 0);
  if (!pid) { need(!close(in[1]) && !close(out[0])); alarm(25); operation_session(subject_uid);
    operation_fds(in[0], out[1]);
    need(!setgroups(0, NULL) && !setgid(subject_gid) && !setuid(subject_uid)); operation_ready(out[1]); operation_control(in[0], 'P');
    /* Test pathname reachability rather than exporting an already opened root. */
    char target[PATH_MAX]; need(snprintf(target, sizeof(target), "%s/allocation/value", root->path) < sizeof(target)); errno = 0;
    int fd = open(target, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600), error = errno; need(fd < 0 && (error == EACCES || error == EPERM));
    need(write(out[1], &error, sizeof(error)) == sizeof(error)); _exit(0); }
  operation_born(&file_probe, in, out, pid);
}
static void private_probe_finish(void) { need(file_probe.pid && write(file_probe.input, "P", 1) == 1); int error;
  need(read(file_probe.output, &error, sizeof(error)) == sizeof(error)); operation_reap(&file_probe);
  printf("{\"code\":\"%s\"}", error == EACCES ? "EACCES" : "EPERM"); }
static void file_publishers_start(void) {
  operation_guard(); need(!file_caller_count); const char *fixed[] = {"006f6c64ff", "006e657700ff", "7365636f6e64"}; putchar('[');
  for (unsigned i = 0; i < 3; i++) { int in[2], out[2]; need(!pipe(in) && !pipe(out)); pid_t pid = fork(); need(pid >= 0);
    if (!pid) { need(!close(in[1]) && !close(out[0])); alarm(25); operation_session(0); operation_ready(out[1]); operation_control(in[0], 'P');
      need(write(out[1], fixed[i], strlen(fixed[i])) == (ssize_t)strlen(fixed[i])); operation_control(in[0], 'R'); _exit(0); }
    if (i) putchar(','); operation_born(&file_callers[i], in, out, pid); file_caller_count++; }
  putchar(']');
}
static void file_publishers_ack(void) { need(file_caller_count == 3); const char *fixed[] = {"006f6c64ff", "006e657700ff", "7365636f6e64"}; putchar('[');
  for (unsigned i = 0; i < 3; i++) { need(write(file_callers[i].input, "P", 1) == 1); char bytes[32] = {0}; size_t size = strlen(fixed[i]);
    need(read(file_callers[i].output, bytes, size) == (ssize_t)size && !memcmp(bytes, fixed[i], size)); if (i) putchar(','); printf("\"%s\"", bytes); } putchar(']'); }
static void file_publishers_finish(void) { need(file_caller_count == 3); for (unsigned i = 0; i < 3; i++) {
    need(write(file_callers[i].input, "R", 1) == 1); operation_reap(&file_callers[i]); } file_caller_count = 0; fputs("{\"reaped\":true}", stdout); }
static void file_reader_start(struct entry *root) {
  file_root(root); need(!file_reader.pid); int in[2], out[2]; need(!pipe(in) && !pipe(out)); pid_t pid = fork(); need(pid >= 0);
  if (!pid) { need(!close(in[1]) && !close(out[0])); alarm(25); operation_session(0); operation_ready(out[1]);
    for (unsigned i = 0; i < 4096; i++) { char op; need(read(in[0], &op, 1) == 1); if (op == 'R') _exit(0); need(op == 'P');
      int parent = openat(root->fd, "allocation", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); need(parent >= 0);
      int fd = openat(parent, "value", O_RDONLY | O_NOFOLLOW | O_CLOEXEC); need(fd >= 0); char id[192]; text(id, identify(fd, false, 1));
      struct stat before, after; unsigned char bytes[4096]; char encoded[8193] = {0}; need(!fstat(fd, &before) && before.st_size >= 0 && before.st_size <= sizeof(bytes)); if (before.st_size) read_at(fd, bytes, before.st_size, 0);
      hex(bytes, before.st_size, encoded); need(!fstat(fd, &after)); same_stat(before, after); need(!close(fd) && !close(parent));
      dprintf(out[1], "{\"identity\":\"%s\",\"bytes\":\"%s\",\"links\":1,\"code\":\"OK\"}\n", id, encoded); } _exit(126); }
  operation_born(&file_reader, in, out, pid);
}
static void file_reader_read(void) { need(file_reader.pid && write(file_reader.input, "P", 1) == 1); char bytes[9000]; line(file_reader.output, bytes, sizeof(bytes)); fputs(bytes, stdout); }
static void file_reader_finish(void) { need(file_reader.pid && write(file_reader.input, "R", 1) == 1); operation_reap(&file_reader); fputs("{\"reaped\":true}", stdout); }
static void file_control_read(void) {
  need(control_root >= 0 && control_parent >= 0);
  if (!strcmp(control_kind, "cross-volume") && control_mounted) {
    struct stat root, foreign; need(!fstat(control_root, &root) && !close(control_foreign));
    control_foreign = openat(control_root, "allocation", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    need(control_foreign >= 0 && !fstat(control_foreign, &foreign) && foreign.st_dev != root.st_dev);
  }
  bool parent = !strcmp(control_kind, "parent") || !strcmp(control_kind, "cross-volume");
  fputs("{\"object\":", stdout); file_object(parent ? control_root : control_parent, parent ? "allocation" : "value", parent, false);
  fputs(",\"saved\":", stdout); file_object(parent ? control_root : control_parent, parent ? ".held-allocation" : ".held-value", parent, false); fputs(",\"temporary\":", stdout); file_object(control_parent, ".pending", false, true); putchar('}');
}
static void file_control_start(struct entry *root, const char *kind) {
  file_root(root); need(control_root < 0 && (!strcmp(kind, "parent") || !strcmp(kind, "leaf") || !strcmp(kind, "symlink") || !strcmp(kind, "hardlink") || !strcmp(kind, "cross-volume")));
  strcpy(control_kind, kind); control_root = dup(root->fd); control_parent = openat(root->fd, "allocation", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); need(control_root >= 0 && control_parent >= 0);
  bool parent = !strcmp(kind, "parent") || !strcmp(kind, "cross-volume"); int at = parent ? control_root : control_parent; const char *name = parent ? "allocation" : "value", *saved = parent ? ".held-allocation" : ".held-value";
  control_saved = openat(at, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (parent ? O_DIRECTORY : 0)); need(control_saved >= 0);
  struct stat st; need(fstatat(at, saved, &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
  if (!strcmp(kind, "hardlink")) need(!linkat(at, name, at, saved, 0));
  else { need(!renameat(at, name, at, saved));
    if (parent) need(!mkdirat(at, name, 0700));
    else if (!strcmp(kind, "symlink")) need(!symlinkat(saved, at, name));
    else { int fd = openat(at, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600); need(fd >= 0 && write(fd, "foreign\n", 8) == 8 && !fsync(fd) && !close(fd)); } }
  control_foreign = openat(at, name, O_RDONLY | O_CLOEXEC | (!strcmp(kind, "symlink") ? O_SYMLINK : O_NOFOLLOW) | (parent ? O_DIRECTORY : 0)); need(control_foreign >= 0 && !fsync(at)); if (!strcmp(kind, "cross-volume")) {
    fputs("{\"prepared\":true,\"mountpoint\":", stdout); file_object(control_root, "allocation", true, false); putchar('}');
  } else file_control_read();
}
static void file_control_restore(void) {
  operation_guard(); no_subjects(); need(!file_pid && control_root >= 0 && control_saved >= 0 && control_foreign >= 0);
  bool parent = !strcmp(control_kind, "parent") || !strcmp(control_kind, "cross-volume"); int at = parent ? control_root : control_parent;
  const char *name = parent ? "allocation" : "value", *saved = parent ? ".held-allocation" : ".held-value"; struct stat foreign, held, named;
  need(!fstat(control_foreign, &foreign) && !fstatat(at, name, &named, AT_SYMLINK_NOFOLLOW)); same_stat(foreign, named);
  need(!fstat(control_saved, &held) && !fstatat(at, saved, &named, AT_SYMLINK_NOFOLLOW)); same_stat(held, named);
  if (!strcmp(control_kind, "hardlink")) need(!unlinkat(at, saved, 0));
  else { need(!unlinkat(at, name, parent ? AT_REMOVEDIR : 0) && !renameat(at, saved, at, name)); }
  need(!fsync(at) && !close(control_foreign) && !close(control_saved) && !close(control_parent) && !close(control_root));
  control_foreign = control_saved = control_parent = control_root = -1; control_kind[0] = 0; fputs("{\"restored\":true}", stdout);
}


/* Only an independently pinned image and the reviewed hdiutil may supply the
 * foreign volume. Mount and detach affect the owned empty control mountpoint. */

static void file_control_rejoin(struct entry *root, const char *kind) {
  file_root(root); no_subjects(); need(!file_pid && control_root < 0 && (!strcmp(kind, "parent") || !strcmp(kind, "leaf") || !strcmp(kind, "symlink") || !strcmp(kind, "hardlink") || !strcmp(kind, "cross-volume")));
  bool parent = !strcmp(kind, "parent") || !strcmp(kind, "cross-volume"); strcpy(control_kind, kind);
  control_root = dup(root->fd); control_parent = openat(root->fd, parent ? ".held-allocation" : "allocation", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  int at = parent ? control_root : control_parent;
  control_saved = openat(at, parent ? ".held-allocation" : ".held-value", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (parent ? O_DIRECTORY : 0));
  control_foreign = openat(at, parent ? "allocation" : "value", O_RDONLY | O_CLOEXEC | (!strcmp(kind, "symlink") ? O_SYMLINK : O_NOFOLLOW) | (parent ? O_DIRECTORY : 0));
  need(control_root >= 0 && control_parent >= 0 && control_saved >= 0 && control_foreign >= 0);
  if (!strcmp(kind, "cross-volume")) { struct stat held, foreign; need(!fstat(control_root, &held) && !fstat(control_foreign, &foreign) && held.st_dev != foreign.st_dev); control_mounted = true; }
  file_control_read();
}
static void file_recovery_pin(const char *index, const char *pin) {
  need(case_mode && number(index) < 32768 && strlen(pin) == 64 && strspn(pin, "0123456789abcdef") == 64); no_subjects();
  char name[64]; snprintf(name, sizeof(name), "receipt-%u.json", number(index));
  int fd = openat(entries[1].fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat before, after; char actual[65];
  need(fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_uid == 0 && before.st_gid == 0 && (before.st_mode & 07777) == 0400 && before.st_nlink == 1 && before.st_size > 0 && before.st_size < 65536);
  sha_range(fd, 0, before.st_size, actual); need(!strcmp(actual, pin) && !fstatat(entries[1].fd, name, &after, AT_SYMLINK_NOFOLLOW)); same_stat(before, after); need(!close(fd));
}
static void file_volume_start(struct entry *tool, struct entry *image, const char *cdhash, unsigned mode) {
  operation_guard(); need(!volume_owner.pid && !strcmp(control_kind, "cross-volume") && mode <= 1 && mode == (control_mounted ? 1 : 0));
  need(!strcmp(tool->path, "/usr/bin/hdiutil")); signature(tool->path, cdhash); stable(image);
  if (mode) { struct stat held, named; need(!fstat(control_foreign, &held) && !fstatat(control_root, "allocation", &named, AT_SYMLINK_NOFOLLOW)); same_stat(held, named);
    need(!close(control_foreign)); control_foreign = -1; }
  volume_mode = mode; char mountpoint[PATH_MAX]; need(snprintf(mountpoint, sizeof(mountpoint), "%s/custody/files/allocation", case_path) < sizeof(mountpoint));
  int in[2], out[2]; need(!pipe(in) && !pipe(out)); pid_t owner = fork(); need(owner >= 0);
  if (!owner) {
    need(!close(in[1]) && !close(out[0])); alarm(45); operation_session(0); operation_ready(out[1]); operation_control(in[0], 'P');
    int bytes[2]; need(!pipe(bytes)); posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
    need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) &&
      !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT) &&
      !posix_spawn_file_actions_addopen(&files, 0, "/dev/null", O_RDONLY, 0) &&
      !posix_spawn_file_actions_adddup2(&files, bytes[1], 1) && !posix_spawn_file_actions_adddup2(&files, bytes[1], 2));
    char *attach[] = {tool->path, "attach", image->path, "-mountpoint", mountpoint, "-nobrowse", "-readonly", "-noautoopen", "-quiet", NULL};
    char *detach[] = {tool->path, "detach", mountpoint, "-quiet", NULL}; char *env[] = {"PATH=/nonexistent", "HOME=/nonexistent", "LANG=C", NULL};
    pid_t worker; need(!posix_spawn(&worker, tool->path, &files, &attributes, mode ? detach : attach, env) &&
      !posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes) && !close(bytes[1]));
    struct identity identity = inspect(worker); need(write(out[1], &identity, sizeof(identity)) == sizeof(identity)); operation_control(in[0], 'R');
    need(!proc_signal_with_audittoken(&identity.token, SIGCONT)); char buffer[4096]; ssize_t size = read(bytes[0], buffer, sizeof(buffer)); need(size == 0 && !close(bytes[0]));
    int status; while (waitpid(worker, &status, 0) < 0) need(errno == EINTR); need(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    need(write(out[1], "D", 1) == 1); operation_control(in[0], 'S'); _exit(0);
  }
  operation_born(&volume_owner, in, out, owner);
}
static void file_volume_worker(void) { need(volume_owner.pid && write(volume_owner.input, "P", 1) == 1); struct identity identity;
  need(read(volume_owner.output, &identity, sizeof(identity)) == sizeof(identity)); emit(identity); }
static void file_volume_run(void) { need(volume_owner.pid && write(volume_owner.input, "R", 1) == 1); char done;
  need(read(volume_owner.output, &done, 1) == 1 && done == 'D'); fputs("{\"exitCode\":0}", stdout); }
static void file_volume_finish(void) { need(volume_owner.pid && write(volume_owner.input, "S", 1) == 1); operation_reap(&volume_owner); control_mounted = volume_mode == 0;
  if (!control_mounted) { control_foreign = openat(control_root, "allocation", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); need(control_foreign >= 0); }
  fputs("{\"reaped\":true", stdout); if (!control_mounted) { fputs(",\"mountpoint\":", stdout); file_object(control_root, "allocation", true, false); } putchar('}'); }
static pid_t git_pid;
static struct identity git_identity;
static int git_in = -1, git_out = -1, git_gate = -1, git_data = -1;
static void git_start(struct entry *git, struct entry *metadata, struct entry *work, struct entry *hooks, struct entry *helper, const char *parent, const char *cdhash) {
  need(!case_fenced);
  operation_guard(); no_subjects(); need(!git_pid && !file_pid && strlen(parent) == 40 && strspn(parent, "0123456789abcdef") == 40);
  need(!strncmp(metadata->path, case_path, strlen(case_path)) && !strncmp(hooks->path, case_path, strlen(case_path)) && strcmp(hooks->path, metadata->path));
  signature(helper->path, cdhash); stable(git); stable(metadata); stable(hooks);
  int in[2], out[2], gate[2]; need(!pipe(in) && !pipe(out) && !socketpair(AF_UNIX, SOCK_STREAM, 0, gate));
  posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
  need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) &&
    !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) &&
    !posix_spawn_file_actions_adddup2(&files, in[0], 0) && !posix_spawn_file_actions_adddup2(&files, out[1], 1) &&
    !posix_spawn_file_actions_addopen(&files, 2, "/dev/null", O_WRONLY, 0) && !posix_spawn_file_actions_adddup2(&files, gate[1], 3));
  char nonce[33]; memcpy(nonce, case_context, 32); nonce[32] = 0;
  char *argv[] = {helper->path, nonce, git->path, metadata->path, work->path, hooks->path, (char *)parent, "commit", "test(fixture): record owned edit", NULL};
  char *env[] = {"CI=true", "GITHUB_ACTIONS=true", "NATIVE_GIT_CUSTODY=true", NULL};
  need(!posix_spawn(&git_pid, helper->path, &files, &attributes, argv, env) && !posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes));
  need(!close(in[0]) && !close(out[1]) && !close(gate[1])); git_in = in[1]; git_out = out[0]; git_gate = gate[0];
  char ready[256]; line(git_out, ready, sizeof(ready)); char expected[256];
  snprintf(expected, sizeof(expected), "{\"nonce\":\"%s\",\"phase\":\"ready\",\"pid\":%d}", nonce, git_pid); need(!strcmp(ready, expected)); git_identity = inspect(git_pid); emit(git_identity);
}
static void git_event(bool payload) { need(git_pid && (!payload || git_data >= 0)); char bytes[FRAME]; line(payload ? git_data : git_out, bytes, sizeof(bytes)); fputs(bytes, stdout); }
static void git_send(const char *ack) { need(git_pid && strlen(ack) == 1 && (*ack == 'P' || *ack == 'R' || *ack == 'S'));
  need(!case_fenced || *ack == 'S');
  if (*ack == 'P') { need(git_in >= 0 && write(git_in, ack, 1) == 1 && !close(git_in)); git_in = -1; }
  else need(write(git_gate, ack, 1) == 1); fputs("null", stdout); }
static void git_close(void) { need(git_pid); if (git_in >= 0) { need(!close(git_in)); git_in = -1; }
  int status; while (waitpid(git_pid, &status, 0) < 0) need(errno == EINTR); char extra;
  need(WIFEXITED(status) && read(git_out, &extra, 1) == 0 && !close(git_out) && !close(git_gate)); git_out = git_gate = -1; git_pid = 0;
  printf("{\"code\":%d,\"signal\":null,\"drained\":true}", WEXITSTATUS(status)); }

static void git_ordinary_start(struct entry *git, struct entry *metadata, struct entry *hooks, struct entry *policy, const char *mode, const char *cdhash) {
  need(!case_fenced);
  operation_guard(); no_subjects(); need(!git_pid && (!strcmp(mode, "inspect") || !strcmp(mode, "git-add") || !strcmp(mode, "git-commit")));
  struct entry *launcher = &entries[4], *payload = &entries[5]; signature(payload->path, cdhash);
#ifdef NATIVE_CI_EXPERIMENT
  need(experiment_exec); memcpy(image_cdhash, cdhash, 41); image_policy_index = (unsigned)(policy - entries);
#endif
  stable(git); stable(metadata); stable(hooks); stable(policy);
  int in[2], out[2], data[2]; need(!pipe(in) && !pipe(out) && !socketpair(AF_UNIX, SOCK_STREAM, 0, data)); posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
#ifdef NATIVE_CI_EXPERIMENT
  struct domain_bootstrap_fork spawn = {0}; bool actions_owned = false, attributes_owned = false;
  bool ready = domain_spawn_check(&spawn, posix_spawn_file_actions_init(&files), "spawn-actions-init", false);
  actions_owned = ready;
  if (ready) ready = domain_spawn_attributes(&spawn, &attributes, &attributes_owned, POSIX_SPAWN_CLOEXEC_DEFAULT);
  if (ready) ready = domain_spawn_check(&spawn, posix_spawn_file_actions_adddup2(&files, in[0], 0), "spawn-control", false) &&
    domain_spawn_check(&spawn, posix_spawn_file_actions_adddup2(&files, out[1], 1), "spawn-output", false) &&
    domain_spawn_check(&spawn, posix_spawn_file_actions_addopen(&files, 2, "/dev/null", O_WRONLY, 0), "spawn-stderr", false) &&
    domain_spawn_check(&spawn, posix_spawn_file_actions_adddup2(&files, data[1], 3), "spawn-data", false);
#else
  need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) &&
    !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) &&
    !posix_spawn_file_actions_adddup2(&files, in[0], 0) && !posix_spawn_file_actions_adddup2(&files, out[1], 1) &&
    !posix_spawn_file_actions_addopen(&files, 2, "/dev/null", O_WRONLY, 0) && !posix_spawn_file_actions_adddup2(&files, data[1], 3));
#endif
  char uid[24], gid[24], nonce[33]; snprintf(uid, sizeof(uid), "%u", subject_uid); snprintf(gid, sizeof(gid), "%u", subject_gid); memcpy(nonce, case_context, 32); nonce[32] = 0;
  char *argv[] = {launcher->path, uid, gid, entries[1].path, entries[2].path, entries[3].path,
    payload->path, payload->pin, (char *)cdhash, policy->path, policy->pin, nonce, "--", nonce, (char *)mode, git->path, metadata->path, entries[3].path, hooks->path, NULL};
#ifdef NATIVE_CI_EXPERIMENT
  char control_path[PATH_MAX + 32], control_hash[96];
  need(*image_control_cdhash && entries[12].fd >= 0);
  snprintf(control_path, sizeof(control_path), "NATIVE_EXEC_CONTROL=%s", entries[12].path);
  snprintf(control_hash, sizeof(control_hash), "NATIVE_EXEC_CONTROL_SHA256=%s", entries[12].pin);
  image_control = true; image_control_retired = image_probed = false;
  char *env[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", "NATIVE_OWNERSHIP_CUSTODY=true", control_path, control_hash, NULL};
#else
  char *env[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", "NATIVE_OWNERSHIP_CUSTODY=true", NULL};
#endif
#ifdef NATIVE_CI_EXPERIMENT
  pid_t child = -1;
  if (ready) ready = domain_spawn_check(&spawn, posix_spawn(&child, launcher->path, &files, &attributes, argv, env), "spawn-launch", false);
  if (ready) { git_pid = child; git_in = in[1]; git_out = out[0]; git_data = data[0]; }
  domain_spawn_settle(&spawn, &files, &actions_owned, &attributes, &attributes_owned);
  case_spawn_refuse(&spawn, git_pid);
#else
  need(!posix_spawn(&git_pid, launcher->path, &files, &attributes, argv, env) && !posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes));
#endif
  need(!close(in[0]) && !close(out[1]) && !close(data[1])); git_in = in[1]; git_out = out[0]; git_data = data[0]; printf("{\"pid\":%d}", git_pid);
}
static void git_ordinary_release(bool payload, const char *ack) { need(!case_fenced && git_pid && git_in >= 0 && strlen(ack) == 1 && (strchr("PRS", *ack)
#ifdef NATIVE_CI_EXPERIMENT
    || (image_control && *ack == 'A')
#endif
    )); need(write(payload ? git_data : git_in, ack, 1) == 1); fputs("null", stdout); }
static void git_ordinary_finish(void) { need(git_pid && git_gate < 0 && git_in >= 0); no_subjects();
  /* The launcher establishes its fresh session before hello. The original
   * admission binds that stable identity, rather than the pre-hello spawn epoch. */
  struct identity owner = inspect(git_pid);
  need(case_audit.ready && !case_audit.closed && case_audit.source.token.val[5] == (unsigned)git_pid &&
    audit_identity_same(owner, case_audit.source) && owner.token.val[1] == 0 && !proc_signal_with_audittoken(&owner.token, SIGKILL)); int status;
  while (waitpid(git_pid, &status, 0) < 0) need(errno == EINTR); need(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  char extra; need(read(git_out, &extra, 1) == 0 && read(git_data, &extra, 1) == 0 && !close(git_in) && !close(git_out) && !close(git_data)); git_in = git_out = git_data = -1; git_pid = 0;
  /* Release only this context's exact unchanged UID/GID claims after native
   * domain absence. The exclusion lease remains held between profile probes. */
  const char *kinds[] = {"uid", "gid"}; const unsigned ids[] = {subject_uid, subject_gid};
  for (unsigned i = 0; i < 2; i++) { char name[64], bytes[33]; snprintf(name, sizeof(name), "%s-%u", kinds[i], ids[i]);
    int fd = openat(entries[1].fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat held, named;
    need(fd >= 0 && !fstat(fd, &held) && S_ISREG(held.st_mode) && held.st_uid == 0 && held.st_gid == 0 && (held.st_mode & 07777) == 0400 && held.st_nlink == 1 && held.st_size == 32 && read(fd, bytes, sizeof(bytes)) == 32 && !memcmp(bytes, case_context, 32));
    need(!fstatat(entries[1].fd, name, &named, AT_SYMLINK_NOFOLLOW)); same_stat(held, named); need(!unlinkat(entries[1].fd, name, 0) && !close(fd)); }
  need(!fsync(entries[1].fd)); fputs("{\"reaped\":true}", stdout); }
static void git_object(struct entry *metadata, const char *name) {
  operation_guard(); need(strlen(name) == 40 && strspn(name, "0123456789abcdef") == 40);
  char relative[64]; snprintf(relative, sizeof(relative), "objects/%.2s/%s", name, name + 2); file_barrier(metadata, relative);
}
static void file_name(struct entry *root, unsigned pair) {
  operation_guard(); need(pair < 3); const char *supplied[] = {"Value", "va\xcc\x81lue", "../value"}, *canonical[] = {"value", "v\xc3\xa1lue", "value"};
#ifdef NATIVE_CI_EXPERIMENT
  /* Positive alias controls are real owned hard links, including the case and
   * Unicode spellings on a case-sensitive host. No filesystem-fold claim is made. */
  char expected[PATH_MAX]; need(snprintf(expected, sizeof(expected), "%s/custody/aliases", case_path) < sizeof(expected));
  if (!strcmp(root->path, expected) && pair == 0) {
    stable(root); no_subjects(); const char bytes[] = "native alias control\n";
    int writer = openat(root->fd, "value", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
    need(writer >= 0 && write(writer, bytes, sizeof(bytes) - 1) == sizeof(bytes) - 1 && !fsync(writer) && !close(writer));
    const char *aliases[] = {"Value", "v\xc3\xa1lue", "va\xcc\x81lue"};
    for (unsigned i = 0; i < 3; i++) {
      struct stat existing; errno = 0;
      if (fstatat(root->fd, aliases[i], &existing, AT_SYMLINK_NOFOLLOW)) { need(errno == ENOENT && !linkat(root->fd, "value", root->fd, aliases[i], 0)); }
    }
    stable(&entries[1]); need(!linkat(root->fd, "value", entries[1].fd, "value", 0) && !fsync(root->fd) && !fsync(entries[1].fd));
  }
#endif
  int left = openat(root->fd, supplied[pair], O_RDONLY | O_NOFOLLOW | O_CLOEXEC), right = openat(root->fd, canonical[pair], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  struct stat a, b, after; need(left >= 0 && right >= 0 && !fstat(left, &a) && !fstat(right, &b)); same_stat(a, b);
  need(S_ISREG(a.st_mode) && a.st_uid == 0 && a.st_gid == 0 && !(a.st_mode & 022));
  struct statfs fs; struct attrlist attrs = {.bitmapcount = ATTR_BIT_MAP_COUNT, .volattr = ATTR_VOL_INFO | ATTR_VOL_UUID};
  struct { uint32_t length; unsigned char uuid[16]; } uuid;
  need(!fstatfs(left, &fs) && !fgetattrlist(left, &attrs, &uuid, sizeof(uuid), 0) && uuid.length == sizeof(uuid));
  struct file_identity id = {(uint32_t)a.st_dev, (uint32_t)fs.f_fsid.val[0], (uint32_t)fs.f_fsid.val[1], (uint32_t)a.st_birthtimespec.tv_nsec, a.st_ino, a.st_birthtimespec.tv_sec, {0}};
  memcpy(id.volume, uuid.uuid, 16); char identity[192], before[65], again[65]; text(identity, id); sha_range(left, 0, a.st_size, before); sha_range(right, 0, b.st_size, again);
  need(!strcmp(before, again) && !fstat(left, &after)); same_stat(a, after); need(!fstatat(root->fd, supplied[pair], &after, AT_SYMLINK_NOFOLLOW)); same_stat(a, after);
  need(!fstatat(root->fd, canonical[pair], &after, AT_SYMLINK_NOFOLLOW)); same_stat(b, after); need(!close(left) && !close(right));
  printf("{\"nativeIdentity\":\"%s\",\"aliasIdentity\":\"%s\",\"beforeSha256\":\"%s\",\"afterSha256\":\"%s\"}", identity, identity, before, again);
}

#ifdef NATIVE_CI_EXPERIMENT
/* A fresh reader cannot reconstruct continuation authority. Recovery retains
 * audit custody and retires the whole original domain, including unseen epochs. */
static struct identity image_creator, image_target;
static struct timespec image_started;
/* At most 128 fixed records of 256 bytes per creator inspection. A failed or
 * partial observation is inconclusive, never an admission/cleanup outcome.
 * Block only our write's SIGPIPE, consuming only a newly pending instance;
 * leave an already pending signal and the caller's disposition/mask intact. */
static void image_note(const char *operation, bool entry, long result, int error) {
  int saved = errno;
  if (!image_diagnostic_active || image_diagnostic_failed || image_diagnostic_records >= 128) return;
  char bytes[256];
  int length = snprintf(bytes, sizeof(bytes), "native-darwin-image-call: sequence=%u pid=%u epoch=%u asid=%u birth=%llu.%llu operation=%s phase=%s result=%ld errno=%d\n",
    image_diagnostic_sequence, image_diagnostic_identity.token.val[5], image_diagnostic_identity.token.val[7],
    image_diagnostic_identity.token.val[6], (unsigned long long)image_diagnostic_identity.bsd.pbi_start_tvsec,
    (unsigned long long)image_diagnostic_identity.bsd.pbi_start_tvusec, operation, entry ? "entry" : "return", result, error);
  sigset_t blocked, previous, pending;
  if (length <= 0 || length >= (int)sizeof(bytes) || sigemptyset(&blocked) || sigaddset(&blocked, SIGPIPE) ||
      sigprocmask(SIG_BLOCK, &blocked, &previous)) {
    image_diagnostic_failed = true; errno = saved; return;
  }
  if (sigpending(&pending)) image_diagnostic_failed = true;
  else {
    bool was_pending = sigismember(&pending, SIGPIPE) == 1;
    image_diagnostic_records++;
    ssize_t written = write(STDERR_FILENO, bytes, (size_t)length); int write_error = errno;
    image_diagnostic_failed = written != length;
    if (written < 0 && write_error == EPIPE && !was_pending) {
      int received;
      if (sigpending(&pending)) image_diagnostic_failed = true;
      else if (sigismember(&pending, SIGPIPE) == 1) (void)sigwait(&blocked, &received);
    }
  }
  if (sigprocmask(SIG_SETMASK, &previous, NULL)) image_diagnostic_failed = true;
  errno = saved;
}
static long image_result(const char *operation, long result) {
  int error = errno;
  image_note(operation, false, result, error);
  errno = error; return result;
}
static void image_deadline(void) {
  struct timespec now; need(!clock_gettime(CLOCK_MONOTONIC, &now));
  need(now.tv_sec > image_started.tv_sec || now.tv_nsec >= image_started.tv_nsec);
  need(now.tv_sec - image_started.tv_sec < 30);
}
static void image_inputs(struct image_closure *value, struct identity expected) {
  IMAGE_NOTE("image_inputs", true, 0, 0);
  task_t task = MACH_PORT_NULL; thread_act_array_t threads = NULL; mach_msg_type_number_t count = 0;
  kern_return_t got = IMAGE_CALL("control/get", task_for_pid(mach_task_self(), expected.token.val[5], &task));
  if (got == KERN_SUCCESS) image_copy(value, task);
  bool ok = image_mach(value, got, "image-control-get");
  audit_token_t token = {{0}}; mach_msg_type_number_t size = TASK_AUDIT_TOKEN_COUNT;
  if (ok) ok = image_mach(value, IMAGE_CALL("control/token", task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &size)), "image-control-epoch") &&
    image_assert(value, size == TASK_AUDIT_TOKEN_COUNT && !memcmp(&token, &expected.token, sizeof(token)), "image-control-binding");
  if (ok) {
    got = IMAGE_CALL("control/threads", task_threads(task, &threads, &count));
    ok = image_mach(value, got, "image-threads-get");
    if (got == KERN_SUCCESS) {
      bool single = count == 1 && threads;
      ok = image_assert(value, single, "image-single-thread") && ok;
      if (single) image_copy(value, threads[0]);
      else {
        kern_return_t settlement = KERN_SUCCESS;
        IMAGE_NOTE("mach_port_deallocate/thread-copies", true, 0, 0);
        for (unsigned i = 0; threads && i < count; i++) {
          kern_return_t release = mach_port_deallocate(mach_task_self(), threads[i]);
          if (release != KERN_SUCCESS) settlement = release;
          domain_bootstrap_check(&value->outcome, release == KERN_SUCCESS, "image-thread-release", "mach", release, true);
        }
        IMAGE_NOTE("mach_port_deallocate/thread-copies", false, settlement, errno);
      }
      if (ok) ok = image_closure_read(value, task, threads[0]);
      if (threads) {
        kern_return_t release = IMAGE_CALL("threads/array-release", mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)threads, count * sizeof(*threads)));
        ok = domain_bootstrap_check(&value->outcome, release == KERN_SUCCESS, "image-threads-array-release", "mach", release, true) && ok;
      }
    }
  }
  if (!ok) { image_failure_cleanup(); image_closure_require(value, false); }
  need(audit_identity_same(expected, inspect(expected.token.val[5])));
  IMAGE_NOTE("image_inputs", false, 1, errno);
}
static void image_begin(void) {
  IMAGE_NOTE("image_begin", true, 0, 0);
  need(case_mode && !case_fenced && (!image_phase || image_phase == 4) && case_audit.ready && !case_audit.closed);
  IMAGE_NOTE("creator/reservation", true, 0, 0);
  reservation_guard();
  IMAGE_NOTE("creator/reservation", false, 1, errno);
  image_creator = case_audit.subject;
  need(case_audit.source.token.val[5] == (unsigned)(operation_mode ? git_pid : case_pid));
  IMAGE_NOTE("creator/identities", true, 0, 0);
  need(audit_identity_same(case_audit.source, inspect(case_audit.source.token.val[5])) &&
    audit_identity_same(image_creator, inspect(image_creator.token.val[5])));
  IMAGE_NOTE("creator/identities", false, 1, errno);
  char path[PATH_MAX]; need(IMAGE_CALL("creator/path", proc_pidpath(image_creator.token.val[5], path, sizeof(path))) > 0 && !strcmp(path, entries[4].path));
  IMAGE_NOTE("creator/credentials", true, 0, 0);
  need(image_creator.token.val[0] == subject_uid && image_creator.token.val[1] == subject_uid && image_creator.token.val[2] == subject_gid);
  IMAGE_NOTE("creator/credentials", false, 1, errno);
  memset(&image_inherited, 0, sizeof(image_inherited)); memset(&image_target, 0, sizeof(image_target));
  image_inputs(&image_inherited, image_creator);
  need(!IMAGE_CALL("creator/clock", clock_gettime(CLOCK_MONOTONIC, &image_started))); image_phase = 1;
  printf("{\"version\":3,\"control\":%s,\"creator\":", image_control ? "true" : "false"); emit(image_creator); fputs(",\"closed\":true}", stdout);
  IMAGE_NOTE("image_begin", false, 1, errno);
}
static void image_exec(void) {
  need(image_phase == 1 && !case_fenced && (image_control || (image_probed && image_control_retired))); image_deadline();
  need(audit_identity_same(image_creator, inspect(image_creator.token.val[5])));
  image_phase = 2; /* consumed before a possibly delivered write */
  need(write(operation_mode ? git_in : case_in, "X", 1) == 1); fputs("null", stdout);
}
static void image_observe(void) {
  need(image_phase == 2 || image_phase == 3); image_deadline(); reservation_guard();
  struct identity target = inspect(image_creator.token.val[5]); need(exec_handoff_identity(image_creator, target));
  if (image_phase == 3) need(audit_identity_same(target, image_target));
  image_target = target;
  struct entry *payload = &entries[image_control ? 12 : 5], *work = &entries[3]; stable(payload); stable(work);
  char path[PATH_MAX]; need(proc_pidpath(target.token.val[5], path, sizeof(path)) > 0 && !strcmp(path, payload->path));
  struct stat st; free(file(path, payload->stat.st_gid, payload->stat.st_mode & 07777, 134217728, payload->pin, &st)); same_stat(st, payload->stat);
  signature(path, image_control ? image_control_cdhash : image_cdhash); stable(payload);
  need(image_policy_index < count); struct entry *policy = &entries[image_policy_index]; stable(policy);
  free(file(policy->path, 0, 0400, 1048576, policy->pin, &st)); same_stat(st, policy->stat); stable(policy);
  struct proc_vnodepathinfo cwd; need(proc_pidinfo(target.token.val[5], PROC_PIDVNODEPATHINFO, 0, &cwd, sizeof(cwd)) == sizeof(cwd));
  need(cwd.pvi_cdir.vip_vi.vi_stat.vst_dev == work->stat.st_dev && cwd.pvi_cdir.vip_vi.vi_stat.vst_ino == work->stat.st_ino && sandbox_active(target.token.val[5]) == (image_control ? 0 : 1));
  if (!image_control) {
    stable(&entries[12]); stable(&entries[2]); stable(&entries[0]); stable(&entries[11]);
    struct stat control; free(file(entries[12].path, subject_gid, 0550, 134217728, entries[12].pin, &control)); same_stat(control, entries[12].stat);
    need(feasibility_sandbox_path(sandbox_binding, target.token.val[5], "file-read-data", entries[12].path) == 0 &&
      feasibility_sandbox_path(sandbox_binding, target.token.val[5], "file-map-executable", entries[12].path) == 0);
  }
  struct proc_fdinfo fds[4]; int size = proc_pidinfo(target.token.val[5], PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  need(size == 3 * sizeof(*fds)); unsigned mask = 0;
  for (unsigned i = 0; i < 3; i++) { need(fds[i].proc_fd >= 0 && fds[i].proc_fd <= 2); mask |= 1u << fds[i].proc_fd; }
  need(mask == 7);
  memset(&image_inspected, 0, sizeof(image_inspected)); image_inputs(&image_inspected, target);
  bool same = image_inspected.host == image_inherited.host && image_inspected.access == image_inherited.access &&
    image_inspected.resource_unsupported == image_inherited.resource_unsupported;
  bool released = image_closure_release(&image_inspected);
  if (!same || !released) { image_failure_cleanup(); image_closure_require(&image_inspected, false); }
  need(audit_identity_same(target, inspect(target.token.val[5])) && inspect(target.token.val[5]).bsd.pbi_status == SSTOP);
  image_phase = 3;
}
static void image_read(void) {
  image_observe(); printf("{\"version\":3,\"control\":%s,\"creator\":", image_control ? "true" : "false"); emit(image_creator);
  fputs(",\"target\":", stdout); emit(image_target);
  printf(",\"closed\":true,\"stopped\":true,\"imageSha256\":\"%s\",\"cdhash\":\"%s\",\"policySha256\":\"%s\"}", entries[image_control ? 12 : 5].pin, image_control ? image_control_cdhash : image_cdhash, entries[image_policy_index].pin);
}
static void image_continue(unsigned index, const char *pin) {
  need(image_phase == 3 && !case_fenced && index < 32768 && strlen(pin) == 64 && strspn(pin, "0123456789abcdef") == 64);
  /* Fresh protected receipt read precedes repeated observations and release.
   * Its complete versioned identity/policy binding is checked by the owner. */
  char path[PATH_MAX]; need(snprintf(path, sizeof(path), "%s/receipt-%u.json", entries[1].path, index) < sizeof(path));
  struct stat st; free(file(path, 0, 0400, 65535, pin, &st));
  image_observe(); bool released = image_closure_release(&image_inherited);
  image_closure_require(&image_inherited, released); image_deadline();
  struct identity target = inspect(image_target.token.val[5]);
  need(audit_identity_same(target, image_target) && target.bsd.pbi_status == SSTOP);
  image_phase = 4; /* uncertain continuation is never replayable */
  need(write(operation_mode ? git_in : case_in, "C", 1) == 1);
  need(!proc_signal_with_audittoken(&target.token, SIGCONT)); fputs("{\"continued\":true}", stdout);
}
/* The original gate remains open throughout T. Independent reads surround the
 * direct native result; returned errno and installed-policy hashes alone cannot
 * establish refusal. An unexpected replacement stays stopped in owned recovery. */
static void image_probe(void) {
  need(!image_control && image_control_retired && !image_probed && image_phase == 1 && !case_fenced);
  image_deadline(); stable(&entries[12]); stable(&entries[2]); stable(&entries[0]);
  struct stat held; free(file(entries[12].path, subject_gid, 0550, 134217728, entries[12].pin, &held));
  same_stat(held, entries[12].stat); signature(entries[12].path, image_control_cdhash);
  need(sandbox_active(image_creator.token.val[5]) == 1 &&
    feasibility_sandbox_path(sandbox_binding, image_creator.token.val[5], "file-read-data", entries[12].path) == 0 &&
    feasibility_sandbox_path(sandbox_binding, image_creator.token.val[5], "file-map-executable", entries[12].path) == 0);
  uint64_t before[8][4], after[8][4];
  need(image_descriptors(image_creator.token.val[5], before) && audit_identity_same(image_creator, inspect(image_creator.token.val[5])));
  image_phase = 5; /* consumed before the possibly delivered T */
  need(write(operation_mode ? git_in : case_in, "T", 1) == 1);
  access_exact(operation_mode ? git_out : case_out, &image_probe_result, sizeof(image_probe_result));
  need(exec_handoff_refused(image_probe_result));
  need(audit_identity_same(image_creator, inspect(image_creator.token.val[5])) &&
    image_descriptors(image_creator.token.val[5], after) && !memcmp(before, after, sizeof(before)));
  char creator_path[PATH_MAX]; need(proc_pidpath(image_creator.token.val[5], creator_path, sizeof(creator_path)) > 0 && !strcmp(creator_path, entries[4].path));
  memset(&image_inspected, 0, sizeof(image_inspected)); image_inputs(&image_inspected, image_creator);
  bool same = image_inspected.host == image_inherited.host && image_inspected.access == image_inherited.access &&
    image_inspected.resource_unsupported == image_inherited.resource_unsupported;
  bool settled = image_closure_release(&image_inspected); need(same && settled);
  stable(&entries[12]); stable(&entries[2]); stable(&entries[0]); stable(&entries[11]); image_deadline();
  image_probed = true; image_phase = 1;
  printf("{\"version\":1,\"subject\":"); emit(image_creator);
  printf(",\"policySha256\":\"%s\",\"assetSha256\":\"%s\",\"status\":%d,\"prepared\":true,\"filesCleanup\":0,\"attributesCleanup\":0,\"read\":0,\"map\":0,\"unchanged\":true}", entries[image_policy_index].pin, entries[12].pin, image_probe_result.status);
}
static void image_control_next(void) {
  need(image_control && image_phase == 4 && !case_fenced && case_audit.closed);
  no_subjects(); struct audit_domain_view view = audit_census(subject_uid, image_creator.token.val[6]);
  need(!view.nl && !view.nd); stable(&entries[12]); stable(&entries[2]); stable(&entries[0]);
  image_control_creator = image_creator; image_control_target = image_target;
  image_control_retired = true; image_control = false;
  need(write(operation_mode ? git_in : case_in, "N", 1) == 1);
  fputs("{\"retired\":true}", stdout);
}
static void image_exec_evidence(pid_t pid) {
  need(!image_control && image_control_retired && image_probed && (image_phase == 3 || image_phase == 4));
  struct identity actual = inspect(pid), parent = inspect(image_target.token.val[5]);
  need(audit_identity_same(parent, image_target) && sandbox_active(pid) == 1);
  bool primary = audit_identity_same(actual, image_target);
  struct entry *executable = &entries[5];
  if (!primary) {
    /* git-fixture.c uses only plain suspended posix_spawn: no SETEXEC,
     * RESETIDS, persona or alternate sandbox request. XNU inherits the parent's
     * MAC credential at creation. Rejoin the real direct parent and stopped
     * Git image, rather than treating UID/ASID equality as that contract. */
    need(operation_mode && actual.bsd.pbi_ppid == parent.token.val[5] && actual.bsd.pbi_status == SSTOP &&
      actual.token.val[6] == parent.token.val[6] && actual.token.val[7] > 0);
    char expected[PATH_MAX]; snprintf(expected, sizeof(expected), "%s/storage/git", case_path);
    executable = NULL;
    for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].path, expected)) { need(!executable); executable = &entries[i]; }
    need(executable);
  }
  need(actual.token.val[0] == subject_uid && actual.token.val[1] == subject_uid && actual.token.val[3] == subject_uid &&
    actual.bsd.pbi_svuid == subject_uid && actual.token.val[2] == subject_gid && actual.token.val[4] == subject_gid && actual.bsd.pbi_svgid == subject_gid);
  char path[PATH_MAX]; need(proc_pidpath(pid, path, sizeof(path)) > 0 && !strcmp(path, executable->path)); stable(executable);
  struct stat st; free(file(path, subject_gid, 0550, 134217728, executable->pin, &st)); same_stat(st, executable->stat);
  CFDictionaryRef info = signature_information(path, false); CFRelease(info);
  need(audit_identity_same(actual, inspect(pid)) && audit_identity_same(parent, inspect(parent.token.val[5])));
  printf("{\"version\":1,\"subject\":"); emit(actual); fputs(",\"creator\":", stdout); emit(image_creator);
  fputs(",\"target\":", stdout); emit(image_target);
  fputs(",\"controlCreator\":", stdout); emit(image_control_creator);
  fputs(",\"controlTarget\":", stdout); emit(image_control_target);
  fputs(",\"controlRetired\":true,\"parent\":", stdout); if (primary) fputs("null", stdout); else emit(parent);
  printf(",\"policySha256\":\"%s\",\"assetSha256\":\"%s\",\"imageSha256\":\"%s\",\"inheritance\":%s,\"status\":%d}",
    entries[image_policy_index].pin, entries[12].pin, executable->pin, primary ? "null" : "\"posix-spawn-inherit-v1\"", image_probe_result.status);
}
static void image_recover(char **fields) {
  need(case_fenced && case_recovery); struct stat named; errno = 0;
  bool absent = fstatat(entries[1].fd, "audit-custody", &named, AT_SYMLINK_NOFOLLOW) == -1;
  if (absent) need(errno == ENOENT);
  unsigned matches = 0, unclosed = 0;
  if (!absent) {
    struct identity expected = case_identity(fields); int fd = case_audit_open(false); struct stat before, after;
    need(!fstat(fd, &before));
    for (off_t at = 0; at < before.st_size; at += sizeof(case_audit)) {
      struct case_audit_custody value; read_at(fd, &value, sizeof(value), at);
      need(value.version == 1 && !memcmp(value.context, case_context, 65));
      if (!value.closed) need(++unclosed == 1);
      if (audit_identity_same(value.subject, expected)) need(++matches == 1);
    }
    need(!fstat(fd, &after)); same_stat(before, after); need(!close(fd));
  }
  /* Historical closed attempts may precede the current open domain. Only an
   * exact existing record can be read while another domain remains open. */
  need(matches == 1 || !unclosed);
  /* New custody is limited to the still-bound original creator. Recovery
   * never opens the exec gate or reconstructs continuation authority. */
  image_recovering = true;
  case_session(fields, matches == 1, matches == 0);
}
#endif
static void case_resume(char **values) {
  operation_guard(); need(git_pid); audit_token_t token = {{0}};
  for (unsigned i = 0; i < 8; i++) token.val[i] = number(values[i]);
  uint64_t seconds = number(values[8]); unsigned micros = number(values[9]), saved_uid = number(values[10]), saved_gid = number(values[11]);
  need(token.val[0] == subject_uid && token.val[1] == subject_uid && token.val[2] == subject_gid && token.val[3] == subject_uid && token.val[4] == subject_gid && token.val[5] > 1 && token.val[6] > 0 && token.val[7] > 0 && saved_uid == subject_uid && saved_gid == subject_gid);
  struct identity actual = inspect(token.val[5]); need(!memcmp(&actual.token, &token, sizeof(token)) && actual.bsd.pbi_start_tvsec == seconds && actual.bsd.pbi_start_tvusec == micros && actual.bsd.pbi_svuid == saved_uid && actual.bsd.pbi_svgid == saved_gid);
#ifdef NATIVE_CI_EXPERIMENT
  /* This legacy operation belongs to Git workers. It cannot bypass or replay
   * the replacement's receipt-bound one-shot continuation. */
  need(actual.token.val[5] != image_creator.token.val[5]);
#endif
  need(!proc_signal_with_audittoken(&token, SIGCONT)); fputs("{\"resumed\":true}", stdout);
}
static bool operation_domain_finished(void) { return operation_mode && !git_pid && !file_pid; }
static bool operations_retired(void) {
#ifdef NATIVE_CI_EXPERIMENT
  need(!access_log_pid);
#endif
  need(!git_pid && !access_audit_pid && !file_caller_count && !file_reader.pid && !file_probe.pid && !volume_owner.pid && control_root < 0); return true;
}

static void file_line(void) { need(file_pid); char bytes[9000]; size_t used = 0;
  for (;;) { char byte; struct pollfd wait = {.fd = file_out, .events = POLLIN}; need(poll(&wait, 1, 30000) == 1);
    ssize_t size = read(file_out, &byte, 1); need(size >= 0);
    if (!size) { need(!used); fputs("{\"eof\":true}", stdout); return; }
    need(byte && (unsigned char)byte < 128 && used + 1 < sizeof(bytes));
    if (byte == '\n') { bytes[used] = 0; fputs(bytes, stdout); return; } bytes[used++] = byte;
  }
}
static void operation_authority(void) { operation_guard(); operation_mode = true; no_subjects(); printf("{\"identity\":"); emit(inspect(getpid()));
  printf(",\"sandboxed\":%s,\"noLiveUid\":true}", sandbox_active(getpid()) == 0 ? "false" : "true"); }
#ifdef NATIVE_CI_EXPERIMENT
/* Privileged launches recheck the fixed hosted sudo/env byte observations.
 * These guards grant no compiler or payload authority. */
static void bootstrap_tool(unsigned index, const char *pin) {
  const char *paths[] = {"/usr/bin/sudo", "/usr/bin/env"}; need(index < 2 && pin);
  struct entry value = {0}; strcpy(value.path, paths[index]);
  value.fd = open(value.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  need(value.fd >= 0 && !fstat(value.fd, &value.stat)); struct stat st = value.stat;
  need(S_ISREG(st.st_mode) && st.st_nlink > 0 && st.st_size > 0 && st.st_size <= 134217728 && installed_input(value.path, &st));
  char hash[65]; sha_range(value.fd, 0, st.st_size, hash); need(!strcmp(hash, pin));
  signing_check(value.path, false);
  struct stat after, named; need(!fstat(value.fd, &after) && !lstat(value.path, &named)); same_stat(st, after); same_stat(st, named); need(!close(value.fd));
}
#endif
int main(int argc, char **argv) {
  need(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 && getenv("CI") && !strcmp(getenv("CI"), "true") && getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"), "true"));
  extern char **environ; unsigned environment = 0;
  for (char **value = environ; *value; value++) { need(!strcmp(*value, "CI=true") || !strcmp(*value, "GITHUB_ACTIONS=true")); environment++; }
  need(environment == 2);
  sandbox_binding = feasibility_sandbox_load();
  if (!feasibility_sandbox_available(sandbox_binding)) { errno = ENOSYS; need(0); }
  struct proc_fdinfo inherited[64]; int inherited_size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, inherited, sizeof(inherited));
  need(inherited_size == 3 * sizeof(inherited[0])); unsigned mask = 0;
  for (unsigned i = 0; i < 3; i++) { need(inherited[i].proc_fd >= 0 && inherited[i].proc_fd < 3); mask |= 1U << inherited[i].proc_fd; }
  need(mask == 7);
  umask(0077); signal(SIGALRM, expire); alarm(120);
#ifdef NATIVE_CI_EXPERIMENT
  if (argc > 3 && !strcmp(argv[1], "--bootstrap-pins")) {
    bootstrap_tool(0, argv[2]); bootstrap_tool(1, argv[3]); argc -= 3; argv += 3;
  } else need(0);
#endif
  if (argc == 3 && !strcmp(argv[1], "--probe")) { pid_t pid = (pid_t)number(argv[2]); need(pid > 1 && pid != getpid()); probe(pid, -1); return 0; }
  if (argc == 6 && !strcmp(argv[1], "--probe-domain")) {
    pid_t pid = (pid_t)number(argv[2]); subject_uid = number(argv[3]); subject_gid = number(argv[4]);
    need(pid > 1 && pid != getpid() && subject_uid > 500 && subject_gid > 500); case_mode = true;
    probe(pid, number(argv[5])); return 0;
  }
  bool building = argc == 4 && !strcmp(argv[1], "--build-serve");
  preparation_mode = argc == 5 && !strcmp(argv[1], "--prepare-serve");
#ifdef NATIVE_CI_EXPERIMENT
  need(!preparation_mode); /* Protected provider preparation is reviewed only. */
#endif
  build_mode = building;
  case_mode = argc == 5 && !strcmp(argv[1], "--case-serve");
  need((argc == 4 && (building || !strcmp(argv[1], "--serve"))) || case_mode || preparation_mode);
  if (preparation_mode) { need(strlen(argv[4]) < sizeof(report_path)); strcpy(report_path, argv[4]); }
  if (case_mode) {
    need(strlen(argv[4]) == 64 && strspn(argv[4], "0123456789abcdef") == 64); strcpy(case_context, argv[4]);
    need(snprintf(case_path, sizeof(case_path), "/private/var/run/native-poc/cases/%s", case_context) < sizeof(case_path));
  }
  /* The longest fixed file recipe is 360 seconds, followed by bounded cleanup. */
  if (building || case_mode || preparation_mode) operation_session(0);
  alarm(building ? 1440 : case_mode ? 420 : 390); /* 22 fixed build commands plus separate cleanup. */
  printf("{\"helper\":"); emit(inspect(getpid())); puts("}"); fflush(stdout);
  char input[FRAME]; line(0, input, sizeof(input)); need(!strcmp(input, "P")); plan(argv[2], argv[3]);
  printf("{"
#ifdef NATIVE_CI_EXPERIMENT
    "\"purpose\":\"experiment\","
#endif
    "\"candidateSha\":\"%s\",\"entries\":%u,\"uid\":%u,\"gid\":%u", candidate, count, subject_uid, subject_gid);
  if (case_mode) { fputs(",\"directories\":", stdout); case_directories(); }
  puts("}"); fflush(stdout);
  for (;;) {
    line(0, input, sizeof(input)); char *tokens[32], *next; unsigned n = 0;
    for (char *p = strtok_r(input, " ", &next); p; p = strtok_r(NULL, " ", &next)) { need(n < 32); tokens[n++] = p; }
    need(n > 0);
    /* Read-only receipt validation precedes dependent commands, including their
     * journals. It cannot create a recursively unverified observation intent. */
    if (n == 3 && !strcmp(tokens[0], "V")) { need((building || case_mode || preparation_mode) && ++operations <= 32768); build_receipt(tokens[1], tokens[2]); continue; }
    if (preparation_mode) need(!strcmp(tokens[0],"prepare-observe") || !strcmp(tokens[0],"root-domain") || !strcmp(tokens[0],"root-retired") ||
      !strcmp(tokens[0],"process") || !strcmp(tokens[0],"inspect") || !strcmp(tokens[0],"location") || !strcmp(tokens[0],"read") ||
      !strcmp(tokens[0],"signature") || !strcmp(tokens[0],"macho") || !strcmp(tokens[0],"cache") || !strcmp(tokens[0],"build") ||
      !strcmp(tokens[0],"open") || !strcmp(tokens[0],"close") || !strcmp(tokens[0],"finish"));
    need(n >= 2 && number(tokens[1]) == ++sequence && ++operations <= 32768);
    printf("{\"sequence\":%u,\"value\":", sequence);
    if (!strcmp(tokens[0], "operation-authority")) { need(n == 2); operation_authority();
    } else if (!strcmp(tokens[0], "file-view")) { need(n == 4); file_view(slot(tokens[2]), slot(tokens[3]));
    } else if (!strcmp(tokens[0], "file-probe-start")) { need(n == 3); private_probe_start(slot(tokens[2]));
    } else if (!strcmp(tokens[0], "file-probe-finish")) { need(n == 2); private_probe_finish();
    } else if (!strcmp(tokens[0], "file-publishers-start")) { need(n == 2); file_publishers_start();
    } else if (!strcmp(tokens[0], "file-publishers-ack")) { need(n == 2); file_publishers_ack();
    } else if (!strcmp(tokens[0], "file-publishers-finish")) { need(n == 2); file_publishers_finish();
    } else if (!strcmp(tokens[0], "file-reader-start")) { need(n == 3); file_reader_start(slot(tokens[2]));
    } else if (!strcmp(tokens[0], "file-reader-read")) { need(n == 2); file_reader_read();
    } else if (!strcmp(tokens[0], "file-reader-finish")) { need(n == 2); file_reader_finish();
    } else if (!strcmp(tokens[0], "file-control-start")) { need(n == 4); file_control_start(slot(tokens[2]), tokens[3]);
    } else if (!strcmp(tokens[0], "file-volume-start")) { need(n == 6); file_volume_start(slot(tokens[2]), slot(tokens[3]), tokens[4], number(tokens[5]));
    } else if (!strcmp(tokens[0], "file-volume-worker")) { need(n == 2); file_volume_worker();
    } else if (!strcmp(tokens[0], "file-volume-run")) { need(n == 2); file_volume_run();
    } else if (!strcmp(tokens[0], "file-volume-finish")) { need(n == 2); file_volume_finish();
    } else if (!strcmp(tokens[0], "file-control-rejoin")) { need(n == 4); file_control_rejoin(slot(tokens[2]), tokens[3]);
    } else if (!strcmp(tokens[0], "file-control-read")) { need(n == 2); file_control_read();
    } else if (!strcmp(tokens[0], "file-control-restore")) { need(n == 2); file_control_restore();
    } else if (!strcmp(tokens[0], "file-name")) { need(n == 4); file_name(slot(tokens[2]), number(tokens[3]));
    } else if (!strcmp(tokens[0], "git-start")) { need(n == 9); git_start(slot(tokens[2]), slot(tokens[3]), slot(tokens[4]), slot(tokens[5]), slot(tokens[6]), tokens[7], tokens[8]);
    } else if (!strcmp(tokens[0], "git-event")) { need(n == 2 || n == 3); git_event(n == 3 && number(tokens[2]) == 1);
    } else if (!strcmp(tokens[0], "git-send")) { need(n == 3); git_send(tokens[2]);
    } else if (!strcmp(tokens[0], "git-close")) { need(n == 2); git_close();
    } else if (!strcmp(tokens[0], "git-ordinary-start")) { need(n == 8); git_ordinary_start(slot(tokens[2]), slot(tokens[3]), slot(tokens[4]), slot(tokens[5]), tokens[6], tokens[7]);
    } else if (!strcmp(tokens[0], "git-ordinary-release")) { need(n == 4); git_ordinary_release(number(tokens[2]) == 1, tokens[3]);
    } else if (!strcmp(tokens[0], "case-resume")) { need(n == 14); case_resume(&tokens[2]);
    } else if (!strcmp(tokens[0], "git-ordinary-finish")) { need(n == 2); git_ordinary_finish();
    } else if (!strcmp(tokens[0], "git-object")) { need(n == 4); git_object(slot(tokens[2]), tokens[3]);
    } else if (!strcmp(tokens[0], "slots-closed")) { need(n == 2); putchar('['); unsigned closed = 0; for (unsigned i = 0; i < count; i++) if (entries[i].fd < 0) { if (closed++) putchar(','); printf("%u", i); } putchar(']');
    } else if (!strcmp(tokens[0], "access-counters")) { need(n == 2); access_counters();
    } else if (!strcmp(tokens[0], "access-payload-sockets")) { need(n == 2); access_payload_sockets();
    } else if (!strcmp(tokens[0], "access-sockets")) { need(n == 2); access_sockets();
    } else if (!strcmp(tokens[0], "access-pf-start")) { need(n == 6); access_pf_start(slot(tokens[2]), slot(tokens[3]), tokens[4], tokens[5]);
    } else if (!strcmp(tokens[0], "access-pf-worker")) { need(n == 2); access_pf_park();
    } else if (!strcmp(tokens[0], "access-pf-run")) { need(n == 2); access_pf_run();
    } else if (!strcmp(tokens[0], "access-audit-start")) { need(n == 5); access_audit_start(slot(tokens[2]), tokens[3], number(tokens[4]));
    } else if (!strcmp(tokens[0], "access-audit")) { need(n == 3); access_audit(tokens[2]);
    } else if (!strcmp(tokens[0], "access-audit-close")) { need(n == 2); access_audit_close();
    } else if (!strcmp(tokens[0], "access-provision")) { need(n == 3); access_provision(slot(tokens[2]));
    } else if (!strcmp(tokens[0], "access-attempt")) { need(n == 4); access_attempt(number(tokens[2]), number(tokens[3]));
    } else if (!strcmp(tokens[0], "access-target")) { need(n == 4); access_target(number(tokens[2]), number(tokens[3]));
    } else if (!strcmp(tokens[0], "access-run")) { need(n == 3); access_run(number(tokens[2]));
#ifdef NATIVE_CI_EXPERIMENT
    } else if (!strcmp(tokens[0], "access-mach-log-start")) { need(n == 4); access_log_start(slot(tokens[2]), tokens[3]);
    } else if (!strcmp(tokens[0], "access-mach-log-run")) { need(n == 2); access_log_run();
#endif
    } else if (!strcmp(tokens[0], "access-peer")) { need(n == 2); access_peer();
    } else if (!strcmp(tokens[0], "access-complete")) { need(n == 3); access_complete(number(tokens[2]));
    } else if (!strcmp(tokens[0], "access-controls-retired")) { need(n == 3); access_controls_retired(slot(tokens[2]));
    } else if (!strcmp(tokens[0], "access-controls-close")) { need(n == 2); access_controls_close();
    } else if (!strcmp(tokens[0], "process") || !strcmp(tokens[0], "session")) {
      need(n == 3); struct identity value = inspect((pid_t)number(tokens[2]));
      /* Outside controls need read-only identity inspection too. Only the
       * reserved subject can acquire retained audit-session custody. */
      if (!strcmp(tokens[0], "session")) { need(value.token.val[0] == subject_uid && value.token.val[1] == subject_uid && value.token.val[2] == subject_gid && value.token.val[6] > 0 && session_count < 32);
        need(!audit_session_port(value.token.val[6], &sessions[session_count]) && sessions[session_count] != MACH_PORT_NULL);
        struct identity again = inspect((pid_t)value.token.val[5]);
        need(!memcmp(&value.token, &again.token, sizeof(value.token)) && value.bsd.pbi_start_tvsec == again.bsd.pbi_start_tvsec && value.bsd.pbi_start_tvusec == again.bsd.pbi_start_tvusec); session_count++; if (case_mode) { need(!case_asid || case_asid == value.token.val[6]); case_asid = value.token.val[6]; } }
      emit(value);
    } else if (!strcmp(tokens[0], "build")) {
      need(n == 2); char os[256], encoded[513]; size_t size = sizeof(os);
      need(!sysctlbyname("kern.osversion", os, &size, NULL, 0) && size > 1 && size <= sizeof(os) && os[size - 1] == 0 && strnlen(os, size) == size - 1);
      hex((const unsigned char *)os, size - 1, encoded); printf("{\"osBuild\":\"%s\",\"macho\":", encoded);
      need(_mh_execute_header.sizeofcmds <= 1048576); macho((const unsigned char *)&_mh_execute_header, sizeof(_mh_execute_header) + _mh_execute_header.sizeofcmds); putchar('}');
    } else if (!strcmp(tokens[0], "open")) {
      need(n == 3); unsigned index = number(tokens[2]); need(index < count); struct entry *entry = &entries[index]; need(entry->fd < 0);
      bool authority = !strcmp(entry->kind, "authority"), dir = !strcmp(entry->kind, "directory"); entry_ancestors(entry);
      entry->fd = lease_entry(entry) ? openat(lease_base, "pf-lease", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) :
        open(entry->path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (dir ? O_DIRECTORY : 0));
      bool hosted = !authority && !dir && experiment_installed_path(entry->path), sampled = false, directory_entry = false;
      const char *predicate = "open";
      bool ok = entry->fd >= 0 && (predicate = "stat", sampled = fstat(entry->fd, &entry->stat) == 0) &&
        (predicate = "eligibility", hosted || ((entry->stat.st_uid == 0 || (authority && entry->stat.st_uid == subject_uid)) && (entry->stat.st_gid == 0 || (authority && entry->stat.st_gid == subject_gid)) && !(entry->stat.st_mode & 022))) &&
        (predicate = "kind", (directory_entry = dir || (authority && S_ISDIR(entry->stat.st_mode))) ? S_ISDIR(entry->stat.st_mode) : S_ISREG(entry->stat.st_mode)) &&
        (predicate = "directory-mode", !directory_entry || (entry->stat.st_mode & 07777) == 0700 || (authority && (entry->stat.st_mode & 07777) == 0710) ||
          (dir && (entry->stat.st_mode & 07777) == 0555 && build_entry(entry))) &&
        (predicate = "links", directory_entry || (entry->stat.st_nlink > 0 && (hosted || entry->stat.st_nlink == 1 || (!authority && strcmp(entry->kind, "helper") && installed_input(entry->path, &entry->stat))))) &&
        (predicate = "size", directory_entry || (entry->stat.st_size >= 0 && entry->stat.st_size <= 536870912));
      if (!ok) input_refusal(entry->path, predicate, sampled ? &entry->stat : NULL);
      need(ok); if (hosted) need(installed_input(entry->path, &entry->stat));
      if (!dir && !authority) { need(entry->stat.st_size > 0); char hash[65]; sha_range(entry->fd, 0, (uint64_t)entry->stat.st_size, hash); need(!strcmp(hash, entry->pin)); }
      stable(entry); need(S_ISDIR(entry->stat.st_mode) || entry->stat.st_nlink == 1 || installed_input(entry->path, &entry->stat)); identity(entry);
    } else if (!strcmp(tokens[0], "case-directory")) { need(n == 3); case_directory(unopened(tokens[2]));
    } else if (!strcmp(tokens[0], "case-rejoin")) { need(n == 3); case_rejoin(unopened(tokens[2]));
    } else if (!strcmp(tokens[0], "case-copy")) { need(n == 4); case_copy(unopened(tokens[2]), slot(tokens[3]));
    } else if (!strcmp(tokens[0], "case-endpoint")) { need(n == 5); case_endpoint(number(tokens[2]), number(tokens[3]), number(tokens[4]));
    } else if (!strcmp(tokens[0], "case-read")) { need(n == 2); case_read();
    } else if (!strcmp(tokens[0], "case-start")) { need(n == 4); case_start(tokens[2], tokens[3]);
    } else if (!strcmp(tokens[0], "case-control")) { need(n == 2); case_line(case_out, false);
    } else if (!strcmp(tokens[0], "case-eof")) {
      need(case_mode && n == 2 && case_data >= 0); char trailing; struct pollfd wait = {.fd = case_data, .events = POLLIN};
      need(poll(&wait, 1, 30000) == 1 && !(wait.revents & (POLLERR | POLLNVAL)) && read(case_data, &trailing, 1) == 0);
      fputs("{\"complete\":true}", stdout);
    } else if (!strcmp(tokens[0], "case-output")) { need(n == 2); case_line(case_data, true);
#ifdef NATIVE_CI_EXPERIMENT
    } else if (!strcmp(tokens[0], "case-observer")) {
      need(case_mode && n == 3); struct identity value; const char *kind = case_observer_identity(number(tokens[2]), &value);
      char hash[65]; need(audit_observer_digest(!strcmp(kind, "sudo") ? "/usr/bin/sudo" : "/usr/sbin/dtrace", hash));
      printf("{\"kind\":\"%s\",\"parentPid\":%u,\"toolSha256\":\"%s\",\"identity\":", kind, value.bsd.pbi_ppid, hash); emit(value); putchar('}');
    } else if (!strcmp(tokens[0], "case-observer-observe") || !strcmp(tokens[0], "case-observer-retire")) {
      need(case_mode && n == 14); case_observer(&tokens[2], !strcmp(tokens[0], "case-observer-retire"));

#endif
#ifdef NATIVE_CI_EXPERIMENT
    } else if (!strcmp(tokens[0], "image-recover")) {
      need(n == 26); image_recover(&tokens[2]);
    } else if (!strcmp(tokens[0], "exec-control-asset")) { need(n == 3); case_exec_control(tokens[2]);
    } else if (!strcmp(tokens[0], "image-creator")) {
      image_diagnostic_identity = case_audit.subject; image_diagnostic_sequence = sequence;
      image_diagnostic_records = 0; image_diagnostic_failed = false; image_diagnostic_active = true;
      IMAGE_NOTE("image-creator-dispatch", true, 0, 0);
      need(n == 2); image_begin();
      IMAGE_NOTE("image-creator-dispatch", false, 1, errno);
      image_diagnostic_active = false;
    } else if (!strcmp(tokens[0], "image-probe")) { need(n == 2); image_probe();
    } else if (!strcmp(tokens[0], "image-control-next")) { need(n == 2); image_control_next();
    } else if (!strcmp(tokens[0], "image-exec")) { need(n == 2); image_exec();
    } else if (!strcmp(tokens[0], "image-read")) { need(n == 2); image_read();
    } else if (!strcmp(tokens[0], "image-continue")) { need(n == 4); image_continue(number(tokens[2]), tokens[3]);
#endif
    } else if (!strcmp(tokens[0], "case-send")) { need(n == 4); case_send(number(tokens[2]) == 1, tokens[3]);
    } else if (!strcmp(tokens[0], "case-receipt")) { need(n == 5); case_receipt(number(tokens[2]), tokens[3], tokens[4], false);
    } else if (!strcmp(tokens[0], "case-receipt-read")) { need(n == 4); case_receipt(number(tokens[2]), tokens[3], NULL, false);
    } else if (!strcmp(tokens[0], "case-receipt-optional")) { need(n == 4); case_receipt(number(tokens[2]), tokens[3], NULL, true);
    } else if (!strcmp(tokens[0], "case-fence")) {
      need(case_mode && n == 2); if (reservation_fd >= 0) reservation_guard();
      case_fenced = true;
#ifdef NATIVE_CI_EXPERIMENT
      /* JavaScript refusals need not fail a native command. Settle their held
       * inspection copies here without reopening either image gate. */
      need(image_settle());
#endif
      fputs("{\"closed\":true}", stdout);
    } else if (!strcmp(tokens[0], "case-session")) {
      need(n == 26); case_session(&tokens[2], false, false);
    } else if (!strcmp(tokens[0], "case-session-read")) {
      need(n == 14); case_session(&tokens[2], true, false);
    } else if (!strcmp(tokens[0], "case-session-close")) {
      need(n == 2); case_session_closed();
    } else if (!strcmp(tokens[0], "case-members")) { need(n == 3); case_members(number(tokens[2]), false);
    } else if (!strcmp(tokens[0], "case-empty")) {
      need(case_mode && n == 2); reservation_guard(); no_subjects(); printf("{\"uid\":%u,\"noLiveUid\":true}", subject_uid);
    } else if (!strcmp(tokens[0], "case-signal")) { need(n == 14); case_signal(&tokens[2]);
    } else if (!strcmp(tokens[0], "case-subject")) { need(n == 3); case_subject(number(tokens[2]));
    } else if (!strcmp(tokens[0], "case-retire")) { need(n == 2); case_retire();
    } else if (!strcmp(tokens[0], "compiler-policy")) { need(building && n == 5); compiler_policy((pid_t)number(tokens[2]), number(tokens[3]), number(tokens[4]));
    } else if (!strcmp(tokens[0], "prepare-observe")) { need(preparation_mode && n == 5 && number(tokens[4]) <= 1); preparation_observe(tokens[2], tokens[3], number(tokens[4]));
    } else if (!strcmp(tokens[0], "build-directory")) { need(building && n == 3); build_directory(tokens[2]);
    } else if (!strcmp(tokens[0], "build-root")) { need(building && n == 3); build_root_snapshot(tokens[2]);
    } else if (!strcmp(tokens[0], "build-open")) { need(building && n == 4); build_open(tokens[2], tokens[3]);
#ifdef NATIVE_CI_EXPERIMENT
    } else if (!strcmp(tokens[0], "build-input")) { need(building && (n == 4 || n == 5)); build_input(tokens[2], tokens[3], n == 5 ? tokens[4] : NULL);
#endif
    } else if (!strcmp(tokens[0], "root-domain")) { need(n == 5); root_domain((pid_t)number(tokens[2]), number(tokens[3]), number(tokens[4]));
    } else if (!strcmp(tokens[0], "root-retired")) {
      need((building || case_mode || preparation_mode) && n == 7); struct identity previous = {0};
      previous.token.val[5] = number(tokens[2]); previous.token.val[6] = number(tokens[3]); previous.token.val[7] = number(tokens[4]);
      previous.bsd.pbi_start_tvsec = number(tokens[5]); previous.bsd.pbi_start_tvusec = number(tokens[6]);
      need(previous.token.val[5] > 1 && previous.token.val[6] > 0 && previous.token.val[7] > 0 &&
        previous.bsd.pbi_start_tvsec > 0 && previous.bsd.pbi_start_tvusec < 1000000 && root_members(previous.token.val[6], false) == 0);
      printf("{\"helper\":"); emit(previous); fputs(",\"complete\":true,\"members\":[]}", stdout);
    } else if (!strcmp(tokens[0], "inspect")) { need(n == 3); identity(slot(tokens[2]));
    } else if (!strcmp(tokens[0], "location")) { need(n == 3); struct entry *entry = slot(tokens[2]); char encoded[PATH_MAX * 2]; hex((unsigned char *)entry->path, strlen(entry->path), encoded); printf("{\"hex\":\"%s\"}", encoded);
    } else if (!strcmp(tokens[0], "read")) {
      need(n == 5); struct entry *entry = slot(tokens[2]); char *end; errno = 0; uint64_t offset = strtoull(tokens[3], &end, 10); unsigned size = number(tokens[4]);
      need(*tokens[3] && *tokens[3] != '-' && !errno && !*end && offset <= INT64_MAX);
      need(S_ISREG(entry->stat.st_mode) && size > 0 && size <= 65536 && offset + size <= (uint64_t)entry->stat.st_size);
      unsigned char bytes[65536]; char encoded[131073]; read_at(entry->fd, bytes, size, offset); stable(entry); hex(bytes, size, encoded); printf("{\"hex\":\"%s\"}", encoded);
    } else if (!strcmp(tokens[0], "signature")) { need(n == 3); struct entry *entry = slot(tokens[2]); signing(entry->path); stable(entry);
    } else if (!strcmp(tokens[0], "macho")) { need(n == 3); image(slot(tokens[2]));
    } else if (!strcmp(tokens[0], "cache")) { need(n == 4); char name[PATH_MAX]; decode(tokens[3], name, sizeof(name)); cache_image(slot(tokens[2]), name);
    } else if (!strcmp(tokens[0], "pf-read")) { need(n == 2); pf_read();
    } else if (!strcmp(tokens[0], "pf-recover")) { need(n == 2); pf_reference(true);
    } else if (!strcmp(tokens[0], "pf-write")) { need(n == 6); if (case_mode) case_policy_possible = true; pf_write(slot(tokens[2]), slot(tokens[3]), tokens[4], tokens[5]);
      if (case_mode && strcmp(tokens[5], "install")) case_policy_possible = false;
    } else if (!strcmp(tokens[0], "authority")) { need(n == 4); effective_authority((pid_t)number(tokens[2]), slot(tokens[3]));
    } else if (!strcmp(tokens[0], "socket")) { need(n == 4); effective_socket((pid_t)number(tokens[2]), (int)number(tokens[3]));
    } else if (!strcmp(tokens[0], "ipc")) { need(n == 4); effective_ipc(number(tokens[2]), (int)number(tokens[3]));
    } else if (!strcmp(tokens[0], "barrier")) { need(n == 4); char name[PATH_MAX]; decode(tokens[3], name, sizeof(name)); file_barrier(slot(tokens[2]), name);
    } else if (!strcmp(tokens[0], "tree")) { need(n == 3); file_tree(slot(tokens[2]));
    } else if (!strcmp(tokens[0], "bsm")) { need(n == 3); bsm_record(tokens[2]);
    } else if (!strcmp(tokens[0], "reserve")) { need(n == 4); reserve(slot(tokens[2]), tokens[3]);
    } else if (!strcmp(tokens[0], "reservation")) { need(n == 2); reservation_read();
    } else if (!strcmp(tokens[0], "reservation-close")) { need(n == 2); reservation_close();
    } else if (!strcmp(tokens[0], "transfer")) { need(n == 7); transfer(slot(tokens[2]), slot(tokens[3]), slot(tokens[4]), tokens[5], tokens[6]);
    } else if (!strcmp(tokens[0], "transfer-recovery")) { need(n == 9); file_recovery_pin(tokens[7], tokens[8]); transfer(slot(tokens[2]), slot(tokens[3]), slot(tokens[4]), tokens[5], tokens[6]);
    } else if (!strcmp(tokens[0], "file-send-recovery")) { need(n == 3 && file_pid && file_in >= 0); char data[9000]; decode(tokens[2], data, sizeof(data));
      need(!strncmp(data, "start ", 6) || !strncmp(data, "recover ", 8) || !strncmp(data, "cleanup ", 8) || !strncmp(data, "continue ", 9) || !strncmp(data, "finish ", 7));
      need(write(file_in, data, strlen(data)) == (ssize_t)strlen(data)); fputs("null", stdout);
    } else if (!strcmp(tokens[0], "file-read")) { need(n == 2 && file_pid); file_line();
    } else if (!strcmp(tokens[0], "file-send")) { need(n == 3 && file_pid && file_in >= 0); char data[9000]; decode(tokens[2], data, sizeof(data)); size_t size = strlen(data);
      need(write(file_in, data, size) == (ssize_t)size); fputs("null", stdout);
    } else if (!strcmp(tokens[0], "file-close")) { need(n == 2 && file_pid); if (file_in >= 0) need(!close(file_in)); file_in = -1;
      int status; while (waitpid(file_pid, &status, 0) < 0) need(errno == EINTR);
      /* Reaping cannot erase queued or partial private protocol bytes. */
      char trailing; need(read(file_out, &trailing, 1) == 0 && !close(file_out)); file_out = -1; file_pid = 0;
      need(WIFEXITED(status) || (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL));
      printf("{\"code\":%s", WIFEXITED(status) ? "" : "null"); if (WIFEXITED(status)) printf("%d", WEXITSTATUS(status));
      char decision[32] = {0}; ssize_t decision_size = read(file_decision, decision, sizeof(decision) - 1); need(decision_size >= 0 && !close(file_decision)); file_decision = -1;
      need(!decision_size || !strcmp(decision, "reject-identity") || !strcmp(decision, "reject-symlink") || !strcmp(decision, "reject-hardlink") || !strcmp(decision, "reject-volume"));
      printf(",\"decision\":"); if (decision_size) printf("\"%s\"", decision); else fputs("null", stdout);
      printf(",\"signal\":%s,\"drained\":true}", WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? "\"SIGKILL\"" : "null");
    } else if (!strcmp(tokens[0], "close")) { need(n == 3 && !file_pid); struct entry *entry = slot(tokens[2]);
      if (case_mode && entry == &entries[1]) case_audit_guard(true);
      need(!close(entry->fd)); entry->fd = -1;
      if (!strcmp(entry->kind, "build")) { need(!close(build_root) && !close(build_parent)); build_root = build_parent = -1; }
      fputs("null", stdout);
    } else if (!strcmp(tokens[0], "finish")) {
      need(n == 2 && !file_pid); for (unsigned i = 0; i < count; i++) need(entries[i].fd < 0);
      if (build_root >= 0) {
        build_guard();
        if (case_mode) need((build_identity.st_mode & 07777) == 0555);
        struct entry value = {.fd = build_root}; strcpy(value.kind, "build"); strcpy(value.path, build_path);
        need(!fstat(build_root, &value.stat)); stable(&value);
        need(!close(build_root) && !close(build_parent)); build_root = build_parent = -1;
      }
      need(reservation_fd < 0 && case_socket_count == 0); /* Recovery releases exclusion independently. */
      if (session_count && !subjects_absent()) { puts("{\"closed\":false}}"); fflush(stdout); continue; }
      if (case_asid) { struct audit_domain_view domain = audit_census(subject_uid, case_asid); need(!domain.nl); }
      for (unsigned i = 0; i < root_domain_count; i++) need(root_members(root_domains[i].token.val[6], false) == 0);
      for (unsigned i = 0; i < session_count; i++) need(mach_port_deallocate(mach_task_self(), sessions[i]) == KERN_SUCCESS);
      if (lease_base >= 0) { need(!close(lease_base) && !close(lease_parent)); lease_base = lease_parent = -1; }
      fputs("{\"closed\":true}", stdout); puts("}"); fflush(stdout); return 0;
    } else need(0);
    puts("}"); need(!fflush(stdout));
  }
}
