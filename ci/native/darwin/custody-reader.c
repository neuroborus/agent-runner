/* Dedicated external CI. Sealed reviewed code, a data-only plan, private pipes,
 * bounded held resources and acknowledged release; never a privileged daemon. */
#define __APPLE_API_PRIVATE 1
#define _DARWIN_C_SOURCE 1
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <bsm/audit.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
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
#include <sys/wait.h>
#include <unistd.h>
#include "custody.h"
#include "file-identity.h"

/* The matched SDK/export review must bind these dyld interfaces and this
 * version-one record. Absence is a build/admission failure, never a fallback. */
struct cache_text { uint64_t version, loadAddress, textSegmentSize; unsigned char dylibUuid[16]; const char *dylibPath; };
extern bool _dyld_get_shared_cache_uuid(unsigned char uuid[16]);
extern const void *_dyld_get_shared_cache_range(size_t *length);
extern int dyld_shared_cache_iterate_text(const unsigned char uuid[16], void (^callback)(const struct cache_text *));
extern const struct mach_header_64 _mh_execute_header;
extern const struct dyld_all_image_infos *_dyld_get_all_image_infos(void);

#define SLOTS 128
#define FRAME 262144
struct entry { char kind[16], pin[65], path[PATH_MAX]; int fd; struct stat stat; };
static struct entry entries[SLOTS];
static unsigned count, sequence, operations;
static uint64_t bytes_read;
static mach_port_t sessions[32];
static unsigned session_count;
static struct identity root_domains[32];
static unsigned root_domain_count;
static pid_t file_pid;
static int file_in = -1, file_out = -1;
static char candidate[41];
static uid_t subject_uid;
static gid_t subject_gid;
static bool build_mode, case_mode, case_started, case_policy_possible;
static char case_path[PATH_MAX], case_context[65];
static int case_sockets[8];
static unsigned case_socket_count;
static int build_parent = -1, build_root = -1;
static char build_path[PATH_MAX], report_path[PATH_MAX];
static struct stat build_identity, report_identity;
static void no_acl(int fd) {
  acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED); acl_entry_t entry;
  need(acl && !acl_valid(acl)); errno = 0;
  /* Darwin returns zero for an entry and EINVAL at the end of a valid ACL. */
  need(acl_get_entry(acl, ACL_FIRST_ENTRY, &entry) == -1 && errno == EINVAL && !acl_free(acl));
}
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
static void ancestors(const char *path) {
  char name[PATH_MAX], canonical[PATH_MAX]; struct stat st;
  need(realpath(path, canonical) && !strcmp(path, canonical));
  need(strlen(path) < sizeof(name)); strcpy(name, path);
  char *slash = strrchr(name, '/'); need(slash && slash != name); *slash = 0;
  for (;;) {
    need(!lstat(name, &st) && S_ISDIR(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 022));
    slash = strrchr(name, '/'); if (slash == name) break; need(slash); *slash = 0;
  }
}
static void stable(struct entry *value) {
  struct stat current, named; need(value->fd >= 0 && !fstat(value->fd, &current) && !lstat(value->path, &named));
  if (S_ISDIR(value->stat.st_mode)) {
    struct stat before = value->stat;
    need(current.st_dev == before.st_dev && current.st_ino == before.st_ino && current.st_mode == before.st_mode && current.st_uid == before.st_uid && current.st_gid == before.st_gid &&
      named.st_dev == before.st_dev && named.st_ino == before.st_ino && named.st_mode == before.st_mode && named.st_uid == before.st_uid && named.st_gid == before.st_gid &&
      current.st_birthtimespec.tv_sec == before.st_birthtimespec.tv_sec && current.st_birthtimespec.tv_nsec == before.st_birthtimespec.tv_nsec);
  } else { same_stat(value->stat, current); same_stat(value->stat, named); }
  if (!strcmp(value->kind, "build")) {
    struct stat root, parent, named; char canonical[PATH_MAX];
    need(realpath(report_path, canonical) && !strcmp(report_path, canonical) &&
      realpath(build_path, canonical) && !strcmp(build_path, canonical));
    need(build_root >= 0 && build_parent >= 0 && !fstat(build_root, &root) && !lstat(build_path, &named) &&
      root.st_dev == build_identity.st_dev && root.st_ino == build_identity.st_ino && root.st_uid == 0 && root.st_gid == 0 &&
      ((root.st_mode & 07777) == 0700 || (root.st_mode & 07777) == 0555));
    same_stat(root, named);
    need(!fstat(build_parent, &parent) && !lstat(report_path, &named) &&
      parent.st_dev == report_identity.st_dev && parent.st_ino == report_identity.st_ino &&
      parent.st_uid == report_identity.st_uid && (parent.st_mode & 07777) == 0700);
    same_stat(parent, named); no_acl(build_root); no_acl(build_parent);
  } else if (case_mode && !strncmp(value->path, case_path, strlen(case_path)) &&
    (!value->path[strlen(case_path)] || value->path[strlen(case_path)] == '/')) {
    for (unsigned i = 0; i < count; i++) if (entries[i].fd >= 0 && S_ISDIR(entries[i].stat.st_mode) &&
      !strncmp(entries[i].path, case_path, strlen(case_path))) {
      struct stat held, named; need(!fstat(entries[i].fd, &held) && !lstat(entries[i].path, &named));
      need(held.st_dev == entries[i].stat.st_dev && held.st_ino == entries[i].stat.st_ino &&
        held.st_uid == entries[i].stat.st_uid && held.st_gid == entries[i].stat.st_gid && held.st_mode == entries[i].stat.st_mode);
      same_stat(held, named); no_acl(entries[i].fd);
    }
  } else ancestors(value->path);
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
static void signing(const char *path) {
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
  SecStaticCodeRef code = NULL; CFDictionaryRef info = NULL;
  need(url && SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess &&
    SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL) == errSecSuccess &&
    SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess);
  CFDataRef unique = CFDictionaryGetValue(info, kSecCodeInfoUnique);
  need(unique && CFGetTypeID(unique) == CFDataGetTypeID() && CFDataGetLength(unique) == 20);
  char cdhash[41], entitlement[65]; hex(CFDataGetBytePtr(unique), 20, cdhash);
  CFDictionaryRef grants = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
  CFDataRef data = grants ? CFPropertyListCreateData(NULL, grants, kCFPropertyListBinaryFormat_v1_0, 0, NULL) : NULL;
  need(!grants || (data && CFDataGetLength(data) <= 65536));
  unsigned char sum[32]; need(CC_SHA256(data ? CFDataGetBytePtr(data) : (const unsigned char *)"", data ? (CC_LONG)CFDataGetLength(data) : 0, sum));
  hex(sum, 32, entitlement); printf("{\"cdhash\":\"%s\",\"entitlementsSha256\":\"%s\",\"valid\":true}", cdhash, entitlement);
  if (data) CFRelease(data); CFRelease(info); CFRelease(code); CFRelease(url);
}
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
static void image(struct entry *value) {
  struct mach_header_64 header; read_at(value->fd, &header, sizeof(header), 0);
  need(header.sizeofcmds <= 1048576 && sizeof(header) + (uint64_t)header.sizeofcmds <= (uint64_t)value->stat.st_size);
  size_t size = sizeof(header) + header.sizeofcmds; unsigned char *bytes = malloc(size); need(bytes); read_at(value->fd, bytes, size, 0); macho(bytes, size); free(bytes); stable(value);
}
static void probe(pid_t pid) {
  struct proc_bsdinfo b; errno = 0; int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, &b, sizeof(b)), error = errno;
  printf("{\"verifier\":"); emit(inspect(getpid())); printf(",\"subject\":");
  if (n == 0 && error == ESRCH) { puts("{\"status\":\"absent\"}}"); return; }
  need(n == sizeof(b) && b.pbi_status != SZOMB); struct identity before = inspect(pid);
  char path[PATH_MAX]; need(proc_pidpath(pid, path, sizeof(path)) > 0); ancestors(path);
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat st, after; need(fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 022) && st.st_nlink == 1);
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
  same_stat(st, after); need(!lstat(path, &after)); same_stat(st, after); need(!close(fd)); puts("]}}");
}
static void plan(const char *path, const char *pin) {
  ancestors(path); struct stat st; char *bytes = (char *)file(path, 0, 0400, FRAME, pin, &st); need(!memchr(bytes, 0, (size_t)st.st_size));
  char *next, *record = strtok_r(bytes, "\n", &next), extra; unsigned uid, gid;
  need(record && sscanf(record, "native-custody-v1 %40s %u %u %c", candidate, &uid, &gid, &extra) == 3 && strlen(candidate) == 40 && strspn(candidate, "0123456789abcdef") == 40 && uid > 500 && uid <= INT_MAX && gid > 500 && gid <= INT_MAX);
  subject_uid = uid; subject_gid = gid;
  while ((record = strtok_r(NULL, "\n", &next))) {
    /* Match the protocol scan width; decode separately enforces PATH_MAX. */
    need(count < SLOTS); struct entry *entry = &entries[count]; char encoded[8193];
    need(sscanf(record, "%15s %64s %8192s %c", entry->kind, entry->pin, encoded, &extra) == 3);
    need(!strcmp(entry->kind, "directory") || !strcmp(entry->kind, "authority") || !strcmp(entry->kind, "image") || !strcmp(entry->kind, "data") || !strcmp(entry->kind, "cache") || !strcmp(entry->kind, "helper"));
    need((!strcmp(entry->kind, "directory") || !strcmp(entry->kind, "authority")) ? !strcmp(entry->pin, "-") : strlen(entry->pin) == 64 && strspn(entry->pin, "0123456789abcdef") == 64);
    decode(encoded, entry->path, sizeof(entry->path));
    const char *leaf = strrchr(entry->path, '/');
    bool private_case = case_mode && !strncmp(entry->path, case_path, strlen(case_path)) &&
      (!entry->path[strlen(case_path)] || entry->path[strlen(case_path)] == '/');
    if (!private_case && !((build_mode || case_mode) && !strcmp(entry->kind, "directory") && leaf && !strcmp(leaf + 1, "platform-build"))) ancestors(entry->path);
    entry->fd = -1;
    for (unsigned i = 0; i < count; i++) need(strcmp(entries[i].path, entry->path)); count++;
  }
  need(count); free(bytes);
}
/* Compiler descendants share a fresh root audit session. Observe its complete
 * kernel membership; reaping the compiler alone cannot retire that domain. */
static unsigned root_members(au_asid_t asid, bool output) {
  pid_t pids[4096]; unsigned members = 0; errno = 0;
  int size = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
  need(!errno && size > 0 && size < (int)sizeof(pids) && size % sizeof(pid_t) == 0);
  for (unsigned i = 0; i < (unsigned)size / sizeof(pid_t); i++) {
    /* PID zero is the kernel, never a member of this fresh userspace session.
     * Scan every other UID: a descendant changing credentials cannot disappear
     * from the domain merely by leaving the root-only process list. */
    if (pids[i] == 0) continue;
    need(pids[i] > 0); for (unsigned j = 0; j < i; j++) need(pids[j] != pids[i]);
    struct proc_bsdinfo before, after;
    auditpinfo_addr_t audit = {.ap_pid = pids[i]}, again = {.ap_pid = pids[i]};
    need(proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &before, sizeof(before)) == sizeof(before) &&
      !auditon(A_GETPINFO_ADDR, &audit, sizeof(audit)) &&
      proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &after, sizeof(after)) == sizeof(after) && before.pbi_uid == after.pbi_uid &&
      !auditon(A_GETPINFO_ADDR, &again, sizeof(again)) && before.pbi_start_tvsec == after.pbi_start_tvsec &&
      before.pbi_start_tvusec == after.pbi_start_tvusec && audit.ap_asid == again.ap_asid && audit.ap_auid == again.ap_auid);
    if (audit.ap_asid == asid) {
      struct identity value = inspect(pids[i]); need(value.token.val[1] == 0 && value.token.val[6] == (unsigned)asid &&
        value.bsd.pbi_start_tvsec == before.pbi_start_tvsec && value.bsd.pbi_start_tvusec == before.pbi_start_tvusec);
      if (output) { if (members) putchar(','); emit(value); }
      members++; need(members <= 32);
    }
  }
  return members;
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
    need(found < count); struct stat stat; ancestors(image);
    need(!lstat(image, &stat) && !(stat.st_mode & 06022));
    free(file(image, 0, stat.st_mode & 07777, 536870912, entries[found].pin, &stat));
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
  need(named >= 0 && same(identify(named, true, 0), r) && !close(named) && r.device == b.device && r.fs0 == b.fs0 && r.fs1 == b.fs1 && !memcmp(r.volume, b.volume, 16));
  struct proc_taskinfo task; need(proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &task, sizeof(task)) == sizeof(task) && task.pti_threadnum == 1);
  int input[2], output[2]; need(!pipe(input) && !pipe(output)); file_pid = fork(); need(file_pid >= 0);
  if (!file_pid) {
    need(dup2(input[0], 0) == 0 && dup2(output[1], 1) == 1);
    int null = open("/dev/null", O_WRONLY | O_CLOEXEC); need(null >= 0 && dup2(null, 2) == 2);
    int rcopy = fcntl(root->fd, F_DUPFD_CLOEXEC, 10), bcopy = fcntl(base->fd, F_DUPFD_CLOEXEC, 10);
    need(rcopy >= 10 && bcopy >= 10 && dup2(rcopy, 3) == 3 && dup2(bcopy, 4) == 4);
    /* The helper owns exactly these two transferred directory descriptors. */
    struct proc_fdinfo fds[4096]; int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    need(size > 0 && size < sizeof(fds) && size % sizeof(fds[0]) == 0);
    for (size_t i = 0; i < (size_t)size / sizeof(fds[0]); i++) if (fds[i].proc_fd >= 5) need(!close(fds[i].proc_fd));
    signature(helper->path, cdhash);
    char *args[] = {helper->path, (char *)nonce, rtext, btext, NULL};
    char *env[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", NULL};
    execve(helper->path, args, env); _exit(126);
  }
  need(!close(input[0]) && !close(output[1])); file_in = input[1]; file_out = output[0]; printf("{\"pid\":%d}", file_pid);
}
static void cache_image(struct entry *entry, const char *name) {
  need(!strcmp(entry->kind, "cache")); unsigned char header[104], uuid[16]; read_at(entry->fd, header, sizeof(header), 0);
  need((!memcmp(header, "dyld_v1  x86_64", 16) || !memcmp(header, "dyld_v1 x86_64h", 16)) &&
    _dyld_get_shared_cache_uuid(uuid) && !memcmp(header + 88, uuid, 16));
  uint64_t offset, length; memcpy(&offset, header + 40, 8); memcpy(&length, header + 48, 8);
  need(length && length <= 134217728 && offset + length <= (uint64_t)entry->stat.st_size); char signature_hash[65]; sha_range(entry->fd, offset, length, signature_hash);
  __block unsigned matched = 0; __block uint64_t address = 0; __block unsigned char image_uuid[16];
  need(!dyld_shared_cache_iterate_text(uuid, ^(const struct cache_text *info) {
    need(info->version == 1 && info->dylibPath && strnlen(info->dylibPath, PATH_MAX) < PATH_MAX);
    if (!strcmp(info->dylibPath, name)) { matched++; address = info->loadAddress; memcpy(image_uuid, info->dylibUuid, 16); }
  }) && matched == 1);
  size_t range_size = 0; const void *range = _dyld_get_shared_cache_range(&range_size);
  const struct dyld_all_image_infos *images = _dyld_get_all_image_infos(); need(range && range_size && images && images->version >= 15);
  address += images->sharedCacheSlide; need(address >= (uintptr_t)range && address + sizeof(struct mach_header_64) <= (uintptr_t)range + range_size);
  struct mach_header_64 image_header; mach_vm_size_t actual;
  need(mach_vm_read_overwrite(mach_task_self(), address, sizeof(image_header), (mach_vm_address_t)&image_header, &actual) == KERN_SUCCESS && actual == sizeof(image_header) && image_header.sizeofcmds <= 1048576);
  size_t size = sizeof(image_header) + image_header.sizeofcmds; unsigned char *bytes = malloc(size); need(bytes && address + size <= (uintptr_t)range + range_size);
  need(mach_vm_read_overwrite(mach_task_self(), address, size, (mach_vm_address_t)bytes, &actual) == KERN_SUCCESS && actual == size);
  char id[33], image_id[33]; hex(uuid, 16, id); hex(image_uuid, 16, image_id);
  printf("{\"cacheUuid\":\"%s\",\"imageUuid\":\"%s\",\"signatureSha256\":\"%s\",\"macho\":", id, image_id, signature_hash); macho(bytes, size); putchar('}'); free(bytes); stable(entry);
}
#include "effective-reader.h"
/* Read the suspended tool's effective credentials, Seatbelt state and complete
 * inherited descriptor set. Expected build vectors are not observations. */
static void compiler_policy(pid_t pid, unsigned version, unsigned asid) {
  struct identity before = inspect(pid), after;
  need(before.token.val[7] == version && before.token.val[6] == asid && asid > 0);
  int sandboxed = sandbox_check(pid, NULL, 0); need(sandboxed == 0 || sandboxed == 1);
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
  struct passwd *pw = getpwuid(subject_uid); struct group *gr = getgrgid(subject_gid);
  char home[PATH_MAX]; need(snprintf(home, sizeof(home), "%s/storage/work", case_path) < sizeof(home));
  need(pw && gr && pw->pw_uid == subject_uid && pw->pw_gid == subject_gid && gr->gr_gid == subject_gid &&
    !strcmp(pw->pw_shell, "/usr/bin/false") && !strcmp(pw->pw_passwd, "*") && !strcmp(pw->pw_dir, home) && gr->gr_mem && !gr->gr_mem[0]);
  gid_t groups[2]; int count = 2; need(getgrouplist(pw->pw_name, subject_gid, groups, &count) >= 0 && count == 1 && groups[0] == subject_gid);
  /* gr_mem omits primary membership. Enumerate both namespaces so another
   * login or group alias cannot acquire the reserved numeric authority. */
  struct case_accounts accounts = {0}; setpwent();
  for (unsigned scanned = 0;; scanned++) {
    errno = 0; struct passwd *value = getpwent(); if (!value) { need(!errno); break; } need(scanned < 4096);
    if (value->pw_uid == subject_uid) { need(value->pw_gid == subject_gid); accounts.uid_accounts++; }
    if (value->pw_gid == subject_gid) { need(value->pw_uid == subject_uid); accounts.primary_members++; }
  } endpwent();
  setgrent();
  for (unsigned scanned = 0;; scanned++) {
    errno = 0; struct group *value = getgrent(); if (!value) { need(!errno); break; } need(scanned < 4096);
    if (value->gr_gid == subject_gid) { need(value->gr_mem && !value->gr_mem[0]); accounts.gid_groups++; }
  } endgrent();
  need(accounts.uid_accounts == 1 && accounts.primary_members == 1 && accounts.gid_groups == 1); return accounts;
}
static void case_directory(struct entry *entry) {
  need(case_mode); reservation_guard(); no_subjects();
  const char *suffix = entry->path + strlen(case_path);
  need(!strncmp(entry->path, case_path, strlen(case_path)));
  bool root = !*suffix, custody = !strcmp(suffix, "/custody"), storage = !strcmp(suffix, "/storage"), work = !strcmp(suffix, "/storage/work");
  need((root && !case_started && !strcmp(entry->kind, "directory")) ||
    (case_started && (custody || storage || work) && !strcmp(entry->kind, "authority")));
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
    !fchmod(entry->fd, (root || storage) ? 0710 : 0700) && !fstat(entry->fd, &entry->stat));
  need(!fstatat(base, leaf, &st, AT_SYMLINK_NOFOLLOW)); same_stat(st, entry->stat); no_acl(entry->fd); file_capabilities(entry->fd);
  need(!close(base)); if (root) case_started = true; stable(entry); identity(entry);
}
static void case_copy(struct entry *target, struct entry *source) {
  need(case_mode && case_started); reservation_guard(); no_subjects(); stable(source); no_acl(source->fd); file_capabilities(source->fd);
  const char *suffix = target->path + strlen(case_path);
  need(!strncmp(target->path, case_path, strlen(case_path)));
  bool policy = !strcmp(suffix, "/custody/policy"), executable = !strcmp(suffix, "/custody/launcher") || !strcmp(suffix, "/storage/payload");
  need((policy && !strcmp(target->kind, "data") && !strcmp(source->kind, "data")) ||
    (executable && !strcmp(target->kind, "image") && !strcmp(source->kind, "image")));
  need(strcmp(source->path, target->path) && !strncmp(source->pin, target->pin, 65) &&
    source->stat.st_uid == 0 && source->stat.st_gid == 0 && S_ISREG(source->stat.st_mode) &&
    !(source->stat.st_mode & 022) && source->stat.st_size > 0 && source->stat.st_size <= 134217728);
  char parent[PATH_MAX]; strcpy(parent, target->path); char *leaf = strrchr(parent, '/'); need(leaf); *leaf++ = 0;
  struct entry *base = NULL; for (unsigned i = 0; i < count; i++) if (entries[i].fd >= 0 && !strcmp(entries[i].path, parent)) base = &entries[i];
  need(base); stable(base); int writer = openat(base->fd, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); need(writer >= 0);
  unsigned char bytes[65536]; for (uint64_t offset = 0; offset < (uint64_t)source->stat.st_size;) {
    size_t size = (uint64_t)source->stat.st_size - offset > sizeof(bytes) ? sizeof(bytes) : (size_t)((uint64_t)source->stat.st_size - offset);
    read_at(source->fd, bytes, size, offset); size_t done = 0;
    while (done < size) { ssize_t n = write(writer, bytes + done, size - done); if (n < 0 && errno == EINTR) continue; need(n > 0); done += n; } offset += size;
  }
  struct stat written; need(!fchown(writer, 0, policy || !strcmp(suffix, "/custody/launcher") ? 0 : subject_gid) && !fchmod(writer, policy ? 0400 : 0550) && !fsync(writer) && !fstat(writer, &written) && !close(writer));
  target->fd = openat(base->fd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); need(target->fd >= 0 && !fstat(target->fd, &target->stat)); same_stat(written, target->stat);
  need(target->stat.st_nlink == 1); no_acl(target->fd); file_capabilities(target->fd);
  char hash[65]; sha_range(target->fd, 0, target->stat.st_size, hash); need(!strcmp(hash, target->pin)); stable(source); stable(target); identity(target);
}
static void case_rejoin(struct entry *entry) {
  need(case_mode); reservation_guard(); no_subjects();
  size_t length = strlen(case_path); need(!strncmp(entry->path, case_path, length) && (!entry->path[length] || entry->path[length] == '/'));
  bool dir = !strcmp(entry->kind, "directory") || !strcmp(entry->kind, "authority");
  entry->fd = open(entry->path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (dir ? O_DIRECTORY : 0));
  need(entry->fd >= 0 && !fstat(entry->fd, &entry->stat) &&
    (entry->stat.st_uid == 0 || entry->stat.st_uid == subject_uid) && (entry->stat.st_gid == 0 || entry->stat.st_gid == subject_gid) && !(entry->stat.st_mode & 022));
  need(dir ? S_ISDIR(entry->stat.st_mode) : S_ISREG(entry->stat.st_mode) && entry->stat.st_nlink == 1 && entry->stat.st_size > 0 && entry->stat.st_size <= 134217728);
  no_acl(entry->fd); file_capabilities(entry->fd); if (!dir) { char hash[65]; sha_range(entry->fd, 0, entry->stat.st_size, hash); need(!strcmp(hash, entry->pin)); }
  if (!entry->path[length]) case_started = true; stable(entry); identity(entry);
}
static void case_endpoint(unsigned family, unsigned protocol, unsigned port) {
  need(case_mode && case_started && case_socket_count < 8 && (family == 4 || family == 6) && (protocol == 6 || protocol == 17) && port >= 1024 && port <= 65535);
  reservation_guard(); no_subjects(); int af = family == 4 ? AF_INET : AF_INET6;
  int fd = socket(af, protocol == 6 ? SOCK_STREAM : SOCK_DGRAM, protocol); need(fd >= 0 && !fcntl(fd, F_SETFD, FD_CLOEXEC));
  int reuse; socklen_t size = sizeof(reuse); need(!getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, &size) && !reuse);
  size = sizeof(reuse); need(!getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, &size) && !reuse);
  if (af == AF_INET) { struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)}; need(!bind(fd, (void *)&address, sizeof(address))); }
  else { int only = 1; need(!setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only))); struct sockaddr_in6 address = {.sin6_len = sizeof(address), .sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_LOOPBACK_INIT}; need(!bind(fd, (void *)&address, sizeof(address))); }
  if (protocol == 6) need(!listen(fd, 1)); case_sockets[case_socket_count++] = fd; fputs("null", stdout);
}
static void case_read(void) {
  need(case_mode && case_started); reservation_guard(); no_subjects(); struct case_accounts accounts = case_account();
  printf("{\"contextSha256\":\"%s\",\"uid\":%u,\"gid\":%u,\"accountVerified\":true,\"accounts\":{\"uidAccounts\":%u,\"primaryGroupMembers\":%u,\"gidGroups\":%u},\"objects\":[",
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
static void case_retire(void) {
  need(case_mode && !case_policy_possible && !file_pid && !session_count); reservation_guard(); no_subjects(); case_account();
  for (unsigned i = 0; i < case_socket_count; i++) need(!close(case_sockets[i])); case_socket_count = 0;
  no_subjects(); need(!close(reservation_fd)); reservation_fd = -1; reservation_entry = NULL;
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
  struct stat named;
  if (fstatat(build_parent, "platform-build", &named, AT_SYMLINK_NOFOLLOW) < 0) {
    need(errno == ENOENT && !mkdirat(build_parent, "platform-build", 0700));
    need(!fstatat(build_parent, "platform-build", &named, AT_SYMLINK_NOFOLLOW));
  } else need(S_ISDIR(named.st_mode) && named.st_uid == 0 && named.st_gid == 0 &&
    ((named.st_mode & 07777) == 0700 || (named.st_mode & 07777) == 0555));
  build_root = openat(build_parent, "platform-build", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(build_root >= 0 && !fstat(build_root, &build_identity) && S_ISDIR(build_identity.st_mode) &&
    build_identity.st_uid == 0 && build_identity.st_gid == 0 &&
    ((build_identity.st_mode & 07777) == 0700 || (build_identity.st_mode & 07777) == 0555));
  same_stat(named, build_identity); no_acl(build_root);
  need(!fchmod(build_root, 0700) && !fstat(build_root, &build_identity));
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
  need(approved == 1 && count < SLOTS);
  unsigned index = count++; struct entry *value = &entries[index]; strcpy(value->kind, "build"); strcpy(value->path, name);
  value->fd = openat(build_root, base, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  need(value->fd >= 0 && !fstat(value->fd, &value->stat) && S_ISREG(value->stat.st_mode) && value->stat.st_uid == 0 &&
    value->stat.st_gid == 0 && value->stat.st_nlink == 1 && (value->stat.st_mode & 07777) == 0555 &&
    value->stat.st_size > 0 && value->stat.st_size <= 134217728); no_acl(value->fd);
  char actual[65]; sha_range(value->fd, 0, value->stat.st_size, actual); need(!strcmp(pin, "-") || !strcmp(pin, actual));
  stable(value); printf("{\"index\":%u,\"object\":", index); identity(value);
  struct entry root = {.fd = build_root}; strcpy(root.kind, "build"); strcpy(root.path, build_path); need(!fstat(build_root, &root.stat)); stable(&root);
  fputs(",\"root\":", stdout); identity(&root); printf(",\"sha256\":\"%s\"}", actual);
}
static void build_receipt(const char *encoded, const char *pin) {
  char name[PATH_MAX], parent[PATH_MAX], canonical[PATH_MAX]; decode(encoded, name, sizeof(name));
  need(realpath(name, canonical) && !strcmp(name, canonical)); strcpy(parent, name);
  char *leaf = strrchr(parent, '/'); need(leaf && !strncmp(leaf + 1, "darwin-", 7)); *leaf = 0;
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
    (before.st_mode & 07777) == 0400 && before.st_nlink == 1 && before.st_size > 0 && before.st_size <= 1048576); no_acl(fd);
  char actual[65]; sha_range(fd, 0, before.st_size, actual);
  need(!strcmp(actual, pin) && !fstat(fd, &after) && !lstat(name, &named)); same_stat(before, after); same_stat(before, named);
  need(!fstat(root, &parent_after) && !lstat(parent, &named)); same_stat(authority, parent_after); same_stat(authority, named);
  no_acl(root); no_acl(fd); need(!close(fd) && !close(root)); printf("{\"receipt\":\"%s\"}\n", actual); fflush(stdout);
}
int main(int argc, char **argv) {
  need(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 && getenv("CI") && !strcmp(getenv("CI"), "true") && getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"), "true"));
  extern char **environ; unsigned environment = 0;
  for (char **value = environ; *value; value++) { need(!strcmp(*value, "CI=true") || !strcmp(*value, "GITHUB_ACTIONS=true")); environment++; }
  need(environment == 2);
  struct proc_fdinfo inherited[64]; int inherited_size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, inherited, sizeof(inherited));
  need(inherited_size == 3 * sizeof(inherited[0])); unsigned mask = 0;
  for (unsigned i = 0; i < 3; i++) { need(inherited[i].proc_fd >= 0 && inherited[i].proc_fd < 3); mask |= 1U << inherited[i].proc_fd; }
  need(mask == 7);
  umask(0077); signal(SIGALRM, expire); alarm(120);
  if (argc == 3 && !strcmp(argv[1], "--probe")) { pid_t pid = (pid_t)number(argv[2]); need(pid > 1 && pid != getpid()); probe(pid); return 0; }
  bool building = argc == 4 && !strcmp(argv[1], "--build-serve");
  build_mode = building;
  case_mode = argc == 5 && !strcmp(argv[1], "--case-serve");
  need((argc == 4 && (building || !strcmp(argv[1], "--serve"))) || case_mode);
  if (case_mode) {
    need(strlen(argv[4]) == 64 && strspn(argv[4], "0123456789abcdef") == 64); strcpy(case_context, argv[4]);
    need(snprintf(case_path, sizeof(case_path), "/private/var/run/native-poc/cases/%s", case_context) < sizeof(case_path));
  }
  /* The longest fixed file recipe is 360 seconds, followed by bounded cleanup. */
  alarm(building ? 1440 : case_mode ? 420 : 390); /* 22 fixed build commands plus separate cleanup. */
  printf("{\"helper\":"); emit(inspect(getpid())); puts("}"); fflush(stdout);
  char input[FRAME]; line(0, input, sizeof(input)); need(!strcmp(input, "P")); plan(argv[2], argv[3]);
  printf("{\"candidateSha\":\"%s\",\"entries\":%u,\"uid\":%u,\"gid\":%u}\n", candidate, count, subject_uid, subject_gid); fflush(stdout);
  for (;;) {
    line(0, input, sizeof(input)); char *tokens[7], *next; unsigned n = 0;
    for (char *p = strtok_r(input, " ", &next); p; p = strtok_r(NULL, " ", &next)) { need(n < 7); tokens[n++] = p; }
    /* Read-only receipt validation precedes dependent commands, including their
     * journals. It cannot create a recursively unverified observation intent. */
    if (n == 3 && !strcmp(tokens[0], "V")) { need((building || case_mode) && ++operations <= 32768); build_receipt(tokens[1], tokens[2]); continue; }
    need(n >= 2 && number(tokens[1]) == ++sequence && ++operations <= 32768);
    printf("{\"sequence\":%u,\"value\":", sequence);
    if (!strcmp(tokens[0], "process") || !strcmp(tokens[0], "session")) {
      need(n == 3); struct identity value = inspect((pid_t)number(tokens[2]));
      /* Outside controls need read-only identity inspection too. Only the
       * reserved subject can acquire retained audit-session custody. */
      if (!strcmp(tokens[0], "session")) { need(value.token.val[0] == subject_uid && value.token.val[1] == subject_uid && value.token.val[2] == subject_gid && value.token.val[6] > 0 && session_count < 32);
        need(!audit_session_port(value.token.val[6], &sessions[session_count]) && sessions[session_count] != MACH_PORT_NULL);
        struct identity again = inspect((pid_t)value.token.val[5]);
        need(!memcmp(&value.token, &again.token, sizeof(value.token)) && value.bsd.pbi_start_tvsec == again.bsd.pbi_start_tvsec && value.bsd.pbi_start_tvusec == again.bsd.pbi_start_tvusec); session_count++; }
      emit(value);
    } else if (!strcmp(tokens[0], "build")) {
      need(n == 2); char os[256], encoded[513]; size_t size = sizeof(os);
      need(!sysctlbyname("kern.osversion", os, &size, NULL, 0) && size > 1 && size <= sizeof(os) && os[size - 1] == 0 && strnlen(os, size) == size - 1);
      hex((const unsigned char *)os, size - 1, encoded); printf("{\"osBuild\":\"%s\",\"macho\":", encoded);
      need(_mh_execute_header.sizeofcmds <= 1048576); macho((const unsigned char *)&_mh_execute_header, sizeof(_mh_execute_header) + _mh_execute_header.sizeofcmds); putchar('}');
    } else if (!strcmp(tokens[0], "open")) {
      need(n == 3); unsigned index = number(tokens[2]); need(index < count); struct entry *entry = &entries[index]; need(entry->fd < 0);
      bool authority = !strcmp(entry->kind, "authority"), dir = !strcmp(entry->kind, "directory"); ancestors(entry->path);
      entry->fd = open(entry->path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (dir ? O_DIRECTORY : 0));
      need(entry->fd >= 0 && !fstat(entry->fd, &entry->stat) && (entry->stat.st_uid == 0 || (authority && entry->stat.st_uid == subject_uid)) && (entry->stat.st_gid == 0 || (authority && entry->stat.st_gid == subject_gid)) && !(entry->stat.st_mode & 022) &&
        (dir || (authority && S_ISDIR(entry->stat.st_mode)) ? S_ISDIR(entry->stat.st_mode) && ((entry->stat.st_mode & 07777) == 0700 || (authority && (entry->stat.st_mode & 07777) == 0710)) : S_ISREG(entry->stat.st_mode) && entry->stat.st_nlink == 1 && entry->stat.st_size >= 0 && entry->stat.st_size <= 536870912));
      if (!dir && !authority) { need(entry->stat.st_size > 0); char hash[65]; sha_range(entry->fd, 0, (uint64_t)entry->stat.st_size, hash); need(!strcmp(hash, entry->pin)); }
      stable(entry); identity(entry);
    } else if (!strcmp(tokens[0], "case-directory")) { need(n == 3); case_directory(unopened(tokens[2]));
    } else if (!strcmp(tokens[0], "case-rejoin")) { need(n == 3); case_rejoin(unopened(tokens[2]));
    } else if (!strcmp(tokens[0], "case-copy")) { need(n == 4); case_copy(unopened(tokens[2]), slot(tokens[3]));
    } else if (!strcmp(tokens[0], "case-endpoint")) { need(n == 5); case_endpoint(number(tokens[2]), number(tokens[3]), number(tokens[4]));
    } else if (!strcmp(tokens[0], "case-read")) { need(n == 2); case_read();
    } else if (!strcmp(tokens[0], "case-retire")) { need(n == 2); case_retire();
    } else if (!strcmp(tokens[0], "compiler-policy")) { need(building && n == 5); compiler_policy((pid_t)number(tokens[2]), number(tokens[3]), number(tokens[4]));
    } else if (!strcmp(tokens[0], "build-directory")) { need(building && n == 3); build_directory(tokens[2]);
    } else if (!strcmp(tokens[0], "build-root")) { need(building && n == 3); build_root_snapshot(tokens[2]);
    } else if (!strcmp(tokens[0], "build-open")) { need(building && n == 4); build_open(tokens[2], tokens[3]);
    } else if (!strcmp(tokens[0], "root-domain")) { need(n == 5); root_domain((pid_t)number(tokens[2]), number(tokens[3]), number(tokens[4]));
    } else if (!strcmp(tokens[0], "root-retired")) {
      need(building && n == 7); struct identity previous = {0};
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
    } else if (!strcmp(tokens[0], "pf-write")) { need(n == 6); if (case_mode) case_policy_possible = true; pf_write(slot(tokens[2]), slot(tokens[3]), tokens[4], tokens[5]);
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
    } else if (!strcmp(tokens[0], "file-read")) { need(n == 2 && file_pid); char result[9000]; line(file_out, result, sizeof(result)); fputs(result, stdout);
    } else if (!strcmp(tokens[0], "file-send")) { need(n == 3 && file_pid && file_in >= 0); char data[9000]; decode(tokens[2], data, sizeof(data)); size_t size = strlen(data);
      need(write(file_in, data, size) == (ssize_t)size); fputs("null", stdout);
    } else if (!strcmp(tokens[0], "file-close")) { need(n == 2 && file_pid); if (file_in >= 0) need(!close(file_in)); file_in = -1;
      int status; while (waitpid(file_pid, &status, 0) < 0) need(errno == EINTR);
      /* Reaping cannot erase queued or partial private protocol bytes. */
      char trailing; need(read(file_out, &trailing, 1) == 0 && !close(file_out)); file_out = -1; file_pid = 0;
      need(WIFEXITED(status) || (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL));
      printf("{\"code\":%s", WIFEXITED(status) ? "" : "null"); if (WIFEXITED(status)) printf("%d", WEXITSTATUS(status));
      printf(",\"signal\":%s,\"drained\":true}", WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? "\"SIGKILL\"" : "null");
    } else if (!strcmp(tokens[0], "close")) { need(n == 3 && !file_pid); struct entry *entry = slot(tokens[2]); need(!close(entry->fd)); entry->fd = -1;
      if (!strcmp(entry->kind, "build")) { need(!close(build_root) && !close(build_parent)); build_root = build_parent = -1; }
      fputs("null", stdout);
    } else if (!strcmp(tokens[0], "finish")) {
      need(n == 2 && !file_pid); for (unsigned i = 0; i < count; i++) need(entries[i].fd < 0);
      if (build_root >= 0) {
        struct entry value = {.fd = build_root}; strcpy(value.kind, "build"); strcpy(value.path, build_path);
        need(!fstat(build_root, &value.stat)); stable(&value);
        need(!close(build_root) && !close(build_parent)); build_root = build_parent = -1;
      }
      need(reservation_fd < 0 && case_socket_count == 0); /* Recovery releases exclusion independently. */
      if (session_count && !subjects_absent()) { puts("{\"closed\":false}}"); fflush(stdout); continue; }
      for (unsigned i = 0; i < root_domain_count; i++) need(root_members(root_domains[i].token.val[6], false) == 0);
      for (unsigned i = 0; i < session_count; i++) need(mach_port_deallocate(mach_task_self(), sessions[i]) == KERN_SUCCESS);
      fputs("{\"closed\":true}", stdout); puts("}"); fflush(stdout); return 0;
    } else need(0);
    puts("}"); need(!fflush(stdout));
  }
}
