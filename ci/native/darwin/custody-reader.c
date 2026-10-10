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
#include <spawn.h>
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
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/un.h>
#include <semaphore.h>
#include <servers/bootstrap.h>
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
static int file_in = -1, file_out = -1, file_decision = -1;
static char candidate[41];
static uid_t subject_uid;
static gid_t subject_gid;
static bool build_mode, preparation_mode, case_mode, case_started, case_policy_possible, operation_mode;
static bool operations_retired(void);
static char case_path[PATH_MAX], case_context[65];
static int case_sockets[8];
static unsigned case_socket_count;
static pid_t case_pid;
static int case_in = -1, case_out = -1, case_data = -1;
static bool case_recovery;
static au_asid_t case_asid;
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
static void case_members(unsigned asid, bool independent);
static void probe(pid_t pid, int asid) {
  struct proc_bsdinfo b; errno = 0; int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, &b, sizeof(b)), error = errno;
  printf("{\"verifier\":"); emit(inspect(getpid())); printf(",\"subject\":");
  if (n == 0 && error == ESRCH) { need(asid < 0); puts("{\"status\":\"absent\"}}"); return; }
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
  same_stat(st, after); need(!lstat(path, &after)); same_stat(st, after); need(!close(fd)); fputs("]}", stdout);
  if (asid >= 0) { fputs(",\"enumeration\":", stdout); case_members((unsigned)asid, true); }
  puts("}");
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
    char prepared_path[PATH_MAX]; need(snprintf(prepared_path,sizeof(prepared_path),"%s/platform-build",report_path) < sizeof(prepared_path));
    bool prepared = preparation_mode && !strncmp(entry->path,prepared_path,strlen(prepared_path)) &&
      (!entry->path[strlen(prepared_path)] || entry->path[strlen(prepared_path)] == '/');
    if (!private_case && !prepared && !((build_mode || case_mode) && !strcmp(entry->kind, "directory") && leaf && !strcmp(leaf + 1, "platform-build"))) ancestors(entry->path);
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
    if (found == count) { char owner_image[PATH_MAX]; need(proc_pidpath(getpid(), owner_image, sizeof(owner_image)) > 0 && !strcmp(image, owner_image)); }
    struct stat stat; ancestors(image);
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
  need(named >= 0 && same(identify(named, true, 0), r) && !close(named) && r.device == b.device && r.fs0 == b.fs0 && r.fs1 == b.fs1 && !memcmp(r.volume, b.volume, 16));
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
static bool owned_access_socket(const char *name, const struct stat *st);
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
  need((root && !case_started && !strcmp(entry->kind, "directory")) ||
    (case_started && (custody || storage || work || (count > 12 &&
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
    !fchmod(entry->fd, (root || storage || (count > 12 && !custody && !work)) ? 0710 : 0700) && !fstat(entry->fd, &entry->stat));
  need(!fstatat(base, leaf, &st, AT_SYMLINK_NOFOLLOW)); same_stat(st, entry->stat); no_acl(entry->fd); file_capabilities(entry->fd);
  need(!close(base)); if (root) case_started = true; stable(entry); identity(entry);
}
static void case_copy(struct entry *target, struct entry *source) {
  need(case_mode && case_started); reservation_guard(); no_subjects(); stable(source); no_acl(source->fd); file_capabilities(source->fd);
  const char *suffix = target->path + strlen(case_path);
  need(!strncmp(target->path, case_path, strlen(case_path)));
  bool policy = !strcmp(suffix, "/custody/policy") || (count > 12 &&
    (!strcmp(suffix, "/custody/darwin-pf.conf") || !strcmp(suffix, "/custody/darwin-pf-before.conf") || !strcmp(suffix, "/custody/access-cases") || !strncmp(suffix, "/custody/git-policy-", 19))), executable = !strcmp(suffix, "/custody/launcher") || !strcmp(suffix, "/storage/payload") || (count > 12 && (!strcmp(suffix, "/custody/pfctl") || !strcmp(suffix, "/custody/observer") || !strcmp(suffix, "/custody/git-executor") || !strcmp(suffix, "/storage/git")));
  bool git_data = !strcmp(suffix, "/outside/sentinel") || git_path(suffix, false) || !strcmp(suffix, "/storage/work/.git") || !strcmp(suffix, "/storage/work/content.txt") || !strcmp(suffix, "/storage/control-work/.git") || !strcmp(suffix, "/storage/control-work/content.txt");
  need(((policy || git_data) && !strcmp(target->kind, "data") && !strcmp(source->kind, "data")) ||
    (executable && (!strcmp(target->kind, "image") || !strcmp(target->kind, "helper")) && (!strcmp(source->kind, "image") || !strcmp(source->kind, "helper"))));
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
  struct stat written; need(!fchown(writer, git_data && (!strncmp(suffix, "/storage/work/", 14) || !strncmp(suffix, "/storage/control-work/", 22)) ? subject_uid : 0, policy || strncmp(suffix, "/custody/", 9) == 0 ? 0 : subject_gid) && !fchmod(writer, policy ? 0400 : git_data ? (git_path(suffix, false) ? 0440 : 0400) : 0550) && !fsync(writer) && !fstat(writer, &written) && !close(writer));
  target->fd = openat(base->fd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); need(target->fd >= 0 && !fstat(target->fd, &target->stat)); same_stat(written, target->stat);
  need(target->stat.st_nlink == 1); no_acl(target->fd); file_capabilities(target->fd);
  char hash[65]; sha_range(target->fd, 0, target->stat.st_size, hash); need(!strcmp(hash, target->pin)); stable(source); stable(target); identity(target);
}
static void case_rejoin(struct entry *entry) {
  need(case_mode); reservation_guard(); if (!case_recovery) no_subjects();
  size_t length = strlen(case_path); need(!strncmp(entry->path, case_path, length) && (!entry->path[length] || entry->path[length] == '/'));
  bool dir = !strcmp(entry->kind, "directory") || !strcmp(entry->kind, "authority");
  entry->fd = open(entry->path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (dir ? O_DIRECTORY : 0));
  need(entry->fd >= 0 && !fstat(entry->fd, &entry->stat) &&
    (entry->stat.st_uid == 0 || entry->stat.st_uid == subject_uid) && (entry->stat.st_gid == 0 || entry->stat.st_gid == subject_gid) && !(entry->stat.st_mode & 022));
  need(dir ? S_ISDIR(entry->stat.st_mode) : S_ISREG(entry->stat.st_mode) && entry->stat.st_nlink == 1 && entry->stat.st_size > 0 && entry->stat.st_size <= 134217728);
  no_acl(entry->fd); file_capabilities(entry->fd); if (!dir) { char hash[65]; sha_range(entry->fd, 0, entry->stat.st_size, hash); need(!strcmp(hash, entry->pin)); }
  if (!entry->path[length]) { case_started = true; case_recovery = true; } stable(entry); identity(entry);
}
/* The reference is born inside held root custody before a root-policy write.
 * Recovery reads it independently; no caller can choose a global PF token. */
static void pf_reference(bool recovering) {
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
}
static void case_endpoint(unsigned family, unsigned protocol, unsigned port) {
  need(case_mode && case_started && case_socket_count < 8 && (family == 4 || family == 6) && (protocol == 6 || protocol == 17) && port >= 1024 && port <= 65535);
  reservation_guard(); no_subjects(); int af = family == 4 ? AF_INET : AF_INET6;
  int handoff[2] = {-1, -1}; pid_t owner = 0;
  if (count > 12) {
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
  if (protocol == 6 && (count == 12 || case_socket_count % 2 == 1)) need(!listen(fd, 1));
  if (count > 12) {
    char rights[CMSG_SPACE(sizeof(int))] = {0}, flag = 'F'; struct iovec io = {.iov_base = &flag, .iov_len = 1};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = rights, .msg_controllen = sizeof(rights)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message); header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd)); need(sendmsg(handoff[1], &message, 0) == 1); _exit(0);
  }
  case_sockets[case_socket_count++] = fd; fputs("null", stdout);
}
static void case_read(void) {
  need(case_mode && case_started); reservation_guard(); struct case_accounts accounts = case_account();
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
/* Finite ownership operations. Privilege is checked here, at the executing
 * owner. No caller path, environment, executable or arbitrary command is used. */
static void case_start(const char *mode, const char *cdhash) {
  need(case_mode && case_started && !case_pid && !case_recovery && (count == 12 || !strcmp(mode, "access")));
  reservation_guard(); no_subjects(); case_account();
  const char *fixed[] = {"literal", "storage", "fork-exec", "double-fork", "reparent", "cancel", "owner-loss", "helper-loss", "receipt-recovery", "stale-identity", "process-limit"};
  bool allowed = count > 12 && !strcmp(mode, "access"); for (unsigned i = 0; i < 11; i++) if (!strcmp(mode, fixed[i])) allowed = true; need(allowed);
  struct entry *launcher = &entries[4], *payload = &entries[5], *policy = &entries[6];
  for (unsigned i = 0; i < 7; i++) stable(&entries[i]);
  signature(payload->path, cdhash);
  /* The launcher copy is joined to the independently approved final build pin
   * by the controller before this command; native validity is checked again. */
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)launcher->path, strlen(launcher->path), false);
  SecStaticCodeRef code = NULL; need(url && SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess &&
    SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL) == errSecSuccess); CFRelease(code); CFRelease(url);
  int control[2], output[2], data[2]; need(!pipe(control) && !pipe(output) && !socketpair(AF_UNIX, SOCK_STREAM, 0, data));
  posix_spawn_file_actions_t actions; posix_spawnattr_t attributes;
  need(!posix_spawn_file_actions_init(&actions) && !posix_spawnattr_init(&attributes) &&
    !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) &&
    !posix_spawn_file_actions_adddup2(&actions, control[0], 0) &&
    !posix_spawn_file_actions_adddup2(&actions, output[1], 1) &&
    !posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0) &&
    !posix_spawn_file_actions_adddup2(&actions, data[1], 3));
  char uid[24], gid[24], nonce[33]; snprintf(uid, sizeof(uid), "%u", subject_uid); snprintf(gid, sizeof(gid), "%u", subject_gid);
  memcpy(nonce, case_context, 32); nonce[32] = 0;
  char *argv[20] = {launcher->path, uid, gid, entries[1].path, entries[2].path, entries[3].path,
    payload->path, payload->pin, (char *)cdhash, policy->path, policy->pin, nonce, "--"};
  if (!strcmp(mode, "literal") || !strcmp(mode, "storage") || !strcmp(mode, "access")) {
    argv[13] = ""; argv[14] = "space value"; argv[15] = "λ雪"; argv[16] = "'\""; argv[17] = "$(false); & | < > *";
  } else { argv[13] = nonce; argv[14] = (char *)mode; }
  char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", !strcmp(mode, "access") ? "NATIVE_ACCESS_CUSTODY=true" : "NATIVE_OWNERSHIP_CUSTODY=true", NULL};
  need(!posix_spawn(&case_pid, launcher->path, &actions, &attributes, argv, environment) &&
    !posix_spawn_file_actions_destroy(&actions) && !posix_spawnattr_destroy(&attributes));
  need(!close(control[0]) && !close(output[1]) && !close(data[1]));
  case_in = control[1]; case_out = output[0]; case_data = data[0];
  /* The hello is consumed separately. No P acknowledgement has been sent. */
  printf("{\"pid\":%d}", case_pid);
}
static void case_line(int fd, bool encoded) {
  need(case_mode && case_pid && fd >= 0); char bytes[8192]; unsigned length = 0;
  for (;;) {
    struct pollfd wait = {.fd = fd, .events = POLLIN}; char byte;
    need(poll(&wait, 1, 30000) == 1 && (wait.revents & POLLIN) && read(fd, &byte, 1) == 1 && byte && length + 1 < sizeof(bytes));
    bytes[length++] = byte; if (byte == '\n') break;
  }
  if (encoded) { char out[16385]; hex((void *)bytes, length, out); printf("{\"hex\":\"%s\"}", out); }
  else { bytes[length - 1] = 0; fputs(bytes, stdout); }
}
static void case_send(bool payload, const char *value) {
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
  need(case_mode && asid < INT32_MAX); if (!independent) { need(asid > 0); reservation_guard(); }
  pid_t pids[4096]; errno = 0; int size = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
  need(!errno && size > 0 && size < sizeof(pids) && size % sizeof(pid_t) == 0);
  printf("{\"uid\":%u,\"complete\":true,\"capacity\":33,\"live\":[", subject_uid); unsigned members = 0, zombies = 0; struct proc_bsdinfo dead[32];
  for (unsigned i = 0; i < (unsigned)size / sizeof(pid_t); i++) {
    if (!pids[i]) continue; struct proc_bsdinfo before, after;
    auditpinfo_addr_t audit = {.ap_pid = pids[i]}, again = {.ap_pid = pids[i]};
    need(proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &before, sizeof(before)) == sizeof(before) &&
      !auditon(A_GETPINFO_ADDR, &audit, sizeof(audit)) &&
      proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &after, sizeof(after)) == sizeof(after) &&
      !auditon(A_GETPINFO_ADDR, &again, sizeof(again)) && before.pbi_start_tvsec == after.pbi_start_tvsec &&
      before.pbi_start_tvusec == after.pbi_start_tvusec && before.pbi_uid == after.pbi_uid && audit.ap_asid == again.ap_asid && audit.ap_auid == again.ap_auid);
    if (before.pbi_uid != subject_uid && (!asid || audit.ap_asid != asid)) continue;
    need(before.pbi_uid == subject_uid && before.pbi_ruid == subject_uid && before.pbi_svuid == subject_uid &&
      before.pbi_gid == subject_gid && before.pbi_rgid == subject_gid && before.pbi_svgid == subject_gid && audit.ap_asid == asid && audit.ap_auid == subject_uid);
    if (before.pbi_status == SZOMB) {
      need(after.pbi_status == SZOMB && zombies < 32); dead[zombies++] = after; continue;
    }
    struct identity actual = inspect(pids[i]); need(actual.token.val[6] == asid && ++members <= 32);
    if (members > 1) putchar(','); emit(actual);
  }
  need(members + zombies <= 32); fputs("],\"zombies\":[", stdout);
  for (unsigned i = 0; i < zombies; i++) {
    struct proc_bsdinfo *b = &dead[i];
    printf("%s{\"pid\":%u,\"uid\":%u,\"gid\":%u,\"ruid\":%u,\"rgid\":%u,\"svuid\":%u,\"svgid\":%u,\"startSeconds\":%llu,\"startMicroseconds\":%llu}",
      i ? "," : "", b->pbi_pid, b->pbi_uid, b->pbi_gid, b->pbi_ruid, b->pbi_rgid, b->pbi_svuid, b->pbi_svgid,
      (unsigned long long)b->pbi_start_tvsec, (unsigned long long)b->pbi_start_tvusec);
  }
  fputs("]}", stdout);
}
extern int proc_signal_with_audittoken(const audit_token_t *, int);
static uint64_t case_number(const char *value, uint64_t maximum) {
  char *end; errno = 0; uint64_t result = strtoull(value, &end, 10);
  need(*value && *value != '-' && !errno && !*end && result <= maximum); return result;
}
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
        if (!actual.token.val[1]) {
          char path[PATH_MAX]; need(proc_pidpath(pid, path, sizeof(path)) > 0 && !strcmp(path, entries[4].path)); stable(&entries[4]);
          struct stat st; free(file(path, 0, 0550, 134217728, entries[4].pin, &st));
        } else need(actual.token.val[0] == subject_uid && actual.token.val[1] == subject_uid && actual.token.val[2] == subject_gid);
        need(!proc_signal_with_audittoken(&actual.token, SIGKILL)); outcome = "sent";
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
  need(sandbox_check(pid, NULL, SANDBOX_CHECK_NO_REPORT) == 1);
  printf("{\"identity\":"); emit(before); printf(",\"imageSha256\":\"%s\",\"cwd\":{\"dev\":\"%u\",\"ino\":\"%llu\"},\"sandboxed\":true,\"decisions\":[", entries[5].pin, v->vst_dev, (unsigned long long)v->vst_ino);
  for (unsigned i = 0; i < 7; i++) {
    int result = sandbox_check(pid, "file-write-data", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, entries[i].path);
    need(result == 0 || result == 1); printf("%s%d", i ? "," : "", result);
  }
  struct identity after = inspect(pid); need(!memcmp(&before.token, &after.token, sizeof(before.token)) && before.bsd.pbi_start_tvsec == after.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == after.bsd.pbi_start_tvusec);
  fputs("]}", stdout);
}
static void case_retire(void) {
  need(case_mode && !case_policy_possible && !file_pid); reservation_guard(); no_subjects(); case_account();
  if (case_pid) {
    int status; while (waitpid(case_pid, &status, 0) < 0) need(errno == EINTR);
    need(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    need(!close(case_in) && !close(case_out) && !close(case_data)); case_pid = 0;
  }
  for (unsigned i = 0; i < case_socket_count; i++) need(!close(case_sockets[i])); case_socket_count = 0;
  no_subjects(); if (count == 12 || (operation_mode && operations_retired())) { need(!close(reservation_fd)); reservation_fd = -1; reservation_entry = NULL; }
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
    (before.st_mode & 07777) == 0400 && before.st_nlink == 1 && before.st_size > 0 && before.st_size <= 1048576); no_acl(fd);
  char actual[65]; sha_range(fd, 0, before.st_size, actual);
  need(!strcmp(actual, pin) && !fstat(fd, &after) && !lstat(name, &named)); same_stat(before, after); same_stat(before, named);
  need(!fstat(root, &parent_after) && !lstat(parent, &named)); same_stat(authority, parent_after); same_stat(authority, named);
  no_acl(root); no_acl(fd); need(!close(fd) && !close(root)); printf("{\"receipt\":\"%s\"}\n", actual); fflush(stdout);
}
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
  if (receipt) need(value.stat.st_uid == authority.st_uid && (value.stat.st_mode & 07777) == 0400 && value.stat.st_size <= 1048576);
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
  need(case_mode && !access_pf_pid && count > 12); reservation_guard();
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
  const unsigned actions[] = {PF_SCRUB, PF_PASS, PF_NAT, PF_BINAT, PF_RDR};
  for (unsigned set = 0; set < PF_RULESET_MAX; set++) {
    need(set < sizeof(actions) / sizeof(actions[0])); struct pfioc_rule rule = {0}; rule.rule.action = actions[set];
    need(!ioctl(pf, DIOCGETRULES, &rule) && rule.ticket == root_tickets[set] && rule.nr == root_counts[set]);
    snprintf(rule.anchor, sizeof(rule.anchor), "native-poc/%.32s", case_context); rule.rule.action = actions[set];
    need(!ioctl(pf, DIOCGETRULES, &rule) && rule.ticket == case_tickets[set] && rule.nr == case_counts[set]);
  }
  need(!close(pf));
  need(write(access_pf_in, "R", 1) == 1); char result[8192]; line(access_pf_out, result, sizeof(result));
  need(!strcmp(result, "{\"exitCode\":0,\"signal\":null}")); access_wait(&access_pf_pid, &access_pf_in, &access_pf_out);
  fputs("{\"exitCode\":0,\"signal\":null}", stdout);
}
static void access_audit_start(struct entry *observer, const char *cdhash, unsigned classes) {
  need(case_mode && count > 12 && !access_audit_pid && classes && observer == access_named("/custody/observer"));
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
static socklen_t access_address(struct sockaddr_storage *storage, unsigned family, const char *name, unsigned port) {
  memset(storage, 0, sizeof(*storage));
  if (family == AF_INET) { struct sockaddr_in *a = (void *)storage; a->sin_len = sizeof(*a); a->sin_family = family; a->sin_port = htons(port); need(inet_pton(family, name, &a->sin_addr) == 1); return sizeof(*a); }
  struct sockaddr_in6 *a = (void *)storage; a->sin6_len = sizeof(*a); a->sin6_family = family; a->sin6_port = htons(port); need(inet_pton(family, name, &a->sin6_addr) == 1); return sizeof(*a);
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
    else if (i < 35) need(!strcmp(op, (i - 19) % 4 == 0 ? "tcp4" : (i - 19) % 4 == 1 ? "udp4" : (i - 19) % 4 == 2 ? "tcp6" : "udp6");
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
  struct pfioc_rule query = {0}; snprintf(query.anchor, sizeof(query.anchor), "native-poc/%.32s", case_context); query.rule.action = PF_PASS;
  need(!ioctl(fd, DIOCGETRULES, &query)); unsigned total = query.nr, ticket = query.ticket; need(total <= 64); putchar('[');
  for (unsigned i = 0; i < total; i++) {
    query.nr = i; query.ticket = ticket; query.rule.action = PF_PASS; need(!ioctl(fd, DIOCGETRULE, &query));
    struct pf_rule *r = &query.rule; uint64_t packets = r->packets[0] + r->packets[1]; need(packets >= r->packets[0]);
    memset(&r->entries, 0, sizeof(r->entries)); memset(r->skip, 0, sizeof(r->skip)); r->kif = NULL; r->anchor = NULL; r->overload_tbl = NULL;
    r->evaluations = r->states_cur = r->states_tot = r->src_nodes = r->nr = 0;
    memset(r->packets, 0, sizeof(r->packets)); memset(r->bytes, 0, sizeof(r->bytes)); memset(&r->rpool.list, 0, sizeof(r->rpool.list)); r->rpool.cur = NULL;
    unsigned char sum[32]; char hash[65]; need(CC_SHA256(r, sizeof(*r), sum)); hex(sum, sizeof(sum), hash);
    printf("%s{\"index\":%u,\"packets\":\"%llu\",\"ruleSha256\":\"%s\",\"action\":\"%s\"}", i ? "," : "", i, (unsigned long long)packets, hash, r->action == PF_PASS ? "permit" : "deny");
  }
  query.rule.action = PF_PASS; need(!ioctl(fd, DIOCGETRULES, &query) && query.nr == total && query.ticket == ticket && !close(fd)); putchar(']');
}

static void access_provision(struct entry *bank) {
  need(case_mode && count > 12 && !access_ready && !access_pending && bank == access_named("/custody/access-cases"));
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
  need(!memcmp(&live.token, &access_subject.token, sizeof(live.token)) && live.bsd.pbi_start_tvsec == access_subject.bsd.pbi_start_tvsec && live.bsd.pbi_start_tvusec == access_subject.bsd.pbi_start_tvusec);
  int fd = access_control ? access_control_in : case_data, output = access_control ? access_control_out : case_data;
  need(write(fd, "P", 1) == 1); char result[8192];
  for (unsigned i = 0; i < 4; i++) {
    access_result_line(output, result, sizeof(result));
    if (strstr(result, "\"nativeCode\":")) { fputs(result, stdout); access_ran = true; return; }
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
  auditinfo_addr_t audit = {0}; audit.ai_auid = uid; audit.ai_asid = AU_ASSIGN_ASID; audit.ai_termid.at_type = AU_IPv4;
  need(!setaudit_addr(&audit, sizeof(audit)) && !getaudit_addr(&audit, sizeof(audit)) && audit.ai_asid > 0 && audit.ai_asid != AU_ASSIGN_ASID);
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
  if (*ack == 'P') { need(git_in >= 0 && write(git_in, ack, 1) == 1 && !close(git_in)); git_in = -1; }
  else need(write(git_gate, ack, 1) == 1); fputs("null", stdout); }
static void git_close(void) { need(git_pid); if (git_in >= 0) { need(!close(git_in)); git_in = -1; }
  int status; while (waitpid(git_pid, &status, 0) < 0) need(errno == EINTR); char extra;
  need(WIFEXITED(status) && read(git_out, &extra, 1) == 0 && !close(git_out) && !close(git_gate)); git_out = git_gate = -1; git_pid = 0;
  printf("{\"code\":%d,\"signal\":null,\"drained\":true}", WEXITSTATUS(status)); }

static void git_ordinary_start(struct entry *git, struct entry *metadata, struct entry *hooks, struct entry *policy, const char *mode, const char *cdhash) {
  operation_guard(); no_subjects(); need(!git_pid && (!strcmp(mode, "inspect") || !strcmp(mode, "git-add") || !strcmp(mode, "git-commit")));
  struct entry *launcher = &entries[4], *payload = &entries[5]; signature(payload->path, cdhash);
  stable(git); stable(metadata); stable(hooks); stable(policy);
  int in[2], out[2], data[2]; need(!pipe(in) && !pipe(out) && !socketpair(AF_UNIX, SOCK_STREAM, 0, data)); posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
  need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) &&
    !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) &&
    !posix_spawn_file_actions_adddup2(&files, in[0], 0) && !posix_spawn_file_actions_adddup2(&files, out[1], 1) &&
    !posix_spawn_file_actions_addopen(&files, 2, "/dev/null", O_WRONLY, 0) && !posix_spawn_file_actions_adddup2(&files, data[1], 3));
  char uid[24], gid[24], nonce[33]; snprintf(uid, sizeof(uid), "%u", subject_uid); snprintf(gid, sizeof(gid), "%u", subject_gid); memcpy(nonce, case_context, 32); nonce[32] = 0;
  char *argv[] = {launcher->path, uid, gid, entries[1].path, entries[2].path, entries[3].path,
    payload->path, payload->pin, (char *)cdhash, policy->path, policy->pin, nonce, "--", nonce, (char *)mode, git->path, metadata->path, entries[3].path, hooks->path, NULL};
  char *env[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", "NATIVE_OWNERSHIP_CUSTODY=true", NULL};
  need(!posix_spawn(&git_pid, launcher->path, &files, &attributes, argv, env) && !posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes));
  need(!close(in[0]) && !close(out[1]) && !close(data[1])); git_in = in[1]; git_out = out[0]; git_data = data[0]; git_identity = inspect(git_pid); printf("{\"pid\":%d}", git_pid);
}
static void git_ordinary_release(bool payload, const char *ack) { need(git_pid && git_in >= 0 && strlen(ack) == 1 && strchr("PRS", *ack)); need(write(payload ? git_data : git_in, ack, 1) == 1); fputs("null", stdout); }
static void git_ordinary_finish(void) { need(git_pid && git_gate < 0 && git_in >= 0); no_subjects();
  struct identity owner = inspect(git_pid); need(!memcmp(&owner.token, &git_identity.token, sizeof(owner.token)) && owner.bsd.pbi_start_tvsec == git_identity.bsd.pbi_start_tvsec && owner.bsd.pbi_start_tvusec == git_identity.bsd.pbi_start_tvusec && owner.token.val[1] == 0 && !proc_signal_with_audittoken(&owner.token, SIGKILL)); int status;
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

static void case_resume(char **values) {
  operation_guard(); need(git_pid); audit_token_t token = {{0}};
  for (unsigned i = 0; i < 8; i++) token.val[i] = number(values[i]);
  uint64_t seconds = number(values[8]); unsigned micros = number(values[9]), saved_uid = number(values[10]), saved_gid = number(values[11]);
  need(token.val[0] == subject_uid && token.val[1] == subject_uid && token.val[2] == subject_gid && token.val[3] == subject_uid && token.val[4] == subject_gid && token.val[5] > 1 && token.val[6] > 0 && token.val[7] > 0 && saved_uid == subject_uid && saved_gid == subject_gid);
  struct identity actual = inspect(token.val[5]); need(!memcmp(&actual.token, &token, sizeof(token)) && actual.bsd.pbi_start_tvsec == seconds && actual.bsd.pbi_start_tvusec == micros && actual.bsd.pbi_svuid == saved_uid && actual.bsd.pbi_svgid == saved_gid);
  need(!proc_signal_with_audittoken(&token, SIGCONT)); fputs("{\"resumed\":true}", stdout);
}
static bool operations_retired(void) { need(!git_pid && !access_audit_pid && !file_caller_count && !file_reader.pid && !file_probe.pid && !volume_owner.pid && control_root < 0); return true; }

static void file_line(void) { need(file_pid); char bytes[9000]; size_t used = 0;
  for (;;) { char byte; struct pollfd wait = {.fd = file_out, .events = POLLIN}; need(poll(&wait, 1, 30000) == 1);
    ssize_t size = read(file_out, &byte, 1); need(size >= 0);
    if (!size) { need(!used); fputs("{\"eof\":true}", stdout); return; }
    need(byte && (unsigned char)byte < 128 && used + 1 < sizeof(bytes));
    if (byte == '\n') { bytes[used] = 0; fputs(bytes, stdout); return; } bytes[used++] = byte;
  }
}
static void operation_authority(void) { operation_guard(); operation_mode = true; no_subjects(); printf("{\"identity\":"); emit(inspect(getpid()));
  printf(",\"sandboxed\":%s,\"noLiveUid\":true}", sandbox_check(getpid(), NULL, 0) == 0 ? "false" : "true"); }
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
  if (argc == 3 && !strcmp(argv[1], "--probe")) { pid_t pid = (pid_t)number(argv[2]); need(pid > 1 && pid != getpid()); probe(pid, -1); return 0; }
  if (argc == 6 && !strcmp(argv[1], "--probe-domain")) {
    pid_t pid = (pid_t)number(argv[2]); subject_uid = number(argv[3]); subject_gid = number(argv[4]);
    need(pid > 1 && pid != getpid() && subject_uid > 500 && subject_gid > 500); case_mode = true;
    probe(pid, number(argv[5])); return 0;
  }
  bool building = argc == 4 && !strcmp(argv[1], "--build-serve");
  preparation_mode = argc == 5 && !strcmp(argv[1], "--prepare-serve");
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
  printf("{\"candidateSha\":\"%s\",\"entries\":%u,\"uid\":%u,\"gid\":%u}\n", candidate, count, subject_uid, subject_gid); fflush(stdout);
  for (;;) {
    line(0, input, sizeof(input)); char *tokens[16], *next; unsigned n = 0;
    for (char *p = strtok_r(input, " ", &next); p; p = strtok_r(NULL, " ", &next)) { need(n < 16); tokens[n++] = p; }
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
    } else if (!strcmp(tokens[0], "case-start")) { need(n == 4); case_start(tokens[2], tokens[3]);
    } else if (!strcmp(tokens[0], "case-control")) { need(n == 2); case_line(case_out, false);
    } else if (!strcmp(tokens[0], "case-eof")) {
      need(case_mode && n == 2 && case_data >= 0); char trailing; struct pollfd wait = {.fd = case_data, .events = POLLIN};
      need(poll(&wait, 1, 30000) == 1 && !(wait.revents & (POLLERR | POLLNVAL)) && read(case_data, &trailing, 1) == 0);
      fputs("{\"complete\":true}", stdout);
    } else if (!strcmp(tokens[0], "case-output")) { need(n == 2); case_line(case_data, true);
    } else if (!strcmp(tokens[0], "case-send")) { need(n == 4); case_send(number(tokens[2]) == 1, tokens[3]);
    } else if (!strcmp(tokens[0], "case-receipt")) { need(n == 5); case_receipt(number(tokens[2]), tokens[3], tokens[4], false);
    } else if (!strcmp(tokens[0], "case-receipt-read")) { need(n == 4); case_receipt(number(tokens[2]), tokens[3], NULL, false);
    } else if (!strcmp(tokens[0], "case-receipt-optional")) { need(n == 4); case_receipt(number(tokens[2]), tokens[3], NULL, true);
    } else if (!strcmp(tokens[0], "case-session")) {
      need(case_mode && n == 3); unsigned asid = number(tokens[2]); need(asid > 0 && (!case_asid || case_asid == asid));
      if (!case_asid) { need(session_count < 32 && !audit_session_port(asid, &sessions[session_count]) && sessions[session_count] != MACH_PORT_NULL); session_count++; case_asid = asid; }
      printf("{\"asid\":%u,\"held\":true}", asid);
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
