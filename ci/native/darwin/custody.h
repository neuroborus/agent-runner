/* Shared protected bytes, signatures and audit-token identity reads. */
#ifndef NATIVE_DARWIN_CUSTODY_H
#define NATIVE_DARWIN_CUSTODY_H
#include <mach-o/loader.h>
#include <sys/acl.h>
static void need(int ok) { if (!ok) _exit(126); }
static unsigned number(const char *s) {
  char *end; errno = 0; unsigned long n = strtoul(s, &end, 10);
  need(*s && !errno && !*end && n <= 0x7fffffffUL); return (unsigned)n;
}
static void hex(const unsigned char *data, size_t n, char *out) {
  for (size_t i = 0; i < n; i++) sprintf(out + 2*i, "%02x", data[i]);
}
static int directory(const char *name, uid_t uid, gid_t gid, mode_t mode) {
  char canonical[PATH_MAX]; struct stat st;
  need(realpath(name, canonical) && !strcmp(name, canonical));
  int fd = open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  need(fd >= 0 && !fstat(fd, &st) && S_ISDIR(st.st_mode) && st.st_uid == uid &&
       st.st_gid == gid && (st.st_mode & 07777) == mode); return fd;
}
static int file_stat_same(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
    a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
    a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
    a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
/* A pin or custody kind never makes a generated input an installed input. */
static int installed_path(const char *name, const struct stat *st) {
  const char *tools[] = {"/usr/bin/clang", "/usr/bin/xcrun", "/usr/bin/codesign", "/usr/bin/env",
    "/usr/bin/sudo", "/usr/bin/git", "/usr/bin/hdiutil", "/sbin/pfctl"};
  if (!S_ISREG(st->st_mode) || st->st_uid != 0 || st->st_nlink <= 0) return 0;
  mode_t mode = st->st_mode & 07777;
  for (unsigned i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) if (!strcmp(name, tools[i]))
    return st->st_gid == 0 && (!strcmp(name, "/usr/bin/sudo") ? mode == 04555 || mode == 04755 : mode == 0555 || mode == 0755);
  if (mode & 06022) return 0;
  const char *base = strrchr(name, '/');
  return !strcmp(name, "/usr/lib/dyld") || !strcmp(name, "/private/etc/security/audit_event") ||
    !strcmp(name, "/private/etc/security/audit_class") || !strcmp(name, "/etc/security/audit_event") || !strcmp(name, "/etc/security/audit_class") ||
    !strncmp(name, "/Library/Developer/", 19) || (!strncmp(name, "/Applications/", 14) && strstr(name, "/Contents/Developer/")) ||
    !strncmp(name, "/usr/include/", 13) || !strncmp(name, "/usr/lib/clang/", 15) ||
    (base && (!strcmp(base + 1, "dyld_shared_cache_x86_64") || !strcmp(base + 1, "dyld_shared_cache_x86_64h")) &&
      (!strncmp(name, "/System/Library/dyld/", 21) || !strncmp(name, "/System/Volumes/Preboot/", 24)));
}
static int installed_input(const char *name, const struct stat *identity) {
  if (!installed_path(name, identity)) return 0;
  char canonical[PATH_MAX], parent[PATH_MAX];
  need(realpath(name, canonical) && !strcmp(name, canonical) && strlen(name) < sizeof(parent));
  strcpy(parent, name); int leaf = 1;
  for (;;) {
    int fd = open(parent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (leaf ? 0 : O_DIRECTORY));
    struct stat before, after, named;
    need(fd >= 0 && !fstat(fd, &before) && before.st_uid == 0 && !(before.st_mode & 022) &&
      (leaf ? file_stat_same(identity, &before) : S_ISDIR(before.st_mode)));
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED); acl_entry_t entry;
    need(acl && !acl_valid(acl)); errno = 0;
    need(acl_get_entry(acl, ACL_FIRST_ENTRY, &entry) == -1 && errno == EINVAL && !acl_free(acl));
    need(!fstat(fd, &after) && !lstat(parent, &named) && file_stat_same(&before, &after) &&
      file_stat_same(&before, &named) && !close(fd));
    if (!strcmp(parent, "/")) break;
    char *slash = strrchr(parent, '/'); need(slash); if (slash == parent) parent[1] = 0; else *slash = 0;
    leaf = 0;
  }
  return 1;
}
static unsigned char *read_file(const char *name, gid_t gid, mode_t mode,
                           size_t limit, const char *pin, struct stat *identity, int installed) {
  char canonical[PATH_MAX], hash[65]; unsigned char sum[CC_SHA256_DIGEST_LENGTH];
  need(realpath(name, canonical) && !strcmp(name, canonical));
  int fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  need(fd >= 0 && !fstat(fd, identity) && S_ISREG(identity->st_mode) &&
       identity->st_uid == 0 && identity->st_gid == gid &&
       (identity->st_nlink == 1 || (installed && installed_input(name, identity))) &&
       (identity->st_mode & 07777) == mode && identity->st_size > 0 &&
       (uint64_t)identity->st_size <= limit && strlen(pin) == 64);
  size_t size = (size_t)identity->st_size, offset = 0;
  unsigned char *bytes = calloc(size + 1, 1); need(bytes != NULL);
  while (offset < size) {
    ssize_t n = read(fd, bytes + offset, size - offset);
    if (n < 0 && errno == EINTR) continue;
    need(n > 0); offset += (size_t)n;
  }
  unsigned char extra; struct stat after, named;
  need(read(fd, &extra, 1) == 0 && !fstat(fd, &after) && !lstat(name, &named) &&
       file_stat_same(identity, &after) && file_stat_same(identity, &named) &&
       (identity->st_nlink == 1 || installed_input(name, &named)));
  need(CC_SHA256(bytes, (CC_LONG)size, sum) != NULL); hex(sum, sizeof(sum), hash);
  need(!strcmp(hash, pin) && !close(fd)); return bytes;
}
static unsigned char *file(const char *name, gid_t gid, mode_t mode,
                           size_t limit, const char *pin, struct stat *identity) {
  return read_file(name, gid, mode, limit, pin, identity, 0);
}
static unsigned char *installed_file(const char *name, gid_t gid, mode_t mode,
                           size_t limit, const char *pin, struct stat *identity) {
  return read_file(name, gid, mode, limit, pin, identity, 1);
}
#ifndef NATIVE_CI_EXPERIMENT
static void reviewed_image(const char *name) {
  /* Fixed experimental helpers are thin x64 images. Their purpose section
   * remains disqualifying even after a valid native signature is attached. */
  int fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  struct stat before, after; struct mach_header_64 header;
  need(fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) &&
    pread(fd, &header, sizeof(header), 0) == sizeof(header));
  if (header.magic == MH_MAGIC_64) {
    need(header.ncmds <= 512 && header.sizeofcmds <= 1048576 &&
      sizeof(header) + (uint64_t)header.sizeofcmds <= (uint64_t)before.st_size);
    unsigned char *commands = malloc(header.sizeofcmds); need(commands);
    need(pread(fd, commands, header.sizeofcmds, sizeof(header)) == header.sizeofcmds);
    size_t at = 0;
    for (unsigned i = 0; i < header.ncmds; i++) {
      need(at + sizeof(struct load_command) <= header.sizeofcmds);
      const struct load_command *command = (const void *)(commands + at);
      need(command->cmdsize >= 8 && command->cmdsize % 8 == 0 && at + command->cmdsize <= header.sizeofcmds);
      if (command->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *segment = (const void *)command;
        need(command->cmdsize >= sizeof(*segment) && segment->nsects <= 128 &&
          sizeof(*segment) + (uint64_t)segment->nsects * sizeof(struct section_64) == command->cmdsize);
        const struct section_64 *sections = (const void *)(segment + 1);
        for (unsigned section = 0; section < segment->nsects; section++)
          need(strncmp(sections[section].sectname, "__nexp", 16));
      }
      at += command->cmdsize;
    }
    need(at == header.sizeofcmds); free(commands);
  }
  need(!fstat(fd, &after) && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
    before.st_size == after.st_size && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
    before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec && !close(fd));
}
#endif
static void signature(const char *name, const char *pin) {
#ifndef NATIVE_CI_EXPERIMENT
  reviewed_image(name);
#endif
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)name,
                                                        (CFIndex)strlen(name), false);
  SecStaticCodeRef code = NULL; CFDictionaryRef info = NULL;
  need(url && SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess &&
       SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL) == errSecSuccess &&
       SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess);
  CFDataRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
  need(hash && CFGetTypeID(hash) == CFDataGetTypeID() && CFDataGetLength(hash) == 20);
  char actual[41]; hex(CFDataGetBytePtr(hash), 20, actual); need(!strcmp(actual, pin));
  CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
  /* An allowed JIT entitlement is not permission to obtain foreign task/persona rights. */
  if (entitlements) {
    need(CFGetTypeID(entitlements) == CFDictionaryGetTypeID());
    const void *keys[2], *values[2]; CFIndex n = CFDictionaryGetCount(entitlements);
    need(n <= 2); CFDictionaryGetKeysAndValues(entitlements, keys, values);
    for (CFIndex i = 0; i < n; i++) need(values[i] == kCFBooleanTrue &&
      (CFEqual(keys[i], CFSTR("com.apple.security.cs.allow-jit")) ||
       CFEqual(keys[i], CFSTR("com.apple.security.cs.allow-unsigned-executable-memory"))));
  }
  CFRelease(info); CFRelease(code); CFRelease(url);
}
struct identity { audit_token_t token; struct proc_bsdinfo bsd; };
static struct identity inspect(pid_t pid) {
  struct identity value = {0}; struct proc_bsdinfo after; audit_token_t again;
  mach_port_t task = MACH_PORT_NULL; mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  need(proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value.bsd, sizeof(value.bsd)) == (int)sizeof(value.bsd) &&
       task_name_for_pid(mach_task_self(), pid, &task) == KERN_SUCCESS && task != MACH_PORT_NULL &&
       task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&value.token, &count) == KERN_SUCCESS &&
       count == TASK_AUDIT_TOKEN_COUNT);
  count = TASK_AUDIT_TOKEN_COUNT;
  need(proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after)) == (int)sizeof(after) &&
       task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&again, &count) == KERN_SUCCESS &&
       count == TASK_AUDIT_TOKEN_COUNT && !memcmp(&again, &value.token, sizeof(again)) &&
       after.pbi_start_tvsec == value.bsd.pbi_start_tvsec && after.pbi_start_tvusec == value.bsd.pbi_start_tvusec &&
       after.pbi_svuid == value.bsd.pbi_svuid && after.pbi_svgid == value.bsd.pbi_svgid &&
       value.token.val[5] == (unsigned)pid &&
       value.token.val[1] == after.pbi_uid && value.token.val[2] == after.pbi_gid &&
       value.token.val[3] == after.pbi_ruid && value.token.val[4] == after.pbi_rgid &&
       mach_port_deallocate(mach_task_self(), task) == KERN_SUCCESS);
  return value;
}
static void emit(struct identity value) {
  unsigned *t = value.token.val; struct proc_bsdinfo *b = &value.bsd;
  printf("{\"pid\":%u,\"pidVersion\":%u,\"asid\":%u,\"auid\":%u,\"uid\":%u,\"gid\":%u,"
    "\"ruid\":%u,\"rgid\":%u,\"svuid\":%u,\"svgid\":%u,\"startSeconds\":%llu,\"startMicroseconds\":%llu}",
    t[5], t[7], t[6], t[0], t[1], t[2], t[3], t[4], b->pbi_svuid, b->pbi_svgid,
    (unsigned long long)b->pbi_start_tvsec, (unsigned long long)b->pbi_start_tvusec);
}
#endif
