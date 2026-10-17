/* Shared protected bytes, signatures and audit-token identity reads. */
#ifndef NATIVE_DARWIN_CUSTODY_H
#define NATIVE_DARWIN_CUSTODY_H
#ifndef NATIVE_AUDIT_DOMAIN_ONLY
#include <mach-o/loader.h>
#include <stdbool.h>
#include <sys/acl.h>
#include <sys/stat.h>
static void need_at(bool ok, const char *file, unsigned line) {
  if (!ok) {
    int error = errno;
    fprintf(stderr, "native-darwin-guard: file=%s line=%u errno=%d\n", file, line, error);
    fflush(stderr); _exit(126);
  }
}
#define need(ok) need_at(!!(ok), __FILE__, __LINE__)
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
/* A null acl_get_fd_np result cannot distinguish absence from a failed read.
 * Inspect FILESEC_ACL on the held object. A hash request serializes actual ACL
 * text, or zero bytes for inspected absence; both paths require no entries. */
static void custody_acl(int fd, char hash[65]) {
  struct stat before, inspected, after;
  filesec_t security = NULL; acl_t acl = NULL; char *bytes = NULL; ssize_t length = 0;
  const char *operation = NULL, *domain = "errno";
  int result, error = 0, present = -1, text_result = 0, acl_result = 0, text_error = 0, acl_error = 0;
  unsigned char sum[32];
  errno = 0; result = fstat(fd, &before); error = errno;
  if (result) { operation = "file-stat"; goto done; }
  errno = 0; security = filesec_init(); error = errno;
  if (!security) { operation = "filesec-init"; goto done; }
  errno = 0; result = fstatx_np(fd, &inspected, security); error = errno;
  if (result) { operation = "filesec-stat"; goto done; }
  if (!file_stat_same(&before, &inspected)) { operation = "file-stable"; domain = "invariant"; error = 0; goto done; }
  errno = 0; result = filesec_query_property(security, FILESEC_ACL, &present); error = errno;
  if (result) { operation = "acl-query"; goto done; }
  /* Presence is a validity bitmask, not a Boolean restricted to zero and one. */
  if (present != 0) {
    errno = 0; result = filesec_get_property(security, FILESEC_ACL, &acl); error = errno;
    if (result || !acl) { operation = "acl-read"; domain = result ? "errno" : "invariant"; if (!result) error = 0; goto done; }
    errno = 0; result = acl_valid(acl); error = errno;
    if (result) { operation = "acl-valid"; goto done; }
    acl_entry_t entry;
    errno = 0; result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry); error = errno;
    /* Darwin returns zero for an entry and -1/EINVAL after a valid empty ACL. */
    if (!(result == -1 && error == EINVAL)) {
      operation = "acl-empty"; domain = result == -1 ? "errno" : "invariant"; if (result != -1) error = 0; goto done;
    }
    if (hash) {
      errno = 0; bytes = acl_to_text(acl, &length); error = errno;
      if (!bytes) { operation = "acl-text"; goto done; }
      if (length < 0 || length > 65536) { operation = "acl-text-size"; domain = "invariant"; error = 0; goto done; }
    }
  }
  errno = 0; result = fstat(fd, &after); error = errno;
  if (result) { operation = "file-stat-again"; goto done; }
  if (!file_stat_same(&before, &after)) { operation = "file-stable"; domain = "invariant"; error = 0; goto done; }
  if (hash && !CC_SHA256(bytes ? bytes : "", (CC_LONG)length, sum)) {
    operation = "acl-hash"; domain = "invariant"; error = 0;
  }
done:
  if (bytes) { errno = 0; text_result = acl_free(bytes); text_error = errno; }
  if (acl) { errno = 0; acl_result = acl_free(acl); acl_error = errno; }
  /* filesec_free has no status; it is independent of both ACL releases. */
  if (security) filesec_free(security);
  if (operation) fprintf(stderr, "native-darwin-acl: operation=%s domain=%s value=%d\n", operation, domain, error);
  if (text_result) fprintf(stderr, "native-darwin-acl-cleanup: operation=acl-text-release domain=errno value=%d\n", text_error);
  if (acl_result) fprintf(stderr, "native-darwin-acl-cleanup: operation=acl-release domain=errno value=%d\n", acl_error);
  if (operation || text_result || acl_result) {
    fflush(stderr); errno = operation ? error : text_result ? text_error : acl_error; need(false);
  }
  if (hash) hex(sum, sizeof(sum), hash);
}
static void no_acl(int fd) { custody_acl(fd, NULL); }
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
    no_acl(fd);
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
#ifdef NATIVE_CI_EXPERIMENT
/* Derive one documented installation, never search for another toolchain.
 * Resolve the installation's named clang separately from the stock shim. */
static inline void developer_paths(const char *sdk, char developer[PATH_MAX], char compiler[PATH_MAX]) {
  const char *clt = "/Library/Developer/CommandLineTools", *sdk_prefix = "/Library/Developer/CommandLineTools/SDKs/", *leaf;
  char named[PATH_MAX], canonical[PATH_MAX];
  if (!strncmp(sdk, sdk_prefix, strlen(sdk_prefix))) {
    strcpy(developer, clt); leaf = sdk + strlen(sdk_prefix);
    need(snprintf(named, sizeof(named), "%s/usr/bin/clang", developer) < sizeof(named));
  } else {
    const char *layout = ".app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/";
    const char *marker = strstr(sdk, layout);
    need(!strncmp(sdk, "/Applications/", 14) && marker && marker > sdk + 14 &&
      (size_t)(marker - sdk) < PATH_MAX && !memchr(sdk + 14, '/', (size_t)(marker - sdk - 14)));
    size_t size = (size_t)(marker - sdk) + strlen(".app/Contents/Developer");
    need(size < PATH_MAX); memcpy(developer, sdk, size); developer[size] = 0;
    leaf = marker + strlen(layout);
    need(snprintf(named, sizeof(named), "%s/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang", developer) < sizeof(named));
  }
  need(*leaf && !strchr(leaf, '/') && strcmp(leaf, ".") && strcmp(leaf, "..") &&
    realpath(developer, canonical) && !strcmp(developer, canonical) && realpath(named, compiler));
  char *slash = strrchr(named, '/'); need(slash); slash[1] = 0;
  need(!strncmp(compiler, named, strlen(named)) && compiler[strlen(named)] && !strchr(compiler + strlen(named), '/'));
}
#endif
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
/* Only fixed native domain owners opt into these shared native operations.
 * The existing exact custody.h source/dependency inventory binds their bytes. */
#ifdef NATIVE_AUDIT_DOMAIN
#ifndef AUDIT_DOMAIN_INSPECT
#define AUDIT_DOMAIN_INSPECT(pid) inspect(pid)
#endif
#ifndef AUDIT_DOMAIN_DIAG
#define AUDIT_DOMAIN_DIAG(ok, operation, kind, value) do { (void)(operation); (void)(kind); (void)(value); need(ok); } while (0)
#endif
static bool audit_identity_same(struct identity a, struct identity b) {
  return !memcmp(&a.token, &b.token, sizeof(a.token)) &&
    a.bsd.pbi_start_tvsec == b.bsd.pbi_start_tvsec && a.bsd.pbi_start_tvusec == b.bsd.pbi_start_tvusec &&
    a.bsd.pbi_svuid == b.bsd.pbi_svuid && a.bsd.pbi_svgid == b.bsd.pbi_svgid;
}
static au_asid_t audit_fresh(uid_t uid) {
  auditinfo_addr_t audit = {0}; audit.ai_auid = uid; audit.ai_asid = AU_ASSIGN_ASID; audit.ai_termid.at_type = AU_IPv4;
  int result = setaudit_addr(&audit, sizeof(audit)), error = errno;
  AUDIT_DOMAIN_DIAG(!result, "audit-session-create", "errno", error);
  result = getaudit_addr(&audit, sizeof(audit)); error = errno;
  AUDIT_DOMAIN_DIAG(!result, "audit-session-read", "errno", error);
  AUDIT_DOMAIN_DIAG(audit.ai_auid == uid && audit.ai_asid > 0 && audit.ai_asid != AU_ASSIGN_ASID, "audit-session-binding", "invariant", 0);
  return audit.ai_asid;
}
static mach_port_t audit_hold(au_asid_t asid) {
  mach_port_t port = MACH_PORT_NULL;
  AUDIT_DOMAIN_DIAG(asid > 0 && asid != AU_ASSIGN_ASID, "audit-session-binding", "invariant", 0);
  int result = audit_session_port(asid, &port), error = errno;
  AUDIT_DOMAIN_DIAG(!result, "audit-session-hold", "errno", error);
  AUDIT_DOMAIN_DIAG(port != MACH_PORT_NULL, "audit-session-port", "invariant", 0); return port;
}
struct audit_domain_view { struct identity live[32]; struct proc_bsdinfo dead[32]; unsigned nl, nd; };
static struct audit_domain_view audit_census(uid_t uid, au_asid_t asid) {
  struct audit_domain_view view = {0}; pid_t pids[4096]; errno = 0;
  int size = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
  int error = errno;
  AUDIT_DOMAIN_DIAG(!error && size > 0, "audit-census-list", error ? "errno" : "status", error ? error : size);
  AUDIT_DOMAIN_DIAG(size < sizeof(pids) && size % sizeof(pid_t) == 0, "audit-census-capacity", "status", size);
  for (unsigned i = 0; i < (unsigned)size / sizeof(pid_t); i++) {
    if (!pids[i]) continue;
    AUDIT_DOMAIN_DIAG(pids[i] > 0, "audit-census-pid", "status", pids[i]);
    for (unsigned j = 0; j < i; j++) AUDIT_DOMAIN_DIAG(pids[i] != pids[j], "audit-census-duplicate", "status", pids[i]);
    struct proc_bsdinfo before, after; auditpinfo_addr_t audit = {.ap_pid = pids[i]}, again = {.ap_pid = pids[i]};
    errno = 0; int result = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &before, sizeof(before)); error = errno;
    AUDIT_DOMAIN_DIAG(result == sizeof(before), "audit-census-bsd", !result && error ? "errno" : "status", !result && error ? error : result);
    result = auditon(A_GETPINFO_ADDR, &audit, sizeof(audit)); error = errno;
    AUDIT_DOMAIN_DIAG(!result, "audit-census-audit", "errno", error);
    errno = 0; result = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &after, sizeof(after)); error = errno;
    AUDIT_DOMAIN_DIAG(result == sizeof(after), "audit-census-bsd-again", !result && error ? "errno" : "status", !result && error ? error : result);
    result = auditon(A_GETPINFO_ADDR, &again, sizeof(again)); error = errno;
    AUDIT_DOMAIN_DIAG(!result, "audit-census-audit-again", "errno", error);
    AUDIT_DOMAIN_DIAG(before.pbi_pid == after.pbi_pid && (before.pbi_status == SZOMB) == (after.pbi_status == SZOMB) &&
      before.pbi_start_tvsec == after.pbi_start_tvsec && before.pbi_start_tvusec == after.pbi_start_tvusec &&
      before.pbi_uid == after.pbi_uid && before.pbi_gid == after.pbi_gid &&
      before.pbi_ruid == after.pbi_ruid && before.pbi_rgid == after.pbi_rgid &&
      before.pbi_svuid == after.pbi_svuid && before.pbi_svgid == after.pbi_svgid &&
      audit.ap_asid == again.ap_asid && audit.ap_auid == again.ap_auid, "audit-census-binding", "invariant", 0);
    if ((!asid || audit.ap_asid != asid) && before.pbi_uid != uid) continue;
    /* A reserved UID outside its admitted session is an escape, never absence.
     * Members inside it remain visible even if their credentials have changed. */
    AUDIT_DOMAIN_DIAG(!asid || audit.ap_asid == asid, "audit-census-session", "invariant", 0);
    AUDIT_DOMAIN_DIAG(view.nl + view.nd < 32, "audit-census-capacity", "invariant", 0);
    if (before.pbi_status == SZOMB) view.dead[view.nd++] = after;
    else {
      struct identity value = AUDIT_DOMAIN_INSPECT(pids[i]); AUDIT_DOMAIN_DIAG(value.token.val[6] == (unsigned)audit.ap_asid &&
        value.token.val[0] == (unsigned)audit.ap_auid && value.bsd.pbi_start_tvsec == before.pbi_start_tvsec &&
        value.bsd.pbi_start_tvusec == before.pbi_start_tvusec, "audit-census-binding", "invariant", 0); view.live[view.nl++] = value;
    }
  }
  return view;
}
static void audit_emit_view(struct audit_domain_view view, uid_t uid, au_asid_t asid) {
  printf("{\"uid\":%u,\"asid\":%u,\"scope\":\"%s\",\"complete\":true,\"capacity\":33,\"live\":[", uid, asid, asid ? "audit-session" : "reserved-uid");
  for (unsigned i = 0; i < view.nl; i++) { if (i) putchar(','); emit(view.live[i]); }
  fputs("],\"zombies\":[", stdout);
  for (unsigned i = 0; i < view.nd; i++) { struct proc_bsdinfo *b = &view.dead[i];
    printf("%s{\"pid\":%u,\"uid\":%u,\"gid\":%u,\"ruid\":%u,\"rgid\":%u,\"svuid\":%u,\"svgid\":%u,\"startSeconds\":%llu,\"startMicroseconds\":%llu}",
      i ? "," : "", b->pbi_pid, b->pbi_uid, b->pbi_gid, b->pbi_ruid, b->pbi_rgid, b->pbi_svuid, b->pbi_svgid,
      (unsigned long long)b->pbi_start_tvsec, (unsigned long long)b->pbi_start_tvusec);
  }
  fputs("]}", stdout);
}
#endif
#endif
