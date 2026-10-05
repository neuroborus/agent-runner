/* Shared protected bytes, signatures and audit-token identity reads. */
#ifndef NATIVE_DARWIN_CUSTODY_H
#define NATIVE_DARWIN_CUSTODY_H
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
static unsigned char *file(const char *name, gid_t gid, mode_t mode,
                           size_t limit, const char *pin, struct stat *identity) {
  char canonical[PATH_MAX], hash[65]; unsigned char sum[CC_SHA256_DIGEST_LENGTH];
  need(realpath(name, canonical) && !strcmp(name, canonical));
  int fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  need(fd >= 0 && !fstat(fd, identity) && S_ISREG(identity->st_mode) &&
       identity->st_uid == 0 && identity->st_gid == gid && identity->st_nlink == 1 &&
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
       after.st_size == identity->st_size && after.st_mtimespec.tv_sec == identity->st_mtimespec.tv_sec &&
       after.st_mtimespec.tv_nsec == identity->st_mtimespec.tv_nsec &&
       after.st_ctimespec.tv_sec == identity->st_ctimespec.tv_sec &&
       after.st_ctimespec.tv_nsec == identity->st_ctimespec.tv_nsec &&
       named.st_dev == identity->st_dev && named.st_ino == identity->st_ino &&
       named.st_mode == identity->st_mode && named.st_uid == 0 && named.st_gid == gid && named.st_nlink == 1);
  need(CC_SHA256(bytes, (CC_LONG)size, sum) != NULL); hex(sum, sizeof(sum), hash);
  need(!strcmp(hash, pin) && !close(fd)); return bytes;
}
static void signature(const char *name, const char *pin) {
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
