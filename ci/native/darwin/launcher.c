/* CI-only, compiled with independently reviewed macOS SDK/framework inputs.
 * Private/deprecated interfaces are prerequisites, never portable fallbacks. */
#define __APPLE_API_PRIVATE 1
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <bsm/audit.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <mach/mach_vm.h>
#include <poll.h>
#include <pwd.h>
#include <sandbox.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern mach_port_t bootstrap_port;
#include "custody.h"
static void descriptors(void) {
  struct proc_fdinfo fds[4096];
  int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  need(size > 0 && size < (int)sizeof(fds) && size % sizeof(fds[0]) == 0);
  for (size_t i = 0; i < (size_t)size / sizeof(fds[0]); i++)
    if (fds[i].proc_fd >= 5) need(!close(fds[i].proc_fd));
  size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  need(size == 5 * (int)sizeof(fds[0]));
  unsigned mask = 0;
  for (size_t i = 0; i < (size_t)size / sizeof(fds[0]); i++) {
    need(fds[i].proc_fd >= 0 && fds[i].proc_fd < 5); mask |= 1U << fds[i].proc_fd;
  }
  need(mask == 31);
  need(!fcntl(3, F_SETFD, FD_CLOEXEC) && !fcntl(4, F_SETFD, FD_CLOEXEC));
}
static void mach_rights(void) {
  task_t self = mach_task_self(); thread_t thread = mach_thread_self();
  mach_port_t host, access; natural_t type; mach_vm_address_t address;
  /* SIP forbids clearing itk_host. Require the ordinary IKOT_HOST (XNU value 3),
   * never a privileged host port; bind this private type/export to the actual SDK. */
  need(task_get_special_port(self, TASK_HOST_PORT, &host) == KERN_SUCCESS &&
       mach_port_kobject(self, host, &type, &address) == KERN_SUCCESS && type == 3 &&
       mach_port_deallocate(self, host) == KERN_SUCCESS &&
       task_get_special_port(self, TASK_ACCESS_PORT, &access) == KERN_SUCCESS && access == MACH_PORT_NULL);
  need(task_set_special_port(self, TASK_BOOTSTRAP_PORT, MACH_PORT_NULL) == KERN_SUCCESS &&
       task_set_special_port(self, TASK_DEBUG_CONTROL_PORT, MACH_PORT_NULL) == KERN_SUCCESS &&
       task_set_special_port(self, TASK_RESOURCE_NOTIFY_PORT, MACH_PORT_NULL) == KERN_SUCCESS &&
       mach_ports_register(self, NULL, 0) == KERN_SUCCESS &&
       task_set_exception_ports(self, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE) == KERN_SUCCESS &&
       thread_set_exception_ports(thread, EXC_MASK_ALL, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE) == KERN_SUCCESS);
  bootstrap_port = MACH_PORT_NULL;
  /* mach_port_destroy itself uses MIG. Replace its cached receive-only reply
   * port, then retain this new local port so the sanitation RPCs can complete. */
  mig_dealloc_reply_port(mig_get_reply_port());
  mach_port_t reply = mig_get_reply_port(); mach_port_type_t replyType;
  need(reply != MACH_PORT_NULL && reply != self && reply != thread &&
       mach_port_type(self, reply, &replyType) == KERN_SUCCESS && replyType == MACH_PORT_TYPE_RECEIVE);
  mach_port_name_array_t names; mach_port_type_array_t types;
  mach_msg_type_number_t n, nt;
  need(mach_port_names(self, &names, &n, &types, &nt) == KERN_SUCCESS && n == nt && n <= 4096);
  for (mach_msg_type_number_t i = 0; i < n; i++)
    if (names[i] != self && names[i] != thread && names[i] != reply)
      need(mach_port_destroy(self, names[i]) == KERN_SUCCESS);
  need(mach_vm_deallocate(self, (mach_vm_address_t)names, n * sizeof(*names)) == KERN_SUCCESS &&
       mach_vm_deallocate(self, (mach_vm_address_t)types, nt * sizeof(*types)) == KERN_SUCCESS &&
       mach_port_deallocate(self, thread) == KERN_SUCCESS);
}
static char command(int fd, int milliseconds) {
  struct pollfd p = { .fd = fd, .events = POLLIN }; char value;
  need(poll(&p, 1, milliseconds) == 1 && (p.revents & POLLIN) && read(fd, &value, 1) == 1);
  return value;
}
static uint64_t wide(const char *s, uint64_t maximum) {
  char *end; errno = 0; unsigned long long n = strtoull(s, &end, 10);
  need(*s && *s != '-' && !errno && !*end && n <= maximum); return n;
}
static void verifier_barrier(void) {
  printf("{\"verifier\":"); emit(inspect(getpid())); puts("}"); fflush(stdout);
  need(command(0, 30000) == 'P');
}
static void zombie(struct proc_bsdinfo *b) {
  printf("{\"pid\":%u,\"uid\":%u,\"gid\":%u,\"ruid\":%u,\"rgid\":%u,\"svuid\":%u,\"svgid\":%u,"
    "\"startSeconds\":%llu,\"startMicroseconds\":%llu}", b->pbi_pid, b->pbi_uid, b->pbi_gid,
    b->pbi_ruid, b->pbi_rgid, b->pbi_svuid, b->pbi_svgid,
    (unsigned long long)b->pbi_start_tvsec, (unsigned long long)b->pbi_start_tvusec);
}
static void members(uid_t uid) {
  /* Fixed capacity exceeds the inherited limit. libproc returns zero both for
   * an empty list and syscall failure; cleared errno distinguishes them. */
  pid_t pids[33]; struct identity live[32]; struct proc_bsdinfo dead[32];
  unsigned nl = 0, nd = 0; errno = 0;
  int size = proc_listpids(PROC_UID_ONLY, uid, pids, sizeof(pids));
  need(!errno && size >= 0 && size < (int)sizeof(pids) && size % sizeof(pid_t) == 0);
  for (size_t i = 0; i < (size_t)size / sizeof(pid_t); i++) {
    need(pids[i] > 0); for (size_t j = 0; j < i; j++) need(pids[j] != pids[i]);
    struct proc_bsdinfo before = {0}, after = {0};
    /* arg=1 explicitly includes zombies in this private BSD-info contract. */
    need(proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &before, sizeof(before)) == (int)sizeof(before) && before.pbi_uid == uid);
    if (before.pbi_status == SZOMB) {
      need(proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 1, &after, sizeof(after)) == (int)sizeof(after) &&
        after.pbi_status == SZOMB && !memcmp(&before, &after, sizeof(before)) && nd < 32);
      dead[nd++] = after;
    } else {
      need(nl < 32); live[nl] = inspect(pids[i]); need(live[nl].token.val[1] == uid); nl++;
    }
  }
  printf("{\"uid\":%u,\"complete\":true,\"capacity\":33,\"live\":[", uid);
  for (unsigned i = 0; i < nl; i++) { if (i) putchar(','); emit(live[i]); }
  printf("],\"zombies\":[");
  for (unsigned i = 0; i < nd; i++) { if (i) putchar(','); zombie(&dead[i]); }
  puts("]}");
}
static void signal_identity(char **args) {
  audit_token_t token; for (unsigned i = 0; i < 8; i++) token.val[i] = (unsigned)wide(args[i], UINT32_MAX);
  uint64_t seconds = wide(args[8], UINT64_MAX), micros = wide(args[9], 999999);
  uid_t saved_uid = (uid_t)wide(args[10], UINT32_MAX); gid_t saved_gid = (gid_t)wide(args[11], UINT32_MAX);
  need(token.val[5] > 1 && token.val[5] <= INT_MAX && token.val[5] != (unsigned)getpid());
  struct proc_bsdinfo b; errno = 0;
  int size = proc_pidinfo((pid_t)token.val[5], PROC_PIDTBSDINFO, 1, &b, sizeof(b));
  if (!size && errno == ESRCH) { puts("{\"outcome\":\"not-found\"}"); return; }
  need(size == (int)sizeof(b));
  if (b.pbi_start_tvsec != seconds || b.pbi_start_tvusec != micros || b.pbi_svuid != saved_uid || b.pbi_svgid != saved_gid ||
      b.pbi_uid != token.val[1] || b.pbi_gid != token.val[2] || b.pbi_ruid != token.val[3] || b.pbi_rgid != token.val[4]) {
    puts("{\"outcome\":\"stale\"}"); return;
  }
  if (b.pbi_status == SZOMB) { puts("{\"outcome\":\"zombie\"}"); return; }
  struct identity current = inspect((pid_t)token.val[5]);
  if (memcmp(&current.token, &token, sizeof(token)) || current.bsd.pbi_start_tvsec != seconds ||
      current.bsd.pbi_start_tvusec != micros || current.bsd.pbi_svuid != saved_uid || current.bsd.pbi_svgid != saved_gid) {
    puts("{\"outcome\":\"stale\"}"); return;
  }
  /* The API returns errno directly. Kernel pidversion lookup reacquires a
   * proc_ident after MAC checks; numeric PID signalling is never a fallback. */
  int error = proc_signal_with_audittoken(&token, SIGKILL);
  need(!error || error == ESRCH);
  puts(error ? "{\"outcome\":\"not-found\"}" : "{\"outcome\":\"sent\"}");
}
static void claim(int fd, const char *kind, unsigned id, const char *nonce) {
  char name[64]; snprintf(name, sizeof(name), "%s-%u", kind, id);
  int file = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
  need(file >= 0 && strlen(nonce) == 32 && write(file, nonce, 32) == 32 && !fsync(file) && !close(file) && !fsync(fd));
}
static void pfctl(char **args) {
  /* The protected reader binds the complete immutable private tool closure. */
  struct stat tool, config;
  free(file(args[0], 0, 0550, 134217728, args[1], &tool));
  free(file(args[3], 0, 0400, 1048576, args[4], &config));
  need(strlen(args[5]) == 43 && !strncmp(args[5], "native-poc/", 11) &&
    strspn(args[5] + 11, "0123456789abcdef") == 32);
  bool validate = !strcmp(args[6], "validate") || !strcmp(args[6], "validate-restore");
  need(validate || !strcmp(args[6], "install") || !strcmp(args[6], "restore"));
  int ready[2], release[2]; need(!pipe(ready) && !pipe(release));
  pid_t worker = fork(); need(worker >= 0);
  if (!worker) {
    close(ready[0]); close(release[1]); struct identity identity = inspect(getpid());
    need(write(ready[1], &identity, sizeof(identity)) == (ssize_t)sizeof(identity));
    need(command(release[0], 30000) == 'R');
    /* Security.framework may create threads. Verify after fork, before exec;
     * no framework state or worker thread crosses this fork boundary. */
    signature(args[0], args[2]);
    int null = open("/dev/null", O_RDWR); need(null >= 0);
    for (int i = 0; i < 3; i++) need(dup2(null, i) == i);
    struct proc_fdinfo fds[4096];
    int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    need(size > 0 && size < (int)sizeof(fds) && size % sizeof(fds[0]) == 0);
    for (size_t i = 0; i < (size_t)size / sizeof(fds[0]); i++)
      if (fds[i].proc_fd >= 3) need(!close(fds[i].proc_fd));
    char *vector[] = {args[0], "-a", args[5], "-f", args[3], NULL, NULL};
    if (validate) {vector[3] = "-n"; vector[4] = "-f"; vector[5] = args[3];}
    char *environment[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", NULL};
    execve(args[0], vector, environment); _exit(126);
  }
  close(ready[1]); close(release[0]); struct identity identity;
  need(read(ready[0], &identity, sizeof(identity)) == (ssize_t)sizeof(identity) &&
    identity.token.val[5] == (unsigned)worker && !close(ready[0]));
  printf("{\"worker\":"); emit(identity); puts("}"); fflush(stdout);
  need(command(0, 30000) == 'R' && write(release[1], "R", 1) == 1 && !close(release[1]));
  int status; while (waitpid(worker, &status, 0) < 0) need(errno == EINTR);
  need(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  puts("{\"exitCode\":0,\"signal\":null}");
}
/* Version-two provider input is public capability data, never credentials.
 * Every key/value also belongs to the candidate-bound native launch receipt. */
static char **provider_environment(const char *nonce) {
  static const char *names[] = {"HOME", "PATH", "LANG", "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME",
    "CODEX_HOME", "NATIVE_POC_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_MODEL", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "CLAUDE_CONFIG_DIR", "DISABLE_AUTOUPDATER", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "CLAUDE_CODE_GIT_BASH_PATH"};
  const char *input = getenv("NATIVE_PROVIDER_ENV"); need(input && strlen(input) <= 32768);
  char *block = strdup(input); need(block); static char *values[sizeof(names) / sizeof(names[0]) + 1]; unsigned seen = 0, count = 0;
  char *next = block;
  while (next && *next) {
    char *line = next, *end = strchr(line, '\n'); if (end) { *end = 0; next = end + 1; } else next = NULL;
    char *equals = strchr(line, '='); need(equals && equals > line && equals[1] && strlen(line) <= 8192);
    for (char *p = line; *p; p++) need((unsigned char)*p >= 32 && (unsigned char)*p != 127);
    unsigned index; for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) if (strlen(names[index]) == (size_t)(equals - line) && !strncmp(names[index], line, (size_t)(equals - line))) break;
    need(index < sizeof(names) / sizeof(names[0]) && !(seen & (1U << index)) && count < sizeof(names) / sizeof(names[0])); seen |= 1U << index;
    if (index == 8 || index == 10) need(!strncmp(equals + 1, "native-poc-", 11) && !strcmp(equals + 12, nonce));
    values[count++] = line;
  }
  need((seen & 1) && (seen & 2) && ((seen & (1U << 8)) != 0) != ((seen & (1U << 10)) != 0));
  values[count] = NULL; return values;
}

int main(int argc, char **argv) {
  need(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 && getenv("CI") && !strcmp(getenv("CI"), "true") &&
       getenv("GITHUB_ACTIONS") && !strcmp(getenv("GITHUB_ACTIONS"), "true"));
  if (argc == 9 && !strcmp(argv[1], "--pfctl")) {
    verifier_barrier(); pfctl(&argv[2]); return 0;
  }
  if (argc == 3 && !strcmp(argv[1], "--members")) {
    uid_t uid = number(argv[2]); need(uid > 500); verifier_barrier(); members(uid); return 0;
  }
  if (argc == 14 && !strcmp(argv[1], "--signal")) {
    verifier_barrier(); signal_identity(&argv[2]); return 0;
  }
  if (argc == 3 && !strcmp(argv[1], "--custody")) {
    au_asid_t asid = (au_asid_t)wide(argv[2], UINT32_MAX - 1); need(asid > 0);
    verifier_barrier(); mach_port_t pin = MACH_PORT_NULL;
    need(!audit_session_port(asid, &pin) && pin != MACH_PORT_NULL);
    printf("{\"asid\":%u,\"held\":true}\n", asid); fflush(stdout);
    need(command(0, 60000) == 'S' && mach_port_deallocate(mach_task_self(), pin) == KERN_SUCCESS); return 0;
  }
  if (argc == 3 && !strcmp(argv[1], "--inspect")) {
    pid_t pid = (pid_t)number(argv[2]); struct identity before = inspect(pid), after;
    struct proc_vnodepathinfo cwd;
    need(proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &cwd, sizeof(cwd)) == (int)sizeof(cwd));
    after = inspect(pid);
    need(!memcmp(&before.token, &after.token, sizeof(before.token)) &&
      before.bsd.pbi_start_tvsec == after.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == after.bsd.pbi_start_tvusec &&
      S_ISDIR(cwd.pvi_cdir.vip_vi.vi_stat.vst_mode));
    struct vinfo_stat *st = &cwd.pvi_cdir.vip_vi.vi_stat;
    printf("{\"verifier\":"); emit(inspect(getpid())); printf(",\"process\":");
    emit(after); printf(",\"cwd\":{\"dev\":\"%u\",\"ino\":\"%llu\",\"uid\":%u,\"gid\":%u,\"mode\":%u}}\n",
      st->vst_dev, (unsigned long long)st->vst_ino, st->vst_uid, st->vst_gid, st->vst_mode & 07777); return 0;
  }
  /* Read-only verification runs in its own receipted root process. Library
   * worker threads and directory-service state never precede the launch fork. */
  if ((argc == 8 && !strcmp(argv[1], "--verify-inputs")) || (argc == 9 && !strcmp(argv[1], "--verify-provider-inputs"))) {
    int providerInput = argc == 9; size_t maximum = providerInput ? wide(argv[8], 536870912) : 134217728; need(maximum > 0);
    printf("{\"verifier\":"); emit(inspect(getpid())); puts("}"); fflush(stdout);
    need(command(0, 30000) == 'P');
    uid_t uid = number(argv[2]); gid_t gid = number(argv[3]); need(uid > 500 && gid > 500);
    struct passwd *pw = getpwuid(uid); struct group *gr = getgrgid(gid);
    need(pw && gr && pw->pw_gid == gid && !strcmp(pw->pw_shell, "/usr/bin/false") &&
         !strcmp(pw->pw_passwd, "*") && !strcmp(pw->pw_dir, argv[4]) && gr->gr_mem && !gr->gr_mem[0]);
    struct stat image; unsigned char *bytes = file(argv[5], gid, 0550, maximum, argv[6], &image);
    need(image.st_size >= 32 && ((uint32_t *)bytes)[0] == 0xfeedfacf &&
         ((uint32_t *)bytes)[1] == 0x01000007 && ((uint32_t *)bytes)[3] == 2);
    need(!providerInput || (size_t)image.st_size == maximum);
    free(bytes); signature(argv[5], argv[7]);
    printf("{\"sha256\":\"%s\",\"cdhash\":\"%s\"}\n", argv[6], argv[7]); return 0;
  }
  /* uid gid custody storage workspace executable exe-sha cdhash policy policy-sha nonce -- argv... */
  int provider = argc >= 13 && !strcmp(argv[12], "--provider");
  need(argc >= 13 && argc <= 77 && (provider || !strcmp(argv[12], "--")));
  const char *ownership = getenv("NATIVE_OWNERSHIP_CUSTODY");
  need(!ownership || (!provider && !strcmp(ownership, "true")));
  const char *access = getenv("NATIVE_ACCESS_CUSTODY");
  need(!access || (!provider && !strcmp(access, "true")));
  if (access) alarm(420);
  if (ownership) alarm(150); /* Fixed ownership work budget plus separate cleanup. */
  const char *imageBound = getenv("NATIVE_PROVIDER_BYTES"); need(!provider || imageBound);
  size_t imageMaximum = provider ? wide(imageBound, 536870912) : 134217728;
  need(imageMaximum > 0); char **providerEnv = provider ? provider_environment(argv[11]) : NULL;
  size_t argumentBytes = 0;
  for (int i = 13; i < argc; i++) {
    size_t length = strlen(argv[i]); need(length <= 4096); argumentBytes += length + 1;
  }
  need(argumentBytes <= 32768);
  /* Privileged setup itself waits for a protected, independently verified
   * helper receipt. No UID/GID claim or fork precedes this acknowledgement. */
  printf("{\"helper\":"); emit(inspect(getpid())); puts(",\"payload\":null}"); fflush(stdout);
  need(command(0, 30000) == 'P');
  uid_t uid = number(argv[1]); gid_t gid = number(argv[2]); need(uid > 500 && gid > 500);
  int custody = directory(argv[3], 0, 0, 0700), storage = directory(argv[4], 0, gid, 0710);
  int workspace = directory(argv[5], uid, gid, 0700); struct stat image, policyIdentity;
  unsigned char *imageBytes = file(argv[6], gid, 0550, imageMaximum, argv[7], &image);
  need(image.st_size >= 32 && ((uint32_t *)imageBytes)[0] == 0xfeedfacf &&
       ((uint32_t *)imageBytes)[1] == 0x01000007 && ((uint32_t *)imageBytes)[3] == 2);
  need(!provider || (size_t)image.st_size == imageMaximum);
  free(imageBytes);
  unsigned char *policy = file(argv[9], 0, 0400, 1048576, argv[10], &policyIdentity);
  need(!memchr(policy, 0, (size_t)policyIdentity.st_size));
  claim(custody, "uid", uid, argv[11]); claim(custody, "gid", gid, argv[11]);
  int ready[2], release[2]; need(!pipe(ready) && !pipe(release));
  /* No directory-service or Security framework call precedes this fork.
   * Reject an unexpected multithreaded launcher instead of forking it. */
  struct proc_taskinfo task;
  need(proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &task, sizeof(task)) == (int)sizeof(task) && task.pti_threadnum == 1);
  pid_t child = fork(); need(child >= 0);
  if (!child) {
    close(ready[0]); close(release[1]);
    need(!fchdir(workspace) && dup2(3, 1) == 1 && dup2(provider ? 5 : 3, 2) == 2);
    need(dup2(provider ? 4 : 3, 0) == 0);
    need(dup2(ready[1], 3) == 3 && dup2(release[0], 4) == 4); descriptors();
    auditinfo_addr_t audit = {0}; audit.ai_auid = uid; audit.ai_asid = AU_ASSIGN_ASID;
    audit.ai_termid.at_type = AU_IPv4;
    struct rlimit limit = { .rlim_cur = 32, .rlim_max = 32 }, observed;
    need(!setrlimit(RLIMIT_NPROC, &limit));
    need(!setaudit_addr(&audit, sizeof(audit)) && !getaudit_addr(&audit, sizeof(audit)) &&
         audit.ai_asid != AU_DEFAUDITSID && audit.ai_asid != AU_ASSIGN_ASID);
    need(!setgroups(0, NULL) && !setgid(gid) && !setuid(uid));
    gid_t only; need(getgroups(1, &only) == 1 && only == gid);
    need(!getrlimit(RLIMIT_NPROC, &observed) && observed.rlim_cur == 32 && observed.rlim_max == 32);
    char *error = NULL; need(!sandbox_init((const char *)policy, 0, &error));
    mach_rights(); descriptors(); struct identity identity = inspect(getpid());
    need(identity.bsd.pbi_uid == uid && identity.bsd.pbi_ruid == uid && identity.bsd.pbi_svuid == uid &&
         identity.bsd.pbi_gid == gid && identity.bsd.pbi_rgid == gid && identity.bsd.pbi_svgid == gid &&
         identity.token.val[0] == uid && identity.token.val[6] == (unsigned)audit.ai_asid);
    need(write(3, &identity, sizeof(identity)) == sizeof(identity) && !close(3));
    need(command(4, 30000) == 'R' && !close(4));
    struct stat named; need(!lstat(argv[6], &named) && named.st_dev == image.st_dev &&
      named.st_ino == image.st_ino && named.st_mode == image.st_mode && named.st_uid == 0 &&
      named.st_gid == gid && named.st_nlink == 1 && named.st_size == image.st_size &&
      named.st_mtimespec.tv_sec == image.st_mtimespec.tv_sec && named.st_mtimespec.tv_nsec == image.st_mtimespec.tv_nsec &&
      named.st_ctimespec.tv_sec == image.st_ctimespec.tv_sec && named.st_ctimespec.tv_nsec == image.st_ctimespec.tv_nsec);
    char home[PATH_MAX + 6]; int length = snprintf(home, sizeof(home), "HOME=%s", argv[5]);
    need(length > 0 && (size_t)length < sizeof(home));
    char *env[] = { home, "PATH=/nonexistent", "LANG=en_US.UTF-8", "TMPDIR=.",
      "CI=true", "GITHUB_ACTIONS=true", ownership ? "NATIVE_OWNERSHIP_CUSTODY=true" : access ? "NATIVE_ACCESS_CUSTODY=true" : NULL, NULL };
    argv[12] = argv[6]; execve(argv[6], &argv[12], provider ? providerEnv : env); _exit(126);
  }
  if (provider) { close(4); close(5); }
  free(policy); close(ready[1]); close(release[0]); close(3); close(workspace); close(storage); close(custody);
  struct pollfd waitReady = { .fd = ready[0], .events = POLLIN }; struct identity parked;
  need(poll(&waitReady, 1, 10000) == 1 && read(ready[0], &parked, sizeof(parked)) == sizeof(parked) &&
       parked.token.val[5] == (unsigned)child && !close(ready[0]));
  /* Acquire after fork: only root custody gets the audit-session send right. */
  mach_port_t auditPin = MACH_PORT_NULL;
  need(!audit_session_port((au_asid_t)parked.token.val[6], &auditPin) && auditPin != MACH_PORT_NULL);
  struct identity live = inspect(child);
  need(!memcmp(&live.token, &parked.token, sizeof(live.token)) &&
       live.bsd.pbi_start_tvsec == parked.bsd.pbi_start_tvsec && live.bsd.pbi_start_tvusec == parked.bsd.pbi_start_tvusec);
  printf("{\"helper\":"); emit(inspect(getpid())); printf(",\"payload\":"); emit(live); puts("}"); fflush(stdout);
  char value = command(0, 30000); need(value == 'R' && write(release[1], &value, 1) == 1 && !close(release[1]));
  int status; while (waitpid(child, &status, 0) < 0) need(errno == EINTR);
  if (ownership) {
    printf("{\"exitCode\":");
    if (WIFEXITED(status)) printf("%d", WEXITSTATUS(status)); else fputs("null", stdout);
    printf(",\"signal\":%s}\n", WIFSIGNALED(status) ? "\"signal\"" : "null"); fflush(stdout);
  }
  /* Direct-child exit is not domain retirement. Retain this session reference
   * until the protected retirement owner stops this exact native identity,
   * after admitting separate recovered audit custody. */
  for (;;) pause();
}
