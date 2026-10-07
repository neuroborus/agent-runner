/* Matched Darwin SDK/libbsm input, sealed with custody-reader.c. All raw
 * selectors, ACLs, audit tokens and rule bytes remain on private root pipes. */
#include <bsm/libbsm.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <net/route.h>
#include <sandbox.h>
#include <spawn.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

static int reservation_fd = -1;
static struct stat reservation_stat;
static struct entry *reservation_entry;
static void reservation_guard(void) {
  struct stat current;
  need(reservation_fd >= 0 && reservation_entry && !fstat(reservation_fd, &current));
  same_stat(reservation_stat, current); stable(reservation_entry);
  need(!flock(reservation_fd, LOCK_EX | LOCK_NB));
}
static bool subjects_absent(void) {
  pid_t pids[4096]; errno = 0;
  int size = proc_listpids(PROC_UID_ONLY, subject_uid, pids, sizeof(pids));
  need(!errno && size >= 0 && size < sizeof(pids) && size % sizeof(pid_t) == 0);
  for (unsigned i = 0; i < (unsigned)size / sizeof(pid_t); i++) if (pids[i]) return false;
  return true;
}
static void no_subjects(void) { need(subjects_absent()); }
static void reserve(struct entry *entry, const char *nonce) {
  need(reservation_fd < 0 && strlen(nonce) == 32 && strspn(nonce, "0123456789abcdef") == 32);
  /* One reusable pinned inode, never replaced to allocate a new job nonce. */
  const char expected[] = "native-poc-pf-lease-v1\n";
  need(!strcmp(entry->path, "/private/var/run/native-poc/pf-lease") && !strcmp(entry->kind, "data"));
  need(S_ISREG(entry->stat.st_mode) && entry->stat.st_uid == 0 && entry->stat.st_gid == 0 && entry->stat.st_size == sizeof(expected) - 1 && (entry->stat.st_mode & 07777) == 0400);
  char bytes[sizeof(expected) - 1]; read_at(entry->fd, bytes, sizeof(bytes), 0); need(!memcmp(bytes, expected, sizeof(bytes)));
  if (!case_mode || !case_recovery) no_subjects(); reservation_fd = dup(entry->fd); need(reservation_fd >= 0 && !flock(reservation_fd, LOCK_EX | LOCK_NB));
  reservation_stat = entry->stat; reservation_entry = entry; reservation_guard(); identity(entry);
}
static void reservation_read(void) {
  reservation_guard(); fputs("{\"held\":true}", stdout);
}
static void reservation_close(void) {
  reservation_guard(); no_subjects();
  int pf = open("/dev/pf", O_RDONLY | O_CLOEXEC); need(pf >= 0); const unsigned actions[] = {PF_SCRUB, PF_PASS, PF_NAT, PF_BINAT, PF_RDR};
  for (unsigned i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) { struct pfioc_rule rule = {0}; rule.rule.action = actions[i]; need(!ioctl(pf, DIOCGETRULES, &rule) && rule.nr == 0); }
  need(!close(pf));
  reservation_guard(); need(!close(reservation_fd)); reservation_fd = -1; reservation_entry = NULL; fputs("null", stdout);
}
static void file_capabilities(int fd) {
  struct attrlist attrs = {.bitmapcount = ATTR_BIT_MAP_COUNT, .volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES};
  struct { uint32_t length; vol_capabilities_attr_t value; } caps;
  need(!fgetattrlist(fd, &attrs, &caps, sizeof(caps), 0) && caps.length == sizeof(caps));
  uint32_t required = VOL_CAP_FMT_CASE_SENSITIVE | VOL_CAP_FMT_CASE_PRESERVING | VOL_CAP_FMT_PERSISTENTOBJECTIDS | VOL_CAP_FMT_HARDLINKS;
  need((caps.value.valid[VOL_CAPABILITIES_FORMAT] & required) == required && (caps.value.capabilities[VOL_CAPABILITIES_FORMAT] & required) == required);
}

static void effective_authority(pid_t pid, struct entry *entry) {
  file_capabilities(entry->fd);
  struct identity before = inspect(pid);
  need(before.token.val[0] == subject_uid && before.token.val[1] == subject_uid && before.token.val[2] == subject_gid);
  int active = sandbox_check(pid, NULL, SANDBOX_CHECK_NO_REPORT);
  need(active == 1); /* Query errors cannot stand in for acknowledged installation. */
  const char *operations[] = {"file-read-data", "file-write-data", "file-write-create", "file-write-unlink", "process-exec"};
  char path_hex[PATH_MAX * 2]; hex((unsigned char *)entry->path, strlen(entry->path), path_hex);
  printf("{\"subject\":"); emit(before); printf(",\"sandboxed\":true,\"path\":\"%s\",\"object\":", path_hex); identity(entry);
  acl_t acl = acl_get_fd_np(entry->fd, ACL_TYPE_EXTENDED); need(acl);
  ssize_t length = 0; char *acl_bytes = acl_to_text(acl, &length); need(acl_bytes && length >= 0 && length <= 65536);
  unsigned char sum[32]; char hash[65]; need(CC_SHA256(acl_bytes, (CC_LONG)length, sum)); hex(sum, 32, hash);
  need(!acl_free(acl_bytes) && !acl_free(acl)); printf(",\"aclSha256\":\"%s\",\"decisions\":[", hash);
  for (unsigned i = 0; i < 5; i++) {
    int result = sandbox_check(pid, operations[i], SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, entry->path);
    need(result == 0 || result == 1); printf("%s%d", i ? "," : "", result);
  }
  struct identity after = inspect(pid);
  need(!memcmp(&before.token, &after.token, sizeof(before.token)) && before.bsd.pbi_start_tvsec == after.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == after.bsd.pbi_start_tvusec);
  stable(entry); fputs("]}", stdout);
}
static void effective_socket(pid_t pid, int descriptor) {
  struct identity before = inspect(pid); struct socket_fdinfo socket;
  need(proc_pidfdinfo(pid, descriptor, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) == sizeof(socket));
  need((socket.psi.soi_family == AF_INET || socket.psi.soi_family == AF_INET6) && (socket.psi.soi_protocol == IPPROTO_TCP || socket.psi.soi_protocol == IPPROTO_UDP) && !(socket.psi.soi_options & (SO_REUSEADDR | SO_REUSEPORT)));
  struct in_sockinfo *in = socket.psi.soi_protocol == IPPROTO_TCP ? &socket.psi.soi_proto.pri_tcp.tcpsi_ini : &socket.psi.soi_proto.pri_in;
  char address[INET6_ADDRSTRLEN]; const void *local = socket.psi.soi_family == AF_INET ? (const void *)&in->insi_laddr.ina_46.i46a_addr4 : (const void *)&in->insi_laddr.ina_6;
  need(inet_ntop(socket.psi.soi_family, local, address, sizeof(address)) && !strcmp(address, socket.psi.soi_family == AF_INET ? "127.0.0.1" : "::1") && ntohs((uint16_t)in->insi_lport) >= 1024);
  struct identity after = inspect(pid); need(!memcmp(&before.token, &after.token, sizeof(before.token)) && before.bsd.pbi_start_tvsec == after.bsd.pbi_start_tvsec && before.bsd.pbi_start_tvusec == after.bsd.pbi_start_tvusec);
  need(socket.psi.soi_so != 0);
  printf("{\"subject\":"); emit(before); printf(",\"descriptor\":%d,\"kernelId\":\"%llx\",\"family\":\"%s\",\"protocol\":\"%s\",\"address\":\"%s\",\"port\":%u,\"exclusive\":true}", descriptor, (unsigned long long)socket.psi.soi_so, socket.psi.soi_family == AF_INET ? "inet" : "inet6", socket.psi.soi_protocol == IPPROTO_TCP ? "tcp" : "udp", address, ntohs((uint16_t)in->insi_lport));
}
static void effective_ipc(unsigned type, int id) {
  struct ipc_perm authority = {0}; uint64_t created = 0, size = 0;
  if (type == 1) { struct msqid_ds value = {0}; need(!msgctl(id, IPC_STAT, &value)); authority = value.msg_perm; created = value.msg_ctime; size = value.msg_qbytes;
  } else if (type == 2) { struct semid_ds value = {0}; union semun argument = {.buf = &value}; need(!semctl(id, 0, IPC_STAT, argument)); authority = value.sem_perm; created = value.sem_ctime; size = value.sem_nsems;
  } else { need(type == 3); struct shmid_ds value = {0}; need(!shmctl(id, IPC_STAT, &value)); authority = value.shm_perm; created = value.shm_ctime; size = value.shm_segsz; }
  need(authority.cuid == 0 && authority.cgid == 0 && created > 0 && size > 0 && size <= 8388608);
  unsigned char bytes[32]; char sum[65]; need(CC_SHA256(&authority, sizeof(authority), bytes)); hex(bytes, sizeof(bytes), sum);
  printf("{\"type\":%u,\"id\":%d,\"created\":\"%llu\",\"size\":%llu,\"authoritySha256\":\"%s\"}", type, id, (unsigned long long)created, (unsigned long long)size, sum);
}

/* Read relative to a held root. No symlink, hard link, magic path or inferred
 * object identity. Mutable bytes must be unchanged through each read window. */
static int relative_file(int root, const char *relative) {
  need(*relative && *relative != '/' && strlen(relative) < PATH_MAX);
  char copy[PATH_MAX]; strcpy(copy, relative); int fd = dup(root); need(fd >= 0);
  char *next, *part = strtok_r(copy, "/", &next);
  while (part) {
    need(strcmp(part, ".") && strcmp(part, "..")); char *following = strtok_r(NULL, "/", &next);
    int child = openat(fd, part, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (following ? O_DIRECTORY : 0));
    need(child >= 0 && !close(fd)); fd = child; part = following;
  }
  return fd;
}
static void barrier_at(int root, const char *relative, bool contents) {
  int fd = relative_file(root, relative); struct stat before, after;
  need(!fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_size >= 0 && before.st_size <= 536870912 &&
    (before.st_uid == 0 || before.st_uid == subject_uid) && !(before.st_mode & 022));
  file_capabilities(fd);
  struct entry object = {.fd = fd, .stat = before};
  char sum[65]; sha_range(fd, 0, (uint64_t)before.st_size, sum);
  fputs("{\"object\":", stdout); identity(&object);
  printf(",\"sha256\":\"%s\"", sum);
  if (contents) {
    need(before.st_size <= 65536); unsigned char bytes[65536]; char encoded[131073];
    read_at(fd, bytes, (size_t)before.st_size, 0); hex(bytes, (size_t)before.st_size, encoded);
    if (!before.st_size) encoded[0] = 0; printf(",\"hex\":\"%s\"", encoded);
  }
  need(!fstat(fd, &after)); same_stat(before, after);
  int named = relative_file(root, relative); need(!fstat(named, &after)); same_stat(before, after);
  need(!close(named) && !close(fd)); putchar('}');
}
static void file_barrier(struct entry *root, const char *relative) {
  need(S_ISDIR(root->stat.st_mode)); barrier_at(root->fd, relative, true); stable(root);
}
static unsigned tree_count, tree_files;
static void tree_at(int root, const char *prefix, unsigned depth) {
  need(depth < 16); int fd = *prefix ? relative_file(root, prefix) : dup(root); need(fd >= 0);
  struct stat before, after; need(!fstat(fd, &before)); DIR *directory = fdopendir(fd); need(directory);
  struct dirent *entry;
  for (;;) {
    errno = 0; entry = readdir(directory); if (!entry) { need(!errno); break; }
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
    need(++tree_count <= 256); char name[PATH_MAX], encoded[PATH_MAX * 2];
    int length = snprintf(name, sizeof(name), "%s%s%s", prefix, *prefix ? "/" : "", entry->d_name);
    need(length > 0 && length <= 256); struct stat st; need(!fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW));
    if (S_ISDIR(st.st_mode)) { tree_at(root, name, depth + 1); continue; }
    if (case_mode && S_ISSOCK(st.st_mode) && owned_access_socket(name, &st)) continue;
    need(S_ISREG(st.st_mode)); hex((unsigned char *)name, (size_t)length, encoded);
    printf("%s{\"name\":\"%s\",\"file\":", tree_files++ ? "," : "", encoded);
    barrier_at(root, name, false); putchar('}');
  }
  need(!fstat(fd, &after)); same_stat(before, after); need(!closedir(directory));
}
static void file_tree(struct entry *root) {
  need(S_ISDIR(root->stat.st_mode)); tree_count = tree_files = 0; putchar('['); tree_at(root->fd, "", 0); putchar(']'); stable(root);
}

/* libbsm establishes token boundaries. Event/class names are read from the
 * installed, reviewed SDK mapping; they are never guessed from XNU references. */
static uint32_t bsm_u32(const unsigned char *bytes) {
  uint32_t value; memcpy(&value, bytes, sizeof(value)); return ntohl(value);
}
static uint64_t bsm_u64(const unsigned char *bytes) {
  return ((uint64_t)bsm_u32(bytes) << 32) | bsm_u32(bytes + 4);
}
static void bsm_record(const char *encoded) {
  need(AUT_ATTR32 == 0x3e && AUT_ATTR64 == 0x73);
  size_t size = strlen(encoded) / 2; need(size >= 18 && size <= 65536 && strlen(encoded) == size * 2);
  unsigned char bytes[65536]; for (size_t i = 0; i < size; i++) bytes[i] = digit(encoded[i * 2]) * 16 + digit(encoded[i * 2 + 1]);
  size_t offset = 0; unsigned header = 0, subject = 0, returned = 0, trailer = 0;
  printf("{\"tokens\":["); unsigned count = 0;
  while (offset < size) {
    tokenstr_t token; memset(&token, 0, sizeof(token));
    need(++count <= 256 && !au_fetch_tok(&token, bytes + offset, (int)(size - offset)) && token.len > 0 && (size_t)token.len <= size - offset);
    const unsigned char *raw = bytes + offset;
    if (token.id == AUT_HEADER32 || token.id == AUT_HEADER64 || token.id == AUT_HEADER32_EX || token.id == AUT_HEADER64_EX) {
      /* The common prefix and trailing timestamps have the same SDK-defined
       * network layout, including extended terminal-address headers. */
      bool wide = token.id == AUT_HEADER64 || token.id == AUT_HEADER64_EX;
      size_t times = wide ? 16 : 8;
      need(offset == 0 && ++header == 1 && (size_t)token.len >= 10 + times && bsm_u32(raw + 1) == size);
      uint16_t event_id; memcpy(&event_id, raw + 6, sizeof(event_id)); event_id = ntohs(event_id);
      const unsigned char *time = raw + token.len - times;
      uint64_t seconds = wide ? bsm_u64(time) : bsm_u32(time), milliseconds = wide ? bsm_u64(time + 8) : bsm_u32(time + 4);
      need(seconds <= UINT32_MAX && milliseconds < 1000);
      au_event_ent_t *event = getauevnum(event_id); need(event && event->ae_name && strlen(event->ae_name) < 256 && event->ae_class);
      char name[513]; hex((unsigned char *)event->ae_name, strlen(event->ae_name), name);
      printf("{\"kind\":\"header\",\"version\":%u,\"event\":%u,\"name\":\"%s\",\"classes\":%u,\"seconds\":%llu,\"milliseconds\":%llu}", raw[5], event_id, name, event->ae_class, (unsigned long long)seconds, (unsigned long long)milliseconds);
    } else if (token.id == AUT_SUBJECT32 || token.id == AUT_SUBJECT64 || token.id == AUT_SUBJECT32_EX || token.id == AUT_SUBJECT64_EX) {
      /* Subject variants share the seven 32-bit identity fields. libbsm has
       * independently bounded the remaining terminal-address representation. */
      need(header && !trailer && ++subject == 1 && token.len >= 29);
      printf(",{\"kind\":\"subject\",\"pid\":%u,\"auid\":%u,\"asid\":%u,\"uid\":%u,\"gid\":%u}", bsm_u32(raw + 21), bsm_u32(raw + 1), bsm_u32(raw + 25), bsm_u32(raw + 5), bsm_u32(raw + 9));
    } else if (token.id == AUT_RETURN32 || token.id == AUT_RETURN64) {
      need(header && !trailer && ++returned == 1);
      /* BSM status numbers are portable audit codes, not Darwin errno values. */
      int native_error; unsigned char status = token.id == AUT_RETURN32 ? token.tt.ret32.status : token.tt.ret64.err;
      need(!au_bsm_to_errno(status, &native_error) && native_error >= 0 && native_error <= 255);
      printf(",{\"kind\":\"return\",\"error\":%d,\"result\":%lld}", native_error,
        token.id == AUT_RETURN32 ? (long long)(int32_t)token.tt.ret32.ret : (long long)token.tt.ret64.val);
    } else if (token.id == AUT_TRAILER) {
      need(++trailer == 1 && offset + token.len == size && token.tt.trail.count == size && token.tt.trail.magic == AUT_TRAILER_MAGIC);
      fputs(",{\"kind\":\"trailer\"}", stdout);
    } else {
      /* Fixed metadata is decoded only by an independently approved route's
       * exact token layout. Arguments/text never become selectors. */
      need(header && !trailer);
      char raw[131073]; hex(bytes + offset, (size_t)token.len, raw);
      printf(",{\"kind\":\"metadata\",\"type\":%u,\"hex\":\"%s\"}", token.id, raw);
    }
    offset += (size_t)token.len;
  }
  need(header == 1 && subject == 1 && returned == 1 && trailer == 1); fputs("]}", stdout); memset(bytes, 0, size);
}

/* Kernel graph inventory, including every ruleset and interface. Opaque rule
 * bytes are protected ABI evidence; semantic projections select the supported
 * closed subset. Unrecognized options cannot disappear from the rule digest. */
static unsigned pf_anchors, pf_rules;
static unsigned root_tickets[PF_RULESET_MAX], root_counts[PF_RULESET_MAX];
static unsigned case_tickets[PF_RULESET_MAX], case_counts[PF_RULESET_MAX];
static bool pf_observed;
static uint64_t pf_enable_token;
static pid_t pf_command(struct entry *tool, char **args, bool enabling) {
  int output[2]; need(!pipe(output)); int status; pid_t child; posix_spawn_file_actions_t files; posix_spawnattr_t attributes;
  need(!posix_spawn_file_actions_init(&files) && !posix_spawnattr_init(&attributes) && !posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) &&
    !posix_spawn_file_actions_addopen(&files, 0, "/dev/null", O_RDWR, 0) && !posix_spawn_file_actions_adddup2(&files, output[1], 1) && !posix_spawn_file_actions_adddup2(&files, output[1], 2) &&
    !posix_spawn_file_actions_addclose(&files, output[0]) && !posix_spawn_file_actions_addclose(&files, output[1]));
  char *env[] = {"CI=true", "GITHUB_ACTIONS=true", "PATH=/nonexistent", NULL};
  need(!posix_spawn(&child, tool->path, &files, &attributes, args, env) && !posix_spawn_file_actions_destroy(&files) && !posix_spawnattr_destroy(&attributes) && !close(output[1]));
  char bytes[32769]; size_t used = 0;
  for (;;) { need(used < sizeof(bytes) - 1); ssize_t size = read(output[0], bytes + used, sizeof(bytes) - 1 - used);
    if (size < 0 && errno == EINTR) continue; need(size >= 0); if (!size) break; used += (size_t)size; }
  bytes[used] = 0; need(!memchr(bytes, 0, used) && !close(output[0]));
  while (waitpid(child, &status, 0) < 0) need(errno == EINTR); need(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  if (enabling) {
    need(!pf_enable_token); char *next; unsigned tokens = 0;
    for (char *line = strtok_r(bytes, "\n", &next); line; line = strtok_r(NULL, "\n", &next)) if (!strncmp(line, "Token : ", 8)) {
      char *end; errno = 0; unsigned long long token = strtoull(line + 8, &end, 10);
      need(++tokens == 1 && line[8] >= '1' && line[8] <= '9' && !errno && !*end && token); pf_enable_token = token;
    }
    need(tokens == 1);
  }
  memset(bytes, 0, sizeof(bytes)); stable(tool); return child;
}
static void pf_graph(int fd, const char *anchor, unsigned depth) {
  need(depth < 8 && ++pf_anchors <= 64 && strlen(anchor) < MAXPATHLEN);
  printf("%s{\"anchor\":\"%s\",\"rules\":[", pf_anchors == 1 ? "" : ",", anchor);
  unsigned emitted = 0;
  for (unsigned set = 0; set < PF_RULESET_MAX; set++) {
    struct pfioc_rule query = {0}; strlcpy(query.anchor, anchor, sizeof(query.anchor)); query.rule.action = set;
    /* DIOCGETRULES selects action, not the ruleset ordinal. */
    const unsigned actions[] = {PF_SCRUB, PF_PASS, PF_NAT, PF_BINAT, PF_RDR}; need(set < sizeof(actions) / sizeof(actions[0])); query.rule.action = actions[set];
    need(!ioctl(fd, DIOCGETRULES, &query)); unsigned total = query.nr, ticket = query.ticket; need(total <= 4096);
    if (!*anchor) { root_tickets[set] = ticket; root_counts[set] = total; }
    for (unsigned i = 0; i < total; i++) {
      need(++pf_rules <= 64); query.nr = i; query.ticket = ticket; query.rule.action = actions[set]; need(!ioctl(fd, DIOCGETRULE, &query));
      need(query.rule.rpool.list.tqh_first == NULL && query.rule.rpool.cur == NULL && query.rule.src.addr.type == PF_ADDR_ADDRMASK && query.rule.dst.addr.type == PF_ADDR_ADDRMASK);
      /* Exclude only kernel custody/counters, never authority, from ABI pins. */
      memset(&query.rule.entries, 0, sizeof(query.rule.entries)); memset(query.rule.skip, 0, sizeof(query.rule.skip)); query.rule.kif = NULL; query.rule.anchor = NULL; query.rule.overload_tbl = NULL;
      query.rule.evaluations = query.rule.states_cur = query.rule.states_tot = query.rule.src_nodes = query.rule.nr = 0;
      memset(query.rule.packets, 0, sizeof(query.rule.packets)); memset(query.rule.bytes, 0, sizeof(query.rule.bytes));
      memset(&query.rule.rpool.list, 0, sizeof(query.rule.rpool.list)); query.rule.rpool.cur = NULL;
      struct pf_rule *r = &query.rule; char opaque[sizeof(*r) * 2 + 1]; hex((unsigned char *)r, sizeof(*r), opaque);
      need(strnlen(query.anchor_call, sizeof(query.anchor_call)) < sizeof(query.anchor_call) && strspn(query.anchor_call, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_/-*") == strlen(query.anchor_call));
      printf("%s{\"set\":%u,\"action\":%u,\"quick\":%s,\"state\":%u,\"call\":\"%s\",\"raw\":\"%s\"}", emitted++ ? "," : "", set, r->action, r->quick ? "true" : "false", r->keep_state, query.anchor_call, opaque);
    }
    query.rule.action = actions[set]; need(!ioctl(fd, DIOCGETRULES, &query) && query.nr == total && query.ticket == ticket);
  }
  fputs("]}", stdout); struct pfioc_ruleset children = {0}; strlcpy(children.path, anchor, sizeof(children.path));
  need(!ioctl(fd, DIOCGETRULESETS, &children)); unsigned total = children.nr; need(total <= 64);
  for (unsigned i = 0; i < total; i++) {
    children.nr = i; need(!ioctl(fd, DIOCGETRULESET, &children));
    need(*children.name && strspn(children.name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == strlen(children.name));
    char name[MAXPATHLEN]; int size = snprintf(name, sizeof(name), "%s%s%s", anchor, *anchor ? "/" : "", children.name); need(size > 0 && size < sizeof(name)); pf_graph(fd, name, depth + 1);
  }
}
static void pf_read(void) {
  int fd = open("/dev/pf", O_RDONLY | O_CLOEXEC); need(fd >= 0); struct pf_status before, after;
  need(!ioctl(fd, DIOCGETSTATUS, &before)); pf_anchors = pf_rules = 0;
  printf("{\"active\":%s,\"states\":%u,\"graph\":[", before.running ? "true" : "false", before.states); pf_graph(fd, "", 0);
  struct pfi_kif interfaces[128]; struct pfioc_iface query = {0}; query.pfiio_esize = sizeof(interfaces[0]); query.pfiio_size = 128; query.pfiio_buffer = interfaces;
  need(!ioctl(fd, DIOCGETIFACES, &query) && query.pfiio_size > 0 && query.pfiio_size < 128); fputs("],\"interfaces\":[", stdout);
  for (int i = 0; i < query.pfiio_size; i++) {
    need(strnlen(interfaces[i].pfik_name, IFNAMSIZ) < IFNAMSIZ && strspn(interfaces[i].pfik_name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == strlen(interfaces[i].pfik_name));
    printf("%s{\"name\":\"%s\",\"skip\":%s}", i ? "," : "", interfaces[i].pfik_name, interfaces[i].pfik_flags & PFI_IFLAG_SKIP ? "true" : "false");
  }
  int mib[] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0}; unsigned char routes[65536]; size_t size = sizeof(routes);
  need(!sysctl(mib, 6, routes, &size, NULL, 0) && size > 0 && size <= sizeof(routes));
  unsigned char sum[32]; char route_hash[65]; need(CC_SHA256(routes, (CC_LONG)size, sum)); hex(sum, 32, route_hash);
  if (case_mode && count > 12) {
    const unsigned actions[] = {PF_SCRUB, PF_PASS, PF_NAT, PF_BINAT, PF_RDR};
    for (unsigned set = 0; set < PF_RULESET_MAX; set++) {
      need(set < sizeof(actions) / sizeof(actions[0])); struct pfioc_rule current = {0};
      snprintf(current.anchor, sizeof(current.anchor), "native-poc/%.32s", case_context); current.rule.action = actions[set];
      need(!ioctl(fd, DIOCGETRULES, &current)); case_tickets[set] = current.ticket; case_counts[set] = current.nr;
    }
  }
  need(!ioctl(fd, DIOCGETSTATUS, &after) && before.running == after.running && before.states == after.states && !close(fd)); pf_observed = true; printf("],\"routesSha256\":\"%s\"}", route_hash);
}
static void pf_write(struct entry *tool, struct entry *configuration, const char *cdhash, const char *operation) {
  reservation_guard(); need(!strcmp(tool->kind, "helper") && (tool->stat.st_mode & 07777) == 0550 && !strcmp(configuration->kind, "data"));
  bool installing = !strcmp(operation, "install"); bool skip = !strcmp(operation, "restore-skip"); need(installing || skip || !strcmp(operation, "restore"));
  const char *expected = installing ? "anchor \"native-poc/*\" all quick\n" : "\n";
  need(configuration->stat.st_size == strlen(expected)); char bytes[64]; read_at(configuration->fd, bytes, strlen(expected), 0); need(!memcmp(bytes, expected, strlen(expected)));
  signature(tool->path, cdhash); no_subjects(); need(pf_observed);
  int check = open("/dev/pf", O_RDONLY | O_CLOEXEC); struct pf_status current; need(check >= 0 && !ioctl(check, DIOCGETSTATUS, &current) && (installing || current.running) && !current.states);
  const unsigned actions[] = {PF_SCRUB, PF_PASS, PF_NAT, PF_BINAT, PF_RDR};
  for (unsigned set = 0; set < PF_RULESET_MAX; set++) { need(set < sizeof(actions) / sizeof(actions[0])); struct pfioc_rule query = {0}; query.rule.action = actions[set];
    need(!ioctl(check, DIOCGETRULES, &query) && query.ticket == root_tickets[set] && query.nr == root_counts[set] && query.nr == (set == 1 && !installing ? 1 : 0)); }
  need(!close(check));
  if (installing && !current.running) { char *enable[] = {tool->path, "-E", NULL}; pf_command(tool, enable, true); }
  char *args[] = {tool->path, "-f", configuration->path, NULL}; pid_t child = pf_command(tool, args, false); stable(configuration);
  int pf = open("/dev/pf", O_RDWR | O_CLOEXEC); need(pf >= 0); struct pfioc_iface loopback = {0};
  strlcpy(loopback.pfiio_name, "lo0", sizeof(loopback.pfiio_name)); loopback.pfiio_flags = PFI_IFLAG_SKIP;
  need(!ioctl(pf, skip ? DIOCSETIFFLAG : DIOCCLRIFFLAG, &loopback) && !close(pf));
  if (!installing && pf_enable_token) { char token[32]; snprintf(token, sizeof(token), "%llu", (unsigned long long)pf_enable_token); char *release[] = {tool->path, "-X", token, NULL}; pf_command(tool, release, false); pf_enable_token = 0; }
  reservation_guard(); printf("{\"pid\":%d,\"settled\":true}", child);
}
