#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One bounded trusted session. No payload runs here and no descriptor leaves
 * it. The host owner must expose neither /anchor nor this process's procfs to
 * payloads. All parent mutation, including permitted faults, is serialized by
 * that owner; flock also excludes another helper on the same anchor. */
struct identity {
  uint64_t inode, mount, seconds;
  unsigned int major, minor, nanoseconds;
};
static int anchor = -1, parent = -1, leaf = -1, temporary = -1;
static struct identity anchor_id, parent_id, leaf_id, temporary_id;
static const char temporary_name[] = ".pending";
static char nonce[37];
static const char *control = NULL, *operation_name = NULL;
static int positive_control = 0;
static void denied(const char *reason);

static void expire(int signal_number) {
  (void)signal_number;
  /* Namespace PID 1 ignores default signal actions; exit without cleanup. */
  _exit(124);
}

static void fail(void) {
  printf("{\"type\":\"file\",\"nonce\":\"%s\",\"phase\":\"retained\","
         "\"anchor\":null,\"allocation\":null,\"leaf\":null,\"temporary\":null}\n", nonce);
  fflush(stdout);
  /* Never guess which pathname to remove after interruption or uncertainty. */
  _exit(1);
}

static int confined_open(int base, const char *name, int flags, mode_t mode) {
  struct open_how how = {
    .flags = (uint64_t)(flags | O_CLOEXEC | O_NOFOLLOW),
    .mode = mode,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
               RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
  };
  int descriptor = (int)syscall(SYS_openat2, base, name, &how, sizeof(how));
  if (descriptor < 0) {
    if (errno == ELOOP) denied("symlink");
    if (errno == EXDEV) denied("mount");
    fail();
  }
  return descriptor;
}

static struct identity identify(int base, const char *name, int directory) {
  struct statx value;
  unsigned int mask = STATX_TYPE | STATX_MODE | STATX_INO | STATX_NLINK |
                      STATX_UID | STATX_MNT_ID | STATX_BTIME;
  int flags = AT_SYMLINK_NOFOLLOW | (name[0] == '\0' ? AT_EMPTY_PATH : 0);
  if (syscall(SYS_statx, base, name, flags, mask, &value) < 0 ||
      (value.stx_mask & mask) != mask || value.stx_uid != getuid() ||
      value.stx_btime.tv_sec <= 0 || value.stx_btime.tv_nsec >= 1000000000U ||
      (directory ? !S_ISDIR(value.stx_mode) ||
                     (value.stx_mode & 07777) != 0700
                 : !S_ISREG(value.stx_mode) ||
                     (value.stx_mode & 07777) != 0600)) fail();
  if (!directory && value.stx_nlink != 1) denied("hard-link");
  return (struct identity){ value.stx_ino, value.stx_mnt_id,
                           (uint64_t)value.stx_btime.tv_sec,
                           value.stx_dev_major, value.stx_dev_minor,
                           value.stx_btime.tv_nsec };
}

static int same(struct identity a, struct identity b) {
  return a.inode == b.inode && a.mount == b.mount &&
         a.major == b.major && a.minor == b.minor &&
         a.seconds == b.seconds && a.nanoseconds == b.nanoseconds;
}

static void named(int base, const char *name, int held,
                  struct identity expected, int directory) {
  int current = confined_open(base, name,
                              O_RDONLY | (directory ? O_DIRECTORY : 0), 0);
  if (!same(identify(held, "", directory), expected) ||
      !same(identify(current, "", directory), expected) ||
      !same(identify(base, name, directory), expected)) denied("identity");
  if (close(current) != 0) fail();
}

static void check_parent(void) {
  if (!same(identify(AT_FDCWD, "/anchor", 1), anchor_id) ||
      !same(identify(anchor, "", 1), anchor_id)) denied("identity");
  if (parent >= 0) named(anchor, "allocation", parent, parent_id, 1);
}

static void identity_text(char text[96], struct identity id) {
  if (snprintf(text, 96, "%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%u",
               id.major, id.minor, id.inode, id.mount, id.seconds, id.nanoseconds) >= 96) fail();
}

static int matches(const char *text, struct identity id) {
  char expected[96];
  identity_text(expected, id);
  return strcmp(text, expected) == 0;
}

/* Bind-mount IDs change in a fresh namespace. Recovery compares the recorded
 * object identity, then openat2 confines it to the newly held anchor mount. */
static int recovery_matches(const char *text, struct identity id) {
  unsigned int major, minor, nanoseconds;
  uint64_t inode, mount, seconds;
  char extra;
  if (sscanf(text, "%u:%u:%" SCNu64 ":%" SCNu64 ":%" SCNu64 ":%u%c",
             &major, &minor, &inode, &mount, &seconds, &nanoseconds, &extra) != 6) fail();
  id.mount = mount;
  return matches(text, id);
}

static void report_record(const char *phase, const char *reason) {
  char allocation[100] = "null", value[100] = "null", pending[100] = "null", root[96], text[96];
  identity_text(root, anchor_id);
  if (parent >= 0) {
    identity_text(text, parent_id);
    snprintf(allocation, sizeof(allocation), "\"%s\"", text);
  }
  if (leaf >= 0) {
    identity_text(text, leaf_id);
    snprintf(value, sizeof(value), "\"%s\"", text);
  }
  if (temporary >= 0) {
    identity_text(text, temporary_id);
    snprintf(pending, sizeof(pending), "\"%s\"", text);
  }
  if (printf("{\"type\":\"file\",\"nonce\":\"%s\",\"phase\":\"%s\","
             "\"anchor\":\"%s\",\"allocation\":%s,\"leaf\":%s,\"temporary\":%s",
             nonce, phase, root, allocation, value, pending) < 0) fail();
  if (reason && printf(",\"operation\":\"%s\",\"reason\":\"%s\",\"positiveControl\":%s",
                       operation_name, reason, positive_control ? "true" : "false") < 0) fail();
  if (printf("}\n") < 0 || fflush(stdout) != 0) fail();
}

static void report(const char *phase) { report_record(phase, NULL); }

/* Only a reached native guard after a permitted control can establish denial.
 * Malformed commands, setup errors, crashes and alarms retain generic failure. */
static void denied(const char *reason) {
  if (!control || !operation_name || !positive_control ||
      (strcmp(operation_name, "replace") && strcmp(operation_name, "cleanup") &&
       strcmp(operation_name, "check"))) fail();
  report_record("denied", reason);
  _exit(39); /* The protected controller must independently observe this exit. */
}

static void line(char *buffer, size_t size) {
  if (!fgets(buffer, (int)size, stdin)) fail();
  size_t length = strlen(buffer);
  if (length == 0 || buffer[length - 1] != '\n') fail();
  buffer[length - 1] = '\0';
}

static void barrier(const char *phase) {
  char acknowledgement[32];
  report(phase);
  line(acknowledgement, sizeof(acknowledgement));
  if (strcmp(acknowledgement, "continue - - - -") != 0) fail();
  check_parent();
}

static void remove_temporary(void) {
  named(parent, temporary_name, temporary, temporary_id, 0);
  if (unlinkat(parent, temporary_name, 0) != 0 || fsync(parent) != 0 ||
      close(temporary) != 0) fail();
  temporary = -1;
}

static int digit(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  fail();
  return 0;
}

static void publish(const char *hex, int replace, const char *expected_leaf) {
  unsigned char bytes[4096];
  size_t length = strcmp(hex, "-") == 0 ? 0 : strlen(hex);
  if (length > 8192 || length % 2 != 0) fail();
  for (size_t index = 0; index < length; index += 2)
    bytes[index / 2] = (unsigned char)(digit(hex[index]) * 16 + digit(hex[index + 1]));
  if (replace) {
    if (leaf < 0 || !matches(expected_leaf, leaf_id)) fail();
  } else if (strcmp(expected_leaf, "-") != 0) fail();
  if (leaf >= 0) named(parent, "value", leaf, leaf_id, 0);
  if (temporary >= 0) fail();
  temporary = confined_open(parent, temporary_name, O_RDWR | O_CREAT | O_EXCL, 0600);
  temporary_id = identify(temporary, "", 0);
  size_t written = 0;
  while (written < length / 2) {
    ssize_t count = write(temporary, bytes + written, length / 2 - written);
    if (count <= 0) fail();
    written += (size_t)count;
  }
  if (fsync(temporary) != 0 || fsync(parent) != 0) fail();
  positive_control = 1;
  barrier("prepared"); /* Complete temporary bytes, before namespace mutation. */
  named(parent, temporary_name, temporary, temporary_id, 0);
  if (leaf >= 0) named(parent, "value", leaf, leaf_id, 0);
  if (syscall(SYS_renameat2, parent, temporary_name, parent, "value",
              replace ? 0 : RENAME_NOREPLACE) != 0) {
    if (replace || errno != EEXIST) fail();
    if (leaf < 0) fail();
    named(parent, "value", leaf, leaf_id, 0);
    /* A conflicting name supplies no identity authority. Preserve it. */
    remove_temporary();
    report("exists");
    return;
  }
  if (leaf >= 0 && close(leaf) != 0) fail();
  leaf = temporary;
  leaf_id = temporary_id;
  temporary = -1;
  barrier("published"); /* Rename completed; directory durability still pending. */
  named(parent, "value", leaf, leaf_id, 0);
  if (fsync(parent) != 0) fail();
  report("complete");
}

static void check_alias(void) {
  char name[96];
  if (!control || (strcmp(control, "magic-link") && strcmp(control, "mount"))) fail();
  if (strcmp(control, "magic-link") == 0) {
    /* Numeric PID avoids /proc/self's ordinary symlink: the final fd entry
     * must be the magic link rejected by the confined positive control. */
    if (snprintf(name, sizeof(name), "/proc/%ld/fd/%d", (long)getpid(), leaf) >= (int)sizeof(name)) fail();
  } else strcpy(name, "/anchor/crossing/value");
  barrier("checking");
  /* Establish a permitted control on this same private proc/mount object. */
  int permitted = open(name, O_RDONLY | O_CLOEXEC);
  if (permitted < 0) fail();
  struct identity observed = identify(permitted, "", 0);
  if (strcmp(control, "magic-link") == 0 && !same(observed, leaf_id)) fail();
  if (close(permitted) != 0) fail();
  positive_control = 1;
  struct open_how how = { .flags = O_RDONLY | O_CLOEXEC,
                         .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
                           (strcmp(control, "mount") == 0 ? RESOLVE_BENEATH | RESOLVE_NO_XDEV : 0) };
  int fd = (int)syscall(SYS_openat2, strcmp(control, "mount") == 0 ? anchor : AT_FDCWD,
                       strcmp(control, "mount") == 0 ? "crossing/value" : name,
                       &how, sizeof(how));
  int error = errno;
  if (fd >= 0) { close(fd); fail(); }
  if (strcmp(control, "mount") == 0 && error == EXDEV) denied("mount");
  if (strcmp(control, "magic-link") == 0 && error == ELOOP) denied("magic-link");
  fail();
}

static void absent(const char *name) {
  struct stat value;
  if (fstatat(parent, name, &value, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) fail();
}

static int recover_leaf(const char *name, const char *expected, struct identity *id) {
  if (strcmp(expected, "-") == 0) {
    absent(name);
    return -1;
  }
  int descriptor = confined_open(parent, name, O_RDONLY, 0);
  *id = identify(descriptor, "", 0);
  if (!recovery_matches(expected, *id)) fail();
  named(parent, name, descriptor, *id, 0);
  return descriptor;
}

int main(int argc, char **argv) {
  if ((argc != 4 && argc != 5) || strcmp(argv[1], "--session") != 0 || strlen(argv[2]) != 36)
    return 1;
  if (argc == 5) {
    const char *allowed[] = { "ancestor", "leaf", "symlink", "magic-link", "mount",
                             "hard-link", "cleanup", "cleanup-leaf" };
    for (unsigned int index = 0; index < sizeof(allowed) / sizeof(allowed[0]); index++)
      if (strcmp(argv[4], allowed[index]) == 0) control = allowed[index];
    if (!control) return 1;
  }
  for (size_t index = 0; index < 36; index++) {
    char value = argv[2][index];
    int hyphen = index == 8 || index == 13 || index == 18 || index == 23;
    if (hyphen ? value != '-' : !((value >= '0' && value <= '9') ||
                                 (value >= 'a' && value <= 'f'))) return 1;
  }
  memcpy(nonce, argv[2], sizeof(nonce));
  umask(077);
  struct sigaction timeout = { .sa_handler = expire };
  if (sigemptyset(&timeout.sa_mask) != 0 || sigaction(SIGALRM, &timeout, NULL) != 0) fail();
  alarm(25); /* Expiry or a lost controller never authorizes cleanup. */
  if (syscall(SYS_close_range, 3U, ~0U, 0) != 0) fail();
  struct open_how how = { .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
                         .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS };
  anchor = (int)syscall(SYS_openat2, AT_FDCWD, "/anchor", &how, sizeof(how));
  if (anchor < 0 || flock(anchor, LOCK_EX | LOCK_NB) != 0) fail();
  anchor_id = identify(anchor, "", 1);
  if (strcmp(argv[3], "-") != 0 && !recovery_matches(argv[3], anchor_id)) fail();
  check_parent();
  report("ready");
  for (unsigned int operation = 0; operation < 32; operation++) {
    char input[8544], command[16], allocation[96], expected_leaf[96], pending[96], hex[8193], extra;
    line(input, sizeof(input));
    if (sscanf(input, "%15s %95s %95s %95s %8192s %c", command, allocation,
               expected_leaf, pending, hex, &extra) != 5) fail();
    operation_name = command;
    positive_control = 0;
    check_parent();
    if (strcmp(command, "allocate") == 0) {
      if (parent >= 0 || strcmp(allocation, "-") || strcmp(expected_leaf, "-") ||
          strcmp(pending, "-") || strcmp(hex, "-") || mkdirat(anchor, "allocation", 0700) != 0) fail();
      parent = confined_open(anchor, "allocation", O_RDONLY | O_DIRECTORY, 0);
      parent_id = identify(parent, "", 1);
      if (fsync(parent) != 0 || fsync(anchor) != 0) fail();
      report("allocated");
    } else if (strcmp(command, "recover") == 0) {
      if (parent >= 0 || strcmp(hex, "-")) fail();
      parent = confined_open(anchor, "allocation", O_RDONLY | O_DIRECTORY, 0);
      parent_id = identify(parent, "", 1);
      if (!recovery_matches(allocation, parent_id)) fail();
      leaf = recover_leaf("value", expected_leaf, &leaf_id);
      temporary = recover_leaf(temporary_name, pending, &temporary_id);
      report("recovered");
    } else if (strcmp(command, "finish") == 0) {
      if (strcmp(allocation, "-") || strcmp(expected_leaf, "-") || strcmp(pending, "-") || strcmp(hex, "-")) fail();
      report("finished");
      return 0;
    } else {
      if (parent < 0 || !matches(allocation, parent_id)) fail();
      if (temporary < 0 ? strcmp(pending, "-") != 0 : !matches(pending, temporary_id)) fail();
      if (strcmp(command, "publish") == 0 || strcmp(command, "replace") == 0)
        publish(hex, strcmp(command, "replace") == 0, expected_leaf);
      else if (strcmp(command, "inspect") == 0 || strcmp(command, "cleanup") == 0 || strcmp(command, "check") == 0) {
        if (strcmp(hex, "-") || (leaf < 0 ? strcmp(expected_leaf, "-") != 0
                                          : !matches(expected_leaf, leaf_id))) fail();
        if (leaf >= 0) named(parent, "value", leaf, leaf_id, 0);
        else absent("value");
        if (temporary >= 0) named(parent, temporary_name, temporary, temporary_id, 0);
        else absent(temporary_name);
        if (strcmp(command, "check") == 0) check_alias();
        else if (strcmp(command, "inspect") == 0) report("inspected");
        else {
          if (control) { positive_control = 1; barrier("removing"); }
          if (temporary >= 0) remove_temporary();
          /* This check/unlink is safe only under exclusive parent authority:
           * no payload grants, inherited fds, procfs or concurrent helper. */
          if (leaf >= 0) {
            named(parent, "value", leaf, leaf_id, 0);
            if (unlinkat(parent, "value", 0) != 0 || fsync(parent) != 0 || close(leaf) != 0) fail();
            leaf = -1;
          }
          named(anchor, "allocation", parent, parent_id, 1);
          if (unlinkat(anchor, "allocation", AT_REMOVEDIR) != 0 ||
              fsync(anchor) != 0 || close(parent) != 0) fail();
          parent = -1;
          report("removed");
        }
      } else fail();
    }
  }
  fail();
  return 1;
}
