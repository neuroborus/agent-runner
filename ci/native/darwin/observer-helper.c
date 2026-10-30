/* CI-only audit-pipe reader. Its inherited pipes are root custody, not logs.
 * The protected BSM decoder filters fixed synthetic fields in memory. The
 * matched SDK/libbsm decoder and event/class mapping are reviewed build inputs.
 * No global audit configuration, trail file, path cleanup or provider launch. */
#include <bsm/audit.h>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RECORD_LIMIT 65536
#define BYTE_LIMIT 8388608

static void fail_at(const char *file, unsigned line, const char *predicate, long result, int error) {
  char bytes[512];
  int length = snprintf(bytes, sizeof(bytes), "native-darwin-audit: file=%s line=%u predicate=%s result=%ld errno=%d\n",
    file, line, predicate, result, error);
  sigset_t blocked, previous, pending;
  if (length > 0 && length < (int)sizeof(bytes) && !sigemptyset(&blocked) && !sigaddset(&blocked, SIGPIPE) &&
      !sigprocmask(SIG_BLOCK, &blocked, &previous)) {
    if (!sigpending(&pending)) {
      int was_pending = sigismember(&pending, SIGPIPE);
      if (was_pending >= 0) {
        ssize_t written = write(STDERR_FILENO, bytes, (size_t)length); int write_error = errno;
        if (written < 0 && write_error == EPIPE && !was_pending) {
          /* Never unmask an undischarged diagnostic SIGPIPE before this exit. */
          if (sigpending(&pending)) _exit(126);
          int present = sigismember(&pending, SIGPIPE);
          if (present < 0) _exit(126);
          if (present) { int received; if (sigwait(&blocked, &received) || received != SIGPIPE) _exit(126); }
        }
      }
    }
    (void)sigprocmask(SIG_SETMASK, &previous, NULL);
  }
  _exit(126);
}
static long native_at(long result, const char *file, unsigned line, const char *predicate) {
  if (result < 0) fail_at(file, line, predicate, result, errno);
  return result;
}
#define native(operation) native_at((operation), __FILE__, __LINE__, #operation)
/* Invariant refusals carry no ambient errno. Wrapped ioctls retain their caller. */
#define need(ok) do { if (!(ok)) fail_at(__FILE__, __LINE__, #ok, 0, 0); } while (0)
#define call(fd, request, value) need(native(ioctl(fd, request, value)) == 0)
static void output(const void *bytes, size_t length) {
  const unsigned char *p = bytes;
  while (length) {
    ssize_t n = write(3, p, length);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) fail_at(__FILE__, __LINE__, "write(3, p, length)", n, errno);
    need(n > 0);
    p += n; length -= (size_t)n;
  }
}
static uint32_t number(const char *s) {
  char *end = NULL;
  need(s && *s && *s >= '1' && *s <= '9');
  errno = 0;
  unsigned long n = strtoul(s, &end, 10);
  need(!errno && !*end && n < UINT32_MAX);
  return (uint32_t)n;
}
static void healthy(int fd) {
  uint64_t drops = 0, truncates = 0;
  call(fd, AUDITPIPE_GET_DROPS, &drops);
  call(fd, AUDITPIPE_GET_TRUNCATES, &truncates);
  need(!drops && !truncates);
}
/* Only the command pipe is polled: buffered input must not hide owner loss. */
static void command_ready(void) {
  struct pollfd command = {0, POLLIN, 0};
  int n;
  do { n = poll(&command, 1, 0); } while (n < 0 && errno == EINTR);
  if (n < 0) fail_at(__FILE__, __LINE__, "poll(&command, 1, 0)", n, errno);
  need(!(command.revents & (POLLERR | POLLHUP | POLLNVAL)));
}

int main(int argc, char **argv) {
  /* Reviewed exact event classes, successful AND failed, for one reserved auid.
   * The session/UID and native identities are joined by the independent decoder
   * before any event can become proof. Missing event routes fail controls. */
  need((argc == 3 || argc == 4) && geteuid() == 0 && getenv("CI") &&
      !strcmp(getenv("CI"), "true") && getenv("GITHUB_ACTIONS") &&
      !strcmp(getenv("GITHUB_ACTIONS"), "true"));
  uint32_t auid = number(argv[1]), classes = number(argv[2]);
  struct stat channel;
  need(native(fstat(0, &channel)) == 0 && S_ISFIFO(channel.st_mode) &&
      native(fstat(3, &channel)) == 0 && S_ISFIFO(channel.st_mode));
  alarm(argc == 4 ? 420 : 120);
  char admission;
  /* The independent owner persists/verifies this parked root process and its
   * private pipes before acknowledging any audit effect. */
  need(native(read(0, &admission, 1)) == 1 && admission == 'A');
  int fd = native(open("/dev/auditpipe", O_RDONLY | O_NONBLOCK | O_CLOEXEC));
  /* XNU's audit open ignores O_NONBLOCK; FIONBIO enables its private bit. */
  int nonblocking = 1;
  call(fd, FIONBIO, &nonblocking);
  unsigned int low = 0, high = 0, size = 0, queue = 1024;
  call(fd, AUDITPIPE_GET_QLIMIT_MIN, &low);
  call(fd, AUDITPIPE_GET_QLIMIT_MAX, &high);
  call(fd, AUDITPIPE_GET_MAXAUDITDATA, &size);
  need(queue >= low && queue <= high && size > 0 && size <= RECORD_LIMIT);
  call(fd, AUDITPIPE_SET_QLIMIT, &queue);
  au_mask_t empty = {0, 0};
  int mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
  call(fd, AUDITPIPE_SET_PRESELECT_MODE, &mode);
  call(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &empty);
  call(fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &empty);
  struct auditpipe_ioctl_preselect selection;
  memset(&selection, 0, sizeof(selection));
  selection.aip_auid = auid;
  selection.aip_mask.am_success = classes;
  selection.aip_mask.am_failure = classes;
  call(fd, AUDITPIPE_SET_PRESELECT_AUID, &selection);
  if (argc == 4) {
    char *end; errno = 0; unsigned long outside = strtoul(argv[3], &end, 10);
    need(*argv[3] && !errno && !*end && outside <= UINT32_MAX && outside != auid);
    if (outside == AU_DEFAUDITID) {
      au_mask_t unattributed = {classes, classes};
      call(fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &unattributed);
    } else {
      selection.aip_auid = (au_id_t)outside;
      call(fd, AUDITPIPE_SET_PRESELECT_AUID, &selection);
    }
  }
  need(native(ioctl(fd, AUDITPIPE_FLUSH)) == 0);
  healthy(fd);
  /* Length zero announces ready; final UINT32_MAX announces drained EOF.
   * The owner independently verifies reader identity/selection before release. */
  uint32_t marker = 0;
  output(&marker, sizeof(marker));
  unsigned char bytes[RECORD_LIMIT];
  uint32_t total = 0, records = 0;
  int stopping = 0, barrier = 0; uint32_t sequence = 0;
  for (;;) {
    command_ready();
    need(fd >= 0 && fd < FD_SETSIZE);
    fd_set ready; FD_ZERO(&ready);
    FD_SET(fd, &ready); FD_SET(0, &ready);
    struct timeval timeout = {stopping ? 0 : 1, 0};
    int n = select(fd + 1, &ready, NULL, NULL, &timeout);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) fail_at(__FILE__, __LINE__, "select(fd + 1, &ready, NULL, NULL, &timeout)", n, errno);
    command_ready();
    if (FD_ISSET(0, &ready)) {
      char command;
      need(native(read(0, &command, 1)) == 1 && !stopping && !barrier && (command == 'S' || command == 'B'));
      if (command == 'S') stopping = 1; else barrier = 1;
    }
    healthy(fd);
    ssize_t count = read(fd, bytes, size);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0 && errno == EAGAIN) {
      unsigned int remaining = 0;
      call(fd, AUDITPIPE_GET_QLEN, &remaining);
      if (barrier && remaining == 0) {
        healthy(fd);
        struct timeval time; need(native(gettimeofday(&time, NULL)) == 0 && time.tv_sec >= 0 && (uint64_t)time.tv_sec <= UINT32_MAX && ++sequence <= 256);
        uint32_t receipt[] = {htonl(UINT32_MAX - 1), htonl(sequence), htonl((uint32_t)time.tv_sec), htonl((uint32_t)(time.tv_usec / 1000))};
        output(receipt, sizeof(receipt)); barrier = 0;
      }
      if (stopping && remaining == 0) break;
      continue;
    }
    if (count < 0) fail_at(__FILE__, __LINE__, "read(fd, bytes, size)", count, errno);
    need(count > 0 && (size_t)count <= sizeof(bytes) && ++records <= 4096 &&
        (uint64_t)total + (uint64_t)count <= BYTE_LIMIT);
    total += (uint32_t)count;
    uint32_t length = htonl((uint32_t)count);
    output(&length, sizeof(length));
    output(bytes, (size_t)count);
    memset(bytes, 0, (size_t)count);
  }
  healthy(fd);
  need(native(close(fd)) == 0); /* Only the helper's cloned pipe-local state. */
  marker = UINT32_MAX;
  output(&marker, sizeof(marker));
  total = htonl(total); records = htonl(records);
  output(&total, sizeof(total)); output(&records, sizeof(records));
  return 0;
}
