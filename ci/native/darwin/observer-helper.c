/* CI-only audit-pipe reader. Its inherited pipes are root custody, not logs.
 * The protected BSM decoder filters fixed synthetic fields in memory. The
 * matched SDK/libbsm decoder and event/class mapping are reviewed build inputs.
 * No global audit configuration, trail file, path cleanup or provider launch. */
#include <bsm/audit.h>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RECORD_LIMIT 65536
#define BYTE_LIMIT 8388608

static void fail(void) { _exit(126); }
static void output(const void *bytes, size_t length) {
  const unsigned char *p = bytes;
  while (length) {
    ssize_t n = write(3, p, length);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) fail();
    p += n; length -= (size_t)n;
  }
}
static uint32_t number(const char *s) {
  char *end = NULL;
  if (!s || !*s || *s < '1' || *s > '9') fail();
  errno = 0;
  unsigned long n = strtoul(s, &end, 10);
  if (errno || *end || n >= UINT32_MAX) fail();
  return (uint32_t)n;
}
static void call(int fd, unsigned long request, void *value) {
  if (ioctl(fd, request, value) != 0) fail();
}
static void healthy(int fd) {
  uint64_t drops = 0, truncates = 0;
  call(fd, AUDITPIPE_GET_DROPS, &drops);
  call(fd, AUDITPIPE_GET_TRUNCATES, &truncates);
  if (drops || truncates) fail();
}

int main(int argc, char **argv) {
  /* Reviewed exact event classes, successful AND failed, for one reserved auid.
   * The session/UID and native identities are joined by the independent decoder
   * before any event can become proof. Missing event routes fail controls. */
  if (argc != 3 || geteuid() != 0 || !getenv("CI") ||
      strcmp(getenv("CI"), "true") || !getenv("GITHUB_ACTIONS") ||
      strcmp(getenv("GITHUB_ACTIONS"), "true")) fail();
  uint32_t auid = number(argv[1]), classes = number(argv[2]);
  struct stat channel;
  if (fstat(0, &channel) || !S_ISFIFO(channel.st_mode) ||
      fstat(3, &channel) || !S_ISFIFO(channel.st_mode)) fail();
  alarm(120);
  char admission;
  /* The independent owner persists/verifies this parked root process and its
   * private pipes before acknowledging any audit effect. */
  if (read(0, &admission, 1) != 1 || admission != 'A') fail();
  int fd = open("/dev/auditpipe", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) fail();
  unsigned int low = 0, high = 0, size = 0, queue = 1024;
  call(fd, AUDITPIPE_GET_QLIMIT_MIN, &low);
  call(fd, AUDITPIPE_GET_QLIMIT_MAX, &high);
  call(fd, AUDITPIPE_GET_MAXAUDITDATA, &size);
  if (queue < low || queue > high || size == 0 || size > RECORD_LIMIT) fail();
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
  if (ioctl(fd, AUDITPIPE_FLUSH) != 0) fail();
  healthy(fd);
  /* Length zero announces ready; final UINT32_MAX announces drained EOF.
   * The owner independently verifies reader identity/selection before release. */
  uint32_t marker = 0;
  output(&marker, sizeof(marker));
  unsigned char bytes[RECORD_LIMIT];
  uint32_t total = 0, records = 0;
  int stopping = 0;
  for (;;) {
    struct pollfd pollers[2] = {{fd, POLLIN, 0}, {0, POLLIN, 0}};
    int n = poll(pollers, 2, stopping ? 0 : 1000);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 || (pollers[0].revents & (POLLERR | POLLHUP | POLLNVAL)) ||
        (pollers[1].revents & (POLLERR | POLLHUP | POLLNVAL))) fail();
    if (pollers[1].revents & POLLIN) {
      char command;
      if (read(0, &command, 1) != 1 || command != 'S' || stopping) fail();
      stopping = 1;
    }
    healthy(fd);
    ssize_t count = read(fd, bytes, size);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0 && errno == EAGAIN) {
      unsigned int remaining = 0;
      call(fd, AUDITPIPE_GET_QLEN, &remaining);
      if (stopping && remaining == 0) break;
      continue;
    }
    if (count <= 0 || (size_t)count > sizeof(bytes) || ++records > 4096 ||
        (uint64_t)total + (uint64_t)count > BYTE_LIMIT) fail();
    total += (uint32_t)count;
    uint32_t length = htonl((uint32_t)count);
    output(&length, sizeof(length));
    output(bytes, (size_t)count);
    memset(bytes, 0, (size_t)count);
  }
  healthy(fd);
  if (close(fd) != 0) fail(); /* Only the helper's cloned pipe-local state. */
  marker = UINT32_MAX;
  output(&marker, sizeof(marker));
  total = htonl(total); records = htonl(records);
  output(&total, sizeof(total)); output(&records, sizeof(records));
  return 0;
}
