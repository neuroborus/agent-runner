/* CI-only parked exec inside the admitted private namespaces. FDs 3/4 are
 * admission channels, closed before the provider image receives authority.
 * Images, arguments, environment and mapped ABI are independently reviewed. */
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <sys/un.h>
extern char **environ;

/* A separate parked child retains the probe pipes. They are CLOEXEC and
 * never inherited by the provider. Only bounded literal data is accepted. */
static int unhex(char *out, const char *in, size_t limit) {
  size_t length = strlen(in);
  if (length % 2 || length / 2 >= limit) return -1;
  for (size_t i = 0; i < length; i += 2) {
    char pair[3] = {in[i], in[i + 1], 0};
    if (strspn(pair, "0123456789abcdef") != 2) return -1;
    out[i / 2] = (char)strtol(pair, NULL, 16);
    if (!out[i / 2]) return -1;
  }
  out[length / 2] = 0; return 0;
}
static void probes(const char *nonce) {
  /* The provider is this child's parent. CLOEXEC alone would leave the probe
   * pipes accessible through procfs or ptrace from that same-UID parent. */
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) || close(3) || close(4) || fcntl(5, F_SETFD, FD_CLOEXEC) || fcntl(6, F_SETFD, FD_CLOEXEC)) _exit(126);
  FILE *control = fdopen(5, "r"), *report = fdopen(6, "w");
  if (!control || !report) _exit(126);
  fprintf(report, "{\"phase\":\"probes\",\"nonce\":\"%s\",\"pid\":%ld}\n", nonce, (long)getpid()); fflush(report);
  char line[32768], operation[32], targetHex[8193], dataHex[16385], extra;
  char target[4097], data[8193]; unsigned sequence = 0, current;
  while (fgets(line, sizeof(line), control)) {
    if (!strchr(line, '\n') || sscanf(line, "%u %31s %8192s %16384s %c", &current, operation, targetHex, dataHex, &extra) != 4 || current != ++sequence || sequence > 4096 || unhex(target, targetHex, sizeof(target))) _exit(126);
    if (!strcmp(dataHex, "-")) data[0] = 0;
    else if (unhex(data, dataHex, sizeof(data))) _exit(126);
    errno = 0; long result = -1; int saved = 0, file = -1;
    if (!strcmp(operation, "barrier")) {
      if (strcmp(target, nonce) || data[0]) _exit(126);
      result = 0;
    } else if (!strcmp(operation, "read") || !strcmp(operation, "write")) {
      if (target[0] != '/') _exit(126);
      file = open(target, (!strcmp(operation, "write") ? O_WRONLY : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC);
      result = file; saved = errno;
      if (file >= 0) {
        if (!strcmp(operation, "write") && write(file, data, strlen(data)) != (ssize_t)strlen(data)) _exit(126);
        if (!strcmp(operation, "read")) { char buffer[8192]; if (read(file, buffer, sizeof(buffer)) < 0) _exit(126); }
        if (close(file)) _exit(126);
      }
    } else if (!strcmp(operation, "signal") || !strcmp(operation, "debug")) {
      char *end; long pid = strtol(target, &end, 10); if (*end || pid <= 0 || pid > 2147483647) _exit(126);
      result = !strcmp(operation, "signal") ? kill((pid_t)pid, 0) : syscall(SYS_ptrace, 16, pid, 0, 0); saved = errno;
      if (!strcmp(operation, "debug") && result == 0) { syscall(SYS_ptrace, 17, pid, 0, 0); _exit(126); }
    } else if (!strcmp(operation, "ipc")) {
      struct sockaddr_un address = {.sun_family = AF_UNIX};
      if (target[0] != '/' || strlen(target) >= sizeof(address.sun_path)) _exit(126);
      strcpy(address.sun_path, target); file = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (file < 0) _exit(126);
      result = connect(file, (struct sockaddr *)&address, sizeof(address)); saved = errno; close(file);
    } else if (!strcmp(operation, "network")) {
      struct sockaddr_in address = {.sin_family = AF_INET}; char host[64]; unsigned port;
      if (sscanf(target, "%63[^:]:%u%c", host, &port, &extra) != 2 || port < 1024 || port > 65535 || inet_pton(AF_INET, host, &address.sin_addr) != 1) _exit(126);
      address.sin_port = htons((unsigned short)port); file = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (file < 0) _exit(126);
      result = connect(file, (struct sockaddr *)&address, sizeof(address)); saved = errno; close(file);
    } else _exit(126);
    fprintf(report, "{\"sequence\":%u,\"pid\":%ld,\"result\":%ld,\"error\":%d}\n", sequence, (long)getpid(), result, result < 0 ? saved : 0); fflush(report);
  }
  if (ferror(control)) _exit(126);
  _exit(0);
}

int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--retire")) {
    if (geteuid() || !getenv("CI") || strcmp(getenv("CI"), "true") || !getenv("GITHUB_ACTIONS") || strcmp(getenv("GITHUB_ACTIONS"), "true")) _exit(126);
    char *end; long pid = strtol(argv[2], &end, 10); if (*end || pid <= 1 || pid > 2147483647) _exit(126);
    int held = (int)syscall(SYS_pidfd_open, pid, 0); if (held < 0) _exit(126);
    char file[128], stat[8192], boot[64]; snprintf(file, sizeof(file), "/proc/%ld/stat", pid);
    FILE *input = fopen(file, "r"); if (!input || !fgets(stat, sizeof(stat), input) || fclose(input)) _exit(126);
    input = fopen("/proc/sys/kernel/random/boot_id", "r"); if (!input || !fgets(boot, sizeof(boot), input) || fclose(input)) _exit(126);
    boot[strcspn(boot, "\n")] = 0; if (strcmp(boot, argv[4])) _exit(126);
    char *field = strrchr(stat, ')'); if (!field) _exit(126); field += 2;
    for (int i = 0; i < 19; i++) { field = strchr(field, ' '); if (!field) _exit(126); field++; }
    field[strcspn(field, " ")] = 0;
    if (strcmp(field, argv[3])) _exit(126);
    char frame[256]; int length = snprintf(frame, sizeof(frame), "{\"phase\":\"retirement-held\",\"pid\":%ld,\"targetPid\":%ld,\"startTicks\":\"%s\",\"bootId\":\"%s\"}\n", (long)getpid(), pid, argv[3], boot);
    if (length <= 0 || length >= (int)sizeof(frame) || write(4, frame, (size_t)length) != length || close(4)) _exit(126);
    struct pollfd control = {3, POLLIN, 0}; char command;
    if (poll(&control, 1, 30000) != 1 || read(3, &command, 1) != 1 || command != 'R' || close(3) || syscall(SYS_pidfd_send_signal, held, SIGKILL, NULL, 0) || close(held)) _exit(126);
    _exit(0);
  }
  if (argc == 5 && !strcmp(argv[1], "--bridge-loopback")) {
    if (!getenv("CI") || strcmp(getenv("CI"), "true") || !getenv("GITHUB_ACTIONS") || strcmp(getenv("GITHUB_ACTIONS"), "true")) _exit(126);
    if (geteuid() || strlen(argv[3]) > 4096 || strlen(argv[4]) > 4096 || strlen(argv[2]) != 32 || strspn(argv[2], "0123456789abcdef") != 32 || argv[3][0] != '/' || argv[4][0] != '/') _exit(126);
    struct stat held, current; int self = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (self < 0 || fstat(5, &held) || fstat(self, &current) || held.st_dev != current.st_dev || held.st_ino != current.st_ino || close(self)) _exit(126);
    char frame[256]; int length = snprintf(frame, sizeof(frame), "{\"phase\":\"bridge-loopback\",\"nonce\":\"%s\",\"netInode\":\"%llu\"}\n", argv[2], (unsigned long long)held.st_ino);
    if (length <= 0 || length >= (int)sizeof(frame) || write(4, frame, (size_t)length) != length) _exit(126);
    // The native owner verifies the held namespace against the admitted
    // payload before acknowledging this sole namespace-local mutation.
    struct pollfd control = {3, POLLIN, 0}; char command;
    if (poll(&control, 1, 30000) != 1 || read(3, &command, 1) != 1 || command != 'R') _exit(126);
    int network = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); struct ifreq interface = {0};
    strcpy(interface.ifr_name, "lo");
    if (network < 0 || ioctl(network, SIOCGIFFLAGS, &interface)) _exit(126);
    interface.ifr_flags |= IFF_UP;
    if (ioctl(network, SIOCSIFFLAGS, &interface) || close(network)) _exit(126);
    if (close(5)) _exit(126); /* No namespace handle reaches the bridge. */
    execve(argv[3], &argv[3], environ); _exit(126);
  }
  if (argc < 4 || argc > 68 || strlen(argv[1]) != 32 || strspn(argv[1], "0123456789abcdef") != 32 ||
      argv[2][0] != '/' || strcmp(argv[3], "--")) _exit(126);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) _exit(126);
  /* Older model-free fixture callers use only 3/4. The composed provider
   * owner always supplies the additional private probe pair. */
  if (fcntl(5, F_GETFD) >= 0 && fcntl(6, F_GETFD) >= 0) {
    pid_t child = fork(); if (child < 0) _exit(126);
    if (!child) probes(argv[1]);
    if (close(5) || close(6)) _exit(126);
  }
  if (fcntl(3, F_SETFD, FD_CLOEXEC) || fcntl(4, F_SETFD, FD_CLOEXEC)) _exit(126);
  char frame[256]; int length = snprintf(frame, sizeof(frame), "{\"nonce\":\"%s\",\"pid\":%ld}\n", argv[1], (long)getpid());
  if (length <= 0 || length >= (int)sizeof(frame) || write(4, frame, (size_t)length) != length || close(4)) _exit(126);
  struct pollfd control = {3, POLLIN, 0}; char command;
  if (poll(&control, 1, 30000) != 1 || read(3, &command, 1) != 1 || command != 'R' || close(3)) _exit(126);
  argv[3] = argv[2]; execve(argv[2], &argv[3], environ); _exit(126);
}
