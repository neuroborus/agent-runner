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
extern char **environ;
int main(int argc, char **argv) {
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
  if (fcntl(3, F_SETFD, FD_CLOEXEC) || fcntl(4, F_SETFD, FD_CLOEXEC)) _exit(126);
  char frame[256]; int length = snprintf(frame, sizeof(frame), "{\"nonce\":\"%s\",\"pid\":%ld}\n", argv[1], (long)getpid());
  if (length <= 0 || length >= (int)sizeof(frame) || write(4, frame, (size_t)length) != length || close(4)) _exit(126);
  struct pollfd control = {3, POLLIN, 0}; char command;
  if (poll(&control, 1, 30000) != 1 || read(3, &command, 1) != 1 || command != 'R' || close(3)) _exit(126);
  argv[3] = argv[2]; execve(argv[2], &argv[3], environ); _exit(126);
}
