/* Synthetic external argv case only; never a provider or shell substitute. */
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (getuid() <= 500 || geteuid() != getuid()) return 126;
  putchar('[');
  for (int i = 1; i < argc; i++) {
    if (i > 1) putchar(',');
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)argv[i]; *p; p++) {
      if (*p < 32) printf("\\u%04x", *p);
      else { if (*p == '"' || *p == '\\') putchar('\\'); putchar(*p); }
    }
    putchar('"');
  }
  puts("]"); return ferror(stdout) ? 126 : 0;
}
