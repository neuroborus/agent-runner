/* Synthetic external argv case only; never a provider or shell substitute. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  /* Loader completion is distinct from custody readiness on stdout. */
  fputs("native-darwin-phase: phase=fixture-main\n", stderr); fflush(stderr);
  if (getuid() <= 500 || geteuid() != getuid()) return 126;
  const char *custody = getenv("NATIVE_OWNERSHIP_CUSTODY");
  if (custody) {
    if (strcmp(custody, "true")) return 126;
    alarm(150);
    /* Independent custody reads the executed image before acknowledging output. */
    puts("{\"phase\":\"armed\"}"); fflush(stdout);
    char acknowledgement;
    if (read(0, &acknowledgement, 1) != 1 || acknowledgement != 'A') return 126;
  }
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
