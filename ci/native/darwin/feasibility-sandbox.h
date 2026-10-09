/* Optional experiment SPI. Source references and native limits: ../README.md. */
#ifndef NATIVE_FEASIBILITY_SANDBOX_H
#define NATIVE_FEASIBILITY_SANDBOX_H

#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* Apple's declaration uses enum sandbox_filter_type. The retained release
 * source corroborates its C int ABI and the const data export on Darwin.
 * Use that ABI representation without redeclaring an SDK-private enum or
 * inventing the value of SANDBOX_CHECK_NO_REPORT. */
_Static_assert(sizeof(int) == 4, "The Darwin sandbox SPI requires a 32-bit C int.");
typedef int (*feasibility_sandbox_check_fn)(pid_t, const char *, int, ...);

struct feasibility_sandbox_binding {
  feasibility_sandbox_check_fn check;
  const int *no_report;
};

static inline struct feasibility_sandbox_binding feasibility_sandbox_load(void) {
  struct feasibility_sandbox_binding binding = {0};
  /* Both are published as libSystem exports. Clear and inspect each lookup's
   * error separately; neither an error string nor an address is public proof. */
  dlerror();
  binding.check = (feasibility_sandbox_check_fn)dlsym(RTLD_DEFAULT, "sandbox_check");
  if (dlerror()) binding.check = NULL;
  dlerror();
  binding.no_report = (const int *)dlsym(RTLD_DEFAULT, "SANDBOX_CHECK_NO_REPORT");
  if (dlerror()) binding.no_report = NULL;
  return binding;
}

static inline bool feasibility_sandbox_available(struct feasibility_sandbox_binding binding) {
  return binding.check != NULL && binding.no_report != NULL;
}

static inline int feasibility_sandbox_active(struct feasibility_sandbox_binding binding, pid_t pid) {
  if (!feasibility_sandbox_available(binding)) {
    errno = ENOSYS;
    return -1;
  }
  /* NULL asks about installed sandbox state and takes no variadic argument.
   * Read the exported object; its address is not the filter value. */
  return binding.check(pid, NULL, *binding.no_report);
}

#endif
