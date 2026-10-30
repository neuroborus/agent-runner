/* Compile with the same reviewed MSVC/UCRT parser as the launch target. The
 * independent observer joins these actual UTF-16 code units to its native
 * process/image/cwd identity. Output alone is never a launch acceptance proof. */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#ifdef NATIVE_ARGV_ENTRY_PROBE
#if !defined(NATIVE_CI_EXPERIMENT) || !defined(_M_X64) || _MSC_VER != 1951
#error The experimental entry requires the selected MSVC 19.51 x64 toolchain.
#endif
/* /ENTRY names a __stdcall entry; on MSVC x64 __stdcall and __cdecl use
 * the same ABI. Delegate to the console CRT's no-argument wmain startup.
 * https://learn.microsoft.com/en-us/cpp/build/reference/entry-entry-point-symbol
 * https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
 * The CRT must initialize its cookie before entering /GS-protected code.
 * This narrow wrapper has no automatic arrays, aggregates or alloca (/GS
 * buffers), no CRT calls and no suppressed checks. Its only address-taken
 * local is a four-byte DWORD. Keep all normal startup in wmainCRTStartup.
 * https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check
 * https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/security-init-cookie */
_Static_assert(sizeof(void *) == 8 && sizeof(DWORD) == 4, "entry ABI");
extern int __cdecl wmainCRTStartup(void);
int __stdcall native_argv_entry(void) {
  DWORD written = 0;
  if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "native-argv-entry-v1\n",
      sizeof("native-argv-entry-v1\n")-1, &written, NULL) ||
      written != sizeof("native-argv-entry-v1\n")-1) ExitProcess(125);
  return wmainCRTStartup();
}
#endif
int wmain(int argc, wchar_t **argv) {
#ifdef NATIVE_ARGV_ENTRY_PROBE
  DWORD written = 0;
  if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "native-argv-wmain-v1\n",
      sizeof("native-argv-wmain-v1\n")-1, &written, NULL) ||
      written != sizeof("native-argv-wmain-v1\n")-1) ExitProcess(125);
#endif
  if (argc < 1 || argc > 65 || GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) != FILE_TYPE_PIPE) return 126;
  if (_setmode(_fileno(stdout), _O_BINARY) == -1) return 126;
  printf("{\"argvUtf16\":[");
  for (int i = 1; i < argc; i++) {
    if (i > 1) putchar(','); putchar('"');
    size_t size = wcslen(argv[i]); if (size > 4096) return 126;
    for (size_t j = 0; j < size; j++) printf("%04x", (unsigned short)argv[i][j]);
    putchar('"');
  }
  printf("]}\n"); return fflush(stdout) ? 126 : 0;
}
