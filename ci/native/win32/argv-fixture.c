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
int wmain(int argc, wchar_t **argv) {
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
