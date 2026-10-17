/* CI-only bounded Security subscription in protected System custody.
 * Native records remain in an inherited private pipe; the protected decoder
 * persists only synthetic metadata joined to held token/process/object IDs.
 * Audit policy and owned SACL setup/restoration belong to the indexed owner. */
#define WIN32_LEAN_AND_MEAN
#include "custody.h"
#include <winevt.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

#define RECORD_LIMIT 65536
#define BYTE_LIMIT 8388608
static HANDLE output;
static void fail(void) { ExitProcess(126); }
static DWORD WINAPI expire(void *unused) { (void)unused; Sleep(CUSTODY_LIFETIME_MS); ExitProcess(124); return 0; }
static void emit(const void *bytes, DWORD length) {
  const BYTE *p = bytes;
  while (length) {
    DWORD written = 0;
    if (!WriteFile(output, p, length, &written, NULL) || !written) fail();
    p += written; length -= written;
  }
}
static void close_event(EVT_HANDLE h) { if (h && !EvtClose(h)) fail(); }
static void system_identity(void) {
  HANDLE token = NULL;
  BYTE buffer[4096]; DWORD length = 0, session = 1;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) ||
      !GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &length) ||
      !IsWellKnownSid(((TOKEN_USER *)buffer)->User.Sid, WinLocalSystemSid) ||
      !ProcessIdToSessionId(GetCurrentProcessId(), &session) || session != 0 ||
      !CloseHandle(token)) fail();
}

int wmain(int argc, wchar_t **argv) {
  wchar_t ci[8], actions[8];
  if (argc != 2 || wcslen(argv[1]) > 16384 ||
      GetEnvironmentVariableW(L"CI", ci, 8) != 4 || wcscmp(ci, L"true") ||
      GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 8) != 4 || wcscmp(actions, L"true")) fail();
  /* The candidate-bound reviewed query includes loss/clear events (1101/1102)
   * and exact successful/failed object/WFP events. An unreviewed query is never
   * launch input. No channel clear, file export or global subscription change. */
  output = GetStdHandle(STD_OUTPUT_HANDLE);
  system_identity();
  HANDLE timer = CreateThread(NULL, 0, expire, NULL, 0, NULL); if (!timer || !CloseHandle(timer)) fail();
  HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  if (GetFileType(output) != FILE_TYPE_PIPE || GetFileType(input) != FILE_TYPE_PIPE) fail();
  ULONGLONG started = GetTickCount64();
  for (;;) {
    DWORD queued = 0;
    if (!PeekNamedPipe(input, NULL, 0, NULL, &queued, NULL) || GetTickCount64() - started >= CUSTODY_LIFETIME_MS) fail();
    if (queued) break;
    Sleep(10);
  }
  char admission; DWORD received = 0;
  /* Park before subscription. Creation-time custody and independent native
   * image/token/handle admission precede this private acknowledgement. */
  if (!ReadFile(input, &admission, 1, &received, NULL) || received != 1 || admission != 'A') fail();
  HANDLE available = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!available) fail();
  EVT_HANDLE bookmark = EvtCreateBookmark(NULL);
  EVT_HANDLE subscription = EvtSubscribe(NULL, available, NULL, argv[1],
      NULL, NULL, NULL, EvtSubscribeToFutureEvents | EvtSubscribeStrict);
  if (!bookmark || !subscription) fail();
  DWORD marker = 0;
  emit(&marker, sizeof(marker));
  DWORD total = 0, records = 0;
  int stopping = 0, barrierPending = 0; DWORD barriers = 0;
  for (;;) {
    if (GetTickCount64() - started >= CUSTODY_LIFETIME_MS) fail();
    DWORD queued = 0;
    if (!PeekNamedPipe(input, NULL, 0, NULL, &queued, NULL)) fail();
    if (queued) {
      char command; DWORD read = 0;
      if (stopping || barrierPending || !ReadFile(input, &command, 1, &read, NULL) || read != 1 || (command != 'S' && command != 'B')) fail();
      if (command == 'S') stopping = 1;
      else barrierPending = 1;
    }
    EVT_HANDLE events[16]; DWORD count = 0;
    if (!EvtNext(subscription, 16, events, 0, 0, &count)) {
      DWORD error = GetLastError();
      if (error != ERROR_NO_MORE_ITEMS) fail(); /* Stale bookmark, log loss, access or reader error. */
      if (barrierPending) {
        if (++barriers > 256) fail(); FILETIME time; GetSystemTimePreciseAsFileTime(&time);
        marker = MAXDWORD - 1; emit(&marker, sizeof(marker)); emit(&barriers, sizeof(barriers)); emit(&time, sizeof(time)); emit(&records, sizeof(records)); barrierPending = 0;
      }
      if (stopping) break;
      if (!ResetEvent(available)) fail();
      DWORD wait = WaitForSingleObject(available, 100);
      if (wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT) fail();
      continue;
    }
    for (DWORD i = 0; i < count; ++i) {
      DWORD bytes = 0, properties = 0;
      if (EvtRender(NULL, events[i], EvtRenderEventXml, 0, NULL, &bytes, &properties) ||
          GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0 || bytes > RECORD_LIMIT) fail();
      BYTE buffer[RECORD_LIMIT];
      if (!EvtRender(NULL, events[i], EvtRenderEventXml, sizeof(buffer), buffer, &bytes, &properties) ||
          !EvtUpdateBookmark(bookmark, events[i]) || ++records > 4096 ||
          (uint64_t)total + bytes > BYTE_LIMIT) fail();
      total += bytes;
      emit(&bytes, sizeof(bytes)); emit(buffer, bytes);
      SecureZeroMemory(buffer, bytes);
      close_event(events[i]);
    }
  }
  /* Finite checkpoint is a decoder/continuity input, never proof of process
   * retirement. The controller drains only after independent domain absence. */
  DWORD bytes = 0, properties = 0;
  if (EvtRender(NULL, bookmark, EvtRenderBookmark, 0, NULL, &bytes, &properties) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes > RECORD_LIMIT || !bytes) fail();
  BYTE checkpoint[RECORD_LIMIT];
  if (!EvtRender(NULL, bookmark, EvtRenderBookmark, sizeof(checkpoint), checkpoint, &bytes, &properties)) fail();
  marker = MAXDWORD;
  emit(&marker, sizeof(marker)); emit(&total, sizeof(total)); emit(&records, sizeof(records));
  emit(&bytes, sizeof(bytes)); emit(checkpoint, bytes);
  SecureZeroMemory(checkpoint, bytes);
  close_event(subscription); close_event(bookmark);
  if (!CloseHandle(available)) fail();
  return 0;
}
