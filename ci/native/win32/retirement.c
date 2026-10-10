/* Separate privileged CI recovery helper. Its Job/process handles are supplied
 * through a protected explicit handle list after independent held-object
 * comparison. A name or numeric PID never supplies termination authority.
 * Build/sign only with reviewed SDK, WTS, parser and loader inputs. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "bcrypt.lib")

static HANDLE job, control;
static BOOL authorized;
static ULONGLONG started;
static const wchar_t *nonce;
static PSID accountSid, restrictingSid;
static HANDLE processes[256];
static unsigned processCount;
static void need(BOOL ok) {
  if (!ok) {
    if (authorized && job) TerminateJobObject(job, 126);
    ExitProcess(126); /* Accounts, ACLs, filters, transport and storage remain reserved. */
  }
}
static void bounded(void) { need(GetTickCount64() - started < 30000); }
static DWORD WINAPI deadline(void *unused) {
  (void)unused;
  ULONGLONG elapsed = GetTickCount64() - started;
  if (elapsed < 30000) Sleep((DWORD)(30000 - elapsed));
  ExitProcess(124); /* Kernel handle closure is not a retirement attestation. */
  return 0;
}
static char acknowledgement(void) {
  char value; DWORD size;
  need(ReadFile(control, &value, 1, &size, NULL) && size == 1);
  bounded(); return value;
}
static void ack(char expected) { need(acknowledgement() == expected); }
static void *token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
  DWORD size = 0; GetTokenInformation(token, kind, NULL, 0, &size);
  need(GetLastError() == ERROR_INSUFFICIENT_BUFFER && size && size <= 65536);
  void *value = calloc(1, size); need(value && GetTokenInformation(token, kind, value, size, &size)); return value;
}
static ULONGLONG creation(HANDLE process) {
  FILETIME created, exited, kernel, user;
  need(GetProcessTimes(process, &created, &exited, &kernel, &user));
  ULARGE_INTEGER time; time.LowPart = created.dwLowDateTime; time.HighPart = created.dwHighDateTime; return time.QuadPart;
}
static void principal(HANDLE process, PSID expected) {
  HANDLE token; need(OpenProcessToken(process, TOKEN_QUERY, &token));
  TOKEN_USER *user = token_info(token, TokenUser); DWORD *session = token_info(token, TokenSessionId);
  need(EqualSid(user->User.Sid, expected) && *session == 0);
  if (accountSid && EqualSid(expected, accountSid)) {
    TOKEN_GROUPS *restricted = token_info(token, TokenRestrictedSids);
    TOKEN_PRIVILEGES *privileges = token_info(token, TokenPrivileges);
    TOKEN_MANDATORY_LABEL *label = token_info(token, TokenIntegrityLevel);
    BYTE low[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(low);
    need(CreateWellKnownSid(WinLowLabelSid, NULL, low, &size) && IsTokenRestricted(token) &&
      restricted->GroupCount == 1 && EqualSid(restricted->Groups[0].Sid, restrictingSid) &&
      privileges->PrivilegeCount == 0 && EqualSid(label->Label.Sid, low));
    free(restricted); free(privileges); free(label);
  }
  free(user); free(session); CloseHandle(token);
}
static void identity(HANDLE process) {
  HANDLE token; need(OpenProcessToken(process, TOKEN_QUERY, &token));
  TOKEN_USER *user = token_info(token, TokenUser); wchar_t *sid;
  need(ConvertSidToStringSidW(user->User.Sid, &sid));
  printf("{\"pid\":%lu,\"creationTime\":\"%llu\",\"sessionId\":0,\"userSid\":\"%ls\"}",
    GetProcessId(process), creation(process), sid);
  LocalFree(sid); free(user); CloseHandle(token);
}
static void system_dacl(HANDLE handle, SE_OBJECT_TYPE type) {
  PSID owner; PACL dacl; PSECURITY_DESCRIPTOR sd = NULL; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
  need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) &&
    GetSecurityInfo(handle, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS && EqualSid(owner, system) && dacl && dacl->AceCount == 1 &&
    GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED));
  ACCESS_ALLOWED_ACE *ace;
  need(GetAce(dacl, 0, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
    !(ace->Header.AceFlags & INHERITED_ACE) && EqualSid((PSID)&ace->SidStart, system)); LocalFree(sd);
}
static void receipt(const wchar_t *path, const wchar_t *pin) {
  HANDLE file = CreateFileW(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  need(file != INVALID_HANDLE_VALUE); system_dacl(file, SE_FILE_OBJECT);
  FILE_ATTRIBUTE_TAG_INFO tag; BY_HANDLE_FILE_INFORMATION info; LARGE_INTEGER length;
  wchar_t canonical[8192]; DWORD size = GetFinalPathNameByHandleW(file, canonical, 8192, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  need(size > 4 && size < 8192 && !wcsncmp(canonical, L"\\\\?\\", 4) && !wcscmp(canonical + 4, path) &&
    GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) &&
    !(tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
    GetFileInformationByHandle(file, &info) && info.nNumberOfLinks == 1 &&
    GetFileSizeEx(file, &length) && length.QuadPart > 0 && length.QuadPart <= 1048576 && wcslen(pin) == 64);
  BCRYPT_ALG_HANDLE algorithm; BCRYPT_HASH_HANDLE hash;
  need(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
    BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) == 0);
  BYTE bytes[8192], sum[32]; DWORD read; ULONGLONG total = 0;
  do { bounded(); need(ReadFile(file, bytes, sizeof(bytes), &read, NULL)); total += read;
    need(total <= 1048576 && BCryptHashData(hash, bytes, read, 0) == 0); } while (read);
  need(total == (ULONGLONG)length.QuadPart && BCryptFinishHash(hash, sum, 32, 0) == 0);
  wchar_t actual[65]; for (unsigned i = 0; i < 32; i++) swprintf_s(actual + i * 2, 65 - i * 2, L"%02x", sum[i]);
  need(!wcscmp(actual, pin)); BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
  /* Keep the immutable receipt open until exit: no write/delete sharing. */
}
static void add_process(HANDLE process) {
  principal(process, accountSid); ULONGLONG time = creation(process); DWORD pid = GetProcessId(process);
  need(SetHandleInformation(process, HANDLE_FLAG_INHERIT, 0));
  for (unsigned i = 0; i < processCount; i++) if (GetProcessId(processes[i]) == pid) {
    need(creation(processes[i]) == time); CloseHandle(process); return;
  }
  need(processCount < 256); processes[processCount++] = process;
}
static unsigned census(BOOL emit) {
  DWORD level = 1, count = 0; PWTS_PROCESS_INFO_EXW entries = NULL;
  need(WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &level, WTS_ANY_SESSION, (LPWSTR *)&entries, &count) &&
    level == 1 && count <= 65536);
  unsigned live = 0, owned = 0;
  for (DWORD i = 0; i < count; i++) {
    bounded();
    if (!entries[i].ProcessId) continue; /* Idle is a kernel pseudo-process, not a creator. */
    need(entries[i].pUserSid != NULL && IsValidSid(entries[i].pUserSid));
    if (!EqualSid(entries[i].pUserSid, accountSid)) continue;
    need(++owned <= 32 && entries[i].SessionId == 0);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entries[i].ProcessId);
    need(process != NULL); principal(process, accountSid);
    DWORD state = WaitForSingleObject(process, 0); need(state == WAIT_OBJECT_0 || state == WAIT_TIMEOUT);
    if (state == WAIT_TIMEOUT) {
      live++;
      BOOL member = FALSE; need(job && IsProcessInJob(process, job, &member) && member);
    }
    if (emit) { if (owned > 1) putchar(','); identity(process); }
    add_process(process);
  }
  need(WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, entries, count)); return live;
}
static void job_limits(void) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits; JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
  need(QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits), NULL) &&
    QueryInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui), NULL));
  DWORD flags = limits.BasicLimitInformation.LimitFlags;
  need((flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) && (flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) &&
    !(flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)) &&
    limits.BasicLimitInformation.ActiveProcessLimit == 32 && ui.UIRestrictionsClass == JOB_OBJECT_UILIMIT_ALL);
  union { JOBOBJECT_BASIC_PROCESS_ID_LIST alignment; BYTE bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 33 * sizeof(ULONG_PTR)]; } buffer;
  JOBOBJECT_BASIC_PROCESS_ID_LIST *members = (JOBOBJECT_BASIC_PROCESS_ID_LIST *)buffer.bytes;
  need(QueryInformationJobObject(job, JobObjectBasicProcessIdList, members, sizeof(buffer.bytes), NULL) &&
    members->NumberOfAssignedProcesses == members->NumberOfProcessIdsInList && members->NumberOfProcessIdsInList <= 32);
  for (DWORD i = 0; i < members->NumberOfProcessIdsInList; i++) {
    need(members->ProcessIdList[i] > 0 && members->ProcessIdList[i] <= MAXDWORD);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, (DWORD)members->ProcessIdList[i]);
    BOOL member; need(process && IsProcessInJob(process, job, &member) && member); add_process(process);
  }
  /* This bounded list corroborates account/token identity; it is never a kill list. */
}
int wmain(int argc, wchar_t **argv) {
  need(argc >= 7 && argc <= 263 && _setmode(_fileno(stdout), _O_BINARY) != -1);
  nonce = argv[1]; need(wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32);
  control = GetStdHandle(STD_INPUT_HANDLE);
  need(GetFileType(control) == FILE_TYPE_PIPE && GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE);
  BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system); need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size));
  principal(GetCurrentProcess(), system); need(ConvertStringSidToSidW(argv[2], &accountSid) && !EqualSid(accountSid, system) &&
    ConvertStringSidToSidW(argv[3], &restrictingSid) && !EqualSid(accountSid, restrictingSid));
  printf("{\"nonce\":\"%ls\",\"phase\":\"helper\",\"helper\":", nonce); identity(GetCurrentProcess()); printf("}\n"); need(fflush(stdout) == 0);
  started = GetTickCount64(); need(CreateThread(NULL, 0, deadline, NULL, 0, NULL) != NULL); ack('P');
  wchar_t *end; ULONGLONG raw = _wcstoui64(argv[4], &end, 10); need(*argv[4] && !*end);
  job = (HANDLE)(ULONG_PTR)raw;
  if (job) { need(SetHandleInformation(job, HANDLE_FLAG_INHERIT, 0)); system_dacl(job, SE_KERNEL_OBJECT); job_limits(); }
  receipt(argv[5], argv[6]);
  for (int i = 7; i < argc; i++) {
    wchar_t *next; raw = _wcstoui64(argv[i], &next, 10); need(next != argv[i] && *next == L':');
    HANDLE process = (HANDLE)(ULONG_PTR)raw; DWORD pid = wcstoul(next + 1, &end, 10); need(end != next + 1 && *end == L':');
    ULONGLONG time = _wcstoui64(end + 1, &next, 10); need(*next == 0 && pid && time &&
      GetProcessId(process) == pid && creation(process) == time); add_process(process);
  }
  BOOL settled = FALSE;
  for (unsigned pass = 0; pass < 8; pass++) {
    bounded(); if (job) job_limits();
    printf("{\"nonce\":\"%ls\",\"phase\":\"snapshot\",\"jobPresent\":%s,\"members\":[", nonce, job ? "true" : "false");
    census(TRUE); printf("]}\n"); need(fflush(stdout) == 0);
    char operation = acknowledgement(); need(operation == 'T' || operation == 'W');
    if (operation == 'T') {
      need(job != NULL); authorized = TRUE; /* Exact Job, receipts and admission seal precede T. */
      job_limits(); need(TerminateJobObject(job, 137));
      printf("{\"nonce\":\"%ls\",\"phase\":\"terminated\"}\n", nonce); need(fflush(stdout) == 0);
      ack('W'); /* Persist and verify the separate wait intent before process waits. */
    }
    for (unsigned i = 0; i < processCount; i++) { bounded();
      ULONGLONG elapsed = GetTickCount64() - started; need(elapsed < 30000);
      DWORD remaining = (DWORD)(30000 - elapsed);
      need(WaitForSingleObject(processes[i], remaining) == WAIT_OBJECT_0);
    }
    unsigned live = census(FALSE), signaled = 0; bounded();
    printf("{\"nonce\":\"%ls\",\"phase\":\"waited\",\"signaled\":[", nonce);
    for (unsigned i = 0; i < processCount; i++) {
      DWORD state = WaitForSingleObject(processes[i], 0); need(state == WAIT_OBJECT_0 || state == WAIT_TIMEOUT);
      if (state == WAIT_TIMEOUT) continue;
      if (signaled++) putchar(','); identity(processes[i]);
    }
    printf("]}\n"); need(fflush(stdout) == 0);
    /* W without T only waits: absent/empty Jobs confer no termination request.
     * S requests a complete new snapshot; C follows independent fresh account,
     * membership, helper and holder reads. No deadline/work budget is reset. */
    char next = acknowledgement(); need(next == 'S' || next == 'C');
    if (next == 'C') {
      need(live == 0 && census(FALSE) == 0);
      for (unsigned i = 0; i < processCount; i++) need(WaitForSingleObject(processes[i], 0) == WAIT_OBJECT_0);
      settled = TRUE; break;
    }
  }
  need(settled); /* Last-handle tests pass job=0, retaining process handles only. */
  if (job) { need(CloseHandle(job)); job = NULL; }
  for (unsigned i = 0; i < processCount; i++) CloseHandle(processes[i]);
  LocalFree(accountSid); LocalFree(restrictingSid); return 0;
}
