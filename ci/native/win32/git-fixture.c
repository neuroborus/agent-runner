/* External Windows 2025 x64 CI only. Ordinary modes are untrusted Job/token
 * payloads. The parked System mode has a separate reviewed fixed Git grant.
 * No shell, installation, arbitrary Git operation or identity override exists. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "advapi32.lib")
#ifndef _WIN64
#error The reviewed Git fixture requires the Windows x64 ABI.
#endif
static const WCHAR *nonce, *git, *metadata, *workspace, *hooks, *head;
static BOOL fixed;
static void need(BOOL ok) { if (!ok) ExitProcess(126); }
static void private_creator(HANDLE token) {
  union { TOKEN_DEFAULT_DACL alignment; BYTE bytes[4096]; } value;
  BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system), length;
  need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) &&
    GetTokenInformation(token, TokenDefaultDacl, &value, sizeof(value), &length) && length <= sizeof(value));
  PACL dacl = ((TOKEN_DEFAULT_DACL *)value.bytes)->DefaultDacl; ACCESS_ALLOWED_ACE *ace;
  need(dacl && IsValidAcl(dacl) && dacl->AceCount == 1 && GetAce(dacl, 0, (void **)&ace) &&
    ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags && ace->Mask == GENERIC_ALL &&
    EqualSid((PSID)&ace->SidStart, system));
}
static DWORD WINAPI expire(void *unused) { (void)unused; Sleep(25000); ExitProcess(124); return 0; }
static void ack(void) { char line[8]; need(fgets(line, sizeof(line), stdin) && !strcmp(line, "P\n")); }
static void path(const WCHAR *value) {
  need(wcslen(value) > 3 && wcslen(value) < 4096 && value[0] >= L'A' && value[0] <= L'Z' && value[1] == L':' && value[2] == L'\\');
  for (const WCHAR *p = value + 3; *p; p++) need((*p >= L'A' && *p <= L'Z') || (*p >= L'a' && *p <= L'z') ||
    (*p >= L'0' && *p <= L'9') || wcschr(L"\\ _.-", *p));
}
static HANDLE held(const WCHAR *name, BOOL directory) {
  HANDLE file = CreateFileW(name, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ | (directory ? FILE_SHARE_WRITE : 0), NULL,
    OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), NULL);
  FILE_ATTRIBUTE_TAG_INFO tag; BY_HANDLE_FILE_INFORMATION info; WCHAR actual[8192];
  need(file != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) &&
    !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && !!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory &&
    GetFileInformationByHandle(file, &info) && info.nNumberOfLinks == 1 && SetHandleInformation(file, HANDLE_FLAG_INHERIT, 0));
  DWORD size = GetFinalPathNameByHandleW(file, actual, 8192, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  need(size > 4 && size < 8192 && !wcsncmp(actual, L"\\\\?\\", 4) && !wcscmp(actual + 4, name));
  return file; /* Protected independent owners also retain IDs, ACLs and hashes. */
}
static void append(WCHAR *line, size_t *offset, WCHAR value) { need(*offset < 32766); line[(*offset)++] = value; line[*offset] = 0; }
static void argument(WCHAR *line, size_t *offset, const WCHAR *value) {
  if (*offset) append(line, offset, L' '); append(line, offset, L'"');
  size_t slashes = 0;
  for (const WCHAR *p = value;; p++) {
    if (*p == L'\\') { slashes++; continue; }
    size_t count = (*p == L'"' || !*p) ? slashes * 2 : slashes;
    for (size_t i = 0; i < count; i++) append(line, offset, L'\\'); slashes = 0;
    if (!*p) break; if (*p == L'"') append(line, offset, L'\\'); append(line, offset, *p);
  }
  append(line, offset, L'"');
}
static void identity(HANDLE process) {
  FILETIME created, exited, kernel, user; HANDLE token; BYTE buffer[256]; DWORD size, session; WCHAR *sid = NULL;
  need(GetProcessTimes(process, &created, &exited, &kernel, &user) && OpenProcessToken(process, TOKEN_QUERY, &token) &&
    GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &size) && ConvertSidToStringSidW(((TOKEN_USER *)buffer)->User.Sid, &sid) &&
    GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size));
  if (fixed) private_creator(token);
  ULARGE_INTEGER time; time.LowPart = created.dwLowDateTime; time.HighPart = created.dwHighDateTime;
  printf("{\"pid\":%lu,\"creationTime\":\"%llu\",\"sessionId\":%lu,\"userSid\":\"%ls\"}", GetProcessId(process), time.QuadPart, session, sid);
  LocalFree(sid); CloseHandle(token);
}
static DWORD command(const WCHAR *operation, const WCHAR *const *args, const char *expected) {
  WCHAR commandLine[32767] = {0}, hook[8192], safe[8192]; size_t offset = 0;
  need(swprintf_s(hook, 8192, L"core.hooksPath=%ls", hooks) > 0 && swprintf_s(safe, 8192, L"safe.directory=%ls", workspace) > 0);
  const WCHAR *prefix[] = {git, L"-c", hook, L"-c", safe, L"-c", L"core.fsmonitor=false", L"-c", L"commit.gpgsign=false",
    L"-c", L"commit.cleanup=verbatim", L"-c", L"core.attributesFile=NUL", L"-c", L"core.autocrlf=false", L"-c", L"core.fileMode=false",
    L"-c", L"gc.auto=0", L"-c", L"maintenance.auto=false", L"--git-dir", metadata, L"--work-tree", workspace, NULL};
  for (unsigned i = 0; prefix[i]; i++) argument(commandLine, &offset, prefix[i]);
  for (unsigned i = 0; args[i]; i++) argument(commandLine, &offset, args[i]);
  WCHAR environment[] = L"GIT_ATTR_NOSYSTEM=1\0GIT_CONFIG_GLOBAL=NUL\0GIT_CONFIG_NOSYSTEM=1\0GIT_OPTIONAL_LOCKS=0\0"
    L"GIT_TERMINAL_PROMPT=0\0HOME=NUL\0LANG=C\0PATH=\0TEMP=NUL\0TMP=NUL\0USERPROFILE=NUL\0\0";
  HANDLE inputRead, inputWrite, outputRead, outputWrite; SECURITY_ATTRIBUTES pipe = {sizeof(pipe), NULL, TRUE};
  need(CreatePipe(&inputRead, &inputWrite, &pipe, 0) && CreatePipe(&outputRead, &outputWrite, &pipe, 0) &&
    SetHandleInformation(inputWrite, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(outputRead, HANDLE_FLAG_INHERIT, 0) && CloseHandle(inputWrite));
  HANDLE handles[] = {inputRead, outputWrite}; SIZE_T size = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &size); need(size > 0 && size <= 65536);
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = malloc(size);
  need(attributes && InitializeProcThreadAttributeList(attributes, 1, 0, &size) &&
    UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), NULL, NULL));
  STARTUPINFOEXW startup = {0}; startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = inputRead; startup.StartupInfo.hStdOutput = outputWrite; startup.StartupInfo.hStdError = outputWrite; startup.lpAttributeList = attributes;
  PROCESS_INFORMATION child = {0};
  need(CreateProcessW(git, commandLine, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
    environment, workspace, &startup.StartupInfo, &child));
  BOOL member; need(IsProcessInJob(child.hProcess, NULL, &member) && member &&
    SetHandleInformation(child.hProcess, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(child.hThread, HANDLE_FLAG_INHERIT, 0));
  DeleteProcThreadAttributeList(attributes); free(attributes); CloseHandle(inputRead); CloseHandle(outputWrite);
  {
    printf("{\"nonce\":\"%ls\",\"phase\":\"child\",\"operation\":\"%ls\",\"suspended\":true,\"identity\":", nonce, operation);
    identity(child.hProcess); need(printf("}\n") > 0 && !fflush(stdout)); ack();
  }
  need(ResumeThread(child.hThread) == 1 && CloseHandle(child.hThread));
  char bytes[4096]; size_t length = 0; DWORD count;
  while (1) {
    if (!ReadFile(outputRead, bytes + length, (DWORD)(sizeof(bytes) - 1 - length), &count, NULL)) { need(GetLastError() == ERROR_BROKEN_PIPE); break; }
    if (!count) break; length += count; need(length < sizeof(bytes) - 1);
  }
  bytes[length] = 0;
  DWORD code; need(CloseHandle(outputRead) && WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0 &&
    GetExitCodeProcess(child.hProcess, &code) && CloseHandle(child.hProcess));
  if (fixed || expected) need(code == 0 && (!expected || (length == strlen(expected) && !memcmp(bytes, expected, length))));
  return code;
}
int wmain(int argc, WCHAR **argv) {
  need(argc == 9 && _setmode(_fileno(stdin), _O_BINARY) != -1 && _setmode(_fileno(stdout), _O_BINARY) != -1);
  need(GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE && GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE);
  nonce = argv[1]; fixed = !wcscmp(argv[2], L"fixed-commit");
  need(wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32 &&
    (fixed || !wcscmp(argv[2], L"inspect") || !wcscmp(argv[2], L"git-add") || !wcscmp(argv[2], L"git-commit") ||
    !wcscmp(argv[2],L"pointer-write") || !wcscmp(argv[2],L"pointer-delete") || !wcscmp(argv[2],L"pointer-replace") ||
    !wcscmp(argv[2],L"metadata-write") || !wcscmp(argv[2],L"ref-write")) &&
    wcslen(argv[7]) == 40 && wcsspn(argv[7], L"0123456789abcdef") == 40 && !wcscmp(argv[8], L"test(fixture): record owned edit"));
  for (unsigned i = 3; i <= 6; i++) path(argv[i]);
  git = argv[3]; metadata = argv[4]; workspace = argv[5]; hooks = argv[6]; head = argv[7];
  HANDLE token; BYTE user[256], system[SECURITY_MAX_SID_SIZE]; DWORD size, session; size = sizeof(system);
  need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) &&
    GetTokenInformation(token, TokenUser, user, sizeof(user), &size) &&
    EqualSid(((TOKEN_USER *)user)->User.Sid, system) == fixed && GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size) && session == 0);
  if (fixed) private_creator(token); need(CloseHandle(token));
  BOOL member; need(IsProcessInJob(GetCurrentProcess(), NULL, &member) && member && CreateThread(NULL, 0, expire, NULL, 0, NULL));
  if (fixed) {
    WCHAR ci[16], actions[16]; need(GetEnvironmentVariableW(L"CI", ci, 16) == 4 && !wcscmp(ci, L"true") &&
      GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 16) == 4 && !wcscmp(actions, L"true"));
  }
  need(printf("{\"nonce\":\"%ls\",\"phase\":\"ready\"}\n", nonce) > 0 && !fflush(stdout)); ack();
  if(!fixed && wcscmp(argv[2],L"inspect") && wcscmp(argv[2],L"git-add") && wcscmp(argv[2],L"git-commit")) {
    WCHAR target[8192]; DWORD desired=GENERIC_WRITE; BOOL pointer=!wcsncmp(argv[2],L"pointer-",8);
    need(swprintf_s(target,8192,L"%ls\\%ls",pointer ? workspace : metadata,pointer ? L".git" : !wcscmp(argv[2],L"ref-write") ? L"refs\\heads\\proof" : L"index")>0);
    if(!wcscmp(argv[2],L"pointer-delete") || !wcscmp(argv[2],L"pointer-replace")) desired=DELETE;
    SetLastError(0); HANDLE denied=CreateFileW(target,desired,FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    DWORD error=GetLastError(); need(denied==INVALID_HANDLE_VALUE && error==ERROR_ACCESS_DENIED);
    need(printf("{\"nonce\":\"%ls\",\"phase\":\"denied\",\"nativeCode\":%lu,\"identity\":",nonce,error)>0); identity(GetCurrentProcess()); need(printf("}\n")>0 && !fflush(stdout)); return 0;
  }
  HANDLE image = held(git, FALSE), repo = held(metadata, TRUE), work = held(workspace, TRUE), empty = held(hooks, TRUE);
  WCHAR pattern[8192]; need(swprintf_s(pattern, 8192, L"%ls\\*", hooks) > 0); WIN32_FIND_DATAW item;
  HANDLE found = FindFirstFileW(pattern, &item); need(found != INVALID_HANDLE_VALUE);
  do { need(!wcscmp(item.cFileName, L".") || !wcscmp(item.cFileName, L"..")); } while (FindNextFileW(found, &item));
  need(GetLastError() == ERROR_NO_MORE_FILES && FindClose(found));
  WCHAR name[8192]; need(swprintf_s(name, 8192, L"%ls\\content.txt", workspace) > 0); HANDLE content = held(name, FALSE);
  char bytes[12]; DWORD read; LARGE_INTEGER length;
  need(GetFileSizeEx(content, &length) && length.QuadPart == 11 && ReadFile(content, bytes, sizeof(bytes), &read, NULL) && read == 11 && !memcmp(bytes, "owned edit\n", 11));
  char expected[42]; for (unsigned i = 0; i < 40; i++) expected[i] = (char)head[i]; expected[40] = '\n'; expected[41] = 0;
  const WCHAR *parent[] = {L"rev-parse", L"HEAD", NULL}, *branch[] = {L"symbolic-ref", L"HEAD", NULL},
    *status[] = {L"status", L"--porcelain=v1", NULL}, *add[] = {L"add", L"--", L"content.txt", NULL},
    *commit[] = {L"commit", L"--cleanup=verbatim", L"-m", L"test(fixture): record owned edit", NULL};
  DWORD code = 0;
  if (fixed) {
    command(L"parent", parent, expected); command(L"branch", branch, "refs/heads/proof\n"); command(L"status", status, " M content.txt\n");
    command(L"add", add, NULL); command(L"commit", commit, NULL);
    need(printf("{\"nonce\":\"%ls\",\"phase\":\"finished\"}\n", nonce) > 0 && !fflush(stdout));
  } else code = command(argv[2], !wcscmp(argv[2], L"inspect") ? parent : !wcscmp(argv[2], L"git-add") ? add : commit, !wcscmp(argv[2], L"inspect") ? expected : NULL);
  need(CloseHandle(content) && CloseHandle(empty) && CloseHandle(work) && CloseHandle(repo) && CloseHandle(image)); return (int)code;
}
