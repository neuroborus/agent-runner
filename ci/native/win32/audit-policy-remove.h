/* SID-scoped removal; callers first prove retirement, original absence and exact policy. */
#ifndef NATIVE_WINDOWS_AUDIT_POLICY_REMOVE_H
#define NATIVE_WINDOWS_AUDIT_POLICY_REMOVE_H
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

struct audit_remove_result { DWORD error, cleanup; };
static void audit_remove_error(DWORD *first, DWORD error) { if (!*first) *first = error ? error : ERROR_GEN_FAILURE; }
/* Installed authorities may mutate the image, never an untrusted principal.
 * Ancestor handles deny deletion; directory creation rights are not file writes. */
static BOOL audit_remove_security(HANDLE file, BOOL directory) {
  PSID system = NULL, administrators = NULL, installer = NULL, owner;
  PACL dacl; PSECURITY_DESCRIPTOR sd = NULL; BOOL valid = FALSE;
  if (!ConvertStringSidToSidW(L"S-1-5-18", &system) ||
      !ConvertStringSidToSidW(L"S-1-5-32-544", &administrators) ||
      !ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer)) goto done;
  if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, NULL, &dacl, NULL, &sd) != ERROR_SUCCESS || !owner || !IsValidSid(owner) ||
      !dacl || !IsValidAcl(dacl) || dacl->AceCount > 128 ||
      !(EqualSid(owner, system) || EqualSid(owner, administrators) || EqualSid(owner, installer))) goto done;
  GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  DWORD writes = DELETE | WRITE_DAC | WRITE_OWNER | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
    (directory ? FILE_DELETE_CHILD : FILE_WRITE_DATA | FILE_APPEND_DATA);
  for (unsigned i = 0; i < dacl->AceCount; i++) {
    ACE_HEADER *header;
    if (!GetAce(dacl, i, (void **)&header) ||
        (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE)) goto done;
    if (header->AceType == ACCESS_DENIED_ACE_TYPE || (header->AceFlags & INHERIT_ONLY_ACE)) continue;
    DWORD sidOffset = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
    if (header->AceSize < sidOffset + 8) goto done;
    ACCESS_ALLOWED_ACE *ace = (void *)header; DWORD mask = ace->Mask; MapGenericMask(&mask, &mapping);
    if (!IsValidSid(&ace->SidStart) ||
        GetLengthSid(&ace->SidStart) > header->AceSize - sidOffset || ((mask & writes) &&
        !EqualSid(&ace->SidStart, system) && !EqualSid(&ace->SidStart, administrators) && !EqualSid(&ace->SidStart, installer))) goto done;
  }
  valid = TRUE;
done:
  if (sd) LocalFree(sd);
  if (system) LocalFree(system); if (administrators) LocalFree(administrators); if (installer) LocalFree(installer);
  return valid;
}
static BOOL audit_remove_owned_policy(PSID sid, struct audit_remove_result *result) {
  HANDLE ancestors[32] = {0}, image = INVALID_HANDLE_VALUE, input = INVALID_HANDLE_VALUE;
  HANDLE output = NULL, writer = NULL, job = NULL, loaded = INVALID_HANDLE_VALUE;
  unsigned ancestorCount = 0; PSECURITY_DESCRIPTOR sd = NULL;
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL; BOOL initialized = FALSE;
  PROCESS_INFORMATION child = {0}; WCHAR *sidText = NULL;
  WCHAR system[4096] = {0}, windows[4096] = {0}, pathname[4096], line[4352], environment[4120] = {0};
  FILE_ID_INFO before, after; FILE_ATTRIBUTE_TAG_INFO tag; LARGE_INTEGER imageSize;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  result->error = result->cleanup = 0;
#define AUDIT_REMOVE_REQUIRE(value) do { if (!(value)) { audit_remove_error(&result->error, ERROR_INVALID_DATA); goto done; } } while (0)
#define AUDIT_REMOVE_CALL(value) do { if (!(value)) { DWORD error = GetLastError(); audit_remove_error(&result->error, error); goto done; } } while (0)
  AUDIT_REMOVE_REQUIRE(sid && IsValidSid(sid) && *GetSidSubAuthorityCount(sid) == 5 &&
    !memcmp(GetSidIdentifierAuthority(sid), &nt, sizeof(nt)) && *GetSidSubAuthority(sid, 0) == 21);
  AUDIT_REMOVE_CALL(ConvertSidToStringSidW(sid, &sidText));
  AUDIT_REMOVE_REQUIRE(wcslen(sidText) < 192 && !wcsncmp(sidText, L"S-1-5-21-", 9));
  UINT size = GetSystemDirectoryW(system, 4096); AUDIT_REMOVE_CALL(size != 0);
  UINT windowsSize = GetWindowsDirectoryW(windows, 4096); AUDIT_REMOVE_CALL(windowsSize != 0);
  AUDIT_REMOVE_REQUIRE(size > 3 && size < 4096 && windowsSize > 3 && windowsSize < 4096 &&
    system[1] == L':' && system[2] == L'\\' && !_wcsnicmp(system, windows, windowsSize) &&
    !_wcsicmp(system + windowsSize, L"\\System32") && !wcschr(system, L'"'));
  AUDIT_REMOVE_REQUIRE(swprintf_s(pathname, 4096, L"%ls\\auditpol.exe", system) > 0);
  /* Retain each literal ancestor and the regular image without reparse traversal. */
  for (unsigned i = 3; pathname[i]; i++) if (pathname[i] == L'\\') {
    AUDIT_REMOVE_REQUIRE(ancestorCount < 32);
    WCHAR saved = pathname[i]; pathname[i] = 0;
    HANDLE held = CreateFileW(pathname, FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    pathname[i] = saved; AUDIT_REMOVE_CALL(held != INVALID_HANDLE_VALUE);
    ancestors[ancestorCount++] = held;
    AUDIT_REMOVE_CALL(GetFileInformationByHandleEx(held, FileAttributeTagInfo, &tag, sizeof(tag)));
    AUDIT_REMOVE_REQUIRE(!(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
      (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && audit_remove_security(held, TRUE));
  }
  image = CreateFileW(pathname, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  AUDIT_REMOVE_CALL(image != INVALID_HANDLE_VALUE);
  AUDIT_REMOVE_CALL(GetFileInformationByHandleEx(image, FileAttributeTagInfo, &tag, sizeof(tag)));
  AUDIT_REMOVE_REQUIRE(!(tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
    audit_remove_security(image, FALSE));
  AUDIT_REMOVE_CALL(GetFileInformationByHandleEx(image, FileIdInfo, &before, sizeof(before)));
  AUDIT_REMOVE_CALL(GetFileSizeEx(image, &imageSize));
  AUDIT_REMOVE_REQUIRE(imageSize.QuadPart > 0 && imageSize.QuadPart <= 16777216);
  /* SID conversion supplies digits/hyphens; braces are auditpol's documented SID form. */
  AUDIT_REMOVE_REQUIRE(swprintf_s(line, 4352, L"\"%ls\" /remove /user:{%ls}", pathname, sidText) > 0);
  int used = swprintf_s(environment, 4120, L"SystemRoot=%ls", windows);
  AUDIT_REMOVE_REQUIRE(used > 0 && used + 1 < 4120); environment[used + 1] = 0;
  /* Token-derived ownership works for both callers without restore privilege. */
  AUDIT_REMOVE_CALL(ConvertStringSecurityDescriptorToSecurityDescriptorW(
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, NULL));
  SECURITY_ATTRIBUTES private = {sizeof(private), sd, FALSE}, inherit = {sizeof(inherit), sd, TRUE};
  job = CreateJobObjectW(&private, NULL); AUDIT_REMOVE_CALL(job != NULL);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  limits.BasicLimitInformation.ActiveProcessLimit = 1;
  AUDIT_REMOVE_CALL(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)));
  input = CreateFileW(L"\\\\.\\NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, NULL);
  AUDIT_REMOVE_CALL(input != INVALID_HANDLE_VALUE);
  AUDIT_REMOVE_CALL(CreatePipe(&output, &writer, &inherit, 0));
  AUDIT_REMOVE_CALL(SetHandleInformation(output, HANDLE_FLAG_INHERIT, 0));
  SIZE_T bytes = 0; BOOL sized = InitializeProcThreadAttributeList(NULL, 2, 0, &bytes); DWORD sizingError = GetLastError();
  AUDIT_REMOVE_REQUIRE(!sized && sizingError == ERROR_INSUFFICIENT_BUFFER && bytes && bytes <= 65536);
  attributes = malloc(bytes); AUDIT_REMOVE_REQUIRE(attributes != NULL);
  AUDIT_REMOVE_CALL(InitializeProcThreadAttributeList(attributes, 2, 0, &bytes)); initialized = TRUE;
  HANDLE handles[] = {input, writer};
  AUDIT_REMOVE_CALL(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof(job), NULL, NULL));
  AUDIT_REMOVE_CALL(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), NULL, NULL));
  STARTUPINFOEXW start = {0}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = attributes;
  start.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  start.StartupInfo.hStdInput = input; start.StartupInfo.hStdOutput = start.StartupInfo.hStdError = writer;
  AUDIT_REMOVE_CALL(CreateProcessW(pathname, line, &private, &private, TRUE,
    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
    environment, system, &start.StartupInfo, &child));
  WCHAR actual[4096]; DWORD actualSize = 4096; BOOL member;
  AUDIT_REMOVE_CALL(QueryFullProcessImageNameW(child.hProcess, 0, actual, &actualSize));
  AUDIT_REMOVE_REQUIRE(actualSize < 4096 && !_wcsicmp(actual, pathname));
  loaded = CreateFileW(actual, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  AUDIT_REMOVE_CALL(loaded != INVALID_HANDLE_VALUE);
  AUDIT_REMOVE_CALL(GetFileInformationByHandleEx(loaded, FileIdInfo, &after, sizeof(after)));
  AUDIT_REMOVE_REQUIRE(!memcmp(&before, &after, sizeof(before)));
  AUDIT_REMOVE_CALL(IsProcessInJob(child.hProcess, job, &member)); AUDIT_REMOVE_REQUIRE(member);
  AUDIT_REMOVE_CALL(CloseHandle(writer)); writer = NULL;
  DWORD suspended = ResumeThread(child.hThread); AUDIT_REMOVE_CALL(suspended != (DWORD)-1); AUDIT_REMOVE_REQUIRE(suspended == 1);
  ULONGLONG deadline = GetTickCount64() + 10000; DWORD total = 0;
  for (;;) {
    DWORD available = 0, wait = WaitForSingleObject(child.hProcess, 0);
    AUDIT_REMOVE_CALL(wait != WAIT_FAILED);
    if (!PeekNamedPipe(output, NULL, 0, NULL, &available, NULL)) {
      DWORD error = GetLastError();
      if (error == ERROR_BROKEN_PIPE && wait == WAIT_OBJECT_0) break;
      audit_remove_error(&result->error, error); goto done;
    }
    if (available) {
      BYTE discarded[4096]; DWORD count = 0;
      AUDIT_REMOVE_CALL(ReadFile(output, discarded, available < 4096 ? available : 4096, &count, NULL));
      if (!count || count > 65536 - total) { audit_remove_error(&result->error, ERROR_BUFFER_OVERFLOW); goto done; }
      total += count; SecureZeroMemory(discarded, sizeof(discarded));
    } else if (wait == WAIT_OBJECT_0) break;
    if (GetTickCount64() >= deadline) { audit_remove_error(&result->error, ERROR_TIMEOUT); goto done; }
    Sleep(1);
  }
  DWORD exitCode; AUDIT_REMOVE_CALL(GetExitCodeProcess(child.hProcess, &exitCode));
  if (exitCode != 0) audit_remove_error(&result->error, ERROR_PROCESS_ABORTED);
done:
  /* Never short-circuit settlement or replace the original tool failure. */
  if (child.hProcess) {
    DWORD wait = WaitForSingleObject(child.hProcess, 0);
    if (wait == WAIT_FAILED) audit_remove_error(&result->cleanup, GetLastError());
    if (wait != WAIT_OBJECT_0) {
      if (!TerminateJobObject(job, 126)) audit_remove_error(&result->cleanup, GetLastError());
      wait = WaitForSingleObject(child.hProcess, 5000);
    }
    if (wait != WAIT_OBJECT_0) audit_remove_error(&result->cleanup, wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT);
    ULONGLONG deadline = GetTickCount64() + 5000;
    for (;;) {
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
      if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL)) {
        audit_remove_error(&result->cleanup, GetLastError()); break;
      }
      if (!accounting.ActiveProcesses) break;
      if (GetTickCount64() >= deadline) { audit_remove_error(&result->cleanup, ERROR_TIMEOUT); break; }
      Sleep(1);
    }
  }
  HANDLE closing[] = {child.hThread, child.hProcess, writer, output, input, loaded, image, job};
  for (unsigned i = 0; i < sizeof(closing)/sizeof(*closing); i++)
    if (closing[i] && closing[i] != INVALID_HANDLE_VALUE && !CloseHandle(closing[i])) audit_remove_error(&result->cleanup, GetLastError());
  for (unsigned i = 0; i < ancestorCount; i++)
    if (!CloseHandle(ancestors[i])) audit_remove_error(&result->cleanup, GetLastError());
  if (initialized) DeleteProcThreadAttributeList(attributes);
  free(attributes); if (sd) LocalFree(sd); if (sidText) LocalFree(sidText);
#undef AUDIT_REMOVE_REQUIRE
#undef AUDIT_REMOVE_CALL
  return !result->error && !result->cleanup;
}
#endif
