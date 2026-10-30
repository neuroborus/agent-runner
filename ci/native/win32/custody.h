/* Shared bounded kernel reads for the sealed Windows custody entry/reader. */
#ifndef NATIVE_WINDOWS_CUSTODY_H
#define NATIVE_WINDOWS_CUSTODY_H
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
/* Longest fixed file recipe plus bounded settlement and entry margin. */
#define CUSTODY_LIFETIME_MS 1170000
#define PREPARATION_LIFETIME_MS (2*30000+13*60000+120000)
/* UTF-16 code units excluding NUL; protocol.js uses the same list-text bound. */
#define WINDOWS_BUILD_ENVIRONMENT_MAX_UNITS 16384
#define WINDOWS_BUILD_ENVIRONMENT_CAPACITY (WINDOWS_BUILD_ENVIRONMENT_MAX_UNITS+1)
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <psapi.h>
#include <winternl.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include <errno.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#if !defined(_WIN64) || (!defined(_M_X64) && !defined(__x86_64__)) || defined(_M_ARM64EC)
#error This reviewed protocol requires the Windows x64 ABI.
#endif
static void need_at(bool ok, const char *file, unsigned line) {
  if (!ok) {
    DWORD error = GetLastError();
#ifdef NATIVE_CUSTODY_FAILURE
    NATIVE_CUSTODY_FAILURE(file, line, error);
#endif
    fprintf(stderr, "native-windows-guard: file=%s line=%u last-error=%lu\n", file, line, error);
    fflush(stderr); ExitProcess(126);
  }
}
#define need(ok) need_at(!!(ok), __FILE__, __LINE__)
static void need_hresult_at(HRESULT result, bool ok, const char *operation, const char *file, unsigned line) {
  if (!ok) {
    DWORD error = GetLastError();
    fprintf(stderr, "native-windows-hresult: operation=%s hresult=0x%08lx file=%s line=%u\n", operation, (unsigned long)(DWORD)result, file, line);
    fflush(stderr); SetLastError(error); need_at(false, file, line);
  }
}
#define need_hr(operation, ...) do { HRESULT custody_hr = operation(__VA_ARGS__); need_hresult_at(custody_hr, SUCCEEDED(custody_hr), #operation, __FILE__, __LINE__); } while (0)
#define need_hr_equal(operation, expected, ...) do { HRESULT custody_hr = operation(__VA_ARGS__); need_hresult_at(custody_hr, custody_hr == (expected), #operation, __FILE__, __LINE__); } while (0)
static void require_build(void) {
  typedef LONG (WINAPI *version)(PRTL_OSVERSIONINFOW); RTL_OSVERSIONINFOW os = {sizeof(os)};
  version get = (version)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
  SYSTEM_INFO system; GetNativeSystemInfo(&system);
  need(system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && get && !get(&os) && os.dwMajorVersion == 10 && os.dwMinorVersion == 0 && os.dwBuildNumber == 26100);
}
static ULONGLONG number(const char *value) {
  char *end; need(*value >= '0' && *value <= '9'); errno = 0;
  ULONGLONG result = _strtoui64(value, &end, 10); need(!errno && !*end); return result;
}
static DWORD bounded_number(const char *value, DWORD maximum) {
  ULONGLONG result = number(value); need(result <= maximum); return (DWORD)result;
}
static void hex(const BYTE *bytes, size_t size) { for (size_t i = 0; i < size; i++) printf("%02x", bytes[i]); }
static void sum(const BYTE *bytes, ULONG size, char out[65]) {
  BCRYPT_ALG_HANDLE algorithm; BCRYPT_HASH_HANDLE hash; BYTE digest[32];
  need(!BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) &&
    !BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) &&
    !BCryptHashData(hash, (BYTE *)bytes, size, 0) && !BCryptFinishHash(hash, digest, 32, 0));
  for (unsigned i = 0; i < 32; i++) sprintf_s(out + 2*i, 65 - 2*i, "%02x", digest[i]);
  BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
}
static PSECURITY_DESCRIPTOR descriptor(const wchar_t *sddl) {
  PSECURITY_DESCRIPTOR result; need(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &result, NULL)); return result;
}
static SECURITY_ATTRIBUTES attributes(PSECURITY_DESCRIPTOR sd, BOOL inherit) {
  SECURITY_ATTRIBUTES result = {sizeof(result), sd, inherit}; return result;
}
static void *token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
  DWORD size = 0; GetTokenInformation(token, kind, NULL, 0, &size);
  need(GetLastError() == ERROR_INSUFFICIENT_BUFFER && size && size <= 65536);
  void *value = calloc(1, size); need(value && GetTokenInformation(token, kind, value, size, &size)); return value;
}
static wchar_t *token_sid(HANDLE token) {
  TOKEN_USER *user = token_info(token, TokenUser); wchar_t *value;
  need(ConvertSidToStringSidW(user->User.Sid, &value)); free(user); return value;
}
static void privilege(const wchar_t *name) {
  HANDLE token; TOKEN_PRIVILEGES value = {0}; value.PrivilegeCount = 1;
  need(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) &&
    LookupPrivilegeValueW(NULL, name, &value.Privileges[0].Luid));
  value.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; SetLastError(ERROR_SUCCESS);
  need(AdjustTokenPrivileges(token, FALSE, &value, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS && CloseHandle(token));
}
static DWORD process_session(HANDLE process) {
  /* Matched x64 SDK/26100 binding: ProcessSessionInformation is class 24. */
  typedef NTSTATUS (NTAPI *query)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
  query get = (query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"); DWORD session; ULONG used;
  need(get && !get(process, (PROCESSINFOCLASS)24, &session, sizeof(session), &used) && used == sizeof(session)); return session;
}
static BOOL system_process(HANDLE process) {
  HANDLE token; need(OpenProcessToken(process, TOKEN_QUERY, &token));
  wchar_t *sid = token_sid(token); DWORD *session = token_info(token, TokenSessionId);
  DWORD actual = process_session(process); need(actual == *session);
  BOOL result = !wcscmp(sid, L"S-1-5-18") && actual == 0;
  LocalFree(sid); free(session); CloseHandle(token); return result;
}
static void retained_identity(HANDLE process, HANDLE token, DWORD actual) {
  FILETIME created, exited, kernel, user; ULARGE_INTEGER time;
  need(GetProcessTimes(process, &created, &exited, &kernel, &user));
  wchar_t *sid = token_sid(token); DWORD *session = token_info(token, TokenSessionId); need(actual == *session);
  time.LowPart = created.dwLowDateTime; time.HighPart = created.dwHighDateTime;
  printf("{\"pid\":%lu,\"creationTime\":\"%llu\",\"sessionId\":%lu,\"userSid\":\"%ls\"}",
    GetProcessId(process), time.QuadPart, *session, sid);
  LocalFree(sid); free(session);
}
static void identity(HANDLE process) {
  HANDLE token; need(OpenProcessToken(process, TOKEN_QUERY, &token));
  retained_identity(process, token, process_session(process)); need(CloseHandle(token));
}
static void security(HANDLE handle, SE_OBJECT_TYPE kind, BOOL private, char digest[65]) {
  PSID owner; PACL dacl; PSECURITY_DESCRIPTOR sd; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  need(GetSecurityInfo(handle, kind, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    &owner, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS && dacl &&
    GetSecurityDescriptorControl(sd, &flags, &revision));
  if (private) {
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(sid); ACCESS_ALLOWED_ACE *ace;
    need(CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &size) && EqualSid(owner, sid) &&
      (flags & SE_DACL_PROTECTED) && dacl->AceCount == 1 && GetAce(dacl, 0, (void **)&ace) &&
      ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags &&
      EqualSid(&ace->SidStart, sid) && (kind == SE_FILE_OBJECT ?
        (ace->Mask & GENERIC_ALL || (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS || ace->Mask == 0x1200a9) : ace->Mask != 0));
  }
  DWORD size = GetSecurityDescriptorLength(sd); need((flags & SE_SELF_RELATIVE) && size && size <= 65536);
  sum((BYTE *)sd, size, digest); LocalFree(sd);
}
struct held_file { HANDLE handle, volume, parents[32]; unsigned count; DWORD links; wchar_t path[4096], volumeName[64], filesystem[32]; FILE_ID_INFO id; };
#ifdef NATIVE_CI_EXPERIMENT
static __declspec(thread) struct {
  const wchar_t *name; const char *operation; BOOL api_failure, directory, sampled;
  FILE_ATTRIBUTE_TAG_INFO tag;
} open_file_failure;
/* Only sampled metadata is published; invariant refusals have no API error.
 * Preserve the original guard's last-error/errno even when stderr fails. */
static void open_file_refusal(const wchar_t *name, const char *operation, BOOL api_failure, BOOL directory, const FILE_ATTRIBUTE_TAG_INFO *tag) {
  DWORD error = GetLastError(); int saved_errno = errno;
  open_file_failure.name = name; open_file_failure.operation = operation;
  open_file_failure.api_failure = api_failure; open_file_failure.directory = directory;
  open_file_failure.sampled = tag != NULL;
  if (tag) {
    open_file_failure.tag.FileAttributes = tag->FileAttributes;
    if (tag->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) open_file_failure.tag.ReparseTag = tag->ReparseTag;
  }
  fprintf(stderr, "native-windows-open: operation=%s domain=%s expected-kind=%s error=", operation,
    api_failure ? "win32" : "invariant", directory ? "directory" : "file");
  if (api_failure) fprintf(stderr, "%lu", error); else fputs("unavailable", stderr);
  if (tag) fprintf(stderr, " attributes=0x%08lx", (unsigned long)tag->FileAttributes);
  else fputs(" attributes=unavailable", stderr);
  if (tag && (tag->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) fprintf(stderr, " tag=0x%08lx", (unsigned long)tag->ReparseTag);
  else fputs(" tag=unavailable", stderr);
  size_t units = wcslen(name);
  fprintf(stderr, " path-units=%zu path-utf16=", units);
  for (size_t i = 0; i < units; i++) fprintf(stderr, "%04x", (unsigned)name[i]);
  fputc('\n', stderr); fflush(stderr);
  errno = saved_errno; SetLastError(error);
}
#endif
static HANDLE open_file_shared(const wchar_t *name, BOOL directory, DWORD access, BOOL mutable) {
  HANDLE result = CreateFileW(name, access | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | (directory || mutable ? FILE_SHARE_WRITE : 0),
    NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  FILE_ATTRIBUTE_TAG_INFO tag; wchar_t canonical[4100]; DWORD size;
#ifdef NATIVE_CI_EXPERIMENT
  if (result == INVALID_HANDLE_VALUE) { open_file_refusal(name, "CreateFileW", TRUE, directory, NULL); need(false); }
  if (!GetFileInformationByHandleEx(result, FileAttributeTagInfo, &tag, sizeof(tag))) {
    open_file_refusal(name, "GetFileInformationByHandleEx/FileAttributeTagInfo", TRUE, directory, NULL); need(false);
  }
  if (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { open_file_refusal(name, "reparse-point", FALSE, directory, &tag); need(false); }
  if (!!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory) { open_file_refusal(name, "file-kind", FALSE, directory, &tag); need(false); }
#else
  need(result != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(result, FileAttributeTagInfo, &tag, sizeof(tag)) &&
    !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && !!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory);
#endif
  size = GetFinalPathNameByHandleW(result, canonical, 4100, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
#ifdef NATIVE_CI_EXPERIMENT
  if (!size) { open_file_refusal(name, "GetFinalPathNameByHandleW", TRUE, directory, NULL); need(false); }
  if (size <= 4 || size >= 4100) { open_file_refusal(name, "final-path-size", FALSE, directory, &tag); need(false); }
  if (wcsncmp(canonical, L"\\\\?\\", 4)) { open_file_refusal(name, "final-path-prefix", FALSE, directory, &tag); need(false); }
  if (wcscmp(canonical + 4, name)) { open_file_refusal(name, "final-path-equality", FALSE, directory, &tag); need(false); }
  if (!SetHandleInformation(result, HANDLE_FLAG_INHERIT, 0)) { open_file_refusal(name, "SetHandleInformation", TRUE, directory, NULL); need(false); }
#else
  need(size > 4 && size < 4100 && !wcsncmp(canonical, L"\\\\?\\", 4) && !wcscmp(canonical + 4, name) &&
    SetHandleInformation(result, HANDLE_FLAG_INHERIT, 0));
#endif
  return result;
}
static HANDLE open_file(const wchar_t *name, BOOL directory, DWORD access) { return open_file_shared(name, directory, access, FALSE); }
static struct held_file hold_shared(const wchar_t *name, BOOL directory, BOOL private, DWORD access, BOOL mutable) {
  struct held_file value = {0}; need(wcslen(name) > 3 && wcslen(name) < 4096 && name[1] == ':' && name[2] == '\\');
  wcscpy_s(value.path, 4096, name); value.handle = open_file_shared(name, directory, access, mutable);
  need(GetFileInformationByHandleEx(value.handle, FileIdInfo, &value.id, sizeof(value.id)));
  BY_HANDLE_FILE_INFORMATION info; need(GetFileInformationByHandle(value.handle, &info)); value.links = info.nNumberOfLinks;
  need(value.links && value.links <= 128 && (directory || !private || value.links == 1));
  wchar_t root[4096]; FILE_ID_INFO volumeId; DWORD serial, maximum, flags;
  need(GetVolumePathNameW(name, root, 4096) && GetVolumeNameForVolumeMountPointW(root, value.volumeName, 64));
  value.volume = open_file(root, TRUE, READ_CONTROL);
  need(GetFileInformationByHandleEx(value.volume, FileIdInfo, &volumeId, sizeof(volumeId)) &&
    volumeId.VolumeSerialNumber == value.id.VolumeSerialNumber &&
    GetVolumeInformationByHandleW(value.volume, NULL, 0, &serial, &maximum, &flags, value.filesystem, 32));
  char hash[65]; security(value.handle, SE_FILE_OBJECT, private, hash);
  wchar_t parent[4096]; wcscpy_s(parent, 4096, name);
  wchar_t *slash = wcsrchr(parent, '\\'); need(slash); *slash = 0;
  while (wcslen(parent) > 2) {
    need(value.count < 32); value.parents[value.count++] = open_file(parent, TRUE, READ_CONTROL);
    slash = wcsrchr(parent, '\\'); need(slash); *slash = 0;
  }
  wchar_t canonical[4100]; DWORD size = GetFinalPathNameByHandleW(value.handle, canonical, 4100, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  need(size > 4 && size < 4100 && !wcsncmp(canonical, L"\\\\?\\", 4) && !wcscmp(canonical + 4, name));
  return value; /* No share-delete: all retained parents resist rename. */
}
static struct held_file hold(const wchar_t *name, BOOL directory, BOOL private, DWORD access) { return hold_shared(name, directory, private, access, FALSE); }
static void file_id(struct held_file *value) {
  FILE_ID_INFO id; need(GetFileInformationByHandleEx(value->handle, FileIdInfo, &id, sizeof(id)) && !memcmp(&id, &value->id, sizeof(id)));
  printf("%016llx:", id.VolumeSerialNumber); hex(id.FileId.Identifier, 16);
}
static BYTE *read_file(struct held_file *file, DWORD maximum, DWORD *size) {
  LARGE_INTEGER length, zero = {0}; BY_HANDLE_FILE_INFORMATION before = {0}, after = {0};
  need(GetFileSizeEx(file->handle, &length) && length.QuadPart > 0 && length.QuadPart <= maximum &&
    GetFileInformationByHandle(file->handle, &before) && before.nNumberOfLinks == file->links &&
    SetFilePointerEx(file->handle, zero, NULL, FILE_BEGIN));
  *size = (DWORD)length.QuadPart; BYTE *bytes = calloc(*size, 1); need(bytes); DWORD total = 0;
  while (total < *size) { DWORD read; need(ReadFile(file->handle, bytes + total, *size - total, &read, NULL) && read); total += read; }
  need(GetFileInformationByHandle(file->handle, &after) &&
    before.dwFileAttributes == after.dwFileAttributes && before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
    before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow &&
    before.nFileSizeHigh == after.nFileSizeHigh && before.nFileSizeLow == after.nFileSizeLow && before.nNumberOfLinks == after.nNumberOfLinks &&
    !memcmp(&before.ftCreationTime, &after.ftCreationTime, sizeof(FILETIME)) && !memcmp(&before.ftLastWriteTime, &after.ftLastWriteTime, sizeof(FILETIME))); return bytes;
}
static void pin(struct held_file *file, const char *expected) {
  DWORD size; BYTE *bytes = read_file(file, 536870912, &size); char actual[65]; sum(bytes, size, actual); need(!strcmp(actual, expected)); free(bytes);
}
static struct held_file catalogs[256]; static unsigned catalog_count;
static struct { struct held_file *file; const char *expected; DWORD choice; LONG result, closed; BOOL active; char inputs[512];
#ifdef NATIVE_CI_EXPERIMENT
  char provider[256];
#endif
} signature_trust;
#ifdef NATIVE_CI_EXPERIMENT
static BOOL signature_provider_read(const void *source, void *target, SIZE_T size) {
  SIZE_T read = 0;
  return source && ReadProcessMemory(GetCurrentProcess(), source, target, size, &read) && read == size;
}
/* Optional failure data from the original state, never another verification.
 * API/state/data/structure, errors, count/pointer, inspected/nonzero/first/code,
 * complete. -1 means unavailable; at most 64 counted steps are inspected. */
static void signature_provider_observe(WINTRUST_DATA *trust) {
  DWORD saved = GetLastError(); int saved_errno = errno;
  LONGLONG observed[13] = {0, trust->hWVTStateData != NULL, 0, 0, -1, -1, -1, -1, 0, -1, -1, -1, 0};
  typedef CRYPT_PROVIDER_DATA *(WINAPI *provider_data)(HANDLE);
  HMODULE module = GetModuleHandleW(L"wintrust.dll");
  provider_data get = module ? (provider_data)GetProcAddress(module, "WTHelperProvDataFromStateData") : NULL;
  observed[0] = get != NULL;
  const CRYPT_PROVIDER_DATA *source = get && trust->hWVTStateData ? get(trust->hWVTStateData) : NULL;
  observed[2] = source != NULL;
  DWORD size = 0; CRYPT_PROVIDER_DATA data = {0};
  if (signature_provider_read(source, &size, sizeof(size)) && size >= sizeof(data) &&
      signature_provider_read(source, &data, sizeof(data)) && data.cbStruct == size) {
    observed[3] = 1; observed[4] = data.dwError; observed[5] = data.dwFinalError;
    observed[6] = data.cdwTrustStepErrors; observed[7] = data.padwTrustStepErrors != NULL;
    if (!!data.cdwTrustStepErrors == !!data.padwTrustStepErrors) {
      DWORD errors[64], count = data.cdwTrustStepErrors < 64 ? data.cdwTrustStepErrors : 64;
      if (!count || signature_provider_read(data.padwTrustStepErrors, errors, count*sizeof(errors[0]))) {
        observed[8] = count; observed[9] = 0; observed[12] = count == data.cdwTrustStepErrors;
        for (DWORD i = 0; i < count; i++) if (errors[i]) {
          observed[9]++;
          if (observed[10] == -1) { observed[10] = i; observed[11] = errors[i]; }
        }
      }
    }
  }
  sprintf_s(signature_trust.provider, sizeof(signature_trust.provider), ",\"provider\":[%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld]",
    observed[0], observed[1], observed[2], observed[3], observed[4], observed[5], observed[6], observed[7],
    observed[8], observed[9], observed[10], observed[11], observed[12]);
  errno = saved_errno; SetLastError(saved);
}
#endif
static void signature_observe(struct held_file *file, WINTRUST_DATA *trust) {
  DWORD saved = GetLastError(), flags = 0;
  BOOL flagged = GetHandleInformation(file->handle, &flags); DWORD flagStatus = flagged ? 0 : GetLastError();
  LARGE_INTEGER size = {0}, position = {0}, zero = {0};
  BOOL sized = GetFileSizeEx(file->handle, &size); DWORD sizeStatus = sized ? 0 : GetLastError();
  /* FILE_CURRENT + zero observes the held offset without rewinding the file. */
  BOOL positioned = SetFilePointerEx(file->handle, zero, &position, FILE_CURRENT); DWORD positionStatus = positioned ? 0 : GetLastError();
  WINTRUST_FILE_INFO *info = trust->dwUnionChoice == WTD_CHOICE_FILE ? trust->pFile : NULL;
  sprintf_s(signature_trust.inputs, sizeof(signature_trust.inputs), "[%lu,%lld,%d,%d,%d,%d,%lu,%lu,%lu,%lu,%lu,%d,%d,%d,%lu,%lld,%lu,%lld,%lu,%lld]",
    trust->cbStruct, info ? (LONGLONG)info->cbStruct : -1,
    info && info->pcwszFilePath && wcslen(info->pcwszFilePath)>3 && info->pcwszFilePath[1]==':' && info->pcwszFilePath[2]=='\\',
    info && info->pcwszFilePath==file->path, info && info->hFile==file->handle, info && info->pgKnownSubject!=NULL,
    trust->dwUIChoice, trust->fdwRevocationChecks, trust->dwStateAction, trust->dwProvFlags, trust->dwUIContext,
    trust->pPolicyCallbackData!=NULL, trust->pSIPClientData!=NULL, trust->hWVTStateData!=NULL,
    flagStatus, flagged ? (LONGLONG)flags : -1, sizeStatus, sized && size.QuadPart>=0 && size.QuadPart<=536870912 ? size.QuadPart : -1,
    positionStatus, positioned && position.QuadPart>=0 && position.QuadPart<=536870912 ? position.QuadPart : -1);
  SetLastError(saved);
}
static void signature_verify(struct held_file *file, const char *expected, WINTRUST_DATA *trust) {
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  if (trust->dwUnionChoice == WTD_CHOICE_FILE) {
    LARGE_INTEGER zero = {0};
    need(SetFilePointerEx(file->handle, zero, NULL, FILE_BEGIN));
  }
  signature_observe(file, trust);
  /* INVALID_HANDLE_VALUE declares that no interactive user is available. */
  LONG result = WinVerifyTrust(INVALID_HANDLE_VALUE, &action, trust);
  /* Save the original LONG before CLOSE can replace native error state. */
  signature_trust.file = file; signature_trust.expected = expected; signature_trust.choice = trust->dwUnionChoice;
  signature_trust.result = result; signature_trust.closed = ERROR_SUCCESS; signature_trust.active = TRUE;
#ifdef NATIVE_CI_EXPERIMENT
  signature_trust.provider[0] = 0;
  if (result != ERROR_SUCCESS) signature_provider_observe(trust);
#endif
  trust->dwStateAction = WTD_STATEACTION_CLOSE;
  LONG closed = WinVerifyTrust(INVALID_HANDLE_VALUE, &action, trust); signature_trust.closed = closed;
  DWORD saved = GetLastError();
  if (result != ERROR_SUCCESS || closed != ERROR_SUCCESS)
    fprintf(stderr, "native-windows-trust: choice=%lu result=0x%08lx close-result=0x%08lx\n", signature_trust.choice, (unsigned long)(DWORD)result, (unsigned long)(DWORD)closed);
  SetLastError(saved);
  need(result == ERROR_SUCCESS); need(closed == ERROR_SUCCESS);
  signature_trust.active = FALSE;
}
static void catalog_signature(struct held_file *file, const char *expected, char actual[65]) {
  HCATADMIN admin; DWORD size = 32; BYTE hash[32]; HCATINFO catalog; CATALOG_INFO info = {sizeof(info)};
  need(CryptCATAdminAcquireContext2(&admin, NULL, L"SHA256", NULL, 0) &&
    CryptCATAdminCalcHashFromFileHandle2(admin, file->handle, &size, hash, 0) && size == 32);
  catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, NULL);
  need(catalog && CryptCATCatalogInfoFromContext(catalog, &info, 0));
  unsigned slot = catalog_count; for (unsigned i = 0; i < catalog_count; i++) if (!_wcsicmp(catalogs[i].path, info.wszCatalogFile)) slot = i;
  if (slot == catalog_count) { need(catalog_count < 256); catalogs[catalog_count++] = hold(info.wszCatalogFile, FALSE, FALSE, GENERIC_READ); }
  wchar_t tag[65]; for (unsigned i = 0; i < 32; i++) swprintf_s(tag+i*2, 65-i*2, L"%02X", hash[i]);
  WINTRUST_CATALOG_INFO member = {0}; member.cbStruct = sizeof(member); member.pcwszCatalogFilePath = info.wszCatalogFile;
  member.pcwszMemberTag = tag; member.pcwszMemberFilePath = file->path; member.hMemberFile = file->handle;
  member.pbCalculatedFileHash = hash; member.cbCalculatedFileHash = size; member.hCatAdmin = admin;
  WINTRUST_DATA trust = {0}; trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_NONE; trust.dwUnionChoice = WTD_CHOICE_CATALOG; trust.pCatalog = &member;
  trust.dwStateAction = WTD_STATEACTION_VERIFY; trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
  signature_verify(file, expected, &trust);
  DWORD bytes; BYTE *data = read_file(&catalogs[slot], 536870912, &bytes); sum(data, bytes, actual); free(data); if (expected) need(!strcmp(expected, actual));
  need(CryptCATAdminReleaseCatalogContext(admin, catalog, 0) && CryptCATAdminReleaseContext(admin, 0));
}
static void signature(struct held_file *file, const char *expected, char actual[65]) {
  DWORD size; BYTE *bytes = read_file(file, 536870912, &size);
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)bytes; need(size >= sizeof(IMAGE_NT_HEADERS64)+64 && dos->e_magic == IMAGE_DOS_SIGNATURE &&
    dos->e_lfanew >= 64 && (DWORD)dos->e_lfanew <= size - sizeof(IMAGE_NT_HEADERS64));
  IMAGE_NT_HEADERS64 *pe = (IMAGE_NT_HEADERS64 *)(bytes + dos->e_lfanew);
  need(pe->Signature == IMAGE_NT_SIGNATURE && pe->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && pe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && pe->OptionalHeader.NumberOfRvaAndSizes >= 5);
  IMAGE_DATA_DIRECTORY cert = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(pe);
  need(pe->FileHeader.NumberOfSections && pe->FileHeader.NumberOfSections <= 96 &&
    (BYTE *)(sections + pe->FileHeader.NumberOfSections) <= bytes + size);
  unsigned markers = 0, markerIndex = 0;
  for (unsigned i = 0; i < pe->FileHeader.NumberOfSections; i++) if (!memcmp(sections[i].Name, ".nexp\0\0\0", 8)) { markers++; markerIndex = i; }
  if (markers) {
#ifdef NATIVE_CI_EXPERIMENT
    unsigned i = markerIndex;
    static const char marker[] = "native-ci-experiment-v1";
    need(markers == 1 && !(sections[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) &&
      !cert.Size && !cert.VirtualAddress && sections[i].SizeOfRawData >= sizeof(marker) &&
      sections[i].PointerToRawData <= size - sizeof(marker) &&
      !memcmp(bytes + sections[i].PointerToRawData, marker, sizeof(marker)));
    /* The observation is the unsigned image digest, never Authenticode trust. */
    sum(bytes, size, actual); if (expected) need(!strcmp(actual, expected)); free(bytes); return;
#else
    need(FALSE);
#endif
  }
  if (!cert.Size) {
    need(!cert.VirtualAddress);
#ifdef NATIVE_CI_EXPERIMENT
    // Installed/copy runtime bytes are observations only. The tagged reader
    // cannot publish these digests as authenticated release evidence.
    sum(bytes, size, actual); if (expected) need(!strcmp(actual, expected)); free(bytes); return;
#else
    free(bytes); catalog_signature(file, expected, actual); return;
#endif
  }
  WINTRUST_FILE_INFO info = {sizeof(info), file->path, file->handle, NULL};
  WINTRUST_DATA trust = {0}; trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_NONE; trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &info;
  trust.dwStateAction = WTD_STATEACTION_VERIFY; trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
  signature_verify(file, expected, &trust);
  need(cert.VirtualAddress && cert.Size >= 8 && cert.VirtualAddress <= size && cert.Size <= size - cert.VirtualAddress);
  sum(bytes + cert.VirtualAddress, cert.Size, actual); if (expected) need(!strcmp(actual, expected)); free(bytes);
}
static void close_file(struct held_file *value) {
  need(CloseHandle(value->handle) && CloseHandle(value->volume)); for (unsigned i = 0; i < value->count; i++) need(CloseHandle(value->parents[i])); value->handle = NULL;
}
static unsigned nibble(char value) {
  need(value >= '0' && value <= '9' || value >= 'a' && value <= 'f');
  return value <= '9' ? value - '0' : value - 'a' + 10;
}
static void bounded_text(const wchar_t *value, size_t size, size_t maximum) {
  need(size && size < maximum && wcslen(value) == size);
  for (size_t i = 0; i < size; i++) {
    need(value[i] >= 32 && value[i] != 127);
    if (value[i] >= 0xd800 && value[i] <= 0xdbff) { need(i+1 < size && value[i+1] >= 0xdc00 && value[i+1] <= 0xdfff); i++; }
    else need(value[i] < 0xdc00 || value[i] > 0xdfff);
  }
}
static void decode_bounded(const char *bytes, wchar_t *out, size_t maximum) {
  size_t size = strlen(bytes); need(size && size % 4 == 0 && size / 4 < maximum);
  BYTE *target = (BYTE *)out;
  for (size_t i = 0; i < size / 2; i++) target[i] = (BYTE)(nibble(bytes[i*2])*16 + nibble(bytes[i*2+1]));
  out[size / 4] = 0; bounded_text(out, size / 4, maximum);
}
static void decode(const char *bytes, wchar_t out[4096]) { decode_bounded(bytes, out, 4096); }
static void line(HANDLE input, char *value, unsigned maximum) {
  unsigned offset = 0; DWORD read;
  while (offset + 1 < maximum) { char byte; need(ReadFile(input, &byte, 1, &read, NULL) && read == 1 && byte > 0 && byte < 128);
    if (byte == '\n') { value[offset] = 0; return; } value[offset++] = byte; }
  need(FALSE);
}
#endif
