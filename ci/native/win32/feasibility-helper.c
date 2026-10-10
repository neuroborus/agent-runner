/* Separate Windows x64 CI experiment. No LocalSystem/account/WFP setup. */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")
#ifndef _WIN64
#error Matching Windows x64 compilation is required.
#endif

static HANDLE ownedJob;
static SRWLOCK jobLock = SRWLOCK_INIT;
static PSID userSid, appSid;
static WCHAR *userText, *appText;
static const WCHAR *root, *nonce;
static BOOL unreceiptedProfile;
static const WCHAR *role;
struct diagnosis { const char *operation, *domain; DWORD value; };
static struct diagnosis first_failure, cleanup_failure;
static SRWLOCK diagnosisLock = SRWLOCK_INIT;
static volatile LONG failing;
static void remember(const char *operation, const char *domain, DWORD value) {
  AcquireSRWLockExclusive(&diagnosisLock);
  if (!first_failure.operation) first_failure = (struct diagnosis){operation, domain, value};
  ReleaseSRWLockExclusive(&diagnosisLock);
}
static void cleanup_error(const char *operation, const char *domain, DWORD value) {
  AcquireSRWLockExclusive(&diagnosisLock);
  if (!cleanup_failure.operation) cleanup_failure = (struct diagnosis){operation, domain, value};
  ReleaseSRWLockExclusive(&diagnosisLock);
}
static BOOL close_job(BOOL emergency) {
  AcquireSRWLockExclusive(&jobLock); HANDLE job = ownedJob; ownedJob = NULL;
  BOOL ok = TRUE;
  if (job && emergency && !TerminateJobObject(job, 126)) {
    DWORD error = GetLastError(); remember("job-terminate", "win32", error); cleanup_error("job-terminate", "win32", error); ok = FALSE;
  }
  if (job && !CloseHandle(job)) {
    DWORD error = GetLastError(); remember("job-close", "win32", error); cleanup_error("job-close", "win32", error); ok = FALSE;
  }
  ReleaseSRWLockExclusive(&jobLock); return ok;
}
static void failure(DWORD code) {
  if (InterlockedCompareExchange(&failing, 1, 0)) ExitProcess(126);
  fprintf(stderr, "native-windows: operation=%s domain=%s value=%lu\n", first_failure.operation, first_failure.domain, first_failure.value);
  close_job(TRUE);
  if (unreceiptedProfile) {
    WCHAR profile[80]; swprintf_s(profile, 80, L"native.feasibility.%ls", nonce);
    HRESULT status = DeleteAppContainerProfile(profile);
    if (FAILED(status)) cleanup_error("profile-delete", "hresult", (DWORD)status);
  }
  AcquireSRWLockShared(&diagnosisLock); struct diagnosis cleanup = cleanup_failure; ReleaseSRWLockShared(&diagnosisLock);
  if (cleanup.operation)
    fprintf(stderr, "native-windows-cleanup: operation=%s domain=%s value=%lu\n", cleanup.operation, cleanup.domain, cleanup.value);
  ExitProcess(code);
}
static void invariant(BOOL ok, const char *operation) {
  if (!ok) { remember(operation, "invariant", 0); failure(126); }
}
/* A predicate has no GetLastError contract. Reached native calls use the
 * API-specific checks below, capturing their result before any cleanup. */
static void need(BOOL ok) { invariant(ok, "helper-invariant"); }
static void win32_check(BOOL ok, const char *operation) {
  if (!ok) { DWORD error = GetLastError(); remember(operation, "win32", error); failure(126); }
}
static void status_check(DWORD status, const char *operation) {
  if (status != ERROR_SUCCESS) { remember(operation, "win32", status); failure(126); }
}
static void nt_check(NTSTATUS status, const char *operation) {
  if (status < 0) { remember(operation, "ntstatus", (DWORD)status); failure(126); }
}
static void hresult_check(HRESULT status, const char *operation) {
  if (FAILED(status)) {
    remember(operation, "hresult", (DWORD)status);
    failure(status == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) || status == E_NOTIMPL ? 78 : 126);
  }
}
static DWORD WINAPI deadline(void *unused) {
  (void)unused; Sleep(90000); ExitProcess(124); /* Closure never supplies a PASS. */
  return 0;
}
static ULONGLONG number(const WCHAR *value) {
  WCHAR *end; ULONGLONG n = _wcstoui64(value, &end, 10);
  need(*value && wcsspn(value, L"0123456789") == wcslen(value) && !*end && n); return n;
}
static void name(WCHAR out[4096], const WCHAR *relative) { invariant(swprintf_s(out, 4096, L"%ls\\%ls", root, relative) > 0, "path-bound"); }
static void ack(char expected) { char value; DWORD size; win32_check(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &value, 1, &size, NULL), "ack-read"); invariant(size == 1 && value == expected, "ack-value"); }
static void *info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
  DWORD size = 0; BOOL queried = GetTokenInformation(token, kind, NULL, 0, &size); DWORD error = GetLastError();
  if (!queried && error != ERROR_INSUFFICIENT_BUFFER) {
    remember("token-size", "win32", error); failure(error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_SUPPORTED ? 78 : 126);
  }
  invariant(!queried && size && size <= 65536, "token-size");
  void *value = calloc(1, size); invariant(value != NULL, "token-allocation");
  win32_check(GetTokenInformation(token, kind, value, size, &size), "token-read"); return value;
}
static void principal(void) {
  HANDLE token; win32_check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "principal-token");
  TOKEN_USER *user = info(token, TokenUser); invariant(IsValidSid(user->User.Sid), "principal-sid"); userSid = malloc(GetLengthSid(user->User.Sid));
  invariant(userSid != NULL, "principal-allocation"); win32_check(CopySid(GetLengthSid(user->User.Sid), userSid, user->User.Sid), "principal-sid");
  win32_check(ConvertSidToStringSidW(userSid, &userText), "principal-sid");
  DWORD *container = info(token, TokenIsAppContainer); invariant(!*container, "principal-container"); free(container); free(user); win32_check(CloseHandle(token), "token-close");
}
static ULONGLONG creation(HANDLE process) {
  FILETIME c, e, k, u; win32_check(GetProcessTimes(process, &c, &e, &k, &u), "process-time");
  ULARGE_INTEGER time; time.LowPart = c.dwLowDateTime; time.HighPart = c.dwHighDateTime; return time.QuadPart;
}
static void identity(HANDLE process) {
  HANDLE token; win32_check(OpenProcessToken(process, TOKEN_QUERY, &token), "process-token"); TOKEN_USER *user = info(token, TokenUser);
  DWORD *session = info(token, TokenSessionId); WCHAR *sid;
  win32_check(ConvertSidToStringSidW(user->User.Sid, &sid), "process-sid");
  DWORD pid = GetProcessId(process); win32_check(pid != 0, "process-id");
  printf("{\"pid\":%lu,\"creationTime\":\"%llu\",\"sessionId\":%lu,\"userSid\":\"%ls\"}", pid, creation(process), *session, sid);
  free(user); free(session); LocalFree(sid); win32_check(CloseHandle(token), "token-close");
}
static void container(HANDLE process) {
  HANDLE token; win32_check(OpenProcessToken(process, TOKEN_QUERY, &token), "container-token");
  DWORD *active = info(token, TokenIsAppContainer); TOKEN_APPCONTAINER_INFORMATION *app = info(token, TokenAppContainerSid);
  TOKEN_GROUPS *caps = info(token, TokenCapabilities); TOKEN_USER *user = info(token, TokenUser);
  invariant(*active == 1 && app->TokenAppContainer && EqualSid(app->TokenAppContainer, appSid) && caps->GroupCount == 0 && EqualSid(user->User.Sid, userSid), "container-identity");
  free(active); free(app); free(caps); free(user); win32_check(CloseHandle(token), "token-close");
}
static PSECURITY_DESCRIPTOR descriptor(DWORD grant, BOOL directory) {
  WCHAR sddl[1024];
  if (grant) invariant(swprintf_s(sddl, 1024, L"O:%lsD:P(A;%ls;FA;;;%ls)(A;%ls;0x%08lx;;;%ls)", userText, directory ? L"OICI" : L"", userText, directory ? L"OICI" : L"", grant, appText) > 0, "security-descriptor");
  else invariant(swprintf_s(sddl, 1024, L"O:%lsD:P(A;%ls;FA;;;%ls)", userText, directory ? L"OICI" : L"", userText) > 0, "security-descriptor");
  PSECURITY_DESCRIPTOR sd; win32_check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL), "security-descriptor"); return sd;
}
static PSECURITY_DESCRIPTOR kernel_descriptor(void) {
  WCHAR sddl[512]; invariant(swprintf_s(sddl, 512, L"O:%lsD:P(A;;GA;;;%ls)", userText, userText) > 0, "security-descriptor");
  PSECURITY_DESCRIPTOR sd; win32_check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL), "security-descriptor"); return sd;
}
static void protect(const WCHAR *file, DWORD grant, BOOL directory) {
  PSECURITY_DESCRIPTOR sd = descriptor(grant, directory);
  need(SetFileSecurityW(file, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd)); LocalFree(sd);
}
static void acl(HANDLE object, SE_OBJECT_TYPE type, BOOL private) {
  PSID owner; PACL dacl; PSECURITY_DESCRIPTOR sd; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  status_check(GetSecurityInfo(object, type, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd), "acl-read");
  invariant(owner && IsValidSid(owner) && EqualSid(owner, userSid), "acl-owner");
  invariant(dacl && IsValidAcl(dacl), "acl-entries");
  win32_check(GetSecurityDescriptorControl(sd, &flags, &revision), "acl-control");
  invariant((flags & SE_DACL_PROTECTED) && dacl->AceCount == (private ? 1 : 2), "acl-entries");
  for (DWORD i = 0; i < dacl->AceCount; i++) {
    ACCESS_ALLOWED_ACE *ace; win32_check(GetAce(dacl, i, (void **)&ace), "acl-entry");
    invariant(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !(ace->Header.AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)), "acl-entry");
    invariant(EqualSid(&ace->SidStart, i == 0 ? userSid : appSid), "acl-sid");
    invariant(i ? (ace->Mask & (WRITE_DAC | WRITE_OWNER | DELETE)) == 0 : (ace->Mask == FILE_ALL_ACCESS || ace->Mask == GENERIC_ALL || (type == SE_KERNEL_OBJECT && (ace->Mask == JOB_OBJECT_ALL_ACCESS || ace->Mask == PROCESS_ALL_ACCESS || ace->Mask == THREAD_ALL_ACCESS))), "acl-mask");
  }
  LocalFree(sd);
}
static HANDLE file(const WCHAR *path, DWORD access) {
  HANDLE h = CreateFileW(path, access | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  win32_check(h != INVALID_HANDLE_VALUE, "file-open"); FILE_ATTRIBUTE_TAG_INFO tag;
  win32_check(GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof(tag)), "file-tag"); invariant(!(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "file-tag");
  WCHAR actual[4096]; DWORD size = GetFinalPathNameByHandleW(h, actual, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  win32_check(size != 0, "file-path"); invariant(size > 4 && size < 4096 && !wcsncmp(actual, L"\\\\?\\", 4) && !_wcsicmp(actual + 4, path), "file-path"); return h;
}
static void fileid(HANDLE h, char out[50]) {
  FILE_ID_INFO id; FILE_STANDARD_INFO standard;
  win32_check(GetFileInformationByHandleEx(h, FileIdInfo, &id, sizeof(id)), "file-id");
  win32_check(GetFileInformationByHandleEx(h, FileStandardInfo, &standard, sizeof(standard)), "file-shape");
  invariant(id.VolumeSerialNumber && !standard.DeletePending && (standard.Directory || standard.NumberOfLinks == 1), "file-shape");
  snprintf(out, 50, "%016llx:", id.VolumeSerialNumber); BYTE nonzero = 0;
  for (unsigned i = 0; i < 16; i++) { nonzero |= id.FileId.Identifier[i]; snprintf(out + 17 + i * 2, 3, "%02x", id.FileId.Identifier[i]); } invariant(nonzero, "file-id");
}
static void hashfile(HANDLE h, char out[65]) {
  LARGE_INTEGER length, zero = {0}; win32_check(GetFileSizeEx(h, &length), "file-size");
  invariant(length.QuadPart >= 0 && length.QuadPart <= 134217728, "file-size"); win32_check(SetFilePointerEx(h, zero, NULL, FILE_BEGIN), "file-seek");
  BCRYPT_ALG_HANDLE algorithm; BCRYPT_HASH_HANDLE hash;
  nt_check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0), "hash-open"); nt_check(BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0), "hash-create");
  BYTE bytes[8192], sum[32]; DWORD size; ULONGLONG total = 0;
  do { win32_check(ReadFile(h, bytes, sizeof(bytes), &size, NULL), "hash-read"); total += size; invariant(total <= (ULONGLONG)length.QuadPart, "file-size"); nt_check(BCryptHashData(hash, bytes, size, 0), "hash-update"); } while (size);
  invariant(total == (ULONGLONG)length.QuadPart, "file-size"); nt_check(BCryptFinishHash(hash, sum, 32, 0), "hash-final");
  for (unsigned i = 0; i < 32; i++) snprintf(out + 2*i, 3, "%02x", sum[i]); nt_check(BCryptDestroyHash(hash), "hash-close"); nt_check(BCryptCloseAlgorithmProvider(algorithm, 0), "hash-provider-close");
}
static void emitfile(const WCHAR *path, BOOL private) {
  HANDLE h = file(path, GENERIC_READ); acl(h, SE_FILE_OBJECT, private); char id[50], hash[65]; fileid(h, id);
  FILE_STANDARD_INFO standard; win32_check(GetFileInformationByHandleEx(h, FileStandardInfo, &standard, sizeof(standard)), "file-shape");
  printf("{\"identity\":\"%s\",\"private\":%s,\"sha256\":", id, private ? "true" : "false");
  if (standard.Directory) printf("null"); else { hashfile(h, hash); printf("\"%s\"", hash); } putchar('}'); win32_check(CloseHandle(h), "file-close");
}
struct profile_record { DWORD magic; WCHAR nonce[33], sid[184]; char rootId[50], intentHash[65]; };
static struct profile_record record;
static void recordio(const WCHAR *relative, void *bytes, DWORD size, BOOL write) {
  WCHAR path[4096]; name(path, relative);
  PSECURITY_DESCRIPTOR sd = descriptor(0, FALSE); SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
  HANDLE h = write ? CreateFileW(path, GENERIC_WRITE | READ_CONTROL, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL) : file(path, GENERIC_READ);
  win32_check(h != INVALID_HANDLE_VALUE, "receipt-open"); LocalFree(sd); acl(h, SE_FILE_OBJECT, TRUE); DWORD used;
  if (write) {
    win32_check(WriteFile(h, bytes, size, &used, NULL), "receipt-write"); invariant(used == size, "receipt-size"); win32_check(FlushFileBuffers(h), "receipt-flush");
  } else {
    LARGE_INTEGER length; win32_check(GetFileSizeEx(h, &length), "receipt-size"); invariant(length.QuadPart == size, "receipt-size");
    win32_check(ReadFile(h, bytes, size, &used, NULL), "receipt-read"); invariant(used == size, "receipt-size");
  }
  win32_check(CloseHandle(h), "receipt-close");
}
static void profile_name(WCHAR out[80]) { invariant(swprintf_s(out, 80, L"native.feasibility.%ls", nonce) > 0, "profile-name"); }
static void derive(void) {
  WCHAR profile[80]; profile_name(profile); HRESULT hr = DeriveAppContainerSidFromAppContainerName(profile, &appSid);
  hresult_check(hr, "profile-derive"); win32_check(ConvertSidToStringSidW(appSid, &appText), "profile-sid");
}
static LONG mapping(HKEY *key) {
  WCHAR path[512]; need(swprintf_s(path, 512, L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings\\%ls", appText) > 0);
  return RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_READ, key);
}
static void profile_observe(void) {
  HKEY key; need(mapping(&key) == ERROR_SUCCESS); WCHAR actual[80], expected[80]; DWORD type, size = sizeof(actual); profile_name(expected);
  need(RegQueryValueExW(key, L"Moniker", NULL, &type, (BYTE *)actual, &size) == ERROR_SUCCESS && type == REG_SZ && size >= 2 && size <= sizeof(actual) && actual[size / 2 - 1] == 0 && !_wcsicmp(actual, expected) && RegCloseKey(key) == ERROR_SUCCESS);
  printf("{\"profileObserved\":true,\"sid\":\"%ls\"}\n", appText);
}
static void owned_profile(void) {
  recordio(L"control\\profile.bin", &record, sizeof(record), FALSE);
  invariant(record.nonce[32] == 0 && record.sid[183] == 0 && record.rootId[49] == 0 && record.intentHash[64] == 0, "profile-receipt");
  HANDLE h = file(root, 0); char id[50]; fileid(h, id); win32_check(CloseHandle(h), "file-close");
  invariant(record.magic == 0x4e463031 && !wcscmp(record.nonce, nonce) && !wcscmp(record.sid, appText) && !strcmp(record.rootId, id), "profile-binding");
  WCHAR path[4096]; name(path, L"control\\intent.json"); h = file(path, GENERIC_READ); acl(h, SE_FILE_OBJECT, TRUE); char pin[65]; hashfile(h, pin); invariant(!strcmp(pin, record.intentHash), "profile-intent"); win32_check(CloseHandle(h), "file-close");
}
static void profile_create(const WCHAR *pin) {
  WCHAR path[4096], profile[80]; name(path, L"control\\intent.json"); HANDLE intent = file(path, GENERIC_READ); acl(intent, SE_FILE_OBJECT, TRUE);
  char hash[65]; hashfile(intent, hash); need(wcslen(pin) == 64);
  for (unsigned i = 0; i < 64; i++) need(pin[i] == hash[i]); need(CloseHandle(intent));
  HANDLE base = file(root, 0); acl(base, SE_FILE_OBJECT, TRUE); fileid(base, record.rootId); need(CloseHandle(base));
  profile_name(profile); PSID created = NULL;
  HKEY key; LONG existing = mapping(&key);
  if (existing == ERROR_SUCCESS) { RegCloseKey(key); puts("{\"created\":false,\"profileUnowned\":true}"); ExitProcess(78); }
  if (existing == ERROR_ACCESS_DENIED || existing == ERROR_NOT_SUPPORTED) { puts("{\"created\":false,\"profileUnowned\":true}"); ExitProcess(78); }
  need(existing == ERROR_FILE_NOT_FOUND);
  HRESULT hr = CreateAppContainerProfile(profile, profile, L"Bounded native experiment", NULL, 0, &created);
  if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) { puts("{\"created\":false,\"profileUnowned\":true}"); ExitProcess(78); }
  if (hr == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) || hr == E_NOTIMPL || hr == E_ACCESSDENIED) ExitProcess(78);
  need(SUCCEEDED(hr) && created && EqualSid(created, appSid)); unreceiptedProfile = TRUE; FreeSid(created);
  record.magic = 0x4e463031; wcscpy_s(record.nonce, 33, nonce); wcscpy_s(record.sid, 184, appText); strcpy_s(record.intentHash, 65, hash);
  /* A crash before this durable receipt leaves exclusion, never deletion authority. */
  recordio(L"control\\profile.bin", &record, sizeof(record), TRUE);
  unreceiptedProfile = FALSE;
  printf("{\"created\":true,\"sid\":\"%ls\"}\n", appText);
}
static unsigned treeEntries;
static void grant_tree(const WCHAR *path, DWORD rights) {
  need(++treeEntries <= 512);
  DWORD attr = GetFileAttributesW(path); need(attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_REPARSE_POINT));
  BOOL directory = !!(attr & FILE_ATTRIBUTE_DIRECTORY); protect(path, rights, directory);
  if (directory) {
    WCHAR pattern[4096]; need(swprintf_s(pattern, 4096, L"%ls\\*", path) > 0); WIN32_FIND_DATAW entry; HANDLE scan = FindFirstFileW(pattern, &entry); need(scan != INVALID_HANDLE_VALUE);
    unsigned count = 0;
    do { if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue; need(++count <= 256);
      WCHAR child[4096]; need(swprintf_s(child, 4096, L"%ls\\%ls", path, entry.cFileName) > 0); grant_tree(child, rights);
    } while (FindNextFileW(scan, &entry)); need(GetLastError() == ERROR_NO_MORE_FILES && FindClose(scan));
  }
}
static void grants(BOOL editing) {
  owned_profile(); WCHAR path[4096];
  protect(root, FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FALSE);
  name(path, L"build"); grant_tree(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
  name(path, L"workspace"); grant_tree(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
  name(path, L"workspace\\edited.txt"); protect(path, FILE_GENERIC_READ | (editing ? FILE_GENERIC_WRITE : 0), FALSE);
  puts("{\"granted\":true}");
}
static void append(WCHAR *line, size_t *offset, WCHAR value) { invariant(*offset < 32766, "argv-bound"); line[(*offset)++] = value; line[*offset] = 0; }
/* Same literal UCRT quoting recipe as launcher.c; no shell interpretation. */
static void argument(WCHAR *line, size_t *offset, const WCHAR *value) {
  if (*offset) append(line, offset, L' '); append(line, offset, L'"'); size_t slashes = 0;
  for (size_t i = 0;; i++) { if (value[i] == L'\\') { slashes++; continue; }
    if (!value[i] || value[i] == L'"') slashes *= 2;
    while (slashes) { append(line, offset, L'\\'); slashes--; } if (!value[i]) break;
    if (value[i] == L'"') append(line, offset, L'\\'); append(line, offset, value[i]); }
  append(line, offset, L'"');
}
static HANDLE original(DWORD pid, ULONGLONG time, DWORD rights) {
  HANDLE h = OpenProcess(rights | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
  win32_check(h != NULL, "process-open"); invariant(creation(h) == time, "process-time"); WCHAR image[4096], self[4096]; DWORD size = 4096;
  win32_check(QueryFullProcessImageNameW(h, 0, image, &size), "process-image"); invariant(size < 4096, "process-image");
  DWORD selfSize = GetModuleFileNameW(NULL, self, 4096); win32_check(selfSize != 0, "process-image");
  invariant(selfSize < 4096 && !_wcsicmp(image, self), "process-image"); return h;
}
static HANDLE duplicate(HANDLE source, const WCHAR *raw, DWORD access) {
  HANDLE h; win32_check(DuplicateHandle(source, (HANDLE)(ULONG_PTR)number(raw), GetCurrentProcess(), &h, access, FALSE, 0), "handle-duplicate"); return h;
}
static void limits(HANDLE job) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION value; win32_check(QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &value, sizeof(value), NULL), "job-query");
  invariant(value.BasicLimitInformation.LimitFlags == (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS) && value.BasicLimitInformation.ActiveProcessLimit == 8, "job-limits");
  acl(job, SE_KERNEL_OBJECT, TRUE);
}
static HANDLE members[8]; static unsigned memberCount;
static void census(HANDLE job) {
  union { JOBOBJECT_BASIC_PROCESS_ID_LIST alignment; BYTE bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 8 * sizeof(ULONG_PTR)]; } storage;
  JOBOBJECT_BASIC_PROCESS_ID_LIST *list = (void *)storage.bytes;
  need(QueryInformationJobObject(job, JobObjectBasicProcessIdList, list, sizeof(storage), NULL) && list->NumberOfAssignedProcesses == list->NumberOfProcessIdsInList && list->NumberOfProcessIdsInList <= 8);
  memberCount = list->NumberOfProcessIdsInList;
  for (unsigned i = 0; i < memberCount; i++) { need(list->ProcessIdList[i] && list->ProcessIdList[i] <= MAXDWORD);
    members[i] = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, (DWORD)list->ProcessIdList[i]); BOOL admitted;
    need(members[i] && IsProcessInJob(members[i], job, &admitted) && admitted); container(members[i]); }
}
struct settled_record { DWORD magic, count, pid[8]; ULONGLONG time[8]; WCHAR nonce[33]; };
struct launch_intent { DWORD magic, pid; ULONGLONG time; WCHAR nonce[33]; };
static void assert_retired(DWORD pid, ULONGLONG time) {
  need(pid && time); HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
  if (h) { need(creation(h) != time || WaitForSingleObject(h, 0) == WAIT_OBJECT_0); need(CloseHandle(h)); }
  else need(GetLastError() == ERROR_INVALID_PARAMETER);
}
static void done(const WCHAR *caseId) {
  struct settled_record value = {0}; value.magic = 0x4e46444e; value.count = memberCount; wcscpy_s(value.nonce, 33, nonce);
  for (unsigned i = 0; i < memberCount; i++) { need(WaitForSingleObject(members[i], 8000) == WAIT_OBJECT_0); value.pid[i] = GetProcessId(members[i]); value.time[i] = creation(members[i]); }
  WCHAR path[128]; need(swprintf_s(path, 128, L"control\\%ls.done", caseId) > 0); recordio(path, &value, sizeof(value), TRUE);
}
static DWORD WINAPI forward(void *parameter) {
  HANDLE pipe = parameter; BYTE bytes[4096]; DWORD size, used, total = 0;
  while (ReadFile(pipe, bytes, sizeof(bytes), &size, NULL) && size) { total += size; need(total <= 65536 && WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), bytes, size, &used, NULL) && used == size); }
  need(GetLastError() == ERROR_BROKEN_PIPE && CloseHandle(pipe)); return 0;
}
static void launch(int argc, WCHAR **argv) {
  owned_profile(); const WCHAR *caseId = argv[4], *image = argv[5];
  BOOL isArgv = !wcscmp(caseId, L"argv"); invariant(isArgv || !wcscmp(caseId, L"read") || !wcscmp(caseId, L"edit") || !wcscmp(caseId, L"cancel") || !wcscmp(caseId, L"owner-loss") || !wcscmp(caseId, L"final-handle-close"), "launch-case");
  WCHAR expected[4096]; name(expected, isArgv ? L"build\\argv-fixture.exe" : L"build\\helper.exe"); invariant(!_wcsicmp(image, expected), "launch-image");
  HANDLE executable = CreateFileW(image, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL); win32_check(executable != INVALID_HANDLE_VALUE, "executable-open");
  FILE_ATTRIBUTE_TAG_INFO tag; win32_check(GetFileInformationByHandleEx(executable, FileAttributeTagInfo, &tag, sizeof(tag)), "executable-tag");
  invariant(!(tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)), "executable-tag"); acl(executable, SE_FILE_OBJECT, FALSE);
  PSECURITY_DESCRIPTOR sd = kernel_descriptor(); SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
  ownedJob = CreateJobObjectW(&sa, NULL); win32_check(ownedJob != NULL, "job-create"); JOBOBJECT_EXTENDED_LIMIT_INFORMATION bounds = {0};
  bounds.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS; bounds.BasicLimitInformation.ActiveProcessLimit = 8;
  win32_check(SetInformationJobObject(ownedJob, JobObjectExtendedLimitInformation, &bounds, sizeof(bounds)), "job-config"); limits(ownedJob);
  HANDLE in, write, read, out; sa.bInheritHandle = TRUE;
  win32_check(CreatePipe(&in, &write, &sa, 0), "stdin-pipe"); win32_check(CreatePipe(&read, &out, &sa, 0), "stdout-pipe");
  win32_check(SetHandleInformation(write, HANDLE_FLAG_INHERIT, 0), "stdin-inherit"); win32_check(SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0), "stdout-inherit");
  SECURITY_CAPABILITIES capabilities = {0}; capabilities.AppContainerSid = appSid;
  SIZE_T size = 0; BOOL sized = InitializeProcThreadAttributeList(NULL, 3, 0, &size); DWORD sizeError = GetLastError();
  if (!sized && sizeError != ERROR_INSUFFICIENT_BUFFER) { remember("attribute-size", "win32", sizeError); failure(126); }
  invariant(!sized && size && size <= 65536, "attribute-size");
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = malloc(size); HANDLE handles[] = {in, out};
  invariant(attributes != NULL, "attribute-allocation"); win32_check(InitializeProcThreadAttributeList(attributes, 3, 0, &size), "attribute-init");
  win32_check(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities), NULL, NULL), "attribute-security");
  win32_check(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &ownedJob, sizeof(ownedJob), NULL, NULL), "attribute-job");
  win32_check(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), NULL, NULL), "attribute-handles");
  WCHAR line[32767] = {0}, workspace[4096], windows[4096], environment[8192] = {0}; size_t offset = 0;
  argument(line, &offset, image); for (int i = 6; i < argc; i++) argument(line, &offset, argv[i]); name(workspace, L"workspace");
  UINT windowsSize = GetWindowsDirectoryW(windows, 4096); win32_check(windowsSize != 0, "windows-directory"); invariant(windowsSize < 4096, "windows-directory");
  int n = swprintf_s(environment, 8192, L"GIT_CONFIG_GLOBAL=NUL"); invariant(n > 0, "environment-bound"); size_t at = (size_t)n + 1;
  const WCHAR *pairs[] = {L"GIT_CONFIG_NOSYSTEM=1", L"GIT_OPTIONAL_LOCKS=0", L"GIT_TERMINAL_PROMPT=0"};
  for (unsigned i = 0; i < 3; i++) { invariant(at < 8192, "environment-bound"); n = swprintf_s(environment + at, 8192 - at, L"%ls", pairs[i]); invariant(n > 0, "environment-bound"); at += n + 1; }
  invariant(at < 8192, "environment-bound"); n = swprintf_s(environment + at, 8192 - at, L"SystemRoot=%ls", windows); invariant(n > 0, "environment-bound"); at += n + 1; invariant(at < 8192, "environment-bound"); environment[at] = 0;
  STARTUPINFOEXW startup = {0}; startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes; startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = in; startup.StartupInfo.hStdOutput = out; startup.StartupInfo.hStdError = out;
  PROCESS_INFORMATION child = {0};
  sa.bInheritHandle = FALSE;
  WCHAR recordName[128]; invariant(swprintf_s(recordName, 128, L"control\\%ls.intent", caseId) > 0, "launch-intent");
  struct launch_intent intent = {0}; intent.magic = 0x4e46494e; intent.pid = GetCurrentProcessId(); intent.time = creation(GetCurrentProcess()); wcscpy_s(intent.nonce, 33, nonce);
  recordio(recordName, &intent, sizeof(intent), TRUE);
  if (!CreateProcessW(image, line, &sa, &sa, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
      environment, workspace, &startup.StartupInfo, &child)) { DWORD error = GetLastError(); JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account;
    remember("process-create", "win32", error);
    invariant(!child.hProcess && !child.hThread, "launch-absence"); win32_check(QueryInformationJobObject(ownedJob, JobObjectBasicAccountingInformation, &account, sizeof(account), NULL), "launch-accounting"); invariant(!account.TotalProcesses && !account.ActiveProcesses, "launch-absence");
    ULONGLONG absent[] = {0, 0}; need(swprintf_s(recordName, 128, L"control\\%ls.launch", caseId) > 0); recordio(recordName, absent, sizeof(absent), TRUE); done(caseId);
    need(close_job(FALSE)); failure(error == ERROR_NOT_SUPPORTED || error == ERROR_PRIVILEGE_NOT_HELD ? 78 : 126); }
  DeleteProcThreadAttributeList(attributes); free(attributes); LocalFree(sd); win32_check(CloseHandle(in), "pipe-close"); win32_check(CloseHandle(out), "pipe-close");
  container(child.hProcess); BOOL member; win32_check(IsProcessInJob(child.hProcess, ownedJob, &member), "process-job"); invariant(member, "process-job");
  WCHAR actual[4096]; DWORD actualSize = 4096; win32_check(QueryFullProcessImageNameW(child.hProcess, 0, actual, &actualSize), "process-image"); invariant(actualSize < 4096 && !_wcsicmp(actual, image), "process-image");
  need(swprintf_s(recordName, 128, L"control\\%ls.launch", caseId) > 0);
  ULONGLONG times[] = {GetProcessId(child.hProcess), creation(child.hProcess)}; recordio(recordName, times, sizeof(times), TRUE);
  printf("{\"event\":\"suspended\",\"owner\":"); identity(GetCurrentProcess()); printf(",\"child\":"); identity(child.hProcess);
  printf(",\"job\":\"%llu\",\"process\":\"%llu\",\"thread\":\"%llu\",\"sid\":\"%ls\",\"image\":", (ULONGLONG)(ULONG_PTR)ownedJob, (ULONGLONG)(ULONG_PTR)child.hProcess, (ULONGLONG)(ULONG_PTR)child.hThread, appText); emitfile(image, FALSE); puts("}"); fflush(stdout);
  ack('R'); DWORD suspended = ResumeThread(child.hThread); win32_check(suspended != (DWORD)-1, "process-release"); invariant(suspended == 1, "process-release"); win32_check(CloseHandle(child.hThread), "thread-close");
  HANDLE writer = CreateThread(NULL, 0, forward, read, 0, NULL); need(writer);
  char command; DWORD used;
  while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), &command, 1, &used, NULL) && used) {
    if (command == 'Q') { need(close_job(FALSE)); need(CloseHandle(write) && WaitForSingleObject(child.hProcess, 8000) == WAIT_OBJECT_0 && WaitForSingleObject(writer, 8000) == WAIT_OBJECT_0);
      need(CloseHandle(writer) && CloseHandle(child.hProcess) && CloseHandle(executable)); puts("{\"event\":\"closed\"}"); return; }
    DWORD sent; need(WriteFile(write, &command, 1, &sent, NULL) && sent == 1);
  }
  need(0); /* Unacknowledged owner loss retains unsettled cleanup. */
}
static void observe(WCHAR **args, BOOL suspended, BOOL terminate, BOOL watch, BOOL final) {
  owned_profile(); HANDLE source = original((DWORD)number(args[0]), number(args[1]), PROCESS_DUP_HANDLE | (watch && !final ? PROCESS_TERMINATE : 0));
  HANDLE job = duplicate(source, args[2], JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE | READ_CONTROL);
  HANDLE child = duplicate(source, args[3], PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | READ_CONTROL);
  invariant(creation(child) == number(args[4]), "process-time"); limits(job); BOOL member;
  win32_check(IsProcessInJob(child, job, &member), "process-job"); invariant(member, "process-job");
  win32_check(IsProcessInJob(GetCurrentProcess(), job, &member), "process-job"); invariant(!member, "process-job");
  DWORD wait = WaitForSingleObject(child, 0); win32_check(wait != WAIT_FAILED, "process-wait");
  invariant(wait == WAIT_TIMEOUT || wait == WAIT_OBJECT_0, "process-wait");
  if (wait == WAIT_TIMEOUT) container(child);
  else invariant(!suspended && !watch && !terminate, "process-wait");
  if (suspended) {
    acl(child, SE_KERNEL_OBJECT, TRUE);
    WCHAR expected[4096], actual[4096]; DWORD size = 4096; name(expected, !wcscmp(args[6], L"argv") ? L"build\\argv-fixture.exe" : L"build\\helper.exe");
    win32_check(QueryFullProcessImageNameW(child, 0, actual, &size), "process-image"); invariant(size < 4096 && !_wcsicmp(actual, expected), "process-image");
    HANDLE thread = duplicate(source, args[5], THREAD_QUERY_INFORMATION | READ_CONTROL); acl(thread, SE_KERNEL_OBJECT, TRUE); typedef LONG (WINAPI *query)(HANDLE, ULONG, void *, ULONG, ULONG *);
    HMODULE module = GetModuleHandleW(L"ntdll.dll"); win32_check(module != NULL, "thread-query");
    query get = (query)GetProcAddress(module, "NtQueryInformationThread"); ULONG count;
    if (!get) { DWORD error = GetLastError(); remember("thread-query", "win32", error); failure(78); }
    LONG status = get(thread, 35, &count, sizeof(count), NULL);
    if (status == (LONG)0xc0000003) { remember("thread-query", "ntstatus", (DWORD)status); failure(78); }
    nt_check(status, "thread-query"); invariant(status == 0 && count == 1, "thread-state");
    DWORD threadPid = GetProcessIdOfThread(thread); win32_check(threadPid != 0, "thread-process");
    DWORD childPid = GetProcessId(child); win32_check(childPid != 0, "process-id");
    invariant(threadPid == childPid, "thread-process"); win32_check(CloseHandle(thread), "thread-close");
    printf("{\"admitted\":true,\"suspended\":true,\"capabilities\":0,\"sid\":\"%ls\",\"child\":", appText); identity(child); printf(",\"verifier\":"); identity(GetCurrentProcess()); printf(",\"image\":"); emitfile(actual, FALSE); puts("}");
  } else {
    census(job); need(memberCount <= 2);
    if (watch) {
      need(memberCount == 2);
      if (final) { HANDLE observation; need(DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &observation, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0) && CloseHandle(source) && CloseHandle(job)); source = observation; job = NULL; }
      printf("{\"event\":\"witness-ready\",\"owner\":"); identity(GetCurrentProcess());
      printf(",\"job\":\"%llu\",\"process\":\"%llu\",\"child\":", (ULONGLONG)(ULONG_PTR)job, (ULONGLONG)(ULONG_PTR)child); identity(child);
      printf(",\"jobHeld\":%s,\"members\":[", final ? "false" : "true");
      for (unsigned i = 0; i < memberCount; i++) { if (i) putchar(','); identity(members[i]); } puts("]}"); fflush(stdout);
      ack('A');
      if (final) { ack('W'); done(args[6]); puts("{\"retired\":true,\"jobHeld\":false}"); }
      else { need(TerminateProcess(source, 125) && WaitForSingleObject(source, 8000) == WAIT_OBJECT_0); puts("{\"event\":\"owner-lost\"}"); fflush(stdout); ack('W'); }
    } else {
      if (terminate) { need(memberCount == 2); printf("{\"event\":\"recovery-ready\",\"verifier\":"); identity(GetCurrentProcess()); printf(",\"members\":[");
        for (unsigned i = 0; i < memberCount; i++) { if (i) putchar(','); identity(members[i]); } puts("]}"); ack('A'); need(TerminateJobObject(job, 137)); }
      if (!memberCount) { members[0] = child; memberCount = 1; }
      for (unsigned i = 0; i < memberCount; i++) need(WaitForSingleObject(members[i], 8000) == WAIT_OBJECT_0);
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account;
      need(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &account, sizeof(account), NULL) && !account.ActiveProcesses);
      if (!terminate) { DWORD exitCode; need(GetExitCodeProcess(child, &exitCode) && !exitCode); }
      done(args[6]);
      puts("{\"retired\":true,\"jobEmpty\":true}");
    }
    for (unsigned i = 0; i < memberCount; i++) if (members[i] != child) need(CloseHandle(members[i]));
  }
  if (job) win32_check(CloseHandle(job), "job-close"); win32_check(CloseHandle(child), "process-close"); win32_check(CloseHandle(source), "process-close");
}
static int connection(BOOL tcp, const WCHAR *address, const WCHAR *value) {
  char text[33]; need(wcslen(value) == 32); for (unsigned i = 0; i < 32; i++) text[i] = (char)value[i]; text[32] = 0;
  if (tcp) {
    SOCKET socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); if (socket == INVALID_SOCKET) return WSAGetLastError();
    DWORD timeout = 5000; need(!setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) && !setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)));
    struct sockaddr_in endpoint = {0}; endpoint.sin_family = AF_INET; endpoint.sin_port = htons((u_short)number(address)); endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socket, (struct sockaddr *)&endpoint, sizeof(endpoint))) { int error = WSAGetLastError(); closesocket(socket); return error; }
    need(send(socket, text, 32, 0) == 32); char reply[32]; int at = 0; while (at < 32) { int n = recv(socket, reply + at, 32 - at, 0); need(n > 0); at += n; }
    need(!memcmp(reply, text, 32) && !closesocket(socket)); return 0;
  }
  HANDLE pipe = CreateFileW(address, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); if (pipe == INVALID_HANDLE_VALUE) return (int)GetLastError();
  char reply[32]; DWORD used, at = 0; need(WriteFile(pipe, text, 32, &used, NULL) && used == 32);
  while (at < 32) { need(ReadFile(pipe, reply + at, 32 - at, &used, NULL) && used); at += used; }
  need(!memcmp(reply, text, 32) && CloseHandle(pipe)); return 0;
}
static void attempt(const char *operation) { printf("{\"event\":\"attempt\",\"operation\":\"%s\"}\n", operation); fflush(stdout); }
static void receipt(const char *operation, DWORD error) { printf("{\"event\":\"completed\",\"operation\":\"%s\",\"error\":%lu}\n", operation, error); fflush(stdout); }
static void write_attempt(const char *operation, const WCHAR *relative, BOOL create) {
  WCHAR path[4096]; name(path, relative); attempt(operation);
  HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, create ? CREATE_NEW : OPEN_EXISTING, 0, NULL); DWORD error = h == INVALID_HANDLE_VALUE ? GetLastError() : 0;
  if (h != INVALID_HANDLE_VALUE) { char bytes[32]; for (unsigned i = 0; i < 32; i++) bytes[i] = (char)nonce[i]; DWORD size; need(WriteFile(h, bytes, 32, &size, NULL) && size == 32 && SetEndOfFile(h) && CloseHandle(h)); } receipt(operation, error);
}
static void write_controls(void) {
  owned_profile(); const WCHAR *paths[] = {L"workspace\\edited.txt", L"workspace\\.git\\index", L"workspace\\.git\\refs\\heads\\fixture", L"control\\sentinel", L"outside\\sentinel"};
  for (unsigned i = 0; i < 5; i++) { WCHAR path[4096]; name(path, paths[i]); HANDLE h = file(path, GENERIC_READ | GENERIC_WRITE); acl(h, SE_FILE_OBJECT, i >= 3);
    LARGE_INTEGER length, zero = {0}; need(GetFileSizeEx(h, &length) && length.QuadPart > 0 && length.QuadPart <= 65536); BYTE bytes[65536]; DWORD used;
    need(ReadFile(h, bytes, (DWORD)length.QuadPart, &used, NULL) && used == length.QuadPart && SetFilePointerEx(h, zero, NULL, FILE_BEGIN) && WriteFile(h, bytes, used, &used, NULL) && used == length.QuadPart && FlushFileBuffers(h) && CloseHandle(h)); }
  WCHAR lock[4096]; name(lock, L"workspace\\.git\\index.lock"); PSECURITY_DESCRIPTOR sd = descriptor(0, FALSE); SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
  HANDLE h = CreateFileW(lock, GENERIC_WRITE | DELETE, 0, &sa, CREATE_NEW, 0, NULL); LocalFree(sd); FILE_DISPOSITION_INFO disposition = {TRUE};
  need(h != INVALID_HANDLE_VALUE && SetFileInformationByHandle(h, FileDispositionInfo, &disposition, sizeof(disposition)) && CloseHandle(h)); puts("{\"writesReady\":true,\"indexMutationReady\":true}");
}
static void bundle(const WCHAR *port, const WCHAR *pipe) {
  puts("{\"event\":\"ready\"}"); ack('A'); attempt("inspect"); WCHAR path[4096]; name(path, L"workspace\\inspection.txt");
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); char bytes[32]; DWORD used;
  need(h != INVALID_HANDLE_VALUE && ReadFile(h, bytes, 32, &used, NULL) && used == 32 && CloseHandle(h));
  for (unsigned i = 0; i < 32; i++) need(bytes[i] == (char)nonce[i]); receipt("inspect", 0);
  write_attempt("edit", L"workspace\\edited.txt", FALSE); attempt("git-status");
  WCHAR git[4096], line[8192]; name(git, L"build\\git.exe"); need(swprintf_s(line, 8192, L"\"%ls\" -c core.fsmonitor=false status --porcelain", git) > 0);
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE}; HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL), output = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
  need(input != INVALID_HANDLE_VALUE && output != INVALID_HANDLE_VALUE); SIZE_T size = 0; InitializeProcThreadAttributeList(NULL, 1, 0, &size); need(size && size <= 65536);
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = malloc(size); HANDLE allow[] = {input, output};
  need(attributes && InitializeProcThreadAttributeList(attributes, 1, 0, &size) && UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, allow, sizeof(allow), NULL, NULL));
  STARTUPINFOEXW startup = {0}; startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes; startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES; startup.StartupInfo.hStdInput = input; startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = output;
  PROCESS_INFORMATION child; need(CreateProcessW(git, line, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &startup.StartupInfo, &child));
  DeleteProcThreadAttributeList(attributes); free(attributes); need(CloseHandle(input) && CloseHandle(output));
  need(WaitForSingleObject(child.hProcess, 8000) == WAIT_OBJECT_0); DWORD code; need(GetExitCodeProcess(child.hProcess, &code) && code == 0 && CloseHandle(child.hThread) && CloseHandle(child.hProcess)); receipt("git-status", 0);
  write_attempt("git-index", L"workspace\\.git\\index.lock", TRUE); write_attempt("git-ref", L"workspace\\.git\\refs\\heads\\fixture", FALSE);
  write_attempt("control", L"control\\sentinel", FALSE); write_attempt("outside", L"outside\\sentinel", FALSE);
  attempt("tcp"); receipt("tcp", connection(TRUE, port, nonce)); attempt("pipe"); receipt("pipe", connection(FALSE, pipe, nonce));
}
static void fault(void) {
  WCHAR image[4096], line[8192]; need(GetModuleFileNameW(NULL, image, 4096));
  need(swprintf_s(line, 8192, L"\"%ls\" park", image) > 0); STARTUPINFOW startup = {0}; startup.cb = sizeof(startup); PROCESS_INFORMATION child;
  need(CreateProcessW(image, line, NULL, NULL, FALSE, DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &startup, &child));
  printf("{\"event\":\"fault-ready\",\"descendant\":"); identity(child.hProcess); puts("}"); fflush(stdout);
  ack('F'); puts("{\"event\":\"fault-ack\"}"); fflush(stdout); Sleep(INFINITE);
}
static HANDLE storage_parent(void) {
  WCHAR path[4096]; name(path, L"storage"); HANDLE h = CreateFileW(path, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  FILE_ATTRIBUTE_TAG_INFO tag; WCHAR actual[4096]; DWORD size;
  need(h != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof(tag)) && (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
  size = GetFinalPathNameByHandleW(h, actual, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS); need(size > 4 && size < 4096 && !wcsncmp(actual, L"\\\\?\\", 4) && !_wcsicmp(actual + 4, path)); acl(h, SE_FILE_OBJECT, TRUE); return h;
}
static void storage(void) {
  owned_profile(); WCHAR parent[4096], leaf[4096], saved[4096]; name(parent, L"storage"); name(leaf, L"storage\\leaf"); name(saved, L"storage\\saved");
  HANDLE owner = storage_parent(); char parentId[50]; fileid(owner, parentId);
  PSECURITY_DESCRIPTOR sd = descriptor(0, FALSE); SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
  HANDLE held = CreateFileW(leaf, GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa, CREATE_NEW, 0, NULL); LocalFree(sd); need(held != INVALID_HANDLE_VALUE);
  DWORD used; need(WriteFile(held, "owned", 5, &used, NULL) && used == 5 && FlushFileBuffers(held)); acl(held, SE_FILE_OBJECT, TRUE); char id[50]; fileid(held, id);
  printf("{\"event\":\"allocated\",\"identity\":\"%s\",\"parent\":\"%s\",\"owner\":", id, parentId); identity(GetCurrentProcess()); puts("}"); fflush(stdout);
  char command; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &command, 1, &used, NULL) && used == 1 && (command == 'N' || command == 'S'));
  HANDLE named = file(leaf, GENERIC_READ); acl(named, SE_FILE_OBJECT, TRUE); char actual[50]; fileid(named, actual); need(CloseHandle(named));
  if (command == 'N') { need(!strcmp(actual, id)); FILE_DISPOSITION_INFO disposition = {TRUE}; need(SetFileInformationByHandle(held, FileDispositionInfo, &disposition, sizeof(disposition))); }
  else need(strcmp(actual, id));
  printf("{\"event\":\"cleanup\",\"removed\":%s}\n", command == 'N' ? "true" : "false"); need(CloseHandle(held) && CloseHandle(owner));
}
static void remove_owned(const WCHAR *relative, const WCHAR *expected, const WCHAR *expectedParent) {
  owned_profile(); need(!wcscmp(relative, L"storage\\leaf") || !wcscmp(relative, L"storage\\saved"));
  HANDLE authority = storage_parent(); char parentId[50]; fileid(authority, parentId); need(wcslen(expectedParent) == 49); for (unsigned i = 0; i < 49; i++) need(expectedParent[i] == parentId[i]);
  WCHAR path[4096]; name(path, relative); HANDLE h = file(path, DELETE); acl(h, SE_FILE_OBJECT, TRUE); char id[50]; fileid(h, id); need(wcslen(expected) == 49);
  for (unsigned i = 0; i < 49; i++) need(expected[i] == id[i]); FILE_DISPOSITION_INFO disposition = {TRUE}; need(SetFileInformationByHandle(h, FileDispositionInfo, &disposition, sizeof(disposition)) && CloseHandle(h) && CloseHandle(authority)); puts("{\"removed\":true}");
}
static void profile_delete(void) {
  owned_profile(); WCHAR pattern[4096]; name(pattern, L"control\\*.intent"); WIN32_FIND_DATAW entry; HANDLE scan = FindFirstFileW(pattern, &entry);
  if (scan != INVALID_HANDLE_VALUE) {
    unsigned count = 0;
    do { need(++count <= 6); WCHAR relative[128]; need(swprintf_s(relative, 128, L"control\\%ls", entry.cFileName) > 0);
      struct launch_intent intent; recordio(relative, &intent, sizeof(intent), FALSE);
      need(intent.magic == 0x4e46494e && intent.nonce[32] == 0 && !wcscmp(intent.nonce, nonce)); assert_retired(intent.pid, intent.time);
      WCHAR *dot = wcsrchr(relative, L'.'); need(dot && !wcscmp(dot, L".intent")); wcscpy_s(dot, 8, L".launch");
      ULONGLONG child[2]; recordio(relative, child, sizeof(child), FALSE);
      wcscpy_s(dot, 6, L".done");
      struct settled_record settled; recordio(relative, &settled, sizeof(settled), FALSE); need(settled.magic == 0x4e46444e && settled.count <= 8 && settled.nonce[32] == 0 && !wcscmp(settled.nonce, nonce));
      need(child[0] <= MAXDWORD && (child[0] ? child[1] && settled.count : !child[1] && !settled.count));
      BOOL matched = !child[0];
      for (unsigned i = 0; i < settled.count; i++) {
        matched |= settled.pid[i] == child[0] && settled.time[i] == child[1];
        assert_retired(settled.pid[i], settled.time[i]);
      } need(matched);
    } while (FindNextFileW(scan, &entry)); need(GetLastError() == ERROR_NO_MORE_FILES && FindClose(scan));
  } else need(GetLastError() == ERROR_FILE_NOT_FOUND);
  name(pattern, L"storage\\*"); scan = FindFirstFileW(pattern, &entry); need(scan != INVALID_HANDLE_VALUE);
  do { need(!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")); } while (FindNextFileW(scan, &entry));
  need(GetLastError() == ERROR_NO_MORE_FILES && FindClose(scan));
  WCHAR profile[80]; profile_name(profile); need(SUCCEEDED(DeleteAppContainerProfile(profile))); puts("{\"deleted\":true}");
}
static void profile_absent(void) {
  HKEY key; LONG error = mapping(&key);
  if (error == ERROR_SUCCESS) { RegCloseKey(key); need(0); } need(error == ERROR_FILE_NOT_FOUND); puts("{\"absent\":true}");
}
static void process_retired(const WCHAR *pid, const WCHAR *time) {
  ULONGLONG value = number(pid); need(value <= MAXDWORD); assert_retired((DWORD)value, number(time)); puts("{\"retired\":true}");
}
static void host_environment(const WCHAR *key, const WCHAR *expected, WCHAR *value, DWORD capacity, const char *operation) {
  DWORD size = GetEnvironmentVariableW(key, value, capacity); win32_check(size != 0, operation);
  invariant(size < capacity && !wcscmp(value, expected), operation);
}
#ifdef NATIVE_COMMAND_EXPERIMENT
#include "feasibility-command.h"
#endif
int wmain(int argc, WCHAR **argv) {
  need(_setmode(_fileno(stdout), _O_BINARY) != -1 && argc >= 2); setvbuf(stdout, NULL, _IONBF, 0);
  role = argv[1];
#ifdef NATIVE_COMMAND_EXPERIMENT
  if (!wcsncmp(role, L"command-", 8)) return command_main(argc, argv);
#endif
  if (!wcscmp(argv[1], L"park") && argc == 2) { HANDLE token; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)); DWORD *active = info(token, TokenIsAppContainer); BOOL member; need(*active && IsProcessInJob(GetCurrentProcess(), NULL, &member) && member && CloseHandle(token)); free(active); Sleep(60000); return 124; }
  need(argc >= 4); root = argv[2]; nonce = argv[3]; need(wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32);
  BOOL payload = !wcscmp(argv[1], L"bundle") || !wcscmp(argv[1], L"fault");
  if (payload) { HANDLE token; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)); DWORD *active = info(token, TokenIsAppContainer); TOKEN_GROUPS *caps = info(token, TokenCapabilities); BOOL member; need(*active && !caps->GroupCount && IsProcessInJob(GetCurrentProcess(), NULL, &member) && member && CloseHandle(token)); free(active); free(caps); }
  if (!payload) {
    WCHAR ci[8], actions[8], worker[32], os[16];
    host_environment(L"CI", L"true", ci, 8, "host-ci"); host_environment(L"GITHUB_ACTIONS", L"true", actions, 8, "host-actions");
    host_environment(L"RUNNER_ENVIRONMENT", L"github-hosted", worker, 32, "host-worker"); host_environment(L"RUNNER_OS", L"Windows", os, 16, "host-os"); principal(); derive();
  }
  HANDLE timer = CreateThread(NULL, 0, deadline, NULL, 0, NULL); win32_check(timer != NULL, "deadline-create"); win32_check(CloseHandle(timer), "thread-close"); WSADATA sockets; status_check((DWORD)WSAStartup(MAKEWORD(2, 2), &sockets), "winsock-start");
  if (!wcscmp(argv[1], L"seal") && argc == 4) { protect(root, 0, TRUE); WCHAR path[4096]; name(path, L"control"); grant_tree(path, 0); name(path, L"storage"); grant_tree(path, 0); name(path, L"outside"); grant_tree(path, 0); puts("{\"sealed\":true}"); }
  else if (!wcscmp(argv[1], L"profile-create") && argc == 5) profile_create(argv[4]);
  else if (!wcscmp(argv[1], L"profile-delete") && argc == 4) profile_delete();
  else if (!wcscmp(argv[1], L"profile-absent") && argc == 4) profile_absent();
  else if (!wcscmp(argv[1], L"profile-observe") && argc == 4) { owned_profile(); profile_observe(); }
  else if (!wcscmp(argv[1], L"process-retired") && argc == 6) process_retired(argv[4], argv[5]);
  else if (!wcscmp(argv[1], L"grants") && argc == 5) { need(!wcscmp(argv[4], L"edit") || !wcscmp(argv[4], L"read")); grants(!wcscmp(argv[4], L"edit")); }
  else if (!wcscmp(argv[1], L"write-controls") && argc == 4) write_controls();
  else if (!wcscmp(argv[1], L"launch") && argc >= 6) launch(argc, argv);
  else if ((!wcscmp(argv[1], L"inspect") || !wcscmp(argv[1], L"settle") || !wcscmp(argv[1], L"recover") || !wcscmp(argv[1], L"hold") || !wcscmp(argv[1], L"witness")) && argc == 11)
    observe(argv + 4, !wcscmp(argv[1], L"inspect"), !wcscmp(argv[1], L"recover"), !wcscmp(argv[1], L"hold") || !wcscmp(argv[1], L"witness"), !wcscmp(argv[1], L"witness"));
  else if (!wcscmp(argv[1], L"bundle") && argc == 6) bundle(argv[4], argv[5]);
  else if (!wcscmp(argv[1], L"fault") && argc == 4) fault();
  else if ((!wcscmp(argv[1], L"control") || !wcscmp(argv[1], L"control-closed")) && argc == 6) {
    BOOL tcp = !wcscmp(argv[4], L"tcp"); need(tcp || !wcscmp(argv[4], L"pipe")); int error = connection(tcp, argv[5], nonce);
    if (!wcscmp(argv[1], L"control")) { need(!error); puts("{\"ready\":true}"); }
    else { need(error == (tcp ? WSAECONNREFUSED : ERROR_FILE_NOT_FOUND)); puts("{\"closed\":true}"); }
  } else if (!wcscmp(argv[1], L"files") && argc >= 5 && argc <= 12) {
    owned_profile(); putchar('['); for (int i = 4; i < argc; i++) { if (i > 4) putchar(','); WCHAR path[4096]; name(path, argv[i]); emitfile(path, !wcsncmp(argv[i], L"control\\", 8) || !wcsncmp(argv[i], L"outside\\", 8) || !wcsncmp(argv[i], L"storage", 7)); } puts("]");
  } else if (!wcscmp(argv[1], L"storage") && argc == 4) storage();
  else if (!wcscmp(argv[1], L"remove") && argc == 7) remove_owned(argv[4], argv[5], argv[6]);
  else if (!wcscmp(argv[1], L"replacement") && argc == 4) { owned_profile(); char bytes[] = "substitute"; recordio(L"storage\\leaf", bytes, 10, TRUE); puts("{\"created\":true}"); }
  else need(0);
  need(!WSACleanup()); return ferror(stdout) ? 126 : 0;
}
