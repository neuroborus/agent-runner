/* Dedicated LocalSystem/session-0 CI only. Build and sign with independently
 * reviewed MSVC/SDK/loader inputs. This helper never invokes a shell, UAC,
 * secondary logon, provider helper or create-then-assign fallback. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <lm.h>
#include <ntsecapi.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "wintrust.lib")

static HANDLE job, control, report, output;
static SRWLOCK jobLock = SRWLOCK_INIT;
static const wchar_t *nonce;
static void stop_job(DWORD code) {
  AcquireSRWLockShared(&jobLock);
  if (job) TerminateJobObject(job, code);
  ReleaseSRWLockShared(&jobLock);
}
static void need(BOOL ok) {
  if (!ok) {
    stop_job(126);
    /* Partial account/DACL/desktop/policy effects remain in protected receipts.
     * Process exit is never authority to delete those reservations. */
    ExitProcess(126);
  }
}
static DWORD providerLifetime = 60000;
static DWORD WINAPI deadline(void *unused) {
  (void)unused;
  Sleep(providerLifetime);
  stop_job(124);
  ExitProcess(124);
  return 0;
}
static void acknowledge(char expected) {
  char value; DWORD size;
  need(ReadFile(control, &value, 1, &size, NULL) && size == 1 && value == expected);
}
static PSECURITY_DESCRIPTOR descriptor(const wchar_t *sddl) {
  PSECURITY_DESCRIPTOR value = NULL;
  need(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &value, NULL));
  return value;
}
static SECURITY_ATTRIBUTES attributes(PSECURITY_DESCRIPTOR value) {
  SECURITY_ATTRIBUTES result = { sizeof(result), value, FALSE };
  return result;
}
static void noninherit(HANDLE handle) { need(SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)); }
static void private_dacl(HANDLE handle) {
  PSID owner; PACL dacl; PSECURITY_DESCRIPTOR sd = NULL; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  need(GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    &owner, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS);
  BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
  need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) && EqualSid(owner, system) && dacl &&
    GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED) && dacl->AceCount == 1);
  ACCESS_ALLOWED_ACE *ace;
  need(GetAce(dacl, 0, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
    !(ace->Header.AceFlags & INHERITED_ACE) && EqualSid((PSID)&ace->SidStart, system) &&
    (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);
  LocalFree(sd);
}
static HANDLE held(const wchar_t *name, BOOL directory, DWORD access) {
  HANDLE handle = CreateFileW(name, access | READ_CONTROL, FILE_SHARE_READ | (directory ? FILE_SHARE_WRITE : 0),
    NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), NULL);
  need(handle != INVALID_HANDLE_VALUE);
  FILE_ATTRIBUTE_TAG_INFO tag;
  need(GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) &&
    !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && !!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory);
  wchar_t canonical[8192]; DWORD size = GetFinalPathNameByHandleW(handle, canonical, 8192, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  need(size > 4 && size < 8192 && !wcsncmp(canonical, L"\\\\?\\", 4) && !wcscmp(canonical + 4, name));
  noninherit(handle);
  return handle;
}
static void file_hash(HANDLE file, const wchar_t *pin, ULONGLONG maximum) {
  LARGE_INTEGER length, zero = {0}; BY_HANDLE_FILE_INFORMATION info;
  need(wcslen(pin) == 64 && GetFileSizeEx(file, &length) && length.QuadPart > 0 && (ULONGLONG)length.QuadPart <= maximum &&
    GetFileInformationByHandle(file, &info) && info.nNumberOfLinks == 1 && SetFilePointerEx(file, zero, NULL, FILE_BEGIN));
  BCRYPT_ALG_HANDLE algorithm = NULL; BCRYPT_HASH_HANDLE hash = NULL;
  need(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
    BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) == 0);
  BYTE bytes[65536], sum[32]; DWORD size; ULONGLONG total = 0;
  do {
    need(ReadFile(file, bytes, sizeof(bytes), &size, NULL)); total += size;
    need(total <= maximum && BCryptHashData(hash, bytes, size, 0) == 0);
  } while (size);
  need(total == (ULONGLONG)length.QuadPart && BCryptFinishHash(hash, sum, sizeof(sum), 0) == 0);
  wchar_t actual[65]; for (unsigned i = 0; i < 32; i++) swprintf_s(actual + i * 2, 65 - i * 2, L"%02x", sum[i]);
  need(!wcscmp(actual, pin));
  BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
}
static void image(HANDLE file, const wchar_t *name, const wchar_t *pin, ULONGLONG maximum, BOOL exact) {
  file_hash(file, pin, maximum);
  LARGE_INTEGER length; need(!exact || (GetFileSizeEx(file, &length) && (ULONGLONG)length.QuadPart == maximum));
  LARGE_INTEGER zero = {0}; BYTE bytes[4096]; DWORD size;
  need(SetFilePointerEx(file, zero, NULL, FILE_BEGIN) && ReadFile(file, bytes, sizeof(bytes), &size, NULL) && size >= 512);
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)bytes;
  need(dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew >= 64 && (DWORD)dos->e_lfanew <= size - sizeof(IMAGE_NT_HEADERS64));
  IMAGE_NT_HEADERS64 *pe = (IMAGE_NT_HEADERS64 *)(bytes + dos->e_lfanew);
  need(pe->Signature == IMAGE_NT_SIGNATURE && pe->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
    pe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && !(pe->FileHeader.Characteristics & IMAGE_FILE_DLL));
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_FILE_INFO info = {0}; info.cbStruct = sizeof(info); info.pcwszFilePath = name; info.hFile = file;
  WINTRUST_DATA trust = {0}; trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_NONE; trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &info;
  trust.dwStateAction = WTD_STATEACTION_VERIFY; trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
  LONG result = WinVerifyTrust(NULL, &action, &trust);
  trust.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(NULL, &action, &trust);
  need(result == ERROR_SUCCESS); /* Exact signature/issuer and trust store are independently bound, too. */
}
static void *token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
  DWORD size = 0; GetTokenInformation(token, kind, NULL, 0, &size);
  need(GetLastError() == ERROR_INSUFFICIENT_BUFFER && size > 0 && size <= 65536);
  void *value = calloc(1, size); need(value && GetTokenInformation(token, kind, value, size, &size));
  return value;
}
static wchar_t *token_sid(HANDLE token) {
  TOKEN_USER *user = token_info(token, TokenUser); wchar_t *sid = NULL;
  need(ConvertSidToStringSidW(user->User.Sid, &sid)); free(user); return sid;
}
static void identity(HANDLE process) {
  FILETIME created, exited, kernel, user; HANDLE token;
  need(GetProcessTimes(process, &created, &exited, &kernel, &user) && OpenProcessToken(process, TOKEN_QUERY, &token));
  wchar_t *userSid = token_sid(token); DWORD *session = token_info(token, TokenSessionId);
  ULARGE_INTEGER time; time.LowPart = created.dwLowDateTime; time.HighPart = created.dwHighDateTime;
  printf("{\"pid\":%lu,\"creationTime\":\"%llu\",\"sessionId\":%lu,\"userSid\":\"%ls\"}",
    GetProcessId(process), time.QuadPart, *session, userSid);
  free(session); LocalFree(userSid); CloseHandle(token);
}
static void frame(const char *phase, HANDLE process, const wchar_t *accountSid) {
  printf("{\"nonce\":\"%ls\",\"phase\":\"%s\",\"helper\":", nonce, phase); identity(GetCurrentProcess());
  printf(",\"payload\":"); if (process) identity(process); else printf("null");
  if (accountSid) printf(",\"accountSid\":\"%ls\"}\n", accountSid); else printf(",\"accountSid\":null}\n");
  need(fflush(stdout) == 0);
}
static void privilege(HANDLE token, const wchar_t *name) {
  TOKEN_PRIVILEGES value = {0}; value.PrivilegeCount = 1;
  need(LookupPrivilegeValueW(NULL, name, &value.Privileges[0].Luid)); value.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  SetLastError(ERROR_SUCCESS);
  need(AdjustTokenPrivileges(token, FALSE, &value, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS);
}
static void rights(PSID user) {
  LSA_OBJECT_ATTRIBUTES attrs = {0}; attrs.Length = sizeof(attrs); LSA_HANDLE policy;
  need(LsaOpenPolicy(NULL, &attrs, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &policy) == 0);
  const wchar_t *names[] = { SE_BATCH_LOGON_NAME, SE_DENY_INTERACTIVE_LOGON_NAME, SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME,
    SE_DENY_NETWORK_LOGON_NAME, SE_DENY_SERVICE_LOGON_NAME };
  LSA_UNICODE_STRING values[5];
  for (unsigned i = 0; i < 5; i++) {
    values[i].Buffer = (wchar_t *)names[i]; values[i].Length = (USHORT)(wcslen(names[i]) * sizeof(wchar_t));
    values[i].MaximumLength = values[i].Length + sizeof(wchar_t);
  }
  need(LsaAddAccountRights(policy, user, values, 5) == 0); LsaClose(policy);
}
static HANDLE account(const wchar_t *name, const wchar_t *custody, wchar_t **userSid) {
  BYTE random[64]; wchar_t password[65];
  need(BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0);
  const wchar_t alphabet[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#";
  for (unsigned i = 0; i < 64; i++) password[i] = alphabet[random[i] & 63]; password[64] = 0;
  password[0] = L'A'; password[1] = L'z'; password[2] = L'7'; password[3] = L'#';
  /* Fresh random credentials never enter argv, environment, control frames,
   * logs or JS receipts. Only the protected native custody file retains them. */
  USER_INFO_1 user = {0}; user.usri1_name = (wchar_t *)name; user.usri1_password = password;
  user.usri1_priv = USER_PRIV_USER; user.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
  DWORD error;
  need(NetUserAdd(NULL, 1, (BYTE *)&user, &error) == NERR_Success);
  LOCALGROUP_USERS_INFO_0 *groups = NULL; DWORD count, total;
  need(NetUserGetLocalGroups(NULL, name, 0, 0, (BYTE **)&groups, MAX_PREFERRED_LENGTH, &count, &total) == NERR_Success && count == total && count <= 128);
  LOCALGROUP_MEMBERS_INFO_3 member = { (wchar_t *)name };
  for (DWORD i = 0; i < count; i++) need(NetLocalGroupDelMembers(NULL, groups[i].lgrui0_name, 3, (BYTE *)&member, 1) == NERR_Success);
  if (groups) NetApiBufferFree(groups);
  BYTE rawSid[SECURITY_MAX_SID_SIZE]; DWORD sidSize = sizeof(rawSid), domainSize = 256; wchar_t domain[256]; SID_NAME_USE type;
  need(LookupAccountNameW(NULL, name, rawSid, &sidSize, domain, &domainSize, &type) && type == SidTypeUser);
  rights(rawSid);
  need(ConvertSidToStringSidW(rawSid, userSid));
  wchar_t secret[4096]; need(swprintf_s(secret, 4096, L"%ls\\account.secret", custody) > 0);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;FA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd);
  HANDLE file = CreateFileW(secret, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH, NULL);
  DWORD written;
  need(file != INVALID_HANDLE_VALUE && WriteFile(file, password, sizeof(password), &written, NULL) && written == sizeof(password) && FlushFileBuffers(file));
  CloseHandle(file); LocalFree(sd);
  HANDLE token;
  need(LogonUserW(name, L".", password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &token));
  SecureZeroMemory(password, sizeof(password)); SecureZeroMemory(random, sizeof(random));
  wchar_t *actual = token_sid(token); need(!wcscmp(actual, *userSid)); LocalFree(actual); noninherit(token);
  return token;
}
static HANDLE restrict_token(HANDLE base, PSID capability) {
  TOKEN_GROUPS *groups = token_info(base, TokenGroups); TOKEN_PRIVILEGES *privileges = token_info(base, TokenPrivileges);
  need(groups->GroupCount <= 128 && privileges->PrivilegeCount <= 64);
  SID_AND_ATTRIBUTES disabled[128]; DWORD count = 0;
  for (DWORD i = 0; i < groups->GroupCount; i++)
    if (!(groups->Groups[i].Attributes & (SE_GROUP_INTEGRITY | SE_GROUP_USE_FOR_DENY_ONLY))) disabled[count++] = groups->Groups[i];
  SID_AND_ATTRIBUTES restricting = { capability, 0 }; HANDLE token;
  /* Delete every privilege explicitly, including SeChangeNotifyPrivilege.
   * Never use WRITE_RESTRICTED (or its read-access escape) here. */
  need(CreateRestrictedToken(base, 0, count, disabled, privileges->PrivilegeCount, privileges->Privileges, 1, &restricting, &token));
  free(groups); free(privileges);
  PSID low; need(ConvertStringSidToSidW(L"S-1-16-4096", &low));
  TOKEN_MANDATORY_LABEL integrity = { { low, SE_GROUP_INTEGRITY } };
  need(SetTokenInformation(token, TokenIntegrityLevel, &integrity, sizeof(integrity) + GetLengthSid(low))); LocalFree(low);
  DWORD off = 0; need(SetTokenInformation(token, TokenVirtualizationEnabled, &off, sizeof(off)));
  TOKEN_PRIVILEGES *after = token_info(token, TokenPrivileges); DWORD *session = token_info(token, TokenSessionId);
  TOKEN_GROUPS *restricted = token_info(token, TokenRestrictedSids);
  need(IsTokenRestricted(token) && after->PrivilegeCount == 0 && *session == 0 && restricted->GroupCount == 1 && EqualSid(restricted->Groups[0].Sid, capability));
  free(after); free(session); free(restricted); noninherit(token);
  return token;
}
static void append(wchar_t *command, size_t *offset, wchar_t value) {
  need(*offset < 32766); command[(*offset)++] = value; command[*offset] = 0;
}
static void argument(wchar_t *command, size_t *offset, const wchar_t *value) {
  if (*offset) append(command, offset, L' '); append(command, offset, L'"');
  size_t slashes = 0;
  for (size_t i = 0;; i++) {
    if (value[i] == L'\\') { slashes++; continue; }
    if (!value[i] || value[i] == L'"') slashes *= 2;
    while (slashes) { append(command, offset, L'\\'); slashes--; }
    if (!value[i]) break;
    if (value[i] == L'"') append(command, offset, L'\\');
    append(command, offset, value[i]);
  }
  append(command, offset, L'"');
}
static ULONGLONG outputMaximum = 1048576;
static DWORD WINAPI forward(void *parameter) {
  HANDLE pipe = (HANDLE)parameter; BYTE bytes[8192]; DWORD size, written; ULONGLONG total = 0;
  while (ReadFile(pipe, bytes, sizeof(bytes), &size, NULL) && size) {
    total += size; need(total <= outputMaximum && WriteFile(output, bytes, size, &written, NULL) && written == size);
  }
  CloseHandle(pipe); return 0;
}
static int environment_order(const void *left, const void *right) {
  return _wcsicmp(*(wchar_t * const *)left, *(wchar_t * const *)right);
}
static void sort_environment(wchar_t *environment, size_t size) {
  wchar_t *entries[16], sorted[16384]; unsigned count = 0; size_t position = 0;
  for (size_t offset = 0; offset < size;) {
    need(count < 16); entries[count++] = environment + offset; offset += wcslen(environment + offset) + 1;
  }
  qsort(entries, count, sizeof(entries[0]), environment_order);
  for (unsigned i = 0; i < count; i++) {
    size_t length = wcslen(entries[i]) + 1; need(position + length < 16384);
    memcpy(sorted + position, entries[i], length * sizeof(wchar_t)); position += length;
  }
  sorted[position] = 0; memcpy(environment, sorted, (position + 1) * sizeof(wchar_t));
}
/* Public capability environment only; the credential pipe is never inherited. */
static void provider_environment(wchar_t *environment, size_t *position, const wchar_t *nonce) {
  static const wchar_t *names[] = {L"HOME", L"PATH", L"LANG", L"TMPDIR", L"TEMP", L"TMP", L"XDG_CACHE_HOME",
    L"CODEX_HOME", L"NATIVE_POC_TOKEN", L"ANTHROPIC_BASE_URL", L"ANTHROPIC_AUTH_TOKEN", L"ANTHROPIC_MODEL", L"USERPROFILE", L"APPDATA", L"LOCALAPPDATA"};
  wchar_t block[32768]; DWORD length = GetEnvironmentVariableW(L"NATIVE_PROVIDER_ENV", block, 32768); need(length > 0 && length < 32768);
  unsigned seen = 0; wchar_t *next = block;
  while (next && *next) {
    wchar_t *line = next, *end = wcschr(line, L'\n'); if (end) { *end = 0; next = end + 1; } else next = NULL;
    wchar_t *equals = wcschr(line, L'='); need(equals && equals > line && equals[1] && wcslen(line) <= 8192);
    for (wchar_t *p = line; *p; p++) need(*p >= 32 && *p != 127);
    unsigned index; for (index = 0; index < 15; index++) if (wcslen(names[index]) == (size_t)(equals - line) && !wcsncmp(names[index], line, (size_t)(equals - line))) break;
    need(index < 15 && !(seen & (1U << index))); seen |= 1U << index;
    if (index == 8 || index == 10) need(!wcsncmp(equals + 1, L"native-poc-", 11) && !wcscmp(equals + 12, nonce));
    size_t size = wcslen(line) + 1; need(*position + size < 16384); memcpy(environment + *position, line, size * sizeof(wchar_t)); *position += size;
  }
  need((seen & 1) && (seen & 2) && ((seen & (1U << 8)) != 0) != ((seen & (1U << 10)) != 0)); environment[*position] = 0;
}

int wmain(int argc, wchar_t **argv) {
  need(_setmode(_fileno(stdout), _O_BINARY) != -1);
  BOOL provider = argc >= 11 && !wcscmp(argv[10], L"--provider");
  need(argc >= 11 && argc <= 75 && (provider || !wcscmp(argv[10], L"--")));
  ULONGLONG imageMaximum = 134217728;
  if (provider) { wchar_t bound[32], *end; DWORD n = GetEnvironmentVariableW(L"NATIVE_PROVIDER_BYTES", bound, 32);
    need(n > 0 && n < 32 && wcsspn(bound, L"0123456789") == n); imageMaximum = _wcstoui64(bound, &end, 10);
    need(!*end && imageMaximum > 0 && imageMaximum <= 536870912); }
  if (provider) { outputMaximum = 8388608; providerLifetime = 120000; }
  nonce = argv[1]; need(wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32);
  wchar_t ci[16], actions[16];
  need(GetEnvironmentVariableW(L"CI", ci, 16) == 4 && !wcscmp(ci, L"true") &&
    GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 16) == 4 && !wcscmp(actions, L"true"));
  control = GetStdHandle(STD_INPUT_HANDLE); report = GetStdHandle(STD_OUTPUT_HANDLE); output = GetStdHandle(STD_ERROR_HANDLE);
  need(GetFileType(control) == FILE_TYPE_PIPE && GetFileType(report) == FILE_TYPE_PIPE && GetFileType(output) == FILE_TYPE_PIPE);
  noninherit(control); noninherit(report); noninherit(output);
  HANDLE self; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &self));
  wchar_t *selfSid = token_sid(self); DWORD *session = token_info(self, TokenSessionId);
  need(!wcscmp(selfSid, L"S-1-5-18") && *session == 0); LocalFree(selfSid); free(session);
  frame("helper", NULL, NULL); acknowledge('P');
  need(CreateThread(NULL, 0, deadline, NULL, 0, NULL) != NULL);
  privilege(self, SE_ASSIGNPRIMARYTOKEN_NAME); privilege(self, SE_INCREASE_QUOTA_NAME); privilege(self, SE_TCB_NAME); CloseHandle(self);
  HANDLE custody = held(argv[3], TRUE, FILE_LIST_DIRECTORY), storage = held(argv[4], TRUE, FILE_LIST_DIRECTORY);
  private_dacl(custody); private_dacl(storage);
  HANDLE policy = held(argv[8], FALSE, GENERIC_READ); private_dacl(policy); file_hash(policy, argv[9], 1048576);
  HANDLE executable = held(argv[6], FALSE, GENERIC_READ); private_dacl(executable); image(executable, argv[6], argv[7], imageMaximum, provider);
  PSECURITY_DESCRIPTOR protectedSd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES protectedSa = attributes(protectedSd);
  wchar_t name[21]; need(swprintf_s(name, 21, L"np_%.16ls", nonce) > 0);
  wchar_t *userSid; HANDLE base = account(name, argv[3], &userSid);
  PSID capability; need(ConvertStringSidToSidW(argv[2], &capability));
  PSID user; need(ConvertStringSidToSidW(userSid, &user) && !EqualSid(user, capability)); LocalFree(user);
  HANDLE token = restrict_token(base, capability); CloseHandle(base);
  PSECURITY_DESCRIPTOR fileSd = descriptor(L"O:SYG:SYD:P(A;OICI;FA;;;SY)"); SECURITY_ATTRIBUTES fileSa = attributes(fileSd);
  need(CreateDirectoryW(argv[5], &fileSa)); LocalFree(fileSd);
  HANDLE workspace = held(argv[5], TRUE, FILE_LIST_DIRECTORY);
  wchar_t jobName[128]; need(swprintf_s(jobName, 128, L"Local\\NativeProof-%ls", nonce) > 0);
  SetLastError(ERROR_SUCCESS); HANDLE createdJob = CreateJobObjectW(&protectedSa, jobName); DWORD jobError = GetLastError();
  if (createdJob && jobError == ERROR_ALREADY_EXISTS) {
    CloseHandle(createdJob); need(FALSE); /* Never terminate an unowned colliding object. */
  }
  need(createdJob != NULL);
  AcquireSRWLockExclusive(&jobLock); job = createdJob; ReleaseSRWLockExclusive(&jobLock); noninherit(job);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  limits.BasicLimitInformation.ActiveProcessLimit = 32;
  need(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)));
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui = { JOB_OBJECT_UILIMIT_ALL };
  need(SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui)));
  wchar_t stationName[128], desktopName[256], uiSddl[2048];
  need(swprintf_s(stationName, 128, L"np_%ls", nonce) > 0 && swprintf_s(desktopName, 256, L"%ls\\payload", stationName) > 0);
  /* The low-label objects are private. No WinSta0, host clipboard, desktop,
   * service, token or Job handle appears in the child's inherited list. */
  need(swprintf_s(uiSddl, 2048, L"O:SYG:SYD:P(A;;GA;;;SY)(A;;0x00000003;;;%ls)(A;;0x00000003;;;%ls)S:(ML;;NW;;;LW)", userSid, argv[2]) > 0);
  PSECURITY_DESCRIPTOR stationSd = descriptor(uiSddl); SECURITY_ATTRIBUTES stationSa = attributes(stationSd);
  HWINSTA original = GetProcessWindowStation(), station = CreateWindowStationW(stationName, CWF_CREATE_ONLY, WINSTA_ALL_ACCESS, &stationSa);
  USEROBJECTFLAGS flags; DWORD returned;
  need(station && GetUserObjectInformationW(station, UOI_FLAGS, &flags, sizeof(flags), &returned) && !(flags.dwFlags & WSF_VISIBLE) && SetProcessWindowStation(station));
  need(swprintf_s(uiSddl, 2048, L"O:SYG:SYD:P(A;;GA;;;SY)(A;;0x000000c7;;;%ls)(A;;0x000000c7;;;%ls)S:(ML;;NW;;;LW)", userSid, argv[2]) > 0);
  PSECURITY_DESCRIPTOR desktopSd = descriptor(uiSddl); SECURITY_ATTRIBUTES desktopSa = attributes(desktopSd);
  HDESK desktop = CreateDesktopW(L"payload", NULL, NULL, 0, DESKTOP_ALL_ACCESS, &desktopSa);
  need(desktop && SetProcessWindowStation(original)); LocalFree(stationSd); LocalFree(desktopSd);
  HANDLE inputRead, inputWrite, outputRead, outputWrite;
  need(CreatePipe(&inputRead, &inputWrite, NULL, 0) && CreatePipe(&outputRead, &outputWrite, NULL, 0));
  noninherit(inputWrite); noninherit(outputRead);
  need(SetHandleInformation(inputRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) && SetHandleInformation(outputWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
  CloseHandle(inputWrite); /* Child stdin is a private EOF pipe, never control. */
  HANDLE errorWrite = outputWrite;
  if (provider) { CloseHandle(inputRead); inputRead = (HANDLE)_get_osfhandle(3); errorWrite = (HANDLE)_get_osfhandle(4);
    need(GetFileType(inputRead) == FILE_TYPE_PIPE && GetFileType(errorWrite) == FILE_TYPE_PIPE);
    need(SetHandleInformation(inputRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) && SetHandleInformation(errorWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)); }
  HANDLE handles[3] = { inputRead, outputWrite, errorWrite }; SIZE_T attributeSize = 0;
  InitializeProcThreadAttributeList(NULL, 2, 0, &attributeSize); need(attributeSize > 0 && attributeSize <= 65536);
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = malloc(attributeSize); need(attributes && InitializeProcThreadAttributeList(attributes, 2, 0, &attributeSize));
  need(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof(job), NULL, NULL) &&
    UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, (provider ? 3 : 2) * sizeof(HANDLE), NULL, NULL));
  frame("setup", NULL, userSid); acknowledge('C'); /* Full external authority policy precedes creation. */
  wchar_t command[32767] = {0}; size_t offset = 0; argument(command, &offset, argv[6]);
  for (int i = 11; i < argc; i++) argument(command, &offset, argv[i]);
  wchar_t windows[4096], environment[16384]; DWORD windowLength = GetWindowsDirectoryW(windows, 4096);
  need(windowLength > 0 && windowLength < 4096);
  int length = swprintf_s(environment, 16384, L"SystemRoot=%ls", windows); need(length > 0);
  size_t position = (size_t)length + 1;
  if (provider) { provider_environment(environment, &position, nonce); sort_environment(environment, position); }
  else {
  length = swprintf_s(environment + position, 16384 - position, L"TEMP=%ls", argv[5]); need(length > 0); position += (size_t)length + 1;
  length = swprintf_s(environment + position, 16384 - position, L"TMP=%ls", argv[5]); need(length > 0); position += (size_t)length + 1; environment[position] = 0;
  }
  STARTUPINFOEXW startup = {0}; startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.lpDesktop = desktopName;
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES; startup.StartupInfo.hStdInput = inputRead;
  startup.StartupInfo.hStdOutput = outputWrite; startup.StartupInfo.hStdError = errorWrite; startup.lpAttributeList = attributes;
  PROCESS_INFORMATION child = {0};
  need(CreateProcessAsUserW(token, argv[6], command, &protectedSa, &protectedSa, TRUE,
    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
    environment, argv[5], &startup.StartupInfo, &child));
  BOOL member; need(IsProcessInJob(child.hProcess, job, &member) && member); noninherit(child.hProcess); noninherit(child.hThread);
  DeleteProcThreadAttributeList(attributes); free(attributes); CloseHandle(inputRead); CloseHandle(outputWrite); if (provider) CloseHandle(errorWrite); CloseHandle(token); LocalFree(capability);
  frame("ready", child.hProcess, userSid); acknowledge('R');
  need(ResumeThread(child.hThread) == 1); CloseHandle(child.hThread);
  need(CreateThread(NULL, 0, forward, outputRead, 0, NULL) != NULL);
  char unexpected; DWORD size;
  /* The owner closes control only after independent recovery/retirement. Loss
   * also terminates through the held Job, never a numeric PID. */
  ReadFile(control, &unexpected, 1, &size, NULL);
  AcquireSRWLockExclusive(&jobLock);
  BOOL terminated = TerminateJobObject(job, 126), closed = CloseHandle(job); job = NULL;
  ReleaseSRWLockExclusive(&jobLock); need(terminated && closed);
  CloseHandle(child.hProcess); CloseHandle(executable); CloseHandle(policy); CloseHandle(workspace); CloseHandle(storage); CloseHandle(custody);
  CloseDesktop(desktop); CloseWindowStation(station); LocalFree(userSid); LocalFree(protectedSd);
  return 0;
}
