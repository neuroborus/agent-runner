/* CI-only LocalSystem/session-0 helper. The protected owner supplies private
 * parent handles through an explicit handle list, retaining sole mutation
 * authority. Build/sign and verify SDK/NTFS semantics only in external CI. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "advapi32.lib")
#ifndef _WIN64
#error This reviewed helper requires the Windows x64 ABI.
#endif

typedef NTSTATUS (NTAPI *create_file)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
  PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *set_file)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *query_file)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
/* These NT layouts/classes/flags require independent SDK/ABI review before
 * admission. There is no Win32 pathname or legacy rename/disposition fallback. */
struct link_name { BOOLEAN replace; HANDLE root; ULONG length; WCHAR name[16]; };
struct rename_name { ULONG flags; HANDLE root; ULONG length; WCHAR name[16]; };
struct stream_info { ULONG next, length; LARGE_INTEGER size, allocation; WCHAR name[1]; };
_Static_assert(offsetof(struct link_name, root) == 8 && offsetof(struct link_name, name) == 20, "NT link ABI");
_Static_assert(offsetof(struct rename_name, root) == 8 && offsetof(struct rename_name, name) == 20, "NT rename ABI");
static create_file nt_create;
static set_file nt_set;
static query_file nt_query;
static HANDLE base, root, parent, leaf, temporary, mutex;
static char base_id[50], root_id[50], parent_id[50], leaf_id[50], temporary_id[50];
static const wchar_t *nonce;
static PSECURITY_DESCRIPTOR security;
static ULONGLONG started;
static void need(BOOL ok) { if (!ok) ExitProcess(126); }
static void bounded(void) { need(GetTickCount64() - started < 25000); }
static DWORD WINAPI expire(void *unused) {
  (void)unused; Sleep(25000); ExitProcess(124); /* Never delete uncertain names. */
  return 0;
}
static void private_dacl(HANDLE handle) {
  PSID owner; PACL dacl; PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
  need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) &&
    GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS && EqualSid(owner, system) && dacl &&
    dacl->AceCount == 1 && GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED));
  ACCESS_ALLOWED_ACE *ace;
  need(GetAce(dacl, 0, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
    !(ace->Header.AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)) &&
    EqualSid((PSID)&ace->SidStart, system) && ace->Mask == FILE_ALL_ACCESS);
  LocalFree(sd);
}
static void streams(HANDLE handle, BOOL directory) {
  union { struct stream_info alignment; BYTE bytes[4096]; } buffer;
  IO_STATUS_BLOCK status = {0};
  need(nt_query(handle, &status, &buffer, sizeof(buffer), (FILE_INFORMATION_CLASS)22) == 0);
  if (directory) { need(status.Information == 0); return; }
  struct stream_info *stream = (struct stream_info *)buffer.bytes;
  need(status.Information >= offsetof(struct stream_info, name) + 14 && status.Information <= sizeof(buffer) &&
    stream->next == 0 && stream->length == 14 && !wmemcmp(stream->name, L"::$DATA", 7));
}
static void no_alternate(HANDLE handle, const WCHAR *name) {
  union { FILE_NAME_INFO alignment; BYTE bytes[1024]; } names;
  FILE_NAME_INFO *alternate = (FILE_NAME_INFO *)names.bytes;
  IO_STATUS_BLOCK information;
  NTSTATUS status = nt_query(handle, &information, &names, sizeof(names), (FILE_INFORMATION_CLASS)21);
  if (status == 0) {
    need(information.Information >= offsetof(FILE_NAME_INFO, FileName) && information.Information <= sizeof(names) &&
      alternate->FileNameLength <= information.Information - offsetof(FILE_NAME_INFO, FileName));
    need(alternate->FileNameLength == 0 || (alternate->FileNameLength == wcslen(name) * 2 &&
      !wmemcmp(alternate->FileName, name, wcslen(name))));
  } else need(status == (NTSTATUS)0xc0000034L);
}
static void identify(HANDLE handle, BOOL directory, unsigned links, char out[50]) {
  bounded(); need(handle && GetFileType(handle) == FILE_TYPE_DISK);
  FILE_ATTRIBUTE_TAG_INFO tag; FILE_ID_INFO id; FILE_STANDARD_INFO standard;
  WCHAR path[4096], filesystem[32]; DWORD flags, maximum;
  need(GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) &&
    !(tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_READONLY)) &&
    !!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory &&
    GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id)) && id.VolumeSerialNumber &&
    GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) &&
    !standard.DeletePending && standard.Directory == directory &&
    (directory || (standard.NumberOfLinks == links && standard.EndOfFile.QuadPart >= 0 && standard.EndOfFile.QuadPart <= 4096)) &&
    GetVolumeInformationByHandleW(handle, NULL, 0, NULL, &maximum, &flags, filesystem, 32) &&
    !wcscmp(filesystem, L"NTFS") &&
    (flags & (FILE_PERSISTENT_ACLS | FILE_SUPPORTS_HARD_LINKS | FILE_SUPPORTS_OPEN_BY_FILE_ID)) ==
      (FILE_PERSISTENT_ACLS | FILE_SUPPORTS_HARD_LINKS | FILE_SUPPORTS_OPEN_BY_FILE_ID));
  DWORD length = GetFinalPathNameByHandleW(handle, path, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  need(length > 7 && length < 4096 && !wcsncmp(path, L"\\\\?\\", 4) &&
    path[4] >= L'A' && path[4] <= L'Z' && path[5] == L':' && path[6] == L'\\');
  /* A local canonical DOS spelling only; no UNC/device, stream or short alias. */
  const WCHAR *part = path + 7;
  for (const WCHAR *p = part;; p++) {
    if (*p == L'\\' || !*p) {
      size_t count = (size_t)(p - part); need(count && count <= 255 && p[-1] != L'.' && p[-1] != L' ');
      WCHAR name[256]; wmemcpy(name, part, count); name[count] = 0;
      WCHAR *dot = wcschr(name, L'.'); if (dot) *dot = 0;
      need(_wcsicmp(name, L"CON") && _wcsicmp(name, L"PRN") && _wcsicmp(name, L"AUX") && _wcsicmp(name, L"NUL") &&
        !(wcslen(name) == 4 && (!_wcsnicmp(name, L"COM", 3) || !_wcsnicmp(name, L"LPT", 3)) && name[3] >= L'1' && name[3] <= L'9'));
      if (!*p) break; part = p + 1;
    } else need((*p >= L'A' && *p <= L'Z') || (*p >= L'a' && *p <= L'z') ||
      (*p >= L'0' && *p <= L'9') || wcschr(L" _.-", *p) != NULL);
  }
  if (directory) {
    FILE_CASE_SENSITIVE_INFO sensitive;
    need(GetFileInformationByHandleEx(handle, FileCaseSensitiveInfo, &sensitive, sizeof(sensitive)) && sensitive.Flags == 0);
  }
  private_dacl(handle); streams(handle, directory); no_alternate(handle, wcsrchr(path, L'\\') + 1);
  BYTE nonzero = 0; for (unsigned i = 0; i < 16; i++) nonzero |= id.FileId.Identifier[i]; need(nonzero);
  snprintf(out, 50, "%016llx:", id.VolumeSerialNumber);
  for (unsigned i = 0; i < 16; i++) snprintf(out + 17 + i * 2, 3, "%02x", id.FileId.Identifier[i]);
}
static BOOL same(const char *a, const char *b) { return !strcmp(a, b); }
static void volume(const char *id) { need(!strncmp(id, root_id, 16)); }
static HANDLE open_leaf(HANDLE at, const WCHAR *name, BOOL directory, BOOL create, BOOL writable, ULONG sharing, BOOL optional) {
  UNICODE_STRING text = {(USHORT)(wcslen(name) * 2), (USHORT)(wcslen(name) * 2), (PWSTR)name};
  OBJECT_ATTRIBUTES attributes = {sizeof(attributes), at, &text, 0, create ? security : NULL, NULL};
  IO_STATUS_BLOCK status; HANDLE handle = NULL;
  ACCESS_MASK rights = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE |
    ((!directory || !wcscmp(name, L"allocation")) ? DELETE : 0) |
    (directory ? FILE_LIST_DIRECTORY | (!wcscmp(name, L"allocation") ? FILE_ADD_FILE : 0) : FILE_READ_DATA) |
    (writable ? FILE_WRITE_DATA : 0);
  NTSTATUS result = nt_create(&handle, rights, &attributes, &status, NULL, FILE_ATTRIBUTE_NORMAL,
    sharing, create ? 2 : 1, 0x00200000 | 0x20 | (directory ? 1 : 0x40), NULL, 0);
  if (optional && result == (NTSTATUS)0xc0000034L) return NULL; /* Exact leaf absent. */
  need(result == 0 && handle && SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0));
  union { FILE_NAME_INFO alignment; BYTE bytes[1024]; } names;
  FILE_NAME_INFO *actual = (FILE_NAME_INFO *)names.bytes;
  IO_STATUS_BLOCK information;
  need(nt_query(handle, &information, &names, sizeof(names), (FILE_INFORMATION_CLASS)9) == 0 &&
    information.Information >= offsetof(FILE_NAME_INFO, FileName) + 2 &&
    information.Information <= sizeof(names) && actual->FileNameLength >= 2 &&
    actual->FileNameLength <= information.Information - offsetof(FILE_NAME_INFO, FileName) && actual->FileNameLength % 2 == 0);
  size_t count = actual->FileNameLength / 2, start = count;
  while (start && actual->FileName[start - 1] != L'\\') start--;
  need(count - start == wcslen(name) && !wmemcmp(actual->FileName + start, name, count - start));
  return handle;
}
static HANDLE opened(HANDLE at, const WCHAR *name, BOOL directory, BOOL optional) {
  return open_leaf(at, name, directory, FALSE, FALSE,
    FILE_SHARE_READ | FILE_SHARE_DELETE | (directory ? FILE_SHARE_WRITE : 0), optional);
}
static void named(HANDLE at, const WCHAR *name, HANDLE handle, const char *expected, BOOL directory, unsigned links) {
  HANDLE current = open_leaf(at, name, directory, FALSE, FALSE,
    FILE_SHARE_READ | FILE_SHARE_DELETE | (directory ? FILE_SHARE_WRITE : 0), FALSE);
  char left[50], right[50];
  identify(handle, directory, links, left); identify(current, directory, links, right);
  need(same(left, expected) && same(right, expected)); volume(left); need(CloseHandle(current));
}
static void absent(HANDLE at, const WCHAR *name, BOOL directory) {
  HANDLE current = opened(at, name, directory, TRUE); need(!current);
}
static void ancestors(void) {
  char current[50]; identify(base, TRUE, 0, current); need(same(current, base_id)); volume(current);
  named(base, L"files", root, root_id, TRUE, 0);
  if (parent) named(root, L"allocation", parent, parent_id, TRUE, 0);
}
static BOOL alias(void) { return leaf && temporary && same(leaf_id, temporary_id); }
static void objects(void) {
  ancestors(); unsigned links = alias() ? 2 : 1;
  if (leaf) named(parent, L"value", leaf, leaf_id, FALSE, links);
  if (temporary) named(parent, L".pending", temporary, temporary_id, FALSE, links);
}
static void report(const char *phase) {
  char p[54] = "null", l[54] = "null", t[54] = "null";
  if (parent) snprintf(p, sizeof(p), "\"%s\"", parent_id);
  if (leaf) snprintf(l, sizeof(l), "\"%s\"", leaf_id);
  if (temporary) snprintf(t, sizeof(t), "\"%s\"", temporary_id);
  need(printf("{\"nonce\":\"%ls\",\"phase\":\"%s\",\"base\":\"%s\",\"root\":\"%s\","
    "\"allocation\":%s,\"leaf\":%s,\"temporary\":%s,\"alias\":%s}\n",
    nonce, phase, base_id, root_id, p, l, t, alias() ? "true" : "false") > 0 && !fflush(stdout));
}
static void line(char *out, size_t size) {
  need(fgets(out, (int)size, stdin) != NULL); size_t length = strlen(out);
  need(length && out[length - 1] == '\n'); out[length - 1] = 0; bounded();
}
static void barrier(const char *phase) {
  report(phase); char ack[32]; line(ack, sizeof(ack)); need(!strcmp(ack, "continue - - - -")); objects();
}
static void remove_name(HANDLE at, const WCHAR *name, HANDLE *handle, const char *expected, BOOL directory, unsigned links) {
  named(at, name, *handle, expected, directory, links);
  ULONG flags = 3; IO_STATUS_BLOCK status; /* DELETE | POSIX_SEMANTICS, class 64. */
  need(nt_set(*handle, &status, &flags, sizeof(flags), (FILE_INFORMATION_CLASS)64) == 0 && CloseHandle(*handle));
  *handle = NULL; absent(at, name, directory);
}
static int digit(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; need(FALSE); return 0; }
static void publish(const char *hex, BOOL replace) {
  need(parent && !temporary && (!replace || leaf)); objects(); absent(parent, L".pending", FALSE);
  temporary = open_leaf(parent, L".pending", FALSE, TRUE, TRUE, FILE_SHARE_READ | FILE_SHARE_DELETE, FALSE);
  identify(temporary, FALSE, 1, temporary_id); volume(temporary_id);
  BYTE bytes[4096]; size_t length = !strcmp(hex, "-") ? 0 : strlen(hex); need(length <= 8192 && length % 2 == 0);
  for (size_t i = 0; i < length; i += 2) bytes[i / 2] = (BYTE)(digit(hex[i]) * 16 + digit(hex[i + 1]));
  DWORD written = 0; while (written < length / 2) {
    DWORD count; need(WriteFile(temporary, bytes + written, (DWORD)(length / 2 - written), &count, NULL) && count); written += count;
  }
  need(FlushFileBuffers(temporary));
  /* Seal away write access while always holding the exact staging identity. */
  HANDLE sealed = open_leaf(parent, L".pending", FALSE, FALSE, FALSE,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FALSE); char id[50];
  identify(sealed, FALSE, 1, id); need(same(id, temporary_id) && CloseHandle(temporary));
  temporary = opened(parent, L".pending", FALSE, FALSE); need(CloseHandle(sealed)); objects();
  barrier("prepared"); IO_STATUS_BLOCK status;
  if (replace) {
    struct rename_name target = {0}; target.flags = 3; target.root = parent; target.length = 10;
    wcscpy_s(target.name, 16, L"value"); /* REPLACE_IF_EXISTS | POSIX_SEMANTICS. */
    need(nt_set(temporary, &status, &target, offsetof(struct rename_name, name) + target.length,
      (FILE_INFORMATION_CLASS)65) == 0 && CloseHandle(leaf));
    leaf = temporary; memcpy(leaf_id, temporary_id, sizeof(leaf_id)); temporary = NULL;
  } else {
    struct link_name target = {0}; target.root = parent; target.length = 10; wcscpy_s(target.name, 16, L"value");
    NTSTATUS result = nt_set(temporary, &status, &target, offsetof(struct link_name, name) + target.length,
      (FILE_INFORMATION_CLASS)11);
    if (result == (NTSTATUS)0xc0000035L) {
      need(leaf != NULL); objects(); remove_name(parent, L".pending", &temporary, temporary_id, FALSE, 1);
      report("exists"); return;
    }
    need(result == 0 && !leaf);
    leaf = opened(parent, L"value", FALSE, FALSE); identify(leaf, FALSE, 2, leaf_id); need(same(leaf_id, temporary_id));
    barrier("linked"); remove_name(parent, L".pending", &temporary, temporary_id, FALSE, 2);
  }
  objects(); absent(parent, L".pending", FALSE); barrier("published"); report("complete");
}
static void recover(const char *allocation, const char *old, const char *pending) {
  need(!parent && strcmp(allocation, "-")); parent = opened(root, L"allocation", TRUE, TRUE);
  if (!parent) { report("recovered"); return; }
  identify(parent, TRUE, 0, parent_id); need(same(parent_id, allocation)); volume(parent_id); ancestors();
  leaf = opened(parent, L"value", FALSE, TRUE); temporary = opened(parent, L".pending", FALSE, TRUE);
  FILE_STANDARD_INFO standard; unsigned links = 1;
  if (temporary) {
    need(GetFileInformationByHandleEx(temporary, FileStandardInfo, &standard, sizeof(standard)) &&
      (standard.NumberOfLinks == 1 || standard.NumberOfLinks == 2)); links = standard.NumberOfLinks;
    identify(temporary, FALSE, links, temporary_id); need(same(temporary_id, pending)); volume(temporary_id);
  }
  if (leaf) {
    identify(leaf, FALSE, links, leaf_id); need(same(leaf_id, old) || same(leaf_id, pending)); volume(leaf_id);
  }
  need(links != 2 || alias()); objects(); report("recovered");
}
static void cleanup(void) {
  objects(); if (!parent) absent(root, L"allocation", TRUE); barrier("removing");
  if (temporary) remove_name(parent, L".pending", &temporary, temporary_id, FALSE, alias() ? 2 : 1);
  if (leaf) remove_name(parent, L"value", &leaf, leaf_id, FALSE, 1);
  if (parent) { ancestors(); remove_name(root, L"allocation", &parent, parent_id, TRUE, 0); }
  report("removed"); /* Empty-directory disposition only; no recursive deletion. */
}
static HANDLE inherited(const wchar_t *value) {
  wchar_t *end; ULONGLONG raw = _wcstoui64(value, &end, 10);
  need(*value >= L'1' && *value <= L'9' && wcsspn(value, L"0123456789") == wcslen(value) && !*end && raw && raw != UINT64_MAX);
  HANDLE handle = (HANDLE)(ULONG_PTR)raw; need(SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)); return handle;
}
int wmain(int argc, wchar_t **argv) {
  need(argc == 6 && _setmode(_fileno(stdin), _O_BINARY) != -1 && _setmode(_fileno(stdout), _O_BINARY) != -1);
  WCHAR ci[16], actions[16];
  need(GetEnvironmentVariableW(L"CI", ci, 16) == 4 && !wcscmp(ci, L"true") &&
    GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 16) == 4 && !wcscmp(actions, L"true"));
  nonce = argv[1]; need(wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32);
  need(GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE && GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE &&
    GetStdHandle(STD_INPUT_HANDLE) != GetStdHandle(STD_OUTPUT_HANDLE) &&
    GetStdHandle(STD_ERROR_HANDLE) == GetStdHandle(STD_OUTPUT_HANDLE));
  HANDLE token; DWORD size, session; BYTE user[256], system[SECURITY_MAX_SID_SIZE]; size = sizeof(system);
  need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) &&
    GetTokenInformation(token, TokenUser, user, sizeof(user), &size) && EqualSid(((TOKEN_USER *)user)->User.Sid, system) &&
    GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size) && session == 0 && CloseHandle(token));
  HMODULE module = GetModuleHandleW(L"ntdll.dll"); need(module != NULL);
  nt_create = (create_file)GetProcAddress(module, "NtCreateFile"); nt_set = (set_file)GetProcAddress(module, "NtSetInformationFile");
  nt_query = (query_file)GetProcAddress(module, "NtQueryInformationFile"); need(nt_create && nt_set && nt_query);
  need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)", SDDL_REVISION_1, &security, NULL));
  started = GetTickCount64(); need(CreateThread(NULL, 0, expire, NULL, 0, NULL) != NULL);
  root = inherited(argv[2]); base = inherited(argv[3]); need(root != base);
  identify(root, TRUE, 0, root_id); identify(base, TRUE, 0, base_id); volume(base_id); need(!same(root_id, base_id));
  char expected[50]; need(wcslen(argv[4]) == 49 && wcslen(argv[5]) == 49 &&
    wcsspn(argv[4], L"0123456789abcdef:") == 49 && wcsspn(argv[5], L"0123456789abcdef:") == 49);
  for (unsigned i = 0; i < 49; i++) expected[i] = (char)argv[4][i]; expected[49] = 0; need(same(expected, root_id));
  for (unsigned i = 0; i < 49; i++) expected[i] = (char)argv[5][i]; need(same(expected, base_id));
  ancestors(); report("ready"); char input[8400]; line(input, sizeof(input)); need(!strcmp(input, "start - - - -"));
  WCHAR name[128]; need(swprintf_s(name, 128, L"Local\\NativeFiles-%hs", root_id) > 0);
  WCHAR *separator = wcschr(name, L':'); if (separator) *separator = L'-';
  SECURITY_ATTRIBUTES attributes = {sizeof(attributes), security, FALSE};
  SetLastError(ERROR_SUCCESS); mutex = CreateMutexW(&attributes, TRUE, name);
  need(mutex && GetLastError() != ERROR_ALREADY_EXISTS);
  for (unsigned count = 0; count < 32; count++) {
    char operation[16], allocation[50], value[50], pending[50], bytes[8193], extra;
    line(input, sizeof(input)); need(sscanf_s(input, "%15s %49s %49s %49s %8192s %c", operation, (unsigned)sizeof(operation),
      allocation, (unsigned)sizeof(allocation), value, (unsigned)sizeof(value), pending, (unsigned)sizeof(pending),
      bytes, (unsigned)sizeof(bytes), &extra, 1u) == 5); ancestors();
    if (!strcmp(operation, "allocate")) {
      need(!parent && !strcmp(allocation, "-") && !strcmp(value, "-") && !strcmp(pending, "-") && !strcmp(bytes, "-"));
      absent(root, L"allocation", TRUE); parent = open_leaf(root, L"allocation", TRUE, TRUE, FALSE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FALSE);
      identify(parent, TRUE, 0, parent_id); volume(parent_id); report("allocated"); continue;
    }
    if (!strcmp(operation, "recover")) { need(!strcmp(bytes, "-")); recover(allocation, value, pending); continue; }
    need((parent ? same(allocation, parent_id) : !strcmp(allocation, "-")) &&
      (leaf ? same(value, leaf_id) : !strcmp(value, "-")) && (temporary ? same(pending, temporary_id) : !strcmp(pending, "-")));
    if (!strcmp(operation, "publish") || !strcmp(operation, "replace")) { publish(bytes, !strcmp(operation, "replace")); continue; }
    need(!strcmp(bytes, "-"));
    if (!strcmp(operation, "cleanup")) { cleanup(); continue; }
    if (!strcmp(operation, "inspect")) { objects(); report("inspected"); continue; }
    if (!strcmp(operation, "finish")) { objects(); report("finished"); need(ReleaseMutex(mutex) && CloseHandle(mutex)); LocalFree(security); return 0; }
    need(FALSE);
  }
  ExitProcess(126);
}
