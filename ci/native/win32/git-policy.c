/* Dedicated System CI only. A protected bridge passes the exact independently
 * reviewed synthetic Git inventory through an explicit native handle list.
 * Install adds read grants only. Remove follows fresh independent retirement.
 * Unknown objects/ACLs retain exclusion; no pathname reopening or recursion. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "advapi32.lib")
#ifndef _WIN64
#error The reviewed Git policy helper requires the Windows x64 ABI.
#endif
static void need(BOOL ok) { if (!ok) ExitProcess(126); }
static DWORD WINAPI expire(void *unused) { (void)unused; Sleep(25000); ExitProcess(124); return 0; }
static HANDLE inherited(const WCHAR *value) {
  WCHAR *end; ULONGLONG raw = _wcstoui64(value, &end, 10);
  need(*value >= L'1' && *value <= L'9' && wcsspn(value, L"0123456789") == wcslen(value) && !*end && raw && raw != UINT64_MAX);
  HANDLE handle = (HANDLE)(ULONG_PTR)raw; need(SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)); return handle;
}
static void identify(HANDLE file, const WCHAR *expected, WCHAR *path, BOOL directory) {
  FILE_ATTRIBUTE_TAG_INFO tag; FILE_ID_INFO id; FILE_STANDARD_INFO standard; WCHAR actual[50];
  need(GetFileType(file) == FILE_TYPE_DISK && GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) &&
    !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && !!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory &&
    GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) && id.VolumeSerialNumber &&
    GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) && !standard.DeletePending && (directory || standard.NumberOfLinks == 1));
  need(swprintf_s(actual, 50, L"%016llx:", id.VolumeSerialNumber) == 17);
  for (unsigned i = 0; i < 16; i++) swprintf_s(actual + 17 + i * 2, 50 - 17 - i * 2, L"%02x", id.FileId.Identifier[i]);
  need(!wcscmp(actual, expected));
  DWORD length = GetFinalPathNameByHandleW(file, path, 8192, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  need(length > 7 && length < 8192 && !wcsncmp(path, L"\\\\?\\", 4) && path[4] >= L'A' && path[4] <= L'Z' && path[5] == L':' && path[6] == L'\\');
}
static BOOL inside(const WCHAR *parent, const WCHAR *child) {
  size_t size = wcslen(parent); return !wcsncmp(parent, child, size) && child[size] == L'\\';
}
static PSECURITY_DESCRIPTOR descriptor(const WCHAR *text) {
  PSECURITY_DESCRIPTOR value = NULL; need(ConvertStringSecurityDescriptorToSecurityDescriptorW(text, SDDL_REVISION_1, &value, NULL)); return value;
}
static void acl(HANDLE file, PSID account, PSID restricting, BOOL directory, BOOL removing, PACL target) {
  PSID owner; PACL dacl; PSECURITY_DESCRIPTOR sd = NULL; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
  need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) &&
    GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS &&
    EqualSid(owner, system) && dacl && GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED) &&
    dacl->AceCount == (removing ? 3 : 1));
  for (unsigned i = 0; i < dacl->AceCount; i++) {
    ACCESS_ALLOWED_ACE *ace; PSID expected = i == 0 ? (PSID)system : i == 1 ? account : restricting;
    DWORD mask = i == 0 ? FILE_ALL_ACCESS : FILE_GENERIC_READ | (directory ? FILE_TRAVERSE : 0);
    need(GetAce(dacl, i, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags &&
      EqualSid((PSID)&ace->SidStart, expected) && ace->Mask == mask);
  }
  LocalFree(sd);
  need(SetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, target, NULL) == ERROR_SUCCESS);
}
int wmain(int argc, WCHAR **argv) {
  need(argc >= 12 && argc <= 777 && (argc - 9) % 3 == 0 && _setmode(_fileno(stdin), _O_BINARY) != -1 && _setmode(_fileno(stdout), _O_BINARY) != -1);
  need(wcslen(argv[1]) == 32 && wcsspn(argv[1], L"0123456789abcdef") == 32);
  BOOL removing = !wcscmp(argv[8], L"remove"); need(removing || !wcscmp(argv[8], L"install"));
  PSID account, restricting; need(ConvertStringSidToSidW(argv[2], &account) && ConvertStringSidToSidW(argv[3], &restricting) && !EqualSid(account, restricting));
  HANDLE token; BYTE user[256], system[SECURITY_MAX_SID_SIZE]; DWORD size, session; size = sizeof(system);
  WCHAR ci[16], actions[16]; need(GetEnvironmentVariableW(L"CI", ci, 16) == 4 && !wcscmp(ci, L"true") &&
    GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 16) == 4 && !wcscmp(actions, L"true") &&
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) &&
    GetTokenInformation(token, TokenUser, user, sizeof(user), &size) && EqualSid(((TOKEN_USER *)user)->User.Sid, system) &&
    GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size) && session == 0 && CloseHandle(token) &&
    !EqualSid(account, system) && !EqualSid(restricting, system));
  need(GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE && GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE &&
    CreateThread(NULL, 0, expire, NULL, 0, NULL));
  HANDLE storage = inherited(argv[4]), workspace = inherited(argv[5]); WCHAR storagePath[8192], workspacePath[8192];
  identify(storage, argv[6], storagePath, TRUE); identify(workspace, argv[7], workspacePath, TRUE); need(inside(storagePath, workspacePath));
  unsigned count = (unsigned)(argc - 9) / 3; HANDLE files[256]; BOOL directories[256];
  WCHAR (*paths)[8192] = calloc(count, sizeof(*paths)); need(paths != NULL);
  WCHAR metadata[8192], hooks[8192], content[8192];
  need(swprintf_s(metadata, 8192, L"%ls\\metadata", storagePath) > 0 && swprintf_s(hooks, 8192, L"%ls\\hooks", storagePath) > 0 &&
    swprintf_s(content, 8192, L"%ls\\content.txt", workspacePath) > 0);
  for (unsigned i = 0; i < count; i++) {
    files[i] = inherited(argv[9 + i * 3]); directories[i] = !wcscmp(argv[11 + i * 3], L"directory");
    need(directories[i] || !wcscmp(argv[11 + i * 3], L"file")); identify(files[i], argv[10 + i * 3], paths[i], directories[i]);
    need((!wcscmp(paths[i], metadata) || inside(metadata, paths[i]) || !wcscmp(paths[i], hooks) || !wcscmp(paths[i], content)) &&
      wcsncmp(argv[10 + i * 3], argv[6], 16) == 0);
    for (unsigned j = 0; j < i; j++) need(wcscmp(argv[10 + i * 3], argv[10 + j * 3]) && _wcsicmp(paths[i], paths[j]));
  }
  need(printf("{\"nonce\":\"%ls\",\"phase\":\"before-write\",\"objects\":%u}\n", argv[1], count) > 0 && !fflush(stdout));
  char ack[8]; need(fgets(ack, sizeof(ack), stdin) && !strcmp(ack, removing ? "D\n" : "I\n"));
  PSECURITY_DESCRIPTOR systemSd = descriptor(L"O:SYG:SYD:P(A;;FA;;;SY)"); PACL systemAcl; BOOL present, defaulted;
  need(GetSecurityDescriptorDacl(systemSd, &present, &systemAcl, &defaulted) && present);
  for (unsigned i = 0; i < count; i++) {
    WCHAR currentStorage[8192], currentWorkspace[8192];
    identify(storage, argv[6], currentStorage, TRUE); identify(workspace, argv[7], currentWorkspace, TRUE);
    need(!wcscmp(currentStorage, storagePath) && !wcscmp(currentWorkspace, workspacePath));
    WCHAR current[8192]; identify(files[i], argv[10 + i * 3], current, directories[i]); need(!wcscmp(current, paths[i]));
    WCHAR text[2048]; DWORD mask = FILE_GENERIC_READ | (directories[i] ? FILE_TRAVERSE : 0);
    need(swprintf_s(text, 2048, L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x%lx;;;%ls)(A;;0x%lx;;;%ls)", mask, argv[2], mask, argv[3]) > 0);
    PSECURITY_DESCRIPTOR readSd = descriptor(text); PACL readAcl; need(GetSecurityDescriptorDacl(readSd, &present, &readAcl, &defaulted) && present);
    acl(files[i], account, restricting, directories[i], removing, removing ? systemAcl : readAcl); LocalFree(readSd);
  }
  need(printf("{\"nonce\":\"%ls\",\"phase\":\"complete\"}\n", argv[1]) > 0 && !fflush(stdout));
  free(paths); LocalFree(systemSd); LocalFree(account); LocalFree(restricting); return 0;
}
