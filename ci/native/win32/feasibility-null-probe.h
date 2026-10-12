/* Diagnostic only. Pinned phnt 53fbbdc and Microsoft SDK 76c04c2 declare
 * these ABIs; neither establishes AppContainer shadow lookup or authority. */
#include <stddef.h>
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } NULL_UNICODE;
typedef struct {
  ULONG Length; HANDLE RootDirectory; NULL_UNICODE *ObjectName; ULONG Attributes;
  void *SecurityDescriptor, *SecurityQualityOfService;
} NULL_ATTRIBUTES;
typedef union {
  struct { HANDLE DirectoryHandle; } Set;
  struct { ULONG DriveMap; UCHAR DriveType[32]; } Query;
} NULL_DEVICE_MAP;
_Static_assert(sizeof(NULL_UNICODE) == 16 && offsetof(NULL_UNICODE, Buffer) == 8, "x64 UNICODE_STRING");
_Static_assert(sizeof(NULL_ATTRIBUTES) == 48 && offsetof(NULL_ATTRIBUTES, RootDirectory) == 8 &&
  offsetof(NULL_ATTRIBUTES, ObjectName) == 16 && offsetof(NULL_ATTRIBUTES, Attributes) == 24 &&
  offsetof(NULL_ATTRIBUTES, SecurityDescriptor) == 32 && offsetof(NULL_ATTRIBUTES, SecurityQualityOfService) == 40, "x64 OBJECT_ATTRIBUTES");
_Static_assert(sizeof(NULL_DEVICE_MAP) == 40 && offsetof(NULL_DEVICE_MAP, Set.DirectoryHandle) == 0 &&
  offsetof(NULL_DEVICE_MAP, Query.DriveMap) == 0 && offsetof(NULL_DEVICE_MAP, Query.DriveType) == 4, "x64 PROCESS_DEVICEMAP_INFORMATION union");
typedef LONG (NTAPI *null_open_directory)(HANDLE *, ACCESS_MASK, NULL_ATTRIBUTES *);
typedef LONG (NTAPI *null_create_directory)(HANDLE *, ACCESS_MASK, NULL_ATTRIBUTES *, HANDLE, ULONG);
typedef LONG (NTAPI *null_create_link)(HANDLE *, ACCESS_MASK, NULL_ATTRIBUTES *, const NULL_UNICODE *);
typedef LONG (NTAPI *null_open_link)(HANDLE *, ACCESS_MASK, NULL_ATTRIBUTES *);
typedef LONG (NTAPI *null_query_link)(HANDLE, NULL_UNICODE *, ULONG *);
typedef LONG (NTAPI *null_set_map)(HANDLE, ULONG, void *, ULONG);
static struct {
  HANDLE source, payload, job, child, base, parent, endpoint, shadow, directory, link, observationLink, controller, recipe;
  char identity[50];
} null_owned;
static NULL_UNICODE null_string(WCHAR *text) {
  size_t bytes = wcslen(text) * sizeof(WCHAR); invariant(bytes <= 65532, "path-bound");
  return (NULL_UNICODE){(USHORT)bytes, (USHORT)(bytes + sizeof(WCHAR)), text};
}
static void null_hex(const WCHAR *text, DWORD chars) {
  putchar('"'); for (DWORD i = 0; i < chars; i++) printf("%04x", (unsigned)text[i]); putchar('"');
}
static void null_error(const char *operation, const char *domain, DWORD value) {
  WCHAR *message = NULL; DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
  flags |= !strcmp(domain, "ntstatus") ? FORMAT_MESSAGE_FROM_HMODULE : FORMAT_MESSAGE_FROM_SYSTEM;
  DWORD size = FormatMessageW(flags, !strcmp(domain, "ntstatus") ? GetModuleHandleW(L"ntdll.dll") : NULL,
    value, 0, (WCHAR *)&message, 0, NULL);
  printf("{\"event\":\"null-error\",\"operation\":\"%s\",\"domain\":\"%s\",\"value\":%lu,\"messageAvailable\":%s,\"messageUtf16\":", operation, domain, value, size ? "true" : "false");
  if (size) null_hex(message, size); else printf("null"); puts("}"); LocalFree(message);
}
static BOOL null_status(const char *operation, LONG status) {
  printf("{\"event\":\"null-operation\",\"operation\":\"%s\",\"status\":%lu}\n", operation, (DWORD)status);
  if (!status) return TRUE; null_error(operation, "ntstatus", (DWORD)status); return FALSE;
}
static void null_controller(null_open_link openLink, null_query_link queryLink, const char *phase) {
  WCHAR nul[] = L"NUL", target[4096]; NULL_UNICODE label = null_string(nul), destination = {0, sizeof(target), target};
  NULL_ATTRIBUTES attributes = {sizeof(attributes), null_owned.shadow, &label, 0x40, NULL, NULL};
  BOOL attempted = null_owned.shadow && openLink && queryLink;
  LONG status = 0; if (attempted) {
    status = openLink(&null_owned.observationLink, 1, &attributes);
    if (!status) status = queryLink(null_owned.observationLink, &destination, NULL);
    if (!release_handle(&null_owned.observationLink, "null-close")) failure(126);
  }
  HANDLE actual = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); null_owned.controller = actual;
  DWORD error = actual == INVALID_HANDLE_VALUE ? GetLastError() : 0, type = 0;
  if (actual != INVALID_HANDLE_VALUE) { SetLastError(0); type = GetFileType(actual); if (type == FILE_TYPE_UNKNOWN) error = GetLastError(); }
  if (!release_handle(&null_owned.controller, "null-close")) failure(126);
  printf("{\"event\":\"null-controller\",\"phase\":\"%s\",\"linkAttempted\":%s,\"linkStatus\":", phase, attempted ? "true" : "false");
  if (attempted) printf("%lu", (DWORD)status); else printf("null"); printf(",\"targetUtf16\":");
  if (attempted && !status && destination.Length <= sizeof(target)) null_hex(target, destination.Length / sizeof(WCHAR)); else printf("null");
  printf(",\"openError\":%lu,\"fileType\":%lu}\n", error, type);
}
static void null_endpoint(const char *phase) {
  if (!null_owned.endpoint || null_owned.endpoint == INVALID_HANDLE_VALUE) return;
  LARGE_INTEGER size; win32_check(GetFileSizeEx(null_owned.endpoint, &size), "null-endpoint-size");
  char id[50]; fileid(null_owned.endpoint, id);
  printf("{\"event\":\"null-endpoint\",\"phase\":\"%s\",\"identity\":\"%s\",\"bytes\":%lld,\"identityUnchanged\":%s}\n", phase, id, size.QuadPart, !strcmp(id, null_owned.identity) ? "true" : "false");
  invariant(size.QuadPart == 0 && !strcmp(id, null_owned.identity), "null-endpoint-state");
}
static void null_cleanup_error(const char *operation, const char *domain, DWORD value) { remember(operation, domain, value); cleanup_error(operation, domain, value); }
static BOOL settle_null_map(void) {
  BOOL ok = TRUE;
  if (null_owned.endpoint && null_owned.endpoint != INVALID_HANDLE_VALUE) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account;
    ULONGLONG expires = GetTickCount64() + 8000;
    BOOL retired = transport_wait(null_owned.child, expires, "null-retirement");
    if (!transport_wait(null_owned.payload, expires, "null-retirement")) retired = FALSE;
    if (retired && null_owned.job) { if (!QueryInformationJobObject(null_owned.job, JobObjectBasicAccountingInformation, &account, sizeof(account), NULL)) { null_cleanup_error("null-retirement", "win32", GetLastError()); retired = FALSE; } else retired = !account.ActiveProcesses; }
    else retired = FALSE;
    if (retired) {
      FILE_DISPOSITION_INFO remove = {TRUE};
      if (!SetFileInformationByHandle(null_owned.endpoint, FileDispositionInfo, &remove, sizeof(remove))) {
        null_cleanup_error("null-remove", "win32", GetLastError()); ok = FALSE;
      }
    } else { null_cleanup_error("null-retirement", "invariant", 0); ok = FALSE; }
  }
  HANDLE *handles[] = {&null_owned.child, &null_owned.link, &null_owned.directory, &null_owned.shadow,
    &null_owned.endpoint, &null_owned.parent, &null_owned.base, &null_owned.job, &null_owned.payload, &null_owned.source,
    &null_owned.observationLink, &null_owned.controller, &null_owned.recipe};
  for (unsigned i = 0; i < sizeof(handles) / sizeof(handles[0]); i++) if (!release_handle(handles[i], "null-close")) ok = FALSE;
  return ok;
}
static void null_map(WCHAR **args) {
  owned_profile();
  printf("{\"event\":\"null-owner\",\"owner\":"); identity(GetCurrentProcess()); puts("}");
  original_owned((DWORD)number(args[0]), number(args[1]), PROCESS_DUP_HANDLE, &null_owned.source);
  null_owned.job = duplicate(null_owned.source, args[2], JOB_OBJECT_QUERY | READ_CONTROL); limits(null_owned.job);
  original_owned((DWORD)number(args[7]), number(args[8]), PROCESS_DUP_HANDLE, &null_owned.payload); container(null_owned.payload);
  null_owned.child = duplicate(null_owned.payload, args[3], PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | READ_CONTROL);
  invariant(creation(null_owned.child) == number(args[4]), "process-time"); container(null_owned.child);
  BOOL member; win32_check(IsProcessInJob(null_owned.child, null_owned.job, &member), "process-job"); invariant(member, "process-job");
  win32_check(IsProcessInJob(null_owned.payload, null_owned.job, &member), "process-job"); invariant(member, "process-job");
  DWORD wait = WaitForSingleObject(null_owned.child, 0); win32_check(wait != WAIT_FAILED, "process-wait"); invariant(wait == WAIT_TIMEOUT, "process-wait");
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  const char *names[] = {"NtOpenDirectoryObject", "NtCreateDirectoryObjectEx", "NtCreateSymbolicLinkObject", "NtOpenSymbolicLinkObject", "NtQuerySymbolicLinkObject", "NtSetInformationProcess"};
  FARPROC apis[6]; DWORD errors[6]; BOOL available = TRUE, bound = FALSE;
  printf("{\"event\":\"null-apis\",\"exports\":[");
  for (unsigned i = 0; i < 6; i++) { apis[i] = GetProcAddress(module, names[i]); errors[i] = apis[i] ? 0 : GetLastError();
    if (i) putchar(','); printf("{\"name\":\"%s\",\"available\":%s,\"error\":%lu}", names[i], apis[i] ? "true" : "false", errors[i]); if (!apis[i]) available = FALSE; } puts("]}");
  null_open_directory openDirectory = (null_open_directory)apis[0]; null_create_directory createDirectory = (null_create_directory)apis[1];
  null_create_link createLink = (null_create_link)apis[2]; null_open_link openLink = (null_open_link)apis[3];
  null_query_link queryLink = (null_query_link)apis[4]; null_set_map setMap = (null_set_map)apis[5];
  if (!available) { null_controller(openLink, queryLink, "before"); for (unsigned i = 0; i < 6; i++) if (!apis[i]) null_error(names[i], "win32", errors[i]); goto held; }
  WCHAR dos[] = L"\\??", nul[] = L"NUL", path[4096], nativePath[4096]; NULL_UNICODE label = null_string(dos);
  NULL_ATTRIBUTES attributes = {sizeof(attributes), NULL, &label, 0x40, NULL, NULL};
  if (!null_status("NtOpenDirectoryObject", openDirectory(&null_owned.shadow, 3, &attributes))) { null_controller(openLink, queryLink, "before"); goto held; }
  null_controller(openLink, queryLink, "before");
  null_owned.base = CreateFileW(root, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (null_owned.base == INVALID_HANDLE_VALUE) { null_error("endpoint-root", "win32", GetLastError()); goto held; }
  char baseId[50]; fileid(null_owned.base, baseId); invariant(!strcmp(baseId, record.rootId), "file-id");
  FILE_ATTRIBUTE_TAG_INFO tag; win32_check(GetFileInformationByHandleEx(null_owned.base, FileAttributeTagInfo, &tag, sizeof(tag)), "file-tag");
  invariant((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "file-tag");
  name(path, L"workspace"); null_owned.parent = CreateFileW(path, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (null_owned.parent == INVALID_HANDLE_VALUE) { null_error("endpoint-parent", "win32", GetLastError()); goto held; }
  win32_check(GetFileInformationByHandleEx(null_owned.parent, FileAttributeTagInfo, &tag, sizeof(tag)), "file-shape");
  invariant(!(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "file-shape"); acl(null_owned.parent, SE_FILE_OBJECT, FALSE);
  WCHAR sddl[1024]; invariant(swprintf_s(sddl, 1024, L"O:%lsD:P(A;;FA;;;%ls)(A;;0x%08lx;;;%ls)S:(ML;;NW;;;LW)", userText, userText, (DWORD)(FILE_GENERIC_READ | FILE_GENERIC_WRITE), appText) > 0, "security-descriptor");
  PSECURITY_DESCRIPTOR security; win32_check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &security, NULL), "security-descriptor"); SECURITY_ATTRIBUTES fileSecurity = {sizeof(fileSecurity), security, FALSE};
  name(path, L"workspace\\null-endpoint"); null_owned.endpoint = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, &fileSecurity, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  DWORD error = null_owned.endpoint == INVALID_HANDLE_VALUE ? GetLastError() : 0; LocalFree(security);
  if (error) { null_error("endpoint-create-exclusive", "win32", error); goto held; }
  fileid(null_owned.endpoint, null_owned.identity); null_endpoint("before");
  DWORD length = GetFinalPathNameByHandleW(null_owned.endpoint, nativePath, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
  if (!length || length >= 4096) { null_error("endpoint-native-path", "win32", length ? ERROR_INSUFFICIENT_BUFFER : GetLastError()); goto held; }
  HANDLE recipe = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  null_owned.recipe = recipe;
  error = recipe == INVALID_HANDLE_VALUE ? GetLastError() : 0;
  printf("{\"event\":\"null-open-recipe\",\"error\":%lu,\"access\":%lu,\"sharing\":7,\"disposition\":3,\"flags\":128,\"targetUtf16\":", error, (DWORD)(GENERIC_READ | GENERIC_WRITE)); null_hex(nativePath, length); puts("}");
  if (!release_handle(&null_owned.recipe, "null-close")) failure(126);
  if (error) { null_error("endpoint-open-recipe", "win32", error); goto held; }
  security = descriptor(2, FALSE); attributes = (NULL_ATTRIBUTES){sizeof(attributes), NULL, NULL, 0, security, NULL};
  LONG status = createDirectory(&null_owned.directory, 0x0f, &attributes, null_owned.shadow, 0); LocalFree(security);
  if (!null_status("NtCreateDirectoryObjectEx", status)) goto held;
  label = null_string(nul); NULL_UNICODE target = null_string(nativePath); security = descriptor(1, FALSE);
  attributes = (NULL_ATTRIBUTES){sizeof(attributes), null_owned.directory, &label, 0x40, security, NULL};
  status = createLink(&null_owned.link, 1, &attributes, &target); LocalFree(security);
  if (!null_status("NtCreateSymbolicLinkObject", status)) goto held;
  NULL_DEVICE_MAP map = {0}; map.Set.DirectoryHandle = null_owned.directory;
  bound = null_status("NtSetInformationProcess", setMap(null_owned.child, 23, &map, sizeof(map)));
held:
  printf("{\"event\":\"null-bound\",\"bound\":%s,\"hypothesis\":\"controller-read-only-shadow\",\"owner\":", bound ? "true" : "false"); identity(GetCurrentProcess()); puts("}");
  ack('Q');
  wait = WaitForSingleObject(null_owned.child, 0); win32_check(wait != WAIT_FAILED, "null-retirement"); invariant(wait == WAIT_OBJECT_0, "null-retirement");
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account; win32_check(QueryInformationJobObject(null_owned.job, JobObjectBasicAccountingInformation, &account, sizeof(account), NULL), "null-retirement"); invariant(!account.ActiveProcesses, "null-retirement");
  null_controller(openLink, queryLink, "after");
  null_endpoint("after"); BOOL closed = settle_null_map();
  printf("{\"event\":\"null-retired\",\"resourcesClosed\":%s}\n", closed ? "true" : "false");
  if (!closed) failure(126);
}
