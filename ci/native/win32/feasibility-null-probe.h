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
_Static_assert(sizeof(((NULL_DEVICE_MAP *)0)->Set) == 8 &&
  offsetof(NULL_DEVICE_MAP, Set.DirectoryHandle) == 0, "x64 PROCESS_DEVICEMAP_INFORMATION SET");
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
typedef struct { FILE_ID_INFO id; WCHAR path[1024]; BOOL valid; } NULL_FILE_PROOF;
static struct { HANDLE held, reached; NULL_FILE_PROOF heldProof, reachedProof; } null_paths[2];
static struct { WCHAR letter, target[512]; HANDLE volume, link; NULL_FILE_PROOF proof; } null_drives[2];
static unsigned null_driveCount;
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
  DWORD size = !strcmp(domain, "invariant") ? 0 : FormatMessageW(flags, !strcmp(domain, "ntstatus") ? GetModuleHandleW(L"ntdll.dll") : NULL,
    value, 0, (WCHAR *)&message, 0, NULL);
  printf("{\"event\":\"null-error\",\"operation\":\"%s\",\"domain\":\"%s\",\"value\":%lu,\"messageAvailable\":%s,\"messageUtf16\":", operation, domain, value, size ? "true" : "false");
  if (size) null_hex(message, size); else printf("null"); puts("}"); LocalFree(message);
}
static BOOL null_status(const char *operation, LONG status) {
  printf("{\"event\":\"null-operation\",\"operation\":\"%s\",\"status\":%lu}\n", operation, (DWORD)status);
  if (!status) return TRUE; null_error(operation, "ntstatus", (DWORD)status); return FALSE;
}
/* Bounded predicates for the live mapping acquisition. */
static DWORD null_current(const WCHAR *bytes, DWORD count, DWORD capacity) {
  if (count < 3 || count > capacity || bytes[count - 1] != 0 || bytes[count - 2] != 0) return 0;
  DWORD first = 0, at = 0;
  while (at < count - 1) {
    DWORD start = at; while (at < count && bytes[at] != 0) at++;
    if (at == start || at >= count - 1) return 0;
    if (first == 0) first = at; at++;
  }
  return at == count - 1 ? first : 0;
}
static unsigned null_drive_count(WCHAR first, WCHAR second) { return first == second ? 1 : 2; }
static BOOL null_path_fits(size_t target, size_t suffix) { return target < 1024 && suffix < 1024 && target + suffix + 14 < 1024; }
static WCHAR null_drive_letter(const WCHAR *path) {
  if (wcslen(path) < 3) return 0;
  WCHAR letter = path[0]; if (letter >= L'a' && letter <= L'z') letter -= L'a' - L'A';
  return letter >= L'A' && letter <= L'Z' && path[1] == L':' && path[2] == L'\\' ? letter : 0;
}
static BOOL null_local_target(const WCHAR *target) {
  if (wcsncmp(target, L"\\Device\\HarddiskVolume", 22)) return FALSE;
  DWORD at = 22; if (target[at] < L'0' || target[at] > L'9') return FALSE;
  while (target[at] >= L'0' && target[at] <= L'9') at++;
  return target[at] == 0;
}
static BOOL null_snapshot(HANDLE handle, NULL_FILE_PROOF *proof, const char *phase, const char *kind, unsigned index) {
  FILE_STANDARD_INFO standard; FILE_ATTRIBUTE_TAG_INFO tag; DWORD length; BYTE nonzero = 0;
  if (!GetFileInformationByHandleEx(handle, FileIdInfo, &proof->id, sizeof(proof->id)) ||
      !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
      !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag))) {
    null_error("mapping-observation", "win32", GetLastError()); return FALSE;
  }
  length = GetFinalPathNameByHandleW(handle, proof->path, 1024, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
  if (!length || length >= 1024) { null_error("mapping-native-path", "win32", length ? ERROR_INSUFFICIENT_BUFFER : GetLastError()); return FALSE; }
  SetLastError(0); DWORD type = GetFileType(handle), typeError = type == FILE_TYPE_UNKNOWN ? GetLastError() : 0;
  for (unsigned i = 0; i < 16; i++) nonzero |= proof->id.FileId.Identifier[i];
  proof->valid = nonzero && proof->id.VolumeSerialNumber && standard.Directory && !standard.DeletePending &&
    !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && type == FILE_TYPE_DISK;
  printf("{\"event\":\"null-map-object\",\"phase\":\"%s\",\"kind\":\"%s\",\"index\":%u,\"valid\":%s,\"fileType\":%lu,\"fileTypeError\":%lu,\"volumeSerial\":\"%016llx\",\"fileId\":\"", phase, kind, index, proof->valid ? "true" : "false", type, typeError, proof->id.VolumeSerialNumber);
  for (unsigned i = 0; i < 16; i++) printf("%02x", proof->id.FileId.Identifier[i]); printf("\",\"nativePathUtf16\":"); null_hex(proof->path, length); puts("}");
  if (typeError) { null_error("mapping-file-type", "win32", typeError); return FALSE; }
  if (!proof->valid) null_error("mapping-object-shape", "invariant", 0); return proof->valid;
}
static BOOL null_same(const NULL_FILE_PROOF *first, const NULL_FILE_PROOF *second) {
  return first->valid && second->valid && !memcmp(&first->id, &second->id, sizeof(first->id)) && !_wcsicmp(first->path, second->path);
}
static BOOL null_recheck(const char *phase) {
  BOOL ok = TRUE;
  HANDLE handles[] = {null_paths[0].held, null_paths[0].reached, null_paths[1].held, null_paths[1].reached, null_drives[0].volume, null_drives[1].volume};
  NULL_FILE_PROOF *proofs[] = {&null_paths[0].heldProof, &null_paths[0].reachedProof, &null_paths[1].heldProof, &null_paths[1].reachedProof, &null_drives[0].proof, &null_drives[1].proof};
  for (unsigned i = 0; i < 6; i++) if (proofs[i]->valid) {
    NULL_FILE_PROOF current = {0}; BOOL unchanged = null_snapshot(handles[i], &current, phase, "recheck", i) && null_same(proofs[i], &current);
    printf("{\"event\":\"null-map-recheck\",\"phase\":\"%s\",\"index\":%u,\"unchanged\":%s}\n", phase, i, unchanged ? "true" : "false");
    if (!unchanged) { null_error("mapping-recheck", "invariant", 0); ok = FALSE; }
  }
  return ok;
}
static BOOL null_prepare_drives(void) {
  WCHAR windows[4096]; DWORD size = GetEnvironmentVariableW(L"SystemRoot", windows, 4096);
  if (!size || size >= 4096) { null_error("mapping-SystemRoot", "win32", size ? ERROR_INSUFFICIENT_BUFFER : GetLastError()); return FALSE; }
  const WCHAR *paths[] = {root, windows}; WCHAR letters[] = {null_drive_letter(root), null_drive_letter(windows)};
  if (!letters[0] || !letters[1]) { null_error("mapping-drive-letter", "invariant", 0); return FALSE; }
  null_driveCount = null_drive_count(letters[0], letters[1]);
  for (unsigned i = 0; i < null_driveCount; i++) {
    WCHAR label[] = {letters[i], L':', 0}, bytes[512] = {0}, path[1024]; null_drives[i].letter = letters[i];
    DWORD count = QueryDosDeviceW(label, bytes, 512), error = count ? 0 : GetLastError();
    DWORD selected = null_current(bytes, count, 512), captured = count && count <= 512 ? count : 512;
    printf("{\"event\":\"null-drive-query\",\"letter\":\"%lc\",\"returnedCharacters\":%lu,\"error\":%lu,\"sourceBytes\":%lu,\"sourceUtf16\":", label[0], count, error, captured * 2); null_hex(bytes, captured); printf(",\"targetUtf16\":");
    if (selected) null_hex(bytes, selected); else printf("null"); puts("}");
    if (!count || !selected || !null_local_target(bytes)) { null_error("mapping-query", count ? "invariant" : "win32", error); return FALSE; }
    wmemcpy(null_drives[i].target, bytes, selected); null_drives[i].target[selected] = 0;
    if (!null_path_fits(selected, 1)) { null_error("mapping-path-bound", "invariant", 0); return FALSE; }
    swprintf_s(path, 1024, L"\\\\?\\GLOBALROOT%ls\\", null_drives[i].target);
    null_drives[i].volume = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (null_drives[i].volume == INVALID_HANDLE_VALUE) { null_error("mapping-volume-open", "win32", GetLastError()); return FALSE; }
    if (!null_snapshot(null_drives[i].volume, &null_drives[i].proof, "before", "volume", i) || _wcsicmp(null_drives[i].proof.path, path + 14)) {
      null_error("mapping-volume-binding", "invariant", 0); return FALSE;
    }
  }
  /* Always prove both suffixes, even when both directories use one letter. */
  for (unsigned i = 0; i < 2; i++) {
    unsigned drive = i && null_driveCount == 2 ? 1 : 0; WCHAR path[1024];
    null_paths[i].held = CreateFileW(paths[i], FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (null_paths[i].held == INVALID_HANDLE_VALUE) { null_error("mapping-path-open", "win32", GetLastError()); return FALSE; }
    if (!null_snapshot(null_paths[i].held, &null_paths[i].heldProof, "before", "held", i)) return FALSE;
    if (!null_path_fits(wcslen(null_drives[drive].target), wcslen(paths[i] + 2))) { null_error("mapping-path-bound", "invariant", 0); return FALSE; }
    swprintf_s(path, 1024, L"\\\\?\\GLOBALROOT%ls%ls", null_drives[drive].target, paths[i] + 2);
    null_paths[i].reached = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (null_paths[i].reached == INVALID_HANDLE_VALUE) { null_error("mapping-target-open", "win32", GetLastError()); return FALSE; }
    if (!null_snapshot(null_paths[i].reached, &null_paths[i].reachedProof, "before", "reached", i) ||
        !null_same(&null_paths[i].heldProof, &null_paths[i].reachedProof) ||
        _wcsicmp(null_paths[i].reachedProof.path, path + 14) ||
        null_paths[i].heldProof.id.VolumeSerialNumber != null_drives[drive].proof.id.VolumeSerialNumber) {
      null_error("mapping-path-binding", "invariant", 0); return FALSE;
    }
    if (!i) {
      char id[50]; snprintf(id, 50, "%016llx:", null_paths[i].heldProof.id.VolumeSerialNumber);
      for (unsigned j = 0; j < 16; j++) snprintf(id + 17 + j * 2, 3, "%02x", null_paths[i].heldProof.id.FileId.Identifier[j]);
      if (strcmp(id, record.rootId)) { null_error("mapping-root-binding", "invariant", 0); return FALSE; }
    }
  }
  return TRUE;
}
static BOOL null_link_drives(null_create_link createLink, null_query_link queryLink) {
  for (unsigned i = 0; i < null_driveCount; i++) {
    WCHAR name[] = {null_drives[i].letter, L':', 0}, observed[512]; NULL_UNICODE label = null_string(name), target = null_string(null_drives[i].target), actual = {0, sizeof(observed), observed};
    PSECURITY_DESCRIPTOR security = descriptor(1, FALSE); NULL_ATTRIBUTES attributes = {sizeof(attributes), null_owned.directory, &label, 0x40, security, NULL};
    LONG status = createLink(&null_drives[i].link, 1, &attributes, &target); LocalFree(security);
    printf("{\"event\":\"null-drive-link\",\"letter\":\"%lc\",\"status\":%lu}\n", name[0], (DWORD)status);
    if (!null_status("NtCreateSymbolicLinkObject", status)) return FALSE;
    status = queryLink(null_drives[i].link, &actual, NULL);
    printf("{\"event\":\"null-drive-link-query\",\"letter\":\"%lc\",\"status\":%lu,\"targetUtf16\":", name[0], (DWORD)status);
    if (!status && actual.Length <= sizeof(observed)) null_hex(observed, actual.Length / 2); else printf("null"); puts("}");
    if (!null_status("NtQuerySymbolicLinkObject", status) || actual.Length != target.Length || memcmp(observed, target.Buffer, target.Length)) {
      null_error("mapping-link-binding", "invariant", 0); return FALSE;
    }
  }
  return TRUE;
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
  if (null_owned.job) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account;
    ULONGLONG expires = GetTickCount64() + 8000;
    BOOL retired = transport_wait(null_owned.child, expires, "null-retirement");
    if (!transport_wait(null_owned.payload, expires, "null-retirement")) retired = FALSE;
    if (retired && null_owned.job) { if (!QueryInformationJobObject(null_owned.job, JobObjectBasicAccountingInformation, &account, sizeof(account), NULL)) { null_cleanup_error("null-retirement", "win32", GetLastError()); retired = FALSE; } else retired = !account.ActiveProcesses; }
    else retired = FALSE;
    if (!retired) { null_cleanup_error("null-retirement", "invariant", 0); return FALSE; }
    if (!null_recheck("after")) { null_cleanup_error("null-retirement", "invariant", 0); ok = FALSE; }
    if (null_owned.endpoint && null_owned.endpoint != INVALID_HANDLE_VALUE) {
      FILE_DISPOSITION_INFO remove = {TRUE};
      if (!SetFileInformationByHandle(null_owned.endpoint, FileDispositionInfo, &remove, sizeof(remove))) {
        null_cleanup_error("null-remove", "win32", GetLastError()); ok = FALSE;
      }
    }
  }
  for (unsigned i = 0; i < 2; i++) {
    HANDLE *mapped[] = {&null_drives[i].link, &null_paths[i].reached, &null_paths[i].held, &null_drives[i].volume};
    for (unsigned j = 0; j < 4; j++) if (!release_handle(mapped[j], "null-close")) ok = FALSE;
    null_paths[i].heldProof.valid = null_paths[i].reachedProof.valid = null_drives[i].proof.valid = FALSE;
  }
  HANDLE *handles[] = {&null_owned.child, &null_owned.link, &null_owned.directory, &null_owned.shadow,
    &null_owned.endpoint, &null_owned.parent, &null_owned.base, &null_owned.job, &null_owned.payload, &null_owned.source,
    &null_owned.observationLink, &null_owned.controller, &null_owned.recipe};
  for (unsigned i = 0; i < sizeof(handles) / sizeof(handles[0]); i++) if (!release_handle(handles[i], "null-close")) ok = FALSE;
  return ok;
}
static void null_map(WCHAR **args) {
  owned_profile();
  printf("{\"event\":\"null-owner\",\"caseId\":\"%ls\",\"owner\":", nullProbeCase); identity(GetCurrentProcess()); puts("}");
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
  FARPROC apis[6]; DWORD errors[6]; BOOL available = TRUE, bound = FALSE, mapped = !wcscmp(nullProbeCase, L"no-shadow-mapped"), mappedSetup = FALSE, setSucceeded = FALSE;
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
  if (mapped && !null_prepare_drives()) goto held;
  security = descriptor(2, FALSE); attributes = (NULL_ATTRIBUTES){sizeof(attributes), NULL, NULL, 0, security, NULL};
  HANDLE creationShadow = !wcscmp(nullProbeCase, L"shadow") ? null_owned.shadow : NULL;
  printf("{\"event\":\"null-directory-request\",\"caseId\":\"%ls\",\"shadowPresent\":%s}\n", nullProbeCase, creationShadow ? "true" : "false");
  LONG status = createDirectory(&null_owned.directory, 0x0f, &attributes, creationShadow, 0); LocalFree(security);
  if (!null_status("NtCreateDirectoryObjectEx", status)) goto held;
  label = null_string(nul); NULL_UNICODE target = null_string(nativePath); security = descriptor(1, FALSE);
  attributes = (NULL_ATTRIBUTES){sizeof(attributes), null_owned.directory, &label, 0x40, security, NULL};
  status = createLink(&null_owned.link, 1, &attributes, &target); LocalFree(security);
  if (!null_status("NtCreateSymbolicLinkObject", status)) goto held;
  if (mapped) { if (!null_link_drives(createLink, queryLink) || !null_recheck("release")) goto held; mappedSetup = TRUE; }
  NULL_DEVICE_MAP map = {0}; map.Set.DirectoryHandle = null_owned.directory;
  const ULONG informationClass = 23, requestBytes = sizeof(map.Set);
  printf("{\"event\":\"null-set-request\",\"caseId\":\"%ls\",\"shadowPresent\":%s,\"informationClass\":%lu,\"requestBytes\":%lu}\n", nullProbeCase, creationShadow ? "true" : "false", informationClass, requestBytes);
  setSucceeded = null_status("NtSetInformationProcess", setMap(null_owned.child, informationClass, &map.Set, requestBytes));
  bound = setSucceeded && (!mapped || mappedSetup);
held:
  printf("{\"event\":\"null-bound\",\"caseId\":\"%ls\",\"bound\":%s,\"mappedSetup\":%s,\"setSucceeded\":%s,\"hypothesis\":\"%s\",\"owner\":", nullProbeCase, bound ? "true" : "false", mappedSetup ? "true" : "false", setSucceeded ? "true" : "false", !wcscmp(nullProbeCase, L"shadow") ? "controller-read-only-shadow" : mapped ? "unshadowed-proven-drive-links" : "unshadowed-directory"); identity(GetCurrentProcess()); puts("}");
  ack('Q');
  wait = WaitForSingleObject(null_owned.child, 0); win32_check(wait != WAIT_FAILED, "null-retirement"); invariant(wait == WAIT_OBJECT_0, "null-retirement");
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account; win32_check(QueryInformationJobObject(null_owned.job, JobObjectBasicAccountingInformation, &account, sizeof(account), NULL), "null-retirement"); invariant(!account.ActiveProcesses, "null-retirement");
  null_controller(openLink, queryLink, "after");
  null_endpoint("after"); BOOL closed = settle_null_map();
  printf("{\"event\":\"null-retired\",\"resourcesClosed\":%s}\n", closed ? "true" : "false");
  if (!closed) failure(126);
}
