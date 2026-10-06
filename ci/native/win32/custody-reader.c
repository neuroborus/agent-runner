/* One-shot LocalSystem/session-0 reader. A retained handle, never a PID/name,
 * owns every observation. The bridge and independent verifier gate admission. */
#define COBJMACROS
#include "custody.h"
#include <fcntl.h>
#include <io.h>
#define SLOTS 128
struct entry { char kind[16], pin[65], signature[65]; wchar_t path[4096]; struct held_file file; };
static struct entry entries[SLOTS]; static unsigned count, sequence;
static HANDLE processes[32], tokens[32], jobs[32]; static unsigned process_count, job_count;
static DWORD sessions[32];
/* The Security observer retains its own pipes while one finite work helper
 * runs. Each lane has separately verified creation and whole-Job retirement. */
static struct helper_custody { HANDLE process, thread, job, input, output; BOOL file; } helpers[2];
static unsigned helper_lane;
#define helper helpers[helper_lane].process
#define helper_thread helpers[helper_lane].thread
#define helper_job helpers[helper_lane].job
#define helper_in helpers[helper_lane].input
#define helper_out helpers[helper_lane].output
#define helper_file helpers[helper_lane].file
static HANDLE control; static char nonce[33], candidate[41];
static struct held_file *dependencies[32]; static unsigned dependency_count, dependency_sizes[32];
static DWORD WINAPI expire(void *unused) { (void)unused; Sleep(CUSTODY_LIFETIME_MS); ExitProcess(124); return 0; }
static struct entry *slot(const char *value) { ULONGLONG index = number(value); need(index < count && entries[index].file.handle); return &entries[index]; }
static void inspect(struct entry *entry) {
  char dacl[65]; security(entry->file.handle, SE_FILE_OBJECT, FALSE, dacl);
  FILE_ATTRIBUTE_TAG_INFO tag; need(GetFileInformationByHandleEx(entry->file.handle, FileAttributeTagInfo, &tag, sizeof(tag)) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
  BY_HANDLE_FILE_INFORMATION info; need(GetFileInformationByHandle(entry->file.handle, &info) && info.nNumberOfLinks == entry->file.links);
  printf("{\"identity\":\""); file_id(&entry->file); printf("\",\"pathHex\":\""); hex((BYTE *)entry->file.path, wcslen(entry->file.path)*2);
  printf("\",\"volumeHex\":\""); hex((BYTE *)entry->file.volumeName, wcslen(entry->file.volumeName)*2);
  printf("\",\"filesystemHex\":\""); hex((BYTE *)entry->file.filesystem, wcslen(entry->file.filesystem)*2);
  printf("\",\"daclSha256\":\"%s\",\"links\":%lu,\"directory\":%s,\"held\":true,\"reparse\":false}", dacl, entry->file.links, tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY ? "true" : "false");
}
static void plan(const wchar_t *name, const char *expected) {
  struct held_file file = hold(name, FALSE, TRUE, GENERIC_READ); pin(&file, expected);
  DWORD size; BYTE *bytes = read_file(&file, 262144, &size); need(bytes[size-1] == '\n' && !memchr(bytes, 0, size));
  char *text = calloc(size+1, 1); need(text); memcpy(text, bytes, size); free(bytes);
  char *state, *first = strtok_s(text, "\n", &state), extra;
  need(first && sscanf_s(first, "native-custody-v1 %40s %32s %c", candidate, 41u, nonce, 33u, &extra, 1u) == 2 &&
    strlen(candidate) == 40 && strspn(candidate, "0123456789abcdef") == 40 && strlen(nonce) == 32 && strspn(nonce, "0123456789abcdef") == 32);
  for (char *next = strtok_s(NULL, "\n", &state); next; next = strtok_s(NULL, "\n", &state)) {
    need(count < SLOTS); struct entry *entry = &entries[count++]; char path[16384];
    need(sscanf_s(next, "%15s %64s %64s %16383s %c", entry->kind, 16u, entry->pin, 65u, entry->signature, 65u, path, (unsigned)sizeof(path), &extra, 1u) == 4);
    need(!strcmp(entry->kind, "directory") || !strcmp(entry->kind, "data") || !strcmp(entry->kind, "mutable") || !strcmp(entry->kind, "image") || !strcmp(entry->kind, "helper") || !strcmp(entry->kind, "sdk"));
    need(!strcmp(entry->kind, "directory") ? !strcmp(entry->pin, "-") : strlen(entry->pin) == 64 && strspn(entry->pin, "0123456789abcdef") == 64);
    need(!strcmp(entry->kind, "image") || !strcmp(entry->kind, "helper") ? strlen(entry->signature) == 64 && strspn(entry->signature, "0123456789abcdef") == 64 : !strcmp(entry->signature, "-"));
    decode(path, entry->path); for (unsigned i = 0; i+1 < count; i++) need(_wcsicmp(entries[i].path, entry->path));
  }
  need(count); free(text); close_file(&file);
}
static unsigned retain_process(DWORD pid) {
  need(pid > 0 && pid != GetCurrentProcessId() && process_count < 32);
  HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL | SYNCHRONIZE, FALSE, pid), token;
  need(process && GetProcessId(process) == pid && OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token));
  for (unsigned i = 0; i < process_count; i++) need(GetProcessId(processes[i]) != pid);
  processes[process_count] = process; tokens[process_count] = token; sessions[process_count] = process_session(process); return process_count++;
}
static void process_read(unsigned index) {
  need(index < process_count); HANDLE process = processes[index], token = tokens[index]; char dacl[65];
  TOKEN_STATISTICS *before = token_info(token, TokenStatistics); TOKEN_GROUPS *groups = token_info(token, TokenGroups), *restricting = token_info(token, TokenRestrictedSids);
  if (WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
    HANDLE current; need(OpenProcessToken(process, TOKEN_QUERY, &current)); TOKEN_STATISTICS *assigned = token_info(current, TokenStatistics);
    need(!memcmp(&before->TokenId, &assigned->TokenId, sizeof(LUID)) && process_session(process) == sessions[index] && CloseHandle(current)); free(assigned);
  }
  TOKEN_PRIVILEGES *privileges = token_info(token, TokenPrivileges); TOKEN_MANDATORY_LABEL *level = token_info(token, TokenIntegrityLevel);
  security(process, SE_KERNEL_OBJECT, FALSE, dacl);
  printf("{\"identity\":"); retained_identity(process, token, sessions[index]); printf(",\"processDaclSha256\":\"%s\",\"tokenId\":\"%08lx%08lx\",\"authenticationId\":\"%08lx%08lx\",\"integritySid\":\"", dacl,
    before->TokenId.HighPart, before->TokenId.LowPart, before->AuthenticationId.HighPart, before->AuthenticationId.LowPart);
  wchar_t *sid; need(ConvertSidToStringSidW(level->Label.Sid, &sid)); printf("%ls\",\"groups\":[", sid); LocalFree(sid);
  need(groups->GroupCount <= 128 && restricting->GroupCount <= 128 && privileges->PrivilegeCount <= 128);
  for (unsigned i = 0; i < groups->GroupCount; i++) { need(ConvertSidToStringSidW(groups->Groups[i].Sid, &sid));
    printf("%s{\"sid\":\"%ls\",\"attributes\":%lu}", i ? "," : "", sid, groups->Groups[i].Attributes); LocalFree(sid); }
  printf("],\"restricting\":[");
  for (unsigned i = 0; i < restricting->GroupCount; i++) { need(ConvertSidToStringSidW(restricting->Groups[i].Sid, &sid)); printf("%s\"%ls\"", i ? "," : "", sid); LocalFree(sid); }
  printf("],\"privileges\":[");
  for (unsigned i = 0; i < privileges->PrivilegeCount; i++) printf("%s{\"luid\":\"%08lx%08lx\",\"attributes\":%lu}", i ? "," : "", privileges->Privileges[i].Luid.HighPart, privileges->Privileges[i].Luid.LowPart, privileges->Privileges[i].Attributes);
  TOKEN_STATISTICS *after = token_info(token, TokenStatistics); need(!memcmp(&before->ModifiedId, &after->ModifiedId, sizeof(LUID)));
  printf("],\"retired\":%s}", WaitForSingleObject(process, 0) == WAIT_OBJECT_0 ? "true" : "false");
  free(before); free(after); free(groups); free(restricting); free(privileges); free(level);
}
/* The live independent verifier is not a payload-domain member. Inspect it
 * through a temporary handle so it cannot obstruct retained-domain retirement. */
static void verifier_read(const char *pidText, const char *creationText) {
  DWORD pid = bounded_number(pidText, MAXDWORD); ULONGLONG creation = number(creationText);
  need(pid && pid != GetCurrentProcessId() && creation);
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
  FILETIME started, ended, kernel, user;
  need(process && GetProcessId(process) == pid && WaitForSingleObject(process, 0) == WAIT_TIMEOUT &&
    system_process(process) && GetProcessTimes(process, &started, &ended, &kernel, &user) &&
    (((ULONGLONG)started.dwHighDateTime << 32) | started.dwLowDateTime) == creation);
  identity(process); need(WaitForSingleObject(process, 0) == WAIT_TIMEOUT && CloseHandle(process));
}
static void job_read(HANDLE job) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits; JOBOBJECT_BASIC_UI_RESTRICTIONS ui; char dacl[65];
  BYTE bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 32*sizeof(ULONG_PTR)]; JOBOBJECT_BASIC_PROCESS_ID_LIST *members = (void *)bytes;
  need(QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits), NULL) &&
    QueryInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui), NULL) &&
    QueryInformationJobObject(job, JobObjectBasicProcessIdList, members, sizeof(bytes), NULL) &&
    members->NumberOfAssignedProcesses == members->NumberOfProcessIdsInList && members->NumberOfProcessIdsInList <= 32);
  security(job, SE_KERNEL_OBJECT, TRUE, dacl);
  HANDLE held[32]; unsigned count = members->NumberOfProcessIdsInList;
  printf("{\"daclSha256\":\"%s\",\"limitFlags\":%lu,\"processLimit\":%lu,\"uiRestrictions\":%lu,\"members\":[", dacl,
    limits.BasicLimitInformation.LimitFlags, limits.BasicLimitInformation.ActiveProcessLimit, ui.UIRestrictionsClass);
  for (unsigned i = 0; i < members->NumberOfProcessIdsInList; i++) { HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, (DWORD)members->ProcessIdList[i]); BOOL belongs;
    need(process && IsProcessInJob(process, job, &belongs) && belongs); held[i] = process; if (i) putchar(','); identity(process); }
  BYTE next[sizeof(bytes)]; JOBOBJECT_BASIC_PROCESS_ID_LIST *again = (void *)next;
  need(QueryInformationJobObject(job, JobObjectBasicProcessIdList, again, sizeof(next), NULL) &&
    again->NumberOfAssignedProcesses == count && again->NumberOfProcessIdsInList == count && !memcmp(again->ProcessIdList, members->ProcessIdList, count*sizeof(ULONG_PTR)));
  for (unsigned i = 0; i < count; i++) need(CloseHandle(held[i]));
  printf("]}");
}
static void remote(HANDLE process, const void *address, void *bytes, SIZE_T size) { SIZE_T read; need(ReadProcessMemory(process, address, bytes, size, &read) && read == size); }
struct api_header { ULONG version, size, flags, count, entry, hash, factor; };
struct api_entry { ULONG flags, name, length, hashed, values, count; };
struct api_value { ULONG flags, name, length, host, size; };
static void api_host(HANDLE process, const wchar_t *contract, wchar_t host[256]) {
  typedef NTSTATUS (NTAPI *query)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
  query get = (query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"); PROCESS_BASIC_INFORMATION info;
  need(get && !get(process, ProcessBasicInformation, &info, sizeof(info), NULL)); void *map;
  remote(process, (BYTE *)info.PebBaseAddress + 0x68, &map, sizeof(map)); struct api_header header; remote(process, map, &header, sizeof(header));
  need(header.version == 6 && header.size >= sizeof(header) && header.size <= 1048576 && header.count <= 2048 && header.entry <= header.size &&
    header.count <= (header.size - header.entry) / sizeof(struct api_entry));
  BYTE *bytes = calloc(header.size, 1); need(bytes); remote(process, map, bytes, header.size); unsigned found = 0;
  for (unsigned i = 0; i < header.count; i++) { struct api_entry *entry = (void *)(bytes + header.entry + i*sizeof(*entry));
    need(entry->length && entry->length <= 510 && entry->name <= header.size && entry->length <= header.size - entry->name && !(entry->length % 2));
    wchar_t name[256] = {0}; memcpy(name, bytes + entry->name, entry->length);
    if (_wcsicmp(name, contract)) continue; need(entry->count == 1 && entry->values <= header.size - sizeof(struct api_value));
    struct api_value *value = (void *)(bytes + entry->values); need(value->length == 0 && value->size && value->size <= 510 && !(value->size % 2) &&
      value->host <= header.size && value->size <= header.size - value->host); memcpy(host, bytes + value->host, value->size); host[value->size/2] = 0; found++;
  }
  free(bytes); need(found == 1); /* Ambiguous importer-specific API sets stay unsupported. */
}
static DWORD rva(BYTE *bytes, DWORD size, IMAGE_NT_HEADERS64 *pe, DWORD address, DWORD needed) {
  need(needed <= size); if (address < pe->OptionalHeader.SizeOfHeaders) { need(address <= size-needed); return address; }
  IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(pe); need((BYTE *)sections >= bytes && (BYTE *)(sections + pe->FileHeader.NumberOfSections) <= bytes + size && pe->FileHeader.NumberOfSections <= 96);
  for (unsigned i = 0; i < pe->FileHeader.NumberOfSections; i++) if (address >= sections[i].VirtualAddress && address - sections[i].VirtualAddress <= sections[i].SizeOfRawData &&
    needed <= sections[i].SizeOfRawData - (address - sections[i].VirtualAddress)) {
    ULONGLONG offset = (ULONGLONG)sections[i].PointerToRawData + address - sections[i].VirtualAddress; need(offset <= size-needed); return (DWORD)offset;
  }
  need(FALSE); return 0;
}
static void loader(unsigned subject, struct entry *image) {
  need(subject < process_count); HANDLE process = processes[subject]; HMODULE modules[128]; DWORD used;
  need(EnumProcessModulesEx(process, modules, sizeof(modules), &used, LIST_MODULES_64BIT) && used && used <= sizeof(modules) && used % sizeof(HMODULE) == 0);
  need(dependency_count < 32); wchar_t (*paths)[4096] = calloc(128, sizeof(*paths));
  struct held_file *files = calloc(128, sizeof(*files)); need(paths && files); unsigned n = used/sizeof(HMODULE);
  printf("{\"loaded\":[");
  for (unsigned i = 0; i < n; i++) { DWORD length = GetModuleFileNameExW(process, modules[i], paths[i], 4096); need(length > 0 && length < 4096);
    files[i] = hold(paths[i], FALSE, FALSE, GENERIC_READ); DWORD size; BYTE *bytes = read_file(&files[i], 134217728, &size); char hash[65], dacl[65], sig[65]; sum(bytes, size, hash); free(bytes);
    wchar_t mapped[4100], named[4100]; DWORD mappedSize = GetMappedFileNameW(process, modules[i], mapped, 4100), namedSize = GetFinalPathNameByHandleW(files[i].handle, named, 4100, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
    need(mappedSize && mappedSize < 4100 && namedSize && namedSize < 4100 && !_wcsicmp(mapped, named));
    security(files[i].handle, SE_FILE_OBJECT, FALSE, dacl); signature(&files[i], NULL, sig);
    if (i) putchar(','); printf("{\"pathHex\":\""); hex((BYTE *)paths[i], wcslen(paths[i])*2); printf("\",\"identity\":\""); file_id(&files[i]);
    printf("\",\"sha256\":\"%s\",\"signatureSha256\":\"%s\",\"daclSha256\":\"%s\",\"links\":%lu}", hash, sig, dacl, files[i].links); }
  printf("],\"imports\":["); unsigned emitted = 0;
  for (unsigned source = 0; source < n; source++) {
  DWORD size; BYTE *bytes = read_file(&files[source], 134217728, &size); IMAGE_DOS_HEADER *dos = (void *)bytes;
  need(size >= 512 && dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew >= 64 && (DWORD)dos->e_lfanew <= size-sizeof(IMAGE_NT_HEADERS64));
  IMAGE_NT_HEADERS64 *pe = (void *)(bytes + dos->e_lfanew); need(pe->Signature == IMAGE_NT_SIGNATURE && pe->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
    pe->FileHeader.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64) && pe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && pe->OptionalHeader.NumberOfRvaAndSizes >= 14);
  for (unsigned directory = 0; directory < 2; directory++) {
    IMAGE_DATA_DIRECTORY table = pe->OptionalHeader.DataDirectory[directory ? IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT : IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!table.Size) { need(!table.VirtualAddress); continue; } DWORD width = directory ? 32 : sizeof(IMAGE_IMPORT_DESCRIPTOR), at = rva(bytes, size, pe, table.VirtualAddress, table.Size); BOOL terminated = FALSE;
    need(table.Size / width <= 128);
    for (unsigned i = 0; (i+1)*width <= table.Size; i++) { DWORD *entry = (void *)(bytes + at + i*width); DWORD nameRva = directory ? entry[1] : entry[3];
      if (!nameRva) { terminated = TRUE; break; } if (directory) need(entry[0] == 1); DWORD nameAt = rva(bytes, size, pe, nameRva, 1), length = 0;
      while (length < 255 && nameAt + length < size && bytes[nameAt+length]) length++; need(length && length < 255 && nameAt+length < size);
      wchar_t name[256] = {0}, host[256] = {0}; for (unsigned j = 0; j < length; j++) { need(bytes[nameAt+j] >= 32 && bytes[nameAt+j] < 127 && bytes[nameAt+j] != '/' && bytes[nameAt+j] != '\\'); name[j] = bytes[nameAt+j]; }
      wcscpy_s(host, 256, name); if (!_wcsnicmp(name, L"api-", 4) || !_wcsnicmp(name, L"ext-", 4)) { wchar_t *dot = wcsrchr(name, '.'); if (dot) *dot = 0; api_host(process, name, host); }
      unsigned match = n; for (unsigned j = 0; j < n; j++) if (!_wcsicmp(wcsrchr(paths[j], '\\')+1, host)) { need(match == n); match = j; } need(match < n);
      need(emitted < 2048); printf("%s{\"source\":%u,\"importHex\":\"", emitted++ ? "," : "", source); hex(bytes+nameAt, length); printf("\",\"resolved\":%u,\"delay\":%s}", match, directory ? "true" : "false");
    } need(terminated);
  }
  free(bytes); }
  DWORD size; BYTE *bytes = read_file(&image->file, 134217728, &size); IMAGE_DOS_HEADER *dos = (void *)bytes;
  need(size >= 512 && dos->e_lfanew >= 64 && (DWORD)dos->e_lfanew <= size-sizeof(IMAGE_NT_HEADERS64)); IMAGE_NT_HEADERS64 *pe = (void *)(bytes + dos->e_lfanew);
  HMODULE again[128]; DWORD next; need(EnumProcessModulesEx(process, again, sizeof(again), &next, LIST_MODULES_64BIT) && next == used && !memcmp(modules, again, used));
  printf("],\"linkerMajor\":%u,\"linkerMinor\":%u,\"timestamp\":%lu,\"complete\":true}", pe->OptionalHeader.MajorLinkerVersion, pe->OptionalHeader.MinorLinkerVersion, pe->FileHeader.TimeDateStamp);
  free(bytes); free(paths); dependencies[dependency_count] = files; dependency_sizes[dependency_count++] = n;
}
static void quoted(wchar_t *command, size_t maximum, const wchar_t *value) {
  need(wcscat_s(command, maximum, L"\"") == 0); unsigned slashes = 0;
  for (const wchar_t *at = value;; at++) {
    if (*at == '\\') { slashes++; continue; }
    unsigned n = (*at == '"' || !*at) ? slashes*2 : slashes;
    for (unsigned i = 0; i < n; i++) need(wcscat_s(command, maximum, L"\\") == 0);
    slashes = 0; if (*at == '"') need(wcscat_s(command, maximum, L"\\") == 0);
    if (!*at) break; wchar_t text[2] = {*at, 0}; need(wcscat_s(command, maximum, text) == 0);
  }
  need(wcscat_s(command, maximum, L"\" ") == 0);
}
static void file_root_sharing(struct entry *root, struct entry *base) {
  need(!strcmp(root->kind, "directory") && !strcmp(base->kind, "directory"));
  wchar_t named[4096]; need(swprintf_s(named, 4096, L"%ls\\files", base->path) > 0 && !_wcsicmp(named, root->path));
  char rootDacl[65], baseDacl[65]; security(root->file.handle, SE_FILE_OBJECT, TRUE, rootDacl); security(base->file.handle, SE_FILE_OBJECT, TRUE, baseDacl);
  /* Share deletion only for the fixed owned substitution root. ReOpenFile
   * preserves object custody; no pathname lookup or parent lease is released. */
  HANDLE next = ReOpenFile(root->file.handle,
    ACCESS_SYSTEM_SECURITY | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | WRITE_DAC | WRITE_OWNER,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
  FILE_ID_INFO id; char after[65];
  need(next != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(next, FileIdInfo, &id, sizeof(id)) &&
    !memcmp(&id, &root->file.id, sizeof(id)) && SetHandleInformation(next, HANDLE_FLAG_INHERIT, 0));
  security(next, SE_FILE_OBJECT, TRUE, after); need(!strcmp(rootDacl, after) && CloseHandle(root->file.handle)); root->file.handle = next;
}
static void start_helper(char **values, unsigned n) {
  need(!helper && n >= 8 && (!strcmp(values[2], "file") || !strcmp(values[2], "policy") || !strcmp(values[2], "observer") ||
    !strcmp(values[2], "build") || !strcmp(values[2], "git") || !strcmp(values[2], "git-policy")));
  struct entry *image = slot(values[3]); BOOL file = !strcmp(values[2], "file"), observer = !strcmp(values[2], "observer"),
    compiler = !strcmp(values[2], "build"), git = !strcmp(values[2], "git"), gitPolicy = !strcmp(values[2], "git-policy");
  need(!strcmp(image->kind, "helper") && !_wcsicmp(wcsrchr(image->path, '\\')+1, file ? L"file-helper.exe" : observer ? L"observer-helper.exe" :
    compiler ? L"build-helper.exe" : git ? L"git-fixture.exe" : gitPolicy ? L"git-policy.exe" : L"policy-helper.exe"));
  unsigned argc = bounded_number(values[4], gitPolicy ? 386 : 55); need(argc >= (observer ? 2U : 5U) && n > 5 + argc);
  wchar_t (*args)[16385] = calloc(argc, sizeof(*args)); need(args);
  for (unsigned i = 0; i < argc; i++) decode_bounded(values[5+i], args[i], observer && i == 1 ? 16385 : 4096);
  need(wcslen(args[0]) == 32); for (unsigned i = 0; i < 32; i++) need(args[0][i] == nonce[i]);
  unsigned inheritedCount = bounded_number(values[5+argc], gitPolicy ? 128 : 44), first = file ? 1 : observer || compiler || git || gitPolicy ? 0 :
    (!wcscmp(args[4], L"install-provider") || !wcscmp(args[4], L"remove-provider") ? 6 : 13);
  need(n == 6 + argc + inheritedCount && (git ? argc == 8 && inheritedCount == 0 && !wcscmp(args[1], L"fixed-commit") :
    gitPolicy ? inheritedCount >= 3 && argc == 8 + (inheritedCount-2)*3 && (!wcscmp(args[7], L"install") || !wcscmp(args[7], L"remove")) :
    compiler ? argc == 14 && inheritedCount == 0 : observer ? argc == 2 && inheritedCount == 0 :
    inheritedCount >= 2 && (file ? argc == 5 && inheritedCount == 2 : argc == first + inheritedCount)));
  if (file) file_root_sharing(slot(values[6+argc]), slot(values[7+argc]));
  HANDLE inherited[130]; PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, TRUE);
  HANDLE childIn, childOut; need(CreatePipe(&childIn, &helper_in, &sa, 0) && CreatePipe(&helper_out, &childOut, &sa, 0) &&
    SetHandleInformation(helper_in, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(helper_out, HANDLE_FLAG_INHERIT, 0));
  inherited[0] = childIn; inherited[1] = childOut;
  for (unsigned i = 0; i < inheritedCount; i++) {
    struct entry *entry = slot(values[6+argc+i]); need(!file || !strcmp(entry->kind, "directory"));
    need(DuplicateHandle(GetCurrentProcess(), entry->file.handle, GetCurrentProcess(), &inherited[i+2], 0, TRUE, DUPLICATE_SAME_ACCESS));
    unsigned argument = gitPolicy ? (i < 2 ? 3+i : 8+(i-2)*3) : first+i;
    need(swprintf_s(args[argument], 4096, L"%llu", (ULONGLONG)(ULONG_PTR)inherited[i+2]) > 0);
  }
  SECURITY_ATTRIBUTES private = attributes(sd, FALSE); helper_job = CreateJobObjectW(&private, NULL); need(helper_job);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0}; limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  limits.BasicLimitInformation.ActiveProcessLimit = compiler || git ? 32 : 1; JOBOBJECT_BASIC_UI_RESTRICTIONS ui = {255};
  need(SetInformationJobObject(helper_job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) && SetInformationJobObject(helper_job, JobObjectBasicUIRestrictions, &ui, sizeof(ui)));
  SIZE_T size = 0; InitializeProcThreadAttributeList(NULL, 2, 0, &size); need(size > 0 && size <= 65536);
  STARTUPINFOEXW start = {0}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = calloc(1, size); need(start.lpAttributeList);
  need(InitializeProcThreadAttributeList(start.lpAttributeList, 2, 0, &size) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, (inheritedCount+2)*sizeof(HANDLE), NULL, NULL) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &helper_job, sizeof(HANDLE), NULL, NULL));
  start.StartupInfo.dwFlags = STARTF_USESTDHANDLES; start.StartupInfo.hStdInput = childIn; start.StartupInfo.hStdOutput = start.StartupInfo.hStdError = childOut;
  wchar_t command[32767] = L""; quoted(command, 32767, image->path); for (unsigned i = observer ? 1 : 0; i < argc; i++) quoted(command, 32767, args[i]);
  wchar_t environment[] = L"CI=true\0GITHUB_ACTIONS=true\0PATH=C:\\nonexistent\0\0";
  wchar_t directory[4096]; wcscpy_s(directory, 4096, image->path); *wcsrchr(directory, '\\') = 0;
  PROCESS_INFORMATION process; char creatorDacl[65];
  if (compiler || git) {
    /* Process/thread DACLs do not govern implicitly created files or children.
     * Give only these fixed grants a separate System-only creator token. */
    HANDLE parent, primary, assigned; PACL acl; BOOL present, defaulted;
    need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &parent) &&
      DuplicateTokenEx(parent, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT,
        &private, SecurityImpersonation, TokenPrimary, &primary) && CloseHandle(parent) &&
      GetSecurityDescriptorDacl(sd, &present, &acl, &defaulted) && present && acl && IsValidAcl(acl));
    TOKEN_DEFAULT_DACL creation = {acl};
    need(SetTokenInformation(primary, TokenDefaultDacl, &creation, sizeof(creation)) &&
      CreateProcessAsUserW(primary, image->path, command, &private, &private, TRUE,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, environment, directory, &start.StartupInfo, &process) &&
      CloseHandle(primary) && OpenProcessToken(process.hProcess, TOKEN_QUERY, &assigned));
    TOKEN_DEFAULT_DACL *actual = token_info(assigned, TokenDefaultDacl);
    need(actual->DefaultDacl && IsValidAcl(actual->DefaultDacl) && actual->DefaultDacl->AclSize == acl->AclSize &&
      !memcmp(actual->DefaultDacl, acl, acl->AclSize));
    sum((BYTE *)actual->DefaultDacl, actual->DefaultDacl->AclSize, creatorDacl); free(actual); need(CloseHandle(assigned));
  } else need(CreateProcessW(image->path, command, &private, &private, TRUE,
    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, environment, directory, &start.StartupInfo, &process));
  free(args);
  helper = process.hProcess; helper_thread = process.hThread;
  helper_file = file;
  DeleteProcThreadAttributeList(start.lpAttributeList); free(start.lpAttributeList);
  for (unsigned i = 0; i < inheritedCount+2; i++) need(CloseHandle(inherited[i]));
  BOOL belongs; char processDacl[65], threadDacl[65]; need(system_process(helper) && IsProcessInJob(helper, helper_job, &belongs) && belongs);
  security(helper, SE_KERNEL_OBJECT, TRUE, processDacl); security(helper_thread, SE_KERNEL_OBJECT, TRUE, threadDacl); LocalFree(sd);
  printf("{\"helper\":"); identity(helper); printf(",\"processDaclSha256\":\"%s\",\"threadDaclSha256\":\"%s\",\"inheritedHandleCount\":%u,\"job\":", processDacl, threadDacl, inheritedCount+2); job_read(helper_job);
  if (compiler || git) printf(",\"creatorDefaultDaclSha256\":\"%s\"", creatorDacl);
  if (file) printf(",\"fileRootDeleteSharing\":true"); printf("}");
}
static void build(void) {
  typedef LONG (WINAPI *version)(PRTL_OSVERSIONINFOW); RTL_OSVERSIONINFOW os = {sizeof(os)};
  version read = (version)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"); need(read && !read(&os));
  HKEY key; wchar_t sdk[4096]; DWORD size = sizeof(sdk), type;
  need(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS &&
    RegQueryValueExW(key, L"KitsRoot10", NULL, &type, (BYTE *)sdk, &size) == ERROR_SUCCESS && type == REG_SZ && size >= 4 && size <= sizeof(sdk) && sdk[size/2-1] == 0 &&
    RegCloseKey(key) == ERROR_SUCCESS);
  printf("{\"major\":%lu,\"minor\":%lu,\"build\":%lu,\"sdkRootHex\":\"", os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber); hex((BYTE *)sdk, size-2); printf("\"}");
}
#include "effective-reader.h"
/* A reviewed certificate is data, not an inherited signing credential. The
 * compiled image must match the reviewed unsigned pin and every signed image
 * byte outside checksum/security-directory fields and aligned certificate data.
 * Only that fixed reviewed publication may replace the unsigned bytes. */
static void publish_build(char **values, unsigned n) {
  need(n == 6 && !helpers[0].process && !helpers[1].process); struct entry *root = slot(values[2]), *image = slot(values[5]);
  need(!strcmp(root->kind, "directory") && !strcmp(image->kind, "helper"));
  wchar_t leaf[4096], output[4096]; decode(values[3], leaf);
  need(!wcschr(leaf, '\\') && !wcschr(leaf, '/') && !wcschr(leaf, ':') && !_wcsicmp(leaf, wcsrchr(image->path, '\\')+1) && wcscmp(leaf, L".") && wcscmp(leaf, L".."));
  need(swprintf_s(output, 4096, L"%ls\\%ls", root->path, leaf) > 0);
  struct held_file target = hold(output, FALSE, TRUE, GENERIC_READ | GENERIC_WRITE);
  need(strlen(values[4]) == 64); pin(&target, values[4]); pin(&image->file, image->pin);
  DWORD unsignedSize, signedSize; BYTE *plain = read_file(&target, 134217728, &unsignedSize), *signedBytes = read_file(&image->file, 134217728, &signedSize);
  IMAGE_DOS_HEADER *dos = (void *)plain, *signedDos = (void *)signedBytes;
  need(unsignedSize >= 512 && signedSize >= unsignedSize && dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew >= 64 &&
    (DWORD)dos->e_lfanew <= unsignedSize-sizeof(IMAGE_NT_HEADERS64) && signedDos->e_lfanew == dos->e_lfanew);
  IMAGE_NT_HEADERS64 *pe = (void *)(plain + dos->e_lfanew), *signedPe = (void *)(signedBytes + dos->e_lfanew);
  need(pe->Signature == IMAGE_NT_SIGNATURE && signedPe->Signature == IMAGE_NT_SIGNATURE && pe->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
    pe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && pe->OptionalHeader.NumberOfRvaAndSizes >= 5 &&
    !pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress && !pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
  IMAGE_DATA_DIRECTORY cert = signedPe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  need(cert.VirtualAddress >= unsignedSize && cert.VirtualAddress-unsignedSize < 8 && cert.Size >= 8 && cert.Size <= signedSize && cert.VirtualAddress <= signedSize-cert.Size && cert.VirtualAddress%8 == 0);
  size_t checksum = (BYTE *)&pe->OptionalHeader.CheckSum-plain, securityOffset = (BYTE *)&pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]-plain;
  for (DWORD i = 0; i < unsignedSize; i++) if (!(i >= checksum && i < checksum+4) && !(i >= securityOffset && i < securityOffset+sizeof(IMAGE_DATA_DIRECTORY))) need(plain[i] == signedBytes[i]);
  for (DWORD i = unsignedSize; i < cert.VirtualAddress; i++) need(!signedBytes[i]);
  char signatureSha[65]; signature(&image->file, image->signature, signatureSha);
  LARGE_INTEGER zero = {0}; need(SetFilePointerEx(target.handle, zero, NULL, FILE_BEGIN));
  DWORD offset = 0; while (offset < signedSize) { DWORD used; need(WriteFile(target.handle, signedBytes+offset, signedSize-offset, &used, NULL) && used); offset += used; }
  need(SetEndOfFile(target.handle) && FlushFileBuffers(target.handle)); pin(&target, image->pin); signature(&target, image->signature, signatureSha);
  char dacl[65]; security(target.handle, SE_FILE_OBJECT, TRUE, dacl);
  FILE_ID_INFO id = target.id; need(CloseHandle(target.handle)); target.handle = open_file(output, FALSE, GENERIC_READ);
  FILE_ID_INFO after; need(GetFileInformationByHandleEx(target.handle, FileIdInfo, &after, sizeof(after)) && !memcmp(&id, &after, sizeof(id)));
  pin(&target, image->pin); printf("{\"identity\":\""); file_id(&target); printf("\",\"sha256\":\"%s\",\"signatureSha256\":\"%s\",\"daclSha256\":\"%s\",\"writerClosed\":true}", image->pin, signatureSha, dacl);
  close_file(&target); SecureZeroMemory(plain, unsignedSize); free(plain); free(signedBytes);
}
int wmain(int argc, wchar_t **argv) {
  need(argc == 8 && !wcscmp(argv[1], L"--serve") && system_process(GetCurrentProcess()));
  require_build();
  wchar_t environment[] = L"CI=true\0GITHUB_ACTIONS=true\0PATH=C:\\nonexistent\0\0";
  need(SetEnvironmentStringsW(environment));
  need(CreateThread(NULL, 0, expire, NULL, 0, NULL)); privilege(SE_DEBUG_NAME); privilege(SE_SECURITY_NAME);
  need(SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED)));
  wchar_t *end; errno = 0; DWORD bridge = wcstoul(argv[7], &end, 10);
  need(bridge && !errno && *argv[7] >= '0' && *argv[7] <= '9' && !*end && wcslen(argv[4]) == 32);
  control = CreateFileW(argv[5], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL); DWORD server;
  need(control != INVALID_HANDLE_VALUE && GetNamedPipeServerProcessId(control, &server) && server == bridge);
  HANDLE peer = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, server), token; need(peer && OpenProcessToken(peer, TOKEN_QUERY, &token));
  wchar_t *sid = token_sid(token); need(!wcscmp(sid, argv[6])); LocalFree(sid); CloseHandle(token);
  /* Scheduled console entries may have CRT descriptor -2. Establish descriptor
   * 1 before replacing it with the sole authenticated private pipe. */
  FILE *stream; need(!_wfreopen_s(&stream, L"NUL", L"wb", stdout) && stream == stdout && _fileno(stdout) >= 0);
  HANDLE out; need(DuplicateHandle(GetCurrentProcess(), control, GetCurrentProcess(), &out, 0, FALSE, DUPLICATE_SAME_ACCESS));
  int fd = _open_osfhandle((intptr_t)out, _O_BINARY); need(fd >= 0 && _dup2(fd, _fileno(stdout)) == 0 && _close(fd) == 0);
  printf("{\"helper\":"); identity(GetCurrentProcess()); printf(",\"peer\":"); identity(peer); puts("}"); fflush(stdout); CloseHandle(peer);
  char input[262144]; line(control, input, sizeof(input)); need(!strcmp(input, "P"));
  char hash[65]; need(wcslen(argv[3]) == 64); for (unsigned i = 0; i < 64; i++) hash[i] = (char)argv[3][i]; hash[64] = 0;
  plan(argv[2], hash); for (unsigned i = 0; i < 32; i++) need(nonce[i] == argv[4][i]);
  printf("{\"candidateSha\":\"%s\",\"nonce\":\"%s\",\"entries\":%u}\n", candidate, nonce, count); fflush(stdout);
  for (unsigned operations = 0; operations < 32768; operations++) {
    line(control, input, sizeof(input)); char *values[520], *state; unsigned n = 0;
    for (char *value = strtok_s(input, " ", &state); value; value = strtok_s(NULL, " ", &state)) { need(n < 520); values[n++] = value; }
    need(n >= 2 && number(values[1]) == ++sequence);
    helper_lane = 0;
    if (n >= 3 && !strcmp(values[0], "helper-start")) helper_lane = !strcmp(values[2], "observer") ? 1 : 0;
    else if (!strncmp(values[0], "helper-", 7)) { need(n >= 3); helper_lane = bounded_number(values[2], 1); }
    printf("{\"sequence\":%u,\"value\":", sequence);
    if (!strcmp(values[0], "open")) {
      need(n == 3); unsigned index = bounded_number(values[2], count-1); need(!entries[index].file.handle); struct entry *entry = &entries[index];
      /* Directory helpers mutate children, not the held root. DELETE access
       * would conflict with later ancestor reads that also deny share-delete. */
      BOOL directory = !strcmp(entry->kind, "directory"); entry->file = hold_shared(entry->path, directory, TRUE,
        ACCESS_SYSTEM_SECURITY | (directory ? FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | WRITE_DAC | WRITE_OWNER : GENERIC_READ | WRITE_DAC | WRITE_OWNER), !strcmp(entry->kind, "mutable"));
      if (!directory) pin(&entry->file, entry->pin); if (!strcmp(entry->kind, "image") || !strcmp(entry->kind, "helper")) { char signatureSha[65]; signature(&entry->file, entry->signature, signatureSha); }
      inspect(entry);
    } else if (!strcmp(values[0], "inspect")) { need(n == 3); inspect(slot(values[2]));
    } else if (!strcmp(values[0], "read")) { need(n == 5); struct entry *entry = slot(values[2]); ULONGLONG offset = number(values[3]), size = number(values[4]);
      need(size > 0 && size <= 65536 && offset <= 134217728-size); LARGE_INTEGER at; at.QuadPart = offset; BYTE bytes[65536]; DWORD used;
      need(SetFilePointerEx(entry->file.handle, at, NULL, FILE_BEGIN) && ReadFile(entry->file.handle, bytes, (DWORD)size, &used, NULL) && used == size);
      printf("{\"hex\":\""); hex(bytes, used); printf("\"}");
    } else if (!strcmp(values[0], "signature")) { need(n == 3); char actual[65]; struct entry *entry = slot(values[2]); signature(&entry->file, entry->signature, actual); printf("{\"sha256\":\"%s\"}", actual);
    } else if (!strcmp(values[0], "process-open")) { need(n == 3); unsigned index = retain_process(bounded_number(values[2], MAXDWORD)); printf("{\"slot\":%u,\"observation\":", index); process_read(index); printf("}");
    } else if (!strcmp(values[0], "process")) { need(n == 3); process_read(bounded_number(values[2], 31));
    } else if (!strcmp(values[0], "process-image")) {
      need(n == 4); unsigned index = bounded_number(values[2], 31); need(index < process_count); struct entry *entry = slot(values[3]);
      wchar_t actual[4096]; DWORD length = 4096; char signatureSha[65];
      need(!strcmp(entry->kind, "image") && QueryFullProcessImageNameW(processes[index], 0, actual, &length) && !_wcsicmp(actual, entry->path));
      pin(&entry->file, entry->pin); signature(&entry->file, entry->signature, signatureSha);
      printf("{\"identity\":"); retained_identity(processes[index], tokens[index], sessions[index]);
      printf(",\"sha256\":\"%s\",\"signatureSha256\":\"%s\"}", entry->pin, signatureSha);
    } else if (!strcmp(values[0], "verifier")) { need(n == 4); verifier_read(values[2], values[3]);
    } else if (!strcmp(values[0], "job-open")) { need(n == 3 && job_count < 32); wchar_t name[96]; need(swprintf_s(name, 96, L"Local\\NativeProof-%hs", nonce) > 0);
      HANDLE job = OpenJobObjectW(JOB_OBJECT_QUERY | READ_CONTROL, FALSE, name); need(job); jobs[job_count] = job; printf("{\"slot\":%u,\"observation\":", job_count++); job_read(job); printf("}");
    } else if (!strcmp(values[0], "job")) { need(n == 3 && number(values[2]) < job_count); job_read(jobs[number(values[2])]);
    } else if (!strcmp(values[0], "loader")) { need(n == 4); loader(bounded_number(values[2], 31), slot(values[3]));
    } else if (!strcmp(values[0], "build")) { need(n == 2); build();
    } else if (!strcmp(values[0], "publish-build")) { publish_build(values, n);
    } else if (!strcmp(values[0], "effective-token")) { need(n == 3); effective_token(bounded_number(values[2], 31));
    } else if (!strcmp(values[0], "acl")) { need(n == 4); effective_acl(bounded_number(values[2], 31), slot(values[3]));
    } else if (!strcmp(values[0], "registry")) { need(n == 3); effective_registry(bounded_number(values[2], 31));
    } else if (!strcmp(values[0], "wfp")) { need(n == 4); effective_wfp(values[3], bounded_number(values[2], 2));
    } else if (!strcmp(values[0], "wfp-inventory")) { need(n == 2); wfp_inventory();
    } else if (!strcmp(values[0], "wfp-global")) { need(n == 3); wfp_global(values[2]);
    } else if (!strcmp(values[0], "barrier")) { need(n == 4); wchar_t name[4096]; decode(values[3], name); struct held_file file = relative_hold(slot(values[2]), name, FALSE); barrier_read(&file, TRUE); close_file(&file);
    } else if (!strcmp(values[0], "file")) { need(n == 3); barrier_read(&slot(values[2])->file, FALSE);
    } else if (!strcmp(values[0], "parents")) { need(n == 3); struct entry *entry = slot(values[2]); putchar('[');
      for (unsigned i = 0; i < entry->file.count; i++) { struct held_file parent = {0}; parent.handle = entry->file.parents[i];
        need(GetFileInformationByHandleEx(parent.handle, FileIdInfo, &parent.id, sizeof(parent.id))); if (i) putchar(','); putchar('"'); file_id(&parent); putchar('"'); } putchar(']');
    } else if (!strcmp(values[0], "tree")) { need(n == 3); unsigned total = 0, emitted = 0; putchar('['); tree_read(slot(values[2]), L"", 0, &total, &emitted); putchar(']');
    } else if (!strcmp(values[0], "audit-snapshot")) { need(n == 3); audit_snapshot(bounded_number(values[2], 31));
    } else if (!strcmp(values[0], "audit-install")) { audit_install(values, n);
    } else if (!strcmp(values[0], "audit-restore")) { need(n == 2); audit_restore();
    } else if (!strcmp(values[0], "xml")) { need(n == 3); xml_decode(values[2]);
    } else if (!strcmp(values[0], "helper-start")) { start_helper(values, n);
    } else if (!strcmp(values[0], "helper-release")) { need(n == 3 && helper_thread && ResumeThread(helper_thread) == 1); need(CloseHandle(helper_thread)); helper_thread = NULL; printf("{\"released\":true}");
    } else if (!strcmp(values[0], "helper-close-input")) { need(n == 3 && helper && !helper_thread && helper_in && CloseHandle(helper_in)); helper_in = NULL; printf("{\"closed\":true}");
    } else if (!strcmp(values[0], "helper-send")) { need(n == 4 && helper && !helper_thread && helper_in); size_t size = strlen(values[3]); BYTE bytes[16384]; need(size && size%2 == 0 && size <= sizeof(bytes)*2);
      for (size_t i = 0; i < size/2; i++) bytes[i] = (BYTE)(nibble(values[3][i*2])*16 + nibble(values[3][i*2+1])); DWORD used;
      need(WriteFile(helper_in, bytes, (DWORD)(size/2), &used, NULL) && used == size/2); printf("{\"sent\":true}");
    } else if (!strcmp(values[0], "helper-read")) { need(n == 3 && helper && !helper_thread); char bytes[16384]; line(helper_out, bytes, sizeof(bytes)); printf("{\"hex\":\""); hex((BYTE *)bytes, strlen(bytes)); printf("\"}");
    } else if (!strcmp(values[0], "helper-bytes")) { need(n == 4 && helper && !helper_thread); DWORD size = bounded_number(values[3], 16384), used; BYTE bytes[16384];
      need(size && ReadFile(helper_out, bytes, size, &used, NULL) && used && used <= size); printf("{\"hex\":\""); hex(bytes, used); printf("\"}"); SecureZeroMemory(bytes, used);
    } else if (!strcmp(values[0], "helper-finish")) { need(n == 3 && helper && !helper_thread && WaitForSingleObject(helper, 0) == WAIT_OBJECT_0); DWORD exit; need(GetExitCodeProcess(helper, &exit) && (exit == 0 || (helper_file && exit == 126)));
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounts; need(QueryInformationJobObject(helper_job, JobObjectBasicAccountingInformation, &accounts, sizeof(accounts), NULL) && accounts.ActiveProcesses == 0);
      BYTE extra; DWORD used = 0; need(!ReadFile(helper_out, &extra, 1, &used, NULL) && GetLastError() == ERROR_BROKEN_PIPE && used == 0);
      need(CloseHandle(helper) && CloseHandle(helper_job) && (!helper_in || CloseHandle(helper_in)) && CloseHandle(helper_out)); helper = helper_job = helper_in = helper_out = NULL; helper_file = FALSE;
      printf("{\"retired\":true,\"members\":0,\"drained\":true,\"exitCode\":%lu}", exit);
    } else if (!strcmp(values[0], "finish")) {
      need(n == 2 && !helpers[0].process && !helpers[1].process && !audit_owned); for (unsigned i = 0; i < process_count; i++) { need(WaitForSingleObject(processes[i], 0) == WAIT_OBJECT_0 && CloseHandle(tokens[i]) && CloseHandle(processes[i])); }
      for (unsigned i = 0; i < job_count; i++) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current; need(QueryInformationJobObject(jobs[i], JobObjectBasicAccountingInformation, &current, sizeof(current), NULL) && current.ActiveProcesses == 0 && CloseHandle(jobs[i])); }
      for (unsigned i = 0; i < count; i++) if (entries[i].file.handle) close_file(&entries[i].file);
      for (unsigned i = 0; i < dependency_count; i++) { for (unsigned j = 0; j < dependency_sizes[i]; j++) close_file(&dependencies[i][j]); free(dependencies[i]); }
      for (unsigned i = 0; i < catalog_count; i++) close_file(&catalogs[i]);
      if (wfp_engine) need(FwpmEngineClose0(wfp_engine) == ERROR_SUCCESS);
      if (registry_key) need(RegCloseKey(registry_key) == ERROR_SUCCESS && CloseHandle(registry_changed));
      CoUninitialize();
      printf("{\"closed\":true}}\n"); fflush(stdout); need(CloseHandle(control)); return 0;
    } else need(FALSE);
    printf("}\n"); need(fflush(stdout) == 0);
  }
  need(FALSE); return 126;
}
