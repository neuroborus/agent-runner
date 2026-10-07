/* One-shot LocalSystem/session-0 reader. A retained handle, never a PID/name,
 * owns every observation. The bridge and independent verifier gate admission. */
#define COBJMACROS
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include "custody.h"
#include "account.h"
#pragma comment(lib, "ws2_32.lib")
#include <fcntl.h>
#include <io.h>
#include <taskschd.h>
#include <oleauto.h>
#include <stddef.h>
#include <tlhelp32.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#define SLOTS 128
struct entry { char kind[16], pin[65], signature[65]; wchar_t path[4096]; struct held_file file; };
static struct entry entries[SLOTS]; static unsigned count, sequence;
static const wchar_t *runner_sid;
static BOOL bridge_entry(const wchar_t *name, const char *pin) {
  const wchar_t *leaf = wcsrchr(name, '\\'); if (!leaf || wcscmp(leaf+1, L"custody-bridge.exe")) return FALSE;
  for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].kind, "helper") && !wcscmp(entries[i].path, name) && !strcmp(entries[i].pin, pin)) return TRUE;
  return FALSE;
}
static void bridge_security(HANDLE file, char hash[65]) {
  PSID system, runner, owner; PACL dacl; PSECURITY_DESCRIPTOR sd; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  need(ConvertStringSidToSidW(L"S-1-5-18", &system) && ConvertStringSidToSidW(runner_sid, &runner) && !EqualSid(system, runner) &&
    GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS &&
    owner && EqualSid(owner, system) && dacl && IsValidAcl(dacl) && (dacl->AceCount == 1 || dacl->AceCount == 2) &&
    GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED));
  GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS}; unsigned found = 0;
  for (unsigned i = 0; i < dacl->AceCount; i++) {
    ACCESS_ALLOWED_ACE *ace; need(GetAce(dacl, i, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags);
    DWORD mask = ace->Mask; MapGenericMask(&mask, &mapping);
    if (EqualSid(&ace->SidStart, system)) { need(!(found&1) && mask == FILE_ALL_ACCESS); found |= 1; }
    else { need(!(found&2) && EqualSid(&ace->SidStart, runner) && mask == (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)); found |= 2; }
  }
  need(found == 1 || found == 3); LocalFree(sd); LocalFree(system); LocalFree(runner); security(file, SE_FILE_OBJECT, FALSE, hash);
}
/* Reviewed installed MSVC/SDK inputs keep their native read ACLs. Only the
 * trusted installation authorities may own or mutate them; held reads still
 * deny write/delete sharing. Private build/source/receipt objects use System. */
static BOOL stock_entry(const wchar_t *name, const char *pin) {
  const wchar_t *msvc = L"\\Program Files\\Microsoft Visual Studio\\", *sdk = L"\\Program Files (x86)\\Windows Kits\\10\\";
  BOOL installed = wcslen(name) > 3 && name[1] == ':' && (!wcsncmp(name+2, msvc, wcslen(msvc)) || !wcsncmp(name+2, sdk, wcslen(sdk)));
  if (!installed) return FALSE;
  const wchar_t *leaf = wcsrchr(name, '\\'); need(leaf);
  for (unsigned i = 0; i < count; i++) if ((!strcmp(entries[i].kind, "image") || !strcmp(entries[i].kind, "sdk")) &&
    !wcscmp(entries[i].path, name) && !strcmp(entries[i].pin, pin) &&
    (!strcmp(entries[i].kind, "sdk") || !wcscmp(leaf+1, L"cl.exe") || !wcscmp(leaf+1, L"rc.exe"))) return TRUE;
  return FALSE;
}
static void stock_security(HANDLE file, char hash[65]) {
  PSID system, administrators, installer, owner; PACL dacl; PSECURITY_DESCRIPTOR sd;
  need(ConvertStringSidToSidW(L"S-1-5-18", &system) && ConvertStringSidToSidW(L"S-1-5-32-544", &administrators) &&
    ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer) &&
    GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS &&
    dacl && IsValidAcl(dacl) && (EqualSid(owner, system) || EqualSid(owner, administrators) || EqualSid(owner, installer)));
  GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  for (unsigned i = 0; i < dacl->AceCount; i++) {
    ACE_HEADER *header; need(GetAce(dacl, i, (void **)&header));
    need(header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE);
    if (header->AceType == ACCESS_DENIED_ACE_TYPE || (header->AceFlags & INHERIT_ONLY_ACE)) continue;
    ACCESS_ALLOWED_ACE *ace = (void *)header; DWORD mask = ace->Mask; MapGenericMask(&mask, &mapping);
    if (mask & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER))
      need(EqualSid(&ace->SidStart, system) || EqualSid(&ace->SidStart, administrators) || EqualSid(&ace->SidStart, installer));
  }
  LocalFree(sd); LocalFree(system); LocalFree(administrators); LocalFree(installer); security(file, SE_FILE_OBJECT, FALSE, hash);
}
static HANDLE processes[128], tokens[128], jobs[32]; static unsigned process_count, job_count;
static DWORD sessions[128];
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
static BOOL preparation_only;
static wchar_t preparation_directory[4096], preparation_output[4096], preparation_plan[4096];
static char preparation_plan_pin[65];
static ULONGLONG preparation_journal_bytes;
static void preparation_journal(const char *request, unsigned sequence) {
  size_t size = strlen(request); need(size && size <= 262144 && preparation_journal_bytes+size*2 < 67108864); preparation_journal_bytes += size*2;
  wchar_t name[4096]; need(swprintf_s(name, 4096, L"%ls\\windows-files-%hs-%u.json", preparation_directory, nonce, sequence) > 0);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  HANDLE file = CreateFileW(name, GENERIC_WRITE | READ_CONTROL, 0, &sa, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL); LocalFree(sd); need(file != INVALID_HANDLE_VALUE);
  FILETIME created, ended, kernel, user; need(GetProcessTimes(GetCurrentProcess(), &created, &ended, &kernel, &user));
  char prefix[512]; int used = sprintf_s(prefix, sizeof(prefix), "{\"schemaVersion\":1,\"candidateSha\":\"%s\",\"nonce\":\"%s\",\"helper\":{\"pid\":%lu,\"userSid\":\"S-1-5-18\",\"sessionId\":0,\"creationTime\":\"%llu\"},\"commandHex\":\"", candidate, nonce, GetCurrentProcessId(), ((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime); DWORD written;
  need(used > 0 && WriteFile(file, prefix, used, &written, NULL) && written == (DWORD)used);
  BYTE *bytes = calloc(size*2+1, 1); need(bytes); const char *digits = "0123456789abcdef";
  for (size_t i = 0; i < size; i++) { bytes[i*2] = digits[((BYTE)request[i])>>4]; bytes[i*2+1] = digits[((BYTE)request[i])&15]; }
  need(WriteFile(file, bytes, (DWORD)size*2, &written, NULL) && written == size*2 && WriteFile(file, "\"}\n", 3, &written, NULL) && written == 3 && FlushFileBuffers(file) && CloseHandle(file)); free(bytes);
}
static struct held_file *dependencies[32]; static unsigned dependency_count, dependency_sizes[32];
static DWORD WINAPI expire(void *unused) { (void)unused; Sleep(preparation_only ? PREPARATION_LIFETIME_MS : CUSTODY_LIFETIME_MS); ExitProcess(124); return 0; }
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
  need(pid > 0 && pid != GetCurrentProcessId() && process_count < (preparation_only ? 128u : 32u));
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
    files[i] = hold(paths[i], FALSE, FALSE, GENERIC_READ); DWORD size; BYTE *bytes = read_file(&files[i], 536870912, &size); char hash[65], dacl[65], sig[65]; sum(bytes, size, hash); free(bytes);
    wchar_t mapped[4100], named[4100]; DWORD mappedSize = GetMappedFileNameW(process, modules[i], mapped, 4100), namedSize = GetFinalPathNameByHandleW(files[i].handle, named, 4100, FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
    need(mappedSize && mappedSize < 4100 && namedSize && namedSize < 4100 && !_wcsicmp(mapped, named));
    security(files[i].handle, SE_FILE_OBJECT, FALSE, dacl); signature(&files[i], NULL, sig);
    if (i) putchar(','); printf("{\"pathHex\":\""); hex((BYTE *)paths[i], wcslen(paths[i])*2); printf("\",\"identity\":\""); file_id(&files[i]);
    printf("\",\"sha256\":\"%s\",\"signatureSha256\":\"%s\",\"daclSha256\":\"%s\",\"links\":%lu}", hash, sig, dacl, files[i].links); }
  printf("],\"imports\":["); unsigned emitted = 0;
  for (unsigned source = 0; source < n; source++) {
  DWORD size; BYTE *bytes = read_file(&files[source], 536870912, &size); IMAGE_DOS_HEADER *dos = (void *)bytes;
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
  DWORD size; BYTE *bytes = read_file(&image->file, 536870912, &size); IMAGE_DOS_HEADER *dos = (void *)bytes;
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
  need(cert.VirtualAddress >= unsignedSize && cert.VirtualAddress-unsignedSize < 8 && cert.Size >= 8 && cert.Size <= signedSize && cert.VirtualAddress == signedSize-cert.Size && cert.VirtualAddress%8 == 0 && cert.Size%8 == 0);
  DWORD certificateOffset = 0;
  while (certificateOffset < cert.Size) {
    need(cert.Size-certificateOffset >= 8); WIN_CERTIFICATE *entry = (void *)(signedBytes+cert.VirtualAddress+certificateOffset);
    need(entry->dwLength >= 8 && entry->dwLength <= cert.Size-certificateOffset && entry->wRevision == WIN_CERT_REVISION_2_0 && entry->wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA);
    DWORD aligned = (entry->dwLength+7)&~7u; need(aligned <= cert.Size-certificateOffset);
    for (DWORD i = entry->dwLength; i < aligned; i++) need(!signedBytes[cert.VirtualAddress+certificateOffset+i]); certificateOffset += aligned;
  }
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
/* An independently admitted reader retains verification subjects and objects.
 * These operations never launch images or release payloads. */
struct verify_handle { void *object; ULONG_PTR pid, handle; ULONG access; USHORT trace, type; ULONG flags, reserved; };
struct verify_handles { ULONG_PTR count, reserved; struct verify_handle entries[1]; };
static HANDLE verified_jobs[128];
static wchar_t verification_job_names[32][96];
static struct verify_handles *handle_inventory(void) {
  typedef NTSTATUS (NTAPI *query)(ULONG, PVOID, ULONG, PULONG);
  query get = (query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
  need(get); ULONG size = 65536, used = 0; void *bytes = NULL; NTSTATUS status;
  do { free(bytes); bytes = calloc(size, 1); need(bytes); status = get(64, bytes, size, &used);
    if (status == (NTSTATUS)0xc0000004L) { need(size <= 16777216 && used <= 33554432); size = used > size ? used : size*2; }
  } while (status == (NTSTATUS)0xc0000004L);
  need(!status && used <= size && used >= offsetof(struct verify_handles, entries)); struct verify_handles *result = bytes;
  need(result->count <= (used - offsetof(struct verify_handles, entries))/sizeof(struct verify_handle)); return result;
}
static BOOL object_type(HANDLE handle, const wchar_t *expected) {
  typedef NTSTATUS (NTAPI *query)(HANDLE, ULONG, PVOID, ULONG, PULONG);
  query get = (query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
  BYTE bytes[4096]; ULONG used; need(get && !get(handle, 2, bytes, sizeof(bytes), &used) && used >= sizeof(UNICODE_STRING) && used <= sizeof(bytes));
  UNICODE_STRING *type = (void *)bytes;
  need(type->Length <= 128 && (uintptr_t)type->Buffer >= (uintptr_t)bytes &&
    (uintptr_t)type->Buffer <= (uintptr_t)bytes + used && type->Length <= (uintptr_t)bytes + used - (uintptr_t)type->Buffer);
  return type->Length == wcslen(expected)*2 && !wcsncmp(type->Buffer, expected, type->Length/2);
}
static void verifier_task(const char *kind, const wchar_t *nonceText, const char *expected, unsigned subject) {
  need((!strcmp(kind, "custody") || !strcmp(kind, "prerequisite")) && wcslen(nonceText) == 32 && wcsspn(nonceText, L"0123456789abcdef") == 32);
  ITaskService *service; ITaskFolder *folder; IRegisteredTask *task; VARIANT empty; VariantInit(&empty);
  need(SUCCEEDED(CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service)) && SUCCEEDED(ITaskService_Connect(service, empty, empty, empty, empty)));
  BSTR root = SysAllocString(L"\\"); need(root && SUCCEEDED(ITaskService_GetFolder(service, root, &folder))); SysFreeString(root);
  wchar_t name[128]; need(swprintf_s(name, 128, L"%ls%ls", !strcmp(kind, "custody") ? L"NativeProof-Custody-" : L"AgentRunnerPrerequisites-", nonceText) > 0);
  BSTR taskName = SysAllocString(name); need(taskName); HRESULT result = ITaskFolder_GetTask(folder, taskName, &task);
  if (result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) { need(!expected); printf("{\"absent\":true}"); }
  else {
    need(SUCCEEDED(result)); BSTR xml, sd; need(SUCCEEDED(IRegisteredTask_get_Xml(task, &xml)) && SUCCEEDED(IRegisteredTask_GetSecurityDescriptor(task, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sd)));
    DWORD a = SysStringByteLen(xml), b = SysStringByteLen(sd); need(a && a <= 262144 && b && b <= 65536);
    BYTE *bytes = calloc(a+b+8, 1); need(bytes); memcpy(bytes, &a, 4); memcpy(bytes+4, xml, a); memcpy(bytes+4+a, &b, 4); memcpy(bytes+8+a, sd, b);
    char hash[65]; sum(bytes, a+b+8, hash); free(bytes); SysFreeString(xml); SysFreeString(sd);
    IRunningTaskCollection *instances; LONG active; need(SUCCEEDED(IRegisteredTask_GetInstances(task, 0, &instances)) && SUCCEEDED(IRunningTaskCollection_get_Count(instances, &active)) && active >= 0 && active <= 32); IRunningTaskCollection_Release(instances);
    if (expected) {
      need(!strcmp(kind, "prerequisite")); wchar_t ownedJob[96]; need(swprintf_s(ownedJob, 96, L"Local\\NativeProof-%ls", nonceText) > 0); BOOL heldJob = FALSE;
      for (unsigned i = 0; i < job_count; i++) if (!wcscmp(verification_job_names[i], ownedJob)) heldJob = TRUE;
      need(heldJob);
      need(strlen(expected) == 64 && strspn(expected, "0123456789abcdef") == 64 && !strcmp(expected, hash) && !active && subject < process_count && WaitForSingleObject(processes[subject], 0) == WAIT_OBJECT_0);
      for (unsigned i = 0; i < process_count; i++) need(WaitForSingleObject(processes[i], 0) == WAIT_OBJECT_0);
      for (unsigned i = 0; i < 128; i++) if (verified_jobs[i]) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current; need(QueryInformationJobObject(verified_jobs[i], JobObjectBasicAccountingInformation, &current, sizeof(current), NULL) && !current.ActiveProcesses); }
      for (unsigned i = 0; i < job_count; i++) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current; need(QueryInformationJobObject(jobs[i], JobObjectBasicAccountingInformation, &current, sizeof(current), NULL) && !current.ActiveProcesses); }
      need(SUCCEEDED(ITaskFolder_DeleteTask(folder, taskName, 0))); IRegisteredTask *again;
      need(ITaskFolder_GetTask(folder, taskName, &again) == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)); printf("{\"removed\":true,\"sha256\":\"%s\"}", hash);
    } else printf("{\"absent\":false,\"sha256\":\"%s\",\"instances\":%ld}", hash, active);
    IRegisteredTask_Release(task);
  }
  SysFreeString(taskName); ITaskFolder_Release(folder); ITaskService_Release(service);
}
static HANDLE duplicate_process_owner(unsigned slot) {
  need(slot < process_count); HANDLE process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetProcessId(processes[slot]));
  FILETIME heldCreation, actualCreation, exited, kernel, user;
  need(process && GetProcessTimes(processes[slot], &heldCreation, &exited, &kernel, &user) &&
    GetProcessTimes(process, &actualCreation, &exited, &kernel, &user) &&
    !memcmp(&heldCreation, &actualCreation, sizeof(FILETIME))); return process;
}
static void verifier_transfer(unsigned child, unsigned creator) {
  need(child < process_count && creator < process_count && child != creator && !verified_jobs[child]);
  HANDLE source = duplicate_process_owner(creator);
  struct verify_handles *list = handle_inventory(); HANDLE job = NULL, thread = NULL;
  for (ULONG_PTR i = 0; i < list->count; i++) {
    struct verify_handle *entry = &list->entries[i]; if (entry->pid != GetProcessId(source)) continue;
    HANDLE duplicate; need(DuplicateHandle(source, (HANDLE)entry->handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS));
    if (object_type(duplicate, L"Job")) {
      BOOL belongs = FALSE; if (IsProcessInJob(processes[child], duplicate, &belongs) && belongs) { need(!job); job = duplicate; continue; }
    } else if (object_type(duplicate, L"Thread") && GetProcessIdOfThread(duplicate) == GetProcessId(processes[child])) {
      need(!thread); thread = duplicate; continue;
    }
    need(CloseHandle(duplicate));
  }
  free(list); need(job && thread && CloseHandle(source)); verified_jobs[child] = job;
  char dacl[65]; security(thread, SE_KERNEL_OBJECT, TRUE, dacl); need(CloseHandle(thread));
  printf("{\"threadDaclSha256\":\"%s\",\"job\":", dacl); job_read(job);
  HANDLE process = duplicate_process_owner(child);
  list = handle_inventory(); unsigned inherited = 0, pipe_count = 0; char pipe_dacl[2][65]; printf(",\"objects\":[");
  for (ULONG_PTR i = 0; i < list->count; i++) {
    struct verify_handle *entry = &list->entries[i]; if (entry->pid != GetProcessId(process) || !(entry->flags & 2)) continue;
    need(inherited < 130); HANDLE duplicate; need(DuplicateHandle(process, (HANDLE)entry->handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS));
    if (inherited++) putchar(','); DWORD type = GetFileType(duplicate);
    if (type == FILE_TYPE_DISK) { FILE_ID_INFO id; need(GetFileInformationByHandleEx(duplicate, FileIdInfo, &id, sizeof(id)));
      printf("\"%016llx:", id.VolumeSerialNumber); hex(id.FileId.Identifier, 16); putchar('"'); }
    else { need(type == FILE_TYPE_PIPE && pipe_count < 2); security(duplicate, SE_FILE_OBJECT, TRUE, pipe_dacl[pipe_count++]); printf("null"); }
    need(CloseHandle(duplicate));
  }
  free(list); need(pipe_count == 2 && CloseHandle(process)); printf("],\"inheritedHandleCount\":%u,\"pipeDaclSha256\":[\"%s\",\"%s\"]", inherited, pipe_dacl[0], pipe_dacl[1]);
  TOKEN_DEFAULT_DACL *creation = token_info(tokens[child], TokenDefaultDacl); need(creation->DefaultDacl && IsValidAcl(creation->DefaultDacl));
  sum((BYTE *)creation->DefaultDacl, creation->DefaultDacl->AclSize, dacl); free(creation);
  printf(",\"creatorDefaultDaclSha256\":\"%s\"}", dacl);
}
/* Read the parked compiler token and inherited kernel handles independently
 * before its first instruction; expected materialization cannot supply these. */
static void compiler_policy(unsigned index, unsigned creator) {
  need(index < process_count && WaitForSingleObject(processes[index], 0) == WAIT_TIMEOUT);
  TOKEN_DEFAULT_DACL *creation = token_info(tokens[index], TokenDefaultDacl);
  printf("{\"defaultDacl\":"); acl_read(creation->DefaultDacl); free(creation);
  HANDLE source = duplicate_process_owner(index); struct verify_handles *list = handle_inventory();
  unsigned pipes = 0;
  for (ULONG_PTR i = 0; i < list->count; i++) {
    struct verify_handle *entry = &list->entries[i]; if (entry->pid != GetProcessId(source) || !(entry->flags & 2)) continue;
    HANDLE duplicate; need(DuplicateHandle(source, (HANDLE)entry->handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS));
    DWORD type = GetFileType(duplicate); need(type == FILE_TYPE_PIPE); pipes++;
    need(CloseHandle(duplicate));
  }
  free(list); need(CloseHandle(source) && pipes == 3);
  source = duplicate_process_owner(creator); list = handle_inventory(); HANDLE compilerJob = NULL;
  for (ULONG_PTR i = 0; i < list->count; i++) {
    struct verify_handle *entry = &list->entries[i]; if (entry->pid != GetProcessId(source)) continue;
    HANDLE duplicate; need(DuplicateHandle(source, (HANDLE)entry->handle, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS));
    BOOL member = FALSE; JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    if (object_type(duplicate, L"Job") && IsProcessInJob(processes[index], duplicate, &member) && member &&
        QueryInformationJobObject(duplicate, JobObjectExtendedLimitInformation, &limits, sizeof(limits), NULL) && limits.BasicLimitInformation.ActiveProcessLimit == 31) {
      need(!compilerJob); compilerJob = duplicate;
    } else need(CloseHandle(duplicate));
  }
  free(list); need(CloseHandle(source) && compilerJob);
  printf(",\"inheritedHandles\":[\"pipe\",\"pipe\",\"pipe\"],\"compilerJob\":"); job_read(compilerJob);
  need(CloseHandle(compilerJob)); putchar('}');
}
static struct held_file verification_files[128]; static unsigned verification_file_count;
static void verification_path(const wchar_t *name, const char *pin, const char *signature) {
  BOOL admitted = FALSE;
  if (preparation_only && !strcmp(signature, "-")) {
    size_t prefix = wcslen(preparation_directory);
    if (!_wcsnicmp(name, preparation_directory, prefix) && name[prefix] == '\\') admitted = TRUE;
    if (!wcscmp(name, preparation_plan) && !strcmp(pin, preparation_plan_pin)) admitted = TRUE;
  }
  for (unsigned i = 0; i < count; i++) {
    struct entry *entry = &entries[i]; size_t prefix = wcslen(entry->path);
    if (!_wcsicmp(name, entry->path) && strcmp(entry->kind, "directory") && strcmp(entry->kind, "mutable") && !strcmp(pin, entry->pin) && !strcmp(signature, entry->signature)) admitted = TRUE;
    if (preparation_only && !strcmp(entry->kind, "helper") && !strcmp(pin, entry->pin) && !strcmp(signature, entry->signature) &&
        !wcsncmp(name, preparation_output, wcslen(preparation_output)) && name[wcslen(preparation_output)] == '\\' &&
        !wcscmp(wcsrchr(name, '\\')+1, wcsrchr(entry->path, '\\')+1)) admitted = TRUE;
    /* Dynamic immutable records remain inside an independently approved root.
     * They can supply data, never executable/signature admission. */
    if (!strcmp(signature, "-") && !strcmp(entry->kind, "directory") && !_wcsnicmp(name, entry->path, prefix) && name[prefix] == '\\') admitted = TRUE;
  }
  need(admitted);
}

static HANDLE case_token, case_job; static unsigned case_custody;
static SOCKET case_sockets[8]; static unsigned case_socket_count;
static struct case_account_record case_record;
static void case_directory(unsigned index, unsigned parent) {
  need(index < count && parent < count && !entries[index].file.handle && !strcmp(entries[index].kind, "directory") && entries[parent].file.handle);
  wchar_t name[4096]; wcscpy_s(name, 4096, entries[index].path); wchar_t *leaf = wcsrchr(name, '\\'); need(leaf); *leaf = 0;
  need(!wcscmp(name, entries[parent].path)); PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  need(CreateDirectoryW(entries[index].path, &sa)); LocalFree(sd);
  entries[index].file = hold(entries[index].path, TRUE, TRUE, FILE_LIST_DIRECTORY); inspect(&entries[index]);
}
static void case_copy(unsigned target, unsigned source, unsigned parent) {
  need(target < count && source < count && parent < count && !entries[target].file.handle && entries[source].file.handle && entries[parent].file.handle &&
    strcmp(entries[target].kind, "directory") && !strcmp(entries[target].kind, entries[source].kind) &&
    !strcmp(entries[target].pin, entries[source].pin) && !strcmp(entries[target].signature, entries[source].signature));
  wchar_t name[4096]; wcscpy_s(name, 4096, entries[target].path); wchar_t *leaf = wcsrchr(name, '\\'); need(leaf); *leaf = 0; need(!wcscmp(name, entries[parent].path));
  pin(&entries[source].file, entries[source].pin); DWORD size; BYTE *bytes = read_file(&entries[source].file, 134217728, &size);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  HANDLE file = CreateFileW(entries[target].path, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL); LocalFree(sd); DWORD written;
  need(file != INVALID_HANDLE_VALUE && WriteFile(file, bytes, size, &written, NULL) && written == size && FlushFileBuffers(file) && CloseHandle(file)); free(bytes);
  entries[target].file = hold(entries[target].path, FALSE, TRUE, GENERIC_READ); pin(&entries[target].file, entries[target].pin);
  if (strcmp(entries[target].signature, "-")) { char hash[65]; signature(&entries[target].file, entries[target].signature, hash); } inspect(&entries[target]);
}
static void case_account_create(unsigned custody, const char *context) {
  need(!case_token && custody < count && entries[custody].file.handle && strlen(context) == 64 && strspn(context, "0123456789abcdef") == 64 && !memcmp(context, nonce, 32));
  need(system_process(GetCurrentProcess())); case_custody = custody; case_record.version = 1;
  strcpy_s(case_record.context, 65, context); strcpy_s(case_record.nonce, 33, nonce);
  /* This immutable intent precedes NetUserAdd and all token/Job effects. */
  HANDLE file = account_file(entries[custody].path, L"account.intent", GENERIC_WRITE, CREATE_NEW); DWORD written;
  need(WriteFile(file, &case_record, sizeof(case_record), &written, NULL) && written == sizeof(case_record) && FlushFileBuffers(file) && CloseHandle(file));
  wchar_t name[21], *sid; need(swprintf_s(name, 21, L"np_%.16hs", nonce) > 0); HANDLE base = account(name, entries[custody].path, &sid);
  wcscpy_s(case_record.accountSid, 256, sid); LocalFree(sid); DWORD random[4];
  need(BCryptGenRandom(NULL, (BYTE *)random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0);
  need(swprintf_s(case_record.restrictingSid, 256, L"S-1-5-21-%lu-%lu-%lu-%lu", random[0] | 1, random[1] | 1, random[2] | 1, (random[3] & 0x7fffffff) + 1000) > 0);
  PSID capability; need(ConvertStringSidToSidW(case_record.restrictingSid, &capability)); case_token = restrict_token(base, capability); need(CloseHandle(base)); LocalFree(capability);
  account_check(name, case_record.accountSid);
  file = account_file(entries[custody].path, L"account.record", GENERIC_WRITE, CREATE_NEW);
  need(WriteFile(file, &case_record, sizeof(case_record), &written, NULL) && written == sizeof(case_record) && FlushFileBuffers(file) && CloseHandle(file));
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE); wchar_t jobName[96];
  need(swprintf_s(jobName, 96, L"Local\\NativeProof-%hs", nonce) > 0); SetLastError(0); case_job = CreateJobObjectW(&sa, jobName); DWORD jobError = GetLastError(); LocalFree(sd);
  need(case_job && jobError != ERROR_ALREADY_EXISTS); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS; limits.BasicLimitInformation.ActiveProcessLimit = 32;
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui = {255}; need(SetInformationJobObject(case_job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) && SetInformationJobObject(case_job, JobObjectBasicUIRestrictions, &ui, sizeof(ui)));
  printf("{\"accountSid\":\"%ls\",\"restrictingSid\":\"%ls\",\"contextSha256\":\"%s\",\"tokenHandle\":\"%llu\"}", case_record.accountSid, case_record.restrictingSid, context, (ULONGLONG)(ULONG_PTR)case_token);
}
static void case_endpoint(BOOL v6, BOOL udp, unsigned port) {
  need(case_token && case_socket_count < 8 && port >= 1024 && port <= 65535); WSADATA data; need(!WSAStartup(MAKEWORD(2, 2), &data));
  SOCKET socket = WSASocketW(v6 ? AF_INET6 : AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, udp ? IPPROTO_UDP : IPPROTO_TCP, NULL, 0, WSA_FLAG_NO_HANDLE_INHERIT);
  need(socket != INVALID_SOCKET); BOOL exclusive = TRUE; need(!setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&exclusive, sizeof(exclusive)));
  if (v6) { BOOL only = TRUE; need(!setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&only, sizeof(only))); struct sockaddr_in6 address = {0}; address.sin6_family = AF_INET6; address.sin6_port = htons((u_short)port); address.sin6_addr = in6addr_loopback; need(!bind(socket, (struct sockaddr *)&address, sizeof(address))); }
  else { struct sockaddr_in address = {0}; address.sin_family = AF_INET; address.sin_port = htons((u_short)port); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); need(!bind(socket, (struct sockaddr *)&address, sizeof(address))); }
  case_sockets[case_socket_count++] = socket; printf("{\"bound\":true}");
}
static void case_read(void) {
  need(case_token && case_job); printf("{\"token\":"); effective_token_handle(case_token); printf(",\"job\":"); job_read(case_job); printf(",\"endpoints\":[");
  for (unsigned i = 0; i < case_socket_count; i++) { struct sockaddr_storage address; int size = sizeof(address), type, typeSize = sizeof(type);
    need(!getsockname(case_sockets[i], (struct sockaddr *)&address, &size) && !getsockopt(case_sockets[i], SOL_SOCKET, SO_TYPE, (char *)&type, &typeSize));
    BOOL v6 = address.ss_family == AF_INET6; unsigned port = ntohs(v6 ? ((struct sockaddr_in6 *)&address)->sin6_port : ((struct sockaddr_in *)&address)->sin_port);
    need(v6 ? IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)&address)->sin6_addr) : ((struct sockaddr_in *)&address)->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    printf("%s{\"family\":\"%s\",\"protocol\":\"%s\",\"port\":%u}", i ? "," : "", v6 ? "v6" : "v4", type == SOCK_DGRAM ? "udp" : "tcp", port);
  } printf("]}");
}
static void verify_case(unsigned subject, unsigned custody, const char *context, const char *tokenHandle) {
  need(subject < process_count && custody < count && !strcmp(entries[custody].kind, "directory"));
  struct case_account_record record = {0}; account_record(entries[custody].path, &record); need(!strcmp(context, record.context));
  HANDLE base = account_adopt(entries[custody].path, &record); need(CloseHandle(base));
  HANDLE source = duplicate_process_owner(subject), token; need(system_process(source) && DuplicateHandle(source, (HANDLE)(ULONG_PTR)number(tokenHandle), GetCurrentProcess(), &token, TOKEN_QUERY | TOKEN_DUPLICATE, FALSE, 0));
  wchar_t *actual = token_sid(token); need(!wcscmp(actual, record.accountSid)); LocalFree(actual);
  char recordPin[65]; sum((BYTE *)&record, sizeof(record), recordPin);
  printf("{\"accountSid\":\"%ls\",\"restrictingSid\":\"%ls\",\"contextSha256\":\"%s\",\"recordSha256\":\"%s\",\"token\":", record.accountSid, record.restrictingSid, context, recordPin);
  effective_token_handle(token); need(CloseHandle(token) && CloseHandle(source)); printf(",\"objects\":[");
  wchar_t root[4096]; wcscpy_s(root, 4096, entries[custody].path); wchar_t *leaf = wcsrchr(root, '\\'); need(leaf && !wcscmp(leaf+1, L"custody")); *leaf = 0;
  unsigned emitted = 0;
  for (unsigned i = 0; i < count; i++) if (!_wcsicmp(root, entries[i].path) || (!wcsncmp(root, entries[i].path, wcslen(root)) && entries[i].path[wcslen(root)] == '\\')) {
    struct entry entry = entries[i]; entry.file = hold(entry.path, !strcmp(entry.kind, "directory"), TRUE, GENERIC_READ | ACCESS_SYSTEM_SECURITY);
    if (strcmp(entry.kind, "directory")) { pin(&entry.file, entry.pin); if (strcmp(entry.signature, "-")) { char sig[65]; signature(&entry.file, entry.signature, sig); } }
    if (emitted++) putchar(','); printf("{\"index\":%u,\"object\":", i); inspect(&entry); printf(",\"security\":"); PSECURITY_DESCRIPTOR sd = file_sd(entry.file.handle, SE_FILE_OBJECT); sd_read(sd); LocalFree(sd); putchar('}'); close_file(&entry.file);
  } printf("]}");
}
static void case_retire(void) {
  need(case_token && case_job && !helpers[0].process && !helpers[1].process && !audit_owned);
  struct case_account_record held = {0}; account_record(entries[case_custody].path, &held); need(!memcmp(&held, &case_record, sizeof(held)));
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION job; need(QueryInformationJobObject(case_job, JobObjectBasicAccountingInformation, &job, sizeof(job), NULL) && !job.ActiveProcesses && job.TotalProcesses == 0);
  wchar_t name[21]; need(swprintf_s(name, 21, L"np_%.16hs", case_record.nonce) > 0); account_check(name, case_record.accountSid);
  for (unsigned i = 0; i < case_socket_count; i++) need(!closesocket(case_sockets[i]) && !WSACleanup()); case_socket_count = 0;
  need(CloseHandle(case_token) && CloseHandle(case_job)); case_token = case_job = NULL;
  PSID user; need(ConvertStringSidToSidW(case_record.accountSid, &user)); LSA_OBJECT_ATTRIBUTES attributes = {0}; attributes.Length = sizeof(attributes); LSA_HANDLE policy;
  need(LsaOpenPolicy(NULL, &attributes, POLICY_LOOKUP_NAMES, &policy) == 0 && LsaRemoveAccountRights(policy, user, TRUE, NULL, 0) == 0); LsaClose(policy); LocalFree(user);
  need(NetUserDel(NULL, name) == NERR_Success); printf("{\"retired\":true}");
}
static void verify_case_retired(unsigned custody, const char *context) {
  need(custody < count); struct case_account_record record = {0}; account_record(entries[custody].path, &record); need(!strcmp(context, record.context));
  wchar_t name[21]; need(swprintf_s(name, 21, L"np_%.16hs", record.nonce) > 0); USER_INFO_1 *user;
  need(NetUserGetInfo(NULL, name, 1, (BYTE **)&user) == NERR_UserNotFound);
  PSID sid; need(ConvertStringSidToSidW(record.accountSid, &sid)); LSA_OBJECT_ATTRIBUTES attributes = {0}; attributes.Length = sizeof(attributes);
  LSA_HANDLE policy; LSA_UNICODE_STRING *rights = NULL; ULONG number = 0;
  need(LsaOpenPolicy(NULL, &attributes, POLICY_LOOKUP_NAMES, &policy) == 0);
  NTSTATUS status = LsaEnumerateAccountRights(policy, sid, &rights, &number);
  /* STATUS_OBJECT_NAME_NOT_FOUND is the only accepted missing LSA account;
   * other errors cannot establish removal of the owned rights. */
  need((status == 0 && number == 0) || status == (NTSTATUS)0xc0000034L);
  if (rights) LsaFreeMemory(rights); need(LsaClose(policy) == 0); LocalFree(sid);
  wchar_t job[96]; need(swprintf_s(job, 96, L"Local\\NativeProof-%hs", record.nonce) > 0); HANDLE handle = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, job);
  need(!handle && GetLastError() == ERROR_FILE_NOT_FOUND); printf("{\"accountAbsent\":true,\"rightsAbsent\":true,\"jobAbsent\":true,\"contextSha256\":\"%s\"}", context);
}
/* Finite ownership operations. The launcher owns creation; these retained
 * objects and short-lived System witnesses own observation and settlement. */
static PROCESS_INFORMATION ownership_launcher;
static HANDLE ownership_launcher_token;
static PROCESS_INFORMATION ownership_owner;
static HANDLE ownership_owner_input, ownership_owner_output, ownership_owner_job, ownership_owner_token;
static BOOL ownership_literal;
static unsigned ownership_stage;
static HANDLE ownership_control, ownership_frames, ownership_output;
static HANDLE ownership_processes[32], ownership_tokens[32]; static unsigned ownership_count;
static BOOL ownership_released, ownership_policy_installed, ownership_creation_verified, ownership_spoofed;
static struct held_file ownership_policy_file, ownership_sentinel;
static PSECURITY_DESCRIPTOR ownership_before[6], ownership_installed[6];
static char ownership_baseline[6][65];
static BOOL ownership_policy_restored;
static const DWORD ownership_masks[6] = {0, 0, 0x120020, 0x12019f, 0, 0x1200a9};
static GUID ownership_provider, ownership_layer, ownership_filters[4];
static char ownership_last_job_pin[65];
static void ownership_keys(void) {
  GUID *keys[] = {&ownership_provider, &ownership_layer, &ownership_filters[0], &ownership_filters[1], &ownership_filters[2], &ownership_filters[3]};
  for (unsigned i = 0; i < 6; i++) { char seed[80], hash[65]; BYTE bytes[32];
    need(sprintf_s(seed, sizeof(seed), "ownership:%s:%u", nonce, i) > 0); sum((BYTE *)seed, (DWORD)strlen(seed), hash);
    for (unsigned j = 0; j < 32; j++) bytes[j] = (BYTE)(nibble(hash[j*2])*16+nibble(hash[j*2+1])); memcpy(keys[i], bytes, sizeof(GUID)); }
}
static void ownership_wfp_security(const GUID *key, unsigned kind) {
  PSECURITY_DESCRIPTOR sd; SECURITY_INFORMATION info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
  DWORD status = kind == 0 ? FwpmProviderGetSecurityInfoByKey0(wfp_engine, key, info, NULL, NULL, NULL, NULL, &sd) :
    kind == 1 ? FwpmSubLayerGetSecurityInfoByKey0(wfp_engine, key, info, NULL, NULL, NULL, NULL, &sd) :
    FwpmFilterGetSecurityInfoByKey0(wfp_engine, key, info, NULL, NULL, NULL, NULL, &sd);
  PACL dacl; BOOL present, defaulted; PSID owner, group, system; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  need(status == ERROR_SUCCESS && ConvertStringSidToSidW(L"S-1-5-18", &system) &&
    GetSecurityDescriptorOwner(sd, &owner, &defaulted) && EqualSid(owner, system) &&
    GetSecurityDescriptorGroup(sd, &group, &defaulted) && EqualSid(group, system) &&
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present && dacl && dacl->AceCount == 1 &&
    GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED));
  ACCESS_ALLOWED_ACE *ace; need(GetAce(dacl, 0, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
    !ace->Header.AceFlags && EqualSid(&ace->SidStart, system) && (ace->Mask == GENERIC_ALL || ace->Mask == FWPM_GENERIC_ALL));
  LocalFree(system); FwpmFreeMemory0((void **)&sd);
}
static void ownership_network_absent(void) {
  ownership_keys(); wfp_open(); FWPM_PROVIDER0 *provider; FWPM_SUBLAYER0 *layer; FWPM_FILTER0 *filter;
  need(FwpmProviderGetByKey0(wfp_engine, &ownership_provider, &provider) == FWP_E_PROVIDER_NOT_FOUND &&
    FwpmSubLayerGetByKey0(wfp_engine, &ownership_layer, &layer) == FWP_E_SUBLAYER_NOT_FOUND);
  for (unsigned i = 0; i < 4; i++) need(FwpmFilterGetByKey0(wfp_engine, &ownership_filters[i], &filter) == FWP_E_FILTER_NOT_FOUND);
}
static void ownership_network(BOOL remove, BOOL observe) {
  ownership_keys(); wfp_open();
  const GUID *layers[] = {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)");
  PSID user, restricting; need(ConvertStringSidToSidW(case_record.accountSid, &user) && ConvertStringSidToSidW(case_record.restrictingSid, &restricting));
  EXPLICIT_ACCESSW access[2] = {0}; PACL acl;
  for (unsigned i = 0; i < 2; i++) { access[i].grfAccessPermissions = FWP_ACTRL_MATCH_FILTER; access[i].grfAccessMode = GRANT_ACCESS;
    access[i].Trustee.TrusteeForm = TRUSTEE_IS_SID; access[i].Trustee.ptstrName = i ? restricting : user; }
  need(SetEntriesInAclW(2, access, NULL, &acl) == ERROR_SUCCESS); SECURITY_DESCRIPTOR match;
  need(InitializeSecurityDescriptor(&match, SECURITY_DESCRIPTOR_REVISION) && SetSecurityDescriptorDacl(&match, TRUE, acl, FALSE));
  DWORD size = 0; MakeSelfRelativeSD(&match, NULL, &size); need(size && size <= 4096); BYTE *relative = calloc(size, 1);
  need(relative && MakeSelfRelativeSD(&match, relative, &size)); FWP_BYTE_BLOB blob = {size, relative};
  if (!observe) need(FwpmTransactionBegin0(wfp_engine, 0) == ERROR_SUCCESS);
  if (remove || observe) {
    FWPM_PROVIDER0 *provider; FWPM_SUBLAYER0 *layer;
    need(FwpmProviderGetByKey0(wfp_engine, &ownership_provider, &provider) == ERROR_SUCCESS && provider->flags == FWPM_PROVIDER_FLAG_PERSISTENT &&
      !provider->providerData.size && !provider->serviceName && provider->displayData.name && !wcscmp(provider->displayData.name, L"NativeProof ownership") && !provider->displayData.description);
    need(FwpmSubLayerGetByKey0(wfp_engine, &ownership_layer, &layer) == ERROR_SUCCESS && layer->providerKey &&
      IsEqualGUID(layer->providerKey, &ownership_provider) && layer->flags == FWPM_SUBLAYER_FLAG_PERSISTENT && layer->weight == 65535 && !layer->providerData.size &&
      layer->displayData.name && !wcscmp(layer->displayData.name, L"NativeProof ownership") && !layer->displayData.description);
    FwpmFreeMemory0((void **)&provider); FwpmFreeMemory0((void **)&layer);
    ownership_wfp_security(&ownership_provider, 0); ownership_wfp_security(&ownership_layer, 1);
  }
  if (!remove && !observe) {
    FWPM_PROVIDER0 provider = {0}; provider.providerKey = ownership_provider; provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    provider.displayData.name = L"NativeProof ownership";
    FWPM_SUBLAYER0 layer = {0}; layer.subLayerKey = ownership_layer; layer.providerKey = &ownership_provider;
    layer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT; layer.weight = 65535; layer.displayData.name = L"NativeProof ownership";
    need(FwpmProviderAdd0(wfp_engine, &provider, sd) == ERROR_SUCCESS && FwpmSubLayerAdd0(wfp_engine, &layer, sd) == ERROR_SUCCESS);
  }
  for (unsigned i = 0; i < 4; i++) {
    UINT64 weight = 10; FWPM_FILTER_CONDITION0 condition = {0}; condition.fieldKey = FWPM_CONDITION_ALE_USER_ID;
    condition.matchType = FWP_MATCH_EQUAL; condition.conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE; condition.conditionValue.sd = &blob;
    FWPM_FILTER0 value = {0}; value.filterKey = ownership_filters[i]; value.providerKey = &ownership_provider;
    value.subLayerKey = ownership_layer; value.layerKey = *layers[i]; value.displayData.name = L"NativeProof ownership deny";
    value.flags = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT; value.action.type = FWP_ACTION_BLOCK;
    value.weight.type = FWP_UINT64; value.weight.uint64 = &weight; value.numFilterConditions = 1; value.filterCondition = &condition;
    if (remove || observe) {
      FWPM_FILTER0 *actual; need(FwpmFilterGetByKey0(wfp_engine, &value.filterKey, &actual) == ERROR_SUCCESS && actual->providerKey &&
        IsEqualGUID(actual->providerKey, &ownership_provider) && IsEqualGUID(&actual->subLayerKey, &ownership_layer) && IsEqualGUID(&actual->layerKey, layers[i]) &&
        actual->flags == value.flags && actual->action.type == value.action.type && actual->weight.type == FWP_UINT64 && actual->weight.uint64 && *actual->weight.uint64 == weight &&
        !actual->providerData.size && !actual->rawContext && !actual->reserved && actual->displayData.name &&
        !wcscmp(actual->displayData.name, value.displayData.name) && !actual->displayData.description &&
        actual->numFilterConditions == 1 && IsEqualGUID(&actual->filterCondition[0].fieldKey, &condition.fieldKey) &&
        actual->filterCondition[0].matchType == FWP_MATCH_EQUAL && actual->filterCondition[0].conditionValue.type == FWP_SECURITY_DESCRIPTOR_TYPE &&
        actual->filterCondition[0].conditionValue.sd->size == size && !memcmp(actual->filterCondition[0].conditionValue.sd->data, relative, size));
      FwpmFreeMemory0((void **)&actual); ownership_wfp_security(&value.filterKey, 2);
      if (remove) need(FwpmFilterDeleteByKey0(wfp_engine, &value.filterKey) == ERROR_SUCCESS);
    } else { UINT64 id; need(FwpmFilterAdd0(wfp_engine, &value, sd, &id) == ERROR_SUCCESS); }
  }
  /* A complete provider census rejects unplanned additional filters. */
  if (observe) {
    FWPM_FILTER_ENUM_TEMPLATE0 filterTemplate = {0}; filterTemplate.providerKey = &ownership_provider;
    HANDLE enumeration; FWPM_FILTER0 **filters; UINT32 number;
    need(FwpmFilterCreateEnumHandle0(wfp_engine, &filterTemplate, &enumeration) == ERROR_SUCCESS &&
      FwpmFilterEnum0(wfp_engine, enumeration, 5, &filters, &number) == ERROR_SUCCESS && number == 4);
    FwpmFreeMemory0((void **)&filters); need(FwpmFilterDestroyEnumHandle0(wfp_engine, enumeration) == ERROR_SUCCESS);
  }
  if (remove) need(FwpmSubLayerDeleteByKey0(wfp_engine, &ownership_layer) == ERROR_SUCCESS && FwpmProviderDeleteByKey0(wfp_engine, &ownership_provider) == ERROR_SUCCESS);
  if (!observe) need(FwpmTransactionCommit0(wfp_engine) == ERROR_SUCCESS);
  free(relative); LocalFree(acl); LocalFree(user); LocalFree(restricting); LocalFree(sd);
}
static void ownership_acl(unsigned i, BOOL restore, BOOL inspectOnly) {
  struct entry *entry = &entries[i+1]; need(entry->file.handle);
  HANDLE file = ReOpenFile(entry->file.handle, READ_CONTROL | FILE_READ_ATTRIBUTES | WRITE_DAC | ACCESS_SYSTEM_SECURITY,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
  FILE_ID_INFO id; need(file != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) && !memcmp(&id, &entry->file.id, sizeof(id)));
  wchar_t text[2048]; DWORD mask = ownership_masks[i];
  if (!mask) wcscpy_s(text, 2048, L"O:SYG:SYD:P(A;;FA;;;SY)");
  else need(swprintf_s(text, 2048, L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x%lx;;;%ls)(A;;0x%lx;;;%ls)%ls", mask, case_record.accountSid, mask, case_record.restrictingSid,
    i == 3 ? L"S:(ML;;NW;;;LW)" : L"") > 0);
  PSECURITY_DESCRIPTOR wanted = descriptor(text), actual = file_sd(file, SE_FILE_OBJECT); PACL acl, expected; BOOL present, defaulted;
  need(GetSecurityDescriptorDacl(wanted, &present, &expected, &defaulted) && present && expected);
  if (restore || inspectOnly) {
    PSID owner, system; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
    need(ConvertStringSidToSidW(L"S-1-5-18", &system) && GetSecurityDescriptorOwner(actual, &owner, &defaulted) && EqualSid(owner, system) &&
      GetSecurityDescriptorControl(actual, &flags, &revision) && (flags & SE_DACL_PROTECTED) && GetSecurityDescriptorDacl(actual, &present, &acl, &defaulted) &&
      present && acl && acl->AclSize == expected->AclSize && !memcmp(acl, expected, acl->AclSize)); LocalFree(system);
    if (i == 3) { PACL label, expectedLabel; need(GetSecurityDescriptorSacl(actual, &present, &label, &defaulted) && present && label &&
      GetSecurityDescriptorSacl(wanted, &present, &expectedLabel, &defaulted) && present && expectedLabel && label->AclSize == expectedLabel->AclSize && !memcmp(label, expectedLabel, label->AclSize)); }
  }
  if (!inspectOnly) {
    if (!restore) { need(!ownership_before[i]); char hash[65]; security(file, SE_FILE_OBJECT, TRUE, hash);
      sum((BYTE *)actual, GetSecurityDescriptorLength(actual), ownership_baseline[i]); ownership_before[i] = actual; actual = NULL; ownership_installed[i] = wanted; wanted = NULL; }
    PSECURITY_DESCRIPTOR target = restore ? ownership_before[i] : ownership_installed[i]; need(target && GetSecurityDescriptorDacl(target, &present, &acl, &defaulted) && present);
    need(SetSecurityInfo(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL) == ERROR_SUCCESS);
    if (i == 3) { PACL label; need(GetSecurityDescriptorSacl(target, &present, &label, &defaulted));
      need(SetSecurityInfo(file, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, present ? label : NULL) == ERROR_SUCCESS); }
  }
  if (actual) LocalFree(actual); if (wanted) LocalFree(wanted); need(CloseHandle(file));
}
static void ownership_retain(DWORD pid, ULONGLONG birth) {
  for (unsigned i = 0; i < ownership_count; i++) if (GetProcessId(ownership_processes[i]) == pid) {
    FILETIME created, exited, kernel, user; need(GetProcessTimes(ownership_processes[i], &created, &exited, &kernel, &user) &&
      (((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime) == birth); return; }
  need(ownership_count < 32); HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | READ_CONTROL | SYNCHRONIZE, FALSE, pid), token;
  FILETIME created, exited, kernel, user;
  need(process && GetProcessId(process) == pid && GetProcessTimes(process, &created, &exited, &kernel, &user) &&
    (((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime) == birth && OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token));
  wchar_t *sid = token_sid(token); need(!wcscmp(sid, case_record.accountSid) && process_session(process) == 0); LocalFree(sid);
  BOOL belongs; need(case_job && IsProcessInJob(process, case_job, &belongs) && belongs);
  ownership_processes[ownership_count] = process; ownership_tokens[ownership_count++] = token;
}
static void ownership_job_pin(HANDLE job, char hash[65]) {
  struct verify_handles *inventory = handle_inventory(); void *object = NULL;
  for (ULONG_PTR i = 0; i < inventory->count; i++) if (inventory->entries[i].pid == GetCurrentProcessId() && inventory->entries[i].handle == (ULONG_PTR)job) object = inventory->entries[i].object;
  need(object); sum((BYTE *)&object, sizeof(object), hash); free(inventory);
}
struct ownership_view {
  struct case_account_record record;
  HANDLE files[6], token, job, launcher, owner, launcherToken, ownerToken, ownerJob, processes[32], tokens[32];
  unsigned count; BOOL installed, restored, released, creationVerified;
  char baseline[6][65];
  char imagePin[65], payloadPin[65], jobPin[65];
  DWORD creator; unsigned sources, sdkCount;
  struct { HANDLE file; char pin[65]; } pins[128];
};
static void ownership_census(struct ownership_view *view) {
  DWORD ids[65536], bytes; need(EnumProcesses(ids, sizeof(ids), &bytes) && bytes < sizeof(ids));
  for (unsigned i = 0; i < bytes/sizeof(DWORD); i++) {
    if (!ids[i] || ids[i] == 4 || ids[i] == GetCurrentProcessId()) continue;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, ids[i]), token;
    if (!process) { need(GetLastError() == ERROR_INVALID_PARAMETER); continue; }
    if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) { CloseHandle(process); continue; }
    need(OpenProcessToken(process, TOKEN_QUERY, &token)); wchar_t *sid = token_sid(token);
    if (!wcscmp(sid, view->record.accountSid)) {
      BOOL found = FALSE; FILETIME created, ended, kernel, user; need(GetProcessTimes(process, &created, &ended, &kernel, &user));
      for (unsigned j = 0; j < view->count; j++) if (GetProcessId(view->processes[j]) == ids[i]) {
        FILETIME held, unused; need(GetProcessTimes(view->processes[j], &held, &unused, &kernel, &user) && !memcmp(&held, &created, sizeof(held))); found = TRUE; }
      need(found); /* Inaccessible, unknown or reused members retain exclusion. */
    }
    LocalFree(sid); need(CloseHandle(token) && CloseHandle(process));
  }
}
static void ownership_witness(HANDLE input) {
  need(system_process(GetCurrentProcess())); require_build(); need(CreateThread(NULL, 0, expire, NULL, 0, NULL)); privilege(SE_DEBUG_NAME); privilege(SE_SECURITY_NAME);
  struct ownership_view view; DWORD read; unsigned received = 0; while (received < sizeof(view)) { need(ReadFile(input, (BYTE *)&view+received, sizeof(view)-received, &read, NULL) && read); received += read; }
  need(view.count <= 32 && view.sources <= 128 && view.sources > 0 && view.sdkCount > 0 && CloseHandle(input));
  for (unsigned i = 0; i < view.sources; i++) { struct held_file file = {0}; file.handle = view.pins[i].file; BY_HANDLE_FILE_INFORMATION info; need(GetFileInformationByHandle(file.handle, &info) && info.nNumberOfLinks == 1); file.links = 1; pin(&file, view.pins[i].pin); }
  need(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "InitializeProcThreadAttributeList") && GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "CreateProcessAsUserW"));
  need(ImpersonateLoggedOnUser(view.token)); SetLastError(0); HANDLE creator = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, view.creator); DWORD error = GetLastError();
  need(!creator && error == ERROR_ACCESS_DENIED && RevertToSelf());
  case_record = view.record; strcpy_s(nonce, 33, case_record.nonce);
  struct case_account_record record = {0}; wchar_t custody[4096]; DWORD length = GetFinalPathNameByHandleW(view.files[1], custody, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  need(length > 4 && length < 4096); account_record(custody+4, &record); need(!memcmp(&record, &view.record, sizeof(record)));
  wchar_t name[21]; need(swprintf_s(name, 21, L"np_%.16hs", record.nonce) > 0); account_check(name, record.accountSid);
  ownership_census(&view);
  for (unsigned i = 0; i < 6; i++) { entries[i+1].file.handle = view.files[i]; need(GetFileInformationByHandleEx(view.files[i], FileIdInfo, &entries[i+1].file.id, sizeof(FILE_ID_INFO)));
    if (view.installed) ownership_acl(i, FALSE, TRUE); else { char hash[65]; security(view.files[i], SE_FILE_OBJECT, TRUE, hash);
      if (view.restored) {
        HANDLE file = ReOpenFile(view.files[i], READ_CONTROL | FILE_READ_ATTRIBUTES | ACCESS_SYSTEM_SECURITY,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS); FILE_ID_INFO id;
        need(file != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) && !memcmp(&id, &entries[i+1].file.id, sizeof(id)));
        PSECURITY_DESCRIPTOR sd = file_sd(file, SE_FILE_OBJECT); sum((BYTE *)sd, GetSecurityDescriptorLength(sd), hash);
        need(!strcmp(hash, view.baseline[i])); LocalFree(sd); need(CloseHandle(file)); } } }
  if (view.installed) ownership_network(FALSE, TRUE);
  if (view.restored) ownership_network_absent();
  BOOL launcherSignaled = !view.launcher || WaitForSingleObject(view.launcher, 0) == WAIT_OBJECT_0,
    ownerSignaled = !view.owner || WaitForSingleObject(view.owner, 0) == WAIT_OBJECT_0, ownerJobEmpty = !view.ownerJob;
  if (view.launcher && !launcherSignaled) need(system_process(view.launcher));
  if (view.owner && !ownerSignaled) need(system_process(view.owner));
  if (view.ownerJob) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    need(QueryInformationJobObject(view.ownerJob, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL)); ownerJobEmpty = !accounting.ActiveProcesses; }
  BOOL jobAbsent = !view.job; unsigned jobHolders = 0; char jobPin[65]; if (view.job) { ownership_job_pin(view.job, jobPin); need(!strcmp(jobPin, view.jobPin));
    struct verify_handles *inventory = handle_inventory(); void *object = NULL;
    for (ULONG_PTR i = 0; i < inventory->count; i++) if (inventory->entries[i].pid == GetCurrentProcessId() && inventory->entries[i].handle == (ULONG_PTR)view.job) object = inventory->entries[i].object;
    need(object); for (ULONG_PTR i = 0; i < inventory->count; i++) if (inventory->entries[i].object == object) {
      need(inventory->entries[i].pid == GetCurrentProcessId() || inventory->entries[i].pid == view.creator || (view.launcher && inventory->entries[i].pid == GetProcessId(view.launcher)) || (view.owner && inventory->entries[i].pid == GetProcessId(view.owner))); jobHolders++; } free(inventory);
  }
  else { wchar_t name[96]; need(swprintf_s(name, 96, L"Local\\NativeProof-%hs", nonce) > 0); HANDLE job = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, name); need(!job && GetLastError() == ERROR_FILE_NOT_FOUND); }
  printf("{\"verifier\":"); identity(GetCurrentProcess());
  printf(",\"helpers\":["); if (view.launcher) { printf("{\"role\":\"launcher\",\"identity\":"); retained_identity(view.launcher, view.launcherToken, 0); printf("}"); }
  if (view.owner) { printf("%s{\"role\":\"custodian\",\"identity\":", view.launcher ? "," : ""); retained_identity(view.owner, view.ownerToken, 0); printf("}"); }
  printf("],\"ownerSignaled\":%s,\"ownerJobEmpty\":%s", ownerSignaled ? "true" : "false", ownerJobEmpty ? "true" : "false");
  printf(",\"accountSid\":\"%ls\",\"restrictingSid\":\"%ls\",\"contextSha256\":\"%s\",\"jobObjectSha256\":\"%s\",\"jobAbsent\":%s,\"jobHolders\":%u,\"job\":",
    record.accountSid, record.restrictingSid, record.context, view.jobPin, jobAbsent ? "true" : "false", jobHolders);
  if (view.job) job_read(view.job); else printf("null");
  printf(",\"enumeration\":{\"complete\":true,\"accountSid\":\"%ls\",\"accountReservationVerified\":true,\"capacity\":33,\"truncated\":false,\"processes\":[", record.accountSid);
  for (unsigned i = 0; i < view.count; i++) {
    if (i) putchar(','); BOOL belongs = FALSE; if (view.job) need(IsProcessInJob(view.processes[i], view.job, &belongs) && belongs);
    TOKEN_DEFAULT_DACL *creation = token_info(view.tokens[i], TokenDefaultDacl); ACCESS_ALLOWED_ACE *ace; BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
    need(creation->DefaultDacl && IsValidAcl(creation->DefaultDacl) && creation->DefaultDacl->AceCount == 1 &&
      CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) && GetAce(creation->DefaultDacl, 0, (void **)&ace) &&
      ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags && ace->Mask == GENERIC_ALL && EqualSid(&ace->SidStart, system)); free(creation);
    if (WaitForSingleObject(view.processes[i], 0) != WAIT_OBJECT_0) {
      HANDLE current; need(OpenProcessToken(view.processes[i], TOKEN_QUERY, &current)); TOKEN_STATISTICS *held = token_info(view.tokens[i], TokenStatistics), *actual = token_info(current, TokenStatistics);
      need(!memcmp(&held->TokenId, &actual->TokenId, sizeof(LUID)) && !memcmp(&held->ModifiedId, &actual->ModifiedId, sizeof(LUID)) && CloseHandle(current)); free(held); free(actual);
    }
    if (i == 0) { char hash[65]; security(view.processes[i], SE_KERNEL_OBJECT, TRUE, hash); }
    printf("{\"identity\":"); retained_identity(view.processes[i], view.tokens[i], 0);
    printf(",\"heldProcessVerified\":true,\"signaled\":%s,\"inJob\":%s,\"jobObjectSha256\":\"%s\"}", WaitForSingleObject(view.processes[i], 0) == WAIT_OBJECT_0 ? "true" : "false", belongs ? "true" : "false", view.jobPin);
  }
  printf("]},\"accountToken\":"); effective_token_handle(view.token); printf(",\"tokens\":["); for (unsigned i = 0; i < view.count; i++) { if (i) putchar(','); effective_token_handle(view.tokens[i]); } printf("],\"objects\":[");
  for (unsigned i = 0; i < 6; i++) { FILE_ID_INFO id; char text[128], hash[65]; need(GetFileInformationByHandleEx(view.files[i], FileIdInfo, &id, sizeof(id)));
    /* JS hashes the canonical held file identity string, exactly as provisioning. */
    struct held_file file = {0}; file.handle = view.files[i]; file.id = id;
    need(sprintf_s(text, sizeof(text), "%016llx:", id.VolumeSerialNumber) > 0);
    size_t used = strlen(text); for (unsigned j = 0; j < 16; j++) need(sprintf_s(text+used+j*2, sizeof(text)-used-j*2, "%02x", id.FileId.Identifier[j]) == 2);
    char quoted[140]; need(sprintf_s(quoted, sizeof(quoted), "\"%s\"", text) > 0); sum((BYTE *)quoted, (DWORD)strlen(quoted), hash);
    printf("%s{\"identitySha256\":\"%s\",\"mask\":%lu}", i ? "," : "", hash, ownership_masks[i]);
  }
  BOOL payloadSignaled = view.count && WaitForSingleObject(view.processes[0], 0) == WAIT_OBJECT_0, suspended = FALSE; DWORD exit = 0;
  if (view.count && !payloadSignaled && !view.released) {
    HANDLE threads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); need(threads != INVALID_HANDLE_VALUE); THREADENTRY32 thread = {sizeof(thread)}; unsigned matched = 0;
    need(Thread32First(threads, &thread)); do { if (thread.th32OwnerProcessID == GetProcessId(view.processes[0])) {
      HANDLE handle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread.th32ThreadID); typedef NTSTATUS (NTAPI *query)(HANDLE, ULONG, PVOID, ULONG, PULONG);
      query get = (query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"); ULONG count;
      need(handle && get && !get(handle, 35, &count, sizeof(count), NULL) && count == 1 && CloseHandle(handle)); matched++; }
    } while (Thread32Next(threads, &thread)); need(GetLastError() == ERROR_NO_MORE_FILES && matched == 1 && CloseHandle(threads)); suspended = TRUE;
  }
  { struct held_file file = {0}; file.handle = view.files[5]; file.links = 1; pin(&file, view.payloadPin); }
  if (view.count) need(GetExitCodeProcess(view.processes[0], &exit));
  printf("],\"policyVerified\":%s,\"policyRestored\":%s,\"payloadSuspended\":%s,\"payloadSignaled\":%s,\"exitCode\":%lu,\"payloadImageSha256\":\"%s\",\"cwdIdentity\":\"", view.installed ? "true" : "false", view.restored ? "true" : "false", suspended ? "true" : "false", payloadSignaled ? "true" : "false", exit, view.payloadPin);
  struct held_file cwd = {0}; cwd.handle = view.files[3]; need(GetFileInformationByHandleEx(cwd.handle, FileIdInfo, &cwd.id, sizeof(cwd.id))); file_id(&cwd);
  if (view.count && !payloadSignaled) {
    wchar_t path[4096], expected[4096]; DWORD size = 4096; need(QueryFullProcessImageNameW(view.processes[0], 0, path, &size));
    DWORD actual = GetFinalPathNameByHandleW(view.files[5], expected, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS); need(actual > 4 && actual < 4096 && !_wcsicmp(path, expected+4));
    typedef NTSTATUS (NTAPI *query)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG); query get = (query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION info; void *params; UNICODE_STRING current; need(get && !get(view.processes[0], ProcessBasicInformation, &info, sizeof(info), NULL));
    remote(view.processes[0], (BYTE *)info.PebBaseAddress+0x20, &params, sizeof(params)); remote(view.processes[0], (BYTE *)params+0x38, &current, sizeof(current));
    need(current.Length && current.Length < sizeof(path)); remote(view.processes[0], current.Buffer, path, current.Length); path[current.Length/2] = 0;
    actual = GetFinalPathNameByHandleW(view.files[3], expected, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS); need(actual > 4 && actual < 4096 && !_wcsicmp(path, expected+4));
  }
  BOOL explicitHandles = TRUE;
  if (suspended) {
    struct verify_handles *inventory = handle_inventory(); unsigned count = 0;
    for (ULONG_PTR i = 0; i < inventory->count; i++) if (inventory->entries[i].pid == GetProcessId(view.processes[0])) {
      HANDLE handle; need(DuplicateHandle(view.processes[0], (HANDLE)inventory->entries[i].handle, GetCurrentProcess(), &handle, 0, FALSE, DUPLICATE_SAME_ACCESS));
      char hash[65]; need(GetFileType(handle) == FILE_TYPE_PIPE); security(handle, SE_FILE_OBJECT, TRUE, hash); need(CloseHandle(handle)); count++; }
    free(inventory); need(count == 2); ownership_creation_verified = TRUE;
  }
  printf("\",\"explicitHandles\":%s,\"creationTimeJob\":%s,\"launcherSignaled\":%s,\"sourceVerified\":true,\"sdkExportsVerified\":true,\"creatorAccessDenied\":true,\"noForeignHandles\":true,\"imageSha256\":\"%s\",\"settled\":true}\n",
    explicitHandles ? "true" : "false", suspended || view.creationVerified ? "true" : "false", launcherSignaled ? "true" : "false", view.imagePin);
  need(fflush(stdout) == 0);
}
static void ownership_fresh(BOOL outsideControl) {
  struct ownership_view view = {0}; view.record = case_record; view.count = ownership_count; view.installed = ownership_policy_installed;
  view.restored = ownership_policy_restored; memcpy(view.baseline, ownership_baseline, sizeof(view.baseline));
  view.released = ownership_released; view.creationVerified = ownership_creation_verified;
  for (unsigned i = 0; i < 6; i++) view.files[i] = entries[i+1].file.handle;
  view.creator = GetCurrentProcessId();
  for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].kind, "data") || !strcmp(entries[i].kind, "sdk")) {
    if (!entries[i].file.handle) entries[i].file = hold(entries[i].path, FALSE, strcmp(entries[i].kind, "sdk") != 0, GENERIC_READ);
    pin(&entries[i].file, entries[i].pin); view.pins[view.sources].file = entries[i].file.handle; strcpy_s(view.pins[view.sources++].pin, 65, entries[i].pin);
    if (!strcmp(entries[i].kind, "sdk")) { char hash[65]; stock_security(entries[i].file.handle, hash); view.sdkCount++; }
  }
  view.token = case_token; view.job = case_job; view.launcher = ownership_launcher.hProcess; view.owner = ownership_owner.hProcess;
  view.launcherToken = ownership_launcher_token; view.ownerToken = ownership_owner_token; view.ownerJob = ownership_owner_job;
  memcpy(view.processes, ownership_processes, sizeof(view.processes)); memcpy(view.tokens, ownership_tokens, sizeof(view.tokens));
  strcpy_s(view.payloadPin, 65, entries[6].pin); if (case_job) ownership_job_pin(case_job, ownership_last_job_pin); strcpy_s(view.jobPin, 65, ownership_last_job_pin);
  unsigned image = count; wchar_t self[4096]; DWORD size = GetModuleFileNameW(NULL, self, 4096); need(size && size < 4096);
  for (unsigned i = 0; i < count; i++) if (!wcscmp(entries[i].path, self) && !strcmp(entries[i].kind, "helper")) image = i;
  need(image < count); if (!entries[image].file.handle) entries[image].file = hold(entries[image].path, FALSE, TRUE, GENERIC_READ);
  pin(&entries[image].file, entries[image].pin); char sig[65]; signature(&entries[image].file, entries[image].signature, sig); strcpy_s(view.imagePin, 65, entries[image].pin);
  HANDLE inherited[208], parentIn, parentOut; unsigned n = 0;
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, TRUE), private = attributes(sd, FALSE);
  need(CreatePipe(&inherited[n++], &parentIn, &sa, 0) && CreatePipe(&parentOut, &inherited[n++], &sa, 0) && SetHandleInformation(parentIn, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(parentOut, HANDLE_FLAG_INHERIT, 0));
  HANDLE *handles[] = {&view.files[0], &view.files[1], &view.files[2], &view.files[3], &view.files[4], &view.files[5], &view.token, &view.job, &view.launcher, &view.owner, &view.launcherToken, &view.ownerToken, &view.ownerJob};
  for (unsigned i = 0; i < sizeof(handles)/sizeof(handles[0]); i++) if (*handles[i]) { need(DuplicateHandle(GetCurrentProcess(), *handles[i], GetCurrentProcess(), &inherited[n], 0, TRUE, DUPLICATE_SAME_ACCESS)); *handles[i] = inherited[n++]; }
  for (unsigned i = 0; i < view.count; i++) for (unsigned j = 0; j < 2; j++) { HANDLE *value = j ? &view.tokens[i] : &view.processes[i];
    need(DuplicateHandle(GetCurrentProcess(), *value, GetCurrentProcess(), &inherited[n], 0, TRUE, DUPLICATE_SAME_ACCESS)); *value = inherited[n++]; }
  for (unsigned i = 0; i < view.sources; i++) { need(n < 208 && DuplicateHandle(GetCurrentProcess(), view.pins[i].file, GetCurrentProcess(), &inherited[n], 0, TRUE, DUPLICATE_SAME_ACCESS)); view.pins[i].file = inherited[n++]; }
  HANDLE job = CreateJobObjectW(&private, NULL); need(job); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0}; limits.BasicLimitInformation.LimitFlags = 0x2008; limits.BasicLimitInformation.ActiveProcessLimit = 1;
  need(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)));
  SIZE_T bytes = 0; InitializeProcThreadAttributeList(NULL, 2, 0, &bytes); STARTUPINFOEXW start = {0}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = calloc(1, bytes);
  need(start.lpAttributeList && InitializeProcThreadAttributeList(start.lpAttributeList, 2, 0, &bytes) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, n*sizeof(HANDLE), NULL, NULL) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof(job), NULL, NULL));
  start.StartupInfo.dwFlags = STARTF_USESTDHANDLES; start.StartupInfo.hStdInput = inherited[0]; start.StartupInfo.hStdOutput = start.StartupInfo.hStdError = inherited[1];
  wchar_t command[8192]; need(swprintf_s(command, 8192, L"\"%ls\" --ownership-witness %llu", self, (ULONGLONG)(ULONG_PTR)inherited[0]) > 0);
  PROCESS_INFORMATION child; need(CreateProcessW(self, command, &private, &private, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | (outsideControl ? CREATE_BREAKAWAY_FROM_JOB : 0), NULL, NULL, &start.StartupInfo, &child));
  for (unsigned i = 0; i < n; i++) need(CloseHandle(inherited[i])); DeleteProcThreadAttributeList(start.lpAttributeList); free(start.lpAttributeList); LocalFree(sd);
  DWORD written; need(system_process(child.hProcess) && ResumeThread(child.hThread) == 1 && WriteFile(parentIn, &view, sizeof(view), &written, NULL) && written == sizeof(view) && CloseHandle(parentIn));
  char result[65536]; line(parentOut, result, sizeof(result)); need(WaitForSingleObject(child.hProcess, 30000) == WAIT_OBJECT_0); DWORD exit; JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
  need(GetExitCodeProcess(child.hProcess, &exit) && !exit && QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL) && !accounting.ActiveProcesses);
  BYTE extra; DWORD used; need(!ReadFile(parentOut, &extra, 1, &used, NULL) && GetLastError() == ERROR_BROKEN_PIPE && !used);
  if (outsideControl) { BOOL belongs; need(case_job && IsProcessInJob(child.hProcess, case_job, &belongs) && !belongs); }
  need(CloseHandle(parentOut) && CloseHandle(child.hProcess) && CloseHandle(child.hThread) && CloseHandle(job));
  if (ownership_count && !ownership_released) ownership_creation_verified = TRUE;
  if (outsideControl) printf("{\"ready\":true,\"reachable\":true}"); else printf("%s", result);
}
static void ownership_send(const char *value) {
  need(ownership_control); size_t size = strlen(value); BYTE bytes[256]; need(size && size%2 == 0 && size <= sizeof(bytes)*2);
  for (size_t i = 0; i < size/2; i++) bytes[i] = (BYTE)(nibble(value[i*2])*16+nibble(value[i*2+1])); DWORD used;

  if (bytes[0] == 'P') { need(size == 2 && ownership_stage == 1); ownership_stage = 2; }
  else if (bytes[0] == 'C') { need(size == 132 && ownership_stage == 3 && ownership_policy_installed); ownership_stage = 4; }
  else if (bytes[0] == 'R') { need(size == 2 && ownership_stage == 5 && ownership_creation_verified && ownership_policy_installed &&
    ownership_owner.hProcess && WaitForSingleObject(ownership_owner.hProcess, 0) == WAIT_TIMEOUT); ownership_stage = 6; }
  else need(size == 2 && ownership_stage == 6 && (bytes[0] == 'G' || bytes[0] == 'E' || bytes[0] == 'A' || bytes[0] == 'Q'));
  need(WriteFile(ownership_control, bytes, (DWORD)size/2, &used, NULL) && used == size/2); if (size == 2 && bytes[0] == 'G' && ownership_spoofed) {
    char pid[32]; int count = sprintf_s(pid, sizeof(pid), "%lu\n", GetCurrentProcessId()); need(count > 0 && WriteFile(ownership_control, pid, count, &used, NULL) && used == (DWORD)count);
  }
  if (size == 2 && bytes[0] == 'E') need(ownership_count && WaitForSingleObject(ownership_processes[0], 30000) == WAIT_OBJECT_0);
  if (size == 2 && bytes[0] == 'R') { need(ownership_creation_verified); ownership_released = TRUE; }
}

/* A separate sealed System custodian holds the domain and creator objects.
 * Losing this owner and losing the launcher are distinct native faults. */
static HANDLE ownership_guard_job, ownership_guard_creator;
static DWORD WINAPI ownership_guard_deadline(void *unused) {
  (void)unused; Sleep(120000); TerminateJobObject(ownership_guard_job, 124); TerminateProcess(ownership_guard_creator, 124); ExitProcess(124); return 0;
}
static void ownership_guardian(HANDLE job, HANDLE creator) {
  need(system_process(GetCurrentProcess())); require_build(); char hash[65]; security(job, SE_KERNEL_OBJECT, TRUE, hash); security(creator, SE_KERNEL_OBJECT, TRUE, hash);
  ownership_guard_job = job; ownership_guard_creator = creator; need(CreateThread(NULL, 0, ownership_guard_deadline, NULL, 0, NULL));
  printf("{\"owner\":"); identity(GetCurrentProcess()); printf("}\n"); need(fflush(stdout) == 0);
  char byte; DWORD used; BOOL released = ReadFile(GetStdHandle(STD_INPUT_HANDLE), &byte, 1, &used, NULL) && used == 1 && byte == 'C';
  if (!released) { need(TerminateJobObject(job, 126)); if (WaitForSingleObject(creator, 0) != WAIT_OBJECT_0) need(TerminateProcess(creator, 126)); }
  need(CloseHandle(job) && CloseHandle(creator));
}
static void ownership_start_owner(void) {
  wchar_t self[4096], command[8192]; DWORD length = GetModuleFileNameW(NULL, self, 4096); need(length && length < 4096);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, TRUE), private = attributes(sd, FALSE);
  HANDLE inherited[4]; need(CreatePipe(&inherited[0], &ownership_owner_input, &sa, 0) && CreatePipe(&ownership_owner_output, &inherited[1], &sa, 0) &&
    SetHandleInformation(ownership_owner_input, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(ownership_owner_output, HANDLE_FLAG_INHERIT, 0) &&
    DuplicateHandle(GetCurrentProcess(), case_job, GetCurrentProcess(), &inherited[2], 0, TRUE, DUPLICATE_SAME_ACCESS) &&
    DuplicateHandle(GetCurrentProcess(), ownership_launcher.hProcess, GetCurrentProcess(), &inherited[3], 0, TRUE, DUPLICATE_SAME_ACCESS));
  ownership_owner_job = CreateJobObjectW(&private, NULL); need(ownership_owner_job); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0}; limits.BasicLimitInformation.LimitFlags = 0x2008; limits.BasicLimitInformation.ActiveProcessLimit = 1;
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui = {255}; need(SetInformationJobObject(ownership_owner_job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) && SetInformationJobObject(ownership_owner_job, JobObjectBasicUIRestrictions, &ui, sizeof(ui)));
  SIZE_T size = 0; InitializeProcThreadAttributeList(NULL, 2, 0, &size); STARTUPINFOEXW start = {0}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = calloc(1, size);
  need(start.lpAttributeList && InitializeProcThreadAttributeList(start.lpAttributeList, 2, 0, &size) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), NULL, NULL) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &ownership_owner_job, sizeof(HANDLE), NULL, NULL));
  start.StartupInfo.dwFlags = STARTF_USESTDHANDLES; start.StartupInfo.hStdInput = inherited[0]; start.StartupInfo.hStdOutput = start.StartupInfo.hStdError = inherited[1];
  need(swprintf_s(command, 8192, L"\"%ls\" --ownership-owner %llu %llu", self, (ULONGLONG)(ULONG_PTR)inherited[2], (ULONGLONG)(ULONG_PTR)inherited[3]) > 0);
  need(CreateProcessW(self, command, &private, &private, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &start.StartupInfo, &ownership_owner));
  for (unsigned i = 0; i < 4; i++) need(CloseHandle(inherited[i])); DeleteProcThreadAttributeList(start.lpAttributeList); free(start.lpAttributeList); LocalFree(sd);
  need(system_process(ownership_owner.hProcess) && OpenProcessToken(ownership_owner.hProcess, TOKEN_QUERY, &ownership_owner_token) && ResumeThread(ownership_owner.hThread) == 1);
  char frame[4096]; line(ownership_owner_output, frame, sizeof(frame));
}
static void ownership_close_owner(void) {
  if (WaitForSingleObject(ownership_owner.hProcess, 0) != WAIT_OBJECT_0) { DWORD used; need(ownership_owner_input && WriteFile(ownership_owner_input, "C", 1, &used, NULL) && used == 1); }
  need(WaitForSingleObject(ownership_owner.hProcess, 30000) == WAIT_OBJECT_0); JOBOBJECT_BASIC_ACCOUNTING_INFORMATION job;
  need(QueryInformationJobObject(ownership_owner_job, JobObjectBasicAccountingInformation, &job, sizeof(job), NULL) && !job.ActiveProcesses);
}
static void ownership_launch(char **values, unsigned n) {
  need(case_token && case_job && !ownership_launcher.hProcess && !helpers[0].process && !helpers[1].process && n >= 4);
  unsigned argc = bounded_number(values[2], 64); need(n == argc+3 && argc >= 2); wchar_t command[32767] = L"", temp[4096];
  quoted(command, 32767, entries[5].path); need(swprintf_s(temp, 4096, L"%hs", nonce) > 0); quoted(command, 32767, temp); quoted(command, 32767, case_record.restrictingSid);
  quoted(command, 32767, entries[2].path); quoted(command, 32767, entries[3].path); quoted(command, 32767, entries[4].path); quoted(command, 32767, entries[6].path);
  need(swprintf_s(temp, 4096, L"%hs", entries[6].pin) > 0); quoted(command, 32767, temp);
  need(swprintf_s(temp, 4096, L"%ls\\policy", entries[2].path) > 0); quoted(command, 32767, temp); quoted(command, 32767, L"pending");
  wchar_t first[4096]; if (!strcmp(values[3], "-")) first[0] = 0; else decode(values[3], first);
  BOOL literal = wcscmp(first, L"detached") && wcscmp(first, L"reparent") && wcscmp(first, L"nested-job") && wcscmp(first, L"breakaway") && wcscmp(first, L"spoofed-parent") && wcscmp(first, L"wmi") && wcscmp(first, L"com") && wcscmp(first, L"service") && wcscmp(first, L"process-limit") && wcscmp(first, L"cancel") && wcscmp(first, L"owner-loss") && wcscmp(first, L"helper-loss") && wcscmp(first, L"last-handle-close") && wcscmp(first, L"admission-interruption") && wcscmp(first, L"receipt-before") && wcscmp(first, L"receipt-after") && wcscmp(first, L"stale-identity");
  ownership_literal = literal; ownership_spoofed = !wcscmp(first, L"spoofed-parent");
  const wchar_t *corpus[] = {L"", L"space value", L"\x03bb\x96ea\xd83d\xde00", L"'\"", L"$(false); & | < > *", L"trailing\\", L"backslash\\\"quote"};
  need(literal ? argc == sizeof(corpus)/sizeof(corpus[0]) : argc == 2);
  quoted(command, 32767, literal ? L"--ownership-literal" : L"--ownership");
  for (unsigned i = 0; i < argc; i++) { if (!strcmp(values[i+3], "-")) temp[0] = 0; else decode(values[i+3], temp);
    if (literal) need(!wcscmp(temp, corpus[i])); else if (i == 1) { need(wcslen(temp) == 32); for (unsigned j = 0; j < 32; j++) need(temp[j] == nonce[j]); }
    quoted(command, 32767, temp); }
  char sig[65]; pin(&entries[5].file, entries[5].pin); signature(&entries[5].file, entries[5].signature, sig);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, TRUE), private = attributes(sd, FALSE);
  HANDLE inherited[3]; need(CreatePipe(&inherited[0], &ownership_control, &sa, 0) && CreatePipe(&ownership_frames, &inherited[1], &sa, 0) && CreatePipe(&ownership_output, &inherited[2], &sa, 0));
  need(SetHandleInformation(ownership_control, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(ownership_frames, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(ownership_output, HANDLE_FLAG_INHERIT, 0));
  /* The sealed System creator has separate process custody. Giving it an
   * ancestor Job would nest the UI-restricted payload Job. Its held process,
   * protected control EOF and finite source fence creation independently. */
  SIZE_T bytes = 0; InitializeProcThreadAttributeList(NULL, 1, 0, &bytes); STARTUPINFOEXW start = {0}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = calloc(1, bytes);
  need(start.lpAttributeList && InitializeProcThreadAttributeList(start.lpAttributeList, 1, 0, &bytes) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), NULL, NULL));
  start.StartupInfo.dwFlags = STARTF_USESTDHANDLES; start.StartupInfo.hStdInput = inherited[0]; start.StartupInfo.hStdOutput = inherited[1]; start.StartupInfo.hStdError = inherited[2];
  need(CreateProcessW(entries[5].path, command, &private, &private, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, entries[2].path, &start.StartupInfo, &ownership_launcher));
  for (unsigned i = 0; i < 3; i++) need(CloseHandle(inherited[i])); DeleteProcThreadAttributeList(start.lpAttributeList); free(start.lpAttributeList); LocalFree(sd);
  need(system_process(ownership_launcher.hProcess) && OpenProcessToken(ownership_launcher.hProcess, TOKEN_QUERY, &ownership_launcher_token) && ResumeThread(ownership_launcher.hThread) == 1); ownership_start_owner(); printf("{\"helper\":"); retained_identity(ownership_launcher.hProcess, ownership_launcher_token, 0); printf(",\"owner\":"); retained_identity(ownership_owner.hProcess, ownership_owner_token, 0); printf("}");
}
static void ownership_outside_control(const wchar_t *mode) {
  need(system_process(GetCurrentProcess()));
  if (!wcscmp(mode, L"service")) { SC_HANDLE handle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE); need(handle && CloseServiceHandle(handle)); }
  else if (!wcscmp(mode, L"spoofed-parent")) { HANDLE handle = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, GetProcessId(ownership_launcher.hProcess)); need(handle && CloseHandle(handle)); }
  else if (!wcscmp(mode, L"wmi")) {
    IWbemLocator *locator; IWbemServices *services; BSTR space = SysAllocString(L"ROOT\\CIMV2"); need(space &&
      SUCCEEDED(CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&locator)) &&
      SUCCEEDED(IWbemLocator_ConnectServer(locator, space, NULL, NULL, NULL, 0, NULL, NULL, &services)));
    IWbemServices_Release(services); IWbemLocator_Release(locator); SysFreeString(space);
  } else if (!wcscmp(mode, L"com")) { ITaskService *service; VARIANT empty; VariantInit(&empty);
    need(SUCCEEDED(CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service)) && SUCCEEDED(ITaskService_Connect(service, empty, empty, empty, empty))); ITaskService_Release(service);
  } else if (!wcscmp(mode, L"breakaway")) {
    /* A separately admitted System witness proves CreateProcess availability
     * with explicit creation-time Job admission outside the restricted Job. */
    ownership_fresh(TRUE); return;
  } else need(FALSE);
  printf("{\"ready\":true,\"reachable\":true}");
}
static void ownership_stop(void) {
  if (ownership_control) { need(CloseHandle(ownership_control)); ownership_control = NULL; }
  if (ownership_launcher.hProcess) need(WaitForSingleObject(ownership_launcher.hProcess, 30000) == WAIT_OBJECT_0);
  ownership_close_owner();
  if (case_job) { need(TerminateJobObject(case_job, 126) && CloseHandle(case_job)); case_job = NULL; }
  for (unsigned i = 0; i < ownership_count; i++) need(WaitForSingleObject(ownership_processes[i], 30000) == WAIT_OBJECT_0);
  HANDLE pipes[] = {ownership_frames, ownership_output, ownership_owner_output};
  for (unsigned i = 0; i < 3; i++) { BYTE data[4096]; DWORD used, total = 0;
    while (ReadFile(pipes[i], data, sizeof(data), &used, NULL) && used) { total += used; need(total <= 65536); }
    need(GetLastError() == ERROR_BROKEN_PIPE); }
  printf("{\"creationSealed\":true,\"helpersSettled\":true}");
}

static void verification(char **values, unsigned n) {
    if (!strcmp(values[0]+7, "case")) { need(n == 6); verify_case(bounded_number(values[2], 127), bounded_number(values[3], count-1), values[4], values[5]);
    } else if (!strcmp(values[0]+7, "case-retired")) { need(n == 4); verify_case_retired(bounded_number(values[2], count-1), values[3]);
    } else if (!strcmp(values[0]+7, "subjects")) {
      need(n == 2); printf("{\"identities\":[");
      for (unsigned i = 0; i < process_count; i++) { if (i) putchar(','); retained_identity(processes[i], tokens[i], sessions[i]); }
      printf("],\"jobs\":[");
      for (unsigned i = 0; i < job_count; i++) printf("%s%u", i ? "," : "", i);
      printf("]}");
    } else if (!strcmp(values[0]+7, "file")) {
      need(n == 6); wchar_t name[4096]; decode(values[2], name); verification_path(name, values[3], values[4]); DWORD maximum = bounded_number(values[5], 134217728); need(maximum && verification_file_count < 128); BOOL stock = stock_entry(name, values[3]), bridge = bridge_entry(name, values[3]); struct held_file file = hold(name, FALSE, !(stock || bridge), GENERIC_READ);
      LARGE_INTEGER length; need(GetFileSizeEx(file.handle, &length) && length.QuadPart > 0 && length.QuadPart <= maximum); pin(&file, values[3]); char dacl[65], sig[65]; if (stock) stock_security(file.handle, dacl); else if (bridge) bridge_security(file.handle, dacl); else security(file.handle, SE_FILE_OBJECT, TRUE, dacl);
      printf("{\"identity\":\""); file_id(&file); printf("\",\"sha256\":\"%s\",\"daclSha256\":\"%s\",\"signatureSha256\":", values[3], dacl);
      if (!strcmp(values[4], "-")) printf("null"); else { signature(&file, values[4], sig); printf("\"%s\"", sig); }
      printf(",\"slot\":%u,\"bytes\":%llu}", verification_file_count, (ULONGLONG)length.QuadPart); verification_files[verification_file_count++] = file;
    } else if (!strcmp(values[0]+7, "sharing")) {
      need(n == 3); wchar_t name[4096]; decode(values[2], name);
      BOOL admitted = FALSE; for (unsigned i = 0; i < count; i++) { size_t prefix = wcslen(entries[i].path);
        if (!_wcsicmp(name, entries[i].path) || (!strcmp(entries[i].kind, "directory") && !_wcsnicmp(name, entries[i].path, prefix) && name[prefix] == '\\')) admitted = TRUE;
      } need(admitted);
      HANDLE handle = CreateFileW(name, DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
      FILE_ATTRIBUTE_TAG_INFO tag; FILE_ID_INFO id;
      need(handle != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) &&
        !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id)));
      printf("{\"identity\":\"%016llx:", id.VolumeSerialNumber); hex(id.FileId.Identifier, 16); printf("\"}"); need(CloseHandle(handle));
    } else if (!strcmp(values[0]+7, "retain")) {
      need(n == 4); DWORD pid = bounded_number(values[2], MAXDWORD); need(pid); unsigned index = process_count;
      for (unsigned i = 0; i < process_count; i++) if (GetProcessId(processes[i]) == pid) { index = i; break; }
      if (index == process_count) index = retain_process(pid);
      FILETIME created, exited, kernel, user; need(GetProcessTimes(processes[index], &created, &exited, &kernel, &user) &&
        (((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime) == number(values[3]));
      printf("{\"slot\":%u,\"process\":", index); process_read(index); putchar('}');
    } else if (!strcmp(values[0]+7, "process")) { need(n == 3); process_read(bounded_number(values[2], 127));
    } else if (!strcmp(values[0]+7, "compiler-policy")) { need(n == 4); compiler_policy(bounded_number(values[2], 127), bounded_number(values[3], 127));
    } else if (!strcmp(values[0]+7, "image")) {
      need(n == 5); unsigned index = bounded_number(values[2], 127); need(index < process_count); wchar_t name[4096]; DWORD size = 4096;
      need(QueryFullProcessImageNameW(processes[index], 0, name, &size) && size && size < 4096);
      verification_path(name, values[3], values[4]);
      BOOL stock = stock_entry(name, values[3]), bridge = bridge_entry(name, values[3]); need(verification_file_count < 128); struct held_file file = hold(name, FALSE, !(stock || bridge), GENERIC_READ); pin(&file, values[3]); char sig[65], dacl[65]; if (stock) stock_security(file.handle, dacl); else if (bridge) bridge_security(file.handle, dacl); signature(&file, values[4], sig);
      printf("{\"sha256\":\"%s\",\"signatureSha256\":\"%s\",\"pathHex\":\"", values[3], sig); hex((BYTE *)name, wcslen(name)*2); printf("\"}"); verification_files[verification_file_count++] = file;
    } else if (!strcmp(values[0]+7, "task")) { need(n == 4); wchar_t name[64]; decode_bounded(values[3], name, 64); verifier_task(values[2], name, NULL, 0);
    } else if (!strcmp(values[0]+7, "transfer")) { need(n == 4); verifier_transfer(bounded_number(values[2], 127), bounded_number(values[3], 127));
    } else if (!strcmp(values[0]+7, "job")) { need(n == 3); unsigned index = bounded_number(values[2], 127); need(index < process_count);
      if (verified_jobs[index]) job_read(verified_jobs[index]); else printf("{\"absent\":true}");
    } else if (!strcmp(values[0]+7, "read")) {
      need(n == 5); unsigned index = bounded_number(values[2], 127); DWORD offset = bounded_number(values[3], 8388608), size = bounded_number(values[4], 32768); need(index < verification_file_count && size && offset <= 8388608-size);
      struct held_file *file = &verification_files[index]; FILE_ID_INFO before, after; LARGE_INTEGER length, position; position.QuadPart = offset;
      need(GetFileInformationByHandleEx(file->handle, FileIdInfo, &before, sizeof(before)) && !memcmp(&before, &file->id, sizeof(before)) &&
        GetFileSizeEx(file->handle, &length) && length.QuadPart > 0 && length.QuadPart <= 8388608 && offset <= length.QuadPart && size <= length.QuadPart-offset && SetFilePointerEx(file->handle, position, NULL, FILE_BEGIN));
      BYTE bytes[32768]; DWORD used = 0; while (used < size) { DWORD read; need(ReadFile(file->handle, bytes+used, size-used, &read, NULL) && read); used += read; }
      need(GetFileInformationByHandleEx(file->handle, FileIdInfo, &after, sizeof(after)) && !memcmp(&before, &after, sizeof(after)));
      printf("{\"hex\":\""); hex(bytes, size); printf("\"}");
    } else if (!strcmp(values[0]+7, "task-remove")) {
      need(n == 6); wchar_t name[64]; decode_bounded(values[3], name, 64); verifier_task(values[2], name, values[4], bounded_number(values[5], 31));
    } else if (!strcmp(values[0]+7, "job-open")) {
      need(n == 3 && job_count < 32); wchar_t name[96]; decode_bounded(values[2], name, 96); need(!wcsncmp(name, L"Local\\NativeProof-", 18) && wcslen(name) == 50 && wcsspn(name+18, L"0123456789abcdef") == 32);
      HANDLE job = OpenJobObjectW(JOB_OBJECT_QUERY | READ_CONTROL, FALSE, name); need(job); wcscpy_s(verification_job_names[job_count], 96, name); jobs[job_count] = job; printf("{\"slot\":%u,\"observation\":", job_count++); job_read(job); putchar('}');
    } else if (!strcmp(values[0]+7, "job-read")) { need(n == 4); unsigned index = bounded_number(values[2], 127); wchar_t name[96]; decode_bounded(values[3], name, 96); need(index < job_count && !wcscmp(name, verification_job_names[index])); job_read(jobs[index]);
    } else need(FALSE);

}
/* This lane is a System file custodian and independent observer, never a
 * compiler/payload owner. A single upload/read slot bounds private memory. */
static struct held_file preparation_read;
static struct held_file preparation_root;
static BYTE *preparation_bytes;
static DWORD preparation_size, preparation_written;
static char preparation_pin[65];
static HANDLE preparation_writer;
static wchar_t preparation_file[4096];
static wchar_t (*preparation_names)[260];
static unsigned preparation_name_count, preparation_name_offset;
static void preparation_command(char **v, unsigned n) {
  need(preparation_only);
  if (!strcmp(v[0], "prepare-list")) {
    need(n == 3); unsigned offset = bounded_number(v[2], 65536);
    if (!offset) {
      need(!preparation_names); preparation_names = calloc(65536, sizeof(*preparation_names)); need(preparation_names); preparation_name_count = preparation_name_offset = 0;
      wchar_t pattern[4096]; need(swprintf_s(pattern, 4096, L"%ls\\windows-*.json", preparation_directory) > 0);
      WIN32_FIND_DATAW data; HANDLE search = FindFirstFileW(pattern, &data);
      if (search == INVALID_HANDLE_VALUE) need(GetLastError() == ERROR_FILE_NOT_FOUND);
      else {
        do { need(preparation_name_count < 65536 && !(data.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
          wcsspn(data.cFileName, L"abcdefghijklmnopqrstuvwxyz0123456789-.") == wcslen(data.cFileName));
          wcscpy_s(preparation_names[preparation_name_count++], 260, data.cFileName);
        } while (FindNextFileW(search, &data));
        need(GetLastError() == ERROR_NO_MORE_FILES && FindClose(search));
      }
    }
    need(preparation_names && offset == preparation_name_offset && offset <= preparation_name_count);
    unsigned end = min(offset+128, preparation_name_count); printf("{\"names\":[");
    for (unsigned i = offset; i < end; i++) { if (i > offset) putchar(','); putchar('"'); hex((BYTE *)preparation_names[i], wcslen(preparation_names[i])*2); putchar('"'); }
    printf("],\"complete\":%s}", end == preparation_name_count ? "true" : "false"); preparation_name_offset = end;
    if (end == preparation_name_count) { free(preparation_names); preparation_names = NULL; }
  } else if (!strcmp(v[0], "prepare-directory")) {
    need(n == 4); wchar_t name[4096]; decode(v[2], name); BOOL build = !wcscmp(name, preparation_output);
    need(!wcscmp(name, preparation_directory) || build);
    if (number(v[3])) {
      need(build); DWORD existing = GetFileAttributesW(name);
      if (existing == INVALID_FILE_ATTRIBUTES) {
        need(GetLastError() == ERROR_FILE_NOT_FOUND); PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
        need(CreateDirectoryW(name, &sa)); LocalFree(sd);
      }
    }
    struct held_file file = hold(name, TRUE, TRUE, FILE_LIST_DIRECTORY); char dacl[65]; security(file.handle, SE_FILE_OBJECT, TRUE, dacl);
    printf("{\"identity\":\""); file_id(&file); printf("\",\"daclSha256\":\"%s\",\"protectedParents\":true}", dacl); close_file(&file);
  } else if (!strcmp(v[0], "prepare-read")) {
    need(n == 6 && !preparation_read.handle && !preparation_bytes && !preparation_writer); wchar_t name[4096]; decode(v[2], name);
    BOOL snapshot = number(v[5]) == 1; need(number(v[5]) <= 1); DWORD maximum = bounded_number(v[4], 134217728); need(maximum);
    if (snapshot) {
      need(!wcsncmp(name, preparation_output, wcslen(preparation_output)) && name[wcslen(preparation_output)] == '\\');
      const wchar_t *leaf = wcsrchr(name, '\\')+1; BOOL found = FALSE;
      for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].kind, "helper") && !wcscmp(leaf, wcsrchr(entries[i].path, '\\')+1)) found = TRUE;
      need(found && strlen(v[3]) == 64);
    } else if (strcmp(v[3], "-")) {
      BOOL admitted = !wcscmp(name, preparation_plan) && !strcmp(v[3], preparation_plan_pin);
      for (unsigned i = 0; i < count; i++) if (!wcscmp(entries[i].path, name) && !strcmp(entries[i].pin, v[3])) admitted = TRUE;
      size_t prefix = wcslen(preparation_directory); if (!wcsncmp(name, preparation_directory, prefix) && name[prefix] == '\\') admitted = TRUE;
      need(admitted);
    }
    else { need(!wcsncmp(name, preparation_directory, wcslen(preparation_directory)) && name[wcslen(preparation_directory)] == '\\'); }
    BOOL stock = !snapshot && stock_entry(name, v[3]), bridge = !snapshot && bridge_entry(name, v[3]); preparation_read = hold(name, FALSE, !(stock || bridge), GENERIC_READ); preparation_bytes = read_file(&preparation_read, maximum, &preparation_size);
    char hash[65], dacl[65]; sum(preparation_bytes, preparation_size, hash); need(!strcmp(v[3], "-") || !strcmp(v[3], hash));
    if (stock) stock_security(preparation_read.handle, dacl); else if (bridge) bridge_security(preparation_read.handle, dacl); else security(preparation_read.handle, SE_FILE_OBJECT, TRUE, dacl);
    printf("{\"identity\":\""); file_id(&preparation_read); printf("\",\"daclSha256\":\"%s\",\"protectedParents\":true,\"sha256\":\"%s\",\"bytes\":%lu,\"slot\":0}", dacl, hash, preparation_size);
  } else if (!strcmp(v[0], "prepare-bytes")) {
    need(n == 5 && !number(v[2]) && preparation_bytes); DWORD offset = bounded_number(v[3], 134217728), size = bounded_number(v[4], 32768);
    need(size && offset <= preparation_size && size <= preparation_size-offset); printf("{\"hex\":\""); hex(preparation_bytes+offset, size); printf("\"}");
  } else if (!strcmp(v[0], "prepare-release")) {
    need(n == 3 && !number(v[2]) && preparation_bytes); close_file(&preparation_read); memset(&preparation_read, 0, sizeof(preparation_read));
    SecureZeroMemory(preparation_bytes, preparation_size); free(preparation_bytes); preparation_bytes = NULL; printf("{\"closed\":true}");
  } else if (!strcmp(v[0], "prepare-write")) {
    need(n == 5 && !preparation_writer && !preparation_bytes); wchar_t leaf[4096]; decode(v[2], leaf);
    need(!wcsncmp(leaf, L"windows-", 8) && wcslen(leaf) > 13 && !wcscmp(leaf+wcslen(leaf)-5, L".json") && !wcschr(leaf, '\\') && !wcschr(leaf, '/') && !wcschr(leaf, ':'));
    preparation_size = bounded_number(v[3], 1048576); need(preparation_size && strlen(v[4]) == 64); strcpy_s(preparation_pin, 65, v[4]); preparation_written = 0;
    need(swprintf_s(preparation_file, 4096, L"%ls\\%ls", preparation_directory, leaf) > 0);
    PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
    preparation_writer = CreateFileW(preparation_file, GENERIC_WRITE | READ_CONTROL, 0, &sa, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL); LocalFree(sd);
    need(preparation_writer != INVALID_HANDLE_VALUE); char dacl[65]; security(preparation_writer, SE_FILE_OBJECT, TRUE, dacl); printf("{\"created\":true}");
  } else if (!strcmp(v[0], "prepare-chunk")) {
    need(n == 4 && preparation_writer && number(v[2]) == preparation_written); size_t size = strlen(v[3]); need(size && !(size%2) && size <= 65536 && size/2 <= preparation_size-preparation_written);
    BYTE bytes[32768]; for (unsigned i = 0; i < size/2; i++) bytes[i] = (BYTE)(nibble(v[3][i*2])*16+nibble(v[3][i*2+1])); DWORD used;
    need(WriteFile(preparation_writer, bytes, (DWORD)size/2, &used, NULL) && used == size/2); preparation_written += used; SecureZeroMemory(bytes, sizeof(bytes)); printf("{\"written\":%lu}", used);
  } else if (!strcmp(v[0], "prepare-seal")) {
    need(n == 2 && preparation_writer && preparation_written == preparation_size && FlushFileBuffers(preparation_writer) && CloseHandle(preparation_writer)); preparation_writer = NULL;
    struct held_file file = hold(preparation_file, FALSE, TRUE, GENERIC_READ); pin(&file, preparation_pin); close_file(&file);
    printf("{\"sha256\":\"%s\",\"writerClosed\":true}", preparation_pin);
  } else need(FALSE);
}
int wmain(int argc, wchar_t **argv) {
  if (argc == 3 && !wcscmp(argv[1], L"--ownership-witness")) {
    wchar_t *end; ULONGLONG input = _wcstoui64(argv[2], &end, 10); need(input && !*end && _setmode(_fileno(stdout), _O_BINARY) != -1);
    ownership_witness((HANDLE)(ULONG_PTR)input); return 0;
  }
  if (argc == 4 && !wcscmp(argv[1], L"--ownership-owner")) {
    wchar_t *a, *b; ULONGLONG job = _wcstoui64(argv[2], &a, 10), creator = _wcstoui64(argv[3], &b, 10);
    need(job && creator && !*a && !*b && _setmode(_fileno(stdout), _O_BINARY) != -1); ownership_guardian((HANDLE)(ULONG_PTR)job, (HANDLE)(ULONG_PTR)creator); return 0;
  }
  preparation_only = argc == 10 && !wcscmp(argv[1], L"--observe");
  need((preparation_only || (argc == 8 && !wcscmp(argv[1], L"--serve"))) && system_process(GetCurrentProcess()));
  runner_sid = argv[6];
  if (preparation_only) { wcscpy_s(preparation_directory, 4096, argv[8]); wcscpy_s(preparation_output, 4096, argv[9]); wcscpy_s(preparation_plan, 4096, argv[2]); }
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
  plan(argv[2], hash);
  if (preparation_only) {
    BOOL output = FALSE; for (unsigned i = 0; i < count; i++) if (!strcmp(entries[i].kind, "directory") && !wcscmp(entries[i].path, preparation_output)) output = TRUE;
    need(output); preparation_root = hold(preparation_directory, TRUE, TRUE, FILE_LIST_DIRECTORY);
    strcpy_s(preparation_plan_pin, 65, hash); for (unsigned i = 0; i < 32; i++) nonce[i] = (char)argv[4][i];
  }
  else for (unsigned i = 0; i < 32; i++) need(nonce[i] == argv[4][i]);
  printf("{\"candidateSha\":\"%s\",\"nonce\":\"%s\",\"entries\":%u}\n", candidate, nonce, count); fflush(stdout);
  for (unsigned operations = 0; operations < 32768; operations++) {
    line(control, input, sizeof(input)); if (preparation_only) preparation_journal(input, sequence+1); char *values[520], *state; unsigned n = 0;
    for (char *value = strtok_s(input, " ", &state); value; value = strtok_s(NULL, " ", &state)) { need(n < 520); values[n++] = value; }
    need(n >= 2 && number(values[1]) == ++sequence);
    need(!preparation_only || !strncmp(values[0], "verify-", 7) || !strncmp(values[0], "prepare-", 8) || !strcmp(values[0], "finish"));
    helper_lane = 0;
    if (n >= 3 && !strcmp(values[0], "helper-start")) helper_lane = !strcmp(values[2], "observer") ? 1 : 0;
    else if (!strncmp(values[0], "helper-", 7)) { need(n >= 3); helper_lane = bounded_number(values[2], 1); }
    printf("{\"sequence\":%u,\"value\":", sequence);
    if (!strncmp(values[0], "prepare-", 8)) { preparation_command(values, n);
    } else if (!strncmp(values[0], "verify-", 7)) { verification(values, n);
    } else if (!strcmp(values[0], "case-directory")) { need(n == 4 && !preparation_only); case_directory(bounded_number(values[2], count-1), bounded_number(values[3], count-1));
    } else if (!strcmp(values[0], "case-copy")) { need(n == 5 && !preparation_only); case_copy(bounded_number(values[2], count-1), bounded_number(values[3], count-1), bounded_number(values[4], count-1));
    } else if (!strcmp(values[0], "case-account")) { need(n == 4 && !preparation_only); case_account_create(bounded_number(values[2], count-1), values[3]);
    } else if (!strcmp(values[0], "case-endpoint")) { need(n == 5 && !preparation_only); need(!strcmp(values[2], "v4") || !strcmp(values[2], "v6")); need(!strcmp(values[3], "tcp") || !strcmp(values[3], "udp")); case_endpoint(!strcmp(values[2], "v6"), !strcmp(values[3], "udp"), bounded_number(values[4], 65535));
    } else if (!strcmp(values[0], "case-read")) { need(n == 2 && !preparation_only); case_read();

    } else if (!strcmp(values[0], "ownership-launch")) { need(!preparation_only); ownership_launch(values, n);
    } else if (!strcmp(values[0], "ownership-control") || !strcmp(values[0], "ownership-output")) {
      need(n == 2 && ownership_launcher.hProcess); char bytes[16384]; line(!strcmp(values[0], "ownership-control") ? ownership_frames : ownership_output, bytes, sizeof(bytes));
      if (!strcmp(values[0], "ownership-control")) {
        need(strstr(bytes, nonce));
        if (strstr(bytes, "\"phase\":\"helper\"")) { need(ownership_stage == 0); ownership_stage = 1; }
        else if (strstr(bytes, "\"phase\":\"setup\"")) { need(ownership_stage == 2); ownership_stage = 3; }
        else { need(strstr(bytes, "\"phase\":\"ready\"") && ownership_stage == 4); ownership_stage = 5; }
      }
      if (!strcmp(values[0], "ownership-output") && ownership_literal) need(ownership_count && WaitForSingleObject(ownership_processes[0], 30000) == WAIT_OBJECT_0);
      printf("{\"hex\":\""); hex((BYTE *)bytes, strlen(bytes));
      if (!strcmp(values[0], "ownership-output")) hex((BYTE *)"\n", 1);
      printf("\"}");
    } else if (!strcmp(values[0], "ownership-send")) { need(n == 3); ownership_send(values[2]); printf("{\"sent\":true}");
    } else if (!strcmp(values[0], "ownership-retain")) { need(n == 4); ownership_retain(bounded_number(values[2], MAXDWORD), number(values[3])); printf("{\"retained\":true}");

    } else if (!strcmp(values[0], "ownership-reconstruct")) {
      need(n == 2 && case_token && ownership_launcher.hProcess); static char jobPin[65];
      if (case_job) {
        ownership_job_pin(case_job, jobPin); BYTE bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)+32*sizeof(ULONG_PTR)]; JOBOBJECT_BASIC_PROCESS_ID_LIST *members = (void *)bytes;
        need(QueryInformationJobObject(case_job, JobObjectBasicProcessIdList, members, sizeof(bytes), NULL) && members->NumberOfAssignedProcesses == members->NumberOfProcessIdsInList && members->NumberOfProcessIdsInList <= 32);
        for (unsigned i = 0; i < members->NumberOfProcessIdsInList; i++) {
          HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)members->ProcessIdList[i]); FILETIME created, ended, kernel, user;
          need(process && GetProcessTimes(process, &created, &ended, &kernel, &user)); ownership_retain(GetProcessId(process), ((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime); need(CloseHandle(process));
        }
      } else strcpy_s(jobPin, 65, ownership_last_job_pin);
      printf("{\"helper\":"); retained_identity(ownership_launcher.hProcess, ownership_launcher_token, 0); printf(",\"jobObjectSha256\":\"%s\",\"members\":[", jobPin);
      for (unsigned i = 0; i < ownership_count; i++) { if (i) putchar(','); retained_identity(ownership_processes[i], ownership_tokens[i], 0); } printf("]}");
    } else if (!strcmp(values[0], "ownership-witness")) { need(n == 2 && case_token); ownership_fresh(FALSE);
    } else if (!strcmp(values[0], "ownership-receipt")) {
      need((n == 4 || n == 5) && case_token && bounded_number(values[2], 4095) < 4096 && strlen(values[3]) == 64 && strspn(values[3], "0123456789abcdef") == 64);
      wchar_t leaf[96]; need(swprintf_s(leaf, 96, L"ownership-%hs.json", values[2]) > 0);
      if (n == 5) { size_t size = strlen(values[4]); need(size && !(size%2) && size <= 32768); BYTE data[16384];
        for (size_t i = 0; i < size/2; i++) data[i] = (BYTE)(nibble(values[4][i*2])*16+nibble(values[4][i*2+1]));
        char hash[65]; sum(data, (DWORD)size/2, hash); need(!strcmp(hash, values[3])); HANDLE file = account_file(entries[case_custody].path, leaf, GENERIC_WRITE, CREATE_NEW); DWORD used;
        need(WriteFile(file, data, (DWORD)size/2, &used, NULL) && used == size/2 && FlushFileBuffers(file) && CloseHandle(file)); }
      HANDLE file = account_file(entries[case_custody].path, leaf, GENERIC_READ, OPEN_EXISTING); BYTE data[16384]; DWORD used; LARGE_INTEGER size;
      need(GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= sizeof(data) && ReadFile(file, data, (DWORD)size.QuadPart, &used, NULL) && used == size.QuadPart);
      char hash[65]; sum(data, used, hash); need(!strcmp(hash, values[3]) && CloseHandle(file)); printf("{\"hex\":\""); hex(data, used); printf("\"}");
    } else if (!strcmp(values[0], "ownership-policy")) {
      need(n == 3 && case_token && case_job && ownership_stage == 3 && !ownership_released && !ownership_policy_installed);
      size_t size = strlen(values[2]); BYTE data[16384]; need(size && !(size%2) && size <= sizeof(data)*2);
      for (size_t i = 0; i < size/2; i++) data[i] = (BYTE)(nibble(values[2][i*2])*16+nibble(values[2][i*2+1]));
      HANDLE file = account_file(entries[case_custody].path, L"policy", GENERIC_WRITE, CREATE_NEW); DWORD used;
      need(WriteFile(file, data, (DWORD)size/2, &used, NULL) && used == size/2 && FlushFileBuffers(file) && CloseHandle(file));
      wchar_t name[4096]; need(swprintf_s(name, 4096, L"%ls\\policy", entries[case_custody].path) > 0); ownership_policy_file = hold(name, FALSE, TRUE, GENERIC_READ);
      ownership_network(FALSE, FALSE); for (unsigned i = 0; i < 6; i++) ownership_acl(i, FALSE, FALSE); ownership_policy_installed = TRUE; printf("{\"installed\":true}");
    } else if (!strcmp(values[0], "ownership-outside")) {
      need(n == 2 && case_token); struct case_account_record record = {0}; account_record(entries[case_custody].path, &record); need(!memcmp(&record, &case_record, sizeof(record)));
      if (!ownership_sentinel.handle) {
        need(!ownership_launcher.hProcess); wchar_t leaf[128], name[4096]; need(swprintf_s(leaf, 128, L"outside-%hs.sentinel", record.context) > 0);
        HANDLE file = account_file(entries[0].path, leaf, GENERIC_WRITE, CREATE_NEW); DWORD used;
        need(WriteFile(file, record.context, 64, &used, NULL) && used == 64 && FlushFileBuffers(file) && CloseHandle(file));
        need(swprintf_s(name, 4096, L"%ls\\%ls", entries[0].path, leaf) > 0); ownership_sentinel = hold(name, FALSE, TRUE, GENERIC_READ);
      }
      char sentinelHash[65]; DWORD sentinelSize; BYTE *sentinel = read_file(&ownership_sentinel, 64, &sentinelSize); need(sentinelSize == 64); sum(sentinel, sentinelSize, sentinelHash); free(sentinel);
      char hash[65]; sum((BYTE *)&record, sizeof(record), hash); printf("{\"record\":\"%s\",\"sentinel\":{\"identity\":\"", hash); file_id(&ownership_sentinel); printf("\",\"sha256\":\"%s\"},\"objects\":[", sentinelHash);
      for (unsigned i = 1; i <= 6; i++) { if (i > 1) putchar(','); putchar('"'); file_id(&entries[i].file); putchar('"'); }
      printf("],\"assets\":["); for (unsigned i = 5; i <= 6; i++) { pin(&entries[i].file, entries[i].pin); printf("%s\"%s\"", i == 6 ? "," : "", entries[i].pin); } printf("]}");
    } else if (!strcmp(values[0], "ownership-outside-control")) { need(n == 3); wchar_t mode[64]; decode_bounded(values[2], mode, 64); ownership_outside_control(mode);
    } else if (!strcmp(values[0], "ownership-stale")) {
      need(n == 4 && ownership_count && bounded_number(values[2], MAXDWORD) == GetProcessId(ownership_processes[0])); FILETIME started, ended, kernel, user;
      need(GetProcessTimes(ownership_processes[0], &started, &ended, &kernel, &user) && (((ULONGLONG)started.dwHighDateTime<<32)|started.dwLowDateTime) != number(values[3]));
      printf("{\"rejected\":true,\"current\":"); retained_identity(ownership_processes[0], ownership_tokens[0], 0); printf("}");
    } else if (!strcmp(values[0], "ownership-arm")) {
      need(n == 3 && ownership_launcher.hProcess); wchar_t mode[64]; decode_bounded(values[2], mode, 64);
      BOOL early = !wcscmp(mode, L"admission-interruption") || !wcscmp(mode, L"receipt-before") || !wcscmp(mode, L"receipt-after");
      BOOL exited = ownership_count && WaitForSingleObject(ownership_processes[0], 0) == WAIT_OBJECT_0;
      if (!early && !exited) { ownership_send("41"); char bytes[16384]; line(ownership_output, bytes, sizeof(bytes));
        need(strstr(bytes, "\"phase\":\"armed\"") && strstr(bytes, nonce)); }
      if (!wcscmp(mode, L"last-handle-close")) {
        struct verify_handles *inventory = handle_inventory(); void *object = NULL;
        for (ULONG_PTR i = 0; i < inventory->count; i++) if (inventory->entries[i].pid == GetCurrentProcessId() && inventory->entries[i].handle == (ULONG_PTR)case_job) object = inventory->entries[i].object;
        need(object); for (ULONG_PTR i = 0; i < inventory->count; i++) if (inventory->entries[i].object == object)
          need(inventory->entries[i].pid == GetCurrentProcessId() || inventory->entries[i].pid == GetProcessId(ownership_launcher.hProcess) || inventory->entries[i].pid == GetProcessId(ownership_owner.hProcess)); free(inventory);
        ownership_close_owner();
        ownership_send("51"); char bytes[4096]; line(ownership_frames, bytes, sizeof(bytes)); need(strstr(bytes, "\"phase\":\"job-closed\"") && strstr(bytes, nonce));
        need(CloseHandle(case_job)); case_job = NULL;
        for (unsigned i = 0; i < ownership_count; i++) need(WaitForSingleObject(ownership_processes[i], 30000) == WAIT_OBJECT_0);
      }
      printf("{\"armed\":true,\"fixtureAcknowledged\":%s,\"holderInventoryComplete\":true}", early ? "false" : "true");
    } else if (!strcmp(values[0], "ownership-fire")) {
      need(n == 3 && ownership_launcher.hProcess); wchar_t mode[64]; decode_bounded(values[2], mode, 64);
      if (!wcscmp(mode, L"owner-loss")) { need(TerminateProcess(ownership_owner.hProcess, 126) && WaitForSingleObject(ownership_owner.hProcess, 30000) == WAIT_OBJECT_0); }
      else if (!wcscmp(mode, L"helper-loss")) need(TerminateProcess(ownership_launcher.hProcess, 126));
      else { need(ownership_control && CloseHandle(ownership_control)); ownership_control = NULL; }
      if (wcscmp(mode, L"owner-loss")) need(WaitForSingleObject(ownership_launcher.hProcess, 30000) == WAIT_OBJECT_0); printf("{\"acknowledged\":true}");
    } else if (!strcmp(values[0], "ownership-stop")) { need(n == 2); ownership_stop();
    } else if (!strcmp(values[0], "ownership-restore")) {
      need(n == 2 && !case_job && ownership_policy_installed); ownership_network(FALSE, TRUE);
      for (unsigned i = 0; i < 6; i++) ownership_acl(i, FALSE, TRUE);
      ownership_network(TRUE, FALSE); for (unsigned i = 0; i < 6; i++) { ownership_acl(i, TRUE, FALSE); LocalFree(ownership_before[i]); LocalFree(ownership_installed[i]); ownership_before[i] = ownership_installed[i] = NULL; }
      close_file(&ownership_policy_file); ownership_policy_installed = FALSE; ownership_policy_restored = TRUE; printf("{\"restored\":true}");
    } else if (!strcmp(values[0], "ownership-account-retire")) {
      need(n == 2 && !case_job && !ownership_policy_installed && ownership_policy_restored && case_token && ownership_launcher.hProcess && WaitForSingleObject(ownership_launcher.hProcess, 0) == WAIT_OBJECT_0);
      for (unsigned i = 0; i < ownership_count; i++) need(WaitForSingleObject(ownership_processes[i], 0) == WAIT_OBJECT_0 && CloseHandle(ownership_processes[i]) && CloseHandle(ownership_tokens[i])); ownership_count = 0;
      need(WaitForSingleObject(ownership_owner.hProcess, 0) == WAIT_OBJECT_0 && CloseHandle(ownership_owner.hProcess) && CloseHandle(ownership_owner.hThread) && CloseHandle(ownership_owner_token) && CloseHandle(ownership_owner_input) && CloseHandle(ownership_owner_output) && CloseHandle(ownership_owner_job)); ZeroMemory(&ownership_owner, sizeof(ownership_owner));
      need(CloseHandle(ownership_launcher_token) && CloseHandle(ownership_launcher.hProcess) && CloseHandle(ownership_launcher.hThread) && CloseHandle(ownership_frames) && CloseHandle(ownership_output)); ZeroMemory(&ownership_launcher, sizeof(ownership_launcher));
      need(CloseHandle(case_token)); case_token = NULL;
      wchar_t name[21]; need(swprintf_s(name, 21, L"np_%.16hs", case_record.nonce) > 0); account_check(name, case_record.accountSid);
      PSID sid; need(ConvertStringSidToSidW(case_record.accountSid, &sid)); LSA_OBJECT_ATTRIBUTES attributes = {0}; attributes.Length = sizeof(attributes); LSA_HANDLE policy;
      need(LsaOpenPolicy(NULL, &attributes, POLICY_LOOKUP_NAMES, &policy) == 0 && LsaRemoveAccountRights(policy, sid, TRUE, NULL, 0) == 0 && LsaClose(policy) == 0); LocalFree(sid);
      need(NetUserDel(NULL, name) == NERR_Success); printf("{\"retired\":true}");
    } else if (!strcmp(values[0], "case-retire")) { need(n == 2 && !preparation_only); case_retire();
    } else if (!strcmp(values[0], "open")) {
      need(n == 3); unsigned index = bounded_number(values[2], count-1); need(!entries[index].file.handle); struct entry *entry = &entries[index];
      /* Directory helpers mutate children, not the held root. DELETE access
       * would conflict with later ancestor reads that also deny share-delete. */
      BOOL directory = !strcmp(entry->kind, "directory"), stock = stock_entry(entry->path, entry->pin), bridge = bridge_entry(entry->path, entry->pin); entry->file = hold_shared(entry->path, directory, !(stock || bridge),
        (stock || bridge) ? GENERIC_READ : ACCESS_SYSTEM_SECURITY | (directory ? FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | WRITE_DAC | WRITE_OWNER : GENERIC_READ | WRITE_DAC | WRITE_OWNER), !strcmp(entry->kind, "mutable"));
      if (stock) { char dacl[65]; stock_security(entry->file.handle, dacl); }
      if (bridge) { char dacl[65]; bridge_security(entry->file.handle, dacl); }
      if (!directory) pin(&entry->file, entry->pin); if (!strcmp(entry->kind, "image") || !strcmp(entry->kind, "helper")) { char signatureSha[65]; signature(&entry->file, entry->signature, signatureSha); }
      inspect(entry);
    } else if (!strcmp(values[0], "inspect")) { need(n == 3); inspect(slot(values[2]));
    } else if (!strcmp(values[0], "read")) { need(n == 5); struct entry *entry = slot(values[2]); ULONGLONG offset = number(values[3]), size = number(values[4]);
      need(size > 0 && size <= 65536 && offset <= 536870912-size); LARGE_INTEGER at; at.QuadPart = offset; BYTE bytes[65536]; DWORD used;
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
      need(!preparation_writer && !preparation_bytes && !preparation_names && !case_token && !case_job && !case_socket_count && !ownership_launcher.hProcess && !ownership_policy_installed);
      need(n == 2 && !helpers[0].process && !helpers[1].process && !audit_owned); if (ownership_sentinel.handle) close_file(&ownership_sentinel); for (unsigned i = 0; i < process_count; i++) { need(WaitForSingleObject(processes[i], 0) == WAIT_OBJECT_0 && CloseHandle(tokens[i]) && CloseHandle(processes[i])); }
      for (unsigned i = 0; i < job_count; i++) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current; need(QueryInformationJobObject(jobs[i], JobObjectBasicAccountingInformation, &current, sizeof(current), NULL) && current.ActiveProcesses == 0 && CloseHandle(jobs[i])); }
      for (unsigned i = 0; i < verification_file_count; i++) close_file(&verification_files[i]);
      for (unsigned i = 0; i < 128; i++) if (verified_jobs[i]) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current; need(QueryInformationJobObject(verified_jobs[i], JobObjectBasicAccountingInformation, &current, sizeof(current), NULL) && !current.ActiveProcesses && CloseHandle(verified_jobs[i])); }
      for (unsigned i = 0; i < count; i++) if (entries[i].file.handle) close_file(&entries[i].file);
      for (unsigned i = 0; i < dependency_count; i++) { for (unsigned j = 0; j < dependency_sizes[i]; j++) close_file(&dependencies[i][j]); free(dependencies[i]); }
      for (unsigned i = 0; i < catalog_count; i++) close_file(&catalogs[i]);
      if (wfp_engine) need(FwpmEngineClose0(wfp_engine) == ERROR_SUCCESS);
      if (registry_key) need(RegCloseKey(registry_key) == ERROR_SUCCESS && CloseHandle(registry_changed));
      if (preparation_only) close_file(&preparation_root);
      CoUninitialize();
      printf("{\"closed\":true}}\n"); fflush(stdout); need(CloseHandle(control)); return 0;
    } else need(FALSE);
    printf("}\n"); need(fflush(stdout) == 0);
  }
  need(FALSE); return 126;
}
