/* One-shot LocalSystem/session-0 reader. A retained handle, never a PID/name,
 * owns every observation. The bridge and independent verifier gate admission. */
#define COBJMACROS
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include "custody.h"
#include "account.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#include <fcntl.h>
#include <io.h>
#include <taskschd.h>
#include <oleauto.h>
#include <stddef.h>
#include <tlhelp32.h>
#include <wbemidl.h>
#include <winioctl.h>
#include <winevt.h>
#pragma comment(lib, "wevtapi.lib")
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
/* Reviewed installed MSVC/SDK and native System32 DLL inputs keep their read ACLs. Only the
 * trusted installation authorities may own or mutate them; held reads still
 * deny write/delete sharing. Private build/source/receipt objects use System. */
static BOOL stock_entry(const wchar_t *name, const char *pin) {
  const wchar_t *msvc = L"\\Program Files\\Microsoft Visual Studio\\", *sdk = L"\\Program Files (x86)\\Windows Kits\\10\\";
  BOOL installed = wcslen(name) > 3 && name[1] == ':' && (!wcsncmp(name+2, msvc, wcslen(msvc)) || !wcsncmp(name+2, sdk, wcslen(sdk)));
  const wchar_t *leaf = wcsrchr(name, '\\'); need(leaf);
  wchar_t system[4096]; DWORD size = GetSystemDirectoryW(system, 4096);
  need(size > 0 && size < 4096);
  BOOL nativeDll = wcslen(name) > size + 1 && !_wcsnicmp(name, system, size) && name[size] == '\\' && leaf == name + size &&
    wcslen(leaf+1) > 4 && !_wcsicmp(leaf+wcslen(leaf)-4, L".dll");
  if (!installed && !nativeDll) return FALSE;
  for (unsigned i = 0; i < count; i++) if ((!strcmp(entries[i].kind, "image") || !strcmp(entries[i].kind, "sdk")) &&
    !wcscmp(entries[i].path, name) && !strcmp(entries[i].pin, pin) &&
    ((installed && (!strcmp(entries[i].kind, "sdk") || !wcscmp(leaf+1, L"cl.exe") || !wcscmp(leaf+1, L"rc.exe"))) ||
     (nativeDll && !strcmp(entries[i].kind, "image")))) return TRUE;
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
/* The fixed namespace makes possible helper/witness Jobs independently
 * discoverable after their creator and transfer handles have disappeared. */
static unsigned recovery_job_count;
static HANDLE recovery_job(SECURITY_ATTRIBUTES *attributes) {
  FILETIME birth, exit, kernel, user; need(GetProcessTimes(GetCurrentProcess(), &birth, &exit, &kernel, &user));
  ULONGLONG creation = ((ULONGLONG)birth.dwHighDateTime << 32) | birth.dwLowDateTime;
  wchar_t name[128]; need(recovery_job_count < 128 && strlen(nonce) == 32 &&
    swprintf_s(name, 128, L"Local\\NativeProof-Recovery-%hs-%lu-%llu-%u", nonce, GetCurrentProcessId(), creation, recovery_job_count++) > 0);
  SetLastError(0); HANDLE job = CreateJobObjectW(attributes, name);
  need(job && GetLastError() != ERROR_ALREADY_EXISTS); return job;
}
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
    HANDLE transfer = entry->file.handle;
    if (!file && !observer && !compiler && !git && !gitPolicy) {
      FILE_ID_INFO actual;
      transfer = ReOpenFile(entry->file.handle, GENERIC_READ | READ_CONTROL | WRITE_DAC | ACCESS_SYSTEM_SECURITY,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
      need(transfer != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(transfer, FileIdInfo, &actual, sizeof(actual)) && !memcmp(&actual, &entry->file.id, sizeof(actual)));
    }
    need(DuplicateHandle(GetCurrentProcess(), transfer, GetCurrentProcess(), &inherited[i+2], 0, TRUE, DUPLICATE_SAME_ACCESS));
    if (transfer != entry->file.handle) need(CloseHandle(transfer));
    unsigned argument = gitPolicy ? (i < 2 ? 3+i : 8+(i-2)*3) : first+i;
    need(swprintf_s(args[argument], 4096, L"%llu", (ULONGLONG)(ULONG_PTR)inherited[i+2]) > 0);
  }
  SECURITY_ATTRIBUTES private = attributes(sd, FALSE); helper_job = recovery_job(&private);
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
static void recovery_job_read(const wchar_t *name) {
  HANDLE job = OpenJobObjectW(JOB_OBJECT_QUERY | READ_CONTROL, FALSE, name);
  if (!job) { need(GetLastError() == ERROR_FILE_NOT_FOUND); printf("{\"absent\":true}"); return; }
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current;
  need(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &current, sizeof(current), NULL) && !current.ActiveProcesses);
  job_read(job); need(CloseHandle(job));
}
static void recovery_jobs(unsigned subject, const char *ownedNonce) {
  need(preparation_only && subject < process_count && strlen(ownedNonce) == 32 && strspn(ownedNonce, "0123456789abcdef") == 32);
  FILETIME birth, exit, kernel, user; need(GetProcessTimes(processes[subject], &birth, &exit, &kernel, &user));
  ULONGLONG creation = ((ULONGLONG)birth.dwHighDateTime << 32) | birth.dwLowDateTime;
  wchar_t name[128]; printf("{\"nonce\":\"%s\",\"identity\":", ownedNonce); retained_identity(processes[subject], tokens[subject], sessions[subject]); printf(",\"jobs\":[");
  for (unsigned i = 0; i < 128; i++) {
    need(swprintf_s(name, 128, L"Local\\NativeProof-Recovery-%hs-%lu-%llu-%u", ownedNonce, GetProcessId(processes[subject]), creation, i) > 0);
    if (i) putchar(','); recovery_job_read(name);
  }
  printf("],\"compilerJob\":");
  need(swprintf_s(name, 128, L"Local\\NativeProof-Compiler-%hs-%lu-%llu", ownedNonce, GetProcessId(processes[subject]), creation) > 0);
  recovery_job_read(name); putchar('}');
}
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
      need(!strcmp(kind, "prerequisite") || !strcmp(kind, "custody")); wchar_t ownedJob[96]; need(swprintf_s(ownedJob, 96, L"Local\\NativeProof-%ls", nonceText) > 0); BOOL heldJob = FALSE;
      for (unsigned i = 0; i < job_count; i++) if (!wcscmp(verification_job_names[i], ownedJob)) heldJob = TRUE;
      if (!strcmp(kind, "prerequisite")) need(heldJob);
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
  entries[target].file = hold(entries[target].path, FALSE, TRUE, GENERIC_READ | WRITE_DAC | ACCESS_SYSTEM_SECURITY); pin(&entries[target].file, entries[target].pin);
  if (strcmp(entries[target].signature, "-")) { char hash[65]; signature(&entries[target].file, entries[target].signature, hash); } inspect(&entries[target]);
}
/* Fixed private data files. Bytes and the mutable owned-file exception are
 * checked against the sealed plan before exclusive creation. */
static void case_file(unsigned index, unsigned parent, BOOL mutable, const char *hexBytes) {
  need(index < count && parent < count && !strcmp(entries[index].kind, mutable ? "mutable" : "data") &&
    !entries[index].file.handle && entries[parent].file.handle && !strcmp(entries[parent].kind, "directory"));
  wchar_t directory[4096]; wcscpy_s(directory, 4096, entries[index].path);
  wchar_t *leaf = wcsrchr(directory, '\\'); need(leaf); *leaf++ = 0;
  BOOL working = (!wcscmp(leaf,L"content.txt") || !wcscmp(leaf,L".git")) && parent==4;
  BOOL gitMutable = !wcscmp(leaf,L"index") || !wcscmp(leaf,L"proof") || working;
  need(!wcscmp(directory, entries[parent].path) && (!mutable || (!wcscmp(leaf, L"owned.txt") && parent == 4) ||
    working || (gitMutable && !wcsncmp(entries[index].path,entries[3].path,wcslen(entries[3].path)) && entries[index].path[wcslen(entries[3].path)]==L'\\')));
  size_t length = strlen(hexBytes); need(length && length % 2 == 0 && length <= 8192);
  BYTE bytes[4096]; for (size_t i = 0; i < length / 2; i++) bytes[i] = (BYTE)(nibble(hexBytes[i * 2]) * 16 + nibble(hexBytes[i * 2 + 1]));
  char hash[65]; sum(bytes, (DWORD)(length / 2), hash); need(!strcmp(hash, entries[index].pin));
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  HANDLE file = CreateFileW(entries[index].path, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL);
  LocalFree(sd); DWORD written;
  need(file != INVALID_HANDLE_VALUE && WriteFile(file, bytes, (DWORD)(length / 2), &written, NULL) && written == length / 2 &&
    FlushFileBuffers(file) && CloseHandle(file));
  entries[index].file = hold_shared(entries[index].path, FALSE, TRUE, GENERIC_READ | WRITE_DAC | ACCESS_SYSTEM_SECURITY, mutable);
  if(mutable && gitMutable) {
    HANDLE shared=ReOpenFile(entries[index].file.handle,GENERIC_READ | READ_CONTROL | WRITE_DAC | ACCESS_SYSTEM_SECURITY,7,FILE_FLAG_OPEN_REPARSE_POINT);
    FILE_ID_INFO id; need(shared!=INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(shared,FileIdInfo,&id,sizeof(id)) && !memcmp(&id,&entries[index].file.id,sizeof(id)) && CloseHandle(entries[index].file.handle)); entries[index].file.handle=shared;
  }
  pin(&entries[index].file, entries[index].pin); inspect(&entries[index]);
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
  need(ImpersonateLoggedOnUser(case_token));
  SOCKET socket = WSASocketW(v6 ? AF_INET6 : AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, udp ? IPPROTO_UDP : IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
  need(socket != INVALID_SOCKET); BOOL exclusive = TRUE; need(!setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&exclusive, sizeof(exclusive)));
  if (v6) { BOOL only = TRUE; need(!setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&only, sizeof(only))); struct sockaddr_in6 address = {0}; address.sin6_family = AF_INET6; address.sin6_port = htons((u_short)port); address.sin6_addr = in6addr_loopback; need(!bind(socket, (struct sockaddr *)&address, sizeof(address))); }
  else { struct sockaddr_in address = {0}; address.sin_family = AF_INET; address.sin_port = htons((u_short)port); address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); need(!bind(socket, (struct sockaddr *)&address, sizeof(address))); }
  need(RevertToSelf()); case_sockets[case_socket_count++] = socket; printf("{\"bound\":true}");
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
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION job; need(QueryInformationJobObject(case_job, JobObjectBasicAccountingInformation, &job, sizeof(job), NULL) && !job.ActiveProcesses);
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
static BOOL ownership_released, ownership_policy_installed, ownership_creation_verified, ownership_spoofed, access_mode;
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
  unsigned count; BOOL installed, restored, released, creationVerified, access;
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
    if (view.installed && !view.access) ownership_acl(i, FALSE, TRUE); else if (!view.access) { char hash[65]; security(view.files[i], SE_FILE_OBJECT, TRUE, hash);
      if (view.restored) {
        HANDLE file = ReOpenFile(view.files[i], READ_CONTROL | FILE_READ_ATTRIBUTES | ACCESS_SYSTEM_SECURITY,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS); FILE_ID_INFO id;
        need(file != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) && !memcmp(&id, &entries[i+1].file.id, sizeof(id)));
        PSECURITY_DESCRIPTOR sd = file_sd(file, SE_FILE_OBJECT); sum((BYTE *)sd, GetSecurityDescriptorLength(sd), hash);
        need(!strcmp(hash, view.baseline[i])); LocalFree(sd); need(CloseHandle(file)); } } }
  if (view.installed && !view.access) ownership_network(FALSE, TRUE);
  if (view.restored && !view.access) ownership_network_absent();
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
  view.released = ownership_released; view.creationVerified = ownership_creation_verified; view.access = access_mode;
  for (unsigned i = 0; i < 6; i++) view.files[i] = entries[i+1].file.handle;
  view.creator = GetCurrentProcessId();
  /* Mutable case bytes are independently observed effects, not immutable
   * source pins. Their approved initial digest is checked at case_file. */
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
  HANDLE job = recovery_job(&private); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0}; limits.BasicLimitInformation.LimitFlags = 0x2008; limits.BasicLimitInformation.ActiveProcessLimit = 1;
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
  need(ownership_control); size_t size = strlen(value); BYTE bytes[32768]; need(size && size%2 == 0 && size <= sizeof(bytes)*2 && (access_mode || size <= 512));
  for (size_t i = 0; i < size/2; i++) bytes[i] = (BYTE)(nibble(value[i*2])*16+nibble(value[i*2+1])); DWORD used;

  if (bytes[0] == 'P') { need(size == 2 && ownership_stage == 1); ownership_stage = 2; }
  else if (bytes[0] == 'C') { need(size == 132 && ownership_stage == 3 && ownership_policy_installed); ownership_stage = 4; }
  else if (bytes[0] == 'R') { need(size == 2 && ownership_stage == 5 && ownership_creation_verified && ownership_policy_installed &&
    ownership_owner.hProcess && WaitForSingleObject(ownership_owner.hProcess, 0) == WAIT_TIMEOUT); ownership_stage = 6; }
  else need(ownership_stage == 6 && (access_mode || (size == 2 && (bytes[0] == 'G' || bytes[0] == 'E' || bytes[0] == 'A' || bytes[0] == 'Q'))));
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
  ownership_owner_job = recovery_job(&private); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0}; limits.BasicLimitInformation.LimitFlags = 0x2008; limits.BasicLimitInformation.ActiveProcessLimit = 1;
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
  access_mode = argc == 2 && !wcscmp(first, L"suite");
  BOOL literal = !access_mode && wcscmp(first, L"detached") && wcscmp(first, L"reparent") && wcscmp(first, L"nested-job") && wcscmp(first, L"breakaway") && wcscmp(first, L"spoofed-parent") && wcscmp(first, L"wmi") && wcscmp(first, L"com") && wcscmp(first, L"service") && wcscmp(first, L"process-limit") && wcscmp(first, L"cancel") && wcscmp(first, L"owner-loss") && wcscmp(first, L"helper-loss") && wcscmp(first, L"last-handle-close") && wcscmp(first, L"admission-interruption") && wcscmp(first, L"receipt-before") && wcscmp(first, L"receipt-after") && wcscmp(first, L"stale-identity");
  ownership_literal = literal; ownership_spoofed = !wcscmp(first, L"spoofed-parent");
  const wchar_t *corpus[] = {L"", L"space value", L"\x03bb\x96ea\xd83d\xde00", L"'\"", L"$(false); & | < > *", L"trailing\\", L"backslash\\\"quote"};
  need(literal ? argc == sizeof(corpus)/sizeof(corpus[0]) : argc == 2);
  quoted(command, 32767, access_mode ? L"--access" : literal ? L"--ownership-literal" : L"--ownership");
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
static void access_quiesce(void);
static void ownership_stop(void) {
  if (ownership_control) { need(CloseHandle(ownership_control)); ownership_control = NULL; }
  if (ownership_launcher.hProcess) need(WaitForSingleObject(ownership_launcher.hProcess, 30000) == WAIT_OBJECT_0);
  ownership_close_owner();
  if (case_job) { need(TerminateJobObject(case_job, 126) && CloseHandle(case_job)); case_job = NULL; }
  for (unsigned i = 0; i < ownership_count; i++) need(WaitForSingleObject(ownership_processes[i], 30000) == WAIT_OBJECT_0);
  if (access_mode) access_quiesce();
  HANDLE pipes[] = {ownership_frames, ownership_output, ownership_owner_output};
  for (unsigned i = 0; i < 3; i++) { BYTE data[4096]; DWORD used, total = 0;
    while (ReadFile(pipes[i], data, sizeof(data), &used, NULL) && used) { total += used; need(total <= 65536); }
    need(GetLastError() == ERROR_BROKEN_PIPE); }
  printf("{\"creationSealed\":true,\"helpersSettled\":true}");
}

/* Access coverage is read by the independently admitted System verifier.
 * The serving reader exports handle numbers, never coverage conclusions. */
struct access_view {
  struct ownership_view domain;
  unsigned objectCount, indices[44], socketCount;
  HANDLE objects[44], sockets[8], payloadSockets[8];
  HANDLE observer, roots[2], payloadRoots[2];
  WSAPROTOCOL_INFOW socketInfo[8];
};
static unsigned access_object_count, access_indices[44];
static HANDLE access_payload_sockets[8];
static HANDLE access_payload_roots[2];
#define ACCESS_ROOT_MASK (FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
static void access_quiesce(void) {
  /* Case processes can close their duplicates while the System custodian still
   * holds the original lease. Detach TCP flows without replacing the reserved
   * socket object/port; later independent tables must show no active flow. */
  for (unsigned i=0;i<case_socket_count;i++) {
    SOCKET socket=case_sockets[i]; int type, size=sizeof(type); need(!getsockopt(socket,SOL_SOCKET,SO_TYPE,(char *)&type,&size));
    if (type!=SOCK_STREAM) continue;
    SOCKADDR_STORAGE peer; int length=sizeof(peer);
    if (getpeername(socket,(SOCKADDR *)&peer,&length)==SOCKET_ERROR) { need(WSAGetLastError()==WSAENOTCONN); continue; }
    SOCKADDR_STORAGE before, after; int beforeSize=sizeof(before), afterSize=sizeof(after);
    need(!getsockname(socket,(SOCKADDR *)&before,&beforeSize));
    GUID id=WSAID_DISCONNECTEX; LPFN_DISCONNECTEX disconnect=NULL; DWORD bytes;
    need(!WSAIoctl(socket,SIO_GET_EXTENSION_FUNCTION_POINTER,&id,sizeof(id),&disconnect,sizeof(disconnect),&bytes,NULL,NULL) &&
      bytes==sizeof(disconnect) && disconnect && disconnect(socket,NULL,0,0));
    need(getpeername(socket,(SOCKADDR *)&peer,&length)==SOCKET_ERROR && WSAGetLastError()==WSAENOTCONN &&
      !getsockname(socket,(SOCKADDR *)&after,&afterSize) && beforeSize==afterSize && !memcmp(&before,&after,beforeSize));
  }
}
static void access_inventory(char **values, unsigned n) {
  need(case_token && case_job && !ownership_launcher.hProcess && n >= 13 && n <= 46);
  access_object_count = n - 2; need(access_object_count >= 11 && access_object_count <= 44);
  for (unsigned i = 0; i < access_object_count; i++) {
    unsigned index = bounded_number(values[i + 2], count - 1);
    need(entries[index].file.handle);
    for (unsigned j = 0; j < i; j++) need(index != access_indices[j]);
    access_indices[i] = index;
  }
  need(access_indices[0] == 2 && access_indices[1] == 3 && access_indices[2] == 4);
  BOOL payload = FALSE; for (unsigned i = 10; i < access_object_count; i++) if (access_indices[i] == 6) payload = TRUE;
  need(payload);
  printf("{\"bound\":true}");
}
/* The serving custody retains baseline and deterministic desired descriptors
 * before invoking the one-shot policy writer. A lost reader retains exclusion;
 * reconstruction never treats missing final output as absence of effects. */
static PSECURITY_DESCRIPTOR access_before[44], access_wanted[44];
static BOOL access_policy_possible;
static void access_key(unsigned index, GUID *value) {
  char seed[128], hash[65]; BYTE bytes[16]; wchar_t text[37];
  need(sprintf_s(seed, sizeof(seed), "windows-policy:%s:%u", nonce, index) > 0); sum((BYTE *)seed, (DWORD)strlen(seed), hash);
  for (unsigned i = 0; i < 16; i++) bytes[i] = (BYTE)(nibble(hash[i * 2]) * 16 + nibble(hash[i * 2 + 1]));
  need(swprintf_s(text, 37, L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]) == 36);
  need(UuidFromStringW((RPC_WSTR)text, value) == RPC_S_OK);
}
static BOOL access_registry_present(void) {
  wchar_t name[256]; need(swprintf_s(name, 256, L"SOFTWARE\\NativeProof\\%hs", nonce) > 0); HKEY key;
  LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, name, 0, KEY_READ | KEY_WOW64_64KEY, &key);
  need(result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND); if (result == ERROR_SUCCESS) need(RegCloseKey(key) == ERROR_SUCCESS);
  return result == ERROR_SUCCESS;
}
static void access_registry_parent(void) {
  HKEY parent; char hash[65];
  need(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\NativeProof",0,READ_CONTROL | KEY_WOW64_64KEY,&parent)==ERROR_SUCCESS);
  security(parent,SE_REGISTRY_KEY,TRUE,hash); need(RegCloseKey(parent)==ERROR_SUCCESS);
}
static void access_policy_begin(const wchar_t *profile) {
  need(access_object_count && !access_policy_possible && !ownership_policy_installed && ownership_stage == 3);
  BOOL writable = !wcscmp(profile, L"workspace-write") || !wcscmp(profile, L"trusted-command"); need(writable || !wcscmp(profile, L"read-only"));
  access_registry_parent(); need(!access_registry_present()); wfp_open(); GUID key; FWPM_PROVIDER0 *provider; FWPM_SUBLAYER0 *layer; FWPM_FILTER0 *filter;
  access_key(0, &key); need(FwpmProviderGetByKey0(wfp_engine, &key, &provider) == FWP_E_PROVIDER_NOT_FOUND);
  access_key(1, &key); need(FwpmSubLayerGetByKey0(wfp_engine, &key, &layer) == FWP_E_SUBLAYER_NOT_FOUND);
  for (unsigned i = 0; i < 52; i++) { access_key(i + 2, &key); need(FwpmFilterGetByKey0(wfp_engine, &key, &filter) == FWP_E_FILTER_NOT_FOUND); }
  for (unsigned i = 0; i < access_object_count; i++) {
    HANDLE file = entries[access_indices[i]].file.handle; char hash[65]; security(file, SE_FILE_OBJECT, TRUE, hash);
    access_before[i] = file_sd(file, SE_FILE_OBJECT); DWORD read = FILE_GENERIC_READ, edit = read | FILE_GENERIC_WRITE | DELETE;
    DWORD mask = i == 1 ? FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE : i == 2 ? read | FILE_TRAVERSE | (writable ? FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY : 0) :
      i == 3 ? (writable ? edit : read) : i == 4 ? read : i >= 10 ? read | FILE_EXECUTE : 0;
    wchar_t text[2048]; if (!mask) wcscpy_s(text, 2048, L"O:SYG:SYD:P(A;;FA;;;SY)"); else
      need(swprintf_s(text, 2048, L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x%lx;;;%ls)(A;;0x%lx;;;%ls)", mask, case_record.accountSid, mask, case_record.restrictingSid) > 0);
    if (i == 2) { DWORD childMask = writable ? edit : read; wchar_t inherited[1536];
      need(swprintf_s(inherited, 1536, L"(D;OICIIO;WDWO;;;OW)(A;OICIIO;FA;;;SY)(A;OIIO;0x%lx;;;%ls)(A;OIIO;0x%lx;;;%ls)(A;CIIO;0x%lx;;;%ls)(A;CIIO;0x%lx;;;%ls)",
        childMask, case_record.accountSid, childMask, case_record.restrictingSid, childMask | FILE_TRAVERSE, case_record.accountSid, childMask | FILE_TRAVERSE, case_record.restrictingSid) > 0);
      need(!wcscat_s(text, 2048, inherited)); }
    if (writable && (i == 2 || i == 3)) need(!wcscat_s(text, 2048, L"S:(ML;OICI;NW;;;LW)"));
    access_wanted[i] = descriptor(text);
  }
  access_policy_possible = TRUE; printf("{\"possible\":true}");
}
static BOOL access_acl_equal(PSECURITY_DESCRIPTOR a, PSECURITY_DESCRIPTOR b, BOOL sacl) {
  PACL left, right; BOOL lp, rp, defaulted;
  need((sacl ? GetSecurityDescriptorSacl(a, &lp, &left, &defaulted) : GetSecurityDescriptorDacl(a, &lp, &left, &defaulted)) &&
    (sacl ? GetSecurityDescriptorSacl(b, &rp, &right, &defaulted) : GetSecurityDescriptorDacl(b, &rp, &right, &defaulted)));
  return (!lp || !left) && (!rp || !right) ? TRUE : lp && rp && left && right && left->AclSize == right->AclSize && !memcmp(left, right, left->AclSize);
}
static void access_policy_installed(const char *hexBytes) {
  need(access_policy_possible && !ownership_policy_installed && !ownership_released && ownership_stage == 3 && strlen(hexBytes) <= 65536);
  for (unsigned i = 0; i < access_object_count; i++) { PSECURITY_DESCRIPTOR actual = file_sd(entries[access_indices[i]].file.handle, SE_FILE_OBJECT);
    need(access_acl_equal(actual, access_wanted[i], FALSE) && access_acl_equal(actual, access_wanted[i], TRUE)); LocalFree(actual); }
  need(access_registry_present()); size_t size = strlen(hexBytes); need(size && !(size % 2)); BYTE *data = calloc(size / 2, 1); need(data);
  for (size_t i = 0; i < size / 2; i++) data[i] = (BYTE)(nibble(hexBytes[i * 2]) * 16 + nibble(hexBytes[i * 2 + 1]));
  HANDLE file = account_file(entries[case_custody].path, L"policy", GENERIC_WRITE, CREATE_NEW); DWORD used;
  need(WriteFile(file, data, (DWORD)size / 2, &used, NULL) && used == size / 2 && FlushFileBuffers(file) && CloseHandle(file)); free(data);
  wchar_t name[4096]; need(swprintf_s(name, 4096, L"%ls\\policy", entries[case_custody].path) > 0); ownership_policy_file = hold(name, FALSE, TRUE, GENERIC_READ);
  ownership_policy_installed = TRUE; printf("{\"installed\":true}");
}
static void access_policy_restore(void) {
  need(access_policy_possible && !case_job && !audit_owned && !helpers[0].process && !helpers[1].process);
  for (unsigned i = 0; i < ownership_count; i++) need(WaitForSingleObject(ownership_processes[i], 0) == WAIT_OBJECT_0);
  /* Validate the whole inventory before any setter, accepting only unchanged
   * baseline or the exact owned installation after an interrupted writer. */
  for (unsigned i = 0; i < access_object_count; i++) { PSECURITY_DESCRIPTOR actual = file_sd(entries[access_indices[i]].file.handle, SE_FILE_OBJECT);
    PSID owner, group, oldOwner, oldGroup; BOOL defaulted; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
    need(GetSecurityDescriptorOwner(actual, &owner, &defaulted) && GetSecurityDescriptorOwner(access_before[i], &oldOwner, &defaulted) && EqualSid(owner, oldOwner) &&
      GetSecurityDescriptorGroup(actual, &group, &defaulted) && GetSecurityDescriptorGroup(access_before[i], &oldGroup, &defaulted) && EqualSid(group, oldGroup) &&
      GetSecurityDescriptorControl(actual, &flags, &revision) && (flags & SE_DACL_PROTECTED) &&
      (access_acl_equal(actual, access_before[i], FALSE) || access_acl_equal(actual, access_wanted[i], FALSE)) &&
      (access_acl_equal(actual, access_before[i], TRUE) || access_acl_equal(actual, access_wanted[i], TRUE))); LocalFree(actual); }
  GUID key; FWPM_FILTER0 *filter; wfp_open(); for (unsigned i = 0; i < 52; i++) { access_key(i + 2, &key); need(FwpmFilterGetByKey0(wfp_engine, &key, &filter) == FWP_E_FILTER_NOT_FOUND); }
  GUID providerKey, layerKey; access_key(0, &providerKey); access_key(1, &layerKey); FWPM_PROVIDER0 *provider; FWPM_SUBLAYER0 *layer;
  DWORD p = FwpmProviderGetByKey0(wfp_engine, &providerKey, &provider), l = FwpmSubLayerGetByKey0(wfp_engine, &layerKey, &layer);
  need((p == FWP_E_PROVIDER_NOT_FOUND && l == FWP_E_SUBLAYER_NOT_FOUND) || (p == ERROR_SUCCESS && l == ERROR_SUCCESS));
  if (p == ERROR_SUCCESS) {
    need(provider->flags == 1 && !provider->providerData.size && !provider->serviceName && layer->flags == 1 && layer->weight == 65535 &&
      layer->providerKey && IsEqualGUID(layer->providerKey, &providerKey) && !layer->providerData.size); FwpmFreeMemory0((void **)&provider); FwpmFreeMemory0((void **)&layer);
    ownership_wfp_security(&providerKey, 0); ownership_wfp_security(&layerKey, 1);
  }
  wchar_t name[256]; need(swprintf_s(name, 256, L"SOFTWARE\\NativeProof\\%hs", nonce) > 0); HKEY registry = NULL;
  if (access_registry_present()) { need(RegOpenKeyExW(HKEY_LOCAL_MACHINE, name, 0, KEY_ALL_ACCESS | ACCESS_SYSTEM_SECURITY | KEY_WOW64_64KEY, &registry) == ERROR_SUCCESS);
    DWORD children, values; need(RegQueryInfoKeyW(registry, NULL, NULL, NULL, &children, NULL, NULL, &values, NULL, NULL, NULL, NULL) == ERROR_SUCCESS && !children && !values);
    char hash[65]; security(registry, SE_REGISTRY_KEY, TRUE, hash); }
  if (p == ERROR_SUCCESS) need(FwpmTransactionBegin0(wfp_engine, 0) == ERROR_SUCCESS && FwpmSubLayerDeleteByKey0(wfp_engine, &layerKey) == ERROR_SUCCESS &&
    FwpmProviderDeleteByKey0(wfp_engine, &providerKey) == ERROR_SUCCESS && FwpmTransactionCommit0(wfp_engine) == ERROR_SUCCESS);
  if (registry) { if (registry_key) { need(RegCloseKey(registry_key) == ERROR_SUCCESS); registry_key = NULL; }
    if (registry_changed) { need(CloseHandle(registry_changed)); registry_changed = NULL; }
    need(RegDeleteKeyExW(HKEY_LOCAL_MACHINE, name, KEY_WOW64_64KEY, 0) == ERROR_SUCCESS && RegCloseKey(registry) == ERROR_SUCCESS); }
  for (unsigned i = 0; i < access_object_count; i++) { PACL dacl, sacl; BOOL present, defaulted;
    need(GetSecurityDescriptorDacl(access_before[i], &present, &dacl, &defaulted) && present &&
      GetSecurityDescriptorSacl(access_before[i], &present, &sacl, &defaulted));
    set_file_security(entries[access_indices[i]].file.handle, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION |
      SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, dacl, present ? sacl : NULL);
    LocalFree(access_before[i]); LocalFree(access_wanted[i]); access_before[i] = access_wanted[i] = NULL;
  }
  if (ownership_policy_file.handle) close_file(&ownership_policy_file);
  access_policy_possible = ownership_policy_installed = FALSE; ownership_policy_restored = TRUE; printf("{\"restored\":true}");
}
static void access_state(DWORD verifierPid, ULONGLONG verifierBorn) {
  HANDLE observer = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, verifierPid); FILETIME created, ended, kernel, user;
  need(observer && system_process(observer) && GetProcessTimes(observer, &created, &ended, &kernel, &user) &&
    (((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime) == verifierBorn && WaitForSingleObject(observer, 0) == WAIT_TIMEOUT && CloseHandle(observer));
  need(case_token && access_object_count);
  struct access_view view = {0};
  view.observer = helpers[1].process;
  for (unsigned i = 0; i < 2; i++) { view.roots[i] = entries[i + 1].file.handle; view.payloadRoots[i] = access_payload_roots[i]; }
  view.domain.record = case_record; view.domain.count = ownership_count;
  view.domain.token = case_token; view.domain.job = case_job ? case_job : (job_count == 1 ? jobs[0] : NULL);
  view.domain.launcher = ownership_launcher.hProcess; view.domain.owner = ownership_owner.hProcess;
  view.domain.launcherToken = ownership_launcher_token; view.domain.ownerToken = ownership_owner_token;
  view.domain.ownerJob = ownership_owner_job; view.domain.creator = GetCurrentProcessId();
  for (unsigned i = 0; i < ownership_count; i++) { view.domain.processes[i] = ownership_processes[i]; view.domain.tokens[i] = ownership_tokens[i]; }
  view.objectCount = access_object_count;
  for (unsigned i = 0; i < access_object_count; i++) { view.indices[i] = access_indices[i]; view.objects[i] = entries[access_indices[i]].file.handle; }
  view.socketCount = case_socket_count; for (unsigned i = 0; i < case_socket_count; i++) { view.sockets[i] = (HANDLE)case_sockets[i]; view.payloadSockets[i] = access_payload_sockets[i];
    need(!WSADuplicateSocketW(case_sockets[i], verifierPid, &view.socketInfo[i])); }
  printf("{\"hex\":\""); hex((BYTE *)&view, sizeof(view)); printf("\"}");
}
static HANDLE access_duplicate(HANDLE source, HANDLE original) {
  HANDLE actual; need(original && DuplicateHandle(source, original, GetCurrentProcess(), &actual, 0, FALSE, DUPLICATE_SAME_ACCESS)); return actual;
}
static BOOL access_bfe_running(void) {
  SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT); need(manager);
  SC_HANDLE service = OpenServiceW(manager, L"BFE", SERVICE_QUERY_STATUS); need(service);
  SERVICE_STATUS_PROCESS status; DWORD size;
  need(QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &size) && size == sizeof(status));
  need(CloseServiceHandle(service) && CloseServiceHandle(manager)); return status.dwCurrentState == SERVICE_RUNNING;
}
static BOOL access_member_pid(struct ownership_view *view, DWORD pid) {
  for (unsigned i = 0; i < view->count; i++) if (GetProcessId(view->processes[i]) == pid) return TRUE;
  return FALSE;
}
static void access_flows(struct ownership_view *view) {
  unsigned emitted = 0; printf("[");
  for (unsigned version = 0; version < 2; version++) {
    ULONG family = version ? AF_INET6 : AF_INET; DWORD size = 0;
    DWORD status = GetExtendedTcpTable(NULL, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    need(status == ERROR_INSUFFICIENT_BUFFER && size && size <= 16777216); BYTE *bytes = calloc(size, 1); need(bytes);
    need(GetExtendedTcpTable(bytes, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR);
    DWORD count = *(DWORD *)bytes; need(count <= 65536);
    for (DWORD i = 0; i < count; i++) {
      DWORD pid, local, remote, state;
      if (version) { MIB_TCP6ROW_OWNER_PID *row = &((MIB_TCP6TABLE_OWNER_PID *)bytes)->table[i]; pid = row->dwOwningPid; local = row->dwLocalPort; remote = row->dwRemotePort; state = row->dwState; }
      else { MIB_TCPROW_OWNER_PID *row = &((MIB_TCPTABLE_OWNER_PID *)bytes)->table[i]; pid = row->dwOwningPid; local = row->dwLocalPort; remote = row->dwRemotePort; state = row->dwState; }
      if (access_member_pid(view, pid) || (pid==view->creator && state!=MIB_TCP_STATE_CLOSED && state!=MIB_TCP_STATE_LISTEN && state!=MIB_TCP_STATE_TIME_WAIT))
        printf("%s{\"family\":\"%s\",\"protocol\":\"tcp\",\"pid\":%lu,\"state\":%lu,\"localPort\":%u,\"remotePort\":%u}", emitted++ ? "," : "", version ? "v6" : "v4", pid, state, ntohs((USHORT)local), ntohs((USHORT)remote));
    }
    free(bytes); size = 0;
    status = GetExtendedUdpTable(NULL, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
    need(status == ERROR_INSUFFICIENT_BUFFER && size && size <= 16777216); bytes = calloc(size, 1); need(bytes);
    need(GetExtendedUdpTable(bytes, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) == NO_ERROR); count = *(DWORD *)bytes; need(count <= 65536);
    for (DWORD i = 0; i < count; i++) {
      DWORD pid, local;
      if (version) { MIB_UDP6ROW_OWNER_PID *row = &((MIB_UDP6TABLE_OWNER_PID *)bytes)->table[i]; pid = row->dwOwningPid; local = row->dwLocalPort; }
      else { MIB_UDPROW_OWNER_PID *row = &((MIB_UDPTABLE_OWNER_PID *)bytes)->table[i]; pid = row->dwOwningPid; local = row->dwLocalPort; }
      if (access_member_pid(view, pid)) printf("%s{\"family\":\"%s\",\"protocol\":\"udp\",\"pid\":%lu,\"state\":0,\"localPort\":%u,\"remotePort\":0}", emitted++ ? "," : "", version ? "v6" : "v4", pid, ntohs((USHORT)local));
    }
    free(bytes);
  }
  printf("]");
}
static void verify_access(unsigned subject, unsigned custody, const char *context, const char *hexBytes) {
  need(subject < process_count && custody < count && strlen(hexBytes) == sizeof(struct access_view) * 2);
  struct access_view view; for (unsigned i = 0; i < sizeof(view); i++) ((BYTE *)&view)[i] = (BYTE)(nibble(hexBytes[i * 2]) * 16 + nibble(hexBytes[i * 2 + 1]));
  need(view.objectCount >= 11 && view.objectCount <= 44 && view.socketCount <= 8 && view.domain.count <= 32);
  struct case_account_record record = {0}; account_record(entries[custody].path, &record);
  need(!strcmp(context, record.context) && !memcmp(&record, &view.domain.record, sizeof(record)));
  case_record = record; strcpy_s(nonce, 33, record.nonce);
  HANDLE source = duplicate_process_owner(subject); need(system_process(source) && view.domain.creator == GetProcessId(source));
  access_registry_parent();
  view.domain.token = access_duplicate(source, view.domain.token);
  wchar_t *sid = token_sid(view.domain.token); need(!wcscmp(sid, record.accountSid)); LocalFree(sid);
  if (view.domain.job) view.domain.job = access_duplicate(source, view.domain.job);
  if (view.domain.launcher) view.domain.launcher = access_duplicate(source, view.domain.launcher);
  if (view.domain.owner) view.domain.owner = access_duplicate(source, view.domain.owner);
  if (view.domain.ownerJob) view.domain.ownerJob = access_duplicate(source, view.domain.ownerJob);
  for (unsigned i = 0; i < view.domain.count; i++) {
    view.domain.processes[i] = access_duplicate(source, view.domain.processes[i]); view.domain.tokens[i] = access_duplicate(source, view.domain.tokens[i]);
    sid = token_sid(view.domain.tokens[i]); need(!wcscmp(sid, record.accountSid)); LocalFree(sid);
    if (WaitForSingleObject(view.domain.processes[i], 0) != WAIT_OBJECT_0) {
      HANDLE current; need(OpenProcessToken(view.domain.processes[i], TOKEN_QUERY, &current));
      TOKEN_STATISTICS *before = token_info(view.domain.tokens[i], TokenStatistics), *after = token_info(current, TokenStatistics);
      need(!memcmp(&before->TokenId, &after->TokenId, sizeof(LUID)) && !memcmp(&before->ModifiedId, &after->ModifiedId, sizeof(LUID)) &&
        process_session(view.domain.processes[i]) == 0 && CloseHandle(current)); free(before); free(after);
    }
  }
  ownership_census(&view.domain);
  printf("{\"accountSid\":\"%ls\",\"restrictingSid\":\"%ls\",\"contextSha256\":\"%s\",\"bfeRunning\":%s,\"token\":",
    record.accountSid, record.restrictingSid, context, access_bfe_running() ? "true" : "false");
  effective_token_handle(view.domain.token); printf(",\"creator\":"); retained_identity(source,tokens[subject],sessions[subject]); printf(",\"job\":");
  if (view.domain.job) job_read(view.domain.job); else {
    wchar_t name[96]; need(swprintf_s(name, 96, L"Local\\NativeProof-%hs", record.nonce) > 0);
    HANDLE job = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, name); need(!job && GetLastError() == ERROR_FILE_NOT_FOUND); printf("null");
  }
  printf(",\"fileRoots\":["); unsigned roots = 0;
  for (unsigned r = 0; r < 2; r++) if (view.payloadRoots[r] && view.domain.count && WaitForSingleObject(view.domain.processes[0], 0) == WAIT_TIMEOUT) {
    HANDLE root = access_duplicate(source, view.roots[r]), actual = access_duplicate(view.domain.processes[0], view.payloadRoots[r]);
    FILE_ID_INFO expected, observed; FILE_ATTRIBUTE_TAG_INFO tag; char hash[65];
    need(GetFileInformationByHandleEx(root, FileIdInfo, &expected, sizeof(expected)) &&
      GetFileInformationByHandleEx(actual, FileIdInfo, &observed, sizeof(observed)) && !memcmp(&expected, &observed, sizeof(expected)) &&
      GetFileInformationByHandleEx(actual, FileAttributeTagInfo, &tag, sizeof(tag)) &&
      (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
    security(root, SE_FILE_OBJECT, TRUE, hash);
    wchar_t name[4096]; DWORD size = GetFinalPathNameByHandleW(root, name, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    need(size > 4 && size < 4096 && !_wcsicmp(name + 4, entries[r + 1].path));
    struct verify_handles *inventory = handle_inventory(); BOOL found = FALSE;
    for (ULONG_PTR i = 0; i < inventory->count; i++) if (inventory->entries[i].pid == GetProcessId(view.domain.processes[0]) &&
      inventory->entries[i].handle == (ULONG_PTR)view.payloadRoots[r]) { need(inventory->entries[i].access == ACCESS_ROOT_MASK); found = TRUE; }
    need(found); free(inventory); struct held_file file = {0}; file.handle = actual; file.id = observed;
    printf("%s{\"index\":%u,\"identity\":\"", roots++ ? "," : "", r + 1); file_id(&file); printf("\",\"accessMask\":%lu}", (DWORD)ACCESS_ROOT_MASK);
    need(CloseHandle(root) && CloseHandle(actual));
  }
  printf("],\"members\":[");
  for (unsigned i = 0; i < view.domain.count; i++) {
    BOOL signaled = WaitForSingleObject(view.domain.processes[i], 0) == WAIT_OBJECT_0, belongs = FALSE;
    if (!signaled) need(view.domain.job && IsProcessInJob(view.domain.processes[i], view.domain.job, &belongs) && belongs);
    if (i) putchar(','); printf("{\"identity\":"); retained_identity(view.domain.processes[i], view.domain.tokens[i], 0);
    printf(",\"signaled\":%s,\"inJob\":%s,\"token\":", signaled ? "true" : "false", belongs ? "true" : "false");
    effective_token_handle(view.domain.tokens[i]);
    TOKEN_DEFAULT_DACL *dacl = token_info(view.domain.tokens[i], TokenDefaultDacl); ACCESS_ALLOWED_ACE *ace; BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
    need(dacl->DefaultDacl && dacl->DefaultDacl->AceCount == 1 && GetAce(dacl->DefaultDacl, 0, (void **)&ace) && CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) &&
      ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags && ace->Mask == GENERIC_ALL && EqualSid(&ace->SidStart, system)); free(dacl); printf("}");
  }
  BOOL ownerEmpty = TRUE;
  if (view.domain.ownerJob) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    need(QueryInformationJobObject(view.domain.ownerJob, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL)); ownerEmpty = !accounting.ActiveProcesses; }
  printf("],\"observerAbsent\":%s,\"creationSealed\":%s,\"objects\":[", view.observer ? "false" : "true", ownerEmpty && (!view.domain.launcher || WaitForSingleObject(view.domain.launcher, 0) == WAIT_OBJECT_0) &&
    (!view.domain.owner || WaitForSingleObject(view.domain.owner, 0) == WAIT_OBJECT_0) ? "true" : "false");
  struct verify_handles *inventory = handle_inventory();
  for (unsigned i = 0; i < view.objectCount; i++) {
    unsigned index = view.indices[i]; need(index < count); HANDLE file = access_duplicate(source, view.objects[i]);
    wchar_t name[4096]; DWORD size = GetFinalPathNameByHandleW(file, name, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    need(size > 4 && size < 4096 && !_wcsicmp(name + 4, entries[index].path));
    FILE_ATTRIBUTE_TAG_INFO tag; BY_HANDLE_FILE_INFORMATION info; struct held_file held = {0}; held.handle = file;
    need(GetFileInformationByHandleEx(file, FileIdInfo, &held.id, sizeof(held.id)) && GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) &&
      !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && GetFileInformationByHandle(file, &info) && info.nNumberOfLinks == 1);
    void *object = NULL; unsigned foreign = 0;
    for (ULONG_PTR j = 0; j < inventory->count; j++) if (inventory->entries[j].pid == GetProcessId(source) && inventory->entries[j].handle == (ULONG_PTR)view.objects[i]) object = inventory->entries[j].object;
    need(object);
    for (ULONG_PTR j = 0; j < inventory->count; j++) if (inventory->entries[j].object == object && inventory->entries[j].pid != GetCurrentProcessId() && inventory->entries[j].pid != GetProcessId(source) &&
      (inventory->entries[j].access & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER))) foreign++;
    printf("%s{\"index\":%u,\"identity\":\"", i ? "," : "", index); file_id(&held);
    printf("\",\"foreignWritableHandles\":%u,\"parents\":[", foreign);
    struct held_file parents = hold_shared(entries[index].path, !!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY), FALSE, GENERIC_READ, TRUE);
    for (unsigned j = 0; j < parents.count; j++) { if (j) putchar(','); FILE_ID_INFO id; need(GetFileInformationByHandleEx(parents.parents[j], FileIdInfo, &id, sizeof(id))); struct held_file parent = {0}; parent.handle = parents.parents[j]; parent.id = id;
      printf("\""); file_id(&parent); printf("\""); }
    printf("],\"security\":"); PSECURITY_DESCRIPTOR sd = file_sd(file, SE_FILE_OBJECT); sd_read(sd); LocalFree(sd); printf("}"); close_file(&parents); need(CloseHandle(file));
  }
  free(inventory); printf("],\"flows\":"); access_flows(&view.domain); printf(",\"endpoints\":[");
  char socketPins[8][65]; BOOL payloadSocketVerified[8] = {0};
  WSADATA socketData; need(!WSAStartup(MAKEWORD(2, 2), &socketData));
  for (unsigned i = 0; i < view.socketCount; i++) {
    SOCKET socket = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &view.socketInfo[i], 0, WSA_FLAG_NO_HANDLE_INHERIT); need(socket != INVALID_SOCKET);
    struct verify_handles *sockets = handle_inventory(); void *original = NULL, *actual = NULL, *payload = NULL;
    for (ULONG_PTR j = 0; j < sockets->count; j++) {
      if (sockets->entries[j].pid == GetProcessId(source) && sockets->entries[j].handle == (ULONG_PTR)view.sockets[i]) original = sockets->entries[j].object;
      if (sockets->entries[j].pid == GetCurrentProcessId() && sockets->entries[j].handle == (ULONG_PTR)socket) actual = sockets->entries[j].object;
      if (view.domain.count && sockets->entries[j].pid == GetProcessId(view.domain.processes[(i%2 && view.domain.count==2) ? 1 : 0]) && sockets->entries[j].handle == (ULONG_PTR)view.payloadSockets[i]) payload = sockets->entries[j].object;
    }
    need(original && original == actual && (!view.domain.count || WaitForSingleObject(view.domain.processes[0], 0) == WAIT_OBJECT_0 || !view.payloadSockets[i] || payload == original));
    for (ULONG_PTR j = 0; j < sockets->count; j++) if (sockets->entries[j].object == original)
      need(sockets->entries[j].pid == GetProcessId(source) || sockets->entries[j].pid == GetCurrentProcessId() ||
        access_member_pid(&view.domain,(DWORD)sockets->entries[j].pid));
    char seed[128]; need(sprintf_s(seed, sizeof(seed), "%s:%p", context, original) > 0); sum((BYTE *)seed, (DWORD)strlen(seed), socketPins[i]);
    payloadSocketVerified[i] = view.domain.count && WaitForSingleObject(view.domain.processes[0], 0) == WAIT_TIMEOUT && payload == original; free(sockets);
    SOCKADDR_STORAGE address; int size = sizeof(address), type, typeSize = sizeof(type), exclusive, optionSize = sizeof(exclusive);
    need(!getsockname((SOCKET)socket, (SOCKADDR *)&address, &size) && !getsockopt((SOCKET)socket, SOL_SOCKET, SO_TYPE, (char *)&type, &typeSize) &&
      !getsockopt((SOCKET)socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&exclusive, &optionSize) && exclusive);
    BOOL v6 = address.ss_family == AF_INET6; need(v6 ? IN6_IS_ADDR_LOOPBACK(&((SOCKADDR_IN6 *)&address)->sin6_addr) : ((SOCKADDR_IN *)&address)->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    if (v6) { int only, bytes = sizeof(only); need(!getsockopt((SOCKET)socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&only, &bytes) && only); }
    printf("%s{\"family\":\"%s\",\"protocol\":\"%s\",\"port\":%u}", i ? "," : "", v6 ? "v6" : "v4", type == SOCK_DGRAM ? "udp" : "tcp",
      ntohs(v6 ? ((SOCKADDR_IN6 *)&address)->sin6_port : ((SOCKADDR_IN *)&address)->sin_port)); need(!closesocket((SOCKET)socket));
  }
  printf("],\"reservations\":[");
  for (unsigned i = 0; i < view.socketCount; i++) printf("%s{\"identitySha256\":\"%s\",\"payloadVerified\":%s}", i ? "," : "", socketPins[i], payloadSocketVerified[i] ? "true" : "false");
  BOOL registryPresent = access_registry_present(); printf("],\"registryPresent\":%s,\"registry\":", registryPresent ? "true" : "false");
  if (!registryPresent) printf("null"); else {
    wchar_t name[256]; HKEY key; need(swprintf_s(name,256,L"SOFTWARE\\NativeProof\\%hs",nonce)>0 &&
      RegOpenKeyExW(HKEY_LOCAL_MACHINE,name,0,READ_CONTROL | ACCESS_SYSTEM_SECURITY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,&key)==ERROR_SUCCESS);
    BYTE bytes[8192]; ULONG used; typedef NTSTATUS (NTAPI *query_key)(HANDLE,ULONG,void *,ULONG,ULONG *);
    query_key query=(query_key)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryKey"); need(query && !query(key,3,bytes,sizeof(bytes),&used));
    DWORD length=*(DWORD *)bytes; need(used>=4 && used<=sizeof(bytes) && length && length<=used-4 && !(length%2)); DWORD children, values; FILETIME written;
    need(RegQueryInfoKeyW(key,NULL,NULL,NULL,&children,NULL,NULL,&values,NULL,NULL,NULL,&written)==ERROR_SUCCESS);
    PSECURITY_DESCRIPTOR sd=file_sd(key,SE_REGISTRY_KEY); printf("{\"nameHex\":\""); hex(bytes+4,length);
    printf("\",\"children\":%lu,\"values\":%lu,\"written\":\"%08lx%08lx\",\"security\":",children,values,written.dwHighDateTime,written.dwLowDateTime);
    sd_read(sd); printf("}"); LocalFree(sd); need(RegCloseKey(key)==ERROR_SUCCESS);
  }
  printf(",\"ownedWfp\":{");
  wfp_open(); BOOL exists[54]={0}; GUID key; FWPM_PROVIDER0 *provider; FWPM_SUBLAYER0 *layer; FWPM_FILTER0 *filter;
  access_key(0, &key); DWORD present = FwpmProviderGetByKey0(wfp_engine, &key, &provider); need(present == ERROR_SUCCESS || present == FWP_E_PROVIDER_NOT_FOUND);
  exists[0]=present==ERROR_SUCCESS; printf("\"provider\":%s,", present == ERROR_SUCCESS ? "true" : "false"); if (!present) FwpmFreeMemory0((void **)&provider);
  access_key(1, &key); present = FwpmSubLayerGetByKey0(wfp_engine, &key, &layer); need(present == ERROR_SUCCESS || present == FWP_E_SUBLAYER_NOT_FOUND);
  exists[1]=present==ERROR_SUCCESS; printf("\"sublayer\":%s,\"filters\":[", present == ERROR_SUCCESS ? "true" : "false"); if (!present) FwpmFreeMemory0((void **)&layer);
  for (unsigned i = 0; i < 52; i++) { access_key(i + 2, &key); present = FwpmFilterGetByKey0(wfp_engine, &key, &filter); need(present == ERROR_SUCCESS || present == FWP_E_FILTER_NOT_FOUND);
    exists[i+2]=present==ERROR_SUCCESS; printf("%s%s", i ? "," : "", present == ERROR_SUCCESS ? "true" : "false"); if (!present) FwpmFreeMemory0((void **)&filter); }
  printf("],\"observations\":{\"provider\":");
  for (unsigned i=0;i<54;i++) { access_key(i,&key); RPC_CSTR text; need(UuidToStringA(&key,&text)==RPC_S_OK);
    if (i==1) printf(",\"sublayer\":"); if (i==2) printf(",\"filters\":["); if (i>2) putchar(',');
    if (exists[i]) effective_wfp((char *)text,i<2 ? i : 2); else printf("null"); need(RpcStringFreeA(&text)==RPC_S_OK);
  } printf("]}}}"); need(!WSACleanup());
  for (unsigned i = 0; i < view.domain.count; i++) need(CloseHandle(view.domain.processes[i]) && CloseHandle(view.domain.tokens[i]));
  HANDLE handles[] = {view.domain.token, view.domain.job, view.domain.launcher, view.domain.owner, view.domain.ownerJob, source};
  for (unsigned i = 0; i < sizeof(handles) / sizeof(handles[0]); i++) if (handles[i]) need(CloseHandle(handles[i]));
}
/* Fixed outside controls are private native objects. No operator callback or
 * timeout can acknowledge availability, policy authority or a socket owner. */
struct access_control_view {
  struct case_account_record record;
  unsigned kind, index;
  HANDLE object, peer, peerToken, payload, peerJob;
  WSAPROTOCOL_INFOW socketInfo;
  wchar_t target[4096]; char id[64];
};
static HANDLE access_pipe, access_alpc;
static BOOL access_controls_ready, access_rpc_ready;
static volatile LONG access_controls_closed;
static SOCKET access_listeners[16]; static unsigned access_listener_count;
struct access_peer_owner { PROCESS_INFORMATION process; HANDLE token, job, input, output; wchar_t home[4096]; struct case_account_record record; HANDLE sockets[8]; WSAPROTOCOL_INFOW infos[8]; };
static struct access_peer_owner access_private_peer, access_other_peer;
static struct access_control_view access_controls[38]; static unsigned access_control_count;
static SOCKET access_foreign_socket = INVALID_SOCKET;
static void access_peer_command(struct access_peer_owner *peer, const wchar_t *operation, const wchar_t *first, const wchar_t *second, char *reply, DWORD capacity) {
  const wchar_t *words[] = {operation, first, second}; char command[16384]; DWORD used = 0, written;
  for (unsigned i=0;i<3 && words[i];i++) { if (i) command[used++]=' '; const BYTE *bytes=(const BYTE *)words[i]; DWORD length=(DWORD)wcslen(words[i])*2;
    need(used+length*2+1<sizeof(command)); for (DWORD j=0;j<length;j++) need(sprintf_s(command+used+j*2,sizeof(command)-used-j*2,"%02x",bytes[j]) == 2); used+=length*2; }
  command[used++]='\n'; need(WriteFile(peer->input,command,used,&written,NULL) && written==used); line(peer->output,reply,capacity); need(strstr(reply,nonce));
}
static ULONGLONG access_reply_handle(const char *reply) {
  const char *value=strstr(reply,"\"handle\":\""); need(value); value+=10; char *end; ULONGLONG handle=_strtoui64(value,&end,10); need(handle && *end=='"'); return handle;
}
static void access_start_peer(struct access_peer_owner *peer, BOOL other) {
  need(access_mode && ownership_released && !access_controls_closed && !peer->process.hProcess);
  PSECURITY_DESCRIPTOR privateSd=descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES private=attributes(privateSd,FALSE), inherited=attributes(privateSd,TRUE);
  HANDLE primary=case_token; wchar_t executable[4096], cwd[4096]; wcscpy_s(executable,4096,entries[6].path); wcscpy_s(cwd,4096,entries[4].path);
  if (other) {
    need(swprintf_s(peer->home,4096,L"%ls\\access-peer",entries[2].path)>0 && CreateDirectoryW(peer->home,&private));
    char seed[128]; need(sprintf_s(seed,sizeof(seed),"%s:access-peer",case_record.context)>0); peer->record.version=1; sum((BYTE *)seed,(DWORD)strlen(seed),peer->record.context); memcpy(peer->record.nonce,peer->record.context,32);
    HANDLE intent=account_file(peer->home,L"account.intent",GENERIC_WRITE,CREATE_NEW); DWORD written;
    need(WriteFile(intent,&peer->record,sizeof(peer->record),&written,NULL) && written==sizeof(peer->record) && FlushFileBuffers(intent) && CloseHandle(intent));
    wchar_t name[21], *sid; need(swprintf_s(name,21,L"np_%.16hs",peer->record.nonce)>0); primary=account(name,peer->home,&sid); wcscpy_s(peer->record.accountSid,256,sid); LocalFree(sid);
    wcscpy_s(peer->record.restrictingSid,256,case_record.restrictingSid);
    HANDLE record=account_file(peer->home,L"account.record",GENERIC_WRITE,CREATE_NEW);
    need(WriteFile(record,&peer->record,sizeof(peer->record),&written,NULL) && written==sizeof(peer->record) && FlushFileBuffers(record) && CloseHandle(record));
    TOKEN_PRIVILEGES *privileges=token_info(primary,TokenPrivileges); LUID notify; need(privileges->PrivilegeCount<=64 && LookupPrivilegeValueW(NULL,SE_CHANGE_NOTIFY_NAME,&notify)); LUID_AND_ATTRIBUTES remove[64]; unsigned count=0;
    for (DWORD i=0;i<privileges->PrivilegeCount;i++) if (memcmp(&privileges->Privileges[i].Luid,&notify,sizeof(LUID))) remove[count++]=privileges->Privileges[i];
    TOKEN_GROUPS *groups=token_info(primary,TokenGroups); need(groups->GroupCount<=128); SID_AND_ATTRIBUTES disabled[128]; unsigned disabledCount=0; for (DWORD i=0;i<groups->GroupCount;i++) if (!(groups->Groups[i].Attributes & (SE_GROUP_INTEGRITY | SE_GROUP_USE_FOR_DENY_ONLY))) disabled[disabledCount++]=groups->Groups[i];
    HANDLE reduced; need(count<=64 && CreateRestrictedToken(primary,0,disabledCount,disabled,count,remove,0,NULL,&reduced) && CloseHandle(primary)); primary=reduced; free(privileges); free(groups);
    wchar_t text[2048]; need(swprintf_s(text,2048,L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FRFX;;;%ls)",peer->record.accountSid)>0); PSECURITY_DESCRIPTOR readable=descriptor(text); SECURITY_ATTRIBUTES readableSa=attributes(readable,FALSE);
    PACL acl; BOOL present,defaulted; need(GetSecurityDescriptorDacl(readable,&present,&acl,&defaulted) && present);
    struct held_file home=hold(peer->home,TRUE,TRUE,FILE_LIST_DIRECTORY | WRITE_DAC); need(SetSecurityInfo(home.handle,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,NULL,NULL,acl,NULL)==ERROR_SUCCESS); close_file(&home);
    for (unsigned i=0;i<access_object_count;i++) { struct entry *entry=&entries[access_indices[i]];
      if (i<10 && access_indices[i]!=6) continue; if (!strcmp(entry->kind,"directory") || !strcmp(entry->kind,"data")) continue;
      const wchar_t *leaf=wcsrchr(entry->path,'\\'); need(leaf && swprintf_s(executable,4096,L"%ls%ls",peer->home,leaf)>0); DWORD size; BYTE *bytes=read_file(&entry->file,134217728,&size);
      HANDLE file=CreateFileW(executable,GENERIC_WRITE,0,&readableSa,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,NULL);
      need(file!=INVALID_HANDLE_VALUE && WriteFile(file,bytes,size,&written,NULL) && written==size && FlushFileBuffers(file) && CloseHandle(file)); free(bytes);
      struct held_file copied=hold_shared(executable,FALSE,FALSE,GENERIC_READ,FALSE); pin(&copied,entry->pin); char signaturePin[65]; signature(&copied,entry->signature,signaturePin); close_file(&copied);
    }
    const wchar_t *leaf=wcsrchr(entries[6].path,'\\'); need(leaf && swprintf_s(executable,4096,L"%ls%ls",peer->home,leaf)>0); wcscpy_s(cwd,4096,peer->home); LocalFree(readable);
    peer->job=recovery_job(&private); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0}; limits.BasicLimitInformation.LimitFlags=0x2008; limits.BasicLimitInformation.ActiveProcessLimit=1;
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui={255}; need(SetInformationJobObject(peer->job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) && SetInformationJobObject(peer->job,JobObjectBasicUIRestrictions,&ui,sizeof(ui)));
  } else peer->job=case_job;
  PACL defaultDacl; BOOL present,defaulted; need(GetSecurityDescriptorDacl(privateSd,&present,&defaultDacl,&defaulted) && present); TOKEN_DEFAULT_DACL creation={defaultDacl}; need(SetTokenInformation(primary,TokenDefaultDacl,&creation,sizeof(creation)));
  HANDLE pipes[2]; need(CreatePipe(&pipes[0],&peer->input,&inherited,0) && CreatePipe(&peer->output,&pipes[1],&inherited,0) && SetHandleInformation(peer->input,HANDLE_FLAG_INHERIT,0) && SetHandleInformation(peer->output,HANDLE_FLAG_INHERIT,0));
  SIZE_T size=0; InitializeProcThreadAttributeList(NULL,2,0,&size); STARTUPINFOEXW start={0}; start.StartupInfo.cb=sizeof(start); start.lpAttributeList=calloc(1,size);
  need(start.lpAttributeList && InitializeProcThreadAttributeList(start.lpAttributeList,2,0,&size) && UpdateProcThreadAttribute(start.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,pipes,sizeof(pipes),NULL,NULL) && UpdateProcThreadAttribute(start.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&peer->job,sizeof(HANDLE),NULL,NULL));
  start.StartupInfo.dwFlags=STARTF_USESTDHANDLES; start.StartupInfo.hStdInput=pipes[0]; start.StartupInfo.hStdOutput=start.StartupInfo.hStdError=pipes[1]; wchar_t command[8192];
  need(swprintf_s(command,8192,L"\"%ls\" controls %hs",executable,nonce)>0); wchar_t environment[2]={0,0};
  need(CreateProcessAsUserW(primary,executable,command,&private,&private,TRUE,CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,environment,cwd,&start.StartupInfo,&peer->process));
  need(CloseHandle(pipes[0]) && CloseHandle(pipes[1]) && OpenProcessToken(peer->process.hProcess,TOKEN_QUERY | TOKEN_DUPLICATE,&peer->token));
  if (!other) { need(ownership_count==1); ownership_processes[1]=peer->process.hProcess; ownership_tokens[1]=peer->token; ownership_count=2; }
  else need(CloseHandle(primary));
  DeleteProcThreadAttributeList(start.lpAttributeList); free(start.lpAttributeList); LocalFree(privateSd);
}
static void access_peers(BOOL activate,DWORD verifierPid) {
  if (!activate) { need(ownership_count==1); access_start_peer(&access_private_peer,FALSE); access_start_peer(&access_other_peer,TRUE); }
  else { need(ownership_count==2 && ResumeThread(access_private_peer.process.hThread)==1 && ResumeThread(access_other_peer.process.hThread)==1);
  for (unsigned i=0;i<8;i++) { WSAPROTOCOL_INFOW info; wchar_t encoded[sizeof(info)*2+1], index[4]; char reply[4096];
    SOCKET socket=case_sockets[i];
    if (i%2) {
      need(!WSADuplicateSocketW(socket,GetProcessId(access_private_peer.process.hProcess),&info)); for (unsigned j=0;j<sizeof(info);j++) need(swprintf_s(encoded+j*2,3,L"%02x",((BYTE *)&info)[j])==2);
      need(swprintf_s(index,4,L"%u",i)>0); access_peer_command(&access_private_peer,L"socket",index,encoded,reply,sizeof(reply)); access_payload_sockets[i]=(HANDLE)(ULONG_PTR)access_reply_handle(reply);
      wchar_t verifier[16]; need(swprintf_s(verifier,16,L"%lu",verifierPid)>0); access_peer_command(&access_private_peer,L"serve",index,verifier,reply,sizeof(reply)); need(strstr(reply,"\"phase\":\"ready\""));
    }
  }
  }
  printf("{\"privatePeer\":"); retained_identity(access_private_peer.process.hProcess,access_private_peer.token,0); printf(",\"otherPeer\":"); retained_identity(access_other_peer.process.hProcess,access_other_peer.token,0); printf("}");
}

static int RPC_ENTRY access_rpc_auth(RPC_BINDING_HANDLE binding, unsigned long operation) {
  (void)operation; if (RpcImpersonateClient(binding) != RPC_S_OK) return FALSE;
  HANDLE token = NULL; BOOL allowed = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
  if (allowed) { wchar_t *sid = token_sid(token); allowed = !wcscmp(sid, L"S-1-5-18"); LocalFree(sid); need(CloseHandle(token)); }
  need(RpcRevertToSelf() == RPC_S_OK); return allowed;
}
static void RPC_ENTRY access_rpc_dispatch(PRPC_MESSAGE message) {
  (void)message; RpcRaiseException(RPC_S_ACCESS_DENIED);
}
static RPC_DISPATCH_FUNCTION access_rpc_functions[] = {access_rpc_dispatch};
static RPC_DISPATCH_TABLE access_rpc_table = {1, access_rpc_functions, 0};
static RPC_SERVER_INTERFACE access_rpc_interface = {
  sizeof(RPC_SERVER_INTERFACE), {{0x2dd5c390,0x3bd3,0x4ea1,{0x9d,0x68,0x1f,0x75,0x80,0x16,0x66,0x10}},{1,0}},
  {{0x8a885d04,0x1ceb,0x11c9,{0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60}},{2,0}},
  &access_rpc_table, 0, NULL, NULL, NULL, 0
};
struct access_echo { SOCKET socket; };
static struct access_echo access_echoes[16];
static DWORD WINAPI access_echo(void *data) {
  SOCKET listener = ((struct access_echo *)data)->socket; int type, size = sizeof(type); need(!getsockopt(listener,SOL_SOCKET,SO_TYPE,(char *)&type,&size));
  for (unsigned i = 0; i < 64; i++) {
    SOCKET socket = listener; SOCKADDR_STORAGE peer; int length = sizeof(peer);
    if (type == SOCK_STREAM) { socket = accept(listener,NULL,NULL); if (socket == INVALID_SOCKET) return 0; }
    char bytes[32]; int used = type == SOCK_DGRAM ? recvfrom(socket,bytes,32,0,(SOCKADDR *)&peer,&length) : recv(socket,bytes,32,MSG_WAITALL);
    if (used == SOCKET_ERROR) { if (socket != listener) closesocket(socket); return 0; }
    if (used == 32 && !memcmp(bytes,nonce,32)) need((type == SOCK_DGRAM ? sendto(socket,bytes,32,0,(SOCKADDR *)&peer,length) : send(socket,bytes,32,0)) == 32);
    if (socket != listener) need(!closesocket(socket));
  }
  return 0;
}
static HANDLE access_echo_threads[16], access_alpc_thread;
struct access_port_message {
  union { struct { USHORT dataLength,totalLength; } lengths; ULONG length; } first;
  union { struct { USHORT type,offset; } fields; ULONG zero; } second;
  CLIENT_ID client; ULONG messageId; SIZE_T view;
};
C_ASSERT(sizeof(struct access_port_message) == 40);
struct access_alpc_message { struct access_port_message header; char bytes[32]; };
static DWORD WINAPI access_alpc_accept(void *unused) {
  (void)unused;
  typedef NTSTATUS (NTAPI *receive_message)(HANDLE,ULONG,void *,void *,void *,SIZE_T *,void *,LARGE_INTEGER *);
  typedef NTSTATUS (NTAPI *accept_port)(PHANDLE,HANDLE,ULONG,POBJECT_ATTRIBUTES,void *,void *,void *,void *,BOOLEAN);
  receive_message receive = (receive_message)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtAlpcSendWaitReceivePort");
  accept_port accept = (accept_port)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtAlpcAcceptConnectPort"); need(receive && accept);
  for (unsigned accepted = 0; accepted < 64;) { struct access_alpc_message message = {0}; SIZE_T size = sizeof(message); LARGE_INTEGER timeout; timeout.QuadPart = -10000000;
    NTSTATUS result = receive(access_alpc,0,NULL,NULL,&message,&size,NULL,&timeout);
    if (result == (NTSTATUS)0x00000102) { if (access_controls_closed) return 0; continue; }
    if (result < 0 && access_controls_closed) return 0;
    need(result == 0 && size <= sizeof(message) && message.header.first.lengths.dataLength == 32 && !memcmp(message.bytes,nonce,32));
    HANDLE connection = NULL; need(accept(&connection,access_alpc,0,NULL,NULL,NULL,&message,NULL,TRUE) == 0 && connection && CloseHandle(connection)); accepted++;
  }
  return 0;
}
static void access_control_objects(void) {
  need(access_mode && ownership_stage == 5 && !access_controls_ready && !access_controls_closed);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE); wchar_t name[256];
  need(swprintf_s(name, 256, L"\\\\.\\pipe\\NativeProof-%hs", nonce) > 0);
  access_pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 64, 64, 0, &sa); need(access_pipe != INVALID_HANDLE_VALUE);
  need(swprintf_s(name, 256, L"\\RPC Control\\NativeProof-%hs", nonce) > 0);
  UNICODE_STRING portName = {(USHORT)(wcslen(name) * sizeof(wchar_t)), (USHORT)(wcslen(name) * sizeof(wchar_t)), name};
  OBJECT_ATTRIBUTES object = {sizeof(object), NULL, &portName, OBJ_CASE_INSENSITIVE, sd, NULL};
  typedef NTSTATUS (NTAPI *create_port)(PHANDLE, POBJECT_ATTRIBUTES, void *);
  struct access_port_attributes { ULONG flags; SECURITY_QUALITY_OF_SERVICE qos;
    SIZE_T messageLength, bandwidth, pool, section, view, total; ULONG duplicates, reserved; } attributes = {0};
  C_ASSERT(sizeof(struct access_port_attributes) == 72);
  attributes.qos.Length = sizeof(attributes.qos); attributes.qos.ImpersonationLevel = SecurityImpersonation;
  attributes.qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING; attributes.qos.EffectiveOnly = TRUE;
  attributes.messageLength = sizeof(struct access_alpc_message);
  create_port create = (create_port)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAlpcCreatePort");
  need(create && create(&access_alpc, &object, &attributes) == 0 && access_alpc);
  need(swprintf_s(name, 256, L"NativeProof-%hs", nonce) > 0 && RpcMgmtSetAuthorizationFn(access_rpc_auth) == RPC_S_OK &&
    RpcServerUseProtseqEpW((RPC_WSTR)L"ncalrpc", 1, (RPC_WSTR)name, sd) == RPC_S_OK &&
    RpcServerRegisterIfEx((RPC_IF_HANDLE)&access_rpc_interface, NULL, NULL, RPC_IF_AUTOLISTEN | RPC_IF_ALLOW_LOCAL_ONLY, 1, NULL) == RPC_S_OK);
  access_alpc_thread = CreateThread(NULL,0,access_alpc_accept,NULL,0,NULL); need(access_alpc_thread);
  access_rpc_ready = access_controls_ready = TRUE; LocalFree(sd); printf("{\"ready\":true}");
}
static void access_control_state(const char *id, DWORD verifierPid) {
  need(access_controls_ready && !access_controls_closed && strlen(id) > 0 && strlen(id) < 64);
  struct access_control_view view = {0}; view.record = case_record; view.payload=ownership_count ? ownership_processes[0] : NULL; strcpy_s(view.id, 64, id);
  for (unsigned i=0;i<access_control_count;i++) if (!strcmp(access_controls[i].id,id)) { view=access_controls[i]; goto export_control; }
  const char *fileIds[] = {"metadata-write", "pointer-write", "pointer-delete", "pointer-replace", "parent-delete", "parent-replace", "custody", "checkout", "configuration", "credentials", "outside-write"};
  const unsigned slots[] = {5,4,4,4,2,2,0,6,7,8,9}; BOOL found = FALSE;
  for (unsigned i = 0; i < sizeof(slots)/sizeof(slots[0]); i++) if (!strcmp(id, fileIds[i])) {
    view.kind = 1; view.index = access_indices[slots[i]]; view.object = entries[view.index].file.handle; wcscpy_s(view.target, 4096, entries[view.index].path); found = TRUE; break;
  }
  if (!found && !strcmp(id, "registry")) { view.kind = 2; need(swprintf_s(view.target, 4096, L"HKLM\\SOFTWARE\\NativeProof\\%hs", nonce) > 0); found = TRUE; }
  if (!found && !strcmp(id, "host-pipe")) { view.kind = 3; view.object = access_pipe; need(swprintf_s(view.target, 4096, L"\\\\.\\pipe\\NativeProof-%hs", nonce) > 0); found = TRUE; }
  if (!found && !strcmp(id, "alpc")) { view.kind = 4; view.object = access_alpc; need(swprintf_s(view.target, 4096, L"\\RPC Control\\NativeProof-%hs", nonce) > 0); found = TRUE; }
  if (!found && !strcmp(id, "rpc")) { view.kind = 5; need(swprintf_s(view.target, 4096, L"ncalrpc:[NativeProof-%hs]", nonce) > 0); found = TRUE; }
  if (!found && !strcmp(id, "com")) { view.kind = 6; wcscpy_s(view.target, 4096, L"TaskScheduler"); found = TRUE; }
  if (!found && !strcmp(id, "wmi")) { view.kind = 7; wcscpy_s(view.target, 4096, L"ROOT\\CIMV2"); found = TRUE; }
  if (!found && !strcmp(id, "delegation")) { view.kind = 8; view.object = ownership_launcher.hProcess; need(swprintf_s(view.target, 4096, L"%lu", GetProcessId(ownership_launcher.hProcess)) > 0); found = TRUE; }
  if (!found) {
    /* Socket controls are created with fixed bind families and independently
     * read endpoints. The caller cannot supply arbitrary server code. */
    view.kind = 9; BOOL v6 = strstr(id, "-v6-") != NULL, udp = strstr(id, "-udp") != NULL;
    need((strstr(id, "-v4-") || v6) && (strstr(id, "-tcp") || udp));
    BOOL wildcard = !strncmp(id, "wildcard-listener-", 18), routed = !strncmp(id, "host-network-", 13), cross = !strncmp(id, "cross-allocation-", 17), foreign = !strncmp(id, "foreign-sender-", 15);
    need(wildcard || routed || cross || foreign || !strncmp(id, "host-listener-", 14));
    if (foreign) {
      unsigned index = (v6 ? 4 : 0) + (udp ? 2 : 0) + 1; need(index < case_socket_count && ownership_count == 2 && access_payload_sockets[index]);
      view.object = (HANDLE)case_sockets[index]; view.peer = ownership_processes[1]; view.peerToken = ownership_tokens[1];
      need(!WSADuplicateSocketW(case_sockets[index], verifierPid, &view.socketInfo));
    } else {
      need(access_listener_count < 16); WSADATA data; need(!WSAStartup(MAKEWORD(2,2), &data));
      SOCKET socket = WSASocketW(v6 ? AF_INET6 : AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, udp ? IPPROTO_UDP : IPPROTO_TCP, NULL, 0, WSA_FLAG_NO_HANDLE_INHERIT); need(socket != INVALID_SOCKET);
      BOOL exclusive = TRUE; need(!setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&exclusive, sizeof(exclusive)));
      if (v6) need(!setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&exclusive, sizeof(exclusive)));
      SOCKADDR_STORAGE address = {0}; unsigned length;
      if (v6) { SOCKADDR_IN6 *a = (void *)&address; a->sin6_family = AF_INET6; a->sin6_addr = wildcard ? in6addr_any : in6addr_loopback; length = sizeof(*a); }
      else { SOCKADDR_IN *a = (void *)&address; a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(wildcard ? INADDR_ANY : INADDR_LOOPBACK); length = sizeof(*a); }
      if (routed) {
        ULONG bytes = 0; need(GetAdaptersAddresses(v6 ? AF_INET6 : AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, NULL, &bytes) == ERROR_BUFFER_OVERFLOW && bytes && bytes <= 1048576);
        IP_ADAPTER_ADDRESSES *adapters = calloc(bytes, 1); need(adapters && GetAdaptersAddresses(v6 ? AF_INET6 : AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, adapters, &bytes) == NO_ERROR);
        BOOL reached = FALSE; for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter && !reached; adapter = adapter->Next) if (adapter->OperStatus == IfOperStatusUp && adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
          for (IP_ADAPTER_UNICAST_ADDRESS *item = adapter->FirstUnicastAddress; item; item = item->Next) if (item->Address.lpSockaddr->sa_family == (v6 ? AF_INET6 : AF_INET) &&
            item->DadState == IpDadStatePreferred && (!v6 || (!IN6_IS_ADDR_LINKLOCAL(&((SOCKADDR_IN6 *)item->Address.lpSockaddr)->sin6_addr) && !((SOCKADDR_IN6 *)item->Address.lpSockaddr)->sin6_scope_id))) {
            need(item->Address.iSockaddrLength == (int)length); memcpy(&address, item->Address.lpSockaddr, length); reached = TRUE; break; }
        free(adapters); need(reached);
      }
      if (cross) {
        need(access_other_peer.process.hProcess && WaitForSingleObject(access_other_peer.process.hProcess,0)==WAIT_TIMEOUT && !closesocket(socket) && !WSACleanup());
        char reply[4096]; access_peer_command(&access_other_peer,L"listen",v6 ? L"v6" : L"v4",udp ? L"udp" : L"tcp",reply,sizeof(reply));
        view.object=(HANDLE)(ULONG_PTR)access_reply_handle(reply); view.peer=access_other_peer.process.hProcess; view.peerToken=access_other_peer.token;
        goto retain_control;
      }
      need(!bind(socket, (SOCKADDR *)&address, length) && (udp || !listen(socket, 2)));
      access_listeners[access_listener_count] = socket; access_echoes[access_listener_count].socket = socket;
      access_echo_threads[access_listener_count] = CreateThread(NULL,0,access_echo,&access_echoes[access_listener_count],0,NULL); need(access_echo_threads[access_listener_count]);
      access_listener_count++; view.object = (HANDLE)socket;
      need(!WSADuplicateSocketW(socket, verifierPid, &view.socketInfo));
    }
  }
retain_control:
  need(access_control_count < 38); access_controls[access_control_count++]=view;
export_control:
  if (view.kind==9 && !strncmp(id,"cross-allocation-",17)) {
    wchar_t pid[16],handle[32]; char reply[4096]; need(swprintf_s(pid,16,L"%lu",verifierPid)>0 && swprintf_s(handle,32,L"%llu",(ULONGLONG)(ULONG_PTR)view.object)>0);
    access_peer_command(&access_other_peer,L"socket-info",pid,handle,reply,sizeof(reply)); const char *bytes=strstr(reply,"\"hex\":\""); need(bytes); bytes+=7;
    for (unsigned i=0;i<sizeof(view.socketInfo);i++) ((BYTE *)&view.socketInfo)[i]=(BYTE)(nibble(bytes[i*2])*16+nibble(bytes[i*2+1])); need(bytes[sizeof(view.socketInfo)*2]=='"');
  } else if (view.kind==9) need(!WSADuplicateSocketW((SOCKET)view.object,verifierPid,&view.socketInfo));
  printf("{\"hex\":\""); hex((BYTE *)&view, sizeof(view)); printf("\"}");
}
static void verify_access_control(unsigned subject, unsigned custody, const char *id, const char *hexBytes) {
  need(subject < process_count && custody < count && strlen(hexBytes) == sizeof(struct access_control_view)*2);
  struct access_control_view view; for (unsigned i = 0; i < sizeof(view); i++) ((BYTE *)&view)[i] = (BYTE)(nibble(hexBytes[i*2])*16+nibble(hexBytes[i*2+1]));
  struct case_account_record record; account_record(entries[custody].path, &record); need(!memcmp(&record, &view.record, sizeof(record)) && !strcmp(view.id, id));
  HANDLE source = duplicate_process_owner(subject); need(system_process(source)); char targetPin[65], sourcePin[65];
  BOOL available = FALSE; unsigned kind = view.kind;
  if (kind == 1) {
    need(view.index < count && !_wcsicmp(view.target, entries[view.index].path)); HANDLE file = access_duplicate(source, view.object); struct held_file held = {0}; held.handle = file;
    need(GetFileInformationByHandleEx(file, FileIdInfo, &held.id, sizeof(held.id))); char text[128];
    need(sprintf_s(text, sizeof(text), "%016llx:", held.id.VolumeSerialNumber) > 0); for (unsigned i = 0; i < 16; i++) need(sprintf_s(text+17+i*2, sizeof(text)-17-i*2, "%02x", held.id.FileId.Identifier[i]) == 2);
    sum((BYTE *)text, (DWORD)strlen(text), targetPin); PSECURITY_DESCRIPTOR sd = file_sd(file, SE_FILE_OBJECT); PACL dacl; BOOL present, defaulted; PSID owner, system;
    need(ConvertStringSidToSidW(L"S-1-5-18", &system) && GetSecurityDescriptorOwner(sd, &owner, &defaulted) && EqualSid(owner, system) &&
      GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present && dacl);
    HANDLE original, token; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &original) && DuplicateToken(original, SecurityImpersonation, &token));
    GENERIC_MAPPING map = {FILE_GENERIC_READ,FILE_GENERIC_WRITE,FILE_GENERIC_EXECUTE,FILE_ALL_ACCESS}; BYTE privileges[65536]; DWORD size = sizeof(privileges), granted; BOOL allowed;
    need(AccessCheck(sd, token, MAXIMUM_ALLOWED, &map, (PPRIVILEGE_SET)privileges, &size, &granted, &allowed) && allowed && (granted & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);
    available = TRUE; LocalFree(system); LocalFree(sd); need(CloseHandle(original) && CloseHandle(token) && CloseHandle(file));
  } else if (kind == 2) {
    wchar_t name[256]; need(swprintf_s(name, 256, L"SOFTWARE\\NativeProof\\%hs", record.nonce) > 0); HKEY key;
    need(RegOpenKeyExW(HKEY_LOCAL_MACHINE, name, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS);
    DWORD children, values; FILETIME written; need(RegQueryInfoKeyW(key,NULL,NULL,NULL,&children,NULL,NULL,&values,NULL,NULL,NULL,&written) == ERROR_SUCCESS && !children && !values && RegCloseKey(key) == ERROR_SUCCESS);
    /* JS derives the same registry identity from independently read native
     * name and write time, retaining those fields instead of approving a hash. */
    strcpy_s(targetPin, 65, ""); available = TRUE;
  } else if (kind == 3 || kind == 4) {
    HANDLE handle = access_duplicate(source, view.object); PSECURITY_DESCRIPTOR sd; char hash[65];
    need(GetSecurityInfo(handle,kind == 3 ? SE_FILE_OBJECT : SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,NULL,NULL,NULL,NULL,&sd) == ERROR_SUCCESS);
    security(handle, kind == 3 ? SE_FILE_OBJECT : SE_KERNEL_OBJECT, TRUE, hash);
    if (kind == 3) { HANDLE client = CreateFileW(view.target,GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL); DWORD used; char bytes[32]; need(client != INVALID_HANDLE_VALUE && WriteFile(client,record.nonce,32,&used,NULL) && used==32 && ReadFile(handle,bytes,32,&used,NULL) && used==32 && !memcmp(bytes,record.nonce,32) && WriteFile(handle,bytes,32,&used,NULL) && used==32 && ReadFile(client,bytes,32,&used,NULL) && used==32 && !memcmp(bytes,record.nonce,32) && CloseHandle(client) && DisconnectNamedPipe(handle)); }
    else { typedef NTSTATUS (NTAPI *connect_port)(PHANDLE,PUNICODE_STRING,POBJECT_ATTRIBUTES,void *,ULONG,PSID,void *,PULONG,void *,void *,LARGE_INTEGER *);
      connect_port connect = (connect_port)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtAlpcConnectPort"); UNICODE_STRING name = {(USHORT)(wcslen(view.target)*2),(USHORT)(wcslen(view.target)*2),view.target};
      HANDLE client = NULL; struct access_alpc_message message={0}; message.header.first.lengths.dataLength=32; message.header.first.lengths.totalLength=sizeof(message); memcpy(message.bytes,record.nonce,32); ULONG used=sizeof(message); LARGE_INTEGER timeout; timeout.QuadPart = -100000000;
      need(connect && connect(&client,&name,NULL,NULL,0,NULL,&message,&used,NULL,NULL,&timeout) == 0 && client && used==sizeof(message) && !memcmp(message.bytes,record.nonce,32) && CloseHandle(client)); }
    sum((BYTE *)sd, GetSecurityDescriptorLength(sd), targetPin); LocalFree(sd); need(CloseHandle(handle)); available = TRUE;
  } else if (kind == 5) { RPC_BINDING_HANDLE binding; need(RpcBindingFromStringBindingW((RPC_WSTR)view.target, &binding) == RPC_S_OK && RpcMgmtIsServerListening(binding) == RPC_S_OK && RpcBindingFree(&binding) == RPC_S_OK);
    sum((BYTE *)view.target, (DWORD)wcslen(view.target)*sizeof(wchar_t), targetPin); available = TRUE;
  } else if (kind == 6 || kind == 7) {
    if (kind == 6) { ITaskService *service; VARIANT empty; VariantInit(&empty); need(SUCCEEDED(CoCreateInstance(&CLSID_TaskScheduler,NULL,CLSCTX_INPROC_SERVER,&IID_ITaskService,(void **)&service)) && SUCCEEDED(ITaskService_Connect(service,empty,empty,empty,empty))); ITaskService_Release(service); }
    else { IWbemLocator *locator; IWbemServices *services; BSTR name = SysAllocString(L"ROOT\\CIMV2"); need(name && SUCCEEDED(CoCreateInstance(&CLSID_WbemLocator,NULL,CLSCTX_INPROC_SERVER,&IID_IWbemLocator,(void **)&locator)) && SUCCEEDED(IWbemLocator_ConnectServer(locator,name,NULL,NULL,NULL,0,NULL,NULL,&services))); IWbemServices_Release(services); IWbemLocator_Release(locator); SysFreeString(name); }
    sum((BYTE *)view.target, (DWORD)wcslen(view.target)*sizeof(wchar_t), targetPin); available = TRUE;
  } else if (kind == 8) {
    HANDLE process = access_duplicate(source, view.object), token; need(system_process(process) && OpenProcessToken(process, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &token));
    sum((BYTE *)view.target,(DWORD)wcslen(view.target)*sizeof(wchar_t),targetPin); need(CloseHandle(process) && CloseHandle(token)); available = TRUE;
  } else need(kind == 9);
  need(available || kind == 9); DWORD denialCode=0;
  if (kind>=3 && kind<=8) {
    HANDLE payload=access_duplicate(source,view.payload), token; need(WaitForSingleObject(payload,0)==WAIT_TIMEOUT && OpenProcessToken(payload,TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,&token)); wchar_t *sid=token_sid(token); need(!wcscmp(sid,record.accountSid)); LocalFree(sid);
    need(ImpersonateLoggedOnUser(token));
    if (kind==3) { HANDLE client=CreateFileW(view.target,GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL); denialCode=GetLastError(); need(client==INVALID_HANDLE_VALUE && denialCode==ERROR_ACCESS_DENIED); }
    else if (kind==4) { typedef NTSTATUS (NTAPI *connect_port)(PHANDLE,PUNICODE_STRING,POBJECT_ATTRIBUTES,void *,ULONG,PSID,void *,PULONG,void *,void *,LARGE_INTEGER *); connect_port connect=(connect_port)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtAlpcConnectPort"); UNICODE_STRING name={(USHORT)(wcslen(view.target)*2),(USHORT)(wcslen(view.target)*2),view.target}; HANDLE client=NULL; LARGE_INTEGER timeout; timeout.QuadPart=-10000000; need(connect && connect(&client,&name,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,&timeout)==(NTSTATUS)0xc0000022 && !client); denialCode=5; }
    else if (kind==5) { RPC_BINDING_HANDLE binding; need(RpcBindingFromStringBindingW((RPC_WSTR)view.target,&binding)==RPC_S_OK); denialCode=RpcMgmtIsServerListening(binding); need(denialCode==RPC_S_ACCESS_DENIED && RpcBindingFree(&binding)==RPC_S_OK); }
    else if (kind==6) { ITaskService *service=NULL; VARIANT empty; VariantInit(&empty); HRESULT result=CoCreateInstance(&CLSID_TaskScheduler,NULL,CLSCTX_INPROC_SERVER,&IID_ITaskService,(void **)&service); if (SUCCEEDED(result)) { result=ITaskService_Connect(service,empty,empty,empty,empty); ITaskService_Release(service); } denialCode=(DWORD)result; need(denialCode==0x80070005); }
    else if (kind==7) { IWbemLocator *locator=NULL; IWbemServices *services=NULL; BSTR name=SysAllocString(L"ROOT\\CIMV2"); need(name); HRESULT result=CoCreateInstance(&CLSID_WbemLocator,NULL,CLSCTX_INPROC_SERVER,&IID_IWbemLocator,(void **)&locator); if (SUCCEEDED(result)) { result=IWbemLocator_ConnectServer(locator,name,NULL,NULL,NULL,0,NULL,NULL,&services); if (services) IWbemServices_Release(services); IWbemLocator_Release(locator); } SysFreeString(name); denialCode=(DWORD)result; need(denialCode==0x80070005 || denialCode==0x80041003); }
    else { HANDLE process=access_duplicate(source,view.object), delegated=NULL; need(!OpenProcessToken(process,TOKEN_DUPLICATE | TOKEN_IMPERSONATE,&delegated) && !delegated && GetLastError()==ERROR_ACCESS_DENIED && CloseHandle(process)); denialCode=5; }
    need(RevertToSelf() && CloseHandle(token) && CloseHandle(payload));
  }
  printf("{\"id\":\"%s\",\"nonce\":\"%s\",\"controller\":", id, record.nonce); retained_identity(source, tokens[subject], sessions[subject]);
  printf(",\"kind\":%u,\"denialCode\":%lu,\"targetHex\":\"",kind,denialCode); hex((BYTE *)view.target,(DWORD)wcslen(view.target)*sizeof(wchar_t));
  printf("\",\"targetIdentitySha256\":\"%s\",\"endpoint\":",kind == 9 ? "" : targetPin);
  if (kind != 9) printf("null"); else {
    WSADATA data; need(!WSAStartup(MAKEWORD(2,2),&data)); SOCKET socket = WSASocketW(FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,&view.socketInfo,0,WSA_FLAG_NO_HANDLE_INHERIT); need(socket != INVALID_SOCKET);
    SOCKADDR_STORAGE address; int length = sizeof(address), type, size = sizeof(type), exclusive, option = sizeof(exclusive);
    need(!getsockname(socket,(SOCKADDR *)&address,&length) && !getsockopt(socket,SOL_SOCKET,SO_TYPE,(char *)&type,&size) && !getsockopt(socket,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(char *)&exclusive,&option) && exclusive);
    BOOL v6 = address.ss_family == AF_INET6; need(v6 || address.ss_family == AF_INET); wchar_t bindAddress[64], destination[64];
    need(InetNtopW(v6 ? AF_INET6 : AF_INET,v6 ? (void *)&((SOCKADDR_IN6 *)&address)->sin6_addr : (void *)&((SOCKADDR_IN *)&address)->sin_addr,bindAddress,64));
    wcscpy_s(destination,64,!wcscmp(bindAddress,L"0.0.0.0") ? L"127.0.0.1" : !wcscmp(bindAddress,L"::") ? L"::1" : bindAddress);
    unsigned port = ntohs(v6 ? ((SOCKADDR_IN6 *)&address)->sin6_port : ((SOCKADDR_IN *)&address)->sin_port); need(port >= 1024);
    HANDLE socketOwner=source; if (view.peer && !strncmp(id,"cross-allocation-",17)) socketOwner=access_duplicate(source,view.peer);
    struct verify_handles *handles = handle_inventory(); void *original = NULL, *actual = NULL;
    for (ULONG_PTR i = 0; i < handles->count; i++) { if (handles->entries[i].pid == GetProcessId(socketOwner) && handles->entries[i].handle == (ULONG_PTR)view.object) original = handles->entries[i].object;
      if (handles->entries[i].pid == GetCurrentProcessId() && handles->entries[i].handle == (ULONG_PTR)socket) actual = handles->entries[i].object; }
    need(original && original == actual); free(handles); if (socketOwner!=source) need(CloseHandle(socketOwner)); char seed[128]; need(sprintf_s(seed,sizeof(seed),"%s:%p",record.context,actual)>0); sum((BYTE *)seed,(DWORD)strlen(seed),sourcePin);
    if (strncmp(id,"foreign-sender-",15)) {
      SOCKET client = WSASocketW(v6 ? AF_INET6 : AF_INET,type,type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP,NULL,0,WSA_FLAG_NO_HANDLE_INHERIT); need(client != INVALID_SOCKET);
      DWORD timeout = 10000; need(!setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout)) && !setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(timeout)));
      if (v6) need(InetPtonW(AF_INET6,destination,&((SOCKADDR_IN6 *)&address)->sin6_addr) == 1); else need(InetPtonW(AF_INET,destination,&((SOCKADDR_IN *)&address)->sin_addr) == 1);
      if (type == SOCK_STREAM) need(!connect(client,(SOCKADDR *)&address,length));
      need((type == SOCK_DGRAM ? sendto(client,record.nonce,32,0,(SOCKADDR *)&address,length) : send(client,record.nonce,32,0)) == 32);
      char echo[32]; need((type == SOCK_DGRAM ? recvfrom(client,echo,32,0,NULL,NULL) : recv(client,echo,32,MSG_WAITALL)) == 32 && !memcmp(echo,record.nonce,32) && !closesocket(client));
    }
    printf("{\"family\":\"%s\",\"protocol\":\"%s\",\"address\":\"%ls\",\"bindAddress\":\"%ls\",\"port\":%u,\"socketIdentitySha256\":\"%s\",\"identity\":",v6?"v6":"v4",type==SOCK_DGRAM?"udp":"tcp",destination,bindAddress,port,sourcePin);
    if (view.peer) { HANDLE peer = access_duplicate(source,view.peer), token = access_duplicate(source,view.peerToken); need(WaitForSingleObject(peer,0)==WAIT_TIMEOUT);
      if (!strncmp(id,"cross-allocation-",17)) { wchar_t home[4096], name[21]; struct case_account_record other; need(swprintf_s(home,4096,L"%ls\\access-peer",entries[custody].path)>0); account_record(home,&other);
        char seed[128],expected[65]; need(sprintf_s(seed,sizeof(seed),"%s:access-peer",record.context)>0); sum((BYTE *)seed,(DWORD)strlen(seed),expected); need(!strcmp(other.context,expected) && swprintf_s(name,21,L"np_%.16hs",other.nonce)>0); account_check(name,other.accountSid);
        wchar_t *sid=token_sid(token); need(!wcscmp(sid,other.accountSid) && wcscmp(sid,record.accountSid)); LocalFree(sid); TOKEN_GROUPS *groups=token_info(token,TokenGroups); TOKEN_PRIVILEGES *privileges=token_info(token,TokenPrivileges); LUID notify; need(LookupPrivilegeValueW(NULL,SE_CHANGE_NOTIFY_NAME,&notify) && privileges->PrivilegeCount<=1);
        for (DWORD i=0;i<privileges->PrivilegeCount;i++) need(!memcmp(&privileges->Privileges[i].Luid,&notify,sizeof(LUID))); free(privileges); for (DWORD i=0;i<groups->GroupCount;i++) need(!(groups->Groups[i].Attributes & SE_GROUP_ENABLED) || (groups->Groups[i].Attributes & SE_GROUP_INTEGRITY)); free(groups);
        wchar_t image[4096]; DWORD length=4096; need(QueryFullProcessImageNameW(peer,0,image,&length)); const wchar_t *leaf=wcsrchr(entries[6].path,'\\'); wchar_t wanted[4096]; need(leaf && swprintf_s(wanted,4096,L"%ls%ls",home,leaf)>0 && !_wcsicmp(wanted,image)); struct held_file held=hold_shared(image,FALSE,FALSE,GENERIC_READ,FALSE); pin(&held,entries[6].pin); char pin[65]; signature(&held,entries[6].signature,pin); close_file(&held);
      }
      retained_identity(peer,token,0); need(CloseHandle(peer)&&CloseHandle(token)); }
    else retained_identity(source,tokens[subject],sessions[subject]); printf("}"); need(!closesocket(socket)&&!WSACleanup());
  }
  printf("}"); need(CloseHandle(source));
}

static void verify_access_socket(unsigned subject, const char *context, const char *handle, const char *hexBytes) {
  need(subject<process_count && strlen(context)==64 && strlen(hexBytes)==sizeof(WSAPROTOCOL_INFOW)*2);
  HANDLE process=duplicate_process_owner(subject); need(WaitForSingleObject(process,0)==WAIT_TIMEOUT);
  WSAPROTOCOL_INFOW info; for (unsigned i=0;i<sizeof(info);i++) ((BYTE *)&info)[i]=(BYTE)(nibble(hexBytes[i*2])*16+nibble(hexBytes[i*2+1]));
  WSADATA data; need(!WSAStartup(MAKEWORD(2,2),&data)); SOCKET socket=WSASocketW(FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,&info,0,WSA_FLAG_NO_HANDLE_INHERIT); need(socket!=INVALID_SOCKET);
  struct verify_handles *inventory=handle_inventory(); void *original=NULL,*actual=NULL;
  for (ULONG_PTR i=0;i<inventory->count;i++) { if (inventory->entries[i].pid==GetProcessId(process) && inventory->entries[i].handle==(ULONG_PTR)number(handle)) original=inventory->entries[i].object;
    if (inventory->entries[i].pid==GetCurrentProcessId() && inventory->entries[i].handle==(ULONG_PTR)socket) actual=inventory->entries[i].object; }
  need(original && original==actual); free(inventory); char seed[128],pin[65]; need(sprintf_s(seed,sizeof(seed),"%s:%p",context,actual)>0); sum((BYTE *)seed,(DWORD)strlen(seed),pin);
  SOCKADDR_STORAGE local,remote; int size=sizeof(local),remoteSize=sizeof(remote),type,typeSize=sizeof(type); need(!getsockname(socket,(SOCKADDR *)&local,&size) && !getsockopt(socket,SOL_SOCKET,SO_TYPE,(char *)&type,&typeSize));
  BOOL v6=local.ss_family==AF_INET6; need(v6 || local.ss_family==AF_INET); wchar_t address[64];
  need(InetNtopW(v6 ? AF_INET6 : AF_INET,v6 ? (void *)&((SOCKADDR_IN6 *)&local)->sin6_addr : (void *)&((SOCKADDR_IN *)&local)->sin_addr,address,64));
  printf("{\"identity\":"); retained_identity(process,tokens[subject],sessions[subject]); printf(",\"socketIdentitySha256\":\"%s\",\"protocol\":\"%s\",\"family\":\"%s\",\"localAddress\":\"%ls\",\"localPort\":%u,\"remote\":",pin,type==SOCK_DGRAM ? "udp" : "tcp",v6 ? "v6" : "v4",address,ntohs(v6 ? ((SOCKADDR_IN6 *)&local)->sin6_port : ((SOCKADDR_IN *)&local)->sin_port));
  if (getpeername(socket,(SOCKADDR *)&remote,&remoteSize)) { need(WSAGetLastError()==WSAENOTCONN); printf("null"); }
  else { need(remote.ss_family==local.ss_family && InetNtopW(v6 ? AF_INET6 : AF_INET,v6 ? (void *)&((SOCKADDR_IN6 *)&remote)->sin6_addr : (void *)&((SOCKADDR_IN *)&remote)->sin_addr,address,64));
    printf("{\"address\":\"%ls\",\"port\":%u}",address,ntohs(v6 ? ((SOCKADDR_IN6 *)&remote)->sin6_port : ((SOCKADDR_IN *)&remote)->sin_port)); }
  printf("}"); need(!closesocket(socket) && !WSACleanup() && CloseHandle(process));
}
static void access_foreign(const char *id,DWORD verifierPid) {
  need(access_mode && !access_controls_closed && access_foreign_socket==INVALID_SOCKET && !strncmp(id,"foreign-sender-",15)); BOOL v6=strstr(id,"-v6-")!=NULL,udp=strstr(id,"-udp")!=NULL;
  unsigned index=(v6 ? 4 : 0)+(udp ? 2 : 0)+1; SOCKADDR_STORAGE remote,local; int length=sizeof(remote); need(index<case_socket_count && !getsockname(case_sockets[index],(SOCKADDR *)&remote,&length));
  local=remote; if (v6) ((SOCKADDR_IN6 *)&local)->sin6_port=0; else ((SOCKADDR_IN *)&local)->sin_port=0;
  SOCKET socket=WSASocketW(v6 ? AF_INET6 : AF_INET,udp ? SOCK_DGRAM : SOCK_STREAM,udp ? IPPROTO_UDP : IPPROTO_TCP,NULL,0,WSA_FLAG_NO_HANDLE_INHERIT); need(socket!=INVALID_SOCKET && !bind(socket,(SOCKADDR *)&local,length));
  access_foreign_socket=socket; u_long nonblocking=1; need(!ioctlsocket(socket,FIONBIO,&nonblocking)); int result=udp ? sendto(socket,nonce,32,0,(SOCKADDR *)&remote,length) : connect(socket,(SOCKADDR *)&remote,length);
  DWORD error=result==SOCKET_ERROR ? WSAGetLastError() : 0; need(udp ? (result==32 || error==WSAEACCES) : (result==SOCKET_ERROR && (error==WSAEACCES || error==WSAEWOULDBLOCK)));
  WSAPROTOCOL_INFOW info; need(!WSADuplicateSocketW(socket,verifierPid,&info)); printf("{\"identity\":"); identity(GetCurrentProcess()); printf(",\"handle\":\"%llu\",\"nativeCode\":%lu,\"hex\":\"",(ULONGLONG)socket,error); hex((BYTE *)&info,sizeof(info)); printf("\"}");
}
static void access_controls_stop(void) {
  need(access_mode); InterlockedExchange(&access_controls_closed,TRUE); /* Fence new sockets/peers before termination. */
  if (access_foreign_socket!=INVALID_SOCKET) { need(!closesocket(access_foreign_socket)); access_foreign_socket=INVALID_SOCKET; }
  if (access_other_peer.process.hProcess) {
    need(TerminateJobObject(access_other_peer.job,126) && WaitForSingleObject(access_other_peer.process.hProcess,30000)==WAIT_OBJECT_0); JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    need(QueryInformationJobObject(access_other_peer.job,JobObjectBasicAccountingInformation,&accounting,sizeof(accounting),NULL) && !accounting.ActiveProcesses);
    wchar_t name[21]; need(swprintf_s(name,21,L"np_%.16hs",access_other_peer.record.nonce)>0); account_check(name,access_other_peer.record.accountSid);
    struct ownership_view view={0}; view.record=access_other_peer.record; view.count=1; view.processes[0]=access_other_peer.process.hProcess; view.tokens[0]=access_other_peer.token; ownership_census(&view);
    PSID sid; need(ConvertStringSidToSidW(access_other_peer.record.accountSid,&sid)); LSA_OBJECT_ATTRIBUTES attributes={0}; attributes.Length=sizeof(attributes); LSA_HANDLE policy;
    need(LsaOpenPolicy(NULL,&attributes,POLICY_LOOKUP_NAMES,&policy)==0 && LsaRemoveAccountRights(policy,sid,TRUE,NULL,0)==0 && LsaClose(policy)==0); LocalFree(sid); need(NetUserDel(NULL,name)==NERR_Success);
  }
  for (unsigned i=0;i<access_listener_count;i++) { need(!closesocket(access_listeners[i])); need(WaitForSingleObject(access_echo_threads[i],10000)==WAIT_OBJECT_0 && CloseHandle(access_echo_threads[i]) && !WSACleanup()); }
  access_listener_count=0;
  if (access_pipe && access_pipe!=INVALID_HANDLE_VALUE) { need(CloseHandle(access_pipe)); access_pipe=NULL; }
  if (access_alpc) { need(CloseHandle(access_alpc)); access_alpc=NULL; need(WaitForSingleObject(access_alpc_thread,10000)==WAIT_OBJECT_0 && CloseHandle(access_alpc_thread)); }
  if (access_rpc_ready) { need(RpcServerUnregisterIf((RPC_IF_HANDLE)&access_rpc_interface,NULL,TRUE)==RPC_S_OK); access_rpc_ready=FALSE; }
  printf("{\"fenced\":true}");
}

static void verify_access_peer_retired(unsigned subject,unsigned custody) {
  need(subject<process_count && custody<count && verified_jobs[subject] && WaitForSingleObject(processes[subject],0)==WAIT_OBJECT_0); JOBOBJECT_BASIC_ACCOUNTING_INFORMATION job; need(QueryInformationJobObject(verified_jobs[subject],JobObjectBasicAccountingInformation,&job,sizeof(job),NULL) && !job.ActiveProcesses); struct case_account_record original,other; account_record(entries[custody].path,&original);
  wchar_t home[4096],name[21]; need(swprintf_s(home,4096,L"%ls\\access-peer",entries[custody].path)>0); account_record(home,&other);
  char seed[128],expected[65]; need(sprintf_s(seed,sizeof(seed),"%s:access-peer",original.context)>0); sum((BYTE *)seed,(DWORD)strlen(seed),expected); need(!strcmp(other.context,expected));
  wchar_t *sid=token_sid(tokens[subject]); need(!wcscmp(sid,other.accountSid)); LocalFree(sid); struct ownership_view census={0}; census.record=other; ownership_census(&census);
  need(swprintf_s(name,21,L"np_%.16hs",other.nonce)>0); USER_INFO_1 *user; need(NetUserGetInfo(NULL,name,1,(BYTE **)&user)==NERR_UserNotFound);
  PSID userSid; need(ConvertStringSidToSidW(other.accountSid,&userSid)); LSA_OBJECT_ATTRIBUTES attributes={0}; attributes.Length=sizeof(attributes); LSA_HANDLE policy; LSA_UNICODE_STRING *rights=NULL; ULONG count=0;
  need(LsaOpenPolicy(NULL,&attributes,POLICY_LOOKUP_NAMES,&policy)==0); NTSTATUS status=LsaEnumerateAccountRights(policy,userSid,&rights,&count); need((status==0 && count==0) || status==(NTSTATUS)0xc0000034L); if (rights) LsaFreeMemory(rights); need(LsaClose(policy)==0); LocalFree(userSid);
  printf("{\"retired\":true,\"accountAbsent\":true,\"rightsAbsent\":true,\"contextSha256\":\"%s\"}",original.context);
}

static void verify_access_peer_policy(unsigned sourceSlot,unsigned custody,unsigned subject,const char *hexBytes) {
  need(sourceSlot<process_count && subject<process_count && custody<count && strlen(hexBytes)==sizeof(struct access_control_view)*2); struct access_control_view view;
  for (unsigned i=0;i<sizeof(view);i++) ((BYTE *)&view)[i]=(BYTE)(nibble(hexBytes[i*2])*16+nibble(hexBytes[i*2+1]));
  struct case_account_record record; account_record(entries[custody].path,&record); need(!memcmp(&record,&view.record,sizeof(record)) && view.kind<=1);
  HANDLE source=duplicate_process_owner(sourceSlot); need(system_process(source)); HANDLE process=access_duplicate(source,view.peer),token=access_duplicate(source,view.peerToken),job=access_duplicate(source,view.peerJob);
  FILETIME created,held,exited,kernel,user; need(GetProcessId(process)==GetProcessId(processes[subject]) && GetProcessTimes(process,&created,&exited,&kernel,&user) && GetProcessTimes(processes[subject],&held,&exited,&kernel,&user) && !memcmp(&created,&held,sizeof(created)) && WaitForSingleObject(process,0)==WAIT_TIMEOUT);
  wchar_t expected[4096],actual[4096],home[4096],name[21]; DWORD length=4096; wchar_t *sid=token_sid(token);
  if (view.kind) { struct case_account_record other; need(swprintf_s(home,4096,L"%ls\\access-peer",entries[custody].path)>0); account_record(home,&other); char seed[128],pin[65]; need(sprintf_s(seed,sizeof(seed),"%s:access-peer",record.context)>0); sum((BYTE *)seed,(DWORD)strlen(seed),pin); need(!strcmp(other.context,pin) && !wcscmp(sid,other.accountSid) && swprintf_s(name,21,L"np_%.16hs",other.nonce)>0); account_check(name,other.accountSid);
    const wchar_t *leaf=wcsrchr(entries[6].path,'\\'); need(leaf && swprintf_s(expected,4096,L"%ls%ls",home,leaf)>0);
  } else { need(!wcscmp(sid,record.accountSid)); wcscpy_s(expected,4096,entries[6].path); }
  LocalFree(sid); need(QueryFullProcessImageNameW(process,0,actual,&length) && !_wcsicmp(actual,expected)); struct held_file file=hold_shared(actual,FALSE,FALSE,GENERIC_READ,FALSE); pin(&file,entries[6].pin); char sig[65]; signature(&file,entries[6].signature,sig); close_file(&file);
  TOKEN_GROUPS *groups=token_info(token,TokenGroups); TOKEN_PRIVILEGES *privileges=token_info(token,TokenPrivileges); LUID notify; need(LookupPrivilegeValueW(NULL,SE_CHANGE_NOTIFY_NAME,&notify));
  for (DWORD i=0;i<groups->GroupCount;i++) need(!(groups->Groups[i].Attributes & SE_GROUP_ENABLED) || (groups->Groups[i].Attributes & SE_GROUP_INTEGRITY));
  need(privileges->PrivilegeCount<=(view.kind ? 1U : 0U)); for (DWORD i=0;i<privileges->PrivilegeCount;i++) need(!memcmp(&privileges->Privileges[i].Luid,&notify,sizeof(LUID))); free(groups); free(privileges);
  BOOL belongs; need(IsProcessInJob(process,job,&belongs) && belongs); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits; JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
  need(QueryInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits),NULL) && limits.BasicLimitInformation.LimitFlags==0x2008 && limits.BasicLimitInformation.ActiveProcessLimit==(view.kind ? 1U : 32U) && QueryInformationJobObject(job,JobObjectBasicUIRestrictions,&ui,sizeof(ui),NULL) && ui.UIRestrictionsClass==255);
  HANDLE threads=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0); need(threads!=INVALID_HANDLE_VALUE); THREADENTRY32 thread={sizeof(thread)}; unsigned found=0; need(Thread32First(threads,&thread));
  do { if (thread.th32OwnerProcessID==GetProcessId(process)) { HANDLE handle=OpenThread(THREAD_QUERY_INFORMATION,FALSE,thread.th32ThreadID); typedef NTSTATUS (NTAPI *query)(HANDLE,ULONG,PVOID,ULONG,PULONG); query get=(query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationThread"); ULONG suspendCount; need(handle && get && !get(handle,35,&suspendCount,sizeof(suspendCount),NULL) && suspendCount==1 && CloseHandle(handle)); found++; } } while (Thread32Next(threads,&thread)); need(GetLastError()==ERROR_NO_MORE_FILES && found==1 && CloseHandle(threads));
  if (view.kind) { need(!verified_jobs[subject]); verified_jobs[subject]=job; } else need(CloseHandle(job));
  printf("{\"parked\":true,\"imageSha256\":\"%s\",\"signatureSha256\":\"%s\"}",entries[6].pin,sig); need(CloseHandle(process) && CloseHandle(token) && CloseHandle(source));
}
static void recovery_case(unsigned custody, const char *context, const char *caseNonce, BOOL required);
static void verification(char **values, unsigned n) {
    if (!strcmp(values[0]+7,"access-peer-policy")) { need(n==6); verify_access_peer_policy(bounded_number(values[2],127),bounded_number(values[3],count-1),bounded_number(values[4],127),values[5]);
    } else if (!strcmp(values[0]+7,"access-peer-retired")) { need(n==4); verify_access_peer_retired(bounded_number(values[2],127),bounded_number(values[3],count-1));
    } else if (!strcmp(values[0]+7, "socket")) { need(n==6); verify_access_socket(bounded_number(values[2],127),values[3],values[4],values[5]);
    } else if (!strcmp(values[0]+7, "access-control")) { need(n == 6); verify_access_control(bounded_number(values[2],127),bounded_number(values[3],count-1),values[4],values[5]);
    } else if (!strcmp(values[0]+7, "receipt")) {
      need(n == 5 && strlen(values[4]) == 64); unsigned custody = bounded_number(values[2], count - 1), index = bounded_number(values[3], 4095);
      wchar_t name[96]; need(swprintf_s(name, 96, L"ownership-%u.json", index) > 0);
      HANDLE file = account_file(entries[custody].path, name, GENERIC_READ, OPEN_EXISTING); BYTE bytes[16384]; DWORD used; LARGE_INTEGER size;
      need(GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= sizeof(bytes) && ReadFile(file, bytes, (DWORD)size.QuadPart, &used, NULL) && used == size.QuadPart);
      char hash[65]; sum(bytes, used, hash); need(!strcmp(hash, values[4]) && CloseHandle(file)); printf("{\"hex\":\""); hex(bytes, used); printf("\"}");
    } else if (!strcmp(values[0]+7, "access")) { need(n == 6); verify_access(bounded_number(values[2], 127), bounded_number(values[3], count-1), values[4], values[5]);
    } else if (!strcmp(values[0]+7, "case")) { need(n == 6); verify_case(bounded_number(values[2], 127), bounded_number(values[3], count-1), values[4], values[5]);
    } else if (!strcmp(values[0]+7, "case-retired")) { need(n == 4); verify_case_retired(bounded_number(values[2], count-1), values[3]);
    } else if (!strcmp(values[0]+7, "case-recover")) {
      need(n == 6); recovery_case(bounded_number(values[2], count-1), values[3], values[4], bounded_number(values[5], 1));
    } else if (!strcmp(values[0]+7, "recovery-object")) {
      need(n == 3); struct entry entry = entries[bounded_number(values[2], count-1)];
      entry.file = hold_shared(entry.path, !strcmp(entry.kind,"directory"), TRUE, GENERIC_READ | ACCESS_SYSTEM_SECURITY, !strcmp(entry.kind,"mutable"));
      printf("{\"object\":"); inspect(&entry); printf(",\"security\":"); PSECURITY_DESCRIPTOR sd = file_sd(entry.file.handle, SE_FILE_OBJECT); sd_read(sd); LocalFree(sd); putchar('}'); close_file(&entry.file);
    } else if (!strcmp(values[0]+7, "recovery-jobs")) { need(n == 4); recovery_jobs(bounded_number(values[2], 127), values[3]);
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
      need(n == 6); wchar_t name[64]; decode_bounded(values[3], name, 64); verifier_task(values[2], name, values[4], bounded_number(values[5], 127));
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
  } else if (!strcmp(v[0], "prepare-batch")) {
    need(n>=3 && n<=18); unsigned total=0,emitted=0,deferredCount=0; wchar_t deferred[16][260]; printf("{\"records\":[");
    for (unsigned i=2;i<n;i++) {
      wchar_t leaf[260],name[4096]; decode_bounded(v[i],leaf,260); size_t length=wcslen(leaf);
      need(length>13 && !wcsncmp(leaf,L"windows-",8) && !wcscmp(leaf+length-5,L".json") &&
        wcsspn(leaf,L"abcdefghijklmnopqrstuvwxyz0123456789-.")==length && swprintf_s(name,4096,L"%ls\\%ls",preparation_directory,leaf)>0);
      struct held_file file=hold(name,FALSE,TRUE,GENERIC_READ); LARGE_INTEGER size;
      need(GetFileSizeEx(file.handle,&size) && size.QuadPart>0 && size.QuadPart<=1048576);
      if (size.QuadPart>60000-total) { wcscpy_s(deferred[deferredCount++],260,leaf); close_file(&file); continue; }
      DWORD used; BYTE *bytes=read_file(&file,(DWORD)size.QuadPart,&used); need(used==size.QuadPart); total+=used;
      char hash[65],dacl[65]; sum(bytes,used,hash); security(file.handle,SE_FILE_OBJECT,TRUE,dacl);
      FILE_ID_INFO again; need(GetFileInformationByHandleEx(file.handle,FileIdInfo,&again,sizeof(again)) && !memcmp(&again,&file.id,sizeof(again)));
      if (emitted++) putchar(','); printf("{\"nameHex\":\""); hex((BYTE *)leaf,wcslen(leaf)*2); printf("\",\"identity\":\""); file_id(&file);
      printf("\",\"daclSha256\":\"%s\",\"protectedParents\":true,\"sha256\":\"%s\",\"hex\":\"",dacl,hash); hex(bytes,used); printf("\"}"); SecureZeroMemory(bytes,used); free(bytes); close_file(&file);
    }
    printf("],\"deferred\":["); for (unsigned i=0;i<deferredCount;i++) { if(i) putchar(','); putchar('"'); hex((BYTE *)deferred[i],wcslen(deferred[i])*2); putchar('"'); } printf("]}");
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
/* Fixed file/Git/release operations. These resources are held by the System
 * custodian, independently of protocol producers and all case workers. */
static wchar_t operation_id[64]; static unsigned operation_slots[128], operation_count;
static BOOL operation_fenced, operation_closed[SLOTS];
static HANDLE file_objects[5]; static FILE_ID_INFO file_ids[5];
static void operation_no_creators(void);
struct operation_record_header { DWORD version,index,size; FILE_ID_INFO object; char context[65],sha256[65]; };
static void operation_record(const wchar_t *leaf,unsigned index,const BYTE *bytes,DWORD size) {
  need(case_token && size && size<=262144 && index<count);
  struct operation_record_header header={0},actual={0};
  header.version=1; header.index=index; header.size=size; strcpy_s(header.context,65,case_record.context);
  need(GetFileInformationByHandleEx(entries[index].file.handle,FileIdInfo,&header.object,sizeof(header.object))); sum(bytes,size,header.sha256);
  HANDLE file=account_file(entries[case_custody].path,leaf,GENERIC_WRITE,CREATE_NEW); DWORD used;
  need(WriteFile(file,&header,sizeof(header),&used,NULL) && used==sizeof(header) && WriteFile(file,bytes,size,&used,NULL) && used==size && FlushFileBuffers(file) && CloseHandle(file));
  file=account_file(entries[case_custody].path,leaf,GENERIC_READ,OPEN_EXISTING); BYTE *read=calloc(size,1); need(read);
  need(ReadFile(file,&actual,sizeof(actual),&used,NULL) && used==sizeof(actual) && !memcmp(&actual,&header,sizeof(header)) && ReadFile(file,read,size,&used,NULL) && used==size && !memcmp(bytes,read,size) && CloseHandle(file));
  SecureZeroMemory(read,size); free(read);
}
static unsigned operation_creations;
struct operation_creation { DWORD version,sequence,image,pid,session; ULONGLONG birth; wchar_t job[128],sid[256]; };
static struct operation_creation operation_creation_intent(unsigned image) {
  struct operation_creation intent={0}; intent.version=1; intent.sequence=operation_creations++; intent.image=image;
  need(intent.sequence<128 && swprintf_s(intent.job,128,L"NativeProof-Operation-%hs-%u",nonce,intent.sequence)>0);
  wchar_t leaf[64]; need(swprintf_s(leaf,64,L"operation-%u.intent",intent.sequence)>0); operation_record(leaf,image,(BYTE *)&intent,sizeof(intent)); return intent;
}
static HANDLE operation_creation_job(struct operation_creation *intent,SECURITY_ATTRIBUTES *attributes) {
  SetLastError(ERROR_SUCCESS);
  HANDLE job=CreateJobObjectW(attributes,intent->job); need(job && GetLastError()!=ERROR_ALREADY_EXISTS); return job;
}
static void operation_creation_birth(struct operation_creation *intent,HANDLE process,HANDLE token) {
  FILETIME born,ended,kernel,user; need(GetProcessTimes(process,&born,&ended,&kernel,&user));
  intent->pid=GetProcessId(process); intent->session=process_session(process); intent->birth=((ULONGLONG)born.dwHighDateTime<<32)|born.dwLowDateTime;
  wchar_t *sid=token_sid(token); wcscpy_s(intent->sid,256,sid); LocalFree(sid);
  wchar_t leaf[64]; need(swprintf_s(leaf,64,L"operation-%u.birth",intent->sequence)>0); operation_record(leaf,intent->image,(BYTE *)intent,sizeof(*intent));
}
static void git_baselines(void);
static unsigned operation_slot(unsigned position) { need(position < operation_count); unsigned index=operation_slots[position]; need(index<count && entries[index].file.handle); return index; }
static void operation_stop_job(HANDLE job) {
  BYTE bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)+32*sizeof(ULONG_PTR)]; JOBOBJECT_BASIC_PROCESS_ID_LIST *members=(void *)bytes;
  need(QueryInformationJobObject(job,JobObjectBasicProcessIdList,members,sizeof(bytes),NULL) && members->NumberOfAssignedProcesses==members->NumberOfProcessIdsInList && members->NumberOfProcessIdsInList<=32);
  HANDLE held[32]={0};
  for(unsigned i=0;i<members->NumberOfProcessIdsInList;i++) { BOOL joined; held[i]=OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,FALSE,(DWORD)members->ProcessIdList[i]);
    need(held[i] && IsProcessInJob(held[i],job,&joined) && joined); }
  need(TerminateJobObject(job,126));
  for(unsigned i=0;i<members->NumberOfProcessIdsInList;i++) need(WaitForSingleObject(held[i],5000)==WAIT_OBJECT_0 && CloseHandle(held[i]));
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION final; need(QueryInformationJobObject(job,JobObjectBasicAccountingInformation,&final,sizeof(final),NULL) && !final.ActiveProcesses);
}
static void operation_bind(char **v,unsigned n) {
  need(!*operation_id && case_token && case_job && n>=4); decode_bounded(v[2],operation_id,64); operation_count=bounded_number(v[3],126); need(n==4+operation_count);
  need(!wcsncmp(operation_id,L"files.",6) || !wcscmp(operation_id,L"git.fixed") || !wcscmp(operation_id,L"git.ordinary") || !wcscmp(operation_id,L"release"));
  for(unsigned i=0;i<operation_count;i++) { operation_slots[i]=bounded_number(v[4+i],count-1); need(entries[operation_slots[i]].file.handle); }
  if(!wcsncmp(operation_id,L"files.",6)) {
    need(operation_count==5 && operation_slots[0]==2); file_objects[0]=entries[operation_slot(0)].file.handle; file_objects[1]=entries[operation_slot(1)].file.handle;
    file_root_sharing(&entries[operation_slot(1)],&entries[operation_slot(0)]); file_objects[1]=entries[operation_slot(1)].file.handle;
    HANDLE retained; need(DuplicateHandle(GetCurrentProcess(),file_objects[1],GetCurrentProcess(),&retained,0,FALSE,DUPLICATE_SAME_ACCESS)); file_objects[1]=retained;
    for(unsigned i=0;i<2;i++) need(GetFileInformationByHandleEx(file_objects[i],FileIdInfo,&file_ids[i],sizeof(file_ids[i])));
  }
  if(!wcscmp(operation_id,L"git.ordinary")) git_baselines();
  printf("{\"bound\":true}");
}
typedef NTSTATUS (NTAPI *operation_create)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
static HANDLE operation_open(HANDLE parent,const wchar_t *name,BOOL directory,ACCESS_MASK access,BOOL optional) {
  operation_create create=(operation_create)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtCreateFile"); need(create && parent && *name && !wcschr(name,'\\') && !wcschr(name,':'));
  UNICODE_STRING text={(USHORT)(wcslen(name)*2),(USHORT)(wcslen(name)*2),(PWSTR)name}; OBJECT_ATTRIBUTES oa={sizeof(oa),parent,&text,0,NULL,NULL}; IO_STATUS_BLOCK io; HANDLE result=NULL;
  NTSTATUS status=create(&result,access | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,1,0x200000 | 0x20 | (directory ? 1 : 0x40),NULL,0);
  if(optional && status==(NTSTATUS)0xc0000034L) return NULL; need(!status && result && SetHandleInformation(result,HANDLE_FLAG_INHERIT,0)); return result;
}
static void operation_identity(HANDLE file) { struct held_file value={0}; value.handle=file; need(GetFileInformationByHandleEx(file,FileIdInfo,&value.id,sizeof(value.id))); file_id(&value); }
static void operation_bytes(HANDLE file) {
  LARGE_INTEGER size,zero={0}; BYTE bytes[4096]; DWORD read; need(GetFileSizeEx(file,&size) && size.QuadPart>=0 && size.QuadPart<=sizeof(bytes) && SetFilePointerEx(file,zero,NULL,FILE_BEGIN) && ReadFile(file,bytes,(DWORD)size.QuadPart,&read,NULL) && read==size.QuadPart); hex(bytes,read);
}
static void operation_file(HANDLE file,HANDLE named,BOOL directory,const wchar_t *name) {
  FILE_ID_INFO id,current; FILE_ATTRIBUTE_TAG_INFO tag; FILE_STANDARD_INFO info; char dacl[65];
  need(GetFileInformationByHandleEx(file,FileIdInfo,&id,sizeof(id)) && GetFileInformationByHandleEx(named,FileIdInfo,&current,sizeof(current)) && !memcmp(&id,&current,sizeof(id)) &&
    GetFileInformationByHandleEx(file,FileAttributeTagInfo,&tag,sizeof(tag)) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
    GetFileInformationByHandleEx(file,FileStandardInfo,&info,sizeof(info)) && !!info.Directory==directory);
  security(file,SE_FILE_OBJECT,TRUE,dacl);
  typedef NTSTATUS (NTAPI *query_file)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
  query_file query=(query_file)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationFile"); need(query); BYTE buffer[4096]; IO_STATUS_BLOCK io;
  NTSTATUS status=query(file,&io,buffer,sizeof(buffer),(FILE_INFORMATION_CLASS)21);
  need(status==(NTSTATUS)0xc0000034L || (!status && ((FILE_NAME_INFO *)buffer)->FileNameLength==0));
  need(!query(file,&io,buffer,sizeof(buffer),(FILE_INFORMATION_CLASS)22));
  if(directory) { FILE_CASE_SENSITIVE_INFO sensitive; need(!io.Information && GetFileInformationByHandleEx(file,FileCaseSensitiveInfo,&sensitive,sizeof(sensitive)) && !sensitive.Flags); }
  else { DWORD *stream=(void *)buffer; need(io.Information>=38 && !stream[0] && stream[1]==14 && !wmemcmp((wchar_t *)(buffer+24),L"::$DATA",7)); }
  wchar_t canonical[4096]; DWORD length=GetFinalPathNameByHandleW(named,canonical,4096,FILE_NAME_NORMALIZED | VOLUME_NAME_DOS); need(length && length<4096 && !wcscmp(wcsrchr(canonical,'\\')+1,name));
  printf("{\"identity\":\""); operation_identity(file); printf("\",\"namedIdentity\":\""); operation_identity(named);
  printf("\",\"ownerSid\":\"S-1-5-18\",\"systemOnlyDacl\":true,\"protectedDacl\":true,\"noReparse\":true,\"canonicalName\":true,\"noShortAlias\":true,\"defaultStreamsOnly\":true,\"kind\":\"%s\",\"caseSensitive\":false,\"links\":%lu,\"bytes\":",directory ? "directory" : "file",info.NumberOfLinks);
  if(directory) printf("null"); else { putchar('"'); operation_bytes(file); putchar('"'); } putchar('}');
}
static void file_view(void) {
  need(!wcsncmp(operation_id,L"files.",6)); const wchar_t *names[]={L"custody",L"files",L"allocation",L"value",L".pending"};
  HANDLE current[5]={file_objects[0],operation_open(file_objects[0],L"files",TRUE,FILE_LIST_DIRECTORY,FALSE),NULL,NULL,NULL};
  current[2]=operation_open(current[1],L"allocation",TRUE,FILE_LIST_DIRECTORY,TRUE);
  if(current[2]) { current[3]=operation_open(current[2],L"value",FALSE,GENERIC_READ,TRUE); current[4]=operation_open(current[2],L".pending",FALSE,GENERIC_READ,TRUE); }
  const char *keys[]={"base","root","allocation","leaf","temporary"}; putchar('{');
  for(unsigned i=0;i<5;i++) {
    if(i) putchar(','); printf("\"%s\":",keys[i]);
    if(!current[i]) { printf("null"); if(i>=2 && file_objects[i]) { need(CloseHandle(file_objects[i])); file_objects[i]=NULL; } continue; }
    FILE_ID_INFO id; need(GetFileInformationByHandleEx(current[i],FileIdInfo,&id,sizeof(id)));
    if(!file_objects[i]) { need(DuplicateHandle(GetCurrentProcess(),current[i],GetCurrentProcess(),&file_objects[i],0,FALSE,DUPLICATE_SAME_ACCESS)); file_ids[i]=id; }
    else if(memcmp(&file_ids[i],&id,sizeof(id))) {
      /* Only a completed replacement may retire the old leaf. Substitution
       * controls use a separate reader and never repin their saved identity. */
      need(i==3 && file_objects[4] && !memcmp(&file_ids[4],&id,sizeof(id))); need(CloseHandle(file_objects[i]));
      need(DuplicateHandle(GetCurrentProcess(),current[i],GetCurrentProcess(),&file_objects[i],0,FALSE,DUPLICATE_SAME_ACCESS)); file_ids[i]=id;
    }
    operation_file(file_objects[i],current[i],i<3,names[i]);
  }
  putchar('}'); for(unsigned i=1;i<5;i++) if(current[i]) need(CloseHandle(current[i]));
}
static void release_pe(unsigned index) {
  need(index<count && entries[index].file.handle); DWORD size; BYTE *bytes=read_file(&entries[index].file,536870912,&size); IMAGE_DOS_HEADER *dos=(void *)bytes;
  need(size>=512 && dos->e_magic==IMAGE_DOS_SIGNATURE && dos->e_lfanew>=64 && (DWORD)dos->e_lfanew<=size-sizeof(IMAGE_NT_HEADERS64));
  IMAGE_NT_HEADERS64 *pe=(void *)(bytes+dos->e_lfanew); need(pe->Signature==IMAGE_NT_SIGNATURE && pe->FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64 &&
    pe->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC && pe->FileHeader.SizeOfOptionalHeader>=sizeof(IMAGE_OPTIONAL_HEADER64) && pe->OptionalHeader.NumberOfRvaAndSizes>=14);
  printf("{\"dll\":%s,\"linkerMajor\":%u,\"linkerMinor\":%u,\"timestamp\":%lu,\"imports\":[",pe->FileHeader.Characteristics & IMAGE_FILE_DLL ? "true" : "false",pe->OptionalHeader.MajorLinkerVersion,pe->OptionalHeader.MinorLinkerVersion,pe->FileHeader.TimeDateStamp);
  unsigned emitted=0;
  for(unsigned directory=0;directory<2;directory++) {
    IMAGE_DATA_DIRECTORY table=pe->OptionalHeader.DataDirectory[directory ? IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT : IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!table.Size) { need(!table.VirtualAddress); continue; } DWORD width=directory ? 32 : sizeof(IMAGE_IMPORT_DESCRIPTOR),at=rva(bytes,size,pe,table.VirtualAddress,table.Size); BOOL terminated=FALSE; need(table.Size/width<=128);
    for(unsigned i=0;(i+1)*width<=table.Size;i++) { DWORD *item=(void *)(bytes+at+i*width),nameRva=directory ? item[1] : item[3];
      if(!nameRva) { terminated=TRUE; break; } if(directory) need(item[0]==1); DWORD nameAt=rva(bytes,size,pe,nameRva,1),length=0;
      while(length<255 && nameAt+length<size && bytes[nameAt+length]) length++; need(length && length<255 && nameAt+length<size);
      wchar_t name[256]={0},host[256]={0}; for(unsigned j=0;j<length;j++) { need((bytes[nameAt+j]>='a' && bytes[nameAt+j]<='z') || (bytes[nameAt+j]>='A' && bytes[nameAt+j]<='Z') || (bytes[nameAt+j]>='0' && bytes[nameAt+j]<='9') || strchr("_.-",bytes[nameAt+j])); name[j]=bytes[nameAt+j]; }
      wcscpy_s(host,256,name); if(!_wcsnicmp(name,L"api-",4) || !_wcsnicmp(name,L"ext-",4)) { wchar_t contract[256]; wcscpy_s(contract,256,name); wchar_t *dot=wcsrchr(contract,'.'); if(dot) *dot=0; api_host(GetCurrentProcess(),contract,host); }
      need(emitted<256); printf("%s{\"name\":\"%ls\",\"host\":\"%ls\",\"delay\":%s}",emitted++ ? "," : "",name,host,directory ? "true" : "false");
    } need(terminated);
  }
  printf("],\"complete\":true}"); free(bytes);
}
static void operation_empty(HANDLE job) {
  JOBOBJECT_BASIC_PROCESS_ID_LIST members={0}; need(QueryInformationJobObject(job,JobObjectBasicProcessIdList,&members,sizeof(members),NULL) && !members.NumberOfAssignedProcesses && !members.NumberOfProcessIdsInList);
}
struct file_worker { PROCESS_INFORMATION process; HANDLE job,input,output,token; BYTE request[16]; DWORD request_size; };
static struct file_worker file_workers[3]; static unsigned file_worker_count;
struct file_read { FILE_ID_INFO identity; DWORD links,size; BYTE bytes[4096]; };
static struct file_read file_old_read;
static void worker_write(HANDLE pipe,const void *bytes,DWORD size) { DWORD used; need(WriteFile(pipe,bytes,size,&used,NULL) && used==size); }
static void worker_read(HANDLE pipe,void *bytes,DWORD size) { DWORD used; need(ReadFile(pipe,bytes,size,&used,NULL) && used==size); }
static struct file_read worker_file(HANDLE file) {
  struct file_read value={0}; LARGE_INTEGER size,zero={0}; BY_HANDLE_FILE_INFORMATION info;
  need(GetFileInformationByHandleEx(file,FileIdInfo,&value.identity,sizeof(value.identity)) && GetFileInformationByHandle(file,&info) && GetFileSizeEx(file,&size) && size.QuadPart>=0 && size.QuadPart<=4096 &&
    SetFilePointerEx(file,zero,NULL,FILE_BEGIN) && ReadFile(file,value.bytes,(DWORD)size.QuadPart,&value.size,NULL) && value.size==size.QuadPart); value.links=info.nNumberOfLinks; return value;
}
static void file_read_json(struct file_read *read) {
  printf("{\"identity\":\"%016llx:",read->identity.VolumeSerialNumber); hex(read->identity.FileId.Identifier,16);
  printf("\",\"bytes\":\""); hex(read->bytes,read->size); printf("\",\"links\":%lu,\"code\":0}",read->links);
}
/* Only inherited directory/pipe handles and finite commands enter this worker.
 * Its parent retains the Job, primary token and birth identity before release. */
static int file_worker_main(int argc,wchar_t **argv) {
  need(argc==4); HANDLE root=(HANDLE)(ULONG_PTR)_wcstoui64(argv[3],NULL,10); need(root && SetHandleInformation(root,HANDLE_FLAG_INHERIT,0));
  HANDLE input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE); need(GetFileType(input)==FILE_TYPE_PIPE && GetFileType(output)==FILE_TYPE_PIPE);
  BOOL member; need(IsProcessInJob(GetCurrentProcess(),NULL,&member) && member); wchar_t mode=argv[2][0]; need(wcslen(argv[2])==1 && wcschr(L"PR012",mode));
  BYTE ready='A'; HANDLE old=NULL;
  if(mode=='R') { HANDLE allocation=operation_open(root,L"allocation",TRUE,FILE_LIST_DIRECTORY,FALSE); old=operation_open(allocation,L"value",FALSE,GENERIC_READ,FALSE); need(CloseHandle(allocation)); }
  worker_write(output,&ready,1);
  BYTE command;
  for(unsigned i=0;i<32;i++) {
    worker_read(input,&command,1);
    if(command=='Q') { if(old) need(CloseHandle(old)); need(CloseHandle(root)); return 0; }
    if(mode=='P') {
      need(command=='P'); operation_create create=(operation_create)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtCreateFile");
      UNICODE_STRING text={20,20,L"allocation"}; OBJECT_ATTRIBUTES oa={sizeof(oa),root,&text,0,NULL,NULL}; IO_STATUS_BLOCK io; HANDLE file=NULL;
      NTSTATUS status=create(&file,FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,1,0x200021,NULL,0);
      DWORD code=status==(NTSTATUS)0xc0000022L ? ERROR_ACCESS_DENIED : 0; need(code==ERROR_ACCESS_DENIED && !file); worker_write(output,&code,sizeof(code)); continue;
    }
    if(mode>=L'0' && mode<=L'2') {
      need(command=='W'); const BYTE requests[3][7]={{0,'o','l','d',255},{0,'n','e','w',0,255},{'s','e','c','o','n','d'}}; const DWORD sizes[]={5,6,6};
      unsigned index=(unsigned)(mode-L'0'); worker_write(output,requests[index],sizes[index]); continue;
    }
    need(mode=='R' && (command=='N' || command=='O')); HANDLE file=old,allocation=NULL;
    if(command=='N') { allocation=operation_open(root,L"allocation",TRUE,FILE_LIST_DIRECTORY,FALSE); file=operation_open(allocation,L"value",FALSE,GENERIC_READ,FALSE); }
    struct file_read read=worker_file(file); worker_write(output,&read,sizeof(read));
    if(command=='N') need(CloseHandle(file) && CloseHandle(allocation));
  }
  return 126;
}
static void file_start_worker(struct file_worker *worker,wchar_t mode,BOOL restricted) {
  need(!worker->process.hProcess && !operation_fenced); unsigned image=operation_slot(3); need(!wcscmp(wcsrchr(entries[image].path,'\\')+1,L"custody-reader.exe"));
  pin(&entries[image].file,entries[image].pin); char signaturePin[65]; signature(&entries[image].file,entries[image].signature,signaturePin);
  struct operation_creation intent=operation_creation_intent(image);
  PSECURITY_DESCRIPTOR sd=descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa=attributes(sd,TRUE),private=attributes(sd,FALSE); HANDLE childIn,childOut,root;
  need(CreatePipe(&childIn,&worker->input,&sa,0) && CreatePipe(&worker->output,&childOut,&sa,0) && SetHandleInformation(worker->input,HANDLE_FLAG_INHERIT,0) && SetHandleInformation(worker->output,HANDLE_FLAG_INHERIT,0) &&
    DuplicateHandle(GetCurrentProcess(),file_objects[1],GetCurrentProcess(),&root,FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,TRUE,0));
  worker->job=operation_creation_job(&intent,&private); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0}; limits.BasicLimitInformation.LimitFlags=0x2008; limits.BasicLimitInformation.ActiveProcessLimit=1;
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui={255}; need(SetInformationJobObject(worker->job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) && SetInformationJobObject(worker->job,JobObjectBasicUIRestrictions,&ui,sizeof(ui)));
  HANDLE inherited[]={childIn,childOut,root}; SIZE_T size=0; InitializeProcThreadAttributeList(NULL,2,0,&size); STARTUPINFOEXW startup={0}; startup.StartupInfo.cb=sizeof(startup);
  startup.lpAttributeList=calloc(1,size); need(startup.lpAttributeList && InitializeProcThreadAttributeList(startup.lpAttributeList,2,0,&size) &&
    UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),NULL,NULL) && UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&worker->job,sizeof(worker->job),NULL,NULL));
  startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES; startup.StartupInfo.hStdInput=childIn; startup.StartupInfo.hStdOutput=startup.StartupInfo.hStdError=childOut;
  wchar_t command[32767]=L"",argument[64]; quoted(command,32767,entries[image].path); quoted(command,32767,L"--file-worker"); argument[0]=mode; argument[1]=0; quoted(command,32767,argument);
  need(swprintf_s(argument,64,L"%llu",(ULONGLONG)(ULONG_PTR)root)>0); quoted(command,32767,argument);
  wchar_t environment[]=L"CI=true\0GITHUB_ACTIONS=true\0PATH=C:\\nonexistent\0\0";
  if(restricted) need(CreateProcessAsUserW(case_token,entries[image].path,command,&private,&private,TRUE,CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,environment,entries[2].path,&startup.StartupInfo,&worker->process));
  else need(CreateProcessW(entries[image].path,command,&private,&private,TRUE,CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,environment,entries[2].path,&startup.StartupInfo,&worker->process));
  need(OpenProcessToken(worker->process.hProcess,TOKEN_QUERY,&worker->token));
  operation_creation_birth(&intent,worker->process.hProcess,worker->token);
  wchar_t *sid=token_sid(worker->token); need(!wcscmp(sid,restricted ? case_record.accountSid : L"S-1-5-18")); LocalFree(sid);
  BOOL member; need(IsProcessInJob(worker->process.hProcess,worker->job,&member) && member && process_session(worker->process.hProcess)==0);
  DeleteProcThreadAttributeList(startup.lpAttributeList); free(startup.lpAttributeList); need(CloseHandle(childIn) && CloseHandle(childOut) && CloseHandle(root)); LocalFree(sd);
  need(ResumeThread(worker->process.hThread)==1 && CloseHandle(worker->process.hThread)); worker->process.hThread=NULL; BYTE ready; worker_read(worker->output,&ready,1); need(ready=='A');
}
static void file_stop_worker(struct file_worker *worker) {
  need(worker->process.hProcess); BYTE command='Q'; worker_write(worker->input,&command,1); DWORD code;
  need(WaitForSingleObject(worker->process.hProcess,5000)==WAIT_OBJECT_0 && GetExitCodeProcess(worker->process.hProcess,&code) && !code); operation_empty(worker->job);
  need(CloseHandle(worker->input) && CloseHandle(worker->output)); worker->input=worker->output=NULL;
}
static void file_drop_worker(struct file_worker *worker) { need(CloseHandle(worker->process.hProcess) && CloseHandle(worker->token) && CloseHandle(worker->job)); memset(worker,0,sizeof(*worker)); }
static void file_workers_retire(void) {
  need(operation_fenced);
  /* Partial admission may own a suspended process without a ready frame. Its
   * held Job closes that entire creation domain; no PID/name-wide kill occurs. */
  for(unsigned i=0;i<3;i++) {
    struct file_worker *worker=&file_workers[i];
    if(worker->job) operation_stop_job(worker->job);
    if(worker->process.hProcess) need(WaitForSingleObject(worker->process.hProcess,5000)==WAIT_OBJECT_0 && CloseHandle(worker->process.hProcess));
    if(worker->process.hThread) need(CloseHandle(worker->process.hThread));
    if(worker->token) need(CloseHandle(worker->token));
    if(worker->input) need(CloseHandle(worker->input));
    if(worker->output) need(CloseHandle(worker->output));
    if(worker->job) need(CloseHandle(worker->job)); memset(worker,0,sizeof(*worker));
  }
  file_worker_count=0; printf("{\"noLiveMembers\":true,\"helpersSettled\":true}");
}
static void file_private(void) {
  need(!file_worker_count && file_objects[2]); struct file_worker worker={0}; file_start_worker(&worker,'P',TRUE);
  HANDLE control=operation_open(file_objects[1],L"allocation",TRUE,FILE_LIST_DIRECTORY,FALSE); FILE_ID_INFO id; need(GetFileInformationByHandleEx(control,FileIdInfo,&id,sizeof(id)) && !memcmp(&id,&file_ids[2],sizeof(id)) && CloseHandle(control));
  BYTE command='P'; worker_write(worker.input,&command,1); DWORD code; worker_read(worker.output,&code,sizeof(code)); need(code==ERROR_ACCESS_DENIED);
  HANDLE impersonation; need(DuplicateTokenEx(worker.token,TOKEN_QUERY | TOKEN_IMPERSONATE,NULL,SecurityImpersonation,TokenImpersonation,&impersonation) && SetThreadToken(NULL,impersonation));
  operation_create create=(operation_create)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtCreateFile"); UNICODE_STRING text={20,20,L"allocation"}; OBJECT_ATTRIBUTES oa={sizeof(oa),file_objects[1],&text,0,NULL,NULL}; IO_STATUS_BLOCK io; HANDLE denied=NULL;
  NTSTATUS status=create(&denied,FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,7,1,0x200021,NULL,0); need(RevertToSelf() && CloseHandle(impersonation) && status==(NTSTATUS)0xc0000022L && !denied);
  file_stop_worker(&worker); printf("{\"identity\":"); retained_identity(worker.process.hProcess,worker.token,0);
  printf(",\"ready\":true,\"reachable\":true,\"attempted\":true,\"allowed\":false,\"nativeCode\":5,\"exitCode\":0,\"signal\":null,\"settled\":true,\"tokenVerified\":true,\"jobVerified\":true}"); file_drop_worker(&worker);
}
static unsigned file_publication_count,file_publication_active; static char file_publication_outcomes[3][9],file_publication_ids[3][50];
static void file_publication_command(const BYTE *bytes,size_t size) {
  if(file_worker_count!=3 || size<8 || memcmp(bytes,"publish ",8)) return;
  need(file_publication_count<3 && !file_publication_active && size<8193);
  char command[8193],kind[16],parent[50],leaf[50],pending[50],request[8193],extra; memcpy(command,bytes,size); command[size]=0;
  need(sscanf_s(command,"%15s %49s %49s %49s %8192s %c",kind,(unsigned)sizeof(kind),parent,(unsigned)sizeof(parent),leaf,(unsigned)sizeof(leaf),pending,(unsigned)sizeof(pending),request,(unsigned)sizeof(request),&extra,1)==5);
  struct file_worker *worker=&file_workers[file_publication_count]; need(strlen(request)==worker->request_size*2);
  for(unsigned i=0;i<worker->request_size;i++) need(nibble(request[i*2])*16+nibble(request[i*2+1])==worker->request[i]);
  file_publication_active=file_publication_count+1;
}
static void file_publication_frame(const char *frame) {
  if(!file_publication_active || (!strstr(frame,"\"phase\":\"complete\"") && !strstr(frame,"\"phase\":\"exists\""))) return;
  unsigned index=file_publication_active-1; need(index==file_publication_count && strstr(frame,nonce));
  HANDLE parent=operation_open(file_objects[1],L"allocation",TRUE,FILE_LIST_DIRECTORY,FALSE),leaf=operation_open(parent,L"value",FALSE,GENERIC_READ,FALSE);
  struct file_read read=worker_file(leaf); need(read.size==file_workers[0].request_size && !memcmp(read.bytes,file_workers[0].request,read.size));
  char id[50]; sprintf_s(id,50,"%016llx:",read.identity.VolumeSerialNumber); for(unsigned i=0;i<16;i++) sprintf_s(id+17+i*2,50-17-i*2,"%02x",read.identity.FileId.Identifier[i]);
  need(strstr(frame,id)); strcpy_s(file_publication_ids[index],50,id);
  strcpy_s(file_publication_outcomes[index],9,strstr(frame,"\"phase\":\"complete\"") ? "complete" : "exists");
  need(CloseHandle(leaf) && CloseHandle(parent)); file_publication_active=0; file_publication_count++;
}

static void file_publishers_start(void) {
  need(!file_worker_count && !file_objects[3]); const BYTE requests[3][7]={{0,'o','l','d',255},{0,'n','e','w',0,255},{'s','e','c','o','n','d'}}; DWORD sizes[]={5,6,6};
  for(unsigned i=0;i<3;i++) { file_start_worker(&file_workers[i],(wchar_t)(L'0'+i),FALSE); file_worker_count++; memcpy(file_workers[i].request,requests[i],sizes[i]); file_workers[i].request_size=sizes[i]; BYTE command='W'; worker_write(file_workers[i].input,&command,1); }
  for(unsigned i=0;i<3;i++) { BYTE reply[16]; worker_read(file_workers[i].output,reply,sizes[i]); need(!memcmp(reply,requests[i],sizes[i])); }
  printf("{\"ready\":true,\"overlapped\":true,\"requestsAcknowledged\":3,\"callers\":["); for(unsigned i=0;i<3;i++) { if(i) putchar(','); identity(file_workers[i].process.hProcess); } printf("]}");
}
static void file_publishers_finish(void) {
  need(file_worker_count==3); BOOL complete=file_publication_count==3 && !file_publication_active;
  printf("{\"complete\":%s,\"settled\":true,\"overlapped\":true,\"requests\":[",complete ? "true" : "false");
  for(unsigned i=0;i<3;i++) { struct file_worker *worker=&file_workers[i]; file_stop_worker(worker); char hash[65]; sum(worker->request,worker->request_size,hash);
    if(i<file_publication_count) {
      printf("%s{\"identity\":",i ? "," : ""); retained_identity(worker->process.hProcess,worker->token,0); printf(",\"bytesSha256\":\"%s\",\"leaf\":\"%s\"",hash,file_publication_ids[i]);
      printf(",\"outcome\":\"%s\",\"nativeEventSha256\":\"%s\"}",file_publication_outcomes[i],hash);
    } file_drop_worker(worker);
  } printf("]}"); file_worker_count=0;
}
static void file_reader_start(void) {
  need(!file_worker_count && file_objects[3]); file_start_worker(&file_workers[0],'R',FALSE); file_worker_count=1; BYTE command='O'; worker_write(file_workers[0].input,&command,1); worker_read(file_workers[0].output,&file_old_read,sizeof(file_old_read));
  printf("{\"reader\":"); identity(file_workers[0].process.hProcess); printf(",\"ready\":true}");
}
static void file_reader_read(void) { need(file_worker_count==1); struct file_read read; BYTE command='N'; worker_write(file_workers[0].input,&command,1); worker_read(file_workers[0].output,&read,sizeof(read)); file_read_json(&read); }
static void file_reader_finish(void) {
  need(file_worker_count==1); BYTE command='O'; worker_write(file_workers[0].input,&command,1); struct file_read read; worker_read(file_workers[0].output,&read,sizeof(read));
  need(!memcmp(&read.identity,&file_old_read.identity,sizeof(read.identity)) && read.size==file_old_read.size && !memcmp(read.bytes,file_old_read.bytes,read.size));
  file_stop_worker(&file_workers[0]); printf("{\"reader\":"); retained_identity(file_workers[0].process.hProcess,file_workers[0].token,0); printf(",\"oldHeld\":"); file_read_json(&read);
  printf(",\"ready\":true,\"overlapped\":true,\"complete\":true,\"settled\":true,\"dropped\":false}"); file_drop_worker(&file_workers[0]); file_worker_count=0;
}
typedef NTSTATUS (NTAPI *operation_set)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
struct operation_rename_name { ULONG flags; HANDLE parent; ULONG length; wchar_t name[64]; };
struct operation_link_name { BOOLEAN replace; HANDLE parent; ULONG length; wchar_t name[16]; };
_Static_assert(offsetof(struct operation_rename_name,name)==20 && offsetof(struct operation_link_name,name)==20,"NT name ABI");
static wchar_t file_control_kind[32]; static unsigned file_control_target;
static HANDLE file_control_object; static FILE_ID_INFO file_control_id;
static char file_control_before[65],file_control_others[65],file_control_foreign[65],file_control_installed[65],file_control_saved[65],file_control_baseline[65]; static BOOL file_control_continued; static DWORD file_last_exit, file_control_sequence;
static void operation_sum(HANDLE file,char hash[65]) { struct file_read value=worker_file(file); sum(value.bytes,value.size,hash); }
static void file_others(unsigned omitted,char hash[65]) {
  BYTE bytes[5*(sizeof(FILE_ID_INFO)+65+65)]={0}; DWORD used=0;
  for(unsigned i=0;i<5;i++) if(i!=omitted && file_objects[i]) {
    FILE_ID_INFO id; char securityPin[65],dataPin[65]={0}; need(GetFileInformationByHandleEx(file_objects[i],FileIdInfo,&id,sizeof(id)));
    security(file_objects[i],SE_FILE_OBJECT,TRUE,securityPin); if(i>=3) operation_sum(file_objects[i],dataPin);
    memcpy(bytes+used,&id,sizeof(id)); used+=sizeof(id); memcpy(bytes+used,securityPin,65); used+=65; memcpy(bytes+used,dataPin,65); used+=65;
  } sum(bytes,used,hash);
}
static void operation_rename(HANDLE file,HANDLE parent,const wchar_t *name) {
  struct operation_rename_name target={0}; IO_STATUS_BLOCK io;
  target.parent=parent; target.length=(DWORD)wcslen(name)*2; need(target.length<sizeof(target.name)); memcpy(target.name,name,target.length);
  operation_set set=(operation_set)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetInformationFile"); need(set && !set(file,&io,&target,offsetof(struct operation_rename_name,name)+target.length,(FILE_INFORMATION_CLASS)65));
}
static HANDLE control_mutation_handle(HANDLE source) {
  FILE_ID_INFO before,after; need(GetFileInformationByHandleEx(source,FileIdInfo,&before,sizeof(before)));
  HANDLE result=ReOpenFile(source,DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_WRITE_ATTRIBUTES | GENERIC_READ | GENERIC_WRITE,7,FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
  need(result!=INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(result,FileIdInfo,&after,sizeof(after)) && !memcmp(&before,&after,sizeof(before))); return result;
}
static void control_fingerprint(HANDLE source,char hash[65]) {
  HANDLE file=ReOpenFile(source,GENERIC_READ | READ_CONTROL | ACCESS_SYSTEM_SECURITY,7,FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
  FILE_ID_INFO id; FILE_STANDARD_INFO standard; FILE_ATTRIBUTE_TAG_INFO tag;
  need(file!=INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(file,FileIdInfo,&id,sizeof(id)) && GetFileInformationByHandleEx(file,FileStandardInfo,&standard,sizeof(standard)) && GetFileInformationByHandleEx(file,FileAttributeTagInfo,&tag,sizeof(tag)));
  BYTE material[32768]={0}; DWORD used=0;
  memcpy(material+used,&id,sizeof(id)); used+=sizeof(id);
  memcpy(material+used,&standard.NumberOfLinks,sizeof(standard.NumberOfLinks)); used+=sizeof(standard.NumberOfLinks);
  memcpy(material+used,&tag,sizeof(tag)); used+=sizeof(tag);
  if(standard.Directory && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    FILE_CASE_SENSITIVE_INFO sensitive; need(GetFileInformationByHandleEx(file,FileCaseSensitiveInfo,&sensitive,sizeof(sensitive))); memcpy(material+used,&sensitive.Flags,sizeof(sensitive.Flags)); used+=sizeof(sensitive.Flags);
  }
  PSECURITY_DESCRIPTOR sd=file_sd(file,SE_FILE_OBJECT); DWORD size=GetSecurityDescriptorLength(sd); need(size && size<=65536);
  char securityPin[65]; sum((BYTE *)sd,size,securityPin); LocalFree(sd); memcpy(material+used,securityPin,65); used+=65;
  wchar_t name[4096]; DWORD length=GetFinalPathNameByHandleW(file,name,4096,FILE_NAME_NORMALIZED | VOLUME_NAME_DOS); need(length && length<4096);
  memcpy(material+used,name,length*2); used+=length*2;
  if(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    need(DeviceIoControl(file,FSCTL_GET_REPARSE_POINT,NULL,0,material+used,16384,&size,NULL) && size && size<=16384); used+=size;
  } else {
    if(!standard.Directory) { struct file_read bytes=worker_file(file); memcpy(material+used,bytes.bytes,bytes.size); used+=bytes.size; }
    typedef NTSTATUS (NTAPI *query_file)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
    query_file query=(query_file)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationFile"); BYTE bytes[4096]={0}; IO_STATUS_BLOCK io;
    need(query && !query(file,&io,bytes,sizeof(bytes),(FILE_INFORMATION_CLASS)22) && io.Information<=sizeof(bytes)); memcpy(material+used,bytes,io.Information); used+=(DWORD)io.Information;
    NTSTATUS status=query(file,&io,bytes,sizeof(bytes),(FILE_INFORMATION_CLASS)21); need(status==(NTSTATUS)0xc0000034L || (!status && io.Information<=sizeof(bytes)));
    if(!status) { memcpy(material+used,bytes,io.Information); used+=(DWORD)io.Information; }
  }
  need(used<=sizeof(material) && CloseHandle(file)); sum(material,used,hash);
}
static void control_summary(HANDLE file,BOOL applied) {
  FILE_ID_INFO id; FILE_STANDARD_INFO standard; FILE_ATTRIBUTE_TAG_INFO tag; char bytes[65];
  need(GetFileInformationByHandleEx(file,FileIdInfo,&id,sizeof(id)) && GetFileInformationByHandleEx(file,FileStandardInfo,&standard,sizeof(standard)) && GetFileInformationByHandleEx(file,FileAttributeTagInfo,&tag,sizeof(tag)));
  if(!standard.Directory && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) operation_sum(file,bytes); else sum((BYTE *)&id,sizeof(id),bytes);
  printf("{\"identity\":\""); operation_identity(file); printf("\",\"kind\":\"%s\",\"bytesSha256\":\"%s\",\"links\":%lu",standard.Directory ? "directory" : "file",bytes,standard.NumberOfLinks);
  if(applied && !wcscmp(file_control_kind,L"case")) {
    wchar_t name[4096]; DWORD length=GetFinalPathNameByHandleW(file,name,4096,FILE_NAME_NORMALIZED | VOLUME_NAME_DOS); need(length && length<4096 && !wcscmp(wcsrchr(name,L'\\')+1,L"Value")); printf(",\"name\":\"Value\"");
  }
  if(applied && (!wcscmp(file_control_kind,L"short-name") || !wcscmp(file_control_kind,L"stream"))) {
    typedef NTSTATUS (NTAPI *query_file)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
    query_file query=(query_file)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationFile"); BYTE bytes[4096]; IO_STATUS_BLOCK io; need(query);
    if(!wcscmp(file_control_kind,L"short-name")) {
      need(!query(file,&io,bytes,sizeof(bytes),(FILE_INFORMATION_CLASS)21) && ((FILE_NAME_INFO *)bytes)->FileNameLength==14 && !wmemcmp(((FILE_NAME_INFO *)bytes)->FileName,L"VALUE~1",7)); printf(",\"alternateName\":\"VALUE~1\"");
    } else {
      need(!query(file,&io,bytes,sizeof(bytes),(FILE_INFORMATION_CLASS)22)); unsigned at=0,count=0; BOOL ordinary=FALSE,control=FALSE;
      for(;;) { need(at+24<=io.Information && count++<2); DWORD *entry=(void *)(bytes+at),length=entry[1]; need(!(length%2) && length && at+24+length<=io.Information); wchar_t *name=(void *)(bytes+at+24);
        if(length==14 && !wmemcmp(name,L"::$DATA",7)) ordinary=TRUE;
        else { need(length==28 && !wmemcmp(name,L":control:$DATA",14)); control=TRUE; }
        if(!entry[0]) break; need(entry[0]>=24+length && at+entry[0]>at); at+=entry[0];
      } need(count==2 && ordinary && control); printf(",\"streams\":2");
    }
  }
  if(applied && (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    need(tag.ReparseTag==(!wcscmp(file_control_kind,L"symlink") ? IO_REPARSE_TAG_SYMLINK : IO_REPARSE_TAG_MOUNT_POINT));
    printf(",\"reparse\":\"%s\"",!wcscmp(file_control_kind,L"symlink") ? "symlink" : "junction");
    if(!wcscmp(file_control_kind,L"cross-volume")) { printf(",\"targetIdentity\":\""); operation_identity(entries[operation_slot(4)].file.handle); putchar('"'); }
  } putchar('}');
}
static void control_reparse(HANDLE file,const wchar_t *target,BOOL symlink) {
  struct { ULONG tag; USHORT length,reserved; USHORT subOffset,subLength,printOffset,printLength; ULONG flags; wchar_t path[4096]; } buffer={0};
  wchar_t substitute[4096]; need(swprintf_s(substitute,4096,L"\\??\\%ls",target)>0); unsigned chars=(unsigned)wcslen(substitute);
  unsigned offset=symlink ? 20 : 16, substituteBytes=(chars+1)*2, targetBytes=((unsigned)wcslen(target)+1)*2;
  /* Both names share the reparse payload; bounding either path alone does not
   * bound their combined copy into this fixed native buffer. */
  need(substituteBytes<=sizeof(buffer)-offset && targetBytes<=sizeof(buffer)-offset-substituteBytes);
  buffer.tag=symlink ? IO_REPARSE_TAG_SYMLINK : IO_REPARSE_TAG_MOUNT_POINT; buffer.subLength=(USHORT)(chars*2); buffer.printOffset=(USHORT)((chars+1)*2); buffer.printLength=(USHORT)(wcslen(target)*2);
  BYTE *paths=(BYTE *)&buffer + offset; memcpy(paths,substitute,substituteBytes); memcpy(paths+buffer.printOffset,target,targetBytes);
  buffer.length=(USHORT)((symlink ? 12 : 8)+buffer.printOffset+buffer.printLength+2); DWORD used;
  need(DeviceIoControl(file,FSCTL_SET_REPARSE_POINT,&buffer,8+buffer.length,NULL,0,&used,NULL));
}
static void file_control_apply(const wchar_t *kind) {
  need(!*file_control_kind && file_objects[2] && file_objects[3] && file_objects[4]);
  need(!wcscmp(kind,L"root") || !wcscmp(kind,L"parent") || !wcscmp(kind,L"junction") || !wcscmp(kind,L"symlink") || !wcscmp(kind,L"case") || !wcscmp(kind,L"stream") || !wcscmp(kind,L"hardlink") || !wcscmp(kind,L"short-name") || !wcscmp(kind,L"cross-volume"));
  wcscpy_s(file_control_kind,32,kind); file_control_target=!wcscmp(kind,L"root") ? 1 : (!wcscmp(kind,L"parent") || !wcscmp(kind,L"junction") || !wcscmp(kind,L"cross-volume")) ? 2 : 3;
  HANDLE original=file_objects[file_control_target]; FILE_ID_INFO id; need(GetFileInformationByHandleEx(original,FileIdInfo,&id,sizeof(id)) && !memcmp(&id,&file_ids[file_control_target],sizeof(id)));
  control_fingerprint(original,file_control_baseline);
  if(file_control_target==3) operation_sum(original,file_control_before); else sum((BYTE *)&id,sizeof(id),file_control_before);
  file_others(file_control_target,file_control_others); file_control_continued=FALSE; file_last_exit=STILL_ACTIVE;
  struct { FILE_ID_INFO saved; wchar_t kind[32]; char baseline[65],others[65]; } intent={0}; intent.saved=id; wcscpy_s(intent.kind,32,kind); strcpy_s(intent.baseline,65,file_control_baseline); strcpy_s(intent.others,65,file_control_others);
  wchar_t record[64]; need(file_control_sequence<64 && swprintf_s(record,64,L"file-control-%u.intent",file_control_sequence)>0); operation_record(record,operation_slot(1),(BYTE *)&intent,sizeof(intent));
  const wchar_t *leaf=file_control_target==1 ? L"files" : file_control_target==2 ? L"allocation" : L"value";
  HANDLE parent=file_control_target==1 ? file_objects[0] : file_control_target==2 ? file_objects[1] : file_objects[2];
  BOOL substitution=file_control_target<3 || !wcscmp(kind,L"symlink");
  HANDLE mutation=control_mutation_handle(original);
  if(substitution) {
    operation_rename(mutation,parent,L".saved"); wchar_t path[4096],base[4096]; DWORD size=GetFinalPathNameByHandleW(parent,base,4096,FILE_NAME_NORMALIZED | VOLUME_NAME_DOS); need(size>4 && size<4096 && swprintf_s(path,4096,L"%ls\\%ls",base+4,leaf)>0);
    PSECURITY_DESCRIPTOR sd=descriptor(L"O:SYG:SYD:P(A;;FA;;;SY)"); SECURITY_ATTRIBUTES sa=attributes(sd,FALSE);
    if(file_control_target<3) need(CreateDirectoryW(path,&sa));
    file_control_object=CreateFileW(path,GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | FILE_WRITE_ATTRIBUTES,7,&sa,file_control_target<3 ? OPEN_EXISTING : CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,NULL);
    LocalFree(sd); need(file_control_object!=INVALID_HANDLE_VALUE);
    if(!wcscmp(kind,L"junction") || !wcscmp(kind,L"symlink") || !wcscmp(kind,L"cross-volume")) {
      unsigned target=operation_slot(!wcscmp(kind,L"cross-volume") ? 4 : 2);
      if(!wcscmp(kind,L"cross-volume")) { FILE_ID_INFO foreign; need(GetFileInformationByHandleEx(entries[target].file.handle,FileIdInfo,&foreign,sizeof(foreign)) && foreign.VolumeSerialNumber!=id.VolumeSerialNumber); sum((BYTE *)&foreign,sizeof(foreign),file_control_foreign); }
      control_reparse(file_control_object,entries[target].path,!wcscmp(kind,L"symlink"));
    }
  } else {
    file_control_object=mutation; mutation=NULL;
    if(!wcscmp(kind,L"case")) operation_rename(file_control_object,parent,L"Value");
    else if(!wcscmp(kind,L"short-name")) need(SetFileShortNameW(file_control_object,L"VALUE~1"));
    else if(!wcscmp(kind,L"stream")) {
      wchar_t path[4096]; need(swprintf_s(path,4096,L"%ls\\files\\allocation\\value:control",entries[2].path)>0); HANDLE stream=CreateFileW(path,GENERIC_WRITE,7,NULL,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,NULL); need(stream!=INVALID_HANDLE_VALUE && FlushFileBuffers(stream) && CloseHandle(stream));
    } else if(!wcscmp(kind,L"hardlink")) {
      struct operation_link_name link={0}; link.parent=parent; link.length=12; wcscpy_s(link.name,16,L".alias"); IO_STATUS_BLOCK io;
      operation_set set=(operation_set)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetInformationFile"); need(set && !set(file_control_object,&io,&link,offsetof(struct operation_link_name,name)+link.length,(FILE_INFORMATION_CLASS)11));
    }
  }
  if(mutation) need(CloseHandle(mutation)); need(GetFileInformationByHandleEx(file_control_object,FileIdInfo,&file_control_id,sizeof(file_control_id)));
  control_fingerprint(file_control_object,file_control_installed);
  control_fingerprint(original,file_control_saved);
  struct { FILE_ID_INFO applied; char installed[65],saved[65]; } installed={0}; installed.applied=file_control_id; strcpy_s(installed.installed,65,file_control_installed); strcpy_s(installed.saved,65,file_control_saved);
  need(swprintf_s(record,64,L"file-control-%u.installed",file_control_sequence++)>0); operation_record(record,operation_slot(1),(BYTE *)&installed,sizeof(installed));
  printf("{\"ready\":true,\"applied\":"); control_summary(file_control_object,TRUE); putchar('}');
}
static void file_control_read(void) {
  need(*file_control_kind && file_control_continued && file_last_exit==126 && !helpers[0].process); FILE_ID_INFO id; need(GetFileInformationByHandleEx(file_control_object,FileIdInfo,&id,sizeof(id)) && !memcmp(&id,&file_control_id,sizeof(id)));
  char others[65]; file_others(file_control_target,others); need(!strcmp(others,file_control_others));
  printf("{\"continued\":true,\"rejected\":true,\"attempted\":true,\"ready\":true,\"reachable\":true,\"exitCode\":126,\"signal\":null,\"nativeDecision\":\"reject-%s\",\"before\":",file_control_target<3 && (!wcscmp(file_control_kind,L"root") || !wcscmp(file_control_kind,L"parent")) ? "identity" : !wcscmp(file_control_kind,L"junction") || !wcscmp(file_control_kind,L"symlink") || !wcscmp(file_control_kind,L"cross-volume") ? "reparse" : !wcscmp(file_control_kind,L"case") ? "case" : !wcscmp(file_control_kind,L"stream") ? "stream" : !wcscmp(file_control_kind,L"hardlink") ? "hardlink" : "short-name");
  printf("{\"identity\":\""); operation_identity(file_objects[file_control_target]); printf("\",\"bytesSha256\":\"%s\",\"links\":1}",file_control_before);
  printf(",\"saved\":"); control_summary(file_objects[file_control_target],FALSE); printf(",\"applied\":"); control_summary(file_control_object,TRUE); printf(",\"after\":"); control_summary(file_control_object,TRUE);
  printf(",\"othersBeforeSha256\":\"%s\",\"othersAfterSha256\":\"%s\"",file_control_others,others);
  if(!wcscmp(file_control_kind,L"cross-volume")) { FILE_ID_INFO foreign; need(GetFileInformationByHandleEx(entries[operation_slot(4)].file.handle,FileIdInfo,&foreign,sizeof(foreign))); char hash[65]; sum((BYTE *)&foreign,sizeof(foreign),hash); need(!strcmp(hash,file_control_foreign));
    printf(",\"foreignTarget\":{\"before\":{\"identity\":\""); operation_identity(entries[operation_slot(4)].file.handle); printf("\",\"kind\":\"directory\",\"stateSha256\":\"%s\"},\"after\":{\"identity\":\"",hash); operation_identity(entries[operation_slot(4)].file.handle); printf("\",\"kind\":\"directory\",\"stateSha256\":\"%s\"}}",hash); }
  putchar('}');
}
static void operation_remove(HANDLE file) { ULONG flags=3; IO_STATUS_BLOCK io; operation_set set=(operation_set)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetInformationFile"); need(set && !set(file,&io,&flags,sizeof(flags),(FILE_INFORMATION_CLASS)64)); }
static void file_control_restore(void) {
  need(*file_control_kind && !helpers[0].process && !file_worker_count); operation_empty(case_job); FILE_ID_INFO id; need(GetFileInformationByHandleEx(file_control_object,FileIdInfo,&id,sizeof(id)) && !memcmp(&id,&file_control_id,sizeof(id)));
  char installed[65],others[65],saved[65]; control_fingerprint(file_control_object,installed); control_fingerprint(file_objects[file_control_target],saved); file_others(file_control_target,others);
  need(!strcmp(installed,file_control_installed) && !strcmp(saved,file_control_saved) && !strcmp(others,file_control_others));
  HANDLE parent=file_control_target==1 ? file_objects[0] : file_control_target==2 ? file_objects[1] : file_objects[2]; const wchar_t *name=file_control_target==1 ? L"files" : file_control_target==2 ? L"allocation" : L"value";
  if(file_control_target<3 || !wcscmp(file_control_kind,L"symlink")) { operation_remove(file_control_object); need(CloseHandle(file_control_object)); file_control_object=NULL; HANDLE source=control_mutation_handle(file_objects[file_control_target]); operation_rename(source,parent,name); need(CloseHandle(source)); }
  else if(!wcscmp(file_control_kind,L"case")) operation_rename(file_control_object,parent,L"value");
  else if(!wcscmp(file_control_kind,L"short-name")) need(SetFileShortNameW(file_control_object,L""));
  else if(!wcscmp(file_control_kind,L"hardlink")) { HANDLE alias=operation_open(parent,L".alias",FALSE,DELETE,FALSE); operation_remove(alias); need(CloseHandle(alias)); }
  else { wchar_t path[4096]; need(swprintf_s(path,4096,L"%ls\\files\\allocation\\value:control",entries[2].path)>0); HANDLE stream=CreateFileW(path,DELETE,7,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL); need(stream!=INVALID_HANDLE_VALUE); operation_remove(stream); need(CloseHandle(stream)); }
  if(file_control_object) need(CloseHandle(file_control_object)); file_control_object=NULL;
  control_fingerprint(file_objects[file_control_target],saved); need(!strcmp(saved,file_control_baseline)); *file_control_kind=0;
  printf("{\"ownedOnly\":true,\"foreignPreserved\":true,\"priorRetirementVerified\":true}");
}
static void operation_authority(void) {
  need(system_process(GetCurrentProcess()) && case_token && case_job); operation_empty(case_job); char hash[65];
  operation_no_creators();
  for(unsigned i=1;i<=6;i++) security(entries[i].file.handle,SE_FILE_OBJECT,TRUE,hash);
  wchar_t name[21]; need(swprintf_s(name,21,L"np_%.16hs",nonce)>0); account_check(name,case_record.accountSid);
  wchar_t filesystem[32]; DWORD flags,maximum; need(GetVolumeInformationByHandleW(entries[2].file.handle,NULL,0,NULL,&maximum,&flags,filesystem,32) && !wcscmp(filesystem,L"NTFS") &&
    (flags & (FILE_PERSISTENT_ACLS | FILE_SUPPORTS_HARD_LINKS | FILE_SUPPORTS_OPEN_BY_FILE_ID))==(FILE_PERSISTENT_ACLS | FILE_SUPPORTS_HARD_LINKS | FILE_SUPPORTS_OPEN_BY_FILE_ID));
  unsigned sdk=0; for(unsigned i=0;i<count;i++) if(!strcmp(entries[i].kind,"sdk")) { need(entries[i].file.handle); pin(&entries[i].file,entries[i].pin); sdk++; } need(sdk);
  printf("{\"systemOnly\":true,\"soleParentAuthority\":true,\"noLiveMembers\":true,\"sdkAndLoaderVerified\":true,\"ntfsSemanticsVerified\":true}");
}
/* Git has separate execution and read-grant inventories. Baselines are held
 * before the first write, and partial installation restores only exact owned
 * descriptors. The fixed System helper never receives an ordinary grant. */
static PSECURITY_DESCRIPTOR git_before[SLOTS],git_wanted[SLOTS];
static BOOL git_base_possible,git_network_owned;
static char git_job_pin[65];
static BOOL git_inventory(unsigned index) {
  for(unsigned i=4;i<operation_count;i++) if(operation_slots[i]==index) return TRUE; return FALSE;
}
static void git_acl(unsigned index,DWORD mask,BOOL install) {
  need(index<count && entries[index].file.handle);
  wchar_t text[2048]; need(swprintf_s(text,2048,L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x%lx;;;%ls)(A;;0x%lx;;;%ls)",mask,case_record.accountSid,mask,case_record.restrictingSid)>0);
  PSECURITY_DESCRIPTOR wanted=descriptor(text); BOOL present,defaulted; PACL acl;
  need(GetSecurityDescriptorDacl(wanted,&present,&acl,&defaulted) && present && acl);
  if(install) {
    if(!git_before[index]) { char hash[65]; wchar_t leaf[64]; security(entries[index].file.handle,SE_FILE_OBJECT,TRUE,hash); git_before[index]=file_sd(entries[index].file.handle,SE_FILE_OBJECT);
      need(swprintf_s(leaf,64,L"git-policy-%u.baseline",index)>0); operation_record(leaf,index,(BYTE *)git_before[index],GetSecurityDescriptorLength(git_before[index])); }
    need(!git_wanted[index]); git_wanted[index]=wanted; wanted=NULL;
    set_file_security(entries[index].file.handle,DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,NULL,acl);
  } else {
    PSECURITY_DESCRIPTOR actual=file_sd(entries[index].file.handle,SE_FILE_OBJECT); PACL read; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
    need(GetSecurityDescriptorControl(actual,&flags,&revision) && (flags & SE_DACL_PROTECTED) &&
      GetSecurityDescriptorDacl(actual,&present,&read,&defaulted) && present && read && read->AclSize==acl->AclSize && !memcmp(read,acl,acl->AclSize));
    LocalFree(actual);
  }
  if(wanted) LocalFree(wanted);
}
static void git_baselines(void) {
  need(!wcsncmp(operation_id,L"git.",4) && operation_count>=7);
  for(unsigned i=4;i<operation_count;i++) {
    unsigned index=operation_slot(i); need(!git_before[index]);
    char hash[65]; security(entries[index].file.handle,SE_FILE_OBJECT,TRUE,hash);
    git_before[index]=file_sd(entries[index].file.handle,SE_FILE_OBJECT);
    wchar_t leaf[64]; need(swprintf_s(leaf,64,L"git-policy-%u.baseline",index)>0); operation_record(leaf,index,(BYTE *)git_before[index],GetSecurityDescriptorLength(git_before[index]));
  }
}
static void git_base_install(void) {
  need(!wcscmp(operation_id,L"git.ordinary") && !git_base_possible && !helpers[0].process); operation_empty(case_job); git_base_possible=TRUE;
  unsigned parents[]={1,3,4}; for(unsigned i=0;i<3;i++) git_acl(parents[i],FILE_GENERIC_READ | FILE_TRAVERSE,TRUE);
  git_acl(6,FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,TRUE); git_acl(operation_slot(0),FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,TRUE);
  /* Only reviewed private DLL copies receive this principal's read/execute
   * grant. Stock DLL ACLs and all unrelated images remain unchanged. */
  for(unsigned i=0;i<count;i++) {
    const wchar_t *leaf=wcsrchr(entries[i].path,L'\\');
    if(!strcmp(entries[i].kind,"image") && entries[i].file.handle && leaf && wcslen(leaf)>4 && !_wcsicmp(leaf+wcslen(leaf)-4,L".dll") &&
      !wcsncmp(entries[i].path,entries[3].path,wcslen(entries[3].path)) && entries[i].path[wcslen(entries[3].path)]==L'\\') git_acl(i,FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,TRUE);
  }
  unsigned pointer=count; wchar_t name[4096]; need(swprintf_s(name,4096,L"%ls\\.git",entries[4].path)>0);
  for(unsigned i=4;i<operation_count;i++) if(!wcscmp(entries[operation_slot(i)].path,name)) pointer=operation_slot(i);
  /* The read-grant helper intentionally excludes the pointer, whose base
   * policy remains separate from metadata authority. */
  if(pointer==count) for(unsigned i=0;i<count;i++) if(entries[i].file.handle && !wcscmp(entries[i].path,name)) pointer=i;
  need(pointer<count && !git_inventory(pointer)); git_acl(pointer,FILE_GENERIC_READ,TRUE);
  ownership_network_absent(); ownership_network(FALSE,FALSE); git_network_owned=TRUE;
  printf("{\"installed\":true}");
}
static void operation_no_creators(void) {
  struct verify_handles *list=handle_inventory();
  HANDLE owned[SLOTS+5]; unsigned ownedCount=0;
  for(unsigned i=1;i<count;i++) if(entries[i].file.handle && (!wcscmp(entries[i].path,entries[1].path) ||
    (!wcsncmp(entries[i].path,entries[1].path,wcslen(entries[1].path)) && entries[i].path[wcslen(entries[1].path)]==L'\\'))) owned[ownedCount++]=entries[i].file.handle;
  if(!wcsncmp(operation_id,L"files.",6)) for(unsigned i=0;i<5;i++) if(file_objects[i]) owned[ownedCount++]=file_objects[i];
  for(unsigned i=0;i<ownedCount;i++) {
    void *object=NULL; for(ULONG_PTR j=0;j<list->count;j++) if(list->entries[j].pid==GetCurrentProcessId() && list->entries[j].handle==(ULONG_PTR)owned[i]) object=list->entries[j].object;
    need(object);
    for(ULONG_PTR j=0;j<list->count;j++) if(list->entries[j].object==object && list->entries[j].pid!=GetCurrentProcessId() &&
      (!helpers[0].process || list->entries[j].pid!=GetProcessId(helpers[0].process)) &&
      (list->entries[j].access & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER))) need(FALSE);
  }
  free(list);
}
static void git_hooks_empty(void) {
  wchar_t name[4096]; need(swprintf_s(name,4096,L"%ls\\*",entries[operation_slot(2)].path)>0);
  WIN32_FIND_DATAW entry; HANDLE search=FindFirstFileW(name,&entry); need(search!=INVALID_HANDLE_VALUE);
  do { need(!wcscmp(entry.cFileName,L".") || !wcscmp(entry.cFileName,L"..")); } while(FindNextFileW(search,&entry));
  need(GetLastError()==ERROR_NO_MORE_FILES && FindClose(search));
}
static void git_policy_read(void) {
  need(!wcsncmp(operation_id,L"git.",4)); git_hooks_empty(); operation_no_creators();
  if(git_base_possible) {
    need(git_network_owned); ownership_network(FALSE,TRUE);
    for(unsigned i=4;i<operation_count;i++) {
      unsigned index=operation_slot(i); FILE_STANDARD_INFO info; need(GetFileInformationByHandleEx(entries[index].file.handle,FileStandardInfo,&info,sizeof(info)));
      git_acl(index,FILE_GENERIC_READ | (info.Directory ? FILE_TRAVERSE : 0),FALSE);
    }
  }
  unsigned git=operation_slot(0); pin(&entries[git].file,entries[git].pin); char sig[65]; signature(&entries[git].file,entries[git].signature,sig);
  for(unsigned i=1;i<count;i++) if(entries[i].file.handle && !wcsncmp(entries[i].path,entries[1].path,wcslen(entries[1].path))) {
    char hash[65]; if(!git_base_possible || !git_before[i]) security(entries[i].file.handle,SE_FILE_OBJECT,TRUE,hash);
  }
  if(helpers[0].job) ownership_job_pin(helpers[0].job,git_job_pin);
  else if(!*git_job_pin) ownership_job_pin(case_job,git_job_pin);
  printf("{\"complete\":true,\"privateParents\":true,\"hooksEmpty\":true,\"noForeignCreators\":true,\"noPrincipalFlows\":true,\"gitClosureVerified\":true,\"soleMetadataAuthority\":true,\"privateCreatorDaclVerified\":true,\"jobIdentitySha256\":\"%s\"}",git_job_pin);
}
static void git_restore(void) {
  need(!helpers[0].process && operation_fenced); operation_empty(case_job);
  if(audit_owned) audit_restore(FALSE);
  for(unsigned i=0;i<count;i++) if(git_before[i]) {
    PSECURITY_DESCRIPTOR actual=file_sd(entries[i].file.handle,SE_FILE_OBJECT); PACL current,before,wanted=NULL; BOOL present,defaulted;
    need(GetSecurityDescriptorDacl(actual,&present,&current,&defaulted) && present && current &&
      GetSecurityDescriptorDacl(git_before[i],&present,&before,&defaulted) && present && before);
    if(git_wanted[i]) need(GetSecurityDescriptorDacl(git_wanted[i],&present,&wanted,&defaulted) && present && wanted);
    else if(git_inventory(i)) {
      FILE_STANDARD_INFO info; need(GetFileInformationByHandleEx(entries[i].file.handle,FileStandardInfo,&info,sizeof(info)));
      wchar_t text[2048]; DWORD mask=FILE_GENERIC_READ | (info.Directory ? FILE_TRAVERSE : 0);
      need(swprintf_s(text,2048,L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x%lx;;;%ls)(A;;0x%lx;;;%ls)",mask,case_record.accountSid,mask,case_record.restrictingSid)>0);
      git_wanted[i]=descriptor(text); need(GetSecurityDescriptorDacl(git_wanted[i],&present,&wanted,&defaulted) && present);
    }
    need((current->AclSize==before->AclSize && !memcmp(current,before,current->AclSize)) ||
      (wanted && current->AclSize==wanted->AclSize && !memcmp(current,wanted,current->AclSize)));
    /* Owner, group, SACL and protection must also remain unchanged. */
    PSID a,b; SECURITY_DESCRIPTOR_CONTROL af,bf; DWORD revision;
    need(GetSecurityDescriptorOwner(actual,&a,&defaulted) && GetSecurityDescriptorOwner(git_before[i],&b,&defaulted) && EqualSid(a,b) &&
      GetSecurityDescriptorGroup(actual,&a,&defaulted) && GetSecurityDescriptorGroup(git_before[i],&b,&defaulted) && EqualSid(a,b) &&
      GetSecurityDescriptorControl(actual,&af,&revision) && GetSecurityDescriptorControl(git_before[i],&bf,&revision) && (af & ~SE_SACL_PRESENT)==(bf & ~SE_SACL_PRESENT));
    PACL ac,bc; BOOL ap,bp; need(GetSecurityDescriptorSacl(actual,&ap,&ac,&defaulted) && GetSecurityDescriptorSacl(git_before[i],&bp,&bc,&defaulted) &&
      ((!ac && !bc) || (ap && bp && ac && bc && ac->AclSize==bc->AclSize && !memcmp(ac,bc,ac->AclSize))));
    set_file_security(entries[i].file.handle,DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,NULL,before); LocalFree(actual);
    char hash[65]; security(entries[i].file.handle,SE_FILE_OBJECT,TRUE,hash);
  }
  if(git_network_owned) { ownership_network(TRUE,FALSE); ownership_network_absent(); git_network_owned=FALSE; }
  printf("{\"unchangedInstalled\":true,\"restored\":true}");
}
static void git_creator_token(HANDLE token,BOOL system) {
  wchar_t *sid=token_sid(token); need(!wcscmp(sid,system ? L"S-1-5-18" : case_record.accountSid)); LocalFree(sid);
  TOKEN_GROUPS *restricted=token_info(token,TokenRestrictedSids);
  if(system) need(!restricted->GroupCount);
  else { PSID expected; need(ConvertStringSidToSidW(case_record.restrictingSid,&expected) && restricted->GroupCount==1 && EqualSid(restricted->Groups[0].Sid,expected)); LocalFree(expected); }
  free(restricted);
  TOKEN_DEFAULT_DACL *creation=token_info(token,TokenDefaultDacl); need(creation->DefaultDacl && IsValidAcl(creation->DefaultDacl));
  if(system) {
    ACCESS_ALLOWED_ACE *ace; PSID expected; need(ConvertStringSidToSidW(L"S-1-5-18",&expected) && creation->DefaultDacl->AceCount==1 &&
      GetAce(creation->DefaultDacl,0,(void **)&ace) && ace->Header.AceType==ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags &&
      ace->Mask==GENERIC_ALL && EqualSid(&ace->SidStart,expected)); LocalFree(expected);
  } else {
    TOKEN_MANDATORY_LABEL *label=token_info(token,TokenIntegrityLevel); DWORD rid=*GetSidSubAuthority(label->Label.Sid,*GetSidSubAuthorityCount(label->Label.Sid)-1);
    need(rid==SECURITY_MANDATORY_LOW_RID); free(label);
    TOKEN_PRIVILEGES *privileges=token_info(token,TokenPrivileges); for(unsigned i=0;i<privileges->PrivilegeCount;i++) need(!(privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)); free(privileges);
  }
  free(creation);
}
static unsigned git_subject(DWORD pid,ULONGLONG birth) {
  unsigned slot=process_count; for(unsigned i=0;i<process_count;i++) if(GetProcessId(processes[i])==pid) {
    FILETIME created,ended,kernel,user; need(GetProcessTimes(processes[i],&created,&ended,&kernel,&user) && (((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime)==birth); slot=i;
  } need(slot<process_count); return slot;
}
static void git_child(DWORD pid,ULONGLONG birth,BOOL retired) {
  unsigned slot=git_subject(pid,birth); need(sessions[slot]==0); git_creator_token(tokens[slot],TRUE);
  if(retired) { DWORD code; need(WaitForSingleObject(processes[slot],0)==WAIT_OBJECT_0 && GetExitCodeProcess(processes[slot],&code) && !code); printf("{\"settled\":true}"); return; }
  BOOL member; need(helpers[0].job && IsProcessInJob(processes[slot],helpers[0].job,&member) && member);
  HANDLE threads=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0); THREADENTRY32 entry={sizeof(entry)}; unsigned matched=0; need(threads!=INVALID_HANDLE_VALUE && Thread32First(threads,&entry));
  do { if(entry.th32OwnerProcessID==pid) {
    HANDLE thread=OpenThread(THREAD_QUERY_INFORMATION,FALSE,entry.th32ThreadID); ULONG suspended=0;
    typedef NTSTATUS (NTAPI *query)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    query read=(query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationThread");
    need(thread && read && !read(thread,35,&suspended,sizeof(suspended),NULL) && suspended==1 && CloseHandle(thread)); matched++;
  } } while(Thread32Next(threads,&entry)); need(GetLastError()==ERROR_NO_MORE_FILES && matched==1 && CloseHandle(threads));
  struct verify_handles *handles=handle_inventory(); HANDLE process=duplicate_process_owner(slot); unsigned inherited=0;
  for(ULONG_PTR i=0;i<handles->count;i++) if(handles->entries[i].pid==pid && (handles->entries[i].flags & 2)) {
    HANDLE value; need(DuplicateHandle(process,(HANDLE)handles->entries[i].handle,GetCurrentProcess(),&value,0,FALSE,DUPLICATE_SAME_ACCESS) &&
      GetFileType(value)==FILE_TYPE_PIPE && CloseHandle(value)); inherited++;
  } need(inherited==2 && CloseHandle(process)); free(handles); ownership_job_pin(helpers[0].job,git_job_pin);
  printf("{\"suspended\":true,\"bornInJob\":true,\"noForeignHandles\":true,\"privateCreatorDaclVerified\":true,\"parentsVerified\":true,\"jobIdentitySha256\":\"%s\"}",git_job_pin);
}

/* Ordinary attempts execute the checked-in finite fixture with the retained
 * restricted token and a creation-time nested Job. The independent custodian
 * repeats AccessCheck against the held target and token: exit codes alone
 * never establish denial. */
static void git_access(HANDLE token,HANDLE file,DWORD mask,BOOL expected) {
  PSECURITY_DESCRIPTOR sd=file_sd(file,SE_FILE_OBJECT); HANDLE impersonation;
  need(DuplicateTokenEx(token,TOKEN_QUERY | TOKEN_IMPERSONATE,NULL,SecurityImpersonation,TokenImpersonation,&impersonation));
  GENERIC_MAPPING mapping={FILE_GENERIC_READ,FILE_GENERIC_WRITE,FILE_GENERIC_EXECUTE,FILE_ALL_ACCESS};
  MapGenericMask(&mask,&mapping); BYTE buffer[4096]; DWORD used=sizeof(buffer),granted; BOOL allowed;
  need(AccessCheck(sd,impersonation,mask,&mapping,(PPRIVILEGE_SET)buffer,&used,&granted,&allowed) && allowed==expected && CloseHandle(impersonation)); LocalFree(sd);
}
/* The same per-principal audit/SACL owner serves finite Git attempts. A pull
 * subscription is admitted before release; contiguous record IDs and native
 * XML decoding reject loss/clear and join failure events to retained births. */
static void git_audit_install(void) {
  need(git_base_possible && !operation_fenced && !helpers[0].process); operation_empty(case_job); operation_no_creators();
  audit_enumerate(); AUDIT_POLICY_INFORMATION *policy; need(AuditQuerySystemPolicy(audit_categories,audit_count,&policy)); char hash[65];
  sum((BYTE *)policy,audit_count*sizeof(*policy),hash);
  operation_record(L"git-audit-system.baseline",case_custody,(BYTE *)policy,audit_count*sizeof(*policy)); AuditFree(policy);
  TOKEN_USER *user=token_info(case_token,TokenUser); need(!audit_principal_exists(user->User.Sid));
  operation_record(L"git-audit-principal.baseline",case_custody,(BYTE *)user->User.Sid,GetLengthSid(user->User.Sid)); free(user);
  char arguments[93][65],*values[93]; for(unsigned i=0;i<93;i++) values[i]=arguments[i]; strcpy_s(arguments[3],65,hash);
  unsigned total=0; for(unsigned i=0;i<count;i++) if(git_before[i]) {
    need(total<44); sprintf_s(arguments[5+total*2],65,"%u",i);
    PSECURITY_DESCRIPTOR sd=file_sd(entries[i].file.handle,SE_FILE_OBJECT); sum((BYTE *)sd,GetSecurityDescriptorLength(sd),arguments[6+total*2]);
    wchar_t leaf[64]; need(swprintf_s(leaf,64,L"git-audit-%u.baseline",i)>0); operation_record(leaf,i,(BYTE *)sd,GetSecurityDescriptorLength(sd)); LocalFree(sd); total++;
  }
  sprintf_s(arguments[4],65,"%u",total); audit_install_token(case_token,values,5+total*2,FALSE); printf("{\"installed\":true}");
}
static struct xml_result git_event(EVT_HANDLE event) {
  DWORD size=0,used,properties; need(!EvtRender(NULL,event,EvtRenderEventXml,0,NULL,&size,&properties) && GetLastError()==ERROR_INSUFFICIENT_BUFFER && size && size<=262144 && !(size%2));
  BYTE *bytes=calloc(size,1); need(bytes && EvtRender(NULL,event,EvtRenderEventXml,size,bytes,&used,&properties) && used==size);
  size_t length=wcslen((wchar_t *)bytes)*2; need(length+2==size); char *encoded=calloc(length*2+1,1); need(encoded);
  const char *digits="0123456789abcdef"; for(unsigned i=0;i<length;i++) { encoded[i*2]=digits[bytes[i]>>4]; encoded[i*2+1]=digits[bytes[i]&15]; }
  struct xml_result result=xml_parse(encoded); free(bytes); free(encoded); need(result.event); return result;
}
static const wchar_t *git_field(struct xml_result *event,const wchar_t *name) {
  for(unsigned i=0;i<event->count;i++) if(!wcscmp(event->fields[i].name,name)) return event->fields[i].value; return L"";
}
static ULONGLONG git_numeric(const wchar_t *value,unsigned radix) { wchar_t *end; need(*value); ULONGLONG result=_wcstoui64(value,&end,radix); need(!*end); return result; }
static void git_event_drop(struct xml_result *event) { SecureZeroMemory(event->fields,96*sizeof(*event->fields)); free(event->fields); }
struct git_audit_window { EVT_HANDLE subscription; HANDLE ready; ULONGLONG record; };
static struct git_audit_window git_audit_start(void) {
  need(audit_owned); EVT_HANDLE query=EvtQuery(NULL,L"Security",L"*",EvtQueryChannelPath | EvtQueryReverseDirection),event; DWORD count;
  need(query && EvtNext(query,1,&event,0,0,&count) && count==1); struct xml_result parsed=git_event(event);
  ULONGLONG record=git_numeric(git_field(&parsed,L"EventRecordID"),10); git_event_drop(&parsed);
  EVT_HANDLE bookmark=EvtCreateBookmark(NULL); need(bookmark && EvtUpdateBookmark(bookmark,event) && EvtClose(event) && EvtClose(query));
  HANDLE ready=CreateEventW(NULL,TRUE,FALSE,NULL); need(ready);
  EVT_HANDLE subscription=EvtSubscribe(NULL,ready,L"Security",L"*",bookmark,NULL,NULL,EvtSubscribeStartAfterBookmark | EvtSubscribeStrict);
  need(subscription && EvtClose(bookmark)); struct git_audit_window result={subscription,ready,record}; return result;
}
static void git_audit_finish(struct git_audit_window *window,HANDLE actor,const wchar_t *image,const wchar_t *target,DWORD access,BOOL failure,char hash[65]) {
  FILETIME born,ended,kernel,user; need(GetProcessTimes(actor,&born,&ended,&kernel,&user)); DWORD pid=GetProcessId(actor);
  ULONGLONG lower=((ULONGLONG)born.dwHighDateTime<<32)|born.dwLowDateTime,upper=((ULONGLONG)ended.dwHighDateTime<<32)|ended.dwLowDateTime;
  BOOL matched=FALSE; unsigned records=0; BYTE (*material)[32]=calloc(8192,32); need(material); DWORD remaining=5000; ULONGLONG started=GetTickCount64();
  for(;;) {
    EVT_HANDLE events[32]; DWORD count=0;
    if(!EvtNext(window->subscription,32,events,0,0,&count)) {
      need(GetLastError()==ERROR_NO_MORE_ITEMS);
      if(matched) break;
      ULONGLONG elapsed=GetTickCount64()-started; need(elapsed<remaining && WaitForSingleObject(window->ready,remaining-(DWORD)elapsed)==WAIT_OBJECT_0 && ResetEvent(window->ready)); continue;
    }
    for(unsigned i=0;i<count;i++) {
      struct xml_result parsed=git_event(events[i]); ULONGLONG id=git_numeric(git_field(&parsed,L"EventRecordID"),10),kind=git_numeric(git_field(&parsed,L"EventID"),10);
      need(id==window->record+1 && records<8192 && kind!=1101 && kind!=1102); window->record=id;
      char recordPin[65]; sum((BYTE *)parsed.fields,parsed.count*sizeof(*parsed.fields),recordPin);
      for(unsigned j=0;j<32;j++) material[records][j]=(BYTE)(nibble(recordPin[j*2])*16+nibble(recordPin[j*2+1])); records++;
      if(kind==4656 && !wcscmp(git_field(&parsed,L"Provider"),L"Microsoft-Windows-Security-Auditing") &&
        !wcscmp(git_field(&parsed,L"SubjectUserSid"),case_record.accountSid) &&
        git_numeric(git_field(&parsed,L"ProcessId"),0)==pid && !_wcsicmp(git_field(&parsed,L"ProcessName"),image)) {
        const wchar_t *name=git_field(&parsed,L"ObjectName"); BOOL same=!_wcsicmp(name,target);
        if(!same && (!wcscmp(wcsrchr(target,L'\\')+1,L"index"))) {
          size_t parent=(size_t)(wcsrchr(target,L'\\')-target); same=!_wcsnicmp(name,target,parent) && !wcscmp(name+parent,L"\\index.lock");
        }
        unsigned year,month,day,hour,minute,second,fraction; SYSTEMTIME time={0}; FILETIME instant;
        need(swscanf_s(git_field(&parsed,L"TimeCreated"),L"%u-%u-%uT%u:%u:%u.%7uZ",&year,&month,&day,&hour,&minute,&second,&fraction)==7 && fraction<10000000);
        time.wYear=(WORD)year; time.wMonth=(WORD)month; time.wDay=(WORD)day; time.wHour=(WORD)hour; time.wMinute=(WORD)minute; time.wSecond=(WORD)second;
        need(SystemTimeToFileTime(&time,&instant)); ULONGLONG stamp=(((ULONGLONG)instant.dwHighDateTime<<32)|instant.dwLowDateTime)+fraction;
        ULONGLONG keywords=git_numeric(git_field(&parsed,L"Keywords"),0),mask=git_numeric(git_field(&parsed,L"AccessMask"),0);
        if(same && stamp>=lower && stamp<=upper && (mask & access)==access &&
          (keywords & (failure ? 0x0010000000000000ULL : 0x0020000000000000ULL))) matched=TRUE;
      }
      git_event_drop(&parsed); need(EvtClose(events[i]));
    }
  }
  need(matched && records && EvtClose(window->subscription) && CloseHandle(window->ready)); sum((BYTE *)material,records*sizeof(*material),hash); SecureZeroMemory(material,8192*32); free(material);
}

static void git_ordinary(char **v,unsigned n) {
  need(n==5 && !wcscmp(operation_id,L"git.ordinary") && !operation_fenced && git_base_possible && git_network_owned && !helpers[0].process);
  wchar_t profile[32],operation[32],parent[64]; decode_bounded(v[2],profile,32); decode_bounded(v[3],operation,32); decode_bounded(v[4],parent,64);
  need(!wcscmp(profile,L"read-only") || !wcscmp(profile,L"workspace-write") || !wcscmp(profile,L"trusted-command"));
  need(wcslen(parent)==40 && wcsspn(parent,L"0123456789abcdef")==40);
  BOOL git=!wcscmp(operation,L"inspect") || !wcscmp(operation,L"git-add") || !wcscmp(operation,L"git-commit");
  BOOL inspect=!wcscmp(operation,L"inspect"),pointer=!wcsncmp(operation,L"pointer-",8);
  need(git || pointer || !wcscmp(operation,L"metadata-write") || !wcscmp(operation,L"ref-write"));
  if(pointer) need(!wcscmp(operation,L"pointer-write") || !wcscmp(operation,L"pointer-delete") || !wcscmp(operation,L"pointer-replace"));
  operation_empty(case_job); git_hooks_empty(); operation_no_creators(); ownership_network(FALSE,TRUE);
  wchar_t target[4096]; need(swprintf_s(target,4096,L"%ls\\%ls",pointer ? entries[4].path : entries[operation_slot(1)].path,
    pointer ? L".git" : !wcscmp(operation,L"ref-write") ? L"refs\\heads\\proof" : inspect ? L"HEAD" : L"index")>0);
  unsigned targetSlot=count; for(unsigned i=0;i<count;i++) if(entries[i].file.handle && !wcscmp(entries[i].path,target)) targetSlot=i;
  need(targetSlot<count); HANDLE targetFile=entries[targetSlot].file.handle;
  DWORD desired=!wcscmp(operation,L"pointer-delete") || !wcscmp(operation,L"pointer-replace") ? DELETE : FILE_WRITE_DATA;
  HANDLE system; need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY | TOKEN_DUPLICATE,&system)); git_access(system,targetFile,inspect ? FILE_READ_DATA : desired,TRUE); need(CloseHandle(system));
  git_access(case_token,targetFile,inspect ? FILE_READ_DATA : desired,inspect);
  struct git_audit_window audit=git_audit_start();
  char before[65],after[65],targetPin[65],jobPin[65]; operation_sum(targetFile,before); sum((BYTE *)&entries[targetSlot].file.id,sizeof(FILE_ID_INFO),targetPin);
  PSECURITY_DESCRIPTOR sd=descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa=attributes(sd,TRUE),private=attributes(sd,FALSE);
  HANDLE childIn,childOut,input,output; need(CreatePipe(&childIn,&input,&sa,0) && CreatePipe(&output,&childOut,&sa,0) &&
    SetHandleInformation(input,HANDLE_FLAG_INHERIT,0) && SetHandleInformation(output,HANDLE_FLAG_INHERIT,0));
  struct operation_creation intent=operation_creation_intent(6);
  HANDLE job=operation_creation_job(&intent,&private); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0}; limits.BasicLimitInformation.LimitFlags=0x2008; limits.BasicLimitInformation.ActiveProcessLimit=32;
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui={255}; need(job && SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) && SetInformationJobObject(job,JobObjectBasicUIRestrictions,&ui,sizeof(ui)));
  HANDLE inherited[]={childIn,childOut},ownedJobs[]={case_job,job}; SIZE_T size=0; InitializeProcThreadAttributeList(NULL,2,0,&size);
  STARTUPINFOEXW startup={0}; startup.StartupInfo.cb=sizeof(startup); startup.lpAttributeList=calloc(1,size);
  need(startup.lpAttributeList && InitializeProcThreadAttributeList(startup.lpAttributeList,2,0,&size) &&
    UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),NULL,NULL) &&
    UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,ownedJobs,sizeof(ownedJobs),NULL,NULL));
  startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES; startup.StartupInfo.hStdInput=childIn; startup.StartupInfo.hStdOutput=startup.StartupInfo.hStdError=childOut;
  wchar_t command[32767]=L"",nonceText[33]; for(unsigned i=0;i<33;i++) nonceText[i]=nonce[i];
  const wchar_t *args[]={entries[6].path,nonceText,operation,entries[operation_slot(0)].path,entries[operation_slot(1)].path,entries[4].path,entries[operation_slot(2)].path,parent,L"test(fixture): record owned edit"};
  for(unsigned i=0;i<9;i++) quoted(command,32767,args[i]);
  wchar_t environment[]=L"CI=true\0GITHUB_ACTIONS=true\0PATH=C:\\nonexistent\0\0"; PROCESS_INFORMATION fixture={0}; HANDLE fixtureToken;
  need(CreateProcessAsUserW(case_token,entries[6].path,command,&private,&private,TRUE,CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
    environment,entries[4].path,&startup.StartupInfo,&fixture) && OpenProcessToken(fixture.hProcess,TOKEN_QUERY | TOKEN_DUPLICATE,&fixtureToken));
  operation_creation_birth(&intent,fixture.hProcess,fixtureToken);
  DeleteProcThreadAttributeList(startup.lpAttributeList); free(startup.lpAttributeList); need(CloseHandle(childIn) && CloseHandle(childOut)); LocalFree(sd);
  git_creator_token(fixtureToken,FALSE); BOOL member; need(IsProcessInJob(fixture.hProcess,job,&member) && member && IsProcessInJob(fixture.hProcess,case_job,&member) && member);
  need(ResumeThread(fixture.hThread)==1 && CloseHandle(fixture.hThread)); fixture.hThread=NULL;
  char frame[4096]; line(output,frame,sizeof(frame)); need(strstr(frame,nonce) && strstr(frame,"\"phase\":\"ready\"")); worker_write(input,"P\n",2);
  line(output,frame,sizeof(frame)); need(strstr(frame,nonce)); HANDLE actor=fixture.hProcess,actorToken=fixtureToken;
  if(git) {
    need(strstr(frame,"\"phase\":\"child\"") && strstr(frame,"\"suspended\":true")); char *start=strstr(frame,"\"pid\":"); unsigned long pid; unsigned long long birth;
    need(start && sscanf_s(start,"\"pid\":%lu,\"creationTime\":\"%llu\"",&pid,&birth)==2);
    actor=OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,FALSE,pid);
    FILETIME created,ended,kernel,user; need(actor && GetProcessTimes(actor,&created,&ended,&kernel,&user) && (((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime)==birth &&
      OpenProcessToken(actor,TOKEN_QUERY | TOKEN_DUPLICATE,&actorToken) && IsProcessInJob(actor,job,&member) && member && IsProcessInJob(actor,case_job,&member) && member);
    git_creator_token(actorToken,FALSE); wchar_t path[4096]; DWORD length=4096; need(QueryFullProcessImageNameW(actor,0,path,&length) && !wcscmp(path,entries[operation_slot(0)].path));
    pin(&entries[operation_slot(0)].file,entries[operation_slot(0)].pin); char signaturePin[65]; signature(&entries[operation_slot(0)].file,entries[operation_slot(0)].signature,signaturePin);
    git_access(actorToken,targetFile,inspect ? FILE_READ_DATA : desired,inspect); worker_write(input,"P\n",2);
  } else need(strstr(frame,"\"phase\":\"denied\"") && strstr(frame,"\"nativeCode\":5"));
  need(CloseHandle(input)); DWORD exit,actorExit; need(WaitForSingleObject(fixture.hProcess,25000)==WAIT_OBJECT_0 &&
    WaitForSingleObject(actor,0)==WAIT_OBJECT_0 && GetExitCodeProcess(fixture.hProcess,&exit) && GetExitCodeProcess(actor,&actorExit) &&
    (inspect ? !exit && !actorExit : git ? (exit==1 || exit==128) && actorExit==exit : !exit));
  operation_empty(job); operation_empty(case_job); ownership_job_pin(job,jobPin);
  BYTE trailing; DWORD used; need(!ReadFile(output,&trailing,1,&used,NULL) && GetLastError()==ERROR_BROKEN_PIPE && !used && CloseHandle(output));
  operation_sum(targetFile,after); need(!strcmp(before,after)); operation_no_creators(); ownership_network(FALSE,TRUE);
  char eventPin[65]; git_audit_finish(&audit,actor,git ? entries[operation_slot(0)].path : entries[6].path,target,inspect ? FILE_READ_DATA : desired,!inspect,eventPin);
  printf("{\"identity\":"); retained_identity(actor,actorToken,0);
  printf(",\"tokenVerified\":true,\"bornInJob\":true,\"noBreakaway\":true,\"settled\":true,\"basePolicyVerified\":true,\"closureVerified\":true,\"decisionVerified\":true,\"auditComplete\":true,\"auditSha256\":\"%s\",\"lossCount\":0,\"jobIdentitySha256\":\"%s\",\"code\":%lu",eventPin,jobPin,exit);
  if(inspect) printf(",\"head\":\"%ls\"",parent);
  else { printf(",\"attempted\":true,\"allowed\":false,\"exitCode\":%lu,\"signal\":null,\"nativeCode\":5,\"nativeDecision\":\"deny-metadata-write\",\"beforeSha256\":\"%s\",\"afterSha256\":\"%s\",\"targetIdentitySha256\":\"%s\",\"control\":{\"identity\":",exit,before,after,targetPin); identity(GetCurrentProcess());
    printf(",\"ready\":true,\"reachable\":true,\"readyBeforeAttempt\":true,\"settled\":true,\"operation\":\"%ls\",\"nativeCode\":0,\"targetIdentitySha256\":\"%s\"}",operation,targetPin);
  }
  putchar('}'); if(git) need(CloseHandle(actor) && CloseHandle(actorToken)); need(CloseHandle(fixture.hProcess) && CloseHandle(fixtureToken) && CloseHandle(job));
}

static BOOL operation_dispatch(char **v,unsigned n) {
  if(!strcmp(v[0],"operation-bind")) operation_bind(v,n);
  else if(!strcmp(v[0],"operation-authority")) { need(n==2); operation_authority(); }
  else if(!strcmp(v[0],"operation-fence")) { need(n==2 && *operation_id); operation_fenced=TRUE; printf("{\"fenced\":true}"); }
  else if(!strcmp(v[0],"operation-helper-retire")) {
    need(n==2 && operation_fenced && !helpers[1].process);
    if(helpers[0].process) {
      operation_stop_job(helpers[0].job); need(WaitForSingleObject(helpers[0].process,5000)==WAIT_OBJECT_0);
      if(helpers[0].thread) { need(CloseHandle(helpers[0].thread)); helpers[0].thread=NULL; }
      BYTE bytes[4096]; DWORD used,total=0;
      while(ReadFile(helpers[0].output,bytes,sizeof(bytes),&used,NULL) && used) { total+=used; need(total<=2097152); }
      need(GetLastError()==ERROR_BROKEN_PIPE);
    }
    printf("{\"helpersSettled\":true}");
  }
  else if(!strcmp(v[0],"file-view")) { need(n==2); file_view(); }
  else if(!strcmp(v[0],"file-private")) { need(n==2); file_private(); }
  else if(!strcmp(v[0],"file-workers-retire")) { need(n==2); file_workers_retire(); }
  else if(!strcmp(v[0],"file-recovery-retirement")) {
    need(n==2 && !wcsncmp(operation_id,L"files.",6) && !helpers[1].process && !file_worker_count); operation_empty(case_job);
    if(helpers[0].process) {
      need(helpers[0].file && system_process(helpers[0].process));
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account; need(QueryInformationJobObject(helpers[0].job,JobObjectBasicAccountingInformation,&account,sizeof(account),NULL) && account.ActiveProcesses==1);
    }
    /* The session checks prior retirement before opening its recovery helper,
     * then again at deletion. Only that admitted System helper may be live. */
    for(unsigned i=0;i<process_count;i++) if(!helpers[0].process || GetProcessId(processes[i])!=GetProcessId(helpers[0].process)) need(WaitForSingleObject(processes[i],0)==WAIT_OBJECT_0);
    printf("{\"noLiveMembers\":true,\"helpersSettled\":true,\"admissionsClosed\":true}");
  }
  else if(!strcmp(v[0],"file-publishers-start")) { need(n==2); file_publishers_start(); }
  else if(!strcmp(v[0],"file-publishers-finish")) { need(n==2); file_publishers_finish(); }
  else if(!strcmp(v[0],"file-reader-start")) { need(n==2); file_reader_start(); }
  else if(!strcmp(v[0],"file-reader-read")) { need(n==2); file_reader_read(); }
  else if(!strcmp(v[0],"file-reader-finish")) { need(n==2); file_reader_finish(); }
  else if(!strcmp(v[0],"file-control")) { need(n==3); wchar_t kind[32]; decode_bounded(v[2],kind,32); file_control_apply(kind); }
  else if(!strcmp(v[0],"file-control-read")) { need(n==2); file_control_read(); }
  else if(!strcmp(v[0],"file-control-restore")) { need(n==2); file_control_restore(); }
  else if(!strcmp(v[0],"git-policy-read")) { need(n==2); git_policy_read(); }
  else if(!strcmp(v[0],"git-policy-install")) { need(n==2); git_base_install(); }
  else if(!strcmp(v[0],"git-audit-install")) { need(n==2); git_audit_install(); }
  else if(!strcmp(v[0],"git-policy-restore")) { need(n==2); git_restore(); }
  else if(!strcmp(v[0],"git-ordinary")) git_ordinary(v,n);
  else if(!strcmp(v[0],"git-child") || !strcmp(v[0],"git-child-retired")) { need(n==4); wchar_t birth[32]; decode_bounded(v[3],birth,32); need(wcsspn(birth,L"0123456789")==wcslen(birth)); git_child(bounded_number(v[2],MAXDWORD),_wcstoui64(birth,NULL,10),!strcmp(v[0],"git-child-retired")); }
  else if(!strcmp(v[0],"operation-retirement")) { need(n==2 && !helpers[0].process); operation_empty(case_job); printf("{\"noLiveMembers\":true,\"helpersSettled\":true,\"admissionsClosed\":true}"); }
  else if(!strcmp(v[0],"release-pe")) { need(n==3); release_pe(bounded_number(v[2],count-1)); }
  else if(!strcmp(v[0],"release-build")) { need(n==3); unsigned index=bounded_number(v[2],count-1); LARGE_INTEGER size; need(entries[index].file.handle && GetFileSizeEx(entries[index].file.handle,&size) && size.QuadPart>0 && size.QuadPart<=536870912); printf("{\"bytes\":%llu}",(ULONGLONG)size.QuadPart); }
  else if(!strcmp(v[0],"release-close")) { need(n==3); unsigned index=bounded_number(v[2],count-1); need(!operation_closed[index] && entries[index].file.handle); close_file(&entries[index].file); memset(&entries[index].file,0,sizeof(entries[index].file)); operation_closed[index]=TRUE; printf("{\"index\":%u,\"closed\":true}",index); }
  else if(!strcmp(v[0],"operation-closed")) { need(n==2); unsigned emitted=0; putchar('['); for(unsigned i=0;i<count;i++) if(operation_closed[i]) { need(!entries[i].file.handle); printf("%s%u",emitted++ ? "," : "",i); } putchar(']'); }
  else return FALSE;
  return TRUE;
}
/* Cold recovery uses the independently approved observer's case plan. Node
 * first proves all possible System creators and observers retired through held
 * creation identities. This lane separately rejoins the account, whole Job and
 * private objects; it never opens a final helper or executes a payload. */
static void recovery_case(unsigned custody, const char *context, const char *caseNonce, BOOL required) {
  need(preparation_only && custody == 2 && count >= 9 && !strcmp(entries[custody].kind,"directory") &&
    strlen(context)==64 && strspn(context,"0123456789abcdef")==64 && strlen(caseNonce)==32 &&
    strspn(caseNonce,"0123456789abcdef")==32 && !memcmp(context,caseNonce,32));
  char savedNonce[33]; strcpy_s(savedNonce,33,nonce); strcpy_s(nonce,33,caseNonce);
  wchar_t name[21], jobName[96], recordName[4096];
  need(swprintf_s(name,21,L"np_%.16hs",caseNonce)>0 && swprintf_s(jobName,96,L"Local\\NativeProof-%hs",caseNonce)>0 &&
    swprintf_s(recordName,4096,L"%ls\\account.record",entries[custody].path)>0);
  DWORD attributes = GetFileAttributesW(recordName); BOOL recorded = attributes != INVALID_FILE_ATTRIBUTES;
  if (!recorded) need((GetLastError()==ERROR_FILE_NOT_FOUND || GetLastError()==ERROR_PATH_NOT_FOUND) && !required);
  struct case_account_record record={0}; if (recorded) { account_record(entries[custody].path,&record); need(!strcmp(record.context,context) && !strcmp(record.nonce,caseNonce)); }
  USER_INFO_1 *user=NULL; NET_API_STATUS status=NetUserGetInfo(NULL,name,1,(BYTE **)&user);
  need(status==NERR_UserNotFound || (recorded && status==NERR_Success)); if (user) NetApiBufferFree(user);
  /* An installed or changed baseline retains exclusion. Its owning restoration
   * must complete before account removal; recovery never overwrites it. */
  for (unsigned i=1;i<count;i++) {
    size_t root=wcslen(entries[1].path); if (wcsncmp(entries[i].path,entries[1].path,root) ||
      (entries[i].path[root] && entries[i].path[root]!='\\')) continue;
    DWORD present=GetFileAttributesW(entries[i].path);
    if (present==INVALID_FILE_ATTRIBUTES) { need(GetLastError()==ERROR_FILE_NOT_FOUND || GetLastError()==ERROR_PATH_NOT_FOUND); continue; }
    struct held_file file=hold_shared(entries[i].path,!strcmp(entries[i].kind,"directory"),TRUE,GENERIC_READ | ACCESS_SYSTEM_SECURITY,!strcmp(entries[i].kind,"mutable"));
    PSECURITY_DESCRIPTOR sd=file_sd(file.handle,SE_FILE_OBJECT); PACL sacl; BOOL has,defaulted;
    need(GetSecurityDescriptorSacl(sd,&has,&sacl,&defaulted));
    if (has && sacl) for (unsigned j=0;j<sacl->AceCount;j++) { ACE_HEADER *ace; need(GetAce(sacl,j,(void **)&ace) && ace->AceType==SYSTEM_MANDATORY_LABEL_ACE_TYPE); }
    LocalFree(sd); close_file(&file);
  }
  ownership_network_absent(); wfp_open(); GUID key; FWPM_PROVIDER0 *provider; FWPM_SUBLAYER0 *layer; FWPM_FILTER0 *filter;
  access_key(0,&key); need(FwpmProviderGetByKey0(wfp_engine,&key,&provider)==FWP_E_PROVIDER_NOT_FOUND);
  access_key(1,&key); need(FwpmSubLayerGetByKey0(wfp_engine,&key,&layer)==FWP_E_SUBLAYER_NOT_FOUND);
  for (unsigned i=0;i<52;i++) { access_key(i+2,&key); need(FwpmFilterGetByKey0(wfp_engine,&key,&filter)==FWP_E_FILTER_NOT_FOUND); }
  need(!access_registry_present());
  PSID sid=NULL; if (recorded) { need(ConvertStringSidToSidW(record.accountSid,&sid) && !audit_principal_exists(sid)); }
  HANDLE job=OpenJobObjectW(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE | READ_CONTROL,FALSE,jobName);
  if (!job) need(GetLastError()==ERROR_FILE_NOT_FOUND);
  else { char pin[65]; security(job,SE_KERNEL_OBJECT,TRUE,pin); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits; JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
    need(QueryInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits),NULL) && limits.BasicLimitInformation.LimitFlags==0x2008 &&
      limits.BasicLimitInformation.ActiveProcessLimit==32 && QueryInformationJobObject(job,JobObjectBasicUIRestrictions,&ui,sizeof(ui),NULL) && ui.UIRestrictionsClass==255); }
  if (status==NERR_Success) {
    account_check(name,record.accountSid); HANDLE census=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); need(census!=INVALID_HANDLE_VALUE);
    PROCESSENTRY32W entry={sizeof(entry)}; unsigned members=0; need(Process32FirstW(census,&entry));
    do { if (!entry.th32ProcessID) continue; HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,FALSE,entry.th32ProcessID);
      if (!process) { need(GetLastError()==ERROR_INVALID_PARAMETER); continue; } HANDLE token; need(OpenProcessToken(process,TOKEN_QUERY,&token));
      wchar_t *actual=token_sid(token); if (!wcscmp(actual,record.accountSid)) { BOOL belongs;
        need(job && ++members<=32 && process_session(process)==0 && IsProcessInJob(process,job,&belongs) && belongs); }
      LocalFree(actual); need(CloseHandle(token) && CloseHandle(process));
    } while (Process32NextW(census,&entry)); need(GetLastError()==ERROR_NO_MORE_FILES && CloseHandle(census));
    if (job) operation_stop_job(job);
    LSA_OBJECT_ATTRIBUTES attributes={0}; attributes.Length=sizeof(attributes); LSA_HANDLE policy;
    need(LsaOpenPolicy(NULL,&attributes,POLICY_LOOKUP_NAMES,&policy)==0 && LsaRemoveAccountRights(policy,sid,TRUE,NULL,0)==0 && LsaClose(policy)==0);
    need(NetUserDel(NULL,name)==NERR_Success);
  }
  if (job) { operation_empty(job); need(CloseHandle(job)); }
  HANDLE absent=OpenJobObjectW(JOB_OBJECT_QUERY,FALSE,jobName); need(!absent && GetLastError()==ERROR_FILE_NOT_FOUND);
  for (unsigned i=0;i<128;i++) { wchar_t operation[128]; need(swprintf_s(operation,128,L"NativeProof-Operation-%hs-%u",caseNonce,i)>0);
    absent=OpenJobObjectW(JOB_OBJECT_QUERY,FALSE,operation); need(!absent && GetLastError()==ERROR_FILE_NOT_FOUND); }
  need(NetUserGetInfo(NULL,name,1,(BYTE **)&user)==NERR_UserNotFound);
  if (sid) { LSA_OBJECT_ATTRIBUTES attributes={0}; attributes.Length=sizeof(attributes); LSA_HANDLE policy; LSA_UNICODE_STRING *rights=NULL; ULONG number=0;
    need(LsaOpenPolicy(NULL,&attributes,POLICY_LOOKUP_NAMES,&policy)==0); NTSTATUS result=LsaEnumerateAccountRights(policy,sid,&rights,&number);
    need((result==0 && !number) || result==(NTSTATUS)0xc0000034L); if (rights) LsaFreeMemory(rights); need(LsaClose(policy)==0); LocalFree(sid); }
  if (recorded) {
    struct ownership_view census={0}; census.record=record; ownership_census(&census);
    wchar_t peerHome[4096], peerFile[4096];
    need(swprintf_s(peerHome,4096,L"%ls\\access-peer",entries[custody].path)>0 &&
      swprintf_s(peerFile,4096,L"%ls\\account.record",peerHome)>0);
    DWORD present=GetFileAttributesW(peerFile);
    if (present!=INVALID_FILE_ATTRIBUTES) {
      struct case_account_record peer={0}; account_record(peerHome,&peer); char seed[128], expected[65];
      need(sprintf_s(seed,sizeof(seed),"%s:access-peer",context)>0); sum((BYTE *)seed,(DWORD)strlen(seed),expected);
      need(!strcmp(peer.context,expected) && !memcmp(peer.nonce,expected,32) && !wcscmp(peer.restrictingSid,record.restrictingSid));
      census.record=peer; ownership_census(&census);
      need(swprintf_s(name,21,L"np_%.16hs",peer.nonce)>0 && NetUserGetInfo(NULL,name,1,(BYTE **)&user)==NERR_UserNotFound);
      PSID peerSid; need(ConvertStringSidToSidW(peer.accountSid,&peerSid));
      LSA_OBJECT_ATTRIBUTES attributes={0}; attributes.Length=sizeof(attributes); LSA_HANDLE policy; LSA_UNICODE_STRING *rights=NULL; ULONG number=0;
      need(LsaOpenPolicy(NULL,&attributes,POLICY_LOOKUP_NAMES,&policy)==0); NTSTATUS result=LsaEnumerateAccountRights(policy,peerSid,&rights,&number);
      need((result==0 && !number) || result==(NTSTATUS)0xc0000034L); if (rights) LsaFreeMemory(rights); need(LsaClose(policy)==0); LocalFree(peerSid);
    } else {
      need(GetLastError()==ERROR_FILE_NOT_FOUND || GetLastError()==ERROR_PATH_NOT_FOUND);
      /* An unacknowledged peer account cannot be guessed from its directory. */
      need(swprintf_s(peerFile,4096,L"%ls\\account.intent",peerHome)>0 && GetFileAttributesW(peerFile)==INVALID_FILE_ATTRIBUTES &&
        (GetLastError()==ERROR_FILE_NOT_FOUND || GetLastError()==ERROR_PATH_NOT_FOUND));
    }
  }
  strcpy_s(nonce,33,savedNonce);
  printf("{\"accountAbsent\":true,\"rightsAbsent\":true,\"jobAbsent\":true,\"contextSha256\":\"%s\",\"policyRestored\":true,\"auditDrained\":true,\"readersClosed\":true}",context);
}
int wmain(int argc, wchar_t **argv) {
  if(argc==4 && !wcscmp(argv[1],L"--file-worker")) return file_worker_main(argc,argv);
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
    } else if (!strcmp(values[0], "case-file")) { need(n == 6 && !preparation_only); case_file(bounded_number(values[2], count-1), bounded_number(values[3], count-1), bounded_number(values[4], 1), values[5]);
    } else if (!strcmp(values[0], "case-account")) { need(n == 4 && !preparation_only); case_account_create(bounded_number(values[2], count-1), values[3]);
    } else if (!strcmp(values[0], "case-endpoint")) { need(n == 5 && !preparation_only); need(!strcmp(values[2], "v4") || !strcmp(values[2], "v6")); need(!strcmp(values[3], "tcp") || !strcmp(values[3], "udp")); case_endpoint(!strcmp(values[2], "v6"), !strcmp(values[3], "udp"), bounded_number(values[4], 65535));
    } else if (!strcmp(values[0], "case-partial-retire")) {
      need(n==2 && !preparation_only && !helpers[0].process && !helpers[1].process && !audit_owned && !ownership_policy_installed && !ownership_launcher.hProcess);
      if (case_token && case_job) case_retire(); else {
        need(!case_token && !case_job); wchar_t name[21], jobName[96]; USER_INFO_1 *user;
        need(swprintf_s(name,21,L"np_%.16hs",nonce)>0 && NetUserGetInfo(NULL,name,1,(BYTE **)&user)==NERR_UserNotFound &&
          swprintf_s(jobName,96,L"Local\\NativeProof-%hs",nonce)>0);
        HANDLE job=OpenJobObjectW(JOB_OBJECT_QUERY,FALSE,jobName); need(!job && GetLastError()==ERROR_FILE_NOT_FOUND);
        printf("{\"retired\":true}");
      }
    } else if (!strcmp(values[0], "access-inventory")) { need(!preparation_only); access_inventory(values, n);
    } else if (!strcmp(values[0], "access-policy-begin")) { need(n == 3 && !preparation_only); wchar_t profile[32]; decode_bounded(values[2], profile, 32); access_policy_begin(profile);
    } else if (!strcmp(values[0], "access-policy-installed")) { need(n == 3 && !preparation_only); access_policy_installed(values[2]);
    } else if (!strcmp(values[0], "access-policy-restore")) { need(n == 2 && !preparation_only); access_policy_restore();
    } else if (!strcmp(values[0], "access-jobs-close")) {
      need(n == 2 && !preparation_only && !case_job && !audit_owned && !helpers[0].process && !helpers[1].process);
      for (unsigned i = 0; i < job_count; i++) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        need(QueryInformationJobObject(jobs[i], JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL) && !accounting.ActiveProcesses && CloseHandle(jobs[i])); jobs[i] = NULL; }
      job_count = 0; printf("{\"closed\":true}");
    } else if (!strcmp(values[0], "access-controls")) { need(n == 2 && !preparation_only); access_control_objects();
    } else if ((!strcmp(values[0], "access-peers") || !strcmp(values[0], "access-peers-park"))) { need(n==3 && !preparation_only); access_peers(!strcmp(values[0], "access-peers"),bounded_number(values[2],MAXDWORD));
    } else if (!strcmp(values[0], "access-control")) { need(n == 4 && !preparation_only); access_control_state(values[2],bounded_number(values[3],MAXDWORD));
    } else if (!strcmp(values[0],"access-peer-state")) {
      need(n==3 && access_mode && ownership_count==2); unsigned other=bounded_number(values[2],1); struct access_peer_owner *peer=other ? &access_other_peer : &access_private_peer;
      struct access_control_view view={0}; view.record=case_record; view.peer=peer->process.hProcess; view.peerToken=peer->token; view.peerJob=peer->job; view.kind=other; printf("{\"hex\":\""); hex((BYTE *)&view,sizeof(view)); printf("\"}");
    } else if (!strcmp(values[0], "access-controls-stop")) { need(n==2 && !preparation_only); access_controls_stop();
    } else if (!strcmp(values[0], "access-foreign")) { need(n==4 && !preparation_only); access_foreign(values[2],bounded_number(values[3],MAXDWORD));
    } else if (!strcmp(values[0], "access-foreign-close")) { need(n==2 && access_foreign_socket!=INVALID_SOCKET && !closesocket(access_foreign_socket)); access_foreign_socket=INVALID_SOCKET; printf("{\"closed\":true}");
    } else if (!strcmp(values[0], "access-state")) { need(n == 4 && !preparation_only); access_state(bounded_number(values[2], MAXDWORD), number(values[3]));
    } else if (!strcmp(values[0], "access-peer-result")) {
      need(n==3 && ownership_count==2); unsigned index=bounded_number(values[2],3); char reply[4096]; line(access_private_peer.output,reply,sizeof(reply));
      char expected[64]; need(sprintf_s(expected,sizeof(expected),"\"index\":%u",index*2+1)>0 && strstr(reply,nonce) && strstr(reply,expected) && strstr(reply,"\"phase\":\"served\""));
      printf("{\"hex\":\""); hex((BYTE *)reply,(DWORD)strlen(reply)); printf("\"}");
    } else if (!strcmp(values[0],"access-controls-drain")) {
      need(n==2 && access_mode && access_controls_closed && !case_job); struct access_peer_owner *peers[]={&access_private_peer,&access_other_peer};
      for (unsigned i=0;i<2;i++) if (peers[i]->process.hProcess) { struct access_peer_owner *peer=peers[i]; need(WaitForSingleObject(peer->process.hProcess,0)==WAIT_OBJECT_0 && CloseHandle(peer->input)); peer->input=NULL;
        BYTE bytes[4096]; DWORD used,total=0; while (ReadFile(peer->output,bytes,sizeof(bytes),&used,NULL) && used) { total+=used; need(total<=65536); } need(GetLastError()==ERROR_BROKEN_PIPE && CloseHandle(peer->output) && CloseHandle(peer->process.hThread)); peer->output=NULL; peer->process.hThread=NULL;
        if (i) { need(CloseHandle(peer->process.hProcess) && CloseHandle(peer->token) && CloseHandle(peer->job)); peer->process.hProcess=peer->token=peer->job=NULL; }
      } printf("{\"drained\":true}");
    } else if (!strcmp(values[0], "access-reservation")) {
      need(n==4 && access_mode && ownership_count==2); unsigned index=bounded_number(values[2],7), member=index%2 ? 1 : 0; need(index<case_socket_count && access_payload_sockets[index]);
      WSAPROTOCOL_INFOW info; need(!WSADuplicateSocketW(case_sockets[index],bounded_number(values[3],MAXDWORD),&info)); printf("{\"identity\":"); retained_identity(ownership_processes[member],ownership_tokens[member],0);
      printf(",\"handle\":\"%llu\",\"hex\":\"",(ULONGLONG)(ULONG_PTR)access_payload_sockets[index]); hex((BYTE *)&info,sizeof(info)); printf("\"}");
    } else if (!strcmp(values[0], "access-transfer-root")) {
      need(n == 3 && access_mode && ownership_released && ownership_count >= 1);
      unsigned index = bounded_number(values[2], 1);
      need(!access_payload_roots[index] &&
        WaitForSingleObject(ownership_processes[0], 0) == WAIT_TIMEOUT);
      HANDLE root = ReOpenFile(entries[index + 1].file.handle, ACCESS_ROOT_MASK, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS); FILE_ID_INFO before, after;
      need(root != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(entries[index + 1].file.handle, FileIdInfo, &before, sizeof(before)) &&
        GetFileInformationByHandleEx(root, FileIdInfo, &after, sizeof(after)) && !memcmp(&before, &after, sizeof(before)) &&
        DuplicateHandle(GetCurrentProcess(), root, ownership_processes[0], &access_payload_roots[index], ACCESS_ROOT_MASK, FALSE, 0) && CloseHandle(root));
      printf("{\"handle\":\"%llu\"}", (ULONGLONG)(ULONG_PTR)access_payload_roots[index]);
    } else if (!strcmp(values[0], "access-transfer-socket")) {
      need(n == 3 && access_mode && ownership_released && ownership_count >= 1); unsigned index = bounded_number(values[2], 7); need(index < case_socket_count);
      need(WaitForSingleObject(ownership_processes[0], 0) == WAIT_TIMEOUT); WSAPROTOCOL_INFOW info;
      need(!WSADuplicateSocketW(case_sockets[index], GetProcessId(ownership_processes[0]), &info)); printf("{\"hex\":\""); hex((BYTE *)&info, sizeof(info)); printf("\"}");
    } else if (!strcmp(values[0], "access-register-socket")) {
      need(n == 4 && access_mode && ownership_released && ownership_count >= 1); unsigned index = bounded_number(values[2], 7); need(index < case_socket_count && !access_payload_sockets[index]);
      HANDLE remote = (HANDLE)(ULONG_PTR)number(values[3]); struct verify_handles *inventory = handle_inventory(); void *source = NULL, *target = NULL;
      for (ULONG_PTR i = 0; i < inventory->count; i++) {
        if (inventory->entries[i].pid == GetCurrentProcessId() && inventory->entries[i].handle == (ULONG_PTR)case_sockets[index]) source = inventory->entries[i].object;
        if (inventory->entries[i].pid == GetProcessId(ownership_processes[0]) && inventory->entries[i].handle == (ULONG_PTR)remote) target = inventory->entries[i].object;
      }
      need(source && source == target); free(inventory); access_payload_sockets[index] = remote; printf("{\"registered\":true}");
    } else if (!strcmp(values[0], "case-read")) { need(n == 2 && !preparation_only); case_read();
    } else if (!preparation_only && operation_dispatch(values,n)) {

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
    } else if (!strcmp(values[0],"access-fault-arm") || !strcmp(values[0],"access-fault-fire")) {
      need(n==3 && access_mode && ownership_released); wchar_t fault[32]; decode_bounded(values[2],fault,32); BOOL owner=!wcscmp(fault,L"owner-loss"); need(owner || !wcscmp(fault,L"helper-loss"));
      HANDLE process=owner ? ownership_owner.hProcess : ownership_launcher.hProcess, token=owner ? ownership_owner_token : ownership_launcher_token; need(process && token && WaitForSingleObject(process,0)==WAIT_TIMEOUT);
      BOOL fire=!strcmp(values[0],"access-fault-fire"); if (fire) need(TerminateProcess(process,126) && WaitForSingleObject(process,30000)==WAIT_OBJECT_0);
      printf("{\"identity\":"); retained_identity(process,token,0); printf(",\"signaled\":%s}",fire ? "true" : "false");
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
      if (access_mode) { for (unsigned i=0;i<case_socket_count;i++) need(!closesocket(case_sockets[i]) && !WSACleanup()); case_socket_count=0; }
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
      need((!strcmp(entry->kind, "image") || !strcmp(entry->kind, "helper")) && QueryFullProcessImageNameW(processes[index], 0, actual, &length) && !_wcsicmp(actual, entry->path));
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
    } else if (!strcmp(values[0], "audit-restore")) { need(n == 2); audit_restore(TRUE);
    } else if (!strcmp(values[0], "xml")) { need(n == 3); xml_decode(values[2]);
    } else if (!strcmp(values[0], "helper-start")) { start_helper(values, n);
    } else if (!strcmp(values[0], "helper-release")) { need(n == 3 && helper_thread && ResumeThread(helper_thread) == 1); need(CloseHandle(helper_thread)); helper_thread = NULL; printf("{\"released\":true}");
    } else if (!strcmp(values[0], "helper-close-input")) { need(n == 3 && helper && !helper_thread && helper_in && CloseHandle(helper_in)); helper_in = NULL; printf("{\"closed\":true}");
    } else if (!strcmp(values[0], "helper-send")) { need(n == 4 && helper && !helper_thread && helper_in); size_t size = strlen(values[3]); BYTE bytes[16384]; need(size && size%2 == 0 && size <= sizeof(bytes)*2);
      for (size_t i = 0; i < size/2; i++) bytes[i] = (BYTE)(nibble(values[3][i*2])*16 + nibble(values[3][i*2+1])); DWORD used;
      if(helper_file) file_publication_command(bytes,size/2);
      if(helper_file && *file_control_kind) { need(size/2==sizeof("continue - - - -\n")-1 && !memcmp(bytes,"continue - - - -\n",sizeof("continue - - - -\n")-1)); file_control_continued=TRUE; }
      need(WriteFile(helper_in, bytes, (DWORD)(size/2), &used, NULL) && used == size/2); printf("{\"sent\":true}");
    } else if (!strcmp(values[0], "helper-read")) { need(n == 3 && helper && !helper_thread); char bytes[16384]; line(helper_out, bytes, sizeof(bytes)); if(helper_file) file_publication_frame(bytes); printf("{\"hex\":\""); hex((BYTE *)bytes, strlen(bytes)); printf("\"}");
    } else if (!strcmp(values[0], "helper-bytes")) { need(n == 4 && helper && !helper_thread); DWORD size = bounded_number(values[3], 16384), used; BYTE bytes[16384];
      need(size && ReadFile(helper_out, bytes, size, &used, NULL) && used && used <= size); printf("{\"hex\":\""); hex(bytes, used); printf("\"}"); SecureZeroMemory(bytes, used);
    } else if (!strcmp(values[0], "helper-stop")) {
      need(n == 3 && access_mode && helper && helper_job);
      if (helper_in) { need(CloseHandle(helper_in)); helper_in = NULL; }
      need(TerminateJobObject(helper_job, 126) && WaitForSingleObject(helper, 30000) == WAIT_OBJECT_0);
      if (helper_thread) { need(CloseHandle(helper_thread)); helper_thread = NULL; }
      BYTE bytes[4096]; DWORD used, total = 0; while (ReadFile(helper_out, bytes, sizeof(bytes), &used, NULL) && used) { total += used; need(total <= 2097152); }
      need(GetLastError() == ERROR_BROKEN_PIPE); printf("{\"stopped\":true,\"drained\":true}");
    } else if (!strcmp(values[0], "helper-finish")) { need(n == 3 && helper && !helper_thread && WaitForSingleObject(helper, 0) == WAIT_OBJECT_0); DWORD exit; need(GetExitCodeProcess(helper, &exit) && (exit == 0 || ((helper_file || access_mode || operation_fenced) && exit == 126)));
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounts; need(QueryInformationJobObject(helper_job, JobObjectBasicAccountingInformation, &accounts, sizeof(accounts), NULL) && accounts.ActiveProcesses == 0);
      BYTE extra; DWORD used = 0; need(!ReadFile(helper_out, &extra, 1, &used, NULL) && GetLastError() == ERROR_BROKEN_PIPE && used == 0);
      if(helper_file) file_last_exit=exit;
      need(CloseHandle(helper) && CloseHandle(helper_job) && (!helper_in || CloseHandle(helper_in)) && CloseHandle(helper_out)); helper = helper_job = helper_in = helper_out = NULL; helper_file = FALSE;
      printf("{\"retired\":true,\"members\":0,\"drained\":true,\"exitCode\":%lu}", exit);
    } else if (!strcmp(values[0], "finish")) {
      need(!preparation_writer && !preparation_bytes && !preparation_names && !case_token && !case_job && !case_socket_count && !ownership_launcher.hProcess && !ownership_policy_installed);
      need(n == 2 && !helpers[0].process && !helpers[1].process && !audit_owned); if (ownership_sentinel.handle) close_file(&ownership_sentinel); for (unsigned i = 0; i < process_count; i++) { need(WaitForSingleObject(processes[i], 0) == WAIT_OBJECT_0 && CloseHandle(tokens[i]) && CloseHandle(processes[i])); }
      for (unsigned i = 0; i < job_count; i++) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current; need(QueryInformationJobObject(jobs[i], JobObjectBasicAccountingInformation, &current, sizeof(current), NULL) && current.ActiveProcesses == 0 && CloseHandle(jobs[i])); }
      for (unsigned i = 0; i < verification_file_count; i++) close_file(&verification_files[i]);
      need(!file_worker_count && !*file_control_kind); for(unsigned i=1;i<5;i++) if(file_objects[i]) need(CloseHandle(file_objects[i]));
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
