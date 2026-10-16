/* Sealed one-shot Task Scheduler entry, never a service or administrator-token
 * substitute for the independently observed LocalSystem/session-0 reader. */
#define COBJMACROS
#include "custody.h"
#include <taskschd.h>
#include <oleauto.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
static HANDLE pipe;
static BOOL observe_only;
static wchar_t receipt_directory[4096];
static struct held_file receipt_root;
#ifdef NATIVE_CI_EXPERIMENT
/* Seal only the freshly allocated, candidate-pinned local bootstrap inventory.
 * This acknowledgement is not custody proof: a distinct System reader must
 * independently reopen every image/source/plan before any compiler admission. */
static void experiment_seal(int argc, wchar_t **argv) {
  need(argc == 6 && wcslen(argv[3]) == 64 && wcslen(argv[5]) == 40);
  privilege(SE_BACKUP_NAME); privilege(SE_RESTORE_NAME);
  struct held_file planFile = hold(argv[2], FALSE, FALSE, GENERIC_READ | WRITE_DAC | WRITE_OWNER);
  char pinSha[65]; for (unsigned i = 0; i < 64; i++) pinSha[i] = (char)argv[3][i]; pinSha[64] = 0; pin(&planFile, pinSha);
  DWORD size; BYTE *bytes = read_file(&planFile, 262144, &size); need(bytes[size-1] == '\n' && !memchr(bytes, 0, size));
  char *text = calloc(size+1, 1); need(text); memcpy(text, bytes, size); free(bytes);
  wchar_t root[4096]; wcscpy_s(root, 4096, planFile.path); wchar_t *slash = wcsrchr(root, '\\'); need(slash); *slash = 0;
  HANDLE token; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)); wchar_t *sid = token_sid(token);
  need(!wcscmp(sid, argv[4])); LocalFree(sid); TOKEN_OWNER *tokenOwner = token_info(token, TokenOwner);
  PSID runner; need(ConvertStringSidToSidW(argv[4], &runner));
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); PSID owner, group; PACL dacl; BOOL present, defaulted;
  need(GetSecurityDescriptorOwner(sd, &owner, &defaulted) && GetSecurityDescriptorGroup(sd, &group, &defaulted) && GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted));
  struct held_file held[40]; unsigned count = 0; held[count++] = hold(root, TRUE, FALSE, FILE_LIST_DIRECTORY | WRITE_DAC | WRITE_OWNER); held[count++] = planFile;
  char *state, *first = strtok_s(text, "\n", &state), candidate[41], nonce[33], extra;
  need(first && sscanf_s(first, "native-experiment-v1 %40s %32s %c", candidate, 41u, nonce, 33u, &extra, 1u) == 2);
  wchar_t expected[41]; for (unsigned i = 0; i < 40; i++) expected[i] = candidate[i]; expected[40] = 0; need(!wcscmp(expected, argv[5]));
  unsigned helpers = 0, sources = 0;
  for (char *next = strtok_s(NULL, "\n", &state); next; next = strtok_s(NULL, "\n", &state)) {
    char kind[16], imagePin[65], signaturePin[65], encoded[16384]; wchar_t name[4096];
    need(sscanf_s(next, "%15s %64s %64s %16383s %c", kind, 16u, imagePin, 65u, signaturePin, 65u, encoded, (unsigned)sizeof(encoded), &extra, 1u) == 4); decode(encoded, name);
    size_t prefix = wcslen(root); if (_wcsnicmp(name, root, prefix) || name[prefix] != '\\') continue;
    /* Tools/output are selectors, never adopted host resources. */
    if (!strcmp(kind, "directory")) continue;
    need(count < 40 && !wcschr(name+prefix+1, '\\') && strlen(imagePin) == 64);
    for (unsigned i = 0; i < count; i++) need(_wcsicmp(held[i].path, name));
    struct held_file file = hold(name, FALSE, FALSE, GENERIC_READ | WRITE_DAC | WRITE_OWNER); need(file.links == 1); pin(&file, imagePin);
    if (!strcmp(kind, "helper")) { char actual[65]; signature(&file, signaturePin, actual); helpers++; }
    else { need(!strcmp(kind, "data") && !strcmp(signaturePin, "-")); sources++; }
    held[count++] = file;
  }
  need(helpers == 13 && sources == 18);
  /* Validate the entire ownership inventory before the first DACL mutation. */
  for (unsigned i = 0; i < count; i++) {
    PSID actual; PSECURITY_DESCRIPTOR prior; need(GetSecurityInfo(held[i].handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &actual, NULL, NULL, NULL, &prior) == ERROR_SUCCESS && (EqualSid(actual, runner) || EqualSid(actual, tokenOwner->Owner))); LocalFree(prior);
  }
  wchar_t report[4096]; wcscpy_s(report, 4096, root); size_t rootLength = wcslen(report);
  need(rootLength > 10 && !wcscmp(report+rootLength-10, L"-bootstrap")); report[rootLength-10] = 0;
  struct held_file reportRoot = hold(report, TRUE, FALSE, FILE_LIST_DIRECTORY | WRITE_DAC | WRITE_OWNER);
  PSID reportOwner; PSECURITY_DESCRIPTOR prior;
  need(GetSecurityInfo(reportRoot.handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &reportOwner, NULL, NULL, NULL, &prior) == ERROR_SUCCESS &&
    (EqualSid(reportOwner, runner) || EqualSid(reportOwner, tokenOwner->Owner))); LocalFree(prior);
  /* A native intent precedes seed DACL changes. Original identities/pins remain
   * in the exact plan; a lost seal reply does not authorize reuse or resealing. */
  wchar_t intentName[4096]; need(swprintf_s(intentName, 4096, L"%ls\\windows-experiment-seal.json", report) > 0);
  SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  HANDLE intent = CreateFileW(intentName, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL); need(intent != INVALID_HANDLE_VALUE);
  char intentBytes[256]; DWORD written;
  int intentSize = sprintf_s(intentBytes, sizeof(intentBytes), "{\"purpose\":\"experiment\",\"candidateSha\":\"%s\",\"planSha256\":\"%s\",\"status\":\"POSSIBLE\"}\n", candidate, pinSha);
  need(intentSize > 0 && WriteFile(intent, intentBytes, intentSize, &written, NULL) && written == (DWORD)intentSize && FlushFileBuffers(intent) && CloseHandle(intent));
  need(SetSecurityInfo(reportRoot.handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, owner, group, dacl, NULL) == ERROR_SUCCESS);
  close_file(&reportRoot); free(tokenOwner); need(CloseHandle(token));
  for (unsigned i = 0; i < count; i++) {
    PACL selected = dacl; PSECURITY_DESCRIPTOR bridgeSd = NULL;
    const wchar_t *leaf = wcsrchr(held[i].path, '\\');
    if (leaf && !wcscmp(leaf+1, L"custody-bridge.exe")) {
      wchar_t sddl[512]; need(swprintf_s(sddl, 512, L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGX;;;%ls)", argv[4]) > 0);
      bridgeSd = descriptor(sddl); need(GetSecurityDescriptorDacl(bridgeSd, &present, &selected, &defaulted));
    }
    need(SetSecurityInfo(held[i].handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, owner, group, selected, NULL) == ERROR_SUCCESS);
    if (bridgeSd) LocalFree(bridgeSd);
  }
  for (unsigned i = 0; i < count; i++) close_file(&held[i]);
  LocalFree(runner); LocalFree(sd); free(text); printf("{\"purpose\":\"experiment\",\"sealed\":true,\"planSha256\":\"%s\"}\n", pinSha);
}
#endif
static void observer_intent(wchar_t **argv, char digest[65]) {
  /* Adopt no populated runner-owned directory. An existing System-private
   * report is independently reopened; only a fresh empty report is protected. */
  struct held_file before = hold(argv[9], TRUE, FALSE, FILE_LIST_DIRECTORY | WRITE_DAC | WRITE_OWNER);
  wchar_t expectedOutput[4096]; need(swprintf_s(expectedOutput, 4096, L"%ls\\platform-build", before.path) > 0 && !wcscmp(expectedOutput, argv[10]));
  wchar_t pattern[4096]; need(swprintf_s(pattern, 4096, L"%ls\\*", argv[9]) > 0);
  WIN32_FIND_DATAW data; HANDLE search = FindFirstFileW(pattern, &data); need(search != INVALID_HANDLE_VALUE); BOOL empty = TRUE;
  do { if (wcscmp(data.cFileName, L".") && wcscmp(data.cFileName, L"..")) empty = FALSE; } while (FindNextFileW(search, &data));
  need(GetLastError() == ERROR_NO_MORE_FILES && FindClose(search));
  if (empty) {
    PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); PSID owner, group; PACL dacl; BOOL present, defaulted;
    need(GetSecurityDescriptorOwner(sd, &owner, &defaulted) && GetSecurityDescriptorGroup(sd, &group, &defaulted) && GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted));
    PSID actual; PACL priorDacl; PSECURITY_DESCRIPTOR prior; PSID runner;
    need(ConvertStringSidToSidW(argv[8], &runner) && GetSecurityInfo(before.handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &actual, NULL, &priorDacl, NULL, &prior) == ERROR_SUCCESS && (EqualSid(actual, runner) || EqualSid(actual, owner)));
    BOOL adopt = EqualSid(actual, runner); LocalFree(runner); LocalFree(prior);
    if (adopt) need(SetSecurityInfo(before.handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, owner, group, dacl, NULL) == ERROR_SUCCESS); LocalFree(sd);
  }
  receipt_root = hold(argv[9], TRUE, TRUE, FILE_LIST_DIRECTORY); wcscpy_s(receipt_directory, 4096, receipt_root.path);
  wchar_t name[4096]; need(swprintf_s(name, 4096, L"%ls\\windows-files-%ls-intent.json", receipt_root.path, argv[7]) > 0);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  HANDLE file = CreateFileW(name, GENERIC_WRITE | READ_CONTROL, 0, &sa, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL); need(file != INVALID_HANDLE_VALUE); LocalFree(sd);
  char bytes[196608] = "{\"schemaVersion\":1,\"argumentsHex\":["; size_t used = strlen(bytes);
  for (unsigned i = 1; i < 11; i++) {
    need(used+4+wcslen(argv[i])*4 < sizeof(bytes)); if (i > 1) bytes[used++] = ','; bytes[used++] = '"';
    BYTE *raw = (BYTE *)argv[i]; const char *digits = "0123456789abcdef";
    for (size_t j = 0; j < wcslen(argv[i])*2; j++) { bytes[used++] = digits[raw[j]>>4]; bytes[used++] = digits[raw[j]&15]; }
    bytes[used++] = '"';
  }
  need(strcpy_s(bytes+used, sizeof(bytes)-used, "],\"status\":\"POSSIBLE\"}\n") == 0); used = strlen(bytes); DWORD written;
  need(WriteFile(file, bytes, (DWORD)used, &written, NULL) && written == used && FlushFileBuffers(file) && CloseHandle(file)); sum((BYTE *)bytes, (ULONG)used, digest);
  struct held_file held = hold(name, FALSE, TRUE, GENERIC_READ); pin(&held, digest); close_file(&held); close_file(&before);
}
static void observer_record(const wchar_t *nonce, const wchar_t *runner, HANDLE helper, const char *taskHash, BOOL completed) {
  wchar_t name[4096]; need(swprintf_s(name, 4096, L"%ls\\windows-files-%ls-%ls.json", receipt_directory, nonce, completed ? L"result" : L"birth") > 0);
  struct held_file root = hold(receipt_directory, TRUE, TRUE, FILE_LIST_DIRECTORY);
  FILETIME birth, exit, kernel, user; need(GetProcessTimes(helper, &birth, &exit, &kernel, &user));
  ULONGLONG helperBirth = ((ULONGLONG)birth.dwHighDateTime<<32)|birth.dwLowDateTime;
  need(GetProcessTimes(GetCurrentProcess(), &birth, &exit, &kernel, &user));
  DWORD session; need(ProcessIdToSessionId(GetCurrentProcessId(), &session));
  char bytes[2048]; int size = sprintf_s(bytes, sizeof(bytes), "{\"schemaVersion\":1,\"nonce\":\"%ls\",\"taskSha256\":\"%s\",\"bridge\":{\"pid\":%lu,\"userSid\":\"%ls\",\"sessionId\":%lu,\"creationTime\":\"%llu\"},\"helper\":{\"pid\":%lu,\"userSid\":\"S-1-5-18\",\"sessionId\":0,\"creationTime\":\"%llu\"},\"status\":\"%s\"}\n",
    nonce, taskHash, GetCurrentProcessId(), runner, session, ((ULONGLONG)birth.dwHighDateTime<<32)|birth.dwLowDateTime, GetProcessId(helper), helperBirth, completed ? "RETIRED" : "POSSIBLE");
  need(size > 0); PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  HANDLE file = CreateFileW(name, GENERIC_WRITE | READ_CONTROL, 0, &sa, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL); LocalFree(sd); DWORD written;
  need(file != INVALID_HANDLE_VALUE && WriteFile(file, bytes, size, &written, NULL) && written == (DWORD)size && FlushFileBuffers(file) && CloseHandle(file)); close_file(&root);
}
static DWORD WINAPI expire(void *unused) { (void)unused; Sleep(observe_only ? PREPARATION_LIFETIME_MS : CUSTODY_LIFETIME_MS); ExitProcess(124); return 0; }
static void ack(char expected) { char value; DWORD used; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &value, 1, &used, NULL) && used == 1 && value == expected); }
static void xml_text(wchar_t *out, size_t maximum, const wchar_t *text) {
  for (; *text; text++) { const wchar_t *escaped = *text == '&' ? L"&amp;" : *text == '<' ? L"&lt;" : *text == '>' ? L"&gt;" : *text == '"' ? L"&quot;" : NULL;
    wchar_t byte[2] = {*text, 0}; need(wcscat_s(out, maximum, escaped ? escaped : byte) == 0); }
}
static void task_check(IRegisteredTask *task, const wchar_t *image, const wchar_t *args, const wchar_t *directory, const wchar_t *runner) {
  ITaskDefinition *definition; IPrincipal *principal; IActionCollection *actions; IAction *action; IExecAction *exec; ITriggerCollection *triggers; ITaskSettings *settings;
  BSTR text; LONG count; TASK_LOGON_TYPE logon; TASK_RUNLEVEL_TYPE level; TASK_INSTANCES_POLICY instances; VARIANT_BOOL hard;
  need_hr(IRegisteredTask_get_Definition, task, &definition);
  need_hr(ITaskDefinition_get_Principal, definition, &principal);
  need_hr(IPrincipal_get_UserId, principal, &text);
  need(text && text[0]);
  BYTE sid[SECURITY_MAX_SID_SIZE], expected[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(sid), expectedSize = sizeof(expected), domainSize = 256; wchar_t domain[256]; SID_NAME_USE type;
  need(CreateWellKnownSid(WinLocalSystemSid, NULL, expected, &expectedSize));
  if (!_wcsnicmp(text, L"S-", 2)) { PSID actual; need(ConvertStringSidToSidW(text, &actual) && IsValidSid(actual) && EqualSid(actual, expected)); LocalFree(actual); }
  else need(LookupAccountNameW(NULL, text, sid, &size, domain, &domainSize, &type) && IsValidSid(sid) && EqualSid(sid, expected));
  SysFreeString(text);
  need_hr(IPrincipal_get_LogonType, principal, &logon); need(logon == TASK_LOGON_SERVICE_ACCOUNT);
  need_hr(IPrincipal_get_RunLevel, principal, &level); need(level == TASK_RUNLEVEL_HIGHEST);
  need_hr(ITaskDefinition_get_Actions, definition, &actions);
  need_hr(IActionCollection_get_Count, actions, &count); need(count == 1);
  need_hr(IActionCollection_get_Item, actions, 1, &action);
  need_hr(IAction_QueryInterface, action, &IID_IExecAction, (void **)&exec);
  need_hr(IExecAction_get_Path, exec, &text); need(!wcscmp(text, image)); SysFreeString(text);
  need_hr(IExecAction_get_Arguments, exec, &text); need(!wcscmp(text, args)); SysFreeString(text);
  need_hr(IExecAction_get_WorkingDirectory, exec, &text); need(!wcscmp(text, directory)); SysFreeString(text);
  need_hr(ITaskDefinition_get_Triggers, definition, &triggers);
  need_hr(ITriggerCollection_get_Count, triggers, &count); need(count == 0);
  need_hr(ITaskDefinition_get_Settings, definition, &settings);
  need_hr(ITaskSettings_get_MultipleInstances, settings, &instances); need(instances == TASK_INSTANCES_IGNORE_NEW);
  need_hr(ITaskSettings_get_AllowHardTerminate, settings, &hard); need(hard == VARIANT_FALSE);
  need_hr(ITaskSettings_get_ExecutionTimeLimit, settings, &text); need(!wcscmp(text, observe_only ? L"PT16M" : L"PT19M30S")); SysFreeString(text);
  need_hr(IRegisteredTask_GetSecurityDescriptor, task, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text);
  PSECURITY_DESCRIPTOR sd = descriptor(text); PSID owner, system, caller; PACL dacl; BOOL present, defaulted; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  need(ConvertStringSidToSidW(L"S-1-5-18", &system) && ConvertStringSidToSidW(runner, &caller) &&
    GetSecurityDescriptorOwner(sd, &owner, &defaulted) && EqualSid(owner, system) && GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present && dacl && dacl->AceCount == 2 &&
    GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED));
  unsigned found = 0;
  for (unsigned i = 0; i < 2; i++) { ACCESS_ALLOWED_ACE *ace; need(GetAce(dacl, i, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags);
    if (EqualSid(&ace->SidStart, system)) { need(ace->Mask == GENERIC_ALL || ace->Mask == FILE_ALL_ACCESS); found |= 1; }
    else { need(EqualSid(&ace->SidStart, caller) && (ace->Mask == (GENERIC_READ | GENERIC_EXECUTE | DELETE) ||
      ace->Mask == (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | DELETE))); found |= 2; } } need(found == 3);
  LocalFree(system); LocalFree(caller); LocalFree(sd); SysFreeString(text);
  ITaskSettings_Release(settings); ITriggerCollection_Release(triggers); IExecAction_Release(exec); IAction_Release(action); IActionCollection_Release(actions); IPrincipal_Release(principal); ITaskDefinition_Release(definition);
}
static void task_hash(IRegisteredTask *task, char out[65]) {
  BSTR xml, security; need_hr(IRegisteredTask_get_Xml, task, &xml);
  need_hr(IRegisteredTask_GetSecurityDescriptor, task, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &security);
  DWORD a = SysStringByteLen(xml), b = SysStringByteLen(security); need(a && a <= 262144 && b && b <= 65536);
  BYTE *bytes = calloc(a+b+8, 1); need(bytes); memcpy(bytes, &a, 4); memcpy(bytes+4, xml, a); memcpy(bytes+4+a, &b, 4); memcpy(bytes+8+a, security, b);
  sum(bytes, a+b+8, out); free(bytes); SysFreeString(xml); SysFreeString(security);
}
static DWORD WINAPI forward(void *unused) {
  (void)unused; BYTE bytes[65536]; DWORD used, written; ULONGLONG total = 0;
  while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), bytes, sizeof(bytes), &used, NULL) && used) {
    total += used; OVERLAPPED write = {0}; write.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); need(write.hEvent && total <= 2147483648ULL);
    BOOL ok = WriteFile(pipe, bytes, used, &written, &write);
    if (!ok) need(GetLastError() == ERROR_IO_PENDING && WaitForSingleObject(write.hEvent, 30000) == WAIT_OBJECT_0 && GetOverlappedResult(pipe, &write, &written, FALSE));
    need(written == used && CloseHandle(write.hEvent));
  }
  return 0;
}
static LONG task_active(ITaskService *service, BSTR name) {
  IRunningTaskCollection *all;LONG count,found=0;wchar_t path[132];need(swprintf_s(path,132,L"\\%ls",name)>0);
  need_hr(ITaskService_GetRunningTasks,service,TASK_ENUM_HIDDEN,&all);need_hr(IRunningTaskCollection_get_Count,all,&count);need(count>=0&&count<=4096);
  for(LONG i=1;i<=count;i++){VARIANT index;VariantInit(&index);index.vt=VT_I4;index.lVal=i;IRunningTask *running;BSTR actual;
    need_hr(IRunningTaskCollection_get_Item,all,index,&running);need_hr(IRunningTask_get_Path,running,&actual);
    if(!_wcsicmp(path,actual))found++;SysFreeString(actual);IRunningTask_Release(running);
  }IRunningTaskCollection_Release(all);return found;
}
int wmain(int argc, wchar_t **argv) {
#ifdef NATIVE_CI_EXPERIMENT
  if (argc > 1 && !wcscmp(argv[1], L"--experiment-seal")) { require_build(); experiment_seal(argc, argv); return 0; }
#endif
  observe_only = argc == 11 && !wcscmp(argv[1], L"--observe");
  if (observe_only) need(!wcschr(argv[9], '%') && !wcschr(argv[10], '%'));
  need((observe_only || (argc == 9 && !wcscmp(argv[1], L"--entry"))) && !wcschr(argv[2], '%') && !wcschr(argv[5], '%') &&
    wcslen(argv[7]) == 32 && wcsspn(argv[7], L"0123456789abcdef") == 32 &&
    !system_process(GetCurrentProcess()) && CreateThread(NULL, 0, expire, NULL, 0, NULL));
  require_build();
  privilege(SE_BACKUP_NAME); privilege(SE_RESTORE_NAME); privilege(SE_DEBUG_NAME);
  char intentHash[65];
  struct held_file image = hold(argv[2], FALSE, TRUE, GENERIC_READ), plan = hold(argv[5], FALSE, TRUE, GENERIC_READ);
  char hash[65], signatureHash[65], planHash[65]; need(wcslen(argv[3]) == 64 && wcslen(argv[4]) == 64 && wcslen(argv[6]) == 64);
  for (unsigned i = 0; i < 64; i++) { hash[i] = (char)argv[3][i]; signatureHash[i] = (char)argv[4][i]; planHash[i] = (char)argv[6][i]; } hash[64] = signatureHash[64] = planHash[64] = 0;
  char observedSignature[65]; pin(&image, hash); signature(&image, signatureHash, observedSignature); pin(&plan, planHash);
  HANDLE token; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)); wchar_t *runner = token_sid(token); need(!wcscmp(runner, argv[8])); CloseHandle(token);
  if (observe_only) observer_intent(argv, intentHash);
  wchar_t name[96], pipeName[128], sddl[1024], pipeSddl[1024], directory[4096];
  need(swprintf_s(name, 96, L"NativeProof-Custody-%ls", argv[7]) > 0 && swprintf_s(pipeName, 128, L"\\\\.\\pipe\\NativeProof-Custody-%ls", argv[7]) > 0 &&
    swprintf_s(sddl, 1024, L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGXSD;;;%ls)", runner) > 0 &&
    swprintf_s(pipeSddl, 1024, L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGW;;;%ls)", runner) > 0);
  wcscpy_s(directory, 4096, argv[2]); wchar_t *slash = wcsrchr(directory, '\\'); need(slash); *slash = 0;
  PSECURITY_DESCRIPTOR sd = descriptor(pipeSddl); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  pipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 262144, 262144, 30000, &sa); need(pipe != INVALID_HANDLE_VALUE);
  wchar_t args[16384]; need(swprintf_s(args, 16384, L"%ls \"%ls\" %ls %ls \"%ls\" %ls %lu", observe_only ? L"--observe" : L"--serve", argv[5], argv[6], argv[7], pipeName, runner, GetCurrentProcessId()) > 0);
  if (observe_only) { wchar_t extra[8192]; need(swprintf_s(extra, 8192, L" \"%ls\" \"%ls\"", argv[9], argv[10]) > 0 && !wcscat_s(args, 16384, extra)); }
  wchar_t xml[32768] = L"<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Principals><Principal id=\"System\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>";
  need(wcscat_s(xml, 32768, observe_only ? L"PT16M" : L"PT19M30S") == 0 && wcscat_s(xml, 32768, L"</ExecutionTimeLimit></Settings><Actions Context=\"System\"><Exec><Command>") == 0);
  xml_text(xml, 32768, argv[2]); need(wcscat_s(xml, 32768, L"</Command><Arguments>") == 0); xml_text(xml, 32768, args);
  need(wcscat_s(xml, 32768, L"</Arguments><WorkingDirectory>") == 0); xml_text(xml, 32768, directory); need(wcscat_s(xml, 32768, L"</WorkingDirectory></Exec></Actions></Task>") == 0);
  sum((BYTE *)xml, (ULONG)(wcslen(xml)*2), hash); printf("{\"phase\":\"task-intent\",\"taskSha256\":\"%s\",\"bridge\":", hash); identity(GetCurrentProcess());
  if (observe_only) printf(",\"intentSha256\":\"%s\"", intentHash); puts("}"); fflush(stdout); ack('T');
  need_hr(CoInitializeEx, NULL, COINIT_MULTITHREADED);
  ITaskService *service; ITaskFolder *folder; IRegisteredTask *task, *old; IRunningTask *running; VARIANT empty, user, securityValue;
  VariantInit(&empty); VariantInit(&user); VariantInit(&securityValue); user.vt = VT_BSTR; user.bstrVal = SysAllocString(L"S-1-5-18"); securityValue.vt = VT_BSTR; securityValue.bstrVal = SysAllocString(sddl);
  need_hr(CoCreateInstance, &CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service);
  need_hr(ITaskService_Connect, service, empty, empty, empty, empty);
  BSTR root = SysAllocString(L"\\"), taskName = SysAllocString(name), definition = SysAllocString(xml); need(root && taskName && definition && user.bstrVal && securityValue.bstrVal);
  need_hr(ITaskService_GetFolder, service, root, &folder);
  need_hr_equal(ITaskFolder_GetTask, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), folder, taskName, &old);
  need_hr(ITaskFolder_RegisterTask, folder, taskName, definition, TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE, user, empty, TASK_LOGON_SERVICE_ACCOUNT, securityValue, &task);
  task_check(task, argv[2], args, directory, runner); task_hash(task, hash);
  printf("{\"phase\":\"task-registered\",\"taskSha256\":\"%s\"}\n", hash); fflush(stdout); ack('B');
  need_hr(IRegisteredTask_Run, task, empty, &running);
  OVERLAPPED connect = {0}; connect.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); need(connect.hEvent);
  BOOL connected = ConnectNamedPipe(pipe, &connect); DWORD error = GetLastError(), used;
  if (!connected && error == ERROR_IO_PENDING) need(WaitForSingleObject(connect.hEvent, 30000) == WAIT_OBJECT_0 && GetOverlappedResult(pipe, &connect, &used, FALSE));
  else need(connected || error == ERROR_PIPE_CONNECTED); CloseHandle(connect.hEvent);
  DWORD pid; need(GetNamedPipeClientProcessId(pipe, &pid)); HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | READ_CONTROL | SYNCHRONIZE, FALSE, pid);
  need(process && system_process(process)); wchar_t actual[4096]; DWORD length = 4096; char dacl[65];
  HANDLE helperToken; need(OpenProcessToken(process,TOKEN_QUERY,&helperToken)); DWORD helperSession=process_session(process);
  need(QueryFullProcessImageNameW(process, 0, actual, &length) && !wcscmp(actual, argv[2])); security(process, SE_KERNEL_OBJECT, FALSE, dacl);
  /* Pipe token inspection refers to the last read message. Keep the parked
   * reader's first frame private until both native peer checks have passed. */
  BYTE initial[4096]; DWORD initialSize = 0;
  for (;;) {
    OVERLAPPED read = {0}; read.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); need(read.hEvent && initialSize < sizeof(initial));
    BOOL ok = ReadFile(pipe, initial+initialSize, sizeof(initial)-initialSize, &used, &read);
    if (!ok) need(GetLastError() == ERROR_IO_PENDING && WaitForSingleObject(read.hEvent, 30000) == WAIT_OBJECT_0 && GetOverlappedResult(pipe, &read, &used, FALSE));
    need(used && CloseHandle(read.hEvent)); initialSize += used;
    BYTE *end = memchr(initial, '\n', initialSize); if (end) { need(end == initial+initialSize-1); break; }
  }
  need(ImpersonateNamedPipeClient(pipe) && OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token));
  wchar_t *client = token_sid(token); DWORD *session = token_info(token, TokenSessionId); SECURITY_IMPERSONATION_LEVEL *level = token_info(token, TokenImpersonationLevel);
  need(!wcscmp(client, L"S-1-5-18") && *session == 0 && *level == SecurityIdentification && RevertToSelf()); free(level); free(session); LocalFree(client); CloseHandle(token);
  if (observe_only) observer_record(argv[7], runner, process, hash, FALSE);
  BSTR instance; TASK_STATE state; DWORD engine;
  need_hr(IRunningTask_Refresh, running); need_hr(IRunningTask_get_InstanceGuid, running, &instance);
  GUID instanceId; wchar_t canonical[40]; need(SUCCEEDED(CLSIDFromString(instance, &instanceId)) && StringFromGUID2(&instanceId, canonical, 40)); SysFreeString(instance);
  need_hr(IRunningTask_get_State, running, &state); need_hr(IRunningTask_get_EnginePID, running, &engine);
  printf("{\"phase\":\"entry\",\"helper\":"); retained_identity(process,helperToken,helperSession); printf(",\"bridge\":"); identity(GetCurrentProcess()); printf(",\"processDaclSha256\":\"%s\",\"instance\":{\"guid\":\"%ls\",\"state\":%u,\"enginePid\":%lu}}\n", dacl, canonical, (unsigned)state, engine); fflush(stdout);
  DWORD written; need(WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), initial, initialSize, &written, NULL) && written == initialSize);
  /* Private duplex relay; overlapped operations retain events through completion. */
  char release[2]; DWORD released=0;
  while(released<2){need(ReadFile(GetStdHandle(STD_INPUT_HANDLE),release+released,2-released,&used,NULL)&&used);released+=used;}
  need((release[0]=='P'||release[0]=='X')&&release[1]=='\n'); BOOL aborting=release[0]=='X';
  OVERLAPPED releaseWrite={0};releaseWrite.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);need(releaseWrite.hEvent);
  BOOL sent=WriteFile(pipe,release,2,&written,&releaseWrite);
  if(!sent)need(GetLastError()==ERROR_IO_PENDING&&WaitForSingleObject(releaseWrite.hEvent,30000)==WAIT_OBJECT_0&&GetOverlappedResult(pipe,&releaseWrite,&written,FALSE));
  need(written==2&&CloseHandle(releaseWrite.hEvent));
  HANDLE input = aborting?NULL:CreateThread(NULL, 0, forward, NULL, 0, NULL); need(aborting||input);
  for (ULONGLONG total = initialSize;;) {
    BYTE bytes[65536]; OVERLAPPED read = {0}; read.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); need(read.hEvent);
    BOOL ok = ReadFile(pipe, bytes, sizeof(bytes), &used, &read); error = GetLastError();
    if (!ok && error == ERROR_IO_PENDING) { need(WaitForSingleObject(read.hEvent, observe_only ? PREPARATION_LIFETIME_MS : CUSTODY_LIFETIME_MS) == WAIT_OBJECT_0); ok = GetOverlappedResult(pipe, &read, &used, FALSE); error = GetLastError(); }
    CloseHandle(read.hEvent); if (!ok) { need(error == ERROR_BROKEN_PIPE); break; }
    total += used; DWORD written; need(used && total <= 2147483648ULL && WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), bytes, used, &written, NULL) && written == used);
  }
  need(WaitForSingleObject(process, 30000) == WAIT_OBJECT_0); DWORD exit; need(GetExitCodeProcess(process, &exit) && exit == 0);
  if(input){CancelSynchronousIo(input); need(WaitForSingleObject(input, 30000) == WAIT_OBJECT_0 && CloseHandle(input));}
  if(aborting){printf("{\"phase\":\"helper-retired\",\"exitCode\":%lu,\"helper\":",exit);retained_identity(process,helperToken,helperSession);puts("}");fflush(stdout);ack('D');}
  ULONGLONG until = GetTickCount64()+30000;
  for (;;) { IRunningTaskCollection *instances; LONG n; need_hr(IRegisteredTask_GetInstances, task, 0, &instances); need_hr(IRunningTaskCollection_get_Count, instances, &n); IRunningTaskCollection_Release(instances);
    if (!n&&!task_active(service,taskName)) break; need(GetTickCount64() < until); Sleep(10); }
  IRegisteredTask *current; need_hr(ITaskFolder_GetTask, folder, taskName, &current); char final[65]; task_check(current, argv[2], args, directory, runner); task_hash(current, final); need(!strcmp(hash, final));
  need_hr(ITaskFolder_DeleteTask, folder, taskName, 0);
  need_hr_equal(ITaskFolder_GetTask, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), folder, taskName, &old);
  printf("{\"phase\":\"retired\",\"taskSha256\":\"%s\",\"taskRemoved\":true,\"helperRetired\":true", hash);
  if (observe_only) {
    need(WaitForSingleObject(process, 0) == WAIT_OBJECT_0);
    need_hr_equal(ITaskFolder_GetTask, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), folder, taskName, &old);
    observer_record(argv[7], runner, process, hash, TRUE);
    printf(",\"helper\":"); retained_identity(process,helperToken,helperSession); printf(",\"observations\":2");
  }
  printf("}\n"); fflush(stdout);
  IRegisteredTask_Release(current); IRunningTask_Release(running); IRegisteredTask_Release(task); ITaskFolder_Release(folder); ITaskService_Release(service);
  SysFreeString(root); SysFreeString(taskName); SysFreeString(definition); VariantClear(&user); VariantClear(&securityValue); CoUninitialize(); LocalFree(runner); LocalFree(sd);
  need(CloseHandle(helperToken) && CloseHandle(process) && CloseHandle(pipe)); close_file(&image); close_file(&plan);
  if (observe_only) close_file(&receipt_root);
  for (unsigned i = 0; i < catalog_count; i++) close_file(&catalogs[i]); return 0;
}
