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
static DWORD WINAPI expire(void *unused) { (void)unused; Sleep(390000); ExitProcess(124); return 0; }
static void ack(char expected) { char value; DWORD used; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &value, 1, &used, NULL) && used == 1 && value == expected); }
static void xml_text(wchar_t *out, size_t maximum, const wchar_t *text) {
  for (; *text; text++) { const wchar_t *escaped = *text == '&' ? L"&amp;" : *text == '<' ? L"&lt;" : *text == '>' ? L"&gt;" : *text == '"' ? L"&quot;" : NULL;
    wchar_t byte[2] = {*text, 0}; need(wcscat_s(out, maximum, escaped ? escaped : byte) == 0); }
}
static void task_check(IRegisteredTask *task, const wchar_t *image, const wchar_t *args, const wchar_t *directory, const wchar_t *runner) {
  ITaskDefinition *definition; IPrincipal *principal; IActionCollection *actions; IAction *action; IExecAction *exec; ITriggerCollection *triggers; ITaskSettings *settings;
  BSTR text; LONG count; TASK_LOGON_TYPE logon; TASK_RUNLEVEL_TYPE level; TASK_INSTANCES_POLICY instances; VARIANT_BOOL hard;
  need(SUCCEEDED(IRegisteredTask_get_Definition(task, &definition)) && SUCCEEDED(ITaskDefinition_get_Principal(definition, &principal)) &&
    SUCCEEDED(IPrincipal_get_UserId(principal, &text)));
  BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(sid), domainSize = 256; wchar_t domain[256]; SID_NAME_USE type;
  PSID expected; need(ConvertStringSidToSidW(L"S-1-5-18", &expected));
  if (text[0] == 'S') { PSID actual; need(ConvertStringSidToSidW(text, &actual) && EqualSid(actual, expected)); LocalFree(actual); }
  else need(LookupAccountNameW(NULL, text, sid, &size, domain, &domainSize, &type) && EqualSid(sid, expected));
  SysFreeString(text); LocalFree(expected);
  need(SUCCEEDED(IPrincipal_get_LogonType(principal, &logon)) && logon == TASK_LOGON_SERVICE_ACCOUNT &&
    SUCCEEDED(IPrincipal_get_RunLevel(principal, &level)) && level == TASK_RUNLEVEL_HIGHEST &&
    SUCCEEDED(ITaskDefinition_get_Actions(definition, &actions)) && SUCCEEDED(IActionCollection_get_Count(actions, &count)) && count == 1 &&
    SUCCEEDED(IActionCollection_get_Item(actions, 1, &action)) && SUCCEEDED(IAction_QueryInterface(action, &IID_IExecAction, (void **)&exec)) &&
    SUCCEEDED(IExecAction_get_Path(exec, &text)) && !wcscmp(text, image)); SysFreeString(text);
  need(SUCCEEDED(IExecAction_get_Arguments(exec, &text)) && !wcscmp(text, args)); SysFreeString(text);
  need(SUCCEEDED(IExecAction_get_WorkingDirectory(exec, &text)) && !wcscmp(text, directory)); SysFreeString(text);
  need(SUCCEEDED(ITaskDefinition_get_Triggers(definition, &triggers)) && SUCCEEDED(ITriggerCollection_get_Count(triggers, &count)) && count == 0 &&
    SUCCEEDED(ITaskDefinition_get_Settings(definition, &settings)) && SUCCEEDED(ITaskSettings_get_MultipleInstances(settings, &instances)) && instances == TASK_INSTANCES_IGNORE_NEW &&
    SUCCEEDED(ITaskSettings_get_AllowHardTerminate(settings, &hard)) && hard == VARIANT_FALSE && SUCCEEDED(ITaskSettings_get_ExecutionTimeLimit(settings, &text)) && !wcscmp(text, L"PT6M30S")); SysFreeString(text);
  need(SUCCEEDED(IRegisteredTask_GetSecurityDescriptor(task, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text)));
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
  BSTR xml, security; need(SUCCEEDED(IRegisteredTask_get_Xml(task, &xml)) &&
    SUCCEEDED(IRegisteredTask_GetSecurityDescriptor(task, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &security)));
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
int wmain(int argc, wchar_t **argv) {
  need(argc == 9 && !wcscmp(argv[1], L"--entry") && !wcschr(argv[2], '%') && !wcschr(argv[5], '%') &&
    wcslen(argv[7]) == 32 && wcsspn(argv[7], L"0123456789abcdef") == 32 &&
    !system_process(GetCurrentProcess()) && CreateThread(NULL, 0, expire, NULL, 0, NULL));
  require_build();
  privilege(SE_BACKUP_NAME); privilege(SE_RESTORE_NAME); privilege(SE_DEBUG_NAME);
  struct held_file image = hold(argv[2], FALSE, TRUE, GENERIC_READ), plan = hold(argv[5], FALSE, TRUE, GENERIC_READ);
  char hash[65], signatureHash[65], planHash[65]; need(wcslen(argv[3]) == 64 && wcslen(argv[4]) == 64 && wcslen(argv[6]) == 64);
  for (unsigned i = 0; i < 64; i++) { hash[i] = (char)argv[3][i]; signatureHash[i] = (char)argv[4][i]; planHash[i] = (char)argv[6][i]; } hash[64] = signatureHash[64] = planHash[64] = 0;
  char observedSignature[65]; pin(&image, hash); signature(&image, signatureHash, observedSignature); pin(&plan, planHash);
  HANDLE token; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)); wchar_t *runner = token_sid(token); need(!wcscmp(runner, argv[8])); CloseHandle(token);
  wchar_t name[96], pipeName[128], sddl[1024], pipeSddl[1024], directory[4096];
  need(swprintf_s(name, 96, L"NativeProof-Custody-%ls", argv[7]) > 0 && swprintf_s(pipeName, 128, L"\\\\.\\pipe\\NativeProof-Custody-%ls", argv[7]) > 0 &&
    swprintf_s(sddl, 1024, L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGXSD;;;%ls)", runner) > 0 &&
    swprintf_s(pipeSddl, 1024, L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GRGW;;;%ls)", runner) > 0);
  wcscpy_s(directory, 4096, argv[2]); wchar_t *slash = wcsrchr(directory, '\\'); need(slash); *slash = 0;
  PSECURITY_DESCRIPTOR sd = descriptor(pipeSddl); SECURITY_ATTRIBUTES sa = attributes(sd, FALSE);
  pipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 262144, 262144, 30000, &sa); need(pipe != INVALID_HANDLE_VALUE);
  wchar_t args[16384]; need(swprintf_s(args, 16384, L"--serve \"%ls\" %ls %ls \"%ls\" %ls %lu", argv[5], argv[6], argv[7], pipeName, runner, GetCurrentProcessId()) > 0);
  wchar_t xml[32768] = L"<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Principals><Principal id=\"System\"><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT6M30S</ExecutionTimeLimit></Settings><Actions Context=\"System\"><Exec><Command>";
  xml_text(xml, 32768, argv[2]); need(wcscat_s(xml, 32768, L"</Command><Arguments>") == 0); xml_text(xml, 32768, args);
  need(wcscat_s(xml, 32768, L"</Arguments><WorkingDirectory>") == 0); xml_text(xml, 32768, directory); need(wcscat_s(xml, 32768, L"</WorkingDirectory></Exec></Actions></Task>") == 0);
  sum((BYTE *)xml, (ULONG)(wcslen(xml)*2), hash); printf("{\"phase\":\"task-intent\",\"taskSha256\":\"%s\",\"bridge\":", hash); identity(GetCurrentProcess()); puts("}"); fflush(stdout); ack('T');
  need(SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED)));
  ITaskService *service; ITaskFolder *folder; IRegisteredTask *task, *old; IRunningTask *running; VARIANT empty, user, securityValue;
  VariantInit(&empty); VariantInit(&user); VariantInit(&securityValue); user.vt = VT_BSTR; user.bstrVal = SysAllocString(L"S-1-5-18"); securityValue.vt = VT_BSTR; securityValue.bstrVal = SysAllocString(sddl);
  need(SUCCEEDED(CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service)) &&
    SUCCEEDED(ITaskService_Connect(service, empty, empty, empty, empty)));
  BSTR root = SysAllocString(L"\\"), taskName = SysAllocString(name), definition = SysAllocString(xml); need(root && taskName && definition && user.bstrVal && securityValue.bstrVal);
  need(SUCCEEDED(ITaskService_GetFolder(service, root, &folder)) && ITaskFolder_GetTask(folder, taskName, &old) == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) &&
    SUCCEEDED(ITaskFolder_RegisterTask(folder, taskName, definition, TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE, user, empty, TASK_LOGON_SERVICE_ACCOUNT, securityValue, &task)));
  task_check(task, argv[2], args, directory, runner); task_hash(task, hash);
  printf("{\"phase\":\"task-registered\",\"taskSha256\":\"%s\"}\n", hash); fflush(stdout); ack('B');
  need(SUCCEEDED(IRegisteredTask_Run(task, empty, &running)));
  OVERLAPPED connect = {0}; connect.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); need(connect.hEvent);
  BOOL connected = ConnectNamedPipe(pipe, &connect); DWORD error = GetLastError(), used;
  if (!connected && error == ERROR_IO_PENDING) need(WaitForSingleObject(connect.hEvent, 30000) == WAIT_OBJECT_0 && GetOverlappedResult(pipe, &connect, &used, FALSE));
  else need(connected || error == ERROR_PIPE_CONNECTED); CloseHandle(connect.hEvent);
  DWORD pid; need(GetNamedPipeClientProcessId(pipe, &pid)); HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | READ_CONTROL | SYNCHRONIZE, FALSE, pid);
  need(process && system_process(process)); wchar_t actual[4096]; DWORD length = 4096; char dacl[65];
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
  printf("{\"phase\":\"entry\",\"helper\":"); identity(process); printf(",\"bridge\":"); identity(GetCurrentProcess()); printf(",\"processDaclSha256\":\"%s\"}\n", dacl); fflush(stdout);
  DWORD written; need(WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), initial, initialSize, &written, NULL) && written == initialSize);
  /* Private duplex relay; overlapped operations retain events through completion. */
  HANDLE input = CreateThread(NULL, 0, forward, NULL, 0, NULL); need(input);
  for (ULONGLONG total = initialSize;;) {
    BYTE bytes[65536]; OVERLAPPED read = {0}; read.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); need(read.hEvent);
    BOOL ok = ReadFile(pipe, bytes, sizeof(bytes), &used, &read); error = GetLastError();
    if (!ok && error == ERROR_IO_PENDING) { need(WaitForSingleObject(read.hEvent, 390000) == WAIT_OBJECT_0); ok = GetOverlappedResult(pipe, &read, &used, FALSE); error = GetLastError(); }
    CloseHandle(read.hEvent); if (!ok) { need(error == ERROR_BROKEN_PIPE); break; }
    total += used; DWORD written; need(used && total <= 2147483648ULL && WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), bytes, used, &written, NULL) && written == used);
  }
  need(WaitForSingleObject(process, 30000) == WAIT_OBJECT_0); DWORD exit; need(GetExitCodeProcess(process, &exit) && exit == 0);
  CancelSynchronousIo(input); need(WaitForSingleObject(input, 30000) == WAIT_OBJECT_0 && CloseHandle(input));
  ULONGLONG until = GetTickCount64()+30000;
  for (;;) { IRunningTaskCollection *instances; LONG n; need(SUCCEEDED(IRegisteredTask_GetInstances(task, 0, &instances)) && SUCCEEDED(IRunningTaskCollection_get_Count(instances, &n))); IRunningTaskCollection_Release(instances);
    if (!n) break; need(GetTickCount64() < until); Sleep(10); }
  IRegisteredTask *current; need(SUCCEEDED(ITaskFolder_GetTask(folder, taskName, &current))); char final[65]; task_check(current, argv[2], args, directory, runner); task_hash(current, final); need(!strcmp(hash, final));
  need(SUCCEEDED(ITaskFolder_DeleteTask(folder, taskName, 0)) && ITaskFolder_GetTask(folder, taskName, &old) == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
  printf("{\"phase\":\"retired\",\"taskSha256\":\"%s\",\"taskRemoved\":true,\"helperRetired\":true}\n", hash); fflush(stdout);
  IRegisteredTask_Release(current); IRunningTask_Release(running); IRegisteredTask_Release(task); ITaskFolder_Release(folder); ITaskService_Release(service);
  SysFreeString(root); SysFreeString(taskName); SysFreeString(definition); VariantClear(&user); VariantClear(&securityValue); CoUninitialize(); LocalFree(runner); LocalFree(sd);
  need(CloseHandle(process) && CloseHandle(pipe)); close_file(&image); close_file(&plan);
  for (unsigned i = 0; i < catalog_count; i++) close_file(&catalogs[i]); return 0;
}
