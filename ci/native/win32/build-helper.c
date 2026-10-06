/* Sealed one-shot System compiler entry. The worker is born in a private Job
 * with an explicit pipe list and remains suspended until the held reader joins
 * its creation identity and reviewed image. Output is private bounded framing. */
#include "custody.h"
#include <io.h>
#include <fcntl.h>
static DWORD WINAPI expire(void *unused) { (void)unused; Sleep(40000); ExitProcess(124); return 0; }
static void quoted(wchar_t *command, size_t maximum, const wchar_t *value) {
  need(!wcscat_s(command, maximum, L"\"")); unsigned slashes = 0;
  for (const wchar_t *at = value;; at++) {
    if (*at == '\\') { slashes++; continue; }
    unsigned count = (*at == '"' || !*at) ? slashes*2 : slashes;
    for (unsigned i = 0; i < count; i++) need(!wcscat_s(command, maximum, L"\\"));
    slashes = 0; if (*at == '"') need(!wcscat_s(command, maximum, L"\\"));
    if (!*at) break; wchar_t next[2] = {*at, 0}; need(!wcscat_s(command, maximum, next));
  }
  need(!wcscat_s(command, maximum, L"\" "));
}
static void narrow_hash(const wchar_t *value, char result[65]) {
  need(wcslen(value) == 64); for (unsigned i = 0; i < 64; i++) { need((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')); result[i] = (char)value[i]; } result[64] = 0;
}
static void command_byte(HANDLE pipe, char expected) {
  char value; DWORD used; need(ReadFile(pipe, &value, 1, &used, NULL) && used == 1 && value == expected);
}
static void create_output(const wchar_t *path) {
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES private = attributes(sd, FALSE);
  HANDLE file = CreateFileW(path, GENERIC_WRITE | READ_CONTROL, 0, &private, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL); char dacl[65];
  need(file != INVALID_HANDLE_VALUE); security(file, SE_FILE_OBJECT, TRUE, dacl); need(CloseHandle(file)); LocalFree(sd);
}
static BOOL drain(HANDLE pipe, const char *stream, DWORD *total) {
  DWORD available; if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL)) { need(GetLastError() == ERROR_BROKEN_PIPE); return TRUE; }
  if (available) {
    BYTE bytes[1024]; DWORD used; need(ReadFile(pipe, bytes, available < sizeof(bytes) ? available : sizeof(bytes), &used, NULL) && used);
    need(*total <= 65536-used); *total += used; printf("{\"stream\":\"%s\",\"hex\":\"", stream); hex(bytes, used); puts("\"}"); need(!fflush(stdout)); SecureZeroMemory(bytes, used);
  }
  return FALSE;
}
int wmain(int argc, wchar_t **argv) {
  need(argc == 15 && system_process(GetCurrentProcess())); require_build();
  need(wcslen(argv[1]) == 32); for (unsigned i = 0; i < 32; i++) need((argv[1][i] >= '0' && argv[1][i] <= '9') || (argv[1][i] >= 'a' && argv[1][i] <= 'f'));
  BOOL compile = !wcscmp(argv[2], L"compile"), compiler = !wcscmp(argv[2], L"compiler-version"), sdk = !wcscmp(argv[2], L"sdk-version"); need(compile || compiler || sdk);
  for (unsigned i = 3; i < 15; i++) need(wcslen(argv[i]) > 0 && wcslen(argv[i]) < 4096);
  wchar_t *end; errno = 0; DWORD deadline = wcstoul(argv[10], &end, 10); need(!errno && !*end && deadline && deadline <= 30000);
  need(CreateThread(NULL, 0, expire, NULL, 0, NULL));
  char pinSha[65], signatureSha[65], signatureActual[65]; narrow_hash(argv[4], pinSha); narrow_hash(argv[5], signatureSha);
  struct held_file tool = hold(argv[3], FALSE, FALSE, GENERIC_READ); pin(&tool, pinSha); signature(&tool, signatureSha, signatureActual);
  wchar_t *name = wcsrchr(tool.path, '\\'); need(name && !_wcsicmp(name+1, sdk ? L"rc.exe" : L"cl.exe"));
  struct held_file directory = hold(argv[9], TRUE, TRUE, FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY), source = {0};
  wchar_t command[32767] = L""; quoted(command, 32767, tool.path);
  if (compile) {
    char sourceSha[65]; narrow_hash(argv[7], sourceSha); source = hold(argv[6], FALSE, TRUE, GENERIC_READ); pin(&source, sourceSha);
    wchar_t output[4096]; need(!wcscpy_s(output, 4096, argv[8])); wchar_t *leaf = wcsrchr(output, '\\'); need(leaf); *leaf = 0; need(!_wcsicmp(output, directory.path));
    create_output(argv[8]); wchar_t object[4096]; need(swprintf_s(object, 4096, L"%ls.obj", argv[8]) > 0); create_output(object);
    const wchar_t *prefix[] = {L"/nologo", L"/std:c17", L"/O2", L"/W4", L"/Brepro"};
    for (unsigned i = 0; i < 5; i++) quoted(command, 32767, prefix[i]); quoted(command, 32767, source.path);
    wchar_t arg[4096]; need(swprintf_s(arg, 4096, L"/Fo%ls.obj", argv[8]) > 0); quoted(command, 32767, arg);
    need(swprintf_s(arg, 4096, L"/Fe%ls", argv[8]) > 0); quoted(command, 32767, arg);
    const wchar_t *link[] = {L"/link", L"/Brepro", L"/INCREMENTAL:NO", L"/DYNAMICBASE", L"/NXCOMPAT", L"advapi32.lib", L"bcrypt.lib", L"crypt32.lib", L"wintrust.lib", L"psapi.lib", L"ole32.lib", L"oleaut32.lib", L"taskschd.lib", L"uuid.lib", L"fwpuclnt.lib", L"xmllite.lib", L"wevtapi.lib"};
    for (unsigned i = 0; i < sizeof(link)/sizeof(link[0]); i++) quoted(command, 32767, link[i]);
  } else { need(!wcscmp(argv[6], L"-") && !wcscmp(argv[7], L"-") && !wcscmp(argv[8], L"-")); quoted(command, 32767, sdk ? L"/?" : L"/Bv"); }
  /* No provider credentials or ambient compiler options survive. These four
   * values are already joined to the independently reviewed SDK/tool graph. */
  wchar_t clear[] = L"CI=true\0GITHUB_ACTIONS=true\0LANG=C\0\0"; need(SetEnvironmentStringsW(clear));
  const wchar_t *keys[] = {L"INCLUDE", L"LIB", L"SystemRoot", L"PATH"}; for (unsigned i = 0; i < 4; i++) need(SetEnvironmentVariableW(keys[i], argv[11+i]));
  need(SetEnvironmentVariableW(L"TEMP", directory.path) && SetEnvironmentVariableW(L"TMP", directory.path));
  HANDLE input = GetStdHandle(STD_INPUT_HANDLE); need(input && input != INVALID_HANDLE_VALUE && GetFileType(input) == FILE_TYPE_PIPE);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES inherited = attributes(sd, TRUE), private = attributes(sd, FALSE);
  HANDLE childIn, parentIn, childOut, parentOut, childError, parentError;
  need(CreatePipe(&childIn, &parentIn, &inherited, 0) && CreatePipe(&parentOut, &childOut, &inherited, 0) && CreatePipe(&parentError, &childError, &inherited, 0));
  need(SetHandleInformation(parentIn, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(parentOut, HANDLE_FLAG_INHERIT, 0) && SetHandleInformation(parentError, HANDLE_FLAG_INHERIT, 0));
  HANDLE job = CreateJobObjectW(&private, NULL); need(job); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS; limits.BasicLimitInformation.ActiveProcessLimit = 31;
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui = {255}; need(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) && SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui)));
  SIZE_T size = 0; InitializeProcThreadAttributeList(NULL, 2, 0, &size); need(size && size <= 65536); STARTUPINFOEXW start = {0}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = calloc(1, size); need(start.lpAttributeList);
  HANDLE handles[] = {childIn, childOut, childError}; need(InitializeProcThreadAttributeList(start.lpAttributeList, 2, 0, &size) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), NULL, NULL) &&
    UpdateProcThreadAttribute(start.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof(job), NULL, NULL));
  start.StartupInfo.dwFlags = STARTF_USESTDHANDLES; start.StartupInfo.hStdInput = childIn; start.StartupInfo.hStdOutput = childOut; start.StartupInfo.hStdError = childError;
  PROCESS_INFORMATION worker; need(CreateProcessW(tool.path, command, &private, &private, TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, NULL, directory.path, &start.StartupInfo, &worker));
  DeleteProcThreadAttributeList(start.lpAttributeList); free(start.lpAttributeList); LocalFree(sd);
  need(CloseHandle(childIn) && CloseHandle(childOut) && CloseHandle(childError) && CloseHandle(parentIn));
  BOOL belongs; need(system_process(worker.hProcess) && IsProcessInJob(worker.hProcess, job, &belongs) && belongs);
  printf("{\"worker\":"); identity(worker.hProcess); puts("}"); need(!fflush(stdout)); command_byte(input, 'R');
  need(ResumeThread(worker.hThread) == 1 && CloseHandle(worker.hThread)); ULONGLONG began = GetTickCount64(); DWORD total = 0;
  BOOL outClosed = FALSE, errorClosed = FALSE;
  for (;;) {
    if (!outClosed) outClosed = drain(parentOut, "stdout", &total); if (!errorClosed) errorClosed = drain(parentError, "stderr", &total);
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounts; need(QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounts, sizeof(accounts), NULL));
    if (WaitForSingleObject(worker.hProcess, 0) == WAIT_OBJECT_0 && accounts.ActiveProcesses == 0 && outClosed && errorClosed) break;
    need(GetTickCount64()-began < deadline); Sleep(1);
  }
  DWORD exit; need(GetExitCodeProcess(worker.hProcess, &exit) && exit <= 255);
  printf("{\"exitCode\":%lu,\"signal\":null,\"members\":0}\n", exit); need(!fflush(stdout)); command_byte(input, 'S');
  need(CloseHandle(parentOut) && CloseHandle(parentError) && CloseHandle(worker.hProcess) && CloseHandle(job));
  if (compile) close_file(&source); close_file(&tool); close_file(&directory); return 0;
}
