/* Untrusted CI fixture, admitted only through the complete restricted launch.
 * Private child acknowledgements precede external fault barriers. Denied host
 * creator capabilities require ready external controls and source arguments;
 * these finite attempts alone cannot establish containment. */
#define UNICODE
#define _UNICODE
#define COBJMACROS
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <wbemidl.h>
#include <taskschd.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "advapi32.lib")

static const wchar_t *nonce;
static HANDLE children[32];
static unsigned childCount;
static BOOL nestedContained;
static void need(BOOL ok) { if (!ok) ExitProcess(126); }
static void barrier(char expected) {
  char byte; DWORD used; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &byte, 1, &used, NULL) && used == 1 && byte == expected);
}
static void denied(const wchar_t *caseId, const char *error) {
  printf("{\"caseId\":\"%ls\",\"nonce\":\"%ls\",\"acknowledged\":true,\"nativeError\":\"%s\"}\n", caseId, nonce, error);
  need(fflush(stdout) == 0);
}
static DWORD child(DWORD flags, BOOL nested) {
  wchar_t image[4096], command[8192]; DWORD length = GetModuleFileNameW(NULL, image, 4096);
  need(length > 0 && length < 4096);
  HANDLE read, write, input, inputWrite;
  need(CreatePipe(&read, &write, NULL, 0) && CreatePipe(&input, &inputWrite, NULL, 0));
  need(SetHandleInformation(write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) &&
    SetHandleInformation(input, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)); CloseHandle(inputWrite);
  need(swprintf_s(command, 8192, L"\"%ls\" park %ls", image, nonce) > 0);
  SIZE_T size = 0; InitializeProcThreadAttributeList(NULL, 1, 0, &size); need(size && size <= 65536);
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = malloc(size); need(attrs && InitializeProcThreadAttributeList(attrs, 1, 0, &size));
  HANDLE handles[2] = { input, write };
  need(UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), NULL, NULL));
  STARTUPINFOEXW startup = {0}; startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES; startup.StartupInfo.hStdInput = input;
  startup.StartupInfo.hStdOutput = write; startup.StartupInfo.hStdError = write; startup.lpAttributeList = attrs;
  PROCESS_INFORMATION process = {0};
  BOOL created = CreateProcessW(image, command, NULL, NULL, TRUE,
    flags | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &startup.StartupInfo, &process);
  DWORD error = GetLastError(); DeleteProcThreadAttributeList(attrs); free(attrs); CloseHandle(write); CloseHandle(input);
  if (!created) { CloseHandle(read); return error; }
  need(childCount < 32); children[childCount++] = process.hProcess;
  if (nested) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job) need(GetLastError() == ERROR_ACCESS_DENIED);
    else {
      if (AssignProcessToJobObject(job, process.hProcess)) nestedContained = TRUE;
      else need(GetLastError() == ERROR_ACCESS_DENIED);
      CloseHandle(job); /* This unnamed nested Job has no kill-on-close flag. */
    }
  }
  need(ResumeThread(process.hThread) == 1); CloseHandle(process.hThread);
  char ready; DWORD bytes; need(ReadFile(read, &ready, 1, &bytes, NULL) && bytes == 1 && ready == 'A'); CloseHandle(read);
  return ERROR_SUCCESS;
}
static void acknowledgement(const wchar_t *caseId) {
  printf("{\"caseId\":\"%ls\",\"nonce\":\"%ls\",\"acknowledged\":true,\"children\":[", caseId, nonce);
  for (unsigned i = 0; i < childCount; i++) {
    FILETIME created, exited, kernel, user; need(GetProcessTimes(children[i], &created, &exited, &kernel, &user));
    ULARGE_INTEGER time; time.LowPart = created.dwLowDateTime; time.HighPart = created.dwHighDateTime;
    if (i) putchar(','); printf("{\"pid\":%lu,\"creationTime\":\"%llu\"}", GetProcessId(children[i]), time.QuadPart);
  }
  printf("],\"nestedOutcome\":\"%s\"}\n", nestedContained ? "contained" : "ERROR_ACCESS_DENIED"); need(fflush(stdout) == 0);
}
static void host_creator(const wchar_t *caseId) {
  if (!wcscmp(caseId, L"service")) {
    SetLastError(ERROR_SUCCESS); SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    DWORD error = GetLastError(); if (manager) CloseServiceHandle(manager);
    need(!manager && error == ERROR_ACCESS_DENIED); denied(caseId, "ERROR_ACCESS_DENIED"); return;
  }
  need(SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED)));
  HRESULT result;
  if (!wcscmp(caseId, L"wmi")) {
    IWbemLocator *locator = NULL;
    result = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&locator);
    if (SUCCEEDED(result)) {
      IWbemServices *services = NULL; BSTR space = SysAllocString(L"ROOT\\CIMV2"); need(space != NULL);
      result = IWbemLocator_ConnectServer(locator, space, NULL, NULL, NULL, 0, NULL, NULL, &services);
      SysFreeString(space); if (services) IWbemServices_Release(services); IWbemLocator_Release(locator);
    }
    need(result == E_ACCESSDENIED || result == WBEM_E_ACCESS_DENIED);
    denied(caseId, result == E_ACCESSDENIED ? "E_ACCESSDENIED" : "WBEM_E_ACCESS_DENIED");
  } else {
    ITaskService *service = NULL;
    result = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service);
    if (SUCCEEDED(result)) {
      VARIANT empty; VariantInit(&empty);
      result = ITaskService_Connect(service, empty, empty, empty, empty); ITaskService_Release(service);
    }
    need(result == E_ACCESSDENIED); denied(caseId, "E_ACCESSDENIED");
  }
  /* Unexpected capability acquisition fails before any task/service/process
   * registration. Protected outside state must independently remain unchanged. */
  CoUninitialize();
}
int wmain(int argc, wchar_t **argv) {
  need(argc >= 3 && argc <= 4 && _setmode(_fileno(stdout), _O_BINARY) != -1);
  const wchar_t *caseId = argv[1]; nonce = argv[2];
  need(wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32 &&
    GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE);
  if (!wcscmp(caseId, L"park")) {
    DWORD bytes; need(WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "A", 1, &bytes, NULL) && bytes == 1);
    WaitForSingleObject(GetCurrentProcess(), INFINITE); return 126;
  }
  barrier('G'); /* Only the private launcher pipe can release an attempt. */
  if (!wcscmp(caseId, L"wmi") || !wcscmp(caseId, L"com") || !wcscmp(caseId, L"service")) host_creator(caseId);
  else if (!wcscmp(caseId, L"spoofed-parent")) {
    char text[32], *end; unsigned i = 0; DWORD used; char byte;
    do { need(i < sizeof(text)-1 && ReadFile(GetStdHandle(STD_INPUT_HANDLE), &byte, 1, &used, NULL) && used == 1); text[i++] = byte; } while (byte != '\n');
    text[i-1] = 0; DWORD pid = strtoul(text, &end, 10); need(pid && *end == 0);
    SetLastError(ERROR_SUCCESS); HANDLE parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid); DWORD error = GetLastError();
    if (parent) CloseHandle(parent); need(!parent && error == ERROR_ACCESS_DENIED); denied(caseId, "ERROR_ACCESS_DENIED");
  } else if (!wcscmp(caseId, L"breakaway")) {
    need(child(CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW, FALSE) == ERROR_ACCESS_DENIED); denied(caseId, "ERROR_ACCESS_DENIED");
  } else if (!wcscmp(caseId, L"process-limit")) {
    for (unsigned i = 0; i < 31; i++) need(child(CREATE_NO_WINDOW, FALSE) == ERROR_SUCCESS);
    DWORD error = child(CREATE_NO_WINDOW, FALSE); need(error == ERROR_ACCESS_DENIED || error == ERROR_NOT_ENOUGH_QUOTA);
    acknowledgement(caseId); denied(caseId, error == ERROR_ACCESS_DENIED ? "ERROR_ACCESS_DENIED" : "ERROR_NOT_ENOUGH_QUOTA");
  } else {
    const wchar_t *cases[] = { L"detached", L"reparent", L"nested-job", L"cancel", L"owner-loss", L"helper-loss", L"last-handle-close", L"stale-identity" };
    BOOL known = FALSE; for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) if (!wcscmp(caseId, cases[i])) known = TRUE;
    need(known && child(!wcscmp(caseId, L"detached") ? DETACHED_PROCESS : CREATE_NO_WINDOW, !wcscmp(caseId, L"nested-job")) == ERROR_SUCCESS);
    acknowledgement(caseId); if (!wcscmp(caseId, L"reparent")) { barrier('E'); return 0; }
  }
  barrier('A');
  printf("{\"phase\":\"armed\",\"caseId\":\"%ls\",\"nonce\":\"%ls\"}\n", caseId, nonce); need(fflush(stdout) == 0);
  WaitForSingleObject(GetCurrentProcess(), INFINITE); return 126;
}
