/* Untrusted, disposable CI fixture. External controls/native observers supply
 * readiness, token/identity, unchanged bytes and BFE permit/drop evidence.
 * Run COM/WMI/service cases with the existing ownership-fixture.c vectors.
 * Build only against the reviewed Winsock, RPC and private ALPC ABI closure. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
static const wchar_t *nonce;
static void need(BOOL ok) { if (!ok) ExitProcess(126); }
static void barrier(const wchar_t *operation) {
  printf("{\"nonce\":\"%ls\",\"operation\":\"%ls\",\"phase\":\"ready\"}\n", nonce, operation); need(fflush(stdout) == 0);
  char ack; DWORD size; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &ack, 1, &size, NULL) && size == 1 && ack == 'A');
}
static void outcome(const wchar_t *operation, BOOL allowed, DWORD code) {
  printf("{\"nonce\":\"%ls\",\"operation\":\"%ls\",\"phase\":\"attempted\",\"allowed\":%s,\"nativeCode\":%lu}\n",
    nonce, operation, allowed ? "true" : "false", code); need(fflush(stdout) == 0);
}
static unsigned port(const wchar_t *text) { wchar_t *end; unsigned value = wcstoul(text, &end, 10); need(*text && !*end && value >= 1024 && value <= 65535); return value; }
static int address(unsigned family, const wchar_t *text, unsigned number, SOCKADDR_STORAGE *storage) {
  ZeroMemory(storage, sizeof(*storage));
  if (family == AF_INET) { SOCKADDR_IN *value = (SOCKADDR_IN *)storage; value->sin_family = AF_INET; value->sin_port = htons((USHORT)number);
    need(InetPtonW(AF_INET, text, &value->sin_addr) == 1); return sizeof(*value); }
  SOCKADDR_IN6 *value = (SOCKADDR_IN6 *)storage; value->sin6_family = AF_INET6; value->sin6_port = htons((USHORT)number);
  need(InetPtonW(AF_INET6, text, &value->sin6_addr) == 1); return sizeof(*value);
}
static DWORD WINAPI deadline(void *unused) { (void)unused; Sleep(30000); ExitProcess(124); return 0; }
static void network(int argc, wchar_t **argv) {
  need(argc == 10); BOOL server = !wcscmp(argv[3], L"server"), udp = !wcscmp(argv[5], L"udp");
  BOOL deniedUdp = !wcscmp(argv[3], L"deny-udp"), deniedTcp = !wcscmp(argv[3], L"deny-tcp");
  need(server || !wcscmp(argv[3], L"client") || (deniedUdp && udp) || (deniedTcp && !udp)); need(udp || !wcscmp(argv[5], L"tcp"));
  unsigned family = !wcscmp(argv[4], L"v4") ? AF_INET : AF_INET6; need(family == AF_INET || !wcscmp(argv[4], L"v6"));
  WSADATA data; need(WSAStartup(MAKEWORD(2, 2), &data) == 0);
  SOCKET socket = WSASocketW(family, udp ? SOCK_DGRAM : SOCK_STREAM, udp ? IPPROTO_UDP : IPPROTO_TCP, NULL, 0, WSA_FLAG_NO_HANDLE_INHERIT);
  need(socket != INVALID_SOCKET); BOOL exclusive = TRUE;
  need(setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&exclusive, sizeof(exclusive)) == 0);
  if (family == AF_INET6) need(setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&exclusive, sizeof(exclusive)) == 0);
  /* The reviewed control supplies the actual local route address. Private
   * cases bind loopback; host-network cases must reach ALE on a routable
   * interface rather than fail because their source was forced to loopback. */
  SOCKADDR_STORAGE local, remote;
  int localSize = address(family, argv[9], port(argv[6]), &local), remoteSize = address(family, argv[8], port(argv[7]), &remote);
  need(bind(socket, (SOCKADDR *)&local, localSize) == 0);
  if (server && !udp) need(listen(socket, 1) == 0);
  barrier(L"network"); /* Native socket identity and remote control are acknowledged before traffic. */
  char bytes[64]; int length = sprintf_s(bytes, sizeof(bytes), "%ls", nonce); need(length == 32);
  SOCKET channel = socket;
  if (server && !udp) { channel = accept(socket, NULL, NULL); need(channel != INVALID_SOCKET && SetHandleInformation((HANDLE)channel, HANDLE_FLAG_INHERIT, 0)); }
  if (deniedTcp) {
    u_long nonblocking = 1; need(ioctlsocket(channel, FIONBIO, &nonblocking) == 0);
    int result = connect(channel, (SOCKADDR *)&remote, remoteSize); DWORD error = WSAGetLastError();
    if (result == SOCKET_ERROR && error == WSAEACCES) { outcome(L"network", FALSE, error); closesocket(channel); WSACleanup(); return; }
    need(result == SOCKET_ERROR && error == WSAEWOULDBLOCK);
    printf("{\"nonce\":\"%ls\",\"phase\":\"initiated\",\"nativeCode\":%lu}\n", nonce, error); need(fflush(stdout) == 0);
    char drop; DWORD size; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &drop, 1, &size, NULL) && size == 1 && drop == 'D');
    closesocket(channel); WSACleanup(); return; /* Native correlated DROP, never pending connect alone, supplies denial. */
  }
  if (!server && !udp && connect(channel, (SOCKADDR *)&remote, remoteSize) != 0) {
    DWORD error = WSAGetLastError(); outcome(L"network", FALSE, error); need(error == WSAEACCES); closesocket(channel); WSACleanup(); return;
  }
  if (!server) {
    int result = udp ? sendto(channel, bytes, length, 0, (SOCKADDR *)&remote, remoteSize) : send(channel, bytes, length, 0);
    if (result == SOCKET_ERROR) { DWORD error = WSAGetLastError(); outcome(L"network", FALSE, error); need(error == WSAEACCES); closesocket(channel); WSACleanup(); return; }
    need(result == length);
    if (deniedUdp) {
      printf("{\"nonce\":\"%ls\",\"phase\":\"sent\",\"nativeCode\":0}\n", nonce); need(fflush(stdout) == 0);
      char drop; DWORD bytes;
      /* D comes only after the independent observer has joined the actual
       * BFE drop to this held socket and send. No socket error is fabricated. */
      need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &drop, 1, &bytes, NULL) && bytes == 1 && drop == 'D');
      closesocket(channel); WSACleanup(); return;
    }
  }
  char received[64]; int size = udp ? recvfrom(channel, received, sizeof(received), 0, NULL, NULL) : recv(channel, received, length, MSG_WAITALL);
  need(size == length && !memcmp(bytes, received, length));
  if (server) need((udp ? sendto(channel, received, size, 0, (SOCKADDR *)&remote, remoteSize) : send(channel, received, size, 0)) == size);
  outcome(L"network", TRUE, 0); if (channel != socket) closesocket(channel); closesocket(socket); WSACleanup();
  /* Missing native drop/permit evidence reaches the deadline and fails proof. */
}
int wmain(int argc, wchar_t **argv) {
  need(argc >= 3 && _setmode(_fileno(stdout), _O_BINARY) != -1); nonce = argv[1];
  need(wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32 &&
    GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE && GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE &&
    CreateThread(NULL, 0, deadline, NULL, 0, NULL));
  if (!wcscmp(argv[2], L"network")) { network(argc, argv); return 0; }
  need(argc == 4); const wchar_t *operation = argv[2], *target = argv[3]; barrier(operation);
  if (!wcscmp(operation, L"registry")) {
    wchar_t path[256]; need(swprintf_s(path, 256, L"SOFTWARE\\NativeProof\\%ls", nonce) > 0 && !wcscmp(target, path));
    HKEY key; LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key);
    if (result == ERROR_SUCCESS) { DWORD value = 1; result = RegSetValueExW(key, L"owned", 0, REG_DWORD, (BYTE *)&value, sizeof(value)); RegCloseKey(key); }
    outcome(operation, result == ERROR_SUCCESS, result); need(result == ERROR_ACCESS_DENIED); return 0;
  }
  if (!wcscmp(operation, L"alpc")) {
    wchar_t expected[256]; need(swprintf_s(expected, 256, L"\\RPC Control\\NativeProof-%ls", nonce) > 0 && !wcscmp(expected, target));
    typedef NTSTATUS (NTAPI *connect_port)(PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, void *, ULONG, PSID, void *, PULONG, void *, void *, PLARGE_INTEGER);
    connect_port connect = (connect_port)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAlpcConnectPort"); need(connect != NULL);
    UNICODE_STRING name; name.Buffer = (PWSTR)target; name.Length = (USHORT)(wcslen(target) * sizeof(wchar_t)); name.MaximumLength = name.Length;
    HANDLE channel = NULL; LARGE_INTEGER timeout; timeout.QuadPart = -100000000;
    NTSTATUS result = connect(&channel, &name, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, &timeout);
    if (channel) CloseHandle(channel); outcome(operation, result >= 0, result == (NTSTATUS)0xc0000022 ? ERROR_ACCESS_DENIED : (DWORD)result);
    need(result == (NTSTATUS)0xc0000022); return 0;
  }
  if (!wcscmp(operation, L"rpc")) {
    wchar_t expected[256]; need(swprintf_s(expected, 256, L"ncalrpc:[NativeProof-%ls]", nonce) > 0 && !wcscmp(expected, target));
    RPC_BINDING_HANDLE binding; need(RpcBindingFromStringBindingW((RPC_WSTR)target, &binding) == RPC_S_OK);
    RPC_STATUS result = RpcMgmtIsServerListening(binding); RpcBindingFree(&binding);
    outcome(operation, result == RPC_S_OK, result); need(result == RPC_S_ACCESS_DENIED); return 0;
  }
  if (!wcscmp(operation, L"delegation")) {
    wchar_t *end; DWORD pid = wcstoul(target, &end, 10); need(*target && !*end && pid);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), token = NULL;
    BOOL allowed = process && OpenProcessToken(process, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &token); DWORD error = GetLastError();
    if (token) CloseHandle(token); if (process) CloseHandle(process); outcome(operation, allowed, error); need(!allowed && error == ERROR_ACCESS_DENIED); return 0;
  }
  if (!wcscmp(operation, L"replace")) {
    wchar_t source[4096]; need(swprintf_s(source, 4096, L"%ls.owned-replacement", target) > 0);
    /* The prepared source is owned and independent state observes both paths. */
    BOOL allowed = MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING); DWORD error = GetLastError();
    outcome(operation, allowed, error); need(!allowed && error == ERROR_ACCESS_DENIED); return 0;
  }
  if (!wcscmp(operation, L"rename")) {
    wchar_t destination[4096]; need(swprintf_s(destination, 4096, L"%ls.owned-relocated", target) > 0);
    BOOL allowed = MoveFileExW(target, destination, 0); DWORD error = GetLastError();
    outcome(operation, allowed, error); need(!allowed && error == ERROR_ACCESS_DENIED); return 0;
  }
  DWORD access = !wcscmp(operation, L"read") ? GENERIC_READ : !wcscmp(operation, L"delete") ? DELETE : GENERIC_WRITE;
  need(!wcscmp(operation, L"read") || !wcscmp(operation, L"delete") || !wcscmp(operation, L"write") || !wcscmp(operation, L"host-pipe"));
  HANDLE file = CreateFileW(target, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
    !wcscmp(operation, L"host-pipe") ? 0 : FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL); DWORD error = GetLastError();
  BOOL allowed = file != INVALID_HANDLE_VALUE;
  if (allowed) {
    if (access == DELETE) { FILE_DISPOSITION_INFO disposition = { TRUE }; allowed = SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition)); }
    else { DWORD size; char bytes[64]; int length = sprintf_s(bytes, sizeof(bytes), "%ls", nonce); need(length == 32);
      if (access == GENERIC_READ) { char expected[64]; memcpy(expected, bytes, length); allowed = ReadFile(file, bytes, length, &size, NULL) && size == (DWORD)length && !memcmp(bytes, expected, length); }
      else { length = sprintf_s(bytes, sizeof(bytes), "%ls-owned-edit", nonce); need(length > 0); allowed = WriteFile(file, bytes, length, &size, NULL) && size == (DWORD)length; } }
    error = allowed ? 0 : GetLastError(); CloseHandle(file);
  }
  outcome(operation, allowed, error); return 0;
}
