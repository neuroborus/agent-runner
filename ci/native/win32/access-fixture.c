/* Untrusted, disposable CI fixture. External controls/native observers supply
 * readiness, token/identity, unchanged bytes and BFE permit/drop evidence.
 * Build only against the reviewed Winsock, RPC and private ALPC ABI closure. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <taskschd.h>
#include <wbemidl.h>
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
static HANDLE file_roots[2];
static wchar_t file_root_paths[2][4096];
static void need(BOOL ok) { if (!ok) ExitProcess(126); }
static void barrier(const wchar_t *operation) {
  printf("{\"nonce\":\"%ls\",\"operation\":\"%ls\",\"phase\":\"ready\"}\n", nonce, operation); need(fflush(stdout) == 0);
  char ack; DWORD size; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &ack, 1, &size, NULL) && size == 1 && ack == 'A');
}
static void outcome(const wchar_t *operation, BOOL allowed, DWORD code) {
  printf("{\"nonce\":\"%ls\",\"operation\":\"%ls\",\"phase\":\"attempted\",\"allowed\":%s,\"nativeCode\":%lu}\n",
    nonce, operation, allowed ? "true" : "false", code); need(fflush(stdout) == 0);
}
/* A reduced, independently checked directory handle reaches the fixed private
 * objects without granting traversal through System-only ancestors. The kernel
 * still checks each descendant's DACL/MIC against the unchanged payload token. */
static HANDLE open_target(const wchar_t *target, DWORD access) {
  if (!file_roots[0]) return CreateFileW(target, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  unsigned root = 0; size_t prefix = wcslen(file_root_paths[0]), custody = wcslen(file_root_paths[1]);
  need(file_roots[1]);
  if (wcslen(target) > custody + 1 && !_wcsnicmp(target, file_root_paths[1], custody) && target[custody] == L'\\') { root = 1; prefix = custody; }
  need(wcslen(target) > prefix + 1 && !_wcsnicmp(target, file_root_paths[root], prefix) && target[prefix] == L'\\');
  const wchar_t *relative = target + prefix + 1;
  for (const wchar_t *part = relative; *part;) {
    const wchar_t *end = wcschr(part, L'\\'); size_t size = end ? (size_t)(end - part) : wcslen(part);
    need(size && !(size == 1 && *part == L'.') && !(size == 2 && part[0] == L'.' && part[1] == L'.') &&
      !wcspbrk(part, L"/:*?"));
    if (!end) break; part = end + 1; need(*part);
  }
  typedef NTSTATUS (NTAPI *create_file)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,
    ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
  typedef ULONG (NTAPI *dos_error)(NTSTATUS);
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  create_file create = (create_file)GetProcAddress(ntdll, "NtCreateFile");
  dos_error error = (dos_error)GetProcAddress(ntdll, "RtlNtStatusToDosError"); need(create && error);
  UNICODE_STRING name = {(USHORT)(wcslen(relative) * sizeof(wchar_t)), (USHORT)(wcslen(relative) * sizeof(wchar_t)), (PWSTR)relative};
  OBJECT_ATTRIBUTES attributes = {sizeof(attributes), file_roots[root], &name, OBJ_CASE_INSENSITIVE, NULL, NULL};
  HANDLE file = NULL; IO_STATUS_BLOCK io;
  /* Reviewed native FILE_OPEN / synchronous-nonalert / open-reparse-point ABI. */
  NTSTATUS result = create(&file, access | SYNCHRONIZE, &attributes, &io, NULL, 0,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 1, 0x20 | 0x200000, NULL, 0);
  SetLastError(result < 0 ? error(result) : ERROR_SUCCESS);
  return result < 0 ? INVALID_HANDLE_VALUE : file;
}
static unsigned port(const wchar_t *text) { wchar_t *end; unsigned value = wcstoul(text, &end, 10); need(*text && !*end && (value == 0 || value >= 1024) && value <= 65535); return value; }
static int address(unsigned family, const wchar_t *text, unsigned number, SOCKADDR_STORAGE *storage) {
  ZeroMemory(storage, sizeof(*storage));
  if (family == AF_INET) { SOCKADDR_IN *value = (SOCKADDR_IN *)storage; value->sin_family = AF_INET; value->sin_port = htons((USHORT)number);
    need(InetPtonW(AF_INET, text, &value->sin_addr) == 1); return sizeof(*value); }
  SOCKADDR_IN6 *value = (SOCKADDR_IN6 *)storage; value->sin6_family = AF_INET6; value->sin6_port = htons((USHORT)number);
  need(InetPtonW(AF_INET6, text, &value->sin6_addr) == 1); return sizeof(*value);
}
static DWORD WINAPI deadline(void *unused) { (void)unused; Sleep(120000); ExitProcess(124); return 0; }
static void network(int argc, wchar_t **argv) {
  need(argc == 11); BOOL server = !wcscmp(argv[3], L"server"), udp = !wcscmp(argv[5], L"udp");
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
  need(!getsockname(socket, (SOCKADDR *)&local, &localSize));
  WSAPROTOCOL_INFOW info; need(!WSADuplicateSocketW(socket,wcstoul(argv[10],NULL,10),&info));
  printf("{\"nonce\":\"%ls\",\"operation\":\"network\",\"phase\":\"ready\",\"handle\":\"%llu\",\"hex\":\"",nonce,(ULONGLONG)socket);
  for (unsigned i=0;i<sizeof(info);i++) printf("%02x",((BYTE *)&info)[i]); printf("\"}\n"); need(fflush(stdout) == 0);
  char acknowledgement; DWORD acknowledged; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&acknowledgement,1,&acknowledged,NULL) && acknowledged == 1 && acknowledgement == 'A');
  char bytes[64]; int length = sprintf_s(bytes, sizeof(bytes), "%ls", nonce); need(length == 32);
  SOCKET channel = socket;
  if (server && !udp) { channel = accept(socket, NULL, NULL); need(channel != INVALID_SOCKET && SetHandleInformation((HANDLE)channel, HANDLE_FLAG_INHERIT, 0)); }
  if (deniedTcp) {
    u_long nonblocking = 1; need(ioctlsocket(channel, FIONBIO, &nonblocking) == 0);
    int result = connect(channel, (SOCKADDR *)&remote, remoteSize); DWORD error = WSAGetLastError();
    need(result == SOCKET_ERROR && (error == WSAEACCES || error == WSAEWOULDBLOCK));
    printf("{\"nonce\":\"%ls\",\"operation\":\"network\",\"phase\":\"initiated\",\"nativeCode\":%lu}\n", nonce, error); need(fflush(stdout) == 0);
    char drop; DWORD size; need(ReadFile(GetStdHandle(STD_INPUT_HANDLE), &drop, 1, &size, NULL) && size == 1 && drop == 'D');
    closesocket(channel); WSACleanup(); return; /* Native correlated DROP, never pending connect alone, supplies denial. */
  }
  if (!server && !udp && connect(channel, (SOCKADDR *)&remote, remoteSize) != 0) {
    DWORD error = WSAGetLastError(); outcome(L"network", FALSE, error); need(error == WSAEACCES); closesocket(channel); WSACleanup(); return;
  }
  if (!server) {
    int result = udp ? sendto(channel, bytes, length, 0, (SOCKADDR *)&remote, remoteSize) : send(channel, bytes, length, 0);
    DWORD sendError = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    need(result == length || (deniedUdp && sendError == WSAEACCES));
    if (deniedUdp) {
      printf("{\"nonce\":\"%ls\",\"operation\":\"network\",\"phase\":\"initiated\",\"nativeCode\":%lu}\n", nonce,sendError); need(fflush(stdout) == 0);
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
static SOCKET retained_sockets[8];
static BOOL sockets_started;
struct serve_context { SOCKET socket; unsigned index; DWORD verifier; };
static struct serve_context servers[8]; static unsigned server_count;
static DWORD WINAPI serve_socket(void *argument) {
  struct serve_context *context=argument; SOCKET listener=context->socket; int type, bytes = sizeof(type); need(!getsockopt(listener,SOL_SOCKET,SO_TYPE,(char *)&type,&bytes));
  if (type == SOCK_STREAM) need(!listen(listener,4));
  char expected[33]; need(sprintf_s(expected,sizeof(expected),"%ls",nonce) == 32); /* includes no terminator in wire bytes */
  for (unsigned i = 0; i < 64; i++) { SOCKET channel = listener; SOCKADDR_STORAGE peer; int length = sizeof(peer); char received[32];
    if (type == SOCK_STREAM) { channel = accept(listener,NULL,NULL); if (channel == INVALID_SOCKET) return 0; }
    int used = type == SOCK_DGRAM ? recvfrom(channel,received,32,0,(SOCKADDR *)&peer,&length) : recv(channel,received,32,MSG_WAITALL);
    if (used == SOCKET_ERROR) return 0; need(used == 32 && !memcmp(expected,received,32));
    need((type == SOCK_DGRAM ? sendto(channel,received,32,0,(SOCKADDR *)&peer,length) : send(channel,received,32,0)) == 32);
    if (context->verifier) { WSAPROTOCOL_INFOW info; need(!WSADuplicateSocketW(channel,context->verifier,&info));
      printf("{\"nonce\":\"%ls\",\"operation\":\"serve\",\"phase\":\"served\",\"index\":%u,\"handle\":\"%llu\",\"bytes\":\"%ls\",\"echo\":\"%ls\",\"hex\":\"",nonce,context->index,(ULONGLONG)channel,nonce,nonce);
      for (unsigned j=0;j<sizeof(info);j++) printf("%02x",((BYTE *)&info)[j]); printf("\"}\n"); need(fflush(stdout)==0);
    } else if (channel != listener) need(!closesocket(channel));
  } return 0;
}
static SOCKADDR_STORAGE pair_client, pair_server;
static int pair_client_size, pair_server_size;
static char pair_bytes[64]; static int pair_length;
static void private_pair(unsigned index) {
  need(index < 4 && retained_sockets[index * 2] != INVALID_SOCKET && retained_sockets[index * 2 + 1] != INVALID_SOCKET);
  pair_client_size = sizeof(pair_client); pair_server_size = sizeof(pair_server);
  need(!getsockname(retained_sockets[index * 2], (SOCKADDR *)&pair_client, &pair_client_size) &&
    !getsockname(retained_sockets[index * 2 + 1], (SOCKADDR *)&pair_server, &pair_server_size));
  pair_length = sprintf_s(pair_bytes, sizeof(pair_bytes), "%ls", nonce); need(pair_length == 32);
  BOOL udp = index % 2; barrier(L"pair");
  SOCKET client = retained_sockets[index * 2];
  if (!udp) need(!connect(client, (SOCKADDR *)&pair_server, pair_server_size));
  need((udp ? sendto(client, pair_bytes, pair_length, 0, (SOCKADDR *)&pair_server, pair_server_size) : send(client, pair_bytes, pair_length, 0)) == pair_length);
  char received[64]; SOCKADDR_STORAGE peer; int peerSize = sizeof(peer);
  int size = udp ? recvfrom(client, received, sizeof(received), 0, (SOCKADDR *)&peer, &peerSize) : recv(client, received, pair_length, MSG_WAITALL);
  need(size == pair_length && !memcmp(received, pair_bytes, size) && (!udp || (peerSize == pair_server_size && !memcmp(&peer, &pair_server, peerSize))));
  printf("{\"nonce\":\"%ls\",\"operation\":\"pair\",\"phase\":\"attempted\",\"index\":%u,\"allowed\":true,\"nativeCode\":0,\"bytes\":\"%ls\",\"echo\":\"%ls\"}\n",
    nonce, index, nonce, nonce); need(fflush(stdout) == 0);
}
static unsigned hex_digit(char value);
static int operation(int argc, wchar_t **argv) {
  need(argc >= 3 && !wcscmp(argv[1], nonce));
  if (!wcscmp(argv[2], L"file-root")) {
    need(argc == 6 && wcslen(argv[5]) < 4096); wchar_t *end;
    unsigned index = wcstoul(argv[3], &end, 10); need(*argv[3] && !*end && index < 2 && !file_roots[index]);
    HANDLE file_root = (HANDLE)(ULONG_PTR)_wcstoui64(argv[4], &end, 10); need(*argv[4] && !*end && file_root);
    FILE_ATTRIBUTE_TAG_INFO tag; wchar_t name[4096];
    DWORD size = GetFinalPathNameByHandleW(file_root, name, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    need(size > 4 && size < 4096 && !_wcsicmp(name + 4, argv[5]) &&
      GetFileInformationByHandleEx(file_root, FileAttributeTagInfo, &tag, sizeof(tag)) &&
      (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
      SetHandleInformation(file_root, HANDLE_FLAG_INHERIT, 0)); file_roots[index] = file_root; wcscpy_s(file_root_paths[index], 4096, argv[5]);
    printf("{\"nonce\":\"%ls\",\"operation\":\"file-root\",\"phase\":\"retained\",\"index\":%u,\"handle\":\"%llu\"}\n",
      nonce, index, (ULONGLONG)(ULONG_PTR)file_root); need(fflush(stdout) == 0); return 0;
  }
  if (!wcscmp(argv[2], L"socket")) {
    need(argc == 5); unsigned index = wcstoul(argv[3], NULL, 10); need(index < 8 && retained_sockets[index] == INVALID_SOCKET);
    if (!sockets_started) { WSADATA data; need(!WSAStartup(MAKEWORD(2, 2), &data)); sockets_started = TRUE; }
    need(wcslen(argv[4]) == sizeof(WSAPROTOCOL_INFOW) * 2); WSAPROTOCOL_INFOW info;
    for (unsigned i = 0; i < sizeof(info); i++) ((BYTE *)&info)[i] = (BYTE)(hex_digit((char)argv[4][i * 2]) * 16 + hex_digit((char)argv[4][i * 2 + 1]));
    retained_sockets[index] = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    need(retained_sockets[index] != INVALID_SOCKET);
    printf("{\"nonce\":\"%ls\",\"operation\":\"socket\",\"phase\":\"retained\",\"index\":%u,\"handle\":\"%llu\"}\n", nonce, index, (ULONGLONG)retained_sockets[index]); need(fflush(stdout) == 0); return 0;
  }
  if (!wcscmp(argv[2], L"pair")) { need(argc == 4); wchar_t *end; unsigned index = wcstoul(argv[3], &end, 10); need(!*end); private_pair(index); return 0; }
  if (!wcscmp(argv[2], L"serve")) { need(argc == 5); unsigned index = wcstoul(argv[3],NULL,10); need(index < 8 && retained_sockets[index] != INVALID_SOCKET && server_count<8); struct serve_context *context=&servers[server_count++]; context->socket=retained_sockets[index]; context->index=index; context->verifier=wcstoul(argv[4],NULL,10); need(context->verifier && CreateThread(NULL,0,serve_socket,context,0,NULL));
    printf("{\"nonce\":\"%ls\",\"operation\":\"serve\",\"phase\":\"ready\",\"index\":%u}\n",nonce,index); need(fflush(stdout)==0); return 0; }
  if (!wcscmp(argv[2], L"listen")) { need(argc == 5); BOOL v6=!wcscmp(argv[3],L"v6"), udp=!wcscmp(argv[4],L"udp"); need((v6 || !wcscmp(argv[3],L"v4")) && (udp || !wcscmp(argv[4],L"tcp")));
    if (!sockets_started) { WSADATA data; need(!WSAStartup(MAKEWORD(2,2),&data)); sockets_started=TRUE; }
    SOCKET socket=WSASocketW(v6 ? AF_INET6 : AF_INET,udp ? SOCK_DGRAM : SOCK_STREAM,udp ? IPPROTO_UDP : IPPROTO_TCP,NULL,0,WSA_FLAG_NO_HANDLE_INHERIT); BOOL exclusive=TRUE;
    need(socket!=INVALID_SOCKET && !setsockopt(socket,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(char *)&exclusive,sizeof(exclusive)) && (!v6 || !setsockopt(socket,IPPROTO_IPV6,IPV6_V6ONLY,(char *)&exclusive,sizeof(exclusive))));
    SOCKADDR_STORAGE bound; int length=address(v6 ? AF_INET6 : AF_INET,v6 ? L"::1" : L"127.0.0.1",0,&bound); need(!bind(socket,(SOCKADDR *)&bound,length) && (udp || !listen(socket,4)) && server_count<8); struct serve_context *context=&servers[server_count++]; context->socket=socket; need(CreateThread(NULL,0,serve_socket,context,0,NULL));
    printf("{\"nonce\":\"%ls\",\"operation\":\"listen\",\"phase\":\"ready\",\"handle\":\"%llu\"}\n",nonce,(ULONGLONG)socket); need(fflush(stdout)==0); return 0; }
  if (!wcscmp(argv[2], L"socket-info")) { need(argc == 5); DWORD pid = wcstoul(argv[3],NULL,10); SOCKET socket = (SOCKET)_wcstoui64(argv[4],NULL,10); WSAPROTOCOL_INFOW info;
    need(socket != INVALID_SOCKET && !WSADuplicateSocketW(socket,pid,&info));
    printf("{\"nonce\":\"%ls\",\"operation\":\"socket-info\",\"phase\":\"read\",\"handle\":\"%llu\",\"hex\":\"",nonce,(ULONGLONG)socket);
    for (unsigned i=0;i<sizeof(info);i++) printf("%02x",((BYTE *)&info)[i]); printf("\"}\n"); need(fflush(stdout)==0); return 0; }
  if (!wcscmp(argv[2], L"network")) { network(argc, argv); return 0; }
  need(argc == 4); const wchar_t *operation = argv[2], *target = argv[3]; barrier(operation);
  if (!wcscmp(operation, L"com") || !wcscmp(operation, L"wmi")) {
    need(SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED))); HRESULT result;
    if (!wcscmp(operation, L"com")) { ITaskService *service = NULL; VARIANT empty; VariantInit(&empty);
      result = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, (void **)&service);
      if (SUCCEEDED(result)) { result = ITaskService_Connect(service, empty, empty, empty, empty); ITaskService_Release(service); }
    } else { IWbemLocator *locator = NULL; IWbemServices *services = NULL; BSTR name = SysAllocString(L"ROOT\\CIMV2"); need(name);
      result = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void **)&locator);
      if (SUCCEEDED(result)) { result = IWbemLocator_ConnectServer(locator, name, NULL, NULL, NULL, 0, NULL, NULL, &services);
        if (services) IWbemServices_Release(services); IWbemLocator_Release(locator); } SysFreeString(name);
    }
    outcome(operation, SUCCEEDED(result), (DWORD)result); CoUninitialize(); return 0;
  }
  if (!wcscmp(operation, L"registry")) {
    wchar_t path[256]; need(swprintf_s(path, 256, L"SOFTWARE\\NativeProof\\%ls", nonce) > 0 && (!wcscmp(target, path) || (!wcsncmp(target, L"HKLM\\", 5) && !wcscmp(target + 5, path))));
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
    wchar_t source[4096]; wcscpy_s(source, 4096, target); wchar_t *leaf = wcsrchr(source, L'\\'); need(leaf); *leaf = 0; need(wcscat_s(source, 4096, L"\\owned.txt") == 0);
    /* Reach the target's actual replacement authority before source lookup.
     * This also observes the read-only profile without treating a missing or
     * inaccessible source as evidence about the protected target. */
    HANDLE destination = open_target(target, DELETE | FILE_WRITE_DATA);
    if (destination == INVALID_HANDLE_VALUE) { DWORD error = GetLastError(); outcome(operation, FALSE, error); need(error == ERROR_ACCESS_DENIED); return 0; }
    need(CloseHandle(destination));
    BOOL allowed = MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING); DWORD error = GetLastError();
    outcome(operation, allowed, error); need(!allowed && error == ERROR_ACCESS_DENIED); return 0;
  }
  if (!wcscmp(operation, L"rename")) {
    HANDLE source = open_target(target, DELETE);
    if (source == INVALID_HANDLE_VALUE) { DWORD error = GetLastError(); outcome(operation, FALSE, error); need(error == ERROR_ACCESS_DENIED); return 0; }
    need(CloseHandle(source));
    wchar_t destination[4096]; need(swprintf_s(destination, 4096, L"%ls.owned-relocated", target) > 0);
    BOOL allowed = MoveFileExW(target, destination, 0); DWORD error = GetLastError();
    outcome(operation, allowed, error); need(!allowed && error == ERROR_ACCESS_DENIED); return 0;
  }
  DWORD access = !wcscmp(operation, L"read") ? GENERIC_READ : !wcscmp(operation, L"delete") ? DELETE : GENERIC_WRITE;
  need(!wcscmp(operation, L"read") || !wcscmp(operation, L"delete") || !wcscmp(operation, L"write") || !wcscmp(operation, L"host-pipe"));
  HANDLE file = !wcscmp(operation, L"host-pipe") ? CreateFileW(target, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING, 0, NULL) : open_target(target, access); DWORD error = GetLastError();
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

static unsigned hex_digit(char value) {
  need((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'));
  return value <= '9' ? value - '0' : value - 'a' + 10;
}
int wmain(int argc, wchar_t **argv) {
  BOOL suite = argc == 3 && (!wcscmp(argv[1], L"suite") || !wcscmp(argv[1], L"controls"));
  nonce = suite ? argv[2] : argc >= 3 ? argv[1] : L"";
  need(_setmode(_fileno(stdout), _O_BINARY) != -1 && wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32 &&
    GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE && GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE &&
    CreateThread(NULL, 0, deadline, NULL, 0, NULL));
  for (unsigned i = 0; i < 8; i++) retained_sockets[i] = INVALID_SOCKET;
  if (!suite) return operation(argc, argv);
  for (unsigned sequence = 0; sequence < 128; sequence++) {
    char line[32768], byte; unsigned size = 0; DWORD used;
    while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), &byte, 1, &used, NULL) && used == 1 && byte != '\n') {
      need(size + 1 < sizeof(line)); line[size++] = byte;
    }
    if (!used) return 0; line[size] = 0;
    wchar_t values[9][4096], *args[11] = { argv[0], (wchar_t *)nonce }; unsigned count = 2; char *next;
    for (char *part = strtok_s(line, " ", &next); part; part = strtok_s(NULL, " ", &next)) {
      size_t length = strlen(part); need(count < 11 && length && length % 4 == 0 && length / 4 < 4096);
      for (unsigned i = 0; i < length / 4; i++) values[count - 2][i] = (wchar_t)((hex_digit(part[i * 4]) * 16 + hex_digit(part[i * 4 + 1])) |
        ((hex_digit(part[i * 4 + 2]) * 16 + hex_digit(part[i * 4 + 3])) << 8));
      values[count - 2][length / 4] = 0; args[count] = values[count - 2]; count++;
    }
    need(count >= 3); operation(count, args);
  }
  ExitProcess(126); return 126;
}
