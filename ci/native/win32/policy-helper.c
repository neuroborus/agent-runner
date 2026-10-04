/* CI-only LocalSystem policy writer. Protected bridges supply an explicit
 * inherited list of held private objects, and verify every derived native
 * object/filter before acknowledging mutation. No arbitrary SDDL/filter input.
 * Build/sign with the separately reviewed SDK/WDK and loader closure. */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <fwpmu.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "rpcrt4.lib")

static HANDLE engine, control;
static const wchar_t *nonce, *account, *restricting;
static PSID accountSid, restrictingSid;
static PSECURITY_DESCRIPTOR systemSd, matchSd, brokerMatchSd;
static GUID provider, sublayer;
static ULONGLONG started;
static unsigned filterNumber;
static BOOL removing, providerMode;
static HANDLE files[44];
static wchar_t paths[44][8192];
static unsigned fileCount;
static void need(BOOL ok) { if (!ok) ExitProcess(126); /* Never roll back uncertain effects. */ }
static void bounded(void) { need(GetTickCount64() - started < 30000); }
static DWORD WINAPI deadline(void *unused) {
  (void)unused; ULONGLONG elapsed = GetTickCount64() - started;
  if (elapsed < 30000) Sleep((DWORD)(30000 - elapsed)); ExitProcess(124); return 0;
}
static void ack(char expected) { char byte; DWORD size; need(ReadFile(control, &byte, 1, &size, NULL) && size == 1 && byte == expected); bounded(); }
static void frame(const char *phase) {
  printf("{\"nonce\":\"%ls\",\"phase\":\"%s\",\"pid\":%lu,\"filters\":%u}\n", nonce, phase, GetCurrentProcessId(), filterNumber);
  need(fflush(stdout) == 0);
}
static void key(unsigned index, GUID *value) {
  char seed[128]; need(sprintf_s(seed, sizeof(seed), "windows-policy:%ls:%u", nonce, index) > 0);
  BCRYPT_ALG_HANDLE algorithm; BCRYPT_HASH_HANDLE hash; BYTE bytes[32];
  need(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
    BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) == 0 &&
    BCryptHashData(hash, (BYTE *)seed, (ULONG)strlen(seed), 0) == 0 && BCryptFinishHash(hash, bytes, 32, 0) == 0);
  wchar_t text[37]; need(swprintf_s(text, 37,
    L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]) == 36);
  need(UuidFromStringW((RPC_WSTR)text, value) == RPC_S_OK);
  BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
}
static PSECURITY_DESCRIPTOR descriptor(const wchar_t *sddl) {
  PSECURITY_DESCRIPTOR result; need(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &result, NULL)); return result;
}
static void system_process(void) {
  HANDLE token; DWORD size = 0; need(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
  GetTokenInformation(token, TokenUser, NULL, 0, &size); need(size && size <= 65536);
  TOKEN_USER *user = calloc(1, size); DWORD session, returned;
  need(user && GetTokenInformation(token, TokenUser, user, size, &returned) &&
    GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &returned) && session == 0);
  BYTE system[SECURITY_MAX_SID_SIZE]; size = sizeof(system);
  need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) && EqualSid(user->User.Sid, system)); free(user); CloseHandle(token);
}
static void private_file(unsigned index, const wchar_t *handle) {
  wchar_t *end; ULONGLONG raw = _wcstoui64(handle, &end, 10); need(*handle && !*end && raw);
  HANDLE file = (HANDLE)(ULONG_PTR)raw; need(SetHandleInformation(file, HANDLE_FLAG_INHERIT, 0));
  FILE_ATTRIBUTE_TAG_INFO tag; BY_HANDLE_FILE_INFORMATION identity;
  DWORD size = GetFinalPathNameByHandleW(file, paths[index], 8192, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  need(size > 4 && size < 8192 && !wcsncmp(paths[index], L"\\\\?\\", 4) &&
    GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
    GetFileInformationByHandle(file, &identity) && identity.nNumberOfLinks == 1);
  PSID owner; PACL dacl; PSECURITY_DESCRIPTOR sd; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  need(GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd) == ERROR_SUCCESS &&
    dacl && GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED));
  BYTE system[SECURITY_MAX_SID_SIZE]; size = sizeof(system); need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &size) && EqualSid(owner, system));
  if (!removing) { ACCESS_ALLOWED_ACE *ace;
    need(dacl->AceCount == 1 && GetAce(dacl, 0, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
      EqualSid((PSID)&ace->SidStart, system) && (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS); }
  LocalFree(sd); files[index] = file;
}
static BOOL within(const wchar_t *parent, const wchar_t *child) {
  size_t length = wcslen(parent); return !_wcsnicmp(parent, child, length) && child[length] == L'\\';
}
static void paths_match(void) {
  need(!within(paths[0], paths[1]) && !within(paths[1], paths[0]) && _wcsicmp(paths[0], paths[1]) && within(paths[1], paths[2]));
  const wchar_t *tails[] = { L"owned.txt", L".git", L"metadata", L"checkout", L"configuration", L"credentials" };
  for (unsigned i = 3; i < 9; i++) {
    wchar_t expected[8192]; const wchar_t *parent = i <= 4 ? paths[2] : paths[1];
    need(swprintf_s(expected, 8192, L"%ls\\%ls", parent, tails[i - 3]) > 0 && !_wcsicmp(expected, paths[i]));
  }
  wchar_t outside[8192]; need(swprintf_s(outside, 8192, L"%ls\\outside-sentinel", paths[0]) > 0 && !_wcsicmp(outside, paths[9]));
  if (providerMode) for (unsigned i = 10; i < 12; i++) {
    wchar_t expected[8192]; need(swprintf_s(expected, 8192, L"%ls\\provider-%ls", paths[1], i == 10 ? L"home" : L"cache") > 0 && !_wcsicmp(expected, paths[i]));
  }
  for (unsigned i = providerMode ? 12 : 10; i < fileCount; i++) need(within(paths[1], paths[i]) && !within(paths[2], paths[i]) &&
    (!providerMode || (!within(paths[10], paths[i]) && !within(paths[11], paths[i]))));
  for (unsigned i = 0; i < fileCount; i++) for (unsigned j = 0; j < i; j++) need(_wcsicmp(paths[i], paths[j]));
  /* Bridges separately verify held volume/file IDs, every ancestor, exact
   * manifest/runtime hashes and the complete baseline directory inventory. */
}
static void grant(unsigned index, DWORD mask, DWORD childMask, BOOL low) {
  wchar_t sddl[2048]; need(swprintf_s(sddl, 2048, L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x%lx;;;%ls)(A;;0x%lx;;;%ls)", mask, account, mask, restricting) > 0);
  if (!mask) wcscpy_s(sddl, 2048, L"O:SYG:SYD:P(A;;FA;;;SY)");
  /* Inheritance alone cannot rule out a creator-supplied protected DACL.
   * Admission requires separately reviewed source/native access evidence that
   * explicit creation descriptors cannot grant foreign authority either. */
  if (childMask) { wchar_t inherited[1536]; need(swprintf_s(inherited, 1536,
      L"(D;OICIIO;WDWO;;;OW)(A;OICIIO;FA;;;SY)(A;OIIO;0x%lx;;;%ls)(A;OIIO;0x%lx;;;%ls)(A;CIIO;0x%lx;;;%ls)(A;CIIO;0x%lx;;;%ls)",
      childMask, account, childMask, restricting, childMask | FILE_TRAVERSE, account, childMask | FILE_TRAVERSE, restricting) > 0);
    need(wcscat_s(sddl, 2048, inherited) == 0); }
  if (low) need(wcscat_s(sddl, 2048, L"S:(ML;OICI;NW;;;LW)") == 0);
  PSECURITY_DESCRIPTOR sd = descriptor(sddl); PACL dacl, sacl; BOOL present, defaulted;
  need(GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present &&
    SetSecurityInfo(files[index], SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL) == ERROR_SUCCESS);
  if (low) need(GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted) && present &&
    SetSecurityInfo(files[index], SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, sacl) == ERROR_SUCCESS);
  LocalFree(sd);
}
static void object_security(const GUID *value, unsigned kind) {
  PACL dacl; PSID owner; BOOL present, defaulted;
  need(GetSecurityDescriptorDacl(systemSd, &present, &dacl, &defaulted) && present && GetSecurityDescriptorOwner(systemSd, &owner, &defaulted));
  /* WFP security setters use the documented owner/DACL information flags.
   * Each Add call already supplies the protected System-only descriptor. */
  SECURITY_INFORMATION info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
  DWORD status = kind == 0 ? FwpmProviderSetSecurityInfoByKey0(engine, value, info, owner, NULL, dacl, NULL) :
    kind == 1 ? FwpmSubLayerSetSecurityInfoByKey0(engine, value, info, owner, NULL, dacl, NULL) :
    FwpmFilterSetSecurityInfoByKey0(engine, value, info, owner, NULL, dacl, NULL);
  need(status == ERROR_SUCCESS);
}
static void match_descriptor(void) {
  EXPLICIT_ACCESSW access[2] = {0};
  for (unsigned i = 0; i < 2; i++) { access[i].grfAccessPermissions = FWP_ACTRL_MATCH_FILTER;
    access[i].grfAccessMode = GRANT_ACCESS; access[i].grfInheritance = NO_INHERITANCE;
    access[i].Trustee.TrusteeForm = TRUSTEE_IS_SID; access[i].Trustee.ptstrName = (LPWSTR)(i ? restrictingSid : accountSid); }
  PACL acl; need(SetEntriesInAclW(2, access, NULL, &acl) == ERROR_SUCCESS);
  SECURITY_DESCRIPTOR sd; need(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) && SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE));
  DWORD size = 0; MakeSelfRelativeSD(&sd, NULL, &size); need(size && size <= 65536);
  matchSd = LocalAlloc(LPTR, size); need(matchSd && MakeSelfRelativeSD(&sd, matchSd, &size)); LocalFree(acl);
}
static void broker_descriptor(void) {
  BYTE system[SECURITY_MAX_SID_SIZE]; DWORD bytes = sizeof(system);
  need(CreateWellKnownSid(WinLocalSystemSid, NULL, system, &bytes));
  EXPLICIT_ACCESSW access = {0}; access.grfAccessPermissions = FWP_ACTRL_MATCH_FILTER; access.grfAccessMode = GRANT_ACCESS;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID; access.Trustee.ptstrName = (LPWSTR)system;
  PACL acl; need(SetEntriesInAclW(1, &access, NULL, &acl) == ERROR_SUCCESS);
  SECURITY_DESCRIPTOR sd; need(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) && SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE));
  DWORD size = 0; MakeSelfRelativeSD(&sd, NULL, &size); need(size && size <= 65536);
  brokerMatchSd = LocalAlloc(LPTR, size); need(brokerMatchSd && MakeSelfRelativeSD(&sd, brokerMatchSd, &size)); LocalFree(acl);
}
static void same_condition(const FWPM_FILTER_CONDITION0 *a, const FWPM_FILTER_CONDITION0 *b) {
  need(IsEqualGUID(&a->fieldKey, &b->fieldKey) && a->matchType == FWP_MATCH_EQUAL && b->matchType == FWP_MATCH_EQUAL &&
    a->conditionValue.type == b->conditionValue.type);
  switch (a->conditionValue.type) {
    case FWP_UINT8: need(a->conditionValue.uint8 == b->conditionValue.uint8); break;
    case FWP_UINT16: need(a->conditionValue.uint16 == b->conditionValue.uint16); break;
    case FWP_UINT32: need(a->conditionValue.uint32 == b->conditionValue.uint32); break;
    case FWP_BYTE_ARRAY16_TYPE: need(!memcmp(a->conditionValue.byteArray16, b->conditionValue.byteArray16, sizeof(FWP_BYTE_ARRAY16))); break;
    case FWP_SECURITY_DESCRIPTOR_TYPE: need(a->conditionValue.sd && b->conditionValue.sd &&
      a->conditionValue.sd->size == b->conditionValue.sd->size && !memcmp(a->conditionValue.sd->data, b->conditionValue.sd->data, a->conditionValue.sd->size)); break;
    default: need(FALSE);
  }
}
static void filter(const GUID *layer, unsigned family, unsigned protocol, int localPort, int remotePort, unsigned principal, FWP_ACTION_TYPE action, UINT64 weight) {
  bounded(); FWPM_FILTER0 value = {0}; FWPM_FILTER_CONDITION0 conditions[6] = {0}; unsigned count = 0;
  key(filterNumber++ + 2, &value.filterKey); value.layerKey = *layer; value.subLayerKey = sublayer; value.providerKey = &provider;
  value.flags = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
  value.action.type = action; value.weight.type = FWP_UINT64; value.weight.uint64 = &weight;
  value.displayData.name = L"NativeProof owned policy";
  PSECURITY_DESCRIPTOR selected = principal == 2 ? brokerMatchSd : matchSd;
  FWP_BYTE_BLOB token = { GetSecurityDescriptorLength(selected), (BYTE *)selected };
  if (principal) { conditions[count].fieldKey = FWPM_CONDITION_ALE_USER_ID; conditions[count].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
    conditions[count++].conditionValue.sd = &token; }
  if (protocol) { conditions[count].fieldKey = FWPM_CONDITION_IP_PROTOCOL; conditions[count].conditionValue.type = FWP_UINT8;
    conditions[count++].conditionValue.uint8 = (UINT8)protocol; }
  FWP_BYTE_ARRAY16 address = {0}; address.byteArray16[15] = 1;
  for (unsigned side = 0; side < 2; side++) {
    int port = side ? remotePort : localPort; if (port < 0 && !(providerMode && principal && action == FWP_ACTION_PERMIT)) continue;
    conditions[count].fieldKey = side ? FWPM_CONDITION_IP_REMOTE_ADDRESS : FWPM_CONDITION_IP_LOCAL_ADDRESS;
    conditions[count].conditionValue.type = family == 4 ? FWP_UINT32 : FWP_BYTE_ARRAY16_TYPE;
    if (family == 4) conditions[count].conditionValue.uint32 = 0x7f000001; else conditions[count].conditionValue.byteArray16 = &address; count++;
    if (port < 0) continue;
    conditions[count].fieldKey = side ? FWPM_CONDITION_IP_REMOTE_PORT : FWPM_CONDITION_IP_LOCAL_PORT;
    conditions[count].conditionValue.type = FWP_UINT16; conditions[count++].conditionValue.uint16 = (UINT16)port;
  }
  value.numFilterConditions = count; value.filterCondition = conditions;
  if (removing) { FWPM_FILTER0 *owned; need(FwpmFilterGetByKey0(engine, &value.filterKey, &owned) == ERROR_SUCCESS &&
      owned->providerKey && IsEqualGUID(owned->providerKey, &provider) && IsEqualGUID(&owned->subLayerKey, &sublayer) &&
      IsEqualGUID(&owned->layerKey, layer) && owned->flags == value.flags && owned->action.type == action &&
      owned->weight.type == FWP_UINT64 && owned->weight.uint64 && *owned->weight.uint64 == weight && owned->numFilterConditions == count);
    for (unsigned i = 0; i < count; i++) { BOOL found = FALSE;
      for (unsigned j = 0; j < count; j++) if (IsEqualGUID(&owned->filterCondition[j].fieldKey, &conditions[i].fieldKey)) {
        need(!found); same_condition(&owned->filterCondition[j], &conditions[i]); found = TRUE; }
      need(found); }
    FwpmFreeMemory0((void **)&owned); need(FwpmFilterDeleteByKey0(engine, &value.filterKey) == ERROR_SUCCESS); }
  else { UINT64 id; need(FwpmFilterAdd0(engine, &value, systemSd, &id) == ERROR_SUCCESS); }
}
int wmain(int argc, wchar_t **argv) {
  need(argc >= 20 && argc <= 56 && _setmode(_fileno(stdout), _O_BINARY) != -1); system_process();
  nonce = argv[1]; account = argv[2]; restricting = argv[3];
  need(wcslen(nonce) == 32 && wcsspn(nonce, L"0123456789abcdef") == 32 &&
    ConvertStringSidToSidW(account, &accountSid) && ConvertStringSidToSidW(restricting, &restrictingSid) && !EqualSid(accountSid, restrictingSid));
  BOOL writable = !wcscmp(argv[4], L"workspace-write") || !wcscmp(argv[4], L"trusted-command");
  need(writable || !wcscmp(argv[4], L"read-only")); providerMode = !wcscmp(argv[5], L"install-provider") || !wcscmp(argv[5], L"remove-provider");
  removing = !wcscmp(argv[5], L"remove") || !wcscmp(argv[5], L"remove-provider");
  need(removing || !wcscmp(argv[5], L"install") || !wcscmp(argv[5], L"install-provider"));
  control = GetStdHandle(STD_INPUT_HANDLE); need(GetFileType(control) == FILE_TYPE_PIPE && GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_PIPE);
  started = GetTickCount64(); need(CreateThread(NULL, 0, deadline, NULL, 0, NULL)); frame("helper"); ack('P');
  unsigned ports[8]; for (unsigned i = 0; i < (providerMode ? 1U : 8U); i++) { wchar_t *end; ports[i] = wcstoul(argv[6 + i], &end, 10);
    need(*argv[6 + i] && !*end && ports[i] >= 1024 && ports[i] <= 65535); for (unsigned j = 0; j < i; j++) need(ports[i] != ports[j]); }
  unsigned firstFile = providerMode ? 7 : 14; fileCount = (unsigned)argc - firstFile;
  need(fileCount >= (providerMode ? 13U : 11U) && fileCount <= (providerMode ? 44U : 42U));
  for (unsigned i = 0; i < fileCount; i++) private_file(i, argv[firstFile + i]); paths_match();
  systemSd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); match_descriptor(); if (providerMode) broker_descriptor(); key(0, &provider); key(1, &sublayer);
  FWPM_SESSION0 session = {0}; session.txnWaitTimeoutInMSec = 5000; /* No DYNAMIC session flag. */
  need(FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine) == ERROR_SUCCESS);
  frame("before-write"); ack(removing ? 'D' : 'I'); /* Fresh independent custody/retirement and exact plan comparison. */
  need(FwpmTransactionBegin0(engine, 0) == ERROR_SUCCESS);
  if (!removing) {
    FWPM_PROVIDER0 p = {0}; p.providerKey = provider; p.flags = FWPM_PROVIDER_FLAG_PERSISTENT; p.displayData.name = L"NativeProof private provider";
    FWPM_SUBLAYER0 s = {0}; s.subLayerKey = sublayer; s.providerKey = &provider; s.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    s.weight = 65535; s.displayData.name = L"NativeProof private sublayer";
    need(FwpmProviderAdd0(engine, &p, systemSd) == ERROR_SUCCESS && FwpmSubLayerAdd0(engine, &s, systemSd) == ERROR_SUCCESS);
  }
  const GUID *layers[] = { &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 };
  for (unsigned layer = 0; layer < 4; layer++) {
    unsigned family = layer % 2 ? 6 : 4; filter(layers[layer], family, 0, -1, -1, TRUE, FWP_ACTION_BLOCK, 10);
    if (providerMode) {
      if (family == 4) {
        filter(layers[layer], family, 6, ports[0], -1, 0, FWP_ACTION_BLOCK, 50);
        filter(layers[layer], family, 6, -1, ports[0], 0, FWP_ACTION_BLOCK, 50);
        filter(layers[layer], family, 6, -1, ports[0], 1, FWP_ACTION_PERMIT, 100);
        filter(layers[layer], family, 6, ports[0], -1, 2, FWP_ACTION_PERMIT, 100);
      }
      continue;
    }
    for (unsigned protocol = 0; protocol < 2; protocol++) {
      unsigned offset = (family == 4 ? 0 : 4) + protocol * 2, ip = protocol ? 17 : 6;
      for (unsigned port = 0; port < 2; port++) for (unsigned side = 0; side < 2; side++)
        filter(layers[layer], family, ip, side ? -1 : ports[offset + port], side ? ports[offset + port] : -1, FALSE, FWP_ACTION_BLOCK, 50);
      filter(layers[layer], family, ip, ports[offset], ports[offset + 1], TRUE, FWP_ACTION_PERMIT, 100);
      filter(layers[layer], family, ip, ports[offset + 1], ports[offset], TRUE, FWP_ACTION_PERMIT, 100);
    }
  }
  need(filterNumber == (providerMode ? 12U : 52U) && FwpmTransactionCommit0(engine) == ERROR_SUCCESS);
  if (!removing) {
    /* Security setters are separate from the creation transaction. Failure
     * retains the initially private persistent objects and prevents release. */
    object_security(&provider, 0); object_security(&sublayer, 1);
    for (unsigned i = 0; i < filterNumber; i++) { GUID filterKey; key(i + 2, &filterKey); object_security(&filterKey, 2); }
    DWORD read = FILE_GENERIC_READ, edit = FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE;
    grant(0, 0, 0, FALSE); grant(1, FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE, 0, FALSE);
    grant(2, read | FILE_TRAVERSE | (writable ? FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY : 0), writable ? edit : read, writable);
    grant(3, writable ? edit : read, 0, writable); grant(4, read, 0, FALSE);
    for (unsigned i = 5; i < 10; i++) grant(i, 0, 0, FALSE);
    if (providerMode) for (unsigned i = 10; i < 12; i++)
      grant(i, read | FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY, edit | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY, TRUE);
    for (unsigned i = providerMode ? 12 : 10; i < fileCount; i++) grant(i, read | FILE_EXECUTE, 0, FALSE);
    wchar_t registry[256]; need(swprintf_s(registry, 256, L"SOFTWARE\\NativeProof\\%ls", nonce) > 0);
    SECURITY_ATTRIBUTES sa = { sizeof(sa), systemSd, FALSE }; HKEY keyHandle; DWORD disposition;
    need(RegCreateKeyExW(HKEY_LOCAL_MACHINE, registry, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &sa, &keyHandle, &disposition) == ERROR_SUCCESS &&
      disposition == REG_CREATED_NEW_KEY); RegCloseKey(keyHandle);
  }
  /* Removing filters does not reset ACLs or release account/storage/registry
   * reservations. Owned provider/sublayer custody remains for later cleanup. */
  frame(removing ? "removed" : "installed"); ack('V');
  need(FwpmEngineClose0(engine) == ERROR_SUCCESS); frame("settled"); return 0;
}
