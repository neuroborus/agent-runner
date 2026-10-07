/* SDK 26100 reads/writes inside the admitted one-shot System reader. Raw
 * descriptors, selectors and XML never leave its protected private pipe. */
#define COBJMACROS
#include <fwpmu.h>
#include <ntsecapi.h>
#include <xmllite.h>
#include <objbase.h>
#include <wctype.h>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "xmllite.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
C_ASSERT(sizeof(FWP_VALUE0) <= sizeof(FWP_CONDITION_VALUE0));
C_ASSERT(FIELD_OFFSET(FWP_VALUE0, uint64) == FIELD_OFFSET(FWP_CONDITION_VALUE0, uint64));

static HANDLE wfp_engine;
static HKEY registry_key;
static HANDLE registry_changed;
static GUID audit_categories[128]; static unsigned audit_count;
static AUDIT_POLICY_INFORMATION *audit_system;
static PSID audit_sid;
static struct { struct entry *entry; PACL before, wanted; PSECURITY_DESCRIPTOR baseline; } audit_objects[44];
static unsigned audit_object_count; static BOOL audit_owned, audit_used;

static void emit_sid(PSID sid) {
  wchar_t *text; need(sid && IsValidSid(sid) && ConvertSidToStringSidW(sid, &text));
  printf("\"%ls\"", text); LocalFree(text);
}
static void emit_guid(const GUID *guid) {
  wchar_t text[39]; need(StringFromGUID2(guid, text, 39) == 39);
  text[37] = 0; for (unsigned i = 1; i < 37; i++) text[i] = towlower(text[i]); printf("\"%ls\"", text + 1);
}
static void acl_read(PACL acl) {
  need(acl && IsValidAcl(acl) && acl->AceCount <= 32); putchar('[');
  for (unsigned i = 0; i < acl->AceCount; i++) {
    ACCESS_ALLOWED_ACE *ace; need(GetAce(acl, i, (void **)&ace) && ace->Header.AceSize >= 12 &&
      (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceType == ACCESS_DENIED_ACE_TYPE ||
       ace->Header.AceType == SYSTEM_AUDIT_ACE_TYPE || ace->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) &&
      IsValidSid(&ace->SidStart) && GetLengthSid(&ace->SidStart) + 8 == ace->Header.AceSize);
    printf("%s{\"type\":%u,\"flags\":%u,\"mask\":%lu,\"sid\":", i ? "," : "", ace->Header.AceType, ace->Header.AceFlags, ace->Mask);
    emit_sid(&ace->SidStart); putchar('}');
  } putchar(']');
}
static PSECURITY_DESCRIPTOR file_sd(HANDLE file, SE_OBJECT_TYPE kind) {
  HANDLE actual = file;
  if (kind == SE_FILE_OBJECT) {
    FILE_ID_INFO before, after;
    need(GetFileInformationByHandleEx(file, FileIdInfo, &before, sizeof(before)));
    actual = ReOpenFile(file, READ_CONTROL | ACCESS_SYSTEM_SECURITY, FILE_SHARE_READ | FILE_SHARE_WRITE,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    need(actual != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(actual, FileIdInfo, &after, sizeof(after)) && !memcmp(&before, &after, sizeof(before)));
  }
  PSECURITY_DESCRIPTOR sd; need(GetSecurityInfo(actual, kind, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
    DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd) == ERROR_SUCCESS);
  need(IsValidSecurityDescriptor(sd) && GetSecurityDescriptorLength(sd) <= 65536);
  if (actual != file) need(CloseHandle(actual));
  return sd;
}
static void set_file_security(HANDLE file, SECURITY_INFORMATION info, PACL dacl, PACL sacl) {
  FILE_ID_INFO before, after;
  need(GetFileInformationByHandleEx(file, FileIdInfo, &before, sizeof(before)));
  HANDLE writer = ReOpenFile(file, READ_CONTROL | WRITE_DAC | ACCESS_SYSTEM_SECURITY,
    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
  need(writer != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(writer, FileIdInfo, &after, sizeof(after)) &&
    !memcmp(&before, &after, sizeof(before)) && SetSecurityInfo(writer, SE_FILE_OBJECT, info, NULL, NULL, dacl, sacl) == ERROR_SUCCESS && CloseHandle(writer));
}
static void sd_read(PSECURITY_DESCRIPTOR sd) {
  PSID owner; PACL dacl, sacl; BOOL present, defaulted; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision; char hash[65], descriptorHash[65];
  need(GetSecurityDescriptorOwner(sd, &owner, &defaulted) && GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present && dacl &&
    GetSecurityDescriptorControl(sd, &flags, &revision) && GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted));
  need(IsValidSecurityDescriptor(sd)); sum((BYTE *)sd, GetSecurityDescriptorLength(sd), descriptorHash);
  sum((BYTE *)dacl, dacl->AclSize, hash); printf("{\"ownerSid\":"); emit_sid(owner);
  printf(",\"protectedDacl\":%s,\"daclSha256\":\"%s\",\"descriptorSha256\":\"%s\",\"aces\":", flags & SE_DACL_PROTECTED ? "true" : "false", hash, descriptorHash); acl_read(dacl);
  printf(",\"sacl\":"); if (present && sacl) acl_read(sacl); else printf("[]"); putchar('}');
}
static void access_read(unsigned subject, PSECURITY_DESCRIPTOR sd, BOOL registry) {
  need(subject < process_count); HANDLE token; TOKEN_STATISTICS *before = token_info(tokens[subject], TokenStatistics);
  need(DuplicateToken(tokens[subject], SecurityImpersonation, &token));
  GENERIC_MAPPING mapping = registry ? (GENERIC_MAPPING){KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS} :
    (GENERIC_MAPPING){FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  DWORD desired = MAXIMUM_ALLOWED, granted = 0, size = 65536; BOOL allowed;
  BYTE privileges[65536]; need(AccessCheck(sd, token, desired, &mapping, (PPRIVILEGE_SET)privileges, &size, &granted, &allowed));
  if (!allowed) granted = 0;
  /* AccessCheck is discretionary. Apply the separately read token mandatory
   * policy and object label, including the default medium/no-write-up label. */
  TOKEN_MANDATORY_LABEL *level = token_info(token, TokenIntegrityLevel);
  TOKEN_MANDATORY_POLICY *policy = token_info(token, TokenMandatoryPolicy);
  need(policy->Policy & TOKEN_MANDATORY_POLICY_NO_WRITE_UP);
  DWORD subjectLevel = *GetSidSubAuthority(level->Label.Sid, *GetSidSubAuthorityCount(level->Label.Sid)-1);
  PACL sacl; BOOL present, defaulted; need(GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted));
  DWORD objectLevel = SECURITY_MANDATORY_MEDIUM_RID, label = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP; unsigned labels = 0;
  if (present && sacl) for (unsigned i = 0; i < sacl->AceCount; i++) { SYSTEM_MANDATORY_LABEL_ACE *ace; need(GetAce(sacl, i, (void **)&ace));
    if (ace->Header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE) continue;
    need(++labels == 1 && IsValidSid(&ace->SidStart)); PSID sid = &ace->SidStart;
    objectLevel = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid)-1); label = ace->Mask;
  }
  DWORD denied = 0;
  if (subjectLevel < objectLevel) {
    if ((label & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) && (policy->Policy & TOKEN_MANDATORY_POLICY_NO_WRITE_UP))
      denied |= registry ? KEY_WRITE | DELETE | WRITE_DAC | WRITE_OWNER : FILE_GENERIC_WRITE | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    if (label & SYSTEM_MANDATORY_LABEL_NO_READ_UP) denied |= registry ? KEY_READ : FILE_GENERIC_READ;
    if (label & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP) denied |= registry ? KEY_EXECUTE : FILE_GENERIC_EXECUTE;
    /* Generic read/write include shared READ_CONTROL/SYNCHRONIZE bits. MIC
     * denies operation rights, rather than those shared query/sync rights. */
    denied &= ~(READ_CONTROL | SYNCHRONIZE);
  }
  TOKEN_STATISTICS *after = token_info(tokens[subject], TokenStatistics);
  need(!memcmp(&before->ModifiedId, &after->ModifiedId, sizeof(LUID)) && CloseHandle(token));
  printf("{\"granted\":%lu,\"micDenied\":%lu,\"subjectLevel\":%lu,\"objectLevel\":%lu,\"label\":%lu,\"tokenId\":\"%08lx%08lx\"}",
    granted, denied, subjectLevel, objectLevel, label, before->TokenId.HighPart, before->TokenId.LowPart);
  free(before); free(after); free(level); free(policy);
}
static void effective_acl(unsigned subject, struct entry *entry) {
  PSECURITY_DESCRIPTOR sd = file_sd(entry->file.handle, SE_FILE_OBJECT), again;
  printf("{\"object\":"); inspect(entry); printf(",\"security\":"); sd_read(sd); printf(",\"access\":"); access_read(subject, sd, FALSE);
  again = file_sd(entry->file.handle, SE_FILE_OBJECT);
  need(GetSecurityDescriptorLength(sd) == GetSecurityDescriptorLength(again) && !memcmp(sd, again, GetSecurityDescriptorLength(sd)));
  LocalFree(sd); LocalFree(again); putchar('}');
}
/* Observe the read-access escape with public AccessCheck, rather than infer
 * TOKEN_WRITE_RESTRICTED from an undocumented TokenAccessInformation bit. The
 * second descriptor is a positive control for the exact retained token. */
static BOOL write_restricted(HANDLE original, PSID user, TOKEN_GROUPS *restricted) {
  need(restricted->GroupCount == 1 && !EqualSid(user, restricted->Groups[0].Sid));
  DWORD size = sizeof(ACL) + 2*sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(user) + GetLengthSid(restricted->Groups[0].Sid);
  PACL acl = calloc(1, size); need(acl && InitializeAcl(acl, size, ACL_REVISION) && AddAccessAllowedAce(acl, ACL_REVISION, FILE_READ_DATA, user));
  SECURITY_DESCRIPTOR sd; need(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
    SetSecurityDescriptorOwner(&sd, user, FALSE) && SetSecurityDescriptorGroup(&sd, user, FALSE) && SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE));
  HANDLE token; need(DuplicateToken(original, SecurityImpersonation, &token));
  GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  BYTE privileges[65536]; DWORD used = sizeof(privileges), granted; BOOL escape, control;
  need(AccessCheck(&sd, token, FILE_READ_DATA, &mapping, (PPRIVILEGE_SET)privileges, &used, &granted, &escape));
  need(AddAccessAllowedAce(acl, ACL_REVISION, FILE_READ_DATA, restricted->Groups[0].Sid)); used = sizeof(privileges);
  need(AccessCheck(&sd, token, FILE_READ_DATA, &mapping, (PPRIVILEGE_SET)privileges, &used, &granted, &control) && control && granted == FILE_READ_DATA && CloseHandle(token));
  free(acl); return escape;
}
static void effective_token_handle(HANDLE token) {
  TOKEN_STATISTICS *before = token_info(token, TokenStatistics);
  TOKEN_GROUPS *restricted = token_info(token, TokenRestrictedSids), *groups = token_info(token, TokenGroups);
  TOKEN_PRIVILEGES *privileges = token_info(token, TokenPrivileges); TOKEN_MANDATORY_LABEL *level = token_info(token, TokenIntegrityLevel);
  DWORD *virtualized = token_info(token, TokenVirtualizationEnabled), *session = token_info(token, TokenSessionId);
  TOKEN_USER *nativeUser = token_info(token, TokenUser); wchar_t *user = token_sid(token);
  BOOL readEscape = write_restricted(token, nativeUser->User.Sid, restricted);
  need(restricted->GroupCount <= 8 && groups->GroupCount <= 128 && privileges->PrivilegeCount <= 64);
  printf("{\"userSid\":\"%ls\",\"restrictedSids\":[", user); LocalFree(user);
  for (unsigned i = 0; i < restricted->GroupCount; i++) { if (i) putchar(','); emit_sid(restricted->Groups[i].Sid); }
  printf("],\"enabledGroups\":["); unsigned emitted = 0;
  for (unsigned i = 0; i < groups->GroupCount; i++) if (groups->Groups[i].Attributes & SE_GROUP_ENABLED) { if (emitted++) putchar(','); emit_sid(groups->Groups[i].Sid); }
  printf("],\"privileges\":[");
  for (unsigned i = 0; i < privileges->PrivilegeCount; i++) printf("%s\"%08lx%08lx\"", i ? "," : "", privileges->Privileges[i].Luid.HighPart, privileges->Privileges[i].Luid.LowPart);
  printf("],\"integritySid\":"); emit_sid(level->Label.Sid);
  printf(",\"sessionId\":%lu,\"tokenId\":\"%08lx%08lx\",\"authenticationId\":\"%08lx%08lx\",\"primary\":%s,\"virtualized\":%s,\"writeRestricted\":%s}",
    *session, before->TokenId.HighPart, before->TokenId.LowPart, before->AuthenticationId.HighPart, before->AuthenticationId.LowPart,
    before->TokenType == TokenPrimary ? "true" : "false", *virtualized ? "true" : "false", readEscape ? "true" : "false");
  TOKEN_STATISTICS *after = token_info(token, TokenStatistics); need(!memcmp(&before->ModifiedId, &after->ModifiedId, sizeof(LUID)));
  free(before); free(after); free(restricted); free(groups); free(privileges); free(level); free(virtualized); free(session); free(nativeUser);
}
static void effective_token(unsigned subject) {
  need(subject < process_count); effective_token_handle(tokens[subject]);
}
static void effective_registry(unsigned subject) {
  wchar_t name[128]; need(swprintf_s(name, 128, L"SOFTWARE\\NativeProof\\%hs", nonce) > 0);
  if (!registry_key) {
    need(RegOpenKeyExW(HKEY_LOCAL_MACHINE, name, 0, READ_CONTROL | ACCESS_SYSTEM_SECURITY | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_WOW64_64KEY, &registry_key) == ERROR_SUCCESS);
    registry_changed = CreateEventW(NULL, TRUE, FALSE, NULL); need(registry_changed &&
      RegNotifyChangeKeyValue(registry_key, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY, registry_changed, TRUE) == ERROR_SUCCESS);
  }
  need(WaitForSingleObject(registry_changed, 0) == WAIT_TIMEOUT);
  typedef NTSTATUS (NTAPI *query)(HANDLE, int, PVOID, ULONG, PULONG);
  query get = (query)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryKey"); BYTE bytes[4096]; ULONG used;
  need(get && !get(registry_key, 3, bytes, sizeof(bytes), &used)); DWORD length = *(DWORD *)bytes;
  need(used >= 4 && length && !(length%2) && length <= used-4 && used <= sizeof(bytes));
  DWORD children, values; FILETIME written; need(RegQueryInfoKeyW(registry_key, NULL, NULL, NULL, &children, NULL, NULL, &values, NULL, NULL, NULL, &written) == ERROR_SUCCESS);
  PSECURITY_DESCRIPTOR sd = file_sd(registry_key, SE_REGISTRY_KEY);
  printf("{\"nameHex\":\""); hex(bytes+4, length); printf("\",\"children\":%lu,\"values\":%lu,\"written\":\"%08lx%08lx\",\"security\":", children, values, written.dwHighDateTime, written.dwLowDateTime);
  sd_read(sd); printf(",\"access\":"); access_read(subject, sd, TRUE); putchar('}'); LocalFree(sd);
  need(WaitForSingleObject(registry_changed, 0) == WAIT_TIMEOUT);
}
static void wfp_open(void) {
  if (!wfp_engine) { FWPM_SESSION0 session = {0}; session.txnWaitTimeoutInMSec = 5000;
    need(FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &wfp_engine) == ERROR_SUCCESS); }
}
static GUID parse_guid(const char *text) {
  need(strlen(text) == 36); wchar_t wide[39]; need(swprintf_s(wide, 39, L"{%hs}", text) == 38); GUID value;
  need(SUCCEEDED(CLSIDFromString(wide, &value))); return value;
}
static void wfp_security(const GUID *key, unsigned kind) {
  PSECURITY_DESCRIPTOR sd; DWORD status;
  SECURITY_INFORMATION flags = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
  status = kind == 0 ? FwpmProviderGetSecurityInfoByKey0(wfp_engine, key, flags, NULL, NULL, NULL, NULL, &sd) :
    kind == 1 ? FwpmSubLayerGetSecurityInfoByKey0(wfp_engine, key, flags, NULL, NULL, NULL, NULL, &sd) :
    FwpmFilterGetSecurityInfoByKey0(wfp_engine, key, flags, NULL, NULL, NULL, NULL, &sd);
  need(status == ERROR_SUCCESS); sd_read(sd); FwpmFreeMemory0((void **)&sd);
}
static void wfp_condition(const FWPM_FILTER_CONDITION0 *condition) {
  const GUID *keys[] = {&FWPM_CONDITION_ALE_USER_ID, &FWPM_CONDITION_IP_PROTOCOL, &FWPM_CONDITION_IP_LOCAL_ADDRESS,
    &FWPM_CONDITION_IP_REMOTE_ADDRESS, &FWPM_CONDITION_IP_LOCAL_PORT, &FWPM_CONDITION_IP_REMOTE_PORT};
  const char *names[] = {"principal", "protocol", "localAddress", "remoteAddress", "localPort", "remotePort"}; unsigned field = 6;
  for (unsigned i = 0; i < 6; i++) if (IsEqualGUID(&condition->fieldKey, keys[i])) field = i;
  need(field < 6 && condition->matchType == FWP_MATCH_EQUAL); printf("{\"field\":\"%s\"", names[field]);
  printf(",\"type\":%u,\"value\":", condition->conditionValue.type);
  switch (condition->conditionValue.type) {
    case FWP_UINT8: printf("%u", condition->conditionValue.uint8); break;
    case FWP_UINT16: printf("%u", condition->conditionValue.uint16); break;
    case FWP_UINT32: printf("%lu", condition->conditionValue.uint32); break;
    case FWP_BYTE_ARRAY16_TYPE: need(condition->conditionValue.byteArray16); putchar('"'); hex(condition->conditionValue.byteArray16->byteArray16, 16); putchar('"'); break;
    case FWP_SECURITY_DESCRIPTOR_TYPE: {
      FWP_BYTE_BLOB *blob = condition->conditionValue.sd; need(blob && blob->size && blob->size <= 4096 && IsValidSecurityDescriptor(blob->data));
      PACL dacl; BOOL present, defaulted; need(GetSecurityDescriptorDacl(blob->data, &present, &dacl, &defaulted) && present && dacl);
      acl_read(dacl); break;
    }
    default: need(FALSE); /* Unsupported native condition types never become inferred observations. */
  } putchar('}');
}
static void effective_wfp(const char *text, unsigned kind) {
  wfp_open(); GUID key = parse_guid(text);
  if (kind == 0) { FWPM_PROVIDER0 *provider; need(FwpmProviderGetByKey0(wfp_engine, &key, &provider) == ERROR_SUCCESS);
    need(provider->providerData.size <= 4096 && (!provider->providerData.size || provider->providerData.data));
    printf("{\"key\":"); emit_guid(&provider->providerKey); printf(",\"flags\":%lu,\"providerData\":\"", provider->flags); hex(provider->providerData.data, provider->providerData.size);
    printf("\",\"serviceNameHex\":"); if (provider->serviceName) { need(wcsnlen_s(provider->serviceName, 2049) <= 2048); putchar('"'); hex((BYTE *)provider->serviceName, wcslen(provider->serviceName)*2); putchar('"'); } else printf("null");
    printf(",\"security\":"); wfp_security(&key, 0); FwpmFreeMemory0((void **)&provider);
  } else if (kind == 1) { FWPM_SUBLAYER0 *sublayer; need(FwpmSubLayerGetByKey0(wfp_engine, &key, &sublayer) == ERROR_SUCCESS && sublayer->providerKey);
    printf("{\"key\":"); emit_guid(&sublayer->subLayerKey); printf(",\"providerKey\":"); emit_guid(sublayer->providerKey);
    need(sublayer->providerData.size <= 4096 && (!sublayer->providerData.size || sublayer->providerData.data));
    printf(",\"weight\":%u,\"flags\":%lu,\"providerData\":\"", sublayer->weight, sublayer->flags); hex(sublayer->providerData.data, sublayer->providerData.size);
    printf("\",\"security\":"); wfp_security(&key, 1); FwpmFreeMemory0((void **)&sublayer);
  } else { FWPM_FILTER0 *filter; need(FwpmFilterGetByKey0(wfp_engine, &key, &filter) == ERROR_SUCCESS && filter->providerKey &&
      filter->weight.type == FWP_UINT64 && filter->weight.uint64 && filter->numFilterConditions <= 8 &&
      (filter->action.type == FWP_ACTION_BLOCK || filter->action.type == FWP_ACTION_PERMIT));
    const GUID *layers[] = {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
    const char *names[] = {"ALE_AUTH_CONNECT_V4", "ALE_AUTH_CONNECT_V6", "ALE_AUTH_RECV_ACCEPT_V4", "ALE_AUTH_RECV_ACCEPT_V6"}; unsigned layer = 4;
    for (unsigned i = 0; i < 4; i++) if (IsEqualGUID(&filter->layerKey, layers[i])) layer = i; need(layer < 4);
    printf("{\"key\":"); emit_guid(&filter->filterKey); printf(",\"providerKey\":"); emit_guid(filter->providerKey); printf(",\"sublayerKey\":"); emit_guid(&filter->subLayerKey);
    printf(",\"id\":\"%llu\",\"layer\":\"%s\",\"flags\":%lu,\"weight\":%llu,\"action\":\"%s\",\"conditions\":[", filter->filterId, names[layer], filter->flags,
      *filter->weight.uint64, filter->action.type == FWP_ACTION_BLOCK ? "BLOCK" : "PERMIT");
    for (unsigned i = 0; i < filter->numFilterConditions; i++) { if (i) putchar(','); wfp_condition(&filter->filterCondition[i]); }
    printf("],\"security\":"); wfp_security(&key, 2); FwpmFreeMemory0((void **)&filter);
  } putchar('}');
}
static void wfp_inventory(void) {
  wfp_open(); HANDLE enumeration; need(FwpmFilterCreateEnumHandle0(wfp_engine, NULL, &enumeration) == ERROR_SUCCESS);
  FWPM_FILTER0 **filters; UINT32 count, total = 0; putchar('[');
  do { need(FwpmFilterEnum0(wfp_engine, enumeration, 128, &filters, &count) == ERROR_SUCCESS);
    for (unsigned i = 0; i < count; i++) { need(++total <= 2048); if (total > 1) putchar(','); emit_guid(&filters[i]->filterKey); }
    FwpmFreeMemory0((void **)&filters);
  } while (count);
  need(FwpmFilterDestroyEnumHandle0(wfp_engine, enumeration) == ERROR_SUCCESS); putchar(']');
}
/* Pointer-free matched SDK values retain foreign/global conditions too. An
 * unsupported representation blocks the complete graph rather than dropping it. */
static void wfp_value(FWP_DATA_TYPE type, const FWP_CONDITION_VALUE0 *value, unsigned depth) {
  need(depth <= 1); printf("{\"type\":%u,\"value\":", type);
  switch (type) {
    case FWP_EMPTY: printf("null"); break;
    case FWP_UINT8: printf("%u", value->uint8); break;
    case FWP_UINT16: printf("%u", value->uint16); break;
    case FWP_UINT32: printf("%lu", value->uint32); break;
    case FWP_UINT64: need(value->uint64); printf("\"%llu\"", *value->uint64); break;
    case FWP_INT8: printf("%d", value->int8); break;
    case FWP_INT16: printf("%d", value->int16); break;
    case FWP_INT32: printf("%ld", value->int32); break;
    case FWP_INT64: need(value->int64); printf("\"%lld\"", *value->int64); break;
    case FWP_FLOAT: putchar('"'); hex((BYTE *)&value->float32, sizeof(value->float32)); putchar('"'); break;
    case FWP_DOUBLE: need(value->double64); putchar('"'); hex((BYTE *)value->double64, sizeof(*value->double64)); putchar('"'); break;
    case FWP_BYTE_ARRAY16_TYPE: need(value->byteArray16); putchar('"'); hex(value->byteArray16->byteArray16, 16); putchar('"'); break;
    case FWP_BYTE_ARRAY6_TYPE: need(value->byteArray6); putchar('"'); hex(value->byteArray6->byteArray6, 6); putchar('"'); break;
    case FWP_BYTE_BLOB_TYPE: case FWP_SECURITY_DESCRIPTOR_TYPE: case FWP_TOKEN_ACCESS_INFORMATION_TYPE: {
      const FWP_BYTE_BLOB *blob = type == FWP_BYTE_BLOB_TYPE ? value->byteBlob : type == FWP_SECURITY_DESCRIPTOR_TYPE ? value->sd : value->tokenAccessInformation;
      need(blob && blob->size <= 4096 && (!blob->size || blob->data)); putchar('"'); hex(blob->data, blob->size); putchar('"'); break;
    }
    case FWP_UNICODE_STRING_TYPE: need(value->unicodeString && wcsnlen_s(value->unicodeString, 2049) <= 2048);
      putchar('"'); hex((BYTE *)value->unicodeString, wcslen(value->unicodeString)*2); putchar('"'); break;
    case FWP_TOKEN_INFORMATION_TYPE: {
      FWP_TOKEN_INFORMATION *token = value->tokenInformation; need(token && token->sidCount <= 128 && token->restrictedSidCount <= 128);
      printf("{\"sids\":["); for (unsigned i = 0; i < token->sidCount; i++) { printf("%s{\"sid\":", i ? "," : ""); emit_sid(token->sids[i].Sid); printf(",\"attributes\":%lu}", token->sids[i].Attributes); }
      printf("],\"restricted\":["); for (unsigned i = 0; i < token->restrictedSidCount; i++) { printf("%s{\"sid\":", i ? "," : ""); emit_sid(token->restrictedSids[i].Sid); printf(",\"attributes\":%lu}", token->restrictedSids[i].Attributes); } printf("]}"); break;
    }
    case FWP_V4_ADDR_MASK: need(value->v4AddrMask); printf("{\"address\":%lu,\"mask\":%lu}", value->v4AddrMask->addr, value->v4AddrMask->mask); break;
    case FWP_V6_ADDR_MASK: need(value->v6AddrMask && value->v6AddrMask->prefixLength <= 128); printf("{\"address\":\""); hex(value->v6AddrMask->addr, 16); printf("\",\"prefix\":%u}", value->v6AddrMask->prefixLength); break;
    case FWP_RANGE_TYPE: {
      need(!depth && value->rangeValue); printf("{\"low\":");
      /* Scalar FWP_VALUE0 and FWP_CONDITION_VALUE0 share the SDK type/union
       * prefix; copy values into initialized storage, never hash pointers. */
      FWP_CONDITION_VALUE0 low = {0}, high = {0};
      memcpy(&low, &value->rangeValue->valueLow, sizeof(FWP_VALUE0)); memcpy(&high, &value->rangeValue->valueHigh, sizeof(FWP_VALUE0));
      wfp_value(low.type, &low, depth+1); printf(",\"high\":"); wfp_value(high.type, &high, depth+1); putchar('}'); break;
    }
    default: need(FALSE);
  } putchar('}');
}
static void wfp_global(const char *text) {
  wfp_open(); GUID key = parse_guid(text); FWPM_FILTER0 *filter;
  need(FwpmFilterGetByKey0(wfp_engine, &key, &filter) == ERROR_SUCCESS && filter->numFilterConditions <= 64);
  FWPM_SUBLAYER0 *sublayer; need(FwpmSubLayerGetByKey0(wfp_engine, &filter->subLayerKey, &sublayer) == ERROR_SUCCESS);
  printf("{\"key\":"); emit_guid(&filter->filterKey); printf(",\"providerKey\":"); if (filter->providerKey) emit_guid(filter->providerKey); else printf("null");
  printf(",\"layer\":"); emit_guid(&filter->layerKey); printf(",\"sublayer\":"); emit_guid(&filter->subLayerKey);
  printf(",\"sublayerWeight\":%u,\"sublayerFlags\":%lu,\"sublayerProviderKey\":", sublayer->weight, sublayer->flags);
  if (sublayer->providerKey) emit_guid(sublayer->providerKey); else printf("null");
  printf(",\"sublayerSecurity\":"); wfp_security(&filter->subLayerKey, 1); FwpmFreeMemory0((void **)&sublayer);
  printf(",\"id\":\"%llu\",\"flags\":%lu,\"action\":%u,\"callout\":", filter->filterId, filter->flags, filter->action.type);
  if (filter->action.type & FWP_ACTION_FLAG_CALLOUT) emit_guid(&filter->action.calloutKey); else printf("null");
  printf(",\"context\":"); if (filter->flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT) emit_guid(&filter->providerContextKey); else printf("\"%llu\"", filter->rawContext);
  need(filter->providerData.size <= 4096 && (!filter->providerData.size || filter->providerData.data));
  printf(",\"providerData\":\""); hex(filter->providerData.data, filter->providerData.size); putchar('"');
  FWP_CONDITION_VALUE0 weight = {0}, effective = {0}; memcpy(&weight, &filter->weight, sizeof(FWP_VALUE0)); memcpy(&effective, &filter->effectiveWeight, sizeof(FWP_VALUE0));
  printf(",\"weight\":"); wfp_value(weight.type, &weight, 0); printf(",\"effectiveWeight\":"); wfp_value(effective.type, &effective, 0);
  printf(",\"conditions\":["); for (unsigned i = 0; i < filter->numFilterConditions; i++) { FWPM_FILTER_CONDITION0 *condition = &filter->filterCondition[i];
    printf("%s{\"field\":", i ? "," : ""); emit_guid(&condition->fieldKey); printf(",\"match\":%u,\"value\":", condition->matchType); wfp_value(condition->conditionValue.type, &condition->conditionValue, 0); putchar('}'); }
  printf("],\"security\":"); wfp_security(&key, 2); putchar('}'); FwpmFreeMemory0((void **)&filter);
}
static struct held_file relative_hold(struct entry *root, const wchar_t *relative, BOOL directory) {
  FILE_ATTRIBUTE_TAG_INFO tag; need(GetFileInformationByHandleEx(root->file.handle, FileAttributeTagInfo, &tag, sizeof(tag)) && tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
  need(*relative && wcslen(relative) < 2048 && !wcschr(relative, ':') && !wcschr(relative, '/') && relative[0] != '\\');
  wchar_t parts[4096], path[4096]; wcscpy_s(parts, 4096, relative); wchar_t *state;
  for (wchar_t *part = wcstok_s(parts, L"\\", &state); part; part = wcstok_s(NULL, L"\\", &state))
    need(*part && wcscmp(part, L".") && wcscmp(part, L"..") && !wcschr(part, '*') && !wcschr(part, '?'));
  need(swprintf_s(path, 4096, L"%ls\\%ls", root->path, relative) > 0); return hold(path, directory, FALSE, directory ? FILE_LIST_DIRECTORY : GENERIC_READ);
}
static void barrier_read(struct held_file *file, BOOL contents) {
  BY_HANDLE_FILE_INFORMATION info; LARGE_INTEGER size; need(GetFileInformationByHandle(file->handle, &info) && info.nNumberOfLinks == 1 && GetFileSizeEx(file->handle, &size) && size.QuadPart >= 0 && size.QuadPart <= (contents ? 65536 : 134217728));
  DWORD used = 0; BYTE *bytes = size.QuadPart ? read_file(file, (DWORD)size.QuadPart, &used) : calloc(1, 1); need(bytes);
  char hash[65], securitySha[65]; sum(bytes, used, hash); security(file->handle, SE_FILE_OBJECT, FALSE, securitySha);
  printf("{\"identity\":\""); file_id(file); printf("\",\"sha256\":\"%s\",\"daclSha256\":\"%s\",\"bytes\":%lu", hash, securitySha, used);
  if (contents) { printf(",\"hex\":\""); hex(bytes, used); putchar('"'); } putchar('}'); SecureZeroMemory(bytes, used); free(bytes);
}
static void tree_read(struct entry *root, const wchar_t *prefix, unsigned depth, unsigned *total, unsigned *emitted) {
  need(depth < 16); wchar_t pattern[4096]; need(swprintf_s(pattern, 4096, L"%ls\\%ls%ls*", root->path, prefix, *prefix ? L"\\" : L"") > 0);
  WIN32_FIND_DATAW value; HANDLE search = FindFirstFileW(pattern, &value);
  if (search == INVALID_HANDLE_VALUE) { need(GetLastError() == ERROR_FILE_NOT_FOUND); return; }
  do { if (!wcscmp(value.cFileName, L".") || !wcscmp(value.cFileName, L"..")) continue;
    need(!(value.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && ++*total <= 256);
    wchar_t relative[4096]; need(swprintf_s(relative, 4096, L"%ls%ls%ls", prefix, *prefix ? L"\\" : L"", value.cFileName) > 0);
    need(wcslen(relative) <= 240); BOOL directory = !!(value.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY); struct held_file file = relative_hold(root, relative, directory);
    if (!directory) { if ((*emitted)++) putchar(','); printf("{\"nameHex\":\""); hex((BYTE *)relative, wcslen(relative)*2); printf("\",\"file\":"); barrier_read(&file, FALSE); putchar('}'); }
    else tree_read(root, relative, depth+1, total, emitted);
    close_file(&file);
  } while (FindNextFileW(search, &value)); need(GetLastError() == ERROR_NO_MORE_FILES && FindClose(search));
}

static void audit_enumerate(void) {
  if (audit_count) return; GUID *categories; ULONG count;
  need(AuditEnumerateSubCategories(NULL, TRUE, &categories, &count) && count && count <= 128);
  memcpy(audit_categories, categories, count*sizeof(GUID)); audit_count = count; AuditFree(categories);
}
static BOOL audit_principal_exists(PSID sid) {
  PAUDIT_SID_ARRAY array; need(AuditEnumeratePerUserPolicy(&array)); BOOL exists = FALSE;
  need(array->UsersCount <= 4096); for (unsigned i = 0; i < array->UsersCount; i++) if (EqualSid(sid, array->UserSidArray[i])) exists = TRUE;
  AuditFree(array); return exists;
}
static void audit_policy_read(const AUDIT_POLICY_INFORMATION *value) {
  putchar('['); for (unsigned i = 0; i < audit_count; i++) { if (i) putchar(','); printf("{\"key\":"); emit_guid(&value[i].AuditSubCategoryGuid); printf(",\"flags\":%lu}", value[i].AuditingInformation); } putchar(']');
}
static void audit_snapshot(unsigned subject) {
  need(subject < process_count); audit_enumerate(); TOKEN_USER *user = token_info(tokens[subject], TokenUser);
  AUDIT_POLICY_INFORMATION *system, *principal = NULL; need(AuditQuerySystemPolicy(audit_categories, audit_count, &system));
  BOOL exists = audit_principal_exists(user->User.Sid); if (exists) need(AuditQueryPerUserPolicy(user->User.Sid, audit_categories, audit_count, &principal));
  char systemHash[65]; sum((BYTE *)system, audit_count*sizeof(*system), systemHash);
  printf("{\"sid\":"); emit_sid(user->User.Sid); printf(",\"systemSha256\":\"%s\",\"system\":", systemHash); audit_policy_read(system);
  printf(",\"principal\":"); if (exists) audit_policy_read(principal); else printf("null"); putchar('}');
  AuditFree(system); if (principal) AuditFree(principal); free(user);
}
static void sacl_hash(PACL acl, char hash[65]) { sum(acl ? (BYTE *)acl : (BYTE *)"", acl ? acl->AclSize : 0, hash); }
static void audit_install(char **values, unsigned n) {
  need(!audit_used && !audit_owned && n >= 5); unsigned subject = bounded_number(values[2], 31), count = bounded_number(values[4], 44);
  need(subject < process_count && count && n == count*2+5 && strlen(values[3]) == 64 && strspn(values[3], "0123456789abcdef") == 64);
  need(WaitForSingleObject(processes[subject], 0) == WAIT_TIMEOUT);
  audit_enumerate(); TOKEN_USER *user = token_info(tokens[subject], TokenUser); need(!audit_principal_exists(user->User.Sid));
  audit_sid = LocalAlloc(LPTR, GetLengthSid(user->User.Sid)); need(audit_sid && CopySid(GetLengthSid(user->User.Sid), audit_sid, user->User.Sid)); free(user);
  need(AuditQuerySystemPolicy(audit_categories, audit_count, &audit_system)); char hash[65];
  sum((BYTE *)audit_system, audit_count*sizeof(*audit_system), hash); need(!strcmp(hash, values[3]));
  /* Validate and retain every approved baseline before the first setter. The
   * external owner must also hold its independently proved exclusive-writer
   * admission; any subsequent uncertainty preserves the complete intent. */
  for (unsigned i = 0; i < count; i++) {
    struct entry *entry = slot(values[5+i*2]); const char *expected = values[6+i*2];
    need(strlen(expected) == 64 && strspn(expected, "0123456789abcdef") == 64);
    for (unsigned j = 0; j < i; j++) need(audit_objects[j].entry != entry);
    audit_objects[i].entry = entry; PSECURITY_DESCRIPTOR sd = file_sd(entry->file.handle, SE_FILE_OBJECT); PACL before; BOOL present, defaulted;
    sum((BYTE *)sd, GetSecurityDescriptorLength(sd), hash); need(!strcmp(hash, expected));
    PSID owner; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
    need(GetSecurityDescriptorOwner(sd, &owner, &defaulted) && IsWellKnownSid(owner, WinLocalSystemSid) &&
      GetSecurityDescriptorControl(sd, &flags, &revision) && (flags & SE_DACL_PROTECTED));
    need(GetSecurityDescriptorSacl(sd, &present, &before, &defaulted));
    if (present && before) {
      need(IsValidAcl(before) && before->AceCount <= 32);
      for (unsigned j = 0; j < before->AceCount; j++) { ACE_HEADER *ace; need(GetAce(before, j, (void **)&ace) && ace->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE); }
      audit_objects[i].before = LocalAlloc(LPTR, before->AclSize); need(audit_objects[i].before); memcpy(audit_objects[i].before, before, before->AclSize);
    }
    audit_objects[i].baseline = sd;
    ACL_SIZE_INFORMATION information = {0}; PACL old = audit_objects[i].before;
    if (old) need(GetAclInformation(old, &information, sizeof(information), AclSizeInformation) && information.AclBytesInUse >= sizeof(ACL));
    DWORD size = (old ? information.AclBytesInUse : sizeof(ACL)) + sizeof(SYSTEM_AUDIT_ACE) - sizeof(DWORD) + GetLengthSid(audit_sid); need(size <= 65535);
    PACL wanted = LocalAlloc(LPTR, size); need(wanted && InitializeAcl(wanted, size, ACL_REVISION));
    if (old) for (unsigned j = 0; j < old->AceCount; j++) { ACE_HEADER *ace; need(GetAce(old, j, (void **)&ace) && AddAce(wanted, ACL_REVISION, MAXDWORD, ace, ace->AceSize)); }
    need(AddAuditAccessAceEx(wanted, ACL_REVISION, 0, FILE_ALL_ACCESS, audit_sid, TRUE, TRUE));
    audit_objects[i].wanted = wanted;
  }
  AUDIT_POLICY_INFORMATION *again; need(AuditQuerySystemPolicy(audit_categories, audit_count, &again));
  sum((BYTE *)again, audit_count*sizeof(*again), hash); need(!strcmp(hash, values[3]) && !audit_principal_exists(audit_sid)); AuditFree(again);
  /* Persisted adapter intent precedes this command. Retain ownership before
   * the first setter; partial failure never attempts automatic restoration. */
  audit_used = audit_owned = TRUE; audit_object_count = count;
  const GUID wanted[] = { {0x0cce921d,0x69ae,0x11d9,{0xbe,0xd3,0x50,0x50,0x54,0x50,0x30,0x30}},
    {0x0cce9225,0x69ae,0x11d9,{0xbe,0xd3,0x50,0x50,0x54,0x50,0x30,0x30}}, {0x0cce9226,0x69ae,0x11d9,{0xbe,0xd3,0x50,0x50,0x54,0x50,0x30,0x30}} };
  AUDIT_POLICY_INFORMATION policy[3] = {0}; for (unsigned i = 0; i < 3; i++) { policy[i].AuditSubCategoryGuid = wanted[i]; policy[i].AuditingInformation = PER_USER_AUDIT_SUCCESS_INCLUDE | PER_USER_AUDIT_FAILURE_INCLUDE; }
  need(AuditSetPerUserPolicy(audit_sid, policy, 3));
  for (unsigned i = 0; i < count; i++) {
    struct entry *entry = audit_objects[i].entry;
    PSECURITY_DESCRIPTOR sd = file_sd(entry->file.handle, SE_FILE_OBJECT);
    sum((BYTE *)sd, GetSecurityDescriptorLength(sd), hash); need(!strcmp(hash, values[6+i*2])); LocalFree(sd);
    set_file_security(entry->file.handle, SACL_SECURITY_INFORMATION, NULL, audit_objects[i].wanted);
  }
  printf("{\"installed\":true,\"objects\":%u}", count);
}
static void audit_restore(void) {
  need(audit_owned && !helpers[0].process && !helpers[1].process);
  for (unsigned i = 0; i < process_count; i++) need(WaitForSingleObject(processes[i], 0) == WAIT_OBJECT_0);
  for (unsigned i = 0; i < job_count; i++) { JOBOBJECT_BASIC_ACCOUNTING_INFORMATION current; need(QueryInformationJobObject(jobs[i], JobObjectBasicAccountingInformation, &current, sizeof(current), NULL) && !current.ActiveProcesses); }
  AUDIT_POLICY_INFORMATION *system, *principal = NULL; need(AuditQuerySystemPolicy(audit_categories, audit_count, &system) &&
    !memcmp(system, audit_system, audit_count*sizeof(*system)));
  BOOL principalExists = audit_principal_exists(audit_sid);
  if (principalExists) need(AuditQueryPerUserPolicy(audit_sid, audit_categories, audit_count, &principal));
  for (unsigned i = 0; principalExists && i < audit_count; i++) { DWORD expected = 0, id = principal[i].AuditSubCategoryGuid.Data1;
    if (id == 0x0cce921d || id == 0x0cce9225 || id == 0x0cce9226) expected = PER_USER_AUDIT_SUCCESS_INCLUDE | PER_USER_AUDIT_FAILURE_INCLUDE;
    need(IsEqualGUID(&principal[i].AuditSubCategoryGuid, &audit_categories[i]) && principal[i].AuditingInformation == expected); }
  for (unsigned i = 0; i < audit_object_count; i++) {
    PSECURITY_DESCRIPTOR sd = file_sd(audit_objects[i].entry->file.handle, SE_FILE_OBJECT), baseline = audit_objects[i].baseline;
    PSID owner, oldOwner, group, oldGroup; PACL dacl, oldDacl, sacl; BOOL present, oldPresent, defaulted, oldDefaulted;
    SECURITY_DESCRIPTOR_CONTROL flags, oldFlags; DWORD revision, oldRevision; char actual[65], before[65], wanted[65];
    need(baseline && GetSecurityDescriptorOwner(sd, &owner, &defaulted) && GetSecurityDescriptorOwner(baseline, &oldOwner, &oldDefaulted) &&
      defaulted == oldDefaulted && EqualSid(owner, oldOwner) && GetSecurityDescriptorGroup(sd, &group, &defaulted) &&
      GetSecurityDescriptorGroup(baseline, &oldGroup, &oldDefaulted) && defaulted == oldDefaulted &&
      ((!group && !oldGroup) || (group && oldGroup && EqualSid(group, oldGroup))) &&
      GetSecurityDescriptorControl(sd, &flags, &revision) && GetSecurityDescriptorControl(baseline, &oldFlags, &oldRevision) &&
      revision == oldRevision && (flags & ~SE_SACL_PRESENT) == (oldFlags & ~SE_SACL_PRESENT) &&
      GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && GetSecurityDescriptorDacl(baseline, &oldPresent, &oldDacl, &oldDefaulted) &&
      present == oldPresent && defaulted == oldDefaulted && dacl && oldDacl && dacl->AclSize == oldDacl->AclSize && !memcmp(dacl, oldDacl, dacl->AclSize) &&
      GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted));
    sacl_hash(present ? sacl : NULL, actual); sacl_hash(audit_objects[i].before, before); sacl_hash(audit_objects[i].wanted, wanted);
    need(!strcmp(actual, before) || !strcmp(actual, wanted)); LocalFree(sd);
  }
  /* Full validation precedes any restoration. Setters touch the owned SACL
   * subset and newly created per-principal entry only; never system policy. */
  for (unsigned i = 0; i < audit_object_count; i++) {
    set_file_security(audit_objects[i].entry->file.handle, SACL_SECURITY_INFORMATION, NULL, audit_objects[i].before);
    PSECURITY_DESCRIPTOR sd = file_sd(audit_objects[i].entry->file.handle, SE_FILE_OBJECT); PACL sacl; BOOL present, defaulted; char before[65], after[65];
    need(GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted)); sacl_hash(audit_objects[i].before, before); sacl_hash(present ? sacl : NULL, after); need(!strcmp(before, after)); LocalFree(sd);
  }
  if (principalExists) need(AuditDeletePerUserPolicy(audit_sid)); need(!audit_principal_exists(audit_sid));
  AuditFree(system); if (principal) AuditFree(principal);
  need(AuditQuerySystemPolicy(audit_categories, audit_count, &system) && !memcmp(system, audit_system, audit_count*sizeof(*system))); AuditFree(system);
  for (unsigned i = 0; i < audit_object_count; i++) {
    LocalFree(audit_objects[i].before); LocalFree(audit_objects[i].wanted); LocalFree(audit_objects[i].baseline);
    audit_objects[i].before = audit_objects[i].wanted = NULL; audit_objects[i].baseline = NULL;
  }
  AuditFree(audit_system); audit_system = NULL; LocalFree(audit_sid); audit_sid = NULL;
  audit_owned = FALSE; printf("{\"restored\":true}");
}

/* XmlLite prohibits DTD/entity expansion. Decode only the matched Event and
 * Bookmark schema; no regex, localized message rendering or path inference. */
struct xml_field { wchar_t name[128], value[4096]; };
static void xml_field_read(struct xml_field *fields, unsigned *count, const wchar_t *name, const wchar_t *value, unsigned length) {
  need(*count < 96 && wcslen(name) < 128 && length < 4096);
  for (unsigned i = 0; i < *count; i++) need(wcscmp(fields[i].name, name));
  wcscpy_s(fields[*count].name, 128, name); wmemcpy(fields[*count].value, value, length); fields[*count].value[length] = 0; (*count)++;
}
static void xml_data_read(struct xml_field *fields, unsigned *count, const wchar_t *name, const wchar_t *value, unsigned length) {
  const wchar_t *reserved[] = {L"Provider", L"EventID", L"Version", L"Keywords", L"Channel", L"EventRecordID", L"TimeCreated"};
  need(*name); for (unsigned i = 0; i < 7; i++) need(wcscmp(name, reserved[i])); xml_field_read(fields, count, name, value, length);
}
static void xml_decode(const char *encoded) {
  size_t length = strlen(encoded); need(length >= 8 && length <= 131072 && length%4 == 0);
  HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, length/2); need(memory); BYTE *bytes = GlobalLock(memory); need(bytes);
  for (size_t i = 0; i < length/2; i++) bytes[i] = (BYTE)(nibble(encoded[2*i])*16 + nibble(encoded[2*i+1]));
  wchar_t *wide = (void *)bytes; need(wide[length/4-1] == 0);
  for (size_t i = 0; i < length/4-1; i++) need(wide[i]);
  need(GlobalUnlock(memory) || GetLastError() == NO_ERROR);
  IStream *stream; need(SUCCEEDED(CreateStreamOnHGlobal(memory, TRUE, &stream)));
  /* Exclude EvtRender's terminal NUL from the XML document stream. */
  ULARGE_INTEGER size; size.QuadPart = length/2-2; need(SUCCEEDED(IStream_SetSize(stream, size)));
  IXmlReader *reader; need(SUCCEEDED(CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL)) &&
    SUCCEEDED(IXmlReader_SetProperty(reader, XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) &&
    SUCCEEDED(IXmlReader_SetProperty(reader, XmlReaderProperty_MaxElementDepth, 8)) && SUCCEEDED(IXmlReader_SetInput(reader, (IUnknown *)stream)));
  struct xml_field *fields = calloc(96, sizeof(*fields)); need(fields); unsigned count = 0, nodes = 0;
  wchar_t stack[8][128], dataName[128] = L"", text[4096] = L""; unsigned depth = 0, textLength = 0;
  BOOL event = FALSE, bookmark = FALSE, closed = FALSE, systemSeen = FALSE, dataSeen = FALSE; HRESULT result; XmlNodeType type;
  while ((result = IXmlReader_Read(reader, &type)) == S_OK) {
    need(++nodes <= 2048 && (!closed || type == XmlNodeType_Whitespace)); const wchar_t *name, *value; UINT used;
    if (type == XmlNodeType_Element) {
      need(depth < 8 && SUCCEEDED(IXmlReader_GetLocalName(reader, &name, &used)) && used < 128); wcscpy_s(stack[depth], 128, name); name = stack[depth];
      const wchar_t *ns; UINT nsLength; need(SUCCEEDED(IXmlReader_GetNamespaceUri(reader, &ns, &nsLength)));
      if (!depth) { event = !wcscmp(name, L"Event"); bookmark = !wcscmp(name, L"BookmarkList"); need(event || bookmark); }
      need(bookmark ? nsLength == 0 : !wcscmp(ns, L"http://schemas.microsoft.com/win/2004/08/events/event"));
      if (event && depth == 1) {
        if (!wcscmp(name, L"System")) { need(!systemSeen); systemSeen = TRUE; }
        else { need(!wcscmp(name, L"EventData") && !dataSeen); dataSeen = TRUE; }
      }
      if (event && depth == 2) need(!wcscmp(stack[1], L"System") || (!wcscmp(stack[1], L"EventData") && !wcscmp(name, L"Data")));
      if (event) need(depth <= 2); else need(depth <= 1 && (!depth || !wcscmp(name, L"Bookmark")));
      textLength = 0; text[0] = 0; dataName[0] = 0;
      if (IXmlReader_MoveToFirstAttribute(reader) == S_OK) do {
        const wchar_t *attribute; UINT attributeLength;
        need(SUCCEEDED(IXmlReader_GetLocalName(reader, &attribute, &attributeLength)) && SUCCEEDED(IXmlReader_GetValue(reader, &value, &used)) && used < 4096);
        if (!wcscmp(name, L"Data") && !wcscmp(attribute, L"Name")) { need(!*dataName && used < 128); wmemcpy(dataName, value, used); dataName[used] = 0; }
        if (event && depth == 2 && ((!wcscmp(name, L"Provider") && !wcscmp(attribute, L"Name")) || (!wcscmp(name, L"TimeCreated") && !wcscmp(attribute, L"SystemTime"))))
          xml_field_read(fields, &count, name, value, used);
        if (bookmark && depth == 1 && !wcscmp(name, L"Bookmark")) {
          need(!wcscmp(attribute, L"Channel") || !wcscmp(attribute, L"RecordId") || !wcscmp(attribute, L"IsCurrent"));
          xml_field_read(fields, &count, attribute, value, used);
        }
      } while (IXmlReader_MoveToNextAttribute(reader) == S_OK);
      need(SUCCEEDED(IXmlReader_MoveToElement(reader)));
      if (IXmlReader_IsEmptyElement(reader)) {
        if (event && depth == 2 && !wcscmp(stack[1], L"EventData") && !wcscmp(name, L"Data")) xml_data_read(fields, &count, dataName, L"", 0);
        if (!depth) closed = TRUE;
      }
      else depth++;
    } else if (type == XmlNodeType_EndElement) {
      need(depth && SUCCEEDED(IXmlReader_GetLocalName(reader, &name, &used)) && !wcscmp(stack[depth-1], name));
      if (event && depth == 3 && !wcscmp(stack[1], L"System") && textLength)
        xml_field_read(fields, &count, name, text, textLength);
      if (event && depth == 3 && !wcscmp(stack[1], L"EventData") && !wcscmp(name, L"Data")) {
        xml_data_read(fields, &count, dataName, text, textLength);
      }
      if (!--depth) closed = TRUE;
    } else if (type == XmlNodeType_Text || type == XmlNodeType_SignificantWhitespace || type == XmlNodeType_Whitespace) {
      need(SUCCEEDED(IXmlReader_GetValue(reader, &value, &used)) && textLength + used < 4096);
      if (depth == 3) { wmemcpy(text+textLength, value, used); textLength += used; text[textLength] = 0; }
      else for (unsigned i = 0; i < used; i++) need(iswspace(value[i]));
    } else need(type == XmlNodeType_XmlDeclaration); /* CDATA, PI and entity nodes are unsupported. */
  }
  need(result == S_FALSE && closed && !depth && count && (!event || (systemSeen && dataSeen)));
  printf("{\"kind\":\"%s\",\"fields\":[", event ? "event" : "bookmark");
  for (unsigned i = 0; i < count; i++) { printf("%s{\"nameHex\":\"", i ? "," : ""); hex((BYTE *)fields[i].name, wcslen(fields[i].name)*2);
    printf("\",\"hex\":\""); hex((BYTE *)fields[i].value, wcslen(fields[i].value)*2); printf("\"}"); }
  printf("]}"); SecureZeroMemory(fields, 96*sizeof(*fields)); free(fields); IXmlReader_Release(reader); IStream_Release(stream);
}
