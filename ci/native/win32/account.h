/* Shared private account and creation-time token owner. Credentials remain
 * in System-only custody and never enter frames, argv or JS records. */
#ifndef NATIVE_WINDOWS_ACCOUNT_H
#define NATIVE_WINDOWS_ACCOUNT_H
#include <lm.h>
#include <ntsecapi.h>
#pragma comment(lib, "netapi32.lib")
static void rights(PSID user) {
  LSA_OBJECT_ATTRIBUTES attrs = {0}; attrs.Length = sizeof(attrs); LSA_HANDLE policy;
  need(LsaOpenPolicy(NULL, &attrs, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &policy) == 0);
  const wchar_t *names[] = { SE_BATCH_LOGON_NAME, SE_DENY_INTERACTIVE_LOGON_NAME, SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME,
    SE_DENY_NETWORK_LOGON_NAME, SE_DENY_SERVICE_LOGON_NAME };
  LSA_UNICODE_STRING values[5];
  for (unsigned i = 0; i < 5; i++) {
    values[i].Buffer = (wchar_t *)names[i]; values[i].Length = (USHORT)(wcslen(names[i]) * sizeof(wchar_t));
    values[i].MaximumLength = values[i].Length + sizeof(wchar_t);
  }
  need(LsaAddAccountRights(policy, user, values, 5) == 0); LsaClose(policy);
}
static HANDLE account(const wchar_t *name, const wchar_t *custody, wchar_t **userSid) {
  BYTE random[64]; wchar_t password[65];
  need(BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0);
  const wchar_t alphabet[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#";
  for (unsigned i = 0; i < 64; i++) password[i] = alphabet[random[i] & 63]; password[64] = 0;
  password[0] = L'A'; password[1] = L'z'; password[2] = L'7'; password[3] = L'#';
  /* Fresh random credentials never enter argv, environment, control frames,
   * logs or JS receipts. Only the protected native custody file retains them. */
  USER_INFO_1 user = {0}; user.usri1_name = (wchar_t *)name; user.usri1_password = password;
  user.usri1_priv = USER_PRIV_USER; user.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
  DWORD error;
  need(NetUserAdd(NULL, 1, (BYTE *)&user, &error) == NERR_Success);
  LOCALGROUP_USERS_INFO_0 *groups = NULL; DWORD count, total;
  need(NetUserGetLocalGroups(NULL, name, 0, 0, (BYTE **)&groups, MAX_PREFERRED_LENGTH, &count, &total) == NERR_Success && count == total && count <= 128);
  LOCALGROUP_MEMBERS_INFO_3 member = { (wchar_t *)name };
  for (DWORD i = 0; i < count; i++) need(NetLocalGroupDelMembers(NULL, groups[i].lgrui0_name, 3, (BYTE *)&member, 1) == NERR_Success);
  if (groups) NetApiBufferFree(groups);
  BYTE rawSid[SECURITY_MAX_SID_SIZE]; DWORD sidSize = sizeof(rawSid), domainSize = 256; wchar_t domain[256]; SID_NAME_USE type;
  need(LookupAccountNameW(NULL, name, rawSid, &sidSize, domain, &domainSize, &type) && type == SidTypeUser);
  rights(rawSid);
  need(ConvertSidToStringSidW(rawSid, userSid));
  wchar_t secret[4096]; need(swprintf_s(secret, 4096, L"%ls\\account.secret", custody) > 0);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;FA;;;SY)"); SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
  HANDLE file = CreateFileW(secret, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH, NULL);
  DWORD written;
  need(file != INVALID_HANDLE_VALUE && WriteFile(file, password, sizeof(password), &written, NULL) && written == sizeof(password) && FlushFileBuffers(file));
  CloseHandle(file); LocalFree(sd);
  HANDLE token;
  need(LogonUserW(name, L".", password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &token));
  SecureZeroMemory(password, sizeof(password)); SecureZeroMemory(random, sizeof(random));
  wchar_t *actual = token_sid(token); need(!wcscmp(actual, *userSid)); LocalFree(actual); need(SetHandleInformation(token, HANDLE_FLAG_INHERIT, 0));
  return token;
}
static HANDLE restrict_token(HANDLE base, PSID capability) {
  TOKEN_GROUPS *groups = token_info(base, TokenGroups); TOKEN_PRIVILEGES *privileges = token_info(base, TokenPrivileges);
  need(groups->GroupCount <= 128 && privileges->PrivilegeCount <= 64);
  SID_AND_ATTRIBUTES disabled[128]; DWORD count = 0;
  for (DWORD i = 0; i < groups->GroupCount; i++)
    if (!(groups->Groups[i].Attributes & (SE_GROUP_INTEGRITY | SE_GROUP_USE_FOR_DENY_ONLY))) disabled[count++] = groups->Groups[i];
  SID_AND_ATTRIBUTES restricting = { capability, 0 }; HANDLE token;
  /* Delete every privilege explicitly, including SeChangeNotifyPrivilege.
   * Never use WRITE_RESTRICTED (or its read-access escape) here. */
  need(CreateRestrictedToken(base, 0, count, disabled, privileges->PrivilegeCount, privileges->Privileges, 1, &restricting, &token));
  free(groups); free(privileges);
  PSID low; need(ConvertStringSidToSidW(L"S-1-16-4096", &low));
  TOKEN_MANDATORY_LABEL integrity = { { low, SE_GROUP_INTEGRITY } };
  need(SetTokenInformation(token, TokenIntegrityLevel, &integrity, sizeof(integrity) + GetLengthSid(low))); LocalFree(low);
  DWORD off = 0; need(SetTokenInformation(token, TokenVirtualizationEnabled, &off, sizeof(off)));
  TOKEN_PRIVILEGES *after = token_info(token, TokenPrivileges); DWORD *session = token_info(token, TokenSessionId);
  TOKEN_GROUPS *restricted = token_info(token, TokenRestrictedSids);
  need(IsTokenRestricted(token) && after->PrivilegeCount == 0 && *session == 0 && restricted->GroupCount == 1 && EqualSid(restricted->Groups[0].Sid, capability));
  free(after); free(session); free(restricted); need(SetHandleInformation(token, HANDLE_FLAG_INHERIT, 0));
  return token;
}

/* A completed native record is necessary for adoption or retirement. An intent
 * without this acknowledgement retains the possible account reservation. */
struct case_account_record {
  DWORD version; char context[65], nonce[33]; wchar_t accountSid[256], restrictingSid[256];
};
static HANDLE account_file(const wchar_t *custody, const wchar_t *leaf, DWORD access, DWORD creation) {
  wchar_t name[4096]; need(swprintf_s(name, 4096, L"%ls\\%ls", custody, leaf) > 0);
  PSECURITY_DESCRIPTOR sd = descriptor(L"O:SYG:SYD:P(A;;GA;;;SY)"); SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
  HANDLE file = CreateFileW(name, access | READ_CONTROL, FILE_SHARE_READ, &sa, creation,
    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, NULL); LocalFree(sd); need(file != INVALID_HANDLE_VALUE);
  FILE_ATTRIBUTE_TAG_INFO tag; BY_HANDLE_FILE_INFORMATION info;
  PSID owner, system; PACL dacl; PSECURITY_DESCRIPTOR actual; SECURITY_DESCRIPTOR_CONTROL flags; DWORD revision;
  need(GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) && !(tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
    GetFileInformationByHandle(file, &info) && info.nNumberOfLinks == 1 && ConvertStringSidToSidW(L"S-1-5-18", &system) &&
    GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &actual) == ERROR_SUCCESS &&
    EqualSid(owner, system) && dacl && dacl->AceCount == 1 && GetSecurityDescriptorControl(actual, &flags, &revision) && (flags & SE_DACL_PROTECTED));
  ACCESS_ALLOWED_ACE *ace; need(GetAce(dacl, 0, (void **)&ace) && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags &&
    EqualSid(&ace->SidStart, system) && (ace->Mask == GENERIC_ALL || ace->Mask == FILE_ALL_ACCESS));
  LocalFree(actual); LocalFree(system); return file;
}
static void account_record(const wchar_t *custody, struct case_account_record *record) {
  HANDLE file = account_file(custody, L"account.record", GENERIC_READ, OPEN_EXISTING); DWORD used; LARGE_INTEGER size;
  need(GetFileSizeEx(file, &size) && size.QuadPart == sizeof(*record) && ReadFile(file, record, sizeof(*record), &used, NULL) && used == sizeof(*record) && CloseHandle(file));
  need(record->version == 1 && record->context[64] == 0 && record->nonce[32] == 0 &&
    strspn(record->context, "0123456789abcdef") == 64 && strspn(record->nonce, "0123456789abcdef") == 32 &&
    !memcmp(record->context, record->nonce, 32) && record->accountSid[255] == 0 && record->restrictingSid[255] == 0);
}
static void account_check(const wchar_t *name, const wchar_t *expected) {
  BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sidSize = sizeof(sid), domainSize = 256; wchar_t domain[256], *text; SID_NAME_USE type;
  need(LookupAccountNameW(NULL, name, sid, &sidSize, domain, &domainSize, &type) && type == SidTypeUser && ConvertSidToStringSidW(sid, &text));
  need(!wcscmp(text, expected)); LocalFree(text);
  LOCALGROUP_USERS_INFO_0 *groups; DWORD count, total;
  need(NetUserGetLocalGroups(NULL, name, 0, 0, (BYTE **)&groups, MAX_PREFERRED_LENGTH, &count, &total) == NERR_Success && count == 0 && total == 0);
  if (groups) NetApiBufferFree(groups);
  USER_INFO_1 *user; need(NetUserGetInfo(NULL, name, 1, (BYTE **)&user) == NERR_Success && user->usri1_priv == USER_PRIV_USER &&
    user->usri1_flags == (UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD)); NetApiBufferFree(user);
  LSA_OBJECT_ATTRIBUTES attributes = {0}; attributes.Length = sizeof(attributes); LSA_HANDLE policy; LSA_UNICODE_STRING *rights; ULONG number;
  need(LsaOpenPolicy(NULL, &attributes, POLICY_LOOKUP_NAMES, &policy) == 0 && LsaEnumerateAccountRights(policy, sid, &rights, &number) == 0 && number == 5);
  const wchar_t *approved[] = {L"SeBatchLogonRight", L"SeDenyInteractiveLogonRight", L"SeDenyRemoteInteractiveLogonRight", L"SeDenyNetworkLogonRight", L"SeDenyServiceLogonRight"};
  unsigned seen = 0;
  for (ULONG i = 0; i < number; i++) { unsigned j;
    for (j = 0; j < 5; j++) if (rights[i].Length == wcslen(approved[j])*sizeof(wchar_t) && !wcsncmp(rights[i].Buffer, approved[j], rights[i].Length/sizeof(wchar_t))) break;
    need(j < 5 && !(seen & (1U << j))); seen |= 1U << j;
  }
  need(seen == 31); LsaFreeMemory(rights); LsaClose(policy);
}
static HANDLE account_adopt(const wchar_t *custody, const struct case_account_record *record) {
  wchar_t name[21]; need(swprintf_s(name, 21, L"np_%.16hs", record->nonce) > 0); account_check(name, record->accountSid);
  HANDLE file = account_file(custody, L"account.secret", GENERIC_READ, OPEN_EXISTING); wchar_t password[65]; DWORD used; LARGE_INTEGER size;
  need(GetFileSizeEx(file, &size) && size.QuadPart == sizeof(password) && ReadFile(file, password, sizeof(password), &used, NULL) && used == sizeof(password) && !password[64] && CloseHandle(file));
  HANDLE token; need(LogonUserW(name, L".", password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &token)); SecureZeroMemory(password, sizeof(password));
  wchar_t *actual = token_sid(token); need(!wcscmp(actual, record->accountSid)); LocalFree(actual); return token;
}
#endif
