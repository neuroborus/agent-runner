/* Finite current-account experiment. No AppContainer wrapper, System custody,
 * release review, system audit-policy setter, installer, or full factory. */
#include <winevt.h>
#include <ntsecapi.h>
#include <objidl.h>
#include <xmllite.h>
#include <objbase.h>
#include <wctype.h>
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "xmllite.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
#include "audit-policy-remove.h"
static unsigned nibble(char c) { need((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); return c <= '9' ? c-'0' : c-'a'+10; }
static void hex(const BYTE *bytes, size_t length) { for (size_t i=0;i<length;i++) printf("%02x", bytes[i]); }
#define WINDOWS_SECURITY_XML_ONLY
#include "effective-reader.h"
#undef WINDOWS_SECURITY_XML_ONLY
static HANDLE command_files[4], command_parents[2], command_client, command_gate;
static HANDLE command_processes[16], command_threads[16], command_input, command_output, command_error;
static DWORD command_lifetime = 150000;
static unsigned command_count, command_action, command_barriers, command_records, command_bytes;
static char command_ids[4][50], command_helper_hash[65], command_image_hash[65];
static WCHAR command_paths[4][4096], command_helper[4096], command_image[4096], command_pipe[128];
static PSECURITY_DESCRIPTOR command_baseline[4], command_parent_baseline[2];
static HANDLE command_helper_file, command_image_file, command_build_parent;
static HANDLE command_null, command_server, command_saved_input, command_saved_output, command_saved_error;
static HANDLE command_broker_token, command_audit_intent, command_closed, command_cleanup_timer;
static BOOL command_control, command_server_released;
static DWORD command_case_pid;
static BOOL command_target_seen, command_marker_seen, command_retirement_seen;
static char command_null_hash[65];
static PACL command_sacls[4];
static EVT_HANDLE command_subscription, command_bookmark;
static HANDLE command_event;
static GUID command_category = {0x0cce921d,0x69ae,0x11d9,{0xbe,0xd3,0x50,0x50,0x54,0x50,0x30,0x30}};
static GUID *command_categories;
static ULONG command_category_count;
static AUDIT_POLICY_INFORMATION *command_system;
static BOOL command_closing, command_coverage_admitted, command_probing, command_coverage_seen;
static ULONGLONG command_started, command_cleanup_started;
static PSECURITY_DESCRIPTOR command_protection[3];
static struct command_preflight_resources {
  BOOL active, impersonating, comReady;
  HANDLE token, medium, launch, mutableNull, event;
  EVT_HANDLE metadata, enumerator, subscription, item;
  BCRYPT_ALG_HANDLE algorithm;
  BCRYPT_HASH_HANDLE hash;
} command_preflight_owned;
static void command_available(BOOL ok, const char *operation) {
  if (!ok) { DWORD error = GetLastError(); remember(operation, "win32", error); failure(78); }
}
static void command_required(BOOL ok, const char *operation) {
  if (!ok) { remember(operation, "invariant", 0); failure(78); }
}
static BOOL command_event_close(EVT_HANDLE *slot) {
  EVT_HANDLE handle = *slot; *slot = NULL;
  if (!handle || EvtClose(handle)) return TRUE;
  DWORD error = GetLastError(); remember("command-metadata-close", "win32", error); cleanup_error("command-metadata-close", "win32", error); return FALSE;
}
static BOOL command_revert(void) {
  if (!command_preflight_owned.impersonating) return TRUE;
  command_preflight_owned.impersonating = FALSE;
  if (RevertToSelf()) return TRUE;
  DWORD error = GetLastError(); remember("command-revert", "win32", error); cleanup_error("command-revert", "win32", error); return FALSE;
}
static BOOL command_hash_close(void) {
  BOOL ok = TRUE; NTSTATUS status;
  if (command_preflight_owned.hash) {
    status = BCryptDestroyHash(command_preflight_owned.hash); command_preflight_owned.hash = NULL;
    if (status) { remember("command-hash-close", "ntstatus", (DWORD)status); cleanup_error("command-hash-close", "ntstatus", (DWORD)status); ok = FALSE; }
  }
  if (command_preflight_owned.algorithm) {
    status = BCryptCloseAlgorithmProvider(command_preflight_owned.algorithm, 0); command_preflight_owned.algorithm = NULL;
    if (status) { remember("command-algorithm-close", "ntstatus", (DWORD)status); cleanup_error("command-algorithm-close", "ntstatus", (DWORD)status); ok = FALSE; }
  }
  return ok;
}
static BOOL command_protection_close(void) {
  BOOL ok = TRUE;
  for (unsigned i = 0; i < 3; i++) {
    PSECURITY_DESCRIPTOR sd = command_protection[i]; command_protection[i] = NULL;
    if (sd && LocalFree(sd)) {
      DWORD error = GetLastError(); remember("command-protect-free", "win32", error);
      cleanup_error("command-protect-free", "win32", error); ok = FALSE;
    }
  }
  return ok;
}
static BOOL command_broker_events_close(void) {
  BOOL ok = TRUE;
  if (!release_handle(&command_audit_intent, "command-event-close")) ok = FALSE;
  if (!release_handle(&command_closed, "command-event-close")) ok = FALSE;
  return ok;
}
static BOOL command_preflight_close(BOOL keepBroker) {
  BOOL ok = command_protection_close();
  if ((!keepBroker || !ok) && !command_broker_events_close()) ok = FALSE;
  /* Launch setup remains owned after preflight has finished. */
  if (!command_revert()) ok = FALSE;
  if (!release_handle(&command_preflight_owned.token, "command-token-close")) ok = FALSE;
  if (!release_handle(&command_preflight_owned.medium, "command-token-close")) ok = FALSE;
  if (!release_handle(&command_preflight_owned.launch, "command-token-close")) ok = FALSE;
  if (!command_preflight_owned.active) return ok;
  if (!release_handle(&command_preflight_owned.mutableNull, "command-null-close")) ok = FALSE;
  EVT_HANDLE *events[] = {&command_preflight_owned.item, &command_preflight_owned.subscription, &command_preflight_owned.enumerator, &command_preflight_owned.metadata};
  for (unsigned i = 0; i < 4; i++) if (!command_event_close(events[i])) ok = FALSE;
  if (!release_handle(&command_preflight_owned.event, "command-event-close")) ok = FALSE;
  if (!command_hash_close()) ok = FALSE;
  if (!keepBroker || !ok) {
    if (!release_handle(&command_null, "command-null-close")) ok = FALSE;
    /* The broker watchdog still waits on its timer until process retirement. */
    if (wcscmp(role, L"command-broker") && !release_handle(&command_cleanup_timer, "command-event-close")) ok = FALSE;
    if (command_categories) { AuditFree(command_categories); command_categories = NULL; }
    if (command_system) { AuditFree(command_system); command_system = NULL; }
    if (command_preflight_owned.comReady) { CoUninitialize(); command_preflight_owned.comReady = FALSE; }
  }
  command_preflight_owned.active = FALSE; return ok;
}
static void command_nt(NTSTATUS status, const char *operation) {
  if (status) { remember(operation, "ntstatus", (DWORD)status); failure(126); }
}
static void command_bound(void) { need(GetTickCount64()-(command_closing?command_cleanup_started:command_started) < (command_closing?30000:120000)); }
static DWORD WINAPI command_expire(void *unused) { (void)unused; ULONGLONG end=GetTickCount64()+command_lifetime;DWORD result=WaitForSingleObject(command_cleanup_timer,command_lifetime);if(result==WAIT_FAILED)win32_check(FALSE,"command-timer-wait");invariant(result==WAIT_TIMEOUT||result==WAIT_OBJECT_0,"command-timer-wait");if(result==WAIT_OBJECT_0){ULONGLONG now=GetTickCount64();Sleep((DWORD)(now>=end?0:(end-now<30000?end-now:30000)));}close_job(TRUE);ExitProcess(124);return 0; }
static void command_cleanup_begin(void) { command_closing=TRUE;if(!command_cleanup_started){command_cleanup_started=GetTickCount64();need(SetEvent(command_cleanup_timer));} }
static void command_interface(BOOL value, const char *operation) {
  if (value) return;
  DWORD error=GetLastError();remember(operation, "win32", error);failure(error==ERROR_NOT_SUPPORTED||error==ERROR_CALL_NOT_IMPLEMENTED||error==ERROR_PRIVILEGE_NOT_HELD?78:126);
}
static PSECURITY_DESCRIPTOR command_sd(HANDLE h, SE_OBJECT_TYPE kind, SECURITY_INFORMATION mask) {
  PSECURITY_DESCRIPTOR sd;DWORD error=GetSecurityInfo(h,kind,mask,NULL,NULL,NULL,NULL,&sd);
  if(error!=ERROR_SUCCESS){remember("command-security-read","win32",error);failure(error==ERROR_NOT_SUPPORTED||error==ERROR_CALL_NOT_IMPLEMENTED||error==ERROR_PRIVILEGE_NOT_HELD?78:126);}return sd;
}
static void command_sum(const BYTE *bytes, DWORD length, char hash[65]) {
  BYTE result[32];
  command_nt(BCryptOpenAlgorithmProvider(&command_preflight_owned.algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0),"command-hash-open");
  command_nt(BCryptCreateHash(command_preflight_owned.algorithm,&command_preflight_owned.hash,NULL,0,NULL,0,0),"command-hash-create");
  command_nt(BCryptHashData(command_preflight_owned.hash,(BYTE *)bytes,length,0),"command-hash-update");
  command_nt(BCryptFinishHash(command_preflight_owned.hash,result,32,0),"command-hash-final");
  for(unsigned i=0;i<32;i++) snprintf(hash+2*i,3,"%02x",result[i]); if(!command_hash_close())failure(126);
}
static DWORD command_integrity(HANDLE token) {
  TOKEN_MANDATORY_LABEL *v=info(token,TokenIntegrityLevel); PSID sid=v->Label.Sid; invariant(IsValidSid(sid) && *GetSidSubAuthorityCount(sid)>0,"command-integrity-sid");
  DWORD value=*GetSidSubAuthority(sid,*GetSidSubAuthorityCount(sid)-1); free(v); return value;
}
static void command_principal(void) {
  win32_check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&command_preflight_owned.token),"principal-token");
  TOKEN_USER *user=info(command_preflight_owned.token,TokenUser);invariant(IsValidSid(user->User.Sid),"principal-sid");userSid=malloc(GetLengthSid(user->User.Sid));
  invariant(userSid!=NULL,"principal-allocation");win32_check(CopySid(GetLengthSid(user->User.Sid),userSid,user->User.Sid),"principal-sid");
  win32_check(ConvertSidToStringSidW(userSid,&userText),"principal-sid");
  DWORD *container=info(command_preflight_owned.token,TokenIsAppContainer);invariant(!*container,"principal-container");free(container);free(user);
  if(!release_handle(&command_preflight_owned.token,"command-token-close"))failure(126);
}
static void command_privilege(const WCHAR *name) {
  TOKEN_PRIVILEGES p={0};win32_check(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&command_preflight_owned.token),"command-privilege-token");
  command_available(LookupPrivilegeValueW(NULL,name,&p.Privileges[0].Luid),"command-privilege-lookup");p.PrivilegeCount=1;p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
  SetLastError(ERROR_SUCCESS);BOOL adjusted=AdjustTokenPrivileges(command_preflight_owned.token,FALSE,&p,0,NULL,NULL);DWORD error=GetLastError();
  if(!adjusted||error!=ERROR_SUCCESS){remember("command-privilege-adjust","win32",error);failure(78);}
  if(!release_handle(&command_preflight_owned.token,"command-token-close"))failure(126);
}
static PSECURITY_DESCRIPTOR command_protection_read(HANDLE h, SECURITY_INFORMATION mask, const char *operation) {
  PSECURITY_DESCRIPTOR sd; DWORD error = GetSecurityInfo(h, SE_KERNEL_OBJECT, mask, NULL, NULL, NULL, NULL, &sd);
  if (error != ERROR_SUCCESS) { remember(operation, "win32", error); failure(error == ERROR_NOT_SUPPORTED || error == ERROR_CALL_NOT_IMPLEMENTED || error == ERROR_PRIVILEGE_NOT_HELD ? 78 : 126); }
  return sd;
}
static PSID command_protection_owner(PSECURITY_DESCRIPTOR sd, const char *operation) {
  PSID owner; BOOL def;
  win32_check(GetSecurityDescriptorOwner(sd, &owner, &def), operation);
  /* Closed refusal values: absent owner, invalid SID, unequal owner. */
  invariant_value(owner != NULL, operation, 1);
  invariant_value(IsValidSid(owner), operation, 2);
  return owner;
}
static void command_protection_verify(PSECURITY_DESCRIPTOR sd, PSID owner, DWORD allAccess, const char *operation) {
  PSID actualOwner; PACL dacl, sacl; BOOL present, def; SECURITY_DESCRIPTOR_CONTROL control; DWORD revision;
  invariant(IsValidSecurityDescriptor(sd), "command-protect-descriptor");
  actualOwner = command_protection_owner(sd, operation);
  invariant_value(EqualSid(owner, actualOwner), operation, 3);
  win32_check(GetSecurityDescriptorControl(sd, &control, &revision), "command-protect-control");
  invariant(control & SE_DACL_PROTECTED, "command-protect-control");
  win32_check(GetSecurityDescriptorDacl(sd, &present, &dacl, &def), "command-protect-dacl");
  invariant(present && dacl && IsValidAcl(dacl) && dacl->AceCount == 1, "command-protect-dacl");
  ACCESS_ALLOWED_ACE *ace; win32_check(GetAce(dacl, 0, (void **)&ace), "command-protect-dacl");
  invariant(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags &&
    IsValidSid(&ace->SidStart) && EqualSid(&ace->SidStart, userSid) &&
    (ace->Mask == GENERIC_ALL || ace->Mask == allAccess), "command-protect-dacl");
  win32_check(GetSecurityDescriptorSacl(sd, &present, &sacl, &def), "command-protect-sacl");
  invariant(present && sacl && IsValidAcl(sacl) && sacl->AceCount == 1, "command-protect-sacl");
  SYSTEM_MANDATORY_LABEL_ACE *label; win32_check(GetAce(sacl, 0, (void **)&label), "command-protect-sacl");
  invariant(label->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE && !label->Header.AceFlags &&
    IsWellKnownSid(&label->SidStart, WinHighLabelSid) &&
    label->Mask == (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP), "command-protect-sacl");
}
static PSECURITY_DESCRIPTOR command_protection_descriptor(void) {
  WCHAR text[512]; invariant(swprintf_s(text,512,L"O:%lsD:P(A;;GA;;;%ls)S:(ML;;NWNR;;;HI)",userText,userText)>0,"command-protect-format");
  PSECURITY_DESCRIPTOR sd;
  win32_check(ConvertStringSecurityDescriptorToSecurityDescriptorW(text, SDDL_REVISION_1, &sd, NULL), "command-protect-descriptor");
  return sd;
}
static void command_protect(HANDLE h, DWORD allAccess, const char *operation) {
  static const char *const ownerOperations[4][3] = {
    {"command-protect-process-baseline-owner", "command-protect-process-input-owner", "command-protect-process-readback-owner"},
    {"command-protect-job-baseline-owner", "command-protect-job-input-owner", "command-protect-job-readback-owner"},
    {"command-protect-intent-event-baseline-owner", "command-protect-intent-event-input-owner", "command-protect-intent-event-readback-owner"},
    {"command-protect-closed-event-baseline-owner", "command-protect-closed-event-input-owner", "command-protect-closed-event-readback-owner"}
  };
  unsigned object = !strcmp(operation, "command-protect-process") ? 0 : !strcmp(operation, "command-protect-job") ? 1 : !strcmp(operation, "command-protect-intent-event") ? 2 : !strcmp(operation, "command-protect-closed-event") ? 3 : 4;
  invariant(object < 4, "command-protect-owner");
  command_protection[0] = command_protection_read(h, OWNER_SECURITY_INFORMATION, ownerOperations[object][0]);
  PSID owner = command_protection_owner(command_protection[0], ownerOperations[object][0]);
  command_protection[1] = command_protection_descriptor();
  command_protection_verify(command_protection[1], userSid, allAccess, ownerOperations[object][1]);
  /* O: supplies a complete descriptor; the mask deliberately leaves the owner alone. */
  BOOL set = SetKernelObjectSecurity(h, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, command_protection[1]);
  DWORD error = set ? ERROR_SUCCESS : GetLastError();
  if (!set) { remember(operation, "win32", error); failure(126); }
  command_protection[2] = command_protection_read(h, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, ownerOperations[object][2]);
  command_protection_verify(command_protection[2], owner, allAccess, ownerOperations[object][2]);
  if (!command_protection_close()) failure(126);
}
static void command_broker_events(void) {
  command_protection[1] = command_protection_descriptor();
  command_protection_verify(command_protection[1], userSid, EVENT_ALL_ACCESS, "command-protect-intent-event-input-owner");
  SECURITY_ATTRIBUTES attributes = {sizeof(attributes), command_protection[1], FALSE};
  command_audit_intent = CreateEventW(&attributes, TRUE, FALSE, NULL);
  win32_check(command_audit_intent != NULL, "command-intent-event");
  command_closed = CreateEventW(&attributes, TRUE, FALSE, NULL);
  win32_check(command_closed != NULL, "command-closed-event");
  command_protection[0] = command_protection_read(command_audit_intent, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, "command-protect-intent-event-readback-owner");
  command_protection_verify(command_protection[0], userSid, EVENT_ALL_ACCESS, "command-protect-intent-event-readback-owner");
  command_protection[2] = command_protection_read(command_closed, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, "command-protect-closed-event-readback-owner");
  command_protection_verify(command_protection[2], userSid, EVENT_ALL_ACCESS, "command-protect-closed-event-readback-owner");
  if (!command_protection_close()) failure(126);
  command_protect(command_audit_intent,EVENT_ALL_ACCESS,"command-protect-intent-event");
  command_protect(command_closed,EVENT_ALL_ACCESS,"command-protect-closed-event");
}
static BOOL command_principal_exists(void) {
  invariant(userSid && IsValidSid(userSid),"command-audit-principal");
  PPOLICY_AUDIT_SID_ARRAY array = NULL;
  BOOL valid = AuditEnumeratePerUserPolicy(&array), found = FALSE;
  DWORD error = valid ? ERROR_SUCCESS : GetLastError();
  if(!valid) remember("command-audit-principals","win32",error);
  if (valid) {
    valid = array && array->UsersCount <= 4096 &&
      (!array->UsersCount || array->UserSidArray);
    for (ULONG i = 0; valid && i < array->UsersCount; i++) {
      PSID candidate = array->UserSidArray[i];
      valid = candidate && IsValidSid(candidate);
      if (valid && EqualSid(userSid, candidate)) found = TRUE;
    }
  }
  if(!valid && error==ERROR_SUCCESS) remember("command-audit-buffer","invariant",0);
  /* AuditFree owns the complete SDK buffer, including returned SID storage.
   * A prior match cannot admit a malformed later entry. */
  if (array) AuditFree(array);
  if(!valid)failure(126); return found;
}
static void command_policy_equal(void) {
  AUDIT_POLICY_INFORMATION *current; need(AuditQuerySystemPolicy(command_categories,command_category_count,&current));
  need(!memcmp(current,command_system,command_category_count*sizeof(*current))); AuditFree(current);
}
static HANDLE command_medium_token(BOOL launch) {
  DWORD access=TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ADJUST_DEFAULT;
  if(launch)access|=TOKEN_ASSIGN_PRIMARY;
  win32_check(OpenProcessToken(GetCurrentProcess(),access,&command_preflight_owned.token),"command-medium-source");
  win32_check(CreateRestrictedToken(command_preflight_owned.token,DISABLE_MAX_PRIVILEGE|LUA_TOKEN,0,NULL,0,NULL,0,NULL,&command_preflight_owned.medium),"command-medium-create");
  if(!release_handle(&command_preflight_owned.token,"command-token-close"))failure(126);
  PSID sid;win32_check(ConvertStringSidToSidW(L"S-1-16-8192",&sid),"command-medium-sid");TOKEN_MANDATORY_LABEL label={0};label.Label.Sid=sid;label.Label.Attributes=SE_GROUP_INTEGRITY;
  BOOL set=SetTokenInformation(command_preflight_owned.medium,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(sid));DWORD error=set?ERROR_SUCCESS:GetLastError();
  if(!set)remember("command-medium-integrity","win32",error);LocalFree(sid);if(!set)failure(126);
  invariant(command_integrity(command_preflight_owned.medium)==SECURITY_MANDATORY_MEDIUM_RID,"command-medium-level");
  if(launch) {
    win32_check(DuplicateHandle(GetCurrentProcess(),command_preflight_owned.medium,GetCurrentProcess(),&command_preflight_owned.launch,TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY,FALSE,0),"command-medium-launch");
    if(!release_handle(&command_preflight_owned.medium,"command-token-close"))failure(126);
    return command_preflight_owned.launch;
  }
  return command_preflight_owned.medium;
}
static void command_preflight(BOOL emit) {
  command_principal();command_required(!wcsncmp(userText,L"S-1-5-21-",9),"command-principal-kind");
  win32_check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&command_preflight_owned.token),"command-integrity-token");
  command_required(command_integrity(command_preflight_owned.token)>=SECURITY_MANDATORY_HIGH_RID,"command-integrity");
  if(!release_handle(&command_preflight_owned.token,"command-token-close"))failure(126);
  command_privilege(SE_SECURITY_NAME); command_privilege(SE_INCREASE_QUOTA_NAME);
  command_required(!command_principal_exists(),"command-audit-existing");
  HANDLE medium=command_medium_token(FALSE);win32_check(ImpersonateLoggedOnUser(medium),"command-impersonate");command_preflight_owned.impersonating=TRUE;
  HANDLE mutableNull=CreateFileW(L"\\\\.\\NUL",READ_CONTROL|WRITE_DAC,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);DWORD nullError=mutableNull==INVALID_HANDLE_VALUE?GetLastError():ERROR_SUCCESS;
  command_preflight_owned.mutableNull=mutableNull;BOOL denied=mutableNull==INVALID_HANDLE_VALUE&&nullError==ERROR_ACCESS_DENIED;
  if(!denied)remember("command-null-control",mutableNull==INVALID_HANDLE_VALUE?"win32":"invariant",nullError);
  BOOL closed=command_revert();if(!release_handle(&command_preflight_owned.medium,"command-token-close"))closed=FALSE;
  if(!release_handle(&command_preflight_owned.mutableNull,"command-null-close"))closed=FALSE;
  if(!closed)failure(126);if(!denied)failure(78);
  command_null=CreateFileW(L"\\\\.\\NUL",READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);command_available(command_null!=INVALID_HANDLE_VALUE,"command-null-open");
  PSECURITY_DESCRIPTOR nullSd=command_sd(command_null,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION); command_sum(nullSd,GetSecurityDescriptorLength(nullSd),command_null_hash);LocalFree(nullSd);
  command_available(AuditEnumerateSubCategories(NULL,TRUE,&command_categories,&command_category_count),"command-audit-categories");invariant(command_category_count&&command_category_count<=128,"command-audit-count");
  BOOL category=FALSE;for(ULONG i=0;i<command_category_count;i++)if(IsEqualGUID(&command_categories[i],&command_category))category=TRUE;command_required(category,"command-audit-category");
  command_available(AuditQuerySystemPolicy(command_categories,command_category_count,&command_system),"command-audit-policy");
  /* System bits are preservation evidence. Inclusion can add success auditing;
   * the held broker token and native delivery establish effective coverage. */
  command_preflight_owned.metadata=EvtOpenPublisherMetadata(NULL,L"Microsoft-Windows-Security-Auditing",NULL,0,0);command_available(command_preflight_owned.metadata!=NULL,"command-publisher-open");
  command_preflight_owned.enumerator=EvtOpenEventMetadataEnum(command_preflight_owned.metadata,0);command_available(command_preflight_owned.enumerator!=NULL,"command-enumerator-open");
  command_preflight_owned.event=CreateEventW(NULL,FALSE,FALSE,NULL);command_available(command_preflight_owned.event!=NULL,"command-audit-event");
  command_preflight_owned.subscription=EvtSubscribe(NULL,command_preflight_owned.event,L"Security",L"*[System[EventID=1101 or EventID=1102]]",NULL,NULL,NULL,EvtSubscribeToFutureEvents|EvtSubscribeStrict);command_available(command_preflight_owned.subscription!=NULL,"command-audit-subscribe");
  BOOL eventClosed=command_event_close(&command_preflight_owned.subscription);if(!release_handle(&command_preflight_owned.event,"command-event-close"))eventClosed=FALSE;if(!eventClosed)failure(126);
  DWORD ids[5]={4656,4663,5152,5156,5157}, versions[5][4]={0}, used[5]={0}; unsigned total=0;
  for(;;) { command_preflight_owned.item=EvtNextEventMetadata(command_preflight_owned.enumerator,0);
    if(!command_preflight_owned.item){DWORD error=GetLastError();if(error==ERROR_NO_MORE_ITEMS)break;remember("command-event-next","win32",error);failure(126);}
    EVT_VARIANT id,version;DWORD size;invariant(++total<=4096,"command-metadata-count");
    win32_check(EvtGetEventMetadataProperty(command_preflight_owned.item,EventMetadataEventID,0,sizeof(id),&id,&size),"command-event-id");invariant(id.Type==EvtVarTypeUInt32,"command-event-id-type");
    win32_check(EvtGetEventMetadataProperty(command_preflight_owned.item,EventMetadataEventVersion,0,sizeof(version),&version,&size),"command-event-version");invariant(version.Type==EvtVarTypeUInt32,"command-event-version-type");
    for(unsigned i=0;i<5;i++)if(ids[i]==id.UInt32Val){invariant(used[i]<4,"command-version-count");invariant(version.UInt32Val<=255,"command-version-range");versions[i][used[i]++]=version.UInt32Val;}
    if(!command_event_close(&command_preflight_owned.item))failure(126);
  }
  if(emit)for(unsigned i=0;i<5;i++)command_required(used[i]>0,"command-version-missing");
  if(!command_preflight_close(!emit))failure(126);if(!emit)return;printf("{\"versions\":[");
  for(unsigned i=0;i<5;i++){printf("%s{\"id\":%lu,\"versions\":[",i?",":"",ids[i]);for(unsigned j=0;j<used[i];j++)printf("%s%lu",j?",":"",versions[i][j]);printf("]}");}
  printf("],\"admission\":true,\"auditInterface\":true,\"completeRetirement\":true}\n");
}
static void command_snapshot_handle(HANDLE file, const char *expected) {
  char id[50],hash[65],dacl[65]; fileid(file,id); invariant(!strcmp(id,expected),"command-file-identity"); hashfile(file,hash);
  PSECURITY_DESCRIPTOR sd=command_sd(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION);
  command_sum(sd,GetSecurityDescriptorLength(sd),dacl); LocalFree(sd);
  printf("{\"identity\":\"%s\",\"sha256\":\"%s\",\"daclSha256\":\"%s\"}",id,hash,dacl);
}
static void command_snapshot(unsigned index) { command_snapshot_handle(command_files[index],command_ids[index]); }
static void command_reset(unsigned index) {
  LARGE_INTEGER zero={0}; DWORD used; char bytes[33]; need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,nonce,-1,bytes,33,NULL,NULL)==33);
  need(SetFilePointerEx(command_files[index],zero,NULL,FILE_BEGIN) && WriteFile(command_files[index],bytes,32,&used,NULL) && used==32 && SetEndOfFile(command_files[index]) && FlushFileBuffers(command_files[index]));
}
static void command_fixture_label(HANDLE h) {
  PSECURITY_DESCRIPTOR sd;PACL sacl;BOOL present,def;win32_check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;ME)",SDDL_REVISION_1,&sd,NULL),"command-fixture-descriptor");
  win32_check(GetSecurityDescriptorSacl(sd,&present,&sacl,&def),"command-fixture-sacl");invariant(present,"command-fixture-sacl");
  status_check(SetSecurityInfo(h,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,sacl),"command-fixture-label");LocalFree(sd);
}
static void command_files_prepare(void) {
  const WCHAR *dirs[]={L"",L"workspace",L"home",L"schema-home",L"schema",L"build"};WCHAR owned[4096];
  for(unsigned i=0;i<6;i++){if(i)name(owned,dirs[i]);else wcscpy_s(owned,4096,root);protect(owned,FALSE,TRUE);if(i!=5){HANDLE h=file(owned,WRITE_OWNER);command_fixture_label(h);if(!close_handle(h,"file-close"))failure(126);}}
  name(command_paths[0],L"workspace\\inspection"); name(command_paths[1],L"workspace\\edit"); name(command_paths[2],L"outside"); name(command_paths[3],L"workspace\\gate");
  WCHAR parent[4096]; name(parent,L"workspace"); const WCHAR *parents[2]={root,parent};
  for(unsigned i=0;i<2;i++){ command_parents[i]=CreateFileW(parents[i],GENERIC_READ|READ_CONTROL|WRITE_DAC|ACCESS_SYSTEM_SECURITY,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);win32_check(command_parents[i]!=INVALID_HANDLE_VALUE,"command-parent-open");FILE_ATTRIBUTE_TAG_INFO tag;win32_check(GetFileInformationByHandleEx(command_parents[i],FileAttributeTagInfo,&tag,sizeof(tag)),"command-parent-tag");invariant(!(tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),"command-parent-tag"); command_parent_baseline[i]=command_sd(command_parents[i],SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION);invariant(GetSecurityDescriptorLength(command_parent_baseline[i])<=8192,"command-parent-baseline"); }
  for(unsigned i=0;i<4;i++) {
    command_files[i]=CreateFileW(command_paths[i],GENERIC_READ|GENERIC_WRITE|READ_CONTROL|WRITE_DAC|ACCESS_SYSTEM_SECURITY|DELETE|WRITE_OWNER,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL); win32_check(command_files[i]!=INVALID_HANDLE_VALUE,"command-file-open");command_fixture_label(command_files[i]);
    FILE_ATTRIBUTE_TAG_INFO tag; win32_check(GetFileInformationByHandleEx(command_files[i],FileAttributeTagInfo,&tag,sizeof(tag)),"command-file-tag");invariant(!(tag.FileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)),"command-file-tag");
    /* Stock workspace grants inherit onto editable files. The read-only audit
     * gate keeps its original DACL; it needs no write-capability grant. */
    PSECURITY_DESCRIPTOR privateSd=descriptor(FALSE,FALSE);PACL privateAcl;BOOL privatePresent,privateDefault;win32_check(GetSecurityDescriptorDacl(privateSd,&privatePresent,&privateAcl,&privateDefault),"command-file-dacl");invariant(privatePresent,"command-file-dacl");status_check(SetSecurityInfo(command_files[i],SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|(i==3?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION),NULL,NULL,privateAcl,NULL),"command-file-protect");LocalFree(privateSd);
    fileid(command_files[i],command_ids[i]); command_baseline[i]=command_sd(command_files[i],SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION);invariant(GetSecurityDescriptorLength(command_baseline[i])<=8192,"command-file-baseline");
    PSID owner; BOOL def; win32_check(GetSecurityDescriptorOwner(command_baseline[i],&owner,&def),"command-file-owner");invariant(EqualSid(owner,userSid),"command-file-owner");
    PACL old; BOOL present; win32_check(GetSecurityDescriptorSacl(command_baseline[i],&present,&old,&def),"command-file-sacl"); DWORD length=(present&&old?old->AclSize:sizeof(ACL))+sizeof(SYSTEM_AUDIT_ACE)+GetLengthSid(userSid);
    invariant(length<=16384,"command-audit-size"); command_sacls[i]=LocalAlloc(LPTR,length); win32_check(command_sacls[i]!=NULL,"command-audit-allocation");win32_check(InitializeAcl(command_sacls[i],length,ACL_REVISION),"command-audit-init");
    for(unsigned j=0;present&&old&&j<old->AceCount;j++){ACE_HEADER *ace;win32_check(GetAce(old,j,(void **)&ace),"command-audit-ace-read");win32_check(AddAce(command_sacls[i],ACL_REVISION,MAXDWORD,ace,ace->AceSize),"command-audit-ace-copy");}
    win32_check(AddAuditAccessAceEx(command_sacls[i],ACL_REVISION,0,FILE_READ_DATA|FILE_WRITE_DATA,userSid,TRUE,TRUE),"command-audit-ace");
  }
}
/* The independent finish owner already holds the complete baseline and intent
 * event before this one-shot mutation. An ambiguous setter can leave a subset. */
static void command_audit_install(void) {
  command_policy_equal(); need(!command_principal_exists() && WaitForSingleObject(command_audit_intent,0)==WAIT_TIMEOUT);
  need(SetEvent(command_audit_intent));
  AUDIT_POLICY_INFORMATION policy={0}; policy.AuditSubCategoryGuid=command_category; policy.AuditingInformation=PER_USER_AUDIT_SUCCESS_INCLUDE|PER_USER_AUDIT_FAILURE_INCLUDE;
  need(AuditSetPerUserPolicy(userSid,&policy,1));
  for(unsigned i=0;i<4;i++) need(SetSecurityInfo(command_files[i],SE_FILE_OBJECT,SACL_SECURITY_INFORMATION,NULL,NULL,NULL,command_sacls[i])==ERROR_SUCCESS);
}
static void command_token_read(HANDLE token) {
  DWORD *container=info(token,TokenIsAppContainer); TOKEN_GROUPS *restricted=info(token,TokenRestrictedSids); TOKEN_STATISTICS *stats=info(token,TokenStatistics);
  need(restricted->GroupCount<=32 && !*container); char hash[65]; BYTE bytes[4096]={0}; unsigned used=0;
  for(unsigned i=0;i<restricted->GroupCount;i++){PSID sid=restricted->Groups[i].Sid;need(IsValidSid(sid) && used+GetLengthSid(sid)+4<=sizeof(bytes));DWORD attributes=restricted->Groups[i].Attributes;memcpy(bytes+used,&attributes,4);used+=4;memcpy(bytes+used,sid,GetLengthSid(sid));used+=GetLengthSid(sid);}
  command_sum(bytes,used,hash); printf("{\"appContainer\":false,\"restricted\":%s,\"restrictingSids\":%lu,\"restrictedSidsSha256\":\"%s\",\"integrity\":%lu,\"authenticationId\":\"%08lx:%08lx\"}",IsTokenRestricted(token)?"true":"false",restricted->GroupCount,hash,command_integrity(token),(DWORD)stats->AuthenticationId.HighPart,stats->AuthenticationId.LowPart);
  free(container);free(restricted);free(stats);
}
static void command_token(HANDLE process) { HANDLE token;need(OpenProcessToken(process,TOKEN_QUERY,&token));command_token_read(token);need(CloseHandle(token)); }
static void command_broker_token_read(HANDLE token) {
  TOKEN_STATISTICS *stats=info(token,TokenStatistics);
  printf("{\"tokenId\":\"%08lx:%08lx\",\"modifiedId\":\"%08lx:%08lx\",\"details\":",(DWORD)stats->TokenId.HighPart,stats->TokenId.LowPart,(DWORD)stats->ModifiedId.HighPart,stats->ModifiedId.LowPart);command_token_read(token);putchar('}');free(stats);
}
/* AuditComputeEffectivePolicyByToken takes a HANDLE with TOKEN_QUERY, not HANDLE *.
 * Advapi32 linkage is supplied by feasibility-helper.c. */
static void command_effective(HANDLE token) {
  AUDIT_POLICY_INFORMATION *policy=NULL;BOOL available=AuditComputeEffectivePolicyByToken(token,&command_category,1,&policy),success=FALSE;
  if(available){need(policy&&IsEqualGUID(&policy->AuditSubCategoryGuid,&command_category));success=(policy->AuditingInformation&POLICY_AUDIT_EVENT_SUCCESS)!=0;AuditFree(policy);}
  printf("{\"available\":%s,\"success\":%s}",available?"true":"false",success?"true":"false");
}
static void command_image_read(HANDLE process, const char *expected, BOOL provider) {
  WCHAR path[4096]; DWORD length=4096; win32_check(QueryFullProcessImageNameW(process,0,path,&length),"command-image-query"); HANDLE h=file(path,GENERIC_READ); char hash[65];
  if(provider)hash_provider_image(h,hash);else hashfile(h,hash);
  BOOL equal=!strcmp(hash,expected);if(!equal)remember("command-image-match","invariant",0);
  BOOL closed=close_handle(h,"file-close");if(!equal||!closed)failure(126);
}
static void command_limits(HANDLE job) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION value; win32_check(QueryInformationJobObject(job,JobObjectExtendedLimitInformation,&value,sizeof(value),NULL),"command-job-query");
  invariant(value.BasicLimitInformation.LimitFlags==(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS) && value.BasicLimitInformation.ActiveProcessLimit==32,"command-job-limits");
}
static DWORD command_members(HANDLE job) {
  BYTE bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)+32*sizeof(ULONG_PTR)]; JOBOBJECT_BASIC_PROCESS_ID_LIST *list=(void *)bytes; DWORD used;
  win32_check(QueryInformationJobObject(job,JobObjectBasicProcessIdList,list,sizeof(bytes),&used),"command-members-query");invariant(list->NumberOfAssignedProcesses==list->NumberOfProcessIdsInList && list->NumberOfProcessIdsInList<=32,"command-members-count");
  for(DWORD i=0;i<list->NumberOfProcessIdsInList;i++){invariant(list->ProcessIdList[i]<=MAXDWORD,"command-member-pid");HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,(DWORD)list->ProcessIdList[i]);BOOL member;
    win32_check(h!=NULL,"command-member-open");win32_check(IsProcessInJob(h,job,&member),"command-member-job");invariant(member,"command-member-job");if(!close_handle(h,"process-close"))failure(126);} return list->NumberOfProcessIdsInList;
}
static void command_capture(void) {
  for(;;){ EVT_HANDLE events[16]; DWORD count=0; if(!EvtNext(command_subscription,16,events,0,0,&count)){need(GetLastError()==ERROR_NO_MORE_ITEMS);return;}
    for(DWORD i=0;i<count;i++){DWORD length=0,counted;EvtRender(NULL,events[i],EvtRenderEventXml,0,NULL,&length,&counted);need(GetLastError()==ERROR_INSUFFICIENT_BUFFER && length>=4 && length<=65536 && !(length%2) && ++command_records<=4096 && command_bytes+length<=8388608);
      BYTE *bytes=calloc(1,length);need(bytes && EvtRender(NULL,events[i],EvtRenderEventXml,length,bytes,&length,&counted));command_bytes+=length;
      printf("{\"event\":\"audit\",\"hex\":\"");hex(bytes,length);printf("\",\"decoded\":");char *encoded=malloc((size_t)length*2+1);need(encoded);for(DWORD j=0;j<length;j++)snprintf(encoded+2*j,3,"%02x",bytes[j]);struct xml_result parsed=xml_parse(encoded);const WCHAR *process=NULL,*object=NULL,*eventId=NULL,*mask=NULL;
      for(unsigned j=0;j<parsed.count;j++){struct xml_field *f=&parsed.fields[j];if(!wcscmp(f->name,L"ProcessId"))process=f->value;else if(!wcscmp(f->name,L"ObjectName"))object=f->value;else if(!wcscmp(f->name,L"EventID"))eventId=f->value;else if(!wcscmp(f->name,L"AccessMask"))mask=f->value;}
      if(command_closing&&process&&object&&eventId&&mask&&!_wcsicmp(object,command_paths[3])&&!wcscmp(eventId,L"4663")){WCHAR *end;ULONGLONG pid=_wcstoui64(process,&end,0);if(!*end&&pid==GetCurrentProcessId()){ULONGLONG rights=_wcstoui64(mask,&end,0);if(!*end&&(rights&1))command_retirement_seen=TRUE;}}
      if(command_probing&&process&&object&&eventId&&mask&&!_wcsicmp(object,command_paths[3])&&!wcscmp(eventId,L"4663")){WCHAR *end;ULONGLONG pid=_wcstoui64(process,&end,0);if(!*end&&pid==GetCurrentProcessId()){ULONGLONG rights=_wcstoui64(mask,&end,0);if(!*end&&(rights&1))command_coverage_seen=TRUE;}}
      if(command_case_pid&&process&&object&&eventId&&mask){WCHAR *end;ULONGLONG pid=_wcstoui64(process,&end,0);if(!*end&&pid==command_case_pid){ULONGLONG rights=_wcstoui64(mask,&end,0);if(!*end){if(!_wcsicmp(object,command_paths[command_action])&&(rights&(command_action==0?1:2)))command_target_seen=TRUE;if(command_target_seen&&!_wcsicmp(object,command_paths[3])&&!wcscmp(eventId,L"4663")&&(rights&1))command_marker_seen=TRUE;}}}free(parsed.fields);
      xml_decode(encoded);puts("}");free(encoded);free(bytes);need(EvtUpdateBookmark(command_bookmark,events[i])&&EvtClose(events[i])); }
  }
}
static void command_gate_read(void) {
  /* Reopen the original held object under the exact queried token. The new
   * access receives the installed SACL; a pre-installation handle cannot prove it. */
  need(ImpersonateLoggedOnUser(command_broker_token));
  HANDLE marker=ReOpenFile(command_files[3],GENERIC_READ|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0);
  char id[50],bytes[32],expected[33];DWORD count;need(marker!=INVALID_HANDLE_VALUE);fileid(marker,id);
  need(!strcmp(id,command_ids[3])&&ReadFile(marker,bytes,32,&count,NULL)&&count==32&&CloseHandle(marker)&&RevertToSelf());
  need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,nonce,-1,expected,33,NULL,NULL)==33&&!memcmp(bytes,expected,32));
}
static void command_coverage_control(void) {
  command_probing=TRUE;command_coverage_seen=FALSE;command_gate_read();ULONGLONG started=GetTickCount64();
  while(!command_coverage_seen&&GetTickCount64()-started<10000){command_bound();command_capture();WaitForSingleObject(command_event,1);}
  command_probing=FALSE;puts("{\"event\":\"P\"}");
}
static void command_barrier(void) { ULONGLONG wait=GetTickCount64();do{command_capture();if(!command_case_pid||command_marker_seen)break;command_bound();need(GetTickCount64()-wait<10000);WaitForSingleObject(command_event,10);}while(1);FILETIME ft;GetSystemTimePreciseAsFileTime(&ft);ULARGE_INTEGER time;time.LowPart=ft.dwLowDateTime;time.HighPart=ft.dwHighDateTime;
  printf("{\"event\":\"B\",\"sequence\":%u,\"time\":\"%llu\",\"records\":%u}\n",++command_barriers,time.QuadPart,command_records); }
static void command_pump(HANDLE *pipe,const char *event) {
  if(!*pipe)return; DWORD available=0; if(!PeekNamedPipe(*pipe,NULL,0,NULL,&available,NULL)){need(GetLastError()==ERROR_BROKEN_PIPE);need(CloseHandle(*pipe));*pipe=NULL;if(!strcmp(event,"rpc")||!strcmp(event,"stderr"))printf("{\"event\":\"%s-end\"}\n",event);return;}
  if(available){BYTE bytes[4096];DWORD count;need(ReadFile(*pipe,bytes,available<sizeof(bytes)?available:sizeof(bytes),&count,NULL)&&count);printf("{\"event\":\"%s\",\"hex\":\"",event);hex(bytes,count);puts("\"}");}
}
static PROCESS_INFORMATION command_spawn(const WCHAR *arguments,const WCHAR *cwd) {
  invariant(command_count<16&&!command_closing,"command-launch-state"); HANDLE readIn,writeOut,writeErr; SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
  win32_check(CreatePipe(&readIn,&command_input,&sa,0),"command-stdin-pipe");win32_check(CreatePipe(&command_output,&writeOut,&sa,0),"command-stdout-pipe");win32_check(CreatePipe(&command_error,&writeErr,&sa,0),"command-stderr-pipe");
  win32_check(SetHandleInformation(command_input,HANDLE_FLAG_INHERIT,0),"command-stdin-inherit");win32_check(SetHandleInformation(command_output,HANDLE_FLAG_INHERIT,0),"command-stdout-inherit");win32_check(SetHandleInformation(command_error,HANDLE_FLAG_INHERIT,0),"command-stderr-inherit");
  HANDLE medium=command_medium_token(TRUE);
  SIZE_T size=0;InitializeProcThreadAttributeList(NULL,2,0,&size);LPPROC_THREAD_ATTRIBUTE_LIST attrs=malloc(size);invariant(attrs!=NULL,"command-attribute-allocation");win32_check(InitializeProcThreadAttributeList(attrs,2,0,&size),"command-attribute-init");
  HANDLE inherit[3]={readIn,writeOut,writeErr};command_interface(UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&ownedJob,sizeof(ownedJob),NULL,NULL),"command-attribute-job");command_interface(UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherit,sizeof(inherit),NULL,NULL),"command-attribute-handles");
  STARTUPINFOEXW si={0};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=readIn;si.StartupInfo.hStdOutput=writeOut;si.StartupInfo.hStdError=writeErr;si.lpAttributeList=attrs;
  WCHAR line[16384]; invariant(wcslen(arguments)<16380,"command-launch-bound");wcscpy_s(line,16384,arguments); LPWCH environment=GetEnvironmentStringsW(); win32_check(environment!=NULL,"command-launch-environment");
  PROCESS_INFORMATION p={0};BOOL created=CreateProcessAsUserW(medium,NULL,line,NULL,NULL,TRUE,CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT,environment,cwd,&si.StartupInfo,&p);
  DWORD error=created?ERROR_SUCCESS:GetLastError();if(!created)remember("command-process-create","win32",error);
  BOOL cleaned=FreeEnvironmentStringsW(environment);if(!cleaned){DWORD cleanup=GetLastError();remember("command-environment-close","win32",cleanup);cleanup_error("command-environment-close","win32",cleanup);}
  DeleteProcThreadAttributeList(attrs);free(attrs);
  if(!release_handle(&command_preflight_owned.launch,"command-token-close"))cleaned=FALSE;
  if(!close_handle(readIn,"pipe-close"))cleaned=FALSE;
  if(!close_handle(writeOut,"pipe-close"))cleaned=FALSE;
  if(!close_handle(writeErr,"pipe-close"))cleaned=FALSE;
  if(!cleaned)failure(126);
  if(!created)failure(error==ERROR_NOT_SUPPORTED||error==ERROR_CALL_NOT_IMPLEMENTED||error==ERROR_PRIVILEGE_NOT_HELD?78:126);
  BOOL member;win32_check(IsProcessInJob(p.hProcess,ownedJob,&member),"command-child-job");invariant(member,"command-child-job");command_processes[command_count]=p.hProcess;command_threads[command_count++]=p.hThread;return p;
}
static void command_probe_output(PROCESS_INFORMATION p,const char *event) {
  need(ResumeThread(p.hThread)==1 && CloseHandle(command_input));command_input=NULL;
  while(WaitForSingleObject(p.hProcess,0)==WAIT_TIMEOUT){command_bound();command_pump(&command_output,"probe-output");command_pump(&command_error,"probe-stderr");command_capture();Sleep(1);}
  command_pump(&command_output,"probe-output");command_pump(&command_error,"probe-stderr");DWORD code;need(GetExitCodeProcess(p.hProcess,&code));printf("{\"event\":\"%s\",\"exitCode\":%lu}\n",event,code);
  if(command_output)need(CloseHandle(command_output));if(command_error)need(CloseHandle(command_error));command_output=command_error=NULL;
}
static void command_case(int argc,WCHAR **argv) {
  need(argc==8 && wcslen(argv[5])==32); HANDLE pipe=CreateFileW(argv[2],GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);need(pipe!=INVALID_HANDLE_VALUE);DWORD count;char nonceBytes[33];
  need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[5],-1,nonceBytes,33,NULL,NULL)==33 && WriteFile(pipe,nonceBytes,32,&count,NULL)&&count==32);char ackValue;need(ReadFile(pipe,&ackValue,1,&count,NULL)&&count==1&&ackValue=='R');
  DWORD rights[2]={PROCESS_DUP_HANDLE,PROCESS_TERMINATE};for(unsigned i=0;i<2;i++){SetLastError(0);HANDLE authority=OpenProcess(rights[i],FALSE,(DWORD)number(argv[7]));need(!authority&&GetLastError()==ERROR_ACCESS_DENIED);}
  BOOL inspect=!wcscmp(argv[4],L"inspect");HANDLE target=CreateFileW(argv[3],inspect?GENERIC_READ:GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
  if(inspect){char bytes[33]={0};need(target!=INVALID_HANDLE_VALUE&&ReadFile(target,bytes,32,&count,NULL)&&count==32&&!memcmp(bytes,nonceBytes,32));printf("%s",bytes);}
  else if(target!=INVALID_HANDLE_VALUE){need(WriteFile(target,nonceBytes,32,&count,NULL)&&count==32&&WriteFile(target,"-edited",7,&count,NULL)&&count==7&&SetEndOfFile(target)&&FlushFileBuffers(target));printf("attempt:written");}
  else {need(GetLastError()==ERROR_ACCESS_DENIED);printf("attempt:denied");} if(target!=INVALID_HANDLE_VALUE)need(CloseHandle(target));need(!fflush(stdout));
  HANDLE marker=CreateFileW(argv[6],GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);char bytes[32];need(marker!=INVALID_HANDLE_VALUE&&ReadFile(marker,bytes,32,&count,NULL)&&count==32&&CloseHandle(marker));
  need(WriteFile(pipe,nonceBytes,32,&count,NULL)&&count==32&&ReadFile(pipe,&ackValue,1,&count,NULL)&&count==1&&ackValue=='F'&&CloseHandle(pipe));
}
static void command_retire_domain(void);
struct command_gate_read { BOOL connect, ok; char bytes[32]; };
static DWORD WINAPI command_gate_receive(void *argument) {
  struct command_gate_read *read=argument;BOOL connected=!read->connect||ConnectNamedPipe(command_gate,NULL)||GetLastError()==ERROR_PIPE_CONNECTED;DWORD count=0;
  read->ok=connected&&ReadFile(command_gate,read->bytes,32,&count,NULL)&&count==32;return 0;
}
/* Receive on a cancellable native thread; D must remain available even when a
 * buffered route rejects admission or the parked command never acknowledges. */
static BOOL command_gate_wait(BOOL connect, char bytes[32]) {
  struct command_gate_read read={0};read.connect=connect;HANDLE thread=CreateThread(NULL,0,command_gate_receive,&read,0,NULL);need(thread);
  while(WaitForSingleObject(thread,0)==WAIT_TIMEOUT){command_bound();command_capture();command_pump(&command_output,command_control?"probe-output":"rpc");command_pump(&command_error,command_control?"probe-stderr":"stderr");
    DWORD available,count;HANDLE input=GetStdHandle(STD_INPUT_HANDLE);need(PeekNamedPipe(input,NULL,0,NULL,&available,NULL));
    if(available>=2){char request[2];need(ReadFile(input,request,2,&count,NULL)&&count==2&&request[0]=='D'&&request[1]=='\n');command_cleanup_begin();
      while(WaitForSingleObject(thread,0)==WAIT_TIMEOUT){command_bound();SetLastError(0);need(CancelSynchronousIo(thread)||GetLastError()==ERROR_NOT_FOUND);WaitForSingleObject(thread,1);}
      need(CloseHandle(thread));command_retire_domain();return FALSE;
    }WaitForSingleObject(thread,1);
  }need(CloseHandle(thread)&&read.ok);memcpy(bytes,read.bytes,32);return TRUE;
}
static void command_case_observe(BOOL after) {
  char bytes[32],expected[33];if(!command_gate_wait(!after,bytes))return;need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,nonce,-1,expected,33,NULL,NULL)==33&&!memcmp(bytes,expected,32));
  if(!after){DWORD pid;need(GetNamedPipeClientProcessId(command_gate,&pid));command_case_pid=pid;command_target_seen=command_marker_seen=FALSE;command_client=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);need(command_client);BOOL member;need(IsProcessInJob(command_client,ownedJob,&member)&&member);command_image_read(command_client,command_helper_hash,FALSE);}
  printf("{\"event\":\"%s\",\"identity\":",after?"F":"N");identity(command_client);printf(",\"token\":");command_token(command_client);printf(",\"imageSha256\":\"%s\",\"object\":",command_helper_hash);command_snapshot(command_action);printf(",\"gate\":");command_snapshot(3);puts("}");

}
static void command_retire_domain(void) {
  command_cleanup_begin();
  need(SetEvent(command_closed));
  if(command_gate){need(CloseHandle(command_gate));command_gate=NULL;}if(command_client){need(CloseHandle(command_client));command_client=NULL;}
  if(command_server&&!command_server_released)need(TerminateProcess(command_server,0));
  if(command_input){need(CloseHandle(command_input));command_input=NULL;}if(command_saved_input&&command_control){need(CloseHandle(command_saved_input));command_saved_input=NULL;}
  while(command_members(ownedJob)){command_bound();command_capture();command_pump(&command_output,command_control?"probe-output":"rpc");command_pump(&command_error,command_control?"probe-stderr":"stderr");Sleep(1);}
  for(unsigned i=0;i<command_count;i++){DWORD code;need(WaitForSingleObject(command_processes[i],0)==WAIT_OBJECT_0&&GetExitCodeProcess(command_processes[i],&code)&&code!=STILL_ACTIVE);}
  /* Admitted runs retain the delivered terminal witness. A refused preflight
   * has no provider domain and cannot depend on its unavailable audit coverage. */
  if(command_coverage_admitted){command_gate_read();ULONGLONG flush=GetTickCount64();while(!command_retirement_seen){command_bound();need(GetTickCount64()-flush<10000);command_capture();WaitForSingleObject(command_event,1);}}
  printf("{\"event\":\"D\",\"empty\":true,\"admissionsClosed\":true,\"files\":[");for(unsigned i=0;i<4;i++){if(i)putchar(',');command_snapshot(i);}puts("]}");
}
static void command_check(int argc,WCHAR **argv) {
  need(argc==9&&(!wcscmp(argv[8],L"helper")||!wcscmp(argv[8],L"provider")));HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_DUP_HANDLE|SYNCHRONIZE,FALSE,(DWORD)number(argv[2]));need(owner&&creation(owner)==number(argv[3])&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT);
  HANDLE job;need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)number(argv[4]),GetCurrentProcess(),&job,JOB_OBJECT_QUERY,FALSE,0));command_limits(job);
  HANDLE child=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,(DWORD)number(argv[5]));BOOL member;need(child&&creation(child)==number(argv[6])&&WaitForSingleObject(child,0)==WAIT_TIMEOUT&&IsProcessInJob(child,job,&member)&&member);
  char expected[65];need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[7],-1,expected,65,NULL,NULL)==65);command_image_read(child,expected,!wcscmp(argv[8],L"provider"));
  printf("{\"identity\":");identity(child);printf(",\"token\":");command_token(child);puts(",\"creationJob\":true}");need(CloseHandle(child)&&CloseHandle(job)&&CloseHandle(owner));
}
static void command_broker_check(int argc,WCHAR **argv) {
  need(argc==8);HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_DUP_HANDLE|SYNCHRONIZE,FALSE,(DWORD)number(argv[2]));need(owner&&creation(owner)==number(argv[3])&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT);
  char expected[65];need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[4],-1,expected,65,NULL,NULL)==65);command_image_read(owner,expected,FALSE);
  HANDLE token,actual,gate,job;need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)number(argv[5]),GetCurrentProcess(),&token,TOKEN_QUERY,FALSE,0)&&OpenProcessToken(owner,TOKEN_QUERY,&actual));
  TOKEN_STATISTICS *held=info(token,TokenStatistics),*current=info(actual,TokenStatistics);TOKEN_USER *user=info(token,TokenUser);
  need(held->TokenType==TokenPrimary&&!memcmp(&held->TokenId,&current->TokenId,sizeof(LUID))&&!memcmp(&held->ModifiedId,&current->ModifiedId,sizeof(LUID))&&!memcmp(&held->AuthenticationId,&current->AuthenticationId,sizeof(LUID))&&EqualSid(user->User.Sid,userSid)&&!IsTokenRestricted(token)&&command_integrity(token)>=SECURITY_MANDATORY_HIGH_RID);
  free(held);free(current);free(user);need(CloseHandle(actual));
  command_privilege(SE_SECURITY_NAME);
  need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)number(argv[6]),GetCurrentProcess(),&gate,GENERIC_READ|READ_CONTROL,FALSE,0)&&DuplicateHandle(owner,(HANDLE)(ULONG_PTR)number(argv[7]),GetCurrentProcess(),&job,JOB_OBJECT_QUERY,FALSE,0));command_limits(job);need(!command_members(job));
  printf("{\"identity\":");identity(owner);printf(",\"token\":");command_broker_token_read(token);printf(",\"effective\":");command_effective(token);char id[50];fileid(gate,id);printf(",\"gate\":");command_snapshot_handle(gate,id);puts("}");need(CloseHandle(token)&&CloseHandle(gate)&&CloseHandle(job)&&CloseHandle(owner));
}
static void command_line(char *out,unsigned capacity) {
  unsigned size=0;DWORD count;char c;do{need(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&c,1,&count,NULL)&&count==1&&size+1<capacity);if(c!='\n')out[size++]=c;}while(c!='\n');out[size]=0;
}
static BYTE *command_unhex(const char *text, DWORD *length) {
  size_t n=strlen(text);need(n&&n<=131072&&!(n%2));*length=(DWORD)(n/2);BYTE *bytes=malloc(*length);need(bytes);for(DWORD i=0;i<*length;i++)bytes[i]=(BYTE)(nibble(text[2*i])*16+nibble(text[2*i+1]));return bytes;
}
static BOOL command_same_acl(PACL a,PACL b) { return (!a&&!b)||(a&&b&&a->AclSize==b->AclSize&&!memcmp(a,b,a->AclSize)); }
static void command_owned_sacl(HANDLE file,PSECURITY_DESCRIPTOR baseline,PACL wanted,BOOL authorized) {
  PSECURITY_DESCRIPTOR sd=command_sd(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION);PACL sacl,old;PSID owner;BOOL present,def;SECURITY_DESCRIPTOR_CONTROL current,saved;DWORD revision;
  need(GetSecurityDescriptorOwner(sd,&owner,&def)&&EqualSid(owner,userSid)&&GetSecurityDescriptorSacl(sd,&present,&sacl,&def)&&GetSecurityDescriptorSacl(baseline,&present,&old,&def)&&GetSecurityDescriptorControl(sd,&current,&revision)&&GetSecurityDescriptorControl(baseline,&saved,&revision)&&!((current^saved)&SE_SACL_PROTECTED));
  need(command_same_acl(sacl,old)||(authorized&&wanted&&command_same_acl(sacl,wanted)));LocalFree(sd);
}
static BOOL command_owned_policy(BOOL authorized) {
  BOOL present=command_principal_exists();if(!present)return FALSE;need(authorized);
  AUDIT_POLICY_INFORMATION *policy;need(AuditQueryPerUserPolicy(userSid,command_categories,command_category_count,&policy));
  for(ULONG i=0;i<command_category_count;i++)need(IsEqualGUID(&policy[i].AuditSubCategoryGuid,&command_categories[i])&&policy[i].AuditingInformation==(IsEqualGUID(&command_categories[i],&command_category)?(PER_USER_AUDIT_SUCCESS_INCLUDE|PER_USER_AUDIT_FAILURE_INCLUDE):0));AuditFree(policy);return TRUE;
}
static void command_finish(int argc,WCHAR **argv) {
  need(argc==7);HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_DUP_HANDLE|PROCESS_TERMINATE|SYNCHRONIZE,FALSE,(DWORD)number(argv[2]));need(owner&&creation(owner)==number(argv[3])&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT);
  char expected[65];need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[4],-1,expected,65,NULL,NULL)==65);command_image_read(owner,expected,FALSE);
  HANDLE job;need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)number(argv[6]),GetCurrentProcess(),&job,JOB_OBJECT_QUERY|JOB_OBJECT_TERMINATE,FALSE,0));command_limits(job);need(!command_members(job));
  printf("{\"ready\":true,\"identity\":");identity(GetCurrentProcess());puts("}");
  char line[131200], systemHash[65],nullHash[65];command_line(line,sizeof(line));need(strlen(line)>130&&strlen(line)<=200&&line[64]==' '&&line[129]==' ');memcpy(systemHash,line,64);systemHash[64]=0;memcpy(nullHash,line+65,64);nullHash[64]=0;
  char *context,*values[3];values[0]=strtok_s(line+130," ",&context);values[1]=strtok_s(NULL," ",&context);values[2]=strtok_s(NULL," ",&context);need(values[0]&&values[1]&&values[2]&&!strtok_s(NULL," ",&context));
  char *nullEnd;ULONGLONG nullValue=_strtoui64(values[0],&nullEnd,10);need(nullValue&&!*nullEnd);HANDLE null;need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)nullValue,GetCurrentProcess(),&null,READ_CONTROL,FALSE,0));
  HANDLE intent,closed;HANDLE *events[2]={&intent,&closed};for(unsigned i=0;i<2;i++){ULONGLONG value=_strtoui64(values[i+1],&nullEnd,10);need(value&&!*nullEnd&&DuplicateHandle(owner,(HANDLE)(ULONG_PTR)value,GetCurrentProcess(),events[i],SYNCHRONIZE,FALSE,0));}
  HANDLE files[6];PSECURITY_DESCRIPTOR baselines[6];PACL wanted[4];char ids[6][50];
  for(unsigned i=0;i<6;i++){command_line(line,sizeof(line));char *context,*source=strtok_s(line," ",&context),*id=strtok_s(NULL," ",&context),*baseline=strtok_s(NULL," ",&context),*sacl=strtok_s(NULL," ",&context);need(source&&id&&baseline&&sacl&&!strtok_s(NULL," ",&context)&&strlen(id)==49);
    char *end;ULONGLONG value=_strtoui64(source,&end,10);need(value&&!*end);need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)value,GetCurrentProcess(),&files[i],0,FALSE,DUPLICATE_SAME_ACCESS));fileid(files[i],ids[i]);need(!strcmp(ids[i],id));DWORD length;baselines[i]=(void *)command_unhex(baseline,&length);need(IsValidSecurityDescriptor(baselines[i])&&GetSecurityDescriptorLength(baselines[i])==length);
    PSID sid;BOOL def;need(GetSecurityDescriptorOwner(baselines[i],&sid,&def)&&EqualSid(sid,userSid));if(i<4){wanted[i]=(void *)command_unhex(sacl,&length);need(IsValidAcl(wanted[i])&&wanted[i]->AclSize==length);}else need(!strcmp(sacl,"-"));
  }
  puts("{\"custodyReady\":true}");BOOL emergency=FALSE;
  for(;;){char request;DWORD count;need(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&request,1,&count,NULL)&&count==1);if(request=='R')break;need(request=='D');command_cleanup_begin();
    if(WaitForSingleObject(owner,0)==WAIT_TIMEOUT&&WaitForSingleObject(closed,0)!=WAIT_OBJECT_0){need(TerminateProcess(owner,126)&&WaitForSingleObject(owner,25000)==WAIT_OBJECT_0&&TerminateJobObject(job,126));emergency=TRUE;}
    if(WaitForSingleObject(owner,0)==WAIT_OBJECT_0&&command_members(job)){need(TerminateJobObject(job,126));emergency=TRUE;}
    while(command_members(job)){command_bound();Sleep(1);}need(WaitForSingleObject(owner,0)==WAIT_OBJECT_0||WaitForSingleObject(closed,0)==WAIT_OBJECT_0);
    BOOL retired=WaitForSingleObject(owner,0)==WAIT_OBJECT_0;DWORD code;if(retired){need(GetExitCodeProcess(owner,&code)&&code!=STILL_ACTIVE);emergency|=code==124||code==126;}
    printf("{\"empty\":true,\"admissionsClosed\":true,\"ownerRetired\":%s,\"emergency\":%s,\"files\":[",retired?"true":"false",emergency?"true":"false");for(unsigned i=0;i<4;i++){if(i)putchar(',');command_snapshot_handle(files[i],ids[i]);}puts("]}");
  }
  command_cleanup_begin();need(WaitForSingleObject(owner,25000)==WAIT_OBJECT_0);DWORD code;need(GetExitCodeProcess(owner,&code)&&code!=STILL_ACTIVE&&!command_members(job)&&CloseHandle(job));job=NULL;
  command_privilege(SE_SECURITY_NAME);need(AuditEnumerateSubCategories(NULL,TRUE,&command_categories,&command_category_count)&&command_category_count&&command_category_count<=128&&AuditQuerySystemPolicy(command_categories,command_category_count,&command_system));
  char actual[65];command_sum((BYTE *)command_system,command_category_count*sizeof(*command_system),actual);need(!strcmp(actual,systemHash));DWORD authorized=WaitForSingleObject(intent,0);need(authorized==WAIT_OBJECT_0||authorized==WAIT_TIMEOUT);BOOL policyPresent=command_owned_policy(authorized==WAIT_OBJECT_0);
  PSECURITY_DESCRIPTOR sd=command_sd(null,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION);command_sum(sd,GetSecurityDescriptorLength(sd),actual);need(!strcmp(actual,nullHash));LocalFree(sd);
  // Validate the complete original handle/descriptor set before any restoration.
  for(unsigned i=0;i<6;i++){char id[50];fileid(files[i],id);need(!strcmp(id,ids[i]));command_owned_sacl(files[i],baselines[i],i<4?wanted[i]:NULL,authorized==WAIT_OBJECT_0);}
  const unsigned order[6]={4,5,0,1,2,3};
  for(unsigned k=0;k<6;k++){unsigned i=order[k];PSID ownerSid;PACL dacl,sacl;BOOL present,def;SECURITY_DESCRIPTOR_CONTROL control;DWORD revision;need(GetSecurityDescriptorOwner(baselines[i],&ownerSid,&def)&&GetSecurityDescriptorDacl(baselines[i],&present,&dacl,&def)&&GetSecurityDescriptorSacl(baselines[i],&present,&sacl,&def)&&GetSecurityDescriptorControl(baselines[i],&control,&revision));
    SECURITY_INFORMATION protection=(control&SE_DACL_PROTECTED?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION)|(control&SE_SACL_PROTECTED?PROTECTED_SACL_SECURITY_INFORMATION:UNPROTECTED_SACL_SECURITY_INFORMATION);
    command_owned_sacl(files[i],baselines[i],i<4?wanted[i]:NULL,authorized==WAIT_OBJECT_0);need(SetSecurityInfo(files[i],SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION|protection,NULL,NULL,dacl,present?sacl:NULL)==ERROR_SUCCESS);
    sd=command_sd(files[i],SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION);PSID actualOwner;PACL actualDacl,actualSacl;BOOL actualPresent;SECURITY_DESCRIPTOR_CONTROL actualControl;need(GetSecurityDescriptorControl(sd,&actualControl,&revision)&&!((control^actualControl)&(SE_DACL_PROTECTED|SE_SACL_PROTECTED))&&GetSecurityDescriptorOwner(sd,&actualOwner,&def)&&EqualSid(ownerSid,actualOwner)&&GetSecurityDescriptorDacl(sd,&actualPresent,&actualDacl,&def)&&actualPresent&&actualDacl&&dacl&&actualDacl->AclSize==dacl->AclSize&&!memcmp(actualDacl,dacl,dacl->AclSize)&&GetSecurityDescriptorSacl(sd,&actualPresent,&actualSacl,&def));need((!sacl&&!actualSacl)||(sacl&&actualSacl&&sacl->AclSize==actualSacl->AclSize&&!memcmp(sacl,actualSacl,sacl->AclSize)));LocalFree(sd);
  }
  need(command_owned_policy(authorized==WAIT_OBJECT_0)==policyPresent);
  if(policyPresent) {
    struct audit_remove_result removal;
    if(!audit_remove_owned_policy(userSid,&removal)) {
      remember("audit-remove","win32",removal.error?removal.error:removal.cleanup);
      if(removal.cleanup)cleanup_error("audit-remove-settle","win32",removal.cleanup);
      failure(126);
    }
  }
  need(!command_principal_exists());command_policy_equal();
  for(unsigned i=0;i<4;i++){FILE_DISPOSITION_INFO deletion={TRUE};need(SetFileInformationByHandle(files[i],FileDispositionInfo,&deletion,sizeof(deletion))&&CloseHandle(files[i]));}for(unsigned i=4;i<6;i++)need(CloseHandle(files[i]));
  sd=command_sd(null,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION);command_sum(sd,GetSecurityDescriptorLength(sd),actual);need(!strcmp(actual,nullHash));LocalFree(sd);need(CloseHandle(null)&&CloseHandle(intent)&&CloseHandle(closed)&&CloseHandle(owner));
  puts("{\"retired\":true,\"completeDomain\":true,\"restored\":true,\"fixturesRemoved\":true}");
}
static void command_watch(int argc,WCHAR **argv) {
  need(argc==6||argc==7);DWORD pid=(DWORD)number(argv[2]);HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_DUP_HANDLE|SYNCHRONIZE,FALSE,pid);need(owner&&creation(owner)==number(argv[3])&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT);char hash[65];need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[4],-1,hash,65,NULL,NULL)==65);command_image_read(owner,hash,FALSE);
  HANDLE job=NULL; if(argc==7){need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)number(argv[6]),GetCurrentProcess(),&job,JOB_OBJECT_QUERY,FALSE,0));command_limits(job);}
  printf("{\"ready\":true,\"identity\":");identity(GetCurrentProcess());puts("}");ack('R');command_cleanup_begin();
  need(WaitForSingleObject(owner,25000)==WAIT_OBJECT_0);DWORD code;need(GetExitCodeProcess(owner,&code)&&code!=STILL_ACTIVE);if(job){need(!command_members(job)&&CloseHandle(job));}
  need(CloseHandle(owner));printf("{\"retired\":true,\"completeDomain\":true,\"exitCode\":%lu}\n",code);
}
static int command_main(int argc,WCHAR **argv) {
  command_preflight_owned.active=!wcscmp(role,L"command-preflight")||!wcscmp(role,L"command-broker");
  command_started=GetTickCount64();WCHAR lifetime[16];SetLastError(ERROR_SUCCESS);DWORD lifetimeSize=GetEnvironmentVariableW(L"NATIVE_COMMAND_LIFETIME_MS",lifetime,16);
  if(!lifetimeSize){DWORD error=GetLastError();if(error!=ERROR_SUCCESS&&error!=ERROR_ENVVAR_NOT_FOUND){remember("command-lifetime-read","win32",error);failure(126);}}
  if(lifetimeSize){invariant(lifetimeSize<16,"command-lifetime-size");ULONGLONG ms=number(lifetime);invariant(ms<=150000,"command-lifetime-range");command_lifetime=(DWORD)ms;win32_check(SetEnvironmentVariableW(L"NATIVE_COMMAND_LIFETIME_MS",NULL),"command-lifetime-clear");}
  if(!wcscmp(role,L"command-case")){command_case(argc,argv);return 0;}
  WCHAR ci[8],os[16];host_environment(L"GITHUB_ACTIONS",L"true",ci,8,"command-host-actions");host_environment(L"RUNNER_OS",L"Windows",os,16,"command-host-os");
  command_cleanup_timer=CreateEventW(NULL,TRUE,FALSE,NULL);win32_check(command_cleanup_timer!=NULL,"command-timer-create");
  if(!wcscmp(role,L"command-watch")||!wcscmp(role,L"command-check")||!wcscmp(role,L"command-broker-check")||!wcscmp(role,L"command-finish")){principal();command_protect(GetCurrentProcess(),PROCESS_ALL_ACCESS,"command-protect-process");HANDLE timer=CreateThread(NULL,0,command_expire,NULL,0,NULL);win32_check(timer!=NULL,"command-timer-thread");if(!close_handle(timer,"thread-close"))failure(126);if(!wcscmp(role,L"command-check"))command_check(argc,argv);else if(!wcscmp(role,L"command-broker-check"))command_broker_check(argc,argv);else if(!wcscmp(role,L"command-finish"))command_finish(argc,argv);else command_watch(argc,argv);return 0;}
  if(!wcscmp(role,L"command-broker")){HANDLE timer=CreateThread(NULL,0,command_expire,NULL,0,NULL);win32_check(timer!=NULL,"command-timer-thread");if(!close_handle(timer,"thread-close"))failure(126);}
  BOOL emit=!wcscmp(role,L"command-preflight");if(emit)invariant(argc==2,"command-preflight-arguments");
  HRESULT initialized=CoInitializeEx(NULL,COINIT_MULTITHREADED);if(FAILED(initialized)){remember("command-com-initialize","hresult",(DWORD)initialized);failure(126);}command_preflight_owned.comReady=TRUE;
  command_preflight(emit);if(emit)return 0;
  invariant(argc==8&&!wcscmp(role,L"command-broker"),"command-broker-arguments");root=argv[2];nonce=argv[3];invariant(wcslen(nonce)==32&&wcsspn(nonce,L"0123456789abcdef")==32,"command-broker-nonce");
  wcscpy_s(command_image,4096,argv[4]);wcscpy_s(command_helper,4096,argv[6]);
  int imageBytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[5],-1,command_image_hash,65,NULL,NULL);win32_check(imageBytes!=0,"command-image-digest");invariant(imageBytes==65,"command-image-digest");
  int helperBytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[7],-1,command_helper_hash,65,NULL,NULL);win32_check(helperBytes!=0,"command-helper-digest");invariant(helperBytes==65,"command-helper-digest");
  WCHAR build[4096];name(build,L"build");command_build_parent=CreateFileW(build,READ_CONTROL|WRITE_OWNER,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);win32_check(command_build_parent!=INVALID_HANDLE_VALUE,"command-build-open");
  PSECURITY_DESCRIPTOR labelSd;win32_check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;HI)",SDDL_REVISION_1,&labelSd,NULL),"command-build-descriptor");PACL labelAcl;BOOL present,def;win32_check(GetSecurityDescriptorSacl(labelSd,&present,&labelAcl,&def),"command-build-sacl");invariant(present,"command-build-sacl");status_check(SetSecurityInfo(command_build_parent,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,labelAcl),"command-build-label");
  command_helper_file=CreateFileW(command_helper,GENERIC_READ|READ_CONTROL|WRITE_OWNER,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);win32_check(command_helper_file!=INVALID_HANDLE_VALUE,"command-helper-open");status_check(SetSecurityInfo(command_helper_file,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,labelAcl),"command-helper-label");LocalFree(labelSd);
  command_image_file=CreateFileW(command_image,GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);win32_check(command_image_file!=INVALID_HANDLE_VALUE,"command-image-open");char actualHash[65];hashfile(command_helper_file,actualHash);invariant(!strcmp(actualHash,command_helper_hash),"command-helper-digest-match");hash_provider_image(command_image_file,actualHash);invariant(!strcmp(actualHash,command_image_hash),"command-image-digest-match");
  command_protect(GetCurrentProcess(),PROCESS_ALL_ACCESS,"command-protect-process");ownedJob=CreateJobObjectW(NULL,NULL);win32_check(ownedJob!=NULL,"command-job-create");command_protect(ownedJob,JOB_OBJECT_ALL_ACCESS,"command-protect-job");JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;limits.BasicLimitInformation.ActiveProcessLimit=32;
  win32_check(SetInformationJobObject(ownedJob,JobObjectExtendedLimitInformation,&limits,sizeof(limits)),"command-job-config");command_limits(ownedJob);BOOL member;win32_check(IsProcessInJob(GetCurrentProcess(),ownedJob,&member),"command-job-membership");invariant(!member,"command-job-membership");
  win32_check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_IMPERSONATE,&command_broker_token),"command-broker-token");command_broker_events();
  command_event=CreateEventW(NULL,FALSE,FALSE,NULL);win32_check(command_event!=NULL,"command-capture-event");command_bookmark=EvtCreateBookmark(NULL);win32_check(command_bookmark!=NULL,"command-bookmark");
  WCHAR admissionLine[8192];invariant(swprintf_s(admissionLine,8192,L"\"%ls\" command-case",command_helper)>0,"command-admission-line");PROCESS_INFORMATION admission=command_spawn(admissionLine,root);command_image_read(admission.hProcess,command_helper_hash,FALSE);win32_check(TerminateProcess(admission.hProcess,0),"command-admission-terminate");
  DWORD waited=WaitForSingleObject(admission.hProcess,10000);if(waited==WAIT_FAILED)win32_check(FALSE,"command-admission-wait");invariant(waited==WAIT_OBJECT_0,"command-admission-wait");
  BOOL pipesClosed=TRUE;if(!release_handle(&command_input,"pipe-close"))pipesClosed=FALSE;if(!release_handle(&command_output,"pipe-close"))pipesClosed=FALSE;if(!release_handle(&command_error,"pipe-close"))pipesClosed=FALSE;if(!pipesClosed)failure(126);invariant(!command_members(ownedJob),"command-admission-members");
  command_files_prepare();WCHAR query[18000];invariant(swprintf_s(query,18000,L"*[System[(EventID=1101 or EventID=1102)]] or *[System[((EventID=4656 and band(Keywords,4503599627370496)) or EventID=4663)] and EventData[Data[@Name=\"SubjectUserSid\"]=\"%ls\" and (Data[@Name=\"ObjectName\"]=\"%ls\" or Data[@Name=\"ObjectName\"]=\"%ls\" or Data[@Name=\"ObjectName\"]=\"%ls\" or Data[@Name=\"ObjectName\"]=\"%ls\")]]",userText,command_paths[0],command_paths[1],command_paths[2],command_paths[3])>0,"command-subscription-query");
  command_subscription=EvtSubscribe(NULL,command_event,L"Security",query,NULL,NULL,NULL,EvtSubscribeToFutureEvents|EvtSubscribeStrict);win32_check(command_subscription!=NULL,"command-subscription-create");invariant(swprintf_s(command_pipe,128,L"\\\\.\\pipe\\native.command.%ls",nonce)>0,"command-gate-name");
  PSECURITY_DESCRIPTOR gateSd;win32_check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GRGW;;;WD)",SDDL_REVISION_1,&gateSd,NULL),"command-gate-descriptor");SECURITY_ATTRIBUTES gateSa={sizeof(gateSa),gateSd,FALSE};
  command_gate=CreateNamedPipeW(command_pipe,PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,64,64,10000,&gateSa);DWORD gateError=command_gate==INVALID_HANDLE_VALUE?GetLastError():ERROR_SUCCESS;if(command_gate==INVALID_HANDLE_VALUE)remember("command-gate-create","win32",gateError);LocalFree(gateSd);if(command_gate==INVALID_HANDLE_VALUE)failure(126);
  printf("{\"event\":\"ready\",\"identity\":");identity(GetCurrentProcess());printf(",\"tokenHandle\":\"%llu\",\"gateHandle\":\"%llu\",\"jobHandle\":\"%llu\",\"files\":[",(ULONGLONG)(ULONG_PTR)command_broker_token,(ULONGLONG)(ULONG_PTR)command_files[3],(ULONGLONG)(ULONG_PTR)ownedJob);for(unsigned i=0;i<4;i++){if(i)putchar(',');command_snapshot(i);}printf("],\"cleanup\":{");char systemHash[65];command_sum((BYTE *)command_system,command_category_count*sizeof(*command_system),systemHash);printf("\"systemSha256\":\"%s\",\"nullSha256\":\"%s\",\"nullHandle\":\"%llu\",\"intentHandle\":\"%llu\",\"closedHandle\":\"%llu\",\"files\":[",systemHash,command_null_hash,(ULONGLONG)(ULONG_PTR)command_null,(ULONGLONG)(ULONG_PTR)command_audit_intent,(ULONGLONG)(ULONG_PTR)command_closed);
  for(unsigned i=0;i<6;i++){HANDLE h=i<4?command_files[i]:command_parents[i-4];PSECURITY_DESCRIPTOR baseline=i<4?command_baseline[i]:command_parent_baseline[i-4];char id[50];fileid(h,id);if(i)putchar(',');printf("{\"handle\":\"%llu\",\"identity\":\"%s\",\"baselineHex\":\"",(ULONGLONG)(ULONG_PTR)h,id);hex(baseline,GetSecurityDescriptorLength(baseline));printf("\",\"saclHex\":\"");if(i<4)hex(command_sacls[i],command_sacls[i]->AclSize);printf("\"}");}puts("]}}");
  PROCESS_INFORMATION server={0}; char line[131100];HANDLE input=GetStdHandle(STD_INPUT_HANDLE);unsigned size=0;
  for(;;){command_bound();command_capture();command_pump(&command_output,command_control?"probe-output":"rpc");command_pump(&command_error,command_control?"probe-stderr":"stderr");DWORD available;
    need(PeekNamedPipe(input,NULL,0,NULL,&available,NULL));if(!available){Sleep(1);continue;}char c;DWORD count;need(ReadFile(input,&c,1,&count,NULL)&&count==1&&size+1<sizeof(line));if(c!='\n'){line[size++]=c;continue;}line[size]=0;size=0;
    WCHAR arguments[16384],cwd[4096];
    if(!strcmp(line,"I")){command_audit_install();puts("{\"event\":\"I\"}");}
    else if(!strcmp(line,"P")){need(WaitForSingleObject(command_audit_intent,0)==WAIT_OBJECT_0&&!command_coverage_admitted);command_coverage_control();}
    else if(!strcmp(line,"M")){need(command_coverage_seen&&!command_coverage_admitted);command_coverage_admitted=TRUE;puts("{\"event\":\"M\"}");}
    else if(!strcmp(line,"V")||!strcmp(line,"G")){need(command_coverage_admitted);name(cwd,L"schema-home");need(SetEnvironmentVariableW(L"CODEX_HOME",cwd)&&SetEnvironmentVariableW(L"HOME",cwd)&&SetEnvironmentVariableW(L"USERPROFILE",cwd)&&SetEnvironmentVariableW(L"TEMP",cwd)&&SetEnvironmentVariableW(L"TMP",cwd));name(cwd,L"schema");if(line[0]=='V')need(swprintf_s(arguments,16384,L"\"%ls\" --version",command_image)>0);else need(swprintf_s(arguments,16384,L"\"%ls\" app-server generate-json-schema --out \"%ls\"",command_image,cwd)>0);command_probe_output(command_spawn(arguments,root),line);}
    else if(!strcmp(line,"A")){need(command_coverage_admitted);name(cwd,L"home");need(SetEnvironmentVariableW(L"CODEX_HOME",cwd)&&SetEnvironmentVariableW(L"HOME",cwd)&&SetEnvironmentVariableW(L"USERPROFILE",cwd)&&SetEnvironmentVariableW(L"TEMP",cwd)&&SetEnvironmentVariableW(L"TMP",cwd));name(cwd,L"workspace");need(swprintf_s(arguments,16384,L"\"%ls\" -c windows.sandbox=\"\\\"unelevated\\\"\" -c web_search=\"\\\"disabled\\\"\" -c mcp_servers={} -c plugins={} -c notify=[] -c cli_auth_credentials_store=\"\\\"ephemeral\\\"\" -c features.apps=false -c features.hooks=false -c features.plugins=false -c features.skip_host_skill_discovery=true -c suppress_unstable_features_warning=true -c approval_policy=\"\\\"never\\\"\" app-server --listen stdio://",command_image)>0);server=command_spawn(arguments,cwd);command_server=server.hProcess;command_image_read(server.hProcess,command_image_hash,TRUE);printf("{\"event\":\"A\",\"identity\":");identity(server.hProcess);printf(",\"token\":");command_token(server.hProcess);printf(",\"imageSha256\":\"%s\",\"creationJob\":true}\n",command_image_hash);}
    else if(!strcmp(line,"R")){need(server.hProcess&&ResumeThread(server.hThread)==1);command_server_released=TRUE;puts("{\"event\":\"R\"}");}
    else if(!strncmp(line,"J ",2)){need(command_input&&!command_closing);size_t n=strlen(line+2);need(n>0&&n<=131072&&!(n%2));BYTE *bytes=malloc(n/2);need(bytes);for(size_t i=0;i<n/2;i++)bytes[i]=(BYTE)(nibble(line[2+2*i])*16+nibble(line[3+2*i]));need(WriteFile(command_input,bytes,(DWORD)(n/2),&count,NULL)&&count==n/2);free(bytes);}
    else if(!strcmp(line,"E")){need(command_input&&CloseHandle(command_input));command_input=NULL;puts("{\"event\":\"E\"}");}
    else if(!strcmp(line,"B"))command_barrier();
    else if(!strncmp(line,"K ",2)){need(!command_client&&strlen(line)==3&&line[2]>='0'&&line[2]<='2');command_action=(unsigned)(line[2]-'0');if(command_action<2)command_reset(command_action);puts("{\"event\":\"K\"}");}
    else if(!strcmp(line,"N"))command_case_observe(FALSE);
    else if(!strcmp(line,"T")){need(command_client&&WriteFile(command_gate,"R",1,&count,NULL)&&count==1);puts("{\"event\":\"T\"}");}
    else if(!strcmp(line,"F"))command_case_observe(TRUE);
    else if(!strcmp(line,"U")){need(command_client&&WriteFile(command_gate,"F",1,&count,NULL)&&count==1&&FlushFileBuffers(command_gate)&&DisconnectNamedPipe(command_gate)&&CloseHandle(command_client));command_client=NULL;
      DWORD controlCode=0;if(command_control){HANDLE child=command_processes[command_count-1];need(WaitForSingleObject(child,10000)==WAIT_OBJECT_0&&GetExitCodeProcess(child,&controlCode));command_pump(&command_output,"probe-output");if(command_input)need(CloseHandle(command_input));if(command_output)need(CloseHandle(command_output));if(command_error)need(CloseHandle(command_error));command_input=command_saved_input;command_output=command_saved_output;command_error=command_saved_error;command_control=FALSE;}printf("{\"event\":\"U\",\"exitCode\":%lu}\n",controlCode);}
    else if(!strcmp(line,"C")){need(command_coverage_admitted);command_control=TRUE;command_saved_input=command_input;command_saved_output=command_output;command_saved_error=command_error;command_input=command_output=command_error=NULL;command_action=2;need(swprintf_s(arguments,16384,L"\"%ls\" command-case \"%ls\" \"%ls\" outside %ls \"%ls\" %lu",command_helper,command_pipe,command_paths[2],nonce,command_paths[3],GetCurrentProcessId())>0);PROCESS_INFORMATION control=command_spawn(arguments,root);need(ResumeThread(control.hThread)==1);puts("{\"event\":\"C\"}");}
    else if(!strcmp(line,"X")){command_reset(2);puts("{\"event\":\"X\"}");}
    else if(!strcmp(line,"D"))command_retire_domain();
    else if(!strcmp(line,"S")){need(command_closing&&!command_members(ownedJob));command_capture();if(command_coverage_admitted){need(command_records>0);
      DWORD bookmarkLength=0,properties;EvtRender(NULL,command_bookmark,EvtRenderBookmark,0,NULL,&bookmarkLength,&properties);need(GetLastError()==ERROR_INSUFFICIENT_BUFFER&&bookmarkLength>=4&&bookmarkLength<=65536&&!(bookmarkLength%2));BYTE *bookmark=calloc(1,bookmarkLength);need(bookmark&&EvtRender(NULL,command_bookmark,EvtRenderBookmark,bookmarkLength,bookmark,&bookmarkLength,&properties));char *encoded=malloc((size_t)bookmarkLength*2+1);need(encoded);for(DWORD i=0;i<bookmarkLength;i++)snprintf(encoded+2*i,3,"%02x",bookmark[i]);printf("{\"event\":\"capture-end\",\"records\":%u,\"bytes\":%u,\"hex\":\"%s\",\"decoded\":",command_records,command_bytes,encoded);xml_decode(encoded);puts("}");free(encoded);free(bookmark);
      }need(EvtClose(command_subscription)&&EvtClose(command_bookmark)&&CloseHandle(command_event));if(command_gate)need(CloseHandle(command_gate));
      for(unsigned i=0;i<6;i++)need(CloseHandle(i<4?command_files[i]:command_parents[i-4]));for(unsigned i=0;i<command_count;i++)need(CloseHandle(command_processes[i])&&CloseHandle(command_threads[i]));
      if(command_output)need(CloseHandle(command_output));if(command_error)need(CloseHandle(command_error));need(CloseHandle(command_helper_file)&&CloseHandle(command_image_file)&&CloseHandle(command_build_parent)&&CloseHandle(command_null)&&CloseHandle(command_broker_token));if(!command_broker_events_close())failure(126);need(close_job(FALSE));puts("{\"event\":\"S\",\"captureRetired\":true}");CoUninitialize();return 0;
    }else need(0);
  }
}
