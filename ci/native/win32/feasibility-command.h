/* Finite current-account experiment. No AppContainer wrapper, System custody,
 * release review, system audit-policy setter, installer, or full factory. */
#include <winevt.h>
#include <ntsecapi.h>
#include <xmllite.h>
#include <objbase.h>
#include <wctype.h>
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "xmllite.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
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
static void command_bound(void) { need(GetTickCount64()-(command_closing?command_cleanup_started:command_started) < (command_closing?30000:120000)); }
static DWORD WINAPI command_expire(void *unused) { (void)unused; ULONGLONG end=GetTickCount64()+command_lifetime;DWORD result=WaitForSingleObject(command_cleanup_timer,command_lifetime);need(result==WAIT_TIMEOUT||result==WAIT_OBJECT_0);if(result==WAIT_OBJECT_0){ULONGLONG now=GetTickCount64();Sleep((DWORD)(now>=end?0:(end-now<30000?end-now:30000)));}close_job(TRUE);ExitProcess(124);return 0; }
static void command_cleanup_begin(void) { command_closing=TRUE;if(!command_cleanup_started){command_cleanup_started=GetTickCount64();need(SetEvent(command_cleanup_timer));} }
static void command_unavailable(BOOL value) { if (!value) ExitProcess(78); }
static void command_interface(BOOL value) {
  DWORD error=GetLastError();if(!value&&(error==ERROR_NOT_SUPPORTED||error==ERROR_CALL_NOT_IMPLEMENTED||error==ERROR_PRIVILEGE_NOT_HELD))ExitProcess(78);need(value);
}
static PSECURITY_DESCRIPTOR command_sd(HANDLE h, SE_OBJECT_TYPE kind, SECURITY_INFORMATION mask) {
  PSECURITY_DESCRIPTOR sd;DWORD error=GetSecurityInfo(h,kind,mask,NULL,NULL,NULL,NULL,&sd);SetLastError(error);command_interface(error==ERROR_SUCCESS);return sd;
}
static void command_sum(const BYTE *bytes, DWORD length, char hash[65]) {
  BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h; BYTE result[32];
  need(!BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,NULL,0) && !BCryptCreateHash(a,&h,NULL,0,NULL,0,0) &&
    !BCryptHashData(h,(BYTE *)bytes,length,0) && !BCryptFinishHash(h,result,32,0));
  for(unsigned i=0;i<32;i++) snprintf(hash+2*i,3,"%02x",result[i]); need(!BCryptDestroyHash(h)&&!BCryptCloseAlgorithmProvider(a,0));
}
static DWORD command_integrity(HANDLE token) {
  TOKEN_MANDATORY_LABEL *v=info(token,TokenIntegrityLevel); PSID sid=v->Label.Sid; need(IsValidSid(sid));
  DWORD value=*GetSidSubAuthority(sid,*GetSidSubAuthorityCount(sid)-1); free(v); return value;
}
static void command_privilege(const WCHAR *name) {
  HANDLE token; TOKEN_PRIVILEGES p={0}; need(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token));
  command_unavailable(LookupPrivilegeValueW(NULL,name,&p.Privileges[0].Luid)); p.PrivilegeCount=1; p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
  SetLastError(ERROR_SUCCESS); command_unavailable(AdjustTokenPrivileges(token,FALSE,&p,0,NULL,NULL) && GetLastError()==ERROR_SUCCESS); need(CloseHandle(token));
}
static void command_protect(HANDLE h) {
  WCHAR text[512]; need(swprintf_s(text,512,L"O:%lsD:P(A;;GA;;;%ls)S:(ML;;NWNR;;;HI)",userText,userText)>0);
  PSECURITY_DESCRIPTOR sd; need(ConvertStringSecurityDescriptorToSecurityDescriptorW(text,SDDL_REVISION_1,&sd,NULL));
  PACL dacl,sacl; BOOL present,def; need(GetSecurityDescriptorDacl(sd,&present,&dacl,&def) && present && GetSecurityDescriptorSacl(sd,&present,&sacl,&def) && present);
  need(SetSecurityInfo(h,SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION,NULL,NULL,dacl,sacl)==ERROR_SUCCESS); LocalFree(sd);
}
static BOOL command_principal_exists(void) {
  PAUDIT_SID_ARRAY array; need(AuditEnumeratePerUserPolicy(&array) && array->UsersCount<=4096); BOOL found=FALSE;
  for(unsigned i=0;i<array->UsersCount;i++) if(EqualSid(userSid,array->UserSidArray[i])) found=TRUE; AuditFree(array); return found;
}
static void command_policy_equal(void) {
  AUDIT_POLICY_INFORMATION *current; need(AuditQuerySystemPolicy(command_categories,command_category_count,&current));
  need(!memcmp(current,command_system,command_category_count*sizeof(*current))); AuditFree(current);
}
static HANDLE command_medium_token(void) {
  HANDLE token, medium; need(OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY,&token) &&
    CreateRestrictedToken(token,DISABLE_MAX_PRIVILEGE|LUA_TOKEN,0,NULL,0,NULL,0,NULL,&medium) && CloseHandle(token));
  PSID sid;need(ConvertStringSidToSidW(L"S-1-16-8192",&sid));TOKEN_MANDATORY_LABEL label={0};label.Label.Sid=sid;label.Label.Attributes=SE_GROUP_INTEGRITY;
  need(SetTokenInformation(medium,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(sid)));LocalFree(sid);return medium;
}
static void command_preflight(BOOL emit) {
  principal(); command_unavailable(!wcsncmp(userText,L"S-1-5-21-",9)); HANDLE token; need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));
  command_unavailable(command_integrity(token)>=SECURITY_MANDATORY_HIGH_RID); need(CloseHandle(token));
  command_privilege(SE_SECURITY_NAME); command_privilege(SE_INCREASE_QUOTA_NAME);
  command_unavailable(!command_principal_exists());
  HANDLE medium=command_medium_token(); need(ImpersonateLoggedOnUser(medium));
  SetLastError(ERROR_SUCCESS); HANDLE mutableNull=CreateFileW(L"\\\\.\\NUL",READ_CONTROL|WRITE_DAC,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL); DWORD nullError=GetLastError();
  need(RevertToSelf()&&CloseHandle(medium)); if(mutableNull!=INVALID_HANDLE_VALUE)CloseHandle(mutableNull);
  command_unavailable(mutableNull==INVALID_HANDLE_VALUE && nullError==ERROR_ACCESS_DENIED);
  command_null=CreateFileW(L"\\\\.\\NUL",READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);command_unavailable(command_null!=INVALID_HANDLE_VALUE);
  PSECURITY_DESCRIPTOR nullSd=command_sd(command_null,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION); command_sum(nullSd,GetSecurityDescriptorLength(nullSd),command_null_hash);LocalFree(nullSd);
  command_unavailable(AuditEnumerateSubCategories(NULL,TRUE,&command_categories,&command_category_count)); need(command_category_count && command_category_count<=128);
  BOOL category=FALSE; for(ULONG i=0;i<command_category_count;i++) if(IsEqualGUID(&command_categories[i],&command_category)) category=TRUE; command_unavailable(category);
  command_unavailable(AuditQuerySystemPolicy(command_categories,command_category_count,&command_system));
  /* System bits are preservation evidence. Inclusion can add success auditing;
   * the held broker token and native delivery establish effective coverage. */
  EVT_HANDLE metadata=EvtOpenPublisherMetadata(NULL,L"Microsoft-Windows-Security-Auditing",NULL,0,0); command_unavailable(metadata!=NULL);
  EVT_HANDLE enumerator=EvtOpenEventMetadataEnum(metadata,0); command_unavailable(enumerator!=NULL);
  HANDLE event=CreateEventW(NULL,FALSE,FALSE,NULL);command_unavailable(event!=NULL);EVT_HANDLE subscription=EvtSubscribe(NULL,event,L"Security",L"*[System[EventID=1101 or EventID=1102]]",NULL,NULL,NULL,EvtSubscribeToFutureEvents|EvtSubscribeStrict);command_unavailable(subscription!=NULL);need(EvtClose(subscription)&&CloseHandle(event));
  DWORD ids[5]={4656,4663,5152,5156,5157}, versions[5][4]={0}, used[5]={0}; unsigned total=0;
  for(;;) { EVT_HANDLE event=EvtNextEventMetadata(enumerator,0); if(!event){need(GetLastError()==ERROR_NO_MORE_ITEMS);break;}
    EVT_VARIANT id,version; DWORD size; need(++total<=4096 && EvtGetEventMetadataProperty(event,EventMetadataEventID,0,sizeof(id),&id,&size) &&
      id.Type==EvtVarTypeUInt32 && EvtGetEventMetadataProperty(event,EventMetadataEventVersion,0,sizeof(version),&version,&size) && version.Type==EvtVarTypeUInt32);
    for(unsigned i=0;i<5;i++) if(ids[i]==id.UInt32Val){need(used[i]<4 && version.UInt32Val<=255);versions[i][used[i]++]=version.UInt32Val;} need(EvtClose(event)); }
  need(EvtClose(enumerator)&&EvtClose(metadata)); if (!emit) return; printf("{\"versions\":[");
  for(unsigned i=0;i<5;i++){command_unavailable(used[i]>0);printf("%s{\"id\":%lu,\"versions\":[",i?",":"",ids[i]);for(unsigned j=0;j<used[i];j++)printf("%s%lu",j?",":"",versions[i][j]);printf("]}");}
  printf("],\"admission\":true,\"auditInterface\":true,\"completeRetirement\":true}\n");
}
static void command_snapshot_handle(HANDLE file, const char *expected) {
  char id[50],hash[65],dacl[65]; fileid(file,id); need(!strcmp(id,expected)); hashfile(file,hash);
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
  PSECURITY_DESCRIPTOR sd;PACL sacl;BOOL present,def;need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;ME)",SDDL_REVISION_1,&sd,NULL)&&GetSecurityDescriptorSacl(sd,&present,&sacl,&def)&&present&&SetSecurityInfo(h,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,sacl)==ERROR_SUCCESS);LocalFree(sd);
}
static void command_files_prepare(void) {
  const WCHAR *dirs[]={L"",L"workspace",L"home",L"schema-home",L"schema",L"build"};WCHAR owned[4096];
  for(unsigned i=0;i<6;i++){if(i)name(owned,dirs[i]);else wcscpy_s(owned,4096,root);protect(owned,FALSE,TRUE);if(i!=5){HANDLE h=file(owned,WRITE_OWNER);command_fixture_label(h);need(CloseHandle(h));}}
  name(command_paths[0],L"workspace\\inspection"); name(command_paths[1],L"workspace\\edit"); name(command_paths[2],L"outside"); name(command_paths[3],L"workspace\\gate");
  WCHAR parent[4096]; name(parent,L"workspace"); const WCHAR *parents[2]={root,parent};
  for(unsigned i=0;i<2;i++){ command_parents[i]=CreateFileW(parents[i],GENERIC_READ|READ_CONTROL|WRITE_DAC|ACCESS_SYSTEM_SECURITY,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);need(command_parents[i]!=INVALID_HANDLE_VALUE);FILE_ATTRIBUTE_TAG_INFO tag;need(GetFileInformationByHandleEx(command_parents[i],FileAttributeTagInfo,&tag,sizeof(tag)) && !(tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)); command_parent_baseline[i]=command_sd(command_parents[i],SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION);need(GetSecurityDescriptorLength(command_parent_baseline[i])<=8192); }
  for(unsigned i=0;i<4;i++) {
    command_files[i]=CreateFileW(command_paths[i],GENERIC_READ|GENERIC_WRITE|READ_CONTROL|WRITE_DAC|ACCESS_SYSTEM_SECURITY|DELETE|WRITE_OWNER,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL); need(command_files[i]!=INVALID_HANDLE_VALUE);command_fixture_label(command_files[i]);
    FILE_ATTRIBUTE_TAG_INFO tag; need(GetFileInformationByHandleEx(command_files[i],FileAttributeTagInfo,&tag,sizeof(tag)) && !(tag.FileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)));
    /* Stock workspace grants inherit onto editable files. The read-only audit
     * gate keeps its original DACL; it needs no write-capability grant. */
    PSECURITY_DESCRIPTOR privateSd=descriptor(FALSE,FALSE);PACL privateAcl;BOOL privatePresent,privateDefault;need(GetSecurityDescriptorDacl(privateSd,&privatePresent,&privateAcl,&privateDefault)&&privatePresent&&SetSecurityInfo(command_files[i],SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|(i==3?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION),NULL,NULL,privateAcl,NULL)==ERROR_SUCCESS);LocalFree(privateSd);
    fileid(command_files[i],command_ids[i]); command_baseline[i]=command_sd(command_files[i],SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION);need(GetSecurityDescriptorLength(command_baseline[i])<=8192);
    PSID owner; BOOL def; need(GetSecurityDescriptorOwner(command_baseline[i],&owner,&def) && EqualSid(owner,userSid));
    PACL old; BOOL present; need(GetSecurityDescriptorSacl(command_baseline[i],&present,&old,&def)); DWORD length=(present&&old?old->AclSize:sizeof(ACL))+sizeof(SYSTEM_AUDIT_ACE)+GetLengthSid(userSid);
    need(length<=16384); command_sacls[i]=LocalAlloc(LPTR,length); need(command_sacls[i] && InitializeAcl(command_sacls[i],length,ACL_REVISION));
    for(unsigned j=0;present&&old&&j<old->AceCount;j++){ACE_HEADER *ace;need(GetAce(old,j,(void **)&ace) && AddAce(command_sacls[i],ACL_REVISION,MAXDWORD,ace,ace->AceSize));}
    need(AddAuditAccessAceEx(command_sacls[i],ACL_REVISION,0,FILE_READ_DATA|FILE_WRITE_DATA,userSid,TRUE,TRUE));
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
static void command_effective(HANDLE token) {
  AUDIT_POLICY_INFORMATION *policy=NULL;BOOL available=AuditComputeEffectivePolicyByToken(token,&command_category,1,&policy),success=FALSE;
  if(available){need(policy&&IsEqualGUID(&policy->AuditSubCategoryGuid,&command_category));success=(policy->AuditingInformation&POLICY_AUDIT_EVENT_SUCCESS)!=0;AuditFree(policy);}
  printf("{\"available\":%s,\"success\":%s}",available?"true":"false",success?"true":"false");
}
static void command_image_read(HANDLE process, const char *expected) {
  WCHAR path[4096]; DWORD length=4096; need(QueryFullProcessImageNameW(process,0,path,&length)); HANDLE h=file(path,GENERIC_READ); char hash[65]; hashfile(h,hash); need(!strcmp(hash,expected)&&CloseHandle(h));
}
static void command_limits(HANDLE job) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION value; need(QueryInformationJobObject(job,JobObjectExtendedLimitInformation,&value,sizeof(value),NULL) &&
    value.BasicLimitInformation.LimitFlags==(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS) && value.BasicLimitInformation.ActiveProcessLimit==32);
}
static DWORD command_members(HANDLE job) {
  BYTE bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)+32*sizeof(ULONG_PTR)]; JOBOBJECT_BASIC_PROCESS_ID_LIST *list=(void *)bytes; DWORD used;
  need(QueryInformationJobObject(job,JobObjectBasicProcessIdList,list,sizeof(bytes),&used) && list->NumberOfAssignedProcesses==list->NumberOfProcessIdsInList && list->NumberOfProcessIdsInList<=32);
  for(DWORD i=0;i<list->NumberOfProcessIdsInList;i++){need(list->ProcessIdList[i]<=MAXDWORD);HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,(DWORD)list->ProcessIdList[i]);BOOL member;
    need(h && IsProcessInJob(h,job,&member)&&member&&CloseHandle(h));} return list->NumberOfProcessIdsInList;
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
  need(command_count<16&&!command_closing); HANDLE readIn,writeOut,writeErr; SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
  need(CreatePipe(&readIn,&command_input,&sa,0)&&CreatePipe(&command_output,&writeOut,&sa,0)&&CreatePipe(&command_error,&writeErr,&sa,0));
  need(SetHandleInformation(command_input,HANDLE_FLAG_INHERIT,0)&&SetHandleInformation(command_output,HANDLE_FLAG_INHERIT,0)&&SetHandleInformation(command_error,HANDLE_FLAG_INHERIT,0));
  HANDLE medium=command_medium_token();
  SIZE_T size=0;InitializeProcThreadAttributeList(NULL,2,0,&size);LPPROC_THREAD_ATTRIBUTE_LIST attrs=malloc(size);need(attrs&&InitializeProcThreadAttributeList(attrs,2,0,&size));
  HANDLE inherit[3]={readIn,writeOut,writeErr};command_interface(UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,&ownedJob,sizeof(ownedJob),NULL,NULL));command_interface(UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherit,sizeof(inherit),NULL,NULL));
  STARTUPINFOEXW si={0};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=readIn;si.StartupInfo.hStdOutput=writeOut;si.StartupInfo.hStdError=writeErr;si.lpAttributeList=attrs;
  WCHAR line[16384]; need(wcslen(arguments)<16380);wcscpy_s(line,16384,arguments); LPWCH environment=GetEnvironmentStringsW(); need(environment);
  PROCESS_INFORMATION p={0};BOOL created=CreateProcessAsUserW(medium,NULL,line,NULL,NULL,TRUE,CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT,environment,cwd,&si.StartupInfo,&p);
  DWORD error=GetLastError();FreeEnvironmentStringsW(environment);DeleteProcThreadAttributeList(attrs);free(attrs);need(CloseHandle(medium)&&CloseHandle(readIn)&&CloseHandle(writeOut)&&CloseHandle(writeErr));SetLastError(error);if(!created&&(error==ERROR_NOT_SUPPORTED||error==ERROR_CALL_NOT_IMPLEMENTED||error==ERROR_PRIVILEGE_NOT_HELD))ExitProcess(78);need(created);
  BOOL member;need(IsProcessInJob(p.hProcess,ownedJob,&member)&&member);command_processes[command_count]=p.hProcess;command_threads[command_count++]=p.hThread;return p;
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
  if(!after){DWORD pid;need(GetNamedPipeClientProcessId(command_gate,&pid));command_case_pid=pid;command_target_seen=command_marker_seen=FALSE;command_client=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);need(command_client);BOOL member;need(IsProcessInJob(command_client,ownedJob,&member)&&member);command_image_read(command_client,command_helper_hash);}
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
  need(argc==8);HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_DUP_HANDLE|SYNCHRONIZE,FALSE,(DWORD)number(argv[2]));need(owner&&creation(owner)==number(argv[3])&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT);
  HANDLE job;need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)number(argv[4]),GetCurrentProcess(),&job,JOB_OBJECT_QUERY,FALSE,0));command_limits(job);
  HANDLE child=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,(DWORD)number(argv[5]));BOOL member;need(child&&creation(child)==number(argv[6])&&WaitForSingleObject(child,0)==WAIT_TIMEOUT&&IsProcessInJob(child,job,&member)&&member);
  char expected[65];need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[7],-1,expected,65,NULL,NULL)==65);command_image_read(child,expected);
  printf("{\"identity\":");identity(child);printf(",\"token\":");command_token(child);puts(",\"creationJob\":true}");need(CloseHandle(child)&&CloseHandle(job)&&CloseHandle(owner));
}
static void command_broker_check(int argc,WCHAR **argv) {
  need(argc==8);HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_DUP_HANDLE|SYNCHRONIZE,FALSE,(DWORD)number(argv[2]));need(owner&&creation(owner)==number(argv[3])&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT);
  char expected[65];need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[4],-1,expected,65,NULL,NULL)==65);command_image_read(owner,expected);
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
  char expected[65];need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[4],-1,expected,65,NULL,NULL)==65);command_image_read(owner,expected);
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
  need(command_owned_policy(authorized==WAIT_OBJECT_0)==policyPresent);if(policyPresent)need(AuditDeletePerUserPolicy(userSid));need(!command_principal_exists());command_policy_equal();
  for(unsigned i=0;i<4;i++){FILE_DISPOSITION_INFO deletion={TRUE};need(SetFileInformationByHandle(files[i],FileDispositionInfo,&deletion,sizeof(deletion))&&CloseHandle(files[i]));}for(unsigned i=4;i<6;i++)need(CloseHandle(files[i]));
  sd=command_sd(null,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION);command_sum(sd,GetSecurityDescriptorLength(sd),actual);need(!strcmp(actual,nullHash));LocalFree(sd);need(CloseHandle(null)&&CloseHandle(intent)&&CloseHandle(closed)&&CloseHandle(owner));
  puts("{\"retired\":true,\"completeDomain\":true,\"restored\":true,\"fixturesRemoved\":true}");
}
static void command_watch(int argc,WCHAR **argv) {
  need(argc==6||argc==7);DWORD pid=(DWORD)number(argv[2]);HANDLE owner=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_DUP_HANDLE|SYNCHRONIZE,FALSE,pid);need(owner&&creation(owner)==number(argv[3])&&WaitForSingleObject(owner,0)==WAIT_TIMEOUT);char hash[65];need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[4],-1,hash,65,NULL,NULL)==65);command_image_read(owner,hash);
  HANDLE job=NULL; if(argc==7){need(DuplicateHandle(owner,(HANDLE)(ULONG_PTR)number(argv[6]),GetCurrentProcess(),&job,JOB_OBJECT_QUERY,FALSE,0));command_limits(job);}
  printf("{\"ready\":true,\"identity\":");identity(GetCurrentProcess());puts("}");ack('R');command_cleanup_begin();
  need(WaitForSingleObject(owner,25000)==WAIT_OBJECT_0);DWORD code;need(GetExitCodeProcess(owner,&code)&&code!=STILL_ACTIVE);if(job){need(!command_members(job)&&CloseHandle(job));}
  need(CloseHandle(owner));printf("{\"retired\":true,\"completeDomain\":true,\"exitCode\":%lu}\n",code);
}
static int command_main(int argc,WCHAR **argv) {
  command_started=GetTickCount64(); WCHAR lifetime[16];if(GetEnvironmentVariableW(L"NATIVE_COMMAND_LIFETIME_MS",lifetime,16)){ULONGLONG ms=number(lifetime);need(ms<=150000);command_lifetime=(DWORD)ms;need(SetEnvironmentVariableW(L"NATIVE_COMMAND_LIFETIME_MS",NULL));}
  if(!wcscmp(role,L"command-case")){command_case(argc,argv);return 0;}
  WCHAR ci[8],os[16];need(GetEnvironmentVariableW(L"GITHUB_ACTIONS",ci,8)==4&&!wcscmp(ci,L"true")&&GetEnvironmentVariableW(L"RUNNER_OS",os,16)==7&&!wcscmp(os,L"Windows"));
  command_cleanup_timer=CreateEventW(NULL,TRUE,FALSE,NULL);need(command_cleanup_timer);
  if(!wcscmp(role,L"command-watch")||!wcscmp(role,L"command-check")||!wcscmp(role,L"command-broker-check")||!wcscmp(role,L"command-finish")){principal();command_protect(GetCurrentProcess());HANDLE timer=CreateThread(NULL,0,command_expire,NULL,0,NULL);need(timer&&CloseHandle(timer));if(!wcscmp(role,L"command-check"))command_check(argc,argv);else if(!wcscmp(role,L"command-broker-check"))command_broker_check(argc,argv);else if(!wcscmp(role,L"command-finish"))command_finish(argc,argv);else command_watch(argc,argv);return 0;}
  if(!wcscmp(role,L"command-broker")){HANDLE timer=CreateThread(NULL,0,command_expire,NULL,0,NULL);need(timer&&CloseHandle(timer));}
  need(SUCCEEDED(CoInitializeEx(NULL,COINIT_MULTITHREADED)));command_preflight(!wcscmp(role,L"command-preflight"));if(!wcscmp(role,L"command-preflight")){need(argc==2);CoUninitialize();return 0;}
  need(argc==8&&!wcscmp(role,L"command-broker"));root=argv[2];nonce=argv[3];need(wcslen(nonce)==32&&wcsspn(nonce,L"0123456789abcdef")==32);
  wcscpy_s(command_image,4096,argv[4]);wcscpy_s(command_helper,4096,argv[6]);need(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[5],-1,command_image_hash,65,NULL,NULL)==65&&WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[7],-1,command_helper_hash,65,NULL,NULL)==65);
  WCHAR build[4096];name(build,L"build");command_build_parent=CreateFileW(build,READ_CONTROL|WRITE_OWNER,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);need(command_build_parent!=INVALID_HANDLE_VALUE);
  PSECURITY_DESCRIPTOR labelSd;need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;HI)",SDDL_REVISION_1,&labelSd,NULL));PACL labelAcl;BOOL present,def;need(GetSecurityDescriptorSacl(labelSd,&present,&labelAcl,&def)&&present&&SetSecurityInfo(command_build_parent,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,labelAcl)==ERROR_SUCCESS);
  command_helper_file=CreateFileW(command_helper,GENERIC_READ|READ_CONTROL|WRITE_OWNER,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);need(command_helper_file!=INVALID_HANDLE_VALUE&&SetSecurityInfo(command_helper_file,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,labelAcl)==ERROR_SUCCESS);LocalFree(labelSd);
  command_image_file=CreateFileW(command_image,GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);need(command_image_file!=INVALID_HANDLE_VALUE);char actualHash[65];hashfile(command_helper_file,actualHash);need(!strcmp(actualHash,command_helper_hash));hashfile(command_image_file,actualHash);need(!strcmp(actualHash,command_image_hash));
  command_protect(GetCurrentProcess());ownedJob=CreateJobObjectW(NULL,NULL);need(ownedJob);command_protect(ownedJob);JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;limits.BasicLimitInformation.ActiveProcessLimit=32;
  need(SetInformationJobObject(ownedJob,JobObjectExtendedLimitInformation,&limits,sizeof(limits)));command_limits(ownedJob);BOOL member;need(IsProcessInJob(GetCurrentProcess(),ownedJob,&member)&&!member);
  need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_IMPERSONATE,&command_broker_token));command_audit_intent=CreateEventW(NULL,TRUE,FALSE,NULL);command_closed=CreateEventW(NULL,TRUE,FALSE,NULL);need(command_audit_intent&&command_closed);command_protect(command_audit_intent);command_protect(command_closed);
  command_event=CreateEventW(NULL,FALSE,FALSE,NULL);command_bookmark=EvtCreateBookmark(NULL);need(command_event&&command_bookmark);
  WCHAR admissionLine[8192];need(swprintf_s(admissionLine,8192,L"\"%ls\" command-case",command_helper)>0);PROCESS_INFORMATION admission=command_spawn(admissionLine,root);command_image_read(admission.hProcess,command_helper_hash);need(TerminateProcess(admission.hProcess,0)&&WaitForSingleObject(admission.hProcess,10000)==WAIT_OBJECT_0);if(command_input)need(CloseHandle(command_input));if(command_output)need(CloseHandle(command_output));if(command_error)need(CloseHandle(command_error));command_input=command_output=command_error=NULL;need(!command_members(ownedJob));
  command_files_prepare();WCHAR query[18000];need(swprintf_s(query,18000,L"*[System[(EventID=1101 or EventID=1102)]] or *[System[((EventID=4656 and band(Keywords,4503599627370496)) or EventID=4663)] and EventData[Data[@Name=\"SubjectUserSid\"]=\"%ls\" and (Data[@Name=\"ObjectName\"]=\"%ls\" or Data[@Name=\"ObjectName\"]=\"%ls\" or Data[@Name=\"ObjectName\"]=\"%ls\" or Data[@Name=\"ObjectName\"]=\"%ls\")]]",userText,command_paths[0],command_paths[1],command_paths[2],command_paths[3])>0);
  command_subscription=EvtSubscribe(NULL,command_event,L"Security",query,NULL,NULL,NULL,EvtSubscribeToFutureEvents|EvtSubscribeStrict);need(command_subscription);need(swprintf_s(command_pipe,128,L"\\\\.\\pipe\\native.command.%ls",nonce)>0);
  PSECURITY_DESCRIPTOR gateSd;need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GRGW;;;WD)",SDDL_REVISION_1,&gateSd,NULL));SECURITY_ATTRIBUTES gateSa={sizeof(gateSa),gateSd,FALSE};
  command_gate=CreateNamedPipeW(command_pipe,PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,64,64,10000,&gateSa);LocalFree(gateSd);need(command_gate!=INVALID_HANDLE_VALUE);
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
    else if(!strcmp(line,"A")){need(command_coverage_admitted);name(cwd,L"home");need(SetEnvironmentVariableW(L"CODEX_HOME",cwd)&&SetEnvironmentVariableW(L"HOME",cwd)&&SetEnvironmentVariableW(L"USERPROFILE",cwd)&&SetEnvironmentVariableW(L"TEMP",cwd)&&SetEnvironmentVariableW(L"TMP",cwd));name(cwd,L"workspace");need(swprintf_s(arguments,16384,L"\"%ls\" -c windows.sandbox=\"\\\"unelevated\\\"\" -c web_search=\"\\\"disabled\\\"\" -c mcp_servers={} -c plugins={} -c notify=[] -c cli_auth_credentials_store=\"\\\"ephemeral\\\"\" -c features.apps=false -c features.hooks=false -c features.plugins=false -c features.skip_host_skill_discovery=true -c suppress_unstable_features_warning=true -c approval_policy=\"\\\"never\\\"\" app-server --listen stdio://",command_image)>0);server=command_spawn(arguments,cwd);command_server=server.hProcess;command_image_read(server.hProcess,command_image_hash);printf("{\"event\":\"A\",\"identity\":");identity(server.hProcess);printf(",\"token\":");command_token(server.hProcess);printf(",\"imageSha256\":\"%s\",\"creationJob\":true}\n",command_image_hash);}
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
      if(command_output)need(CloseHandle(command_output));if(command_error)need(CloseHandle(command_error));need(CloseHandle(command_helper_file)&&CloseHandle(command_image_file)&&CloseHandle(command_build_parent)&&CloseHandle(command_null)&&CloseHandle(command_broker_token)&&CloseHandle(command_audit_intent)&&CloseHandle(command_closed)&&close_job(FALSE));puts("{\"event\":\"S\",\"captureRetired\":true}");CoUninitialize();return 0;
    }else need(0);
  }
}
