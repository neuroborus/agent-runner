/* Finite experiment only. Private native pipes; no full observer/review contract. */
#include <bsm/libbsm.h>
#include <bsm/audit_record.h>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <spawn.h>
#include <grp.h>
#if defined(TOKEN_VERSION)
#define COMMAND_BSM_VERSION TOKEN_VERSION
#elif defined(AUDIT_HEADER_VERSION)
#define COMMAND_BSM_VERSION AUDIT_HEADER_VERSION
#else
#error The matching SDK must declare the BSM header version.
#endif

static uid_t command_uid;
static gid_t command_gid;
static const char *command_root, *command_image, *command_image_hash, *command_helper_hash, *command_nonce;
static char command_helper[4096], command_gate[4096], command_policy[4096], command_target[3][4096];
static int command_objects[3], command_audit, command_in = -1, command_out = -1, command_err = -1, command_gate_fd;
static mach_port_t command_rights[16];
static au_asid_t command_sessions[16];
static pid_t command_wrappers[16];
static pid_t command_server_wrapper;
static bool command_server_clean;
static unsigned command_count, command_records, command_bytes, command_barriers;
static uint64_t command_latest_record_time, command_previous_barrier_time;
static struct identity command_case_identity;
static int command_action = -1;
static bool command_attempt_seen, command_attempt_permitted, command_marker_seen;
static bool command_control;
static char command_control_before[512], command_control_after[512];
static char command_control_gate_before[256], command_control_gate_after[256];
static au_asid_t command_case_asid;
static volatile sig_atomic_t command_expired;
static pid_t command_owner;
static bool command_failing, command_prerequisite, command_admissions_closed, command_cleanup_started;
static void command_expire(int value) { (void)value; command_expired = 1; }
static void command_hex(const unsigned char *bytes, size_t size) { for (size_t i=0;i<size;i++) printf("%02x",bytes[i]); }
static void command_path(char *out, const char *leaf) { need(snprintf(out,4096,"%s/%s",command_root,leaf)>0 && strlen(out)<4095); }
static void command_health(void) {
  uint64_t drops=0, truncated=0;
  need(!ioctl(command_audit,AUDITPIPE_GET_DROPS,&drops) && !ioctl(command_audit,AUDITPIPE_GET_TRUNCATES,&truncated) && !drops && !truncated);
}
static unsigned command_members(au_asid_t asid, bool signal_members) {
  pid_t pids[4096]; errno=0; int size=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
  need(!errno && size>0 && size<(int)sizeof(pids) && size%sizeof(pid_t)==0);
  unsigned found=0;
  for (unsigned i=0;i<(unsigned)size/sizeof(pid_t);i++) {
    if (!pids[i]) continue;
    need(pids[i]>0); for(unsigned j=0;j<i;j++) need(pids[i]!=pids[j]);
    struct proc_bsdinfo before, after; auditpinfo_addr_t a={.ap_pid=pids[i]}, b={.ap_pid=pids[i]};
    need(proc_pidinfo(pids[i],PROC_PIDTBSDINFO,1,&before,sizeof(before))==sizeof(before) &&
      !auditon(A_GETPINFO_ADDR,&a,sizeof(a)) && proc_pidinfo(pids[i],PROC_PIDTBSDINFO,1,&after,sizeof(after))==sizeof(after) &&
      !auditon(A_GETPINFO_ADDR,&b,sizeof(b)) && before.pbi_start_tvsec==after.pbi_start_tvsec &&
      before.pbi_start_tvusec==after.pbi_start_tvusec && before.pbi_uid==after.pbi_uid && a.ap_asid==b.ap_asid && a.ap_auid==b.ap_auid);
    if (a.ap_asid==asid) { need(++found<=32); if(after.pbi_status==SZOMB){need(before.pbi_status==SZOMB);continue;}
      struct identity member; need(inspect(pids[i],&member) && member.token.val[6]==(unsigned)asid);
      if(signal_members) signal_identity(member,SIGKILL); }
  }
  return found;
}
/* Even a protocol/capture failure attempts bounded owned settlement. No fatal
 * path emits successful evidence or signals an unbound numeric PID. */
static void command_failure(void) {
  if(command_prerequisite) _exit(78);
  if(command_failing || getpid()!=command_owner || getuid()!=0) return;
  command_failing=true; command_admissions_closed=true;
  if(!command_cleanup_started){command_cleanup_started=true;command_expired=0;alarm(30);}
  if(command_in>=0) {close(command_in);command_in=-1;}
  for(unsigned pass=0;pass<2000 && !command_expired;pass++) {
    bool empty=true;
    for(unsigned i=0;i<command_count;i++) {
      int status;(void)waitpid(command_wrappers[i],&status,WNOHANG);
      if(command_members(command_sessions[i],pass>=100)) empty=false;
    }
    if(empty) break;
    (void)poll(NULL,0,10);
  }
}
static void command_image_identity(struct identity value, const char *path, const char *expected) {
  char actual[4096]; need(live(value) && proc_pidpath((pid_t)value.token.val[5],actual,sizeof(actual))>0 && !strcmp(actual,path));
  int fd=open(actual,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat before,after,named; unsigned char bytes[8192],sum[32];
  need(fd>=0 && !fstat(fd,&before) && S_ISREG(before.st_mode) && before.st_nlink==1 && before.st_uid==command_uid &&
    before.st_size>0 && before.st_size<=134217728 && !(before.st_mode&022));
  CC_SHA256_CTX context; need(CC_SHA256_Init(&context)); ssize_t n; while((n=read(fd,bytes,sizeof(bytes)))>0) need(CC_SHA256_Update(&context,bytes,(CC_LONG)n));
  need(!n && CC_SHA256_Final(sum,&context) && !fstat(fd,&after) && !lstat(actual,&named) &&
    before.st_dev==after.st_dev && before.st_ino==after.st_ino && before.st_size==after.st_size &&
    before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec &&
    named.st_dev==before.st_dev && named.st_ino==before.st_ino && !close(fd) && live(value));
  char hex[65]; for(unsigned i=0;i<32;i++) snprintf(hex+i*2,3,"%02x",sum[i]); need(!strcmp(hex,expected));
}
static void command_object(unsigned index, char *out) {
  struct stat st,named,after; struct statfs fs; int fd=command_objects[index];
  need(!fstat(fd,&st) && !lstat(command_target[index],&named) && st.st_dev==named.st_dev && st.st_ino==named.st_ino &&
    S_ISREG(st.st_mode) && st.st_uid==command_uid && st.st_gid==command_gid && st.st_nlink==1 && (st.st_mode&07777)==0600 && !fstatfs(fd,&fs));
  no_acl(fd); struct attrlist attrs={.bitmapcount=ATTR_BIT_MAP_COUNT,.volattr=ATTR_VOL_INFO|ATTR_VOL_UUID};
  struct {uint32_t size; unsigned char uuid[16];} volume; need(!fgetattrlist(fd,&attrs,&volume,sizeof(volume),0) && volume.size==sizeof(volume));
  char uuid[33]; for(unsigned i=0;i<16;i++) snprintf(uuid+i*2,3,"%02x",volume.uuid[i]);
  unsigned char bytes[65537],sum[32]; ssize_t n=pread(fd,bytes,sizeof(bytes),0); need(n==st.st_size && n>=0 && n<=65536 && CC_SHA256(bytes,(CC_LONG)n,sum));
  need(!fstat(fd,&after) && !lstat(command_target[index],&named) && after.st_dev==st.st_dev && after.st_ino==st.st_ino &&
    after.st_size==st.st_size && after.st_mode==st.st_mode && after.st_uid==st.st_uid && after.st_gid==st.st_gid && after.st_nlink==1 &&
    after.st_mtimespec.tv_sec==st.st_mtimespec.tv_sec && after.st_mtimespec.tv_nsec==st.st_mtimespec.tv_nsec &&
    named.st_dev==st.st_dev && named.st_ino==st.st_ino && named.st_birthtimespec.tv_sec==st.st_birthtimespec.tv_sec && named.st_birthtimespec.tv_nsec==st.st_birthtimespec.tv_nsec);
  no_acl(fd); char hex[65],text[512];for(unsigned i=0;i<32;i++)snprintf(hex+i*2,3,"%02x",sum[i]);
  need(snprintf(text,sizeof(text),"{\"identity\":\"%u:%u:%u:%" PRIu64 ":%lld:%ld:%u:%u:%o:%s\",\"sha256\":\"%s\"}",(unsigned)st.st_dev,(unsigned)fs.f_fsid.val[0],
    (unsigned)fs.f_fsid.val[1],st.st_ino,(long long)st.st_birthtimespec.tv_sec,st.st_birthtimespec.tv_nsec,st.st_uid,st.st_gid,st.st_mode,uuid,hex)<(int)sizeof(text));
  if(out)strcpy(out,text);else fputs(text,stdout);
}
static void command_gate_object(char *out) {
  struct stat held,named;need(!fstat(command_gate_fd,&held)&&!lstat(command_gate,&named)&&S_ISFIFO(held.st_mode)&&
    held.st_dev==named.st_dev&&held.st_ino==named.st_ino&&held.st_birthtimespec.tv_sec==named.st_birthtimespec.tv_sec&&held.st_birthtimespec.tv_nsec==named.st_birthtimespec.tv_nsec&&
    held.st_uid==command_uid&&held.st_gid==command_gid&&held.st_nlink==1&&(held.st_mode&07777)==0600);no_acl(command_gate_fd);
  char text[256];need(snprintf(text,sizeof(text),"{\"device\":\"%u\",\"inode\":\"%llu\",\"uid\":%u,\"gid\":%u,\"mode\":%u}",(unsigned)held.st_dev,
    (unsigned long long)held.st_ino,held.st_uid,held.st_gid,held.st_mode&07777)<(int)sizeof(text));if(out)strcpy(out,text);else fputs(text,stdout);
}
static unsigned command_classes(void) {
  unsigned classes=0; const char *names[]={"fr","fw","fc","pc"};
  for(unsigned i=0;i<4;i++){ au_class_ent_t *entry=getauclassnam(names[i]); need(entry && entry->ac_class); classes|=entry->ac_class; }
  need(classes && classes<UINT32_MAX); return classes;
}
static void command_mapping(unsigned classes) {
  printf("\"events\":["); unsigned count=0,paths=0; setauevent(); au_event_ent_t *entry;
  while((entry=getauevent())) if(entry->ae_class&classes) {
    need(++count<=256 && entry->ae_name && strlen(entry->ae_name)<64 && strspn(entry->ae_name,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")==strlen(entry->ae_name));
    if(!strncmp(entry->ae_name,"AUE_OPEN",8))paths++;
    printf("%s{\"event\":%u,\"opcode\":\"%s\",\"classes\":%u,\"selector\":\"%s\"}",count>1?",":"",entry->ae_number,entry->ae_name,
      entry->ae_class,!strncmp(entry->ae_name,"AUE_OPEN",8)?"path":"none");
  }
  endauevent(); need(count && paths); printf("],\"headerVersion\":%u",COMMAND_BSM_VERSION);
}
static int command_pipe(unsigned classes, uid_t uid, bool select) {
  int fd=open("/dev/auditpipe",O_RDONLY|O_NONBLOCK|O_CLOEXEC); if(fd<0 && (errno==EACCES || errno==ENOENT || errno==ENOTSUP)) _exit(78); need(fd>=0);
  unsigned low,high,size,queue=1024; int mode=AUDITPIPE_PRESELECT_MODE_LOCAL; au_mask_t empty={0,0};
  need(!ioctl(fd,AUDITPIPE_GET_QLIMIT_MIN,&low) && !ioctl(fd,AUDITPIPE_GET_QLIMIT_MAX,&high) && queue>=low && queue<=high &&
    !ioctl(fd,AUDITPIPE_GET_MAXAUDITDATA,&size) && size>0 && size<=65536 && !ioctl(fd,AUDITPIPE_SET_QLIMIT,&queue) &&
    !ioctl(fd,AUDITPIPE_SET_PRESELECT_MODE,&mode) && !ioctl(fd,AUDITPIPE_SET_PRESELECT_FLAGS,&empty) && !ioctl(fd,AUDITPIPE_SET_PRESELECT_NAFLAGS,&empty));
  if(select){struct auditpipe_ioctl_preselect choice={0}; choice.aip_auid=uid; choice.aip_mask.am_success=choice.aip_mask.am_failure=classes;
    need(!ioctl(fd,AUDITPIPE_SET_PRESELECT_AUID,&choice));}
  need(!ioctl(fd,AUDITPIPE_FLUSH)); return fd;
}
/* Same matched libbsm token boundaries as effective-reader.h, on this separate
 * experiment pipe. Protected reviews and custody are never substituted here. */
static uint32_t command_u32(const unsigned char *p){uint32_t n;memcpy(&n,p,4);return ntohl(n);}
static uint64_t command_u64(const unsigned char *p){return ((uint64_t)command_u32(p)<<32)|command_u32(p+4);}
static void command_record(unsigned char *bytes, size_t size) {
  need(AUT_ATTR32==0x3e && AUT_ATTR64==0x73 && AUT_PATH==0x23);
  printf("{\"event\":\"audit\",\"hex\":\""); command_hex(bytes,size); printf("\",\"tokens\":{\"tokens\":[");
  unsigned count=0,headers=0,subjects=0,returns=0,trailers=0; size_t offset=0; pid_t subject=0; bool target=false,marker=false; int error=-1;
  while(offset<size){ tokenstr_t token={0}; need(++count<=256 && !au_fetch_tok(&token,bytes+offset,(int)(size-offset)) && token.len>0 && (size_t)token.len<=size-offset);
    const unsigned char *raw=bytes+offset;
    if(token.id==AUT_HEADER32 || token.id==AUT_HEADER64 || token.id==AUT_HEADER32_EX || token.id==AUT_HEADER64_EX){
      bool wide=token.id==AUT_HEADER64 || token.id==AUT_HEADER64_EX; size_t times=wide?16:8;
      need(!offset && ++headers==1 && (size_t)token.len>=10+times && command_u32(raw+1)==size);
      uint16_t id; memcpy(&id,raw+6,2); au_event_ent_t *e=getauevnum(ntohs(id)); need(e && e->ae_name && e->ae_class);
      const unsigned char *time=raw+token.len-times; uint64_t seconds=wide?command_u64(time):command_u32(time),milliseconds=wide?command_u64(time+8):command_u32(time+4);
      need(seconds<=UINT32_MAX && milliseconds<1000);
      uint64_t stamp=seconds*1000+milliseconds;if(stamp>command_latest_record_time)command_latest_record_time=stamp;
      printf("{\"kind\":\"header\",\"version\":%u,\"event\":%u,\"name\":\"",raw[5],ntohs(id)); command_hex((unsigned char*)e->ae_name,strlen(e->ae_name));
      printf("\",\"classes\":%u,\"seconds\":%llu,\"milliseconds\":%llu}",e->ae_class,(unsigned long long)seconds,(unsigned long long)milliseconds);
    }else if(token.id==AUT_SUBJECT32 || token.id==AUT_SUBJECT64 || token.id==AUT_SUBJECT32_EX || token.id==AUT_SUBJECT64_EX){
      need(headers && !trailers && ++subjects==1 && token.len>=29); subject=(pid_t)command_u32(raw+21);
      printf(",{\"kind\":\"subject\",\"pid\":%u,\"auid\":%u,\"asid\":%u,\"uid\":%u,\"gid\":%u}",subject,command_u32(raw+1),command_u32(raw+25),command_u32(raw+5),command_u32(raw+9));
    }else if(token.id==AUT_RETURN32 || token.id==AUT_RETURN64){
      need(headers && !trailers && ++returns==1); unsigned char status=token.id==AUT_RETURN32?token.tt.ret32.status:token.tt.ret64.err;
      need(!au_bsm_to_errno(status,&error) && error>=0 && error<=255);
      printf(",{\"kind\":\"return\",\"error\":%d,\"result\":%lld}",error,token.id==AUT_RETURN32?(long long)(int32_t)token.tt.ret32.ret:(long long)token.tt.ret64.val);
    }else if(token.id==AUT_TRAILER){need(++trailers==1 && offset+token.len==size && token.tt.trail.count==size && token.tt.trail.magic==AUT_TRAILER_MAGIC);printf(",{\"kind\":\"trailer\"}");}
    else {need(headers && !trailers); printf(",{\"kind\":\"metadata\",\"type\":%u,\"hex\":\"",token.id); command_hex(raw,(size_t)token.len);printf("\"}");
      if(command_action>=0 && token.id==AUT_PATH && token.len>=4 && raw[token.len-1]==0){
        target=token.len==(int)strlen(command_target[command_action])+4 && !memcmp(raw+3,command_target[command_action],(size_t)token.len-4);
        marker=token.len==(int)strlen(command_gate)+4 && !memcmp(raw+3,command_gate,(size_t)token.len-4);
      }
    }
    offset+=(size_t)token.len;
  }
  need(headers==1 && subjects==1 && returns==1 && trailers==1); puts("]}}");
  if(subject==(pid_t)command_case_identity.token.val[5]) {
    if(marker && !error && command_attempt_seen)command_marker_seen=true;
    if(target){command_attempt_seen=true;command_attempt_permitted=error==0;}
  }
}
static void command_drain(void) {
  command_health(); unsigned char bytes[65536];
  for(;;){ssize_t n=read(command_audit,bytes,sizeof(bytes));if(n<0 && errno==EINTR)continue;if(n<0 && errno==EAGAIN)break;
    need(n>0 && ++command_records<=4096 && (uint64_t)command_bytes+(uint64_t)n<=8388608);command_bytes+=(unsigned)n;command_record(bytes,(size_t)n);memset(bytes,0,(size_t)n);}
  command_health();
}
static void command_poll(void) {struct pollfd fd={command_audit,POLLIN,0};need(!command_expired && poll(&fd,1,10)>=0);command_drain();}
static uint64_t command_clock(struct timeval *time) {
  need(!gettimeofday(time,NULL)&&time->tv_sec>0&&(uint64_t)time->tv_sec<=UINT32_MAX&&time->tv_usec>=0&&time->tv_usec<1000000);
  return (uint64_t)time->tv_sec*1000+(unsigned)time->tv_usec/1000;
}
/* BSM has millisecond precision. Preserve the decoder's strict window rather
 * than admitting events on an ambiguous boundary or inventing a timestamp. */
static void command_barrier(void) {
  struct timeval time;uint64_t stamp;
  for(;;){command_drain();stamp=command_clock(&time);
    if(stamp>command_latest_record_time&&stamp>command_previous_barrier_time)break;command_poll();}
  need(++command_barriers<=256);command_previous_barrier_time=stamp;
  printf("{\"event\":\"barrier\",\"sequence\":%u,\"seconds\":%u,\"milliseconds\":%u}\n",command_barriers,(unsigned)time.tv_sec,(unsigned)(time.tv_usec/1000));
  /* The next release/operation cannot share the acknowledged start tick. */
  do{command_poll();}while(command_clock(&time)<=stamp);
}
static struct identity command_spawn(char **args, const char *home_leaf) {
  need(command_count<16 && !command_expired && !command_admissions_closed); int input[2],output[2],errors[2],birth[2],release[2]; need(!pipe(input)&&!pipe(output)&&!pipe(errors)&&!pipe(birth)&&!pipe(release));
  pid_t wrapper=fork();need(wrapper>=0);
  if(!wrapper){close(input[1]);close(output[0]);close(errors[0]);close(birth[0]);close(release[1]);
    auditinfo_addr_t audit={0};audit.ai_auid=command_uid;audit.ai_asid=AU_ASSIGN_ASID;audit.ai_termid.at_type=AU_IPv4;
    need(!setaudit_addr(&audit,sizeof(audit))&&!setgroups(0,NULL)&&!setgid(command_gid)&&!setuid(command_uid));
    char cwd[4096];command_path(cwd,"workspace");need(!chdir(cwd));policy(command_policy);
    /* The normal-UID launcher cannot create Codex until the root owner holds
     * and independently inspects its fresh inherited audit-session domain. */
    char byte;need(write(birth[1],"W",1)==1 && read(release[0],&byte,1)==1 && byte=='P' && !close(release[0]));
    posix_spawnattr_t attributes;posix_spawn_file_actions_t files;need(!posix_spawnattr_init(&attributes)&&!posix_spawn_file_actions_init(&files)&&
      !posix_spawnattr_setflags(&attributes,POSIX_SPAWN_START_SUSPENDED|POSIX_SPAWN_CLOEXEC_DEFAULT)&&
      !posix_spawn_file_actions_adddup2(&files,input[0],0)&&!posix_spawn_file_actions_adddup2(&files,output[1],1)&&!posix_spawn_file_actions_adddup2(&files,errors[1],2));
    char home[4120],codex_home[4128],path_env[8192];need(snprintf(home,sizeof(home),"HOME=%s/%s",command_root,home_leaf)<(int)sizeof(home)&&snprintf(codex_home,sizeof(codex_home),"CODEX_HOME=%s/%s",command_root,home_leaf)<(int)sizeof(codex_home));
    char directory[4096];need(strlen(command_image)<sizeof(directory));strcpy(directory,command_image);char *last=strrchr(directory,'/');need(last);*last=0;
    need(snprintf(path_env,sizeof(path_env),"PATH=%s/codex-path:/usr/bin:/bin",directory)<(int)sizeof(path_env));
    char *environment[]={home,codex_home,path_env,"LANG=C","CI=true","GITHUB_ACTIONS=true","RUNNER_ENVIRONMENT=github-hosted","RUNNER_OS=macOS",NULL};
    pid_t child;need(!posix_spawn(&child,args[0],&files,&attributes,args,environment)&&write(birth[1],&child,sizeof(child))==sizeof(child));
    close(birth[1]);close(input[0]);close(output[1]);close(errors[1]);int status;need(waitpid(child,&status,0)==child);_exit(WIFEXITED(status)?WEXITSTATUS(status):126);
  }
  close(input[0]);close(output[1]);close(errors[1]);close(birth[1]);close(release[0]);char byte;need(read(birth[0],&byte,1)==1&&byte=='W');
  struct identity owner;need(inspect(wrapper,&owner)&&owner.token.val[0]==command_uid&&owner.token.val[1]==command_uid&&owner.token.val[2]==command_gid&&owner.token.val[6]>0);
  need(!audit_session_port(owner.token.val[6],&command_rights[command_count])&&command_rights[command_count]!=MACH_PORT_NULL);
  command_sessions[command_count]=owner.token.val[6];command_wrappers[command_count++]=wrapper;
  command_image_identity(owner,command_helper,command_helper_hash);need(feasibility_sandbox_active(sandbox_binding,wrapper)==1 && !audit_signal(&owner.token,0));
  printf("{\"event\":\"custody\",\"identity\":");emit_identity(owner);puts(",\"sessionHeld\":true}");
  need(write(release[1],"P",1)==1&&!close(release[1]));pid_t child;need(read(birth[0],&child,sizeof(child))==sizeof(child)&&!close(birth[0]));
  struct identity identity;need(inspect(child,&identity)&&identity.token.val[0]==command_uid&&identity.token.val[1]==command_uid&&identity.token.val[2]==command_gid&&identity.token.val[6]==owner.token.val[6]);
  command_image_identity(identity,args[0],!strcmp(args[0],command_image)?command_image_hash:command_helper_hash);
  need(feasibility_sandbox_active(sandbox_binding,child)==1);
  command_in=input[1];command_out=output[0];command_err=errors[0];return identity;
}
static void command_continue(struct identity identity){need(live(identity)&&!audit_signal(&identity.token,SIGCONT));}
static void command_capture(const char *event) {
  unsigned char output[65536],errors[65536];size_t used=0,err=0;int fds[]={command_out,command_err};
  while(fds[0]>=0||fds[1]>=0){command_poll();struct pollfd p[]={{fds[0],POLLIN,0},{fds[1],POLLIN,0}};need(poll(p,2,10)>=0);
    for(unsigned i=0;i<2;i++)if(p[i].revents&(POLLIN|POLLHUP)){ssize_t n=read(fds[i],(i?errors:output)+(i?err:used),65536-(i?err:used));need(n>=0);if(!n){close(fds[i]);fds[i]=-1;}else{if(i)err+=(size_t)n;else used+=(size_t)n;need(used+err<65536);}}}
  int status;need(waitpid(command_wrappers[command_count-1],&status,0)==command_wrappers[command_count-1]&&WIFEXITED(status));
  if(event) printf("{\"event\":\"%s\",\"exitCode\":%d,\"stdout\":\"",event,WEXITSTATUS(status));
  /* The only accepted version text has no JSON escapes except its newline. */
  if(event){for(size_t i=0;i<used;i++){if(output[i]=='\n')printf("\\n");else{need(output[i]>=32&&output[i]<127&&output[i]!='"'&&output[i]!='\\');putchar(output[i]);}}puts("\"}");}
  else need(WEXITSTATUS(status)==0 && used==15 && !memcmp(output,"attempt:written",15));
  command_out=command_err=-1;close(command_in);command_in=-1;
}
static void command_case_ready(void) {
  need(command_action>=0);for(unsigned pass=0;pass<1000;pass++){
    pid_t pids[4096];int size=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));need(size>=0&&size<(int)sizeof(pids));
    unsigned found=0;struct identity selected={0};
    for(unsigned i=0;i<(unsigned)size/sizeof(pid_t);i++){if(pids[i]<=1)continue;bool wrapper=false;for(unsigned j=0;j<command_count;j++)if(pids[i]==command_wrappers[j])wrapper=true;if(wrapper)continue;
      char image[4096];if(proc_pidpath(pids[i],image,sizeof(image))<=0||strcmp(image,command_helper))continue;
      struct identity value;if(!inspect(pids[i],&value))continue;if(value.token.val[6]!=command_case_asid)continue;selected=value;found++;}
    need(found<=1);if(found){command_case_identity=selected;command_image_identity(selected,command_helper,command_helper_hash);need(feasibility_sandbox_active(sandbox_binding,(pid_t)selected.token.val[5])==1);
      if(!command_control){printf("{\"event\":\"N\",\"identity\":");emit_identity(selected);printf(",\"sandboxed\":true,\"object\":");command_object((unsigned)command_action,NULL);printf(",\"gate\":");command_gate_object(NULL);puts("}");}
      else {command_object(2,command_control_before);command_gate_object(command_control_gate_before);}
      need(write(command_gate_fd,"A",1)==1);return;}command_poll();}
  need(0);
}
static void command_case_finish(void) {
  for(unsigned pass=0;pass<1000&&(!command_attempt_seen||!command_marker_seen);pass++)command_poll();need(command_attempt_seen&&command_marker_seen&&live(command_case_identity));
  command_image_identity(command_case_identity,command_helper,command_helper_hash);need(feasibility_sandbox_active(sandbox_binding,(pid_t)command_case_identity.token.val[5])==1);
  if(!command_control){printf("{\"event\":\"F\",\"identity\":");emit_identity(command_case_identity);printf(",\"sandboxed\":true,\"imageSha256\":\"%s\",\"object\":",command_helper_hash);command_object((unsigned)command_action,NULL);printf(",\"gate\":");command_gate_object(NULL);puts("}");}
  else {command_object(2,command_control_after);command_gate_object(command_control_gate_after);}
  need(write(command_gate_fd,"F",1)==1);
}
static int command_entry(int argc,char **argv) {
  need(getenv("CI")&&!strcmp(getenv("CI"),"true")&&getenv("GITHUB_ACTIONS")&&!strcmp(getenv("GITHUB_ACTIONS"),"true")&&
    getenv("RUNNER_ENVIRONMENT")&&!strcmp(getenv("RUNNER_ENVIRONMENT"),"github-hosted")&&getenv("RUNNER_OS")&&!strcmp(getenv("RUNNER_OS"),"macOS"));
  audit_signal=(audit_signal_fn)dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");sandbox_binding=feasibility_sandbox_load();
  if(!strcmp(argv[1],"command-case")){need(argc==6&&getuid()>500&&geteuid()==getuid()&&strlen(argv[5])==32);alarm(15);
    int gate=open(argv[2],O_RDONLY|O_NOFOLLOW);struct stat st;need(gate>=0&&!fstat(gate,&st)&&S_ISFIFO(st.st_mode)&&st.st_uid==getuid());char byte;need(read(gate,&byte,1)==1&&byte=='A');
    bool reading=!strcmp(argv[4],"inspect"),control=!strcmp(argv[4],"control");need(reading||control||!strcmp(argv[4],"edit")||!strcmp(argv[4],"outside"));
    int fd=open(argv[3],(reading?O_RDONLY:O_WRONLY)|O_NOFOLLOW);int error=fd<0?errno:0;
    if(fd>=0){if(reading){char text[33]={0};need(read(fd,text,sizeof(text))==32&&!strcmp(text,argv[5]));printf("%s",text);}
      else{char text[48];int n=snprintf(text,sizeof(text),"%s%s",argv[5],control?"":"-edited");need(write(fd,text,(size_t)n)==n);}need(!close(fd));}
    if(!reading)printf("attempt:%s",error?"denied":"written");fflush(stdout);need(!close(gate));
    /* A second audited gate open acknowledges completed I/O before the root
     * reader snapshots held bytes. The helper stays live until that read joins. */
    gate=open(argv[2],O_RDONLY|O_NOFOLLOW);struct stat again;need(gate>=0&&!fstat(gate,&again)&&st.st_dev==again.st_dev&&st.st_ino==again.st_ino&&
      st.st_birthtimespec.tv_sec==again.st_birthtimespec.tv_sec&&st.st_birthtimespec.tv_nsec==again.st_birthtimespec.tv_nsec);
    need(read(gate,&byte,1)==1&&byte=='F'&&!close(gate));return 0;
  }
  if(getuid()!=0||geteuid()!=0||!audit_signal||!feasibility_sandbox_available(sandbox_binding))return 78;
  if(!strcmp(argv[1],"command-observe")){need(argc==14);struct identity value=parse_identity(argv+2);need(!live(value));puts("{\"status\":\"RETIRED\"}");return 0;}
  if(!strcmp(argv[1],"command-verify")){need(argc==3);unsigned asid=(unsigned)number(argv[2]);need(asid>0&&!command_members(asid,false));puts("{\"empty\":true}");return 0;}
  command_prerequisite=!strcmp(argv[1],"command-prerequisites");unsigned classes=command_classes();
  if(command_prerequisite){need(argc==5&&AUT_ATTR32==0x3e&&AUT_ATTR64==0x73&&AUT_PATH==0x23);command_root=argv[2];command_path(command_policy,"admission.sb");command_uid=(uid_t)number(argv[3]);command_gid=(gid_t)number(argv[4]);need(command_uid>500);
    struct identity parent;need(inspect(getpid(),&parent)&&parent.token.val[6]>0&&parent.token.val[0]==command_uid);
    int fd=command_pipe(classes,command_uid,true), ready[2], release[2];need(!pipe(ready)&&!pipe(release));pid_t child=fork();need(child>=0);
    if(!child){alarm(10);close(ready[0]);close(release[1]);auditinfo_addr_t audit={0};audit.ai_auid=command_uid;audit.ai_asid=AU_ASSIGN_ASID;audit.ai_termid.at_type=AU_IPv4;
      need(!setaudit_addr(&audit,sizeof(audit))&&!setgroups(0,NULL)&&!setgid(command_gid)&&!setuid(command_uid));policy(command_policy);
      /* Session membership is useful only if the admitted normal-UID policy
       * cannot create a new session or acquire a foreign session capability. */
      auditinfo_addr_t attempt={0};attempt.ai_auid=command_uid;attempt.ai_asid=AU_ASSIGN_ASID;attempt.ai_termid.at_type=AU_IPv4;
      errno=0;need(setaudit_addr(&attempt,sizeof(attempt))==-1&&(errno==EPERM||errno==EACCES));mach_port_t foreign=MACH_PORT_NULL;
      need(audit_session_port(parent.token.val[6],&foreign)!=0&&foreign==MACH_PORT_NULL);
      char byte;need(write(ready[1],"W",1)==1);(void)read(release[0],&byte,1);_exit(0);}
    close(ready[1]);close(release[0]);char byte;need(read(ready[0],&byte,1)==1&&byte=='W');struct identity value;
    need(inspect(child,&value)&&value.token.val[0]==command_uid&&value.token.val[1]==command_uid&&value.token.val[6]>0&&value.token.val[6]!=parent.token.val[6]&&feasibility_sandbox_active(sandbox_binding,child)==1);
    mach_port_t right=MACH_PORT_NULL;need(!audit_session_port(value.token.val[6],&right)&&right!=MACH_PORT_NULL&&command_members(value.token.val[6],false)==1);
    need(!audit_signal(&value.token,0)&&!audit_signal(&value.token,SIGKILL));close(release[1]);close(ready[0]);int status;
    need(waitpid(child,&status,0)==child&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL&&!command_members(value.token.val[6],false)&&
      mach_port_deallocate(mach_task_self(),right)==KERN_SUCCESS&&!close(fd));
    printf("{\"audit\":true,\"admission\":true,\"completeRetirement\":true,\"sessionEscapeDenied\":true,\"classes\":%u,",classes);command_mapping(classes);puts("}");return 0;}
  need(argc==9&&!strcmp(argv[1],"command-broker"));command_owner=getpid();command_root=argv[2];command_image=argv[3];command_image_hash=argv[4];command_uid=(uid_t)number(argv[5]);command_gid=(gid_t)number(argv[6]);command_nonce=argv[7];command_helper_hash=argv[8];
  need(command_uid>500&&strlen(command_nonce)==32&&strlen(command_image_hash)==64&&strlen(command_helper_hash)==64);
  struct stat root;char canonical[4096];need(realpath(command_root,canonical)&&!strcmp(canonical,command_root)&&!lstat(command_root,&root)&&S_ISDIR(root.st_mode)&&root.st_uid==command_uid&&(root.st_mode&07777)==0700);
  command_path(command_helper,"build/helper");command_path(command_gate,"workspace/.command-gate");command_path(command_policy,"admission.sb");
  const char *leaves[]={"workspace/inspection.txt","workspace/edit.txt","outside.txt"};for(unsigned i=0;i<3;i++){command_path(command_target[i],leaves[i]);command_objects[i]=open(command_target[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(command_objects[i]>=0);}
  need(!mkfifo(command_gate,0600)&&!chown(command_gate,command_uid,command_gid));command_gate_fd=open(command_gate,O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);need(command_gate_fd>=0);
  command_audit=command_pipe(classes,command_uid,true);command_health();
  /* No SA_RESTART: an alarm must interrupt a blocked native read, write or
   * waitpid so the owned failure path can enter its separate cleanup bound. */
  struct sigaction deadline={.sa_handler=command_expire};need(!sigemptyset(&deadline.sa_mask)&&!sigaction(SIGALRM,&deadline,NULL)&&
    !sigaction(SIGTERM,&deadline,NULL)&&!sigaction(SIGINT,&deadline,NULL)&&signal(SIGPIPE,SIG_IGN)!=SIG_ERR);alarm(120);
  struct identity observer;need(inspect(getpid(),&observer));command_image_identity(observer,command_helper,command_helper_hash);
  printf("{\"event\":\"ready\",\"imageSha256\":\"%s\",\"identity\":",command_helper_hash);emit_identity(observer);puts("}");
  struct identity server={0};char line[131080];bool stopping=false;setvbuf(stdin,NULL,_IONBF,0);
  while(!stopping){need(!command_expired);struct pollfd fds[]={{0,POLLIN,0},{command_audit,POLLIN,0},{command_out,POLLIN,0},{command_err,POLLIN,0}};need(poll(fds,4,1000)>=0);command_drain();
    for(unsigned i=2;i<4;i++)if(fds[i].revents&(POLLIN|POLLHUP)){unsigned char bytes[8192];ssize_t n=read(fds[i].fd,bytes,sizeof(bytes));need(n>=0);if(n){printf("{\"event\":\"%s\",\"hex\":\"",i==2?"rpc":"stderr");command_hex(bytes,(size_t)n);puts("\"}");}else{close(fds[i].fd);if(i==2)command_out=-1;else command_err=-1;printf("{\"event\":\"%s-end\"}\n",i==2?"rpc":"stderr");}}
    need(!(fds[0].revents&(POLLHUP|POLLERR|POLLNVAL)));if(!(fds[0].revents&POLLIN))continue;need(fgets(line,sizeof(line),stdin)&&strchr(line,'\n'));line[strlen(line)-1]=0;
    need((!command_expired && !command_admissions_closed) || !strcmp(line,"D") || !strcmp(line,"S"));
    if(!strcmp(line,"V")||!strcmp(line,"G")){char directory[4096];command_path(directory,"schema");char *v[]={(char*)command_image,"--version",NULL},*g[]={(char*)command_image,"app-server","generate-json-schema","--out",directory,NULL};struct identity child=command_spawn(line[0]=='V'?v:g,"schema-home");command_continue(child);command_capture(line);}
    else if(!strcmp(line,"A")){char *args[]={(char*)command_image,"-c","web_search=\"disabled\"","-c","mcp_servers={}","app-server","--listen","stdio://",NULL};server=command_spawn(args,"home");command_server_wrapper=command_wrappers[command_count-1];command_case_asid=server.token.val[6];printf("{\"event\":\"A\",\"identity\":");emit_identity(server);printf(",\"sessionHeld\":true,\"imageSha256\":\"%s\"}\n",command_image_hash);}
    else if(!strcmp(line,"R")){command_continue(server);puts("{\"event\":\"R\"}");}
    else if(!strncmp(line,"J ",2)){size_t n=strlen(line+2);need(command_in>=0&&n>0&&n<=131072&&n%2==0);unsigned char bytes[65536];for(size_t i=0;i<n/2;i++){char hex[3]={line[2+i*2],line[3+i*2],0};char *end;unsigned long b=strtoul(hex,&end,16);need(!*end);bytes[i]=(unsigned char)b;}need(write(command_in,bytes,n/2)==(ssize_t)(n/2));}
    else if(!strcmp(line,"E")){need(command_in>=0&&!close(command_in));command_in=-1;}
    else if(!strcmp(line,"B"))command_barrier();
    else if(!strncmp(line,"K ",2)){command_action=!strcmp(line+2,"inspect")?0:!strcmp(line+2,"edit")?1:!strcmp(line+2,"outside")?2:-1;need(command_action>=0);command_attempt_seen=false;command_attempt_permitted=false;command_marker_seen=false;memset(&command_case_identity,0,sizeof(command_case_identity));}
    else if(!strcmp(line,"N"))command_case_ready();else if(!strcmp(line,"F"))command_case_finish();
    else if(!strcmp(line,"C")){/* The same outer policy must permit this control. Preserve the server's RPC pipes. */
      int in=command_in,out=command_out,err=command_err;command_control=true;command_action=2;command_attempt_seen=false;command_marker_seen=false;char *args[]={command_helper,"command-case",command_gate,command_target[2],"control",(char*)command_nonce,NULL};
      struct identity child=command_spawn(args,"home");command_case_asid=child.token.val[6];command_continue(child);command_case_ready();command_case_finish();command_capture(NULL);need(command_attempt_permitted);
      printf("{\"event\":\"C\",\"permitted\":true,\"exitCode\":0,\"stdout\":\"attempt:written\",\"before\":");emit_identity(command_case_identity);printf(",\"after\":");emit_identity(command_case_identity);
      printf(",\"sandboxed\":true,\"imageSha256\":\"%s\",\"object\":{\"before\":%s,\"after\":%s},\"gate\":{\"before\":%s,\"after\":%s}}\n",command_helper_hash,command_control_before,command_control_after,command_control_gate_before,command_control_gate_after);
      command_in=in;command_out=out;command_err=err;command_control=false;command_case_asid=server.token.val[6];}
    else if(!strcmp(line,"D")){need(!command_cleanup_started);command_cleanup_started=true;command_admissions_closed=true;command_expired=0;alarm(30);if(command_in>=0){close(command_in);command_in=-1;}bool empty=false,emergency=false;for(unsigned pass=0;pass<2000&&!empty;pass++){empty=true;for(unsigned i=0;i<command_count;i++){int status;pid_t reaped=waitpid(command_wrappers[i],&status,WNOHANG);
      if(reaped>0&&reaped==command_server_wrapper)command_server_clean=WIFEXITED(status)&&WEXITSTATUS(status)==0;if(command_members(command_sessions[i],false))empty=false;}
      if(!empty && pass==100){emergency=true;for(unsigned i=0;i<command_count;i++)(void)command_members(command_sessions[i],true);}if(!empty)command_poll();}
      need(empty);printf("{\"event\":\"D\",\"empty\":true,\"emergency\":%s,\"serverClean\":%s,\"sessions\":[",emergency?"true":"false",!command_server_wrapper||command_server_clean?"true":"false");for(unsigned i=0;i<command_count;i++)printf("%s%u",i?",":"",command_sessions[i]);puts("]}");}
    else if(!strcmp(line,"S")){for(unsigned i=0;i<command_count;i++)need(!command_members(command_sessions[i],false));command_drain();need(!close(command_audit));
      printf("{\"event\":\"capture-end\",\"bytes\":%u,\"records\":%u}\n",command_bytes,command_records);
      for(unsigned i=0;i<command_count;i++)need(mach_port_deallocate(mach_task_self(),command_rights[i])==KERN_SUCCESS);puts("{\"event\":\"S\"}");stopping=true;}
    else need(0);
  }
  return 0;
}
