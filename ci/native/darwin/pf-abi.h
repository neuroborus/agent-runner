/*
 * Copyright (c) 2007-2024 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*	$apfw: git commit b6bf13f8321283cd7ee82b1795e86506084b1b95 $ */
/*	$OpenBSD: pfvar.h,v 1.259 2007/12/02 12:08:04 pascoe Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * NAT64 - Copyright (c) 2010 Viagenie Inc. (http://www.viagenie.ca)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef NATIVE_CI_DARWIN_PF_ABI_H
#define NATIVE_CI_DARWIN_PF_ABI_H

/* Bounded user-space LP64 extraction from bsd/net/pfvar.h:
 * https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/bsd/net/pfvar.h
 * Git blob: 691a4e711f5c8ec77184d575e4ffebb9ce41d772
 * SHA-256: aeaaa90c761577247bfa0328bd4765512f787f5af9a56b9bb530030c90a692c9
 * Only the reader's records, their by-value dependencies and ioctl constants
 * are retained. KERNEL and non-LP64 branches are excluded, not approximated.
 * This reference is not proof of any running kernel patch or PF semantics.
 */
#if !defined(NATIVE_CI_EXPERIMENT) || !defined(__APPLE__) || !defined(__x86_64__) || !defined(__LP64__) || defined(KERNEL)
#error "PF ABI adapter is private to the Darwin x86_64 LP64 experiment"
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stddef.h>

/* Reference action/ruleset ordinals (lines 174-179), including DUMMYNET. */
enum { PF_PASS, PF_DROP, PF_SCRUB, PF_NOSCRUB, PF_NAT, PF_NONAT,
  PF_BINAT, PF_NOBINAT, PF_RDR, PF_NORDR, PF_SYNPROXY_DROP,
  PF_DUMMYNET, PF_NODUMMYNET, PF_NAT64, PF_NONAT64 };
enum { PF_RULESET_SCRUB, PF_RULESET_FILTER, PF_RULESET_NAT,
  PF_RULESET_BINAT, PF_RULESET_RDR, PF_RULESET_DUMMYNET,
  PF_RULESET_MAX };
/* Reference timeout enum (lines 192-201) and record bounds. */
enum { PFTM_TCP_FIRST_PACKET, PFTM_TCP_OPENING, PFTM_TCP_ESTABLISHED,
  PFTM_TCP_CLOSING, PFTM_TCP_FIN_WAIT, PFTM_TCP_CLOSED,
  PFTM_UDP_FIRST_PACKET, PFTM_UDP_SINGLE, PFTM_UDP_MULTIPLE,
  PFTM_ICMP_FIRST_PACKET, PFTM_ICMP_ERROR_REPLY,
  PFTM_GREv1_FIRST_PACKET, PFTM_GREv1_INITIATING,
  PFTM_GREv1_ESTABLISHED, PFTM_ESP_FIRST_PACKET, PFTM_ESP_INITIATING,
  PFTM_ESP_ESTABLISHED, PFTM_OTHER_FIRST_PACKET, PFTM_OTHER_SINGLE,
  PFTM_OTHER_MULTIPLE, PFTM_FRAG, PFTM_INTERVAL,
  PFTM_ADAPTIVE_START, PFTM_ADAPTIVE_END, PFTM_SRC_NODE,
  PFTM_TS_DIFF, PFTM_MAX, PFTM_PURGE, PFTM_UNLINKED };

#define PF_TABLE_NAME_SIZE 32
#ifndef RTLABEL_LEN
#define RTLABEL_LEN 32
#endif
#define PF_ANCHOR_NAME_SIZE 64
#define PF_SKIP_COUNT 8
#define PF_RULE_LABEL_SIZE 64
#define PF_QNAME_SIZE 64
#define PF_TAG_NAME_SIZE 64
#define PF_OWNER_NAME_SIZE 64
#define PFRES_MAX 17 /* total+1 */
#define LCNT_MAX 7 /* total+1 */
#define FCNT_MAX 3
#define SCNT_MAX 3
#define PF_MD5_DIGEST_LENGTH 16
#define PFI_IFLAG_SKIP 0x0100 /* skip filtering on interface */

/* PF_ADDR_ADDRMASK is the first reference address-kind ordinal (line 237). */
enum { PF_ADDR_ADDRMASK };

struct pf_addr {
  union {
    struct in_addr _v4addr;
    struct in6_addr _v6addr;
    u_int8_t _addr8[16];
    u_int16_t _addr16[8];
    u_int32_t _addr32[4];
  } pfa;
};

struct pf_addr_wrap {
  union {
    struct {
      struct pf_addr addr;
      struct pf_addr mask;
    } a;
    char ifname[IFNAMSIZ];
    char tblname[PF_TABLE_NAME_SIZE];
    char rtlabelname[RTLABEL_LEN];
    u_int32_t rtlabel;
  } v;
  union {
    void *dyn __attribute__((aligned(8)));
    void *tbl __attribute__((aligned(8)));
    int dyncnt __attribute__((aligned(8)));
    int tblcnt __attribute__((aligned(8)));
  } p __attribute__((aligned(8)));
  u_int8_t type;
  u_int8_t iflags;
};

struct pf_port_range {
  u_int16_t port[2];
  u_int8_t op;
};

union pf_rule_xport {
  struct pf_port_range range;
  u_int16_t call_id;
  u_int32_t spi;
};

struct pf_rule_uid {
  uid_t uid[2];
  u_int8_t op;
  u_int8_t _pad[3];
};

struct pf_rule_gid {
  uid_t gid[2];
  u_int8_t op;
  u_int8_t _pad[3];
};

struct pf_rule_addr {
  struct pf_addr_wrap addr;
  union pf_rule_xport xport;
  u_int8_t neg;
};

TAILQ_HEAD(pf_palist, pf_pooladdr);

struct pf_poolhashkey {
  union {
    u_int8_t key8[16];
    u_int16_t key16[8];
    u_int32_t key32[4];
  } pfk;
};

struct pf_pool {
  struct pf_palist list;
  void *cur __attribute__((aligned(8)));
  struct pf_poolhashkey key __attribute__((aligned(8)));
  struct pf_addr counter;
  int tblidx;
  u_int16_t proxy_port[2];
  u_int8_t port_op;
  u_int8_t opts;
  sa_family_t af;
};

typedef u_int32_t pf_osfp_t;

union pf_rule_ptr {
  struct pf_rule *ptr __attribute__((aligned(8)));
  u_int32_t nr __attribute__((aligned(8)));
} __attribute__((aligned(8)));

struct pf_rule {
  struct pf_rule_addr src;
  struct pf_rule_addr dst;
  union pf_rule_ptr skip[PF_SKIP_COUNT];
  char label[PF_RULE_LABEL_SIZE];
  char ifname[IFNAMSIZ];
  char qname[PF_QNAME_SIZE];
  char pqname[PF_QNAME_SIZE];
  char tagname[PF_TAG_NAME_SIZE];
  char match_tagname[PF_TAG_NAME_SIZE];
  char overload_tblname[PF_TABLE_NAME_SIZE];
  TAILQ_ENTRY(pf_rule) entries;
  struct pf_pool rpool;
  u_int64_t evaluations;
  u_int64_t packets[2];
  u_int64_t bytes[2];
  u_int64_t ticket;
  char owner[PF_OWNER_NAME_SIZE];
  u_int32_t priority;
  void *kif __attribute__((aligned(8)));
  struct pf_anchor *anchor __attribute__((aligned(8)));
  void *overload_tbl __attribute__((aligned(8)));
  pf_osfp_t os_fingerprint __attribute__((aligned(8)));
  unsigned int rtableid;
  u_int32_t timeout[PFTM_MAX];
  u_int32_t states;
  u_int32_t max_states;
  u_int32_t src_nodes;
  u_int32_t max_src_nodes;
  u_int32_t max_src_states;
  u_int32_t max_src_conn;
  struct {
    u_int32_t limit;
    u_int32_t seconds;
  } max_src_conn_rate;
  u_int32_t qid;
  u_int32_t pqid;
  u_int32_t rt_listid;
  u_int32_t nr;
  u_int32_t prob;
  uid_t cuid;
  pid_t cpid;
  u_int16_t return_icmp;
  u_int16_t return_icmp6;
  u_int16_t max_mss;
  u_int16_t tag;
  u_int16_t match_tag;
  struct pf_rule_uid uid;
  struct pf_rule_gid gid;
  u_int32_t rule_flag;
  u_int8_t action;
  u_int8_t direction;
  u_int8_t log;
  u_int8_t logif;
  u_int8_t quick;
  u_int8_t ifnot;
  u_int8_t match_tag_not;
  u_int8_t natpass;
  u_int8_t keep_state;
  sa_family_t af;
  u_int8_t proto;
  u_int8_t type;
  u_int8_t code;
  u_int8_t flags;
  u_int8_t flagset;
  u_int8_t min_ttl;
  u_int8_t allow_opts;
  u_int8_t rt;
  u_int8_t return_ttl;
  u_int8_t tos;
  u_int8_t anchor_relative;
  u_int8_t anchor_wildcard;
  u_int8_t flush;
  u_int8_t proto_variant;
  u_int8_t extfilter;
  u_int8_t extmap;
  u_int32_t dnpipe;
  u_int32_t dntype;
};

struct pf_status {
  u_int64_t counters[PFRES_MAX];
  u_int64_t lcounters[LCNT_MAX];
  u_int64_t fcounters[FCNT_MAX];
  u_int64_t scounters[SCNT_MAX];
  u_int64_t pcounters[2][2][3];
  u_int64_t bcounters[2][2];
  u_int64_t stateid;
  u_int32_t running;
  u_int32_t states;
  u_int32_t src_nodes;
  u_int64_t since __attribute__((aligned(8)));
  u_int32_t debug;
  u_int32_t hostid;
  char ifname[IFNAMSIZ];
  u_int8_t pf_chksum[PF_MD5_DIGEST_LENGTH];
};

struct pfi_kif {
  char pfik_name[IFNAMSIZ];
  u_int64_t pfik_packets[2][2][2];
  u_int64_t pfik_bytes[2][2][2];
  u_int64_t pfik_tzero;
  int pfik_flags;
  int pfik_states;
  int pfik_rules;
};

struct pfioc_rule {
  u_int32_t action;
  u_int32_t ticket;
  u_int32_t pool_ticket;
  u_int32_t nr;
  char anchor[MAXPATHLEN];
  char anchor_call[MAXPATHLEN];
  struct pf_rule rule;
};

struct pfioc_ruleset {
  u_int32_t nr;
  char path[MAXPATHLEN];
  char name[PF_ANCHOR_NAME_SIZE];
};

struct pfioc_iface {
  char pfiio_name[IFNAMSIZ];
  void *pfiio_buffer __attribute__((aligned(8)));
  int pfiio_esize __attribute__((aligned(8)));
  int pfiio_size;
  int pfiio_nzero;
  int pfiio_flags;
};

/* Reference pfioc_states (lines 1884-1892); opaque records are retained only
 * as bounded evidence. Stateless recipes reject every nonempty state table. */
struct pfioc_states {
  int ps_len;
  union { caddr_t psu_buf; struct pfsync_state *psu_states; } ps_u __attribute__((aligned(8)));
#define ps_buf ps_u.psu_buf
};
enum { PF_INOUT, PF_IN, PF_OUT };
enum { PF_OP_NONE, PF_OP_IRG, PF_OP_EQ };
#define PFRULE_RETURN 0x0008 /* reference line 838 */
/* Reference ioctl numbers/types (lines 2152-2217); SDK supplies encoding. */
#define DIOCGETRULES _IOWR('D', 6, struct pfioc_rule)
#define DIOCGETRULE _IOWR('D', 7, struct pfioc_rule)
#define DIOCGETSTATES _IOWR('D', 25, struct pfioc_states)
#define DIOCGETSTATUS _IOWR('D', 21, struct pf_status)
#define DIOCGETRULESETS _IOWR('D', 58, struct pfioc_ruleset)
#define DIOCGETRULESET _IOWR('D', 59, struct pfioc_ruleset)
#define DIOCIGETIFACES _IOWR('D', 87, struct pfioc_iface)
#define DIOCSETIFFLAG _IOWR('D', 89, struct pfioc_iface)
#define DIOCCLRIFFLAG _IOWR('D', 90, struct pfioc_iface)

/* LP64 Darwin layout arithmetic from the above reference declarations.
 * These assert the SDK's scalar/queue assumptions as well as every nested
 * record boundary and each reader-accessed field used for ioctl/readback.
 * They establish compilation compatibility only, never kernel compatibility.
 */
_Static_assert(sizeof(void *) == 8 && sizeof(int) == 4 && sizeof(uid_t) == 4 && sizeof(pid_t) == 4 && sizeof(sa_family_t) == 1, "Darwin LP64 scalars");
_Static_assert(IFNAMSIZ == 16 && RTLABEL_LEN == 32 && MAXPATHLEN == 1024 && PFTM_MAX == 26 && PF_RULESET_MAX == 6, "reference bounds");
#define PF_ABI_LAYOUT(type, size, alignment) \
_Static_assert(sizeof(type) == (size) && _Alignof(type) == (alignment), #type " layout")
#define PF_ABI_OFFSET(type, field, offset) \
_Static_assert(offsetof(type, field) == (offset), #type "." #field " offset")
PF_ABI_LAYOUT(struct pf_addr, 16, 4);
PF_ABI_OFFSET(struct pf_addr, pfa, 0);
PF_ABI_LAYOUT(struct pf_addr_wrap, 48, 8);
PF_ABI_OFFSET(struct pf_addr_wrap, v, 0);
PF_ABI_OFFSET(struct pf_addr_wrap, p, 32);
PF_ABI_OFFSET(struct pf_addr_wrap, type, 40);
PF_ABI_OFFSET(struct pf_addr_wrap, iflags, 41);
PF_ABI_LAYOUT(struct pf_port_range, 6, 2);
PF_ABI_OFFSET(struct pf_port_range, op, 4);
PF_ABI_LAYOUT(union pf_rule_xport, 8, 4);
PF_ABI_LAYOUT(struct pf_rule_uid, 12, 4);
PF_ABI_OFFSET(struct pf_rule_uid, op, 8);
PF_ABI_LAYOUT(struct pf_rule_gid, 12, 4);
PF_ABI_OFFSET(struct pf_rule_gid, op, 8);
PF_ABI_LAYOUT(struct pf_rule_addr, 64, 8);
PF_ABI_OFFSET(struct pf_rule_addr, addr, 0);
PF_ABI_OFFSET(struct pf_rule_addr, xport, 48);
PF_ABI_OFFSET(struct pf_rule_addr, neg, 56);
PF_ABI_LAYOUT(struct pf_palist, 16, 8);
PF_ABI_OFFSET(struct pf_palist, tqh_first, 0);
PF_ABI_OFFSET(struct pf_palist, tqh_last, 8);
PF_ABI_LAYOUT(struct pf_poolhashkey, 16, 4);
PF_ABI_LAYOUT(struct pf_pool, 72, 8);
PF_ABI_OFFSET(struct pf_pool, list, 0);
PF_ABI_OFFSET(struct pf_pool, cur, 16);
PF_ABI_OFFSET(struct pf_pool, key, 24);
PF_ABI_OFFSET(struct pf_pool, counter, 40);
PF_ABI_OFFSET(struct pf_pool, tblidx, 56);
PF_ABI_OFFSET(struct pf_pool, proxy_port, 60);
PF_ABI_OFFSET(struct pf_pool, af, 66);
PF_ABI_LAYOUT(union pf_rule_ptr, 8, 8);
PF_ABI_LAYOUT(struct pf_rule, 1040, 8);
PF_ABI_OFFSET(struct pf_rule, src, 0);
PF_ABI_OFFSET(struct pf_rule, dst, 64);
PF_ABI_OFFSET(struct pf_rule, skip, 128);
PF_ABI_OFFSET(struct pf_rule, label, 192);
PF_ABI_OFFSET(struct pf_rule, entries, 560);
PF_ABI_OFFSET(struct pf_rule, rpool, 576);
PF_ABI_OFFSET(struct pf_rule, evaluations, 648);
PF_ABI_OFFSET(struct pf_rule, packets, 656);
PF_ABI_OFFSET(struct pf_rule, bytes, 672);
PF_ABI_OFFSET(struct pf_rule, ticket, 688);
PF_ABI_OFFSET(struct pf_rule, owner, 696);
PF_ABI_OFFSET(struct pf_rule, priority, 760);
PF_ABI_OFFSET(struct pf_rule, kif, 768);
PF_ABI_OFFSET(struct pf_rule, anchor, 776);
PF_ABI_OFFSET(struct pf_rule, overload_tbl, 784);
PF_ABI_OFFSET(struct pf_rule, os_fingerprint, 792);
PF_ABI_OFFSET(struct pf_rule, timeout, 800);
PF_ABI_OFFSET(struct pf_rule, states, 904);
PF_ABI_OFFSET(struct pf_rule, src_nodes, 912);
PF_ABI_OFFSET(struct pf_rule, nr, 948);
PF_ABI_OFFSET(struct pf_rule, uid, 976);
PF_ABI_OFFSET(struct pf_rule, gid, 988);
PF_ABI_OFFSET(struct pf_rule, rule_flag, 1000);
PF_ABI_OFFSET(struct pf_rule, action, 1004);
PF_ABI_OFFSET(struct pf_rule, quick, 1008);
PF_ABI_OFFSET(struct pf_rule, keep_state, 1012);
PF_ABI_OFFSET(struct pf_rule, af, 1013);
PF_ABI_OFFSET(struct pf_rule, anchor_relative, 1024);
PF_ABI_OFFSET(struct pf_rule, dnpipe, 1032);
PF_ABI_OFFSET(struct pf_rule, dntype, 1036);
PF_ABI_LAYOUT(struct pfioc_states, 16, 8);
PF_ABI_OFFSET(struct pfioc_states, ps_u, 8);
PF_ABI_LAYOUT(struct pf_status, 440, 8);
PF_ABI_OFFSET(struct pf_status, running, 376);
PF_ABI_OFFSET(struct pf_status, states, 380);
PF_ABI_OFFSET(struct pf_status, since, 392);
PF_ABI_OFFSET(struct pf_status, pf_chksum, 424);
PF_ABI_LAYOUT(struct pfi_kif, 168, 8);
PF_ABI_OFFSET(struct pfi_kif, pfik_name, 0);
PF_ABI_OFFSET(struct pfi_kif, pfik_packets, 16);
PF_ABI_OFFSET(struct pfi_kif, pfik_bytes, 80);
PF_ABI_OFFSET(struct pfi_kif, pfik_tzero, 144);
PF_ABI_OFFSET(struct pfi_kif, pfik_flags, 152);
PF_ABI_OFFSET(struct pfi_kif, pfik_states, 156);
PF_ABI_OFFSET(struct pfi_kif, pfik_rules, 160);
PF_ABI_LAYOUT(struct pfioc_rule, 3104, 8);
PF_ABI_OFFSET(struct pfioc_rule, ticket, 4);
PF_ABI_OFFSET(struct pfioc_rule, nr, 12);
PF_ABI_OFFSET(struct pfioc_rule, anchor, 16);
PF_ABI_OFFSET(struct pfioc_rule, anchor_call, 1040);
PF_ABI_OFFSET(struct pfioc_rule, rule, 2064);
PF_ABI_LAYOUT(struct pfioc_ruleset, 1092, 4);
PF_ABI_OFFSET(struct pfioc_ruleset, path, 4);
PF_ABI_OFFSET(struct pfioc_ruleset, name, 1028);
PF_ABI_LAYOUT(struct pfioc_iface, 40, 8);
PF_ABI_OFFSET(struct pfioc_iface, pfiio_name, 0);
PF_ABI_OFFSET(struct pfioc_iface, pfiio_buffer, 16);
PF_ABI_OFFSET(struct pfioc_iface, pfiio_esize, 24);
PF_ABI_OFFSET(struct pfioc_iface, pfiio_size, 28);
PF_ABI_OFFSET(struct pfioc_iface, pfiio_nzero, 32);
PF_ABI_OFFSET(struct pfioc_iface, pfiio_flags, 36);
#undef PF_ABI_OFFSET
#undef PF_ABI_LAYOUT
#endif
