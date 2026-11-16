// SPDX-License-Identifier: GPL-2.0
// Minimal CO-RE types: offsets are relocated from the running kernel's BTF.
#define __VMLINUX_H__
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct mnt_namespace { struct ns_common ns; } __attribute__((preserve_access_index));
struct nsproxy { struct mnt_namespace *mnt_ns; } __attribute__((preserve_access_index));
struct super_block { unsigned long s_magic; unsigned int s_dev; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; } __attribute__((preserve_access_index));
struct inode { struct super_block *i_sb; } __attribute__((preserve_access_index));
struct fdtable { unsigned int max_fds; struct file **fd; } __attribute__((preserve_access_index));
struct files_struct { struct fdtable *fdt; } __attribute__((preserve_access_index));
struct task_struct { struct nsproxy *nsproxy; struct files_struct *files; } __attribute__((preserve_access_index));
struct fuse_mount { struct super_block *sb; } __attribute__((preserve_access_index));
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
 unsigned long r15,r14,r13,r12,bp,bx,r11,r10,r9,r8,ax,cx,dx,si,di,orig_ax,ip,cs,flags,sp,ss;
};
#else
struct user_pt_regs { unsigned long regs[31], sp, pc, pstate; };
struct pt_regs { unsigned long regs[31], sp, pc, pstate; };
#endif
const volatile __u32 fuse_mount_argument = 1;
struct event { __u64 cgroup; __u64 ns; __u32 pid; __u32 dev; };
struct key { __u64 ns; __u32 dev; __u32 pad; };
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,65536); __type(key,__u32); __type(value,__u8); } allowed SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,65536); __type(key,__u64); __type(value,struct event); } reads SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,65536); __type(key,__u64); __type(value,struct event); } requests SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,65536); __type(key,struct key); __type(value,__u64); } cooldown SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,1<<20); } events SEC(".maps");

static __always_inline int identify(struct super_block *sb, struct event *e) {
 if (!sb || BPF_CORE_READ(sb,s_magic) != 0x65735546) return 0;
 e->dev = BPF_CORE_READ(sb,s_dev);
 if (!bpf_map_lookup_elem(&allowed,&e->dev)) return 0;
 struct task_struct *task=(void *)bpf_get_current_task();
 e->ns=BPF_CORE_READ(task,nsproxy,mnt_ns,ns.inum);
 e->pid=bpf_get_current_pid_tgid()>>32;
 e->cgroup=bpf_get_current_cgroup_id();
 return 1;
}
static __always_inline void emit(struct event *e, long ret) {
 if (ret != -5 && ret != -107) return;
 struct key key={.ns=e->ns,.dev=e->dev};
 __u64 now=bpf_ktime_get_ns(), *last=bpf_map_lookup_elem(&cooldown,&key);
 if (last && now-*last<1000000000ULL) return;
 if (bpf_ringbuf_output(&events,e,sizeof(*e),0)==0) bpf_map_update_elem(&cooldown,&key,&now,BPF_ANY);
}
struct enter_read { __u64 unused; long id; unsigned long fd; };
struct exit_read { __u64 unused; long id; long ret; };
SEC("tracepoint/syscalls/sys_enter_read") int read_enter(struct enter_read *ctx) {
 struct task_struct *task=(void *)bpf_get_current_task();
 struct fdtable *fdt=BPF_CORE_READ(task,files,fdt);
 if (ctx->fd>=BPF_CORE_READ(fdt,max_fds)) return 0;
 struct file **fds=BPF_CORE_READ(fdt,fd), *f=0;
 bpf_probe_read_kernel(&f,sizeof(f),&fds[ctx->fd]);
 struct event e={};
 if (identify(BPF_CORE_READ(f,f_inode,i_sb),&e)) {
  __u64 tid=bpf_get_current_pid_tgid(); bpf_map_update_elem(&reads,&tid,&e,BPF_ANY);
 }
 return 0;
}
SEC("tracepoint/syscalls/sys_exit_read") int read_exit(struct exit_read *ctx) {
 __u64 tid=bpf_get_current_pid_tgid(); struct event *e=bpf_map_lookup_elem(&reads,&tid);
 if (e) { emit(e,ctx->ret); bpf_map_delete_elem(&reads,&tid); } return 0;
}
// fuse_get_req covers failures during lookup/open/getattr before a read FD exists.
SEC("kprobe/fuse_get_req") int request_enter(struct pt_regs *ctx) {
 unsigned long arg1=PT_REGS_PARM1(ctx), arg2=PT_REGS_PARM2(ctx);
 asm volatile("" : "+r"(arg1), "+r"(arg2));
 struct fuse_mount *fm=(void *)(fuse_mount_argument == 2 ? arg2 : arg1); struct event e={};
 if (identify(BPF_CORE_READ(fm,sb),&e)) {
  __u64 tid=bpf_get_current_pid_tgid(); bpf_map_update_elem(&requests,&tid,&e,BPF_ANY);
 } return 0;
}
SEC("kretprobe/fuse_get_req") int request_exit(struct pt_regs *ctx) {
 __u64 tid=bpf_get_current_pid_tgid(); struct event *e=bpf_map_lookup_elem(&requests,&tid);
 if (e) { emit(e,(long)PT_REGS_RC(ctx)); bpf_map_delete_elem(&requests,&tid); } return 0;
}
char LICENSE[] SEC("license")="GPL";
