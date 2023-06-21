#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");


SEC("kprobe/do_renameat2")
int probe_renameat2(struct pt_regs *ctx)
{
    struct data_t data = {};
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    data.pid = bpf_get_current_pid_tgid();
    data.uid = uid;
    data.op_code = 3;
    const char *newname = (const char *)PT_REGS_PARM2_SYSCALL(ctx);
    //char *newname_ptr = (char *)(ctx->si);


    // Read the actual string from user space
    int ret = bpf_probe_read(&data.newpath, sizeof(data.newpath), newname_ptr);
    data.debug = ret;

    

    
 
    // data.newpath[0] = 'a'; //newname[0];
    // data.newpath[1] = 'b'; //newname[1];
    // data.newpath[2] = 'c'; //newname[2];
    // data.newpath[6] = 0;


       	long unsigned int r15;
	data.r14 = ctx->r14;
	data.r13 = ctx->r13;
	data.r12 = ctx->r12;
	data.bp = ctx->bp;
	data.bx = ctx->bx;
	data.r11 = ctx->r11;
	data.r10 = ctx->r10;
	data.r9 = ctx->r9;
	data.r8 = ctx->r8;
	data.ax = ctx->ax;
	data.cx = ctx->cx;
	data.dx = ctx->dx;
	data.si = ctx->si;
	data.di = ctx->di;
	data.orig_ax = ctx->orig_ax;
	data.ip = ctx->ip;
	data.cs = ctx->cs;
	data.flags = ctx->flags;
	data.sp = ctx->sp;
	data.ss = ctx->ss;
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));


    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";


/*
/tmp/tmp1.txt
name: sys_enter_renameat2
ID: 739
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int olddfd;       offset:16;      size:8; signed:0;
        field:const char * oldname;     offset:24;      size:8; signed:0;
        field:int newdfd;       offset:32;      size:8; signed:0;
        field:const char * newname;     offset:40;      size:8; signed:0;
        field:unsigned int flags;       offset:48;      size:8; signed:0;

print fmt: "olddfd: 0x%08lx, oldname: 0x%08lx, newdfd: 0x%08lx, newname: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->olddfd)), ((unsigned long)(REC->oldname)), ((unsigned long)(REC->newdfd)), ((unsigned long)(REC->newname)), ((unsigned long)(REC->flags))



*/