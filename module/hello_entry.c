#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>

#include "linux/cred.h"
#include "linux/sched.h"
#include "wxshadow_internal.h"

struct selinux_state {
    bool enforcing;
} __randomize_layout;

extern struct selinux_state selinux_state;

static void setenforce(bool enforce)
{
    selinux_state.enforcing = enforce;
}

static char *target_syscall = "__arm64_sys_membarrier";
module_param(target_syscall, charp, 0644);
MODULE_PARM_DESC(target_syscall, "Syscall symbol to attach kretprobe to");

static unsigned long magic_key = 0x53454c58UL;
module_param(magic_key, ulong, 0644);
MODULE_PARM_DESC(magic_key, "Special key in arg0 to identify control request");

static unsigned long magic_cmd_enforcing = 0x1UL;
module_param(magic_cmd_enforcing, ulong, 0644);
MODULE_PARM_DESC(magic_cmd_enforcing, "Command value in arg1: request enforcing");

static unsigned long magic_cmd_permissive = 0x0UL;
module_param(magic_cmd_permissive, ulong, 0644);
MODULE_PARM_DESC(magic_cmd_permissive, "Command value in arg1: request permissive");

struct membarrier_ret_ctx {
    bool override;
    long ret;
};

static struct kretprobe syscall_kretprobe;

static int read_membarrier_args(struct pt_regs *regs,
                                unsigned long *arg0,
                                unsigned long *arg1,
                                unsigned long *arg2,
                                unsigned long *arg3,
                                unsigned long *arg4,
                                unsigned long *arg5)
{
#if defined(CONFIG_ARM64)
    const struct pt_regs *sys_regs = (const struct pt_regs *)regs->regs[0];

    if (!sys_regs)
        return -EINVAL;

    *arg0 = sys_regs->regs[0];
    *arg1 = sys_regs->regs[1];
    *arg2 = sys_regs->regs[2];
    *arg3 = sys_regs->regs[3];
    *arg4 = sys_regs->regs[4];
    *arg5 = sys_regs->regs[5];
    return 0;
#else
    (void)regs;
    (void)arg0;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    return -EOPNOTSUPP;
#endif
}

static void set_syscall_return(struct pt_regs *regs, long ret)
{
#if defined(CONFIG_ARM64)
    regs->regs[0] = ret;
#elif defined(CONFIG_X86_64)
    regs->ax = ret;
#else
    (void)regs;
    (void)ret;
#endif
}

static int syscall_entry_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct membarrier_ret_ctx *ctx = (struct membarrier_ret_ctx *)ri->data;
    unsigned long arg0 = 0;
    unsigned long arg1 = 0;
    unsigned long arg2 = 0;
    unsigned long arg3 = 0;
    unsigned long arg4 = 0;
    unsigned long arg5 = 0;
    int ret;

    memset(ctx, 0, sizeof(*ctx));

    ret = read_membarrier_args(regs, &arg0, &arg1, &arg2, &arg3, &arg4, &arg5);
    if (ret)
        return 0;

    if (arg0 != magic_key)
        return 0;

    ctx->override = true;

    if (arg1 == magic_cmd_enforcing) {
        setenforce(true);
        ctx->ret = 0;
        return 0;
    }

    if (arg1 == magic_cmd_permissive) {
        setenforce(false);
        ctx->ret = 0;
        return 0;
    }

    ctx->ret = wxshadow_dispatch_membarrier(arg1, arg2, arg3, arg4, arg5);
    return 0;
}

static int syscall_ret_handler(struct kretprobe_instance *ri,
                               struct pt_regs *regs)
{
    struct membarrier_ret_ctx *ctx = (struct membarrier_ret_ctx *)ri->data;

    if (ctx->override)
        set_syscall_return(regs, ctx->ret);

    return 0;
}

static int __init hello_init(void)
{
    int ret;

#if !defined(CONFIG_ARM64)
    pr_err("hello_lkm: wxshadow integration currently supports ARM64 only\n");
    return -EOPNOTSUPP;
#endif

    ret = wxshadow_runtime_init();
    if (ret) {
        pr_err("hello_lkm: wxshadow runtime init failed: %d\n", ret);
        return ret;
    }

    memset(&syscall_kretprobe, 0, sizeof(syscall_kretprobe));
    syscall_kretprobe.kp.symbol_name = target_syscall;
    syscall_kretprobe.entry_handler = syscall_entry_handler;
    syscall_kretprobe.handler = syscall_ret_handler;
    syscall_kretprobe.data_size = sizeof(struct membarrier_ret_ctx);
    syscall_kretprobe.maxactive = 128;

    ret = register_kretprobe(&syscall_kretprobe);
    if (ret) {
        pr_err("hello_lkm: failed to register kretprobe on %s: %d\n",
               target_syscall, ret);
        wxshadow_runtime_exit();
        return ret;
    }

    pr_info("hello_lkm: module loaded, kretprobe=%s key=0x%lx cmd_perm=0x%lx cmd_enf=0x%lx\n",
            target_syscall, magic_key, magic_cmd_permissive,
            magic_cmd_enforcing);
    return 0;
}

static void __exit hello_exit(void)
{
    unregister_kretprobe(&syscall_kretprobe);
    wxshadow_runtime_exit();
    pr_info("hello_lkm: module unloaded, kretprobe detached from %s\n",
            target_syscall);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Codex");
MODULE_DESCRIPTION("External LKM with membarrier command mux + wxshadow runtime");
