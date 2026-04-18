#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>

#include "linux/cred.h"
#include "linux/sched.h"


struct selinux_state { // L90
	bool enforcing;
} __randomize_layout; // L109

extern struct selinux_state selinux_state; 

void setenforce(bool enforce)
{
    selinux_state.enforcing = enforce;
}

static char *target_syscall = "__arm64_sys_membarrier";
module_param(target_syscall, charp, 0644);
MODULE_PARM_DESC(target_syscall, "Syscall symbol to attach kprobe to");

static unsigned long magic_key = 0x53454c58UL;
module_param(magic_key, ulong, 0644);
MODULE_PARM_DESC(magic_key, "Special key in arg0 to identify control request");

static unsigned long magic_cmd_enforcing = 0x1UL;
module_param(magic_cmd_enforcing, ulong, 0644);
MODULE_PARM_DESC(magic_cmd_enforcing, "Command value in arg1: request enforcing");

static unsigned long magic_cmd_permissive = 0x0UL;
module_param(magic_cmd_permissive, ulong, 0644);
MODULE_PARM_DESC(magic_cmd_permissive, "Command value in arg1: request permissive");

static struct kprobe syscall_kp = {
	.pre_handler = NULL,
};

static int read_syscall_args(struct pt_regs *regs,
			     unsigned long *arg0,
			     unsigned long *arg1,
			     unsigned long *arg2)
{
#if defined(CONFIG_ARM64)
	const struct pt_regs *sys_regs = (const struct pt_regs *)regs->regs[0];
	if (!sys_regs)
		return -EINVAL;
	*arg0 = sys_regs->regs[0];
	*arg1 = sys_regs->regs[1];
	*arg2 = sys_regs->regs[2];
	return 0;
#elif defined(CONFIG_X86_64)
	const struct pt_regs *sys_regs = (const struct pt_regs *)regs->di;
	if (!sys_regs)
		return -EINVAL;
	*arg0 = sys_regs->di;
	*arg1 = sys_regs->si;
	*arg2 = sys_regs->dx;
	return 0;
#else
	(void)regs;
	(void)arg0;
	(void)arg1;
	(void)arg2;
	return -EOPNOTSUPP;
#endif
}

static int syscall_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long arg0 = 0;
	unsigned long arg1 = 0;
	unsigned long arg2 = 0;
	int ret;

	ret = read_syscall_args(regs, &arg0, &arg1, &arg2);
	if (ret)
		return 0;

	if (arg0 != magic_key)
		return 0;

	if (arg1 == magic_cmd_enforcing) {
		pr_warn("hello_lkm: special request on %s => cmd enforcing token=0x%lx ignored\n",
			p->symbol_name, arg2);
			setenforce(1);
	} else if (arg1 == magic_cmd_permissive) {
		pr_warn("hello_lkm: special request on %s => cmd permissive token=0x%lx ignored\n",
			p->symbol_name, arg2);
			setenforce(0);
	} else {
		pr_warn("hello_lkm: special request on %s => unknown cmd=0x%lx token=0x%lx ignored\n",
			p->symbol_name, arg1, arg2);
	}

	return 0;
}

static int __init hello_init(void)
{
	int ret;

	syscall_kp.pre_handler = syscall_pre_handler;
	syscall_kp.symbol_name = target_syscall;

	ret = register_kprobe(&syscall_kp);
	if (ret) {
		pr_err("hello_lkm: failed to register kprobe on %s: %d\n",
		       target_syscall, ret);
		return ret;
	}

	pr_info("hello_lkm: module loaded, kprobe=%s key=0x%lx cmd_perm=0x%lx cmd_enf=0x%lx\n",
		target_syscall, magic_key, magic_cmd_permissive, magic_cmd_enforcing);
	return 0;
}

static void __exit hello_exit(void)
{
	unregister_kprobe(&syscall_kp);
	pr_info("hello_lkm: module unloaded, kprobe detached from %s\n",
		target_syscall);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Codex");
MODULE_DESCRIPTION("Minimal out-of-tree LKM with syscall kprobe + special argument check");
