#ifndef WXSHADOW_COMPAT_H
#define WXSHADOW_COMPAT_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/stddef.h>
#include <asm/unistd.h>
#include <asm/current.h>
#include <asm/ptrace.h>

#define KPM_NAME(name)
#define KPM_VERSION(ver)
#define KPM_LICENSE(lic)
#define KPM_AUTHOR(author)
#define KPM_DESCRIPTION(desc)
#define KPM_INIT(fn)
#define KPM_CTL0(fn)
#define KPM_CTL1(fn)
#define KPM_EXIT(fn)

typedef struct {
    unsigned long data0;
    unsigned long data1;
    unsigned long data2;
    unsigned long data3;
} hook_local_state_t;

typedef struct hook_fargs8 {
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    unsigned long arg6;
    unsigned long arg7;
    long ret;
    unsigned int skip_origin;
    hook_local_state_t local;
} hook_fargs8_t;

typedef hook_fargs8_t hook_fargs1_t;
typedef hook_fargs8_t hook_fargs2_t;
typedef hook_fargs8_t hook_fargs3_t;
typedef hook_fargs8_t hook_fargs4_t;
typedef hook_fargs8_t hook_fargs5_t;

typedef int hook_err_t;

#define HOOK_NO_ERR 0

#define syscall_argn(args, n) \
    ((n) == 0 ? (args)->arg0 : \
     (n) == 1 ? (args)->arg1 : \
     (n) == 2 ? (args)->arg2 : \
     (n) == 3 ? (args)->arg3 : \
     (n) == 4 ? (args)->arg4 : \
     (n) == 5 ? (args)->arg5 : \
     (n) == 6 ? (args)->arg6 : (args)->arg7)

struct task_struct_offset_info {
    int16_t tasks_offset;
    int16_t mm_offset;
    int16_t comm_offset;
    int16_t active_mm_offset;
};

struct mm_struct_offset_info {
    int16_t pgd_offset;
};

extern struct task_struct_offset_info task_struct_offset;
extern struct mm_struct_offset_info mm_struct_offset;

unsigned long wxshadow_lookup_symbol(const char *name);

int hook_wrap1(void *target,
               void (*before)(hook_fargs1_t *args, void *udata),
               void (*after)(hook_fargs1_t *args, void *udata),
               void *udata);
int hook_wrap2(void *target,
               void (*before)(hook_fargs2_t *args, void *udata),
               void (*after)(hook_fargs2_t *args, void *udata),
               void *udata);
int hook_wrap3(void *target,
               void (*before)(hook_fargs3_t *args, void *udata),
               void (*after)(hook_fargs3_t *args, void *udata),
               void *udata);
int hook_wrap5(void *target,
               void (*before)(hook_fargs5_t *args, void *udata),
               void (*after)(hook_fargs5_t *args, void *udata),
               void *udata);
int hook_unwrap(void *target, void *before, void *after);
int hook_syscalln(int syscall_nr, int nargs, void *before, void *after,
                  void *udata);
void unhook_syscalln(int syscall_nr,
                     void *before,
                     void *udata);

#endif
