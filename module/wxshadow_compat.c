#include "wxshadow_compat.h"
#include <linux/version.h>

struct task_struct_offset_info task_struct_offset = {
    .tasks_offset = offsetof(struct task_struct, tasks),
    .mm_offset = offsetof(struct task_struct, mm),
    .comm_offset = offsetof(struct task_struct, comm),
    .active_mm_offset = offsetof(struct task_struct, active_mm),
};

struct mm_struct_offset_info mm_struct_offset = {
    .pgd_offset = offsetof(struct mm_struct, pgd),
};

struct wx_hook_slot {
    bool used;
    bool use_kretprobe;
    unsigned int nargs;
    void *target;
    void (*before)(hook_fargs8_t *args, void *udata);
    void (*after)(hook_fargs8_t *args, void *udata);
    void *udata;
    struct kprobe kp;
    struct kretprobe krp;
};

struct wx_hook_ret_data {
    hook_fargs8_t args;
};

#define WX_MAX_HOOK_SLOTS 48
static struct wx_hook_slot wx_hook_slots[WX_MAX_HOOK_SLOTS];
static DEFINE_SPINLOCK(wx_hook_slots_lock);

static inline struct kretprobe *wx_ri_get_rp(struct kretprobe_instance *ri)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
    return ri->rp;
#else
    return ri->rph ? ri->rph->rp : NULL;
#endif
}

static void wxshadow_fill_args(hook_fargs8_t *args, struct pt_regs *regs)
{
    memset(args, 0, sizeof(*args));
#if defined(CONFIG_ARM64)
    args->arg0 = regs->regs[0];
    args->arg1 = regs->regs[1];
    args->arg2 = regs->regs[2];
    args->arg3 = regs->regs[3];
    args->arg4 = regs->regs[4];
    args->arg5 = regs->regs[5];
    args->arg6 = regs->regs[6];
    args->arg7 = regs->regs[7];
#elif defined(CONFIG_X86_64)
    args->arg0 = regs->di;
    args->arg1 = regs->si;
    args->arg2 = regs->dx;
    args->arg3 = regs->cx;
    args->arg4 = regs->r8;
    args->arg5 = regs->r9;
#else
    (void)regs;
#endif
}

static void wxshadow_set_return(struct pt_regs *regs, long ret)
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

static long wxshadow_get_return(struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    return regs->regs[0];
#elif defined(CONFIG_X86_64)
    return regs->ax;
#else
    (void)regs;
    return 0;
#endif
}

static void wxshadow_skip_origin(struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    regs->pc = regs->regs[30];
#elif defined(CONFIG_X86_64)
    regs->ip = regs->sp;
#else
    (void)regs;
#endif
}

static int wx_kprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct wx_hook_slot *slot = container_of(kp, struct wx_hook_slot, kp);
    hook_fargs8_t args;

    wxshadow_fill_args(&args, regs);
    if (slot->before)
        slot->before(&args, slot->udata);

    if (args.skip_origin) {
        wxshadow_set_return(regs, args.ret);
        wxshadow_skip_origin(regs);
        return 1;
    }

    return 0;
}

static int wx_kret_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kretprobe *rp = wx_ri_get_rp(ri);
    struct wx_hook_slot *slot;
    struct wx_hook_ret_data *data = (struct wx_hook_ret_data *)ri->data;

    if (!rp)
        return 0;
    slot = container_of(rp, struct wx_hook_slot, krp);

    wxshadow_fill_args(&data->args, regs);
    if (slot->before)
        slot->before(&data->args, slot->udata);

    if (data->args.skip_origin) {
        wxshadow_set_return(regs, data->args.ret);
        wxshadow_skip_origin(regs);
    }

    return 0;
}

static int wx_kret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct kretprobe *rp = wx_ri_get_rp(ri);
    struct wx_hook_slot *slot;
    struct wx_hook_ret_data *data = (struct wx_hook_ret_data *)ri->data;
    hook_fargs8_t args = data->args;

    if (!rp)
        return 0;
    slot = container_of(rp, struct wx_hook_slot, krp);

    args.ret = wxshadow_get_return(regs);
    if (slot->after)
        slot->after(&args, slot->udata);

    if (args.ret != wxshadow_get_return(regs))
        wxshadow_set_return(regs, args.ret);

    return 0;
}

static struct wx_hook_slot *wx_alloc_slot(void)
{
    int i;

    spin_lock(&wx_hook_slots_lock);
    for (i = 0; i < WX_MAX_HOOK_SLOTS; i++) {
        if (!wx_hook_slots[i].used) {
            wx_hook_slots[i].used = true;
            spin_unlock(&wx_hook_slots_lock);
            memset(&wx_hook_slots[i].kp, 0, sizeof(wx_hook_slots[i].kp));
            memset(&wx_hook_slots[i].krp, 0, sizeof(wx_hook_slots[i].krp));
            return &wx_hook_slots[i];
        }
    }
    spin_unlock(&wx_hook_slots_lock);
    return NULL;
}

static void wx_free_slot(struct wx_hook_slot *slot)
{
    spin_lock(&wx_hook_slots_lock);
    memset(slot, 0, sizeof(*slot));
    spin_unlock(&wx_hook_slots_lock);
}

static int wx_hook_wrap_n(unsigned int nargs, void *target,
                          void (*before)(hook_fargs8_t *args, void *udata),
                          void (*after)(hook_fargs8_t *args, void *udata),
                          void *udata)
{
    struct wx_hook_slot *slot;
    int ret;

    if (!target || !before)
        return -EINVAL;

    slot = wx_alloc_slot();
    if (!slot)
        return -ENOSPC;

    slot->target = target;
    slot->nargs = nargs;
    slot->before = before;
    slot->after = after;
    slot->udata = udata;

    if (after) {
        slot->use_kretprobe = true;
        slot->krp.kp.addr = target;
        slot->krp.entry_handler = wx_kret_entry_handler;
        slot->krp.handler = wx_kret_handler;
        slot->krp.data_size = sizeof(struct wx_hook_ret_data);
        slot->krp.maxactive = 128;
        ret = register_kretprobe(&slot->krp);
    } else {
        slot->use_kretprobe = false;
        slot->kp.addr = target;
        slot->kp.pre_handler = wx_kprobe_pre_handler;
        ret = register_kprobe(&slot->kp);
    }

    if (ret) {
        wx_free_slot(slot);
        return ret;
    }

    return HOOK_NO_ERR;
}

int hook_wrap1(void *target,
               void (*before)(hook_fargs1_t *args, void *udata),
               void (*after)(hook_fargs1_t *args, void *udata),
               void *udata)
{
    return wx_hook_wrap_n(1, target, (void *)before, (void *)after, udata);
}

int hook_wrap2(void *target,
               void (*before)(hook_fargs2_t *args, void *udata),
               void (*after)(hook_fargs2_t *args, void *udata),
               void *udata)
{
    return wx_hook_wrap_n(2, target, (void *)before, (void *)after, udata);
}

int hook_wrap3(void *target,
               void (*before)(hook_fargs3_t *args, void *udata),
               void (*after)(hook_fargs3_t *args, void *udata),
               void *udata)
{
    return wx_hook_wrap_n(3, target, (void *)before, (void *)after, udata);
}

int hook_wrap5(void *target,
               void (*before)(hook_fargs5_t *args, void *udata),
               void (*after)(hook_fargs5_t *args, void *udata),
               void *udata)
{
    return wx_hook_wrap_n(5, target, (void *)before, (void *)after, udata);
}

int hook_unwrap(void *target, void *before, void *after)
{
    int i;

    for (i = 0; i < WX_MAX_HOOK_SLOTS; i++) {
        struct wx_hook_slot *slot = &wx_hook_slots[i];

        if (!slot->used)
            continue;
        if (slot->target != target)
            continue;
        if (slot->before != before)
            continue;
        if (slot->after != after)
            continue;

        if (slot->use_kretprobe)
            unregister_kretprobe(&slot->krp);
        else
            unregister_kprobe(&slot->kp);

        wx_free_slot(slot);
        return HOOK_NO_ERR;
    }

    return -ENOENT;
}

unsigned long wxshadow_lookup_symbol(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name,
    };
    unsigned long addr;
    int ret;

    ret = register_kprobe(&kp);
    if (ret)
        return 0;

    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static const char *wx_syscall_symbol_name(int nr)
{
#if defined(CONFIG_ARM64)
    if (nr == __NR_prctl)
        return "__arm64_sys_prctl";
#ifdef __NR_membarrier
    if (nr == __NR_membarrier)
        return "__arm64_sys_membarrier";
#endif
#elif defined(CONFIG_X86_64)
    if (nr == __NR_prctl)
        return "__x64_sys_prctl";
#ifdef __NR_membarrier
    if (nr == __NR_membarrier)
        return "__x64_sys_membarrier";
#endif
#endif
    return NULL;
}

int hook_syscalln(int syscall_nr, int nargs, void *before, void *after,
                  void *udata)
{
    const char *name = wx_syscall_symbol_name(syscall_nr);
    unsigned long addr;

    (void)nargs;

    if (!name)
        return -EINVAL;

    addr = wxshadow_lookup_symbol(name);
    if (!addr)
        return -ENOENT;

    return wx_hook_wrap_n(nargs, (void *)addr, before, after, udata);
}

void unhook_syscalln(int syscall_nr,
                     void *before,
                     void *udata)
{
    int i;

    (void)udata;

    for (i = 0; i < WX_MAX_HOOK_SLOTS; i++) {
        const char *name;
        unsigned long addr;
        struct wx_hook_slot *slot = &wx_hook_slots[i];

        if (!slot->used)
            continue;

        name = wx_syscall_symbol_name(syscall_nr);
        if (!name)
            return;

        addr = wxshadow_lookup_symbol(name);
        if (!addr)
            return;

        if ((unsigned long)slot->target != addr)
            continue;
        if (slot->before != before)
            continue;

        if (slot->use_kretprobe)
            unregister_kretprobe(&slot->krp);
        else
            unregister_kprobe(&slot->kp);

        wx_free_slot(slot);
        return;
    }
}
