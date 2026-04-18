/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KPM_WXSHADOW_INTERNAL_H_
#define _KPM_WXSHADOW_INTERNAL_H_

#include "wxshadow_compat.h"
#include "wxshadow.h"

#include <linux/err.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/delay.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/init_task.h>
#include <linux/smp.h>
#include <linux/mm_inline.h>
#include <linux/pgtable.h>
#include <asm/esr.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

/* ========== ARM64 CPU helpers ========== */

static inline void wxshadow_cpu_relax(void)
{
#if defined(CONFIG_ARM64)
    asm volatile("yield" ::: "memory");
#else
    cpu_relax();
#endif
}

static inline void wxshadow_page_pte_lock(struct wxshadow_page *page)
{
    while (atomic_cmpxchg(&page->pte_lock, 0, 1) != 0)
        wxshadow_cpu_relax();
}

static inline void wxshadow_page_pte_unlock(struct wxshadow_page *page)
{
    atomic_set(&page->pte_lock, 0);
}

static inline struct task_struct *wx_next_task(struct task_struct *task)
{
    return list_entry(task->tasks.next, struct task_struct, tasks);
}

/* ========== Kernel function pointers ========== */

extern void *(*kfunc_find_vma)(void *mm, unsigned long addr);
extern void *(*kfunc_get_task_mm)(void *task);
extern void (*kfunc_mmput)(void *mm);

extern void *kfunc_exit_mmap;

extern unsigned long (*kfunc___get_free_pages)(unsigned int gfp_mask,
                                               unsigned int order);
extern void (*kfunc_free_pages)(unsigned long addr, unsigned int order);

extern s64 *kvar_memstart_addr;
extern s64 *kvar_physvirt_offset;
extern unsigned long page_offset_base;
extern s64 detected_physvirt_offset;
extern int physvirt_offset_valid;

extern int wx_page_shift;
extern int wx_page_level;

#define wxfunc(func) wx_##func
#define wxfunc_def(func) (*wx_##func)

extern void wxfunc_def(_raw_spin_lock)(raw_spinlock_t *lock);
extern void wxfunc_def(_raw_spin_unlock)(raw_spinlock_t *lock);

extern struct task_struct *wxfunc_def(find_task_by_vpid)(pid_t nr);
extern pid_t wxfunc_def(__task_pid_nr_ns)(struct task_struct *task,
                                          enum pid_type type,
                                          struct pid_namespace *ns);

extern struct task_struct *wx_init_task;

extern void (*kfunc_flush_dcache_page)(void *page);
extern void (*kfunc___flush_icache_range)(unsigned long start,
                                          unsigned long end);

extern void (*kfunc_user_enable_single_step)(void *task);
extern void (*kfunc_user_disable_single_step)(void *task);
extern void (*kfunc_kernel_enable_single_step)(struct pt_regs *regs);
extern void (*kfunc_kernel_disable_single_step)(void);

extern void *kfunc_brk_handler;
extern void *kfunc_single_step_handler;

extern void (*kfunc_register_user_break_hook)(struct wx_break_hook *hook);
extern void (*kfunc_register_user_step_hook)(struct wx_step_hook *hook);
extern spinlock_t *kptr_debug_hook_lock;

extern void (*kfunc_rcu_read_lock)(void);
extern void (*kfunc_rcu_read_unlock)(void);
extern void (*kfunc_synchronize_rcu)(void);
extern void (*kfunc_kick_all_cpus_sync)(void);

extern void *(*kfunc_kzalloc)(size_t size, unsigned int flags);
extern void *(*kfunc_kcalloc)(size_t n, size_t size, unsigned int flags);
extern void (*kfunc_kfree)(void *ptr);

extern long (*kfunc_copy_from_kernel_nofault)(void *dst,
                                              const void *src,
                                              size_t size);

extern void *kfunc_do_page_fault;
extern void *kfunc_follow_page_pte;

extern void *kfunc_dup_mmap;
extern void *kfunc_uprobe_dup_mmap;
extern void *kfunc_copy_process;
extern void *kfunc_cgroup_post_fork;

extern void (*kfunc_flush_tlb_page)(void *vma, unsigned long uaddr);
extern void (*kfunc___flush_tlb_range)(void *vma, unsigned long start,
                                       unsigned long end,
                                       unsigned long stride,
                                       bool last_level, int tlb_level);

extern void (*kfunc___split_huge_pmd)(void *vma, void *pmd,
                                      unsigned long address,
                                      bool freeze, void *page);

extern int16_t vma_vm_mm_offset;
extern int16_t mm_context_id_offset;
extern int tlb_flush_mode;

extern struct list_head page_list;
extern spinlock_t global_lock;
extern atomic_t wx_in_flight;
extern bool wxshadow_breakpoint_enabled;

#define WX_HANDLER_ENTER() atomic_inc(&wx_in_flight)
#define WX_HANDLER_EXIT()  atomic_dec(&wx_in_flight)

#define WXSHADOW_RELEASE_WAIT_LOOPS 2000000

static inline bool is_el0_instruction_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
}

static inline bool is_el0_data_abort(unsigned int esr)
{
    return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW;
}

static inline bool is_permission_fault(unsigned int esr)
{
    unsigned int fsc = esr & 0x3F;
    return (fsc & 0x3C) == 0x0C;
}

enum wxshadow_fault_access {
    WXSHADOW_FAULT_NONE = 0,
    WXSHADOW_FAULT_EXEC,
    WXSHADOW_FAULT_READ,
    WXSHADOW_FAULT_WRITE,
};

static inline enum wxshadow_fault_access
wxshadow_classify_permission_fault(unsigned int esr)
{
    if (!is_permission_fault(esr))
        return WXSHADOW_FAULT_NONE;

    if (is_el0_instruction_abort(esr))
        return WXSHADOW_FAULT_EXEC;

    if (!is_el0_data_abort(esr))
        return WXSHADOW_FAULT_NONE;

    if (esr & ESR_ELx_S1PTW)
        return WXSHADOW_FAULT_NONE;
    if (esr & ESR_ELx_CM)
        return WXSHADOW_FAULT_READ;

    return (esr & ESR_ELx_WNR) ? WXSHADOW_FAULT_WRITE
                               : WXSHADOW_FAULT_READ;
}

/* ========== Helpers ========== */

static inline bool is_kva(unsigned long addr)
{
#if defined(CONFIG_ARM64)
    return (addr >> 48) == 0xffff;
#else
    return addr >= PAGE_OFFSET;
#endif
}

static inline bool wxshadow_has_single_step_api(void)
{
    if (kfunc_user_enable_single_step && kfunc_user_disable_single_step)
        return true;
    if (kfunc_kernel_enable_single_step && kfunc_kernel_disable_single_step)
        return true;
    return false;
}

static inline void wxshadow_enable_single_step_for_current(struct pt_regs *regs)
{
    if (kfunc_user_enable_single_step) {
        kfunc_user_enable_single_step(current);
        return;
    }

    if (kfunc_kernel_enable_single_step)
        kfunc_kernel_enable_single_step(regs);
}

static inline void wxshadow_disable_single_step_for_current(struct pt_regs *regs)
{
    if (kfunc_user_disable_single_step) {
        kfunc_user_disable_single_step(current);
        return;
    }

    if (kfunc_kernel_disable_single_step)
        kfunc_kernel_disable_single_step();
}

static inline bool safe_read_u64(unsigned long addr, u64 *out)
{
    if (!out || !is_kva(addr))
        return false;

    if (kfunc_copy_from_kernel_nofault) {
        if (kfunc_copy_from_kernel_nofault(out, (const void *)addr,
                                           sizeof(*out)) != 0)
            return false;
        return true;
    }

    memcpy(out, (const void *)addr, sizeof(*out));
    return true;
}

static inline bool safe_read_ptr(unsigned long addr, void **out)
{
    return safe_read_u64(addr, (u64 *)out);
}

static inline void *vma_mm(void *vma)
{
    struct vm_area_struct *vm = (struct vm_area_struct *)vma;

    return vm ? (void *)vm->vm_mm : NULL;
}

static inline unsigned long vma_start(void *vma)
{
    struct vm_area_struct *vm = (struct vm_area_struct *)vma;

    return vm ? vm->vm_start : 0;
}

static inline unsigned long vma_end(void *vma)
{
    struct vm_area_struct *vm = (struct vm_area_struct *)vma;

    return vm ? vm->vm_end : 0;
}

static inline void *mm_pgd(void *mm)
{
    struct mm_struct *m = (struct mm_struct *)mm;

    return m ? (void *)m->pgd : NULL;
}

static inline void *safe_kcalloc(size_t n, size_t size, unsigned int flags)
{
    if (kfunc_kcalloc)
        return kfunc_kcalloc(n, size, flags);
    if (n != 0 && size > ((size_t)-1) / n)
        return NULL;
    return kfunc_kzalloc(n * size, flags);
}

static inline unsigned long vaddr_to_paddr_at(unsigned long vaddr)
{
    u64 par;

#if defined(CONFIG_ARM64)
    asm volatile("at s1e1r, %0" : : "r"(vaddr));
    asm volatile("isb");
    asm volatile("mrs %0, par_el1" : "=r"(par));
    if (par & 1)
        return 0;
    return (par & 0x0000FFFFFFFFF000UL) | (vaddr & 0xFFF);
#else
    return (unsigned long)virt_to_phys((const volatile void *)vaddr);
#endif
}

static inline unsigned long phys_to_virt_safe(unsigned long pa)
{
    return (unsigned long)__va(pa);
}

static inline unsigned long kaddr_to_phys(unsigned long vaddr)
{
    return (unsigned long)__pa((const volatile void *)vaddr);
}

static inline unsigned long kaddr_to_pfn(unsigned long vaddr)
{
    return kaddr_to_phys(vaddr) >> PAGE_SHIFT;
}

static inline void *wxshadow_pfn_to_kaddr(unsigned long pfn)
{
    unsigned long pa = pfn << PAGE_SHIFT;

    return (void *)phys_to_virt_safe(pa);
}

#define safe_kunmap(addr) do { } while (0)

static inline void wxshadow_flush_kern_dcache_area(unsigned long kva,
                                                    unsigned long size)
{
#if defined(CONFIG_ARM64)
    unsigned long addr;
    unsigned long end;
    u64 ctr_el0;
    u64 line_size;

    asm volatile("mrs %0, ctr_el0" : "=r"(ctr_el0));
    line_size = 4 << ((ctr_el0 >> 16) & 0xf);

    end = kva + size;
    for (addr = kva & ~(line_size - 1); addr < end; addr += line_size)
        asm volatile("dc cvau, %0" : : "r"(addr) : "memory");
    asm volatile("dsb ish" : : : "memory");
#else
    flush_dcache_range(kva, kva + size);
#endif
}

static inline void wxshadow_flush_icache_range(unsigned long start,
                                               unsigned long end)
{
    if (kfunc___flush_icache_range) {
        kfunc___flush_icache_range(start, end);
#if defined(CONFIG_ARM64)
        asm volatile("isb" : : : "memory");
#endif
        return;
    }

#if defined(CONFIG_ARM64)
    asm volatile("ic ialluis" : : : "memory");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
#else
    flush_icache_range(start, end);
#endif
}

static inline void wxshadow_flush_icache_page(unsigned long addr)
{
    wxshadow_flush_icache_range(addr & PAGE_MASK,
                                (addr & PAGE_MASK) + PAGE_SIZE);
}

/* ========== Core functions (wxshadow_core.c) ========== */

void wxshadow_page_put(struct wxshadow_page *page);
struct wxshadow_page *wxshadow_find_page(void *mm, unsigned long addr);
struct wxshadow_page *wxshadow_create_page(void *mm, unsigned long page_addr);
void wxshadow_free_page(struct wxshadow_page *page);
struct wxshadow_bp *wxshadow_find_bp(struct wxshadow_page *page_info,
                                     unsigned long addr);
void wxshadow_sync_page_tracking(struct wxshadow_page *page);
int wxshadow_validate_page_mapping(void *mm, void *vma,
                                   struct wxshadow_page *page_info,
                                   unsigned long page_addr);
int wxshadow_teardown_page(struct wxshadow_page *page, const char *reason);
int wxshadow_teardown_pages_for_mm(void *mm, const char *reason);
int wxshadow_release_page_logically(struct wxshadow_page *page,
                                    const char *reason);
int wxshadow_release_pages_for_mm(void *mm, const char *reason);
int wxshadow_handle_write_fault(void *mm, unsigned long addr);
void wxshadow_sync_shadow_exec_zero(struct wxshadow_page *page,
                                    const char *reason);
void wxshadow_mark_patch_dirty(struct wxshadow_page *page,
                               unsigned long offset,
                               unsigned long len);
void wxshadow_mark_bp_dirty(struct wxshadow_page *page, unsigned long offset);
void wxshadow_clear_bp_dirty(struct wxshadow_page *page, unsigned long offset);
bool wxshadow_page_has_patch_dirty(struct wxshadow_page *page);
void wxshadow_clear_page_tracking(struct wxshadow_page *page);
int wxshadow_restore_shadow_ranges(struct wxshadow_page *page);

/* ========== Page table functions (wxshadow_pgtable.c) ========== */

u64 *get_user_pte(void *mm, unsigned long addr, void **ptlp);
int wxshadow_try_split_pmd(void *mm, void *vma, unsigned long addr);
void wxshadow_pte_unmap_unlock(u64 *pte, void *ptl);
void wxshadow_flush_tlb_page(void *vma, unsigned long uaddr);
u64 make_pte(unsigned long pfn, u64 prot);
int wxshadow_page_activate_shadow(struct wxshadow_page *page, void *vma,
                                  unsigned long addr);
int wxshadow_page_activate_shadow_locked(struct wxshadow_page *page, void *vma,
                                         unsigned long addr);
int wxshadow_page_enter_original(struct wxshadow_page *page, void *vma,
                                 unsigned long addr);
int wxshadow_page_resume_shadow(struct wxshadow_page *page, void *vma,
                                unsigned long addr);
int wxshadow_page_begin_stepping(struct wxshadow_page *page, void *vma,
                                 unsigned long addr, void *task);
int wxshadow_page_finish_stepping(struct wxshadow_page *page, void *vma,
                                  unsigned long addr, void *task);
int wxshadow_page_restore_original_for_teardown_locked(
    struct wxshadow_page *page, void *vma, unsigned long addr);
int wxshadow_page_begin_gup_hide(struct wxshadow_page *page, void *mm,
                                 unsigned long addr, u64 **out_ptep,
                                 u64 *out_orig_pte);
int wxshadow_page_finish_gup_hide(struct wxshadow_page *page, void *vma,
                                  unsigned long addr, u64 *ptep,
                                  u64 orig_pte);
int wxshadow_page_restore_child_original_locked(struct wxshadow_page *page,
                                                void *child_mm,
                                                unsigned long addr);
int wxshadow_page_enter_dormant_locked(struct wxshadow_page *page, void *vma,
                                       unsigned long addr);

/* ========== Handlers (wxshadow_handlers.c) ========== */

void before_dup_mmap_wx(hook_fargs2_t *args, void *udata);
void after_dup_mmap_wx(hook_fargs2_t *args, void *udata);
void before_uprobe_dup_mmap_wx(hook_fargs2_t *args, void *udata);
void after_uprobe_dup_mmap_wx(hook_fargs2_t *args, void *udata);
void before_copy_process_wx(hook_fargs8_t *args, void *udata);
void after_copy_process_wx(hook_fargs8_t *args, void *udata);

int wxshadow_handle_read_fault(void *mm, unsigned long addr);
int wxshadow_handle_exec_fault(void *mm, unsigned long addr);
void do_page_fault_before(hook_fargs3_t *args, void *udata);
void follow_page_pte_before(hook_fargs5_t *args, void *udata);
void follow_page_pte_after(hook_fargs5_t *args, void *udata);
void exit_mmap_before(hook_fargs1_t *args, void *udata);
int wxshadow_brk_handler(struct pt_regs *regs, unsigned int esr);
int wxshadow_step_handler(struct pt_regs *regs, unsigned int esr);
void brk_handler_before(hook_fargs3_t *args, void *udata);
void single_step_handler_before(hook_fargs3_t *args, void *udata);

/* ========== Commands (wxshadow_bp.c) ========== */

int wxshadow_do_set_bp(void *mm, unsigned long addr);
int wxshadow_do_set_reg(void *mm, unsigned long addr,
                        unsigned int reg_idx, unsigned long value);
int wxshadow_do_del_bp(void *mm, unsigned long addr);
int wxshadow_do_patch(void *mm, unsigned long addr,
                      void __user *buf, unsigned long len);
int wxshadow_do_release(void *mm, unsigned long addr);
void prctl_before(hook_fargs4_t *args, void *udata);
long wxshadow_dispatch_membarrier(unsigned long cmd,
                                  unsigned long arg2,
                                  unsigned long arg3,
                                  unsigned long arg4,
                                  unsigned long arg5);

/* ========== Scan (wxshadow_scan.c) ========== */

int resolve_symbols(void);
int scan_mm_struct_offsets(void);
int scan_vma_struct_offsets(void);
int detect_task_struct_offsets(void);
int try_scan_mm_context_id_offset(void);
void debug_print_tasks_list(int max_count);

/* ========== Runtime entry (wxshadow_core.c) ========== */

int wxshadow_runtime_init(void);
void wxshadow_runtime_exit(void);

#endif
