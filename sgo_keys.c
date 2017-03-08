/*
 *  bugficks@samygo
 *      (c) 2016 - inf
 *
 *  License: GPLv2
 *
 *  CONFIG_KEYS as module for Samsung HAWKM/P.
 *  Required for cifs/nfs.
 *
 *  includes sources from security/keys/
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define LOG_PREFIX " [SGO_KEYS] "

//for some reason THIS_MODULE->version doesn't show "version" anymore
#define _MODULE_VERSION "0.1.0"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef CONFIG_KEYS
#error CONFIG_KEYS
#endif

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/key.h>
#include <linux/integrity.h>
#include <linux/ima.h>
#include <linux/evm.h>
#include <linux/fsnotify.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/personality.h>
#include <linux/backing-dev.h>
#include <linux/tracehook.h>
#include <linux/syscalls.h>
#include <net/flow.h>

#include "utils.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

MODULE_DESCRIPTION("CONFIG_KEYS as module");
MODULE_AUTHOR("bugficks@samygo");
MODULE_VERSION(_MODULE_VERSION);
MODULE_LICENSE("GPL");

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static struct security_operations *__security_ops = 0;
static rwlock_t *__tasklist_lock = 0;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct cred *(*cred_alloc_blank_t)(void);
static cred_alloc_blank_t __cred_alloc_blank = 0;
static struct cred *sgo_cred_alloc_blank(void);

typedef struct callback_head *(*task_work_cancel_t)(
		struct task_struct *task, task_work_func_t func);
static task_work_cancel_t __task_work_cancel = 0;
static struct callback_head *sgo_task_work_cancel(
		struct task_struct *task, task_work_func_t func);

typedef int (*task_work_add_t)(struct task_struct *task, struct callback_head *work, bool notify);
static task_work_add_t __task_work_add = 0;
static int sgo_task_work_add(struct task_struct *task, struct callback_head *work, bool notify);


typedef ssize_t (*rw_copy_check_uvector_t)(
		int type, const struct iovec __user * uvector, unsigned long nr_segs, unsigned long fast_segs,
		struct iovec *fast_pointer, struct iovec **ret_pointer);
static rw_copy_check_uvector_t __rw_copy_check_uvector = 0;
static ssize_t sgo_rw_copy_check_uvector(
		int type, const struct iovec __user * uvector, unsigned long nr_segs, unsigned long fast_segs,
		struct iovec *fast_pointer, struct iovec **ret_pointer);


typedef int (*groups_search_t)(
		const struct group_info *group_info, kgid_t grp);
static groups_search_t __groups_search = 0;
static int sgo_groups_search(
		const struct group_info *group_info, kgid_t grp);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define tasklist_lock           (*__tasklist_lock)
#define cred_alloc_blank        sgo_cred_alloc_blank
#define task_work_cancel        sgo_task_work_cancel
#define task_work_add           sgo_task_work_add

#define rw_copy_check_uvector   sgo_rw_copy_check_uvector
#define groups_search           sgo_groups_search

#include <security/keys/gc.c>
#include <security/keys/key.c>
#include <security/keys/keyring.c>
#include <security/keys/keyctl.c>
#include <security/keys/permission.c>
#include <security/keys/process_keys.c>
#include <security/keys/request_key.c>
#include <security/keys/request_key_auth.c>
#include <security/keys/user_defined.c>

#ifdef CONFIG_PROC_FS
#pragma push_macro("__initcall")
#undef __initcall
#define __initcall(A)
#include <security/keys/proc.c>
#pragma pop_macro("__initcall")
#endif

#ifdef CONFIG_SYSCTL
#include <security/keys/sysctl.c>
#endif

#undef tasklist_lock
#undef cred_alloc_blank
#undef task_work_cancel
#undef task_work_add

#undef rw_copy_check_uvector
#undef groups_search

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// security/capability.c

static int cap_key_alloc(
		struct key *key, const struct cred *cred, unsigned long flags)
{
    return 0;
}

static void cap_key_free(
		struct key *key)
{
}

static int cap_key_permission(
		key_ref_t key_ref, const struct cred *cred, key_perm_t perm)
{
    return 0;
}

static int cap_key_getsecurity(
		struct key *key, char **_buffer)
{
    *_buffer = NULL;
    return 0;
}

static int cap_cred_alloc_blank(
		struct cred *cred, gfp_t gfp)
{
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// security/security.c

void security_transfer_creds(
		struct cred *new, const struct cred *old)
{
    if(__security_ops->cred_transfer)
	    __security_ops->cred_transfer(new, old);
}

int security_key_alloc(
		struct key *key, const struct cred *cred, unsigned long flags)
{
    if(!__security_ops->key_alloc)
        return cap_key_alloc(key, cred, flags);
	return __security_ops->key_alloc(key, cred, flags);
}

void security_key_free(
		struct key *key)
{
    if(!__security_ops->key_free)
        return cap_key_free(key);
	__security_ops->key_free(key);
}

int security_key_permission(
		key_ref_t key_ref, const struct cred *cred, key_perm_t perm)
{
    if(!__security_ops->key_permission)
        return cap_key_permission(key_ref, cred, perm);
	return __security_ops->key_permission(key_ref, cred, perm);
}

int security_key_getsecurity(
		struct key *key, char **_buffer)
{
    if(!__security_ops->key_getsecurity)
        return cap_key_getsecurity(key, _buffer);
	return __security_ops->key_getsecurity(key, _buffer);
}

int security_cred_alloc_blank(
		struct cred *cred, gfp_t gfp)
{
    if(!__security_ops->cred_alloc_blank)
        return cap_cred_alloc_blank(cred, gfp);
	return __security_ops->cred_alloc_blank(cred, gfp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// kernel/cred.c

struct cred *sgo_cred_alloc_blank(void)
{
	return __cred_alloc_blank();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// fs/read_write.c

ssize_t sgo_rw_copy_check_uvector(
		int type, const struct iovec __user * uvector, unsigned long nr_segs, unsigned long fast_segs,
		struct iovec *fast_pointer, struct iovec **ret_pointer)
{
	return __rw_copy_check_uvector(type, uvector, nr_segs, fast_segs, fast_pointer, ret_pointer);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// kernel/groups.c

int sgo_groups_search(
		const struct group_info *group_info, kgid_t grp)
{
	return __groups_search(group_info, grp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// kernel/task_work.c

struct callback_head *sgo_task_work_cancel(
		struct task_struct *task, task_work_func_t func)
{
	return __task_work_cancel(task, func);
}

int sgo_task_work_add(
		struct task_struct *task, struct callback_head *work, bool notify)
{
	return __task_work_add(task, work, notify);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static uintptr_t search_addr_security_ops(void)
{
    static uintptr_t ploc = 0;
    if(ploc)
        return ploc;

    const u32 *ppp = (const u32*)security_sb_copy_data;
    int i;
    for(i = 0; i < 5; i++)
    {
        if(((ppp[i] & 0xFFFF0000) >> 16)  == 0xE59F)
        {
            ploc = (uintptr_t)arm_ldr_get_label_addr((u8 *)(ppp + i));
            return ploc;
        }
    }

    return 0;
}

static uintptr_t search_addr_tasklist_lock(void)
{
	// HKM
    // .text:C0041484             sys_ptrace
	// HKP
    // .text:C00428A8             sys_ptrace
	static const u8 search_pat_HKX[20] =
	{
        0x0D, 0xC0, 0xA0, 0xE1, 0xF0, 0xDB, 0x2D, 0xE9, 0x04, 0xB0, 0x4C, 0xE2, 0x00, 0x60, 0x50, 0xE2,
        0x01, 0x40, 0xA0, 0xE1,
	};

    sgo_addr_search_t saddr[] =
    {
#ifdef CONFIG_ARCH_SDP1406
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC0041000, 0x1000 },
#endif
#ifdef CONFIG_ARCH_SDP1404
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC0042200, 0x1000 },
#endif
    };

    static uintptr_t ploc = 0;
    if(ploc)
        return ploc;

    const u32 *ppp = (const u32*)sgo_addr_search(saddr, ARRAY_SIZE(saddr));//sys_ptrace;
    if(!ppp)
        return 0;

    int i;
    for(i = 0; i < 10; i++)
    {
        if(((ppp[i] & 0xFFFF0000) >> 16)  == 0xE59F)
        {
            ploc = (uintptr_t)arm_ldr_get_label_addr((u8 *)(ppp + i));
            return ploc;
        }
    }

    return 0;
}

static uintptr_t search_addr_cred_alloc_blank(void)
{
	// HKM
    // .text:C00593C8             cred_alloc_blank
	// HKP
	// .text:C005A794             cred_alloc_blank
	static const u8 search_pat_HKX[20] =
	{
        0x0D, 0xC0, 0xA0, 0xE1, 0x30, 0xD8, 0x2D, 0xE9, 0x04, 0xB0, 0x4C, 0xE2, 0x3C, 0x30, 0x9F, 0xE5,
        0xD0, 0x10, 0x08, 0xE3,
	};

    sgo_addr_search_t saddr[] =
    {
#ifdef CONFIG_ARCH_SDP1406
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC0059000, 0x1000 },
#endif
#ifdef CONFIG_ARCH_SDP1404
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC005A000, 0x1000 },
#endif
    };

    static uintptr_t ploc = 0;
    if(ploc)
        return ploc;

	ploc = sgo_addr_search(saddr, ARRAY_SIZE(saddr));

    return ploc;
}


static uintptr_t search_addr_task_work_cancel(void)
{
	// .text:C00507A4             task_work_cancel                        ; CODE XREF: irq_thread+150p
	static const u8 search_pat_HKM[20] =
	{
		0x0D, 0xC0, 0xA0, 0xE1, 0xF0, 0xD8, 0x2D, 0xE9, 0x04, 0xB0, 0x4C, 0xE2, 0xAF, 0x6F, 0x80, 0xE2,
		0xAA, 0x5F, 0x80, 0xE2,
	};

	// .text:C0051BC4                         task_work_cancel                        ; CODE XREF: irq_thread+150p
	static const u8 search_pat_HKP[20] =
	{
		0x0D, 0xC0, 0xA0, 0xE1, 0xF0, 0xD8, 0x2D, 0xE9, 0x04, 0xB0, 0x4C, 0xE2, 0xB3, 0x6F, 0x80, 0xE2,
		0xAE, 0x5F, 0x80, 0xE2,
	};

    sgo_addr_search_t saddr[] =
    {
#ifdef CONFIG_ARCH_SDP1406
        { sizeof(search_pat_HKM), search_pat_HKM, 0xC0050000, 0x1000 },
#endif
#ifdef CONFIG_ARCH_SDP1404
        { sizeof(search_pat_HKP), search_pat_HKP, 0xC0051000, 0x1000 },
#endif
    };

    static uintptr_t ploc = 0;
    if(ploc)
        return ploc;

	ploc = sgo_addr_search(saddr, ARRAY_SIZE(saddr));

    return ploc;
}

static uintptr_t search_addr_task_work_add(void)
{
	// HKM
	// .text:C0050714             task_work_add                           ; CODE XREF: irq_thread+54p
	// HKP
	// .text:C0051B34             task_work_add                           ; CODE XREF: irq_thread+54p
	static const u8 search_pat_HKX[20] =
	{
		0x0D, 0xC0, 0xA0, 0xE1, 0x30, 0xD8, 0x2D, 0xE9, 0x04, 0xB0, 0x4C, 0xE2, 0x78, 0xE0, 0x9F, 0xE5,
		0x00, 0x40, 0xA0, 0xE1,
	};

    sgo_addr_search_t saddr[] =
    {
#ifdef CONFIG_ARCH_SDP1406
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC0050000, 0x1000 },
#endif
#ifdef CONFIG_ARCH_SDP1404
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC0051000, 0x1000 },
#endif
    };

    static uintptr_t ploc = 0;
    if(ploc)
        return ploc;

	ploc = sgo_addr_search(saddr, ARRAY_SIZE(saddr));

    return ploc;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static uintptr_t search_addr_rw_copy_check_uvector(void)
{
	// HKM
    // .text:C00D04EC             rw_copy_check_uvector                   ; CODE XREF: do_readv_writev+48p
	// HKP
    // .text:C00D4C04             rw_copy_check_uvector                   ; CODE XREF: do_readv_writev+48p
	static const u8 search_pat_HKX[20] =
	{
        0x0D, 0xC0, 0xA0, 0xE1, 0xF0, 0xDB, 0x2D, 0xE9, 0x04, 0xB0, 0x4C, 0xE2, 0x00, 0x00, 0x52, 0xE3,
        0x00, 0x70, 0xA0, 0xE1,
	};

    sgo_addr_search_t saddr[] =
    {
#ifdef CONFIG_ARCH_SDP1406
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC00D0000, 0x1000 },
#endif
#ifdef CONFIG_ARCH_SDP1404
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC00D4000, 0x1000 },
#endif
    };

    static uintptr_t ploc = 0;
    if(ploc)
        return ploc;

	ploc = sgo_addr_search(saddr, ARRAY_SIZE(saddr));

    return ploc;
}

static uintptr_t search_addr_groups_search(void)
{
	// HKM
    // .text:C005A190             groups_search                           ; CODE XREF: in_group_p+34p
	// HKP
    // .text:C005B55C             groups_search                           ; CODE XREF: in_group_p+34p
	static const u8 search_pat_HKX[20] =
	{
        0x0D, 0xC0, 0xA0, 0xE1, 0x10, 0xD8, 0x2D, 0xE9, 0x04, 0xB0, 0x4C, 0xE2, 0x00, 0x00, 0x50, 0xE3,
        0x10, 0xA8, 0x9D, 0x08,
	};

    sgo_addr_search_t saddr[] =
    {
#ifdef CONFIG_ARCH_SDP1406
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC005A000, 0x1000 },
#endif
#ifdef CONFIG_ARCH_SDP1404
        { sizeof(search_pat_HKX), search_pat_HKX, 0xC005B000, 0x1000 },
#endif
    };

    static uintptr_t ploc = 0;
    if(ploc)
        return ploc;

	ploc = sgo_addr_search(saddr, ARRAY_SIZE(saddr));

    return ploc;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int __init key_proc_exit(void)
{
#ifdef CONFIG_KEYS_DEBUG_PROC_KEYS
	remove_proc_entry("keys", NULL);
#endif

    remove_proc_entry("key-users", NULL);

    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define ADDR_VERIFY(A) \
    if(!__ ## A) \
    { \
        pr_err(LOG_PREFIX"Error getting address of " #A "\n"); \
        return -EINVAL; \
    }

#define ADDR_INIT(T, A) \
    __ ## A = (T)search_addr_ ## A(); \
    pr_err(LOG_PREFIX #A ": %p\n", __ ## A);

int __init sgo_key_init(void)
{
    pr_err(LOG_PREFIX"=============================================================\n");
    pr_err(LOG_PREFIX"%s v%s - (c) bugficks 2016 - inf\n", THIS_MODULE->name, _MODULE_VERSION);
    pr_err(LOG_PREFIX"CONFIG_KEYS as module (because sectroyer has no clue :P)");

    ADDR_INIT(struct security_operations *, security_ops);
    ADDR_INIT(cred_alloc_blank_t, cred_alloc_blank);
    ADDR_INIT(task_work_cancel_t, task_work_cancel);
    ADDR_INIT(task_work_add_t, task_work_add);
    ADDR_INIT(rwlock_t *, tasklist_lock);

    ADDR_INIT(rw_copy_check_uvector_t, rw_copy_check_uvector);
    ADDR_INIT(groups_search_t, groups_search);

    ADDR_VERIFY(security_ops);
    ADDR_VERIFY(cred_alloc_blank);
    ADDR_VERIFY(task_work_cancel);
    ADDR_VERIFY(task_work_add);
    ADDR_VERIFY(tasklist_lock);

    ADDR_VERIFY(rw_copy_check_uvector);
    ADDR_VERIFY(groups_search);

    key_init();
    key_proc_init();

    pr_err(LOG_PREFIX"=============================================================\n");

    return 0;
}


static void __exit sgo_key_exit(void)
{
    pr_err(LOG_PREFIX"=============================================================\n");
    pr_err(LOG_PREFIX"%s exiting\n", THIS_MODULE->name);

    key_proc_exit();

    kmem_cache_destroy(key_jar);

    pr_err(LOG_PREFIX"=============================================================\n");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

module_init(sgo_key_init);
module_exit(sgo_key_exit);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
