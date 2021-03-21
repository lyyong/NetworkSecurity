#include <linux/kern_levels.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

static int __init init_my_module(void) {
    printk(KERN_INFO "Hello world!\n");
    return 0;
}

static void __exit exit_my_module(void) {
    printk(KERN_INFO "Bye world!\n");
}

module_init(init_my_module);
module_exit(exit_my_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TEST");