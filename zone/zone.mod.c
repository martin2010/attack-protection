#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xb85014ac, "module_layout" },
	{ 0x2df172e4, "kmalloc_caches" },
	{ 0xaf8738f9, "_write_unlock_bh" },
	{ 0xdd23dc69, "dev_get_by_name" },
	{ 0x4661e311, "__tracepoint_kmalloc" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x3c3e2a70, "_read_lock_bh" },
	{ 0xc7a9c1ea, "_write_lock_bh" },
	{ 0xb72397d5, "printk" },
	{ 0x2da418b5, "copy_to_user" },
	{ 0x2c105736, "init_net" },
	{ 0x31bf85c4, "kmem_cache_alloc" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x4896966f, "nf_unregister_sockopt" },
	{ 0x13f19a0e, "_read_unlock_bh" },
	{ 0x37a0cba, "kfree" },
	{ 0x7dfda415, "nf_register_sockopt" },
	{ 0xf2a644fb, "copy_from_user" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

