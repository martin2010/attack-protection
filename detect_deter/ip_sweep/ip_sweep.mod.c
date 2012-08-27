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
	{ 0x583db676, "module_layout" },
	{ 0x8ad820a7, "nf_register_sockopt" },
	{ 0x890d41c6, "nf_register_hooks" },
	{ 0x37a0cba, "kfree" },
	{ 0x434e9620, "zone_put" },
	{ 0x2da418b5, "copy_to_user" },
	{ 0x49da9a9a, "_read_unlock_bh" },
	{ 0xe4c1df3e, "_read_lock_bh" },
	{ 0x4696d578, "zone_get_by_name" },
	{ 0xf2a644fb, "copy_from_user" },
	{ 0xd42b7232, "_write_unlock_bh" },
	{ 0x343a1a8, "__list_add" },
	{ 0x4661e311, "__tracepoint_kmalloc" },
	{ 0x6dcedb09, "kmem_cache_alloc" },
	{ 0x5113d3a4, "malloc_sizes" },
	{ 0xb72397d5, "printk" },
	{ 0x7d11c268, "jiffies" },
	{ 0xa2a1e5c9, "_write_lock_bh" },
	{ 0xdf50c605, "nf_unregister_hooks" },
	{ 0x4df86786, "nf_unregister_sockopt" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=zone";


MODULE_INFO(srcversion, "E5B8BFE720CAE870810DB85");
