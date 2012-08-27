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
	{ 0xd42b7232, "_write_unlock_bh" },
	{ 0x5113d3a4, "malloc_sizes" },
	{ 0x90f7b293, "dev_get_by_name" },
	{ 0x4661e311, "__tracepoint_kmalloc" },
	{ 0x343a1a8, "__list_add" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x2bc95bd4, "memset" },
	{ 0xe4c1df3e, "_read_lock_bh" },
	{ 0xa2a1e5c9, "_write_lock_bh" },
	{ 0xb72397d5, "printk" },
	{ 0x2da418b5, "copy_to_user" },
	{ 0x521445b, "list_del" },
	{ 0x530550a, "init_net" },
	{ 0x6dcedb09, "kmem_cache_alloc" },
	{ 0x4df86786, "nf_unregister_sockopt" },
	{ 0x49da9a9a, "_read_unlock_bh" },
	{ 0x37a0cba, "kfree" },
	{ 0x8ad820a7, "nf_register_sockopt" },
	{ 0xf2a644fb, "copy_from_user" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "8A0AEDE65782FC6EF52C4D3");
