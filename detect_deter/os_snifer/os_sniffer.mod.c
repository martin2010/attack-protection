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
	{ 0x434e9620, "zone_put" },
	{ 0x2da418b5, "copy_to_user" },
	{ 0x4696d578, "zone_get_by_name" },
	{ 0xf2a644fb, "copy_from_user" },
	{ 0xb72397d5, "printk" },
	{ 0xdf50c605, "nf_unregister_hooks" },
	{ 0x4df86786, "nf_unregister_sockopt" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=zone";


MODULE_INFO(srcversion, "9B5DCD7630123E2EA77B60B");
