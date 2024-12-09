#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xf8cdd757, "module_layout" },
	{ 0xe222cb8, "param_ops_int" },
	{ 0x58d9cd11, "cdev_add" },
	{ 0x71a3afd4, "cdev_init" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x6aee3d4e, "register_netdev" },
	{ 0x83dba64c, "alloc_netdev_mqs" },
	{ 0xd9a5ea54, "__init_waitqueue_head" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x361c68dd, "cdev_del" },
	{ 0xef045c19, "free_netdev" },
	{ 0x51adffd1, "unregister_netdev" },
	{ 0x90a9fe8, "__dev_kfree_skb_any" },
	{ 0xb05be19c, "ether_setup" },
	{ 0x591e6107, "netif_rx" },
	{ 0x1030cd3d, "eth_type_trans" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x5bce0a2a, "skb_put" },
	{ 0x696246f, "__netdev_alloc_skb" },
	{ 0x27e1a049, "printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "ADB9187CBBF3206B567CD9B");
MODULE_INFO(rhelversion, "8.9");
