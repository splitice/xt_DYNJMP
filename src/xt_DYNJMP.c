/*
 * Copyright (c) 2010 Mathew Heard <mheard@x4b.net>
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <linux/version.h>
#include "xt_DYNJMP.h"

MODULE_ALIAS("ipt_DYNJMP");
MODULE_ALIAS("ip6t_DYNJMP");
MODULE_ALIAS("xt_SYNJMP");
MODULE_ALIAS("ipt_SYNJMP");
MODULE_ALIAS("ip6t_SYNJMP");

static unsigned int
DYNJMP_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct iphdr *iph;
	
	/* This is the raw table, we will need to do some checks */
	iph = ip_hdr(skb);
	if(unlikely(iph == NULL)) return XT_DROP;
	
	uint8_t upperBytes = htonl(iph->daddr) & 0xFF;
	if(unlikely(upperBytes == 0)) return XT_CONTINUE;
	unsigned int ret = 0xFF | (upperBytes << 8);
	return ret;
}

static unsigned int
SYNJMP_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct iphdr *iph;
	
	/* This is the raw table, we will need to do some checks */
	iph = ip_hdr(skb);
	if(unlikely(iph == NULL)) return XT_DROP;
	
	uint8_t upperBytes = htonl(iph->saddr) & 0xFF;
	if(unlikely(upperBytes == 0)) return XT_CONTINUE;
	unsigned int ret = 0xFF | (upperBytes << 8);
	return ret;
}

static int DYNJMP_chk(const struct xt_tgchk_param *par)
{
	struct xt_DYNJMP_target_info *info = par->targinfo;
	pr_warn("chk entry");
	memset(info, 0, sizeof(*info));
#if LINUX_VERSION_CODE > KERNEL_VERSION(5,7,0)
	info->size = 256;
	barrier();
	info->set = 0;
	barrier();
#endif
	return 0;
}


static void xt_DYNJMP_tg_destroy_v0(const struct xt_tgdtor_param *par)
{
}

static struct xt_target dynjmp_tg_reg[] __read_mostly = {
	{
	.name		= "DYNJMP",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.checkentry	= DYNJMP_chk,
	.target		= DYNJMP_tg,
	.destroy	= xt_DYNJMP_tg_destroy_v0,
	.targetsize     = sizeof(struct xt_DYNJMP_target_info),
	.me		= THIS_MODULE
	},
	{
	.name		= "SYNJMP",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.checkentry	= DYNJMP_chk,
	.target		= SYNJMP_tg,
	.destroy	= xt_DYNJMP_tg_destroy_v0,
	.targetsize     = sizeof(struct xt_DYNJMP_target_info),
	.me		= THIS_MODULE
	}
};

static int __init xt_ct_tg_init(void)
{
	int ret;

	return xt_register_targets(dynjmp_tg_reg, ARRAY_SIZE(dynjmp_tg_reg));
}

static void __exit xt_ct_tg_exit(void)
{
	xt_unregister_targets(dynjmp_tg_reg, ARRAY_SIZE(dynjmp_tg_reg));
}

module_init(xt_ct_tg_init);
module_exit(xt_ct_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: DYNJMP target");
MODULE_ALIAS("ipt_DYNJMP");
MODULE_ALIAS("ip6t_DYNJMP");