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
#include "xt_DYNJMP.h"

static unsigned int
DYNJMP_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct iphdr *iph;
	
	/* This is the raw table, we will need to do some checks */
	iph = ip_hdr(skb);
	
	uint8_t upperBytes = htonl(iph->daddr) & 0xFF;
	unsigned int ret = 0xFF | (upperBytes << 8);
	return ret;
}

static int DYNJMP_chk(const struct xt_tgchk_param *par)
{
	return 0;
}


static void xt_DYNJMP_tg_destroy_v0(const struct xt_tgdtor_param *par)
{
}

static struct xt_target DYNJMP_tg_reg __read_mostly = {
	.name		= "DYNJMP",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.checkentry	= DYNJMP_chk,
	.target		= DYNJMP_tg,
	.destroy	= xt_DYNJMP_tg_destroy_v0,
	.targetsize     = sizeof(struct xt_DYNJMP_target_info),
	.me		= THIS_MODULE,
};

static int __init xt_ct_tg_init(void)
{
	int ret;

	ret = xt_register_target(&DYNJMP_tg_reg);
	if (ret < 0)
		return ret;

	return 0;
}

static void __exit xt_ct_tg_exit(void)
{
	xt_unregister_target(&DYNJMP_tg_reg);
}

module_init(xt_ct_tg_init);
module_exit(xt_ct_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: DYNJMP target");
MODULE_ALIAS("ipt_DYNJMP");
MODULE_ALIAS("ip6t_DYNJMP");