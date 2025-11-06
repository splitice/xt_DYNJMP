/*
 * Copyright (c) 2010-2013 Mathew Heard <mheard@x4b.net>
 */

#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/version.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include "xt_DYNJMP.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static void dynjmp_help(void)
{
	printf(
"DYNJMP target options:\n"
" none\n"
	);
}


static void dynjmp_save(const void *ip, const struct xt_entry_target *target)
{
}

static struct xtables_target ct_target_reg[] = {
	{
		.family        = NFPROTO_UNSPEC,
		.name          = "DYNJMP",
		.revision      = 0,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_DYNJMP_target_info)),
     	.save		   = dynjmp_save,
		.userspacesize = 0,
		.help          = dynjmp_help
	},
	{
		.family        = NFPROTO_UNSPEC,
		.name          = "SYNJMP",
		.revision      = 0,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_DYNJMP_target_info)),
     	.save		   = dynjmp_save,
		.userspacesize = 0,
		.help          = dynjmp_help
	}
};

#ifndef _init
#define _init __attribute__((constructor)) _INIT
#endif
void _init(void)
{
	xtables_register_targets(ct_target_reg, ARRAY_SIZE(ct_target_reg));
}