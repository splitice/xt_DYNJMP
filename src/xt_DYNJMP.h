#ifndef XT_DYNJMP_H
#define XT_DYNJMP_H

#include <linux/types.h>

struct xt_DYNJMP_target_info {
#if LINUX_VERSION_CODE > KERNEL_VERSION(5,7,0)
    uint32_t size;
#endif
    uint32_t offsets[256];
};

#endif