#ifndef XT_DYNJMP_H
#define XT_DYNJMP_H

#include <linux/types.h>

struct xt_DYNJMP_target_info {
    uint32_t size;
    uint32_t offsets[256];
};

#endif