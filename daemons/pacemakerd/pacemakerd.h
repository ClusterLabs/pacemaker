/*
 * Copyright 2010-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <stdint.h>

#include <crm/crm.h>
#include <crm/common/xml.h>

#define SIZEOF(a)   (sizeof(a) / sizeof(a[0]))
#define MAX_RESPAWN		100

gboolean mcp_read_config(void);

gboolean cluster_connect_cfg(uint32_t * nodeid);
gboolean cluster_disconnect_cfg(void);

void pcmk_shutdown(int nsig);

void sysrq_init(void);
