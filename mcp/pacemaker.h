/* 
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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
#define crm_flag_none		0x00000000
#define crm_flag_members	0x00000001
#define MAX_RESPAWN		100

extern uint32_t local_nodeid;

gboolean mcp_read_config(void);

gboolean cluster_connect_cfg(uint32_t * nodeid);
gboolean cluster_disconnect_cfg(void);

gboolean update_node_processes(uint32_t node, const char *uname, uint32_t procs);

void enable_mgmtd(gboolean enable);
void enable_crmd_as_root(gboolean enable);

void pcmk_shutdown(int nsig);

void mcp_make_realtime(int priority, int stackgrowK, int heapgrowK);
void sysrq_init(void);

int watchdog_init(const char *device, int interval, int mode);
int watchdog_tickle(void);
void watchdog_close(void);

void do_crashdump(void);
void do_reset(void);
void do_off(void);



