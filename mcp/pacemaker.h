/* 
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <crm/crm.h>
#include <crm/common/xml.h>

#define SIZEOF(a)   (sizeof(a) / sizeof(a[0]))
#define crm_flag_none		0x00000000
#define crm_flag_members	0x00000001
#define MAX_RESPAWN		100
#define PW_BUFFER_LEN		500

extern uint32_t local_nodeid;

typedef struct pcmk_peer_s 
{
	uint32_t id;
	uint32_t processes;
	char *uname;
} pcmk_peer_t;

extern gboolean read_config(void);

extern gboolean cluster_connect_cfg(uint32_t *nodeid);
extern gboolean cluster_disconnect_cfg(void);

extern gboolean cluster_connect_cpg(void);
extern gboolean cluster_disconnect_cpg(void);
extern gboolean send_cpg_message(struct iovec *iov);

extern void update_process_clients(void);
extern void update_process_peers(pcmk_peer_t *node);
extern gboolean update_node_processes(uint32_t node, const char *uname, uint32_t procs);

extern char *get_local_node_name(void);

