/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
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

typedef struct pcmk_child_s {
    pid_t pid;
    int start_seq;
    int respawn_count;
    gboolean respawn;
    const char *name;
    const char *uid;
    const char *command;
    const char *endpoint;  /* IPC server name */

    gboolean active_before_startup;
} pcmk_child_t;

#define SIZEOF(a)   (sizeof(a) / sizeof(a[0]))
#define MAX_RESPAWN		100

extern GMainLoop *mainloop;
extern const char *pacemakerd_state;
extern gboolean running_with_sbd;
extern unsigned int shutdown_complete_state_reported_to;
extern gboolean shutdown_complete_state_reported_client_closed;
extern crm_trigger_t *shutdown_trigger;
extern crm_trigger_t *startup_trigger;

gboolean mcp_read_config(void);

gboolean cluster_connect_cfg(void);
gboolean cluster_disconnect_cfg(void);
void pcmkd_shutdown_corosync(void);

void pcmk_shutdown(int nsig);
crm_exit_t request_shutdown(crm_ipc_t *ipc);
