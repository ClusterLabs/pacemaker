/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>

typedef struct pcmk_child_s {
    pid_t pid;
    int start_seq;
    int respawn_count;
    bool respawn;
    const char *name;
    const char *uid;
    const char *command;
    const char *endpoint;  /* IPC server name */
    bool needs_cluster;

    bool active_before_startup;
} pcmk_child_t;

#define SIZEOF(a)   (sizeof(a) / sizeof(a[0]))
#define MAX_RESPAWN		100

extern GMainLoop *mainloop;
extern struct qb_ipcs_service_handlers mcp_ipc_callbacks;
extern const char *pacemakerd_state;
extern gboolean running_with_sbd;
extern unsigned int shutdown_complete_state_reported_to;
extern gboolean shutdown_complete_state_reported_client_closed;
extern crm_trigger_t *shutdown_trigger;
extern crm_trigger_t *startup_trigger;

gboolean mcp_read_config(void);

gboolean cluster_connect_cfg(void);
void cluster_disconnect_cfg(void);
int find_and_track_existing_processes(void);
gboolean init_children_processes(void *user_data);
void pcmk_shutdown(int nsig);
void pcmk_handle_ping_request(pcmk__client_t *c, xmlNode *msg, uint32_t id);
void pcmk_handle_shutdown_request(pcmk__client_t *c, xmlNode *msg, uint32_t id, uint32_t flags);
void pcmkd_shutdown_corosync(void);
