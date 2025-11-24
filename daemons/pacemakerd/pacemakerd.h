/*
 * Copyright 2010-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#define MAX_RESPAWN		100

extern GMainLoop *mainloop;
extern const char *pacemakerd_state;
extern bool running_with_sbd;
extern bool shutdown_complete_state_reported_client_closed;
extern unsigned int shutdown_complete_state_reported_to;
extern crm_trigger_t *shutdown_trigger;
extern crm_trigger_t *startup_trigger;
extern time_t subdaemon_check_progress;

int find_and_track_existing_processes(void);
gboolean init_children_processes(void *user_data);
void pcmk_shutdown(int nsig);
void restart_cluster_subdaemons(void);

void pacemakerd_ipc_init(void);
void pacemakerd_ipc_cleanup(void);
void pacemakerd_unregister_handlers(void);
void pacemakerd_handle_request(pcmk__request_t *request);
