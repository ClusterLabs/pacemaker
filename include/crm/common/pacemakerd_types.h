/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PACEMAKERD_TYPES__H
#  define PACEMAKERD_TYPES__H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>

enum pacemakerd_conn_state {
    pacemakerd_conn_connected,
    pacemakerd_conn_disconnected
};

enum pacemakerd_state {
    pacemakerd_state_invalid = -1,
    pacemakerd_state_init = 0,
    pacemakerd_state_starting_daemons,
    pacemakerd_state_wait_for_ping,
    pacemakerd_state_running,
    pacemakerd_state_shutting_down,
    pacemakerd_state_shutdown_complete,
    pacemakerd_state_max = pacemakerd_state_shutdown_complete,
};

typedef struct pacemakerd_s pacemakerd_t;

typedef struct pacemakerd_api_operations_s {
    int (*connect) (pacemakerd_t *pacemakerd, const char *name);
    int (*disconnect) (pacemakerd_t *pacemakerd);
    void (*free) (pacemakerd_t *pacemakerd);
    int (*set_ping_callback) (pacemakerd_t *pacemakerd,
                              void (*callback) (pacemakerd_t *pacemakerd,
                                                time_t last_good,
                                                enum pacemakerd_state state,
                                                int rc, gpointer userdata),
                              gpointer userdata);
    int (*set_disconnect_callback) (pacemakerd_t *pacemakerd,
                                    void (*callback) (gpointer userdata),
                                    gpointer userdata
                                    );
    int (*ping) (pacemakerd_t *pacemakerd, const char *name,
                 const char *admin_uuid, int call_options);
} pacemakerd_api_operations_t;

struct pacemakerd_s {
    enum pacemakerd_conn_state conn_state;
    void *pacemakerd_private;
    pacemakerd_api_operations_t *cmds;
};

pacemakerd_t * pacemakerd_api_new(void);
void pacemakerd_api_delete(pacemakerd_t * pacemakerd);
enum pacemakerd_state pacemakerd_state_text2enum(const char *state);
const char *pacemakerd_state_enum2text(enum pacemakerd_state state);

#ifdef __cplusplus
}
#endif

#endif // PACEMAKERD_TYPES__H