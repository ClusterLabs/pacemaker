/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_IPC_PACEMAKERD__H
#  define PCMK__CRM_COMMON_IPC_PACEMAKERD__H

#include <sys/types.h>       // time_t
#include <crm/common/ipc.h>  // pcmk_ipc_api_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief IPC commands for Pacemakerd
 *
 * \ingroup core
 */

enum pcmk_pacemakerd_state {
    pcmk_pacemakerd_state_invalid = -1,
    pcmk_pacemakerd_state_init = 0,
    pcmk_pacemakerd_state_starting_daemons,
    pcmk_pacemakerd_state_wait_for_ping,
    pcmk_pacemakerd_state_running,
    pcmk_pacemakerd_state_shutting_down,
    pcmk_pacemakerd_state_shutdown_complete,
    pcmk_pacemakerd_state_remote,
    pcmk_pacemakerd_state_max = pcmk_pacemakerd_state_remote,
};

//! Possible types of pacemakerd replies
enum pcmk_pacemakerd_api_reply {
    pcmk_pacemakerd_reply_unknown,
    pcmk_pacemakerd_reply_ping,
    pcmk_pacemakerd_reply_shutdown,
};

/*!
 * Pacemakerd reply passed to event callback
 */
typedef struct {
    enum pcmk_pacemakerd_api_reply reply_type;

    union {
        // pcmk_pacemakerd_reply_ping
        struct {
            const char *sys_from;
            enum pcmk_pacemakerd_state state;
            time_t last_good;
            int status;
        } ping;
        // pcmk_pacemakerd_reply_shutdown
        struct {
            int status;
        } shutdown;
    } data;
} pcmk_pacemakerd_api_reply_t;

int pcmk_pacemakerd_api_ping(pcmk_ipc_api_t *api, const char *ipc_name);
int pcmk_pacemakerd_api_shutdown(pcmk_ipc_api_t *api, const char *ipc_name);

enum pcmk_pacemakerd_state
    pcmk_pacemakerd_api_daemon_state_text2enum(const char *state);
const char
    *pcmk_pacemakerd_api_daemon_state_enum2text(enum pcmk_pacemakerd_state state);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_IPC_PACEMAKERD__H
