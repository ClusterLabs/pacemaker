/*
 * Copyright 2013-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_REMOTE_RA_H
#define CONTROLD_REMOTE_RA_H

#include <crm_internal.h>

#include <stdint.h>                 // uint32_t
#include <time.h>                   // time_t

#include <glib.h>                   // GList, guint

#include <crm/lrmd.h>               // lrmd_key_value_t
#include <crm/common/mainloop.h>    // crm_trigger_t

typedef struct {
    /*! the local node the cmd is issued from */
    char *owner;
    /*! the remote node the cmd is executed on */
    char *rsc_id;
    /*! the action to execute */
    char *action;
    /*! some string the client wants us to give it back */
    char *userdata;
    /*! start delay in ms */
    int start_delay;
    /*! timer id used for start delay. */
    int delay_id;
    /*! timeout in ms for cmd */
    int timeout;
    /*! recurring interval in ms */
    guint interval_ms;
    /*! interval timer id */
    int interval_id;
    int monitor_timeout_id;
    int takeover_timeout_id;
    /*! action parameters */
    lrmd_key_value_t *params;
    pcmk__action_result_t result;
    int call_id;
    time_t start_time;
    uint32_t status;
} remote_ra_cmd_t;

typedef struct {
    crm_trigger_t *work;
    remote_ra_cmd_t *cur_cmd;
    GList *cmds;
    GList *recurring_cmds;
    uint32_t status;
} remote_ra_data_t;

#endif  // CONTROLD_REMOTE_RA_H
