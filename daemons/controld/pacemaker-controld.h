/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRMD__H
#  define CRMD__H

#include <controld_alerts.h>
#include <controld_callbacks.h>
#include <controld_fencing.h>
#include <controld_fsa.h>
#include <controld_timers.h>
#include <controld_lrm.h>
#include <controld_membership.h>
#include <controld_messages.h>
#include <controld_metadata.h>
#include <controld_throttle.h>
#include <controld_transition.h>
#include <controld_utils.h>

typedef struct {
    // Booleans

    //! Group of \p controld_flags values
    uint32_t flags;


    // Other

    //! Cluster name
    char *cluster_name;

    //! Main event loop
    GMainLoop *mainloop;
} controld_globals_t;

extern controld_globals_t controld_globals;

/*!
 * \internal
 * \enum controld_flags
 * \brief Bit flags to store various controller state and configuration info
 */
enum controld_flags {
    //! The DC left in a membership change that is being processed
    controld_dc_left                = (1 << 0),

    //! The FSA is stalled waiting for further input
    controld_fsa_is_stalled         = (1 << 1),

    //! The local node has been in a quorate partition at some point
    controld_ever_had_quorum        = (1 << 2),

    //! The local node is currently in a quorate partition
    controld_has_quorum             = (1 << 3),

    //! Panic the local node if it loses quorum
    controld_no_quorum_suicide      = (1 << 4),

    //! Lock resources to the local node when it shuts down cleanly
    controld_shutdown_lock_enabled  = (1 << 5),
};

#  define controld_trigger_config()  \
    controld_trigger_config_as(__func__, __LINE__)

void do_cib_updated(const char *event, xmlNode * msg);
void do_cib_replaced(const char *event, xmlNode * msg);
void crmd_metadata(void);
void controld_trigger_config_as(const char *fn, int line);
void controld_election_init(const char *uname);
void controld_remove_voter(const char *uname);
void controld_election_fini(void);
void controld_set_election_period(const char *value);
void controld_stop_current_election_timeout(void);
void controld_disconnect_cib_manager(void);

#endif
