/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_GLOBALS__H
#  define CONTROLD_GLOBALS__H

#include <crm_internal.h>       // pcmk__output_t, etc.

#include <stdint.h>             // uint32_t, uint64_t
#include <glib.h>               // GList, GMainLoop
#include <crm/cib.h>            // cib_t
#include <pacemaker-internal.h> // pcmk__graph_t
#include <controld_fsa.h>       // enum crmd_fsa_state

typedef struct {
    // Group of \p controld_flags values
    uint32_t flags;


    /* Controller finite state automaton */

    // FSA state
    enum crmd_fsa_state fsa_state;

    // FSA actions (group of \p A_* flags)
    uint64_t fsa_actions;

    // FSA input register contents (group of \p R_* flags)
    uint64_t fsa_input_register;

    // FSA message queue
    GList *fsa_message_queue;


    /* CIB */

    // Connection to the CIB
    cib_t *cib_conn;


    /* Scheduler */

    // Reference of the scheduler request being waited on
    char *fsa_pe_ref;


    /* Transitioner */

    // Transitioner UUID
    char *te_uuid;

    // Graph of transition currently being processed
    pcmk__graph_t *transition_graph;


    /* Logging */

    // Output object for controller log messages
    pcmk__output_t *logger_out;


    /* Cluster layer */

    // Cluster name
    char *cluster_name;

    // Cluster connection
    pcmk_cluster_t *cluster;

    /* @TODO Figure out, document, and clean up the code involving
     * controld_globals.membership_id, controld_globals.peer_seq, and
     * highest_seq. It's convoluted with no comments. It has something to do
     * with corosync quorum notifications and the current ring ID, but it's
     * unclear why we need three separate variables for it.
     */
    // Last saved cluster communication layer membership ID
    unsigned long long membership_id;

    unsigned long long peer_seq;


    /* Other */

    // Designated controller name
    char *dc_name;

    // Designated controller's Pacemaker version
    char *dc_version;

    // Local node's UUID
    char *our_uuid;

    // Max lifetime (in seconds) of a resource's shutdown lock to a node
    guint shutdown_lock_limit;

    // Node pending timeout
    guint node_pending_timeout;

    // Main event loop
    GMainLoop *mainloop;
} controld_globals_t;

extern controld_globals_t controld_globals;

/*!
 * \internal
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
    controld_no_quorum_panic        = (1 << 4),

    //! Lock resources to the local node when it shuts down cleanly
    controld_shutdown_lock_enabled  = (1 << 5),
};

#  define controld_set_global_flags(flags_to_set) do {                      \
        controld_globals.flags = pcmk__set_flags_as(__func__, __LINE__,     \
                                                    PCMK__LOG_TRACE,        \
                                                    "Global", "controller", \
                                                    controld_globals.flags, \
                                                    (flags_to_set),         \
                                                    #flags_to_set);         \
    } while (0)

#  define controld_clear_global_flags(flags_to_clear) do {                    \
        controld_globals.flags = pcmk__clear_flags_as(__func__, __LINE__,     \
                                                      PCMK__LOG_TRACE,        \
                                                      "Global", "controller", \
                                                      controld_globals.flags, \
                                                      (flags_to_clear),       \
                                                      #flags_to_clear);       \
    } while (0)

#endif  // ifndef CONTROLD_GLOBALS__H
