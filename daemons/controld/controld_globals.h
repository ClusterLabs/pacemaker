/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_GLOBALS__H
#  define CONTROLD_GLOBALS__H

typedef struct {
    // Booleans

    //! Group of \p controld_flags values
    uint32_t flags;


    // Controller FSA

    //! FSA state
    enum crmd_fsa_state fsa_state;

    //! FSA actions (group of \p A_* flags)
    uint64_t fsa_actions;

    //! FSA input register contents (group of \p R_* flags)
    uint64_t fsa_input_register;

    //! FSA message queue
    GList *fsa_message_queue;


    // CIB

    //! Connection to the CIB
    cib_t *cib_conn;


    // Scheduler

    //! Reference of the scheduler request being waited on
    char *fsa_pe_ref;


    // Other

    //! Cluster name
    char *cluster_name;

    //! Designated controller name
    char *dc_name;

    //! Designated controller's Pacemaker version
    char *dc_version;

    //! Local node's node name
    char *our_nodename;

    //! Local node's UUID
    char *our_uuid;

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

#  define controld_set_global_flags(flags_to_set) do {                      \
        controld_globals.flags = pcmk__set_flags_as(__func__, __LINE__,     \
                                                    LOG_TRACE,              \
                                                    "Global", "controller", \
                                                    controld_globals.flags, \
                                                    (flags_to_set),         \
                                                    #flags_to_set);         \
    } while (0)

#  define controld_clear_global_flags(flags_to_clear) do {                  \
        controld_globals.flags                                              \
            = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Global", \
                                   "controller", controld_globals.flags,    \
                                   (flags_to_clear), #flags_to_clear);      \
    } while (0)

#endif  // ifndef CONTROLD_GLOBALS__H
