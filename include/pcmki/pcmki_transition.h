/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_TRANSITION__H
#define PCMK__PCMKI_PCMKI_TRANSITION__H

#include <stdbool.h>                    // bool
#include <stdint.h>                     // uint32_t
#include <sys/types.h>                  // time_t
#include <glib.h>                       // guint, GList, GHashTable
#include <libxml/tree.h>                // xmlNode

#include <crm/common/scheduler_types.h> // pcmk_scheduler_t
#include <crm/lrmd_events.h>            // lrmd_event_data_t

#ifdef __cplusplus
extern "C" {
#endif

enum pcmk__graph_action_type {
    pcmk__pseudo_graph_action,
    pcmk__rsc_graph_action,
    pcmk__cluster_graph_action,
    /* @TODO maybe separate a new pcmk__fencing_graph_action from
     * pcmk__cluster_graph_action to make code cleaner (for example, see
     * initiate_action())
     */
};

enum pcmk__synapse_flags {
    pcmk__synapse_ready       = (1 << 0),
    pcmk__synapse_failed      = (1 << 1),
    pcmk__synapse_executed    = (1 << 2),
    pcmk__synapse_confirmed   = (1 << 3),
};

typedef struct {
    int id;
    int priority;

    uint32_t flags; // Group of pcmk__synapse_flags

    GList *actions;           /* pcmk__graph_action_t* */
    GList *inputs;            /* pcmk__graph_action_t* */
} pcmk__graph_synapse_t;

#define pcmk__set_synapse_flags(synapse, flags_to_set) do {             \
        (synapse)->flags = pcmk__set_flags_as(__func__, __LINE__,       \
            LOG_TRACE,                                                  \
            "Synapse", "synapse",                       \
            (synapse)->flags, (flags_to_set), #flags_to_set);           \
    } while (0)

#define pcmk__clear_synapse_flags(synapse, flags_to_clear) do {         \
        (synapse)->flags = pcmk__clear_flags_as(__func__, __LINE__,     \
            LOG_TRACE,                                                  \
            "Synapse", "synapse",                      \
            (synapse)->flags, (flags_to_clear), #flags_to_clear);       \
    } while (0)

enum pcmk__graph_action_flags {
    pcmk__graph_action_sent_update   = (1 << 0),     /* sent to the CIB */
    pcmk__graph_action_executed      = (1 << 1),     /* sent to the CRM */
    pcmk__graph_action_confirmed     = (1 << 2),
    pcmk__graph_action_failed        = (1 << 3),
};

typedef struct {
    int id;
    int timeout;
    int timer;
    guint interval_ms;
    GHashTable *params;
    enum pcmk__graph_action_type type;
    pcmk__graph_synapse_t *synapse;

    uint32_t flags; // Group of pcmk__graph_action_flags

    xmlNode *xml;

} pcmk__graph_action_t;

#define pcmk__set_graph_action_flags(action, flags_to_set) do {       \
        (action)->flags = pcmk__set_flags_as(__func__, __LINE__,      \
            LOG_TRACE,                                                \
            "Action", "action",                                       \
            (action)->flags, (flags_to_set), #flags_to_set);          \
    } while (0)

#define pcmk__clear_graph_action_flags(action, flags_to_clear) do {   \
        (action)->flags = pcmk__clear_flags_as(__func__, __LINE__,    \
            LOG_TRACE,                                                \
            "Action", "action",                                       \
            (action)->flags, (flags_to_clear), #flags_to_clear);      \
    } while (0)

// What to do after finished processing a transition graph
enum pcmk__graph_next {
    // Order matters: lowest priority to highest
    pcmk__graph_done,       // Transition complete, nothing further needed
    pcmk__graph_wait,       // Transition interrupted, wait for further changes
    pcmk__graph_restart,    // Transition interrupted, start a new one
    pcmk__graph_shutdown,   // Transition interrupted, local shutdown needed
};

typedef struct {
    int id;
    char *source;
    int abort_priority;

    bool complete;
    const char *abort_reason;
    enum pcmk__graph_next completion_action;

    int num_actions;
    int num_synapses;

    int batch_limit;
    guint network_delay;
    guint stonith_timeout;

    int fired;
    int pending;
    int skipped;
    int completed;
    int incomplete;

    GList *synapses;          /* pcmk__graph_synapse_t* */

    int migration_limit;

    //! Failcount after one failed stop action
    char *failed_stop_offset;

    //! Failcount after one failed start action
    char *failed_start_offset;

    //! Time (from epoch) by which the controller should re-run the scheduler
    time_t recheck_by;
} pcmk__graph_t;


typedef struct {
    int (*pseudo) (pcmk__graph_t *graph, pcmk__graph_action_t *action);
    int (*rsc) (pcmk__graph_t *graph, pcmk__graph_action_t *action);
    int (*cluster) (pcmk__graph_t *graph, pcmk__graph_action_t *action);
    int (*fence) (pcmk__graph_t *graph, pcmk__graph_action_t *action);
    bool (*allowed) (pcmk__graph_t *graph, pcmk__graph_action_t *action);
} pcmk__graph_functions_t;

enum pcmk__graph_status {
    pcmk__graph_active,     // Some actions have been performed
    pcmk__graph_pending,    // No actions performed yet
    pcmk__graph_complete,
    pcmk__graph_terminated,
};

void pcmk__set_graph_functions(pcmk__graph_functions_t *fns);
pcmk__graph_t *pcmk__unpack_graph(const xmlNode *xml_graph,
                                  const char *reference);
enum pcmk__graph_status pcmk__execute_graph(pcmk__graph_t *graph);
void pcmk__update_graph(pcmk__graph_t *graph,
                        const pcmk__graph_action_t *action);
void pcmk__free_graph(pcmk__graph_t *graph);
const char *pcmk__graph_status2text(enum pcmk__graph_status state);
void pcmk__log_graph(unsigned int log_level, pcmk__graph_t *graph);
void pcmk__log_graph_action(int log_level, pcmk__graph_action_t *action);
void pcmk__log_transition_summary(const pcmk_scheduler_t *scheduler,
                                  const char *filename);
lrmd_event_data_t *pcmk__event_from_graph_action(const xmlNode *resource,
                                                 const pcmk__graph_action_t *action,
                                                 int status, int rc,
                                                 const char *exit_reason);

#ifdef __cplusplus
}
#endif

#endif // PCMK__PCMKI_PCMKI_TRANSITION__H
