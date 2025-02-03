/*
 * Copyright 2014-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_SCHEDULER__H
#define PCMK__PCMKI_PCMKI_SCHEDULER__H

#include <glib.h>               // GList
#include <stdbool.h>            // bool
#include <libxml/tree.h>        // xmlNode

#include <crm/lrmd_events.h>    // lrmd_event_data_t
#include <crm/pengine/status.h> // pcmk_resource_t, pcmk_scheduler_t

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *id;
    const char *node_attribute;
    pcmk_resource_t *dependent; // The resource being colocated
    pcmk_resource_t *primary;   // The resource the dependent is colocated with

    int dependent_role; // Colocation applies only if dependent has this role
    int primary_role;   // Colocation applies only if primary has this role

    int score;
    uint32_t flags;     // Group of enum pcmk__coloc_flags
} pcmk__colocation_t;

void pcmk__unpack_constraints(pcmk_scheduler_t *scheduler);

void pcmk__schedule_actions(pcmk_scheduler_t *scheduler);

GList *pcmk__copy_node_list(const GList *list, bool reset);

xmlNode *pcmk__create_history_xml(xmlNode *parent, lrmd_event_data_t *event,
                                  const char *caller_version, int target_rc,
                                  const char *node, const char *origin);

#ifdef __cplusplus
}
#endif

#endif // PCMK__PCMKI_PCMKI_SCHEDULER__H
