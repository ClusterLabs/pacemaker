/*
 * Copyright 2014-2023 the Pacemaker project contributors
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

#include <crm/lrmd.h>           // lrmd_event_data_t
#include <crm/pengine/status.h> // pe_resource_t, pe_working_set_t

typedef struct {
    const char *id;
    const char *node_attribute;
    pe_resource_t *dependent;   // The resource being colocated
    pe_resource_t *primary;     // The resource the dependent is colocated with

    int dependent_role; // Colocation applies only if dependent has this role
    int primary_role;   // Colocation applies only if primary has this role

    int score;
    uint32_t flags;     // Group of enum pcmk__coloc_flags
} pcmk__colocation_t;

void pcmk__unpack_constraints(pe_working_set_t *data_set);

void pcmk__schedule_actions(xmlNode *cib, unsigned long long flags,
                            pe_working_set_t *data_set);

GList *pcmk__copy_node_list(const GList *list, bool reset);

xmlNode *pcmk__create_history_xml(xmlNode *parent, lrmd_event_data_t *event,
                                  const char *caller_version, int target_rc,
                                  const char *node, const char *origin);

#endif
