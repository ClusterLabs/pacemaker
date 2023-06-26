/*
 * Copyright 2014-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_SCHEDULER__H
#  define PCMK__PCMKI_PCMKI_SCHEDULER__H

#  include <glib.h>
#  include <crm/crm.h>
#  include <crm/common/iso8601.h>
#  include <crm/pengine/rules.h>
#  include <crm/pengine/common.h>
#  include <crm/pengine/status.h>

#  include <crm/pengine/complex.h>

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

GList *pcmk__with_this_colocations(const pe_resource_t *rsc);
GList *pcmk__this_with_colocations(const pe_resource_t *rsc);

#endif
