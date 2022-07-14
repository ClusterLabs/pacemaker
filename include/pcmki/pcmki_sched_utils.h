/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_SCHED_UTILS__H
#  define PCMK__PCMKI_PCMKI_SCHED_UTILS__H

#include <stdbool.h>                    // bool
#include <glib.h>                       // GList, GHashTable, gboolean, guint
#include <crm/lrmd.h>                   // lrmd_event_data_t
#include <crm/cib.h>                    // cib_t
#include <crm/pengine/pe_types.h>
#include <crm/common/xml_internal.h>
#include <crm/pengine/internal.h>
#include <pcmki/pcmki_scheduler.h>
#include <pcmki/pcmki_transition.h>
#include <pacemaker.h>

/* Constraint helper functions */
GList *pcmk__copy_node_list(const GList *list, bool reset);

int copies_per_node(pe_resource_t * rsc);

xmlNode *pcmk__create_history_xml(xmlNode *parent, lrmd_event_data_t *event,
                                 const char *caller_version, int target_rc,
                                 const char *node, const char *origin);

#endif
