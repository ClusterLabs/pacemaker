/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PCMKI_PCMKI_SCHED_ALLOCATE__H
#  define PCMK__PCMKI_PCMKI_SCHED_ALLOCATE__H

#  include <glib.h>
#  include <crm/common/xml.h>
#  include <crm/pengine/status.h>
#  include <crm/pengine/complex.h>
#  include <crm/common/xml_internal.h>
#  include <crm/pengine/internal.h>
#  include <crm/common/xml.h>
#  include <pcmki/pcmki_scheduler.h>

pe_node_t *pcmk__bundle_allocate(pe_resource_t *rsc, const pe_node_t *prefer);
void pcmk__bundle_create_actions(pe_resource_t *rsc);
bool pcmk__bundle_create_probe(pe_resource_t *rsc, pe_node_t *node);
void pcmk__bundle_internal_constraints(pe_resource_t *rsc);
void pcmk__bundle_rsc_location(pe_resource_t *rsc, pe__location_t *constraint);
enum pe_action_flags pcmk__bundle_action_flags(pe_action_t *action,
                                               const pe_node_t *node);
void pcmk__bundle_expand(pe_resource_t *rsc);
void pcmk__bundle_add_utilization(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc,
                                  GList *all_rscs, GHashTable *utilization);
void pcmk__bundle_shutdown_lock(pe_resource_t *rsc);

void pcmk__log_transition_summary(const char *filename);

#endif
