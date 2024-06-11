/*
 * Copyright 2015-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_ALERTS__H
#define CONTROLD_ALERTS__H

#include <libxml/tree.h>            // xmlNode

#include <crm/cluster/internal.h>   // pcmk__node_status_t
#include <crm/lrmd_events.h>        // lrmd_event_data_t
#include <crm/stonith-ng.h>         // stonith_event_t

void crmd_unpack_alerts(xmlNode *alerts);
void crmd_alert_node_event(pcmk__node_status_t *node);
void crmd_alert_fencing_op(stonith_event_t *e);
void crmd_alert_resource_op(const char *node, lrmd_event_data_t *op);

#endif
