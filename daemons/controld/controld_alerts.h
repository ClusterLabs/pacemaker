/*
 * Copyright 2015-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CONTROLD_ALERTS__H
#  define CONTROLD_ALERTS__H

#  include <crm/crm.h>
#  include <crm/cluster.h>
#  include <crm/stonith-ng.h>

void crmd_unpack_alerts(xmlNode *alerts);
void crmd_alert_node_event(crm_node_t *node);
void crmd_alert_fencing_op(stonith_event_t *e);
void crmd_alert_resource_op(const char *node, lrmd_event_data_t *op);

#endif
