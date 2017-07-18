/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/lrmd_alerts_internal.h>
#include "crmd_lrm.h"
#include "crmd_alerts.h"
#include "crmd_messages.h"
#include <crm/common/alerts_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/pengine/rules_internal.h>

static GListPtr crmd_alert_list = NULL;

void
crmd_unpack_alerts(xmlNode *alerts)
{
    pe_free_alert_list(crmd_alert_list);
    crmd_alert_list = pe_unpack_alerts(alerts);
}

void
crmd_alert_node_event(crm_node_t *node)
{
    lrmd_send_node_alert(crmd_alert_list, crmd_local_lrmd_conn, node->uname,
                         node->id, node->state);
}

void
crmd_alert_fencing_op(stonith_event_t * e)
{
    char *desc = crm_strdup_printf("Operation %s of %s by %s for %s@%s: %s (ref=%s)",
                                   e->action, e->target,
                                   (e->executioner? e->executioner : "<no-one>"),
                                   e->client_origin, e->origin,
                                   pcmk_strerror(e->result), e->id);

    lrmd_send_fencing_alert(crmd_alert_list, crmd_local_lrmd_conn, e->target,
                            e->operation, desc, e->result);
    free(desc);
}

void
crmd_alert_resource_op(const char *node, lrmd_event_data_t * op)
{
    lrmd_send_resource_alert(crmd_alert_list, crmd_local_lrmd_conn, node, op);
}
