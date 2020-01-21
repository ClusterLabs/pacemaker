/*
 * Copyright 2015-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef LRMD_INTERNAL__H
#define LRMD_INTERNAL__H

#include <stdint.h>                     // uint32_t
#include <glib.h>                       // GList
#include <libxml/tree.h>                // xmlNode
#include <crm/common/remote_internal.h> // pcmk__remote_t
#include <crm/lrmd.h>                   // lrmd_t, lrmd_event_data_t

int lrmd_send_attribute_alert(lrmd_t *lrmd, GList *alert_list,
                              const char *node, uint32_t nodeid,
                              const char *attr_name, const char *attr_value);
int lrmd_send_node_alert(lrmd_t *lrmd, GList *alert_list,
                         const char *node, uint32_t nodeid, const char *state);
int lrmd_send_fencing_alert(lrmd_t *lrmd, GList *alert_list,
                            const char *target, const char *task,
                            const char *desc, int op_rc);
int lrmd_send_resource_alert(lrmd_t *lrmd, GList *alert_list,
                             const char *node, lrmd_event_data_t *op);

int lrmd_tls_send_msg(pcmk__remote_t *session, xmlNode *msg, uint32_t id,
                      const char *msg_type);

#endif
