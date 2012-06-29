/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cluster.h>
#include <crm/common/xml.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>
#include <tengine.h>

#include <sys/types.h>
#include <sys/stat.h>

extern void post_cache_update(int seq);
extern void crmd_ha_connection_destroy(gpointer user_data);

/*	 A_HA_CONNECT	*/
#if SUPPORT_COROSYNC

static gboolean
crmd_ais_dispatch(AIS_Message * wrapper, char *data, int sender)
{
    int seq = 0;
    xmlNode *xml = NULL;
    const char *seq_s = NULL;

    xml = string2xml(data);
    if (xml == NULL) {
        crm_err("Could not parse message content (%d): %.100s", wrapper->header.id, data);
        return TRUE;
    }

    switch (wrapper->header.id) {
        case crm_class_members:
            seq_s = crm_element_value(xml, "id");
            seq = crm_int_helper(seq_s, NULL);
            set_bit_inplace(fsa_input_register, R_PEER_DATA);
            post_cache_update(seq);

            /* fall through */
        case crm_class_quorum:
            crm_update_quorum(crm_have_quorum, FALSE);
            if (AM_I_DC) {
                const char *votes = crm_element_value(xml, "expected");

                if (votes == NULL || check_number(votes) == FALSE) {
                    crm_log_xml_err(xml, "Invalid quorum/membership update");

                } else {
                    int rc = update_attr(fsa_cib_conn,
                                         cib_quorum_override | cib_scope_local | cib_inhibit_notify,
                                         XML_CIB_TAG_CRMCONFIG, NULL, NULL, NULL, NULL,
                                         XML_ATTR_EXPECTED_VOTES, votes, FALSE);

                    crm_info("Setting expected votes to %s", votes);
                    if (pcmk_ok > rc) {
                        crm_err("Quorum update failed: %s", pcmk_strerror(rc));
                    }
                }
            }
            break;

        case crm_class_cluster:
            crm_xml_add(xml, F_ORIG, wrapper->sender.uname);
            crm_xml_add_int(xml, F_SEQ, wrapper->id);
            crmd_ha_msg_filter(xml);
            break;

        case crm_class_rmpeer:
            /* Ignore */
            break;

        case crm_class_notify:
        case crm_class_nodeid:
            crm_err("Unexpected message class (%d): %.100s", wrapper->header.id, data);
            break;

        default:
            crm_err("Invalid message class (%d): %.100s", wrapper->header.id, data);
    }

    free_xml(xml);
    return TRUE;
}

static gboolean
crmd_cman_dispatch(unsigned long long seq, gboolean quorate)
{
    crm_update_quorum(quorate, FALSE);
    post_cache_update(seq);
    return TRUE;
}

static void
crmd_quorum_destroy(gpointer user_data)
{
    if (is_set(fsa_input_register, R_HA_DISCONNECTED)) {
        crm_err("connection terminated");
        exit(1);

    } else {
        crm_info("connection closed");
    }
}

static void
crmd_ais_destroy(gpointer user_data)
{
    if (is_set(fsa_input_register, R_HA_DISCONNECTED)) {
        crm_err("connection terminated");
        exit(1);

    } else {
        crm_info("connection closed");
    }
}

#if SUPPORT_CMAN
static void
crmd_cman_destroy(gpointer user_data)
{
    if (is_set(fsa_input_register, R_HA_DISCONNECTED)) {
        crm_err("connection terminated");
        exit(1);

    } else {
        crm_info("connection closed");
    }
}
#endif

extern gboolean crm_connect_corosync(void);

gboolean
crm_connect_corosync(void)
{
    gboolean rc = FALSE;

    if (is_openais_cluster()) {
        crm_set_status_callback(&peer_update_callback);
        rc = crm_cluster_connect(&fsa_our_uname, &fsa_our_uuid, crmd_ais_dispatch, crmd_ais_destroy,
                                 NULL);
    }

    if (rc && is_corosync_cluster()) {
        init_quorum_connection(crmd_cman_dispatch, crmd_quorum_destroy);
    }

#if SUPPORT_CMAN
    if (rc && is_cman_cluster()) {
        init_cman_connection(crmd_cman_dispatch, crmd_cman_destroy);
        set_bit_inplace(fsa_input_register, R_MEMBERSHIP);
    }
#endif
    return rc;
}

#endif
