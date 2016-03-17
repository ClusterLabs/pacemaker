/*
 * Copyright (C) 2013 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include <glib.h>

gboolean
is_rsc_baremetal_remote_node(resource_t *rsc, pe_working_set_t * data_set)
{
    node_t *node;

    if (rsc == NULL) {
        return FALSE;
    } else if (rsc->is_remote_node == FALSE) {
        return FALSE;
    }

    node = pe_find_node(data_set->nodes, rsc->id);
    if (node == NULL) {
        return FALSE;
    }

    return is_baremetal_remote_node(node);
}

gboolean
is_baremetal_remote_node(node_t *node)
{
    if (is_remote_node(node) && (node->details->remote_rsc == FALSE || node->details->remote_rsc->container == FALSE)) {
        return TRUE;
    }
    return FALSE;
}

gboolean
is_container_remote_node(node_t *node)
{
    if (is_remote_node(node) && (node->details->remote_rsc && node->details->remote_rsc->container)) {
        return TRUE;
    }
    return FALSE;
}

gboolean
is_remote_node(node_t *node)
{
    if (node && node->details->type == node_remote) {
        return TRUE;
    }
    return FALSE;
}

resource_t *
rsc_contains_remote_node(pe_working_set_t * data_set, resource_t *rsc)
{
    if (is_set(data_set->flags, pe_flag_have_remote_nodes) == FALSE) {
        return NULL;
    }

    if (rsc->fillers) {
        GListPtr gIter = NULL;
        for (gIter = rsc->fillers; gIter != NULL; gIter = gIter->next) {
            resource_t *filler = (resource_t *) gIter->data;

            if (filler->is_remote_node) {
                return filler;
            }
        }
    }
    return NULL;
}

gboolean
xml_contains_remote_node(xmlNode *xml)
{
    const char *class = crm_element_value(xml, XML_AGENT_ATTR_CLASS);
    const char *provider = crm_element_value(xml, XML_AGENT_ATTR_PROVIDER);
    const char *agent = crm_element_value(xml, XML_ATTR_TYPE);

    if (safe_str_eq(agent, "remote") && safe_str_eq(provider, "pacemaker") && safe_str_eq(class, "ocf")) {
        return TRUE;
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Execute a supplied function for each guest node running on a host
 *
 * \param[in]     data_set   Working set for cluster
 * \param[in]     host       Host node to check
 * \param[in]     helper     Function to call for each guest node
 * \param[in/out] user_data  Pointer to pass to helper function
 */
void
pe_foreach_guest_node(const pe_working_set_t *data_set, const node_t *host,
                      void (*helper)(const node_t*, void*), void *user_data)
{
    GListPtr iter;

    CRM_CHECK(data_set && host && host->details && helper, return);
    if (!is_set(data_set->flags, pe_flag_have_remote_nodes)) {
        return;
    }
    for (iter = host->details->running_rsc; iter != NULL; iter = iter->next) {
        resource_t *rsc = (resource_t *) iter->data;

        if (rsc->is_remote_node && (rsc->container != NULL)) {
            node_t *guest_node = pe_find_node(data_set->nodes, rsc->id);

            if (guest_node) {
                (*helper)(guest_node, user_data);
            }
        }
    }
}
