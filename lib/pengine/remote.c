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
    if (is_remote_node(node) && (node->details->remote_rsc == NULL || node->details->remote_rsc->container == FALSE)) {
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

    if (safe_str_eq(agent, "remote") && safe_str_eq(provider, "pacemaker")
        && safe_str_eq(class, PCMK_RESOURCE_CLASS_OCF)) {
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
 * \param[in,out] user_data  Pointer to pass to helper function
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

/*!
 * \internal
 * \brief Create CIB XML for an implicit remote connection
 *
 * \param[in] parent           If not NULL, use as parent XML element
 * \param[in] uname            Name of Pacemaker Remote node
 * \param[in] container        If not NULL, use this as connection container
 * \param[in] migrateable      If not NULL, use as allow-migrate value
 * \param[in] is_managed       If not NULL, use as is-managed value
 * \param[in] start_timeout    If not NULL, use as remote connect timeout
 * \param[in] server           If not NULL, use as remote server value
 * \param[in] port             If not NULL, use as remote port value
 */
xmlNode *
pe_create_remote_xml(xmlNode *parent, const char *uname,
                     const char *container_id, const char *migrateable,
                     const char *is_managed, const char *start_timeout,
                     const char *server, const char *port)
{
    xmlNode *remote;
    xmlNode *xml_sub;

    remote = create_xml_node(parent, XML_CIB_TAG_RESOURCE);

    // Add identity
    crm_xml_add(remote, XML_ATTR_ID, uname);
    crm_xml_add(remote, XML_AGENT_ATTR_CLASS, PCMK_RESOURCE_CLASS_OCF);
    crm_xml_add(remote, XML_AGENT_ATTR_PROVIDER, "pacemaker");
    crm_xml_add(remote, XML_ATTR_TYPE, "remote");

    // Add meta-attributes
    xml_sub = create_xml_node(remote, XML_TAG_META_SETS);
    crm_xml_set_id(xml_sub, "%s-%s", uname, XML_TAG_META_SETS);
    crm_create_nvpair_xml(xml_sub, NULL,
                          XML_RSC_ATTR_INTERNAL_RSC, XML_BOOLEAN_TRUE);
    if (container_id) {
        crm_create_nvpair_xml(xml_sub, NULL,
                              XML_RSC_ATTR_CONTAINER, container_id);
    }
    if (migrateable) {
        crm_create_nvpair_xml(xml_sub, NULL,
                              XML_OP_ATTR_ALLOW_MIGRATE, migrateable);
    }
    if (is_managed) {
        crm_create_nvpair_xml(xml_sub, NULL, XML_RSC_ATTR_MANAGED, is_managed);
    }

    // Add instance attributes
    if (port || server) {
        xml_sub = create_xml_node(remote, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_sub, "%s-%s", uname, XML_TAG_ATTR_SETS);
        if (server) {
            crm_create_nvpair_xml(xml_sub, NULL, "addr", server);
        }
        if (port) {
            crm_create_nvpair_xml(xml_sub, NULL, "port", port);
        }
    }

    // Add operations
    xml_sub = create_xml_node(remote, "operations");
    crm_create_op_xml(xml_sub, uname, "monitor", "30s", "30s");
    if (start_timeout) {
        crm_create_op_xml(xml_sub, uname, "start", "0", start_timeout);
    }
    return remote;
}
