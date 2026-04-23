/*
 * Copyright 2013-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include <glib.h>

/*!
 * \internal
 * \brief Check whether a resource creates a guest node
 *
 * If a given resource contains a launched resource that is a remote connection,
 * return that launched resource (or NULL if none is found).
 *
 * \param[in] scheduler  Scheduler data
 * \param[in] rsc        Resource to check
 *
 * \return Launched remote connection, or NULL if none found
 */
pcmk_resource_t *
pe__resource_contains_guest_node(const pcmk_scheduler_t *scheduler,
                                 const pcmk_resource_t *rsc)
{
    if ((rsc != NULL) && (scheduler != NULL)
        && pcmk__is_set(scheduler->flags, pcmk__sched_have_remote_nodes)) {

        for (GList *gIter = rsc->priv->launched;
             gIter != NULL; gIter = gIter->next) {

            pcmk_resource_t *launched = gIter->data;

            if (pcmk__is_set(launched->flags, pcmk__rsc_is_remote_connection)) {
                return launched;
            }
        }
    }
    return NULL;
}

bool
xml_contains_remote_node(xmlNode *xml)
{
    const char *value = NULL;

    if (xml == NULL) {
        return false;
    }

    value = pcmk__xe_get(xml, PCMK_XA_TYPE);
    if (!pcmk__str_eq(value, "remote", pcmk__str_casei)) {
        return false;
    }

    value = pcmk__xe_get(xml, PCMK_XA_CLASS);
    if (!pcmk__str_eq(value, PCMK_RESOURCE_CLASS_OCF, pcmk__str_casei)) {
        return false;
    }

    value = pcmk__xe_get(xml, PCMK_XA_PROVIDER);
    if (!pcmk__str_eq(value, "pacemaker", pcmk__str_casei)) {
        return false;
    }

    return true;
}

/*!
 * \internal
 * \brief Execute a supplied function for each guest node running on a host
 *
 * \param[in]     scheduler  Scheduler data
 * \param[in]     host       Host node to check
 * \param[in]     helper     Function to call for each guest node
 * \param[in,out] user_data  Pointer to pass to helper function
 */
void
pe_foreach_guest_node(const pcmk_scheduler_t *scheduler,
                      const pcmk_node_t *host,
                      void (*helper)(const pcmk_node_t*, void*),
                      void *user_data)
{
    GList *iter;

    CRM_CHECK(scheduler && host && host->details && helper, return);
    if (!pcmk__is_set(scheduler->flags, pcmk__sched_have_remote_nodes)) {
        return;
    }
    for (iter = host->details->running_rsc; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (pcmk__is_set(rsc->flags, pcmk__rsc_is_remote_connection)
            && (rsc->priv->launcher != NULL)) {
            pcmk_node_t *guest_node = pcmk_find_node(scheduler, rsc->id);

            if (guest_node) {
                helper(guest_node, user_data);
            }
        }
    }
}

/*!
 * \internal
 * \brief Create CIB XML for an implicit remote connection
 *
 * \param[in,out] parent         If not \c NULL, use as parent XML element
 * \param[in]     uname          Name of Pacemaker Remote node
 * \param[in]     container_id   If not \c NULL, use this as connection container
 * \param[in]     migrateable    If not \c NULL, use as remote
 *                               \c PCMK_META_ALLOW_MIGRATE value
 * \param[in]     is_managed     If not \c NULL, use as remote
 *                               \c PCMK_META_IS_MANAGED value
 * \param[in]     start_timeout  If not \c NULL, use as remote connect timeout
 * \param[in]     server         If not \c NULL, use as \c PCMK_REMOTE_RA_ADDR
 * \param[in]     port           If not \c NULL, use as \c PCMK_REMOTE_RA_PORT
 *
 * \return Newly created XML
 */
xmlNode *
pe_create_remote_xml(xmlNode *parent, const char *uname,
                     const char *container_id, const char *migrateable,
                     const char *is_managed, const char *start_timeout,
                     const char *server, const char *port)
{
    xmlNode *remote;
    xmlNode *xml_sub;

    remote = pcmk__xe_create(parent, PCMK_XE_PRIMITIVE);

    // Add identity
    pcmk__xe_set(remote, PCMK_XA_ID, uname);
    pcmk__xe_set(remote, PCMK_XA_CLASS, PCMK_RESOURCE_CLASS_OCF);
    pcmk__xe_set(remote, PCMK_XA_PROVIDER, "pacemaker");
    pcmk__xe_set(remote, PCMK_XA_TYPE, "remote");

    // Add meta-attributes
    xml_sub = pcmk__xe_create(remote, PCMK_XE_META_ATTRIBUTES);
    pcmk__xe_set_id(xml_sub, "%s-%s", uname, PCMK_XE_META_ATTRIBUTES);
    crm_create_nvpair_xml(xml_sub, NULL,
                          PCMK__META_INTERNAL_RSC, PCMK_VALUE_TRUE);
    if (container_id) {
        crm_create_nvpair_xml(xml_sub, NULL,
                              PCMK__META_CONTAINER, container_id);
    }
    if (migrateable) {
        crm_create_nvpair_xml(xml_sub, NULL,
                              PCMK_META_ALLOW_MIGRATE, migrateable);
    }
    if (is_managed) {
        crm_create_nvpair_xml(xml_sub, NULL, PCMK_META_IS_MANAGED, is_managed);
    }

    // Add instance attributes
    if (port || server) {
        xml_sub = pcmk__xe_create(remote, PCMK_XE_INSTANCE_ATTRIBUTES);
        pcmk__xe_set_id(xml_sub, "%s-%s", uname, PCMK_XE_INSTANCE_ATTRIBUTES);
        if (server) {
            crm_create_nvpair_xml(xml_sub, NULL, PCMK_REMOTE_RA_ADDR, server);
        }
        if (port) {
            crm_create_nvpair_xml(xml_sub, NULL, PCMK_REMOTE_RA_PORT, port);
        }
    }

    // Add operations
    xml_sub = pcmk__xe_create(remote, PCMK_XE_OPERATIONS);
    crm_create_op_xml(xml_sub, uname, PCMK_ACTION_MONITOR, "30s", "30s");
    if (start_timeout) {
        crm_create_op_xml(xml_sub, uname, PCMK_ACTION_START, "0",
                          start_timeout);
    }
    return remote;
}
