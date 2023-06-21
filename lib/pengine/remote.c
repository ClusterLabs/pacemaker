/*
 * Copyright 2013-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>
#include <glib.h>

bool
pe__resource_is_remote_conn(const pe_resource_t *rsc,
                            const pe_working_set_t *data_set)
{
    return (rsc != NULL) && rsc->is_remote_node
           && pe__is_remote_node(pe_find_node(data_set->nodes, rsc->id));
}

bool
pe__is_remote_node(const pe_node_t *node)
{
    return (node != NULL) && (node->details->type == node_remote)
           && ((node->details->remote_rsc == NULL)
               || (node->details->remote_rsc->container == NULL));
}

bool
pe__is_guest_node(const pe_node_t *node)
{
    return (node != NULL) && (node->details->type == node_remote)
           && (node->details->remote_rsc != NULL)
           && (node->details->remote_rsc->container != NULL);
}

bool
pe__is_guest_or_remote_node(const pe_node_t *node)
{
    return (node != NULL) && (node->details->type == node_remote);
}

bool
pe__is_bundle_node(const pe_node_t *node)
{
    return pe__is_guest_node(node)
           && pe_rsc_is_bundled(node->details->remote_rsc);
}

/*!
 * \internal
 * \brief Check whether a resource creates a guest node
 *
 * If a given resource contains a filler resource that is a remote connection,
 * return that filler resource (or NULL if none is found).
 *
 * \param[in] data_set  Working set of cluster
 * \param[in] rsc       Resource to check
 *
 * \return Filler resource with remote connection, or NULL if none found
 */
pe_resource_t *
pe__resource_contains_guest_node(const pe_working_set_t *data_set,
                                 const pe_resource_t *rsc)
{
    if ((rsc != NULL) && (data_set != NULL)
        && pcmk_is_set(data_set->flags, pe_flag_have_remote_nodes)) {

        for (GList *gIter = rsc->fillers; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *filler = gIter->data;

            if (filler->is_remote_node) {
                return filler;
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

    value = crm_element_value(xml, XML_ATTR_TYPE);
    if (!pcmk__str_eq(value, "remote", pcmk__str_casei)) {
        return false;
    }

    value = crm_element_value(xml, XML_AGENT_ATTR_CLASS);
    if (!pcmk__str_eq(value, PCMK_RESOURCE_CLASS_OCF, pcmk__str_casei)) {
        return false;
    }

    value = crm_element_value(xml, XML_AGENT_ATTR_PROVIDER);
    if (!pcmk__str_eq(value, "pacemaker", pcmk__str_casei)) {
        return false;
    }

    return true;
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
pe_foreach_guest_node(const pe_working_set_t *data_set, const pe_node_t *host,
                      void (*helper)(const pe_node_t*, void*), void *user_data)
{
    GList *iter;

    CRM_CHECK(data_set && host && host->details && helper, return);
    if (!pcmk_is_set(data_set->flags, pe_flag_have_remote_nodes)) {
        return;
    }
    for (iter = host->details->running_rsc; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (rsc->is_remote_node && (rsc->container != NULL)) {
            pe_node_t *guest_node = pe_find_node(data_set->nodes, rsc->id);

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
 * \param[in,out] parent           If not NULL, use as parent XML element
 * \param[in]     uname            Name of Pacemaker Remote node
 * \param[in]     container        If not NULL, use this as connection container
 * \param[in]     migrateable      If not NULL, use as allow-migrate value
 * \param[in]     is_managed       If not NULL, use as is-managed value
 * \param[in]     start_timeout    If not NULL, use as remote connect timeout
 * \param[in]     server           If not NULL, use as remote server value
 * \param[in]     port             If not NULL, use as remote port value
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
            crm_create_nvpair_xml(xml_sub, NULL, XML_RSC_ATTR_REMOTE_RA_ADDR,
                                  server);
        }
        if (port) {
            crm_create_nvpair_xml(xml_sub, NULL, "port", port);
        }
    }

    // Add operations
    xml_sub = create_xml_node(remote, "operations");
    crm_create_op_xml(xml_sub, uname, "monitor", "30s", "30s");
    if (start_timeout) {
        crm_create_op_xml(xml_sub, uname, PCMK_ACTION_START, "0",
                          start_timeout);
    }
    return remote;
}

// History entry to be checked for fail count clearing
struct check_op {
    const xmlNode *rsc_op; // History entry XML
    pe_resource_t *rsc;    // Known resource corresponding to history entry
    pe_node_t *node; // Known node corresponding to history entry
    enum pe_check_parameters check_type; // What needs checking
};

void
pe__add_param_check(const xmlNode *rsc_op, pe_resource_t *rsc,
                    pe_node_t *node, enum pe_check_parameters flag,
                    pe_working_set_t *data_set)
{
    struct check_op *check_op = NULL;

    CRM_CHECK(data_set && rsc_op && rsc && node, return);

    check_op = calloc(1, sizeof(struct check_op));
    CRM_ASSERT(check_op != NULL);

    crm_trace("Deferring checks of %s until after allocation", ID(rsc_op));
    check_op->rsc_op = rsc_op;
    check_op->rsc = rsc;
    check_op->node = node;
    check_op->check_type = flag;
    data_set->param_check = g_list_prepend(data_set->param_check, check_op);
}

/*!
 * \internal
 * \brief Call a function for each action to be checked for addr substitution
 *
 * \param[in,out] data_set  Working set for cluster
 * \param[in]     cb        Function to be called
 */
void
pe__foreach_param_check(pe_working_set_t *data_set,
                       void (*cb)(pe_resource_t*, pe_node_t*, const xmlNode*,
                                  enum pe_check_parameters))
{
    CRM_CHECK(data_set && cb, return);

    for (GList *item = data_set->param_check; item != NULL; item = item->next) {
        struct check_op *check_op = item->data;

        cb(check_op->rsc, check_op->node, check_op->rsc_op,
           check_op->check_type);
    }
}

void
pe__free_param_checks(pe_working_set_t *data_set)
{
    if (data_set && data_set->param_check) {
        g_list_free_full(data_set->param_check, free);
        data_set->param_check = NULL;
    }
}
