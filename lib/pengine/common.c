/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>

#include <glib.h>

#include <crm/common/scheduler_internal.h>
#include <crm/pengine/internal.h>

const char *
fail2text(enum action_fail_response fail)
{
    const char *result = "<unknown>";

    switch (fail) {
        case pcmk_on_fail_ignore:
            result = "ignore";
            break;
        case pcmk_on_fail_demote:
            result = "demote";
            break;
        case pcmk_on_fail_block:
            result = "block";
            break;
        case pcmk_on_fail_restart:
            result = "recover";
            break;
        case pcmk_on_fail_ban:
            result = "migrate";
            break;
        case pcmk_on_fail_stop:
            result = "stop";
            break;
        case pcmk_on_fail_fence_node:
            result = "fence";
            break;
        case pcmk_on_fail_standby_node:
            result = "standby";
            break;
        case pcmk_on_fail_restart_container:
            result = "restart-container";
            break;
        case pcmk_on_fail_reset_remote:
            result = "reset-remote";
            break;
    }
    return result;
}

void
add_hash_param(GHashTable * hash, const char *name, const char *value)
{
    CRM_CHECK(hash != NULL, return);

    crm_trace("Adding name='%s' value='%s' to hash table",
              pcmk__s(name, "<null>"), pcmk__s(value, "<null>"));
    if (name == NULL || value == NULL) {
        return;

    } else if (pcmk__str_eq(value, "#default", pcmk__str_casei)) {
        return;

    } else if (g_hash_table_lookup(hash, name) == NULL) {
        g_hash_table_insert(hash, strdup(name), strdup(value));
    }
}

/*!
 * \internal
 * \brief Look up an attribute value on the appropriate node
 *
 * If \p node is a guest node and either the \c PCMK_META_CONTAINER_ATTR_TARGET
 * meta attribute is set to \c PCMK_VALUE_HOST for \p rsc or \p force_host is
 * \c true, query the attribute on the node's host. Otherwise, query the
 * attribute on \p node itself.
 *
 * \param[in] node        Node to query attribute value on by default
 * \param[in] name        Name of attribute to query
 * \param[in] rsc         Resource on whose behalf we're querying
 * \param[in] node_type   Type of resource location lookup
 * \param[in] force_host  Force a lookup on the guest node's host, regardless of
 *                        the \c PCMK_META_CONTAINER_ATTR_TARGET value
 *
 * \return Value of the attribute on \p node or on the host of \p node
 *
 * \note If \p force_host is \c true, \p node \e must be a guest node.
 */
const char *
pe__node_attribute_calculated(const pcmk_node_t *node, const char *name,
                              const pcmk_resource_t *rsc,
                              enum pcmk__rsc_node node_type,
                              bool force_host)
{
    // @TODO: Use pe__is_guest_node() after merging libpe_{rules,status}
    bool is_guest = (node != NULL)
                    && (node->details->type == pcmk_node_variant_remote)
                    && (node->details->remote_rsc != NULL)
                    && (node->details->remote_rsc->container != NULL);
    const char *source = NULL;
    const char *node_type_s = NULL;
    const char *reason = NULL;

    const pcmk_resource_t *container = NULL;
    const pcmk_node_t *host = NULL;

    CRM_ASSERT((node != NULL) && (name != NULL) && (rsc != NULL)
               && (!force_host || is_guest));

    /* Ignore PCMK_META_CONTAINER_ATTR_TARGET if node is not a guest node. This
     * represents a user configuration error.
     */
    source = g_hash_table_lookup(rsc->meta, PCMK_META_CONTAINER_ATTR_TARGET);
    if (!force_host
        && (!is_guest
            || !pcmk__str_eq(source, PCMK_VALUE_HOST, pcmk__str_casei))) {

        return g_hash_table_lookup(node->details->attrs, name);
    }

    container = node->details->remote_rsc->container;

    switch (node_type) {
        case pcmk__rsc_node_assigned:
            node_type_s = "assigned";
            host = container->allocated_to;
            if (host == NULL) {
                reason = "not assigned";
            }
            break;

        case pcmk__rsc_node_current:
            node_type_s = "current";

            if (container->running_on != NULL) {
                host = container->running_on->data;
            }
            if (host == NULL) {
                reason = "inactive";
            }
            break;

        default:
            // Add support for other enum pcmk__rsc_node values if needed
            CRM_ASSERT(false);
            break;
    }

    if (host != NULL) {
        const char *value = g_hash_table_lookup(host->details->attrs, name);

        pcmk__rsc_trace(rsc,
                        "%s: Value lookup for %s on %s container host %s %s%s",
                        rsc->id, name, node_type_s, pcmk__node_name(host),
                        ((value != NULL)? "succeeded: " : "failed"),
                        pcmk__s(value, ""));
        return value;
    }
    pcmk__rsc_trace(rsc,
                    "%s: Not looking for %s on %s container host: %s is %s",
                    rsc->id, name, node_type_s, container->id, reason);
    return NULL;
}

const char *
pe_node_attribute_raw(const pcmk_node_t *node, const char *name)
{
    if(node == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(node->details->attrs, name);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/pengine/common_compat.h>

const char *
role2text(enum rsc_role_e role)
{
    return pcmk_role_text(role);
}

enum rsc_role_e
text2role(const char *role)
{
    return pcmk_parse_role(role);
}

const char *
task2text(enum action_tasks task)
{
    return pcmk_action_text(task);
}

enum action_tasks
text2task(const char *task)
{
    return pcmk_parse_action(task);
}

const char *
pe_pref(GHashTable * options, const char *name)
{
    return pcmk__cluster_option(options, name);
}

// LCOV_EXCL_STOP
// End deprecated API
