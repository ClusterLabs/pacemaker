/*
 * Copyright 2011-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>

#include <crm/common/xml.h>
#include <crm/common/scheduler.h>
#include <crm/common/scheduler_internal.h>

#define OCF_RESKEY_PREFIX "OCF_RESKEY_"
#define LRM_TARGET_ENV OCF_RESKEY_PREFIX CRM_META "_" PCMK__META_ON_NODE

/*!
 * \internal
 * \brief Get the node name that should be used to set node attributes
 *
 * If given NULL, "auto", or "localhost" as an argument, check the environment
 * to detect the node name that should be used to set node attributes. (The
 * caller might not know the correct name, for example if the target is part of
 * a bundle with \c PCMK_META_CONTAINER_ATTRIBUTE_TARGET set to
 * \c PCMK_VALUE_HOST.)
 *
 * \param[in] name  NULL, "auto" or "localhost" to check environment variables,
 *                  or anything else to return NULL
 *
 * \return Node name that should be used for node attributes based on the
 *         environment if known, otherwise NULL
 */
const char *
pcmk__node_attr_target(const char *name)
{
    if (name == NULL || pcmk__strcase_any_of(name, "auto", "localhost", NULL)) {
        char *buf = NULL;
        char *target_var = crm_meta_name(PCMK_META_CONTAINER_ATTRIBUTE_TARGET);
        char *phys_var = crm_meta_name(PCMK__META_PHYSICAL_HOST);
        const char *target = NULL;
        const char *host_physical = NULL;

        buf = pcmk__assert_asprintf(OCF_RESKEY_PREFIX "%s", target_var);
        target = getenv(buf);
        free(buf);

        buf = pcmk__assert_asprintf(OCF_RESKEY_PREFIX "%s", phys_var);
        host_physical = getenv(buf);
        free(buf);

        free(target_var);
        free(phys_var);

        // It is important to use the name by which the scheduler knows us
        if (host_physical
            && pcmk__str_eq(target, PCMK_VALUE_HOST, pcmk__str_casei)) {
            name = host_physical;

        } else {
            const char *host_pcmk = getenv(LRM_TARGET_ENV);

            if (host_pcmk) {
                name = host_pcmk;
            }
        }

        // TODO? Call pcmk__cluster_local_node_name() if name == NULL
        // (currently would require linkage against libcrmcluster)
        return name;
    } else {
        return NULL;
    }
}

/*!
 * \brief Return the name of the node attribute used as a promotion score
 *
 * \param[in] rsc_id  Resource ID that promotion score is for (or NULL to
 *                    check the OCF_RESOURCE_INSTANCE environment variable)
 *
 * \return Newly allocated string with the node attribute name (or NULL on
 *         error, including no ID or environment variable specified)
 * \note It is the caller's responsibility to free() the result.
 */
char *
pcmk_promotion_score_name(const char *rsc_id)
{
    if (pcmk__str_empty(rsc_id)) {
        rsc_id = getenv("OCF_RESOURCE_INSTANCE");
        if (pcmk__str_empty(rsc_id)) {
            return NULL;
        }
    }
    return pcmk__assert_asprintf("master-%s", rsc_id);
}

/*!
 * \internal
 * \brief Get the value of a node attribute
 *
 * \param[in] node       Node to get attribute for
 * \param[in] name       Name of node attribute to get
 * \param[in] target     If this is \c PCMK_VALUE_HOST and \p node is a guest
 *                       (bundle) node, get the value from the guest's host,
 *                       otherwise get the value from \p node itself
 * \param[in] node_type  If getting the value from \p node's host, this
 *                       indicates whether to check the current or assigned host
 *
 * \return Value of \p name attribute for \p node
 */
const char *
pcmk__node_attr(const pcmk_node_t *node, const char *name, const char *target,
                enum pcmk__rsc_node node_type)
{
    // @TODO accept a group of enum pcmk__rsc_node flags as node_type
    const char *value = NULL;       // Attribute value to return
    const char *node_type_s = NULL; // Readable equivalent of node_type
    const pcmk_node_t *host = NULL;
    const pcmk_resource_t *container = NULL;

    if ((node == NULL) || (name == NULL)) {
        return NULL;
    }

    /* Check the node's own attributes unless this is a guest (bundle) node with
     * the container host as the attribute target.
     */
    if (!pcmk__is_guest_or_bundle_node(node)
        || !pcmk__str_eq(target, PCMK_VALUE_HOST, pcmk__str_casei)) {
        value = g_hash_table_lookup(node->priv->attrs, name);
        pcmk__trace("%s='%s' on %s", name, pcmk__s(value, ""),
                    pcmk__node_name(node));
        return value;
    }

    /* This resource needs attributes set for the container's host instead of
     * for the container itself (useful when the container uses the host's
     * storage).
     */
    container = node->priv->remote->priv->launcher;

    switch (node_type) {
        case pcmk__rsc_node_assigned:
            host = container->priv->assigned_node;
            if (host == NULL) {
                pcmk__trace("Skipping %s lookup for %s because its container "
                            "%s is unassigned",
                            name, pcmk__node_name(node), container->id);
                return NULL;
            }
            node_type_s = "assigned";
            break;

        case pcmk__rsc_node_current:
            if (container->priv->active_nodes != NULL) {
                host = container->priv->active_nodes->data;
            }
            if (host == NULL) {
                pcmk__trace("Skipping %s lookup for %s because its container "
                            "%s is inactive",
                            name, pcmk__node_name(node), container->id);
                return NULL;
            }
            node_type_s = "current";
            break;

        default:
            // Add support for other enum pcmk__rsc_node values if needed
            pcmk__assert(false);
            break;
    }

    value = g_hash_table_lookup(host->priv->attrs, name);
    pcmk__trace("%s='%s' for %s on %s container host %s", name,
                pcmk__s(value, ""), pcmk__node_name(node), node_type_s,
                pcmk__node_name(host));
    return value;
}
