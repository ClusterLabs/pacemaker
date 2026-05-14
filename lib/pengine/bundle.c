/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>                     // va_arg, va_list
#include <stdbool.h>                    // bool, true, false
#include <stddef.h>                     // NULL
#include <stdint.h>                     // uint32_t
#include <stdio.h>                      // sscanf
#include <stdlib.h>                     // free
#include <string.h>                     // strcmp, strdup, strlen

#include <glib.h>                       // g_*, etc.
#include <libxml/tree.h>                // xmlNode
#include <qb/qblog.h>                   // LOG_TRACE

#include <crm/common/actions.h>         // crm_create_op_xml, PCMK_ACTION_*
#include <crm/common/agents.h>          // PCMK_RESOURCE_CLASS_OCF
#include <crm/common/logging.h>         // CRM_CHECK, CRM_LOG_ASSERT
#include <crm/common/nvpair.h>          // crm_create_nvpair_xml
#include <crm/common/options.h>         // PCMK_META_*, PCMK_VALUE_*
#include <crm/common/output.h>          // pcmk_show_implicit_rscs
#include <crm/common/results.h>         // pcmk_rc_*
#include <crm/common/roles.h>           // pcmk_role_unknown, rsc_role_e
#include <crm/common/scheduler.h>       // pcmk_node_t, pcmk_scheduler_t, etc.
#include <crm/common/scores.h>          // PCMK_SCORE_INFINITY
#include <crm/common/xml.h>             // PCMK_XA_*, PCMK_XE_*, etc.
#include <crm/crm.h>                    // CRM_ATTR_KIND
#include <crm/lrmd.h>                   // DEFAULT_REMOTE_*
#include <crm/pengine/complex.h>        // pe_rsc_params
#include <crm/pengine/internal.h>       // pe__*, etc.
#include <crm/pengine/status.h>         // pe_bundle_replicas, etc.

#include "pe_status_private.h"          // pe__bundle_*, pe__unpack_resource

enum pe__bundle_mount_flags {
    pe__bundle_mount_none       = 0x00,

    // mount instance-specific subdirectory rather than source directly
    pe__bundle_mount_subdir     = 0x01
};

typedef struct {
    char *source;
    char *target;
    char *options;
    uint32_t flags; // bitmask of pe__bundle_mount_flags
} pe__bundle_mount_t;

typedef struct {
    char *source;
    char *target;
} pe__bundle_port_t;

enum pe__container_agent {
    PE__CONTAINER_AGENT_UNKNOWN,
    PE__CONTAINER_AGENT_DOCKER,
    PE__CONTAINER_AGENT_PODMAN,
};

#define PE__CONTAINER_AGENT_UNKNOWN_S "unknown"
#define PE__CONTAINER_AGENT_DOCKER_S  "docker"
#define PE__CONTAINER_AGENT_PODMAN_S  "podman"

typedef struct {
        int promoted_max;
        int nreplicas;
        int nreplicas_per_host;
        char *prefix;
        char *image;
        const char *ip_last;
        char *host_network;
        char *host_netmask;
        char *control_port;
        char *container_network;
        char *ip_range_start;
        bool add_host;
        gchar *container_host_options;
        char *container_command;
        char *launcher_options;
        const char *attribute_target;

        pcmk_resource_t *child;

        GList *replicas;    // pcmk__bundle_replica_t *
        GList *ports;       // pe__bundle_port_t *
        GList *mounts;      // pe__bundle_mount_t *

        /* @TODO Maybe use a more object-oriented design instead, with a set of
         * methods that are different per type rather than switching on this
         */
        enum pe__container_agent agent_type;
} pe__bundle_variant_data_t;

#define get_bundle_variant_data(data, rsc) do { \
        pcmk__assert(pcmk__is_bundle(rsc));     \
        data = rsc->priv->variant_opaque;       \
    } while (0)

/*!
 * \internal
 * \brief Get maximum number of bundle replicas allowed to run
 *
 * \param[in] rsc  Bundle or bundled resource to check
 *
 * \return Maximum replicas for bundle corresponding to \p rsc
 */
int
pe__bundle_max(const pcmk_resource_t *rsc)
{
    const pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, pe__const_top_resource(rsc, true));
    return bundle_data->nreplicas;
}

/*!
 * \internal
 * \brief Get the resource inside a bundle
 *
 * \param[in] bundle  Bundle to check
 *
 * \return Resource inside \p bundle if any, otherwise NULL
 */
pcmk_resource_t *
pe__bundled_resource(const pcmk_resource_t *rsc)
{
    const pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, pe__const_top_resource(rsc, true));
    return bundle_data->child;
}

/*!
 * \internal
 * \brief Get containerized resource corresponding to a given bundle container
 *
 * \param[in] instance  Collective instance that might be a bundle container
 *
 * \return Bundled resource instance inside \p instance if it is a bundle
 *         container instance, otherwise NULL
 */
const pcmk_resource_t *
pe__get_rsc_in_container(const pcmk_resource_t *instance)
{
    const pe__bundle_variant_data_t *data = NULL;
    const pcmk_resource_t *top = pe__const_top_resource(instance, true);

    if (!pcmk__is_bundle(top)) {
        return NULL;
    }
    get_bundle_variant_data(data, top);

    for (const GList *iter = data->replicas; iter != NULL; iter = iter->next) {
        const pcmk__bundle_replica_t *replica = iter->data;

        if (instance == replica->container) {
            return replica->child;
        }
    }
    return NULL;
}

/*!
 * \internal
 * \brief Check whether a given node is created by a bundle
 *
 * \param[in] bundle  Bundle resource to check
 * \param[in] node    Node to check
 *
 * \return true if \p node is an instance of \p bundle, otherwise false
 */
bool
pe__node_is_bundle_instance(const pcmk_resource_t *bundle,
                            const pcmk_node_t *node)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, bundle);
    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;

        if (pcmk__same_node(node, replica->node)) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Get the container of a bundle's first replica
 *
 * \param[in] bundle  Bundle resource to get container for
 *
 * \return Container resource from first replica of \p bundle if any,
 *         otherwise NULL
 */
pcmk_resource_t *
pe__first_container(const pcmk_resource_t *bundle)
{
    const pe__bundle_variant_data_t *bundle_data = NULL;
    const pcmk__bundle_replica_t *replica = NULL;

    get_bundle_variant_data(bundle_data, bundle);
    if (bundle_data->replicas == NULL) {
        return NULL;
    }
    replica = bundle_data->replicas->data;
    return replica->container;
}

/*!
 * \internal
 * \brief Iterate over bundle replicas
 *
 * \param[in,out] bundle     Bundle to iterate over
 * \param[in]     fn         Function to call for each replica (its return value
 *                           indicates whether to continue iterating)
 * \param[in,out] user_data  Pointer to pass to \p fn
 */
void
pe__foreach_bundle_replica(pcmk_resource_t *bundle,
                           bool (*fn)(pcmk__bundle_replica_t *, void *),
                           void *user_data)
{
    const pe__bundle_variant_data_t *bundle_data = NULL;

    pcmk__assert(fn != NULL);

    get_bundle_variant_data(bundle_data, bundle);
    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        if (!fn((pcmk__bundle_replica_t *) iter->data, user_data)) {
            break;
        }
    }
}

/*!
 * \internal
 * \brief Iterate over const bundle replicas
 *
 * \param[in]     bundle     Bundle to iterate over
 * \param[in]     fn         Function to call for each replica (its return value
 *                           indicates whether to continue iterating)
 * \param[in,out] user_data  Pointer to pass to \p fn
 */
void
pe__foreach_const_bundle_replica(const pcmk_resource_t *bundle,
                                 bool (*fn)(const pcmk__bundle_replica_t *,
                                            void *),
                                 void *user_data)
{
    const pe__bundle_variant_data_t *bundle_data = NULL;

    pcmk__assert(fn != NULL);

    get_bundle_variant_data(bundle_data, bundle);
    for (const GList *iter = bundle_data->replicas; iter != NULL;
         iter = iter->next) {

        if (!fn((const pcmk__bundle_replica_t *) iter->data, user_data)) {
            break;
        }
    }
}

static char *
next_ip(const char *last_ip)
{
    unsigned int oct1 = 0;
    unsigned int oct2 = 0;
    unsigned int oct3 = 0;
    unsigned int oct4 = 0;
    int rc = sscanf(last_ip, "%u.%u.%u.%u", &oct1, &oct2, &oct3, &oct4);

    if (rc != 4) {
        /*@ TODO check for IPv6 */
        return NULL;

    } else if (oct3 > 253) {
        return NULL;

    } else if (oct4 > 253) {
        ++oct3;
        oct4 = 1;

    } else {
        ++oct4;
    }

    return pcmk__assert_asprintf("%u.%u.%u.%u", oct1, oct2, oct3, oct4);
}

static void
allocate_ip(pe__bundle_variant_data_t *data, pcmk__bundle_replica_t *replica,
            GString *buffer)
{
    if(data->ip_range_start == NULL) {
        return;

    } else if(data->ip_last) {
        replica->ipaddr = next_ip(data->ip_last);

    } else {
        replica->ipaddr = pcmk__str_copy(data->ip_range_start);
    }

    data->ip_last = replica->ipaddr;

    if ((data->agent_type != PE__CONTAINER_AGENT_DOCKER)
        && (data->agent_type != PE__CONTAINER_AGENT_PODMAN)) {

        return;
    }

    if (data->add_host) {
        g_string_append_printf(buffer, " --add-host=%s-%d:%s", data->prefix,
                               replica->offset, replica->ipaddr);
        return;
    }

    g_string_append_printf(buffer, " --hosts-entry=%s=%s-%d", replica->ipaddr,
                           data->prefix, replica->offset);
}

static xmlNode *
create_resource(const char *name, const char *provider, const char *kind)
{
    xmlNode *rsc = pcmk__xe_create(NULL, PCMK_XE_PRIMITIVE);

    pcmk__xe_set(rsc, PCMK_XA_ID, name);
    pcmk__xe_set(rsc, PCMK_XA_CLASS, PCMK_RESOURCE_CLASS_OCF);
    pcmk__xe_set(rsc, PCMK_XA_PROVIDER, provider);
    pcmk__xe_set(rsc, PCMK_XA_TYPE, kind);

    return rsc;
}

static int
create_ip_resource(pcmk_resource_t *parent, pcmk__bundle_replica_t *replica)
{
    char *id = NULL;
    xmlNode *xml_ip = NULL;
    xmlNode *xml_obj = NULL;
    int rc = pcmk_rc_ok;
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, parent);

    if (bundle_data->ip_range_start == NULL) {
        goto done;
    }

    id = pcmk__assert_asprintf("%s-ip-%s", bundle_data->prefix,
                               replica->ipaddr);
    pcmk__xml_sanitize_id(id);
    xml_ip = create_resource(id, "heartbeat", "IPaddr2");

    xml_obj = pcmk__xe_create(xml_ip, PCMK_XE_INSTANCE_ATTRIBUTES);
    pcmk__xe_set_id(xml_obj, "%s-attributes-%d", bundle_data->prefix,
                    replica->offset);

    crm_create_nvpair_xml(xml_obj, NULL, "ip", replica->ipaddr);

    if (bundle_data->host_network != NULL) {
        crm_create_nvpair_xml(xml_obj, NULL, "nic", bundle_data->host_network);
    }

    crm_create_nvpair_xml(xml_obj, NULL, "cidr_netmask",
                          pcmk__s(bundle_data->host_netmask, "32"));

    xml_obj = pcmk__xe_create(xml_ip, PCMK_XE_OPERATIONS);
    crm_create_op_xml(xml_obj, id, PCMK_ACTION_MONITOR, "60s", NULL);

    // TODO: Other ops? Timeouts and intervals from underlying resource?

    if (pe__unpack_resource(xml_ip, &replica->ip, parent,
                            parent->priv->scheduler) != pcmk_rc_ok) {
        rc = pcmk_rc_unpack_error;
        goto done;
    }

    parent->priv->children = g_list_append(parent->priv->children, replica->ip);

done:
    free(id);
    pcmk__xml_free(xml_ip);
    return rc;
}

static const char*
container_agent_str(enum pe__container_agent t)
{
    switch (t) {
        case PE__CONTAINER_AGENT_DOCKER: return PE__CONTAINER_AGENT_DOCKER_S;
        case PE__CONTAINER_AGENT_PODMAN: return PE__CONTAINER_AGENT_PODMAN_S;
        default: // PE__CONTAINER_AGENT_UNKNOWN
            break;
    }
    return PE__CONTAINER_AGENT_UNKNOWN_S;
}

static int
create_container_resource(pcmk_resource_t *parent,
                          pcmk__bundle_replica_t *replica)
{
    char *id = NULL;
    xmlNode *xml_container = NULL;
    xmlNode *xml_obj = NULL;
    const char *agent_str = NULL;
    GString *buffer = NULL;
    GString *dbuffer = NULL;
    int rc = pcmk_rc_ok;
    const pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, parent);

    if ((bundle_data->agent_type != PE__CONTAINER_AGENT_DOCKER)
        && (bundle_data->agent_type != PE__CONTAINER_AGENT_PODMAN)) {

        rc = pcmk_rc_unpack_error;
        goto done;
    }

    agent_str = container_agent_str(bundle_data->agent_type);
    buffer = g_string_sized_new(4096);

    id = pcmk__assert_asprintf("%s-%s-%d", bundle_data->prefix, agent_str,
                               replica->offset);
    pcmk__xml_sanitize_id(id);
    xml_container = create_resource(id, "heartbeat", agent_str);

    xml_obj = pcmk__xe_create(xml_container, PCMK_XE_INSTANCE_ATTRIBUTES);
    pcmk__xe_set_id(xml_obj, "%s-attributes-%d", bundle_data->prefix,
                    replica->offset);

    crm_create_nvpair_xml(xml_obj, NULL, "image", bundle_data->image);
    crm_create_nvpair_xml(xml_obj, NULL, "allow_pull", PCMK_VALUE_TRUE);
    crm_create_nvpair_xml(xml_obj, NULL, "force_kill", PCMK_VALUE_FALSE);
    crm_create_nvpair_xml(xml_obj, NULL, "reuse", PCMK_VALUE_FALSE);

    if (bundle_data->agent_type == PE__CONTAINER_AGENT_DOCKER) {
        g_string_append(buffer, " --restart=no");
    }

    /* Set a container hostname only if we have an IP to map it to. The user can
     * set -h or --uts=host themselves if they want a nicer name for logs, but
     * this makes applications happy who need their  hostname to match the IP
     * they bind to.
     */
    if (bundle_data->ip_range_start != NULL) {
        g_string_append_printf(buffer, " -h %s-%d", bundle_data->prefix,
                               replica->offset);
    }

    g_string_append(buffer, " -e PCMK_stderr=1");

    if (bundle_data->container_network != NULL) {
        pcmk__g_strcat(buffer, " --net=", bundle_data->container_network, NULL);
    }

    if (bundle_data->control_port != NULL) {
        pcmk__g_strcat(buffer, " -e PCMK_" PCMK__ENV_REMOTE_PORT "=",
                       bundle_data->control_port, NULL);

    } else {
        g_string_append_printf(buffer, " -e PCMK_" PCMK__ENV_REMOTE_PORT "=%d",
                               DEFAULT_REMOTE_PORT);
    }

    for (GList *iter = bundle_data->mounts; iter != NULL; iter = iter->next) {
        pe__bundle_mount_t *mount = iter->data;
        char *source = NULL;

        if (pcmk__is_set(mount->flags, pe__bundle_mount_subdir)) {
            source = pcmk__assert_asprintf("%s/%s-%d", mount->source,
                                           bundle_data->prefix,
                                           replica->offset);
            pcmk__add_separated_word(&dbuffer, 1024, source, ",");
        }

        pcmk__g_strcat(buffer, " -v ", pcmk__s(source, mount->source), ":",
                       mount->target, NULL);

        if (mount->options != NULL) {
            pcmk__g_strcat(buffer, ":", mount->options, NULL);
        }

        free(source);
    }

    for (GList *iter = bundle_data->ports; iter != NULL; iter = iter->next) {
        pe__bundle_port_t *port = iter->data;

        if (replica->ipaddr != NULL) {
            pcmk__g_strcat(buffer, " -p ", replica->ipaddr, ":", port->source,
                           ":", port->target, NULL);

        } else if (!pcmk__str_eq(bundle_data->container_network,
                                 PCMK_VALUE_HOST, pcmk__str_none)) {

            // No need to do port mapping if net == host
            pcmk__g_strcat(buffer, " -p ", port->source, ":", port->target,
                           NULL);
        }
    }

    /* @COMPAT: We should use pcmk__add_word() here, but we can't yet, because
     * it would cause restarts during rolling upgrades.
     *
     * In a previous version of the container resource creation logic, if
     * bundle_data->launcher_options is not NULL, we append
     * (" %s", bundle_data->launcher_options) even if
     * bundle_data->launcher_options is an empty string. Likewise for
     * bundle_data->container_host_options. Using
     *
     *     pcmk__add_word(buffer, 0, bundle_data->launcher_options)
     *
     * removes that extra trailing space, causing a resource definition change.
     */
    if (bundle_data->launcher_options != NULL) {
        pcmk__g_strcat(buffer, " ", bundle_data->launcher_options, NULL);
    }

    if (bundle_data->container_host_options != NULL) {
        pcmk__g_strcat(buffer, " ", bundle_data->container_host_options, NULL);
    }

    crm_create_nvpair_xml(xml_obj, NULL, "run_opts", buffer->str);
    g_string_free(buffer, TRUE);

    crm_create_nvpair_xml(xml_obj, NULL, "mount_points",
                          (dbuffer != NULL)? dbuffer->str : "");
    if (dbuffer != NULL) {
        g_string_free(dbuffer, TRUE);
    }

    if (replica->child != NULL) {
        if (bundle_data->container_command != NULL) {
            crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                  bundle_data->container_command);
        } else {
            crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                  SBIN_DIR "/" PCMK__SERVER_REMOTED);
        }

        /* TODO: Allow users to specify their own?
         *
         * We just want to know if the container is alive; we'll monitor the
         * child independently.
         */
        crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
#if 0
        /* @TODO Consider supporting the use case where we can start and stop
         * resources, but not proxy local commands (such as setting node
         * attributes), by running the local executor in stand-alone mode.
         * However, this would probably be better done via ACLs as with other
         * Pacemaker Remote nodes.
         */
    } else if ((child != NULL) && bundle_data->untrusted) {
        crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                              CRM_DAEMON_DIR "/" PCMK__SERVER_EXECD);
        crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd",
                              CRM_DAEMON_DIR "/pacemaker/cts-exec-helper -c poke");
#endif
    } else {
        if (bundle_data->container_command != NULL) {
            crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                  bundle_data->container_command);
        }

        /* TODO: Allow users to specify their own?
         *
         * We don't know what's in the container, so we just want to know if it
         * is alive.
         */
        crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
    }

    xml_obj = pcmk__xe_create(xml_container, PCMK_XE_OPERATIONS);
    crm_create_op_xml(xml_obj, pcmk__xe_id(xml_container), PCMK_ACTION_MONITOR,
                      "60s", NULL);

    // TODO: Other ops? Timeouts and intervals from underlying resource?
    if (pe__unpack_resource(xml_container, &replica->container, parent,
                            parent->priv->scheduler) != pcmk_rc_ok) {

        rc = pcmk_rc_unpack_error;
        goto done;
    }

    pcmk__set_rsc_flags(replica->container, pcmk__rsc_replica_container);
    parent->priv->children = g_list_append(parent->priv->children,
                                           replica->container);

done:
    free(id);
    pcmk__xml_free(xml_container);
    return rc;
}

/*!
 * \brief Ban a node from a resource's (and its children's) allowed nodes list
 *
 * \param[in,out] rsc    Resource to modify
 * \param[in]     uname  Name of node to ban
 */
static void
disallow_node(pcmk_resource_t *rsc, const char *uname)
{
    void *match = g_hash_table_lookup(rsc->priv->allowed_nodes, uname);

    if (match) {
        ((pcmk_node_t *) match)->assign->score = -PCMK_SCORE_INFINITY;
        ((pcmk_node_t *) match)->assign->probe_mode = pcmk__probe_never;
    }
    g_list_foreach(rsc->priv->children, (GFunc) disallow_node, (void *) uname);
}

static int
create_remote_resource(pcmk_resource_t *parent, pcmk__bundle_replica_t *replica)
{
    GHashTableIter iter;
    pcmk_node_t *node = NULL;
    pcmk_node_t *copy = NULL;
    xmlNode *xml_remote = NULL;
    char *id = NULL;
    const char *uname = NULL;
    const char *connect_name = NULL;
    pcmk_scheduler_t *scheduler = parent->priv->scheduler;
    int rc = pcmk_rc_ok;
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, parent);

    if (replica->child == NULL) {
        goto done;
    }

    id = pcmk__assert_asprintf("%s-%d", bundle_data->prefix, replica->offset);

    if (pe_find_resource(scheduler->priv->resources, id) != NULL) {
        free(id);

        // The biggest hammer we have
        id = pcmk__assert_asprintf("pcmk-internal-%s-remote-%d",
                                   replica->child->id, replica->offset);

        // @TODO return error instead of asserting?
        pcmk__assert(pe_find_resource(scheduler->priv->resources, id) == NULL);
    }

    /* REMOTE_CONTAINER_HACK: Using "#uname" as the server name when the
     * connection does not have its own IP is a magic string that we use to
     * support nested remotes (i.e. a bundle running on a remote node).
     */
    connect_name = pcmk__s(replica->ipaddr, "#uname");

    /* This sets replica->container as replica->remote's container, which is
     * similar to what happens with guest nodes. This is how the scheduler knows
     * that the bundle node is fenced by recovering the container, and that
     * remote should be ordered relative to the container.
     */
    if (bundle_data->control_port != NULL) {
        xml_remote = pe_create_remote_xml(NULL, id, replica->container->id,
                                          NULL, NULL, NULL, connect_name,
                                          bundle_data->control_port);

    } else {
        char *port_s = pcmk__itoa(DEFAULT_REMOTE_PORT);

        xml_remote = pe_create_remote_xml(NULL, id, replica->container->id,
                                          NULL, NULL, NULL, connect_name,
                                          port_s);
        free(port_s);
    }

    /* Abandon our created ID, and pull the copy from the XML, because we need
     * something that will get freed during scheduler data cleanup to use as the
     * node ID and uname.
     */
    uname = pcmk__xe_id(xml_remote);

    /* Ensure a node has been created for the guest (it may have already been,
     * if it has a permanent node attribute), and ensure its weight is -INFINITY
     * so no other resources can run on it.
     */
    node = pcmk_find_node(scheduler, uname);

    if (node == NULL) {
        node = pe__create_node(uname, uname, PCMK_VALUE_REMOTE,
                               -PCMK_SCORE_INFINITY, scheduler);

    } else {
        node->assign->score = -PCMK_SCORE_INFINITY;
    }

    node->assign->probe_mode = pcmk__probe_never;

    /* unpack_remote_nodes() ensures that each remote node and guest node has a
     * pcmk_node_t entry. Ideally, it would do the same for bundle nodes.
     * Unfortunately, a bundle has to be mostly unpacked before it's obvious
     * what nodes will be needed, so we do it just above.
     *
     * Worse, that means that the node may have been utilized while unpacking
     * other resources, without our weight correction. The most likely place for
     * this to happen is when pe__unpack_resource() calls resource_location() to
     * set a default score in symmetric clusters. This adds a node *copy* to
     * each resource's allowed nodes, and these copies will have the wrong
     * weight.
     *
     * As a hacky workaround, fix those copies here.
     *
     * @TODO Possible alternative: ensure bundles are unpacked before other
     * resources, so the weight is correct before any copies are made.
     */
    g_list_foreach(scheduler->priv->resources, (GFunc) disallow_node,
                   (void *) uname);

    replica->node = pe__copy_node(node);
    replica->node->assign->score = 500;
    replica->node->assign->probe_mode = pcmk__probe_exclusive;

    // Ensure the node shows up as allowed and with the correct discovery set
    g_clear_pointer(&replica->child->priv->allowed_nodes, g_hash_table_destroy);

    replica->child->priv->allowed_nodes =
        pcmk__strkey_table(NULL, pcmk__free_node_copy);

    g_hash_table_insert(replica->child->priv->allowed_nodes,
                        (void *) replica->node->priv->id,
                        pe__copy_node(replica->node));

    copy = pe__copy_node(replica->node);
    copy->assign->score = -PCMK_SCORE_INFINITY;

    g_hash_table_insert(replica->child->priv->parent->priv->allowed_nodes,
                        (void *) replica->node->priv->id, copy);

    if (pe__unpack_resource(xml_remote, &replica->remote, parent,
                            scheduler) != pcmk_rc_ok) {

        rc = pcmk_rc_unpack_error;
        goto done;
    }

    // Make Coverity happy
    pcmk__assert(replica->remote != NULL);

    g_hash_table_iter_init(&iter, replica->remote->priv->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
        if (pcmk__is_pacemaker_remote_node(node)) {
            // Remote resources can only run on 'normal' cluster node
            node->assign->score = -PCMK_SCORE_INFINITY;
        }
    }

    replica->node->priv->remote = replica->remote;

    // Ensure pcmk__is_guest_or_bundle_node() functions correctly
    replica->remote->priv->launcher = replica->container;

    /* A bundle's #kind is closer to "container" (guest node) than the "remote"
     * set by pe__create_node()
     */
    pcmk__insert_dup(replica->node->priv->attrs, CRM_ATTR_KIND, "container");

    /* One effect of this is that unpack_launcher() will add replica->remote to
     * replica->container's launched resources, which will make
     * pe__resource_contains_guest_node() true for replica->container.
     *
     * replica->child does NOT get added to replica->container's launched
     * resources. The only noticeable effect if it did would be for its fail
     * count to be taken into account when checking replica->container's
     * migration threshold.
     */
    parent->priv->children = g_list_append(parent->priv->children,
                                           replica->remote);

done:
    free(id);
    pcmk__xml_free(xml_remote);
    return rc;
}

static int
create_replica_resources(pcmk_resource_t *parent,
                         pcmk__bundle_replica_t *replica)
{
    int rc = pcmk_rc_ok;

    rc = create_container_resource(parent, replica);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = create_ip_resource(parent, replica);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = create_remote_resource(parent, replica);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if ((replica->child != NULL) && (replica->ipaddr != NULL)) {
        pcmk__insert_meta(replica->child->priv, "external-ip", replica->ipaddr);
    }

    if (replica->remote != NULL) {
        /*
         * Allow the remote connection resource to be allocated to a
         * different node than the one on which the container is active.
         *
         * This makes it possible to have Pacemaker Remote nodes running
         * containers with the remote executor inside in order to start
         * services inside those containers.
         */
        pcmk__set_rsc_flags(replica->remote, pcmk__rsc_remote_nesting_allowed);
    }
    return rc;
}

static void
mount_add(pe__bundle_variant_data_t *bundle_data, const char *source,
          const char *target, const char *options, uint32_t flags)
{
    pe__bundle_mount_t *mount = pcmk__assert_alloc(1,
                                                   sizeof(pe__bundle_mount_t));

    mount->source = pcmk__str_copy(source);
    mount->target = pcmk__str_copy(target);
    mount->options = pcmk__str_copy(options);
    mount->flags = flags;
    bundle_data->mounts = g_list_append(bundle_data->mounts, mount);
}

static void
mount_free(pe__bundle_mount_t *mount)
{
    free(mount->source);
    free(mount->target);
    free(mount->options);
    free(mount);
}

static void
port_free(pe__bundle_port_t *port)
{
    free(port->source);
    free(port->target);
    free(port);
}

static pcmk__bundle_replica_t *
replica_for_remote(pcmk_resource_t *remote)
{
    pcmk_resource_t *top = remote;
    pe__bundle_variant_data_t *bundle_data = NULL;

    if (top == NULL) {
        return NULL;
    }
    while (top->priv->parent != NULL) {
        top = top->priv->parent;
    }

    get_bundle_variant_data(bundle_data, top);
    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;

        if (replica->remote == remote) {
            return replica;
        }
    }
    CRM_LOG_ASSERT(FALSE);
    return NULL;
}

bool
pe__bundle_needs_remote_name(pcmk_resource_t *rsc)
{
    const char *value;
    GHashTable *params = NULL;

    if (rsc == NULL) {
        return false;
    }

    // Use NULL node since pcmk__bundle_expand() uses that to set value
    params = pe_rsc_params(rsc, NULL, rsc->priv->scheduler);
    value = g_hash_table_lookup(params, PCMK_REMOTE_RA_ADDR);

    return pcmk__str_eq(value, "#uname", pcmk__str_casei)
           && xml_contains_remote_node(rsc->priv->xml);
}

const char *
pe__add_bundle_remote_name(pcmk_resource_t *rsc, xmlNode *xml,
                           const char *field)
{
    // REMOTE_CONTAINER_HACK: Allow remote nodes that start containers with pacemaker remote inside

    pcmk_node_t *node = NULL;
    pcmk__bundle_replica_t *replica = NULL;

    if (!pe__bundle_needs_remote_name(rsc)) {
        return NULL;
    }

    replica = replica_for_remote(rsc);
    if (replica == NULL) {
        return NULL;
    }

    node = replica->container->priv->assigned_node;
    if (node == NULL) {
        /* If it won't be running anywhere after the
         * transition, go with where it's running now.
         */
        node = pcmk__current_node(replica->container);
    }

    if(node == NULL) {
        pcmk__trace("Cannot determine address for bundle connection %s",
                    rsc->id);
        return NULL;
    }

    pcmk__trace("Setting address for bundle connection %s to bundle host %s",
                rsc->id, pcmk__node_name(node));
    if(xml != NULL && field != NULL) {
        pcmk__xe_set(xml, field, node->priv->name);
    }

    return node->priv->name;
}

/*!
 * \internal
 * \brief Get container XML element from a bundle resource and set agent type
 *
 * On success, this sets the \c agent_type field of the resource's bundle
 * private data.
 *
 * \param[in,out] rsc  Bundle resource
 *
 * \return Child XML element for container within <tt>rsc->priv->xml</tt>
 */
static xmlNode *
get_container_xml(pcmk_resource_t *rsc)
{
    xmlNode *xml = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, rsc);

    xml = pcmk__xe_first_child(rsc->priv->xml, PCMK_XE_DOCKER, NULL, NULL);
    if (xml != NULL) {
        bundle_data->agent_type = PE__CONTAINER_AGENT_DOCKER;
        return xml;
    }

    xml = pcmk__xe_first_child(rsc->priv->xml, PCMK_XE_PODMAN, NULL, NULL);
    if (xml != NULL) {
        bundle_data->agent_type = PE__CONTAINER_AGENT_PODMAN;
        return xml;
    }

    return NULL;
}

/*!
 * \internal
 * \brief Unpack a bundle resource's container child into bundle private data
 *
 * This does not create or unpack a container resource.
 *
 * \param[in,out] rsc  Bundle resource
 *
 * \return Standard Pacemaker return code
 */
static int
unpack_bundle_container(pcmk_resource_t *rsc)
{
    xmlNode *xml = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    const char *value = NULL;

    xml = get_container_xml(rsc);
    if (xml == NULL) {
        return pcmk_rc_unpack_error;
    }

    get_bundle_variant_data(bundle_data, rsc);

    // Use 0 for default, minimum, and invalid PCMK_XA_PROMOTED_MAX
    value = pcmk__xe_get(xml, PCMK_XA_PROMOTED_MAX);
    pcmk__scan_min_int(value, &bundle_data->promoted_max, 0);

    // Default nreplicas to PCMK_XA_PROMOTED_MAX if specified or 1 otherwise
    value = pcmk__xe_get(xml, PCMK_XA_REPLICAS);

    if ((value == NULL) && (bundle_data->promoted_max > 0)) {
        bundle_data->nreplicas = bundle_data->promoted_max;

    } else {
        pcmk__scan_min_int(value, &bundle_data->nreplicas, 1);
    }

    /* Communication between containers on the same host via the floating IPs
     * works only if the container is started with:
     *   --userland-proxy=false --ip-masq=false
     */
    value = pcmk__xe_get(xml, PCMK_XA_REPLICAS_PER_HOST);
    pcmk__scan_min_int(value, &bundle_data->nreplicas_per_host, 1);

    if (bundle_data->nreplicas_per_host == 1) {
        pcmk__clear_rsc_flags(rsc, pcmk__rsc_unique);
    }

    bundle_data->container_command = pcmk__xe_get_copy(xml,
                                                       PCMK_XA_RUN_COMMAND);
    bundle_data->launcher_options = pcmk__xe_get_copy(xml, PCMK_XA_OPTIONS);
    bundle_data->image = pcmk__xe_get_copy(xml, PCMK_XA_IMAGE);
    bundle_data->container_network = pcmk__xe_get_copy(xml, PCMK_XA_NETWORK);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Unpack a bundle resource's network child into bundle private data
 *
 * This does not create or unpack an IP resource.
 *
 * \param[in,out] rsc  Bundle resource
 */
static void
unpack_bundle_network(pcmk_resource_t *rsc)
{
    xmlNode *xml = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    const char *value = NULL;

    xml = pcmk__xe_first_child(rsc->priv->xml, PCMK_XE_NETWORK, NULL, NULL);
    if (xml == NULL) {
        return;
    }

    get_bundle_variant_data(bundle_data, rsc);

    bundle_data->ip_range_start = pcmk__xe_get_copy(xml,
                                                    PCMK_XA_IP_RANGE_START);
    bundle_data->host_netmask = pcmk__xe_get_copy(xml, PCMK_XA_HOST_NETMASK);
    bundle_data->host_network = pcmk__xe_get_copy(xml, PCMK_XA_HOST_INTERFACE);
    bundle_data->control_port = pcmk__xe_get_copy(xml, PCMK_XA_CONTROL_PORT);

    value = pcmk__xe_get(xml, PCMK_XA_ADD_HOST);
    if ((value == NULL)
        || (pcmk__parse_bool(value, &bundle_data->add_host) != pcmk_rc_ok)) {

        // Default to true if unset or invaid
        bundle_data->add_host = true;
    }

    for (const xmlNode *mapping = pcmk__xe_first_child(xml,
                                                       PCMK_XE_PORT_MAPPING,
                                                       NULL, NULL);
         mapping != NULL;
         mapping = pcmk__xe_next(mapping, PCMK_XE_PORT_MAPPING)) {

        pe__bundle_port_t *port = pcmk__assert_alloc(1,
                                                     sizeof(pe__bundle_port_t));

        port->source = pcmk__xe_get_copy(mapping, PCMK_XA_PORT);

        if (port->source == NULL) {
            port->source = pcmk__xe_get_copy(mapping, PCMK_XA_RANGE);

        } else {
            port->target = pcmk__xe_get_copy(mapping, PCMK_XA_INTERNAL_PORT);
        }

        if (pcmk__str_empty(port->source)) {
            pcmk__config_err("Invalid " PCMK_XA_PORT " directive %s",
                             pcmk__xe_id(mapping));
            port_free(port);
            return;
        }

        if (port->target == NULL) {
            port->target = pcmk__str_copy(port->source);
        }

        bundle_data->ports = g_list_append(bundle_data->ports, port);
    }
}

/*!
 * \internal
 * \brief Unpack a bundle resource's storage child into bundle private data
 *
 * \param[in,out] rsc  Bundle resource
 *
 * \return \c true if a mount with target \c "/var/log" was unpacked, or
 *         \c false otherwise
 */
static bool
unpack_bundle_storage(pcmk_resource_t *rsc)
{
    xmlNode *xml = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    bool have_log_mount = false;

    xml = pcmk__xe_first_child(rsc->priv->xml, PCMK_XE_STORAGE, NULL, NULL);
    if (xml == NULL) {
        return false;
    }

    get_bundle_variant_data(bundle_data, rsc);

    for (const xmlNode *mapping = pcmk__xe_first_child(xml,
                                                       PCMK_XE_STORAGE_MAPPING,
                                                       NULL, NULL);
         mapping != NULL;
         mapping = pcmk__xe_next(mapping, PCMK_XE_STORAGE_MAPPING)) {

        const char *source = pcmk__xe_get(mapping, PCMK_XA_SOURCE_DIR);
        const char *target = pcmk__xe_get(mapping, PCMK_XA_TARGET_DIR);
        const char *options = pcmk__xe_get(mapping, PCMK_XA_OPTIONS);
        uint32_t flags = pe__bundle_mount_none;

        if (source == NULL) {
            source = pcmk__xe_get(mapping, PCMK_XA_SOURCE_DIR_ROOT);
            flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,
                                       "Bundle mount", pcmk__xe_id(mapping),
                                       flags, pe__bundle_mount_subdir,
                                       "pe__bundle_mount_subdir");
        }

        if ((source == NULL) || (target == NULL)) {
            pcmk__config_err("Invalid mount directive %s",
                             pcmk__xe_id(mapping));
            continue;
        }

        mount_add(bundle_data, source, target, options, flags);
        if (pcmk__str_eq(target, "/var/log", pcmk__str_none)) {
            have_log_mount = true;
        }
    }

    return have_log_mount;
}

/*!
 * \internal
 * \brief Validate a bundle's networking configuration for running a primitive
 *
 * The networking configuration is considered valid if an IP range or control
 * port has been specified. If a control port is used without an IP range,
 * replicas per host must be 1.
 *
 * \param[in,out] rsc  Bundle resource
 *
 * \return \c true if the configuration is valid, or \c false otherwise
 */
static bool
valid_network_for_primitive(pcmk_resource_t *rsc)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, rsc);

    if (bundle_data->ip_range_start != NULL) {
        return true;
    }

    if (bundle_data->control_port == NULL) {
        return false;
    }

    if (bundle_data->nreplicas_per_host > 1) {
        pcmk__config_warn("Using " PCMK_XA_REPLICAS_PER_HOST "=1 for %s "
                          "because specifying " PCMK_XA_CONTROL_PORT " "
                          "requires it", bundle_data->prefix);
        bundle_data->nreplicas_per_host = 1;
        pcmk__clear_rsc_flags(rsc, pcmk__rsc_unique);
    }

    return true;
}

/*!
 * \internal
 * \brief Unpack a bundle resource's primitive child
 *
 * If a primitive child is found, this creates a \c PCMK_XE_CLONE element
 * containing a copy of the primitive element and appropriate options. This does
 * not unpack the created element.
 *
 * \param[in,out] rsc        Bundle resource
 * \param[out]    clone_xml  Where to store newly allocated \c PCMK_XE_CLONE
 *
 * \return Standard Pacemaker return code
 *
 * \note The caller is responsible for freeing \p *clone_xml using
 *       \c pcmk__xml_free().
 */
static int
unpack_bundle_primitive(pcmk_resource_t *rsc, xmlNode **clone_xml)
{
    xmlNode *xml = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    const char *suffix = NULL;
    xmlNode *xml_set = NULL;
    xmlNode *nvpair = NULL;

    xml = pcmk__xe_first_child(rsc->priv->xml, PCMK_XE_PRIMITIVE, NULL, NULL);
    if (xml == NULL) {
        return pcmk_rc_ok;
    }

    if (!valid_network_for_primitive(rsc)) {
        pcmk__config_err("Cannot control %s inside %s without either "
                         PCMK_XA_IP_RANGE_START " or " PCMK_XA_CONTROL_PORT,
                         rsc->id, pcmk__xe_id(xml));
        return pcmk_rc_unpack_error;
    }

    get_bundle_variant_data(bundle_data, rsc);

    *clone_xml = pcmk__xe_create(NULL, PCMK_XE_CLONE);

    /* @COMPAT We no longer use the <master> tag, but we need to keep it as part
     * of the resource name, so that bundles don't restart in a rolling upgrade.
     * (It also avoids needing to change regression tests.)
     */
    suffix = (bundle_data->promoted_max > 0)? "master" : PCMK_XE_CLONE;
    pcmk__xe_set_id(*clone_xml, "%s-%s", bundle_data->prefix, suffix);

    xml_set = pcmk__xe_create(*clone_xml, PCMK_XE_META_ATTRIBUTES);
    pcmk__xe_set_id(xml_set, "%s-%s-meta", bundle_data->prefix,
                    (*clone_xml)->name);

    crm_create_nvpair_xml(xml_set, NULL, PCMK_META_ORDERED, PCMK_VALUE_TRUE);

    nvpair = crm_create_nvpair_xml(xml_set, NULL, PCMK_META_CLONE_MAX, NULL);
    pcmk__xe_set_int(nvpair, PCMK_XA_VALUE, bundle_data->nreplicas);

    nvpair = crm_create_nvpair_xml(xml_set, NULL, PCMK_META_CLONE_NODE_MAX,
                                   NULL);
    pcmk__xe_set_int(nvpair, PCMK_XA_VALUE, bundle_data->nreplicas_per_host);

    nvpair = crm_create_nvpair_xml(xml_set, NULL, PCMK_META_GLOBALLY_UNIQUE,
                                   NULL);
    pcmk__xe_set_bool(nvpair, PCMK_XA_VALUE,
                      (bundle_data->nreplicas_per_host > 1));

    if (bundle_data->promoted_max != 0) {
        crm_create_nvpair_xml(xml_set, NULL, PCMK_META_PROMOTABLE,
                              PCMK_VALUE_TRUE);

        nvpair = crm_create_nvpair_xml(xml_set, NULL, PCMK_META_PROMOTED_MAX,
                                       NULL);
        pcmk__xe_set_int(nvpair, PCMK_XA_VALUE, bundle_data->promoted_max);
    }

    //pcmk__xe_set(xml, PCMK_XA_ID, bundle_data->prefix);
    pcmk__xml_copy(*clone_xml, xml);

    return pcmk_rc_ok;
}

bool
pe__unpack_bundle(pcmk_resource_t *rsc)
{
    xmlNode *clone_xml = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    bool have_log_mount = false;

    pcmk__assert(rsc != NULL);
    pcmk__rsc_trace(rsc, "Processing resource %s...", rsc->id);

    bundle_data = pcmk__assert_alloc(1, sizeof(pe__bundle_variant_data_t));
    rsc->priv->variant_opaque = bundle_data;
    bundle_data->prefix = pcmk__str_copy(rsc->id);

    if (unpack_bundle_container(rsc) != pcmk_rc_ok) {
        return false;
    }

    unpack_bundle_network(rsc);

    have_log_mount = unpack_bundle_storage(rsc);

    if (unpack_bundle_primitive(rsc, &clone_xml) != pcmk_rc_ok) {
        return false;
    }

    if (clone_xml != NULL) {
        int lpc = 0;
        pe__bundle_port_t *port = NULL;
        GString *buffer = NULL;
        int rc = pe__unpack_resource(clone_xml, &bundle_data->child, rsc,
                                     rsc->priv->scheduler);

        pcmk__xml_free(clone_xml);

        if (rc != pcmk_rc_ok) {
            return false;
        }

        /* Currently, we always map the default authentication key location
         * into the same location inside the container.
         *
         * Ideally, we would respect the host's PCMK_authkey_location, but:
         * - it may be different on different nodes;
         * - the actual connection will do extra checking to make sure the key
         *   file exists and is readable, that we can't do here on the DC
         * - tools such as crm_resource and crm_simulate may not have the same
         *   environment variables as the cluster, causing operation digests to
         *   differ
         *
         * Always using the default location inside the container is fine,
         * because we control the pacemaker_remote environment, and it avoids
         * having to pass another environment variable to the container.
         *
         * @TODO A better solution may be to have only pacemaker_remote use the
         * environment variable, and have the cluster nodes use a new
         * cluster option for key location. This would introduce the limitation
         * of the location being the same on all cluster nodes, but that's
         * reasonable.
         */
        mount_add(bundle_data, DEFAULT_REMOTE_KEY_LOCATION,
                  DEFAULT_REMOTE_KEY_LOCATION, NULL, pe__bundle_mount_none);

        if (!have_log_mount) {
            mount_add(bundle_data, CRM_BUNDLE_DIR, "/var/log", NULL,
                      pe__bundle_mount_subdir);
        }

        port = pcmk__assert_alloc(1, sizeof(pe__bundle_port_t));
        if(bundle_data->control_port) {
            port->source = pcmk__str_copy(bundle_data->control_port);
        } else {
            /* If we wanted to respect PCMK_remote_port, we could use
             * crm_default_remote_port() here and elsewhere in this file instead
             * of DEFAULT_REMOTE_PORT.
             *
             * However, it gains nothing, since we control both the container
             * environment and the connection resource parameters, and the user
             * can use a different port if desired by setting
             * PCMK_XA_CONTROL_PORT.
             */
            port->source = pcmk__itoa(DEFAULT_REMOTE_PORT);
        }
        port->target = pcmk__str_copy(port->source);
        bundle_data->ports = g_list_append(bundle_data->ports, port);

        buffer = g_string_sized_new(1024);
        for (GList *iter = bundle_data->child->priv->children;
             iter != NULL; iter = iter->next) {

            pcmk__bundle_replica_t *replica = NULL;

            replica = pcmk__assert_alloc(1, sizeof(pcmk__bundle_replica_t));
            replica->child = iter->data;
            pcmk__set_rsc_flags(replica->child, pcmk__rsc_exclusive_probes);
            replica->offset = lpc++;

            // Ensure the child's notify gets set based on the underlying primitive's value
            if (pcmk__is_set(replica->child->flags, pcmk__rsc_notify)) {
                pcmk__set_rsc_flags(bundle_data->child, pcmk__rsc_notify);
            }

            allocate_ip(bundle_data, replica, buffer);
            bundle_data->replicas = g_list_append(bundle_data->replicas,
                                                  replica);

            // coverity[null_field : FALSE] replica->child can't be NULL here
            bundle_data->attribute_target =
                g_hash_table_lookup(replica->child->priv->meta,
                                    PCMK_META_CONTAINER_ATTRIBUTE_TARGET);
        }
        bundle_data->container_host_options = g_string_free(buffer, false);

        if (bundle_data->attribute_target) {
            pcmk__insert_dup(rsc->priv->meta,
                             PCMK_META_CONTAINER_ATTRIBUTE_TARGET,
                             bundle_data->attribute_target);
            pcmk__insert_dup(bundle_data->child->priv->meta,
                             PCMK_META_CONTAINER_ATTRIBUTE_TARGET,
                             bundle_data->attribute_target);
        }

    } else {
        // Just a naked container, no pacemaker-remote
        GString *buffer = g_string_sized_new(1024);

        for (int lpc = 0; lpc < bundle_data->nreplicas; lpc++) {
            pcmk__bundle_replica_t *replica = NULL;

            replica = pcmk__assert_alloc(1, sizeof(pcmk__bundle_replica_t));
            replica->offset = lpc;
            allocate_ip(bundle_data, replica, buffer);
            bundle_data->replicas = g_list_append(bundle_data->replicas,
                                                  replica);
        }
        bundle_data->container_host_options = g_string_free(buffer, false);
    }

    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;

        if (create_replica_resources(rsc, replica) != pcmk_rc_ok) {
            pcmk__config_err("Failed unpacking resource %s", rsc->id);
            pcmk__free_resource(rsc);
            return false;
        }

        /* Utilization needs special handling for bundles. It makes no sense for
         * the inner primitive to have utilization, because it is tied
         * one-to-one to the guest node created by the container resource -- and
         * there's no way to set capacities for that guest node anyway.
         *
         * What the user really wants is to configure utilization for the
         * container. However, the schema only allows utilization for
         * primitives, and the container resource is implicit anyway, so the
         * user can *only* configure utilization for the inner primitive. If
         * they do, move the primitive's utilization values to the container.
         *
         * @TODO This means that bundles without an inner primitive can't have
         * utilization. An alternative might be to allow utilization values in
         * the top-level bundle XML in the schema, and copy those to each
         * container.
         */
        if (replica->child != NULL) {
            GHashTable *empty = replica->container->priv->utilization;

            replica->container->priv->utilization =
                replica->child->priv->utilization;

            replica->child->priv->utilization = empty;
        }
    }

    if (bundle_data->child) {
        rsc->priv->children = g_list_append(rsc->priv->children,
                                            bundle_data->child);
    }
    return true;
}

static int
replica_resource_active(pcmk_resource_t *rsc, gboolean all)
{
    if (rsc) {
        gboolean child_active = rsc->priv->fns->active(rsc, all);

        if (child_active && !all) {
            return TRUE;
        } else if (!child_active && all) {
            return FALSE;
        }
    }
    return -1;
}

bool
pe__bundle_active(const pcmk_resource_t *rsc, bool all)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    GList *iter = NULL;

    get_bundle_variant_data(bundle_data, rsc);
    for (iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;
        int rsc_active;

        rsc_active = replica_resource_active(replica->ip, all);
        if (rsc_active >= 0) {
            return (bool) rsc_active;
        }

        rsc_active = replica_resource_active(replica->child, all);
        if (rsc_active >= 0) {
            return (bool) rsc_active;
        }

        rsc_active = replica_resource_active(replica->container, all);
        if (rsc_active >= 0) {
            return (bool) rsc_active;
        }

        rsc_active = replica_resource_active(replica->remote, all);
        if (rsc_active >= 0) {
            return (bool) rsc_active;
        }
    }

    /* If "all" is TRUE, we've already checked that no resources were inactive,
     * so return TRUE; if "all" is FALSE, we didn't find any active resources,
     * so return FALSE.
     */
    return all;
}

/*!
 * \internal
 * \brief Find the bundle replica corresponding to a given node
 *
 * \param[in] bundle  Top-level bundle resource
 * \param[in] node    Node to search for
 *
 * \return Bundle replica if found, NULL otherwise
 */
pcmk_resource_t *
pe__find_bundle_replica(const pcmk_resource_t *bundle, const pcmk_node_t *node)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    pcmk__assert((bundle != NULL) && (node != NULL));

    get_bundle_variant_data(bundle_data, bundle);
    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;

        pcmk__assert((replica != NULL) && (replica->node != NULL));
        if (pcmk__same_node(replica->node, node)) {
            return replica->child;
        }
    }
    return NULL;
}

PCMK__OUTPUT_ARGS("bundle", "uint32_t", "pcmk_resource_t *", "GList *",
                  "GList *")
int
pe__bundle_xml(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    pe__bundle_variant_data_t *bundle_data = NULL;
    int rc = pcmk_rc_no_output;
    gboolean printed_header = FALSE;
    bool print_everything = true;

    const char *desc = NULL;

    pcmk__assert(rsc != NULL);
    get_bundle_variant_data(bundle_data, rsc);

    if (rsc->priv->fns->is_filtered(rsc, only_rsc, true)) {
        return rc;
    }

    print_everything = pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches);

    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;
        pcmk_resource_t *ip = replica->ip;
        pcmk_resource_t *child = replica->child;
        pcmk_resource_t *container = replica->container;
        pcmk_resource_t *remote = replica->remote;
        char *id = NULL;
        gboolean print_ip, print_child, print_ctnr, print_remote;

        pcmk__assert(replica != NULL);

        if (pcmk__rsc_filtered_by_node(container, only_node)) {
            continue;
        }

        print_ip = (ip != NULL)
                   && !ip->priv->fns->is_filtered(ip, only_rsc,
                                                  print_everything);
        print_child = (child != NULL)
                      && !child->priv->fns->is_filtered(child, only_rsc,
                                                        print_everything);
        print_ctnr = !container->priv->fns->is_filtered(container, only_rsc,
                                                        print_everything);
        print_remote = (remote != NULL)
                       && !remote->priv->fns->is_filtered(remote, only_rsc,
                                                          print_everything);

        if (!print_everything && !print_ip && !print_child && !print_ctnr && !print_remote) {
            continue;
        }

        if (!printed_header) {
            const char *type = container_agent_str(bundle_data->agent_type);
            const char *unique = pcmk__flag_text(rsc->flags, pcmk__rsc_unique);
            const char *maintenance = pcmk__flag_text(rsc->flags,
                                                      pcmk__rsc_maintenance);
            const char *managed = pcmk__flag_text(rsc->flags,
                                                  pcmk__rsc_managed);
            const char *failed = pcmk__flag_text(rsc->flags, pcmk__rsc_failed);

            printed_header = TRUE;

            desc = pe__resource_description(rsc, show_opts);

            rc = pe__name_and_nvpairs_xml(out, true, PCMK_XE_BUNDLE,
                                          PCMK_XA_ID, rsc->id,
                                          PCMK_XA_TYPE, type,
                                          PCMK_XA_IMAGE, bundle_data->image,
                                          PCMK_XA_UNIQUE, unique,
                                          PCMK_XA_MAINTENANCE, maintenance,
                                          PCMK_XA_MANAGED, managed,
                                          PCMK_XA_FAILED, failed,
                                          PCMK_XA_DESCRIPTION, desc,
                                          NULL);
            pcmk__assert(rc == pcmk_rc_ok);
        }

        id = pcmk__itoa(replica->offset);
        rc = pe__name_and_nvpairs_xml(out, true, PCMK_XE_REPLICA,
                                      PCMK_XA_ID, id,
                                      NULL);
        free(id);
        pcmk__assert(rc == pcmk_rc_ok);

        if (print_ip) {
            out->message(out, (const char *) ip->priv->xml->name, show_opts,
                         ip, only_node, only_rsc);
        }

        if (print_child) {
            out->message(out, (const char *) child->priv->xml->name,
                         show_opts, child, only_node, only_rsc);
        }

        if (print_ctnr) {
            out->message(out, (const char *) container->priv->xml->name,
                         show_opts, container, only_node, only_rsc);
        }

        if (print_remote) {
            out->message(out, (const char *) remote->priv->xml->name,
                         show_opts, remote, only_node, only_rsc);
        }

        pcmk__output_xml_pop_parent(out); // replica
    }

    if (printed_header) {
        pcmk__output_xml_pop_parent(out); // bundle
    }

    return rc;
}

static void
pe__bundle_replica_output_html(pcmk__output_t *out,
                               pcmk__bundle_replica_t *replica,
                               pcmk_node_t *node, uint32_t show_opts)
{
    const pcmk_resource_t *child_rsc = replica->child;
    const pcmk_resource_t *remote_rsc = replica->remote;
    GString *buffer = g_string_sized_new(128);

    if (child_rsc == NULL) {
        child_rsc = replica->container;
    }
    if (remote_rsc == NULL) {
        remote_rsc = replica->container;
    }

    g_string_append(buffer, rsc_printable_id(remote_rsc));
    if (replica->ipaddr != NULL) {
        pcmk__g_strcat(buffer, " (", replica->ipaddr, ")", NULL);
    }

    pe__common_output_html(out, child_rsc, buffer->str, node, show_opts);
    g_string_free(buffer, TRUE);
}

/*!
 * \internal
 * \brief Get a string describing a resource's unmanaged state or lack thereof
 *
 * \param[in] rsc  Resource to describe
 *
 * \return A string indicating that a resource is in maintenance mode or
 *         otherwise unmanaged, or an empty string otherwise
 */
static const char *
get_unmanaged_str(const pcmk_resource_t *rsc)
{
    if (pcmk__is_set(rsc->flags, pcmk__rsc_maintenance)) {
        return " (maintenance)";
    }
    if (!pcmk__is_set(rsc->flags, pcmk__rsc_managed)) {
        return " (unmanaged)";
    }
    return "";
}

PCMK__OUTPUT_ARGS("bundle", "uint32_t", "pcmk_resource_t *", "GList *",
                  "GList *")
int
pe__bundle_html(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    const char *desc = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    int rc = pcmk_rc_no_output;
    bool print_everything = true;

    pcmk__assert(rsc != NULL);
    get_bundle_variant_data(bundle_data, rsc);

    desc = pe__resource_description(rsc, show_opts);

    if (rsc->priv->fns->is_filtered(rsc, only_rsc, true)) {
        return rc;
    }

    print_everything = pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches);

    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;
        pcmk_resource_t *ip = replica->ip;
        pcmk_resource_t *child = replica->child;
        pcmk_resource_t *container = replica->container;
        pcmk_resource_t *remote = replica->remote;
        gboolean print_ip, print_child, print_ctnr, print_remote;

        pcmk__assert(replica != NULL);

        if (pcmk__rsc_filtered_by_node(container, only_node)) {
            continue;
        }

        print_ip = (ip != NULL)
                   && !ip->priv->fns->is_filtered(ip, only_rsc,
                                                  print_everything);
        print_child = (child != NULL)
                      && !child->priv->fns->is_filtered(child, only_rsc,
                                                        print_everything);
        print_ctnr = !container->priv->fns->is_filtered(container, only_rsc,
                                                        print_everything);
        print_remote = (remote != NULL)
                       && !remote->priv->fns->is_filtered(remote, only_rsc,
                                                          print_everything);

        if (pcmk__is_set(show_opts, pcmk_show_implicit_rscs)
            || (!print_everything
                && (print_ip || print_child || print_ctnr || print_remote))) {
            /* The text output messages used below require pe_print_implicit to
             * be set to do anything.
             */
            const bool multiple = (bundle_data->nreplicas > 1);
            const bool unique = pcmk__is_set(rsc->flags, pcmk__rsc_unique);
            const uint32_t new_show_opts = show_opts | pcmk_show_implicit_rscs;

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc,
                                     "Container bundle%s: %s [%s]%s%s%s%s%s",
                                     (multiple? " set" : ""), rsc->id,
                                     bundle_data->image,
                                     (unique? " (unique)" : ""),
                                     ((desc != NULL)? " (" : ""),
                                     pcmk__s(desc, ""),
                                     ((desc != NULL)? ")" : ""),
                                     get_unmanaged_str(rsc));

            if (pcmk__list_of_multiple(bundle_data->replicas)) {
                out->begin_list(out, NULL, NULL, "Replica[%d]", replica->offset);
            }

            if (print_ip) {
                out->message(out, (const char *) ip->priv->xml->name,
                             new_show_opts, ip, only_node, only_rsc);
            }

            if (print_child) {
                out->message(out, (const char *) child->priv->xml->name,
                             new_show_opts, child, only_node, only_rsc);
            }

            if (print_ctnr) {
                out->message(out, (const char *) container->priv->xml->name,
                             new_show_opts, container, only_node, only_rsc);
            }

            if (print_remote) {
                out->message(out, (const char *) remote->priv->xml->name,
                             new_show_opts, remote, only_node, only_rsc);
            }

            if (pcmk__list_of_multiple(bundle_data->replicas)) {
                out->end_list(out);
            }
        } else if (print_everything == FALSE && !(print_ip || print_child || print_ctnr || print_remote)) {
            continue;
        } else {
            const bool multiple = (bundle_data->nreplicas > 1);
            const bool unique = pcmk__is_set(rsc->flags, pcmk__rsc_unique);

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc,
                                     "Container bundle%s: %s [%s]%s%s%s%s%s",
                                     (multiple? " set" : ""), rsc->id,
                                     bundle_data->image,
                                     (unique? " (unique)" : ""),
                                     ((desc != NULL)? " (" : ""),
                                     pcmk__s(desc, ""),
                                     ((desc != NULL)? ")" : ""),
                                     get_unmanaged_str(rsc));

            pe__bundle_replica_output_html(out, replica,
                                           pcmk__current_node(container),
                                           show_opts);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

static void
pe__bundle_replica_output_text(pcmk__output_t *out,
                               pcmk__bundle_replica_t *replica,
                               pcmk_node_t *node, uint32_t show_opts)
{
    const pcmk_resource_t *child_rsc = replica->child;
    const pcmk_resource_t *remote_rsc = replica->remote;
    GString *buffer = g_string_sized_new(128);

    if (child_rsc == NULL) {
        child_rsc = replica->container;
    }
    if (remote_rsc == NULL) {
        remote_rsc = replica->container;
    }

    g_string_append(buffer, rsc_printable_id(remote_rsc));
    if (replica->ipaddr != NULL) {
        pcmk__g_strcat(buffer, " (", replica->ipaddr, ")", NULL);
    }

    pe__common_output_text(out, child_rsc, buffer->str, node, show_opts);
    g_string_free(buffer, TRUE);
}

PCMK__OUTPUT_ARGS("bundle", "uint32_t", "pcmk_resource_t *", "GList *",
                  "GList *")
int
pe__bundle_text(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pcmk_resource_t *rsc = va_arg(args, pcmk_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    const char *desc = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    int rc = pcmk_rc_no_output;
    bool print_everything = true;

    desc = pe__resource_description(rsc, show_opts);

    pcmk__assert(rsc != NULL);
    get_bundle_variant_data(bundle_data, rsc);

    if (rsc->priv->fns->is_filtered(rsc, only_rsc, true)) {
        return rc;
    }

    print_everything = pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches);

    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;
        pcmk_resource_t *ip = replica->ip;
        pcmk_resource_t *child = replica->child;
        pcmk_resource_t *container = replica->container;
        pcmk_resource_t *remote = replica->remote;
        gboolean print_ip, print_child, print_ctnr, print_remote;

        pcmk__assert(replica != NULL);

        if (pcmk__rsc_filtered_by_node(container, only_node)) {
            continue;
        }

        print_ip = (ip != NULL)
                   && !ip->priv->fns->is_filtered(ip, only_rsc,
                                                  print_everything);
        print_child = (child != NULL)
                      && !child->priv->fns->is_filtered(child, only_rsc,
                                                        print_everything);
        print_ctnr = !container->priv->fns->is_filtered(container, only_rsc,
                                                        print_everything);
        print_remote = (remote != NULL)
                       && !remote->priv->fns->is_filtered(remote, only_rsc,
                                                          print_everything);

        if (pcmk__is_set(show_opts, pcmk_show_implicit_rscs)
            || (!print_everything
                && (print_ip || print_child || print_ctnr || print_remote))) {
            /* The text output messages used below require pe_print_implicit to
             * be set to do anything.
             */
            const bool multiple = (bundle_data->nreplicas > 1);
            const bool unique = pcmk__is_set(rsc->flags, pcmk__rsc_unique);
            const uint32_t new_show_opts = show_opts | pcmk_show_implicit_rscs;

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc,
                                     "Container bundle%s: %s [%s]%s%s%s%s%s",
                                     (multiple? " set" : ""), rsc->id,
                                     bundle_data->image,
                                     (unique? " (unique)" : ""),
                                     ((desc != NULL)? " (" : ""),
                                     pcmk__s(desc, ""),
                                     ((desc != NULL)? ")" : ""),
                                     get_unmanaged_str(rsc));

            if (pcmk__list_of_multiple(bundle_data->replicas)) {
                out->list_item(out, NULL, "Replica[%d]", replica->offset);
            }

            out->begin_list(out, NULL, NULL, NULL);

            if (print_ip) {
                out->message(out, (const char *) ip->priv->xml->name,
                             new_show_opts, ip, only_node, only_rsc);
            }

            if (print_child) {
                out->message(out, (const char *) child->priv->xml->name,
                             new_show_opts, child, only_node, only_rsc);
            }

            if (print_ctnr) {
                out->message(out, (const char *) container->priv->xml->name,
                             new_show_opts, container, only_node, only_rsc);
            }

            if (print_remote) {
                out->message(out, (const char *) remote->priv->xml->name,
                             new_show_opts, remote, only_node, only_rsc);
            }

            out->end_list(out);
        } else if (print_everything == FALSE && !(print_ip || print_child || print_ctnr || print_remote)) {
            continue;
        } else {
            const bool multiple = (bundle_data->nreplicas > 1);
            const bool unique = pcmk__is_set(rsc->flags, pcmk__rsc_unique);

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc,
                                     "Container bundle%s: %s [%s]%s%s%s%s%s",
                                     (multiple? " set" : ""), rsc->id,
                                     bundle_data->image,
                                     (unique? " (unique)" : ""),
                                     ((desc != NULL)? " (" : ""),
                                     pcmk__s(desc, ""),
                                     ((desc != NULL)? ")" : ""),
                                     get_unmanaged_str(rsc));

            pe__bundle_replica_output_text(out, replica,
                                           pcmk__current_node(container),
                                           show_opts);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

static void
free_bundle_replica(pcmk__bundle_replica_t *replica)
{
    if (replica == NULL) {
        return;
    }

    g_clear_pointer(&replica->node, pcmk__free_node_copy);

    pcmk__free_resource(replica->ip);
    pcmk__free_resource(replica->container);
    pcmk__free_resource(replica->remote);

    free(replica->ipaddr);
    free(replica);
}

void
pe__free_bundle(pcmk_resource_t *rsc)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    CRM_CHECK(rsc != NULL, return);

    get_bundle_variant_data(bundle_data, rsc);
    pcmk__rsc_trace(rsc, "Freeing %s", rsc->id);

    free(bundle_data->prefix);
    free(bundle_data->image);
    free(bundle_data->control_port);
    free(bundle_data->host_network);
    free(bundle_data->host_netmask);
    free(bundle_data->ip_range_start);
    free(bundle_data->container_network);
    free(bundle_data->launcher_options);
    free(bundle_data->container_command);
    g_free(bundle_data->container_host_options);

    g_list_free_full(bundle_data->replicas,
                     (GDestroyNotify) free_bundle_replica);
    g_list_free_full(bundle_data->mounts, (GDestroyNotify)mount_free);
    g_list_free_full(bundle_data->ports, (GDestroyNotify)port_free);
    g_list_free(rsc->priv->children);

    pcmk__free_resource(bundle_data->child);

    common_free(rsc);
}

enum rsc_role_e
pe__bundle_resource_state(const pcmk_resource_t *rsc, bool current)
{
    enum rsc_role_e container_role = pcmk_role_unknown;
    return container_role;
}

/*!
 * \brief Get the number of configured replicas in a bundle
 *
 * \param[in] rsc  Bundle resource
 *
 * \return Number of configured replicas, or 0 on error
 */
int
pe_bundle_replicas(const pcmk_resource_t *rsc)
{
    if (pcmk__is_bundle(rsc)) {
        pe__bundle_variant_data_t *bundle_data = NULL;

        get_bundle_variant_data(bundle_data, rsc);
        return bundle_data->nreplicas;
    }
    return 0;
}

void
pe__count_bundle(pcmk_resource_t *rsc)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, rsc);
    for (GList *item = bundle_data->replicas; item != NULL; item = item->next) {
        pcmk__bundle_replica_t *replica = item->data;

        if (replica->ip) {
            replica->ip->priv->fns->count(replica->ip);
        }
        if (replica->child) {
            replica->child->priv->fns->count(replica->child);
        }
        if (replica->container) {
            replica->container->priv->fns->count(replica->container);
        }
        if (replica->remote) {
            replica->remote->priv->fns->count(replica->remote);
        }
    }
}

bool
pe__bundle_is_filtered(const pcmk_resource_t *rsc, const GList *only_rsc,
                       bool check_parent)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    if (pcmk__str_in_list(rsc_printable_id(rsc), only_rsc,
                          pcmk__str_star_matches)) {
        return false;
    }

    get_bundle_variant_data(bundle_data, rsc);

    for (const GList *iter = bundle_data->replicas; iter != NULL;
         iter = iter->next) {
        const pcmk__bundle_replica_t *replica = iter->data;

        const pcmk_resource_t *ip = replica->ip;
        const pcmk_resource_t *child = replica->child;
        const pcmk_resource_t *container = replica->container;
        const pcmk_resource_t *remote = replica->remote;

        if ((ip != NULL) && !ip->priv->fns->is_filtered(ip, only_rsc, false)) {
            return false;
        }

        if ((child != NULL)
            && !child->priv->fns->is_filtered(child, only_rsc, false)) {

            return false;
        }

        if (!container->priv->fns->is_filtered(container, only_rsc, false)) {
            return false;
        }

        if ((remote != NULL)
            && !remote->priv->fns->is_filtered(remote, only_rsc, false)) {

            return false;
        }
    }

    return true;
}

/*!
 * \internal
 * \brief Get a list of a bundle's containers
 *
 * \param[in] bundle  Bundle resource
 *
 * \return Newly created list of \p bundle's containers
 * \note It is the caller's responsibility to free the result with
 *       g_list_free().
 */
GList *
pe__bundle_containers(const pcmk_resource_t *bundle)
{
    /* @TODO It would be more efficient to do this once when unpacking the
     * bundle, creating a new GList* in the variant data
     */
    GList *containers = NULL;
    const pe__bundle_variant_data_t *data = NULL;

    get_bundle_variant_data(data, bundle);
    for (GList *iter = data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;

        containers = g_list_append(containers, replica->container);
    }
    return containers;
}

// Bundle implementation of pcmk__rsc_methods_t:active_node()
pcmk_node_t *
pe__bundle_active_node(const pcmk_resource_t *rsc, unsigned int *count_all,
                       unsigned int *count_clean)
{
    pcmk_node_t *active = NULL;
    pcmk_node_t *node = NULL;
    pcmk_resource_t *container = NULL;
    GList *containers = NULL;
    GList *iter = NULL;
    GHashTable *nodes = NULL;
    const pe__bundle_variant_data_t *data = NULL;

    if (count_all != NULL) {
        *count_all = 0;
    }
    if (count_clean != NULL) {
        *count_clean = 0;
    }
    if (rsc == NULL) {
        return NULL;
    }

    /* For the purposes of this method, we only care about where the bundle's
     * containers are active, so build a list of active containers.
     */
    get_bundle_variant_data(data, rsc);
    for (iter = data->replicas; iter != NULL; iter = iter->next) {
        pcmk__bundle_replica_t *replica = iter->data;

        if (replica->container->priv->active_nodes != NULL) {
            containers = g_list_append(containers, replica->container);
        }
    }
    if (containers == NULL) {
        return NULL;
    }

    /* If the bundle has only a single active container, just use that
     * container's method. If live migration is ever supported for bundle
     * containers, this will allow us to prefer the migration source when there
     * is only one container and it is migrating. For now, this just lets us
     * avoid creating the nodes table.
     */
    if (pcmk__list_of_1(containers)) {
        container = containers->data;
        node = container->priv->fns->active_node(container, count_all,
                                                 count_clean);
        g_list_free(containers);
        return node;
    }

    // Add all containers' active nodes to a hash table (for uniqueness)
    nodes = g_hash_table_new(NULL, NULL);
    for (iter = containers; iter != NULL; iter = iter->next) {
        container = iter->data;
        for (GList *node_iter = container->priv->active_nodes;
             node_iter != NULL; node_iter = node_iter->next) {

            node = node_iter->data;

            // If insert returns true, we haven't counted this node yet
            if (g_hash_table_insert(nodes, (void *) node->details,
                                    (void *) node)
                && !pe__count_active_node(rsc, node, &active, count_all,
                                          count_clean)) {
                goto done;
            }
        }
    }

done:
    g_list_free(containers);
    g_hash_table_destroy(nodes);
    return active;
}

/*!
 * \internal
 * \brief Get maximum bundle resource instances per node
 *
 * \param[in] rsc  Bundle resource to check
 *
 * \return Maximum number of \p rsc instances that can be active on one node
 */
unsigned int
pe__bundle_max_per_node(const pcmk_resource_t *rsc)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, rsc);
    pcmk__assert(bundle_data->nreplicas_per_host >= 0);
    return (unsigned int) bundle_data->nreplicas_per_host;
}
