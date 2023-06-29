/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <ctype.h>
#include <stdint.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/output.h>
#include <crm/common/xml_internal.h>
#include <pe_status_private.h>

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
    PE__CONTAINER_AGENT_RKT,
    PE__CONTAINER_AGENT_PODMAN,
};

#define PE__CONTAINER_AGENT_UNKNOWN_S "unknown"
#define PE__CONTAINER_AGENT_DOCKER_S  "docker"
#define PE__CONTAINER_AGENT_RKT_S     "rkt"
#define PE__CONTAINER_AGENT_PODMAN_S  "podman"

typedef struct pe__bundle_variant_data_s {
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
        gboolean add_host;
        gchar *container_host_options;
        char *container_command;
        char *launcher_options;
        const char *attribute_target;

        pe_resource_t *child;

        GList *replicas;    // pe__bundle_replica_t *
        GList *ports;       // pe__bundle_port_t *
        GList *mounts;      // pe__bundle_mount_t *

        enum pe__container_agent agent_type;
} pe__bundle_variant_data_t;

#define get_bundle_variant_data(data, rsc)                      \
    CRM_ASSERT(rsc != NULL);                                    \
    CRM_ASSERT(rsc->variant == pe_container);                   \
    CRM_ASSERT(rsc->variant_opaque != NULL);                    \
    data = (pe__bundle_variant_data_t *) rsc->variant_opaque;

/*!
 * \internal
 * \brief Get maximum number of bundle replicas allowed to run
 *
 * \param[in] rsc  Bundle or bundled resource to check
 *
 * \return Maximum replicas for bundle corresponding to \p rsc
 */
int
pe__bundle_max(const pe_resource_t *rsc)
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
pe_resource_t *
pe__bundled_resource(const pe_resource_t *rsc)
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
const pe_resource_t *
pe__get_rsc_in_container(const pe_resource_t *instance)
{
    const pe__bundle_variant_data_t *data = NULL;
    const pe_resource_t *top = pe__const_top_resource(instance, true);

    if ((top == NULL) || (top->variant != pe_container)) {
        return NULL;
    }
    get_bundle_variant_data(data, top);

    for (const GList *iter = data->replicas; iter != NULL; iter = iter->next) {
        const pe__bundle_replica_t *replica = iter->data;

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
pe__node_is_bundle_instance(const pe_resource_t *bundle, const pe_node_t *node)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, bundle);
    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pe__bundle_replica_t *replica = iter->data;

        if (pe__same_node(node, replica->node)) {
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
pe_resource_t *
pe__first_container(const pe_resource_t *bundle)
{
    const pe__bundle_variant_data_t *bundle_data = NULL;
    const pe__bundle_replica_t *replica = NULL;

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
pe__foreach_bundle_replica(pe_resource_t *bundle,
                           bool (*fn)(pe__bundle_replica_t *, void *),
                           void *user_data)
{
    const pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, bundle);
    for (GList *iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        if (!fn((pe__bundle_replica_t *) iter->data, user_data)) {
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
pe__foreach_const_bundle_replica(const pe_resource_t *bundle,
                                 bool (*fn)(const pe__bundle_replica_t *,
                                            void *),
                                 void *user_data)
{
    const pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, bundle);
    for (const GList *iter = bundle_data->replicas; iter != NULL;
         iter = iter->next) {

        if (!fn((const pe__bundle_replica_t *) iter->data, user_data)) {
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

    return crm_strdup_printf("%u.%u.%u.%u", oct1, oct2, oct3, oct4);
}

static void
allocate_ip(pe__bundle_variant_data_t *data, pe__bundle_replica_t *replica,
            GString *buffer)
{
    if(data->ip_range_start == NULL) {
        return;

    } else if(data->ip_last) {
        replica->ipaddr = next_ip(data->ip_last);

    } else {
        replica->ipaddr = strdup(data->ip_range_start);
    }

    data->ip_last = replica->ipaddr;
    switch (data->agent_type) {
        case PE__CONTAINER_AGENT_DOCKER:
        case PE__CONTAINER_AGENT_PODMAN:
            if (data->add_host) {
                g_string_append_printf(buffer, " --add-host=%s-%d:%s",
                                       data->prefix, replica->offset,
                                       replica->ipaddr);
            } else {
                g_string_append_printf(buffer, " --hosts-entry=%s=%s-%d",
                                       replica->ipaddr, data->prefix,
                                       replica->offset);
            }
            break;

        case PE__CONTAINER_AGENT_RKT:
            g_string_append_printf(buffer, " --hosts-entry=%s=%s-%d",
                                   replica->ipaddr, data->prefix,
                                   replica->offset);
            break;

        default: // PE__CONTAINER_AGENT_UNKNOWN
            break;
    }
}

static xmlNode *
create_resource(const char *name, const char *provider, const char *kind)
{
    xmlNode *rsc = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);

    crm_xml_add(rsc, XML_ATTR_ID, name);
    crm_xml_add(rsc, XML_AGENT_ATTR_CLASS, PCMK_RESOURCE_CLASS_OCF);
    crm_xml_add(rsc, XML_AGENT_ATTR_PROVIDER, provider);
    crm_xml_add(rsc, XML_ATTR_TYPE, kind);

    return rsc;
}

/*!
 * \internal
 * \brief Check whether cluster can manage resource inside container
 *
 * \param[in,out] data  Container variant data
 *
 * \return TRUE if networking configuration is acceptable, FALSE otherwise
 *
 * \note The resource is manageable if an IP range or control port has been
 *       specified. If a control port is used without an IP range, replicas per
 *       host must be 1.
 */
static bool
valid_network(pe__bundle_variant_data_t *data)
{
    if(data->ip_range_start) {
        return TRUE;
    }
    if(data->control_port) {
        if(data->nreplicas_per_host > 1) {
            pe_err("Specifying the 'control-port' for %s requires 'replicas-per-host=1'", data->prefix);
            data->nreplicas_per_host = 1;
            // @TODO to be sure: pe__clear_resource_flags(rsc, pe_rsc_unique);
        }
        return TRUE;
    }
    return FALSE;
}

static int
create_ip_resource(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                   pe__bundle_replica_t *replica)
{
    if(data->ip_range_start) {
        char *id = NULL;
        xmlNode *xml_ip = NULL;
        xmlNode *xml_obj = NULL;

        id = crm_strdup_printf("%s-ip-%s", data->prefix, replica->ipaddr);
        crm_xml_sanitize_id(id);
        xml_ip = create_resource(id, "heartbeat", "IPaddr2");
        free(id);

        xml_obj = create_xml_node(xml_ip, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_obj, "%s-attributes-%d",
                       data->prefix, replica->offset);

        crm_create_nvpair_xml(xml_obj, NULL, "ip", replica->ipaddr);
        if(data->host_network) {
            crm_create_nvpair_xml(xml_obj, NULL, "nic", data->host_network);
        }

        if(data->host_netmask) {
            crm_create_nvpair_xml(xml_obj, NULL,
                                  "cidr_netmask", data->host_netmask);

        } else {
            crm_create_nvpair_xml(xml_obj, NULL, "cidr_netmask", "32");
        }

        xml_obj = create_xml_node(xml_ip, "operations");
        crm_create_op_xml(xml_obj, ID(xml_ip), "monitor", "60s", NULL);

        // TODO: Other ops? Timeouts and intervals from underlying resource?

        if (pe__unpack_resource(xml_ip, &replica->ip, parent,
                                parent->cluster) != pcmk_rc_ok) {
            return pcmk_rc_unpack_error;
        }

        parent->children = g_list_append(parent->children, replica->ip);
    }
    return pcmk_rc_ok;
}

static const char*
container_agent_str(enum pe__container_agent t)
{
    switch (t) {
        case PE__CONTAINER_AGENT_DOCKER: return PE__CONTAINER_AGENT_DOCKER_S;
        case PE__CONTAINER_AGENT_RKT:    return PE__CONTAINER_AGENT_RKT_S;
        case PE__CONTAINER_AGENT_PODMAN: return PE__CONTAINER_AGENT_PODMAN_S;
        default: // PE__CONTAINER_AGENT_UNKNOWN
            break;
    }
    return PE__CONTAINER_AGENT_UNKNOWN_S;
}

static int
create_container_resource(pe_resource_t *parent,
                          const pe__bundle_variant_data_t *data,
                          pe__bundle_replica_t *replica)
{
    char *id = NULL;
    xmlNode *xml_container = NULL;
    xmlNode *xml_obj = NULL;

    // Agent-specific
    const char *hostname_opt = NULL;
    const char *env_opt = NULL;
    const char *agent_str = NULL;
    int volid = 0;  // rkt-only

    GString *buffer = NULL;
    GString *dbuffer = NULL;

    // Where syntax differences are drop-in replacements, set them now
    switch (data->agent_type) {
        case PE__CONTAINER_AGENT_DOCKER:
        case PE__CONTAINER_AGENT_PODMAN:
            hostname_opt = "-h ";
            env_opt = "-e ";
            break;
        case PE__CONTAINER_AGENT_RKT:
            hostname_opt = "--hostname=";
            env_opt = "--environment=";
            break;
        default:    // PE__CONTAINER_AGENT_UNKNOWN
            return pcmk_rc_unpack_error;
    }
    agent_str = container_agent_str(data->agent_type);

    buffer = g_string_sized_new(4096);

    id = crm_strdup_printf("%s-%s-%d", data->prefix, agent_str,
                           replica->offset);
    crm_xml_sanitize_id(id);
    xml_container = create_resource(id, "heartbeat", agent_str);
    free(id);

    xml_obj = create_xml_node(xml_container, XML_TAG_ATTR_SETS);
    crm_xml_set_id(xml_obj, "%s-attributes-%d", data->prefix, replica->offset);

    crm_create_nvpair_xml(xml_obj, NULL, "image", data->image);
    crm_create_nvpair_xml(xml_obj, NULL, "allow_pull", XML_BOOLEAN_TRUE);
    crm_create_nvpair_xml(xml_obj, NULL, "force_kill", XML_BOOLEAN_FALSE);
    crm_create_nvpair_xml(xml_obj, NULL, "reuse", XML_BOOLEAN_FALSE);

    if (data->agent_type == PE__CONTAINER_AGENT_DOCKER) {
        g_string_append(buffer, " --restart=no");
    }

    /* Set a container hostname only if we have an IP to map it to. The user can
     * set -h or --uts=host themselves if they want a nicer name for logs, but
     * this makes applications happy who need their  hostname to match the IP
     * they bind to.
     */
    if (data->ip_range_start != NULL) {
        g_string_append_printf(buffer, " %s%s-%d", hostname_opt, data->prefix,
                               replica->offset);
    }
    pcmk__g_strcat(buffer, " ", env_opt, "PCMK_stderr=1", NULL);

    if (data->container_network != NULL) {
        pcmk__g_strcat(buffer, " --net=", data->container_network, NULL);
    }

    if (data->control_port != NULL) {
        pcmk__g_strcat(buffer, " ", env_opt, "PCMK_remote_port=",
                      data->control_port, NULL);
    } else {
        g_string_append_printf(buffer, " %sPCMK_remote_port=%d", env_opt,
                               DEFAULT_REMOTE_PORT);
    }

    for (GList *iter = data->mounts; iter != NULL; iter = iter->next) {
        pe__bundle_mount_t *mount = (pe__bundle_mount_t *) iter->data;
        char *source = NULL;

        if (pcmk_is_set(mount->flags, pe__bundle_mount_subdir)) {
            source = crm_strdup_printf("%s/%s-%d", mount->source, data->prefix,
                                       replica->offset);
            pcmk__add_separated_word(&dbuffer, 1024, source, ",");
        }

        switch (data->agent_type) {
            case PE__CONTAINER_AGENT_DOCKER:
            case PE__CONTAINER_AGENT_PODMAN:
                pcmk__g_strcat(buffer,
                               " -v ", pcmk__s(source, mount->source),
                               ":", mount->target, NULL);

                if (mount->options != NULL) {
                    pcmk__g_strcat(buffer, ":", mount->options, NULL);
                }
                break;
            case PE__CONTAINER_AGENT_RKT:
                g_string_append_printf(buffer,
                                       " --volume vol%d,kind=host,"
                                       "source=%s%s%s "
                                       "--mount volume=vol%d,target=%s",
                                       volid, pcmk__s(source, mount->source),
                                       (mount->options != NULL)? "," : "",
                                       pcmk__s(mount->options, ""),
                                       volid, mount->target);
                volid++;
                break;
            default:
                break;
        }
        free(source);
    }

    for (GList *iter = data->ports; iter != NULL; iter = iter->next) {
        pe__bundle_port_t *port = (pe__bundle_port_t *) iter->data;

        switch (data->agent_type) {
            case PE__CONTAINER_AGENT_DOCKER:
            case PE__CONTAINER_AGENT_PODMAN:
                if (replica->ipaddr != NULL) {
                    pcmk__g_strcat(buffer,
                                   " -p ", replica->ipaddr, ":", port->source,
                                   ":", port->target, NULL);

                } else if (!pcmk__str_eq(data->container_network, "host",
                                         pcmk__str_none)) {
                    // No need to do port mapping if net == host
                    pcmk__g_strcat(buffer,
                                   " -p ", port->source, ":", port->target,
                                   NULL);
                }
                break;
            case PE__CONTAINER_AGENT_RKT:
                if (replica->ipaddr != NULL) {
                    pcmk__g_strcat(buffer,
                                   " --port=", port->target,
                                   ":", replica->ipaddr, ":", port->source,
                                   NULL);
                } else {
                    pcmk__g_strcat(buffer,
                                   " --port=", port->target, ":", port->source,
                                   NULL);
                }
                break;
            default:
                break;
        }
    }

    /* @COMPAT: We should use pcmk__add_word() here, but we can't yet, because
     * it would cause restarts during rolling upgrades.
     *
     * In a previous version of the container resource creation logic, if
     * data->launcher_options is not NULL, we append
     * (" %s", data->launcher_options) even if data->launcher_options is an
     * empty string. Likewise for data->container_host_options. Using
     *
     *     pcmk__add_word(buffer, 0, data->launcher_options)
     *
     * removes that extra trailing space, causing a resource definition change.
     */
    if (data->launcher_options != NULL) {
        pcmk__g_strcat(buffer, " ", data->launcher_options, NULL);
    }

    if (data->container_host_options != NULL) {
        pcmk__g_strcat(buffer, " ", data->container_host_options, NULL);
    }

    crm_create_nvpair_xml(xml_obj, NULL, "run_opts",
                          (const char *) buffer->str);
    g_string_free(buffer, TRUE);

    crm_create_nvpair_xml(xml_obj, NULL, "mount_points",
                          (dbuffer != NULL)? (const char *) dbuffer->str : "");
    if (dbuffer != NULL) {
        g_string_free(dbuffer, TRUE);
    }

    if (replica->child != NULL) {
        if (data->container_command != NULL) {
            crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                  data->container_command);
        } else {
            crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                  SBIN_DIR "/pacemaker-remoted");
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
    } else if ((child != NULL) && data->untrusted) {
        crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                              CRM_DAEMON_DIR "/pacemaker-execd");
        crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd",
                              CRM_DAEMON_DIR "/pacemaker/cts-exec-helper -c poke");
#endif
    } else {
        if (data->container_command != NULL) {
            crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                  data->container_command);
        }

        /* TODO: Allow users to specify their own?
         *
         * We don't know what's in the container, so we just want to know if it
         * is alive.
         */
        crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
    }

    xml_obj = create_xml_node(xml_container, "operations");
    crm_create_op_xml(xml_obj, ID(xml_container), "monitor", "60s", NULL);

    // TODO: Other ops? Timeouts and intervals from underlying resource?
    if (pe__unpack_resource(xml_container, &replica->container, parent,
                            parent->cluster) != pcmk_rc_ok) {
        return pcmk_rc_unpack_error;
    }
    pe__set_resource_flags(replica->container, pe_rsc_replica_container);
    parent->children = g_list_append(parent->children, replica->container);

    return pcmk_rc_ok;
}

/*!
 * \brief Ban a node from a resource's (and its children's) allowed nodes list
 *
 * \param[in,out] rsc    Resource to modify
 * \param[in]     uname  Name of node to ban
 */
static void
disallow_node(pe_resource_t *rsc, const char *uname)
{
    gpointer match = g_hash_table_lookup(rsc->allowed_nodes, uname);

    if (match) {
        ((pe_node_t *) match)->weight = -INFINITY;
        ((pe_node_t *) match)->rsc_discover_mode = pe_discover_never;
    }
    if (rsc->children) {
        g_list_foreach(rsc->children, (GFunc) disallow_node, (gpointer) uname);
    }
}

static int
create_remote_resource(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                       pe__bundle_replica_t *replica)
{
    if (replica->child && valid_network(data)) {
        GHashTableIter gIter;
        pe_node_t *node = NULL;
        xmlNode *xml_remote = NULL;
        char *id = crm_strdup_printf("%s-%d", data->prefix, replica->offset);
        char *port_s = NULL;
        const char *uname = NULL;
        const char *connect_name = NULL;

        if (pe_find_resource(parent->cluster->resources, id) != NULL) {
            free(id);
            // The biggest hammer we have
            id = crm_strdup_printf("pcmk-internal-%s-remote-%d",
                                   replica->child->id, replica->offset);
            //@TODO return error instead of asserting?
            CRM_ASSERT(pe_find_resource(parent->cluster->resources,
                                        id) == NULL);
        }

        /* REMOTE_CONTAINER_HACK: Using "#uname" as the server name when the
         * connection does not have its own IP is a magic string that we use to
         * support nested remotes (i.e. a bundle running on a remote node).
         */
        connect_name = (replica->ipaddr? replica->ipaddr : "#uname");

        if (data->control_port == NULL) {
            port_s = pcmk__itoa(DEFAULT_REMOTE_PORT);
        }

        /* This sets replica->container as replica->remote's container, which is
         * similar to what happens with guest nodes. This is how the scheduler
         * knows that the bundle node is fenced by recovering the container, and
         * that remote should be ordered relative to the container.
         */
        xml_remote = pe_create_remote_xml(NULL, id, replica->container->id,
                                          NULL, NULL, NULL,
                                          connect_name, (data->control_port?
                                          data->control_port : port_s));
        free(port_s);

        /* Abandon our created ID, and pull the copy from the XML, because we
         * need something that will get freed during data set cleanup to use as
         * the node ID and uname.
         */
        free(id);
        id = NULL;
        uname = ID(xml_remote);

        /* Ensure a node has been created for the guest (it may have already
         * been, if it has a permanent node attribute), and ensure its weight is
         * -INFINITY so no other resources can run on it.
         */
        node = pe_find_node(parent->cluster->nodes, uname);
        if (node == NULL) {
            node = pe_create_node(uname, uname, "remote", "-INFINITY",
                                  parent->cluster);
        } else {
            node->weight = -INFINITY;
        }
        node->rsc_discover_mode = pe_discover_never;

        /* unpack_remote_nodes() ensures that each remote node and guest node
         * has a pe_node_t entry. Ideally, it would do the same for bundle nodes.
         * Unfortunately, a bundle has to be mostly unpacked before it's obvious
         * what nodes will be needed, so we do it just above.
         *
         * Worse, that means that the node may have been utilized while
         * unpacking other resources, without our weight correction. The most
         * likely place for this to happen is when pe__unpack_resource() calls
         * resource_location() to set a default score in symmetric clusters.
         * This adds a node *copy* to each resource's allowed nodes, and these
         * copies will have the wrong weight.
         *
         * As a hacky workaround, fix those copies here.
         *
         * @TODO Possible alternative: ensure bundles are unpacked before other
         * resources, so the weight is correct before any copies are made.
         */
        g_list_foreach(parent->cluster->resources, (GFunc) disallow_node,
                       (gpointer) uname);

        replica->node = pe__copy_node(node);
        replica->node->weight = 500;
        replica->node->rsc_discover_mode = pe_discover_exclusive;

        /* Ensure the node shows up as allowed and with the correct discovery set */
        if (replica->child->allowed_nodes != NULL) {
            g_hash_table_destroy(replica->child->allowed_nodes);
        }
        replica->child->allowed_nodes = pcmk__strkey_table(NULL, free);
        g_hash_table_insert(replica->child->allowed_nodes,
                            (gpointer) replica->node->details->id,
                            pe__copy_node(replica->node));

        {
            pe_node_t *copy = pe__copy_node(replica->node);
            copy->weight = -INFINITY;
            g_hash_table_insert(replica->child->parent->allowed_nodes,
                                (gpointer) replica->node->details->id, copy);
        }
        if (pe__unpack_resource(xml_remote, &replica->remote, parent,
                                parent->cluster) != pcmk_rc_ok) {
            return pcmk_rc_unpack_error;
        }

        g_hash_table_iter_init(&gIter, replica->remote->allowed_nodes);
        while (g_hash_table_iter_next(&gIter, NULL, (void **)&node)) {
            if (pe__is_guest_or_remote_node(node)) {
                /* Remote resources can only run on 'normal' cluster node */
                node->weight = -INFINITY;
            }
        }

        replica->node->details->remote_rsc = replica->remote;

        // Ensure pe__is_guest_node() functions correctly immediately
        replica->remote->container = replica->container;

        /* A bundle's #kind is closer to "container" (guest node) than the
         * "remote" set by pe_create_node().
         */
        g_hash_table_insert(replica->node->details->attrs,
                            strdup(CRM_ATTR_KIND), strdup("container"));

        /* One effect of this is that setup_container() will add
         * replica->remote to replica->container's fillers, which will make
         * pe__resource_contains_guest_node() true for replica->container.
         *
         * replica->child does NOT get added to replica->container's fillers.
         * The only noticeable effect if it did would be for its fail count to
         * be taken into account when checking replica->container's migration
         * threshold.
         */
        parent->children = g_list_append(parent->children, replica->remote);
    }
    return pcmk_rc_ok;
}

static int
create_replica_resources(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                         pe__bundle_replica_t *replica)
{
    int rc = pcmk_rc_ok;

    rc = create_container_resource(parent, data, replica);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = create_ip_resource(parent, data, replica);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = create_remote_resource(parent, data, replica);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if ((replica->child != NULL) && (replica->ipaddr != NULL)) {
        add_hash_param(replica->child->meta, "external-ip", replica->ipaddr);
    }

    if (replica->remote != NULL) {
        /*
         * Allow the remote connection resource to be allocated to a
         * different node than the one on which the container is active.
         *
         * This makes it possible to have Pacemaker Remote nodes running
         * containers with pacemaker-remoted inside in order to start
         * services inside those containers.
         */
        pe__set_resource_flags(replica->remote, pe_rsc_allow_remote_remotes);
    }
    return rc;
}

static void
mount_add(pe__bundle_variant_data_t *bundle_data, const char *source,
          const char *target, const char *options, uint32_t flags)
{
    pe__bundle_mount_t *mount = calloc(1, sizeof(pe__bundle_mount_t));

    CRM_ASSERT(mount != NULL);
    mount->source = strdup(source);
    mount->target = strdup(target);
    pcmk__str_update(&mount->options, options);
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

static pe__bundle_replica_t *
replica_for_remote(pe_resource_t *remote)
{
    pe_resource_t *top = remote;
    pe__bundle_variant_data_t *bundle_data = NULL;

    if (top == NULL) {
        return NULL;
    }

    while (top->parent != NULL) {
        top = top->parent;
    }

    get_bundle_variant_data(bundle_data, top);
    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        if (replica->remote == remote) {
            return replica;
        }
    }
    CRM_LOG_ASSERT(FALSE);
    return NULL;
}

bool
pe__bundle_needs_remote_name(pe_resource_t *rsc)
{
    const char *value;
    GHashTable *params = NULL;

    if (rsc == NULL) {
        return false;
    }

    // Use NULL node since pcmk__bundle_expand() uses that to set value
    params = pe_rsc_params(rsc, NULL, rsc->cluster);
    value = g_hash_table_lookup(params, XML_RSC_ATTR_REMOTE_RA_ADDR);

    return pcmk__str_eq(value, "#uname", pcmk__str_casei)
           && xml_contains_remote_node(rsc->xml);
}

const char *
pe__add_bundle_remote_name(pe_resource_t *rsc, pe_working_set_t *data_set,
                           xmlNode *xml, const char *field)
{
    // REMOTE_CONTAINER_HACK: Allow remote nodes that start containers with pacemaker remote inside

    pe_node_t *node = NULL;
    pe__bundle_replica_t *replica = NULL;

    if (!pe__bundle_needs_remote_name(rsc)) {
        return NULL;
    }

    replica = replica_for_remote(rsc);
    if (replica == NULL) {
        return NULL;
    }

    node = replica->container->allocated_to;
    if (node == NULL) {
        /* If it won't be running anywhere after the
         * transition, go with where it's running now.
         */
        node = pe__current_node(replica->container);
    }

    if(node == NULL) {
        crm_trace("Cannot determine address for bundle connection %s", rsc->id);
        return NULL;
    }

    crm_trace("Setting address for bundle connection %s to bundle host %s",
              rsc->id, pe__node_name(node));
    if(xml != NULL && field != NULL) {
        crm_xml_add(xml, field, node->details->uname);
    }

    return node->details->uname;
}

#define pe__set_bundle_mount_flags(mount_xml, flags, flags_to_set) do {     \
        flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,           \
                                   "Bundle mount", ID(mount_xml), flags,    \
                                   (flags_to_set), #flags_to_set);          \
    } while (0)

gboolean
pe__unpack_bundle(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    const char *value = NULL;
    xmlNode *xml_obj = NULL;
    xmlNode *xml_resource = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    bool need_log_mount = TRUE;

    CRM_ASSERT(rsc != NULL);
    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    bundle_data = calloc(1, sizeof(pe__bundle_variant_data_t));
    rsc->variant_opaque = bundle_data;
    bundle_data->prefix = strdup(rsc->id);

    xml_obj = first_named_child(rsc->xml, PE__CONTAINER_AGENT_DOCKER_S);
    if (xml_obj != NULL) {
        bundle_data->agent_type = PE__CONTAINER_AGENT_DOCKER;
    } else {
        xml_obj = first_named_child(rsc->xml, PE__CONTAINER_AGENT_RKT_S);
        if (xml_obj != NULL) {
            bundle_data->agent_type = PE__CONTAINER_AGENT_RKT;
        } else {
            xml_obj = first_named_child(rsc->xml, PE__CONTAINER_AGENT_PODMAN_S);
            if (xml_obj != NULL) {
                bundle_data->agent_type = PE__CONTAINER_AGENT_PODMAN;
            } else {
                return FALSE;
            }
        }
    }

    // Use 0 for default, minimum, and invalid promoted-max
    value = crm_element_value(xml_obj, XML_RSC_ATTR_PROMOTED_MAX);
    if (value == NULL) {
        // @COMPAT deprecated since 2.0.0
        value = crm_element_value(xml_obj, "masters");
    }
    pcmk__scan_min_int(value, &bundle_data->promoted_max, 0);

    // Default replicas to promoted-max if it was specified and 1 otherwise
    value = crm_element_value(xml_obj, "replicas");
    if ((value == NULL) && (bundle_data->promoted_max > 0)) {
        bundle_data->nreplicas = bundle_data->promoted_max;
    } else {
        pcmk__scan_min_int(value, &bundle_data->nreplicas, 1);
    }

    /*
     * Communication between containers on the same host via the
     * floating IPs only works if the container is started with:
     *   --userland-proxy=false --ip-masq=false
     */
    value = crm_element_value(xml_obj, "replicas-per-host");
    pcmk__scan_min_int(value, &bundle_data->nreplicas_per_host, 1);
    if (bundle_data->nreplicas_per_host == 1) {
        pe__clear_resource_flags(rsc, pe_rsc_unique);
    }

    bundle_data->container_command = crm_element_value_copy(xml_obj, "run-command");
    bundle_data->launcher_options = crm_element_value_copy(xml_obj, "options");
    bundle_data->image = crm_element_value_copy(xml_obj, "image");
    bundle_data->container_network = crm_element_value_copy(xml_obj, "network");

    xml_obj = first_named_child(rsc->xml, "network");
    if(xml_obj) {

        bundle_data->ip_range_start = crm_element_value_copy(xml_obj, "ip-range-start");
        bundle_data->host_netmask = crm_element_value_copy(xml_obj, "host-netmask");
        bundle_data->host_network = crm_element_value_copy(xml_obj, "host-interface");
        bundle_data->control_port = crm_element_value_copy(xml_obj, "control-port");
        value = crm_element_value(xml_obj, "add-host");
        if (crm_str_to_boolean(value, &bundle_data->add_host) != 1) {
            bundle_data->add_host = TRUE;
        }

        for (xmlNode *xml_child = pcmk__xe_first_child(xml_obj); xml_child != NULL;
             xml_child = pcmk__xe_next(xml_child)) {

            pe__bundle_port_t *port = calloc(1, sizeof(pe__bundle_port_t));
            port->source = crm_element_value_copy(xml_child, "port");

            if(port->source == NULL) {
                port->source = crm_element_value_copy(xml_child, "range");
            } else {
                port->target = crm_element_value_copy(xml_child, "internal-port");
            }

            if(port->source != NULL && strlen(port->source) > 0) {
                if(port->target == NULL) {
                    port->target = strdup(port->source);
                }
                bundle_data->ports = g_list_append(bundle_data->ports, port);

            } else {
                pe_err("Invalid port directive %s", ID(xml_child));
                port_free(port);
            }
        }
    }

    xml_obj = first_named_child(rsc->xml, "storage");
    for (xmlNode *xml_child = pcmk__xe_first_child(xml_obj); xml_child != NULL;
         xml_child = pcmk__xe_next(xml_child)) {

        const char *source = crm_element_value(xml_child, "source-dir");
        const char *target = crm_element_value(xml_child, "target-dir");
        const char *options = crm_element_value(xml_child, "options");
        int flags = pe__bundle_mount_none;

        if (source == NULL) {
            source = crm_element_value(xml_child, "source-dir-root");
            pe__set_bundle_mount_flags(xml_child, flags,
                                       pe__bundle_mount_subdir);
        }

        if (source && target) {
            mount_add(bundle_data, source, target, options, flags);
            if (strcmp(target, "/var/log") == 0) {
                need_log_mount = FALSE;
            }
        } else {
            pe_err("Invalid mount directive %s", ID(xml_child));
        }
    }

    xml_obj = first_named_child(rsc->xml, "primitive");
    if (xml_obj && valid_network(bundle_data)) {
        char *value = NULL;
        xmlNode *xml_set = NULL;

        xml_resource = create_xml_node(NULL, XML_CIB_TAG_INCARNATION);

        /* @COMPAT We no longer use the <master> tag, but we need to keep it as
         * part of the resource name, so that bundles don't restart in a rolling
         * upgrade. (It also avoids needing to change regression tests.)
         */
        crm_xml_set_id(xml_resource, "%s-%s", bundle_data->prefix,
                      (bundle_data->promoted_max? "master"
                      : (const char *)xml_resource->name));

        xml_set = create_xml_node(xml_resource, XML_TAG_META_SETS);
        crm_xml_set_id(xml_set, "%s-%s-meta", bundle_data->prefix, xml_resource->name);

        crm_create_nvpair_xml(xml_set, NULL,
                              XML_RSC_ATTR_ORDERED, XML_BOOLEAN_TRUE);

        value = pcmk__itoa(bundle_data->nreplicas);
        crm_create_nvpair_xml(xml_set, NULL,
                              XML_RSC_ATTR_INCARNATION_MAX, value);
        free(value);

        value = pcmk__itoa(bundle_data->nreplicas_per_host);
        crm_create_nvpair_xml(xml_set, NULL,
                              XML_RSC_ATTR_INCARNATION_NODEMAX, value);
        free(value);

        crm_create_nvpair_xml(xml_set, NULL, XML_RSC_ATTR_UNIQUE,
                              pcmk__btoa(bundle_data->nreplicas_per_host > 1));

        if (bundle_data->promoted_max) {
            crm_create_nvpair_xml(xml_set, NULL,
                                  XML_RSC_ATTR_PROMOTABLE, XML_BOOLEAN_TRUE);

            value = pcmk__itoa(bundle_data->promoted_max);
            crm_create_nvpair_xml(xml_set, NULL,
                                  XML_RSC_ATTR_PROMOTED_MAX, value);
            free(value);
        }

        //crm_xml_add(xml_obj, XML_ATTR_ID, bundle_data->prefix);
        add_node_copy(xml_resource, xml_obj);

    } else if(xml_obj) {
        pe_err("Cannot control %s inside %s without either ip-range-start or control-port",
               rsc->id, ID(xml_obj));
        return FALSE;
    }

    if(xml_resource) {
        int lpc = 0;
        GList *childIter = NULL;
        pe__bundle_port_t *port = NULL;
        GString *buffer = NULL;

        if (pe__unpack_resource(xml_resource, &(bundle_data->child), rsc,
                                data_set) != pcmk_rc_ok) {
            return FALSE;
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

        if (need_log_mount) {
            mount_add(bundle_data, CRM_BUNDLE_DIR, "/var/log", NULL,
                      pe__bundle_mount_subdir);
        }

        port = calloc(1, sizeof(pe__bundle_port_t));
        if(bundle_data->control_port) {
            port->source = strdup(bundle_data->control_port);
        } else {
            /* If we wanted to respect PCMK_remote_port, we could use
             * crm_default_remote_port() here and elsewhere in this file instead
             * of DEFAULT_REMOTE_PORT.
             *
             * However, it gains nothing, since we control both the container
             * environment and the connection resource parameters, and the user
             * can use a different port if desired by setting control-port.
             */
            port->source = pcmk__itoa(DEFAULT_REMOTE_PORT);
        }
        port->target = strdup(port->source);
        bundle_data->ports = g_list_append(bundle_data->ports, port);

        buffer = g_string_sized_new(1024);
        for (childIter = bundle_data->child->children; childIter != NULL;
             childIter = childIter->next) {

            pe__bundle_replica_t *replica = calloc(1, sizeof(pe__bundle_replica_t));

            replica->child = childIter->data;
            replica->child->exclusive_discover = TRUE;
            replica->offset = lpc++;

            // Ensure the child's notify gets set based on the underlying primitive's value
            if (pcmk_is_set(replica->child->flags, pe_rsc_notify)) {
                pe__set_resource_flags(bundle_data->child, pe_rsc_notify);
            }

            allocate_ip(bundle_data, replica, buffer);
            bundle_data->replicas = g_list_append(bundle_data->replicas,
                                                  replica);
            bundle_data->attribute_target = g_hash_table_lookup(replica->child->meta,
                                                                XML_RSC_ATTR_TARGET);
        }
        bundle_data->container_host_options = g_string_free(buffer, FALSE);

        if (bundle_data->attribute_target) {
            g_hash_table_replace(rsc->meta, strdup(XML_RSC_ATTR_TARGET),
                                 strdup(bundle_data->attribute_target));
            g_hash_table_replace(bundle_data->child->meta,
                                 strdup(XML_RSC_ATTR_TARGET),
                                 strdup(bundle_data->attribute_target));
        }

    } else {
        // Just a naked container, no pacemaker-remote
        GString *buffer = g_string_sized_new(1024);

        for (int lpc = 0; lpc < bundle_data->nreplicas; lpc++) {
            pe__bundle_replica_t *replica = calloc(1, sizeof(pe__bundle_replica_t));

            replica->offset = lpc;
            allocate_ip(bundle_data, replica, buffer);
            bundle_data->replicas = g_list_append(bundle_data->replicas,
                                                  replica);
        }
        bundle_data->container_host_options = g_string_free(buffer, FALSE);
    }

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        if (create_replica_resources(rsc, bundle_data, replica) != pcmk_rc_ok) {
            pe_err("Failed unpacking resource %s", rsc->id);
            rsc->fns->free(rsc);
            return FALSE;
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
            GHashTable *empty = replica->container->utilization;

            replica->container->utilization = replica->child->utilization;
            replica->child->utilization = empty;
        }
    }

    if (bundle_data->child) {
        rsc->children = g_list_append(rsc->children, bundle_data->child);
    }
    return TRUE;
}

static int
replica_resource_active(pe_resource_t *rsc, gboolean all)
{
    if (rsc) {
        gboolean child_active = rsc->fns->active(rsc, all);

        if (child_active && !all) {
            return TRUE;
        } else if (!child_active && all) {
            return FALSE;
        }
    }
    return -1;
}

gboolean
pe__bundle_active(pe_resource_t *rsc, gboolean all)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    GList *iter = NULL;

    get_bundle_variant_data(bundle_data, rsc);
    for (iter = bundle_data->replicas; iter != NULL; iter = iter->next) {
        pe__bundle_replica_t *replica = iter->data;
        int rsc_active;

        rsc_active = replica_resource_active(replica->ip, all);
        if (rsc_active >= 0) {
            return (gboolean) rsc_active;
        }

        rsc_active = replica_resource_active(replica->child, all);
        if (rsc_active >= 0) {
            return (gboolean) rsc_active;
        }

        rsc_active = replica_resource_active(replica->container, all);
        if (rsc_active >= 0) {
            return (gboolean) rsc_active;
        }

        rsc_active = replica_resource_active(replica->remote, all);
        if (rsc_active >= 0) {
            return (gboolean) rsc_active;
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
pe_resource_t *
pe__find_bundle_replica(const pe_resource_t *bundle, const pe_node_t *node)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    CRM_ASSERT(bundle && node);

    get_bundle_variant_data(bundle_data, bundle);
    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica && replica->node);
        if (replica->node->details == node->details) {
            return replica->child;
        }
    }
    return NULL;
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
static void
print_rsc_in_list(pe_resource_t *rsc, const char *pre_text, long options,
                  void *print_data)
{
    if (rsc != NULL) {
        if (options & pe_print_html) {
            status_print("<li>");
        }
        rsc->fns->print(rsc, pre_text, options, print_data);
        if (options & pe_print_html) {
            status_print("</li>\n");
        }
    }
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
static void
bundle_print_xml(pe_resource_t *rsc, const char *pre_text, long options,
                 void *print_data)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    char *child_text = NULL;
    CRM_CHECK(rsc != NULL, return);

    if (pre_text == NULL) {
        pre_text = "";
    }
    child_text = crm_strdup_printf("%s        ", pre_text);

    get_bundle_variant_data(bundle_data, rsc);

    status_print("%s<bundle ", pre_text);
    status_print(XML_ATTR_ID "=\"%s\" ", rsc->id);
    status_print("type=\"%s\" ", container_agent_str(bundle_data->agent_type));
    status_print("image=\"%s\" ", bundle_data->image);
    status_print("unique=\"%s\" ", pe__rsc_bool_str(rsc, pe_rsc_unique));
    status_print("managed=\"%s\" ", pe__rsc_bool_str(rsc, pe_rsc_managed));
    status_print("failed=\"%s\" ", pe__rsc_bool_str(rsc, pe_rsc_failed));
    status_print(">\n");

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);
        status_print("%s    <replica " XML_ATTR_ID "=\"%d\">\n",
                     pre_text, replica->offset);
        print_rsc_in_list(replica->ip, child_text, options, print_data);
        print_rsc_in_list(replica->child, child_text, options, print_data);
        print_rsc_in_list(replica->container, child_text, options, print_data);
        print_rsc_in_list(replica->remote, child_text, options, print_data);
        status_print("%s    </replica>\n", pre_text);
    }
    status_print("%s</bundle>\n", pre_text);
    free(child_text);
}

PCMK__OUTPUT_ARGS("bundle", "uint32_t", "pe_resource_t *", "GList *", "GList *")
int
pe__bundle_xml(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    pe__bundle_variant_data_t *bundle_data = NULL;
    int rc = pcmk_rc_no_output;
    gboolean printed_header = FALSE;
    gboolean print_everything = TRUE;

    const char *desc = NULL;

    CRM_ASSERT(rsc != NULL);
    
    get_bundle_variant_data(bundle_data, rsc);

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return rc;
    }

    print_everything = pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;
        char *id = NULL;
        gboolean print_ip, print_child, print_ctnr, print_remote;

        CRM_ASSERT(replica);

        if (pcmk__rsc_filtered_by_node(replica->container, only_node)) {
            continue;
        }

        print_ip = replica->ip != NULL &&
                   !replica->ip->fns->is_filtered(replica->ip, only_rsc, print_everything);
        print_child = replica->child != NULL &&
                      !replica->child->fns->is_filtered(replica->child, only_rsc, print_everything);
        print_ctnr = !replica->container->fns->is_filtered(replica->container, only_rsc, print_everything);
        print_remote = replica->remote != NULL &&
                       !replica->remote->fns->is_filtered(replica->remote, only_rsc, print_everything);

        if (!print_everything && !print_ip && !print_child && !print_ctnr && !print_remote) {
            continue;
        }

        if (!printed_header) {
            printed_header = TRUE;

            desc = pe__resource_description(rsc, show_opts);

            rc = pe__name_and_nvpairs_xml(out, true, "bundle", 8,
                     "id", rsc->id,
                     "type", container_agent_str(bundle_data->agent_type),
                     "image", bundle_data->image,
                     "unique", pe__rsc_bool_str(rsc, pe_rsc_unique),
                     "maintenance", pe__rsc_bool_str(rsc, pe_rsc_maintenance),
                     "managed", pe__rsc_bool_str(rsc, pe_rsc_managed),
                     "failed", pe__rsc_bool_str(rsc, pe_rsc_failed),
                     "description", desc);
            CRM_ASSERT(rc == pcmk_rc_ok);
        }

        id = pcmk__itoa(replica->offset);
        rc = pe__name_and_nvpairs_xml(out, true, "replica", 1, "id", id);
        free(id);
        CRM_ASSERT(rc == pcmk_rc_ok);

        if (print_ip) {
            out->message(out, crm_map_element_name(replica->ip->xml), show_opts,
                         replica->ip, only_node, only_rsc);
        }

        if (print_child) {
            out->message(out, crm_map_element_name(replica->child->xml), show_opts,
                         replica->child, only_node, only_rsc);
        }

        if (print_ctnr) {
            out->message(out, crm_map_element_name(replica->container->xml), show_opts,
                         replica->container, only_node, only_rsc);
        }

        if (print_remote) {
            out->message(out, crm_map_element_name(replica->remote->xml), show_opts,
                         replica->remote, only_node, only_rsc);
        }

        pcmk__output_xml_pop_parent(out); // replica
    }

    if (printed_header) {
        pcmk__output_xml_pop_parent(out); // bundle
    }

    return rc;
}

static void
pe__bundle_replica_output_html(pcmk__output_t *out, pe__bundle_replica_t *replica,
                               pe_node_t *node, uint32_t show_opts)
{
    pe_resource_t *rsc = replica->child;

    int offset = 0;
    char buffer[LINE_MAX];

    if(rsc == NULL) {
        rsc = replica->container;
    }

    if (replica->remote) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s",
                           rsc_printable_id(replica->remote));
    } else {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s",
                           rsc_printable_id(replica->container));
    }
    if (replica->ipaddr) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, " (%s)",
                           replica->ipaddr);
    }

    pe__common_output_html(out, rsc, buffer, node, show_opts);
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
get_unmanaged_str(const pe_resource_t *rsc)
{
    if (pcmk_is_set(rsc->flags, pe_rsc_maintenance)) {
        return " (maintenance)";
    }
    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        return " (unmanaged)";
    }
    return "";
}

PCMK__OUTPUT_ARGS("bundle", "uint32_t", "pe_resource_t *", "GList *", "GList *")
int
pe__bundle_html(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    const char *desc = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    int rc = pcmk_rc_no_output;
    gboolean print_everything = TRUE;

    CRM_ASSERT(rsc != NULL);

    get_bundle_variant_data(bundle_data, rsc);

    desc = pe__resource_description(rsc, show_opts);

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return rc;
    }

    print_everything = pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;
        gboolean print_ip, print_child, print_ctnr, print_remote;

        CRM_ASSERT(replica);

        if (pcmk__rsc_filtered_by_node(replica->container, only_node)) {
            continue;
        }

        print_ip = replica->ip != NULL &&
                   !replica->ip->fns->is_filtered(replica->ip, only_rsc, print_everything);
        print_child = replica->child != NULL &&
                      !replica->child->fns->is_filtered(replica->child, only_rsc, print_everything);
        print_ctnr = !replica->container->fns->is_filtered(replica->container, only_rsc, print_everything);
        print_remote = replica->remote != NULL &&
                       !replica->remote->fns->is_filtered(replica->remote, only_rsc, print_everything);

        if (pcmk_is_set(show_opts, pcmk_show_implicit_rscs) ||
            (print_everything == FALSE && (print_ip || print_child || print_ctnr || print_remote))) {
            /* The text output messages used below require pe_print_implicit to
             * be set to do anything.
             */
            uint32_t new_show_opts = show_opts | pcmk_show_implicit_rscs;

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Container bundle%s: %s [%s]%s%s%s%s%s",
                                     (bundle_data->nreplicas > 1)? " set" : "",
                                     rsc->id, bundle_data->image,
                                     pcmk_is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                                     desc ? " (" : "", desc ? desc : "", desc ? ")" : "",
                                     get_unmanaged_str(rsc));

            if (pcmk__list_of_multiple(bundle_data->replicas)) {
                out->begin_list(out, NULL, NULL, "Replica[%d]", replica->offset);
            }

            if (print_ip) {
                out->message(out, crm_map_element_name(replica->ip->xml),
                             new_show_opts, replica->ip, only_node, only_rsc);
            }

            if (print_child) {
                out->message(out, crm_map_element_name(replica->child->xml),
                             new_show_opts, replica->child, only_node, only_rsc);
            }

            if (print_ctnr) {
                out->message(out, crm_map_element_name(replica->container->xml),
                             new_show_opts, replica->container, only_node, only_rsc);
            }

            if (print_remote) {
                out->message(out, crm_map_element_name(replica->remote->xml),
                             new_show_opts, replica->remote, only_node, only_rsc);
            }

            if (pcmk__list_of_multiple(bundle_data->replicas)) {
                out->end_list(out);
            }
        } else if (print_everything == FALSE && !(print_ip || print_child || print_ctnr || print_remote)) {
            continue;
        } else {
            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Container bundle%s: %s [%s]%s%s%s%s%s",
                                     (bundle_data->nreplicas > 1)? " set" : "",
                                     rsc->id, bundle_data->image,
                                     pcmk_is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                                     desc ? " (" : "", desc ? desc : "", desc ? ")" : "",
                                     get_unmanaged_str(rsc));

            pe__bundle_replica_output_html(out, replica, pe__current_node(replica->container),
                                           show_opts);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

static void
pe__bundle_replica_output_text(pcmk__output_t *out, pe__bundle_replica_t *replica,
                               pe_node_t *node, uint32_t show_opts)
{
    const pe_resource_t *rsc = replica->child;

    int offset = 0;
    char buffer[LINE_MAX];

    if(rsc == NULL) {
        rsc = replica->container;
    }

    if (replica->remote) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s",
                           rsc_printable_id(replica->remote));
    } else {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s",
                           rsc_printable_id(replica->container));
    }
    if (replica->ipaddr) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, " (%s)",
                           replica->ipaddr);
    }

    pe__common_output_text(out, rsc, buffer, node, show_opts);
}

PCMK__OUTPUT_ARGS("bundle", "uint32_t", "pe_resource_t *", "GList *", "GList *")
int
pe__bundle_text(pcmk__output_t *out, va_list args)
{
    uint32_t show_opts = va_arg(args, uint32_t);
    pe_resource_t *rsc = va_arg(args, pe_resource_t *);
    GList *only_node = va_arg(args, GList *);
    GList *only_rsc = va_arg(args, GList *);

    const char *desc = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;
    int rc = pcmk_rc_no_output;
    gboolean print_everything = TRUE;

    desc = pe__resource_description(rsc, show_opts);
    
    get_bundle_variant_data(bundle_data, rsc);

    CRM_ASSERT(rsc != NULL);

    if (rsc->fns->is_filtered(rsc, only_rsc, TRUE)) {
        return rc;
    }

    print_everything = pcmk__str_in_list(rsc->id, only_rsc, pcmk__str_star_matches);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;
        gboolean print_ip, print_child, print_ctnr, print_remote;

        CRM_ASSERT(replica);

        if (pcmk__rsc_filtered_by_node(replica->container, only_node)) {
            continue;
        }

        print_ip = replica->ip != NULL &&
                   !replica->ip->fns->is_filtered(replica->ip, only_rsc, print_everything);
        print_child = replica->child != NULL &&
                      !replica->child->fns->is_filtered(replica->child, only_rsc, print_everything);
        print_ctnr = !replica->container->fns->is_filtered(replica->container, only_rsc, print_everything);
        print_remote = replica->remote != NULL &&
                       !replica->remote->fns->is_filtered(replica->remote, only_rsc, print_everything);

        if (pcmk_is_set(show_opts, pcmk_show_implicit_rscs) ||
            (print_everything == FALSE && (print_ip || print_child || print_ctnr || print_remote))) {
            /* The text output messages used below require pe_print_implicit to
             * be set to do anything.
             */
            uint32_t new_show_opts = show_opts | pcmk_show_implicit_rscs;

            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Container bundle%s: %s [%s]%s%s%s%s%s",
                                     (bundle_data->nreplicas > 1)? " set" : "",
                                     rsc->id, bundle_data->image,
                                     pcmk_is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                                     desc ? " (" : "", desc ? desc : "", desc ? ")" : "",
                                     get_unmanaged_str(rsc));

            if (pcmk__list_of_multiple(bundle_data->replicas)) {
                out->list_item(out, NULL, "Replica[%d]", replica->offset);
            }

            out->begin_list(out, NULL, NULL, NULL);

            if (print_ip) {
                out->message(out, crm_map_element_name(replica->ip->xml),
                             new_show_opts, replica->ip, only_node, only_rsc);
            }

            if (print_child) {
                out->message(out, crm_map_element_name(replica->child->xml),
                             new_show_opts, replica->child, only_node, only_rsc);
            }

            if (print_ctnr) {
                out->message(out, crm_map_element_name(replica->container->xml),
                             new_show_opts, replica->container, only_node, only_rsc);
            }

            if (print_remote) {
                out->message(out, crm_map_element_name(replica->remote->xml),
                             new_show_opts, replica->remote, only_node, only_rsc);
            }

            out->end_list(out);
        } else if (print_everything == FALSE && !(print_ip || print_child || print_ctnr || print_remote)) {
            continue;
        } else {
            PCMK__OUTPUT_LIST_HEADER(out, FALSE, rc, "Container bundle%s: %s [%s]%s%s%s%s%s",
                                     (bundle_data->nreplicas > 1)? " set" : "",
                                     rsc->id, bundle_data->image,
                                     pcmk_is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                                     desc ? " (" : "", desc ? desc : "", desc ? ")" : "",
                                     get_unmanaged_str(rsc));

            pe__bundle_replica_output_text(out, replica, pe__current_node(replica->container),
                                           show_opts);
        }
    }

    PCMK__OUTPUT_LIST_FOOTER(out, rc);
    return rc;
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
static void
print_bundle_replica(pe__bundle_replica_t *replica, const char *pre_text,
                     long options, void *print_data)
{
    pe_node_t *node = NULL;
    pe_resource_t *rsc = replica->child;

    int offset = 0;
    char buffer[LINE_MAX];

    if(rsc == NULL) {
        rsc = replica->container;
    }

    if (replica->remote) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s",
                           rsc_printable_id(replica->remote));
    } else {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s",
                           rsc_printable_id(replica->container));
    }
    if (replica->ipaddr) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, " (%s)",
                           replica->ipaddr);
    }

    node = pe__current_node(replica->container);
    common_print(rsc, pre_text, buffer, node, options, print_data);
}

/*!
 * \internal
 * \deprecated This function will be removed in a future release
 */
void
pe__print_bundle(pe_resource_t *rsc, const char *pre_text, long options,
                 void *print_data)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    char *child_text = NULL;
    CRM_CHECK(rsc != NULL, return);

    if (options & pe_print_xml) {
        bundle_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    get_bundle_variant_data(bundle_data, rsc);

    if (pre_text == NULL) {
        pre_text = " ";
    }

    status_print("%sContainer bundle%s: %s [%s]%s%s\n",
                 pre_text, ((bundle_data->nreplicas > 1)? " set" : ""),
                 rsc->id, bundle_data->image,
                 pcmk_is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                 pcmk_is_set(rsc->flags, pe_rsc_managed) ? "" : " (unmanaged)");
    if (options & pe_print_html) {
        status_print("<br />\n<ul>\n");
    }


    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);
        if (options & pe_print_html) {
            status_print("<li>");
        }

        if (pcmk_is_set(options, pe_print_implicit)) {
            child_text = crm_strdup_printf("     %s", pre_text);
            if (pcmk__list_of_multiple(bundle_data->replicas)) {
                status_print("  %sReplica[%d]\n", pre_text, replica->offset);
            }
            if (options & pe_print_html) {
                status_print("<br />\n<ul>\n");
            }
            print_rsc_in_list(replica->ip, child_text, options, print_data);
            print_rsc_in_list(replica->container, child_text, options, print_data);
            print_rsc_in_list(replica->remote, child_text, options, print_data);
            print_rsc_in_list(replica->child, child_text, options, print_data);
            if (options & pe_print_html) {
                status_print("</ul>\n");
            }
        } else {
            child_text = crm_strdup_printf("%s  ", pre_text);
            print_bundle_replica(replica, child_text, options, print_data);
        }
        free(child_text);

        if (options & pe_print_html) {
            status_print("</li>\n");
        }
    }
    if (options & pe_print_html) {
        status_print("</ul>\n");
    }
}

static void
free_bundle_replica(pe__bundle_replica_t *replica)
{
    if (replica == NULL) {
        return;
    }

    if (replica->node) {
        free(replica->node);
        replica->node = NULL;
    }

    if (replica->ip) {
        free_xml(replica->ip->xml);
        replica->ip->xml = NULL;
        replica->ip->fns->free(replica->ip);
        replica->ip = NULL;
    }
    if (replica->container) {
        free_xml(replica->container->xml);
        replica->container->xml = NULL;
        replica->container->fns->free(replica->container);
        replica->container = NULL;
    }
    if (replica->remote) {
        free_xml(replica->remote->xml);
        replica->remote->xml = NULL;
        replica->remote->fns->free(replica->remote);
        replica->remote = NULL;
    }
    free(replica->ipaddr);
    free(replica);
}

void
pe__free_bundle(pe_resource_t *rsc)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    CRM_CHECK(rsc != NULL, return);

    get_bundle_variant_data(bundle_data, rsc);
    pe_rsc_trace(rsc, "Freeing %s", rsc->id);

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
    g_list_free(rsc->children);

    if(bundle_data->child) {
        free_xml(bundle_data->child->xml);
        bundle_data->child->xml = NULL;
        bundle_data->child->fns->free(bundle_data->child);
    }
    common_free(rsc);
}

enum rsc_role_e
pe__bundle_resource_state(const pe_resource_t *rsc, gboolean current)
{
    enum rsc_role_e container_role = RSC_ROLE_UNKNOWN;
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
pe_bundle_replicas(const pe_resource_t *rsc)
{
    if ((rsc == NULL) || (rsc->variant != pe_container)) {
        return 0;
    } else {
        pe__bundle_variant_data_t *bundle_data = NULL;

        get_bundle_variant_data(bundle_data, rsc);
        return bundle_data->nreplicas;
    }
}

void
pe__count_bundle(pe_resource_t *rsc)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, rsc);
    for (GList *item = bundle_data->replicas; item != NULL; item = item->next) {
        pe__bundle_replica_t *replica = item->data;

        if (replica->ip) {
            replica->ip->fns->count(replica->ip);
        }
        if (replica->child) {
            replica->child->fns->count(replica->child);
        }
        if (replica->container) {
            replica->container->fns->count(replica->container);
        }
        if (replica->remote) {
            replica->remote->fns->count(replica->remote);
        }
    }
}

gboolean
pe__bundle_is_filtered(const pe_resource_t *rsc, GList *only_rsc,
                       gboolean check_parent)
{
    gboolean passes = FALSE;
    pe__bundle_variant_data_t *bundle_data = NULL;

    if (pcmk__str_in_list(rsc_printable_id(rsc), only_rsc, pcmk__str_star_matches)) {
        passes = TRUE;
    } else {
        get_bundle_variant_data(bundle_data, rsc);

        for (GList *gIter = bundle_data->replicas; gIter != NULL; gIter = gIter->next) {
            pe__bundle_replica_t *replica = gIter->data;

            if (replica->ip != NULL && !replica->ip->fns->is_filtered(replica->ip, only_rsc, FALSE)) {
                passes = TRUE;
                break;
            } else if (replica->child != NULL && !replica->child->fns->is_filtered(replica->child, only_rsc, FALSE)) {
                passes = TRUE;
                break;
            } else if (!replica->container->fns->is_filtered(replica->container, only_rsc, FALSE)) {
                passes = TRUE;
                break;
            } else if (replica->remote != NULL && !replica->remote->fns->is_filtered(replica->remote, only_rsc, FALSE)) {
                passes = TRUE;
                break;
            }
        }
    }

    return !passes;
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
pe__bundle_containers(const pe_resource_t *bundle)
{
    GList *containers = NULL;
    const pe__bundle_variant_data_t *data = NULL;

    get_bundle_variant_data(data, bundle);
    for (GList *iter = data->replicas; iter != NULL; iter = iter->next) {
        pe__bundle_replica_t *replica = iter->data;

        containers = g_list_append(containers, replica->container);
    }
    return containers;
}

// Bundle implementation of resource_object_functions_t:active_node()
pe_node_t *
pe__bundle_active_node(const pe_resource_t *rsc, unsigned int *count_all,
                       unsigned int *count_clean)
{
    pe_node_t *active = NULL;
    pe_node_t *node = NULL;
    pe_resource_t *container = NULL;
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
        pe__bundle_replica_t *replica = iter->data;

        if (replica->container->running_on != NULL) {
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
        node = container->fns->active_node(container, count_all, count_clean);
        g_list_free(containers);
        return node;
    }

    // Add all containers' active nodes to a hash table (for uniqueness)
    nodes = g_hash_table_new(NULL, NULL);
    for (iter = containers; iter != NULL; iter = iter->next) {
        container = iter->data;

        for (GList *node_iter = container->running_on; node_iter != NULL;
             node_iter = node_iter->next) {
            node = node_iter->data;

            // If insert returns true, we haven't counted this node yet
            if (g_hash_table_insert(nodes, (gpointer) node->details,
                                    (gpointer) node)
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
pe__bundle_max_per_node(const pe_resource_t *rsc)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    get_bundle_variant_data(bundle_data, rsc);
    CRM_ASSERT(bundle_data->nreplicas_per_host >= 0);
    return (unsigned int) bundle_data->nreplicas_per_host;
}
