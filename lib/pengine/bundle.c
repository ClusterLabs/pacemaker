/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <ctype.h>

#include <crm/common/curses_internal.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>

#define PE__VARIANT_BUNDLE 1
#include "./variant.h"

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

static int
allocate_ip(pe__bundle_variant_data_t *data, pe__bundle_replica_t *replica,
            char *buffer, int max)
{
    if(data->ip_range_start == NULL) {
        return 0;

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
                return snprintf(buffer, max, " --add-host=%s-%d:%s",
                                data->prefix, replica->offset,
                                replica->ipaddr);
            }
        case PE__CONTAINER_AGENT_RKT:
            return snprintf(buffer, max, " --hosts-entry=%s=%s-%d",
                            replica->ipaddr, data->prefix, replica->offset);
        default: // PE__CONTAINER_AGENT_UNKNOWN
            break;
    }
    return 0;
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
 * \param[in] data  Container variant data
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
            /* @TODO to be sure: clear_bit(rsc->flags, pe_rsc_unique); */
        }
        return TRUE;
    }
    return FALSE;
}

static bool
create_ip_resource(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                   pe__bundle_replica_t *replica, pe_working_set_t *data_set)
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

        if (!common_unpack(xml_ip, &replica->ip, parent, data_set)) {
            return FALSE;
        }

        parent->children = g_list_append(parent->children, replica->ip);
    }
    return TRUE;
}

static bool
create_docker_resource(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                       pe__bundle_replica_t *replica,
                       pe_working_set_t *data_set)
{
        int offset = 0, max = 4096;
        char *buffer = calloc(1, max+1);

        int doffset = 0, dmax = 1024;
        char *dbuffer = calloc(1, dmax+1);

        char *id = NULL;
        xmlNode *xml_container = NULL;
        xmlNode *xml_obj = NULL;

        id = crm_strdup_printf("%s-docker-%d", data->prefix, replica->offset);
        crm_xml_sanitize_id(id);
        xml_container = create_resource(id, "heartbeat",
                                        PE__CONTAINER_AGENT_DOCKER_S);
        free(id);

        xml_obj = create_xml_node(xml_container, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_obj, "%s-attributes-%d",
                       data->prefix, replica->offset);

        crm_create_nvpair_xml(xml_obj, NULL, "image", data->image);
        crm_create_nvpair_xml(xml_obj, NULL, "allow_pull", XML_BOOLEAN_TRUE);
        crm_create_nvpair_xml(xml_obj, NULL, "force_kill", XML_BOOLEAN_FALSE);
        crm_create_nvpair_xml(xml_obj, NULL, "reuse", XML_BOOLEAN_FALSE);

        offset += snprintf(buffer+offset, max-offset, " --restart=no");

        /* Set a container hostname only if we have an IP to map it to.
         * The user can set -h or --uts=host themselves if they want a nicer
         * name for logs, but this makes applications happy who need their
         * hostname to match the IP they bind to.
         */
        if (data->ip_range_start != NULL) {
            offset += snprintf(buffer+offset, max-offset, " -h %s-%d",
                               data->prefix, replica->offset);
        }

        offset += snprintf(buffer+offset, max-offset, " -e PCMK_stderr=1");

        if (data->container_network) {
#if 0
            offset += snprintf(buffer+offset, max-offset, " --link-local-ip=%s",
                               replica->ipaddr);
#endif
            offset += snprintf(buffer+offset, max-offset, " --net=%s",
                               data->container_network);
        }

        if(data->control_port) {
            offset += snprintf(buffer+offset, max-offset, " -e PCMK_remote_port=%s", data->control_port);
        } else {
            offset += snprintf(buffer+offset, max-offset, " -e PCMK_remote_port=%d", DEFAULT_REMOTE_PORT);
        }

        for(GListPtr pIter = data->mounts; pIter != NULL; pIter = pIter->next) {
            pe__bundle_mount_t *mount = pIter->data;

            if (is_set(mount->flags, pe__bundle_mount_subdir)) {
                char *source = crm_strdup_printf(
                    "%s/%s-%d", mount->source, data->prefix, replica->offset);

                if(doffset > 0) {
                    doffset += snprintf(dbuffer+doffset, dmax-doffset, ",");
                }
                doffset += snprintf(dbuffer+doffset, dmax-doffset, "%s", source);
                offset += snprintf(buffer+offset, max-offset, " -v %s:%s", source, mount->target);
                free(source);

            } else {
                offset += snprintf(buffer+offset, max-offset, " -v %s:%s", mount->source, mount->target);
            }
            if(mount->options) {
                offset += snprintf(buffer+offset, max-offset, ":%s", mount->options);
            }
        }

        for(GListPtr pIter = data->ports; pIter != NULL; pIter = pIter->next) {
            pe__bundle_port_t *port = pIter->data;

            if (replica->ipaddr) {
                offset += snprintf(buffer+offset, max-offset, " -p %s:%s:%s",
                                   replica->ipaddr, port->source,
                                   port->target);
            } else if(safe_str_neq(data->container_network, "host")) {
                // No need to do port mapping if net=host
                offset += snprintf(buffer+offset, max-offset, " -p %s:%s", port->source, port->target);
            }
        }

        if (data->launcher_options) {
            offset += snprintf(buffer+offset, max-offset, " %s",
                               data->launcher_options);
        }

        if (data->container_host_options) {
            offset += snprintf(buffer + offset, max - offset, " %s",
                               data->container_host_options);
        }

        crm_create_nvpair_xml(xml_obj, NULL, "run_opts", buffer);
        free(buffer);

        crm_create_nvpair_xml(xml_obj, NULL, "mount_points", dbuffer);
        free(dbuffer);

        if (replica->child) {
            if (data->container_command) {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", data->container_command);
            } else {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", SBIN_DIR "/pacemaker-remoted");
            }

            /* TODO: Allow users to specify their own?
             *
             * We just want to know if the container is alive, we'll
             * monitor the child independently
             */
            crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
        /* } else if(child && data->untrusted) {
         * Support this use-case?
         *
         * The ability to have resources started/stopped by us, but
         * unable to set attributes, etc.
         *
         * Arguably better to control API access this with ACLs like
         * "normal" remote nodes
         *
         *     crm_create_nvpair_xml(xml_obj, NULL,
         *                           "run_cmd",
         *                           "/usr/libexec/pacemaker/pacemaker-execd");
         *     crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd",
         *         "/usr/libexec/pacemaker/lrmd_internal_ctl -c poke");
         */
        } else {
            if (data->container_command) {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", data->container_command);
            }

            /* TODO: Allow users to specify their own?
             *
             * We don't know what's in the container, so we just want
             * to know if it is alive
             */
            crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
        }


        xml_obj = create_xml_node(xml_container, "operations");
        crm_create_op_xml(xml_obj, ID(xml_container), "monitor", "60s", NULL);

        // TODO: Other ops? Timeouts and intervals from underlying resource?
        if (!common_unpack(xml_container, &replica->container, parent, data_set)) {
            return FALSE;
        }
        parent->children = g_list_append(parent->children, replica->container);
        return TRUE;
}

static bool
create_podman_resource(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                       pe__bundle_replica_t *replica,
                       pe_working_set_t *data_set)
{
        int offset = 0, max = 4096;
        char *buffer = calloc(1, max+1);

        int doffset = 0, dmax = 1024;
        char *dbuffer = calloc(1, dmax+1);

        char *id = NULL;
        xmlNode *xml_container = NULL;
        xmlNode *xml_obj = NULL;

        id = crm_strdup_printf("%s-podman-%d", data->prefix, replica->offset);
        crm_xml_sanitize_id(id);
        xml_container = create_resource(id, "heartbeat",
                                        PE__CONTAINER_AGENT_PODMAN_S);
        free(id);

        xml_obj = create_xml_node(xml_container, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_obj, "%s-attributes-%d",
                       data->prefix, replica->offset);

        crm_create_nvpair_xml(xml_obj, NULL, "image", data->image);
        crm_create_nvpair_xml(xml_obj, NULL, "allow_pull", XML_BOOLEAN_TRUE);
        crm_create_nvpair_xml(xml_obj, NULL, "force_kill", XML_BOOLEAN_FALSE);
        crm_create_nvpair_xml(xml_obj, NULL, "reuse", XML_BOOLEAN_FALSE);

        // FIXME: (bandini 2018-08) podman has no restart policies
        //offset += snprintf(buffer+offset, max-offset, " --restart=no");

        /* Set a container hostname only if we have an IP to map it to.
         * The user can set -h or --uts=host themselves if they want a nicer
         * name for logs, but this makes applications happy who need their
         * hostname to match the IP they bind to.
         */
        if (data->ip_range_start != NULL) {
            offset += snprintf(buffer+offset, max-offset, " -h %s-%d",
                               data->prefix, replica->offset);
        }

        offset += snprintf(buffer+offset, max-offset, " -e PCMK_stderr=1");

        if (data->container_network) {
#if 0
            // podman has no support for --link-local-ip
            offset += snprintf(buffer+offset, max-offset, " --link-local-ip=%s",
                               replica->ipaddr);
#endif
            offset += snprintf(buffer+offset, max-offset, " --net=%s",
                               data->container_network);
        }

        if(data->control_port) {
            offset += snprintf(buffer+offset, max-offset, " -e PCMK_remote_port=%s", data->control_port);
        } else {
            offset += snprintf(buffer+offset, max-offset, " -e PCMK_remote_port=%d", DEFAULT_REMOTE_PORT);
        }

        for(GListPtr pIter = data->mounts; pIter != NULL; pIter = pIter->next) {
            pe__bundle_mount_t *mount = pIter->data;

            if (is_set(mount->flags, pe__bundle_mount_subdir)) {
                char *source = crm_strdup_printf(
                    "%s/%s-%d", mount->source, data->prefix, replica->offset);

                if(doffset > 0) {
                    doffset += snprintf(dbuffer+doffset, dmax-doffset, ",");
                }
                doffset += snprintf(dbuffer+doffset, dmax-doffset, "%s", source);
                offset += snprintf(buffer+offset, max-offset, " -v %s:%s", source, mount->target);
                free(source);

            } else {
                offset += snprintf(buffer+offset, max-offset, " -v %s:%s", mount->source, mount->target);
            }
            if(mount->options) {
                offset += snprintf(buffer+offset, max-offset, ":%s", mount->options);
            }
        }

        for(GListPtr pIter = data->ports; pIter != NULL; pIter = pIter->next) {
            pe__bundle_port_t *port = pIter->data;

            if (replica->ipaddr) {
                offset += snprintf(buffer+offset, max-offset, " -p %s:%s:%s",
                                   replica->ipaddr, port->source,
                                   port->target);
            } else if(safe_str_neq(data->container_network, "host")) {
                // No need to do port mapping if net=host
                offset += snprintf(buffer+offset, max-offset, " -p %s:%s", port->source, port->target);
            }
        }

        if (data->launcher_options) {
            offset += snprintf(buffer+offset, max-offset, " %s",
                               data->launcher_options);
        }

        if (data->container_host_options) {
            offset += snprintf(buffer + offset, max - offset, " %s",
                               data->container_host_options);
        }

        crm_create_nvpair_xml(xml_obj, NULL, "run_opts", buffer);
        free(buffer);

        crm_create_nvpair_xml(xml_obj, NULL, "mount_points", dbuffer);
        free(dbuffer);

        if (replica->child) {
            if (data->container_command) {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", data->container_command);
            } else {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", SBIN_DIR "/pacemaker-remoted");
            }

            /* TODO: Allow users to specify their own?
             *
             * We just want to know if the container is alive, we'll
             * monitor the child independently
             */
            crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
        /* } else if(child && data->untrusted) {
         * Support this use-case?
         *
         * The ability to have resources started/stopped by us, but
         * unable to set attributes, etc.
         *
         * Arguably better to control API access this with ACLs like
         * "normal" remote nodes
         *
         *     crm_create_nvpair_xml(xml_obj, NULL,
         *                           "run_cmd",
         *                           "/usr/libexec/pacemaker/pacemaker-execd");
         *     crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd",
         *         "/usr/libexec/pacemaker/lrmd_internal_ctl -c poke");
         */
        } else {
            if (data->container_command) {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", data->container_command);
            }

            /* TODO: Allow users to specify their own?
             *
             * We don't know what's in the container, so we just want
             * to know if it is alive
             */
            crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
        }


        xml_obj = create_xml_node(xml_container, "operations");
        crm_create_op_xml(xml_obj, ID(xml_container), "monitor", "60s", NULL);

        // TODO: Other ops? Timeouts and intervals from underlying resource?
        if (!common_unpack(xml_container, &replica->container, parent,
                           data_set)) {
            return FALSE;
        }
        parent->children = g_list_append(parent->children, replica->container);
        return TRUE;
}

static bool
create_rkt_resource(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                    pe__bundle_replica_t *replica, pe_working_set_t *data_set)
{
        int offset = 0, max = 4096;
        char *buffer = calloc(1, max+1);

        int doffset = 0, dmax = 1024;
        char *dbuffer = calloc(1, dmax+1);

        char *id = NULL;
        xmlNode *xml_container = NULL;
        xmlNode *xml_obj = NULL;

        int volid = 0;

        id = crm_strdup_printf("%s-rkt-%d", data->prefix, replica->offset);
        crm_xml_sanitize_id(id);
        xml_container = create_resource(id, "heartbeat",
                                        PE__CONTAINER_AGENT_RKT_S);
        free(id);

        xml_obj = create_xml_node(xml_container, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_obj, "%s-attributes-%d",
                       data->prefix, replica->offset);

        crm_create_nvpair_xml(xml_obj, NULL, "image", data->image);
        crm_create_nvpair_xml(xml_obj, NULL, "allow_pull", "true");
        crm_create_nvpair_xml(xml_obj, NULL, "force_kill", "false");
        crm_create_nvpair_xml(xml_obj, NULL, "reuse", "false");

        /* Set a container hostname only if we have an IP to map it to.
         * The user can set -h or --uts=host themselves if they want a nicer
         * name for logs, but this makes applications happy who need their
         * hostname to match the IP they bind to.
         */
        if (data->ip_range_start != NULL) {
            offset += snprintf(buffer+offset, max-offset, " --hostname=%s-%d",
                               data->prefix, replica->offset);
        }

        offset += snprintf(buffer+offset, max-offset, " --environment=PCMK_stderr=1");

        if (data->container_network) {
#if 0
            offset += snprintf(buffer+offset, max-offset, " --link-local-ip=%s",
                               replica->ipaddr);
#endif
            offset += snprintf(buffer+offset, max-offset, " --net=%s",
                               data->container_network);
        }

        if(data->control_port) {
            offset += snprintf(buffer+offset, max-offset, " --environment=PCMK_remote_port=%s", data->control_port);
        } else {
            offset += snprintf(buffer+offset, max-offset, " --environment=PCMK_remote_port=%d", DEFAULT_REMOTE_PORT);
        }

        for(GListPtr pIter = data->mounts; pIter != NULL; pIter = pIter->next) {
            pe__bundle_mount_t *mount = pIter->data;

            if (is_set(mount->flags, pe__bundle_mount_subdir)) {
                char *source = crm_strdup_printf(
                    "%s/%s-%d", mount->source, data->prefix, replica->offset);

                if(doffset > 0) {
                    doffset += snprintf(dbuffer+doffset, dmax-doffset, ",");
                }
                doffset += snprintf(dbuffer+doffset, dmax-doffset, "%s", source);
                offset += snprintf(buffer+offset, max-offset, " --volume vol%d,kind=host,source=%s", volid, source);
                if(mount->options) {
                    offset += snprintf(buffer+offset, max-offset, ",%s", mount->options);
                }
                offset += snprintf(buffer+offset, max-offset, " --mount volume=vol%d,target=%s", volid, mount->target);
                free(source);

            } else {
                offset += snprintf(buffer+offset, max-offset, " --volume vol%d,kind=host,source=%s", volid, mount->source);
                if(mount->options) {
                    offset += snprintf(buffer+offset, max-offset, ",%s", mount->options);
                }
                offset += snprintf(buffer+offset, max-offset, " --mount volume=vol%d,target=%s", volid, mount->target);
            }
            volid++;
        }

        for(GListPtr pIter = data->ports; pIter != NULL; pIter = pIter->next) {
            pe__bundle_port_t *port = pIter->data;

            if (replica->ipaddr) {
                offset += snprintf(buffer+offset, max-offset,
                                   " --port=%s:%s:%s", port->target,
                                   replica->ipaddr, port->source);
            } else {
                offset += snprintf(buffer+offset, max-offset, " --port=%s:%s", port->target, port->source);
            }
        }

        if (data->launcher_options) {
            offset += snprintf(buffer+offset, max-offset, " %s",
                               data->launcher_options);
        }

        if (data->container_host_options) {
            offset += snprintf(buffer + offset, max - offset, " %s",
                               data->container_host_options);
        }

        crm_create_nvpair_xml(xml_obj, NULL, "run_opts", buffer);
        free(buffer);

        crm_create_nvpair_xml(xml_obj, NULL, "mount_points", dbuffer);
        free(dbuffer);

        if (replica->child) {
            if (data->container_command) {
                crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                      data->container_command);
            } else {
                crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                      SBIN_DIR "/pacemaker-remoted");
            }

            /* TODO: Allow users to specify their own?
             *
             * We just want to know if the container is alive, we'll
             * monitor the child independently
             */
            crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
        /* } else if(child && data->untrusted) {
         * Support this use-case?
         *
         * The ability to have resources started/stopped by us, but
         * unable to set attributes, etc.
         *
         * Arguably better to control API access this with ACLs like
         * "normal" remote nodes
         *
         *     crm_create_nvpair_xml(xml_obj, NULL,
         *                           "run_cmd",
         *                           "/usr/libexec/pacemaker/pacemaker-execd");
         *     crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd",
         *         "/usr/libexec/pacemaker/lrmd_internal_ctl -c poke");
         */
        } else {
            if (data->container_command) {
                crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                      data->container_command);
            }

            /* TODO: Allow users to specify their own?
             *
             * We don't know what's in the container, so we just want
             * to know if it is alive
             */
            crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
        }


        xml_obj = create_xml_node(xml_container, "operations");
        crm_create_op_xml(xml_obj, ID(xml_container), "monitor", "60s", NULL);

        // TODO: Other ops? Timeouts and intervals from underlying resource?

        if (!common_unpack(xml_container, &replica->container, parent, data_set)) {
            return FALSE;
        }
        parent->children = g_list_append(parent->children, replica->container);
        return TRUE;
}

/*!
 * \brief Ban a node from a resource's (and its children's) allowed nodes list
 *
 * \param[in,out] rsc    Resource to modify
 * \param[in]     uname  Name of node to ban
 */
static void
disallow_node(resource_t *rsc, const char *uname)
{
    gpointer match = g_hash_table_lookup(rsc->allowed_nodes, uname);

    if (match) {
        ((pe_node_t *) match)->weight = -INFINITY;
        ((pe_node_t *) match)->rsc_discover_mode = pe_discover_never;
    }
    if (rsc->children) {
        GListPtr child;

        for (child = rsc->children; child != NULL; child = child->next) {
            disallow_node((resource_t *) (child->data), uname);
        }
    }
}

static bool
create_remote_resource(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                       pe__bundle_replica_t *replica,
                       pe_working_set_t *data_set)
{
    if (replica->child && valid_network(data)) {
        GHashTableIter gIter;
        GListPtr rsc_iter = NULL;
        node_t *node = NULL;
        xmlNode *xml_remote = NULL;
        char *id = crm_strdup_printf("%s-%d", data->prefix, replica->offset);
        char *port_s = NULL;
        const char *uname = NULL;
        const char *connect_name = NULL;

        if (remote_id_conflict(id, data_set)) {
            free(id);
            // The biggest hammer we have
            id = crm_strdup_printf("pcmk-internal-%s-remote-%d",
                                   replica->child->id, replica->offset);
            CRM_ASSERT(remote_id_conflict(id, data_set) == FALSE);
        }

        /* REMOTE_CONTAINER_HACK: Using "#uname" as the server name when the
         * connection does not have its own IP is a magic string that we use to
         * support nested remotes (i.e. a bundle running on a remote node).
         */
        connect_name = (replica->ipaddr? replica->ipaddr : "#uname");

        if (data->control_port == NULL) {
            port_s = crm_itoa(DEFAULT_REMOTE_PORT);
        }

        /* This sets replica->container as replica->remote's container, which is
         * similar to what happens with guest nodes. This is how the PE knows
         * that the bundle node is fenced by recovering the container, and that
         * remote should be ordered relative to the container.
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
        node = pe_find_node(data_set->nodes, uname);
        if (node == NULL) {
            node = pe_create_node(uname, uname, "remote", "-INFINITY",
                                  data_set);
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
         * likely place for this to happen is when common_unpack() calls
         * resource_location() to set a default score in symmetric clusters.
         * This adds a node *copy* to each resource's allowed nodes, and these
         * copies will have the wrong weight.
         *
         * As a hacky workaround, fix those copies here.
         *
         * @TODO Possible alternative: ensure bundles are unpacked before other
         * resources, so the weight is correct before any copies are made.
         */
        for (rsc_iter = data_set->resources; rsc_iter; rsc_iter = rsc_iter->next) {
            disallow_node((resource_t *) (rsc_iter->data), uname);
        }

        replica->node = node_copy(node);
        replica->node->weight = 500;
        replica->node->rsc_discover_mode = pe_discover_exclusive;

        /* Ensure the node shows up as allowed and with the correct discovery set */
        if (replica->child->allowed_nodes != NULL) {
            g_hash_table_destroy(replica->child->allowed_nodes);
        }
        replica->child->allowed_nodes = g_hash_table_new_full(crm_str_hash,
                                                              g_str_equal,
                                                              NULL, free);
        g_hash_table_insert(replica->child->allowed_nodes,
                            (gpointer) replica->node->details->id,
                            node_copy(replica->node));

        {
            node_t *copy = node_copy(replica->node);
            copy->weight = -INFINITY;
            g_hash_table_insert(replica->child->parent->allowed_nodes,
                                (gpointer) replica->node->details->id, copy);
        }
        if (!common_unpack(xml_remote, &replica->remote, parent, data_set)) {
            return FALSE;
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
    return TRUE;
}

static bool
create_container(pe_resource_t *parent, pe__bundle_variant_data_t *data,
                 pe__bundle_replica_t *replica, pe_working_set_t *data_set)
{

    switch (data->agent_type) {
        case PE__CONTAINER_AGENT_DOCKER:
            if (!create_docker_resource(parent, data, replica, data_set)) {
                return FALSE;
            }
            break;

        case PE__CONTAINER_AGENT_PODMAN:
            if (!create_podman_resource(parent, data, replica, data_set)) {
                return FALSE;
            }
            break;

        case PE__CONTAINER_AGENT_RKT:
            if (!create_rkt_resource(parent, data, replica, data_set)) {
                return FALSE;
            }
            break;
        default: // PE__CONTAINER_AGENT_UNKNOWN
            return FALSE;
    }

    if (create_ip_resource(parent, data, replica, data_set) == FALSE) {
        return FALSE;
    }
    if(create_remote_resource(parent, data, replica, data_set) == FALSE) {
        return FALSE;
    }
    if (replica->child && replica->ipaddr) {
        add_hash_param(replica->child->meta, "external-ip", replica->ipaddr);
    }

    if (replica->remote) {
        /*
         * Allow the remote connection resource to be allocated to a
         * different node than the one on which the container is active.
         *
         * This makes it possible to have Pacemaker Remote nodes running
         * containers with pacemaker-remoted inside in order to start
         * services inside those containers.
         */
        set_bit(replica->remote->flags, pe_rsc_allow_remote_remotes);
    }

    return TRUE;
}

static void
mount_add(pe__bundle_variant_data_t *bundle_data, const char *source,
          const char *target, const char *options, uint32_t flags)
{
    pe__bundle_mount_t *mount = calloc(1, sizeof(pe__bundle_mount_t));

    mount->source = strdup(source);
    mount->target = strdup(target);
    if (options) {
        mount->options = strdup(options);
    }
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
    resource_t *top = remote;
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

    if (rsc == NULL) {
        return FALSE;
    }

    value = g_hash_table_lookup(rsc->parameters, XML_RSC_ATTR_REMOTE_RA_ADDR);
    if (safe_str_eq(value, "#uname") == FALSE) {
        return FALSE;

    } else {
        const char *match[3][2] = {
            { XML_ATTR_TYPE,           "remote"                },
            { XML_AGENT_ATTR_CLASS,    PCMK_RESOURCE_CLASS_OCF },
            { XML_AGENT_ATTR_PROVIDER, "pacemaker"             },
        };

        for (int m = 0; m < 3; m++) {
            value = crm_element_value(rsc->xml, match[m][0]);
            if (safe_str_neq(value, match[m][1])) {
                return FALSE;
            }
        }
    }
    return TRUE;
}

const char *
pe__add_bundle_remote_name(pe_resource_t *rsc, xmlNode *xml, const char *field)
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
              rsc->id, node->details->uname);
    if(xml != NULL && field != NULL) {
        crm_xml_add(xml, field, node->details->uname);
    }

    return node->details->uname;
}

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

    value = crm_element_value(xml_obj, XML_RSC_ATTR_PROMOTED_MAX);
    if (value == NULL) {
        // @COMPAT deprecated since 2.0.0
        value = crm_element_value(xml_obj, "masters");
    }
    bundle_data->promoted_max = crm_parse_int(value, "0");
    if (bundle_data->promoted_max < 0) {
        pe_err("%s for %s must be nonnegative integer, using 0",
               XML_RSC_ATTR_PROMOTED_MAX, rsc->id);
        bundle_data->promoted_max = 0;
    }

    value = crm_element_value(xml_obj, "replicas");
    if ((value == NULL) && bundle_data->promoted_max) {
        bundle_data->nreplicas = bundle_data->promoted_max;
    } else {
        bundle_data->nreplicas = crm_parse_int(value, "1");
    }
    if (bundle_data->nreplicas < 1) {
        pe_err("'replicas' for %s must be positive integer, using 1", rsc->id);
        bundle_data->nreplicas = 1;
    }

    /*
     * Communication between containers on the same host via the
     * floating IPs only works if the container is started with:
     *   --userland-proxy=false --ip-masq=false
     */
    value = crm_element_value(xml_obj, "replicas-per-host");
    bundle_data->nreplicas_per_host = crm_parse_int(value, "1");
    if (bundle_data->nreplicas_per_host < 1) {
        pe_err("'replicas-per-host' for %s must be positive integer, using 1",
               rsc->id);
        bundle_data->nreplicas_per_host = 1;
    }
    if (bundle_data->nreplicas_per_host == 1) {
        clear_bit(rsc->flags, pe_rsc_unique);
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
        if (check_boolean(value) == FALSE) {
            bundle_data->add_host = TRUE;
        } else {
            crm_str_to_boolean(value, &bundle_data->add_host);
        }

        for (xmlNode *xml_child = __xml_first_child_element(xml_obj); xml_child != NULL;
             xml_child = __xml_next_element(xml_child)) {

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
    for (xmlNode *xml_child = __xml_first_child_element(xml_obj); xml_child != NULL;
         xml_child = __xml_next_element(xml_child)) {

        const char *source = crm_element_value(xml_child, "source-dir");
        const char *target = crm_element_value(xml_child, "target-dir");
        const char *options = crm_element_value(xml_child, "options");
        int flags = pe__bundle_mount_none;

        if (source == NULL) {
            source = crm_element_value(xml_child, "source-dir-root");
            set_bit(flags, pe__bundle_mount_subdir);
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

        value = crm_itoa(bundle_data->nreplicas);
        crm_create_nvpair_xml(xml_set, NULL,
                              XML_RSC_ATTR_INCARNATION_MAX, value);
        free(value);

        value = crm_itoa(bundle_data->nreplicas_per_host);
        crm_create_nvpair_xml(xml_set, NULL,
                              XML_RSC_ATTR_INCARNATION_NODEMAX, value);
        free(value);

        crm_create_nvpair_xml(xml_set, NULL, XML_RSC_ATTR_UNIQUE,
                (bundle_data->nreplicas_per_host > 1)?
                XML_BOOLEAN_TRUE : XML_BOOLEAN_FALSE);

        if (bundle_data->promoted_max) {
            crm_create_nvpair_xml(xml_set, NULL,
                                  XML_RSC_ATTR_PROMOTABLE, XML_BOOLEAN_TRUE);

            value = crm_itoa(bundle_data->promoted_max);
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
        GListPtr childIter = NULL;
        resource_t *new_rsc = NULL;
        pe__bundle_port_t *port = NULL;

        int offset = 0, max = 1024;
        char *buffer = NULL;

        if (common_unpack(xml_resource, &new_rsc, rsc, data_set) == FALSE) {
            pe_err("Failed unpacking resource %s", ID(rsc->xml));
            if (new_rsc != NULL && new_rsc->fns != NULL) {
                new_rsc->fns->free(new_rsc);
            }
            return FALSE;
        }

        bundle_data->child = new_rsc;

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
            port->source = crm_itoa(DEFAULT_REMOTE_PORT);
        }
        port->target = strdup(port->source);
        bundle_data->ports = g_list_append(bundle_data->ports, port);

        buffer = calloc(1, max+1);
        for (childIter = bundle_data->child->children; childIter != NULL;
             childIter = childIter->next) {

            pe__bundle_replica_t *replica = calloc(1, sizeof(pe__bundle_replica_t));

            replica->child = childIter->data;
            replica->child->exclusive_discover = TRUE;
            replica->offset = lpc++;

            // Ensure the child's notify gets set based on the underlying primitive's value
            if (is_set(replica->child->flags, pe_rsc_notify)) {
                set_bit(bundle_data->child->flags, pe_rsc_notify);
            }

            offset += allocate_ip(bundle_data, replica, buffer+offset,
                                  max-offset);
            bundle_data->replicas = g_list_append(bundle_data->replicas,
                                                  replica);
            bundle_data->attribute_target = g_hash_table_lookup(replica->child->meta,
                                                                XML_RSC_ATTR_TARGET);
        }
        bundle_data->container_host_options = buffer;
        if (bundle_data->attribute_target) {
            g_hash_table_replace(rsc->meta, strdup(XML_RSC_ATTR_TARGET),
                                 strdup(bundle_data->attribute_target));
            g_hash_table_replace(bundle_data->child->meta,
                                 strdup(XML_RSC_ATTR_TARGET),
                                 strdup(bundle_data->attribute_target));
        }

    } else {
        // Just a naked container, no pacemaker-remote
        int offset = 0, max = 1024;
        char *buffer = calloc(1, max+1);

        for (int lpc = 0; lpc < bundle_data->nreplicas; lpc++) {
            pe__bundle_replica_t *replica = calloc(1, sizeof(pe__bundle_replica_t));

            replica->offset = lpc;
            offset += allocate_ip(bundle_data, replica, buffer+offset,
                                  max-offset);
            bundle_data->replicas = g_list_append(bundle_data->replicas,
                                                  replica);
        }
        bundle_data->container_host_options = buffer;
    }

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        if (!create_container(rsc, bundle_data, replica, data_set)) {
            pe_err("Failed unpacking resource %s", rsc->id);
            rsc->fns->free(rsc);
            return FALSE;
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
    GListPtr iter = NULL;

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

static void
print_rsc_in_list(resource_t *rsc, const char *pre_text, long options,
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
    child_text = crm_concat(pre_text, "       ", ' ');

    get_bundle_variant_data(bundle_data, rsc);

    status_print("%s<bundle ", pre_text);
    status_print("id=\"%s\" ", rsc->id);
    status_print("type=\"%s\" ", container_agent_str(bundle_data->agent_type));
    status_print("image=\"%s\" ", bundle_data->image);
    status_print("unique=\"%s\" ", is_set(rsc->flags, pe_rsc_unique)? "true" : "false");
    status_print("managed=\"%s\" ", is_set(rsc->flags, pe_rsc_managed) ? "true" : "false");
    status_print("failed=\"%s\" ", is_set(rsc->flags, pe_rsc_failed) ? "true" : "false");
    status_print(">\n");

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);
        status_print("%s    <replica id=\"%d\">\n", pre_text, replica->offset);
        print_rsc_in_list(replica->ip, child_text, options, print_data);
        print_rsc_in_list(replica->child, child_text, options, print_data);
        print_rsc_in_list(replica->container, child_text, options, print_data);
        print_rsc_in_list(replica->remote, child_text, options, print_data);
        status_print("%s    </replica>\n", pre_text);
    }
    status_print("%s</bundle>\n", pre_text);
    free(child_text);
}

int
pe__bundle_xml(pcmk__output_t *out, va_list args)
{
    long options = va_arg(args, int);
    resource_t *rsc = va_arg(args, resource_t *);
    pe__bundle_variant_data_t *bundle_data = NULL;
    int rc = 0;

    CRM_ASSERT(rsc != NULL);

    get_bundle_variant_data(bundle_data, rsc);

    rc = pe__name_and_nvpairs_xml(out, true, "bundle", 6
                 , "id", rsc->id
                 , "type", container_agent_str(bundle_data->agent_type)
                 , "image", bundle_data->image
                 , "unique", BOOL2STR(is_set(rsc->flags, pe_rsc_unique))
                 , "managed", BOOL2STR(is_set(rsc->flags, pe_rsc_managed))
                 , "failed", BOOL2STR(is_set(rsc->flags, pe_rsc_failed)));
    CRM_ASSERT(rc == 0);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;
        char *id = crm_itoa(replica->offset);

        CRM_ASSERT(replica);

        rc = pe__name_and_nvpairs_xml(out, true, "replica", 1, "id", id);
        free(id);
        CRM_ASSERT(rc == 0);

        if (replica->ip != NULL) {
            out->message(out, crm_element_name(replica->ip->xml), options, replica->ip);
        }

        if (replica->child != NULL) {
            out->message(out, crm_element_name(replica->child->xml), options, replica->child);
        }

        out->message(out, crm_element_name(replica->container->xml), options, replica->container);

        if (replica->remote != NULL) {
            out->message(out, crm_element_name(replica->remote->xml), options, replica->remote);
        }

        pcmk__output_xml_pop_parent(out); // replica
    }
    pcmk__output_xml_pop_parent(out); // bundle
    return rc;
}

static void
pe__bundle_replica_output_html(pcmk__output_t *out, pe__bundle_replica_t *replica,
                               long options)
{
    node_t *node = NULL;
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
    pe__common_output_html(out, rsc, buffer, node, options);
}

int
pe__bundle_html(pcmk__output_t *out, va_list args)
{
    long options = va_arg(args, int);
    resource_t *rsc = va_arg(args, resource_t *);
    pe__bundle_variant_data_t *bundle_data = NULL;
    char buffer[LINE_MAX];

    CRM_ASSERT(rsc != NULL);

    get_bundle_variant_data(bundle_data, rsc);

    snprintf(buffer, LINE_MAX, "Container bundle%s: %s [%s]%s%s",
                 ((bundle_data->nreplicas > 1)? " set" : ""),
                 rsc->id, bundle_data->image,
                 is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                 is_set(rsc->flags, pe_rsc_managed) ? "" : " (unmanaged)");

    pcmk__output_create_xml_node(out, "br");
    out->begin_list(out, buffer, NULL, NULL);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);

        pcmk__output_xml_create_parent(out, "li");
        if (is_set(options, pe_print_implicit)) {
            if(g_list_length(bundle_data->replicas) > 1) {
                snprintf(buffer, LINE_MAX, " Replica[%d]", replica->offset);
                xmlNodeSetContent(pcmk__output_xml_peek_parent(out), (pcmkXmlStr) buffer);
            }
            pcmk__output_create_xml_node(out, "br");
            out->begin_list(out, NULL, NULL, NULL);

            if (replica->ip != NULL) {
                out->message(out, crm_element_name(replica->ip->xml), options, replica->ip);
            }

            if (replica->child != NULL) {
                out->message(out, crm_element_name(replica->child->xml), options, replica->child);
            }

            out->message(out, crm_element_name(replica->container->xml), options, replica->container);

            if (replica->remote != NULL) {
                out->message(out, crm_element_name(replica->remote->xml), options, replica->remote);
            }

            out->end_list(out);
        } else {
            pe__bundle_replica_output_html(out, replica, options);
        }

        pcmk__output_xml_pop_parent(out);
    }

    out->end_list(out);
    return 0;
}

static void
pe__bundle_replica_output_text(pcmk__output_t *out, pe__bundle_replica_t *replica,
                               const char *pre_text, long options)
{
    node_t *node = NULL;
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
    pe__common_output_text(out, rsc, pre_text, buffer, node, options);
}

int
pe__bundle_text(pcmk__output_t *out, va_list args)
{
    long options = va_arg(args, int);
    resource_t *rsc = va_arg(args, resource_t *);
    const char *pre_text = va_arg(args, char *);

    pe__bundle_variant_data_t *bundle_data = NULL;
    char *child_text = NULL;

    CRM_ASSERT(rsc != NULL);

    get_bundle_variant_data(bundle_data, rsc);

    if (pre_text == NULL) {
        pre_text = " ";
    }

    fprintf(out->dest, "%sContainer bundle%s: %s [%s]%s%s\n",
            pre_text, ((bundle_data->nreplicas > 1)? " set" : ""),
            rsc->id, bundle_data->image,
            is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
            is_set(rsc->flags, pe_rsc_managed) ? "" : " (unmanaged)");

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);

        if (is_set(options, pe_print_implicit)) {
            child_text = crm_strdup_printf("     %s", pre_text);
            if(g_list_length(bundle_data->replicas) > 1) {
                fprintf(out->dest, "  %sReplica[%d]\n", pre_text, replica->offset);
            }

            if (replica->ip != NULL) {
                out->message(out, crm_element_name(replica->ip->xml), options, replica->ip, child_text);
            }

            if (replica->child != NULL) {
                out->message(out, crm_element_name(replica->child->xml), options, replica->child, child_text);
            }

            out->message(out, crm_element_name(replica->container->xml), options, replica->container, child_text);

            if (replica->remote != NULL) {
                out->message(out, crm_element_name(replica->remote->xml), options, replica->remote, child_text);
            }
        } else {
            child_text = crm_strdup_printf("%s  ", pre_text);
            pe__bundle_replica_output_text(out, replica, child_text, options);
        }
        free(child_text);
    }
    return 0;
}

static void
print_bundle_replica(pe__bundle_replica_t *replica, const char *pre_text,
                     long options, void *print_data)
{
    node_t *node = NULL;
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
                 is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                 is_set(rsc->flags, pe_rsc_managed) ? "" : " (unmanaged)");
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

        if (is_set(options, pe_print_implicit)) {
            child_text = crm_strdup_printf("     %s", pre_text);
            if(g_list_length(bundle_data->replicas) > 1) {
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
    free(bundle_data->container_host_options);

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
pe_bundle_replicas(const resource_t *rsc)
{
    if ((rsc == NULL) || (rsc->variant != pe_container)) {
        return 0;
    } else {
        pe__bundle_variant_data_t *bundle_data = NULL;

        get_bundle_variant_data(bundle_data, rsc);
        return bundle_data->nreplicas;
    }
}
