/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

#include <ctype.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <unpack.h>
#include <crm/msg_xml.h>

#define VARIANT_CONTAINER 1
#include "./variant.h"

void tuple_free(container_grouping_t *tuple);

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
allocate_ip(container_variant_data_t *data, container_grouping_t *tuple, char *buffer, int max) 
{
    if(data->ip_range_start == NULL) {
        return 0;

    } else if(data->ip_last) {
        tuple->ipaddr = next_ip(data->ip_last);

    } else {
        tuple->ipaddr = strdup(data->ip_range_start);
    }

    data->ip_last = tuple->ipaddr;
#if 0
    return snprintf(buffer, max, " --add-host=%s-%d:%s --link %s-docker-%d:%s-link-%d",
                    data->prefix, tuple->offset, tuple->ipaddr,
                    data->prefix, tuple->offset, data->prefix, tuple->offset);
#else
    if (data->type == PE_CONTAINER_TYPE_DOCKER) {
        return snprintf(buffer, max, " --add-host=%s-%d:%s",
                        data->prefix, tuple->offset, tuple->ipaddr);
    } else if (data->type == PE_CONTAINER_TYPE_RKT) {
        return snprintf(buffer, max, " --hosts-entry=%s=%s-%d",
                        tuple->ipaddr, data->prefix, tuple->offset);
    } else {
        return 0;
    }
#endif
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
valid_network(container_variant_data_t *data)
{
    if(data->ip_range_start) {
        return TRUE;
    }
    if(data->control_port) {
        if(data->replicas_per_host > 1) {
            pe_err("Specifying the 'control-port' for %s requires 'replicas-per-host=1'", data->prefix);
            data->replicas_per_host = 1;
            /* @TODO to be sure: clear_bit(rsc->flags, pe_rsc_unique); */
        }
        return TRUE;
    }
    return FALSE;
}

static bool
create_ip_resource(
    resource_t *parent, container_variant_data_t *data, container_grouping_t *tuple,
    pe_working_set_t * data_set) 
{
    if(data->ip_range_start) {
        char *id = NULL;
        xmlNode *xml_ip = NULL;
        xmlNode *xml_obj = NULL;

        id = crm_strdup_printf("%s-ip-%s", data->prefix, tuple->ipaddr);
        crm_xml_sanitize_id(id);
        xml_ip = create_resource(id, "heartbeat", "IPaddr2");
        free(id);

        xml_obj = create_xml_node(xml_ip, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_obj, "%s-attributes-%d", data->prefix, tuple->offset);

        crm_create_nvpair_xml(xml_obj, NULL, "ip", tuple->ipaddr);
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

        crm_log_xml_trace(xml_ip, "Container-ip");
        if (common_unpack(xml_ip, &tuple->ip, parent, data_set) == false) {
            return FALSE;
        }

        parent->children = g_list_append(parent->children, tuple->ip);
    }
    return TRUE;
}

static bool
create_docker_resource(
    resource_t *parent, container_variant_data_t *data, container_grouping_t *tuple,
    pe_working_set_t * data_set) 
{
        int offset = 0, max = 4096;
        char *buffer = calloc(1, max+1);

        int doffset = 0, dmax = 1024;
        char *dbuffer = calloc(1, dmax+1);

        char *id = NULL;
        xmlNode *xml_docker = NULL;
        xmlNode *xml_obj = NULL;

        id = crm_strdup_printf("%s-docker-%d", data->prefix, tuple->offset);
        crm_xml_sanitize_id(id);
        xml_docker = create_resource(id, "heartbeat", "docker");
        free(id);

        xml_obj = create_xml_node(xml_docker, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_obj, "%s-attributes-%d", data->prefix, tuple->offset);

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
                               data->prefix, tuple->offset);
        }

        offset += snprintf(buffer+offset, max-offset, " -e PCMK_stderr=1");

        if(data->docker_network) {
//        offset += snprintf(buffer+offset, max-offset, " --link-local-ip=%s", tuple->ipaddr);
            offset += snprintf(buffer+offset, max-offset, " --net=%s", data->docker_network);
        }

        if(data->control_port) {
            offset += snprintf(buffer+offset, max-offset, " -e PCMK_remote_port=%s", data->control_port);
        } else {
            offset += snprintf(buffer+offset, max-offset, " -e PCMK_remote_port=%d", DEFAULT_REMOTE_PORT);
        }

        for(GListPtr pIter = data->mounts; pIter != NULL; pIter = pIter->next) {
            container_mount_t *mount = pIter->data;

            if(mount->flags) {
                char *source = crm_strdup_printf(
                    "%s/%s-%d", mount->source, data->prefix, tuple->offset);

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
            container_port_t *port = pIter->data;

            if(tuple->ipaddr) {
                offset += snprintf(buffer+offset, max-offset, " -p %s:%s:%s",
                                   tuple->ipaddr, port->source, port->target);
            } else if(safe_str_neq(data->docker_network, "host")) {
                // No need to do port mapping if net=host
                offset += snprintf(buffer+offset, max-offset, " -p %s:%s", port->source, port->target);
            }
        }

        if(data->docker_run_options) {
            offset += snprintf(buffer+offset, max-offset, " %s", data->docker_run_options);
        }

        if(data->docker_host_options) {
            offset += snprintf(buffer+offset, max-offset, " %s", data->docker_host_options);
        }

        crm_create_nvpair_xml(xml_obj, NULL, "run_opts", buffer);
        free(buffer);

        crm_create_nvpair_xml(xml_obj, NULL, "mount_points", dbuffer);
        free(dbuffer);

        if(tuple->child) {
            if(data->docker_run_command) {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", data->docker_run_command);
            } else {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", SBIN_DIR "/pacemaker_remoted");
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
         *                           "run_cmd", "/usr/libexec/pacemaker/lrmd");
         *     crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd",
         *         "/usr/libexec/pacemaker/lrmd_internal_ctl -c poke");
         */
        } else {
            if(data->docker_run_command) {
                crm_create_nvpair_xml(xml_obj, NULL,
                                      "run_cmd", data->docker_run_command);
            }

            /* TODO: Allow users to specify their own?
             *
             * We don't know what's in the container, so we just want
             * to know if it is alive
             */
            crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
        }


        xml_obj = create_xml_node(xml_docker, "operations");
        crm_create_op_xml(xml_obj, ID(xml_docker), "monitor", "60s", NULL);

        // TODO: Other ops? Timeouts and intervals from underlying resource?
        crm_log_xml_trace(xml_docker, "Container-docker");
        if (common_unpack(xml_docker, &tuple->docker, parent, data_set) == FALSE) {
            return FALSE;
        }
        parent->children = g_list_append(parent->children, tuple->docker);
        return TRUE;
}

static bool
create_rkt_resource(
    resource_t *parent, container_variant_data_t *data, container_grouping_t *tuple,
    pe_working_set_t * data_set)
{
        int offset = 0, max = 4096;
        char *buffer = calloc(1, max+1);

        int doffset = 0, dmax = 1024;
        char *dbuffer = calloc(1, dmax+1);

        char *id = NULL;
        xmlNode *xml_docker = NULL;
        xmlNode *xml_obj = NULL;

        int volid = 0;

        id = crm_strdup_printf("%s-rkt-%d", data->prefix, tuple->offset);
        crm_xml_sanitize_id(id);
        xml_docker = create_resource(id, "heartbeat", "rkt");
        free(id);

        xml_obj = create_xml_node(xml_docker, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_obj, "%s-attributes-%d", data->prefix, tuple->offset);

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
                               data->prefix, tuple->offset);
        }

        offset += snprintf(buffer+offset, max-offset, " --environment=PCMK_stderr=1");

        if(data->docker_network) {
//        offset += snprintf(buffer+offset, max-offset, " --link-local-ip=%s", tuple->ipaddr);
            offset += snprintf(buffer+offset, max-offset, " --net=%s", data->docker_network);
        }

        if(data->control_port) {
            offset += snprintf(buffer+offset, max-offset, " --environment=PCMK_remote_port=%s", data->control_port);
        } else {
            offset += snprintf(buffer+offset, max-offset, " --environment=PCMK_remote_port=%d", DEFAULT_REMOTE_PORT);
        }

        for(GListPtr pIter = data->mounts; pIter != NULL; pIter = pIter->next) {
            container_mount_t *mount = pIter->data;

            if(mount->flags) {
                char *source = crm_strdup_printf(
                    "%s/%s-%d", mount->source, data->prefix, tuple->offset);

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
            container_port_t *port = pIter->data;

            if(tuple->ipaddr) {
                offset += snprintf(buffer+offset, max-offset, " --port=%s:%s:%s",
                                   port->target, tuple->ipaddr, port->source);
            } else {
                offset += snprintf(buffer+offset, max-offset, " --port=%s:%s", port->target, port->source);
            }
        }

        if(data->docker_run_options) {
            offset += snprintf(buffer+offset, max-offset, " %s", data->docker_run_options);
        }

        if(data->docker_host_options) {
            offset += snprintf(buffer+offset, max-offset, " %s", data->docker_host_options);
        }

        crm_create_nvpair_xml(xml_obj, NULL, "run_opts", buffer);
        free(buffer);

        crm_create_nvpair_xml(xml_obj, NULL, "mount_points", dbuffer);
        free(dbuffer);

        if(tuple->child) {
            if(data->docker_run_command) {
                crm_create_nvpair_xml(xml_obj, NULL, "run_cmd", data->docker_run_command);
            } else {
                crm_create_nvpair_xml(xml_obj, NULL, "run_cmd", SBIN_DIR"/pacemaker_remoted");
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
         *                           "run_cmd", "/usr/libexec/pacemaker/lrmd");
         *     crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd",
         *         "/usr/libexec/pacemaker/lrmd_internal_ctl -c poke");
         */
        } else {
            if(data->docker_run_command) {
                crm_create_nvpair_xml(xml_obj, NULL, "run_cmd",
                                      data->docker_run_command);
            }

            /* TODO: Allow users to specify their own?
             *
             * We don't know what's in the container, so we just want
             * to know if it is alive
             */
            crm_create_nvpair_xml(xml_obj, NULL, "monitor_cmd", "/bin/true");
        }


        xml_obj = create_xml_node(xml_docker, "operations");
        crm_create_op_xml(xml_obj, ID(xml_docker), "monitor", "60s", NULL);

        // TODO: Other ops? Timeouts and intervals from underlying resource?

        crm_log_xml_trace(xml_docker, "Container-rkt");
        if (common_unpack(xml_docker, &tuple->docker, parent, data_set) == FALSE) {
            return FALSE;
        }
        parent->children = g_list_append(parent->children, tuple->docker);
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
create_remote_resource(
    resource_t *parent, container_variant_data_t *data, container_grouping_t *tuple,
    pe_working_set_t * data_set) 
{
    if (tuple->child && valid_network(data)) {
        GHashTableIter gIter;
        GListPtr rsc_iter = NULL;
        node_t *node = NULL;
        xmlNode *xml_remote = NULL;
        char *id = crm_strdup_printf("%s-%d", data->prefix, tuple->offset);
        char *port_s = NULL;
        const char *uname = NULL;
        const char *connect_name = NULL;

        if (remote_id_conflict(id, data_set)) {
            free(id);
            // The biggest hammer we have
            id = crm_strdup_printf("pcmk-internal-%s-remote-%d", tuple->child->id, tuple->offset);
            CRM_ASSERT(remote_id_conflict(id, data_set) == FALSE);
        }

        /* REMOTE_CONTAINER_HACK: Using "#uname" as the server name when the
         * connection does not have its own IP is a magic string that we use to
         * support nested remotes (i.e. a bundle running on a remote node).
         */
        connect_name = (tuple->ipaddr? tuple->ipaddr : "#uname");

        if (data->control_port == NULL) {
            port_s = crm_itoa(DEFAULT_REMOTE_PORT);
        }

        /* This sets tuple->docker as tuple->remote's container, which is
         * similar to what happens with guest nodes. This is how the PE knows
         * that the bundle node is fenced by recovering docker, and that
         * remote should be ordered relative to docker.
         */
        xml_remote = pe_create_remote_xml(NULL, id, tuple->docker->id,
                                          NULL, NULL, "60s", NULL,
                                          NULL, connect_name,
                                          (data->control_port?
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

        tuple->node = node_copy(node);
        tuple->node->weight = 500;
        tuple->node->rsc_discover_mode = pe_discover_exclusive;

        /* Ensure the node shows up as allowed and with the correct discovery set */
        if (tuple->child->allowed_nodes != NULL) {
            g_hash_table_destroy(tuple->child->allowed_nodes);
        }
        tuple->child->allowed_nodes = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, g_hash_destroy_str);
        g_hash_table_insert(tuple->child->allowed_nodes, (gpointer) tuple->node->details->id, node_copy(tuple->node));

        {
            node_t *copy = node_copy(tuple->node);
            copy->weight = -INFINITY;
            g_hash_table_insert(tuple->child->parent->allowed_nodes, (gpointer) tuple->node->details->id, copy);
        }
        crm_log_xml_trace(xml_remote, "Container-remote");
        if (common_unpack(xml_remote, &tuple->remote, parent, data_set) == FALSE) {
            return FALSE;
        }

        g_hash_table_iter_init(&gIter, tuple->remote->allowed_nodes);
        while (g_hash_table_iter_next(&gIter, NULL, (void **)&node)) {
            if(is_remote_node(node)) {
                /* Remote resources can only run on 'normal' cluster node */
                node->weight = -INFINITY;
            }
        }

        tuple->node->details->remote_rsc = tuple->remote;
        tuple->remote->container = tuple->docker; // Ensures is_container_remote_node() functions correctly immediately

        /* A bundle's #kind is closer to "container" (guest node) than the
         * "remote" set by pe_create_node().
         */
        g_hash_table_insert(tuple->node->details->attrs,
                            strdup(CRM_ATTR_KIND), strdup("container"));

        /* One effect of this is that setup_container() will add
         * tuple->remote to tuple->docker's fillers, which will make
         * rsc_contains_remote_node() true for tuple->docker.
         *
         * tuple->child does NOT get added to tuple->docker's fillers.
         * The only noticeable effect if it did would be for its fail count to
         * be taken into account when checking tuple->docker's migration
         * threshold.
         */
        parent->children = g_list_append(parent->children, tuple->remote);
    }
    return TRUE;
}

static bool
create_container(
    resource_t *parent, container_variant_data_t *data, container_grouping_t *tuple,
    pe_working_set_t * data_set)
{

    if (data->type == PE_CONTAINER_TYPE_DOCKER &&
          create_docker_resource(parent, data, tuple, data_set) == FALSE) {
        return FALSE;
    }
    if (data->type == PE_CONTAINER_TYPE_RKT &&
          create_rkt_resource(parent, data, tuple, data_set) == FALSE) {
        return FALSE;
    }

    if(create_ip_resource(parent, data, tuple, data_set) == FALSE) {
        return FALSE;
    }
    if(create_remote_resource(parent, data, tuple, data_set) == FALSE) {
        return FALSE;
    }
    if(tuple->child && tuple->ipaddr) {
        add_hash_param(tuple->child->meta, "external-ip", tuple->ipaddr);
    }

    if(tuple->remote) {
        /*
         * Allow the remote connection resource to be allocated to a
         * different node than the one on which the docker container
         * is active.
         *
         * Makes it possible to have remote nodes, running docker
         * containers with pacemaker_remoted inside in order to start
         * services inside those containers.
         */
        set_bit(tuple->remote->flags, pe_rsc_allow_remote_remotes);
    }

    return TRUE;
}

static void
mount_add(container_variant_data_t *container_data, const char *source,
          const char *target, const char *options, int flags)
{
    container_mount_t *mount = calloc(1, sizeof(container_mount_t));

    mount->source = strdup(source);
    mount->target = strdup(target);
    if (options) {
        mount->options = strdup(options);
    }
    mount->flags = flags;
    container_data->mounts = g_list_append(container_data->mounts, mount);
}

static void mount_free(container_mount_t *mount)
{
    free(mount->source);
    free(mount->target);
    free(mount->options);
    free(mount);
}

static void port_free(container_port_t *port)
{
    free(port->source);
    free(port->target);
    free(port);
}

static container_grouping_t *
tuple_for_remote(resource_t *remote) 
{
    resource_t *top = remote;
    container_variant_data_t *container_data = NULL;

    if (top == NULL) {
        return NULL;
    }

    while (top->parent != NULL) {
        top = top->parent;
    }

    get_container_variant_data(container_data, top);
    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;
        if(tuple->remote == remote) {
            return tuple;
        }
    }
    CRM_LOG_ASSERT(FALSE);
    return NULL;
}

bool
container_fix_remote_addr(resource_t *rsc) 
{
    const char *name;
    const char *value;
    const char *attr_list[] = {
        XML_ATTR_TYPE,
        XML_AGENT_ATTR_CLASS,
        XML_AGENT_ATTR_PROVIDER
    };
    const char *value_list[] = {
        "remote",
        PCMK_RESOURCE_CLASS_OCF,
        "pacemaker"
    };

    if(rsc == NULL) {
        return FALSE;
    }

    name = "addr";
    value = g_hash_table_lookup(rsc->parameters, name);
    if (safe_str_eq(value, "#uname") == FALSE) {
        return FALSE;
    }

    for (int lpc = 0; lpc < DIMOF(attr_list); lpc++) {
        name = attr_list[lpc];
        value = crm_element_value(rsc->xml, attr_list[lpc]);
        if (safe_str_eq(value, value_list[lpc]) == FALSE) {
            return FALSE;
        }
    }
    return TRUE;
}

const char *
container_fix_remote_addr_in(resource_t *rsc, xmlNode *xml, const char *field) 
{
    // REMOTE_CONTAINER_HACK: Allow remote nodes that start containers with pacemaker remote inside

    pe_node_t *node = NULL;
    container_grouping_t *tuple = NULL;

    if(container_fix_remote_addr(rsc) == FALSE) {
        return NULL;
    }

    tuple = tuple_for_remote(rsc);
    if(tuple == NULL) {
        return NULL;
    }

    node = tuple->docker->allocated_to;
    if (node == NULL) {
        /* If it won't be running anywhere after the
         * transition, go with where it's running now.
         */
        node = pe__current_node(tuple->docker);
    }

    if(node == NULL) {
        crm_trace("Cannot fix address for %s", tuple->remote->id);
        return NULL;
    }

    crm_trace("Fixing addr for %s on %s", rsc->id, node->details->uname);
    if(xml != NULL && field != NULL) {
        crm_xml_add(xml, field, node->details->uname);
    }

    return node->details->uname;
}

gboolean
container_unpack(resource_t * rsc, pe_working_set_t * data_set)
{
    const char *value = NULL;
    xmlNode *xml_obj = NULL;
    xmlNode *xml_resource = NULL;
    container_variant_data_t *container_data = NULL;

    CRM_ASSERT(rsc != NULL);
    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    container_data = calloc(1, sizeof(container_variant_data_t));
    rsc->variant_opaque = container_data;
    container_data->prefix = strdup(rsc->id);

    xml_obj = first_named_child(rsc->xml, "docker");
    if (xml_obj != NULL) {
        container_data->type = PE_CONTAINER_TYPE_DOCKER;
    } else {
        xml_obj = first_named_child(rsc->xml, "rkt");
        if (xml_obj != NULL) {
            container_data->type = PE_CONTAINER_TYPE_RKT;
        } else {
            return FALSE;
        }
    }

    value = crm_element_value(xml_obj, "masters");
    container_data->masters = crm_parse_int(value, "0");
    if (container_data->masters < 0) {
        pe_err("'masters' for %s must be nonnegative integer, using 0",
               rsc->id);
        container_data->masters = 0;
    }

    value = crm_element_value(xml_obj, "replicas");
    if ((value == NULL) && (container_data->masters > 0)) {
        container_data->replicas = container_data->masters;
    } else {
        container_data->replicas = crm_parse_int(value, "1");
    }
    if (container_data->replicas < 1) {
        pe_err("'replicas' for %s must be positive integer, using 1", rsc->id);
        container_data->replicas = 1;
    }

    /*
     * Communication between containers on the same host via the
     * floating IPs only works if docker is started with:
     *   --userland-proxy=false --ip-masq=false
     */
    value = crm_element_value(xml_obj, "replicas-per-host");
    container_data->replicas_per_host = crm_parse_int(value, "1");
    if (container_data->replicas_per_host < 1) {
        pe_err("'replicas-per-host' for %s must be positive integer, using 1",
               rsc->id);
        container_data->replicas_per_host = 1;
    }
    if (container_data->replicas_per_host == 1) {
        clear_bit(rsc->flags, pe_rsc_unique);
    }

    container_data->docker_run_command = crm_element_value_copy(xml_obj, "run-command");
    container_data->docker_run_options = crm_element_value_copy(xml_obj, "options");
    container_data->image = crm_element_value_copy(xml_obj, "image");
    container_data->docker_network = crm_element_value_copy(xml_obj, "network");

    xml_obj = first_named_child(rsc->xml, "network");
    if(xml_obj) {

        container_data->ip_range_start = crm_element_value_copy(xml_obj, "ip-range-start");
        container_data->host_netmask = crm_element_value_copy(xml_obj, "host-netmask");
        container_data->host_network = crm_element_value_copy(xml_obj, "host-interface");
        container_data->control_port = crm_element_value_copy(xml_obj, "control-port");

        for (xmlNode *xml_child = __xml_first_child_element(xml_obj); xml_child != NULL;
             xml_child = __xml_next_element(xml_child)) {

            container_port_t *port = calloc(1, sizeof(container_port_t));
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
                container_data->ports = g_list_append(container_data->ports, port);

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
        int flags = 0;

        if (source == NULL) {
            source = crm_element_value(xml_child, "source-dir-root");
            flags = 1;
        }

        if (source && target) {
            mount_add(container_data, source, target, options, flags);
        } else {
            pe_err("Invalid mount directive %s", ID(xml_child));
        }
    }

    xml_obj = first_named_child(rsc->xml, "primitive");
    if (xml_obj && valid_network(container_data)) {
        char *value = NULL;
        xmlNode *xml_set = NULL;

        if(container_data->masters > 0) {
            xml_resource = create_xml_node(NULL, XML_CIB_TAG_MASTER);

        } else {
            xml_resource = create_xml_node(NULL, XML_CIB_TAG_INCARNATION);
        }

        crm_xml_set_id(xml_resource, "%s-%s", container_data->prefix, xml_resource->name);

        xml_set = create_xml_node(xml_resource, XML_TAG_META_SETS);
        crm_xml_set_id(xml_set, "%s-%s-meta", container_data->prefix, xml_resource->name);

        crm_create_nvpair_xml(xml_set, NULL,
                              XML_RSC_ATTR_ORDERED, XML_BOOLEAN_TRUE);

        value = crm_itoa(container_data->replicas);
        crm_create_nvpair_xml(xml_set, NULL,
                              XML_RSC_ATTR_INCARNATION_MAX, value);
        free(value);

        value = crm_itoa(container_data->replicas_per_host);
        crm_create_nvpair_xml(xml_set, NULL,
                              XML_RSC_ATTR_INCARNATION_NODEMAX, value);
        free(value);

        crm_create_nvpair_xml(xml_set, NULL, XML_RSC_ATTR_UNIQUE,
                (container_data->replicas_per_host > 1)?
                XML_BOOLEAN_TRUE : XML_BOOLEAN_FALSE);

        if(container_data->masters) {
            value = crm_itoa(container_data->masters);
            crm_create_nvpair_xml(xml_set, NULL,
                                  XML_RSC_ATTR_MASTER_MAX, value);
            free(value);
        }

        //crm_xml_add(xml_obj, XML_ATTR_ID, container_data->prefix);
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
        container_port_t *port = NULL;

        int offset = 0, max = 1024;
        char *buffer = NULL;

        if (common_unpack(xml_resource, &new_rsc, rsc, data_set) == FALSE) {
            pe_err("Failed unpacking resource %s", ID(rsc->xml));
            if (new_rsc != NULL && new_rsc->fns != NULL) {
                new_rsc->fns->free(new_rsc);
            }
            return FALSE;
        }

        container_data->child = new_rsc;

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
        mount_add(container_data, DEFAULT_REMOTE_KEY_LOCATION,
                  DEFAULT_REMOTE_KEY_LOCATION, NULL, 0);

        mount_add(container_data, CRM_LOG_DIR "/bundles", "/var/log", NULL, 1);

        port = calloc(1, sizeof(container_port_t));
        if(container_data->control_port) {
            port->source = strdup(container_data->control_port);
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
        container_data->ports = g_list_append(container_data->ports, port);

        buffer = calloc(1, max+1);
        for(childIter = container_data->child->children; childIter != NULL; childIter = childIter->next) {
            container_grouping_t *tuple = calloc(1, sizeof(container_grouping_t));
            tuple->child = childIter->data;
            tuple->child->exclusive_discover = TRUE;
            tuple->offset = lpc++;

            // Ensure the child's notify gets set based on the underlying primitive's value
            if(is_set(tuple->child->flags, pe_rsc_notify)) {
                set_bit(container_data->child->flags, pe_rsc_notify);
            }

            offset += allocate_ip(container_data, tuple, buffer+offset, max-offset);
            container_data->tuples = g_list_append(container_data->tuples, tuple);
            container_data->attribute_target = g_hash_table_lookup(tuple->child->meta, XML_RSC_ATTR_TARGET);
        }
        container_data->docker_host_options = buffer;
        if(container_data->attribute_target) {
            g_hash_table_replace(rsc->meta, strdup(XML_RSC_ATTR_TARGET), strdup(container_data->attribute_target));
            g_hash_table_replace(container_data->child->meta, strdup(XML_RSC_ATTR_TARGET), strdup(container_data->attribute_target));
        }

    } else {
        // Just a naked container, no pacemaker-remote
        int offset = 0, max = 1024;
        char *buffer = calloc(1, max+1);

        for(int lpc = 0; lpc < container_data->replicas; lpc++) {
            container_grouping_t *tuple = calloc(1, sizeof(container_grouping_t));
            tuple->offset = lpc;
            offset += allocate_ip(container_data, tuple, buffer+offset, max-offset);
            container_data->tuples = g_list_append(container_data->tuples, tuple);
        }

        container_data->docker_host_options = buffer;
    }

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;
        if (create_container(rsc, container_data, tuple, data_set) == FALSE) {
            pe_err("Failed unpacking resource %s", rsc->id);
            rsc->fns->free(rsc);
            return FALSE;
        }
    }

    if(container_data->child) {
        rsc->children = g_list_append(rsc->children, container_data->child);
    }
    return TRUE;
}

static int
tuple_rsc_active(resource_t *rsc, gboolean all)
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
container_active(resource_t * rsc, gboolean all)
{
    container_variant_data_t *container_data = NULL;
    GListPtr iter = NULL;

    get_container_variant_data(container_data, rsc);
    for (iter = container_data->tuples; iter != NULL; iter = iter->next) {
        container_grouping_t *tuple = (container_grouping_t *)(iter->data);
        int rsc_active;

        rsc_active = tuple_rsc_active(tuple->ip, all);
        if (rsc_active >= 0) {
            return (gboolean) rsc_active;
        }

        rsc_active = tuple_rsc_active(tuple->child, all);
        if (rsc_active >= 0) {
            return (gboolean) rsc_active;
        }

        rsc_active = tuple_rsc_active(tuple->docker, all);
        if (rsc_active >= 0) {
            return (gboolean) rsc_active;
        }

        rsc_active = tuple_rsc_active(tuple->remote, all);
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
 * \brief Find the container child corresponding to a given node
 *
 * \param[in] bundle  Top-level bundle resource
 * \param[in] node    Node to search for
 *
 * \return Container child if found, NULL otherwise
 */
resource_t *
find_container_child(const resource_t *bundle, const node_t *node)
{
    container_variant_data_t *container_data = NULL;
    CRM_ASSERT(bundle && node);

    get_container_variant_data(container_data, bundle);
    for (GListPtr gIter = container_data->tuples; gIter != NULL;
         gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple && tuple->node);
        if (tuple->node->details == node->details) {
            return tuple->child;
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
container_type_as_string(enum container_type t)
{
    if (t == PE_CONTAINER_TYPE_DOCKER) {
        return PE_CONTAINER_TYPE_DOCKER_S;
    } else if (t == PE_CONTAINER_TYPE_RKT) {
        return PE_CONTAINER_TYPE_RKT_S;
    } else {
        return PE_CONTAINER_TYPE_UNKNOWN_S;
    }
}

static void
container_print_xml(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    container_variant_data_t *container_data = NULL;
    char *child_text = NULL;
    CRM_CHECK(rsc != NULL, return);

    if (pre_text == NULL) {
        pre_text = "";
    }
    child_text = crm_concat(pre_text, "       ", ' ');

    get_container_variant_data(container_data, rsc);

    status_print("%s<bundle ", pre_text);
    status_print("id=\"%s\" ", rsc->id);

    // Always lowercase the container technology type for use as XML value
    status_print("type=\"");
    for (const char *c = container_type_as_string(container_data->type);
         *c; ++c) {
        status_print("%c", tolower(*c));
    }
    status_print("\" ");

    status_print("image=\"%s\" ", container_data->image);
    status_print("unique=\"%s\" ", is_set(rsc->flags, pe_rsc_unique)? "true" : "false");
    status_print("managed=\"%s\" ", is_set(rsc->flags, pe_rsc_managed) ? "true" : "false");
    status_print("failed=\"%s\" ", is_set(rsc->flags, pe_rsc_failed) ? "true" : "false");
    status_print(">\n");

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        status_print("%s    <replica id=\"%d\">\n", pre_text, tuple->offset);
        print_rsc_in_list(tuple->ip, child_text, options, print_data);
        print_rsc_in_list(tuple->child, child_text, options, print_data);
        print_rsc_in_list(tuple->docker, child_text, options, print_data);
        print_rsc_in_list(tuple->remote, child_text, options, print_data);
        status_print("%s    </replica>\n", pre_text);
    }
    status_print("%s</bundle>\n", pre_text);
    free(child_text);
}

static void
tuple_print(container_grouping_t * tuple, const char *pre_text, long options, void *print_data)
{
    node_t *node = NULL;
    resource_t *rsc = tuple->child;

    int offset = 0;
    char buffer[LINE_MAX];

    if(rsc == NULL) {
        rsc = tuple->docker;
    }

    if(tuple->remote) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s", rsc_printable_id(tuple->remote));
    } else {
        offset += snprintf(buffer + offset, LINE_MAX - offset, "%s", rsc_printable_id(tuple->docker));
    }
    if(tuple->ipaddr) {
        offset += snprintf(buffer + offset, LINE_MAX - offset, " (%s)", tuple->ipaddr);
    }

    node = pe__current_node(tuple->docker);
    common_print(rsc, pre_text, buffer, node, options, print_data);
}

void
container_print(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    container_variant_data_t *container_data = NULL;
    char *child_text = NULL;
    CRM_CHECK(rsc != NULL, return);

    if (options & pe_print_xml) {
        container_print_xml(rsc, pre_text, options, print_data);
        return;
    }

    get_container_variant_data(container_data, rsc);

    if (pre_text == NULL) {
        pre_text = " ";
    }

    status_print("%s%s container%s: %s [%s]%s%s\n",
                 pre_text, container_type_as_string(container_data->type),
                 container_data->replicas>1?" set":"", rsc->id, container_data->image,
                 is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                 is_set(rsc->flags, pe_rsc_managed) ? "" : " (unmanaged)");
    if (options & pe_print_html) {
        status_print("<br />\n<ul>\n");
    }


    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        if (options & pe_print_html) {
            status_print("<li>");
        }

        if (is_set(options, pe_print_implicit)) {
            child_text = crm_strdup_printf("     %s", pre_text);
            if(g_list_length(container_data->tuples) > 1) {
                status_print("  %sReplica[%d]\n", pre_text, tuple->offset);
            }
            if (options & pe_print_html) {
                status_print("<br />\n<ul>\n");
            }
            print_rsc_in_list(tuple->ip, child_text, options, print_data);
            print_rsc_in_list(tuple->docker, child_text, options, print_data);
            print_rsc_in_list(tuple->remote, child_text, options, print_data);
            print_rsc_in_list(tuple->child, child_text, options, print_data);
            if (options & pe_print_html) {
                status_print("</ul>\n");
            }
        } else {
            child_text = crm_strdup_printf("%s  ", pre_text);
            tuple_print(tuple, child_text, options, print_data);
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

void
tuple_free(container_grouping_t *tuple) 
{
    if(tuple == NULL) {
        return;
    }

    if(tuple->node) {
        free(tuple->node);
        tuple->node = NULL;
    }

    if(tuple->ip) {
        free_xml(tuple->ip->xml);
        tuple->ip->xml = NULL;
        tuple->ip->fns->free(tuple->ip);
        tuple->ip = NULL;
    }
    if(tuple->docker) {
        free_xml(tuple->docker->xml);
        tuple->docker->xml = NULL;
        tuple->docker->fns->free(tuple->docker);
        tuple->docker = NULL;
    }
    if(tuple->remote) {
        free_xml(tuple->remote->xml);
        tuple->remote->xml = NULL;
        tuple->remote->fns->free(tuple->remote);
        tuple->remote = NULL;
    }
    free(tuple->ipaddr);
    free(tuple);
}

void
container_free(resource_t * rsc)
{
    container_variant_data_t *container_data = NULL;
    CRM_CHECK(rsc != NULL, return);

    get_container_variant_data(container_data, rsc);
    pe_rsc_trace(rsc, "Freeing %s", rsc->id);

    free(container_data->prefix);
    free(container_data->image);
    free(container_data->control_port);
    free(container_data->host_network);
    free(container_data->host_netmask);
    free(container_data->ip_range_start);
    free(container_data->docker_network);
    free(container_data->docker_run_options);
    free(container_data->docker_run_command);
    free(container_data->docker_host_options);

    g_list_free_full(container_data->tuples, (GDestroyNotify)tuple_free);
    g_list_free_full(container_data->mounts, (GDestroyNotify)mount_free);
    g_list_free_full(container_data->ports, (GDestroyNotify)port_free);
    g_list_free(rsc->children);

    if(container_data->child) {
        free_xml(container_data->child->xml);
        container_data->child->xml = NULL;
        container_data->child->fns->free(container_data->child);
    }
    common_free(rsc);
}

enum rsc_role_e
container_resource_state(const resource_t * rsc, gboolean current)
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
        container_variant_data_t *container_data = NULL;

        get_container_variant_data(container_data, rsc);
        return container_data->replicas;
    }
}
