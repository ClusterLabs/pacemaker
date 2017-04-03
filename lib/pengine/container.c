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
    return snprintf(buffer, max, " --add-host=%s-%d:%s",
                    data->prefix, tuple->offset, tuple->ipaddr);
#endif
}

static xmlNode *
create_resource(const char *name, const char *provider, const char *kind) 
{
    xmlNode *rsc = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);

    crm_xml_add(rsc, XML_ATTR_ID, name);
    crm_xml_add(rsc, XML_AGENT_ATTR_CLASS, "ocf");
    crm_xml_add(rsc, XML_AGENT_ATTR_PROVIDER, provider);
    crm_xml_add(rsc, XML_ATTR_TYPE, kind);

    return rsc;
}

static void
create_nvp(xmlNode *parent, const char *name, const char *value) 
{
    xmlNode *xml_nvp = create_xml_node(parent, XML_CIB_TAG_NVPAIR);

    crm_xml_set_id(xml_nvp, "%s-%s", ID(parent), name);
    crm_xml_add(xml_nvp, XML_NVPAIR_ATTR_NAME, name);
    crm_xml_add(xml_nvp, XML_NVPAIR_ATTR_VALUE, value);
}

static void
create_op(xmlNode *parent, const char *prefix, const char *task, const char *interval) 
{
    xmlNode *xml_op = create_xml_node(parent, "op");

    crm_xml_set_id(xml_op, "%s-%s-%s", prefix, task, interval);
    crm_xml_add(xml_op, XML_LRM_ATTR_INTERVAL, interval);
    crm_xml_add(xml_op, "name", task);
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

        create_nvp(xml_obj, "ip", tuple->ipaddr);
        if(data->host_network) {
            create_nvp(xml_obj, "nic", data->host_network);
        }

        if(data->host_netmask) {
            create_nvp(xml_obj, "cidr_netmask", data->host_netmask);

        } else {
            create_nvp(xml_obj, "cidr_netmask", "32");
        }

        xml_obj = create_xml_node(xml_ip, "operations");
        create_op(xml_obj, ID(xml_ip), "monitor", "60s");

        // TODO: Other ops? Timeouts and intervals from underlying resource?

        if (common_unpack(xml_ip, &tuple->ip, NULL, data_set) == false) {
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

        create_nvp(xml_obj, "image", data->image);
        create_nvp(xml_obj, "allow_pull", "true");
        create_nvp(xml_obj, "force_kill", "false");
        create_nvp(xml_obj, "reuse", "false");

        offset += snprintf(buffer+offset, max-offset, "-h %s-%d --restart=no ",
                           data->prefix, tuple->offset);

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
            } else {
                offset += snprintf(buffer+offset, max-offset, " -p %s:%s", port->source, port->target);
            }
        }

        if(data->docker_run_options) {
            offset += snprintf(buffer+offset, max-offset, " %s", data->docker_run_options);
        }

        if(data->docker_host_options) {
            offset += snprintf(buffer+offset, max-offset, " %s", data->docker_host_options);
        }

        create_nvp(xml_obj, "run_opts", buffer);
        free(buffer);

        create_nvp(xml_obj, "mount_points", dbuffer);
        free(dbuffer);

        if(tuple->child) {
            if(data->docker_run_command) {
                create_nvp(xml_obj, "run_cmd", data->docker_run_command);
            } else {
                create_nvp(xml_obj, "run_cmd", SBIN_DIR"/pacemaker_remoted");
            }

            /* TODO: Allow users to specify their own?
             *
             * We just want to know if the container is alive, we'll
             * monitor the child independently
             */
            create_nvp(xml_obj, "monitor_cmd", "/bin/true"); 
        /* } else if(child && data->untrusted) {
         * Support this use-case?
         *
         * The ability to have resources started/stopped by us, but
         * unable to set attributes, etc.
         *
         * Arguably better to control API access this with ACLs like
         * "normal" remote nodes
         *
         *     create_nvp(xml_obj, "run_cmd", "/usr/libexec/pacemaker/lrmd");
         *     create_nvp(xml_obj, "monitor_cmd", "/usr/libexec/pacemaker/lrmd_internal_ctl -c poke");
         */
        } else {
            /* TODO: Allow users to specify their own?
             *
             * We don't know what's in the container, so we just want
             * to know if it is alive
             */
            create_nvp(xml_obj, "monitor_cmd", "/bin/true");
        }


        xml_obj = create_xml_node(xml_docker, "operations");
        create_op(xml_obj, ID(xml_docker), "monitor", "60s");

        // TODO: Other ops? Timeouts and intervals from underlying resource?

        if (common_unpack(xml_docker, &tuple->docker, NULL, data_set) == FALSE) {
            return FALSE;
        }
        parent->children = g_list_append(parent->children, tuple->docker);
        tuple->docker->parent = parent;
        return TRUE;
}

static bool
create_remote_resource(
    resource_t *parent, container_variant_data_t *data, container_grouping_t *tuple,
    pe_working_set_t * data_set) 
{
    if (tuple->child && valid_network(data)) {
        node_t *node = NULL;
        xmlNode *xml_obj = NULL;
        xmlNode *xml_remote = NULL;
        char *nodeid = crm_strdup_printf("%s-%d", data->prefix, tuple->offset);
        char *id = NULL;

        if (remote_id_conflict(nodeid, data_set)) {
            // The biggest hammer we have
            id = crm_strdup_printf("pcmk-internal-%s-remote-%d", tuple->child->id, tuple->offset);
            CRM_ASSERT(remote_id_conflict(id, data_set) == FALSE);
        } else {
            id = strdup(nodeid);
        }

        xml_remote = create_resource(id, "pacemaker", "remote");
        free(id);

        xml_obj = create_xml_node(xml_remote, "operations");
        create_op(xml_obj, ID(xml_remote), "monitor", "60s");

        xml_obj = create_xml_node(xml_remote, XML_TAG_ATTR_SETS);
        crm_xml_set_id(xml_obj, "%s-attributes-%d", data->prefix, tuple->offset);

        if(tuple->ipaddr) {
            create_nvp(xml_obj, "addr", tuple->ipaddr);
        } else {
            create_nvp(xml_obj, "addr", "localhost");
        }

        if(data->control_port) {
            create_nvp(xml_obj, "port", data->control_port);
        } else {
            create_nvp(xml_obj, "port", crm_itoa(DEFAULT_REMOTE_PORT));
        }

        xml_obj = create_xml_node(xml_remote, XML_TAG_META_SETS);
        crm_xml_set_id(xml_obj, "%s-meta-%d", data->prefix, tuple->offset);

        create_nvp(xml_obj, XML_OP_ATTR_ALLOW_MIGRATE, "false");

        // Sets up node->details->remote_rsc->container == tuple->docker
        create_nvp(xml_obj, XML_RSC_ATTR_CONTAINER, tuple->docker->id);

        // TODO: Do this generically, eg with rsc->flags
        // create_nvp(xml_obj, XML_RSC_ATTR_INTERNAL_RSC, "true"); // Suppress printing

        // tuple->docker->fillers = g_list_append(tuple->docker->fillers, child);

        // -INFINITY prevents anyone else from running here
        node = pe_create_node(strdup(nodeid), nodeid, "remote", "-INFINITY",
                              data_set);
        tuple->node = node_copy(node);
        tuple->node->weight = 500;
        nodeid = NULL;
        id = NULL;

        if (common_unpack(xml_remote, &tuple->remote, NULL, data_set) == FALSE) {
            return FALSE;
        }

        tuple->node->details->remote_rsc = tuple->remote;
        parent->children = g_list_append(parent->children, tuple->remote);
    }
    return TRUE;
}

static bool
create_container(
    resource_t *parent, container_variant_data_t *data, container_grouping_t *tuple,
    pe_working_set_t * data_set)
{

    if(create_docker_resource(parent, data, tuple, data_set) == FALSE) {
        return TRUE;
    }
    if(create_ip_resource(parent, data, tuple, data_set) == FALSE) {
        return TRUE;
    }
    if(create_remote_resource(parent, data, tuple, data_set) == FALSE) {
        return TRUE;
    }
    if(tuple->child && tuple->ipaddr) {
        add_hash_param(tuple->child->meta, "external-ip", tuple->ipaddr);
    }

    return FALSE;
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
    if(xml_obj == NULL) {
        return FALSE;
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

        container_mount_t *mount = calloc(1, sizeof(container_mount_t));
        mount->source = crm_element_value_copy(xml_child, "source-dir");

        if(mount->source == NULL) {
            mount->source = crm_element_value_copy(xml_child, "source-dir-root");
            mount->flags = 1;
        }
        mount->target = crm_element_value_copy(xml_child, "target-dir");
        mount->options = crm_element_value_copy(xml_child, "options");

        if(mount->source && mount->target) {
            container_data->mounts = g_list_append(container_data->mounts, mount);
        } else {
            pe_err("Invalid mount directive %s", ID(xml_child));
            mount_free(mount);
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

        create_nvp(xml_set, XML_RSC_ATTR_ORDERED, "true");

        value = crm_itoa(container_data->replicas);
        create_nvp(xml_set, XML_RSC_ATTR_INCARNATION_MAX, value);
        free(value);

        value = crm_itoa(container_data->replicas_per_host);
        create_nvp(xml_set, XML_RSC_ATTR_INCARNATION_NODEMAX, value);
        free(value);

        if(container_data->replicas_per_host > 1) {
            create_nvp(xml_set, XML_RSC_ATTR_UNIQUE, "true");
        } else {
            create_nvp(xml_set, XML_RSC_ATTR_UNIQUE, "false");
        }

        if(container_data->masters) {
            value = crm_itoa(container_data->masters);
            create_nvp(xml_set, XML_RSC_ATTR_MASTER_MAX, value);
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
        container_mount_t *mount = NULL;
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
        container_data->child->orig_xml = xml_obj; // Also the trigger for common_free()
                                                   // to free xml_resource as container_data->child->xml

        mount = calloc(1, sizeof(container_mount_t));
        mount->source = strdup(DEFAULT_REMOTE_KEY_LOCATION);
        mount->target = strdup(DEFAULT_REMOTE_KEY_LOCATION);
        mount->options = NULL;
        mount->flags = 0;
        container_data->mounts = g_list_append(container_data->mounts, mount);

        mount = calloc(1, sizeof(container_mount_t));
        mount->source = strdup(CRM_LOG_DIR "/bundles");
        mount->target = strdup("/var/log");
        mount->options = NULL;
        mount->flags = 1;
        container_data->mounts = g_list_append(container_data->mounts, mount);

        port = calloc(1, sizeof(container_port_t));
        if(container_data->control_port) {
            port->source = strdup(container_data->control_port);
        } else {
            port->source = crm_itoa(DEFAULT_REMOTE_PORT);
        }
        port->target = strdup(port->source);
        container_data->ports = g_list_append(container_data->ports, port);

        buffer = calloc(1, max+1);
        for(childIter = container_data->child->children; childIter != NULL; childIter = childIter->next) {
            container_grouping_t *tuple = calloc(1, sizeof(container_grouping_t));
            tuple->child = childIter->data;
            tuple->offset = lpc++;

            offset += allocate_ip(container_data, tuple, buffer+offset, max-offset);
            container_data->tuples = g_list_append(container_data->tuples, tuple);
        }
        container_data->docker_host_options = buffer;

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
        // TODO: Remove from list if create_container() returns TRUE
        create_container(rsc, container_data, tuple, data_set);
    }

    if(container_data->child) {
        rsc->children = g_list_append(rsc->children, container_data->child);
    }
    return TRUE;
}

gboolean
container_active(resource_t * rsc, gboolean all)
{
    return TRUE;
}

resource_t *
find_container_child(const char *stem, resource_t * rsc, node_t *node) 
{
    container_variant_data_t *container_data = NULL;
    resource_t *parent = uber_parent(rsc);
    CRM_ASSERT(parent->parent);

    parent = parent->parent;
    get_container_variant_data(container_data, parent);

    if (is_not_set(rsc->flags, pe_rsc_unique)) {
        for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
            container_grouping_t *tuple = (container_grouping_t *)gIter->data;

            CRM_ASSERT(tuple);
            if(tuple->node->details == node->details) {
                rsc = tuple->child;
                break;
            }
        }
    }

    if (rsc && safe_str_neq(stem, rsc->id)) {
        free(rsc->clone_name);
        rsc->clone_name = strdup(stem);
    }

    return rsc;
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
    status_print("type=\"docker\" ");
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

    if(tuple->remote && tuple->remote->running_on != NULL) {
        node = tuple->remote->running_on->data;
    } else if (tuple->remote == NULL && rsc->running_on != NULL) {
        node = rsc->running_on->data;
    }
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

    status_print("%sDocker container%s: %s [%s]%s%s\n",
                 pre_text, container_data->replicas>1?" set":"", rsc->id, container_data->image,
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

        if(is_set(options, pe_print_clone_details)) {
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

    // TODO: Free tuple->node ?

    if(tuple->ip) {
        tuple->ip->fns->free(tuple->ip);
        tuple->ip = NULL;
    }
    if(tuple->child) {
        tuple->child->fns->free(tuple->child);
        tuple->child = NULL;
    }
    if(tuple->docker) {
        tuple->docker->fns->free(tuple->docker);
        tuple->docker = NULL;
    }
    if(tuple->remote) {
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
    common_free(rsc);
}

enum rsc_role_e
container_resource_state(const resource_t * rsc, gboolean current)
{
    enum rsc_role_e container_role = RSC_ROLE_UNKNOWN;
    return container_role;
}
