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
next_ip(char *last_ip)
{
    int oct1 = 0;
    int oct2 = 0;
    int oct3 = 0;
    int oct4 = 0;

    int rc = sscanf(last_ip, "%d.%d.%d.%d", &oct1, &oct2, &oct3, &oct4);
    if (rc != 4) {
        return NULL;

    } else if(oct4 > 255) {
        return NULL;
    }

    return crm_strdup_printf("%d.%d.%d.%d", oct1, oct2, oct3, oct4+1);
}

static xmlNode *
create_resource(const char *name, const char *provider, const char *kind) 
{
    xmlNode *rsc = create_xml_node(NULL, XML_CIB_TAG_RESOURCE);
    crm_xml_add(rsc, XML_ATTR_ID, name);
    crm_xml_add(rsc, XML_AGENT_ATTR_CLASS, "ocf");
    crm_xml_add(rsc, XML_AGENT_ATTR_PROVIDER, provider);
    crm_xml_add(rsc, "type", kind);
    return rsc;
}

static void
create_nvp(xmlNode *parent, const char *name, const char *value) 
{
    char *id = crm_strdup_printf("%s-%s", ID(parent), name);
    xmlNode *xml_nvp = create_xml_node(parent, XML_CIB_TAG_NVPAIR);
    crm_xml_add(xml_nvp, XML_ATTR_ID, id); free(id);
    crm_xml_add(xml_nvp, XML_NVPAIR_ATTR_NAME, name);
    crm_xml_add(xml_nvp, XML_NVPAIR_ATTR_VALUE, value);
}

static void
create_op(xmlNode *parent, const char *prefix, const char *task, const char *interval) 
{
    char *id = crm_strdup_printf("%s-%s-%s", prefix, task, interval);
    xmlNode *xml_op = create_xml_node(parent, "op");

    crm_xml_add(xml_op, XML_ATTR_ID, id); free(id);
    crm_xml_add(xml_op, XML_LRM_ATTR_INTERVAL, interval);
    crm_xml_add(xml_op, "name", task);
}


static container_grouping_t *
create_container(
    resource_t *parent, container_variant_data_t *data, resource_t *child, int index,
    pe_working_set_t * data_set) 
{
    xmlNode *xml_obj = NULL;
    container_grouping_t *tuple = calloc(1, sizeof(container_grouping_t));

    tuple->offset = index;
    if(data->ip_range_start) {
        char *id = NULL;
        xmlNode *xml_ip = NULL;

        // Create an IP resource
        if(data->ip_last) {
            char *next = next_ip(data->ip_last);

            free(data->ip_last);
            data->ip_last = next;

        } else {
            data->ip_last = strdup(data->ip_range_start);
        }

        id = crm_strdup_printf("%s-ip-%s", data->prefix, data->ip_last);
        xml_ip = create_resource(id, "heartbeat", "IPaddr2");

        id = crm_strdup_printf("%s-attributes-%d", data->prefix, tuple->offset);
        xml_obj = create_xml_node(xml_ip, XML_TAG_ATTR_SETS);
        crm_xml_add(xml_obj, XML_ATTR_ID, id); free(id);

        create_nvp(xml_obj, "ip", data->ip_last);

        // TODO: Support NIC and/or netmask

        xml_obj = create_xml_node(xml_ip, "operations");
        create_op(xml_obj, ID(xml_ip), "monitor", "60s");

        // TODO: Other ops? Timeouts and intervals from underlying resource?

        if (common_unpack(xml_ip, &tuple->ip, NULL, data_set) == false) {
            tuple_free(tuple);
            return NULL;
        }
    }

    // Create a container
    {
        int offset = 0, max = 1024;
        char *buffer = calloc(1, max+1);
        char *id = crm_strdup_printf("%s-docker-%d", data->prefix, tuple->offset);
        xmlNode *xml_docker = create_resource(id, "heartbeat", "docker");

        int doffset = 0, dmax = 1024;
        char *dbuffer = calloc(1, dmax+1);

        id = crm_strdup_printf("%s-attributes-%d", data->prefix, tuple->offset);
        xml_obj = create_xml_node(xml_docker, XML_TAG_ATTR_SETS);
        crm_xml_add(xml_obj, XML_ATTR_ID, id); free(id);

        create_nvp(xml_obj, "image", data->image);
        create_nvp(xml_obj, "allow_pull", "true");
        create_nvp(xml_obj, "force_kill", "false");
        create_nvp(xml_obj, "reuse", "false");

        for(GListPtr pIter = data->mounts; pIter != NULL; pIter = pIter->next) {
            container_mount_t *mount = pIter->data;

            if(mount->flags) {
                char *source = crm_strdup_printf(
                    "%s/%s-%d", mount->source, data->prefix, tuple->offset);

                offset += snprintf(buffer+offset, max-offset, " -v %s:%s", source, mount->target);
                doffset += snprintf(dbuffer+doffset, dmax-doffset, "#%s", source);

            } else {
                offset += snprintf(buffer+offset, max-offset, " -v %s:%s", mount->source, mount->target);
            }
            if(mount->options) {
                offset += snprintf(buffer+offset, max-offset, ":%s", mount->options);
            }
        }

        for(GListPtr pIter = data->ports; pIter != NULL; pIter = pIter->next) {
            char *port = pIter->data;

            offset += snprintf(buffer+offset, max-offset, " -p %s:%s:%s",
                               data->ip_last, port, port);
        }

        if(data->docker_run_options) {
            offset += snprintf(buffer+offset, max-offset, " %s", data->docker_run_options);
        }
        create_nvp(xml_obj, "run_opts", buffer);
        free(buffer);

        // TODO: How will these directories get created on the host?
        create_nvp(xml_obj, "directory-list", dbuffer);
        free(dbuffer);

        if(child) {
            // TODO: Use autoconf var
            create_nvp(xml_obj, "run_cmd", "/usr/sbin/pacemaker_remoted");

            // TODO: Allow users to specify their own?
            create_nvp(xml_obj, "monitor_cmd", "/bin/true"); // We just want to know if the container
                                                             // is alive, we'll monitor the child independantly

        /* } else if(child && data->isolated) { */
        /*     create_nvp(xml_obj, "run_cmd", "/usr/libexec/pacemaker/lrmd"); */
        /*     create_nvp(xml_obj, "monitor_cmd", "/usr/libexec/pacemaker/lrmd_internal_ctl -c poke"); */
        } else {
            // TODO: Leave blank to use the built-in one?
        }


        xml_obj = create_xml_node(xml_docker, "operations");
        create_op(xml_obj, ID(xml_docker), "monitor", "60s");

        // TODO: Other ops? Timeouts and intervals from underlying resource?

        if (common_unpack(xml_docker, &tuple->docker, NULL, data_set) == false) {
            tuple_free(tuple);
            return NULL;
        }
    }

    // Create a remote resource
    if(data->ip_last && child) {
        node_t *node = NULL;
        xmlNode *xml_remote = NULL;
        char *nodeid = crm_strdup_printf("%s-%d", data->prefix, tuple->offset);
        char *id = strdup(nodeid);

        if(remote_id_conflict(id, data_set)) {
            // The biggest hammer we have
            id = crm_strdup_printf("pcmk-internal-%s-remote-%d", child->id, tuple->offset);
        }

        CRM_ASSERT(remote_id_conflict(id, data_set) == FALSE);

        xml_remote = create_resource(id, "pacemaker", "remote");
        xml_obj = create_xml_node(xml_remote, "operations");
        create_op(xml_obj, ID(xml_remote), "monitor", "60s");

        id = crm_strdup_printf("%s-attributes-%d", data->prefix, tuple->offset);
        xml_obj = create_xml_node(xml_remote, XML_TAG_ATTR_SETS);
        crm_xml_add(xml_obj, XML_ATTR_ID, id); free(id);

        create_nvp(xml_obj, "addr", data->ip_last);
        create_nvp(xml_obj, "port", crm_itoa(DEFAULT_REMOTE_PORT));

        id = crm_strdup_printf("%s-meta-%d", data->prefix, tuple->offset);
        xml_obj = create_xml_node(xml_remote, XML_TAG_META_SETS);
        crm_xml_add(xml_obj, XML_ATTR_ID, id); free(id);

        create_nvp(xml_obj, XML_OP_ATTR_ALLOW_MIGRATE, "false");

        // Sets up node->details->remote_rsc->container == tuple->docker
        create_nvp(xml_obj, XML_RSC_ATTR_CONTAINER, tuple->docker->id);

        // TODO: Do this generically, eg with rsc->flags
        // create_nvp(xml_obj, XML_RSC_ATTR_INTERNAL_RSC, "true"); // Suppress printing

        // tuple->docker->fillers = g_list_append(tuple->docker->fillers, child);

        // -INFINITY prevents anyone else from running here
        node = create_node(strdup(nodeid), nodeid, "remote", "-INFINITY", data_set);
        tuple->node = node_copy(node);
        tuple->node->weight = 500;
        nodeid = NULL;
        id = NULL;

        if (common_unpack(xml_remote, &tuple->remote, NULL, data_set) == false) {
            tuple_free(tuple);
            return NULL;
        }

        tuple->node->details->remote_rsc = tuple->remote;
    }

    if(child) {
        CRM_ASSERT(data->ip_range_start);
        tuple->child = child;
    }

    if(tuple->ip) {
        parent->children = g_list_append(parent->children, tuple->ip);
    }
    if(tuple->docker) {
        parent->children = g_list_append(parent->children, tuple->docker);
    }
    if(tuple->remote) {
        parent->children = g_list_append(parent->children, tuple->remote);
    }

    data->tuples = g_list_append(data->tuples, tuple);
    return tuple;
}

static void mount_free(container_mount_t *mount) 
{
    free(mount->source);
    free(mount->target);
    free(mount->options);
    free(mount);
}

gboolean
container_unpack(resource_t * rsc, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    xmlNode *xml_resource = NULL;
    container_variant_data_t *container_data = NULL;

    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    container_data = calloc(1, sizeof(container_variant_data_t));
    rsc->variant_opaque = container_data;
    container_data->prefix = strdup(rsc->id);
    container_data->image = crm_element_value_copy(rsc->xml, "image");

    for (xmlNode *xml_child = __xml_first_child_element(rsc->xml); xml_child != NULL;
         xml_child = __xml_next_element(xml_child)) {

        const char *id = ID(xml_child);

        if(xml_resource == NULL && id != NULL) {
            xml_resource = xml_child;

        } else if(id != NULL) {
            pe_err("Only one child (%s) is per container (%s): Ignoring %s",
                   crm_element_value(xml_resource, XML_ATTR_ID), rsc->id, id);
        }
    }

    xml_obj = first_named_child(rsc->xml, "docker");
    if(xml_obj) {
        const char *replicas = crm_element_value(xml_obj, "replicas");
        container_data->replicas = crm_parse_int(replicas, "1");
        container_data->docker_run_options = crm_element_value_copy(xml_obj, "options");

    } else {
        container_data->replicas = 1;
    }

    xml_obj = first_named_child(rsc->xml, "network");
    if(xml_obj) {

        container_data->ip_range_start = crm_element_value_copy(xml_obj, "ip-range-start");

        for (xmlNode *xml_child = __xml_first_child_element(xml_obj); xml_child != NULL;
             xml_child = __xml_next_element(xml_child)) {

            char *port = crm_element_value_copy(xml_child, "port");

            if(port == NULL) {
                port = crm_element_value_copy(xml_child, "range");
            }

            if(port != NULL) {
                container_data->ports = g_list_append(container_data->ports, port);
            } else {
                pe_err("Invalid port directive %s", ID(xml_child));
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

    if(xml_resource && container_data->ip_range_start) {
        int lpc = 0;
        GListPtr childIter = NULL;
        resource_t *new_rsc = NULL;
        // TODO: Enforce that clone-max is >= container_data->replicas

        container_mount_t *mount = NULL;

        mount = calloc(1, sizeof(container_mount_t));
        mount->source = strdup(DEFAULT_REMOTE_KEY_LOCATION);
        mount->target = strdup(DEFAULT_REMOTE_KEY_LOCATION);
        mount->options = NULL;
        mount->flags = 0;
        container_data->mounts = g_list_append(container_data->mounts, mount);

        mount = calloc(1, sizeof(container_mount_t));
        mount->source = strdup("/var/log/containers");
        mount->target = strdup("/var/log");
        mount->options = NULL;
        mount->flags = 1;
        container_data->mounts = g_list_append(container_data->mounts, mount);

        container_data->ports = g_list_append(container_data->ports, crm_itoa(DEFAULT_REMOTE_PORT));

        if (common_unpack(xml_resource, &new_rsc, rsc, data_set) == FALSE) {
            pe_err("Failed unpacking resource %s", crm_element_value(rsc->xml, XML_ATTR_ID));
            if (new_rsc != NULL && new_rsc->fns != NULL) {
                new_rsc->fns->free(new_rsc);
            }
            return FALSE;

        } else if(container_data->replicas > 1 && new_rsc->variant < pe_clone) {
            pe_err("%d replicas requested but %s is not a clone", container_data->replicas, new_rsc->id);
            // fake a clone??
            // container_data->child = new_rsc;
            return FALSE;

        }

        container_data->child = new_rsc;
        for(childIter = container_data->child->children; childIter != NULL; childIter = childIter->next) {
            create_container(rsc, container_data, childIter->data, lpc++, data_set);
        }

    } else if(xml_resource) {
        pe_err("Cannot control %s inside container %s without a value for ip-range-start",
               rsc->id, ID(xml_resource));
        return FALSE;

    } else {
        // Just a naked container, no pacemaker-remote
        for(int lpc = 0; lpc < container_data->replicas; lpc++) {
            create_container(rsc, container_data, NULL, lpc, data_set);
        }
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

static void
container_print_xml(resource_t * rsc, const char *pre_text, long options, void *print_data)
{
    container_variant_data_t *container_data = NULL;
    char *child_text = NULL;
    CRM_CHECK(rsc != NULL, return);

    if (pre_text == NULL) {
        pre_text = "";
    }
    child_text = crm_concat(pre_text, "   ", ' ');

    status_print("%s<container ", pre_text);
    status_print("id=\"%s\" ", rsc->id);
    status_print("managed=\"%s\" ", is_set(rsc->flags, pe_rsc_managed) ? "true" : "false");
    status_print("failed=\"%s\" ", is_set(rsc->flags, pe_rsc_failed) ? "true" : "false");
    status_print(">\n");

    get_container_variant_data(container_data, rsc);

    status_print("%sDocker container: %s [%s]%s%s",
                 pre_text, rsc->id, container_data->image,
                 is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                 is_set(rsc->flags, pe_rsc_managed) ? "" : " (unmanaged)");

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        if(tuple->ip) {
            tuple->ip->fns->print(tuple->ip, child_text, options, print_data);
        }
        if(tuple->child) {
            tuple->child->fns->print(tuple->child, child_text, options, print_data);
        }
        if(tuple->docker) {
            tuple->docker->fns->print(tuple->docker, child_text, options, print_data);
        }
        if(tuple->remote) {
            tuple->remote->fns->print(tuple->remote, child_text, options, print_data);
        }
    }
    status_print("%s</container>\n", pre_text);
    free(child_text);
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

    child_text = crm_strdup_printf("     %s", pre_text);
    status_print("%sDocker container%s: %s [%s]%s%s\n",
                 pre_text, container_data->replicas>1?" set":"", rsc->id, container_data->image,
                 is_set(rsc->flags, pe_rsc_unique) ? " (unique)" : "",
                 is_set(rsc->flags, pe_rsc_managed) ? "" : " (unmanaged)");

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);

        if(g_list_length(container_data->tuples) > 1) {
            status_print("  %sReplica[%d]\n", pre_text, tuple->offset);
        }

        if(tuple->ip) {
            tuple->ip->fns->print(tuple->ip, child_text, options, print_data);
        }
        if(tuple->docker) {
            tuple->docker->fns->print(tuple->docker, child_text, options, print_data);
        }
        if(tuple->remote) {
            tuple->remote->fns->print(tuple->remote, child_text, options, print_data);
        }
        if(tuple->child) {
            tuple->child->fns->print(tuple->child, child_text, options, print_data);
        }
    }
}

void
tuple_free(container_grouping_t *tuple) 
{
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
    free(tuple);
}

void
container_free(resource_t * rsc)
{
    container_variant_data_t *container_data = NULL;
    CRM_CHECK(rsc != NULL, return);

    get_container_variant_data(container_data, rsc);
    pe_rsc_trace(rsc, "Freeing %s", rsc->id);

    g_list_free_full(container_data->tuples, (GDestroyNotify)tuple_free);
    g_list_free_full(container_data->mounts, (GDestroyNotify)mount_free);
    g_list_free_full(container_data->ports, free);
    common_free(rsc);
}

enum rsc_role_e
container_resource_state(const resource_t * rsc, gboolean current)
{
    enum rsc_role_e container_role = RSC_ROLE_UNKNOWN;
    return container_role;
}
