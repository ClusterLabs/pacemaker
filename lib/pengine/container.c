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
        char *value = NULL;
        xmlNode *xml_ip = NULL;

        // Create an IP resource
        if(data->ip_last) {
            char *next = next_ip(data->ip_last);

            free(data->ip_last);
            data->ip_last = next;

        } else {
            data->ip_last = strdup(data->ip_range_start);
        }

        value = crm_strdup_printf("%s-ip-%s", data->prefix, data->ip_last);
        xml_ip = create_resource(value, "heartbeat", "IPaddr2");

        value = crm_strdup_printf("%s-attributes-%d", data->prefix, tuple->offset);
        xml_obj = create_xml_node(xml_ip, XML_TAG_ATTR_SETS);
        crm_xml_add(xml_obj, XML_ATTR_ID, value); free(value);

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
        char *value = crm_strdup_printf("%s-docker-%d", data->prefix, tuple->offset);
        xmlNode *xml_ip = create_resource(value, "heartbeat", "docker");

        value = crm_strdup_printf("%s-attributes-%d", data->prefix, tuple->offset);
        xml_obj = create_xml_node(xml_ip, XML_TAG_ATTR_SETS);
        crm_xml_add(xml_obj, XML_ATTR_ID, value); free(value);

        create_nvp(xml_obj, "image", data->image);
        create_nvp(xml_obj, "allow_pull", "true");
        create_nvp(xml_obj, "force_kill", "false");
        create_nvp(xml_obj, "reuse", "false");

        offset += snprintf(buffer+offset, max-offset, " -v %s:%s",
                           DEFAULT_REMOTE_KEY_LOCATION, DEFAULT_REMOTE_KEY_LOCATION);
        offset += snprintf(buffer+offset, max-offset, " -p %s:%d:%d",
                           data->ip_last, DEFAULT_REMOTE_PORT, DEFAULT_REMOTE_PORT);
        if(data->docker_run_options) {
            offset += snprintf(buffer+offset, max-offset, " %s", data->docker_run_options);
        }
        create_nvp(xml_obj, "run_opts", buffer);
        free(buffer);

        if(child) {
            // TODO: Use autoconf var
            create_nvp(xml_obj, "run_cmd", "/usr/sbin/pacemaker_remoted");
            create_nvp(xml_obj, "monitor_cmd", "/bin/true"); // We just want to know if the container
                                                              // is alive, we'll monitor the child independantly

        /* } else if(child && data->isolated) { */
        /*     create_nvp(xml_obj, "run_cmd", "/usr/libexec/pacemaker/lrmd"); */
        /*     create_nvp(xml_obj, "monitor_cmd", "/usr/libexec/pacemaker/lrmd_internal_ctl -c poke"); */
        } else {
            // TODO: Leave blank to use the built-in one?
        }


        xml_obj = create_xml_node(xml_ip, "operations");
        create_op(xml_obj, ID(xml_ip), "monitor", "60s");

        // TODO: Other ops? Timeouts and intervals from underlying resource?

        if (common_unpack(xml_ip, &tuple->docker, NULL, data_set) == false) {
            tuple_free(tuple);
            return NULL;
        }
    }

    // Create a remote resource
    if(data->ip_last && child) {
        char *value = crm_strdup_printf("%s-remote-%d", data->prefix, tuple->offset);
        xmlNode *xml_ip = create_resource(value, "pacemaker", "remote");

        xml_obj = create_xml_node(xml_ip, "operations");
        create_op(xml_obj, ID(xml_ip), "monitor", "60s");

        value = crm_strdup_printf("%s-attributes-%d", data->prefix, tuple->offset);
        xml_obj = create_xml_node(xml_ip, XML_TAG_ATTR_SETS);
        crm_xml_add(xml_obj, XML_ATTR_ID, value); free(value);

        create_nvp(xml_obj, "addr", data->ip_last);
        create_nvp(xml_obj, "port", "3121"); // DEFAULT_REMOTE_PORT

        value = crm_strdup_printf("%s-meta-%d", data->prefix, tuple->offset);
        xml_obj = create_xml_node(xml_ip, XML_TAG_META_SETS);
        crm_xml_add(xml_obj, XML_ATTR_ID, value); free(value);

        create_nvp(xml_obj, XML_RSC_ATTR_CONTAINER, tuple->docker->id);
        // create_nvp(xml_obj, XML_RSC_ATTR_INTERNAL_RSC, "true"); // Suppress printing

    /* 
    new_node_id = expand_remote_rsc_meta(xml_obj, xml_resources, &rsc_name_check);
    if (new_node_id && pe_find_node(data_set->nodes, new_node_id) == NULL) {
        crm_trace("Found guest remote node %s in container resource %s", new_node_id, ID(xml_obj));
        create_node(new_node_id, new_node_id, "remote", NULL, data_set);
    }
    */
        if (common_unpack(xml_ip, &tuple->remote, NULL, data_set) == false) {
            tuple_free(tuple);
            return NULL;
        }
    }

    if(child) {
        CRM_ASSERT(data->ip_range_start);
        tuple->child = child;
    }
#if 0
    if(tuple->ip) {
        parent->children = g_list_append(parent->children, tuple->ip);
    }
    if(tuple->docker) {
        parent->children = g_list_append(parent->children, tuple->docker);
    }
    if(tuple->remote) {
        parent->children = g_list_append(parent->children, tuple->remote);
    }
#endif
    data->tuples = g_list_append(data->tuples, tuple);
    return tuple;
}


gboolean
container_unpack(resource_t * rsc, pe_working_set_t * data_set)
{
    xmlNode *xml_resource = NULL;
    container_variant_data_t *container_data = NULL;

    pe_rsc_trace(rsc, "Processing resource %s...", rsc->id);

    container_data = calloc(1, sizeof(container_variant_data_t));
    rsc->variant_opaque = container_data;
    container_data->prefix = strdup(rsc->id);
    container_data->image = crm_element_value_copy(rsc->xml, "image");

    for (xmlNode *xml_child = __xml_first_child_element(rsc->xml); xml_child != NULL;
         xml_child = __xml_next_element(xml_child)) {
        if (crm_str_eq((const char *)xml_child->name, "docker", TRUE)) {
            container_data->xml_docker_options = xml_child;
            container_data->xml_mounts = first_named_child(xml_child, "storage");
            container_data->xml_network = first_named_child(xml_child, "network");

        /* } else if(xml_resource->type != NULL) { */
        } else if(xml_resource == NULL) {
            xml_resource = xml_child;
            crm_err("Found: %s %d", xml_child->name, xml_child->type);

        } else {
            pe_err("Only one child (%s) is per container (%s): Ignoring %s",
                   crm_element_value(xml_resource, XML_ATTR_ID), rsc->id, crm_element_value(xml_child, XML_ATTR_ID));
        }
    }

    if(container_data->xml_docker_options) {
        const char *replicas = crm_element_value(container_data->xml_docker_options, "replicas");
        container_data->replicas = crm_parse_int(replicas, "1");

    } else {
        container_data->replicas = 1;
        /* int replicas; */
        /* char *image; */
        /* char *ip_range_start; */
        /* char *docker_options; */

        /* GListPtr containers; /\* resource_t *       *\/ */
    }

    if(container_data->xml_network) {
        container_data->ip_range_start = crm_element_value_copy(container_data->xml_network, "ip-range-start");
    }

    // TODO: Parse the mount options
    // TODO: Parse the port options

    if(xml_resource && container_data->ip_range_start) {
        int lpc = 0;
        GListPtr childIter = NULL;
        resource_t *new_rsc = NULL;
        // TODO: Enforce that clone-max is >= container_data->replicas

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
    status_print("%sDocker container: %s [%s]%s%s\n",
                 pre_text, rsc->id, container_data->image,
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

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        tuple_free(tuple);
    }

    common_free(rsc);
}

enum rsc_role_e
container_resource_state(const resource_t * rsc, gboolean current)
{
    enum rsc_role_e container_role = RSC_ROLE_UNKNOWN;
    return container_role;
}
