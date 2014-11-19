
/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>

#include <crm/cib.h>
#include <crm/attrd.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>

#include "fake_transition.h"
extern xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, crm_time_t * now);

bool scope_master = FALSE;
gboolean do_force = FALSE;
gboolean BE_QUIET = FALSE;
const char *attr_set_type = XML_TAG_ATTR_SETS;
char *host_id = NULL;
const char *rsc_id = NULL;
const char *host_uname = NULL;
const char *prop_name = NULL;
const char *prop_value = NULL;
const char *rsc_type = NULL;
const char *prop_id = NULL;
const char *prop_set = NULL;
char *move_lifetime = NULL;
char rsc_cmd = 'L';
const char *rsc_long_cmd = NULL;
char *our_pid = NULL;
crm_ipc_t *crmd_channel = NULL;
char *xml_file = NULL;
int cib_options = cib_sync_call;
int crmd_replies_needed = 1; /* The welcome message */
GMainLoop *mainloop = NULL;
gboolean print_pending = FALSE;

extern void cleanup_alloc_calculations(pe_working_set_t * data_set);

#define CMD_ERR(fmt, args...) do {		\
	crm_warn(fmt, ##args);			\
	fprintf(stderr, fmt, ##args);		\
    } while(0)

#define message_timeout_ms 60*1000

static gboolean
resource_ipc_timeout(gpointer data)
{
    fprintf(stderr, "No messages received in %d seconds.. aborting\n",
            (int)message_timeout_ms / 1000);
    crm_err("No messages received in %d seconds", (int)message_timeout_ms / 1000);
    return crm_exit(-1);
}

static void
resource_ipc_connection_destroy(gpointer user_data)
{
    crm_info("Connection to CRMd was terminated");
    crm_exit(1);
}

static void
start_mainloop(void)
{
    if (crmd_replies_needed == 0) {
        return;
    }

    mainloop = g_main_new(FALSE);
    fprintf(stderr, "Waiting for %d replies from the CRMd", crmd_replies_needed);
    crm_debug("Waiting for %d replies from the CRMd", crmd_replies_needed);

    g_timeout_add(message_timeout_ms, resource_ipc_timeout, NULL);
    g_main_run(mainloop);
}

static int
resource_ipc_callback(const char *buffer, ssize_t length, gpointer userdata)
{
    xmlNode *msg = string2xml(buffer);

    fprintf(stderr, ".");
    crm_log_xml_trace(msg, "[inbound]");

    crmd_replies_needed--;
    if (crmd_replies_needed == 0) {
        fprintf(stderr, " OK\n");
        crm_debug("Got all the replies we expected");
        return crm_exit(pcmk_ok);
    }

    free_xml(msg);
    return 0;
}

struct ipc_client_callbacks crm_callbacks = {
    .dispatch = resource_ipc_callback,
    .destroy = resource_ipc_connection_destroy,
};

static int
do_find_resource(const char *rsc, resource_t * the_rsc, pe_working_set_t * data_set)
{
    int found = 0;
    GListPtr lpc = NULL;

    if (the_rsc == NULL) {
        the_rsc = pe_find_resource(data_set->resources, rsc);
    }

    if (the_rsc == NULL) {
        return -ENXIO;
    }

    if (the_rsc->variant >= pe_clone) {
        GListPtr gIter = the_rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            found += do_find_resource(rsc, gIter->data, data_set);
        }
        return found;
    }

    for (lpc = the_rsc->running_on; lpc != NULL; lpc = lpc->next) {
        node_t *node = (node_t *) lpc->data;

        crm_trace("resource %s is running on: %s", rsc, node->details->uname);
        if (BE_QUIET) {
            fprintf(stdout, "%s\n", node->details->uname);
        } else {
            const char *state = "";

            if (the_rsc->variant < pe_clone && the_rsc->fns->state(the_rsc, TRUE) == RSC_ROLE_MASTER) {
                state = "Master";
            }
            fprintf(stdout, "resource %s is running on: %s %s\n", rsc, node->details->uname, state);
        }

        found++;
    }

    if (BE_QUIET == FALSE && found == 0) {
        fprintf(stderr, "resource %s is NOT running\n", rsc);
    }

    return 0;
}

#define cons_string(x) x?x:"NA"
static void
print_cts_constraints(pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;
    xmlNode *lifetime = NULL;
    xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set->input);

    for (xml_obj = __xml_first_child(cib_constraints); xml_obj != NULL;
         xml_obj = __xml_next(xml_obj)) {
        const char *id = crm_element_value(xml_obj, XML_ATTR_ID);

        if (id == NULL) {
            continue;
        }

        lifetime = first_named_child(xml_obj, "lifetime");

        if (test_ruleset(lifetime, NULL, data_set->now) == FALSE) {
            continue;
        }

        if (safe_str_eq(XML_CONS_TAG_RSC_DEPEND, crm_element_name(xml_obj))) {
            printf("Constraint %s %s %s %s %s %s %s\n",
                   crm_element_name(xml_obj),
                   cons_string(crm_element_value(xml_obj, XML_ATTR_ID)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET)),
                   cons_string(crm_element_value(xml_obj, XML_RULE_ATTR_SCORE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_SOURCE_ROLE)),
                   cons_string(crm_element_value(xml_obj, XML_COLOC_ATTR_TARGET_ROLE)));

        } else if (safe_str_eq(XML_CONS_TAG_RSC_LOCATION, crm_element_name(xml_obj))) {
            /* unpack_location(xml_obj, data_set); */
        }
    }
}

static void
print_cts_rsc(resource_t * rsc)
{
    GListPtr lpc = NULL;
    const char *host = NULL;
    gboolean needs_quorum = TRUE;
    const char *rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    const char *rprov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    const char *rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

    if (safe_str_eq(rclass, "stonith")) {
        xmlNode *op = NULL;

        needs_quorum = FALSE;

        for (op = __xml_first_child(rsc->ops_xml); op != NULL; op = __xml_next(op)) {
            if (crm_str_eq((const char *)op->name, "op", TRUE)) {
                const char *name = crm_element_value(op, "name");

                if (safe_str_neq(name, CRMD_ACTION_START)) {
                    const char *value = crm_element_value(op, "requires");

                    if (safe_str_eq(value, "nothing")) {
                        needs_quorum = FALSE;
                    }
                    break;
                }
            }
        }
    }

    if (rsc->running_on != NULL && g_list_length(rsc->running_on) == 1) {
        node_t *tmp = rsc->running_on->data;

        host = tmp->details->uname;
    }

    printf("Resource: %s %s %s %s %s %s %s %s %d %lld 0x%.16llx\n",
           crm_element_name(rsc->xml), rsc->id,
           rsc->clone_name ? rsc->clone_name : rsc->id, rsc->parent ? rsc->parent->id : "NA",
           rprov ? rprov : "NA", rclass, rtype, host ? host : "NA", needs_quorum, rsc->flags,
           rsc->flags);

    for (lpc = rsc->children; lpc != NULL; lpc = lpc->next) {
        resource_t *child = (resource_t *) lpc->data;

        print_cts_rsc(child);
    }
}

static void
print_raw_rsc(resource_t * rsc)
{
    GListPtr lpc = NULL;
    GListPtr children = rsc->children;

    if (children == NULL) {
        printf("%s\n", rsc->id);
    }

    for (lpc = children; lpc != NULL; lpc = lpc->next) {
        resource_t *child = (resource_t *) lpc->data;

        print_raw_rsc(child);
    }
}

static int
do_find_resource_list(pe_working_set_t * data_set, gboolean raw)
{
    int found = 0;

    GListPtr lpc = NULL;
    int opts = pe_print_printf | pe_print_rsconly;

    if (print_pending) {
        opts |= pe_print_pending;
    }

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        resource_t *rsc = (resource_t *) lpc->data;

        if (is_set(rsc->flags, pe_rsc_orphan)
            && rsc->fns->active(rsc, TRUE) == FALSE) {
            continue;
        }
        rsc->fns->print(rsc, NULL, opts, stdout);
        found++;
    }

    if (found == 0) {
        printf("NO resources configured\n");
        return -ENXIO;
    }

    return 0;
}

static resource_t *
find_rsc_or_clone(const char *rsc, pe_working_set_t * data_set)
{
    resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);

    if (the_rsc == NULL) {
        char *as_clone = crm_concat(rsc, "0", ':');

        the_rsc = pe_find_resource(data_set->resources, as_clone);
        free(as_clone);
    }
    return the_rsc;
}

static int
dump_resource(const char *rsc, pe_working_set_t * data_set, gboolean expanded)
{
    char *rsc_xml = NULL;
    resource_t *the_rsc = find_rsc_or_clone(rsc, data_set);
    int opts = pe_print_printf;

    if (the_rsc == NULL) {
        return -ENXIO;
    }

    if (print_pending) {
        opts |= pe_print_pending;
    }
    the_rsc->fns->print(the_rsc, NULL, opts, stdout);

    if (expanded) {
        rsc_xml = dump_xml_formatted(the_rsc->xml);
    } else {
        if (the_rsc->orig_xml) {
            rsc_xml = dump_xml_formatted(the_rsc->orig_xml);
        } else {
            rsc_xml = dump_xml_formatted(the_rsc->xml);
        }
    }

    fprintf(stdout, "%sxml:\n%s\n", expanded ? "" : "raw ", rsc_xml);

    free(rsc_xml);

    return 0;
}

static int
dump_resource_attr(const char *rsc, const char *attr, pe_working_set_t * data_set)
{
    int rc = -ENXIO;
    node_t *current = NULL;
    GHashTable *params = NULL;
    resource_t *the_rsc = find_rsc_or_clone(rsc, data_set);
    const char *value = NULL;

    if (the_rsc == NULL) {
        return -ENXIO;
    }

    if (g_list_length(the_rsc->running_on) == 1) {
        current = the_rsc->running_on->data;

    } else if (g_list_length(the_rsc->running_on) > 1) {
        CMD_ERR("%s is active on more than one node,"
                " returning the default value for %s\n", the_rsc->id, crm_str(value));
    }

    params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                   g_hash_destroy_str, g_hash_destroy_str);

    if (safe_str_eq(attr_set_type, XML_TAG_ATTR_SETS)) {
        get_rsc_attributes(params, the_rsc, current, data_set);
    } else if (safe_str_eq(attr_set_type, XML_TAG_META_SETS)) {
        get_meta_attributes(params, the_rsc, current, data_set);
    } else {
        unpack_instance_attributes(data_set->input, the_rsc->xml, XML_TAG_UTILIZATION, NULL,
                                   params, NULL, FALSE, data_set->now);
    }

    crm_debug("Looking up %s in %s", attr, the_rsc->id);
    value = g_hash_table_lookup(params, attr);
    if (value != NULL) {
        fprintf(stdout, "%s\n", value);
        rc = 0;

    } else {
        CMD_ERR("Attribute '%s' not found for '%s'\n", attr, the_rsc->id);
    }

    g_hash_table_destroy(params);
    return rc;
}

static int
find_resource_attr(cib_t * the_cib, const char *attr, const char *rsc, const char *set_type,
                   const char *set_name, const char *attr_id, const char *attr_name, char **value)
{
    int offset = 0;
    static int xpath_max = 1024;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;
    char *xpath_string = NULL;

    CRM_ASSERT(value != NULL);
    *value = NULL;

    if(the_cib == NULL) {
        return -ENOTCONN;
    }

    xpath_string = calloc(1, xpath_max);
    offset +=
        snprintf(xpath_string + offset, xpath_max - offset, "%s", get_object_path("resources"));

    offset += snprintf(xpath_string + offset, xpath_max - offset, "//*[@id=\"%s\"]", rsc);

    if (set_type) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "/%s", set_type);
        if (set_name) {
            offset += snprintf(xpath_string + offset, xpath_max - offset, "[@id=\"%s\"]", set_name);
        }
    }

    offset += snprintf(xpath_string + offset, xpath_max - offset, "//nvpair[");
    if (attr_id) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "@id=\"%s\"", attr_id);
    }

    if (attr_name) {
        if (attr_id) {
            offset += snprintf(xpath_string + offset, xpath_max - offset, " and ");
        }
        offset += snprintf(xpath_string + offset, xpath_max - offset, "@name=\"%s\"", attr_name);
    }
    offset += snprintf(xpath_string + offset, xpath_max - offset, "]");
    CRM_LOG_ASSERT(offset > 0);

    rc = the_cib->cmds->query(the_cib, xpath_string, &xml_search,
                              cib_sync_call | cib_scope_local | cib_xpath);

    if (rc != pcmk_ok) {
        goto bail;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_has_children(xml_search)) {
        xmlNode *child = NULL;

        rc = -EINVAL;
        printf("Multiple attributes match name=%s\n", attr_name);

        for (child = __xml_first_child(xml_search); child != NULL; child = __xml_next(child)) {
            printf("  Value: %s \t(id=%s)\n",
                   crm_element_value(child, XML_NVPAIR_ATTR_VALUE), ID(child));
        }

    } else {
        const char *tmp = crm_element_value(xml_search, attr);

        if (tmp) {
            *value = strdup(tmp);
        }
    }

  bail:
    free(xpath_string);
    free_xml(xml_search);
    return rc;
}

#include "../pengine/pengine.h"


static int
set_resource_attr(const char *rsc_id, const char *attr_set, const char *attr_id,
                  const char *attr_name, const char *attr_value, bool recursive,
                  cib_t * cib, pe_working_set_t * data_set)
{
    int rc = pcmk_ok;
    static bool need_init = TRUE;

    char *local_attr_id = NULL;
    char *local_attr_set = NULL;

    xmlNode *xml_top = NULL;
    xmlNode *xml_obj = NULL;

    gboolean use_attributes_tag = FALSE;
    resource_t *rsc = find_rsc_or_clone(rsc_id, data_set);

    if (rsc == NULL) {
        return -ENXIO;
    }

    if (safe_str_eq(attr_set_type, XML_TAG_ATTR_SETS)) {
        rc = find_resource_attr(cib, XML_ATTR_ID, rsc_id, XML_TAG_META_SETS, attr_set, attr_id,
                                attr_name, &local_attr_id);
        if (rc == pcmk_ok) {
            printf("WARNING: There is already a meta attribute called %s (id=%s)\n", attr_name,
                   local_attr_id);
        }
    }
    rc = find_resource_attr(cib, XML_ATTR_ID, rsc_id, attr_set_type, attr_set, attr_id, attr_name,
                            &local_attr_id);

    if (rc == pcmk_ok) {
        crm_debug("Found a match for name=%s: id=%s", attr_name, local_attr_id);
        attr_id = local_attr_id;

    } else if (rc != -ENXIO) {
        free(local_attr_id);
        return rc;

    } else {
        const char *value = NULL;
        xmlNode *cib_top = NULL;
        const char *tag = crm_element_name(rsc->xml);

        cib->cmds->query(cib, "/cib", &cib_top,
                              cib_sync_call | cib_scope_local | cib_xpath | cib_no_children);
        value = crm_element_value(cib_top, "ignore_dtd");
        if (value != NULL) {
            use_attributes_tag = TRUE;

        } else {
            value = crm_element_value(cib_top, XML_ATTR_VALIDATION);
            if (value && strstr(value, "-0.6")) {
                use_attributes_tag = TRUE;
            }
        }
        free_xml(cib_top);

        if (attr_set == NULL) {
            local_attr_set = crm_concat(rsc_id, attr_set_type, '-');
            attr_set = local_attr_set;
        }
        if (attr_id == NULL) {
            local_attr_id = crm_concat(attr_set, attr_name, '-');
            attr_id = local_attr_id;
        }

        if (use_attributes_tag && safe_str_eq(tag, XML_CIB_TAG_MASTER)) {
            tag = "master_slave";       /* use the old name */
        }

        xml_top = create_xml_node(NULL, tag);
        crm_xml_add(xml_top, XML_ATTR_ID, rsc_id);

        xml_obj = create_xml_node(xml_top, attr_set_type);
        crm_xml_add(xml_obj, XML_ATTR_ID, attr_set);

        if (use_attributes_tag) {
            xml_obj = create_xml_node(xml_obj, XML_TAG_ATTRS);
        }
    }

    xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
    if (xml_top == NULL) {
        xml_top = xml_obj;
    }

    crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);

    crm_log_xml_debug(xml_top, "Update");

    rc = cib->cmds->modify(cib, XML_CIB_TAG_RESOURCES, xml_top, cib_options);
    free_xml(xml_top);
    free(local_attr_id);
    free(local_attr_set);

    if(recursive && safe_str_eq(attr_set_type, XML_TAG_META_SETS)) {
        GListPtr lpc = NULL;

        if(need_init) {
            xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set->input);

            need_init = FALSE;
            unpack_constraints(cib_constraints, data_set);

            for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
                resource_t *r = (resource_t *) lpc->data;

                clear_bit(r->flags, pe_rsc_allocating);
            }
        }

        crm_debug("Looking for dependancies %p", rsc->rsc_cons_lhs);
        set_bit(rsc->flags, pe_rsc_allocating);
        for (lpc = rsc->rsc_cons_lhs; lpc != NULL; lpc = lpc->next) {
            rsc_colocation_t *cons = (rsc_colocation_t *) lpc->data;
            resource_t *peer = cons->rsc_lh;

            crm_debug("Checking %s %d", cons->id, cons->score);
            if (cons->score > 0 && is_not_set(peer->flags, pe_rsc_allocating)) {
                /* Don't get into colocation loops */
                crm_debug("Setting %s=%s for dependant resource %s", attr_name, attr_value, peer->id);
                set_resource_attr(peer->id, NULL, NULL, attr_name, attr_value, recursive, cib, data_set);
            }
        }
    }

    return rc;
}

static int
delete_resource_attr(const char *rsc_id, const char *attr_set, const char *attr_id,
                     const char *attr_name, cib_t * cib, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;

    int rc = pcmk_ok;
    char *local_attr_id = NULL;
    resource_t *rsc = find_rsc_or_clone(rsc_id, data_set);

    if (rsc == NULL) {
        return -ENXIO;
    }

    rc = find_resource_attr(cib, XML_ATTR_ID, rsc_id, attr_set_type, attr_set, attr_id, attr_name,
                            &local_attr_id);

    if (rc == -ENXIO) {
        return pcmk_ok;

    } else if (rc != pcmk_ok) {
        return rc;
    }

    if (attr_id == NULL) {
        attr_id = local_attr_id;
    }

    xml_obj = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
    crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);

    crm_log_xml_debug(xml_obj, "Delete");

    CRM_ASSERT(cib);
    rc = cib->cmds->delete(cib, XML_CIB_TAG_RESOURCES, xml_obj, cib_options);

    if (rc == pcmk_ok) {
        printf("Deleted %s option: id=%s%s%s%s%s\n", rsc_id, local_attr_id,
               attr_set ? " set=" : "", attr_set ? attr_set : "",
               attr_name ? " name=" : "", attr_name ? attr_name : "");
    }

    free_xml(xml_obj);
    free(local_attr_id);
    return rc;
}

static int
dump_resource_prop(const char *rsc, const char *attr, pe_working_set_t * data_set)
{
    const char *value = NULL;
    resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);

    if (the_rsc == NULL) {
        return -ENXIO;
    }

    value = crm_element_value(the_rsc->xml, attr);

    if (value != NULL) {
        fprintf(stdout, "%s\n", value);
        return 0;
    }
    return -ENXIO;
}

static int
send_lrm_rsc_op(crm_ipc_t * crmd_channel, const char *op,
                const char *host_uname, const char *rsc_id,
                gboolean only_failed, pe_working_set_t * data_set)
{
    char *key = NULL;
    int rc = -ECOMM;
    xmlNode *cmd = NULL;
    xmlNode *xml_rsc = NULL;
    const char *value = NULL;
    const char *router_node = host_uname;
    xmlNode *params = NULL;
    xmlNode *msg_data = NULL;
    resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

    if (rsc == NULL) {
        CMD_ERR("Resource %s not found\n", rsc_id);
        return -ENXIO;

    } else if (rsc->variant != pe_native) {
        CMD_ERR("We can only process primitive resources, not %s\n", rsc_id);
        return -EINVAL;

    } else if (host_uname == NULL) {
        CMD_ERR("Please supply a hostname with -H\n");
        return -EINVAL;
    } else {
        node_t *node = pe_find_node(data_set->nodes, host_uname);

        if (node && is_remote_node(node)) {
            if (node->details->remote_rsc == NULL || node->details->remote_rsc->running_on == NULL) {
                CMD_ERR("No lrmd connection detected to remote node %s", host_uname);
                return -ENXIO;
            }
            node = node->details->remote_rsc->running_on->data;
            router_node = node->details->uname;
        }
    }

    key = generate_transition_key(0, getpid(), 0, "xxxxxxxx-xrsc-opxx-xcrm-resourcexxxx");

    msg_data = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
    crm_xml_add(msg_data, XML_ATTR_TRANSITION_KEY, key);
    free(key);

    crm_xml_add(msg_data, XML_LRM_ATTR_TARGET, host_uname);
    if (safe_str_neq(router_node, host_uname)) {
        crm_xml_add(msg_data, XML_LRM_ATTR_ROUTER_NODE, router_node);
    }

    xml_rsc = create_xml_node(msg_data, XML_CIB_TAG_RESOURCE);
    if (rsc->clone_name) {
        crm_xml_add(xml_rsc, XML_ATTR_ID, rsc->clone_name);
        crm_xml_add(xml_rsc, XML_ATTR_ID_LONG, rsc->id);

    } else {
        crm_xml_add(xml_rsc, XML_ATTR_ID, rsc->id);
    }

    value = crm_element_value(rsc->xml, XML_ATTR_TYPE);
    crm_xml_add(xml_rsc, XML_ATTR_TYPE, value);
    if (value == NULL) {
        CMD_ERR("%s has no type!  Aborting...\n", rsc_id);
        return -ENXIO;
    }

    value = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    crm_xml_add(xml_rsc, XML_AGENT_ATTR_CLASS, value);
    if (value == NULL) {
        CMD_ERR("%s has no class!  Aborting...\n", rsc_id);
        return -ENXIO;
    }

    value = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    crm_xml_add(xml_rsc, XML_AGENT_ATTR_PROVIDER, value);

    params = create_xml_node(msg_data, XML_TAG_ATTRS);
    crm_xml_add(params, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    key = crm_meta_name(XML_LRM_ATTR_INTERVAL);
    crm_xml_add(params, key, "60000");  /* 1 minute */
    free(key);

    cmd = create_request(op, msg_data, router_node, CRM_SYSTEM_CRMD, crm_system_name, our_pid);

/* 	crm_log_xml_warn(cmd, "send_lrm_rsc_op"); */
    free_xml(msg_data);

    if (crm_ipc_send(crmd_channel, cmd, 0, 0, NULL) > 0) {
        rc = 0;

    } else {
        CMD_ERR("Could not send %s op to the crmd", op);
        rc = -ENOTCONN;
    }

    free_xml(cmd);
    return rc;
}

static int
delete_lrm_rsc(cib_t *cib_conn, crm_ipc_t * crmd_channel, const char *host_uname,
               resource_t * rsc, pe_working_set_t * data_set)
{
    int rc = pcmk_ok;
    node_t *node = NULL;

    if (rsc == NULL) {
        return -ENXIO;

    } else if (rsc->children) {
        GListPtr lpc = NULL;

        for (lpc = rsc->children; lpc != NULL; lpc = lpc->next) {
            resource_t *child = (resource_t *) lpc->data;

            delete_lrm_rsc(cib_conn, crmd_channel, host_uname, child, data_set);
        }
        return pcmk_ok;

    } else if (host_uname == NULL) {
        GListPtr lpc = NULL;

        for (lpc = data_set->nodes; lpc != NULL; lpc = lpc->next) {
            node = (node_t *) lpc->data;

            if (node->details->online) {
                delete_lrm_rsc(cib_conn, crmd_channel, node->details->uname, rsc, data_set);
            }
        }

        return pcmk_ok;
    }

    node = pe_find_node(data_set->nodes, host_uname);

    if (node && node->details->rsc_discovery_enabled) {
        printf("Cleaning up %s on %s\n", rsc->id, host_uname);
        rc = send_lrm_rsc_op(crmd_channel, CRM_OP_LRM_DELETE, host_uname, rsc->id, TRUE, data_set);
    } else {
        printf("Resource discovery disabled on %s. Unable to delete lrm state.\n", host_uname);
    }

    if (rc == pcmk_ok) {
        char *attr_name = NULL;
        const char *id = rsc->id;

        if(node && node->details->remote_rsc == NULL && node->details->rsc_discovery_enabled) {
            crmd_replies_needed++;
        }
        if (rsc->clone_name) {
            id = rsc->clone_name;
        }

        attr_name = crm_concat("fail-count", id, '-');
        rc = attrd_update_delegate(NULL, 'D', host_uname, attr_name, NULL, XML_CIB_TAG_STATUS, NULL,
                              NULL, NULL, node ? is_remote_node(node) : FALSE);
        free(attr_name);
    }
    return rc;
}

static int
fail_lrm_rsc(crm_ipc_t * crmd_channel, const char *host_uname,
             const char *rsc_id, pe_working_set_t * data_set)
{
    crm_warn("Failing: %s", rsc_id);
    return send_lrm_rsc_op(crmd_channel, CRM_OP_LRM_FAIL, host_uname, rsc_id, FALSE, data_set);
}

static char *
parse_cli_lifetime(const char *input)
{
    char *later_s = NULL;
    crm_time_t *now = NULL;
    crm_time_t *later = NULL;
    crm_time_t *duration = NULL;

    if (input == NULL) {
        return NULL;
    }

    duration = crm_time_parse_duration(move_lifetime);
    if (duration == NULL) {
        CMD_ERR("Invalid duration specified: %s\n", move_lifetime);
        CMD_ERR("Please refer to"
                " http://en.wikipedia.org/wiki/ISO_8601#Durations"
                " for examples of valid durations\n");
        return NULL;
    }

    now = crm_time_new(NULL);
    later = crm_time_add(now, duration);
    crm_time_log(LOG_INFO, "now     ", now,
                 crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_log(LOG_INFO, "later   ", later,
                 crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_log(LOG_INFO, "duration", duration, crm_time_log_date | crm_time_log_timeofday);
    later_s = crm_time_as_string(later, crm_time_log_date | crm_time_log_timeofday);
    printf("Migration will take effect until: %s\n", later_s);

    crm_time_free(duration);
    crm_time_free(later);
    crm_time_free(now);
    return later_s;
}

static int
ban_resource(const char *rsc_id, const char *host, GListPtr allnodes, cib_t * cib_conn)
{
    char *later_s = NULL;
    int rc = pcmk_ok;
    char *id = NULL;
    xmlNode *fragment = NULL;
    xmlNode *location = NULL;

    if(host == NULL) {
        GListPtr n = allnodes;
        for(; n && rc == pcmk_ok; n = n->next) {
            node_t *target = n->data;

            rc = ban_resource(rsc_id, target->details->uname, NULL, cib_conn);
        }
        return rc;
    }

    later_s = parse_cli_lifetime(move_lifetime);
    if(move_lifetime && later_s == NULL) {
        return -EINVAL;
    }

    fragment = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINTS);

    id = g_strdup_printf("cli-ban-%s-on-%s", rsc_id, host);
    location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
    crm_xml_add(location, XML_ATTR_ID, id);
    free(id);

    if (BE_QUIET == FALSE) {
        CMD_ERR("WARNING: Creating rsc_location constraint '%s'"
                " with a score of -INFINITY for resource %s"
                " on %s.\n", ID(location), rsc_id, host);
        CMD_ERR("\tThis will prevent %s from %s"
                " on %s until the constraint is removed using"
                " the 'crm_resource --clear' command or manually"
                " with cibadmin\n", rsc_id, scope_master?"being promoted":"running", host);
        CMD_ERR("\tThis will be the case even if %s is"
                " the last node in the cluster\n", host);
        CMD_ERR("\tThis message can be disabled with --quiet\n");
    }

    crm_xml_add(location, XML_COLOC_ATTR_SOURCE, rsc_id);
    if(scope_master) {
        crm_xml_add(location, XML_RULE_ATTR_ROLE, RSC_ROLE_MASTER_S);
    } else {
        crm_xml_add(location, XML_RULE_ATTR_ROLE, RSC_ROLE_STARTED_S);
    }

    if (later_s == NULL) {
        /* Short form */
        crm_xml_add(location, XML_CIB_TAG_NODE, host);
        crm_xml_add(location, XML_RULE_ATTR_SCORE, MINUS_INFINITY_S);

    } else {
        xmlNode *rule = create_xml_node(location, XML_TAG_RULE);
        xmlNode *expr = create_xml_node(rule, XML_TAG_EXPRESSION);

        id = g_strdup_printf("cli-ban-%s-on-%s-rule", rsc_id, host);
        crm_xml_add(rule, XML_ATTR_ID, id);
        free(id);

        crm_xml_add(rule, XML_RULE_ATTR_SCORE, MINUS_INFINITY_S);
        crm_xml_add(rule, XML_RULE_ATTR_BOOLEAN_OP, "and");

        id = g_strdup_printf("cli-ban-%s-on-%s-expr", rsc_id, host);
        crm_xml_add(expr, XML_ATTR_ID, id);
        free(id);

        crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, "#uname");
        crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
        crm_xml_add(expr, XML_EXPR_ATTR_VALUE, host);
        crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");

        expr = create_xml_node(rule, "date_expression");
        id = g_strdup_printf("cli-ban-%s-on-%s-lifetime", rsc_id, host);
        crm_xml_add(expr, XML_ATTR_ID, id);
        free(id);

        crm_xml_add(expr, "operation", "lt");
        crm_xml_add(expr, "end", later_s);
    }

    crm_log_xml_notice(fragment, "Modify");
    rc = cib_conn->cmds->update(cib_conn, XML_CIB_TAG_CONSTRAINTS, fragment, cib_options);

    free_xml(fragment);
    free(later_s);
    return rc;
}

static int
prefer_resource(const char *rsc_id, const char *host, cib_t * cib_conn)
{
    char *later_s = parse_cli_lifetime(move_lifetime);
    int rc = pcmk_ok;
    char *id = NULL;
    xmlNode *location = NULL;
    xmlNode *fragment = NULL;

    if(move_lifetime && later_s == NULL) {
        return -EINVAL;
    }

    if(cib_conn == NULL) {
        free(later_s);
        return -ENOTCONN;
    }

    fragment = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINTS);

    id = g_strdup_printf("cli-prefer-%s", rsc_id);
    location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
    crm_xml_add(location, XML_ATTR_ID, id);
    free(id);

    crm_xml_add(location, XML_COLOC_ATTR_SOURCE, rsc_id);
    if(scope_master) {
        crm_xml_add(location, XML_RULE_ATTR_ROLE, RSC_ROLE_MASTER_S);
    } else {
        crm_xml_add(location, XML_RULE_ATTR_ROLE, RSC_ROLE_STARTED_S);
    }

    if (later_s == NULL) {
        /* Short form */
        crm_xml_add(location, XML_CIB_TAG_NODE, host);
        crm_xml_add(location, XML_RULE_ATTR_SCORE, INFINITY_S);

    } else {
        xmlNode *rule = create_xml_node(location, XML_TAG_RULE);
        xmlNode *expr = create_xml_node(rule, XML_TAG_EXPRESSION);

        id = crm_concat("cli-prefer-rule", rsc_id, '-');
        crm_xml_add(rule, XML_ATTR_ID, id);
        free(id);

        crm_xml_add(rule, XML_RULE_ATTR_SCORE, INFINITY_S);
        crm_xml_add(rule, XML_RULE_ATTR_BOOLEAN_OP, "and");

        id = crm_concat("cli-prefer-expr", rsc_id, '-');
        crm_xml_add(expr, XML_ATTR_ID, id);
        free(id);

        crm_xml_add(expr, XML_EXPR_ATTR_ATTRIBUTE, "#uname");
        crm_xml_add(expr, XML_EXPR_ATTR_OPERATION, "eq");
        crm_xml_add(expr, XML_EXPR_ATTR_VALUE, host);
        crm_xml_add(expr, XML_EXPR_ATTR_TYPE, "string");

        expr = create_xml_node(rule, "date_expression");
        id = crm_concat("cli-prefer-lifetime-end", rsc_id, '-');
        crm_xml_add(expr, XML_ATTR_ID, id);
        free(id);

        crm_xml_add(expr, "operation", "lt");
        crm_xml_add(expr, "end", later_s);
    }

    crm_log_xml_info(fragment, "Modify");
    rc = cib_conn->cmds->update(cib_conn, XML_CIB_TAG_CONSTRAINTS, fragment, cib_options);

    free_xml(fragment);
    free(later_s);
    return rc;
}

static int
clear_resource(const char *rsc_id, const char *host, GListPtr allnodes, cib_t * cib_conn)
{
    char *id = NULL;
    int rc = pcmk_ok;
    xmlNode *fragment = NULL;
    xmlNode *location = NULL;

    if(cib_conn == NULL) {
        return -ENOTCONN;
    }

    fragment = create_xml_node(NULL, XML_CIB_TAG_CONSTRAINTS);

    if(host) {
        id = g_strdup_printf("cli-ban-%s-on-%s", rsc_id, host);
        location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
        crm_xml_add(location, XML_ATTR_ID, id);
        free(id);

    } else {
        GListPtr n = allnodes;
        for(; n; n = n->next) {
            node_t *target = n->data;

            id = g_strdup_printf("cli-ban-%s-on-%s", rsc_id, target->details->uname);
            location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
            crm_xml_add(location, XML_ATTR_ID, id);
            free(id);
        }
    }

    id = g_strdup_printf("cli-prefer-%s", rsc_id);
    location = create_xml_node(fragment, XML_CONS_TAG_RSC_LOCATION);
    crm_xml_add(location, XML_ATTR_ID, id);
    if(host && do_force == FALSE) {
        crm_xml_add(location, XML_CIB_TAG_NODE, host);
    }
    free(id);

    crm_log_xml_info(fragment, "Delete");
    rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_CONSTRAINTS, fragment, cib_options);
    if (rc == -ENXIO) {
        rc = pcmk_ok;

    } else if (rc != pcmk_ok) {
        goto bail;
    }

  bail:
    free_xml(fragment);
    return rc;
}

static int
list_resource_operations(const char *rsc_id, const char *host_uname, gboolean active,
                         pe_working_set_t * data_set)
{
    resource_t *rsc = NULL;
    int opts = pe_print_printf | pe_print_rsconly | pe_print_suppres_nl;
    GListPtr ops = find_operations(rsc_id, host_uname, active, data_set);
    GListPtr lpc = NULL;

    if (print_pending) {
        opts |= pe_print_pending;
    }

    for (lpc = ops; lpc != NULL; lpc = lpc->next) {
        xmlNode *xml_op = (xmlNode *) lpc->data;

        const char *op_rsc = crm_element_value(xml_op, "resource");
        const char *last = crm_element_value(xml_op, XML_RSC_OP_LAST_CHANGE);
        const char *status_s = crm_element_value(xml_op, XML_LRM_ATTR_OPSTATUS);
        const char *op_key = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
        int status = crm_parse_int(status_s, "0");

        rsc = pe_find_resource(data_set->resources, op_rsc);
        if(rsc) {
            rsc->fns->print(rsc, "", opts, stdout);
        } else {
            fprintf(stdout, "Unknown resource %s", op_rsc);
        }

        fprintf(stdout, ": %s (node=%s, call=%s, rc=%s",
                op_key ? op_key : ID(xml_op),
                crm_element_value(xml_op, XML_ATTR_UNAME),
                crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                crm_element_value(xml_op, XML_LRM_ATTR_RC));
        if (last) {
            time_t run_at = crm_parse_int(last, "0");

            fprintf(stdout, ", last-rc-change=%s, exec=%sms",
                    crm_strip_trailing_newline(ctime(&run_at)), crm_element_value(xml_op, XML_RSC_OP_T_EXEC));
        }
        fprintf(stdout, "): %s\n", services_lrm_status_str(status));
    }
    return pcmk_ok;
}

static void
show_location(resource_t * rsc, const char *prefix)
{
    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_location;
    int offset = 0;

    if (prefix) {
        offset = strlen(prefix) - 2;
    }

    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        rsc_to_node_t *cons = (rsc_to_node_t *) lpc->data;

        GListPtr lpc2 = NULL;

        for (lpc2 = cons->node_list_rh; lpc2 != NULL; lpc2 = lpc2->next) {
            node_t *node = (node_t *) lpc2->data;
            char *score = score2char(node->weight);

            fprintf(stdout, "%s: Node %-*s (score=%s, id=%s)\n",
                    prefix ? prefix : "  ", 71 - offset, node->details->uname, score, cons->id);
            free(score);
        }
    }
}

static void
show_colocation(resource_t * rsc, gboolean dependants, gboolean recursive, int offset)
{
    char *prefix = NULL;
    GListPtr lpc = NULL;
    GListPtr list = rsc->rsc_cons;

    prefix = calloc(1, (offset * 4) + 1);
    memset(prefix, ' ', offset * 4);

    if (dependants) {
        list = rsc->rsc_cons_lhs;
    }

    if (is_set(rsc->flags, pe_rsc_allocating)) {
        /* Break colocation loops */
        printf("loop %s\n", rsc->id);
        free(prefix);
        return;
    }

    set_bit(rsc->flags, pe_rsc_allocating);
    for (lpc = list; lpc != NULL; lpc = lpc->next) {
        rsc_colocation_t *cons = (rsc_colocation_t *) lpc->data;

        char *score = NULL;
        resource_t *peer = cons->rsc_rh;

        if (dependants) {
            peer = cons->rsc_lh;
        }

        if (is_set(peer->flags, pe_rsc_allocating)) {
            if (dependants == FALSE) {
                fprintf(stdout, "%s%-*s (id=%s - loop)\n", prefix, 80 - (4 * offset), peer->id,
                        cons->id);
            }
            continue;
        }

        if (dependants && recursive) {
            show_colocation(peer, dependants, recursive, offset + 1);
        }

        score = score2char(cons->score);
        if (cons->role_rh > RSC_ROLE_STARTED) {
            fprintf(stdout, "%s%-*s (score=%s, %s role=%s, id=%s)\n", prefix, 80 - (4 * offset),
                    peer->id, score, dependants ? "needs" : "with", role2text(cons->role_rh),
                    cons->id);
        } else {
            fprintf(stdout, "%s%-*s (score=%s, id=%s)\n", prefix, 80 - (4 * offset),
                    peer->id, score, cons->id);
        }
        show_location(peer, prefix);
        free(score);

        if (!dependants && recursive) {
            show_colocation(peer, dependants, recursive, offset + 1);
        }
    }
    free(prefix);
}

static GHashTable *
generate_resource_params(resource_t * rsc, pe_working_set_t * data_set)
{
    GHashTable *params = NULL;
    GHashTable *meta = NULL;
    GHashTable *combined = NULL;
    GHashTableIter iter;

    if (!rsc) {
        crm_err("Resource does not exist in config");
        return NULL;
    }

    params =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);
    meta = g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);
    combined =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    get_rsc_attributes(params, rsc, NULL /* TODO: Pass in local node */ , data_set);
    get_meta_attributes(meta, rsc, NULL /* TODO: Pass in local node */ , data_set);

    if (params) {
        char *key = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            g_hash_table_insert(combined, strdup(key), strdup(value));
        }
        g_hash_table_destroy(params);
    }

    if (meta) {
        char *key = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, meta);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            char *crm_name = crm_meta_name(key);

            g_hash_table_insert(combined, crm_name, strdup(value));
        }
        g_hash_table_destroy(meta);
    }

    return combined;
}

static bool resource_is_running_on(resource_t *rsc, const char *host) 
{
    bool found = TRUE;
    GListPtr hIter = NULL;
    GListPtr hosts = NULL;

    if(rsc == NULL) {
        return FALSE;
    }

    rsc->fns->location(rsc, &hosts, TRUE);
    for (hIter = hosts; host != NULL && hIter != NULL; hIter = hIter->next) {
        pe_node_t *node = (pe_node_t *) hIter->data;

        if(strcmp(host, node->details->uname) == 0) {
            crm_trace("Resource %s is running on %s\n", rsc->id, host);
            goto done;
        } else if(strcmp(host, node->details->id) == 0) {
            crm_trace("Resource %s is running on %s\n", rsc->id, host);
            goto done;
        }
    }

    if(host != NULL) {
        crm_trace("Resource %s is not running on: %s\n", rsc->id, host);
        found = FALSE;

    } else if(host == NULL && hosts == NULL) {
        crm_trace("Resource %s is not running\n", rsc->id);
        found = FALSE;
    }

  done:

    g_list_free(hosts);
    return found;
}

static GList *get_active_resources(const char *host, pe_working_set_t *data_set) 
{
    GList *rIter = NULL;
    GList *active = NULL;

    for (rIter = data_set->resources; rIter != NULL; rIter = rIter->next) {
        resource_t *rsc = (resource_t *) rIter->data;

        if(resource_is_running_on(rsc, host)) {
            active = g_list_append(active, strdup(rsc->id));
        }
    }

    return active;
}

static GList *subtract_lists(GList *from, GList *items) 
{
    GList *item = NULL;
    GList *result = g_list_copy(from);

    for (item = items; item != NULL; item = item->next) {
        GList *candidate = NULL;
        for (candidate = from; candidate != NULL; candidate = candidate->next) {
            crm_info("Comparing %s with %s", candidate->data, item->data);
            if(strcmp(candidate->data, item->data) == 0) {
                result = g_list_remove(result, candidate->data);
                break;
            }
        }
    }

    return result;
}

static void dump_list(GList *items, const char *tag) 
{
    int lpc = 0;
    GList *item = NULL;

    for (item = items; item != NULL; item = item->next) {
        crm_trace("%s[%d]: %s", tag, lpc, item->data);
        lpc++;
    }
}

static void display_list(GList *items, const char *tag) 
{
    GList *item = NULL;

    for (item = items; item != NULL; item = item->next) {
        fprintf(stdout, "%s%s\n", tag, (const char *)item->data);
    }
}

static int
update_dataset(cib_t *cib, pe_working_set_t * data_set, bool simulate)
{
    char *pid = NULL;
    char *shadow_file = NULL;
    cib_t *shadow_cib = NULL;
    xmlNode *cib_xml_copy = NULL;
    int rc = cib->cmds->query(cib, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);

    if(rc != pcmk_ok) {
        fprintf(stdout, "Could not obtain the current CIB: %s (%d)\n", pcmk_strerror(rc), rc);
        goto cleanup;

    } else if (cli_config_update(&cib_xml_copy, NULL, FALSE) == FALSE) {
        fprintf(stderr, "Could not upgrade the current CIB\n");
        rc = -ENOKEY;
        goto cleanup;
    }

    set_working_set_defaults(data_set);
    data_set->input = cib_xml_copy;
    data_set->now = crm_time_new(NULL);

    if(simulate) {
        pid = crm_itoa(getpid());
        shadow_cib = cib_shadow_new(pid);
        shadow_file = get_shadow_file(pid);

        if (shadow_cib == NULL) {
            fprintf(stderr, "Could not create shadow cib: '%s'\n", pid);
            rc = -ENXIO;
            goto cleanup;
        }

        free(pid);
        rc = write_xml_file(cib_xml_copy, shadow_file, FALSE);

        if (rc < 0) {
            fprintf(stderr, "Could not populate shadow cib: %s (%d)\n", pcmk_strerror(rc), rc);
            goto cleanup;
        }

        rc = shadow_cib->cmds->signon(shadow_cib, crm_system_name, cib_command);
        if(rc != pcmk_ok) {
            fprintf(stderr, "Could not connect to shadow cib: %s (%d)\n", pcmk_strerror(rc), rc);
            goto cleanup;
        }

        do_calculations(data_set, cib_xml_copy, NULL);
        run_simulation(data_set, shadow_cib, NULL, TRUE);
        rc = update_dataset(shadow_cib, data_set, FALSE);

    } else {
        cluster_status(data_set);
    }

  cleanup:
    cib_delete(shadow_cib);
    free_xml(cib_xml_copy);
    free(pid);

    if(shadow_file) {
        unlink(shadow_file);
        free(shadow_file);
    }

    return rc;
}

static int
max_delay_for_resource(pe_working_set_t * data_set, resource_t *rsc) 
{
    int delay = 0;
    int max_delay = 0;

    if(rsc && rsc->children) {
        GList *iter = NULL;

        for(iter = rsc->children; iter; iter = iter->next) {
            resource_t *child = (resource_t *)iter->data;

            delay = max_delay_for_resource(data_set, child);
            if(delay > max_delay) {
                double seconds = delay / 1000;
                crm_trace("Calculated new delay of %.1fs due to %s", seconds, child->id);
                max_delay = delay;
            }
        }

    } else if(rsc) {
        char *key = g_strdup_printf("%s_%s_0", rsc->id, RSC_STOP);
        action_t *stop = custom_action(rsc, key, RSC_STOP, NULL, TRUE, FALSE, data_set);
        const char *value = g_hash_table_lookup(stop->meta, XML_ATTR_TIMEOUT);

        max_delay = crm_int_helper(value, NULL);
        pe_free_action(stop);
    }


    return max_delay;
}

static int
max_delay_in(pe_working_set_t * data_set, GList *resources) 
{
    int max_delay = 0;
    GList *item = NULL;

    for (item = resources; item != NULL; item = item->next) {
        int delay = 0;
        resource_t *rsc = pe_find_resource(data_set->resources, (const char *)item->data);

        delay = max_delay_for_resource(data_set, rsc);

        if(delay > max_delay) {
            double seconds = delay / 1000;
            crm_trace("Calculated new delay of %.1fs due to %s", seconds, rsc->id);
            max_delay = delay;
        }
    }

    return 5 + (max_delay / 1000);
}

static int
resource_restart(resource_t * rsc, const char *host, int timeout_ms, cib_t * cib)
{
    int rc = 0;
    int lpc = 0;
    int before = 0;
    int step_timeout_s = 0;
    int sleep_interval = 2;
    int timeout = timeout_ms / 1000;

    bool is_clone = FALSE;
    char *rsc_id = NULL;

    GList *list_delta = NULL;
    GList *target_active = NULL;
    GList *current_active = NULL;
    GList *restart_target_active = NULL;

    pe_working_set_t data_set;

    if(resource_is_running_on(rsc, host) == FALSE) {
        return -ENXIO;
    }

    attr_set_type = XML_TAG_META_SETS;
    rsc_id = strdup(rsc->id);
    if(rsc->variant > pe_group) {
        is_clone = TRUE;
    }

    /*
      grab full cib
      determine resource state of list
      disable or ban
      poll and and watch for resources to get stopped
      without --wait, calculate the stop timeout for each step and wait for that
      if we hit --wait or the service timeout, re-enable or un-ban, report failure and indicate which resources we couldn't take down
      if everything stopped, re-enable or un-ban
      poll and and watch for resources to get stopped
      without --wait, calculate the start timeout for each step and wait for that
      if we hit --wait or the service timeout, report (different) failure and indicate which resources we couldn't bring back up
      report success

      Optimizations:
      - use constraints to determine ordered list of affected resources
      - Allow a --no-deps option (aka. --force-restart)
    */


    set_working_set_defaults(&data_set);
    rc = update_dataset(cib, &data_set, FALSE);
    if(rc != pcmk_ok) {
        fprintf(stdout, "Could not get new resource list: %s (%d)\n", pcmk_strerror(rc), rc);
        free(rsc_id);
        return rc;
    }

    restart_target_active = get_active_resources(host, &data_set);
    current_active = get_active_resources(host, &data_set);

    dump_list(current_active, "Origin");

    if(is_clone && host) {
        BE_QUIET = TRUE;
        rc = ban_resource(rsc_id, host, NULL, cib);

    } else {
        rc = set_resource_attr(rsc_id, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, RSC_STOPPED, FALSE, cib, &data_set);
    }
    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not set target-role for %s: %s (%d)\n", rsc_id, pcmk_strerror(rc), rc);
        free(rsc_id);
        return crm_exit(rc);
    }

    rc = update_dataset(cib, &data_set, TRUE);
    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not determine which resources would be stopped\n");
        goto failure;
    }

    target_active = get_active_resources(host, &data_set);
    dump_list(target_active, "Target");

    list_delta = subtract_lists(current_active, target_active);
    fprintf(stdout, "Waiting for %d resources to stop:\n", g_list_length(list_delta));
    display_list(list_delta, " * ");

    step_timeout_s = timeout / sleep_interval;
    while(g_list_length(list_delta) > 0) {
        before = g_list_length(list_delta);
        if(timeout_ms == 0) {
            step_timeout_s = max_delay_in(&data_set, list_delta) / sleep_interval;
        }

        /* We probably don't need the entire step timeout */
        for(lpc = 0; lpc < step_timeout_s && g_list_length(list_delta) > 0; lpc++) {
            sleep(sleep_interval);
            if(timeout) {
                timeout -= sleep_interval;
                crm_trace("%ds remaining", timeout);
            }
            rc = update_dataset(cib, &data_set, FALSE);
            if(rc != pcmk_ok) {
                fprintf(stderr, "Could not determine which resources were stopped\n");
                goto failure;
            }

            current_active = get_active_resources(host, &data_set);
            list_delta = subtract_lists(current_active, target_active);
            dump_list(current_active, "Current");
            dump_list(list_delta, "Delta");
        }

        crm_trace("%d (was %d) resources remaining", before, g_list_length(list_delta));
        if(before == g_list_length(list_delta)) {
            /* aborted during stop phase, print the contents of list_delta */
            fprintf(stderr, "Could not complete shutdown of %s, %d resources remaining\n", rsc_id, g_list_length(list_delta));
            display_list(list_delta, " * ");
            rc = -ETIME;
            goto failure;
        }

    }

    if(is_clone && host) {
        rc = clear_resource(rsc_id, host, NULL, cib);

    } else {
        rc = delete_resource_attr(rsc_id, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, cib, &data_set);
    }

    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not unset target-role for %s: %s (%d)\n", rsc_id, pcmk_strerror(rc), rc);
        free(rsc_id);
        return crm_exit(rc);
    }

    target_active = restart_target_active;
    list_delta = subtract_lists(target_active, current_active);
    fprintf(stdout, "Waiting for %d resources to start again:\n", g_list_length(list_delta));
    display_list(list_delta, " * ");

    step_timeout_s = timeout / sleep_interval;
    while(g_list_length(list_delta) > 0) {
        if(timeout_ms == 0) {
            step_timeout_s = max_delay_in(&data_set, list_delta) / sleep_interval;
        }

        /* We probably don't need the entire step timeout */
        for(lpc = 0; lpc < step_timeout_s && g_list_length(list_delta) > 0; lpc++) {
            sleep(sleep_interval);
            if(timeout) {
                timeout -= sleep_interval;
                crm_trace("%ds remaining", timeout);
            }

            rc = update_dataset(cib, &data_set, FALSE);
            if(rc != pcmk_ok) {
                fprintf(stderr, "Could not determine which resources were started\n");
                goto failure;
            }

            current_active = get_active_resources(host, &data_set);
            list_delta = subtract_lists(target_active, current_active);
            dump_list(current_active, "Current");
            dump_list(list_delta, "Delta");
        }

        if(before == g_list_length(list_delta)) {
            /* aborted during start phase, print the contents of list_delta */
            fprintf(stdout, "Could not complete restart of %s, %d resources remaining\n", rsc_id, g_list_length(list_delta));
            display_list(list_delta, " * ");
            rc = -ETIME;
            goto failure;
        }

    } while(g_list_length(list_delta) > 0);

    free(rsc_id);
    return pcmk_ok;

  failure:
    if(is_clone && host) {
        clear_resource(rsc_id, host, NULL, cib);

    } else {
        delete_resource_attr(rsc_id, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, cib, &data_set);
    }
    free(rsc_id);
    return rc;
}

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\t\tThis text"},
    {"version", 0, 0, '$', "\t\tVersion information"  },
    {"verbose", 0, 0, 'V', "\t\tIncrease debug output"},
    {"quiet",   0, 0, 'Q', "\t\tPrint only the value on stdout\n"},

    {"resource",   1, 0, 'r', "\tResource ID" },

    {"-spacer-",1, 0, '-', "\nQueries:"},
    {"list",       0, 0, 'L', "\t\tList all cluster resources"},
    {"list-raw",   0, 0, 'l', "\tList the IDs of all instantiated resources (no groups/clones/...)"},
    {"list-cts",   0, 0, 'c', NULL, 1},
    {"list-operations", 0, 0, 'O', "\tList active resource operations.  Optionally filtered by resource (-r) and/or node (-N)"},
    {"list-all-operations", 0, 0, 'o', "List all resource operations.  Optionally filtered by resource (-r) and/or node (-N)"},
    {"pending",    0, 0, 'j', "\t\tDisplay pending state if 'record-pending' is enabled\n"},

    {"list-standards",        0, 0, 0, "\tList supported standards"},
    {"list-ocf-providers",    0, 0, 0, "List all available OCF providers"},
    {"list-agents",           1, 0, 0, "List all agents available for the named standard and/or provider."},
    {"list-ocf-alternatives", 1, 0, 0, "List all available providers for the named OCF agent\n"},
    {"show-metadata",         1, 0, 0, "Show the metadata for the named class:provider:agent"},

    {"query-xml",  0, 0, 'q', "\tQuery the definition of a resource (template expanded)"},
    {"query-xml-raw",  0, 0, 'w', "\tQuery the definition of a resource (raw xml)"},
    {"locate",     0, 0, 'W', "\t\tDisplay the current location(s) of a resource"},
    {"stack",      0, 0, 'A', "\t\tDisplay the prerequisites and dependents of a resource"},
    {"constraints",0, 0, 'a', "\tDisplay the (co)location constraints that apply to a resource"},

    {"-spacer-",	1, 0, '-', "\nCommands:"},
    {"cleanup",         0, 0, 'C', "\t\tDelete the resource history and re-check the current state. Optional: --resource"},
    {"set-parameter",   1, 0, 'p', "Set the named parameter for a resource. See also -m, --meta"},
    {"get-parameter",   1, 0, 'g', "Display the named parameter for a resource. See also -m, --meta"},
    {"delete-parameter",1, 0, 'd', "Delete the named parameter for a resource. See also -m, --meta"},
    {"get-property",    1, 0, 'G', "Display the 'class', 'type' or 'provider' of a resource", 1},
    {"set-property",    1, 0, 'S', "(Advanced) Set the class, type or provider of a resource", 1},

    {"-spacer-",	1, 0, '-', "\nResource location:"},
    {
        "move",    0, 0, 'M',
        "\t\tMove a resource from its current location to the named destination.\n  "
        "\t\t\t\tRequires: --host. Optional: --lifetime, --master\n\n"
        "\t\t\t\tNOTE: This may prevent the resource from running on the previous location node until the implicit constraints expire or are removed with --unban\n"
    },
    {
        "ban",    0, 0, 'B',
        "\t\tPrevent the named resource from running on the named --host.  \n"
        "\t\t\t\tRequires: --resource. Optional: --host, --lifetime, --master\n\n"
        "\t\t\t\tIf --host is not specified, it defaults to:\n"
        "\t\t\t\t * the curent location for primitives and groups, or\n\n"
        "\t\t\t\t * the curent location of the master for m/s resources with master-max=1\n\n"
        "\t\t\t\tAll other situations result in an error as there is no sane default.\n\n"
        "\t\t\t\tNOTE: This will prevent the resource from running on this node until the constraint expires or is removed with --clear\n"
    },
    {
        "clear", 0, 0, 'U', "\t\tRemove all constraints created by the --ban and/or --move commands.  \n"
        "\t\t\t\tRequires: --resource. Optional: --host, --master\n\n"
        "\t\t\t\tIf --host is not specified, all constraints created by --ban and --move will be removed for the named resource.\n"
    },
    {"lifetime",   1, 0, 'u', "\tLifespan of constraints created by the --ban and --move commands"},
    {
        "master",  0, 0,  0,
        "\t\tLimit the scope of the --ban, --move and --clear  commands to the Master role.\n"
        "\t\t\t\tFor --ban and --move, the previous master can still remain active in the Slave role."
    },

    {"-spacer-",   1, 0, '-', "\nAdvanced Commands:"},
    {"delete",     0, 0, 'D', "\t\t(Advanced) Delete a resource from the CIB"},
    {"fail",       0, 0, 'F', "\t\t(Advanced) Tell the cluster this resource has failed"},
    {"restart",    0, 0,  0,  NULL, 1},
    {"force-stop", 0, 0,  0,  "\t(Advanced) Bypass the cluster and stop a resource on the local node. Additional detail with -V"},
    {"force-start",0, 0,  0,  "\t(Advanced) Bypass the cluster and start a resource on the local node. Additional detail with -V"},
    {"force-check",0, 0,  0,  "\t(Advanced) Bypass the cluster and check the state of a resource on the local node. Additional detail with -V\n"},

    {"-spacer-",	1, 0, '-', "\nAdditional Options:"},
    {"node",		1, 0, 'N', "\tHost uname"},
    {"recursive",       0, 0,  0,  "\tFollow colocation chains when using --set-parameter"},
    {"resource-type",	1, 0, 't', "Resource type (primitive, clone, group, ...)"},
    {"parameter-value", 1, 0, 'v', "Value to use with -p or -S"},
    {"meta",		0, 0, 'm', "\t\tModify a resource's configuration option rather than one which is passed to the resource agent script. For use with -p, -g, -d"},
    {"utilization",	0, 0, 'z', "\tModify a resource's utilization attribute. For use with -p, -g, -d"},
    {"set-name",        1, 0, 's', "\t(Advanced) ID of the instance_attributes object to change"},
    {"nvpair",          1, 0, 'i', "\t(Advanced) ID of the nvpair object to change/delete"},
    {"timeout",         1, 0, 'T',  "\t(Advanced) How long to wait for --restart to take effect", 1},
    {"force",		0, 0, 'f', "\n" /* Is this actually true anymore?
					   "\t\tForce the resource to move by creating a rule for the current location and a score of -INFINITY"
					   "\n\t\tThis should be used if the resource's stickiness and constraint scores total more than INFINITY (Currently 100,000)"
					   "\n\t\tNOTE: This will prevent the resource from running on this node until the constraint is removed with -U or the --lifetime duration expires\n"*/ },

    {"xml-file", 1, 0, 'x', NULL, 1},\

    /* legacy options */
    {"host-uname", 1, 0, 'H', NULL, 1},
    {"migrate",    0, 0, 'M', NULL, 1},
    {"un-migrate", 0, 0, 'U', NULL, 1},
    {"un-move",    0, 0, 'U', NULL, 1},

    {"refresh",    0, 0, 'R', NULL, 1},
    {"reprobe",    0, 0, 'P', NULL, 1},

    {"-spacer-",	1, 0, '-', "\nExamples:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "List the configured resources:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --list", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "List the available OCF agents:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --list-agents ocf", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "List the available OCF agents from the linux-ha project:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --list-agents ocf:heartbeat", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Display the current location of 'myResource':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --locate", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Move 'myResource' to another machine:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --move", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Move 'myResource' to a specific machine:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --move --node altNode", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Allow (but not force) 'myResource' to move back to its original location:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --un-move", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Tell the cluster that 'myResource' failed:", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --fail", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Stop a 'myResource' (and anything that depends on it):", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --set-parameter target-role --meta --parameter-value Stopped", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Tell the cluster not to manage 'myResource':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "The cluster will not attempt to start or stop the resource under any circumstances."},
    {"-spacer-",	1, 0, '-', "Useful when performing maintenance tasks on a resource.", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --set-parameter is-managed --meta --parameter-value false", pcmk_option_example},
    {"-spacer-",	1, 0, '-', "Erase the operation history of 'myResource' on 'aNode':", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', "The cluster will 'forget' the existing resource state (including any errors) and attempt to recover the resource."},
    {"-spacer-",	1, 0, '-', "Useful when a resource had failed permanently and has been repaired by an administrator.", pcmk_option_paragraph},
    {"-spacer-",	1, 0, '-', " crm_resource --resource myResource --cleanup --node aNode", pcmk_option_example},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    const char *longname = NULL;
    pe_working_set_t data_set;
    xmlNode *cib_xml_copy = NULL;
    cib_t *cib_conn = NULL;
    bool do_trace = FALSE;
    bool recursive = FALSE;

    int rc = pcmk_ok;
    int option_index = 0;
    int timeout_ms = 0;
    int argerr = 0;
    int flag;

    crm_log_cli_init("crm_resource");
    crm_set_options(NULL, "(query|command) [options]", long_options,
                    "Perform tasks related to cluster resources.\nAllows resources to be queried (definition and location), modified, and moved around the cluster.\n");

    if (argc < 2) {
        crm_help('?', EX_USAGE);
    }

    while (1) {
        flag = crm_get_option_long(argc, argv, &option_index, &longname);
        if (flag == -1)
            break;

        switch (flag) {
            case 0:
                if (safe_str_eq("master", longname)) {
                    scope_master = TRUE;

                } else if(safe_str_eq(longname, "recursive")) {
                    recursive = TRUE;

                } else if (safe_str_eq("force-stop", longname)
                    || safe_str_eq("restart", longname)
                    || safe_str_eq("force-start", longname)
                    || safe_str_eq("force-check", longname)) {
                    rsc_cmd = flag;
                    rsc_long_cmd = longname;

                } else if (safe_str_eq("list-ocf-providers", longname)
                           || safe_str_eq("list-ocf-alternatives", longname)
                           || safe_str_eq("list-standards", longname)) {
                    const char *text = NULL;
                    lrmd_list_t *list = NULL;
                    lrmd_list_t *iter = NULL;
                    lrmd_t *lrmd_conn = lrmd_api_new();

                    if (safe_str_eq("list-ocf-providers", longname)
                        || safe_str_eq("list-ocf-alternatives", longname)) {
                        rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, optarg, &list);
                        text = "OCF providers";

                    } else if (safe_str_eq("list-standards", longname)) {
                        rc = lrmd_conn->cmds->list_standards(lrmd_conn, &list);
                        text = "standards";
                    }

                    if (rc > 0) {
                        rc = 0;
                        for (iter = list; iter != NULL; iter = iter->next) {
                            rc++;
                            printf("%s\n", iter->val);
                        }
                        lrmd_list_freeall(list);

                    } else if (optarg) {
                        fprintf(stderr, "No %s found for %s\n", text, optarg);
                    } else {
                        fprintf(stderr, "No %s found\n", text);
                    }

                    lrmd_api_delete(lrmd_conn);
                    return crm_exit(rc);

                } else if (safe_str_eq("show-metadata", longname)) {
                    char standard[512];
                    char provider[512];
                    char type[512];
                    char *metadata = NULL;
                    lrmd_t *lrmd_conn = lrmd_api_new();

                    rc = sscanf(optarg, "%[^:]:%[^:]:%s", standard, provider, type);
                    if (rc == 3) {
                        rc = lrmd_conn->cmds->get_metadata(lrmd_conn, standard, provider, type,
                                                           &metadata, 0);

                    } else if (rc == 2) {
                        rc = lrmd_conn->cmds->get_metadata(lrmd_conn, standard, NULL, provider,
                                                           &metadata, 0);

                    } else if (rc < 2) {
                        fprintf(stderr,
                                "Please specify standard:type or standard:provider:type, not %s\n",
                                optarg);
                        rc = -EINVAL;
                    }

                    if (metadata) {
                        printf("%s\n", metadata);
                    } else {
                        fprintf(stderr, "Metadata query for %s failed: %d\n", optarg, rc);
                    }
                    lrmd_api_delete(lrmd_conn);
                    return crm_exit(rc);

                } else if (safe_str_eq("list-agents", longname)) {
                    lrmd_list_t *list = NULL;
                    lrmd_list_t *iter = NULL;
                    char standard[512];
                    char provider[512];
                    lrmd_t *lrmd_conn = lrmd_api_new();

                    rc = sscanf(optarg, "%[^:]:%s", standard, provider);
                    if (rc == 1) {
                        rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, optarg, NULL);
                        provider[0] = '*';
                        provider[1] = 0;

                    } else if (rc == 2) {
                        rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, standard, provider);
                    }

                    if (rc > 0) {
                        rc = 0;
                        for (iter = list; iter != NULL; iter = iter->next) {
                            printf("%s\n", iter->val);
                            rc++;
                        }
                        lrmd_list_freeall(list);
                        rc = 0;
                    } else {
                        fprintf(stderr, "No agents found for standard=%s, provider=%s\n", standard,
                                provider);
                        rc = -1;
                    }
                    lrmd_api_delete(lrmd_conn);
                    return crm_exit(rc);

                } else {
                    crm_err("Unhandled long option: %s", longname);
                }
                break;
            case 'V':
                do_trace = TRUE;
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            case 'x':
                xml_file = strdup(optarg);
                break;
            case 'Q':
                BE_QUIET = TRUE;
                break;
            case 'm':
                attr_set_type = XML_TAG_META_SETS;
                break;
            case 'z':
                attr_set_type = XML_TAG_UTILIZATION;
                break;
            case 'u':
                move_lifetime = strdup(optarg);
                break;
            case 'f':
                do_force = TRUE;
                break;
            case 'i':
                prop_id = optarg;
                break;
            case 's':
                prop_set = optarg;
                break;
            case 'r':
                rsc_id = optarg;
                break;
            case 'v':
                prop_value = optarg;
                break;
            case 't':
                rsc_type = optarg;
                break;
            case 'T':
                timeout_ms = crm_get_msec(optarg);
                break;
            case 'C':
            case 'R':
            case 'P':
                rsc_cmd = 'C';
                break;
            case 'L':
            case 'c':
            case 'l':
            case 'q':
            case 'w':
            case 'D':
            case 'F':
            case 'W':
            case 'M':
            case 'U':
            case 'B':
            case 'O':
            case 'o':
            case 'A':
            case 'a':
                rsc_cmd = flag;
                break;
            case 'j':
                print_pending = TRUE;
                break;
            case 'p':
            case 'g':
            case 'd':
            case 'S':
            case 'G':
                prop_name = optarg;
                rsc_cmd = flag;
                break;
            case 'h':
            case 'H':
            case 'N':
                crm_trace("Option %c => %s", flag, optarg);
                host_uname = optarg;
                break;

            default:
                CMD_ERR("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc && argv[optind] != NULL) {
        CMD_ERR("non-option ARGV-elements: ");
        while (optind < argc && argv[optind] != NULL) {
            CMD_ERR("%s ", argv[optind++]);
            ++argerr;
        }
        CMD_ERR("\n");
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    our_pid = calloc(1, 11);
    if (our_pid != NULL) {
        snprintf(our_pid, 10, "%d", getpid());
        our_pid[10] = '\0';
    }

    if (do_force) {
        crm_debug("Forcing...");
        cib_options |= cib_quorum_override;
    }

    set_working_set_defaults(&data_set);
    if (rsc_cmd != 'P' || rsc_id) {
        resource_t *rsc = NULL;

        cib_conn = cib_new();
        rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
        if (rc != pcmk_ok) {
            CMD_ERR("Error signing on to the CIB service: %s\n", pcmk_strerror(rc));
            return crm_exit(rc);
        }

        if (xml_file != NULL) {
            cib_xml_copy = filename2xml(xml_file);

        } else {
            rc = cib_conn->cmds->query(cib_conn, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
        }

        if(rc != pcmk_ok) {
            goto bail;
        } else if (cli_config_update(&cib_xml_copy, NULL, FALSE) == FALSE) {
            rc = -ENOKEY;
            goto bail;
        }

        data_set.input = cib_xml_copy;
        data_set.now = crm_time_new(NULL);

        cluster_status(&data_set);
        if (rsc_id) {
            rsc = find_rsc_or_clone(rsc_id, &data_set);
        }
        if (rsc == NULL && rsc_cmd != 'C') {
            rc = -ENXIO;
        }
    }

    if (rsc_cmd == 'R' || rsc_cmd == 'C' || rsc_cmd == 'F' || rsc_cmd == 'P') {
        xmlNode *xml = NULL;
        mainloop_io_t *source =
            mainloop_add_ipc_client(CRM_SYSTEM_CRMD, G_PRIORITY_DEFAULT, 0, NULL, &crm_callbacks);
        crmd_channel = mainloop_get_ipc_client(source);

        if (crmd_channel == NULL) {
            CMD_ERR("Error signing on to the CRMd service\n");
            rc = -ENOTCONN;
            goto bail;
        }

        xml = create_hello_message(our_pid, crm_system_name, "0", "1");
        crm_ipc_send(crmd_channel, xml, 0, 0, NULL);
        free_xml(xml);
    }

    if (rsc_cmd == 'L') {
        rc = pcmk_ok;
        do_find_resource_list(&data_set, FALSE);

    } else if (rsc_cmd == 'l') {
        int found = 0;
        GListPtr lpc = NULL;

        rc = pcmk_ok;
        for (lpc = data_set.resources; lpc != NULL; lpc = lpc->next) {
            resource_t *rsc = (resource_t *) lpc->data;

            found++;
            print_raw_rsc(rsc);
        }

        if (found == 0) {
            printf("NO resources configured\n");
            rc = -ENXIO;
            goto bail;
        }

    } else if (rsc_cmd == 0 && rsc_long_cmd && safe_str_eq(rsc_long_cmd, "restart")) {
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);

        rc = resource_restart(rsc, host_uname, timeout_ms, cib_conn);

    } else if (rsc_cmd == 0 && rsc_long_cmd) {
        svc_action_t *op = NULL;
        const char *rtype = NULL;
        const char *rprov = NULL;
        const char *rclass = NULL;
        const char *action = NULL;
        GHashTable *params = NULL;
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);

        if (rsc == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }

        if (safe_str_eq(rsc_long_cmd, "force-stop")) {
            action = "stop";
        } else if (safe_str_eq(rsc_long_cmd, "force-start")) {
            action = "start";
            if(rsc->variant >= pe_clone) {
                rc = do_find_resource(rsc_id, NULL, &data_set);
                if(rc > 0 && do_force == FALSE) {
                    CMD_ERR("It is not safe to start %s here: the cluster claims it is already active", rsc_id);
                    CMD_ERR("Try setting target-role=stopped first or specifying --force");
                    crm_exit(EPERM);
                }
            }

        } else if (safe_str_eq(rsc_long_cmd, "force-check")) {
            action = "monitor";
        }

        if(rsc->variant == pe_clone || rsc->variant == pe_master) {
            /* Grab the first child resource in the hope its not a group */
            rsc = rsc->children->data;
        }

        if(rsc->variant == pe_group) {
            CMD_ERR("Sorry, --%s doesn't support group resources\n", rsc_long_cmd);
            crm_exit(EOPNOTSUPP);
        }

        rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
        rprov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
        rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);

        if(safe_str_eq(rclass, "stonith")){
            CMD_ERR("Sorry, --%s doesn't support %s resources yet\n", rsc_long_cmd, rclass);
            crm_exit(EOPNOTSUPP);
        }

        params = generate_resource_params(rsc, &data_set);
        op = resources_action_create(rsc->id, rclass, rprov, rtype, action, 0, -1, params);

        if(do_trace) {
            setenv("OCF_TRACE_RA", "1", 1);
        }

        if(op == NULL) {
            /* Re-run but with stderr enabled so we can display a sane error message */
            crm_enable_stderr(TRUE);
            resources_action_create(rsc->id, rclass, rprov, rtype, action, 0, -1, params);
            return crm_exit(EINVAL);

        } else if (services_action_sync(op)) {
            int more, lpc, last;
            char *local_copy = NULL;

            if (op->status == PCMK_LRM_OP_DONE) {
                printf("Operation %s for %s (%s:%s:%s) returned %d\n",
                       action, rsc->id, rclass, rprov ? rprov : "", rtype, op->rc);
            } else {
                printf("Operation %s for %s (%s:%s:%s) failed: %d\n",
                       action, rsc->id, rclass, rprov ? rprov : "", rtype, op->status);
            }

            if (op->stdout_data) {
                local_copy = strdup(op->stdout_data);
                more = strlen(local_copy);
                last = 0;

                for (lpc = 0; lpc < more; lpc++) {
                    if (local_copy[lpc] == '\n' || local_copy[lpc] == 0) {
                        local_copy[lpc] = 0;
                        printf(" >  stdout: %s\n", local_copy + last);
                        last = lpc + 1;
                    }
                }
                free(local_copy);
            }
            if (op->stderr_data) {
                local_copy = strdup(op->stderr_data);
                more = strlen(local_copy);
                last = 0;

                for (lpc = 0; lpc < more; lpc++) {
                    if (local_copy[lpc] == '\n' || local_copy[lpc] == 0) {
                        local_copy[lpc] = 0;
                        printf(" >  stderr: %s\n", local_copy + last);
                        last = lpc + 1;
                    }
                }
                free(local_copy);
            }
        }
        rc = op->rc;
        services_action_free(op);
        return crm_exit(rc);

    } else if (rsc_cmd == 'A' || rsc_cmd == 'a') {
        GListPtr lpc = NULL;
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
        xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set.input);

        if (rsc == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }

        unpack_constraints(cib_constraints, &data_set);

        for (lpc = data_set.resources; lpc != NULL; lpc = lpc->next) {
            resource_t *r = (resource_t *) lpc->data;

            clear_bit(r->flags, pe_rsc_allocating);
        }

        show_colocation(rsc, TRUE, rsc_cmd == 'A', 1);

        fprintf(stdout, "* %s\n", rsc->id);
        show_location(rsc, NULL);

        for (lpc = data_set.resources; lpc != NULL; lpc = lpc->next) {
            resource_t *r = (resource_t *) lpc->data;

            clear_bit(r->flags, pe_rsc_allocating);
        }

        show_colocation(rsc, FALSE, rsc_cmd == 'A', 1);

    } else if (rsc_cmd == 'c') {
        int found = 0;
        GListPtr lpc = NULL;

        rc = pcmk_ok;
        for (lpc = data_set.resources; lpc != NULL; lpc = lpc->next) {
            resource_t *rsc = (resource_t *) lpc->data;

            print_cts_rsc(rsc);
            found++;
        }
        print_cts_constraints(&data_set);

    } else if (rsc_cmd == 'F') {
        rc = fail_lrm_rsc(crmd_channel, host_uname, rsc_id, &data_set);
        if (rc == pcmk_ok) {
            start_mainloop();
        }

    } else if (rsc_cmd == 'O') {
        rc = list_resource_operations(rsc_id, host_uname, TRUE, &data_set);

    } else if (rsc_cmd == 'o') {
        rc = list_resource_operations(rsc_id, host_uname, FALSE, &data_set);

    } else if (rc == -ENXIO) {
        CMD_ERR("Resource '%s' not found: %s\n", crm_str(rsc_id), pcmk_strerror(rc));

    } else if (rsc_cmd == 'W') {
        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }
        rc = do_find_resource(rsc_id, NULL, &data_set);

    } else if (rsc_cmd == 'q') {
        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }
        rc = dump_resource(rsc_id, &data_set, TRUE);

    } else if (rsc_cmd == 'w') {
        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }
        rc = dump_resource(rsc_id, &data_set, FALSE);

    } else if (rsc_cmd == 'U') {
        node_t *dest = NULL;

        if (rsc_id == NULL) {
            CMD_ERR("No value specified for --resource\n");
            rc = -ENXIO;
            goto bail;
        }

        if (host_uname) {
            dest = pe_find_node(data_set.nodes, host_uname);
            if (dest == NULL) {
                CMD_ERR("Unknown node: %s\n", host_uname);
                rc = -ENXIO;
                goto bail;
            }
            rc = clear_resource(rsc_id, dest->details->uname, NULL, cib_conn);

        } else {
            rc = clear_resource(rsc_id, NULL, data_set.nodes, cib_conn);
        }

    } else if (rsc_cmd == 'M' && host_uname) {

        int count = 0;
        node_t *current = NULL;
        node_t *dest = pe_find_node(data_set.nodes, host_uname);
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
        gboolean cur_is_dest = FALSE;

        rc = -EINVAL;

        if (rsc == NULL) {
            CMD_ERR("Resource '%s' not moved: not found\n", rsc_id);
            rc = -ENXIO;
            goto bail;

        } else if (scope_master && rsc->variant < pe_master) {
            resource_t *p = uber_parent(rsc);
            if(p->variant == pe_master) {
                CMD_ERR("Using parent '%s' for --move command instead of '%s'.\n", rsc->id, rsc_id);
                rsc_id = p->id;
                rsc = p;

            } else {
                CMD_ERR("Ignoring '--master' option: not valid for %s resources.\n",
                        get_resource_typename(rsc->variant));
                scope_master = FALSE;
            }
        }

        if(rsc->variant == pe_master) {
            GListPtr iter = NULL;

            for(iter = rsc->children; iter; iter = iter->next) {
                resource_t *child = (resource_t *)iter->data;
                enum rsc_role_e child_role = child->fns->state(child, TRUE);

                if(child_role == RSC_ROLE_MASTER) {
                    rsc = child;
                    count++;
                }
            }

            if(scope_master == FALSE && count == 0) {
                count = g_list_length(rsc->running_on);
            }

        } else if (rsc->variant > pe_group) {
            count = g_list_length(rsc->running_on);

        } else if (g_list_length(rsc->running_on) > 1) {
            CMD_ERR("Resource '%s' not moved: active on multiple nodes\n", rsc_id);
            goto bail;
        }

        if(dest == NULL) {
            CMD_ERR("Error performing operation: node '%s' is unknown\n", host_uname);
            rc = -ENXIO;
            goto bail;
        }

        if(g_list_length(rsc->running_on) == 1) {
            current = rsc->running_on->data;
        }

        if(current == NULL) {
            /* Nothing to check */

        } else if(scope_master && rsc->fns->state(rsc, TRUE) != RSC_ROLE_MASTER) {
            crm_trace("%s is already active on %s but not in correct state", rsc_id, dest->details->uname);
        } else if (safe_str_eq(current->details->uname, dest->details->uname)) {
            cur_is_dest = TRUE;
            if (do_force) {
                crm_info("%s is already %s on %s, reinforcing placement with location constraint.\n",
                         rsc_id, scope_master?"promoted":"active", dest->details->uname);
            } else {
                CMD_ERR("Error performing operation: %s is already %s on %s\n",
                        rsc_id, scope_master?"promoted":"active", dest->details->uname);
                goto bail;
            }
        }

        /* Clear any previous constraints for 'dest' */
        clear_resource(rsc_id, dest->details->uname, data_set.nodes, cib_conn);

        /* Record an explicit preference for 'dest' */
        rc = prefer_resource(rsc_id, dest->details->uname, cib_conn);

        crm_trace("%s%s now prefers node %s%s",
                  rsc->id, scope_master?" (master)":"", dest->details->uname, do_force?"(forced)":"");

        /* only ban the previous location if current location != destination location.
         * it is possible to use -M to enforce a location without regard of where the
         * resource is currently located */
        if(do_force && (cur_is_dest == FALSE)) {
            /* Ban the original location if possible */
            if(current) {
                ban_resource(rsc_id, current->details->uname, NULL, cib_conn);

            } else if(count > 1) {
                CMD_ERR("Resource '%s' is currently %s in %d locations.  One may now move one to %s\n",
                        rsc_id, scope_master?"promoted":"active", count, dest->details->uname);
                CMD_ERR("You can prevent '%s' from being %s at a specific location with:"
                        " --ban %s--host <name>\n", rsc_id, scope_master?"promoted":"active", scope_master?"--master ":"");

            } else {
                crm_trace("Not banning %s from it's current location: not active", rsc_id);
            }
        }

    } else if (rsc_cmd == 'B' && host_uname) {
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
        node_t *dest = pe_find_node(data_set.nodes, host_uname);

        rc = -ENXIO;
        if (rsc_id == NULL) {
            CMD_ERR("No value specified for --resource\n");
            goto bail;
        } else if(rsc == NULL) {
            CMD_ERR("Resource '%s' not moved: unknown\n", rsc_id);

        } else if (dest == NULL) {
            CMD_ERR("Error performing operation: node '%s' is unknown\n", host_uname);
            goto bail;
        }
        rc = ban_resource(rsc_id, dest->details->uname, NULL, cib_conn);

    } else if (rsc_cmd == 'B' || rsc_cmd == 'M') {
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);

        rc = -ENXIO;
        if (rsc_id == NULL) {
            CMD_ERR("No value specified for --resource\n");
            goto bail;
        }

        rc = -EINVAL;
        if(rsc == NULL) {
            CMD_ERR("Resource '%s' not moved: unknown\n", rsc_id);

        } else if(g_list_length(rsc->running_on) == 1) {
            node_t *current = rsc->running_on->data;
            rc = ban_resource(rsc_id, current->details->uname, NULL, cib_conn);

        } else if(rsc->variant == pe_master) {
            int count = 0;
            GListPtr iter = NULL;
            node_t *current = NULL;

            for(iter = rsc->children; iter; iter = iter->next) {
                resource_t *child = (resource_t *)iter->data;
                enum rsc_role_e child_role = child->fns->state(child, TRUE);

                if(child_role == RSC_ROLE_MASTER) {
                    count++;
                    current = child->running_on->data;
                }
            }

            if(count == 1 && current) {
                rc = ban_resource(rsc_id, current->details->uname, NULL, cib_conn);

            } else {
                CMD_ERR("Resource '%s' not moved: active in %d locations (promoted in %d).\n", rsc_id, g_list_length(rsc->running_on), count);
                CMD_ERR("You can prevent '%s' from running on a specific location with: --ban --host <name>\n", rsc_id);
                CMD_ERR("You can prevent '%s' from being promoted at a specific location with:"
                        " --ban --master --host <name>\n", rsc_id);
            }

        } else {
            CMD_ERR("Resource '%s' not moved: active in %d locations.\n", rsc_id, g_list_length(rsc->running_on));
            CMD_ERR("You can prevent '%s' from running on a specific location with: --ban --host <name>\n", rsc_id);
        }

    } else if (rsc_cmd == 'G') {
        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }
        rc = dump_resource_prop(rsc_id, prop_name, &data_set);

    } else if (rsc_cmd == 'S') {
        xmlNode *msg_data = NULL;

        if (prop_value == NULL || strlen(prop_value) == 0) {
            CMD_ERR("You need to supply a value with the -v option\n");
            rc = -EINVAL;
            goto bail;

        } else if (cib_conn == NULL) {
            rc = -ENOTCONN;
            goto bail;
        }

        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }
        CRM_LOG_ASSERT(rsc_type != NULL);
        CRM_LOG_ASSERT(prop_name != NULL);
        CRM_LOG_ASSERT(prop_value != NULL);

        msg_data = create_xml_node(NULL, rsc_type);
        crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);
        crm_xml_add(msg_data, prop_name, prop_value);

        rc = cib_conn->cmds->modify(cib_conn, XML_CIB_TAG_RESOURCES, msg_data, cib_options);
        free_xml(msg_data);

    } else if (rsc_cmd == 'g') {
        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }
        rc = dump_resource_attr(rsc_id, prop_name, &data_set);

    } else if (rsc_cmd == 'p') {
        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }
        if (prop_value == NULL || strlen(prop_value) == 0) {
            CMD_ERR("You need to supply a value with the -v option\n");
            rc = -EINVAL;
            goto bail;
        }

        /* coverity[var_deref_model] False positive */
        rc = set_resource_attr(rsc_id, prop_set, prop_id, prop_name,
                               prop_value, recursive, cib_conn, &data_set);

    } else if (rsc_cmd == 'd') {
        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;
        }
        /* coverity[var_deref_model] False positive */
        rc = delete_resource_attr(rsc_id, prop_set, prop_id, prop_name, cib_conn, &data_set);

    } else if (rsc_cmd == 'C' && rsc_id) {
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);

        crm_debug("Re-checking the state of %s on %s", rsc_id, host_uname);
        if(rsc) {
            crmd_replies_needed = 0;
            rc = delete_lrm_rsc(cib_conn, crmd_channel, host_uname, rsc, &data_set);
        } else {
            rc = -ENODEV;
        }

        if (rc == pcmk_ok) {
            start_mainloop();
        }

    } else if (rsc_cmd == 'C') {
#if HAVE_ATOMIC_ATTRD
        xmlNode *cmd = create_request(CRM_OP_REPROBE, NULL, host_uname,
                                      CRM_SYSTEM_CRMD, crm_system_name, our_pid);

        crm_debug("Re-checking the state of all resources on %s", host_uname?host_uname:"all nodes");

        rc = attrd_update_delegate(
            NULL, 'u', host_uname, "fail-count-*", NULL, XML_CIB_TAG_STATUS, NULL, NULL, NULL, FALSE);

        if (crm_ipc_send(crmd_channel, cmd, 0, 0, NULL) > 0) {
            start_mainloop();
        }

        free_xml(cmd);
#else
        GListPtr rIter = NULL;

        crmd_replies_needed = 0;
        for (rIter = data_set.resources; rIter; rIter = rIter->next) {
            resource_t *rsc = rIter->data;
            delete_lrm_rsc(cib_conn, crmd_channel, host_uname, rsc, &data_set);
        }

        start_mainloop();
#endif

    } else if (rsc_cmd == 'D') {
        xmlNode *msg_data = NULL;

        if (rsc_id == NULL) {
            CMD_ERR("Must supply a resource id with -r\n");
            rc = -ENXIO;
            goto bail;

        }
        if (rsc_type == NULL) {
            CMD_ERR("You need to specify a resource type with -t");
            rc = -ENXIO;
            goto bail;

        } else if (cib_conn == NULL) {
            rc = -ENOTCONN;
            goto bail;
        }

        msg_data = create_xml_node(NULL, rsc_type);
        crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);

        rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_RESOURCES, msg_data, cib_options);
        free_xml(msg_data);

    } else {
        CMD_ERR("Unknown command: %c\n", rsc_cmd);
    }

  bail:

    if (data_set.input != NULL) {
        cleanup_alloc_calculations(&data_set);
    }
    if (cib_conn != NULL) {
        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
    }

    if (rc == -pcmk_err_no_quorum) {
        CMD_ERR("Error performing operation: %s\n", pcmk_strerror(rc));
        CMD_ERR("Try using -f\n");

    } else if (rc != pcmk_ok) {
        CMD_ERR("Error performing operation: %s\n", pcmk_strerror(rc));
    }

    return crm_exit(rc);
}
