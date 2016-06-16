
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

#include <crm_resource.h>

bool do_trace = FALSE;
bool do_force = FALSE;
int crmd_replies_needed = 1; /* The welcome message */

const char *attr_set_type = XML_TAG_ATTR_SETS;

static int
do_find_resource(const char *rsc, resource_t * the_rsc, pe_working_set_t * data_set)
{
    int found = 0;
    GListPtr lpc = NULL;

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

    return found;
}

int
cli_resource_search(const char *rsc, pe_working_set_t * data_set)
{
    int found = 0;
    resource_t *the_rsc = NULL;
    resource_t *parent = NULL;

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

    /* The anonymous clone children's common ID is supplied */
    } else if ((parent = uber_parent(the_rsc)) != NULL
               && parent->variant >= pe_clone
               && is_not_set(the_rsc->flags, pe_rsc_unique)
               && the_rsc->clone_name
               && safe_str_eq(rsc, the_rsc->clone_name)
               && safe_str_neq(rsc, the_rsc->id)) {
        GListPtr gIter = parent->children;

        for (; gIter != NULL; gIter = gIter->next) {
            found += do_find_resource(rsc, gIter->data, data_set);
        }

    } else {
        found += do_find_resource(rsc, the_rsc, data_set);
    }

    return found;
}

resource_t *
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
find_resource_attr(cib_t * the_cib, const char *attr, const char *rsc, const char *set_type,
                   const char *set_name, const char *attr_id, const char *attr_name, char **value)
{
    int offset = 0;
    static int xpath_max = 1024;
    int rc = pcmk_ok;
    xmlNode *xml_search = NULL;
    char *xpath_string = NULL;

    if(value) {
        *value = NULL;
    }

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

    } else if(value) {
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

static resource_t *
find_matching_attr_resource(resource_t * rsc, const char * rsc_id, const char * attr_set, const char * attr_id,
                            const char * attr_name, cib_t * cib, const char * cmd)
{
    int rc = pcmk_ok;
    char *lookup_id = NULL;
    char *local_attr_id = NULL;

    if(do_force == TRUE) {
        return rsc;

    } else if(rsc->parent) {
        switch(rsc->parent->variant) {
            case pe_group:
                if (BE_QUIET == FALSE) {
                    printf("Performing %s of '%s' for '%s' will not apply to its peers in '%s'\n", cmd, attr_name, rsc_id, rsc->parent->id);
                }
                break;
            case pe_master:
            case pe_clone:

                rc = find_resource_attr(cib, XML_ATTR_ID, rsc_id, attr_set_type, attr_set, attr_id, attr_name, &local_attr_id);
                free(local_attr_id);

                if(rc != pcmk_ok) {
                    rsc = rsc->parent;
                    if (BE_QUIET == FALSE) {
                        printf("Performing %s of '%s' on '%s', the parent of '%s'\n", cmd, attr_name, rsc->id, rsc_id);
                    }
                }
                break;
            default:
                break;
        }

    } else if (rsc->parent && BE_QUIET == FALSE) {
        printf("Forcing %s of '%s' for '%s' instead of '%s'\n", cmd, attr_name, rsc_id, rsc->parent->id);

    } else if(rsc->parent == NULL && rsc->children) {
        resource_t *child = rsc->children->data;

        if(child->variant == pe_native) {
            lookup_id = clone_strip(child->id); /* Could be a cloned group! */
            rc = find_resource_attr(cib, XML_ATTR_ID, lookup_id, attr_set_type, attr_set, attr_id, attr_name, &local_attr_id);

            if(rc == pcmk_ok) {
                rsc = child;
                if (BE_QUIET == FALSE) {
                    printf("A value for '%s' already exists in child '%s', performing %s on that instead of '%s'\n", attr_name, lookup_id, cmd, rsc_id);
                }
            }

            free(local_attr_id);
            free(lookup_id);
        }
    }

    return rsc;
}

int
cli_resource_update_attribute(const char *rsc_id, const char *attr_set, const char *attr_id,
                  const char *attr_name, const char *attr_value, bool recursive,
                  cib_t * cib, pe_working_set_t * data_set)
{
    int rc = pcmk_ok;
    static bool need_init = TRUE;

    char *lookup_id = NULL;
    char *local_attr_id = NULL;
    char *local_attr_set = NULL;

    xmlNode *xml_top = NULL;
    xmlNode *xml_obj = NULL;

    bool use_attributes_tag = FALSE;
    resource_t *rsc = find_rsc_or_clone(rsc_id, data_set);

    if (rsc == NULL) {
        return -ENXIO;
    }

    if(attr_id == NULL
       && do_force == FALSE
       && pcmk_ok != find_resource_attr(
           cib, XML_ATTR_ID, uber_parent(rsc)->id, NULL, NULL, NULL, attr_name, NULL)) {
        printf("\n");
    }

    if (safe_str_eq(attr_set_type, XML_TAG_ATTR_SETS)) {
        if (do_force == FALSE) {
            rc = find_resource_attr(cib, XML_ATTR_ID, uber_parent(rsc)->id,
                                    XML_TAG_META_SETS, attr_set, attr_id,
                                    attr_name, &local_attr_id);
            if (rc == pcmk_ok && BE_QUIET == FALSE) {
                printf("WARNING: There is already a meta attribute for '%s' called '%s' (id=%s)\n",
                       uber_parent(rsc)->id, attr_name, local_attr_id);
                printf("         Delete '%s' first or use --force to override\n", local_attr_id);
            }
            free(local_attr_id);
            if (rc == pcmk_ok) {
                return -ENOTUNIQ;
            }
        }

    } else {
        rsc = find_matching_attr_resource(rsc, rsc_id, attr_set, attr_id, attr_name, cib, "update");
    }

    lookup_id = clone_strip(rsc->id); /* Could be a cloned group! */
    rc = find_resource_attr(cib, XML_ATTR_ID, lookup_id, attr_set_type, attr_set, attr_id, attr_name,
                            &local_attr_id);

    if (rc == pcmk_ok) {
        crm_debug("Found a match for name=%s: id=%s", attr_name, local_attr_id);
        attr_id = local_attr_id;

    } else if (rc != -ENXIO) {
        free(lookup_id);
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
            local_attr_set = crm_concat(lookup_id, attr_set_type, '-');
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
        crm_xml_add(xml_top, XML_ATTR_ID, lookup_id);

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
    if (rc == pcmk_ok && BE_QUIET == FALSE) {
        printf("Set '%s' option: id=%s%s%s%s%s=%s\n", lookup_id, local_attr_id,
               attr_set ? " set=" : "", attr_set ? attr_set : "",
               attr_name ? " name=" : "", attr_name ? attr_name : "", attr_value);
    }

    free_xml(xml_top);

    free(lookup_id);
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

        crm_debug("Looking for dependencies %p", rsc->rsc_cons_lhs);
        set_bit(rsc->flags, pe_rsc_allocating);
        for (lpc = rsc->rsc_cons_lhs; lpc != NULL; lpc = lpc->next) {
            rsc_colocation_t *cons = (rsc_colocation_t *) lpc->data;
            resource_t *peer = cons->rsc_lh;

            crm_debug("Checking %s %d", cons->id, cons->score);
            if (cons->score > 0 && is_not_set(peer->flags, pe_rsc_allocating)) {
                /* Don't get into colocation loops */
                crm_debug("Setting %s=%s for dependent resource %s", attr_name, attr_value, peer->id);
                cli_resource_update_attribute(peer->id, NULL, NULL, attr_name, attr_value, recursive, cib, data_set);
            }
        }
    }

    return rc;
}

int
cli_resource_delete_attribute(const char *rsc_id, const char *attr_set, const char *attr_id,
                     const char *attr_name, cib_t * cib, pe_working_set_t * data_set)
{
    xmlNode *xml_obj = NULL;

    int rc = pcmk_ok;
    char *lookup_id = NULL;
    char *local_attr_id = NULL;
    resource_t *rsc = find_rsc_or_clone(rsc_id, data_set);

    if (rsc == NULL) {
        return -ENXIO;
    }

    if(attr_id == NULL
       && do_force == FALSE
       && find_resource_attr(
           cib, XML_ATTR_ID, uber_parent(rsc)->id, NULL, NULL, NULL, attr_name, NULL) != pcmk_ok) {
        printf("\n");
    }

    if(safe_str_eq(attr_set_type, XML_TAG_META_SETS)) {
        rsc = find_matching_attr_resource(rsc, rsc_id, attr_set, attr_id, attr_name, cib, "delete");
    }

    lookup_id = clone_strip(rsc->id);
    rc = find_resource_attr(cib, XML_ATTR_ID, lookup_id, attr_set_type, attr_set, attr_id, attr_name,
                            &local_attr_id);

    if (rc == -ENXIO) {
        free(lookup_id);
        return pcmk_ok;

    } else if (rc != pcmk_ok) {
        free(lookup_id);
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

    if (rc == pcmk_ok && BE_QUIET == FALSE) {
        printf("Deleted '%s' option: id=%s%s%s%s%s\n", lookup_id, local_attr_id,
               attr_set ? " set=" : "", attr_set ? attr_set : "",
               attr_name ? " name=" : "", attr_name ? attr_name : "");
    }

    free(lookup_id);
    free_xml(xml_obj);
    free(local_attr_id);
    return rc;
}

static int
send_lrm_rsc_op(crm_ipc_t * crmd_channel, const char *op,
                const char *host_uname, const char *rsc_id,
                bool only_failed, pe_working_set_t * data_set)
{
    char *our_pid = NULL;
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
        CMD_ERR("Resource %s not found", rsc_id);
        return -ENXIO;

    } else if (rsc->variant != pe_native) {
        CMD_ERR("We can only process primitive resources, not %s", rsc_id);
        return -EINVAL;

    } else if (host_uname == NULL) {
        CMD_ERR("Please supply a hostname with -H");
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
        CMD_ERR("%s has no type!  Aborting...", rsc_id);
        return -ENXIO;
    }

    value = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    crm_xml_add(xml_rsc, XML_AGENT_ATTR_CLASS, value);
    if (value == NULL) {
        CMD_ERR("%s has no class!  Aborting...", rsc_id);
        return -ENXIO;
    }

    value = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    crm_xml_add(xml_rsc, XML_AGENT_ATTR_PROVIDER, value);

    params = create_xml_node(msg_data, XML_TAG_ATTRS);
    crm_xml_add(params, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    key = crm_meta_name(XML_LRM_ATTR_INTERVAL);
    crm_xml_add(params, key, "60000");  /* 1 minute */
    free(key);

    our_pid = calloc(1, 11);
    if (our_pid != NULL) {
        snprintf(our_pid, 10, "%d", getpid());
        our_pid[10] = '\0';
    }
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
cli_delete_attr(cib_t * cib_conn, const char * host_uname, const char * attr_name,
                pe_working_set_t * data_set)
{
    node_t *node = pe_find_node(data_set->nodes, host_uname);
    int attr_options = attrd_opt_none;

    if (node && is_remote_node(node)) {
#if HAVE_ATOMIC_ATTRD
        set_bit(attr_options, attrd_opt_remote);
#else
        /* Talk directly to cib for remote nodes if it's legacy attrd */
        return delete_attr_delegate(cib_conn, cib_sync_call, XML_CIB_TAG_STATUS, node->details->id, NULL, NULL,
                                    NULL, attr_name, NULL, FALSE, NULL);
#endif
    }
    return attrd_update_delegate(NULL, 'D', host_uname, attr_name, NULL,
                                 XML_CIB_TAG_STATUS, NULL, NULL, NULL,
                                 attr_options);
}

int
cli_resource_delete(cib_t *cib_conn, crm_ipc_t * crmd_channel, const char *host_uname,
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

            rc = cli_resource_delete(cib_conn, crmd_channel, host_uname, child, data_set);
            if(rc != pcmk_ok
               || (rsc->variant >= pe_clone && is_not_set(rsc->flags, pe_rsc_unique))) {
                return rc;
            }
        }
        return pcmk_ok;

    } else if (host_uname == NULL) {
        GListPtr lpc = NULL;

        for (lpc = data_set->nodes; lpc != NULL; lpc = lpc->next) {
            node = (node_t *) lpc->data;

            if (node->details->online) {
                cli_resource_delete(cib_conn, crmd_channel, node->details->uname, rsc, data_set);
            }
        }

        return pcmk_ok;
    }

    node = pe_find_node(data_set->nodes, host_uname);

    if (node && node->details->rsc_discovery_enabled) {
        printf("Cleaning up %s on %s", rsc->id, host_uname);
        rc = send_lrm_rsc_op(crmd_channel, CRM_OP_LRM_DELETE, host_uname, rsc->id, TRUE, data_set);
    } else {
        printf("Resource discovery disabled on %s. Unable to delete lrm state.\n", host_uname);
        rc = -EOPNOTSUPP;
    }

    if (rc == pcmk_ok) {
        char *attr_name = NULL;

        if(node && node->details->remote_rsc == NULL && node->details->rsc_discovery_enabled) {
            crmd_replies_needed++;
        }

        if(is_not_set(rsc->flags, pe_rsc_unique)) {
            char *id = clone_strip(rsc->id);
            attr_name = crm_strdup_printf("fail-count-%s", id);
            free(id);

        } else if (rsc->clone_name) {
            attr_name = crm_strdup_printf("fail-count-%s", rsc->clone_name);

        } else {
            attr_name = crm_strdup_printf("fail-count-%s", rsc->id);
        }

        printf(", removing %s\n", attr_name);
        rc = cli_delete_attr(cib_conn, host_uname, attr_name, data_set);
        free(attr_name);

    } else if(rc != -EOPNOTSUPP) {
        printf(" - FAILED\n");
    }

    return rc;
}

void
cli_resource_check(cib_t * cib_conn, resource_t *rsc)
{
    int need_nl = 0;
    char *role_s = NULL;
    char *managed = NULL;
    resource_t *parent = uber_parent(rsc);

    find_resource_attr(cib_conn, XML_NVPAIR_ATTR_VALUE, parent->id,
                       NULL, NULL, NULL, XML_RSC_ATTR_MANAGED, &managed);

    find_resource_attr(cib_conn, XML_NVPAIR_ATTR_VALUE, parent->id,
                       NULL, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, &role_s);

    if(role_s) {
        enum rsc_role_e role = text2role(role_s);
        if(role == RSC_ROLE_UNKNOWN) {
            // Treated as if unset

        } else if(role == RSC_ROLE_STOPPED) {
            printf("\n  * The configuration specifies that '%s' should remain stopped\n", parent->id);
            need_nl++;

        } else if(parent->variant > pe_clone && role == RSC_ROLE_SLAVE) {
            printf("\n  * The configuration specifies that '%s' should not be promoted\n", parent->id);
            need_nl++;
        }
    }

    if(managed && crm_is_true(managed) == FALSE) {
        printf("%s  * The configuration prevents the cluster from stopping or starting '%s' (unmanaged)\n", need_nl == 0?"\n":"", parent->id);
        need_nl++;
    }

    if(need_nl) {
        printf("\n");
    }
}

int
cli_resource_fail(crm_ipc_t * crmd_channel, const char *host_uname,
             const char *rsc_id, pe_working_set_t * data_set)
{
    crm_warn("Failing: %s", rsc_id);
    return send_lrm_rsc_op(crmd_channel, CRM_OP_LRM_FAIL, host_uname, rsc_id, FALSE, data_set);
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

/*!
 * \internal
 * \brief Create a list of all resources active on host from a given list
 *
 * \param[in] host      Name of host to check whether resources are active
 * \param[in] rsc_list  List of resources to check
 *
 * \return New list of resources from list that are active on host
 */
static GList *
get_active_resources(const char *host, GList *rsc_list)
{
    GList *rIter = NULL;
    GList *active = NULL;

    for (rIter = rsc_list; rIter != NULL; rIter = rIter->next) {
        resource_t *rsc = (resource_t *) rIter->data;

        /* Expand groups to their members, because if we're restarting a member
         * other than the first, we can't otherwise tell which resources are
         * stopping and starting.
         */
        if (rsc->variant == pe_group) {
            active = g_list_concat(active,
                                   get_active_resources(host, rsc->children));
        } else if (resource_is_running_on(rsc, host)) {
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
        crm_trace("%s[%d]: %s", tag, lpc, (char*)item->data);
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

/*!
 * \internal
 * \brief Upgrade XML to latest schema version and use it as working set input
 *
 * This also updates the working set timestamp to the current time.
 *
 * \param[in] data_set   Working set instance to update
 * \param[in] xml        XML to use as input
 *
 * \return pcmk_ok on success, -ENOKEY if unable to upgrade XML
 * \note On success, caller is responsible for freeing memory allocated for
 *       data_set->now.
 * \todo This follows the example of other callers of cli_config_update()
 *       and returns -ENOKEY ("Required key not available") if that fails,
 *       but perhaps -pcmk_err_schema_validation would be better in that case.
 */
int
update_working_set_xml(pe_working_set_t *data_set, xmlNode **xml)
{
    if (cli_config_update(xml, NULL, FALSE) == FALSE) {
        return -ENOKEY;
    }
    data_set->input = *xml;
    data_set->now = crm_time_new(NULL);
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Update a working set's XML input based on a CIB query
 *
 * \param[in] data_set   Data set instance to initialize
 * \param[in] cib        Connection to the CIB
 *
 * \return pcmk_ok on success, -errno on failure
 * \note On success, caller is responsible for freeing memory allocated for
 *       data_set->input and data_set->now.
 */
static int
update_working_set_from_cib(pe_working_set_t * data_set, cib_t *cib)
{
    xmlNode *cib_xml_copy = NULL;
    int rc;

    rc = cib->cmds->query(cib, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not obtain the current CIB: %s (%d)\n", pcmk_strerror(rc), rc);
        return rc;
    }
    rc = update_working_set_xml(data_set, &cib_xml_copy);
    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not upgrade the current CIB XML\n");
        free_xml(cib_xml_copy);
        return rc;
    }
    return pcmk_ok;
}

static int
update_dataset(cib_t *cib, pe_working_set_t * data_set, bool simulate)
{
    char *pid = NULL;
    char *shadow_file = NULL;
    cib_t *shadow_cib = NULL;
    int rc;

    cleanup_alloc_calculations(data_set);
    rc = update_working_set_from_cib(data_set, cib);
    if (rc != pcmk_ok) {
        return rc;
    }

    if(simulate) {
        pid = crm_itoa(getpid());
        shadow_cib = cib_shadow_new(pid);
        shadow_file = get_shadow_file(pid);

        if (shadow_cib == NULL) {
            fprintf(stderr, "Could not create shadow cib: '%s'\n", pid);
            rc = -ENXIO;
            goto cleanup;
        }

        rc = write_xml_file(data_set->input, shadow_file, FALSE);

        if (rc < 0) {
            fprintf(stderr, "Could not populate shadow cib: %s (%d)\n", pcmk_strerror(rc), rc);
            goto cleanup;
        }

        rc = shadow_cib->cmds->signon(shadow_cib, crm_system_name, cib_command);
        if(rc != pcmk_ok) {
            fprintf(stderr, "Could not connect to shadow cib: %s (%d)\n", pcmk_strerror(rc), rc);
            goto cleanup;
        }

        do_calculations(data_set, data_set->input, NULL);
        run_simulation(data_set, shadow_cib, NULL, TRUE);
        rc = update_dataset(shadow_cib, data_set, FALSE);

    } else {
        cluster_status(data_set);
    }

  cleanup:
    /* Do not free data_set->input here, we need rsc->xml to be valid later on */
    cib_delete(shadow_cib);
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
                double seconds = delay / 1000.0;
                crm_trace("Calculated new delay of %.1fs due to %s", seconds, child->id);
                max_delay = delay;
            }
        }

    } else if(rsc) {
        char *key = crm_strdup_printf("%s_%s_0", rsc->id, RSC_STOP);
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
            double seconds = delay / 1000.0;
            crm_trace("Calculated new delay of %.1fs due to %s", seconds, rsc->id);
            max_delay = delay;
        }
    }

    return 5 + (max_delay / 1000);
}

#define waiting_for_starts(d, r, h) ((g_list_length(d) > 0) || \
                                    (resource_is_running_on((r), (h)) == FALSE))

/*!
 * \internal
 * \brief Restart a resource (on a particular host if requested).
 *
 * \param[in] rsc        The resource to restart
 * \param[in] host       The host to restart the resource on (or NULL for all)
 * \param[in] timeout_ms Consider failed if actions do not complete in this time
 *                       (specified in milliseconds, but a two-second
 *                       granularity is actually used; if 0, a timeout will be
 *                       calculated based on the resource timeout)
 * \param[in] cib        Connection to the CIB for modifying/checking resource
 *
 * \return pcmk_ok on success, -errno on failure (exits on certain failures)
 */
int
cli_resource_restart(resource_t * rsc, const char *host, int timeout_ms, cib_t * cib)
{
    int rc = 0;
    int lpc = 0;
    int before = 0;
    int step_timeout_s = 0;
    int sleep_interval = 2;
    int timeout = timeout_ms / 1000;

    bool is_clone = FALSE;
    char *rsc_id = NULL;
    char *orig_target_role = NULL;

    GList *list_delta = NULL;
    GList *target_active = NULL;
    GList *current_active = NULL;
    GList *restart_target_active = NULL;

    pe_working_set_t data_set;

    if(resource_is_running_on(rsc, host) == FALSE) {
        const char *id = rsc->clone_name?rsc->clone_name:rsc->id;
        if(host) {
            printf("%s is not running on %s and so cannot be restarted\n", id, host);
        } else {
            printf("%s is not running anywhere and so cannot be restarted\n", id);
        }
        return -ENXIO;
    }

    /* We might set the target-role meta-attribute */
    attr_set_type = XML_TAG_META_SETS;

    rsc_id = strdup(rsc->id);
    if(rsc->variant > pe_group) {
        is_clone = TRUE;
    }

    /*
      grab full cib
      determine originally active resources
      disable or ban
      poll cib and watch for affected resources to get stopped
      without --timeout, calculate the stop timeout for each step and wait for that
      if we hit --timeout or the service timeout, re-enable or un-ban, report failure and indicate which resources we couldn't take down
      if everything stopped, re-enable or un-ban
      poll cib and watch for affected resources to get started
      without --timeout, calculate the start timeout for each step and wait for that
      if we hit --timeout or the service timeout, report (different) failure and indicate which resources we couldn't bring back up
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

    restart_target_active = get_active_resources(host, data_set.resources);
    current_active = get_active_resources(host, data_set.resources);

    dump_list(current_active, "Origin");

    if(is_clone && host) {
        /* Stop the clone instance by banning it from the host */
        BE_QUIET = TRUE;
        rc = cli_resource_ban(rsc_id, host, NULL, cib);

    } else {
        /* Stop the resource by setting target-role to Stopped.
         * Remember any existing target-role so we can restore it later
         * (though it only makes any difference if it's Slave).
         */
        char *lookup_id = clone_strip(rsc->id);

        find_resource_attr(cib, XML_NVPAIR_ATTR_VALUE, lookup_id, NULL, NULL,
                           NULL, XML_RSC_ATTR_TARGET_ROLE, &orig_target_role);
        free(lookup_id);
        rc = cli_resource_update_attribute(rsc_id, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, RSC_STOPPED, FALSE, cib, &data_set);
    }
    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not set target-role for %s: %s (%d)\n", rsc_id, pcmk_strerror(rc), rc);
        if (current_active) {
            g_list_free_full(current_active, free);
        }
        if (restart_target_active) {
            g_list_free_full(restart_target_active, free);
        }
        free(rsc_id);
        return crm_exit(rc);
    }

    rc = update_dataset(cib, &data_set, TRUE);
    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not determine which resources would be stopped\n");
        goto failure;
    }

    target_active = get_active_resources(host, data_set.resources);
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

            if (current_active) {
                g_list_free_full(current_active, free);
            }
            current_active = get_active_resources(host, data_set.resources);
            g_list_free(list_delta);
            list_delta = subtract_lists(current_active, target_active);
            dump_list(current_active, "Current");
            dump_list(list_delta, "Delta");
        }

        crm_trace("%d (was %d) resources remaining", g_list_length(list_delta), before);
        if(before == g_list_length(list_delta)) {
            /* aborted during stop phase, print the contents of list_delta */
            fprintf(stderr, "Could not complete shutdown of %s, %d resources remaining\n", rsc_id, g_list_length(list_delta));
            display_list(list_delta, " * ");
            rc = -ETIME;
            goto failure;
        }

    }

    if(is_clone && host) {
        rc = cli_resource_clear(rsc_id, host, NULL, cib);

    } else if (orig_target_role) {
        rc = cli_resource_update_attribute(rsc_id, NULL, NULL,
                                           XML_RSC_ATTR_TARGET_ROLE,
                                           orig_target_role, FALSE, cib,
                                           &data_set);
        free(orig_target_role);
        orig_target_role = NULL;
    } else {
        rc = cli_resource_delete_attribute(rsc_id, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, cib, &data_set);
    }

    if(rc != pcmk_ok) {
        fprintf(stderr, "Could not unset target-role for %s: %s (%d)\n", rsc_id, pcmk_strerror(rc), rc);
        free(rsc_id);
        return crm_exit(rc);
    }

    if (target_active) {
        g_list_free_full(target_active, free);
    }
    target_active = restart_target_active;
    if (list_delta) {
        g_list_free(list_delta);
    }
    list_delta = subtract_lists(target_active, current_active);
    fprintf(stdout, "Waiting for %d resources to start again:\n", g_list_length(list_delta));
    display_list(list_delta, " * ");

    step_timeout_s = timeout / sleep_interval;
    while (waiting_for_starts(list_delta, rsc, host)) {
        before = g_list_length(list_delta);
        if(timeout_ms == 0) {
            step_timeout_s = max_delay_in(&data_set, list_delta) / sleep_interval;
        }

        /* We probably don't need the entire step timeout */
        for (lpc = 0; (lpc < step_timeout_s) && waiting_for_starts(list_delta, rsc, host); lpc++) {

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

            if (current_active) {
                g_list_free_full(current_active, free);
            }

            /* It's OK if dependent resources moved to a different node,
             * so we check active resources on all nodes.
             */
            current_active = get_active_resources(NULL, data_set.resources);
            g_list_free(list_delta);
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

    }

    rc = pcmk_ok;
    goto done;

  failure:
    if(is_clone && host) {
        cli_resource_clear(rsc_id, host, NULL, cib);
    } else if (orig_target_role) {
        cli_resource_update_attribute(rsc_id, NULL, NULL,
                                      XML_RSC_ATTR_TARGET_ROLE,
                                      orig_target_role, FALSE, cib, &data_set);
        free(orig_target_role);
    } else {
        cli_resource_delete_attribute(rsc_id, NULL, NULL, XML_RSC_ATTR_TARGET_ROLE, cib, &data_set);
    }

done:
    if (list_delta) {
        g_list_free(list_delta);
    }
    if (current_active) {
        g_list_free_full(current_active, free);
    }
    if (target_active && (target_active != restart_target_active)) {
        g_list_free_full(target_active, free);
    }
    if (restart_target_active) {
        g_list_free_full(restart_target_active, free);
    }
    cleanup_alloc_calculations(&data_set);
    free(rsc_id);
    return rc;
}

#define action_is_pending(action) \
    ((is_set((action)->flags, pe_action_optional) == FALSE) \
    && (is_set((action)->flags, pe_action_runnable) == TRUE) \
    && (is_set((action)->flags, pe_action_pseudo) == FALSE))

/*!
 * \internal
 * \brief Return TRUE if any actions in a list are pending
 *
 * \param[in] actions   List of actions to check
 *
 * \return TRUE if any actions in the list are pending, FALSE otherwise
 */
static bool
actions_are_pending(GListPtr actions)
{
    GListPtr action;

    for (action = actions; action != NULL; action = action->next) {
        if (action_is_pending((action_t *) action->data)) {
            return TRUE;
        }
    }
    return FALSE;
}

/*!
 * \internal
 * \brief Print pending actions to stderr
 *
 * \param[in] actions   List of actions to check
 *
 * \return void
 */
static void
print_pending_actions(GListPtr actions)
{
    GListPtr action;

    fprintf(stderr, "Pending actions:\n");
    for (action = actions; action != NULL; action = action->next) {
        action_t *a = (action_t *) action->data;

        if (action_is_pending(a)) {
            fprintf(stderr, "\tAction %d: %s", a->id, a->uuid);
            if (a->node) {
                fprintf(stderr, "\ton %s", a->node->details->uname);
            }
            fprintf(stderr, "\n");
        }
    }
}

/* For --wait, timeout (in seconds) to use if caller doesn't specify one */
#define WAIT_DEFAULT_TIMEOUT_S (60 * 60)

/* For --wait, how long to sleep between cluster state checks */
#define WAIT_SLEEP_S (2)

/*!
 * \internal
 * \brief Wait until all pending cluster actions are complete
 *
 * This waits until either the CIB's transition graph is idle or a timeout is
 * reached.
 *
 * \param[in] timeout_ms Consider failed if actions do not complete in this time
 *                       (specified in milliseconds, but one-second granularity
 *                       is actually used; if 0, a default will be used)
 * \param[in] cib        Connection to the CIB
 *
 * \return pcmk_ok on success, -errno on failure
 */
int
wait_till_stable(int timeout_ms, cib_t * cib)
{
    pe_working_set_t data_set;
    int rc = -1;
    int timeout_s = timeout_ms? ((timeout_ms + 999) / 1000) : WAIT_DEFAULT_TIMEOUT_S;
    time_t expire_time = time(NULL) + timeout_s;
    time_t time_diff;

    set_working_set_defaults(&data_set);
    do {

        /* Abort if timeout is reached */
        time_diff = expire_time - time(NULL);
        if (time_diff > 0) {
            crm_info("Waiting up to %d seconds for cluster actions to complete", time_diff);
        } else {
            print_pending_actions(data_set.actions);
            cleanup_alloc_calculations(&data_set);
            return -ETIME;
        }
        if (rc == pcmk_ok) { /* this avoids sleep on first loop iteration */
            sleep(WAIT_SLEEP_S);
        }

        /* Get latest transition graph */
        cleanup_alloc_calculations(&data_set);
        rc = update_working_set_from_cib(&data_set, cib);
        if (rc != pcmk_ok) {
            cleanup_alloc_calculations(&data_set);
            return rc;
        }
        do_calculations(&data_set, data_set.input, NULL);

    } while (actions_are_pending(data_set.actions));

    return pcmk_ok;
}

int
cli_resource_execute(const char *rsc_id, const char *rsc_action, GHashTable *override_hash, cib_t * cib, pe_working_set_t *data_set)
{
    int rc = pcmk_ok;
    svc_action_t *op = NULL;
    const char *rtype = NULL;
    const char *rprov = NULL;
    const char *rclass = NULL;
    const char *action = NULL;
    GHashTable *params = NULL;
    resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

    if (rsc == NULL) {
        CMD_ERR("Must supply a resource id with -r");
        return -ENXIO;
    }

    if (safe_str_eq(rsc_action, "force-check")) {
        action = "monitor";

    } else if (safe_str_eq(rsc_action, "force-stop")) {
        action = rsc_action+6;

    } else if (safe_str_eq(rsc_action, "force-start")
               || safe_str_eq(rsc_action, "force-demote")
               || safe_str_eq(rsc_action, "force-promote")) {
        action = rsc_action+6;

        if(rsc->variant >= pe_clone) {
            rc = cli_resource_search(rsc_id, data_set);
            if(rc > 0 && do_force == FALSE) {
                CMD_ERR("It is not safe to %s %s here: the cluster claims it is already active", action, rsc_id);
                CMD_ERR("Try setting target-role=stopped first or specifying --force");
                crm_exit(EPERM);
            }
        }
    }

    if(rsc->variant == pe_clone || rsc->variant == pe_master) {
        /* Grab the first child resource in the hope it's not a group */
        rsc = rsc->children->data;
    }

    if(rsc->variant == pe_group) {
        CMD_ERR("Sorry, --%s doesn't support group resources", rsc_action);
        crm_exit(EOPNOTSUPP);
    }

    rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    rprov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
    rtype = crm_element_value(rsc->xml, XML_ATTR_TYPE);

    if(safe_str_eq(rclass, "stonith")){
        CMD_ERR("Sorry, --%s doesn't support %s resources yet", rsc_action, rclass);
        crm_exit(EOPNOTSUPP);
    }

    params = generate_resource_params(rsc, data_set);
    op = resources_action_create(rsc->id, rclass, rprov, rtype, action, 0, -1, params, 0);

    if(do_trace) {
        setenv("OCF_TRACE_RA", "1", 1);
    }

    if(op && override_hash) {
        GHashTableIter iter;
        char *name = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, override_hash);
        while (g_hash_table_iter_next(&iter, (gpointer *) & name, (gpointer *) & value)) {
            printf("Overriding the cluser configuration for '%s' with '%s' = '%s'\n", rsc->id, name, value);
            g_hash_table_replace(op->params, strdup(name), strdup(value));
        }
    }

    if(op == NULL) {
        /* Re-run but with stderr enabled so we can display a sane error message */
        crm_enable_stderr(TRUE);
        resources_action_create(rsc->id, rclass, rprov, rtype, action, 0, -1, params, 0);
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
    return rc;
}

int
cli_resource_move(const char *rsc_id, const char *host_name, cib_t * cib, pe_working_set_t *data_set)
{
    int rc = -EINVAL;
    int count = 0;
    node_t *current = NULL;
    node_t *dest = pe_find_node(data_set->nodes, host_name);
    resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);
    bool cur_is_dest = FALSE;

    if (rsc == NULL) {
        CMD_ERR("Resource '%s' not moved: not found", rsc_id);
        return -ENXIO;

    } else if (scope_master && rsc->variant < pe_master) {
        resource_t *p = uber_parent(rsc);
        if(p->variant == pe_master) {
            CMD_ERR("Using parent '%s' for --move command instead of '%s'.", rsc->id, rsc_id);
            rsc_id = p->id;
            rsc = p;

        } else {
            CMD_ERR("Ignoring '--master' option: not valid for %s resources.",
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
        CMD_ERR("Resource '%s' not moved: active on multiple nodes", rsc_id);
        return rc;
    }

    if(dest == NULL) {
        CMD_ERR("Error performing operation: node '%s' is unknown", host_name);
        return -ENXIO;
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
            crm_info("%s is already %s on %s, reinforcing placement with location constraint.",
                     rsc_id, scope_master?"promoted":"active", dest->details->uname);
        } else {
            CMD_ERR("Error performing operation: %s is already %s on %s",
                    rsc_id, scope_master?"promoted":"active", dest->details->uname);
            return rc;
        }
    }

    /* Clear any previous constraints for 'dest' */
    cli_resource_clear(rsc_id, dest->details->uname, data_set->nodes, cib);

    /* Record an explicit preference for 'dest' */
    rc = cli_resource_prefer(rsc_id, dest->details->uname, cib);

    crm_trace("%s%s now prefers node %s%s",
              rsc->id, scope_master?" (master)":"", dest->details->uname, do_force?"(forced)":"");

    /* only ban the previous location if current location != destination location.
     * it is possible to use -M to enforce a location without regard of where the
     * resource is currently located */
    if(do_force && (cur_is_dest == FALSE)) {
        /* Ban the original location if possible */
        if(current) {
            (void)cli_resource_ban(rsc_id, current->details->uname, NULL, cib);

        } else if(count > 1) {
            CMD_ERR("Resource '%s' is currently %s in %d locations.  One may now move one to %s",
                    rsc_id, scope_master?"promoted":"active", count, dest->details->uname);
            CMD_ERR("You can prevent '%s' from being %s at a specific location with:"
                    " --ban %s--host <name>", rsc_id, scope_master?"promoted":"active", scope_master?"--master ":"");

        } else {
            crm_trace("Not banning %s from it's current location: not active", rsc_id);
        }
    }

    return rc;
}
