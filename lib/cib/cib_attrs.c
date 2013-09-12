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
#include <crm/common/xml.h>
#include <crm/cib/internal.h>

#define attr_msg(level, fmt, args...) do {	\
	if(to_console) {			\
	    printf(fmt"\n", ##args);		\
	} else {				\
	    do_crm_log(level, fmt , ##args);	\
	}					\
    } while(0)

extern int
find_nvpair_attr_delegate(cib_t * the_cib, const char *attr, const char *section,
                          const char *node_uuid, const char *attr_set_type, const char *set_name,
                          const char *attr_id, const char *attr_name, gboolean to_console,
                          char **value, const char *user_name)
{
    int offset = 0;
    static int xpath_max = 1024;
    int rc = pcmk_ok;

    char *xpath_string = NULL;
    xmlNode *xml_search = NULL;
    const char *set_type = NULL;
    const char *node_type = NULL;

    if (attr_set_type) {
        set_type = attr_set_type;
    } else {
        set_type = XML_TAG_ATTR_SETS;
    }

    CRM_ASSERT(value != NULL);
    *value = NULL;

    if (safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
        node_uuid = NULL;
        set_type = XML_CIB_TAG_PROPSET;

    } else if (safe_str_eq(section, XML_CIB_TAG_OPCONFIG)
               || safe_str_eq(section, XML_CIB_TAG_RSCCONFIG)) {
        node_uuid = NULL;
        set_type = XML_TAG_META_SETS;

    } else if (safe_str_eq(section, XML_CIB_TAG_TICKETS)) {
        node_uuid = NULL;
        section = XML_CIB_TAG_STATUS;
        node_type = XML_CIB_TAG_TICKETS;

    } else if (node_uuid == NULL) {
        return -EINVAL;
    }

    xpath_string = calloc(1, xpath_max);
    offset += snprintf(xpath_string + offset, xpath_max - offset, "%.128s", get_object_path(section));

    if (safe_str_eq(node_type, XML_CIB_TAG_TICKETS)) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "//%s", node_type);

    } else if (node_uuid) {
        const char *node_type = XML_CIB_TAG_NODE;

        if (safe_str_eq(section, XML_CIB_TAG_STATUS)) {
            node_type = XML_CIB_TAG_STATE;
            set_type = XML_TAG_TRANSIENT_NODEATTRS;
        }
        offset +=
            snprintf(xpath_string + offset, xpath_max - offset, "//%s[@id='%s']", node_type,
                     node_uuid);
    }

    if (set_name) {
        offset +=
            snprintf(xpath_string + offset, xpath_max - offset, "//%s[@id='%.128s']", set_type,
                     set_name);
    } else {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "//%s", set_type);
    }

    offset += snprintf(xpath_string + offset, xpath_max - offset, "//nvpair[");
    if (attr_id) {
        offset += snprintf(xpath_string + offset, xpath_max - offset, "@id='%s'", attr_id);
    }

    if (attr_name) {
        if (attr_id) {
            offset += snprintf(xpath_string + offset, xpath_max - offset, " and ");
        }
        offset += snprintf(xpath_string + offset, xpath_max - offset, "@name='%.128s'", attr_name);
    }
    offset += snprintf(xpath_string + offset, xpath_max - offset, "]");

    rc = cib_internal_op(the_cib, CIB_OP_QUERY, NULL, xpath_string, NULL, &xml_search,
                         cib_sync_call | cib_scope_local | cib_xpath, user_name);

    if (rc != pcmk_ok) {
        crm_trace("Query failed for attribute %s (section=%s, node=%s, set=%s, xpath=%s): %s",
                  attr_name, section, crm_str(node_uuid), crm_str(set_name), xpath_string,
                  pcmk_strerror(rc));
        goto done;
    }

    crm_log_xml_debug(xml_search, "Match");
    if (xml_has_children(xml_search)) {
        xmlNode *child = NULL;

        rc = -ENOTUNIQ;
        attr_msg(LOG_WARNING, "Multiple attributes match name=%s", attr_name);

        for (child = __xml_first_child(xml_search); child != NULL; child = __xml_next(child)) {
            attr_msg(LOG_INFO, "  Value: %s \t(id=%s)",
                     crm_element_value(child, XML_NVPAIR_ATTR_VALUE), ID(child));
        }

    } else {
        const char *tmp = crm_element_value(xml_search, attr);

        if (tmp) {
            *value = strdup(tmp);
        }
    }

  done:
    free(xpath_string);
    free_xml(xml_search);
    return rc;
}

int
update_attr_delegate(cib_t * the_cib, int call_options,
                     const char *section, const char *node_uuid, const char *set_type,
                     const char *set_name, const char *attr_id, const char *attr_name,
                     const char *attr_value, gboolean to_console, const char *user_name)
{
    const char *tag = NULL;
    int rc = pcmk_ok;
    xmlNode *xml_top = NULL;
    xmlNode *xml_obj = NULL;

    char *local_attr_id = NULL;
    char *local_set_name = NULL;
    gboolean use_attributes_tag = FALSE;

    CRM_CHECK(section != NULL, return -EINVAL);
    CRM_CHECK(attr_value != NULL, return -EINVAL);
    CRM_CHECK(attr_name != NULL || attr_id != NULL, return -EINVAL);

    rc = find_nvpair_attr_delegate(the_cib, XML_ATTR_ID, section, node_uuid, set_type, set_name,
                                   attr_id, attr_name, to_console, &local_attr_id, user_name);
    if (rc == pcmk_ok) {
        attr_id = local_attr_id;
        goto do_modify;

    } else if (rc != -ENXIO) {
        return rc;

        /* } else if(attr_id == NULL) { */
        /*     return -EINVAL; */

    } else {
        const char *value = NULL;
        const char *node_type = NULL;
        xmlNode *cib_top = NULL;

        crm_trace("%s does not exist, create it", attr_name);
        rc = cib_internal_op(the_cib, CIB_OP_QUERY, NULL, "/cib", NULL, &cib_top,
                             cib_sync_call | cib_scope_local | cib_xpath | cib_no_children,
                             user_name);

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

        if (safe_str_eq(section, XML_CIB_TAG_TICKETS)) {
            node_uuid = NULL;
            section = XML_CIB_TAG_STATUS;
            node_type = XML_CIB_TAG_TICKETS;

            xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_STATUS);
            if (xml_top == NULL) {
                xml_top = xml_obj;
            }

            xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_TICKETS);

        } else if (safe_str_eq(section, XML_CIB_TAG_NODES)) {
            tag = XML_CIB_TAG_NODE;
            if (node_uuid == NULL) {
                return -EINVAL;
            }

        } else if (safe_str_eq(section, XML_CIB_TAG_STATUS)) {
            tag = XML_TAG_TRANSIENT_NODEATTRS;
            if (node_uuid == NULL) {
                return -EINVAL;
            }

            xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_STATE);
            crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);
            if (xml_top == NULL) {
                xml_top = xml_obj;
            }

        } else {
            tag = section;
            node_uuid = NULL;
        }

        if (set_name == NULL) {
            if (safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
                local_set_name = strdup(CIB_OPTIONS_FIRST);

            } else if (safe_str_eq(node_type, XML_CIB_TAG_TICKETS)) {
                local_set_name = crm_concat(section, XML_CIB_TAG_TICKETS, '-');

            } else if (node_uuid) {
                local_set_name = crm_concat(section, node_uuid, '-');

                if (set_type) {
                    char *tmp_set_name = local_set_name;

                    local_set_name = crm_concat(tmp_set_name, set_type, '-');
                    free(tmp_set_name);
                }
            } else {
                local_set_name = crm_concat(section, "options", '-');
            }
            set_name = local_set_name;
        }

        if (attr_id == NULL) {
            int lpc = 0;

            local_attr_id = crm_concat(set_name, attr_name, '-');
            attr_id = local_attr_id;

            /* Minimal attempt at sanitizing automatic IDs */
            for (lpc = 0; local_attr_id[lpc] != 0; lpc++) {
                switch (local_attr_id[lpc]) {
                    case ':':
                        local_attr_id[lpc] = '.';
                }
            }

        } else if (attr_name == NULL) {
            attr_name = attr_id;
        }

        crm_trace("Creating %s/%s", section, tag);
        if (tag != NULL) {
            xml_obj = create_xml_node(xml_obj, tag);
            crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);
            if (xml_top == NULL) {
                xml_top = xml_obj;
            }
        }

        if (node_uuid == NULL && safe_str_neq(node_type, XML_CIB_TAG_TICKETS)) {
            if (safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
                xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_PROPSET);
            } else {
                xml_obj = create_xml_node(xml_obj, XML_TAG_META_SETS);
            }

        } else if (set_type) {
            xml_obj = create_xml_node(xml_obj, set_type);

        } else {
            xml_obj = create_xml_node(xml_obj, XML_TAG_ATTR_SETS);
        }
        crm_xml_add(xml_obj, XML_ATTR_ID, set_name);

        if (xml_top == NULL) {
            xml_top = xml_obj;
        }

        if (use_attributes_tag) {
            xml_obj = create_xml_node(xml_obj, XML_TAG_ATTRS);
        }
    }

  do_modify:
    xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
    if (xml_top == NULL) {
        xml_top = xml_obj;
    }

    crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);

    crm_log_xml_trace(xml_top, "update_attr");
    rc = cib_internal_op(the_cib, CIB_OP_MODIFY, NULL, section, xml_top, NULL,
                         call_options | cib_quorum_override, user_name);

    if (rc < pcmk_ok) {
        attr_msg(LOG_ERR, "Error setting %s=%s (section=%s, set=%s): %s",
                 attr_name, attr_value, section, crm_str(set_name), pcmk_strerror(rc));
        crm_log_xml_info(xml_top, "Update");
    }

    free(local_set_name);
    free(local_attr_id);
    free_xml(xml_top);

    return rc;
}

int
read_attr_delegate(cib_t * the_cib,
                   const char *section, const char *node_uuid, const char *set_type,
                   const char *set_name, const char *attr_id, const char *attr_name,
                   char **attr_value, gboolean to_console, const char *user_name)
{
    int rc = pcmk_ok;

    CRM_ASSERT(attr_value != NULL);
    CRM_CHECK(section != NULL, return -EINVAL);
    CRM_CHECK(attr_name != NULL || attr_id != NULL, return -EINVAL);

    *attr_value = NULL;

    rc = find_nvpair_attr_delegate(the_cib, XML_NVPAIR_ATTR_VALUE, section, node_uuid, set_type,
                                   set_name, attr_id, attr_name, to_console, attr_value, user_name);
    if (rc != pcmk_ok) {
        crm_trace("Query failed for attribute %s (section=%s, node=%s, set=%s): %s",
                  attr_name, section, crm_str(set_name), crm_str(node_uuid), pcmk_strerror(rc));
    }
    return rc;
}

int
delete_attr_delegate(cib_t * the_cib, int options,
                     const char *section, const char *node_uuid, const char *set_type,
                     const char *set_name, const char *attr_id, const char *attr_name,
                     const char *attr_value, gboolean to_console, const char *user_name)
{
    int rc = pcmk_ok;
    xmlNode *xml_obj = NULL;
    char *local_attr_id = NULL;

    CRM_CHECK(section != NULL, return -EINVAL);
    CRM_CHECK(attr_name != NULL || attr_id != NULL, return -EINVAL);

    if (attr_id == NULL) {
        rc = find_nvpair_attr_delegate(the_cib, XML_ATTR_ID, section, node_uuid, set_type,
                                       set_name, attr_id, attr_name, to_console, &local_attr_id,
                                       user_name);
        if (rc != pcmk_ok) {
            return rc;
        }
        attr_id = local_attr_id;
    }

    xml_obj = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
    crm_xml_add(xml_obj, XML_ATTR_ID, attr_id);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, attr_name);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, attr_value);

    rc = cib_internal_op(the_cib, CIB_OP_DELETE, NULL, section, xml_obj, NULL,
                         options | cib_quorum_override, user_name);

    if (rc == pcmk_ok) {
        attr_msg(LOG_DEBUG, "Deleted %s %s: id=%s%s%s%s%s\n",
                 section, node_uuid ? "attribute" : "option", local_attr_id,
                 set_name ? " set=" : "", set_name ? set_name : "",
                 attr_name ? " name=" : "", attr_name ? attr_name : "");
    }

    free(local_attr_id);
    free_xml(xml_obj);
    return rc;
}

static int
get_remote_node_uuid(cib_t * the_cib, const char *uname, char **uuid)
{
#define REMOTE_NODE_XPATH "//nvpair[@name='remote-node'][@value='%s']"
#define REMOTE_NODE_XPATH2 "//primitive[@type='remote'][@provider='pacemaker'][@id='%s']"
    int rc = pcmk_ok;
    char *xpath_string = NULL;
    size_t len = strlen(REMOTE_NODE_XPATH) + strlen(uname) + 1;
    xmlNode *xml_search = NULL;

    xpath_string = calloc(1, len);
    sprintf(xpath_string, REMOTE_NODE_XPATH, uname);
    rc = cib_internal_op(the_cib, CIB_OP_QUERY, NULL, xpath_string, NULL, &xml_search,
                         cib_sync_call | cib_scope_local | cib_xpath, NULL);
    free(xpath_string);
    free(xml_search);
    xml_search = NULL;
    xpath_string = NULL;

    if (rc != pcmk_ok) {
        len = strlen(REMOTE_NODE_XPATH2) + strlen(uname) + 1;
        xpath_string = calloc(1, len);
        sprintf(xpath_string, REMOTE_NODE_XPATH2, uname);
        rc = cib_internal_op(the_cib, CIB_OP_QUERY, NULL, xpath_string, NULL, &xml_search,
                             cib_sync_call | cib_scope_local | cib_xpath, NULL);

        free(xpath_string);
        free(xml_search);
    }

    if (rc == pcmk_ok) {
        *uuid = strdup(uname);
    }

    return rc;
}

static int
get_cluster_node_uuid(cib_t * the_cib, const char *uname, char **uuid)
{
    int rc = pcmk_ok;
    xmlNode *a_child = NULL;
    xmlNode *xml_obj = NULL;
    xmlNode *fragment = NULL;
    const char *child_name = NULL;

    rc = the_cib->cmds->query(the_cib, XML_CIB_TAG_NODES, &fragment,
                              cib_sync_call | cib_scope_local);
    if (rc != pcmk_ok) {
        return rc;
    }

    xml_obj = fragment;
    CRM_CHECK(safe_str_eq(crm_element_name(xml_obj), XML_CIB_TAG_NODES), return -ENOMSG);
    CRM_ASSERT(xml_obj != NULL);
    crm_log_xml_debug(xml_obj, "Result section");

    rc = -ENXIO;
    *uuid = NULL;

    for (a_child = __xml_first_child(xml_obj); a_child != NULL; a_child = __xml_next(a_child)) {
        if (crm_str_eq((const char *)a_child->name, XML_CIB_TAG_NODE, TRUE)) {
            child_name = crm_element_value(a_child, XML_ATTR_UNAME);
            if (safe_str_eq(uname, child_name)) {
                child_name = ID(a_child);
                if (child_name != NULL) {
                    *uuid = strdup(child_name);
                    rc = pcmk_ok;
                }
                break;
            }
        }
    }

    free_xml(fragment);
    return rc;
}

int
query_node_uuid(cib_t * the_cib, const char *uname, char **uuid, int *is_remote_node)
{
    int rc = pcmk_ok;

    CRM_ASSERT(uname != NULL);
    CRM_ASSERT(uuid != NULL);

    rc = get_cluster_node_uuid(the_cib, uname, uuid);
    if (rc != pcmk_ok) {
        crm_debug("%s is not a cluster node, checking to see if remote-node", uname);
        rc = get_remote_node_uuid(the_cib, uname, uuid);
        if (rc != pcmk_ok) {
            crm_debug("%s is not a remote node either", uname);

        } else if (is_remote_node) {
            *is_remote_node = TRUE;
        }
    }

    if (rc != pcmk_ok) {
        crm_debug("Could not map name=%s to a UUID: %s\n", uname, pcmk_strerror(rc));
    } else {
        crm_info("Mapped %s to %s", uname, *uuid);
    }

    return rc;
}

int
query_node_uname(cib_t * the_cib, const char *uuid, char **uname)
{
    int rc = pcmk_ok;
    xmlNode *a_child = NULL;
    xmlNode *xml_obj = NULL;
    xmlNode *fragment = NULL;
    const char *child_name = NULL;

    CRM_ASSERT(uname != NULL);
    CRM_ASSERT(uuid != NULL);

    rc = the_cib->cmds->query(the_cib, XML_CIB_TAG_NODES, &fragment,
                              cib_sync_call | cib_scope_local);
    if (rc != pcmk_ok) {
        return rc;
    }

    xml_obj = fragment;
    CRM_CHECK(safe_str_eq(crm_element_name(xml_obj), XML_CIB_TAG_NODES), return -ENOMSG);
    CRM_ASSERT(xml_obj != NULL);
    crm_log_xml_trace(xml_obj, "Result section");

    rc = -ENXIO;
    *uname = NULL;

    for (a_child = __xml_first_child(xml_obj); a_child != NULL; a_child = __xml_next(a_child)) {
        if (crm_str_eq((const char *)a_child->name, XML_CIB_TAG_NODE, TRUE)) {
            child_name = ID(a_child);
            if (safe_str_eq(uuid, child_name)) {
                child_name = crm_element_value(a_child, XML_ATTR_UNAME);
                if (child_name != NULL) {
                    *uname = strdup(child_name);
                    rc = pcmk_ok;
                }
                break;
            }
        }
    }

    free_xml(fragment);
    return rc;
}

int
set_standby(cib_t * the_cib, const char *uuid, const char *scope, const char *standby_value)
{
    int rc = pcmk_ok;
    char *attr_id = NULL;

    CRM_CHECK(uuid != NULL, return -EINVAL);
    CRM_CHECK(standby_value != NULL, return -EINVAL);

    if (safe_str_eq(scope, "reboot") || safe_str_eq(scope, XML_CIB_TAG_STATUS)) {
        scope = XML_CIB_TAG_STATUS;
        attr_id = g_strdup_printf("transient-standby-%.256s", uuid);

    } else {
        scope = XML_CIB_TAG_NODES;
        attr_id = g_strdup_printf("standby-%.256s", uuid);
    }

    rc = update_attr_delegate(the_cib, cib_sync_call, scope, uuid, NULL, NULL,
                              attr_id, "standby", standby_value, TRUE, NULL);

    g_free(attr_id);
    return rc;
}
