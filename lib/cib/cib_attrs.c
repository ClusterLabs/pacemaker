/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
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
#include <crm/common/xml_internal.h>
#include <crm/common/output_internal.h>
#include <crm/cib/internal.h>

/* could also check for possible truncation */
#define attr_snprintf(_str, _offset, _limit, ...) do {              \
    _offset += snprintf(_str + _offset,                             \
                        (_limit > _offset) ? _limit - _offset : 0,  \
                        __VA_ARGS__);                               \
    } while(0)

#define XPATH_MAX 1024

static pcmk__output_t *
new_output_object(const char *ty)
{
    int rc = pcmk_rc_ok;
    pcmk__output_t *out = NULL;
    const char* argv[] = { "", NULL };
    pcmk__supported_format_t formats[] = {
        PCMK__SUPPORTED_FORMAT_LOG,
        PCMK__SUPPORTED_FORMAT_TEXT,
        { NULL, NULL, NULL }
    };

    pcmk__register_formats(NULL, formats);
    rc = pcmk__output_new(&out, ty, NULL, (char**)argv);
    if ((rc != pcmk_rc_ok) || (out == NULL)) {
        crm_err("Can't out due to internal error: %s", pcmk_rc_str(rc));
        return NULL;
    }

    return out;
}

static int
find_attr(cib_t *cib, const char *section, const char *node_uuid,
          const char *attr_set_type, const char *set_name, const char *attr_id,
          const char *attr_name, const char *user_name, xmlNode **result)
{
    int offset = 0;
    int rc = pcmk_rc_ok;

    const char *xpath_base = NULL;
    char *xpath_string = NULL;
    xmlNode *xml_search = NULL;
    const char *set_type = NULL;
    const char *node_type = NULL;

    if (attr_set_type) {
        set_type = attr_set_type;
    } else {
        set_type = XML_TAG_ATTR_SETS;
    }

    if (pcmk__str_eq(section, XML_CIB_TAG_CRMCONFIG, pcmk__str_casei)) {
        node_uuid = NULL;
        set_type = XML_CIB_TAG_PROPSET;

    } else if (pcmk__strcase_any_of(section, XML_CIB_TAG_OPCONFIG, XML_CIB_TAG_RSCCONFIG,
                                    NULL)) {
        node_uuid = NULL;
        set_type = XML_TAG_META_SETS;

    } else if (pcmk__str_eq(section, XML_CIB_TAG_TICKETS, pcmk__str_casei)) {
        node_uuid = NULL;
        section = XML_CIB_TAG_STATUS;
        node_type = XML_CIB_TAG_TICKETS;

    } else if (node_uuid == NULL) {
        return EINVAL;
    }

    xpath_base = pcmk_cib_xpath_for(section);
    if (xpath_base == NULL) {
        crm_warn("%s CIB section not known", section);
        return ENOMSG;
    }

    xpath_string = calloc(1, XPATH_MAX);
    if (xpath_string == NULL) {
        crm_perror(LOG_CRIT, "Could not create xpath");
        return ENOMEM;
    }
    attr_snprintf(xpath_string, offset, XPATH_MAX, "%s", xpath_base);

    if (pcmk__str_eq(node_type, XML_CIB_TAG_TICKETS, pcmk__str_casei)) {
        attr_snprintf(xpath_string, offset, XPATH_MAX, "//%s", node_type);

    } else if (node_uuid) {
        const char *node_type = XML_CIB_TAG_NODE;

        if (pcmk__str_eq(section, XML_CIB_TAG_STATUS, pcmk__str_casei)) {
            node_type = XML_CIB_TAG_STATE;
            set_type = XML_TAG_TRANSIENT_NODEATTRS;
        }
        attr_snprintf(xpath_string, offset, XPATH_MAX, "//%s[@id='%s']", node_type,
                      node_uuid);
    }

    if (set_name) {
        attr_snprintf(xpath_string, offset, XPATH_MAX, "//%s[@id='%.128s']", set_type,
                      set_name);
    } else {
        attr_snprintf(xpath_string, offset, XPATH_MAX, "//%s", set_type);
    }

    attr_snprintf(xpath_string, offset, XPATH_MAX, "//nvpair");

    if (attr_id && attr_name) {
        attr_snprintf(xpath_string, offset, XPATH_MAX, "[@id='%s' and @name='%.128s']",
                      attr_id, attr_name);
    } else if (attr_id) {
        attr_snprintf(xpath_string, offset, XPATH_MAX, "[@id='%s']", attr_id);
    } else if (attr_name) {
        attr_snprintf(xpath_string, offset, XPATH_MAX, "[@name='%.128s']", attr_name);
    }

    CRM_LOG_ASSERT(offset > 0);

    rc = cib_internal_op(cib, CIB_OP_QUERY, NULL, xpath_string, NULL, &xml_search,
                         cib_sync_call | cib_scope_local | cib_xpath, user_name);
    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
        crm_trace("Query failed for attribute %s (section=%s, node=%s, set=%s, xpath=%s): %s",
                  attr_name, section, crm_str(node_uuid), crm_str(set_name), xpath_string,
                  pcmk_rc_str(rc));
        goto done;
    } else {
        rc = pcmk_rc_ok;
    }

    crm_log_xml_debug(xml_search, "Match");

  done:
    free(xpath_string);
    *result = xml_search;
    return rc;
}

static int
handle_multiples(pcmk__output_t *out, xmlNode *search, const char *attr_name)
{
    if (xml_has_children(search)) {
        xmlNode *child = NULL;
        out->info(out, "Multiple attributes match name=%s", attr_name);

        for (child = pcmk__xml_first_child(search); child != NULL;
             child = pcmk__xml_next(child)) {
            out->info(out, "  Value: %s \t(id=%s)",
                      crm_element_value(child, XML_NVPAIR_ATTR_VALUE), ID(child));
        }

        return ENOTUNIQ;

    } else {
        return pcmk_rc_ok;
    }
}

int
cib__update_node_attr(pcmk__output_t *out, cib_t *cib, int call_options, const char *section,
                      const char *node_uuid, const char *set_type, const char *set_name,
                      const char *attr_id, const char *attr_name, const char *attr_value,
                      const char *user_name, const char *node_type)
{
    const char *tag = NULL;
    int rc = pcmk_rc_ok;
    xmlNode *xml_top = NULL;
    xmlNode *xml_obj = NULL;
    xmlNode *xml_search = NULL;

    char *local_attr_id = NULL;
    char *local_set_name = NULL;

    CRM_CHECK(section != NULL, return EINVAL);
    CRM_CHECK(attr_value != NULL, return EINVAL);
    CRM_CHECK(attr_name != NULL || attr_id != NULL, return EINVAL);

    rc = find_attr(cib, section, node_uuid, set_type, set_name, attr_id,
                   attr_name, user_name, &xml_search);

    if (rc == pcmk_rc_ok) {
        if (handle_multiples(out, xml_search, attr_name) == ENOTUNIQ) {
            free_xml(xml_search);
            return ENOTUNIQ;
        } else {
            pcmk__str_update(&local_attr_id, crm_element_value(xml_search, XML_ATTR_ID));
            attr_id = local_attr_id;
            free_xml(xml_search);
            goto do_modify;
        }

    } else if (rc != ENXIO) {
        free_xml(xml_search);
        return rc;

        /* } else if(attr_id == NULL) { */
        /*     return EINVAL; */

    } else {
        free_xml(xml_search);
        crm_trace("%s does not exist, create it", attr_name);
        if (pcmk__str_eq(section, XML_CIB_TAG_TICKETS, pcmk__str_casei)) {
            node_uuid = NULL;
            section = XML_CIB_TAG_STATUS;
            node_type = XML_CIB_TAG_TICKETS;

            xml_top = create_xml_node(xml_obj, XML_CIB_TAG_STATUS);
            xml_obj = create_xml_node(xml_top, XML_CIB_TAG_TICKETS);

        } else if (pcmk__str_eq(section, XML_CIB_TAG_NODES, pcmk__str_casei)) {

            if (node_uuid == NULL) {
                return EINVAL;
            }

            if (pcmk__str_eq(node_type, "remote", pcmk__str_casei)) {
                xml_top = create_xml_node(xml_obj, XML_CIB_TAG_NODES);
                xml_obj = create_xml_node(xml_top, XML_CIB_TAG_NODE);
                crm_xml_add(xml_obj, XML_ATTR_TYPE, "remote");
                crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);
                crm_xml_add(xml_obj, XML_ATTR_UNAME, node_uuid);
            } else {
                tag = XML_CIB_TAG_NODE;
            }

        } else if (pcmk__str_eq(section, XML_CIB_TAG_STATUS, pcmk__str_casei)) {
            tag = XML_TAG_TRANSIENT_NODEATTRS;
            if (node_uuid == NULL) {
                return EINVAL;
            }

            xml_top = create_xml_node(xml_obj, XML_CIB_TAG_STATE);
            crm_xml_add(xml_top, XML_ATTR_ID, node_uuid);
            xml_obj = xml_top;

        } else {
            tag = section;
            node_uuid = NULL;
        }

        if (set_name == NULL) {
            if (pcmk__str_eq(section, XML_CIB_TAG_CRMCONFIG, pcmk__str_casei)) {
                local_set_name = strdup(CIB_OPTIONS_FIRST);

            } else if (pcmk__str_eq(node_type, XML_CIB_TAG_TICKETS, pcmk__str_casei)) {
                local_set_name = crm_strdup_printf("%s-%s", section,
                                                   XML_CIB_TAG_TICKETS);

            } else if (node_uuid) {
                local_set_name = crm_strdup_printf("%s-%s", section, node_uuid);

                if (set_type) {
                    char *tmp_set_name = local_set_name;

                    local_set_name = crm_strdup_printf("%s-%s", tmp_set_name,
                                                       set_type);
                    free(tmp_set_name);
                }
            } else {
                local_set_name = crm_strdup_printf("%s-options", section);
            }
            set_name = local_set_name;
        }

        if (attr_id == NULL) {
            local_attr_id = crm_strdup_printf("%s-%s", set_name, attr_name);
            crm_xml_sanitize_id(local_attr_id);
            attr_id = local_attr_id;

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

        if (node_uuid == NULL && !pcmk__str_eq(node_type, XML_CIB_TAG_TICKETS, pcmk__str_casei)) {
            if (pcmk__str_eq(section, XML_CIB_TAG_CRMCONFIG, pcmk__str_casei)) {
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
    }

  do_modify:
    xml_obj = crm_create_nvpair_xml(xml_obj, attr_id, attr_name, attr_value);
    if (xml_top == NULL) {
        xml_top = xml_obj;
    }

    crm_log_xml_trace(xml_top, "update_attr");
    rc = cib_internal_op(cib, CIB_OP_MODIFY, NULL, section, xml_top, NULL,
                         call_options | cib_quorum_override, user_name);
    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);

        out->err(out, "Error setting %s=%s (section=%s, set=%s): %s",
                 attr_name, attr_value, section, crm_str(set_name), pcmk_rc_str(rc));
        crm_log_xml_info(xml_top, "Update");
    } else {
        rc = pcmk_rc_ok;
    }

    free(local_set_name);
    free(local_attr_id);
    free_xml(xml_top);

    return rc;
}

int
cib__read_node_attr(pcmk__output_t *out, cib_t *cib, const char *section,
                    const char *node_uuid, const char *set_type, const char *set_name,
                    const char *attr_id, const char *attr_name, char **attr_value,
                    const char *user_name)
{
    xmlNode *xml_search = NULL;
    int rc = pcmk_rc_ok;

    CRM_ASSERT(attr_value != NULL);
    CRM_CHECK(section != NULL, return EINVAL);
    CRM_CHECK(attr_name != NULL || attr_id != NULL, return EINVAL);

    *attr_value = NULL;

    rc = find_attr(cib, section, node_uuid, set_type, set_name, attr_id, attr_name,
                   user_name, &xml_search);

    if (rc != pcmk_rc_ok || handle_multiples(out, xml_search, attr_name) == ENOTUNIQ) {
        crm_trace("Query failed for attribute %s (section=%s, node=%s, set=%s): %s",
                  attr_name, section, crm_str(set_name), crm_str(node_uuid), pcmk_strerror(rc));
    } else {
        pcmk__str_update(attr_value, crm_element_value(xml_search, XML_NVPAIR_ATTR_VALUE));
    }

    free_xml(xml_search);
    return rc;
}

int
cib__delete_node_attr(pcmk__output_t *out, cib_t *cib, int options, const char *section,
                      const char *node_uuid, const char *set_type, const char *set_name,
                      const char *attr_id, const char *attr_name, const char *attr_value,
                      const char *user_name)
{
    int rc = pcmk_rc_ok;
    xmlNode *xml_obj = NULL;
    xmlNode *xml_search = NULL;
    char *local_attr_id = NULL;

    CRM_CHECK(section != NULL, return EINVAL);
    CRM_CHECK(attr_name != NULL || attr_id != NULL, return EINVAL);

    if (attr_id == NULL) {
        rc = find_attr(cib, section, node_uuid, set_type, set_name, attr_id,
                       attr_name, user_name, &xml_search);

        if (rc != pcmk_rc_ok || handle_multiples(out, xml_search, attr_name) == ENOTUNIQ) {
            free_xml(xml_search);
            return rc;
        } else {
            pcmk__str_update(&local_attr_id, crm_element_value(xml_search, XML_ATTR_ID));
            attr_id = local_attr_id;
            free_xml(xml_search);
        }
    }

    xml_obj = crm_create_nvpair_xml(NULL, attr_id, attr_name, attr_value);

    rc = cib_internal_op(cib, CIB_OP_DELETE, NULL, section, xml_obj, NULL,
                         options | cib_quorum_override, user_name);
    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
    } else {
        rc = pcmk_rc_ok;
        out->info(out, "Deleted %s %s: id=%s%s%s%s%s",
                  section, node_uuid ? "attribute" : "option", local_attr_id,
                  set_name ? " set=" : "", set_name ? set_name : "",
                  attr_name ? " name=" : "", attr_name ? attr_name : "");
    }

    free(local_attr_id);
    free_xml(xml_obj);
    return rc;
}

int
find_nvpair_attr_delegate(cib_t *cib, const char *attr, const char *section,
                          const char *node_uuid, const char *attr_set_type, const char *set_name,
                          const char *attr_id, const char *attr_name, gboolean to_console,
                          char **value, const char *user_name)
{
    pcmk__output_t *out = NULL;
    xmlNode *xml_search = NULL;
    int rc = pcmk_ok;

    out = new_output_object(to_console ? "text" : "log");
    if (out == NULL) {
        return pcmk_err_generic;
    }

    rc = find_attr(cib, section, node_uuid, attr_set_type, set_name, attr_id,
                   attr_name, user_name, &xml_search);

    if (rc == pcmk_rc_ok) {
        rc = handle_multiples(out, xml_search, attr_name);

        if (rc == pcmk_rc_ok) {
            pcmk__str_update(value, crm_element_value(xml_search, attr));
        }
    }

    out->finish(out, CRM_EX_OK, true, NULL);
    free_xml(xml_search);
    pcmk__output_free(out);
    return pcmk_rc2legacy(rc);
}

int
update_attr_delegate(cib_t *cib, int call_options, const char *section,
                     const char *node_uuid, const char *set_type, const char *set_name,
                     const char *attr_id, const char *attr_name, const char *attr_value,
                     gboolean to_console, const char *user_name, const char *node_type)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_ok;

    out = new_output_object(to_console ? "text" : "log");
    if (out == NULL) {
        return pcmk_err_generic;
    }

    rc = cib__update_node_attr(out, cib, call_options, section, node_uuid, set_type,
                               set_name, attr_id, attr_name, attr_value, user_name,
                               node_type);

    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__output_free(out);
    return pcmk_rc2legacy(rc);
}

int
read_attr_delegate(cib_t *cib, const char *section, const char *node_uuid,
                   const char *set_type, const char *set_name, const char *attr_id,
                   const char *attr_name, char **attr_value, gboolean to_console,
                   const char *user_name)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_ok;

    out = new_output_object(to_console ? "text" : "log");
    if (out == NULL) {
        return pcmk_err_generic;
    }

    rc = cib__read_node_attr(out, cib, section, node_uuid, set_type, set_name,
                             attr_id, attr_name, attr_value, user_name);

    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__output_free(out);
    return pcmk_rc2legacy(rc);
}

int
delete_attr_delegate(cib_t *cib, int options, const char *section, const char *node_uuid,
                     const char *set_type, const char *set_name, const char *attr_id,
                     const char *attr_name, const char *attr_value, gboolean to_console,
                     const char *user_name)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_ok;

    out = new_output_object(to_console ? "text" : "log");
    if (out == NULL) {
        return pcmk_err_generic;
    }

    rc = cib__delete_node_attr(out, cib, options, section, node_uuid, set_type,
                               set_name, attr_id, attr_name, attr_value, user_name);

    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__output_free(out);
    return pcmk_rc2legacy(rc);
}

/*!
 * \internal
 * \brief Parse node UUID from search result
 *
 * \param[in]  result     XML search result
 * \param[out] uuid       If non-NULL, where to store parsed UUID
 * \param[out] is_remote  If non-NULL, set TRUE if result is remote node
 *
 * \return pcmk_ok if UUID was successfully parsed, -ENXIO otherwise
 */
static int
get_uuid_from_result(xmlNode *result, char **uuid, int *is_remote)
{
    int rc = -ENXIO;
    const char *tag;
    const char *parsed_uuid = NULL;
    int parsed_is_remote = FALSE;

    if (result == NULL) {
        return rc;
    }

    /* If there are multiple results, the first is sufficient */
    tag = (const char *) (result->name);
    if (pcmk__str_eq(tag, "xpath-query", pcmk__str_casei)) {
        result = pcmk__xml_first_child(result);
        CRM_CHECK(result != NULL, return rc);
        tag = (const char *) (result->name);
    }

    if (pcmk__str_eq(tag, XML_CIB_TAG_NODE, pcmk__str_casei)) {
        /* Result is <node> tag from <nodes> section */

        if (pcmk__str_eq(crm_element_value(result, XML_ATTR_TYPE), "remote", pcmk__str_casei)) {
            parsed_uuid = crm_element_value(result, XML_ATTR_UNAME);
            parsed_is_remote = TRUE;
        } else {
            parsed_uuid = ID(result);
            parsed_is_remote = FALSE;
        }

    } else if (pcmk__str_eq(tag, XML_CIB_TAG_RESOURCE, pcmk__str_casei)) {
        /* Result is <primitive> for ocf:pacemaker:remote resource */

        parsed_uuid = ID(result);
        parsed_is_remote = TRUE;

    } else if (pcmk__str_eq(tag, XML_CIB_TAG_NVPAIR, pcmk__str_casei)) {
        /* Result is remote-node parameter of <primitive> for guest node */

        parsed_uuid = crm_element_value(result, XML_NVPAIR_ATTR_VALUE);
        parsed_is_remote = TRUE;

    } else if (pcmk__str_eq(tag, XML_CIB_TAG_STATE, pcmk__str_casei)) {
        /* Result is <node_state> tag from <status> section */

        parsed_uuid = crm_element_value(result, XML_ATTR_UNAME);
        if (pcmk__xe_attr_is_true(result, XML_NODE_IS_REMOTE)) {
            parsed_is_remote = TRUE;
        }
    }

    if (parsed_uuid) {
        if (uuid) {
            *uuid = strdup(parsed_uuid);
        }
        if (is_remote) {
            *is_remote = parsed_is_remote;
        }
        rc = pcmk_ok;
    }

    return rc;
}

/* Search string to find a node by name, as:
 * - cluster or remote node in nodes section
 * - remote node in resources section
 * - guest node in resources section
 * - orphaned remote node or bundle guest node in status section
 */
#define XPATH_UPPER_TRANS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define XPATH_LOWER_TRANS "abcdefghijklmnopqrstuvwxyz"
#define XPATH_NODE \
    "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_NODES \
        "/" XML_CIB_TAG_NODE "[translate(@" XML_ATTR_UNAME ",'" XPATH_UPPER_TRANS "','" XPATH_LOWER_TRANS "') ='%s']" \
    "|/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_RESOURCES \
        "/" XML_CIB_TAG_RESOURCE \
        "[@class='ocf'][@provider='pacemaker'][@type='remote'][translate(@id,'" XPATH_UPPER_TRANS "','" XPATH_LOWER_TRANS "') ='%s']" \
    "|/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_RESOURCES \
        "/" XML_CIB_TAG_RESOURCE "/" XML_TAG_META_SETS "/" XML_CIB_TAG_NVPAIR \
        "[@name='" XML_RSC_ATTR_REMOTE_NODE "'][translate(@value,'" XPATH_UPPER_TRANS "','" XPATH_LOWER_TRANS "') ='%s']" \
    "|/" XML_TAG_CIB "/" XML_CIB_TAG_STATUS "/" XML_CIB_TAG_STATE \
        "[@" XML_NODE_IS_REMOTE "='true'][translate(@" XML_ATTR_UUID ",'" XPATH_UPPER_TRANS "','" XPATH_LOWER_TRANS "') ='%s']"

int
query_node_uuid(cib_t * the_cib, const char *uname, char **uuid, int *is_remote_node)
{
    int rc = pcmk_ok;
    char *xpath_string;
    xmlNode *xml_search = NULL;
    char *host_lowercase = NULL;

    CRM_ASSERT(uname != NULL);

    host_lowercase = g_ascii_strdown(uname, -1);

    if (uuid) {
        *uuid = NULL;
    }
    if (is_remote_node) {
        *is_remote_node = FALSE;
    }

    xpath_string = crm_strdup_printf(XPATH_NODE, host_lowercase, host_lowercase, host_lowercase, host_lowercase);
    if (cib_internal_op(the_cib, CIB_OP_QUERY, NULL, xpath_string, NULL,
                        &xml_search, cib_sync_call|cib_scope_local|cib_xpath,
                        NULL) == pcmk_ok) {
        rc = get_uuid_from_result(xml_search, uuid, is_remote_node);
    } else {
        rc = -ENXIO;
    }
    free(xpath_string);
    free_xml(xml_search);
    g_free(host_lowercase);

    if (rc != pcmk_ok) {
        crm_debug("Could not map node name '%s' to a UUID: %s",
                  uname, pcmk_strerror(rc));
    } else {
        crm_info("Mapped node name '%s' to UUID %s", uname, (uuid? *uuid : ""));
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
    CRM_CHECK(pcmk__str_eq(crm_element_name(xml_obj), XML_CIB_TAG_NODES, pcmk__str_casei),
              return -ENOMSG);
    CRM_ASSERT(xml_obj != NULL);
    crm_log_xml_trace(xml_obj, "Result section");

    rc = -ENXIO;
    *uname = NULL;

    for (a_child = pcmk__xml_first_child(xml_obj); a_child != NULL;
         a_child = pcmk__xml_next(a_child)) {

        if (pcmk__str_eq((const char *)a_child->name, XML_CIB_TAG_NODE,
                         pcmk__str_none)) {
            child_name = ID(a_child);
            if (pcmk__str_eq(uuid, child_name, pcmk__str_casei)) {
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

    if (pcmk__strcase_any_of(scope, "reboot", XML_CIB_TAG_STATUS, NULL)) {
        scope = XML_CIB_TAG_STATUS;
        attr_id = crm_strdup_printf("transient-standby-%.256s", uuid);

    } else {
        scope = XML_CIB_TAG_NODES;
        attr_id = crm_strdup_printf("standby-%.256s", uuid);
    }

    rc = update_attr_delegate(the_cib, cib_sync_call, scope, uuid, NULL, NULL,
                              attr_id, "standby", standby_value, TRUE, NULL, NULL);

    free(attr_id);
    return rc;
}
