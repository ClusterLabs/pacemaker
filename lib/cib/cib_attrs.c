/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EINVAL, ENOMSG, ENOTUNIQ, ENXIO
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdlib.h>                 // free
#include <string.h>                 // strdup

#include <glib.h>                   // g_*, gboolean, GString, TRUE, FALSE, etc.
#include <libxml/tree.h>            // xmlNode

#include <crm/common/internal.h>    // pcmk__str_*, etc.
#include <crm/common/logging.h>     // CRM_CHECK
#include <crm/common/nvpair.h>      // crm_create_nvpair_xml
#include <crm/common/options.h>     // PCMK_META_*, PCMK_VALUE_*
#include <crm/common/results.h>     // pcmk_rc_*, pcmk_ok, CRM_EX_OK, etc.
#include <crm/common/xml.h>         // PCMK_XA_*, PCMK_XE_*
#include <crm/cib.h>                // cib_*, *_delegate, query_node_uuid
#include <crm/cib/internal.h>       // cib__*, PCMK___CIB_*

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
        pcmk__err("Can't out due to internal error: %s", pcmk_rc_str(rc));
        return NULL;
    }

    return out;
}

static int
find_attr(cib_t *cib, const char *section, const char *node_uuid,
          const char *attr_set_type, const char *set_name, const char *attr_id,
          const char *attr_name, const char *user_name, xmlNode **result)
{
    int rc = pcmk_rc_ok;

    const char *xpath_base = NULL;
    GString *xpath = NULL;
    xmlNode *xml_search = NULL;
    const char *set_type = NULL;
    const char *node_type = NULL;

    if (attr_set_type) {
        set_type = attr_set_type;
    } else {
        set_type = PCMK_XE_INSTANCE_ATTRIBUTES;
    }

    if (pcmk__str_eq(section, PCMK_XE_CRM_CONFIG, pcmk__str_casei)) {
        node_uuid = NULL;
        set_type = PCMK_XE_CLUSTER_PROPERTY_SET;

    } else if (pcmk__strcase_any_of(section,
                                    PCMK_XE_OP_DEFAULTS, PCMK_XE_RSC_DEFAULTS,
                                    NULL)) {
        node_uuid = NULL;
        set_type = PCMK_XE_META_ATTRIBUTES;

    } else if (pcmk__str_eq(section, PCMK_XE_TICKETS, pcmk__str_casei)) {
        node_uuid = NULL;
        section = PCMK_XE_STATUS;
        node_type = PCMK_XE_TICKETS;

    } else if (node_uuid == NULL) {
        return EINVAL;
    }

    xpath_base = pcmk_cib_xpath_for(section);
    if (xpath_base == NULL) {
        pcmk__warn("%s CIB section not known", section);
        return ENOMSG;
    }

    xpath = g_string_sized_new(1024);
    g_string_append(xpath, xpath_base);

    if (pcmk__str_eq(node_type, PCMK_XE_TICKETS, pcmk__str_casei)) {
        pcmk__g_strcat(xpath, "//", node_type, NULL);

    } else if (node_uuid) {
        const char *node_type = PCMK_XE_NODE;

        if (pcmk__str_eq(section, PCMK_XE_STATUS, pcmk__str_casei)) {
            node_type = PCMK__XE_NODE_STATE;
            set_type = PCMK__XE_TRANSIENT_ATTRIBUTES;
        }
        pcmk__g_strcat(xpath,
                       "//", node_type, "[@" PCMK_XA_ID "='", node_uuid, "']",
                       NULL);
    }

    pcmk__g_strcat(xpath, "//", set_type, NULL);
    if (set_name) {
        pcmk__g_strcat(xpath, "[@" PCMK_XA_ID "='", set_name, "']", NULL);
    }

    g_string_append(xpath, "//nvpair");

    if (attr_id && attr_name) {
        pcmk__g_strcat(xpath,
                       "[@" PCMK_XA_ID "='", attr_id, "' "
                       "and @" PCMK_XA_NAME "='", attr_name, "']", NULL);

    } else if (attr_id) {
        pcmk__g_strcat(xpath, "[@" PCMK_XA_ID "='", attr_id, "']", NULL);

    } else if (attr_name) {
        pcmk__g_strcat(xpath, "[@" PCMK_XA_NAME "='", attr_name, "']", NULL);
    }

    rc = cib_internal_op(cib, PCMK__CIB_REQUEST_QUERY, NULL,
                         (const char *) xpath->str, NULL, &xml_search,
                         cib_sync_call|cib_xpath, user_name);
    rc = pcmk_legacy2rc(rc);

    if (rc != pcmk_rc_ok) {
        pcmk__trace("Query failed for attribute %s (section=%s, node=%s, "
                    "set=%s, xpath=%s): %s",
                    attr_name, section, pcmk__s(node_uuid, "<null>"),
                    pcmk__s(set_name, "<null>"), xpath->str, pcmk_rc_str(rc));
    } else {
        pcmk__log_xml_debug(xml_search, "Match");
    }

    g_string_free(xpath, TRUE);
    *result = xml_search;
    return rc;
}

static int
handle_multiples(pcmk__output_t *out, xmlNode *search, const char *attr_name)
{
    if ((search != NULL) && (search->children != NULL)) {
        pcmk__warn_multiple_name_matches(out, search, attr_name);
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

    CRM_CHECK((out != NULL) && (cib != NULL) && (section != NULL)
              && ((attr_id != NULL) || (attr_name != NULL))
              && (attr_value != NULL), return EINVAL);

    rc = find_attr(cib, section, node_uuid, set_type, set_name, attr_id,
                   attr_name, user_name, &xml_search);

    if (rc == pcmk_rc_ok) {
        if (handle_multiples(out, xml_search, attr_name) == ENOTUNIQ) {
            pcmk__xml_free(xml_search);
            return ENOTUNIQ;
        } else {
            local_attr_id = pcmk__xe_get_copy(xml_search, PCMK_XA_ID);
            attr_id = local_attr_id;
            pcmk__xml_free(xml_search);
            goto do_modify;
        }

    } else if (rc != ENXIO) {
        pcmk__xml_free(xml_search);
        return rc;

        /* } else if(attr_id == NULL) { */
        /*     return EINVAL; */

    } else {
        pcmk__xml_free(xml_search);
        pcmk__trace("%s does not exist, create it", attr_name);
        if (pcmk__str_eq(section, PCMK_XE_TICKETS, pcmk__str_casei)) {
            node_uuid = NULL;
            section = PCMK_XE_STATUS;
            node_type = PCMK_XE_TICKETS;

            xml_top = pcmk__xe_create(xml_obj, PCMK_XE_STATUS);
            xml_obj = pcmk__xe_create(xml_top, PCMK_XE_TICKETS);

        } else if (pcmk__str_eq(section, PCMK_XE_NODES, pcmk__str_casei)) {

            if (node_uuid == NULL) {
                return EINVAL;
            }

            if (pcmk__str_eq(node_type, PCMK_VALUE_REMOTE, pcmk__str_casei)) {
                xml_top = pcmk__xe_create(xml_obj, PCMK_XE_NODES);
                xml_obj = pcmk__xe_create(xml_top, PCMK_XE_NODE);
                pcmk__xe_set(xml_obj, PCMK_XA_TYPE, PCMK_VALUE_REMOTE);
                pcmk__xe_set(xml_obj, PCMK_XA_ID, node_uuid);
                pcmk__xe_set(xml_obj, PCMK_XA_UNAME, node_uuid);
            } else {
                tag = PCMK_XE_NODE;
            }

        } else if (pcmk__str_eq(section, PCMK_XE_STATUS, pcmk__str_casei)) {
            tag = PCMK__XE_TRANSIENT_ATTRIBUTES;
            if (node_uuid == NULL) {
                return EINVAL;
            }

            xml_top = pcmk__xe_create(xml_obj, PCMK__XE_NODE_STATE);
            pcmk__xe_set(xml_top, PCMK_XA_ID, node_uuid);
            xml_obj = xml_top;

        } else {
            tag = section;
            node_uuid = NULL;
        }

        if (set_name == NULL) {
            if (pcmk__str_eq(section, PCMK_XE_CRM_CONFIG, pcmk__str_casei)) {
                local_set_name =
                    pcmk__str_copy(PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS);

            } else if (pcmk__str_eq(node_type, PCMK_XE_TICKETS,
                                    pcmk__str_casei)) {
                local_set_name = pcmk__assert_asprintf("%s-%s", section,
                                                       PCMK_XE_TICKETS);

            } else if (node_uuid) {
                local_set_name = pcmk__assert_asprintf("%s-%s", section,
                                                       node_uuid);

                if (set_type) {
                    char *tmp_set_name = local_set_name;

                    local_set_name = pcmk__assert_asprintf("%s-%s",
                                                           tmp_set_name,
                                                           set_type);
                    free(tmp_set_name);
                }
            } else {
                local_set_name = pcmk__assert_asprintf("%s-options", section);
            }
            set_name = local_set_name;
        }

        if (attr_id == NULL) {
            local_attr_id = pcmk__assert_asprintf("%s-%s", set_name, attr_name);
            pcmk__xml_sanitize_id(local_attr_id);
            attr_id = local_attr_id;

        } else if (attr_name == NULL) {
            attr_name = attr_id;
        }

        pcmk__trace("Creating %s/%s", section, tag);
        if (tag != NULL) {
            xml_obj = pcmk__xe_create(xml_obj, tag);
            pcmk__xe_set(xml_obj, PCMK_XA_ID, node_uuid);
            if (xml_top == NULL) {
                xml_top = xml_obj;
            }
        }

        if ((node_uuid == NULL)
            && !pcmk__str_eq(node_type, PCMK_XE_TICKETS, pcmk__str_casei)) {

            if (pcmk__str_eq(section, PCMK_XE_CRM_CONFIG, pcmk__str_casei)) {
                xml_obj = pcmk__xe_create(xml_obj,
                                          PCMK_XE_CLUSTER_PROPERTY_SET);
            } else {
                xml_obj = pcmk__xe_create(xml_obj, PCMK_XE_META_ATTRIBUTES);
            }

        } else if (set_type) {
            xml_obj = pcmk__xe_create(xml_obj, set_type);

        } else {
            xml_obj = pcmk__xe_create(xml_obj, PCMK_XE_INSTANCE_ATTRIBUTES);
        }
        pcmk__xe_set(xml_obj, PCMK_XA_ID, set_name);

        if (xml_top == NULL) {
            xml_top = xml_obj;
        }
    }

  do_modify:
    xml_obj = crm_create_nvpair_xml(xml_obj, attr_id, attr_name, attr_value);
    if (xml_top == NULL) {
        xml_top = xml_obj;
    }

    pcmk__log_xml_trace(xml_top, "update_attr");
    rc = cib_internal_op(cib, PCMK__CIB_REQUEST_MODIFY, NULL, section, xml_top,
                         NULL, call_options, user_name);

    if (!pcmk__is_set(call_options, cib_sync_call) && (cib->variant != cib_file)
        && (rc >= 0)) {
        // For async call, positive rc is the call ID (file always synchronous)
        rc = pcmk_rc_ok;
    } else {
        rc = pcmk_legacy2rc(rc);
    }

    if (rc != pcmk_rc_ok) {
        out->err(out, "Error setting %s=%s (section=%s, set=%s): %s",
                 attr_name, attr_value, section, pcmk__s(set_name, "<null>"),
                 pcmk_rc_str(rc));
        pcmk__log_xml_info(xml_top, "Update");
    }

    free(local_set_name);
    free(local_attr_id);
    pcmk__xml_free(xml_top);

    return rc;
}

int
cib__get_node_attrs(pcmk__output_t *out, cib_t *cib, const char *section,
                    const char *node_uuid, const char *set_type, const char *set_name,
                    const char *attr_id, const char *attr_name, const char *user_name,
                    xmlNode **result)
{
    int rc = pcmk_rc_ok;

    pcmk__assert(result != NULL);
    CRM_CHECK(section != NULL, return EINVAL);

    *result = NULL;

    rc = find_attr(cib, section, node_uuid, set_type, set_name, attr_id, attr_name,
                   user_name, result);

    if (rc != pcmk_rc_ok) {
        pcmk__trace("Query failed for attribute %s (section=%s node=%s "
                    "set=%s): %s",
                    pcmk__s(attr_name, "with unspecified name"), section,
                    pcmk__s(set_name, "<null>"), pcmk__s(node_uuid, "<null>"),
                    pcmk_rc_str(rc));
    }

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
            pcmk__xml_free(xml_search);
            return rc;
        } else {
            local_attr_id = pcmk__xe_get_copy(xml_search, PCMK_XA_ID);
            attr_id = local_attr_id;
            pcmk__xml_free(xml_search);
        }
    }

    xml_obj = crm_create_nvpair_xml(NULL, attr_id, attr_name, attr_value);

    rc = cib_internal_op(cib, PCMK__CIB_REQUEST_DELETE, NULL, section, xml_obj,
                         NULL, options, user_name);

    if (!pcmk__is_set(options, cib_sync_call) && (cib->variant != cib_file)
        && (rc >= 0)) {
        // For async call, positive rc is the call ID (file always synchronous)
        rc = pcmk_rc_ok;
    } else {
        rc = pcmk_legacy2rc(rc);
    }

    if (rc == pcmk_rc_ok) {
        out->info(out, "Deleted %s %s: id=%s%s%s%s%s",
                  section, node_uuid ? "attribute" : "option", local_attr_id,
                  set_name ? " set=" : "", set_name ? set_name : "",
                  attr_name ? " name=" : "", attr_name ? attr_name : "");
    }
    free(local_attr_id);
    pcmk__xml_free(xml_obj);
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
            pcmk__str_update(value, pcmk__xe_get(xml_search, attr));
        }
    }

    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__xml_free(xml_search);
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
    xmlNode *result = NULL;
    int rc = pcmk_ok;

    out = new_output_object(to_console ? "text" : "log");
    if (out == NULL) {
        return pcmk_err_generic;
    }

    rc = cib__get_node_attrs(out, cib, section, node_uuid, set_type, set_name,
                             attr_id, attr_name, user_name, &result);

    if (rc == pcmk_rc_ok) {
        if (result->children == NULL) {
            pcmk__str_update(attr_value, pcmk__xe_get(result, PCMK_XA_VALUE));
        } else {
            rc = ENOTUNIQ;
        }
    }

    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__xml_free(result);
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
get_uuid_from_result(const xmlNode *result, char **uuid, int *is_remote)
{
    int rc = -ENXIO;
    const char *parsed_uuid = NULL;
    int parsed_is_remote = FALSE;

    if (result == NULL) {
        return rc;
    }

    /* If there are multiple results, the first is sufficient */
    if (pcmk__xe_is(result, PCMK__XE_XPATH_QUERY)) {
        result = pcmk__xe_first_child(result, NULL, NULL, NULL);
        CRM_CHECK(result != NULL, return rc);
    }

    if (pcmk__xe_is(result, PCMK_XE_NODE)) {
        // Result is PCMK_XE_NODE element from PCMK_XE_NODES section

        if (pcmk__str_eq(pcmk__xe_get(result, PCMK_XA_TYPE), PCMK_VALUE_REMOTE,
                         pcmk__str_casei)) {
            parsed_uuid = pcmk__xe_get(result, PCMK_XA_UNAME);
            parsed_is_remote = TRUE;
        } else {
            parsed_uuid = pcmk__xe_id(result);
            parsed_is_remote = FALSE;
        }

    } else if (pcmk__xe_is(result, PCMK_XE_PRIMITIVE)) {
        /* Result is <primitive> for ocf:pacemaker:remote resource */

        parsed_uuid = pcmk__xe_id(result);
        parsed_is_remote = TRUE;

    } else if (pcmk__xe_is(result, PCMK_XE_NVPAIR)) {
        /* Result is PCMK_META_REMOTE_NODE parameter of <primitive> for guest
         * node
         */

        parsed_uuid = pcmk__xe_get(result, PCMK_XA_VALUE);
        parsed_is_remote = TRUE;

    } else if (pcmk__xe_is(result, PCMK__XE_NODE_STATE)) {
        // Result is PCMK__XE_NODE_STATE element from PCMK_XE_STATUS section

        parsed_uuid = pcmk__xe_get(result, PCMK_XA_UNAME);
        if (pcmk__xe_attr_is_true(result, PCMK_XA_REMOTE_NODE)) {
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
 * - removed remote node or bundle guest node in status section
 */
#define XPATH_UPPER_TRANS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define XPATH_LOWER_TRANS "abcdefghijklmnopqrstuvwxyz"
#define XPATH_NODE \
    "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_NODES \
        "/" PCMK_XE_NODE "[translate(@" PCMK_XA_UNAME ",'" XPATH_UPPER_TRANS "','" XPATH_LOWER_TRANS "') ='%s']" \
    "|/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_RESOURCES \
        "/" PCMK_XE_PRIMITIVE \
        "[@class='ocf'][@provider='pacemaker'][@type='remote'][translate(@id,'" XPATH_UPPER_TRANS "','" XPATH_LOWER_TRANS "') ='%s']" \
    "|/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_RESOURCES \
        "/" PCMK_XE_PRIMITIVE "/" PCMK_XE_META_ATTRIBUTES "/" PCMK_XE_NVPAIR \
        "[@name='" PCMK_META_REMOTE_NODE "'][translate(@value,'" XPATH_UPPER_TRANS "','" XPATH_LOWER_TRANS "') ='%s']" \
    "|/" PCMK_XE_CIB "/" PCMK_XE_STATUS "/" PCMK__XE_NODE_STATE \
        "[@" PCMK_XA_REMOTE_NODE "='true'][translate(@" PCMK_XA_ID ",'" XPATH_UPPER_TRANS "','" XPATH_LOWER_TRANS "') ='%s']"

int
query_node_uuid(cib_t * the_cib, const char *uname, char **uuid, int *is_remote_node)
{
    int rc = pcmk_ok;
    char *xpath_string;
    xmlNode *xml_search = NULL;
    char *host_lowercase = NULL;

    pcmk__assert(uname != NULL);

    host_lowercase = g_ascii_strdown(uname, -1);

    if (uuid) {
        *uuid = NULL;
    }
    if (is_remote_node) {
        *is_remote_node = FALSE;
    }

    xpath_string = pcmk__assert_asprintf(XPATH_NODE, host_lowercase,
                                         host_lowercase, host_lowercase,
                                         host_lowercase);
    if (cib_internal_op(the_cib, PCMK__CIB_REQUEST_QUERY, NULL, xpath_string,
                        NULL, &xml_search, cib_sync_call|cib_xpath,
                        NULL) == pcmk_ok) {
        rc = get_uuid_from_result(xml_search, uuid, is_remote_node);
    } else {
        rc = -ENXIO;
    }
    free(xpath_string);
    pcmk__xml_free(xml_search);
    g_free(host_lowercase);

    if (rc != pcmk_ok) {
        pcmk__debug("Could not map node name '%s' to a UUID: %s", uname,
                    pcmk_strerror(rc));
    } else {
        pcmk__info("Mapped node name '%s' to UUID %s", uname,
                   ((uuid != NULL)? *uuid : ""));
    }
    return rc;
}
