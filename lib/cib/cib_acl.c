/* 
 * Copyright (C) 2009 Yan Gao <ygao@novell.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

#include <pwd.h>

#include <crm/cib.h>
#include <cib_private.h>
#include <crm/common/xml.h>

typedef struct acl_obj_s {
    const char *mode;
    const char *tag;
    const char *ref;
    const char *xpath;
    const char *attribute;
} acl_obj_t;

typedef struct xml_perm_s {
    const char *mode;
    GHashTable *attribute_perms;
} xml_perm_t;

static gboolean req_by_privileged(xmlNode * request);
static xmlNode *diff_xml_object_orig(xmlNode * old, xmlNode * new, gboolean suppress,
                                     xmlNode * new_diff);

static gboolean unpack_user_acl(xmlNode * xml_acls, const char *user, GListPtr * user_acl);
static gboolean user_match(const char *user, const char *uid);
static gboolean unpack_acl(xmlNode * xml_acls, xmlNode * xml_acl, GListPtr * acl);
static gboolean unpack_role_acl(xmlNode * xml_acls, const char *role, GListPtr * acl);
static gboolean acl_append(xmlNode * acl_child, GListPtr * acl);
static void free_acl(GListPtr acl);
static gboolean parse_acl_xpath(xmlNode * xml, GListPtr acl, GListPtr * parsed_acl);

static gboolean gen_xml_perms(xmlNode * xml, GListPtr acl, GHashTable ** xml_perms);
static int search_xml_children(GListPtr * children, xmlNode * root,
                               const char *tag, const char *field, const char *value,
                               gboolean search_matches);
static int search_xpath_objects(GListPtr * objects, xmlNode * xml_obj, const char *xpath);
static gboolean update_xml_perms(xmlNode * xml, acl_obj_t * acl_obj, GHashTable * xml_perms);
static gboolean update_xml_children_perms(xmlNode * xml, const char *mode, GHashTable * xml_perms);
static void free_xml_perm(gpointer xml_perm);

static gboolean acl_filter_xml(xmlNode * xml, GHashTable * xml_perms);
static gboolean acl_check_diff_xml(xmlNode * xml, GHashTable * xml_perms);

gboolean
acl_enabled(GHashTable * config_hash)
{
    const char *value = NULL;
    gboolean rc = FALSE;

    value = cib_pref(config_hash, "enable-acl");
    rc = crm_is_true(value);

    crm_debug("CIB ACL is %s", rc ? "enabled" : "disabled");
    return rc;
}

/* rc = TRUE if orig_cib has been filtered*/
/* That means *filtered_cib rather than orig_cib should be exploited afterwards*/
gboolean
acl_filter_cib(xmlNode * request, xmlNode * current_cib, xmlNode * orig_cib,
               xmlNode ** filtered_cib)
{
    const char *user = NULL;
    xmlNode *xml_acls = NULL;
    xmlNode *tmp_cib = NULL;
    GListPtr user_acl = NULL;
    GHashTable *xml_perms = NULL;

    *filtered_cib = NULL;

    if (req_by_privileged(request)) {
        return FALSE;
    }

    if (orig_cib == NULL) {
        return FALSE;
    }

    if (current_cib == NULL) {
        return TRUE;
    }

    xml_acls = get_object_root(XML_CIB_TAG_ACLS, current_cib);
    if (xml_acls == NULL) {
        crm_warn("Ordinary users cannot access the CIB without any defined ACLs: '%s'", user);
        return TRUE;
    }

    user = crm_element_value(request, F_CIB_USER);
    unpack_user_acl(xml_acls, user, &user_acl);

    tmp_cib = copy_xml(orig_cib);

    gen_xml_perms(tmp_cib, user_acl, &xml_perms);

    if (acl_filter_xml(tmp_cib, xml_perms)) {
        crm_warn("User '%s' doesn't have the permission for the whole CIB", user);
        tmp_cib = NULL;
    }

    g_hash_table_destroy(xml_perms);
    free_acl(user_acl);

    *filtered_cib = tmp_cib;
    return TRUE;
}

/* rc = TRUE if the request passes the ACL check */
/* rc = FALSE if the permission is denied */
gboolean
acl_check_diff(xmlNode * request, xmlNode * current_cib, xmlNode * result_cib, xmlNode * diff)
{
    const char *user = NULL;
    xmlNode *xml_acls = NULL;
    GListPtr user_acl = NULL;
    xmlNode *orig_diff = NULL;
    xmlNode *diff_child = NULL;
    int rc = FALSE;

    if (req_by_privileged(request)) {
        return TRUE;
    }

    if (diff == NULL) {
        return TRUE;
    }

    if (current_cib == NULL) {
        return FALSE;
    }

    xml_acls = get_object_root(XML_CIB_TAG_ACLS, current_cib);
    if (xml_acls == NULL) {
        crm_warn("Ordinary users cannot access the CIB without any defined ACLs: '%s'", user);
        return FALSE;
    }

    user = crm_element_value(request, F_CIB_USER);
    unpack_user_acl(xml_acls, user, &user_acl);

    orig_diff = diff_xml_object_orig(current_cib, result_cib, FALSE, diff);

    for (diff_child = __xml_first_child(orig_diff); diff_child; diff_child = __xml_next(diff_child)) {
        const char *tag = crm_element_name(diff_child);
        GListPtr parsed_acl = NULL;
        xmlNode *diff_cib = NULL;

        crm_debug("Preparing ACL checking on '%s'", tag);

        if (crm_str_eq(tag, XML_TAG_DIFF_REMOVED, TRUE)) {
            crm_debug("Parsing any xpaths under the ACL according to the current CIB");
            parse_acl_xpath(current_cib, user_acl, &parsed_acl);
        } else if (crm_str_eq(tag, XML_TAG_DIFF_ADDED, TRUE)) {
            crm_debug("Parsing any xpaths under the ACL according to the result CIB");
            parse_acl_xpath(result_cib, user_acl, &parsed_acl);
        } else {
            continue;
        }

        for (diff_cib = __xml_first_child(diff_child); diff_cib; diff_cib = __xml_next(diff_cib)) {
            GHashTable *xml_perms = NULL;

            gen_xml_perms(diff_cib, parsed_acl, &xml_perms);
            rc = acl_check_diff_xml(diff_cib, xml_perms);
            g_hash_table_destroy(xml_perms);

            if (rc == FALSE) {
                crm_warn("User '%s' doesn't have enough permission to modify the CIB objects",
                         user);
                goto done;
            }
        }
        free_acl(parsed_acl);
    }

  done:
    free_xml(orig_diff);
    free_acl(user_acl);
    return rc;
}

static gboolean
req_by_privileged(xmlNode * request)
{
    const char *user = crm_element_value(request, F_CIB_USER);

    if (user == NULL || strcmp(user, "") == 0) {
        crm_debug("Request without an explicit client user: op=%s, origin=%s, client=%s",
                  crm_element_value(request, F_CIB_OPERATION),
                  crm_element_value(request, F_ORIG) ? crm_element_value(request, F_ORIG) : "local",
                  crm_element_value(request, F_CIB_CLIENTNAME));
        return TRUE;
    }

    if (is_privileged(user)) {
        return TRUE;
    }
    return FALSE;
}

/* Borrowed from lib/common/xml.c: diff_xml_object() */
/* But if a new format of diff ("new_diff") exists, we could reuse its "diff-removed" part */
/* So it would be more time-saving than generating the diff from start */
static xmlNode *
diff_xml_object_orig(xmlNode * old, xmlNode * new, gboolean suppress, xmlNode * new_diff)
{
    xmlNode *tmp1 = NULL;
    xmlNode *diff = create_xml_node(NULL, "diff");
    xmlNode *removed = NULL;
    xmlNode *added = NULL;

    crm_xml_add(diff, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    if (new_diff && (tmp1 = find_xml_node(new_diff, "diff-removed", FALSE))) {
        removed = add_node_copy(diff, tmp1);

    } else {
        removed = create_xml_node(diff, "diff-removed");

        tmp1 = subtract_xml_object(removed, old, new, FALSE, "removed:top");
        if (suppress && tmp1 != NULL && can_prune_leaf(tmp1)) {
            free_xml_from_parent(removed, tmp1);
        }
    }

    added = create_xml_node(diff, "diff-added");

    tmp1 = subtract_xml_object(added, new, old, FALSE, "added:top");
    if (suppress && tmp1 != NULL && can_prune_leaf(tmp1)) {
        free_xml_from_parent(added, tmp1);
    }

    if (added->children == NULL && removed->children == NULL) {
        free_xml(diff);
        diff = NULL;
    }

    return diff;
}

static gboolean
unpack_user_acl(xmlNode * xml_acls, const char *user, GListPtr * user_acl)
{
    xmlNode *xml_acl = NULL;

    if (xml_acls == NULL) {
        return FALSE;
    }

    for (xml_acl = __xml_first_child(xml_acls); xml_acl; xml_acl = __xml_next(xml_acl)) {
        const char *tag = crm_element_name(xml_acl);
        const char *id = crm_element_value(xml_acl, XML_ATTR_ID);

        if (crm_str_eq(tag, XML_ACL_TAG_USER, TRUE)) {
            if (user_match(user, id)) {
                crm_debug("Unpacking ACL of user: '%s'", id);
                unpack_acl(xml_acls, xml_acl, user_acl);
                return TRUE;
            }
        }
    }
    return FALSE;
}

static gboolean
user_match(const char *user, const char *uid)
{
    CRM_CHECK(user != NULL && user[0] != '\0' && uid != NULL && uid[0] != '\0', return FALSE);

    if (crm_str_eq(user, uid, TRUE)) {
        return TRUE;
    }

    return FALSE;
}

static gboolean
unpack_acl(xmlNode * xml_acls, xmlNode * xml_acl, GListPtr * acl)
{
    xmlNode *acl_child = NULL;

    for (acl_child = __xml_first_child(xml_acl); acl_child; acl_child = __xml_next(acl_child)) {
        const char *tag = crm_element_name(acl_child);

        if (crm_str_eq(XML_ACL_TAG_ROLE_REF, tag, TRUE)) {
            const char *ref_role = crm_element_value(acl_child, XML_ATTR_ID);

            if (ref_role) {
                unpack_role_acl(xml_acls, ref_role, acl);
            }
        } else if (crm_str_eq(XML_ACL_TAG_READ, tag, TRUE)
                   || crm_str_eq(XML_ACL_TAG_WRITE, tag, TRUE)
                   || crm_str_eq(XML_ACL_TAG_DENY, tag, TRUE)) {
            acl_append(acl_child, acl);
        }
    }

    return TRUE;
}

static gboolean
unpack_role_acl(xmlNode * xml_acls, const char *role, GListPtr * acl)
{
    xmlNode *xml_acl = NULL;

    for (xml_acl = __xml_first_child(xml_acls); xml_acl; xml_acl = __xml_next(xml_acl)) {
        if (crm_str_eq(XML_ACL_TAG_ROLE, (const char *)xml_acl->name, TRUE)) {
            const char *role_id = crm_element_value(xml_acl, XML_ATTR_ID);

            if (role_id && crm_str_eq(role, role_id, TRUE)) {
                crm_debug("Unpacking ACL of the referenced role: '%s'", role);
                unpack_acl(xml_acls, xml_acl, acl);
                return TRUE;
            }
        }
    }
    return FALSE;
}

static gboolean
acl_append(xmlNode * acl_child, GListPtr * acl)
{
    acl_obj_t *acl_obj = NULL;

    const char *tag = crm_element_value(acl_child, XML_ACL_ATTR_TAG);
    const char *ref = crm_element_value(acl_child, XML_ACL_ATTR_REF);
    const char *xpath = crm_element_value(acl_child, XML_ACL_ATTR_XPATH);

    if (tag == NULL && ref == NULL && xpath == NULL) {
        return FALSE;
    }

    acl_obj = calloc(1, sizeof(acl_obj_t));
    if (acl_obj == NULL) {
        return FALSE;
    }

    acl_obj->mode = crm_element_name(acl_child);
    acl_obj->tag = tag;
    acl_obj->ref = ref;
    acl_obj->xpath = xpath;
    acl_obj->attribute = crm_element_value(acl_child, XML_ACL_ATTR_ATTRIBUTE);

    *acl = g_list_append(*acl, acl_obj);

    crm_trace("ACL object appended: mode=%s, tag=%s, ref=%s, xpath=%s, attribute=%s",
              acl_obj->mode, acl_obj->tag, acl_obj->ref, acl_obj->xpath, acl_obj->attribute);

    return TRUE;
}

static void
free_acl(GListPtr acl)
{
    GListPtr iterator = acl;

    while (iterator != NULL) {
        free(iterator->data);
        iterator = iterator->next;
    }
    if (acl != NULL) {
        g_list_free(acl);
    }
}

static gboolean
parse_acl_xpath(xmlNode * xml, GListPtr acl, GListPtr * parsed_acl)
{
    GListPtr acl_iterator = acl;
    acl_obj_t *new_acl_obj = NULL;

    *parsed_acl = NULL;

    while (acl_iterator != NULL) {
        acl_obj_t *acl_obj = acl_iterator->data;

        if (acl_obj->tag || acl_obj->ref) {
            new_acl_obj = calloc(1, sizeof(acl_obj_t));
            if (new_acl_obj == NULL) {
                return FALSE;
            }

            memcpy(new_acl_obj, acl_obj, sizeof(acl_obj_t));

            *parsed_acl = g_list_append(*parsed_acl, new_acl_obj);

            crm_trace("Copied ACL object: mode=%s, tag=%s, ref=%s, xpath=%s, attribute=%s",
                      new_acl_obj->mode, new_acl_obj->tag, new_acl_obj->ref,
                      new_acl_obj->xpath, new_acl_obj->attribute);

        } else if (acl_obj->xpath) {
            GListPtr children = NULL;
            GListPtr children_iterator = NULL;

            search_xpath_objects(&children, xml, acl_obj->xpath);

            children_iterator = children;
            while (children_iterator != NULL) {
                new_acl_obj = calloc(1, sizeof(acl_obj_t));
                if (new_acl_obj == NULL) {
                    return FALSE;
                }

                new_acl_obj->mode = acl_obj->mode;
                new_acl_obj->tag = crm_element_name((xmlNode *) children_iterator->data);
                new_acl_obj->ref = crm_element_value(children_iterator->data, XML_ATTR_ID);
                new_acl_obj->attribute = acl_obj->attribute;

                *parsed_acl = g_list_append(*parsed_acl, new_acl_obj);

                crm_trace
                    ("Parsed the ACL object with xpath '%s' to: mode=%s, tag=%s, ref=%s, xpath=%s, attribute=%s",
                     acl_obj->xpath, new_acl_obj->mode, new_acl_obj->tag, new_acl_obj->ref,
                     new_acl_obj->xpath, new_acl_obj->attribute);

                children_iterator = children_iterator->next;
            }
            g_list_free(children);
        }
        acl_iterator = acl_iterator->next;
    }

    return TRUE;
}

static gboolean
gen_xml_perms(xmlNode * xml, GListPtr acl, GHashTable ** xml_perms)
{
    GListPtr acl_iterator = acl;

    if (*xml_perms == NULL) {
        *xml_perms = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free_xml_perm);
    }

    while (acl_iterator != NULL) {
        acl_obj_t *acl_obj = acl_iterator->data;
        GListPtr children = NULL;
        GListPtr children_iterator = NULL;

        crm_debug
            ("Generating permissions with ACL: mode=%s, tag=%s, ref=%s, xpath=%s, attribute=%s",
             acl_obj->mode, acl_obj->tag, acl_obj->ref, acl_obj->xpath, acl_obj->attribute);
        if (acl_obj->tag || acl_obj->ref) {
            search_xml_children(&children, xml, acl_obj->tag, XML_ATTR_ID, acl_obj->ref, TRUE);

        } else if (acl_obj->xpath) {
            /* Never be here for a modification operation */
            /* Already parse_acl_xpath() previously */
            search_xpath_objects(&children, xml, acl_obj->xpath);
        }

        children_iterator = children;
        while (children_iterator != NULL) {
            update_xml_perms(children_iterator->data, acl_obj, *xml_perms);

            children_iterator = children_iterator->next;
        }
        g_list_free(children);

        acl_iterator = acl_iterator->next;
    }

    return TRUE;
}

/* Borrowed from lib/common/xml.c: find_xml_children() */
/* But adding the original xmlNode pointers into a GList */
static int
search_xml_children(GListPtr * children, xmlNode * root,
                    const char *tag, const char *field, const char *value, gboolean search_matches)
{
    int match_found = 0;

    CRM_CHECK(root != NULL, return FALSE);
    CRM_CHECK(children != NULL, return FALSE);

    if (tag != NULL && safe_str_neq(tag, crm_element_name(root))) {

    } else if (value != NULL && safe_str_neq(value, crm_element_value(root, field))) {

    } else {
        *children = g_list_append(*children, root);
        match_found = 1;
    }

    if (search_matches || match_found == 0) {
        xmlNode *child = NULL;

        for (child = __xml_first_child(root); child; child = __xml_next(child)) {
            match_found += search_xml_children(children, child, tag, field, value, search_matches);
        }
    }

    return match_found;
}

static int
search_xpath_objects(GListPtr * objects, xmlNode * xml_obj, const char *xpath)
{
    int match_found = 0;
    xmlXPathObjectPtr xpathObj = NULL;

    if (xpath == NULL) {
        return 0;
    }

    xpathObj = xpath_search(xml_obj, xpath);

    if (xpathObj == NULL || xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr < 1) {
        crm_debug("No match for %s in %s", xpath, xmlGetNodePath(xml_obj));

    } else if (xpathObj->nodesetval->nodeNr > 0) {
        int lpc = 0, max = xpathObj->nodesetval->nodeNr;

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *match = getXpathResult(xpathObj, lpc);

            if (match == NULL) {
                continue;
            }

            *objects = g_list_append(*objects, match);
            match_found++;
        }
    }

    if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }
    return match_found;
}

static gboolean
update_xml_perms(xmlNode * xml, acl_obj_t * acl_obj, GHashTable * xml_perms)
{
    xml_perm_t *perm = NULL;

    if (g_hash_table_lookup_extended(xml_perms, xml, NULL, (gpointer) & perm)) {
        if (perm->mode != NULL) {
            return FALSE;
        }
    } else {
        perm = calloc(1, sizeof(xml_perm_t));
        if (perm == NULL) {
            return FALSE;
        }
        g_hash_table_insert(xml_perms, xml, perm);
    }

    if (acl_obj->attribute == NULL) {
        xmlNode *child = NULL;

        perm->mode = acl_obj->mode;
        crm_trace("Permission for element: element_mode=%s, tag=%s, id=%s",
                  perm->mode, crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID));

        for (child = __xml_first_child(xml); child; child = __xml_next(child)) {
            update_xml_children_perms(child, perm->mode, xml_perms);
        }

    } else {
        if (perm->attribute_perms == NULL
            || (g_hash_table_lookup_extended(perm->attribute_perms,
                                             acl_obj->attribute, NULL, NULL) == FALSE)) {

            if (perm->attribute_perms == NULL) {
                perm->attribute_perms =
                    g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str,
                                          g_hash_destroy_str);
            }

            g_hash_table_insert(perm->attribute_perms,
                                crm_strdup(acl_obj->attribute), crm_strdup(acl_obj->mode));
            crm_trace("Permission for attribute: attribute_mode=%s, tag=%s, id=%s attribute=%s",
                      acl_obj->mode, crm_element_name(xml),
                      crm_element_value(xml, XML_ATTR_ID), acl_obj->attribute);
        }
    }

    return TRUE;
}

static gboolean
update_xml_children_perms(xmlNode * xml, const char *mode, GHashTable * xml_perms)
{
    xml_perm_t *perm = NULL;
    xmlNode *child = NULL;

    if (g_hash_table_lookup_extended(xml_perms, xml, NULL, (gpointer) & perm)) {
        if (perm->mode != NULL) {
            return FALSE;
        }
    } else {
        perm = calloc(1, sizeof(xml_perm_t));
        if (perm == NULL) {
            return FALSE;
        }
        g_hash_table_insert(xml_perms, xml, perm);
    }

    perm->mode = mode;
    crm_trace("Permission for child element: element_mode=%s, tag=%s, id=%s",
              mode, crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID));

    for (child = __xml_first_child(xml); child; child = __xml_next(child)) {
        update_xml_children_perms(child, mode, xml_perms);
    }

    return TRUE;
}

static void
free_xml_perm(gpointer xml_perm)
{
    xml_perm_t *perm = xml_perm;

    if (perm == NULL) {
        return;
    }

    if (perm->attribute_perms != NULL) {
        g_hash_table_destroy(perm->attribute_perms);
    }

    free(perm);
}

#define can_read(mode) (crm_str_eq(mode, XML_ACL_TAG_READ, TRUE) \
			|| crm_str_eq(mode, XML_ACL_TAG_WRITE, TRUE))

#define can_write(mode) crm_str_eq(mode, XML_ACL_TAG_WRITE, TRUE)

/* rc = TRUE if the xml is filtered out*/
static gboolean
acl_filter_xml(xmlNode * xml, GHashTable * xml_perms)
{
    int children_counter = 0;
    xml_perm_t *perm = NULL;
    int allow_counter = 0;
    xmlNode *child = NULL;

    for (child = __xml_first_child(xml); child; child = __xml_next(child)) {
        if (acl_filter_xml(child, xml_perms) == FALSE) {
            children_counter++;
        }
    }

    g_hash_table_lookup_extended(xml_perms, xml, NULL, (gpointer) & perm);

    if (perm == NULL) {
        crm_trace("No ACL defined to read the element: tag=%s, id=%s",
                  crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID));
        goto end_filter;
    }

    if (perm->attribute_perms == NULL) {
        if (can_read(perm->mode)) {
            return FALSE;
        } else {
            crm_trace("No enough permission to read the element: element_mode=%s, tag=%s, id=%s",
                      perm->mode, crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID));
            goto end_filter;
        }
    }

    if (xml) {
        xmlAttrPtr xIter = xml->properties;

        while (xIter) {
            const char *prop_name = (const char *)xIter->name;
            gpointer mode = NULL;

            xIter = xIter->next;
            if (g_hash_table_lookup_extended(perm->attribute_perms, prop_name, NULL, &mode)) {
                if (can_read(mode)) {
                    allow_counter++;
                } else {
                    xml_remove_prop(xml, prop_name);
                    crm_trace
                        ("Filtered out the attribute: attribute_mode=%s, tag=%s, id=%s, attribute=%s",
                         (char *)mode, crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID),
                         prop_name);
                }
            } else {
                if (can_read(perm->mode)) {
                    allow_counter++;
                } else if (crm_str_eq(prop_name, XML_ATTR_ID, TRUE) == FALSE) {
                    xml_remove_prop(xml, prop_name);
                    crm_trace
                        ("Filtered out the attribute: element_mode=%s, tag=%s, id=%s, attribute=%s",
                         perm->mode, crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID),
                         prop_name);
                }
            }
        }
    }

    if (allow_counter) {
        return FALSE;
    }

    if (can_read(perm->mode)) {
        return FALSE;
    }

  end_filter:
    if (children_counter) {
        crm_trace
            ("Don't filter out the element (tag=%s, id=%s) because user can read its children",
             crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID));
        return FALSE;
    }

    free_xml_from_parent(NULL, xml);
    crm_trace("Filtered out the element: tag=%s, id=%s",
              crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID));
    return TRUE;
}

static gboolean
acl_check_diff_xml(xmlNode * xml, GHashTable * xml_perms)
{
    xml_perm_t *perm = NULL;
    xmlNode *child = NULL;

    for (child = __xml_first_child(xml); child; child = __xml_next(child)) {
        if (acl_check_diff_xml(child, xml_perms) == FALSE) {
            return FALSE;
        }
    }

    g_hash_table_lookup_extended(xml_perms, xml, NULL, (gpointer) & perm);

    if (xml) {
        xmlAttrPtr xIter = NULL;

        for (xIter = xml->properties; xIter; xIter = xIter->next) {
            const char *prop_name = (const char *)xIter->name;
            gpointer mode = NULL;

            if (crm_str_eq(crm_element_name(xml), XML_TAG_CIB, TRUE)) {
                if (crm_str_eq(prop_name, XML_ATTR_GENERATION, TRUE)
                    || crm_str_eq(prop_name, XML_ATTR_NUMUPDATES, TRUE)
                    || crm_str_eq(prop_name, XML_ATTR_GENERATION_ADMIN, TRUE)) {
                    continue;
                }
            }

            if (crm_str_eq(prop_name, XML_ATTR_ID, TRUE)) {
                continue;
            }

            if (crm_str_eq(prop_name, XML_DIFF_MARKER, TRUE) && xml_has_children(xml)) {
                continue;
            }

            if (perm == NULL) {
                crm_warn("No ACL defined to modify the element: tag=%s, id=%s, attribute=%s",
                         crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID), prop_name);
                return FALSE;
            }

            if (perm->attribute_perms == NULL) {
                if (can_write(perm->mode)) {
                    return TRUE;
                } else {
                    crm_warn
                        ("No enough permission to modify the element: element_mode=%s, tag=%s, id=%s, attribute=%s",
                         perm->mode, crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID),
                         prop_name);
                    return FALSE;
                }
            }

            if (g_hash_table_lookup_extended(perm->attribute_perms, prop_name, NULL, &mode)) {
                if (can_write(mode) == FALSE) {
                    crm_warn
                        ("No enough permission to modify the attribute: attribute_mode=%s, tag=%s, id=%s, attribute=%s",
                         (char *)mode, crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID),
                         prop_name);
                    return FALSE;
                }
            } else if (can_write(perm->mode) == FALSE) {
                crm_warn
                    ("No enough permission to modify the element and the attribute: element_mode=%s, tag=%s, id=%s, attribute=%s",
                     perm->mode, crm_element_name(xml), crm_element_value(xml, XML_ATTR_ID),
                     prop_name);
                return FALSE;
            }
        }
    }

    return TRUE;
}
