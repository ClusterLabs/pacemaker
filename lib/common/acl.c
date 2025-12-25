/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <libxml/tree.h>                // xmlNode, etc.
#include <libxml/xmlstring.h>           // xmlChar
#include <libxml/xpath.h>               // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/common/xml.h>
#include "crmcommon_private.h"

typedef struct xml_acl_s {
    enum pcmk__xml_flags mode;
    gchar *xpath;
} xml_acl_t;

static void
free_acl(void *data)
{
    if (data) {
        xml_acl_t *acl = data;

        g_free(acl->xpath);
        free(acl);
    }
}

void
pcmk__free_acls(GList *acls)
{
    g_list_free_full(acls, free_acl);
}

static GList *
create_acl(const xmlNode *xml, GList *acls, enum pcmk__xml_flags mode)
{
    xml_acl_t *acl = NULL;

    const char *tag = pcmk__xe_get(xml, PCMK_XA_OBJECT_TYPE);
    const char *ref = pcmk__xe_get(xml, PCMK_XA_REFERENCE);
    const char *xpath = pcmk__xe_get(xml, PCMK_XA_XPATH);
    const char *attr = pcmk__xe_get(xml, PCMK_XA_ATTRIBUTE);

    if ((tag == NULL) && (ref == NULL) && (xpath == NULL)) {
        // Schema should prevent this, but to be safe ...
        pcmk__trace("Ignoring ACL <%s> element without selection criteria",
                    xml->name);
        return NULL;
    }

    acl = pcmk__assert_alloc(1, sizeof (xml_acl_t));

    acl->mode = mode;
    if (xpath) {
        acl->xpath = g_strdup(xpath);
        pcmk__trace("Unpacked ACL <%s> element using xpath: %s", xml->name,
                    acl->xpath);

    } else {
        GString *buf = g_string_sized_new(128);

        if ((ref != NULL) && (attr != NULL)) {
            // NOTE: schema currently does not allow this
            pcmk__g_strcat(buf, "//", pcmk__s(tag, "*"), "[@" PCMK_XA_ID "='",
                           ref, "' and @", attr, "]", NULL);

        } else if (ref != NULL) {
            pcmk__g_strcat(buf, "//", pcmk__s(tag, "*"), "[@" PCMK_XA_ID "='",
                           ref, "']", NULL);

        } else if (attr != NULL) {
            pcmk__g_strcat(buf, "//", pcmk__s(tag, "*"), "[@", attr, "]", NULL);

        } else {
            pcmk__g_strcat(buf, "//", pcmk__s(tag, "*"), NULL);
        }

        acl->xpath = buf->str;

        g_string_free(buf, FALSE);
        pcmk__trace("Unpacked ACL <%s> element as xpath: %s", xml->name,
                    acl->xpath);
    }

    return g_list_append(acls, acl);
}

/*!
 * \internal
 * \brief Unpack a user, group, or role subtree of the ACLs section
 *
 * \param[in]     acl_top    XML of entire ACLs section
 * \param[in]     acl_entry  XML of ACL element being unpacked
 * \param[in,out] acls       List of ACLs unpacked so far
 *
 * \return New head of (possibly modified) acls
 *
 * \note This function is recursive
 */
static GList *
parse_acl_entry(const xmlNode *acl_top, const xmlNode *acl_entry, GList *acls)
{
    for (const xmlNode *child = pcmk__xe_first_child(acl_entry, NULL, NULL,
                                                     NULL);
         child != NULL; child = pcmk__xe_next(child, NULL)) {

        if (pcmk__xe_is(child, PCMK_XE_ACL_PERMISSION)) {
            const char *kind = pcmk__xe_get(child, PCMK_XA_KIND);

            pcmk__assert(kind != NULL);
            pcmk__trace("Unpacking <" PCMK_XE_ACL_PERMISSION "> element of "
                        "kind '%s'",
                        kind);

            if (pcmk__str_eq(kind, PCMK_VALUE_READ, pcmk__str_none)) {
                acls = create_acl(child, acls, pcmk__xf_acl_read);

            } else if (pcmk__str_eq(kind, PCMK_VALUE_WRITE, pcmk__str_none)) {
                acls = create_acl(child, acls, pcmk__xf_acl_write);

            } else if (pcmk__str_eq(kind, PCMK_VALUE_DENY, pcmk__str_none)) {
                acls = create_acl(child, acls, pcmk__xf_acl_deny);

            } else {
                pcmk__warn("Ignoring unknown ACL kind '%s'", kind);
            }

        } else if (pcmk__xe_is(child, PCMK_XE_ROLE)) {
            const char *ref_role = pcmk__xe_get(child, PCMK_XA_ID);

            pcmk__trace("Unpacking <" PCMK_XE_ROLE "> element");

            if (ref_role == NULL) {
                continue;
            }

            for (xmlNode *role = pcmk__xe_first_child(acl_top, NULL, NULL,
                                                      NULL);
                 role != NULL; role = pcmk__xe_next(role, NULL)) {

                const char *role_id = NULL;

                if (!pcmk__xe_is(role, PCMK_XE_ACL_ROLE)) {
                    continue;
                }

                role_id = pcmk__xe_get(role, PCMK_XA_ID);

                if (pcmk__str_eq(ref_role, role_id, pcmk__str_none)) {
                    pcmk__trace("Unpacking referenced role '%s' in <%s> "
                                "element",
                                role_id, acl_entry->name);
                    acls = parse_acl_entry(acl_top, role, acls);
                    break;
                }
            }
        }
    }

    return acls;
}

/*
    <acls>
      <acl_target id="l33t-haxor"><role id="auto-l33t-haxor"/></acl_target>
      <acl_role id="auto-l33t-haxor">
        <acl_permission id="crook-nothing" kind="deny" xpath="/cib"/>
      </acl_role>
      <acl_target id="niceguy">
        <role id="observer"/>
      </acl_target>
      <acl_role id="observer">
        <acl_permission id="observer-read-1" kind="read" xpath="/cib"/>
        <acl_permission id="observer-write-1" kind="write" xpath="//nvpair[@name='fencing-enabled']"/>
        <acl_permission id="observer-write-2" kind="write" xpath="//nvpair[@name='target-role']"/>
      </acl_role>
      <acl_target id="badidea"><role id="auto-badidea"/></acl_target>
      <acl_role id="auto-badidea">
        <acl_permission id="badidea-resources" kind="read" xpath="//meta_attributes"/>
        <acl_permission id="badidea-resources-2" kind="deny" reference="dummy-meta_attributes"/>
      </acl_role>
    </acls>
*/

static const char *
acl_to_text(enum pcmk__xml_flags flags)
{
    if (pcmk__is_set(flags, pcmk__xf_acl_deny)) {
        return "deny";

    } else if (pcmk__any_flags_set(flags,
                                   pcmk__xf_acl_write|pcmk__xf_acl_create)) {
        return "read/write";

    } else if (pcmk__is_set(flags, pcmk__xf_acl_read)) {
        return "read";
    }
    return "none";
}

static void
apply_acl(xmlDoc *doc, const xml_acl_t *acl)
{
    xml_node_private_t *nodepriv = NULL;
    xmlXPathObject *xpath_obj = pcmk__xpath_search(doc, acl->xpath);
    int num_results = pcmk__xpath_num_results(xpath_obj);

    for (int i = 0; i < num_results; i++) {
        GString *path = NULL;
        xmlNode *match = pcmk__xpath_result(xpath_obj, i);

        if (match == NULL) {
            continue;
        }

        /* @COMPAT If the ACL's XPath matches a node that is neither an element
         * nor a document, we apply the ACL to the parent element rather than to
         * the matched node. For example, if the XPath matches a "score"
         * attribute, then it applies to every element that contains a "score"
         * attribute. That is, the XPath expression "//@score" matches all
         * attributes named "score", but we apply the ACL to all elements
         * containing such an attribute.
         *
         * This behavior is incorrect from an XPath standpoint and is thus
         * confusing and counterintuitive. The correct way to match all elements
         * containing a "score" attribute is to use an XPath predicate:
         * "// *[@score]". (Space inserted after slashes so that GCC doesn't
         * throw an error about nested comments.)
         *
         * Additionally, if an XPath expression matches the entire document (for
         * example, "/"), then the ACL applies to the document's root element if
         * it exists.
         *
         * These behaviors should be changed so that the ACL applies to the
         * nodes matched by the XPath expression, or so that it doesn't apply at
         * all if applying an ACL to an attribute doesn't make sense.
         *
         * Unfortunately, we document in Pacemaker Explained that matching
         * attributes is a valid way to match elements: "Attributes may be
         * specified in the XPath to select particular elements, but the
         * permissions apply to the entire element."
         *
         * So we have to keep this behavior at least until a compatibility
         * break. Even then, it's not feasible in the general case to transform
         * such XPath expressions using XSLT.
         */
        match = pcmk__xpath_match_element(match);
        if (match == NULL) {
            continue;
        }

        nodepriv = match->_private;
        pcmk__set_xml_flags(nodepriv, acl->mode);

        path = pcmk__element_xpath(match);
        pcmk__trace("Applying %s ACL to %s matched by %s",
                    acl_to_text(acl->mode), path->str, acl->xpath);
        g_string_free(path, TRUE);
    }

    pcmk__trace("Applied %s ACL %s (%d match%s)", acl_to_text(acl->mode),
                acl->xpath, num_results,
                pcmk__plural_alt(num_results, "", "es"));
    xmlXPathFreeObject(xpath_obj);
}

void
pcmk__apply_acls(xmlNode *xml)
{
    xml_doc_private_t *docpriv = NULL;

    pcmk__assert(xml != NULL);
    docpriv = xml->doc->_private;

    if (!pcmk__xml_doc_all_flags_set(xml->doc, pcmk__xf_acl_enabled)) {
        return;
    }

    for (const GList *iter = docpriv->acls; iter != NULL; iter = iter->next) {
        const xml_acl_t *acl = iter->data;

        apply_acl(xml->doc, acl);
    }
}

/*!
 * \internal
 * \brief Unpack ACLs for a given user into the
 * metadata of the target XML tree
 *
 * Taking the description of ACLs from the source XML tree and
 * marking up the target XML tree with access information for the
 * given user by tacking it onto the relevant nodes
 *
 * \param[in]     source  XML with ACL definitions
 * \param[in,out] target  XML that ACLs will be applied to
 * \param[in]     user    Username whose ACLs need to be unpacked
 */
void
pcmk__unpack_acl(xmlNode *source, xmlNode *target, const char *user)
{
    xml_doc_private_t *docpriv = NULL;

    if ((target == NULL) || (target->doc == NULL)
        || (target->doc->_private == NULL)) {
        return;
    }

    docpriv = target->doc->_private;
    if (!pcmk_acl_required(user)) {
        pcmk__trace("Not unpacking ACLs because not required for user '%s'",
                    user);

    } else if (docpriv->acls == NULL) {
        xmlNode *acls = pcmk__xpath_find_one(source->doc, "//" PCMK_XE_ACLS,
                                             PCMK__LOG_NEVER);

        pcmk__str_update(&(docpriv->acl_user), user);

        if (acls) {
            xmlNode *child = NULL;

            for (child = pcmk__xe_first_child(acls, NULL, NULL, NULL);
                 child != NULL; child = pcmk__xe_next(child, NULL)) {

                if (pcmk__xe_is(child, PCMK_XE_ACL_TARGET)) {
                    const char *id = pcmk__xe_get(child, PCMK_XA_NAME);

                    if (id == NULL) {
                        id = pcmk__xe_get(child, PCMK_XA_ID);
                    }

                    if (id && strcmp(id, user) == 0) {
                        pcmk__debug("Unpacking ACLs for user '%s'", id);
                        docpriv->acls = parse_acl_entry(acls, child, docpriv->acls);
                    }
                } else if (pcmk__xe_is(child, PCMK_XE_ACL_GROUP)) {
                    const char *id = pcmk__xe_get(child, PCMK_XA_NAME);

                    if (id == NULL) {
                        id = pcmk__xe_get(child, PCMK_XA_ID);
                    }

                    if (id && pcmk__is_user_in_group(user,id)) {
                        pcmk__debug("Unpacking ACLs for group '%s'", id);
                        docpriv->acls = parse_acl_entry(acls, child, docpriv->acls);
                    }
                }
            }
        }
    }
}

/*!
 * \internal
 * \brief Copy source to target and set xf_acl_enabled flag in target
 *
 * \param[in]     acl_source    XML with ACL definitions
 * \param[in,out] target        XML that ACLs will be applied to
 * \param[in]     user          Username whose ACLs need to be set
 */
void
pcmk__enable_acl(xmlNode *acl_source, xmlNode *target, const char *user)
{
    if (target == NULL) {
        return;
    }
    pcmk__unpack_acl(acl_source, target, user);
    pcmk__xml_doc_set_flags(target->doc, pcmk__xf_acl_enabled);
    pcmk__apply_acls(target);
}

static inline bool
test_acl_mode(enum pcmk__xml_flags allowed, enum pcmk__xml_flags requested)
{
    if (pcmk__is_set(allowed, pcmk__xf_acl_deny)) {
        return false;

    } else if (pcmk__all_flags_set(allowed, requested)) {
        return true;

    } else if (pcmk__is_set(requested, pcmk__xf_acl_read)
               && pcmk__is_set(allowed, pcmk__xf_acl_write)) {
        return true;

    } else if (pcmk__is_set(requested, pcmk__xf_acl_create)
               && pcmk__any_flags_set(allowed,
                                      pcmk__xf_acl_write|pcmk__xf_created)) {
        return true;
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether an XML attribute's name is not \c PCMK_XA_ID
 *
 * \param[in] attr       Attribute to check
 * \param[in] user_data  Ignored
 *
 * \return \c true if the attribute's name is not \c PCMK_XA_ID, or \c false
 *         otherwise
 *
 * \note This is compatible with \c pcmk__xe_remove_matching_attrs().
 */
static bool
attr_is_not_id(xmlAttr *attr, void *user_data)
{
    return !pcmk__str_eq((const char *) attr->name, PCMK_XA_ID, pcmk__str_none);
}

/*!
 * \internal
 * \brief Rid XML tree of all unreadable nodes and node properties
 *
 * \param[in,out] xml   Root XML node to be purged of attributes
 *
 * \return true if this node or any of its children are readable
 *         if false is returned, xml will be freed
 *
 * \note This function is recursive
 */
static bool
purge_xml_attributes(xmlNode *xml)
{
    xmlNode *child = NULL;
    bool readable_children = false;
    xml_node_private_t *nodepriv = xml->_private;

    if (test_acl_mode(nodepriv->flags, pcmk__xf_acl_read)) {
        pcmk__trace("%s[@" PCMK_XA_ID "=%s] is readable", xml->name,
                    pcmk__xe_id(xml));
        return true;
    }

    pcmk__xe_remove_matching_attrs(xml, true, attr_is_not_id, NULL);

    child = pcmk__xe_first_child(xml, NULL, NULL, NULL);
    while (child != NULL) {
        xmlNode *tmp = child;

        child = pcmk__xe_next(child, NULL);

        if (purge_xml_attributes(tmp)) {
            readable_children = true;
        }
    }

    if (!readable_children) {
        // Nothing readable under here, so purge completely
        pcmk__xml_free(xml);
    }
    return readable_children;
}

/*!
 * \brief Copy ACL-allowed portions of specified XML
 *
 * \param[in]  user        Username whose ACLs should be used
 * \param[in]  acl_source  XML containing ACLs
 * \param[in]  xml         XML to be copied
 * \param[out] result      Copy of XML portions readable via ACLs
 *
 * \return true if xml exists and ACLs are required for user, false otherwise
 * \note If this returns true, caller should use \p result rather than \p xml
 */
bool
xml_acl_filtered_copy(const char *user, xmlNode *acl_source, xmlNode *xml,
                      xmlNode **result)
{
    xmlNode *target = NULL;
    xml_doc_private_t *docpriv = NULL;

    *result = NULL;
    if ((xml == NULL) || !pcmk_acl_required(user)) {
        return false;
    }

    target = pcmk__xml_copy(NULL, xml);
    docpriv = target->doc->_private;

    pcmk__enable_acl(acl_source, target, user);

    pcmk__trace("Filtering XML copy using user '%s' ACLs", user);

    for (const GList *iter = docpriv->acls; iter != NULL; iter = iter->next) {
        const xml_acl_t *acl = iter->data;
        xmlXPathObject *xpath_obj = NULL;
        int num_results = 0;

        if ((acl->mode != pcmk__xf_acl_deny) || (acl->xpath == NULL)) {
            continue;
        }

        xpath_obj = pcmk__xpath_search(target->doc, acl->xpath);
        num_results = pcmk__xpath_num_results(xpath_obj);

        for (int i = 0; i < num_results; i++) {
            xmlNode *match = pcmk__xpath_result(xpath_obj, i);

            if (match == NULL) {
                continue;
            }

            // @COMPAT See COMPAT comment in pcmk__apply_acls()
            match = pcmk__xpath_match_element(match);
            if (match == NULL) {
                continue;
            }

            if (!purge_xml_attributes(match) && (match == target)) {
                pcmk__trace("ACLs deny user '%s' access to entire XML document",
                            user);
                xmlXPathFreeObject(xpath_obj);
                return true;
            }
        }
        pcmk__trace("ACLs deny user '%s' access to %s (%d match%s)", user,
                    acl->xpath, num_results,
                    pcmk__plural_alt(num_results, "", "es"));
        xmlXPathFreeObject(xpath_obj);
    }

    if (!purge_xml_attributes(target)) {
        pcmk__trace("ACLs deny user '%s' access to entire XML document", user);
        return true;
    }

    if (docpriv->acls == NULL) {
        pcmk__trace("User '%s' without ACLs denied access to entire XML "
                    "document", user);
        pcmk__xml_free(target);
        return true;
    }

    g_clear_pointer(&docpriv->acls, pcmk__free_acls);
    *result = target;
    return true;
}

/*!
 * \internal
 * \brief Check whether creation of an XML element is implicitly allowed
 *
 * Check whether XML is a "scaffolding" element whose creation is implicitly
 * allowed regardless of ACLs (that is, it is not in the ACL section and has
 * no attributes other than \c PCMK_XA_ID).
 *
 * \param[in] xml  XML element to check
 *
 * \return true if XML element is implicitly allowed, false otherwise
 */
static bool
implicitly_allowed(const xmlNode *xml)
{
    GString *path = NULL;

    for (xmlAttr *prop = xml->properties; prop != NULL; prop = prop->next) {
        if (strcmp((const char *) prop->name, PCMK_XA_ID) != 0) {
            return false;
        }
    }

    path = pcmk__element_xpath(xml);
    pcmk__assert(path != NULL);

    if (strstr((const char *) path->str, "/" PCMK_XE_ACLS "/") != NULL) {
        g_string_free(path, TRUE);
        return false;
    }

    g_string_free(path, TRUE);
    return true;
}

#define display_id(xml) pcmk__s(pcmk__xe_id(xml), "<unset>")

/*!
 * \internal
 * \brief Drop XML nodes created in violation of ACLs
 *
 * Given an XML element, free all of its descendant nodes created in violation
 * of ACLs, with the exception of allowing "scaffolding" elements (i.e. those
 * that aren't in the ACL section and don't have any attributes other than
 * \c PCMK_XA_ID).
 *
 * \param[in,out] xml        XML to check
 * \param[in]     check_top  Whether to apply checks to argument itself
 *                           (if true, xml might get freed)
 *
 * \note This function is recursive
 */
void
pcmk__apply_creation_acl(xmlNode *xml, bool check_top)
{
    xml_node_private_t *nodepriv = xml->_private;

    if (pcmk__is_set(nodepriv->flags, pcmk__xf_created)) {
        if (implicitly_allowed(xml)) {
            pcmk__trace("Creation of <%s> scaffolding with "
                        PCMK_XA_ID "=\"%s\" is implicitly allowed",
                        xml->name, display_id(xml));

        } else if (pcmk__check_acl(xml, NULL, pcmk__xf_acl_write)) {
            pcmk__trace("ACLs allow creation of <%s> with "
                        PCMK_XA_ID "=\"%s\"",
                        xml->name, display_id(xml));

        } else if (check_top) {
            /* is_root=true should be impossible with check_top=true, but check
             * for sanity
             */
            bool is_root = (xmlDocGetRootElement(xml->doc) == xml);
            xml_doc_private_t *docpriv = xml->doc->_private;

            pcmk__trace("ACLs disallow creation of %s<%s> with "
                        PCMK_XA_ID "=\"%s\"",
                        (is_root? "root element " : ""), xml->name,
                        display_id(xml));

            // pcmk__xml_free() checks ACLs if enabled, which would fail
            pcmk__clear_xml_flags(docpriv, pcmk__xf_acl_enabled);
            pcmk__xml_free(xml);

            if (!is_root) {
                // If root, the document was freed. Otherwise re-enable ACLs.
                pcmk__set_xml_flags(docpriv, pcmk__xf_acl_enabled);
            }
            return;

        } else {
            const bool is_root = (xml == xmlDocGetRootElement(xml->doc));

            pcmk__notice("ACLs would disallow creation of %s<%s> with "
                         PCMK_XA_ID "=\"%s\"",
                         (is_root? "root element " : ""), xml->name,
                         display_id(xml));
        }
    }

    for (xmlNode *cIter = pcmk__xml_first_child(xml); cIter != NULL; ) {
        xmlNode *child = cIter;
        cIter = pcmk__xml_next(cIter); /* In case it is free'd */
        pcmk__apply_creation_acl(child, true);
    }
}

/*!
 * \brief Check whether or not an XML node is ACL-denied
 *
 * \param[in]  xml node to check
 *
 * \return true if XML node exists and is ACL-denied, false otherwise
 */
bool
xml_acl_denied(const xmlNode *xml)
{
    if (xml && xml->doc && xml->doc->_private){
        xml_doc_private_t *docpriv = xml->doc->_private;

        return pcmk__is_set(docpriv->flags, pcmk__xf_acl_denied);
    }
    return false;
}

void
xml_acl_disable(xmlNode *xml)
{
    if ((xml != NULL)
        && pcmk__xml_doc_all_flags_set(xml->doc, pcmk__xf_acl_enabled)) {

        xml_doc_private_t *docpriv = xml->doc->_private;

        /* Catch anything that was created but shouldn't have been */
        pcmk__apply_acls(xml);
        pcmk__apply_creation_acl(xml, false);
        pcmk__clear_xml_flags(docpriv, pcmk__xf_acl_enabled);
    }
}

/*!
 * \internal
 * \brief Deny access to an XML tree's document based on ACLs
 *
 * \param[in,out] xml        XML tree
 * \param[in]     attr_name  Name of attribute being accessed in \p xml (for
 *                           logging only)
 * \param[in]     prefix     Prefix describing ACL that denied access (for
 *                           logging only)
 * \param[in]     user       User accessing \p xml (for logging only)
 * \param[in]     mode       Access mode (for logging only)
 */
#define check_acl_deny(xml, attr_name, prefix, user, mode) do {             \
        xmlNode *tree = xml;                                                \
                                                                            \
        pcmk__xml_doc_set_flags(tree->doc, pcmk__xf_acl_denied);            \
        pcmk__if_tracing(                                                   \
            {                                                               \
                GString *xpath = pcmk__element_xpath(tree);                 \
                                                                            \
                if ((attr_name) != NULL) {                                  \
                    pcmk__g_strcat(xpath, "[@", attr_name, "]", NULL);      \
                }                                                           \
                qb_log_from_external_source(__func__, __FILE__,             \
                                            "%sACL denies user '%s' %s "    \
                                            "access to %s",                 \
                                            LOG_TRACE, __LINE__, 0 ,        \
                                            prefix, user,                   \
                                            acl_to_text(mode), xpath->str); \
                g_string_free(xpath, TRUE);                                 \
            },                                                              \
            {}                                                              \
        );                                                                  \
    } while (false);

bool
pcmk__check_acl(xmlNode *xml, const char *attr_name, enum pcmk__xml_flags mode)
{
    xml_doc_private_t *docpriv = NULL;

    pcmk__assert((xml != NULL) && (xml->doc->_private != NULL));

    if (!pcmk__xml_doc_all_flags_set(xml->doc,
                                     pcmk__xf_tracking|pcmk__xf_acl_enabled)) {
        return true;
    }

    docpriv = xml->doc->_private;
    if (docpriv->acls == NULL) {
        check_acl_deny(xml, attr_name, "Lack of ", docpriv->acl_user, mode);
        return false;
    }

    /* Walk the tree upwards looking for xml_acl_* flags
     * - Creating an attribute requires write permissions for the node
     * - Creating a child requires write permissions for the parent
     */

    if (attr_name != NULL) {
        xmlAttr *attr = xmlHasProp(xml, (const xmlChar *) attr_name);

        if ((attr != NULL) && (mode == pcmk__xf_acl_create)) {
            mode = pcmk__xf_acl_write;
        }
    }

    for (const xmlNode *parent = xml;
         (parent != NULL) && (parent->_private != NULL);
         parent = parent->parent) {

        const xml_node_private_t *nodepriv = parent->_private;

        if (test_acl_mode(nodepriv->flags, mode)) {
            return true;
        }

        if (pcmk__is_set(nodepriv->flags, pcmk__xf_acl_deny)) {
            const char *pfx = (parent != xml)? "Parent " : "";

            check_acl_deny(xml, attr_name, pfx, docpriv->acl_user, mode);
            return false;
        }
    }

    check_acl_deny(xml, attr_name, "Default ", docpriv->acl_user, mode);
    return false;
}

/*!
 * \brief Check whether ACLs are required for a given user
 *
 * \param[in]  User name to check
 *
 * \return true if the user requires ACLs, false otherwise
 */
bool
pcmk_acl_required(const char *user)
{
    if (pcmk__str_empty(user)) {
        pcmk__trace("ACLs not required because no user set");
        return false;

    } else if (!strcmp(user, CRM_DAEMON_USER) || !strcmp(user, "root")) {
        pcmk__trace("ACLs not required for privileged user %s", user);
        return false;
    }
    pcmk__trace("ACLs required for %s", user);
    return true;
}

char *
pcmk__uid2username(uid_t uid)
{
    struct passwd *pwent = NULL;

    errno = 0;
    pwent = getpwuid(uid);

    if (pwent == NULL) {
        pcmk__err("Cannot get name from password database for user ID %lld: %s",
                  (long long) uid,
                  ((errno != 0)? strerror(errno) : "No matching entry found"));
        return NULL;
    }

    return pcmk__str_copy(pwent->pw_name);
}

/*!
 * \internal
 * \brief Set the ACL user field properly on an XML request
 *
 * Multiple user names are potentially involved in an XML request: the effective
 * user of the current process; the user name known from an IPC client
 * connection; and the user name obtained from the request itself, whether by
 * the current standard XML attribute name or an older legacy attribute name.
 * This function chooses the appropriate one that should be used for ACLs, sets
 * it in the request (using the standard attribute name, and the legacy name if
 * given), and returns it.
 *
 * \param[in,out] request    XML request to update
 * \param[in]     field      Alternate name for ACL user name XML attribute
 * \param[in]     peer_user  User name as known from IPC connection
 *
 * \return ACL user name actually used
 */
const char *
pcmk__update_acl_user(xmlNode *request, const char *field,
                      const char *peer_user)
{
    static const char *effective_user = NULL;
    const char *requested_user = NULL;
    const char *user = NULL;

    if (effective_user == NULL) {
        effective_user = pcmk__uid2username(geteuid());
        if (effective_user == NULL) {
            effective_user = pcmk__str_copy("#unprivileged");
            pcmk__err("Unable to determine effective user, assuming "
                      "unprivileged for ACLs");
        }
    }

    requested_user = pcmk__xe_get(request, PCMK__XA_ACL_TARGET);
    if (requested_user == NULL) {
        /* Currently, different XML attribute names are used for the ACL user in
         * different contexts (PCMK__XA_ATTR_USER, PCMK__XA_CIB_USER, etc.).
         * The caller may specify that name as the field argument.
         *
         * @TODO Standardize on PCMK__XA_ACL_TARGET and eventually drop the
         * others once rolling upgrades from versions older than that are no
         * longer supported.
         */
        requested_user = pcmk__xe_get(request, field);
    }

    if (!pcmk__is_privileged(effective_user)) {
        /* We're not running as a privileged user, set or overwrite any existing
         * value for PCMK__XA_ACL_TARGET
         */
        user = effective_user;

    } else if (peer_user == NULL && requested_user == NULL) {
        /* No user known or requested, use 'effective_user' and make sure one is
         * set for the request
         */
        user = effective_user;

    } else if (peer_user == NULL) {
        /* No user known, trusting 'requested_user' */
        user = requested_user;

    } else if (!pcmk__is_privileged(peer_user)) {
        /* The peer is not a privileged user, set or overwrite any existing
         * value for PCMK__XA_ACL_TARGET
         */
        user = peer_user;

    } else if (requested_user == NULL) {
        /* Even if we're privileged, make sure there is always a value set */
        user = peer_user;

    } else {
        /* Legal delegation to 'requested_user' */
        user = requested_user;
    }

    // This requires pointer comparison, not string comparison
    if (user != pcmk__xe_get(request, PCMK__XA_ACL_TARGET)) {
        pcmk__xe_set(request, PCMK__XA_ACL_TARGET, user);
    }

    if ((field != NULL) && (user != pcmk__xe_get(request, field))) {
        pcmk__xe_set(request, field, user);
    }

    return requested_user;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/acl_compat.h>
#include <crm/common/xml_compat.h>

bool
xml_acl_enabled(const xmlNode *xml)
{
    if (xml && xml->doc && xml->doc->_private){
        xml_doc_private_t *docpriv = xml->doc->_private;

        return pcmk__is_set(docpriv->flags, pcmk__xf_acl_enabled);
    }
    return false;
}

// LCOV_EXCL_STOP
// End deprecated API
