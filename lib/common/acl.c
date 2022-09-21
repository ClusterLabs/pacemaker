/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include "crmcommon_private.h"

typedef struct xml_acl_s {
        enum xml_private_flags mode;
        char *xpath;
} xml_acl_t;

static void
free_acl(void *data)
{
    if (data) {
        xml_acl_t *acl = data;

        free(acl->xpath);
        free(acl);
    }
}

void
pcmk__free_acls(GList *acls)
{
    g_list_free_full(acls, free_acl);
}

static GList *
create_acl(xmlNode *xml, GList *acls, enum xml_private_flags mode)
{
    xml_acl_t *acl = NULL;

    const char *tag = crm_element_value(xml, XML_ACL_ATTR_TAG);
    const char *ref = crm_element_value(xml, XML_ACL_ATTR_REF);
    const char *xpath = crm_element_value(xml, XML_ACL_ATTR_XPATH);
    const char *attr = crm_element_value(xml, XML_ACL_ATTR_ATTRIBUTE);

    if (tag == NULL) {
        // @COMPAT rolling upgrades <=1.1.11
        tag = crm_element_value(xml, XML_ACL_ATTR_TAGv1);
    }
    if (ref == NULL) {
        // @COMPAT rolling upgrades <=1.1.11
        ref = crm_element_value(xml, XML_ACL_ATTR_REFv1);
    }

    if ((tag == NULL) && (ref == NULL) && (xpath == NULL)) {
        // Schema should prevent this, but to be safe ...
        crm_trace("Ignoring ACL <%s> element without selection criteria",
                  crm_element_name(xml));
        return NULL;
    }

    acl = calloc(1, sizeof (xml_acl_t));
    CRM_ASSERT(acl != NULL);

    acl->mode = mode;
    if (xpath) {
        acl->xpath = strdup(xpath);
        CRM_ASSERT(acl->xpath != NULL);
        crm_trace("Unpacked ACL <%s> element using xpath: %s",
                  crm_element_name(xml), acl->xpath);

    } else {
        GString *buf = g_string_sized_new(128);

        if ((ref != NULL) && (attr != NULL)) {
            // NOTE: schema currently does not allow this
            pcmk__g_strcat(buf, "//", pcmk__s(tag, "*"), "[@" XML_ATTR_ID "='",
                           ref, "' and @", attr, "]", NULL);

        } else if (ref != NULL) {
            pcmk__g_strcat(buf, "//", pcmk__s(tag, "*"), "[@" XML_ATTR_ID "='",
                           ref, "']", NULL);

        } else if (attr != NULL) {
            pcmk__g_strcat(buf, "//", pcmk__s(tag, "*"), "[@", attr, "]", NULL);

        } else {
            pcmk__g_strcat(buf, "//", pcmk__s(tag, "*"), NULL);
        }

        acl->xpath = strdup((const char *) buf->str);
        CRM_ASSERT(acl->xpath != NULL);

        g_string_free(buf, TRUE);
        crm_trace("Unpacked ACL <%s> element as xpath: %s",
                  crm_element_name(xml), acl->xpath);
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
parse_acl_entry(xmlNode *acl_top, xmlNode *acl_entry, GList *acls)
{
    xmlNode *child = NULL;

    for (child = pcmk__xe_first_child(acl_entry); child;
         child = pcmk__xe_next(child)) {
        const char *tag = crm_element_name(child);
        const char *kind = crm_element_value(child, XML_ACL_ATTR_KIND);

        if (strcmp(XML_ACL_TAG_PERMISSION, tag) == 0){
            CRM_ASSERT(kind != NULL);
            crm_trace("Unpacking ACL <%s> element of kind '%s'", tag, kind);
            tag = kind;
        } else {
            crm_trace("Unpacking ACL <%s> element", tag);
        }

        if (strcmp(XML_ACL_TAG_ROLE_REF, tag) == 0
                   || strcmp(XML_ACL_TAG_ROLE_REFv1, tag) == 0) {
            const char *ref_role = crm_element_value(child, XML_ATTR_ID);

            if (ref_role) {
                xmlNode *role = NULL;

                for (role = pcmk__xe_first_child(acl_top); role;
                     role = pcmk__xe_next(role)) {
                    if (!strcmp(XML_ACL_TAG_ROLE, (const char *) role->name)) {
                        const char *role_id = crm_element_value(role,
                                                                XML_ATTR_ID);

                        if (role_id && strcmp(ref_role, role_id) == 0) {
                            crm_trace("Unpacking referenced role '%s' in ACL <%s> element",
                                      role_id, crm_element_name(acl_entry));
                            acls = parse_acl_entry(acl_top, role, acls);
                            break;
                        }
                    }
                }
            }

        } else if (strcmp(XML_ACL_TAG_READ, tag) == 0) {
            acls = create_acl(child, acls, pcmk__xf_acl_read);

        } else if (strcmp(XML_ACL_TAG_WRITE, tag) == 0) {
            acls = create_acl(child, acls, pcmk__xf_acl_write);

        } else if (strcmp(XML_ACL_TAG_DENY, tag) == 0) {
            acls = create_acl(child, acls, pcmk__xf_acl_deny);

        } else {
            crm_warn("Ignoring unknown ACL %s '%s'",
                     (kind? "kind" : "element"), tag);
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
        <acl_permission id="observer-write-1" kind="write" xpath="//nvpair[@name='stonith-enabled']"/>
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
acl_to_text(enum xml_private_flags flags)
{
    if (pcmk_is_set(flags, pcmk__xf_acl_deny)) {
        return "deny";

    } else if (pcmk_any_flags_set(flags, pcmk__xf_acl_write|pcmk__xf_acl_create)) {
        return "read/write";

    } else if (pcmk_is_set(flags, pcmk__xf_acl_read)) {
        return "read";
    }
    return "none";
}

void
pcmk__apply_acl(xmlNode *xml)
{
    GList *aIter = NULL;
    xml_doc_private_t *docpriv = xml->doc->_private;
    xml_node_private_t *nodepriv;
    xmlXPathObjectPtr xpathObj = NULL;

    if (!xml_acl_enabled(xml)) {
        crm_trace("Skipping ACLs for user '%s' because not enabled for this XML",
                  docpriv->user);
        return;
    }

    for (aIter = docpriv->acls; aIter != NULL; aIter = aIter->next) {
        int max = 0, lpc = 0;
        xml_acl_t *acl = aIter->data;

        xpathObj = xpath_search(xml, acl->xpath);
        max = numXpathResults(xpathObj);

        for (lpc = 0; lpc < max; lpc++) {
            static struct qb_log_callsite *trace_cs = NULL;
            xmlNode *match = getXpathResult(xpathObj, lpc);

            nodepriv = match->_private;
            pcmk__set_xml_flags(nodepriv, acl->mode);

            /* Build a GString only if tracing is enabled.
             * Can't use pcmk__log_else() because the else_action would be
             * continue.
             */
            if (trace_cs == NULL) {
                trace_cs = qb_log_callsite_get(__func__, __FILE__, "apply_acl",
                                               LOG_TRACE, __LINE__, 0);
            }
            if (crm_is_callsite_active(trace_cs, LOG_TRACE, 0)) {
                GString *path = pcmk__element_xpath(match);
                crm_trace("Applying %s ACL to %s matched by %s",
                          acl_to_text(acl->mode), (const char *) path->str,
                          acl->xpath);
                g_string_free(path, TRUE);
            }
        }
        crm_trace("Applied %s ACL %s (%d match%s)",
                  acl_to_text(acl->mode), acl->xpath, max,
                  ((max == 1)? "" : "es"));
        freeXpathObject(xpathObj);
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
        crm_trace("Not unpacking ACLs because not required for user '%s'",
                  user);

    } else if (docpriv->acls == NULL) {
        xmlNode *acls = get_xpath_object("//" XML_CIB_TAG_ACLS,
                                         source, LOG_NEVER);

        pcmk__str_update(&docpriv->user, user);

        if (acls) {
            xmlNode *child = NULL;

            for (child = pcmk__xe_first_child(acls); child;
                 child = pcmk__xe_next(child)) {
                const char *tag = crm_element_name(child);

                if (!strcmp(tag, XML_ACL_TAG_USER)
                    || !strcmp(tag, XML_ACL_TAG_USERv1)) {
                    const char *id = crm_element_value(child, XML_ATTR_NAME);

                    if (id == NULL) {
                        id = crm_element_value(child, XML_ATTR_ID);
                    }

                    if (id && strcmp(id, user) == 0) {
                        crm_debug("Unpacking ACLs for user '%s'", id);
                        docpriv->acls = parse_acl_entry(acls, child, docpriv->acls);
                    }
                } else if (!strcmp(tag, XML_ACL_TAG_GROUP)) {
                    const char *id = crm_element_value(child, XML_ATTR_NAME);

                    if (id == NULL) {
                        id = crm_element_value(child, XML_ATTR_ID);
                    }

                    if (id && pcmk__is_user_in_group(user,id)) {
                        crm_debug("Unpacking ACLs for group '%s'", id);
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
    pcmk__unpack_acl(acl_source, target, user);
    pcmk__set_xml_doc_flag(target, pcmk__xf_acl_enabled);
    pcmk__apply_acl(target);
}

static inline bool
test_acl_mode(enum xml_private_flags allowed, enum xml_private_flags requested)
{
    if (pcmk_is_set(allowed, pcmk__xf_acl_deny)) {
        return false;

    } else if (pcmk_all_flags_set(allowed, requested)) {
        return true;

    } else if (pcmk_is_set(requested, pcmk__xf_acl_read)
               && pcmk_is_set(allowed, pcmk__xf_acl_write)) {
        return true;

    } else if (pcmk_is_set(requested, pcmk__xf_acl_create)
               && pcmk_any_flags_set(allowed, pcmk__xf_acl_write|pcmk__xf_created)) {
        return true;
    }
    return false;
}

/*!
 * \internal
 * \brief Rid XML tree of all unreadable nodes and node properties
 *
 * \param[in]     xml root node to be purged of attributes
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
    xmlAttr *xIter = NULL;
    bool readable_children = false;
    xml_node_private_t *nodepriv = xml->_private;

    if (test_acl_mode(nodepriv->flags, pcmk__xf_acl_read)) {
        crm_trace("%s[@id=%s] is readable", crm_element_name(xml), ID(xml));
        return true;
    }

    xIter = xml->properties;
    while (xIter != NULL) {
        xmlAttr *tmp = xIter;
        const char *prop_name = (const char *)xIter->name;

        xIter = xIter->next;
        if (strcmp(prop_name, XML_ATTR_ID) == 0) {
            continue;
        }

        xmlUnsetProp(xml, tmp->name);
    }

    child = pcmk__xml_first_child(xml);
    while ( child != NULL ) {
        xmlNode *tmp = child;

        child = pcmk__xml_next(child);
        readable_children |= purge_xml_attributes(tmp);
    }

    if (!readable_children) {
        free_xml(xml); /* Nothing readable under here, purge completely */
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
    GList *aIter = NULL;
    xmlNode *target = NULL;
    xml_doc_private_t *docpriv = NULL;

    *result = NULL;
    if ((xml == NULL) || !pcmk_acl_required(user)) {
        crm_trace("Not filtering XML because ACLs not required for user '%s'",
                  user);
        return false;
    }

    crm_trace("Filtering XML copy using user '%s' ACLs", user);
    target = copy_xml(xml);
    if (target == NULL) {
        return true;
    }

    pcmk__enable_acl(acl_source, target, user);

    docpriv = target->doc->_private;
    for(aIter = docpriv->acls; aIter != NULL && target; aIter = aIter->next) {
        int max = 0;
        xml_acl_t *acl = aIter->data;

        if (acl->mode != pcmk__xf_acl_deny) {
            /* Nothing to do */

        } else if (acl->xpath) {
            int lpc = 0;
            xmlXPathObjectPtr xpathObj = xpath_search(target, acl->xpath);

            max = numXpathResults(xpathObj);
            for(lpc = 0; lpc < max; lpc++) {
                xmlNode *match = getXpathResult(xpathObj, lpc);

                if (!purge_xml_attributes(match) && (match == target)) {
                    crm_trace("ACLs deny user '%s' access to entire XML document",
                              user);
                    freeXpathObject(xpathObj);
                    return true;
                }
            }
            crm_trace("ACLs deny user '%s' access to %s (%d %s)",
                      user, acl->xpath, max,
                      pcmk__plural_alt(max, "match", "matches"));
            freeXpathObject(xpathObj);
        }
    }

    if (!purge_xml_attributes(target)) {
        crm_trace("ACLs deny user '%s' access to entire XML document", user);
        return true;
    }

    if (docpriv->acls) {
        g_list_free_full(docpriv->acls, free_acl);
        docpriv->acls = NULL;

    } else {
        crm_trace("User '%s' without ACLs denied access to entire XML document",
                  user);
        free_xml(target);
        target = NULL;
    }

    if (target) {
        *result = target;
    }

    return true;
}

/*!
 * \internal
 * \brief Check whether creation of an XML element is implicitly allowed
 *
 * Check whether XML is a "scaffolding" element whose creation is implicitly
 * allowed regardless of ACLs (that is, it is not in the ACL section and has
 * no attributes other than "id").
 *
 * \param[in] xml  XML element to check
 *
 * \return true if XML element is implicitly allowed, false otherwise
 */
static bool
implicitly_allowed(xmlNode *xml)
{
    GString *path = NULL;

    for (xmlAttr *prop = xml->properties; prop != NULL; prop = prop->next) {
        if (strcmp((const char *) prop->name, XML_ATTR_ID) != 0) {
            return false;
        }
    }

    path = pcmk__element_xpath(xml);
    CRM_ASSERT(path != NULL);

    if (strstr((const char *) path->str, "/" XML_CIB_TAG_ACLS "/") != NULL) {
        g_string_free(path, TRUE);
        return false;
    }

    g_string_free(path, TRUE);
    return true;
}

#define display_id(xml) (ID(xml)? ID(xml) : "<unset>")

/*!
 * \internal
 * \brief Drop XML nodes created in violation of ACLs
 *
 * Given an XML element, free all of its descendent nodes created in violation
 * of ACLs, with the exception of allowing "scaffolding" elements (i.e. those
 * that aren't in the ACL section and don't have any attributes other than
 * "id").
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

    if (pcmk_is_set(nodepriv->flags, pcmk__xf_created)) {
        if (implicitly_allowed(xml)) {
            crm_trace("Creation of <%s> scaffolding with id=\"%s\""
                      " is implicitly allowed",
                      crm_element_name(xml), display_id(xml));

        } else if (pcmk__check_acl(xml, NULL, pcmk__xf_acl_write)) {
            crm_trace("ACLs allow creation of <%s> with id=\"%s\"",
                      crm_element_name(xml), display_id(xml));

        } else if (check_top) {
            crm_trace("ACLs disallow creation of <%s> with id=\"%s\"",
                      crm_element_name(xml), display_id(xml));
            pcmk_free_xml_subtree(xml);
            return;

        } else {
            crm_notice("ACLs would disallow creation of %s<%s> with id=\"%s\" ",
                       ((xml == xmlDocGetRootElement(xml->doc))? "root element " : ""),
                       crm_element_name(xml), display_id(xml));
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

        return pcmk_is_set(docpriv->flags, pcmk__xf_acl_denied);
    }
    return false;
}

void
xml_acl_disable(xmlNode *xml)
{
    if (xml_acl_enabled(xml)) {
        xml_doc_private_t *docpriv = xml->doc->_private;

        /* Catch anything that was created but shouldn't have been */
        pcmk__apply_acl(xml);
        pcmk__apply_creation_acl(xml, false);
        pcmk__clear_xml_flags(docpriv, pcmk__xf_acl_enabled);
    }
}

/*!
 * \brief Check whether or not an XML node is ACL-enabled
 *
 * \param[in]  xml node to check
 *
 * \return true if XML node exists and is ACL-enabled, false otherwise
 */
bool
xml_acl_enabled(xmlNode *xml)
{
    if (xml && xml->doc && xml->doc->_private){
        xml_doc_private_t *docpriv = xml->doc->_private;

        return pcmk_is_set(docpriv->flags, pcmk__xf_acl_enabled);
    }
    return false;
}

bool
pcmk__check_acl(xmlNode *xml, const char *name, enum xml_private_flags mode)
{
    CRM_ASSERT(xml);
    CRM_ASSERT(xml->doc);
    CRM_ASSERT(xml->doc->_private);

    if (pcmk__tracking_xml_changes(xml, false) && xml_acl_enabled(xml)) {
        xmlNode *parent = xml;
        xml_doc_private_t *docpriv = xml->doc->_private;
        GString *xpath = NULL;

        if (docpriv->acls == NULL) {
            pcmk__set_xml_doc_flag(xml, pcmk__xf_acl_denied);

            pcmk__log_else(LOG_TRACE, return false);
            xpath = pcmk__element_xpath(xml);
            if (name != NULL) {
                pcmk__g_strcat(xpath, "[@", name, "]", NULL);
            }

            qb_log_from_external_source(__func__, __FILE__,
                                        "User '%s' without ACLs denied %s "
                                        "access to %s", LOG_TRACE, __LINE__, 0,
                                        docpriv->user, acl_to_text(mode),
                                        (const char *) xpath->str);
            g_string_free(xpath, TRUE);
            return false;
        }

        /* Walk the tree upwards looking for xml_acl_* flags
         * - Creating an attribute requires write permissions for the node
         * - Creating a child requires write permissions for the parent
         */

        if (name) {
            xmlAttr *attr = xmlHasProp(xml, (pcmkXmlStr) name);

            if (attr && mode == pcmk__xf_acl_create) {
                mode = pcmk__xf_acl_write;
            }
        }

        while (parent && parent->_private) {
            xml_node_private_t *nodepriv = parent->_private;
            if (test_acl_mode(nodepriv->flags, mode)) {
                return true;

            } else if (pcmk_is_set(nodepriv->flags, pcmk__xf_acl_deny)) {
                pcmk__set_xml_doc_flag(xml, pcmk__xf_acl_denied);

                pcmk__log_else(LOG_TRACE, return false);
                xpath = pcmk__element_xpath(xml);
                if (name != NULL) {
                    pcmk__g_strcat(xpath, "[@", name, "]", NULL);
                }

                qb_log_from_external_source(__func__, __FILE__,
                                            "%sACL denies user '%s' %s access "
                                            "to %s", LOG_TRACE, __LINE__, 0,
                                            (parent != xml)? "Parent ": "",
                                            docpriv->user, acl_to_text(mode),
                                            (const char *) xpath->str);
                g_string_free(xpath, TRUE);
                return false;
            }
            parent = parent->parent;
        }

        pcmk__set_xml_doc_flag(xml, pcmk__xf_acl_denied);

        pcmk__log_else(LOG_TRACE, return false);
        xpath = pcmk__element_xpath(xml);
        if (name != NULL) {
            pcmk__g_strcat(xpath, "[@", name, "]", NULL);
        }

        qb_log_from_external_source(__func__, __FILE__,
                                    "Default ACL denies user '%s' %s access to "
                                    "%s", LOG_TRACE, __LINE__, 0,
                                    docpriv->user, acl_to_text(mode),
                                    (const char *) xpath->str);
        g_string_free(xpath, TRUE);
        return false;
    }

    return true;
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
        crm_trace("ACLs not required because no user set");
        return false;

    } else if (!strcmp(user, CRM_DAEMON_USER) || !strcmp(user, "root")) {
        crm_trace("ACLs not required for privileged user %s", user);
        return false;
    }
    crm_trace("ACLs required for %s", user);
    return true;
}

char *
pcmk__uid2username(uid_t uid)
{
    struct passwd *pwent = getpwuid(uid);

    if (pwent == NULL) {
        crm_perror(LOG_INFO, "Cannot get user details for user ID %d", uid);
        return NULL;
    }
    return strdup(pwent->pw_name);
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
            effective_user = strdup("#unprivileged");
            CRM_CHECK(effective_user != NULL, return NULL);
            crm_err("Unable to determine effective user, assuming unprivileged for ACLs");
        }
    }

    requested_user = crm_element_value(request, XML_ACL_TAG_USER);
    if (requested_user == NULL) {
        /* @COMPAT rolling upgrades <=1.1.11
         *
         * field is checked for backward compatibility with older versions that
         * did not use XML_ACL_TAG_USER.
         */
        requested_user = crm_element_value(request, field);
    }

    if (!pcmk__is_privileged(effective_user)) {
        /* We're not running as a privileged user, set or overwrite any existing
         * value for $XML_ACL_TAG_USER
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
         * value for $XML_ACL_TAG_USER
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
    if (user != crm_element_value(request, XML_ACL_TAG_USER)) {
        crm_xml_add(request, XML_ACL_TAG_USER, user);
    }

    if (field != NULL && user != crm_element_value(request, field)) {
        crm_xml_add(request, field, user);
    }

    return requested_user;
}
