/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
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
#include "crmcommon_private.h"

#define MAX_XPATH_LEN	4096

typedef struct xml_acl_s {
        enum xml_private_flags mode;
        char *xpath;
} xml_acl_t;

static void
__xml_acl_free(void *data)
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
    g_list_free_full(acls, __xml_acl_free);
}

static GList *
__xml_acl_create(xmlNode *xml, GList *acls, enum xml_private_flags mode)
{
    xml_acl_t *acl = NULL;

    const char *tag = crm_element_value(xml, XML_ACL_ATTR_TAG);
    const char *ref = crm_element_value(xml, XML_ACL_ATTR_REF);
    const char *xpath = crm_element_value(xml, XML_ACL_ATTR_XPATH);

    if (tag == NULL) {
        // @COMPAT rolling upgrades <=1.1.11
        tag = crm_element_value(xml, XML_ACL_ATTR_TAGv1);
    }
    if (ref == NULL) {
        // @COMPAT rolling upgrades <=1.1.11
        ref = crm_element_value(xml, XML_ACL_ATTR_REFv1);
    }

    if ((tag == NULL) && (ref == NULL) && (xpath == NULL)) {
        crm_trace("No criteria %p", xml);
        return NULL;
    }

    acl = calloc(1, sizeof (xml_acl_t));
    if (acl) {
        const char *attr = crm_element_value(xml, XML_ACL_ATTR_ATTRIBUTE);

        acl->mode = mode;
        if (xpath) {
            acl->xpath = strdup(xpath);
            crm_trace("Using xpath: %s", acl->xpath);

        } else {
            int offset = 0;
            char buffer[MAX_XPATH_LEN];

            if (tag) {
                offset += snprintf(buffer + offset, MAX_XPATH_LEN - offset,
                                   "//%s", tag);
            } else {
                offset += snprintf(buffer + offset, MAX_XPATH_LEN - offset,
                                   "//*");
            }

            if (ref || attr) {
                offset += snprintf(buffer + offset, MAX_XPATH_LEN - offset,
                                   "[");
            }

            if (ref) {
                offset += snprintf(buffer + offset, MAX_XPATH_LEN - offset,
                                   "@id='%s'", ref);
            }

            if (ref && attr) {
                offset += snprintf(buffer + offset, MAX_XPATH_LEN - offset,
                                   " and ");
            }

            if (attr) {
                offset += snprintf(buffer + offset, MAX_XPATH_LEN - offset,
                                   "@%s", attr);
            }

            if (ref || attr) {
                offset += snprintf(buffer + offset, MAX_XPATH_LEN - offset,
                                   "]");
            }

            CRM_LOG_ASSERT(offset > 0);
            acl->xpath = strdup(buffer);
            crm_trace("Built xpath: %s", acl->xpath);
        }

        acls = g_list_append(acls, acl);
    }
    return acls;
}

static GList *
__xml_acl_parse_entry(xmlNode *acl_top, xmlNode *acl_entry, GList *acls)
{
    xmlNode *child = NULL;

    for (child = __xml_first_child(acl_entry); child;
         child = __xml_next(child)) {
        const char *tag = crm_element_name(child);
        const char *kind = crm_element_value(child, XML_ACL_ATTR_KIND);

        if (strcmp(XML_ACL_TAG_PERMISSION, tag) == 0){
            tag = kind;
        }

        crm_trace("Processing %s %p", tag, child);
        if (tag == NULL) {
            CRM_ASSERT(tag != NULL);

        } else if (strcmp(XML_ACL_TAG_ROLE_REF, tag) == 0
                   || strcmp(XML_ACL_TAG_ROLE_REFv1, tag) == 0) {
            const char *ref_role = crm_element_value(child, XML_ATTR_ID);

            if (ref_role) {
                xmlNode *role = NULL;

                for (role = __xml_first_child(acl_top); role;
                     role = __xml_next(role)) {
                    if (!strcmp(XML_ACL_TAG_ROLE, (const char *) role->name)) {
                        const char *role_id = crm_element_value(role,
                                                                XML_ATTR_ID);

                        if (role_id && strcmp(ref_role, role_id) == 0) {
                            crm_debug("Unpacking referenced role: %s", role_id);
                            acls = __xml_acl_parse_entry(acl_top, role, acls);
                            break;
                        }
                    }
                }
            }

        } else if (strcmp(XML_ACL_TAG_READ, tag) == 0) {
            acls = __xml_acl_create(child, acls, xpf_acl_read);

        } else if (strcmp(XML_ACL_TAG_WRITE, tag) == 0) {
            acls = __xml_acl_create(child, acls, xpf_acl_write);

        } else if (strcmp(XML_ACL_TAG_DENY, tag) == 0) {
            acls = __xml_acl_create(child, acls, xpf_acl_deny);

        } else {
            crm_warn("Unknown ACL entry: %s/%s", tag, kind);
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

#ifdef SUSE_ACL_COMPAT
static const char *
__xml_acl_to_text(enum xml_private_flags flags)
{
    if (is_set(flags, xpf_acl_deny)) {
        return "deny";

    } else if (is_set(flags, xpf_acl_write)) {
        return "read/write";

    } else if (is_set(flags, xpf_acl_read)) {
        return "read";
    }
    return "none";
}
#endif

void
pcmk__apply_acl(xmlNode *xml)
{
    GListPtr aIter = NULL;
    xml_private_t *p = xml->doc->_private;
    xmlXPathObjectPtr xpathObj = NULL;

    if (xml_acl_enabled(xml) == FALSE) {
        crm_trace("Not applying ACLs for %s", p->user);
        return;
    }

    for (aIter = p->acls; aIter != NULL; aIter = aIter->next) {
        int max = 0, lpc = 0;
        xml_acl_t *acl = aIter->data;

        xpathObj = xpath_search(xml, acl->xpath);
        max = numXpathResults(xpathObj);

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *match = getXpathResult(xpathObj, lpc);
            char *path = xml_get_path(match);

            p = match->_private;
            crm_trace("Applying %x to %s for %s", acl->mode, path, acl->xpath);

#ifdef SUSE_ACL_COMPAT
            if (is_not_set(p->flags, acl->mode)
                && (is_set(p->flags, xpf_acl_read)
                    || is_set(p->flags, xpf_acl_write)
                    || is_set(p->flags, xpf_acl_deny))) {
                crm_config_warn("Configuration element %s is matched by "
                                "multiple ACL rules, only the first applies "
                                "('%s' wins over '%s')",
                                path, __xml_acl_to_text(p->flags),
                                __xml_acl_to_text(acl->mode));
                free(path);
                continue;
            }
#endif
            p->flags |= acl->mode;
            free(path);
        }
        crm_trace("Now enforcing ACL: %s (%d matches)", acl->xpath, max);
        freeXpathObject(xpathObj);
    }

    p = xml->_private;
    if (is_not_set(p->flags, xpf_acl_read)
        && is_not_set(p->flags, xpf_acl_write)) {

        p->flags |= xpf_acl_deny;
        p = xml->doc->_private;
        crm_info("Enforcing default ACL for %s to %s",
                 p->user, crm_element_name(xml));
    }

}

void
pcmk__unpack_acl(xmlNode *source, xmlNode *target, const char *user)
{
#if ENABLE_ACL
    xml_private_t *p = NULL;

    if ((target == NULL) || (target->doc == NULL)
        || (target->doc->_private == NULL)) {
        return;
    }

    p = target->doc->_private;
    if (pcmk_acl_required(user) == FALSE) {
        crm_trace("no acls needed for '%s'", user);

    } else if (p->acls == NULL) {
        xmlNode *acls = get_xpath_object("//" XML_CIB_TAG_ACLS,
                                         source, LOG_TRACE);

        free(p->user);
        p->user = strdup(user);

        if (acls) {
            xmlNode *child = NULL;

            for (child = __xml_first_child(acls); child;
                 child = __xml_next(child)) {
                const char *tag = crm_element_name(child);

                if (!strcmp(tag, XML_ACL_TAG_USER)
                    || !strcmp(tag, XML_ACL_TAG_USERv1)) {
                    const char *id = crm_element_value(child, XML_ATTR_ID);

                    if (id && strcmp(id, user) == 0) {
                        crm_debug("Unpacking ACLs for %s", id);
                        p->acls = __xml_acl_parse_entry(acls, child, p->acls);
                    }
                }
            }
        }
    }
#endif
}

static inline bool
__xml_acl_mode_test(enum xml_private_flags allowed,
                    enum xml_private_flags requested)
{
    if (is_set(allowed, xpf_acl_deny)) {
        return FALSE;

    } else if (is_set(allowed, requested)) {
        return TRUE;

    } else if (is_set(requested, xpf_acl_read)
               && is_set(allowed, xpf_acl_write)) {
        return TRUE;

    } else if (is_set(requested, xpf_acl_create)
               && is_set(allowed, xpf_acl_write)) {
        return TRUE;

    } else if (is_set(requested, xpf_acl_create)
               && is_set(allowed, xpf_created)) {
        return TRUE;
    }
    return FALSE;
}

/* rc = TRUE if orig_cib has been filtered
 * That means '*result' rather than 'xml' should be exploited afterwards
 */
static bool
__xml_purge_attributes(xmlNode *xml)
{
    xmlNode *child = NULL;
    xmlAttr *xIter = NULL;
    bool readable_children = FALSE;
    xml_private_t *p = xml->_private;

    if (__xml_acl_mode_test(p->flags, xpf_acl_read)) {
        crm_trace("%s[@id=%s] is readable", crm_element_name(xml), ID(xml));
        return TRUE;
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

    child = __xml_first_child(xml);
    while ( child != NULL ) {
        xmlNode *tmp = child;

        child = __xml_next(child);
        readable_children |= __xml_purge_attributes(tmp);
    }

    if (readable_children == FALSE) {
        free_xml(xml); /* Nothing readable under here, purge completely */
    }
    return readable_children;
}

bool
xml_acl_filtered_copy(const char *user, xmlNode *acl_source, xmlNode *xml,
                      xmlNode **result)
{
    GListPtr aIter = NULL;
    xmlNode *target = NULL;
    xml_private_t *p = NULL;
    xml_private_t *doc = NULL;

    *result = NULL;
    if (xml == NULL || pcmk_acl_required(user) == FALSE) {
        crm_trace("no acls needed for '%s'", user);
        return FALSE;
    }

    crm_trace("filtering copy of %p for '%s'", xml, user);
    target = copy_xml(xml);
    if (target == NULL) {
        return TRUE;
    }

    pcmk__unpack_acl(acl_source, target, user);
    pcmk__set_xml_flag(target, xpf_acl_enabled);
    pcmk__apply_acl(target);

    doc = target->doc->_private;
    for(aIter = doc->acls; aIter != NULL && target; aIter = aIter->next) {
        int max = 0;
        xml_acl_t *acl = aIter->data;

        if (acl->mode != xpf_acl_deny) {
            /* Nothing to do */

        } else if (acl->xpath) {
            int lpc = 0;
            xmlXPathObjectPtr xpathObj = xpath_search(target, acl->xpath);

            max = numXpathResults(xpathObj);
            for(lpc = 0; lpc < max; lpc++) {
                xmlNode *match = getXpathResult(xpathObj, lpc);

                crm_trace("Purging attributes from %s", acl->xpath);
                if (__xml_purge_attributes(match) == FALSE && match == target) {
                    crm_trace("No access to the entire document for %s", user);
                    freeXpathObject(xpathObj);
                    return TRUE;
                }
            }
            crm_trace("Enforced ACL %s (%d matches)", acl->xpath, max);
            freeXpathObject(xpathObj);
        }
    }

    p = target->_private;
    if (is_set(p->flags, xpf_acl_deny)
        && (__xml_purge_attributes(target) == FALSE)) {
        crm_trace("No access to the entire document for %s", user);
        return TRUE;
    }

    if (doc->acls) {
        g_list_free_full(doc->acls, __xml_acl_free);
        doc->acls = NULL;

    } else {
        crm_trace("Ordinary user '%s' cannot access the CIB without any defined ACLs",
                  doc->user);
        free_xml(target);
        target = NULL;
    }

    if (target) {
        *result = target;
    }

    return TRUE;
}

void
pcmk__post_process_acl(xmlNode *xml)
{
    xmlNode *cIter = __xml_first_child(xml);
    xml_private_t *p = xml->_private;

    if (is_set(p->flags, xpf_created)) {
        xmlAttr *xIter = NULL;
        char *path = xml_get_path(xml);

        /* Always allow new scaffolding (e.g. node with no attributes or only an
         * 'id'), except in the ACLs section
         */

        for (xIter = xml->properties; xIter != NULL; xIter = xIter->next) {
            const char *prop_name = (const char *)xIter->name;

            if (!strcmp(prop_name, XML_ATTR_ID)
                && !strstr(path, "/"XML_CIB_TAG_ACLS"/")) {
                /* Delay the acl check */
                continue;

            } else if (pcmk__check_acl(xml, NULL, xpf_acl_write)) {
                crm_trace("Creation of %s=%s is allowed",
                          crm_element_name(xml), ID(xml));
                break;

            } else {
                crm_trace("Cannot add new node %s at %s",
                          crm_element_name(xml), path);

                if (xml != xmlDocGetRootElement(xml->doc)) {
                    xmlUnlinkNode(xml);
                    xmlFreeNode(xml);
                }
                free(path);
                return;
            }
        }
        free(path);
    }

    while (cIter != NULL) {
        xmlNode *child = cIter;
        cIter = __xml_next(cIter); /* In case it is free'd */
        pcmk__post_process_acl(child);
    }
}

bool
xml_acl_denied(xmlNode *xml)
{
    if (xml && xml->doc && xml->doc->_private){
        xml_private_t *p = xml->doc->_private;

        return is_set(p->flags, xpf_acl_denied);
    }
    return FALSE;
}

void
xml_acl_disable(xmlNode *xml)
{
    if (xml_acl_enabled(xml)) {
        xml_private_t *p = xml->doc->_private;

        /* Catch anything that was created but shouldn't have been */
        pcmk__apply_acl(xml);
        pcmk__post_process_acl(xml);
        clear_bit(p->flags, xpf_acl_enabled);
    }
}

bool
xml_acl_enabled(xmlNode *xml)
{
    if (xml && xml->doc && xml->doc->_private){
        xml_private_t *p = xml->doc->_private;

        return is_set(p->flags, xpf_acl_enabled);
    }
    return FALSE;
}

bool
pcmk__check_acl(xmlNode *xml, const char *name, enum xml_private_flags mode)
{
    CRM_ASSERT(xml);
    CRM_ASSERT(xml->doc);
    CRM_ASSERT(xml->doc->_private);

#if ENABLE_ACL
    if (pcmk__tracking_xml_changes(xml, FALSE) && xml_acl_enabled(xml)) {
        int offset = 0;
        xmlNode *parent = xml;
        char buffer[MAX_XPATH_LEN];
        xml_private_t *docp = xml->doc->_private;

        if (docp->acls == NULL) {
            crm_trace("Ordinary user %s cannot access the CIB without any defined ACLs",
                      docp->user);
            pcmk__set_xml_flag(xml, xpf_acl_denied);
            return FALSE;
        }

        offset = pcmk__element_xpath(NULL, xml, buffer, offset,
                                     sizeof(buffer));
        if (name) {
            offset += snprintf(buffer + offset, MAX_XPATH_LEN - offset,
                               "[@%s]", name);
        }
        CRM_LOG_ASSERT(offset > 0);

        /* Walk the tree upwards looking for xml_acl_* flags
         * - Creating an attribute requires write permissions for the node
         * - Creating a child requires write permissions for the parent
         */

        if (name) {
            xmlAttr *attr = xmlHasProp(xml, (const xmlChar *)name);

            if (attr && mode == xpf_acl_create) {
                mode = xpf_acl_write;
            }
        }

        while (parent && parent->_private) {
            xml_private_t *p = parent->_private;
            if (__xml_acl_mode_test(p->flags, mode)) {
                return TRUE;

            } else if (is_set(p->flags, xpf_acl_deny)) {
                crm_trace("%x access denied to %s: parent", mode, buffer);
                pcmk__set_xml_flag(xml, xpf_acl_denied);
                return FALSE;
            }
            parent = parent->parent;
        }

        crm_trace("%x access denied to %s: default", mode, buffer);
        pcmk__set_xml_flag(xml, xpf_acl_denied);
        return FALSE;
    }
#endif

    return TRUE;
}

bool
pcmk_acl_required(const char *user)
{
#if ENABLE_ACL
    if (user == NULL || strlen(user) == 0) {
        crm_trace("no user set");
        return FALSE;

    } else if (strcmp(user, CRM_DAEMON_USER) == 0) {
        return FALSE;

    } else if (strcmp(user, "root") == 0) {
        return FALSE;
    }
    crm_trace("ACLs required for %s", user);
    return TRUE;
#else
    crm_trace("ACLs not supported");
    return FALSE;
#endif
}

#if ENABLE_ACL
char *
uid2username(uid_t uid)
{
    struct passwd *pwent = getpwuid(uid);

    if (pwent == NULL) {
        crm_perror(LOG_INFO, "Cannot get user details for user ID %d", uid);
        return NULL;
    }
    return strdup(pwent->pw_name);
}

const char *
crm_acl_get_set_user(xmlNode *request, const char *field, const char *peer_user)
{
    static const char *effective_user = NULL;
    const char *requested_user = NULL;
    const char *user = NULL;

    if (effective_user == NULL) {
        effective_user = uid2username(geteuid());
        if (effective_user == NULL) {
            return NULL;
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

    if (is_privileged(effective_user) == FALSE) {
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

    } else if (is_privileged(peer_user) == FALSE) {
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
#endif
