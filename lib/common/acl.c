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

typedef struct {
    enum pcmk__xml_flags mode;
    gchar *xpath;
} xml_acl_t;

/*!
 * \internal
 * \brief Free an \c xml_acl_t object
 *
 * \param[in,out] data  \c xml_acl_t object to free
 *
 * \note This is a \c GDestroyNotify function.
 */
static void
free_acl(void *data)
{
    xml_acl_t *acl = data;

    if (acl == NULL) {
        return;
    }

    g_free(acl->xpath);
    free(acl);
}

/*!
 * \internal
 * \brief Free a list of \c xml_acl_t objects
 *
 * \param[in,out] acls  List of \c xml_acl_t objects
 */
void
pcmk__free_acls(GList *acls)
{
    g_list_free_full(acls, free_acl);
}

/*!
 * \internal
 * \brief Get readable description of an ACL mode
 *
 * \param[in] mode  ACL mode (one of \c pcmk__xf_acl_read,
 *                  \c pcmk__xf_acl_write, \c pcmk__xf_acl_deny, or
 *                  \c pcmk__xf_acl_create
 *
 * \return Static string describing \p mode, or \c "none" if \p mode is invalid
 */
static const char *
acl_mode_text(enum pcmk__xml_flags mode)
{
    switch (mode) {
        case pcmk__xf_acl_read:
            return "read";

        case pcmk__xf_acl_create:
        case pcmk__xf_acl_write:
            return "read/write";

        case pcmk__xf_acl_deny:
            return "deny";

        default:
            return "none";
    }
}

/*!
 * \internal
 * \brief Parse an ACL mode from a string
 *
 * \param[in] text  String to parse
 *
 * \return ACL mode corresponding to \p text
 */
static enum pcmk__xml_flags
parse_acl_mode(const char *text)
{
    if (pcmk__str_eq(text, PCMK_VALUE_READ, pcmk__str_none)) {
        return pcmk__xf_acl_read;
    }

    if (pcmk__str_eq(text, PCMK_VALUE_WRITE, pcmk__str_none)) {
        return pcmk__xf_acl_write;
    }

    if (pcmk__str_eq(text, PCMK_VALUE_DENY, pcmk__str_none)) {
        return pcmk__xf_acl_deny;
    }

    return pcmk__xf_none;
}

/*!
 * \internal
 * \brief Set a config warning if ACL permission specifiers are mismatched
 *
 * The schema requires exactly one of \c PCMK_XA_XPATH, \c PCMK_XA_REFERENCE,
 * or \c PCMK_XA_OBJECT_TYPE. Additionally, \c PCMK_XA_ATTRIBUTE may be used
 * only with \c PCMK_XA_OBJECT_TYPE.
 *
 * We've handled these in a very permissive and inconsistent manner thus far. To
 * avoid breaking backward compatibility, the best we can do for now is to set
 * configuration warnings and log how we will behave if the specifiers are set
 * incorrectly.
 *
 * The caller has already ensured that at least one of \c PCMK_XA_XPATH,
 * \c PCMK_XA_REFERENCE, or \c PCMK_XA_OBJECT_TYPE is set.
 */
static void
warn_on_specifier_mismatch(const xmlNode *xml, const char *xpath,
                           const char *ref, const char *tag, const char *attr)
{
    // @COMPAT Let's be more strict at a compatibility break... please...

    const char *id = pcmk__s(pcmk__xe_id(xml), "without ID");
    const char *parent_id = pcmk__s(pcmk__xe_id(xml->parent), "without ID");
    const char *parent_type = (const char *) xml->parent->name;

    if ((xpath != NULL) && (ref == NULL) && (tag == NULL) && (attr == NULL)) {
        return;
    }

    if ((xpath == NULL) && (ref != NULL) && (tag == NULL) && (attr == NULL)) {
        return;
    }

    if ((xpath == NULL) && (ref == NULL) && (tag != NULL)) {
        return;
    }

    // Remaining cases are not possible with schema validation enabled

    if (xpath != NULL) {
        pcmk__config_warn("<" PCMK_XE_ACL_PERMISSION "> element %s "
                          "(in <%s> %s) has " PCMK_XA_XPATH " set along with "
                          PCMK_XA_REFERENCE ", " PCMK_XA_OBJECT_TYPE ", or "
                          PCMK_XA_ATTRIBUTE ". Using " PCMK_XA_XPATH " and "
                          "ignoring the rest.", id, parent_type, parent_id);
        return;
    }

    // Log both of the below if appropriate

    if ((tag == NULL) && (attr != NULL)) {
        pcmk__config_warn("<" PCMK_XE_ACL_PERMISSION "> element %s "
                          "(in <%s> %s) has " PCMK_XA_ATTRIBUTE " set without "
                          PCMK_XA_OBJECT_TYPE ". Using '*' for "
                          PCMK_XA_OBJECT_TYPE ".", id, parent_type, parent_id);
    }

    if (ref != NULL) {
        pcmk__config_warn("<" PCMK_XE_ACL_PERMISSION "> element %s "
                          "(in <%s> %s) has " PCMK_XA_REFERENCE " set along "
                          "with " PCMK_XA_OBJECT_TYPE " or "
                          PCMK_XA_ATTRIBUTE ". Using all of these criteria "
                          "together, but support may be removed in a future "
                          "release.", id, parent_type, parent_id);
    }
}

/*!
 * \internal
 * \brief Create an ACL based on an ACL permission XML element
 *
 * The \c PCMK_XE_ACL_PERMISSION element should have already been validated for
 * unrecoverable schema violations when this function is called. There may be
 * recoverable violations, but the element should be well-formed enough to
 * create an \c xml_acl_t.
 *
 * \param[in] xml   \c PCMK_XE_ACL_PERMISSION element
 * \param[in] mode  One of \c pcmk__xf_acl_read, \c pcmk__xf_acl_write, or
 *                  \c pcmk__xf_acl_deny
 *
 * \return Newly allocated ACL object (guaranteed not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using
 *       \c free_acl().
 */
static xml_acl_t *
create_acl(const xmlNode *xml, enum pcmk__xml_flags mode)
{
    const char *tag = pcmk__xe_get(xml, PCMK_XA_OBJECT_TYPE);
    const char *ref = pcmk__xe_get(xml, PCMK_XA_REFERENCE);
    const char *xpath = pcmk__xe_get(xml, PCMK_XA_XPATH);
    const char *attr = pcmk__xe_get(xml, PCMK_XA_ATTRIBUTE);

    GString *buf = NULL;
    xml_acl_t *acl = pcmk__assert_alloc(1, sizeof (xml_acl_t));

    warn_on_specifier_mismatch(xml, xpath, ref, tag, attr);

    acl->mode = mode;

    if (xpath != NULL) {
        acl->xpath = g_strdup(xpath);
        return acl;
    }

    buf = g_string_sized_new(128);

    g_string_append_printf(buf, "//%s", pcmk__s(tag, "*"));

    if ((ref != NULL) && (attr != NULL)) {
        // Not possible with schema validation enabled
        g_string_append_printf(buf, "[@" PCMK_XA_ID "='%s' and @%s]", ref,
                               attr);

    } else if (ref != NULL) {
        g_string_append_printf(buf, "[@" PCMK_XA_ID "='%s']", ref);

    } else if (attr != NULL) {
        g_string_append_printf(buf, "[@%s]", attr);
    }

    acl->xpath = g_string_free(buf, FALSE);
    return acl;
}

/*!
 * \internal
 * \brief Unpack a \c PCMK_XE_ACL_PERMISSION element to an \c xml_acl_t
 *
 * Append the new \c xml_acl_t object to a list.
 *
 * \param[in]     xml        Permission element to unpack
 * \param[in,out] user_data  List of ACLs to append to (<tt>GList **</tt>)
 *
 * \return \c pcmk_rc_ok (to keep iterating)
 *
 * \note The caller is responsible for freeing \p *user_data using
 *       \c pcmk__free_acls().
 * \note This is used as a callback for \c pcmk__xe_foreach_child().
 */
static int
unpack_acl_permission(xmlNode *xml, void *user_data)
{
    GList **acls = user_data;
    const char *id = pcmk__xe_id(xml);
    const char *parent_id = pcmk__s(pcmk__xe_id(xml->parent), "without ID");
    const char *parent_type = (const char *) xml->parent->name;

    const char *kind_s = pcmk__xe_get(xml, PCMK_XA_KIND);
    enum pcmk__xml_flags kind = pcmk__xf_none;
    xml_acl_t *acl = NULL;

    if (id == NULL) {
        // Not possible with schema validation enabled
        pcmk__config_warn("<" PCMK_XE_ACL_PERMISSION "> element in <%s> %s has "
                          "no " PCMK_XA_ID " attribute", parent_type,
                          parent_id);

        // Set a value to use for logging and continue unpacking
        id = "without ID";
    }

    if (kind_s == NULL) {
        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring <" PCMK_XE_ACL_PERMISSION "> element %s "
                         "(in <%s> %s) with no " PCMK_XA_KIND " attribute", id,
                         parent_type, parent_id);
        return pcmk_rc_ok;
    }

    kind = parse_acl_mode(kind_s);
    if (kind == pcmk__xf_none) {
        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring <" PCMK_XE_ACL_PERMISSION "> element %s "
                         "(in <%s> %s) with unknown ACL kind '%s'", id,
                         parent_type, parent_id, kind_s);
        return pcmk_rc_ok;
    }

    if ((pcmk__xe_get(xml, PCMK_XA_OBJECT_TYPE) == NULL)
        && (pcmk__xe_get(xml, PCMK_XA_REFERENCE) == NULL)
        && (pcmk__xe_get(xml, PCMK_XA_XPATH) == NULL)) {

        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring <" PCMK_XE_ACL_PERMISSION "> element %s "
                         "(in <%s> %s) without selection criteria. Exactly one "
                         "of the following attributes is required: "
                         PCMK_XA_OBJECT_TYPE ", " PCMK_XA_REFERENCE ", "
                         PCMK_XA_XPATH ".", id, parent_type, parent_id);
        return pcmk_rc_ok;
    }

    acl = create_acl(xml, kind);
    *acls = g_list_append(*acls, acl);

    pcmk__trace("Unpacked <" PCMK_XE_ACL_PERMISSION "> element %s "
                "(in <%s> %s) with " PCMK_XA_KIND "='%s' as XPath '%s'", id,
                parent_type, parent_id, kind_s, acl->xpath);

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Get the ACL role whose ID matches a role reference
 *
 * If there are multiple matches (not allowed by the schema), return the first
 * one for backward compatibility and set a config warning.
 *
 * \param[in] xml  \c PCMK_XE_ROLE element (an ACL role reference)
 *
 * \return \c PCMK_XE_ACL_ROLE element whose \c PCMK_XA_ID attribute matches
 *         that of \p xml, or \c NULL if none is found
 */
static xmlNode *
resolve_acl_role_ref(xmlNode *xml)
{
    const char *id = pcmk__xe_id(xml);
    const char *parent_id = pcmk__s(pcmk__xe_id(xml->parent), "without ID");
    const char *parent_type = (const char *) xml->parent->name;

    xmlNode *result = NULL;
    char *xpath = pcmk__assert_asprintf("//" PCMK_XE_ACL_ROLE
                                        "[@" PCMK_XA_ID "='%s']", id);
    xmlXPathObject *xpath_obj = pcmk__xpath_search(xml->doc, xpath);
    const int num_results = pcmk__xpath_num_results(xpath_obj);

    switch (num_results) {
        case 0:
            // Caller calls pcmk__config_err()
            break;

        case 1:
            // Success
            result = pcmk__xpath_result(xpath_obj, 0);
            break;

        default:
            /* Not possible with schema validation enabled.
             *
             * @COMPAT At a compatibility break, use pcmk__xpath_find_one(),
             * treat this as an error, and return NULL. For now, return the
             * first match.
             */
            result = pcmk__xpath_result(xpath_obj, 0);
            pcmk__config_warn("Multiple <" PCMK_XE_ACL_ROLE "> elements have "
                              PCMK_XA_ID "='%s'. Returning the first one for "
                              "<" PCMK_XE_ROLE "> in <%s> %s.", id, parent_type,
                              parent_id);
            break;
    }

    free(xpath);
    xmlXPathFreeObject(xpath_obj);
    return result;
}

/*!
 * \internal
 * \brief Unpack an ACL role reference to a list of \c xml_acl_t
 *
 * Unpack a \c PCMK_XE_ROLE element within a \c PCMK_XE_ACL_TARGET or
 * \c PCMK_XE_ACL_GROUP element. This element is a role reference. Its
 * \c PCMK_XA_ID attribute is an IDREF; it must match the ID of a
 * \c PCMK_XE_ACL_ROLE child of the \c PCMK_XE_ACLS element.
 *
 * The referenced \c PCMK_XE_ACL_ROLE contains zero or more
 * \c PCMK_XE_ACL_PERMISSION children. Unpack those children to \c xml_acl_t
 * objects and append them to a list.
 *
 * \param[in]     xml   Role reference element to unpack
 * \param[in,out] acls  List of ACLs to append to (\c NULL to start a new list)
 *
 * \return On success, \p acls with the new items appended, or a new list
 *         containing only the new items if \p acls is \c NULL. On failure,
 *         \p acls (unmodified).
 *
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__free_acls().
 */
static GList *
unpack_acl_role_ref(xmlNode *xml, GList *acls)
{
    const char *id = pcmk__xe_id(xml);
    const char *parent_id = pcmk__s(pcmk__xe_id(xml->parent), "without ID");
    const char *parent_type = (const char *) xml->parent->name;

    xmlNode *role = NULL;

    if (id == NULL) {
        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring <" PCMK_XE_ROLE "> element in <%s> %s with "
                         "no " PCMK_XA_ID " attribute", parent_type, parent_id);

        // There is no reference role ID to match and unpack
        return acls;
    }

    role = resolve_acl_role_ref(xml);
    if (role == NULL) {
        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring <" PCMK_XE_ROLE "> element %s in <%s> %s: "
                         "no <" PCMK_XE_ACL_ROLE "> with matching "
                         PCMK_XA_ID " found", id, parent_type, parent_id);
        return acls;
    }

    pcmk__trace("Unpacking role '%s' referenced in <%s> element %s", id,
                parent_type, parent_id);

    pcmk__xe_foreach_child(role, PCMK_XE_ACL_PERMISSION, unpack_acl_permission,
                           &acls);
    return acls;
}

/*!
 * \internal
 * \brief Unpack a child of an ACL target or group to a list of \c xml_acl_t
 *
 * \param[in]     xml        Child of a \c PCMK_XE_ACL_TARGET or
 *                           \c PCMK_XE_ACL_GROUP
 * \param[in,out] user_data  List of ACLs to append to (<tt>GList **</tt>)
 *
 * \return \c pcmk_rc_ok (to keep iterating)
 *
 * \note The caller is responsible for freeing \p *user_data using
 *       \c pcmk__free_acls().
 * \note This is used as a callback for \c pcmk__xe_foreach_child().
 */
static int
unpack_acl_role_ref_or_perm(xmlNode *xml, void *user_data)
{
    GList **acls = user_data;
    const char *id = pcmk__s(pcmk__xe_id(xml), "without ID");
    const char *parent_id = pcmk__s(pcmk__xe_id(xml->parent), "without ID");
    const char *parent_type = (const char *) xml->parent->name;

    if (pcmk__xe_is(xml, PCMK_XE_ROLE)) {
        *acls = unpack_acl_role_ref(xml, *acls);
        return pcmk_rc_ok;
    }

    if (!pcmk__xe_is(xml, PCMK_XE_ACL_PERMISSION)) {
        return pcmk_rc_ok;
    }

    /* Not possible with schema validation enabled.
     *
     * @COMPAT Drop this support at a compatibility break. A PCMK_XE_ACL_TARGET
     * or PCMK_XE_ACL_GROUP element should contain only PCMK_XE_ROLE elements as
     * children.
     */
    pcmk__config_warn("<" PCMK_XE_ACL_PERMISSION "> element %s is a child of "
                      "<%s> %s. It should be a child of an "
                      "<" PCMK_XE_ACL_ROLE ">, and the parent should reference "
                      "that <" PCMK_XE_ACL_ROLE ">.", id, parent_type,
                      parent_id);

    unpack_acl_permission(xml, acls);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Unpack an ACL target (user) element to a list of \c xml_acl_t
 *
 * \param[in]     xml      \c PCMK_XE_ACL_TARGET element to unpack
 * \param[in,out] docpriv  XML document private data whose \c acls field to
 *                         append to
 */
static void
unpack_acl_target(xmlNode *xml, xml_doc_private_t *docpriv)
{
    const char *id = pcmk__s(pcmk__xe_get(xml, PCMK_XA_NAME), pcmk__xe_id(xml));

    if (id == NULL) {
        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring <" PCMK_XE_ACL_TARGET "> element with no "
                         PCMK_XA_NAME " or " PCMK_XA_ID " attribute");

        // There is no user ID for the current ACL user to match
        return;
    }

    if (!pcmk__str_eq(id, docpriv->acl_user, pcmk__str_none)) {
        return;
    }

    pcmk__trace("Unpacking ACLs for user '%s'", id);
    pcmk__xe_foreach_child(xml, NULL, unpack_acl_role_ref_or_perm,
                           &docpriv->acls);
}

/*!
 * \internal
 * \brief Unpack an ACL group element to a list of \c xml_acl_t
 *
 * \param[in]     xml      \c PCMK_XE_ACL_TARGET element to unpack
 * \param[in,out] docpriv  XML document private data whose \c acls field to
 *                         append to
 */
static void
unpack_acl_group(xmlNode *xml, xml_doc_private_t *docpriv)
{
    const char *id = pcmk__s(pcmk__xe_get(xml, PCMK_XA_NAME), pcmk__xe_id(xml));

    if (id == NULL) {
        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring <" PCMK_XE_ACL_GROUP "> element with no "
                         PCMK_XA_NAME " or " PCMK_XA_ID " attribute");

        // There is no group ID for the current ACL user to match
        return;
    }

    if (!pcmk__is_user_in_group(docpriv->acl_user, id)) {
        return;
    }

    pcmk__trace("Unpacking ACLs for group '%s' (user '%s')", id,
                docpriv->acl_user);
    pcmk__xe_foreach_child(xml, NULL, unpack_acl_role_ref_or_perm,
                           &docpriv->acls);
}

/*!
 * \internal
 * \brief Unpack an ACL target (user) or group element to a list of \c xml_acl_t
 *
 * \param[in]     xml        Element to unpack (\c PCMK_XE_ACL_TARGET
 *                           or \c PCMK_XE_ACL_GROUP)
 * \param[in,out] user_data  XML document private data whose \c acls field to
 *                           append to (<tt>xml_doc_private_t *</tt>)
 *
 * \return \c pcmk_rc_ok (to keep iterating)
 *
 * \note The caller is responsible for freeing \p user_data->acls using
 *       \c pcmk__free_acls().
 * \note This is used as a callback for \c pcmk__xe_foreach_child().
 */
static int
unpack_acl_target_or_group(xmlNode *xml, void *user_data)
{
    if (pcmk__xe_is(xml, PCMK_XE_ACL_TARGET)) {
        unpack_acl_target(xml, user_data);
        return pcmk_rc_ok;
    }

    if (pcmk__xe_is(xml, PCMK_XE_ACL_GROUP)) {
        unpack_acl_group(xml, user_data);
        return pcmk_rc_ok;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Add a user's ACLs to a target XML document's private data
 *
 * Unpack the ACLs that apply to the user from the \c PCMK_XE_ACLS element in
 * the source document to the \c acls list in the target document. If that list
 * is already non-empty or if the user doesn't require ACLs, do nothing.
 *
 * Also set the target document's \c acl_user field to the given user.
 *
 * \param[in]     source  XML document whose ACL definitions to use
 * \param[in,out] target  XML document private data whose \c acls field to set
 * \param[in]     user    User whose ACLs to unpack
 */
void
pcmk__unpack_acls(xmlDoc *source, xml_doc_private_t *target, const char *user)
{
    xmlNode *acls = NULL;

    pcmk__assert(target != NULL);

    if ((target->acls != NULL) || !pcmk_acl_required(user)) {
        return;
    }

    pcmk__str_update(&target->acl_user, user);

    acls = pcmk__xpath_find_one(source, "//" PCMK_XE_ACLS, PCMK__LOG_NEVER);
    pcmk__xe_foreach_child(acls, NULL, unpack_acl_target_or_group, target);
}

/*!
 * \internal
 * \brief Set an ACL's mode on a node that matches its XPath expression
 *
 * Given a node that matches an ACL's XPath expression, get the corresponding
 * XML element. Then set the ACL's mode flag in the private data of that
 * element. For details, see comment in the body below, as well as the doc
 * comment for \c pcmk__xpath_match_element().
 *
 * \param[in,out] match      Node matched by the ACL's XPath expression
 * \param[in]     user_data  ACL object (<tt>xml_acl_t *</tt>)
 */
static void
apply_acl_to_match(xmlNode *match, void *user_data)
{
    const xml_acl_t *acl = user_data;
    xml_node_private_t *nodepriv = NULL;
    GString *path = NULL;

    /* @COMPAT If the ACL's XPath matches a node that is neither an element nor
     * a document, we apply the ACL to the parent element rather than to the
     * matched node. For example, if the XPath matches a "score" attribute, then
     * it applies to every element that contains a "score" attribute. That is,
     * the XPath expression "//@score" matches all attributes named "score", but
     * we apply the ACL to all elements containing such an attribute.
     *
     * This behavior is incorrect from an XPath standpoint and is thus confusing
     * and counterintuitive. The correct way to match all elements containing a
     * "score" attribute is to use an XPath predicate: "// *[@score]". (Space
     * inserted after slashes so that GCC doesn't throw an error about nested
     * comments.)
     *
     * Additionally, if an XPath expression matches the entire document (for
     * example, "/"), then the ACL applies to the document's root element if it
     * exists.
     *
     * These behaviors should be changed so that the ACL applies to the nodes
     * matched by the XPath expression, or so that it doesn't apply at all if
     * applying an ACL to an attribute doesn't make sense.
     *
     * Unfortunately, we document in Pacemaker Explained that matching
     * attributes is a valid way to match elements: "Attributes may be specified
     * in the XPath to select particular elements, but the permissions apply to
     * the entire element."
     *
     * So we have to keep this behavior at least until a compatibility break.
     * Even then, it's not feasible in the general case to transform such XPath
     * expressions using XSLT.
     */
    match = pcmk__xpath_match_element(match);
    if (match == NULL) {
        return;
    }

    nodepriv = match->_private;
    pcmk__set_xml_flags(nodepriv, acl->mode);

    path = pcmk__element_xpath(match);
    pcmk__trace("Applied %s ACL to %s matched by %s", acl_mode_text(acl->mode),
                path->str, acl->xpath);
    g_string_free(path, TRUE);
}

/*!
 * \internal
 * \brief Apply an ACL to each matching node in an XML document
 *
 * See \c apply_acl_to_match() for details on applying the ACL.
 *
 * \param[in,out] data       ACL object to apply (<tt>xml_acl_t *</tt>)
 * \param[in,out] user_data  XML document to match against (<tt>xmlDoc *</tt>)
 */
static void
apply_acl_to_doc(gpointer data, gpointer user_data)
{
    xml_acl_t *acl = data;
    xmlDoc *doc = user_data;

    pcmk__xpath_foreach_result(doc, acl->xpath, apply_acl_to_match, acl);
}

/*!
 * \internal
 * \brief Apply all of an XML document's ACLs
 *
 * For each ACL in the document's \c acls list, search the document for nodes
 * that match the ACL's XPath expression. Then apply the ACL to each matching
 * node.
 *
 * See \c apply_acl_to_doc() and \c apply_acl_to_match() for details.
 *
 * \param[in,out] doc  XML document
 */
void
pcmk__apply_acls(xmlDoc *doc)
{
    xml_doc_private_t *docpriv = NULL;

    pcmk__assert(doc != NULL);
    docpriv = doc->_private;

    if (!pcmk__xml_doc_all_flags_set(doc, pcmk__xf_acl_enabled)) {
        return;
    }

    g_list_foreach(docpriv->acls, apply_acl_to_doc, doc);
}

/*!
 * \internal
 * \brief Fetch a user's ACLs from a source document and apply them to a target
 *
 * Unpack the given user's ACLs from the \c PCMK_XE_ACLS element in the source
 * document to the \c acls list in the target document. Then set the target
 * document's \c pcmk__xf_acl_enabled flag and apply the unpacked ACLs.
 *
 * \param[in]     source  XML document whose ACL definitions to use
 * \param[in,out] target  XML document to apply ACLs to
 * \param[in]     user    User whose ACLs to apply
 */
void
pcmk__enable_acls(xmlDoc *source, xmlDoc *target, const char *user)
{
    if (target == NULL) {
        return;
    }
    pcmk__unpack_acls(source, target->_private, user);
    pcmk__xml_doc_set_flags(target, pcmk__xf_acl_enabled);
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
 * \return \c true if \p acl_source and \p xml are non-<tt>NULL</tt> and ACLs
 *         are required for \p user, or \c false otherwise
 *
 * \note If this returns true, caller should use \p result rather than \p xml
 */
bool
xml_acl_filtered_copy(const char *user, xmlNode *acl_source, xmlNode *xml,
                      xmlNode **result)
{
    xmlNode *target = NULL;
    xml_doc_private_t *docpriv = NULL;

    *result = NULL;
    if ((acl_source == NULL) || (acl_source->doc == NULL) || (xml == NULL)
        || !pcmk_acl_required(user)) {

        return false;
    }

    target = pcmk__xml_copy(NULL, xml);
    docpriv = target->doc->_private;

    pcmk__enable_acls(acl_source->doc, target->doc, user);

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
        pcmk__apply_acls(xml->doc);
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
                                            acl_mode_text(mode),            \
                                            xpath->str);                    \
                g_string_free(xpath, TRUE);                                 \
            },                                                              \
            {}                                                              \
        );                                                                  \
    } while (0)

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

    } else if (pcmk__is_privileged(user)) {
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
