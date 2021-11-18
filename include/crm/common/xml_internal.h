/*
 * Copyright 2017-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__XML_INTERNAL__H
#  define PCMK__XML_INTERNAL__H

/*
 * Internal-only wrappers for and extensions to libxml2 (libxslt)
 */

#  include <stdlib.h>
#  include <stdio.h>
#  include <string.h>

#  include <crm/crm.h>  /* transitively imports qblog.h */


/*!
 * \brief Base for directing lib{xml2,xslt} log into standard libqb backend
 *
 * This macro implements the core of what can be needed for directing
 * libxml2 or libxslt error messaging into standard, preconfigured
 * libqb-backed log stream.
 *
 * It's a bit unfortunate that libxml2 (and more sparsely, also libxslt)
 * emits a single message by chunks (location is emitted separatedly from
 * the message itself), so we have to take the effort to combine these
 * chunks back to single message.  Whether to do this or not is driven
 * with \p dechunk toggle.
 *
 * The form of a macro was chosen for implicit deriving of __FILE__, etc.
 * and also because static dechunking buffer should be differentiated per
 * library (here we assume different functions referring to this macro
 * will not ever be using both at once), preferably also per-library
 * context of use to avoid clashes altogether.
 *
 * Note that we cannot use qb_logt, because callsite data have to be known
 * at the moment of compilation, which it is not always the case -- xml_log
 * (and unfortunately there's no clear explanation of the fail to compile).
 *
 * Also note that there's no explicit guard against said libraries producing
 * never-newline-terminated chunks (which would just keep consuming memory),
 * as it's quite improbable.  Termination of the program in between the
 * same-message chunks will raise a flag with valgrind and the likes, though.
 *
 * And lastly, regarding how dechunking combines with other non-message
 * parameters -- for \p priority, most important running specification
 * wins (possibly elevated to LOG_ERR in case of nonconformance with the
 * newline-termination "protocol"), \p dechunk is expected to always be
 * on once it was at the start, and the rest (\p postemit and \p prefix)
 * are picked directly from the last chunk entry finalizing the message
 * (also reasonable to always have it the same with all related entries).
 *
 * \param[in] priority Syslog priority for the message to be logged
 * \param[in] dechunk  Whether to dechunk new-line terminated message
 * \param[in] postemit Code to be executed once message is sent out
 * \param[in] prefix   How to prefix the message or NULL for raw passing
 * \param[in] fmt      Format string as with printf-like functions
 * \param[in] ap       Variable argument list to supplement \p fmt format string
 */
#define PCMK__XML_LOG_BASE(priority, dechunk, postemit, prefix, fmt, ap)        \
do {                                                                            \
    if (!(dechunk) && (prefix) == NULL) {  /* quick pass */                     \
        qb_log_from_external_source_va(__func__, __FILE__, (fmt),               \
                                       (priority), __LINE__, 0, (ap));          \
        (void) (postemit);                                                      \
    } else {                                                                    \
        int CXLB_len = 0;                                                       \
        char *CXLB_buf = NULL;                                                  \
        static int CXLB_buffer_len = 0;                                         \
        static char *CXLB_buffer = NULL;                                        \
        static uint8_t CXLB_priority = 0;                                       \
                                                                                \
        CXLB_len = vasprintf(&CXLB_buf, (fmt), (ap));                           \
                                                                                \
        if (CXLB_len <= 0 || CXLB_buf[CXLB_len - 1] == '\n' || !(dechunk)) {    \
            if (CXLB_len < 0) {                                                 \
                CXLB_buf = (char *) "LOG CORRUPTION HAZARD"; /*we don't modify*/\
                CXLB_priority = QB_MIN(CXLB_priority, LOG_ERR);                 \
            } else if (CXLB_len > 0 /* && (dechunk) */                          \
                       && CXLB_buf[CXLB_len - 1] == '\n') {                     \
                CXLB_buf[CXLB_len - 1] = '\0';                                  \
            }                                                                   \
            if (CXLB_buffer) {                                                  \
                qb_log_from_external_source(__func__, __FILE__, "%s%s%s",       \
                                            CXLB_priority, __LINE__, 0,         \
                                            (prefix) != NULL ? (prefix) : "",   \
                                            CXLB_buffer, CXLB_buf);             \
                free(CXLB_buffer);                                              \
            } else {                                                            \
                qb_log_from_external_source(__func__, __FILE__, "%s%s",         \
                                            (priority), __LINE__, 0,            \
                                            (prefix) != NULL ? (prefix) : "",   \
                                            CXLB_buf);                          \
            }                                                                   \
            if (CXLB_len < 0) {                                                 \
                CXLB_buf = NULL;  /* restore temporary override */              \
            }                                                                   \
            CXLB_buffer = NULL;                                                 \
            CXLB_buffer_len = 0;                                                \
            (void) (postemit);                                                  \
                                                                                \
        } else if (CXLB_buffer == NULL) {                                       \
            CXLB_buffer_len = CXLB_len;                                         \
            CXLB_buffer = CXLB_buf;                                             \
            CXLB_buf = NULL;                                                    \
            CXLB_priority = (priority);  /* remember as a running severest */   \
                                                                                \
        } else {                                                                \
            CXLB_buffer = realloc(CXLB_buffer, 1 + CXLB_buffer_len + CXLB_len); \
            memcpy(CXLB_buffer + CXLB_buffer_len, CXLB_buf, CXLB_len);          \
            CXLB_buffer_len += CXLB_len;                                        \
            CXLB_buffer[CXLB_buffer_len] = '\0';                                \
            CXLB_priority = QB_MIN(CXLB_priority, (priority));  /* severest? */ \
        }                                                                       \
        free(CXLB_buf);                                                         \
    }                                                                           \
} while (0)

/* XML search strings for guest, remote and pacemaker_remote nodes */

/* search string to find CIB resources entries for cluster nodes */
#define PCMK__XP_MEMBER_NODE_CONFIG \
    "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_NODES \
    "/" XML_CIB_TAG_NODE "[not(@type) or @type='member']"

/* search string to find CIB resources entries for guest nodes */
#define PCMK__XP_GUEST_NODE_CONFIG \
    "//" XML_TAG_CIB "//" XML_CIB_TAG_CONFIGURATION "//" XML_CIB_TAG_RESOURCE \
    "//" XML_TAG_META_SETS "//" XML_CIB_TAG_NVPAIR \
    "[@name='" XML_RSC_ATTR_REMOTE_NODE "']"

/* search string to find CIB resources entries for remote nodes */
#define PCMK__XP_REMOTE_NODE_CONFIG \
    "//" XML_TAG_CIB "//" XML_CIB_TAG_CONFIGURATION "//" XML_CIB_TAG_RESOURCE \
    "[@type='remote'][@provider='pacemaker']"

/* search string to find CIB node status entries for pacemaker_remote nodes */
#define PCMK__XP_REMOTE_NODE_STATUS \
    "//" XML_TAG_CIB "//" XML_CIB_TAG_STATUS "//" XML_CIB_TAG_STATE \
    "[@" XML_NODE_IS_REMOTE "='true']"

enum pcmk__xml_artefact_ns {
    pcmk__xml_artefact_ns_legacy_rng = 1,
    pcmk__xml_artefact_ns_legacy_xslt,
    pcmk__xml_artefact_ns_base_rng,
    pcmk__xml_artefact_ns_base_xslt,
};

void pcmk__strip_xml_text(xmlNode *xml);
const char *pcmk__xe_add_last_written(xmlNode *xe);

xmlNode *pcmk__xe_match(xmlNode *parent, const char *node_name,
                        const char *attr_n, const char *attr_v);

void pcmk__xe_remove_matching_attrs(xmlNode *element,
                                    bool (*match)(xmlAttrPtr, void *),
                                    void *user_data);

/*!
 * \internal
 * \brief Get the root directory to scan XML artefacts of given kind for
 *
 * \param[in] ns governs the hierarchy nesting against the inherent root dir
 *
 * \return root directory to scan XML artefacts of given kind for
 */
char *
pcmk__xml_artefact_root(enum pcmk__xml_artefact_ns ns);

/*!
 * \internal
 * \brief Get the fully unwrapped path to particular XML artifact (RNG/XSLT)
 *
 * \param[in] ns       denotes path forming details (parent dir, suffix)
 * \param[in] filespec symbolic file specification to be combined with
 *                     #artefact_ns to form the final path
 * \return unwrapped path to particular XML artifact (RNG/XSLT)
 */
char *pcmk__xml_artefact_path(enum pcmk__xml_artefact_ns ns,
                              const char *filespec);

enum pcmk__acl_render_how {
    pcmk__acl_render_ns_simple = 1,
    pcmk__acl_render_text,
    pcmk__acl_render_color,
};

/*!
 * \internal
 * \brief Serialize-render already pcmk_acl_evaled_as_namespaces annotated XML
 *
 * This function is vitally coupled with externalized material:
 * - access-render-2.xsl
 *
 * In fact, it's just a wrapper for a graceful conducting of such
 * transformation, in particular, it cares about converting values of some
 * configuration parameters directly in said stylesheet since the desired
 * ANSI colors at the output are not expressible directly (alternative approach
 * to this preprocessing: eventual postprocessing, which is less handy here).
 *
 * \param[in] annotated_doc pcmk_acl_evaled_as_namespaces annotated XML
 * \param[in] how           render kind, see #pcmk__acl_render_how enumeration
 * \param[out] doc_txt_ptr  where to put the final outcome string
 * \return 0 or -1, see \c xsltSaveResultToString
 *
 * \note Currently, the function did not receive enough of testing regarding
 *       leak of resources, hence it is not recommended for anything other
 *       than short-lived processes at this time.
 */
int pcmk__acl_evaled_render(xmlDoc *annotated_doc, enum pcmk__acl_render_how,
                            xmlChar **doc_txt_ptr);

/*!
 * \internal
 * \brief Return first non-text child node of an XML node
 *
 * \param[in] parent  XML node to check
 *
 * \return First non-text child node of \p parent (or NULL if none)
 */
static inline xmlNode *
pcmk__xml_first_child(const xmlNode *parent)
{
    xmlNode *child = (parent? parent->children : NULL);

    while (child && (child->type == XML_TEXT_NODE)) {
        child = child->next;
    }
    return child;
}

/*!
 * \internal
 * \brief Return next non-text sibling node of an XML node
 *
 * \param[in] child  XML node to check
 *
 * \return Next non-text sibling of \p child (or NULL if none)
 */
static inline xmlNode *
pcmk__xml_next(const xmlNode *child)
{
    xmlNode *next = (child? child->next : NULL);

    while (next && (next->type == XML_TEXT_NODE)) {
        next = next->next;
    }
    return next;
}

/*!
 * \internal
 * \brief Return first non-text child element of an XML node
 *
 * \param[in] parent  XML node to check
 *
 * \return First child element of \p parent (or NULL if none)
 */
static inline xmlNode *
pcmk__xe_first_child(const xmlNode *parent)
{
    xmlNode *child = (parent? parent->children : NULL);

    while (child && (child->type != XML_ELEMENT_NODE)) {
        child = child->next;
    }
    return child;
}

/*!
 * \internal
 * \brief Return next non-text sibling element of an XML element
 *
 * \param[in] child  XML element to check
 *
 * \return Next sibling element of \p child (or NULL if none)
 */
static inline xmlNode *
pcmk__xe_next(const xmlNode *child)
{
    xmlNode *next = child? child->next : NULL;

    while (next && (next->type != XML_ELEMENT_NODE)) {
        next = next->next;
    }
    return next;
}

/*!
 * \internal
 * \brief Like pcmk__xe_set_props, but takes a va_list instead of
 *        arguments directly.
 */
void
pcmk__xe_set_propv(xmlNodePtr node, va_list pairs);

/*!
 * \internal
 * \brief Add a NULL-terminated list of name/value pairs to the given
 *        XML node as properties.
 *
 * \param[in,out] node XML node to add properties to
 * \param[in]     ...  NULL-terminated list of name/value pairs
 *
 * \note A NULL name terminates the arguments; a NULL value will be skipped.
 */
void
pcmk__xe_set_props(xmlNodePtr node, ...)
G_GNUC_NULL_TERMINATED;

/*!
 * \internal
 * \brief Get first attribute of an XML element
 *
 * \param[in] xe  XML element to check
 *
 * \return First attribute of \p xe (or NULL if \p xe is NULL or has none)
 */
static inline xmlAttr *
pcmk__xe_first_attr(const xmlNode *xe)
{
    return (xe == NULL)? NULL : xe->properties;
}

/*!
 * \internal
 * \brief Extract the ID attribute from an XML element
 *
 * \param[in] xpath String to search
 * \param[in] node  Node to get the ID for
 *
 * \return ID attribute of \p node in xpath string \p xpath
 */
char *
pcmk__xpath_node_id(const char *xpath, const char *node);

#endif // PCMK__XML_INTERNAL__H
